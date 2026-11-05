//! Everything the server keeps except metrics, in SQLite, Postgres or MySQL.
//! The URL picks the database, and SeaORM handles the differences between them.
//! Schema changes live in [`crate::migrations`].

mod agent;
mod agent_config_status;
mod agent_fact;
mod alert;
mod alert_rule;
mod alert_rule_channel;
mod alerting;
mod config_rule;
mod config_rule_setting;
mod notification;
mod notification_channel;
mod remote_check;
mod remote_checks;
mod server_secret;
mod stats;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use maxnines_protocol::auth::new_nonce;
use sea_orm::sea_query::Expr;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

pub use self::stats::DatabaseStats;
use crate::facts::{FlatFacts, decode, encode, flatten, unflatten};
use crate::migrations::Migrator;
use crate::registration::{AgentRecord, AgentState};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Registry calls run one at a time, so a small pool is plenty.
const MAX_CONNECTIONS: u32 = 5;

/// A value a fact held for a period. `valid_to_ms` is empty while it's current.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FactVersion {
    pub name: String,
    pub value: Value,
    pub valid_from_ms: u64,
    pub valid_to_ms: Option<u64>,
}

/// A rule as stored, with its settings in their natural shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigRule {
    pub id: i64,
    #[serde(flatten)]
    pub rule: RuleInput,
}

/// What can be set on a rule. Validated by [`crate::rule_engine::check_rule`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleInput {
    pub name: String,
    /// Higher priorities apply later, so they win.
    pub priority: i32,
    /// A CEL expression. An empty condition matches every agent.
    pub condition: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub settings: Value,
}

fn default_enabled() -> bool {
    true
}

/// What an agent last said about its config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigStatus {
    pub version: String,
    pub error: Option<String>,
    pub reported_at_ms: u64,
}

#[derive(Clone)]
pub struct Database {
    connection: DatabaseConnection,
    /// Two connections using one agent key must not both update its facts,
    /// or a fact could end up with two current values.
    facts_lock: Arc<Mutex<()>>,
}

impl Database {
    /// Connects and brings the schema up to date. Errors don't mention the URL,
    /// because it can hold a password.
    pub async fn connect(url: &str) -> Result<Self> {
        create_sqlite_folder(url)?;

        // SQLite allows one writer, and each connection to an in-memory
        // database gets its own empty database.
        let is_sqlite = url.starts_with("sqlite:");
        let mut options = ConnectOptions::new(url);
        options
            .max_connections(if is_sqlite { 1 } else { MAX_CONNECTIONS })
            .connect_timeout(CONNECT_TIMEOUT)
            .acquire_timeout(CONNECT_TIMEOUT)
            .sqlx_logging(false);

        let connection = sea_orm::Database::connect(options)
            .await
            .context("connecting to the database")?;
        Migrator::up(&connection, None)
            .await
            .context("updating the database schema")?;
        Ok(Self {
            connection,
            facts_lock: Arc::default(),
        })
    }

    pub async fn load_agents(&self) -> Result<Vec<AgentRecord>> {
        let rows = agent::Entity::find()
            .all(&self.connection)
            .await
            .context("loading agents")?;
        rows.into_iter().map(to_record).collect()
    }

    /// Creates or replaces an agent's record.
    pub async fn save_agent(&self, record: &AgentRecord) -> Result<()> {
        let row = agent::ActiveModel {
            id: Set(record.id.clone()),
            public_key: Set(record.public_key.clone()),
            host: Set(record.host.clone()),
            state: Set(record.state.as_str().to_string()),
            decided_by: Set(record.decided_by.clone()),
            first_seen_ms: Set(record.first_seen_ms as i64),
            decided_at_ms: Set(record.decided_at_ms.map(|ms| ms as i64)),
        };

        let on_conflict = OnConflict::column(agent::Column::Id)
            .update_columns([
                agent::Column::PublicKey,
                agent::Column::Host,
                agent::Column::State,
                agent::Column::DecidedBy,
                agent::Column::FirstSeenMs,
                agent::Column::DecidedAtMs,
            ])
            .to_owned();

        agent::Entity::insert(row)
            .on_conflict(on_conflict)
            .exec_without_returning(&self.connection)
            .await
            .context("saving agent")?;
        Ok(())
    }
}

impl Database {
    /// Closes facts that changed or went away, and adds the new values, all in
    /// one transaction. Returns whether anything changed.
    pub async fn record_facts(
        &self,
        agent_id: &str,
        facts: &FlatFacts,
        now_ms: u64,
    ) -> Result<bool> {
        let _only_writer = self.facts_lock.lock().await;
        let transaction = self.connection.begin().await.context("saving facts")?;

        let current = agent_fact::Entity::find()
            .filter(agent_fact::Column::AgentId.eq(agent_id))
            .filter(agent_fact::Column::ValidToMs.is_null())
            .all(&transaction)
            .await
            .context("loading facts")?;

        let mut unchanged = BTreeSet::new();
        let mut closed = Vec::new();
        for row in current {
            let same = facts.get(&row.name).is_some_and(|value| {
                let (text, value_type) = encode(value);
                text == row.value && value_type == row.value_type
            });
            if same {
                unchanged.insert(row.name);
            } else {
                closed.push(row.id);
            }
        }

        let added: Vec<agent_fact::ActiveModel> = facts
            .iter()
            .filter(|(name, _)| !unchanged.contains(*name))
            .map(|(name, value)| {
                let (text, value_type) = encode(value);
                agent_fact::ActiveModel {
                    agent_id: Set(agent_id.to_string()),
                    name: Set(name.clone()),
                    value: Set(text),
                    value_type: Set(value_type.to_string()),
                    valid_from_ms: Set(now_ms as i64),
                    valid_to_ms: Set(None),
                    ..Default::default()
                }
            })
            .collect();

        let changed = !closed.is_empty() || !added.is_empty();

        if !closed.is_empty() {
            agent_fact::Entity::update_many()
                .col_expr(agent_fact::Column::ValidToMs, Expr::value(now_ms as i64))
                .filter(agent_fact::Column::Id.is_in(closed))
                .exec(&transaction)
                .await
                .context("closing old facts")?;
        }
        if !added.is_empty() {
            agent_fact::Entity::insert_many(added)
                .exec_without_returning(&transaction)
                .await
                .context("saving facts")?;
        }

        transaction.commit().await.context("saving facts")?;
        Ok(changed)
    }

    pub async fn current_facts(&self, agent_id: &str) -> Result<Vec<FactVersion>> {
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::AgentId.eq(agent_id))
            .filter(agent_fact::Column::ValidToMs.is_null())
            .order_by_asc(agent_fact::Column::Name)
            .all(&self.connection)
            .await
            .context("loading facts")?;
        rows.into_iter().map(to_fact_version).collect()
    }

    /// Every agent's current facts, in one query so that looking across all
    /// agents doesn't cost a query each.
    pub async fn all_current_facts(&self) -> Result<BTreeMap<String, FlatFacts>> {
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::ValidToMs.is_null())
            .all(&self.connection)
            .await
            .context("loading facts")?;

        let mut agents: BTreeMap<String, FlatFacts> = BTreeMap::new();
        for row in rows {
            let agent = row.agent_id.clone();
            let fact = to_fact_version(row)?;
            agents
                .entry(agent)
                .or_default()
                .insert(fact.name, fact.value);
        }
        Ok(agents)
    }

    /// Every fact name in use and how its values are written, for offering in
    /// forms. A list appears once under its own name, as a list item's type.
    pub async fn known_facts(&self) -> Result<BTreeMap<String, String>> {
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::ValidToMs.is_null())
            .all(&self.connection)
            .await
            .context("loading fact names")?;

        let mut known = BTreeMap::new();
        for row in rows {
            let name = match row.name.strip_suffix(']').and_then(|n| n.rsplit_once('[')) {
                Some((list, _)) => list.to_string(),
                None => row.name,
            };
            // Items inside lists of maps can't be reached by a simple condition.
            if !name.contains('[') {
                known.insert(name, row.value_type);
            }
        }
        Ok(known)
    }

    /// Every value each fact has had, oldest first. Rows are ordered by ID, not
    /// time, because two reports can share a timestamp and clocks can go back.
    pub async fn facts_history(&self, agent_id: &str) -> Result<Vec<FactVersion>> {
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::AgentId.eq(agent_id))
            .order_by_asc(agent_fact::Column::Id)
            .all(&self.connection)
            .await
            .context("loading facts history")?;
        rows.into_iter().map(to_fact_version).collect()
    }
}

const ADMIN_TOKEN: &str = "admin_token";

impl Database {
    /// The token that protects the admin API, created the first time it's asked
    /// for. Two servers starting at once can't end up with different tokens, as
    /// only the first insert counts and both read the result.
    pub async fn admin_token(&self) -> Result<String> {
        let saved = server_secret::Entity::find_by_id(ADMIN_TOKEN)
            .one(&self.connection)
            .await
            .context("reading the admin token")?;
        if let Some(saved) = saved {
            return Ok(saved.value);
        }

        let row = server_secret::ActiveModel {
            name: Set(ADMIN_TOKEN.to_string()),
            value: Set(new_nonce()?),
        };
        server_secret::Entity::insert(row)
            .on_conflict_do_nothing_on([server_secret::Column::Name])
            .exec_without_returning(&self.connection)
            .await
            .context("saving the admin token")?;

        let saved = server_secret::Entity::find_by_id(ADMIN_TOKEN)
            .one(&self.connection)
            .await
            .context("reading the admin token")?;
        Ok(saved.context("the admin token wasn't saved")?.value)
    }
}

impl Database {
    /// Lowest priority first, which is the order they're applied in.
    pub async fn list_rules(&self) -> Result<Vec<ConfigRule>> {
        let rows = config_rule::Entity::find()
            .order_by_asc(config_rule::Column::Priority)
            .order_by_asc(config_rule::Column::Id)
            .all(&self.connection)
            .await
            .context("loading rules")?;

        let settings = config_rule_setting::Entity::find()
            .all(&self.connection)
            .await
            .context("loading rule settings")?;

        rows.into_iter()
            .map(|row| {
                let mine = settings.iter().filter(|setting| setting.rule_id == row.id);
                to_rule(row.clone(), mine)
            })
            .collect()
    }

    pub async fn get_rule(&self, id: i64) -> Result<Option<ConfigRule>> {
        let row = config_rule::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading rule")?;
        let Some(row) = row else {
            return Ok(None);
        };

        let settings = config_rule_setting::Entity::find()
            .filter(config_rule_setting::Column::RuleId.eq(id))
            .all(&self.connection)
            .await
            .context("loading rule settings")?;
        to_rule(row, settings.iter()).map(Some)
    }

    pub async fn create_rule(&self, input: &RuleInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving rule")?;
        let row = config_rule::ActiveModel {
            name: Set(input.name.clone()),
            priority: Set(input.priority),
            condition_expr: Set(input.condition.clone()),
            enabled: Set(input.enabled),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .context("saving rule")?;

        save_settings(&transaction, row.id, &input.settings).await?;
        transaction.commit().await.context("saving rule")?;
        Ok(row.id)
    }

    /// Returns false if there's no such rule.
    pub async fn update_rule(&self, id: i64, input: &RuleInput) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving rule")?;
        let found = config_rule::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading rule")?;
        let Some(row) = found else {
            return Ok(false);
        };

        let mut row: config_rule::ActiveModel = row.into();
        row.name = Set(input.name.clone());
        row.priority = Set(input.priority);
        row.condition_expr = Set(input.condition.clone());
        row.enabled = Set(input.enabled);
        row.update(&transaction).await.context("saving rule")?;

        config_rule_setting::Entity::delete_many()
            .filter(config_rule_setting::Column::RuleId.eq(id))
            .exec(&transaction)
            .await
            .context("replacing rule settings")?;
        save_settings(&transaction, id, &input.settings).await?;

        transaction.commit().await.context("saving rule")?;
        Ok(true)
    }

    /// Returns false if there's no such rule.
    pub async fn delete_rule(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting rule")?;
        config_rule_setting::Entity::delete_many()
            .filter(config_rule_setting::Column::RuleId.eq(id))
            .exec(&transaction)
            .await
            .context("deleting rule settings")?;
        let deleted = config_rule::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting rule")?;
        transaction.commit().await.context("deleting rule")?;
        Ok(deleted.rows_affected > 0)
    }

    pub async fn save_config_status(&self, agent_id: &str, status: &ConfigStatus) -> Result<()> {
        let row = agent_config_status::ActiveModel {
            agent_id: Set(agent_id.to_string()),
            version: Set(status.version.clone()),
            error: Set(status.error.clone()),
            reported_at_ms: Set(status.reported_at_ms as i64),
        };
        let on_conflict = OnConflict::column(agent_config_status::Column::AgentId)
            .update_columns([
                agent_config_status::Column::Version,
                agent_config_status::Column::Error,
                agent_config_status::Column::ReportedAtMs,
            ])
            .to_owned();

        agent_config_status::Entity::insert(row)
            .on_conflict(on_conflict)
            .exec_without_returning(&self.connection)
            .await
            .context("saving config status")?;
        Ok(())
    }

    pub async fn config_status(&self, agent_id: &str) -> Result<Option<ConfigStatus>> {
        let row = agent_config_status::Entity::find_by_id(agent_id)
            .one(&self.connection)
            .await
            .context("loading config status")?;
        Ok(row.map(|row| ConfigStatus {
            version: row.version,
            error: row.error,
            reported_at_ms: row.reported_at_ms as u64,
        }))
    }
}

async fn save_settings(
    connection: &impl ConnectionTrait,
    rule_id: i64,
    settings: &Value,
) -> Result<()> {
    let rows: Vec<config_rule_setting::ActiveModel> = flatten(settings)?
        .iter()
        .map(|(name, value)| {
            let (text, value_type) = encode(value);
            config_rule_setting::ActiveModel {
                rule_id: Set(rule_id),
                name: Set(name.clone()),
                value: Set(text),
                value_type: Set(value_type.to_string()),
                ..Default::default()
            }
        })
        .collect();

    if !rows.is_empty() {
        config_rule_setting::Entity::insert_many(rows)
            .exec_without_returning(connection)
            .await
            .context("saving rule settings")?;
    }
    Ok(())
}

fn to_rule<'a>(
    row: config_rule::Model,
    settings: impl Iterator<Item = &'a config_rule_setting::Model>,
) -> Result<ConfigRule> {
    let flat = settings
        .map(|setting| {
            let value = decode(&setting.value, &setting.value_type)
                .with_context(|| format!("setting {} has an invalid value", setting.name))?;
            Ok((setting.name.clone(), value))
        })
        .collect::<Result<FlatFacts>>()?;

    Ok(ConfigRule {
        id: row.id,
        rule: RuleInput {
            name: row.name,
            priority: row.priority,
            condition: row.condition_expr,
            enabled: row.enabled,
            settings: unflatten(&flat),
        },
    })
}

fn to_fact_version(row: agent_fact::Model) -> Result<FactVersion> {
    Ok(FactVersion {
        value: decode(&row.value, &row.value_type)
            .with_context(|| format!("fact {} has an invalid value", row.name))?,
        name: row.name,
        valid_from_ms: row.valid_from_ms as u64,
        valid_to_ms: row.valid_to_ms.map(|ms| ms as u64),
    })
}

fn to_record(row: agent::Model) -> Result<AgentRecord> {
    Ok(AgentRecord {
        state: AgentState::parse(&row.state)
            .with_context(|| format!("agent {} has unknown state {:?}", row.id, row.state))?,
        id: row.id,
        public_key: row.public_key,
        host: row.host,
        decided_by: row.decided_by,
        first_seen_ms: row.first_seen_ms as u64,
        decided_at_ms: row.decided_at_ms.map(|ms| ms as u64),
    })
}

/// SQLite can create its file but not the folder it goes in.
fn create_sqlite_folder(url: &str) -> Result<()> {
    let Some(rest) = url.strip_prefix("sqlite://") else {
        return Ok(());
    };
    let path = rest.split('?').next().unwrap_or(rest);
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating folder {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
impl Database {
    pub async fn in_memory() -> Self {
        Self::connect("sqlite::memory:").await.unwrap()
    }

    /// Makes every later query fail, as if the database had gone away.
    pub async fn break_for_test(&self) {
        use sea_orm::ConnectionTrait;
        self.connection
            .execute_unprepared("DROP TABLE agent_config_status")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DROP TABLE agent_facts")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DROP TABLE agents")
            .await
            .unwrap();
    }

    async fn clear_for_test(&self) {
        use sea_orm::ConnectionTrait;
        self.connection
            .execute_unprepared("DELETE FROM agent_config_status")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM agent_facts")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM config_rules WHERE name <> 'Default'")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM alerts")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM agents WHERE id <> 'server'")
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::facts::flatten;

    fn record(id: &str) -> AgentRecord {
        AgentRecord {
            id: id.to_string(),
            public_key: "ab".repeat(32),
            host: "web-1".to_string(),
            state: AgentState::Pending,
            decided_by: None,
            first_seen_ms: 1_789_000_000_123,
            decided_at_ms: None,
        }
    }

    /// Everything but the built-in agent, which every database starts with.
    async fn machines(database: &Database) -> Vec<AgentRecord> {
        let mut agents = database.load_agents().await.unwrap();
        agents.retain(|agent| !agent.is_local());
        agents
    }

    fn sorted(mut records: Vec<AgentRecord>) -> Vec<AgentRecord> {
        records.sort_by(|a, b| a.id.cmp(&b.id));
        records
    }

    #[tokio::test]
    async fn the_admin_token_survives_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}?mode=rwc", folder.path().join("db").display());

        let first = Database::connect(&url).await.unwrap();
        let token = first.admin_token().await.unwrap();
        drop(first);

        let reopened = Database::connect(&url).await.unwrap();
        assert_eq!(reopened.admin_token().await.unwrap(), token);
    }

    #[tokio::test]
    async fn each_database_gets_its_own_admin_token() {
        let first = Database::in_memory().await.admin_token().await.unwrap();
        let second = Database::in_memory().await.admin_token().await.unwrap();
        assert_ne!(first, second);
    }

    /// Everything each database has to get right. It runs against SQLite
    /// always, and against real servers with `cargo test -- --ignored`.
    async fn exercise(url: &str) {
        let database = Database::connect(url).await.unwrap();
        database.clear_for_test().await;
        assert!(machines(&database).await.is_empty());

        // Creating.
        let pending = record("agent-1");
        database.save_agent(&pending).await.unwrap();
        assert_eq!(machines(&database).await, vec![pending.clone()]);

        // Saving identical data, which MySQL reports as zero rows changed.
        database.save_agent(&pending).await.unwrap();
        assert_eq!(machines(&database).await, vec![pending.clone()]);

        // Replacing, including going from NULL to a value.
        let approved = AgentRecord {
            state: AgentState::Approved,
            decided_by: Some("rule:production-subnet".to_string()),
            decided_at_ms: Some(1_789_000_000_456),
            ..pending.clone()
        };
        database.save_agent(&approved).await.unwrap();
        assert_eq!(machines(&database).await, vec![approved.clone()]);

        // The largest hostname allowed, non-ASCII text, and a long rule name.
        let unusual = AgentRecord {
            host: "x".repeat(255),
            decided_by: Some(format!("rule:{}", "é🚀".repeat(200))),
            ..record("agent-2")
        };
        database.save_agent(&unusual).await.unwrap();
        let unicode = AgentRecord {
            host: "сервер-🚀".to_string(),
            ..record("agent-3")
        };
        database.save_agent(&unicode).await.unwrap();
        assert_eq!(
            sorted(machines(&database).await),
            [approved.clone(), unusual.clone(), unicode.clone()]
        );

        exercise_facts(&database, &approved.id, &unusual.id).await;
        exercise_rules(&database).await;
        exercise_config_status(&database, &approved.id).await;

        // A second connection sees it all, and migrating again changes nothing.
        let reopened = Database::connect(url).await.unwrap();
        assert_eq!(
            sorted(machines(&reopened).await),
            [approved, unusual, unicode]
        );

        database.clear_for_test().await;
    }

    fn flat(pairs: &[(&str, Value)]) -> FlatFacts {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect()
    }

    fn current(versions: &[FactVersion]) -> Vec<(&str, &Value)> {
        versions
            .iter()
            .filter(|version| version.valid_to_ms.is_none())
            .map(|version| (version.name.as_str(), &version.value))
            .collect()
    }

    fn rule_input(name: &str, priority: i32) -> RuleInput {
        RuleInput {
            name: name.to_string(),
            priority,
            condition: Some("facts.os.family == \"linux\"".to_string()),
            enabled: true,
            settings: json!({
                "interval_secs": 10,
                "collectors": {
                    "disk": { "enabled": true, "mount_points": ["/", "/data"] },
                },
            }),
        }
    }

    #[tokio::test]
    async fn known_facts_lists_each_name_once_with_its_type() {
        let database = Database::in_memory().await;
        database.save_agent(&record("agent-1")).await.unwrap();
        database.save_agent(&record("agent-2")).await.unwrap();
        let facts = flatten(&json!({
            "os": { "family": "linux" },
            "custom": { "tags": ["a", "b"], "rack": 12, "disks": [{ "mount": "/" }] },
        }))
        .unwrap();
        database.record_facts("agent-1", &facts, 1).await.unwrap();
        database.record_facts("agent-2", &facts, 1).await.unwrap();

        let known = database.known_facts().await.unwrap();

        assert_eq!(
            known,
            BTreeMap::from([
                ("custom.rack".to_string(), "number".to_string()),
                ("custom.tags".to_string(), "string".to_string()),
                ("os.family".to_string(), "string".to_string()),
            ])
        );
    }

    async fn exercise_rules(database: &Database) {
        // A new install has a default rule, from the migration.
        let rules = database.list_rules().await.unwrap();
        assert_eq!(rules[0].rule.name, "Default");
        assert_eq!(rules[0].rule.condition, None);
        assert_eq!(rules[0].rule.settings["interval_secs"], 15);
        assert_eq!(rules[0].rule.settings["collectors"]["cpu"]["enabled"], true);

        // Settings come back with their types and shape.
        let later = database
            .create_rule(&rule_input("later", 200))
            .await
            .unwrap();
        let earlier = database
            .create_rule(&rule_input("earlier", 100))
            .await
            .unwrap();
        let rule = database.get_rule(later).await.unwrap().unwrap();
        assert_eq!(rule.rule, rule_input("later", 200));

        // Lowest priority first.
        let names: Vec<String> = database
            .list_rules()
            .await
            .unwrap()
            .into_iter()
            .map(|rule| rule.rule.name)
            .collect();
        assert_eq!(names, ["Default", "earlier", "later"]);

        // Updating replaces the settings instead of adding to them.
        let mut changed = rule_input("renamed", 300);
        changed.condition = None;
        changed.enabled = false;
        changed.settings = json!({ "interval_secs": 5 });
        assert!(database.update_rule(later, &changed).await.unwrap());
        assert_eq!(
            database.get_rule(later).await.unwrap().unwrap().rule,
            changed
        );

        // Unknown rules are reported, not errors.
        assert!(!database.update_rule(9_999_999, &changed).await.unwrap());
        assert!(!database.delete_rule(9_999_999).await.unwrap());
        assert_eq!(database.get_rule(9_999_999).await.unwrap(), None);

        // A second rule can't take a name that's in use.
        assert!(
            database
                .create_rule(&rule_input("earlier", 1))
                .await
                .is_err()
        );

        assert!(database.delete_rule(later).await.unwrap());
        assert!(database.delete_rule(earlier).await.unwrap());
        assert_eq!(database.list_rules().await.unwrap().len(), 1);
    }

    async fn exercise_config_status(database: &Database, agent: &str) {
        assert_eq!(database.config_status(agent).await.unwrap(), None);

        let failed = ConfigStatus {
            version: "v1".to_string(),
            error: Some("unknown collector".to_string()),
            reported_at_ms: 100,
        };
        database.save_config_status(agent, &failed).await.unwrap();
        assert_eq!(
            database.config_status(agent).await.unwrap(),
            Some(failed.clone())
        );

        // Saving identical data, which MySQL reports as zero rows changed.
        database.save_config_status(agent, &failed).await.unwrap();

        let applied = ConfigStatus {
            version: "v2".to_string(),
            error: None,
            reported_at_ms: 200,
        };
        database.save_config_status(agent, &applied).await.unwrap();
        assert_eq!(database.config_status(agent).await.unwrap(), Some(applied));
    }

    async fn exercise_facts(database: &Database, agent: &str, other: &str) {
        assert!(database.current_facts(agent).await.unwrap().is_empty());

        // Every value type, and non-ASCII text.
        let first = flat(&[
            ("os.family", json!("linux")),
            ("os.version", json!("24.04")),
            ("memory.total_bytes", json!(51_539_607_552_u64)),
            ("custom.enabled", json!(true)),
            ("custom.note", json!("сервер-🚀")),
        ]);
        assert!(database.record_facts(agent, &first, 100).await.unwrap());
        assert!(!database.record_facts(agent, &first, 200).await.unwrap());

        let facts = database.current_facts(agent).await.unwrap();
        assert_eq!(facts.len(), 5);
        let value = |name: &str| {
            let fact = facts.iter().find(|f| f.name == name).unwrap();
            fact.value.clone()
        };
        assert_eq!(value("memory.total_bytes"), json!(51_539_607_552_u64));
        assert_eq!(value("custom.enabled"), json!(true));
        assert_eq!(value("custom.note"), json!("сервер-🚀"));

        // One fact changes, one goes away, one is new, and the rest stay put.
        let second = flat(&[
            ("os.family", json!("linux")),
            ("os.version", json!("24.10")),
            ("memory.total_bytes", json!(51_539_607_552_u64)),
            ("custom.enabled", json!(true)),
            ("custom.role", json!("web")),
        ]);
        assert!(database.record_facts(agent, &second, 300).await.unwrap());

        let history = database.facts_history(agent).await.unwrap();
        assert_eq!(history.len(), 7);
        let family = history.iter().find(|f| f.name == "os.family").unwrap();
        assert_eq!((family.valid_from_ms, family.valid_to_ms), (100, None));
        let old = history.iter().find(|f| f.value == json!("24.04")).unwrap();
        assert_eq!((old.valid_from_ms, old.valid_to_ms), (100, Some(300)));
        let new = history.iter().find(|f| f.value == json!("24.10")).unwrap();
        assert_eq!((new.valid_from_ms, new.valid_to_ms), (300, None));
        let gone = history.iter().find(|f| f.name == "custom.note").unwrap();
        assert_eq!(gone.valid_to_ms, Some(300));
        assert_eq!(database.current_facts(agent).await.unwrap().len(), 5);
        assert_eq!(current(&history).len(), 5);

        // Going back to earlier values is a change too: os.version and
        // custom.note return, so two more rows.
        assert!(database.record_facts(agent, &first, 400).await.unwrap());
        assert_eq!(database.facts_history(agent).await.unwrap().len(), 9);

        // A value keeps its type: 1 and "1" are different facts.
        let number = flat(&[("custom.level", json!(1))]);
        let text = flat(&[("custom.level", json!("1"))]);
        assert!(database.record_facts(other, &number, 500).await.unwrap());
        assert!(database.record_facts(other, &text, 600).await.unwrap());
        let levels = database.current_facts(other).await.unwrap();

        // Each agent's current values, and none of the ones they replaced.
        assert_eq!(
            database.all_current_facts().await.unwrap(),
            BTreeMap::from([
                (agent.to_string(), first.clone()),
                (other.to_string(), text.clone())
            ])
        );

        assert_eq!(levels[0].value, json!("1"));

        // Changing a list only touches the items that changed.
        let names = |facts: &[FactVersion]| -> Vec<(String, Value)> {
            facts
                .iter()
                .filter(|f| f.name.starts_with("custom.tags"))
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect()
        };
        let tags = |value: Value| flatten(&json!({ "custom": { "tags": value } })).unwrap();

        let list = tags(json!(["web", "prod"]));
        assert!(database.record_facts(other, &list, 700).await.unwrap());
        assert!(!database.record_facts(other, &list, 750).await.unwrap());

        let longer = tags(json!(["web", "prod", "eu"]));
        let before = database.facts_history(other).await.unwrap().len();
        assert!(database.record_facts(other, &longer, 800).await.unwrap());
        let after = database.facts_history(other).await.unwrap().len();
        assert_eq!(after, before + 1);

        let current = database.current_facts(other).await.unwrap();
        assert_eq!(
            names(&current),
            [
                ("custom.tags[0]".to_string(), json!("web")),
                ("custom.tags[1]".to_string(), json!("prod")),
                ("custom.tags[2]".to_string(), json!("eu")),
            ]
        );

        // Removing the first item shifts the rest and drops the last name.
        let shifted = tags(json!(["prod", "eu"]));
        assert!(database.record_facts(other, &shifted, 900).await.unwrap());
        let current = database.current_facts(other).await.unwrap();
        assert_eq!(
            names(&current),
            [
                ("custom.tags[0]".to_string(), json!("prod")),
                ("custom.tags[1]".to_string(), json!("eu")),
            ]
        );

        // A single value is a different name from a one-item list.
        let single = tags(json!("prod"));
        assert!(database.record_facts(other, &single, 1000).await.unwrap());
        let current = database.current_facts(other).await.unwrap();
        assert_eq!(
            names(&current),
            [("custom.tags".to_string(), json!("prod"))]
        );

        // Each agent has its own facts.
        assert_eq!(database.current_facts(agent).await.unwrap().len(), 5);

        exercise_alerting(database, agent).await;
        exercise_remote_checks(database).await;

        let token = database.admin_token().await.unwrap();
        assert!(token.len() >= 32);
        assert_eq!(database.admin_token().await.unwrap(), token);

        let stats = database.stats().await.unwrap();
        assert!(stats.size_bytes.unwrap_or(0) > 0, "{stats:?}");
        assert!(stats.latest_migration.is_some());
        assert_eq!(stats.tables[0].name, "Agents");
        assert!(stats.tables[0].rows > 0);
    }

    async fn exercise_remote_checks(database: &Database) {
        use maxnines_protocol::{Check, CheckKind};

        use crate::remote_checks::{LOCAL_AGENT_ID, RemoteCheckInput};

        let agents = database.load_agents().await.unwrap();
        assert!(agents.iter().any(|agent| agent.id == LOCAL_AGENT_ID));

        let name = format!("site {}", crate::metrics::now_ms());
        let mut check = Check::new(&name, CheckKind::Http, "https://example.com/");
        check.timeout_secs = Some(5);
        check.method = Some("POST".to_string());
        check.body = Some("é".repeat(100));
        check.regex = Some("Welcome".to_string());
        check.insecure = Some(true);
        let mut input = RemoteCheckInput {
            check,
            interval_secs: 60,
            enabled: true,
        };

        let id = database.create_remote_check(&input).await.unwrap();
        let saved = database.get_remote_check(id).await.unwrap().unwrap();
        assert_eq!(saved.input, input);

        input.interval_secs = 120;
        input.check.count = None;
        assert!(database.update_remote_check(id, &input).await.unwrap());
        let list = database.list_remote_checks().await.unwrap();
        let saved = list.iter().find(|check| check.id == id).unwrap();
        assert_eq!(saved.input.interval_secs, 120);

        assert!(database.delete_remote_check(id).await.unwrap());
        assert!(database.get_remote_check(id).await.unwrap().is_none());
    }

    /// Names are unique per run, because real databases keep their rows.
    async fn exercise_alerting(database: &Database, agent: &str) {
        use crate::alerting::{
            AlertRuleInput, ChannelInput, ChannelKind, Comparison, Event, NewAlert, RuleKind,
            Severity,
        };

        let suffix = crate::metrics::now_ms();
        let channel = database
            .create_channel(&ChannelInput {
                name: format!("Ops {suffix}"),
                kind: ChannelKind::Webhook,
                target: "https://example.com/hook".to_string(),
                credential: Some("secret".to_string()),
            })
            .await
            .unwrap();
        let mut input = AlertRuleInput {
            name: format!("High CPU {suffix}"),
            kind: RuleKind::Metric,
            metric: Some("cpu.usage".to_string()),
            series: Some("/data*".to_string()),
            comparison: Some(Comparison::Above),
            threshold: Some(90.5),
            for_secs: 120,
            severity: Severity::Critical,
            condition: Some("true".to_string()),
            enabled: true,
            channels: vec![channel],
        };
        let rule = database.create_alert_rule(&input).await.unwrap();
        assert_eq!(
            database.get_alert_rule(rule).await.unwrap().unwrap().rule,
            input
        );

        input.threshold = Some(75.25);
        assert!(database.update_alert_rule(rule, &input).await.unwrap());
        assert_eq!(
            database.get_alert_rule(rule).await.unwrap().unwrap().rule,
            input
        );

        let started_ms = suffix;
        let new = NewAlert {
            rule_id: rule,
            rule_name: input.name.clone(),
            severity: input.severity,
            agent_id: agent.to_string(),
            host: "é".repeat(255),
            series: "é".repeat(255),
            value: Some(91.5),
            summary: "x".repeat(5000),
            started_ms,
        };
        let alert = database.fire_alert(&new, &[channel]).await.unwrap();
        let open = database.open_alerts().await.unwrap();
        let saved = open.iter().find(|a| a.id == alert).unwrap();
        assert_eq!(saved.host, new.host);
        assert_eq!(saved.value, Some(91.5));

        let due = database.due_deliveries(started_ms, 500).await.unwrap();
        let firing = due.iter().find(|d| d.alert.id == alert).unwrap();
        assert_eq!(firing.event, Event::Firing);
        database
            .delivery_failed(
                firing.id,
                1,
                "the webhook returned status 500",
                Some(started_ms + 5),
            )
            .await
            .unwrap();
        let problems = database.delivery_problems(10).await.unwrap();
        assert_eq!(problems[0].error, "the webhook returned status 500");
        database
            .delivery_sent(firing.id, 2, started_ms + 5, Some("C123:1.2"))
            .await
            .unwrap();

        database
            .resolve_alert(alert, started_ms + 10, "The problem cleared")
            .await
            .unwrap();
        let due = database.due_deliveries(started_ms + 10, 500).await.unwrap();
        let resolved = due.iter().find(|d| d.alert.id == alert).unwrap();
        assert_eq!(resolved.event, Event::Resolved);
        assert_eq!(resolved.reply_to.as_deref(), Some("C123:1.2"));
        assert_eq!(
            resolved.channel.channel.credential.as_deref(),
            Some("secret")
        );

        // The alert outlives its rule, and its queue goes with its channel.
        assert!(database.delete_alert_rule(rule).await.unwrap());
        let history = database.resolved_alerts(10).await.unwrap();
        let ended = history.iter().find(|a| a.id == alert).unwrap();
        assert_eq!(ended.rule_id, None);
        assert!(database.delete_channel(channel).await.unwrap());
        let due = database.due_deliveries(started_ms + 10, 500).await.unwrap();
        assert!(!due.iter().any(|d| d.alert.id == alert));
    }

    #[tokio::test]
    async fn facts_need_a_registered_agent() {
        let database = Database::in_memory().await;
        let result = database
            .record_facts("nobody", &flat(&[("a", json!(1))]), 1)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_failed_update_leaves_the_previous_facts_in_place() {
        use sea_orm::ConnectionTrait;

        let database = Database::in_memory().await;
        database.save_agent(&record("agent-1")).await.unwrap();
        let before = flat(&[("os.version", json!("24.04"))]);
        database
            .record_facts("agent-1", &before, 100)
            .await
            .unwrap();

        // The old value is closed first, then adding the new one fails.
        database
            .connection
            .execute_unprepared(
                "CREATE TRIGGER block_new_version BEFORE INSERT ON agent_facts
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END",
            )
            .await
            .unwrap();

        let after = flat(&[("os.version", json!("24.10"))]);
        assert!(database.record_facts("agent-1", &after, 200).await.is_err());

        let facts = database.current_facts("agent-1").await.unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].value, json!("24.04"));
    }

    #[tokio::test]
    async fn concurrent_reports_never_leave_two_current_values() {
        let database = Database::in_memory().await;
        database.save_agent(&record("agent-1")).await.unwrap();

        let reports = (0..20).map(|n| {
            let database = database.clone();
            tokio::spawn(async move {
                let facts = flat(&[("os.version", json!(n))]);
                database.record_facts("agent-1", &facts, n).await.unwrap();
            })
        });
        for report in reports.collect::<Vec<_>>() {
            report.await.unwrap();
        }

        assert_eq!(database.current_facts("agent-1").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn works_on_sqlite() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/folder/agents.db");
        exercise(&format!("sqlite://{}?mode=rwc", path.display())).await;
    }

    #[tokio::test]
    #[ignore = "needs a server: set MAXNINES_TEST_POSTGRES_URL"]
    async fn works_on_postgres() {
        exercise(&std::env::var("MAXNINES_TEST_POSTGRES_URL").unwrap()).await;
    }

    #[tokio::test]
    #[ignore = "needs a server: set MAXNINES_TEST_MYSQL_URL"]
    async fn works_on_mysql() {
        exercise(&std::env::var("MAXNINES_TEST_MYSQL_URL").unwrap()).await;
    }

    #[tokio::test]
    async fn a_corrupt_state_is_an_error_not_a_guess() {
        use sea_orm::ConnectionTrait;

        let database = Database::in_memory().await;
        database
            .connection
            .execute_unprepared(
                "INSERT INTO agents (id, public_key, host, state, first_seen_ms)
                 VALUES ('a', 'b', 'c', 'trusted', 1)",
            )
            .await
            .unwrap();

        assert!(database.load_agents().await.is_err());
    }

    #[tokio::test]
    async fn an_unreachable_server_fails_without_showing_the_password() {
        let url = "postgres://user:hunter2@127.0.0.1:1/maxnines";

        let error = match Database::connect(url).await {
            Err(error) => format!("{error:#}"),
            Ok(_) => panic!("connected to nothing"),
        };

        assert!(!error.contains("hunter2"), "{error}");
    }
}
