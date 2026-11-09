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
mod api_key;
mod config_rule;
mod config_rule_setting;
mod dashboard;
mod dashboard_widget;
mod dashboards;
mod location_rule;
mod location_rules;
mod maintenance_window;
mod maintenance_windows;
mod notification;
mod notification_channel;
mod remote_check;
mod remote_checks;
mod server_secret;
mod silence;
mod silences;
mod stats;
mod user;
mod user_session;
mod users;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use maxnines_protocol::auth::new_nonce;
use sea_orm::sea_query::Expr;
use sea_orm::sea_query::OnConflict;
use sea_orm::sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectOptions, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

pub use self::stats::DatabaseStats;
pub use self::users::{
    DEFAULT_THEME, SESSION_LIFETIME_MS, THEMES, User, UserChange, check_new_password,
    check_new_user, is_theme,
};
use crate::facts::{FlatFacts, decode, encode, flatten, unflatten};
use crate::host_filter;
use crate::migrations::Migrator;
use crate::registration::hash_token;
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
        // The default journal waits on the disk several times for every write, which
        // a fleet reporting at once can't get through on a slow disk. In this mode a
        // power cut can lose the last few writes, but can't damage the database.
        if is_sqlite {
            options.map_sqlx_sqlite_opts(|sqlite| {
                sqlite
                    .journal_mode(SqliteJournalMode::Wal)
                    .synchronous(SqliteSynchronous::Normal)
            });
        }

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

    /// Deletes an agent and everything kept about it: its facts, what it said about
    /// its config, its alerts with their notifications, and a place on the map made
    /// for it alone. All or nothing. Returns false if there was no such agent.
    pub async fn delete_agent(&self, id: &str) -> Result<bool> {
        let _only_writer = self.facts_lock.lock().await;
        let transaction = self.connection.begin().await.context("deleting an agent")?;
        // Their notifications go with them.
        alert::Entity::delete_many()
            .filter(alert::Column::AgentId.eq(id))
            .exec(&transaction)
            .await
            .context("deleting an agent's alerts")?;
        agent_fact::Entity::delete_many()
            .filter(agent_fact::Column::AgentId.eq(id))
            .exec(&transaction)
            .await
            .context("deleting an agent's facts")?;
        agent_config_status::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting an agent's config status")?;
        location_rule::Entity::delete_many()
            .filter(location_rule::Column::Filter.eq(host_filter::only(id)))
            .exec(&transaction)
            .await
            .context("deleting an agent's place on the map")?;
        let deleted = agent::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting an agent")?;
        transaction.commit().await.context("deleting an agent")?;
        Ok(deleted.rows_affected > 0)
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
        by_agent(rows)
    }

    /// The current facts of some agents, for when a page only shows those.
    pub async fn facts_of(&self, agent_ids: &[&str]) -> Result<BTreeMap<String, FlatFacts>> {
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::ValidToMs.is_null())
            .filter(agent_fact::Column::AgentId.is_in(agent_ids.iter().copied()))
            .all(&self.connection)
            .await
            .context("loading facts")?;
        by_agent(rows)
    }

    /// Every agent's current values of some facts, including the items of lists.
    pub async fn facts_named(&self, names: &[&str]) -> Result<BTreeMap<String, FlatFacts>> {
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::ValidToMs.is_null())
            .filter(fact_or_its_items(names))
            .all(&self.connection)
            .await
            .context("loading facts")?;
        by_agent(rows)
    }

    /// The names facts are reported under, with a list appearing under its own name.
    pub async fn fact_names(&self) -> Result<Vec<String>> {
        let names: Vec<String> = agent_fact::Entity::find()
            .select_only()
            .column(agent_fact::Column::Name)
            .distinct()
            .filter(agent_fact::Column::ValidToMs.is_null())
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading fact names")?;
        let names: BTreeSet<String> = names.into_iter().filter_map(simple_fact_name).collect();
        Ok(names.into_iter().collect())
    }

    /// Different values a fact has containing some text, in order.
    pub async fn fact_values(&self, name: &str, text: &str, limit: u64) -> Result<Vec<String>> {
        agent_fact::Entity::find()
            .select_only()
            .column(agent_fact::Column::Value)
            .distinct()
            .filter(agent_fact::Column::ValidToMs.is_null())
            .filter(fact_or_its_items(&[name]))
            .filter(agent_fact::Column::Value.contains(text))
            .order_by_asc(agent_fact::Column::Value)
            .limit(limit)
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading fact values")
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
            if let Some(name) = simple_fact_name(row.name) {
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

/// What the database column holds.
const MAX_API_KEY_NAME_LEN: usize = 100;
/// How much of a key is kept to tell it apart, which is `mxn_` and 8 of its 64 digits.
const API_KEY_HINT_LEN: usize = 12;
/// How current "last used" stays, so using a key doesn't write on every request.
const API_KEY_USE_ACCURACY_MS: i64 = 60_000;

/// A key for the API, without the key itself, which only exists when it's created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub hint: String,
    pub created_ms: i64,
    /// Empty means it never expires.
    pub expires_ms: Option<i64>,
    pub last_used_ms: Option<i64>,
    pub revoked_ms: Option<i64>,
}

impl ApiKey {
    pub fn has_expired(&self, now_ms: i64) -> bool {
        self.expires_ms.is_some_and(|expires| now_ms >= expires)
    }
}

impl From<api_key::Model> for ApiKey {
    fn from(row: api_key::Model) -> Self {
        Self {
            id: row.id,
            name: row.name,
            hint: row.hint,
            created_ms: row.created_ms,
            expires_ms: row.expires_ms,
            last_used_ms: row.last_used_ms,
            revoked_ms: row.revoked_ms,
        }
    }
}

pub fn check_api_key_name(name: &str) -> Result<()> {
    anyhow::ensure!(!name.trim().is_empty(), "A key needs a name.");
    anyhow::ensure!(
        name.len() <= MAX_API_KEY_NAME_LEN,
        "A key's name can be up to {MAX_API_KEY_NAME_LEN} characters."
    );
    Ok(())
}

/// When a key lasting this long from now runs out.
pub fn expiry_after(secs: u64, now_ms: i64) -> Result<i64> {
    anyhow::ensure!(secs > 0, "A key has to last longer than that.");
    i64::try_from(secs)
        .ok()
        .and_then(|secs| secs.checked_mul(1000))
        .and_then(|ms| now_ms.checked_add(ms))
        .context("That's too long for a key to last. Leave it out for a key that never expires.")
}

fn api_key_hash(key: &str) -> String {
    hex::encode(hash_token(key))
}

impl Database {
    /// The token that protects the admin API, created the first time it's asked
    /// for. Two servers starting at once can't end up with different tokens, as
    /// only the first insert counts and both read the result.
    /// Makes a key, and gives back the only copy of it there'll ever be.
    pub async fn create_api_key(
        &self,
        name: &str,
        expires_ms: Option<i64>,
        now_ms: i64,
    ) -> Result<(ApiKey, String)> {
        let key = format!("mxn_{}", new_nonce()?);
        let row = api_key::ActiveModel {
            name: Set(name.to_string()),
            hint: Set(key[..API_KEY_HINT_LEN].to_string()),
            token_hash: Set(api_key_hash(&key)),
            created_ms: Set(now_ms),
            expires_ms: Set(expires_ms),
            ..Default::default()
        }
        .insert(&self.connection)
        .await
        .context("saving an API key")?;
        Ok((row.into(), key))
    }

    /// Every key, newest first, including revoked ones.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        let rows = api_key::Entity::find()
            .order_by_desc(api_key::Column::Id)
            .all(&self.connection)
            .await
            .context("loading API keys")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Stops a key working. Returns false if there's no such key.
    pub async fn revoke_api_key(&self, id: i64, now_ms: i64) -> Result<bool> {
        let Some(row) = api_key::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading an API key")?
        else {
            return Ok(false);
        };
        if row.revoked_ms.is_none() {
            let mut row: api_key::ActiveModel = row.into();
            row.revoked_ms = Set(Some(now_ms));
            row.update(&self.connection)
                .await
                .context("revoking an API key")?;
        }
        Ok(true)
    }

    /// Whether this is a key that still works, noting that it's been used.
    pub async fn accept_api_key(&self, key: &str, now_ms: i64) -> Result<bool> {
        let row = api_key::Entity::find()
            .filter(api_key::Column::TokenHash.eq(api_key_hash(key)))
            .filter(api_key::Column::RevokedMs.is_null())
            .one(&self.connection)
            .await
            .context("checking an API key")?;
        let Some(row) = row.filter(|row| row.expires_ms.is_none_or(|expires| now_ms < expires))
        else {
            return Ok(false);
        };
        let stale = row
            .last_used_ms
            .is_none_or(|used| now_ms - used >= API_KEY_USE_ACCURACY_MS);
        if stale {
            let mut row: api_key::ActiveModel = row.into();
            row.last_used_ms = Set(Some(now_ms));
            row.update(&self.connection)
                .await
                .context("noting an API key's use")?;
        }
        Ok(true)
    }

    /// A secret the server made for itself, created the first time it's asked for.
    /// Two servers starting on one database get the same one.
    pub async fn server_secret(&self, name: &str) -> Result<String> {
        let saved = server_secret::Entity::find_by_id(name)
            .one(&self.connection)
            .await
            .with_context(|| format!("reading the {name}"))?;
        if let Some(saved) = saved {
            return Ok(saved.value);
        }

        let row = server_secret::ActiveModel {
            name: Set(name.to_string()),
            value: Set(new_nonce()?),
        };
        server_secret::Entity::insert(row)
            .on_conflict_do_nothing_on([server_secret::Column::Name])
            .exec_without_returning(&self.connection)
            .await
            .with_context(|| format!("saving the {name}"))?;

        let saved = server_secret::Entity::find_by_id(name)
            .one(&self.connection)
            .await
            .with_context(|| format!("reading the {name}"))?;
        Ok(saved
            .with_context(|| format!("the {name} wasn't saved"))?
            .value)
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

/// A list's own name for an item of it. Items inside lists of maps can't be reached
/// by a simple name, so they have none.
fn simple_fact_name(name: String) -> Option<String> {
    let name = match name.strip_suffix(']').and_then(|n| n.rsplit_once('[')) {
        Some((list, _)) => list.to_string(),
        None => name,
    };
    (!name.contains('[')).then_some(name)
}

fn fact_or_its_items(names: &[&str]) -> Condition {
    names.iter().fold(Condition::any(), |wanted, name| {
        wanted
            .add(agent_fact::Column::Name.eq(*name))
            .add(agent_fact::Column::Name.starts_with(format!("{name}[")))
    })
}

fn by_agent(rows: Vec<agent_fact::Model>) -> Result<BTreeMap<String, FlatFacts>> {
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
async fn hold_all<DB: sea_orm::sqlx::Database>(
    pool: &sea_orm::sqlx::Pool<DB>,
) -> Vec<sea_orm::sqlx::pool::PoolConnection<DB>> {
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.unwrap());
    }
    held
}

/// Makes a new database on a test server, and returns the URL to reach it.
#[cfg(test)]
async fn fresh_test_database(server: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};

    use sea_orm::ConnectionTrait;

    static MADE: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "maxnines_test_{}_{}",
        std::process::id(),
        MADE.fetch_add(1, Ordering::Relaxed)
    );
    let connection = sea_orm::Database::connect(server).await.unwrap();
    connection
        .execute_unprepared(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    connection.close().await.unwrap();
    let (host, _) = server.rsplit_once('/').unwrap();
    format!("{host}/{name}")
}

#[cfg(test)]
impl Database {
    /// An empty database of its own. SQLite in memory, unless `MAXNINES_TEST_DATABASE_URL`
    /// names a Postgres or MySQL server to run the tests against instead.
    pub async fn for_test() -> Self {
        let url = match std::env::var("MAXNINES_TEST_DATABASE_URL") {
            Ok(server) => fresh_test_database(&server).await,
            Err(_) => "sqlite::memory:".to_string(),
        };
        Self::connect(&url).await.unwrap()
    }

    /// Takes every connection, so that queries wait until it's dropped, as they do on a
    /// database that's stalled.
    pub async fn stall_for_test(&self) -> Box<dyn std::any::Any + Send> {
        use sea_orm::DatabaseBackend;
        match self.connection.get_database_backend() {
            DatabaseBackend::Postgres => {
                Box::new(hold_all(self.connection.get_postgres_connection_pool()).await)
            }
            DatabaseBackend::MySql => {
                Box::new(hold_all(self.connection.get_mysql_connection_pool()).await)
            }
            _ => Box::new(hold_all(self.connection.get_sqlite_connection_pool()).await),
        }
    }

    /// Makes every later query about agents fail, while signing in still works.
    pub async fn break_for_test(&self) {
        use sea_orm::ConnectionTrait;
        for table in ["agent_config_status", "agent_facts", "agents"] {
            self.connection
                .execute_unprepared(&format!("ALTER TABLE {table} RENAME TO {table}_gone"))
                .await
                .unwrap();
        }
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
    async fn an_api_key_works_until_it_is_revoked() {
        let database = Database::for_test().await;
        let (key, secret) = database.create_api_key("backup", None, 1000).await.unwrap();

        assert!(database.accept_api_key(&secret, 2000).await.unwrap());
        assert!(database.revoke_api_key(key.id, 3000).await.unwrap());
        assert!(!database.accept_api_key(&secret, 4000).await.unwrap());
    }

    #[tokio::test]
    async fn only_a_real_key_is_accepted() {
        let database = Database::for_test().await;
        database.create_api_key("backup", None, 1000).await.unwrap();

        assert!(!database.accept_api_key("mxn_guess", 2000).await.unwrap());
        assert!(!database.accept_api_key("", 2000).await.unwrap());
    }

    #[tokio::test]
    async fn the_key_itself_is_never_stored() {
        let database = Database::for_test().await;
        let (_, secret) = database.create_api_key("backup", None, 1000).await.unwrap();

        let rows = api_key::Entity::find()
            .all(&database.connection)
            .await
            .unwrap();

        assert_ne!(rows[0].token_hash, secret);
        assert!(!format!("{rows:?}").contains(&secret));
        assert!(secret.starts_with(&rows[0].hint));
        assert!(rows[0].hint.len() < secret.len() / 4);
    }

    #[tokio::test]
    async fn each_key_is_different() {
        let database = Database::for_test().await;
        let (_, first) = database.create_api_key("a", None, 1).await.unwrap();
        let (_, second) = database.create_api_key("a", None, 1).await.unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn using_a_key_is_noted_without_writing_every_time() {
        let database = Database::for_test().await;
        let (_, secret) = database.create_api_key("backup", None, 0).await.unwrap();
        let used = async || database.list_api_keys().await.unwrap()[0].last_used_ms;
        assert_eq!(used().await, None);

        database.accept_api_key(&secret, 100_000).await.unwrap();
        assert_eq!(used().await, Some(100_000));

        database.accept_api_key(&secret, 100_500).await.unwrap();
        assert_eq!(used().await, Some(100_000));

        database.accept_api_key(&secret, 170_000).await.unwrap();
        assert_eq!(used().await, Some(170_000));
    }

    #[tokio::test]
    async fn revoking_twice_keeps_the_first_time() {
        let database = Database::for_test().await;
        let (key, _) = database.create_api_key("backup", None, 0).await.unwrap();

        database.revoke_api_key(key.id, 100).await.unwrap();
        database.revoke_api_key(key.id, 200).await.unwrap();

        let keys = database.list_api_keys().await.unwrap();
        assert_eq!(keys[0].revoked_ms, Some(100));
        assert!(!database.revoke_api_key(999, 300).await.unwrap());
    }

    #[tokio::test]
    async fn a_key_stops_working_when_it_expires() {
        let database = Database::for_test().await;
        let (key, secret) = database
            .create_api_key("deploy", Some(5000), 1000)
            .await
            .unwrap();

        assert!(database.accept_api_key(&secret, 4999).await.unwrap());
        assert!(!database.accept_api_key(&secret, 5000).await.unwrap());
        assert!(!database.accept_api_key(&secret, 9000).await.unwrap());
        assert!(!key.has_expired(4999));
        assert!(key.has_expired(5000));
    }

    #[tokio::test]
    async fn a_key_with_no_expiry_lasts() {
        let database = Database::for_test().await;
        let (key, secret) = database.create_api_key("a", None, 0).await.unwrap();

        assert!(database.accept_api_key(&secret, i64::MAX).await.unwrap());
        assert!(!key.has_expired(i64::MAX));
    }

    #[test]
    fn expiry_is_counted_from_now() {
        assert_eq!(expiry_after(60, 1000).unwrap(), 61_000);
        assert!(expiry_after(0, 1000).is_err());
        assert!(expiry_after(u64::MAX, 1000).is_err());
    }

    #[test]
    fn keys_need_a_sensible_name() {
        assert!(check_api_key_name("backup").is_ok());
        assert!(check_api_key_name("  ").is_err());
        assert!(check_api_key_name(&"x".repeat(101)).is_err());
    }

    #[tokio::test]
    async fn sqlite_does_not_wait_on_the_disk_for_every_write() {
        let folder = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}/app.db?mode=rwc", folder.path().display());
        let database = Database::connect(&url).await.unwrap();

        let pragma = async |name: &str| {
            let statement = sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                format!("PRAGMA {name}"),
            );
            let row = database.connection.query_one_raw(statement).await.unwrap();
            row.unwrap()
        };

        let mode: String = pragma("journal_mode")
            .await
            .try_get("", "journal_mode")
            .unwrap();
        let synchronous: i32 = pragma("synchronous")
            .await
            .try_get("", "synchronous")
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(synchronous, 1, "NORMAL");
    }

    #[tokio::test]
    async fn a_server_secret_survives_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}?mode=rwc", folder.path().join("db").display());

        let first = Database::connect(&url).await.unwrap();
        let secret = first.server_secret("csrf_key").await.unwrap();
        drop(first);

        let reopened = Database::connect(&url).await.unwrap();
        assert_eq!(reopened.server_secret("csrf_key").await.unwrap(), secret);
        assert_ne!(reopened.server_secret("csrf_salt").await.unwrap(), secret);
    }

    #[tokio::test]
    async fn each_database_gets_its_own_secrets() {
        let first = Database::for_test()
            .await
            .server_secret("csrf_key")
            .await
            .unwrap();
        let second = Database::for_test()
            .await
            .server_secret("csrf_key")
            .await
            .unwrap();
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
        let database = Database::for_test().await;
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

        let secret = database.server_secret("csrf_key").await.unwrap();
        assert!(secret.len() >= 32);
        assert_eq!(database.server_secret("csrf_key").await.unwrap(), secret);

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
                app_token: None,
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
            calculation: None,
            group_by: None,
            filter: None,
            window_secs: None,
            remind_every_secs: None,
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
        assert!(
            database
                .delete_alert_rule(rule, started_ms + 20)
                .await
                .unwrap()
        );
        let history = database.resolved_alerts(10).await.unwrap();
        let ended = history.iter().find(|a| a.id == alert).unwrap();
        assert_eq!(ended.rule_id, None);
        assert!(database.delete_channel(channel).await.unwrap());
        let due = database.due_deliveries(started_ms + 10, 500).await.unwrap();
        assert!(!due.iter().any(|d| d.alert.id == alert));
    }

    #[tokio::test]
    async fn facts_need_a_registered_agent() {
        let database = Database::for_test().await;
        let result = database
            .record_facts("nobody", &flat(&[("a", json!(1))]), 1)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_failed_update_leaves_the_previous_facts_in_place() {
        use sea_orm::ConnectionTrait;

        let database = Database::for_test().await;
        database.save_agent(&record("agent-1")).await.unwrap();
        let before = flat(&[("os.version", json!("24.04"))]);
        database
            .record_facts("agent-1", &before, 100)
            .await
            .unwrap();

        // The old value is closed first, then adding the new one fails.
        let trigger = match database.connection.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => {
                "CREATE FUNCTION block_new_version() RETURNS trigger AS
                 $$ BEGIN RAISE EXCEPTION 'blocked'; END $$ LANGUAGE plpgsql;
                 CREATE TRIGGER block_new_version BEFORE INSERT ON agent_facts
                 FOR EACH ROW EXECUTE FUNCTION block_new_version()"
            }
            sea_orm::DatabaseBackend::MySql => {
                "CREATE TRIGGER block_new_version BEFORE INSERT ON agent_facts
                 FOR EACH ROW SIGNAL SQLSTATE '45000'"
            }
            _ => {
                "CREATE TRIGGER block_new_version BEFORE INSERT ON agent_facts
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END"
            }
        };
        database
            .connection
            .execute_unprepared(trigger)
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
        let database = Database::for_test().await;
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

        let database = Database::for_test().await;
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
    async fn every_migration_can_be_undone_and_applied_again() {
        let database = Database::for_test().await;
        let connection = &database.connection;
        let count = u32::try_from(Migrator::migrations().len()).unwrap();

        for _ in 0..count {
            Migrator::down(connection, Some(1)).await.unwrap();
            Migrator::up(connection, Some(1)).await.unwrap();
        }
        Migrator::down(connection, None).await.unwrap();
        assert!(
            Migrator::get_applied_migrations(connection)
                .await
                .unwrap()
                .is_empty()
        );

        Migrator::up(connection, None).await.unwrap();
        let agents = database.load_agents().await.unwrap();
        assert_eq!(agents.len(), 2, "both built-in agents are back: {agents:?}");
    }

    #[tokio::test]
    async fn starting_again_changes_nothing_and_keeps_what_was_saved() {
        let database = Database::for_test().await;
        database.save_agent(&record("agent-1")).await.unwrap();

        Migrator::up(&database.connection, None).await.unwrap();

        let agents = database.load_agents().await.unwrap();
        assert!(agents.iter().any(|agent| agent.id == "agent-1"));
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
