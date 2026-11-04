//! Everything the server keeps except metrics, in SQLite, Postgres or MySQL.
//! The URL picks the database, and SeaORM handles the differences between them.

mod agent;
mod agent_fact;
mod migration;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use sea_orm::sea_query::Expr;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, ConnectOptions, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::facts::{FlatFacts, decode, encode};
use crate::registration::{AgentRecord, AgentState};
use migration::Migrator;

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
            .execute_unprepared("DELETE FROM agent_facts")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM agents")
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

    fn sorted(mut records: Vec<AgentRecord>) -> Vec<AgentRecord> {
        records.sort_by(|a, b| a.id.cmp(&b.id));
        records
    }

    /// Everything each database has to get right. It runs against SQLite
    /// always, and against real servers with `cargo test -- --ignored`.
    async fn exercise(url: &str) {
        let database = Database::connect(url).await.unwrap();
        database.clear_for_test().await;
        assert!(database.load_agents().await.unwrap().is_empty());

        // Creating.
        let pending = record("agent-1");
        database.save_agent(&pending).await.unwrap();
        assert_eq!(database.load_agents().await.unwrap(), vec![pending.clone()]);

        // Saving identical data, which MySQL reports as zero rows changed.
        database.save_agent(&pending).await.unwrap();
        assert_eq!(database.load_agents().await.unwrap(), vec![pending.clone()]);

        // Replacing, including going from NULL to a value.
        let approved = AgentRecord {
            state: AgentState::Approved,
            decided_by: Some("rule:production-subnet".to_string()),
            decided_at_ms: Some(1_789_000_000_456),
            ..pending.clone()
        };
        database.save_agent(&approved).await.unwrap();
        assert_eq!(
            database.load_agents().await.unwrap(),
            vec![approved.clone()]
        );

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
            sorted(database.load_agents().await.unwrap()),
            [approved.clone(), unusual.clone(), unicode.clone()]
        );

        exercise_facts(&database, &approved.id, &unusual.id).await;

        // A second connection sees it all, and migrating again changes nothing.
        let reopened = Database::connect(url).await.unwrap();
        assert_eq!(
            sorted(reopened.load_agents().await.unwrap()),
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
