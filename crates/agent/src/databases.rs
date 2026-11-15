//! The databases collector: health, load and replication read from databases
//! the agent's own config defines. How each kind is read is in
//! [`maxnines_checks::databases`], which the server shares.
//!
//! A `database` block holds where a database is and how to sign in, and a config
//! rule picks which to read by name, and what extras to read from each. So a
//! login never comes from the server, never goes to it, and is only ever sent to
//! the address beside it.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use futures_util::future::join_all;
use maxnines_checks::Credentials;
use maxnines_checks::databases::{Database, Reader, Settle, TIMEOUT, is_database};
use maxnines_protocol::{Check, CheckKind, DatabaseChoice, is_page_name};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::background::Background;
use crate::collector::Collector;

/// How many databases the agent's config can define.
const MAX_DEFINED: usize = 64;

/// A database the agent's config allows to be read, with how to sign in:
///
/// ```hcl
/// database "orders" {
///   kind     = "postgres"
///   target   = "127.0.0.1:5432"
///   username = "maxnines"
///   password = env("ORDERS_DB_PASSWORD")
/// }
/// ```
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseDefinition {
    kind: String,
    target: String,
    /// PostgreSQL: the database to sign in to. MongoDB: the one the account
    /// belongs to.
    #[serde(default)]
    database: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    insecure: Option<bool>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

impl fmt::Debug for DatabaseDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseDefinition")
            .field("kind", &self.kind)
            .field("target", &self.target)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl DatabaseDefinition {
    fn database(&self, name: &str) -> Result<Database> {
        let kind = CheckKind::parse(&self.kind)
            .filter(|kind| is_database(*kind))
            .with_context(|| {
                format!(
                    "{:?} isn't a kind of database, which are postgres, mysql and mongodb",
                    self.kind
                )
            })?;
        let mut check = Check::new(name, kind, &self.target);
        check.database = self.database.clone();
        check.tls = self.tls;
        check.insecure = self.insecure;
        check.validate()?;
        Ok(Database {
            check,
            credentials: Credentials {
                username: self.username.clone(),
                password: self.password.clone(),
                private_key: None,
            },
        })
    }
}

/// The databases the agent's config allows, by name.
pub type DatabaseDefinitions = BTreeMap<String, DatabaseDefinition>;

pub fn check_database_definitions(definitions: &DatabaseDefinitions) -> Result<()> {
    ensure!(
        definitions.len() <= MAX_DEFINED,
        "the config can define at most {MAX_DEFINED} databases"
    );
    for (name, definition) in definitions {
        let problem = |what: &str| anyhow!("database {name:?} in agent.hcl {what}");
        ensure!(is_page_name(name), problem("needs a name without spaces"));
        let database = definition
            .database(name)
            .map_err(|error| problem(&format!("has a problem: {error:#}")))?;
        if database.check.kind != CheckKind::Mongodb {
            ensure!(
                definition
                    .username
                    .as_deref()
                    .is_some_and(|username| !username.is_empty()),
                problem("needs a username")
            );
        }
    }
    Ok(())
}

pub struct DatabaseCollector {
    background: Background,
    settle: Settle,
    /// Databases a rule asked for that the agent's config doesn't have, which
    /// say so with every sample.
    missing: Vec<Value>,
}

impl DatabaseCollector {
    pub fn new(
        chosen: &[DatabaseChoice],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Self {
        let mut readers = Vec::new();
        let mut missing = Vec::new();
        for choice in chosen {
            let name = &choice.name;
            let found = definitions
                .get(name)
                .context("agent.hcl has no database by that name")
                .and_then(|definition| definition.database(name));
            match found {
                Ok(database) => readers.push(Reader::new(name, database, &choice.extras)),
                Err(error) => missing.push(json!({
                    "name": name,
                    "up": 0,
                    "error": format!("{error:#}"),
                })),
            }
        }
        // Rounds never overlap, so each reader keeps its connection between them.
        let readers = Arc::new(Mutex::new(readers));
        let limit = interval.min(TIMEOUT);
        let background = Background::start(interval, move || {
            let readers = readers.clone();
            async move {
                let mut readers = readers.lock().await;
                let reads = readers.iter_mut().map(|reader| reader.read(limit));
                let rows: Vec<Vec<Value>> = join_all(reads).await;
                Value::Array(rows.into_iter().flatten().collect())
            }
        });
        Self {
            background,
            settle: Settle::default(),
            missing,
        }
    }
}

impl Collector for DatabaseCollector {
    fn name(&self) -> &'static str {
        "databases"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(match self.background.latest() {
            Value::Array(rows) => {
                let mut rows = self.settle.settle(rows);
                rows.extend(self.missing.iter().cloned());
                Value::Array(rows)
            }
            // The first round hasn't finished.
            waiting => waiting,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Instant;

    use super::*;

    fn defined(kind: &str, target: &str) -> DatabaseDefinition {
        DatabaseDefinition {
            kind: kind.to_string(),
            target: target.to_string(),
            database: None,
            tls: None,
            insecure: None,
            username: Some("maxnines".to_string()),
            password: Some("s3cret".to_string()),
        }
    }

    #[test]
    fn a_defined_database_has_a_kind_an_address_and_someone_to_sign_in_as() {
        let one = |name: &str, definition: DatabaseDefinition| {
            check_database_definitions(&DatabaseDefinitions::from([(name.to_string(), definition)]))
        };
        one("orders", defined("postgres", "127.0.0.1:5432")).unwrap();
        one("cache", defined("mysql", "db:3306")).unwrap();
        // MongoDB can be read without signing in, where it allows that.
        let open = DatabaseDefinition {
            username: None,
            password: None,
            ..defined("mongodb", "db:27017")
        };
        one("documents", open).unwrap();

        for (name, definition, why) in [
            ("two words", defined("postgres", "a:1"), "without spaces"),
            (
                "orders",
                defined("redis", "a:1"),
                "isn't a kind of database",
            ),
            ("orders", defined("postgres", "nowhere"), "host:port"),
            (
                "orders",
                DatabaseDefinition {
                    username: None,
                    ..defined("postgres", "a:1")
                },
                "needs a username",
            ),
            (
                "orders",
                DatabaseDefinition {
                    tls: Some(true),
                    ..defined("postgres", "a:1")
                },
                "can't use tls",
            ),
        ] {
            let error = format!("{:#}", one(name, definition).unwrap_err());
            assert!(error.contains(why), "{name}: {error}");
        }
        assert!(!format!("{:?}", defined("postgres", "a:1")).contains("s3cret"));
    }

    #[test]
    fn a_rule_reads_the_databases_the_config_defines_and_only_those() {
        let definitions =
            DatabaseDefinitions::from([("orders".to_string(), defined("postgres", "127.0.0.1:0"))]);
        let chosen = [
            DatabaseChoice {
                name: "orders".to_string(),
                extras: Vec::new(),
            },
            DatabaseChoice {
                name: "nowhere".to_string(),
                extras: Vec::new(),
            },
        ];
        let mut collector =
            DatabaseCollector::new(&chosen, &definitions, Duration::from_millis(100));
        let deadline = Instant::now() + Duration::from_secs(10);
        let output = loop {
            let output = collector.collect().unwrap();
            if output.is_array() {
                break output;
            }
            assert!(Instant::now() < deadline, "no rows");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(output[0]["name"], "orders");
        assert_eq!(output[0]["up"], 0, "{output}");
        assert_eq!(
            output[1],
            json!({ "name": "nowhere", "up": 0, "error": "agent.hcl has no database by that name" })
        );
    }
}
