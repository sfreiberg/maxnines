//! The databases collector: health, load and replication read from databases
//! the agent's own config defines. How each kind is read is in
//! [`maxnines_checks::databases`], which the server shares. A kind that's read only
//! by templates, such as PostgreSQL, is left to them, as [`crate::templates`] reads
//! every database the config defines whether a rule picks it or not.
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
use maxnines_checks::Credentials;
use maxnines_checks::databases::{
    Database, Reader, Settle, TIMEOUT, by_kind, has_reader, is_database,
};
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
    /// What kind of database it says it is, such as `postgres`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn database(&self, name: &str) -> Result<Database> {
        let kind = CheckKind::parse(&self.kind)
            .filter(|kind| is_database(*kind))
            .with_context(|| {
                format!(
                    "{:?} isn't a kind of database, which are postgres, mysql, mongodb and clickhouse",
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
        let problem = |what: &str| anyhow!("database {name:?} in the agent's config {what}");
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
}

impl DatabaseCollector {
    pub fn new(
        chosen: &[DatabaseChoice],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Result<Self> {
        let mut background = Background::new();
        let limit = interval.min(TIMEOUT);
        for choice in chosen {
            let name = &choice.name;
            // Templates read it, and nothing here can.
            let templates_only = definitions
                .get(name)
                .and_then(|definition| CheckKind::parse(&definition.kind))
                .is_some_and(|kind| is_database(kind) && !has_reader(kind));
            if templates_only {
                continue;
            }
            let found = definitions
                .get(name)
                .context("the agent's config has no database by that name")
                .and_then(|definition| definition.database(name));
            match found {
                Ok(database) => {
                    // Rounds never overlap, so it keeps its connection between them.
                    let reader = Arc::new(Mutex::new(Reader::new(name, database, &choice.extras)));
                    // Its running totals become changes as it's read.
                    let mut settle = Settle::default();
                    background.repeat(
                        interval,
                        None,
                        move || {
                            let reader = reader.clone();
                            async move { reader.lock().await.read(limit).await }
                        },
                        move |rows| Value::Array(settle.settle(rows.unwrap_or_default())),
                    )?;
                }
                Err(error) => {
                    // Under its kind, if it says a real one.
                    let kind = definitions
                        .get(name)
                        .and_then(|definition| CheckKind::parse(&definition.kind))
                        .filter(|kind| is_database(*kind))
                        .map(CheckKind::as_str);
                    // Says so with every sample.
                    background.constant(json!({
                        "name": name,
                        "kind": kind,
                        "up": 0,
                        "error": format!("{error:#}"),
                    }));
                }
            }
        }
        Ok(Self { background })
    }
}

impl Collector for DatabaseCollector {
    fn name(&self) -> &'static str {
        "databases"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(match self.background.rows() {
            Value::Array(rows) => by_kind(rows),
            // Nothing has been read yet.
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
                    database: Some("sales".to_string()),
                    ..defined("mysql", "a:1")
                },
                "can't use database",
            ),
        ] {
            let error = format!("{:#}", one(name, definition).unwrap_err());
            assert!(error.contains(why), "{name}: {error}");
        }
        assert!(!format!("{:?}", defined("postgres", "a:1")).contains("s3cret"));
    }

    #[test]
    fn a_rule_reads_the_databases_the_config_defines_and_only_those() {
        let definitions = DatabaseDefinitions::from([
            ("orders".to_string(), defined("mongodb", "127.0.0.1:0")),
            ("ledger".to_string(), defined("postgres", "127.0.0.1:0")),
            ("shop".to_string(), defined("mysql", "127.0.0.1:0")),
        ]);
        let chosen = ["orders", "ledger", "shop", "nowhere"].map(|name| DatabaseChoice {
            name: name.to_string(),
            extras: Vec::new(),
        });
        let mut collector =
            DatabaseCollector::new(&chosen, &definitions, Duration::from_millis(100)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let output = loop {
            let output = collector.collect().unwrap();
            if output["mongodb"].is_array() {
                break output;
            }
            assert!(Instant::now() < deadline, "no rows");
            thread::sleep(Duration::from_millis(10));
        };
        // Each under its kind, so its values are its kind's own.
        assert_eq!(output["mongodb"][0]["name"], "orders");
        assert_eq!(output["mongodb"][0]["up"], 0, "{output}");
        assert_eq!(
            output["unknown"][0],
            json!({ "name": "nowhere", "up": 0, "error": "the agent's config has no database by that name" })
        );
        // PostgreSQL and MySQL are their templates' to read.
        assert!(output.get("postgres").is_none(), "{output}");
        assert!(output.get("mysql").is_none(), "{output}");
    }
}
