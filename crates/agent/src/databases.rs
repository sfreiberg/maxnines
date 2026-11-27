//! The databases the agent's own config defines, which the built-in templates read,
//! as [`crate::templates`] does for every database the config defines. How each
//! kind is read is in [`maxnines_checks::templates`], which the server shares.
//!
//! A `database` block holds where a database is and how to sign in, so a login
//! never comes from the server, never goes to it, and is only ever sent to the
//! address beside it.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, anyhow, ensure};
use maxnines_checks::Credentials;
use maxnines_checks::databases::{Database, is_database};
use maxnines_protocol::{Check, CheckKind, is_page_name};
use serde::Deserialize;

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
                    "{:?} isn't a kind of database, which are postgres, mysql, mongodb, clickhouse and redis",
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

/// Checks each definition, so a mistake stops the agent starting rather than the
/// database never being read.
pub fn check_database_definitions(definitions: &mut DatabaseDefinitions) -> Result<()> {
    ensure!(
        definitions.len() <= MAX_DEFINED,
        "the config can define at most {MAX_DEFINED} databases"
    );
    for (name, definition) in definitions.iter_mut() {
        let problem = |what: &str| anyhow!("database {name:?} in the agent's config {what}");
        ensure!(is_page_name(name), problem("needs a name without spaces"));
        // An empty one, as from an environment variable that isn't set, is none, so
        // it's never sent.
        for given in [&mut definition.username, &mut definition.password] {
            if given.as_deref() == Some("") {
                *given = None;
            }
        }
        let database = definition
            .database(name)
            .map_err(|error| problem(&format!("has a problem: {error:#}")))?;
        let username = definition.username.is_some();
        // MongoDB and Redis can be read without signing in, where they allow it,
        // and Redis before 6 has a password and no usernames.
        if !matches!(database.check.kind, CheckKind::Mongodb | CheckKind::Redis) {
            ensure!(username, problem("needs a username"));
        }
        let password = definition.password.is_some();
        if let Some(why) = maxnines_checks::sign_in_problem(&database.check, username, password) {
            return Err(problem(&format!("can never be signed in to: {why}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
            let mut definitions = DatabaseDefinitions::from([(name.to_string(), definition)]);
            check_database_definitions(&mut definitions).map(|()| definitions)
        };
        one("orders", defined("postgres", "127.0.0.1:5432")).unwrap();
        one("cache", defined("mysql", "db:3306")).unwrap();
        // MongoDB can be read without signing in, where it allows that.
        let open = DatabaseDefinition {
            username: None,
            password: None,
            ..defined("mongodb", "db:27017")
        };
        one("documents", open.clone()).unwrap();
        one(
            "cache",
            DatabaseDefinition {
                kind: "redis".to_string(),
                ..open
            },
        )
        .unwrap();
        // Redis before 6, or its default user, with a password alone.
        let password_only = DatabaseDefinition {
            username: None,
            ..defined("redis", "127.0.0.1:6379")
        };
        one("sessions", password_only).unwrap();

        for (name, definition, why) in [
            ("two words", defined("postgres", "a:1"), "without spaces"),
            (
                "orders",
                defined("memcached", "a:1"),
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
            // An unset environment variable's empty username is none.
            (
                "orders",
                DatabaseDefinition {
                    username: Some(String::new()),
                    ..defined("postgres", "a:1")
                },
                "needs a username",
            ),
            // ClickHouse's password goes as it is, so only over TLS elsewhere.
            (
                "events",
                defined("clickhouse", "db.example.com:8123"),
                "TLS",
            ),
        ] {
            let error = format!("{:#}", one(name, definition).unwrap_err());
            assert!(error.contains(why), "{name}: {error}");
        }
        assert!(!format!("{:?}", defined("postgres", "a:1")).contains("s3cret"));
    }

    #[test]
    fn an_empty_password_is_none_and_clickhouse_on_its_own_host_or_over_tls_is_fine() {
        let check = |name: &str, definition: DatabaseDefinition| {
            let mut definitions = DatabaseDefinitions::from([(name.to_string(), definition)]);
            check_database_definitions(&mut definitions).unwrap();
            definitions.remove(name).unwrap()
        };
        let unset = DatabaseDefinition {
            password: Some(String::new()),
            ..defined("postgres", "db:5432")
        };
        let read = check("orders", unset).database("orders").unwrap();
        assert_eq!(read.credentials.password, None);
        check("events", defined("clickhouse", "127.0.0.1:8123"));
        let tls = DatabaseDefinition {
            tls: Some(true),
            ..defined("clickhouse", "db.example.com:8443")
        };
        check("events", tls);
    }
}
