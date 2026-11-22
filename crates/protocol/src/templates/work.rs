//! What the server has an agent read for its templates, worked out for that host:
//! for each database a template runs for, the SQL of its discover blocks and of the
//! queries that run there now. The server has already picked queries by version and
//! by what discovery found, and filled in each piece of SQL picked by version, so
//! an agent runs only what it's sent, with no CEL and no templates of its own.
//!
//! What an agent reads goes back in its samples: the rows of each template under
//! `template.<key>`, labelled with the database they're from, and what discovery
//! found under [`DISCOVERED`].

use std::time::Duration;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::is_key;
use crate::time;

/// The most templates one agent is sent, counting each database one runs for.
pub const MAX_WORK: usize = 64;
/// The most discover blocks and queries in one.
pub const MAX_STATEMENTS: usize = 64;
/// The longest a piece of SQL can be.
pub const MAX_SQL_LEN: usize = 64 * 1024;
/// The most labels or running totals a query has.
pub const MAX_COLUMNS: usize = 256;
/// What a sample calls what discovery found.
pub const DISCOVERED: &str = "discovered";
/// What each of a template's rows says it's from: the query's key. It can't be a
/// metric's, as a key starts with a letter, and the server takes it out before the
/// rows are stored.
pub const QUERY_FIELD: &str = "_query";
/// The collector a template's samples are under, which no collector an agent has
/// built in can be called, as a key has no dot.
pub fn collector_of(key: &str) -> String {
    format!("template.{key}")
}

/// One template, run for one database in the agent's own config, or once on the
/// host for a template that isn't for a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateWork {
    /// The template's key.
    pub template: String,
    /// The database, by its name in the agent's own config, for a template that's
    /// for a kind of database. Only those run SQL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discover: Vec<DiscoverWork>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<QueryWork>,
}

/// One discover block: its first row's columns are what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverWork {
    pub key: String,
    #[serde(rename = "interval_secs", with = "time::seconds")]
    pub interval: Duration,
    pub sql: String,
}

/// One query, its SQL filled in for the version found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryWork {
    pub key: String,
    pub sql: String,
    /// How often it runs, if less often than every sample.
    #[serde(
        rename = "interval_secs",
        with = "time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub interval: Option<Duration>,
    /// The columns that tell rows apart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// The columns that are running totals, sent as the change since the last read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub totals: Vec<String>,
    /// The columns left out, as they're metrics only from a later version than the
    /// one found.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omit: Vec<String>,
}

/// What one discovery found for one database, as a sample sends it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Discovered {
    pub template: String,
    pub database: String,
    /// What every discover block found, by column.
    pub values: serde_json::Map<String, serde_json::Value>,
}

/// Refuses work no server would send, before an agent runs any of it.
pub fn check_work(work: &[TemplateWork]) -> Result<()> {
    ensure!(
        work.len() <= MAX_WORK,
        "an agent can be sent at most {MAX_WORK} templates to run"
    );
    for (index, one) in work.iter().enumerate() {
        ensure!(
            is_key(&one.template),
            "{:?} isn't a template's key",
            one.template
        );
        if let Some(database) = &one.database {
            ensure!(
                crate::is_page_name(database),
                "{database:?} isn't a database's name"
            );
        }
        ensure!(
            one.database.is_some() || one.discover.is_empty() && one.queries.is_empty(),
            "template {:?} has SQL but no database to run it on",
            one.template
        );
        ensure!(
            !work[..index]
                .iter()
                .any(|other| other.template == one.template && other.database == one.database),
            "template {:?} is sent twice for {:?}",
            one.template,
            one.database
        );
        ensure!(
            one.discover.len() + one.queries.len() <= MAX_STATEMENTS,
            "template {:?} has more than {MAX_STATEMENTS} discover blocks and queries",
            one.template
        );
        let intervals = one
            .discover
            .iter()
            .map(|discover| (&discover.key, &discover.sql, Some(discover.interval)))
            .chain(
                one.queries
                    .iter()
                    .map(|query| (&query.key, &query.sql, query.interval)),
            );
        for (key, sql, interval) in intervals {
            ensure!(is_key(key), "{key:?} isn't a key");
            ensure!(
                !sql.trim().is_empty() && sql.len() <= MAX_SQL_LEN,
                "{key:?} needs SQL of up to {MAX_SQL_LEN} bytes"
            );
            if let Some(interval) = interval {
                ensure!(
                    (Duration::from_secs(1)..=crate::MAX_INTERVAL).contains(&interval),
                    "{key:?} needs an interval from 1 second to a day"
                );
            }
        }
        for query in &one.queries {
            ensure!(
                query.labels.len() <= MAX_COLUMNS
                    && query.totals.len() <= MAX_COLUMNS
                    && query.omit.len() <= MAX_COLUMNS,
                "query {:?} has too many labels or totals",
                query.key
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work() -> TemplateWork {
        TemplateWork {
            template: "pg".to_string(),
            database: Some("orders".to_string()),
            discover: vec![DiscoverWork {
                key: "role".to_string(),
                interval: Duration::from_secs(10),
                sql: "SELECT 'primary' AS role".to_string(),
            }],
            queries: vec![QueryWork {
                key: "sessions".to_string(),
                sql: "SELECT count(*) AS connections FROM pg_stat_activity".to_string(),
                interval: None,
                labels: Vec::new(),
                totals: Vec::new(),
                omit: Vec::new(),
            }],
        }
    }

    #[test]
    fn work_reads_back_as_sent() {
        let sent = serde_json::to_value([work()]).unwrap();
        assert_eq!(sent[0]["discover"][0]["interval_secs"], 10);
        let read: Vec<TemplateWork> = serde_json::from_value(sent).unwrap();
        assert_eq!(read, [work()]);
        check_work(&read).unwrap();
    }

    #[test]
    fn work_no_server_sends_is_refused() {
        let refused = |change: &dyn Fn(&mut Vec<TemplateWork>)| {
            let mut all = vec![work()];
            change(&mut all);
            check_work(&all).unwrap_err().to_string()
        };
        assert!(refused(&|all| all.push(work())).contains("sent twice"));
        assert!(refused(&|all| all[0].template = "Bad".into()).contains("isn't a template's key"));
        assert!(refused(&|all| all[0].database = Some("two words".into())).contains("database"));
        assert!(refused(&|all| all[0].database = None).contains("no database to run it on"));
        // One that isn't for a database runs once on the host.
        let host_wide = TemplateWork {
            template: "host".to_string(),
            database: None,
            discover: Vec::new(),
            queries: Vec::new(),
        };
        check_work(&[host_wide]).unwrap();
        assert!(refused(&|all| all[0].queries[0].sql = " ".into()).contains("needs SQL"));
        assert!(refused(&|all| all[0].discover[0].interval = Duration::ZERO).contains("interval"));
    }
}
