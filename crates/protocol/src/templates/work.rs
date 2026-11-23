//! What the server has an agent read for its templates, worked out for that host:
//! for each database a template runs for, the SQL of its discover blocks and of the
//! queries that run there now, and for a template that runs once on a Windows host,
//! the registry values and counter sets its discover blocks look for and the
//! performance counters it reads now. The server has already picked queries and
//! counters by version and by what discovery found, and filled in each piece of SQL
//! picked by version, so an agent runs only what it's sent, with no CEL and no
//! templates of its own.
//!
//! What an agent reads goes back in its samples: the rows of each template under
//! `template.<key>`, labelled with the database they're from, if any, what discovery
//! found under [`DISCOVERED`], and what the account each database is read with may
//! do beyond reading under [`ACCOUNTS`].

use std::collections::BTreeMap;
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
/// The collector a sample has what each database's account may do beyond reading
/// under: one item for each database a template reads, with its `name` and a 1 or 0
/// for each of `overprivileged`, `superuser`, `writes`, `manages` and
/// `server_files`.
pub const ACCOUNTS: &str = "database_accounts";
/// What each of a template's rows says it's from: the key of the query or counters
/// block. It can't be a metric's, as a key starts with a letter, and the server takes
/// it out before the rows are stored.
pub const QUERY_FIELD: &str = "_query";
/// The collector a template's samples are under, which no collector an agent has
/// built in can be called, as a key has no dot.
pub fn collector_of(key: &str) -> String {
    format!("template.{key}")
}

/// The most instances of a counter set one counters block reads, as each becomes
/// series on the server.
pub const MAX_INSTANCES: usize = 256;
/// The most registry values or counter sets one discover block looks for.
pub const MAX_LOOKED_FOR: usize = 64;

/// Whether a discover block looks for more than an agent takes, from how many values
/// it reads from each registry key and how many counter sets it looks for.
pub fn looks_for_too_much(
    registry_values: impl IntoIterator<Item = usize>,
    counter_sets: usize,
) -> bool {
    registry_values.into_iter().sum::<usize>() + counter_sets > MAX_LOOKED_FOR
}

/// One template, run for one database in the agent's own config, or once on the
/// host for a template that isn't for a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateWork {
    /// The template's key.
    pub template: String,
    /// The database, by its name in the agent's own config, for a template that's
    /// for a kind of database. Only those run SQL; the others read Windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discover: Vec<DiscoverWork>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<QueryWork>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counters: Vec<CountersWork>,
}

/// One discover block. For a database, its SQL's first row's columns are what it
/// finds. On the host, it's registry values and whether counter sets are there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverWork {
    pub key: String,
    #[serde(rename = "interval_secs", with = "time::seconds")]
    pub interval: Duration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry: Vec<RegistryWork>,
    /// Whether the host has each counter set, by the name it's found as.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counter_sets: BTreeMap<String, String>,
}

/// Values read from one registry key, such as `HKLM\SOFTWARE\Microsoft\InetStp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryWork {
    pub key: String,
    /// Each value's name in the registry, by the name it's found as.
    pub values: BTreeMap<String, String>,
}

/// One counters block, as it reads now: a counter set's counters, each instance
/// labelled by its name, a pattern, a counter or another counter set's instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountersWork {
    pub key: String,
    /// The counter set, by its English name, such as `Web Service`.
    pub object: String,
    /// Which of its instances are read, and how each is labelled.
    pub instances: Instances,
    /// Instances left out, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// Labels whose values are read from a counter of the same instance, such as
    /// `pid` from `ID Process`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinWork>,
    /// How often it's read, if less often than every sample.
    #[serde(
        rename = "interval_secs",
        with = "time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub interval: Option<Duration>,
    pub metrics: Vec<CounterWork>,
}

/// Which instances of a counter set are read, and how each is labelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Instances {
    /// A counter set with no instances, read as it is.
    None,
    /// Only this one, unlabelled.
    One(String),
    /// Every one but `_Total`, labelled with its name under this label.
    Labelled(String),
    /// Every one but `_Total` that this regular expression matches, labelled by its
    /// named groups.
    Pattern(String),
}

/// Another counter set whose instances label these: those matching `pattern` are
/// matched to these by the groups both have, and its other groups become labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinWork {
    pub object: String,
    pub pattern: String,
}

/// One metric of a counters block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterWork {
    pub key: String,
    /// The counter, by its English name, such as `Current Connections`.
    pub counter: String,
    /// A running total, sent as the change since the last read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub total: bool,
    /// Instances with the same labels take the highest, as a percentage does,
    /// rather than adding up.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub highest: bool,
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

/// What one discovery found for one database, or on the host, as a sample sends it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Discovered {
    pub template: String,
    /// The database, for a template that's for a kind of database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// What every discover block found, by name.
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
            !work[..index]
                .iter()
                .any(|other| other.template == one.template && other.database == one.database),
            "template {:?} is sent twice for {:?}",
            one.template,
            one.database
        );
        ensure!(
            one.discover.len() + one.queries.len() + one.counters.len() <= MAX_STATEMENTS,
            "template {:?} has more than {MAX_STATEMENTS} discover blocks, queries and counters",
            one.template
        );
        let on_database = one.database.is_some();
        ensure!(
            on_database || one.queries.is_empty(),
            "template {:?} has SQL but no database to run it on",
            one.template
        );
        ensure!(
            !on_database || one.counters.is_empty(),
            "template {:?} reads counters for a database, which are the host's",
            one.template
        );
        for discover in &one.discover {
            check_key(&discover.key)?;
            check_interval(&discover.key, Some(discover.interval))?;
            match (&discover.sql, on_database) {
                (Some(sql), true) => check_sql(&discover.key, sql)?,
                (None, false) => {}
                (Some(_), false) => {
                    anyhow::bail!("{:?} has SQL but no database to run it on", discover.key)
                }
                (None, true) => anyhow::bail!("{:?} needs SQL to run", discover.key),
            }
            ensure!(
                !on_database || discover.registry.is_empty() && discover.counter_sets.is_empty(),
                "{:?} looks at the host for a database",
                discover.key
            );
            let too_much = looks_for_too_much(
                discover.registry.iter().map(|read| read.values.len()),
                discover.counter_sets.len(),
            );
            ensure!(
                !too_much,
                "{:?} looks for more than {MAX_LOOKED_FOR} things",
                discover.key
            );
            for name in discover
                .registry
                .iter()
                .flat_map(|read| read.values.keys())
                .chain(discover.counter_sets.keys())
            {
                check_key(name)?;
            }
        }
        for query in &one.queries {
            check_key(&query.key)?;
            check_interval(&query.key, query.interval)?;
            check_sql(&query.key, &query.sql)?;
            ensure!(
                query.labels.len() <= MAX_COLUMNS
                    && query.totals.len() <= MAX_COLUMNS
                    && query.omit.len() <= MAX_COLUMNS,
                "query {:?} has too many labels or totals",
                query.key
            );
        }
        for counters in &one.counters {
            check_counters(counters)?;
        }
    }
    Ok(())
}

fn check_key(key: &str) -> Result<()> {
    ensure!(is_key(key), "{key:?} isn't a key");
    Ok(())
}

fn check_interval(key: &str, interval: Option<Duration>) -> Result<()> {
    if let Some(interval) = interval {
        ensure!(
            (Duration::from_secs(1)..=crate::MAX_INTERVAL).contains(&interval),
            "{key:?} needs an interval from 1 second to a day"
        );
    }
    Ok(())
}

fn check_sql(key: &str, sql: &str) -> Result<()> {
    ensure!(
        !sql.trim().is_empty() && sql.len() <= MAX_SQL_LEN,
        "{key:?} needs SQL of up to {MAX_SQL_LEN} bytes"
    );
    Ok(())
}

fn check_counters(counters: &CountersWork) -> Result<()> {
    let key = &counters.key;
    check_key(key)?;
    check_interval(key, counters.interval)?;
    let name = |text: &str| !text.trim().is_empty() && text.len() <= 255;
    ensure!(name(&counters.object), "{key:?} needs a counter set");
    ensure!(
        !counters.metrics.is_empty() && counters.metrics.len() <= MAX_COLUMNS,
        "{key:?} needs from 1 to {MAX_COLUMNS} metrics"
    );
    ensure!(
        counters.exclude.len() <= MAX_INSTANCES && counters.groups.len() <= MAX_COLUMNS,
        "{key:?} leaves out or groups too many"
    );
    for metric in &counters.metrics {
        check_key(&metric.key)?;
        ensure!(name(&metric.counter), "{:?} needs a counter", metric.key);
    }
    for (group, counter) in &counters.groups {
        check_key(group)?;
        ensure!(name(counter), "{group:?} needs a counter");
    }
    match &counters.instances {
        Instances::None => {}
        Instances::One(instance) => ensure!(name(instance), "{key:?} needs an instance"),
        Instances::Labelled(label) => check_key(label)?,
        Instances::Pattern(pattern) => {
            super::named_groups(pattern).map_err(|error| anyhow::anyhow!("{key:?} {error}"))?;
        }
    }
    if let Some(join) = &counters.join {
        ensure!(name(&join.object), "{key:?} needs a counter set to join");
        super::named_groups(&join.pattern).map_err(|error| anyhow::anyhow!("{key:?} {error}"))?;
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
                sql: Some("SELECT 'primary' AS role".to_string()),
                registry: Vec::new(),
                counter_sets: BTreeMap::new(),
            }],
            queries: vec![QueryWork {
                key: "sessions".to_string(),
                sql: "SELECT count(*) AS connections FROM pg_stat_activity".to_string(),
                interval: None,
                labels: Vec::new(),
                totals: Vec::new(),
                omit: Vec::new(),
            }],
            counters: Vec::new(),
        }
    }

    fn host_work() -> TemplateWork {
        TemplateWork {
            template: "iis".to_string(),
            database: None,
            discover: vec![DiscoverWork {
                key: "iis".to_string(),
                interval: Duration::from_secs(3600),
                sql: None,
                registry: vec![RegistryWork {
                    key: r"HKLM\SOFTWARE\Microsoft\InetStp".to_string(),
                    values: BTreeMap::from([("version".to_string(), "VersionString".to_string())]),
                }],
                counter_sets: BTreeMap::from([("asp_net".to_string(), "ASP.NET".to_string())]),
            }],
            queries: Vec::new(),
            counters: vec![CountersWork {
                key: "workers".to_string(),
                object: "W3SVC_W3WP".to_string(),
                instances: Instances::Pattern(r"^\d+_(?<pool>.+)$".to_string()),
                exclude: Vec::new(),
                groups: BTreeMap::new(),
                join: None,
                interval: None,
                metrics: vec![CounterWork {
                    key: "active_requests".to_string(),
                    counter: "Active Requests".to_string(),
                    total: false,
                    highest: false,
                }],
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

        let sent = serde_json::to_value([host_work()]).unwrap();
        assert_eq!(
            sent[0]["counters"][0]["instances"],
            serde_json::json!({ "pattern": r"^\d+_(?<pool>.+)$" })
        );
        let read: Vec<TemplateWork> = serde_json::from_value(sent).unwrap();
        assert_eq!(read, [host_work()]);
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
        assert!(refused(&|all| all[0].queries[0].sql = " ".into()).contains("needs SQL"));
        assert!(refused(&|all| all[0].discover[0].interval = Duration::ZERO).contains("interval"));
        assert!(refused(&|all| all[0].discover[0].sql = None).contains("needs SQL"));
        assert!(
            refused(&|all| all[0].counters = host_work().counters).contains("which are the host's")
        );

        // One that isn't for a database runs once on the host, and has no SQL.
        let refused = |change: &dyn Fn(&mut TemplateWork)| {
            let mut one = host_work();
            change(&mut one);
            check_work(&[one]).unwrap_err().to_string()
        };
        assert!(
            refused(&|one| one.discover[0].sql = Some("SELECT 1".into()))
                .contains("no database to run it on")
        );
        assert!(
            refused(&|one| one.counters[0].instances = Instances::Pattern("(".into()))
                .contains("isn't a regular expression")
        );
        assert!(refused(&|one| one.counters[0].metrics.clear()).contains("metrics"));
        assert!(
            refused(&|one| one.counters[0].instances = Instances::Labelled("Bad".into()))
                .contains("isn't a key")
        );
    }
}
