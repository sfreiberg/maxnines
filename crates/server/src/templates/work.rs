//! What each agent is sent to read for its templates.
//!
//! For each template on and for the host, and each database it runs for there, the
//! agent is sent the template's discover blocks, and the queries that run there now:
//! those whose `since` the version found is at or past and whose `when` holds of
//! what discovery found, each with its SQL filled in for that version. A query that
//! depends on what discovery finds waits until something has been found. When what
//! discovery finds changes, so does what's sent.
//!
//! Only database templates are sent so far: performance counters and the registry,
//! which Windows templates read, aren't yet.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Map, Value};

use maxnines_protocol::templates::work::{DiscoverWork, QueryWork, TemplateWork};
use maxnines_protocol::templates::{
    DEFAULT_DISCOVERY_INTERVAL, Query, Target, Template, Version, fill, parse_duration,
};

use super::hosts::RunningTemplates;
use crate::rule_engine::{Condition, Host};

/// What discovery found on one host, by template ID and database.
pub type Discoveries = HashMap<(i64, String), Map<String, Value>>;

/// The column discovery finds a version in.
pub const VERSION: &str = "version";

/// The version discovery found, if it found one.
pub fn version_in(found: &Map<String, Value>) -> Option<Version> {
    match found.get(VERSION)? {
        Value::String(text) => Version::find(text),
        Value::Number(number) => Version::find(&number.to_string()),
        _ => None,
    }
}

/// Whether something with this `when` and `since` is for a database where
/// discovery found `found`, or nothing yet. With neither, it always is. With
/// either, it isn't until something's found.
pub fn picked(when: Option<&str>, since: Option<&str>, found: Option<&Map<String, Value>>) -> bool {
    if when.is_none() && since.is_none() {
        return true;
    }
    let Some(found) = found else {
        return false;
    };
    if let Some(since) = since {
        let (Some(at), Some(since)) = (version_in(found), Version::parse(since)) else {
            return false;
        };
        if at < since {
            return false;
        }
    }
    when.is_none_or(|when| {
        Condition::compile(when).is_ok_and(|condition| condition.check_values(found))
    })
}

fn seconds(text: Option<&String>) -> Option<Duration> {
    text.and_then(|text| parse_duration(text).ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
}

/// What the agent on this host is sent to read.
pub fn work_for(
    templates: &RunningTemplates,
    host: &Host,
    discoveries: &Discoveries,
) -> Vec<TemplateWork> {
    let mut work = Vec::new();
    for assigned in templates.for_host(host) {
        let template = assigned.template();
        if !matches!(template.target, Some(Target::Database(_))) {
            continue;
        }
        for database in assigned.instances(host.facts).into_iter().flatten() {
            let found = discoveries.get(&(assigned.id(), database.clone()));
            work.push(TemplateWork {
                template: template.key.clone(),
                discover: discover_work(template),
                queries: query_work(template, found),
                database,
            });
        }
    }
    work
}

fn discover_work(template: &Template) -> Vec<DiscoverWork> {
    template
        .discover
        .iter()
        .filter_map(|discover| {
            Some(DiscoverWork {
                key: discover.key.clone(),
                interval: seconds(discover.interval.as_ref()).unwrap_or(DEFAULT_DISCOVERY_INTERVAL),
                sql: discover.sql.clone()?,
            })
        })
        .collect()
}

/// Whether a query needs to know what discovery found before it can run.
fn needs_discovery(template: &Template, query: &Query) -> bool {
    query.when.is_some()
        || query.since.is_some()
        || !query.fills.is_empty()
        || template.min_version.is_some()
}

fn query_work(template: &Template, found: Option<&Map<String, Value>>) -> Vec<QueryWork> {
    let version = found.and_then(version_in);
    // Below the oldest version it's for, only discovery runs.
    if let (Some(oldest), Some(at)) = (
        template.min_version.as_deref().and_then(Version::parse),
        &version,
    ) && *at < oldest
    {
        return Vec::new();
    }
    template
        .queries
        .iter()
        .filter(|query| query.enabled)
        .filter(|query| !needs_discovery(template, query) || found.is_some())
        .filter(|query| picked(query.when.as_deref(), query.since.as_deref(), found))
        .map(|query| QueryWork {
            key: query.key.clone(),
            sql: fill(query, version.as_ref()),
            interval: seconds(query.interval.as_ref()),
            labels: query.labels.clone(),
            totals: query
                .metrics
                .iter()
                .filter(|metric| metric.total)
                .map(|metric| metric.key.clone())
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::templates::hosts::Running;

    fn running(text: &str) -> RunningTemplates {
        RunningTemplates::new([Running {
            id: 7,
            template: maxnines_protocol::templates::parse(text).unwrap(),
            host_ids: BTreeSet::new(),
        }])
    }

    const APP: &str = r#"
        template "pg" {
          name        = "PG"
          database    = "postgres"
          min_version = "10"
          discover "server" {
            sql = "SELECT current_setting('server_version') AS version"
          }
          discover "role" {
            interval = "10s"
            sql      = "SELECT 'primary' AS role"
          }
          query "always" {
            interval = "1m"
            sql      = "SELECT 1 AS one"
            metrics  = { one = { total = true } }
          }
          query "standbys" {
            when   = "role == 'primary'"
            labels = ["application"]
            sql    = "SELECT application_name AS application, 1 AS lag FROM pg_stat_replication"
          }
          query "wal" {
            since = "14"
            sql   = "SELECT {{ bytes }} AS wal_written"
            fill "bytes" {
              versions = { "15" = "wal_bytes FROM pg_stat_wal" }
              older    = "0"
            }
          }
        }
    "#;

    fn facts() -> Value {
        json!({ "agent": { "databases": { "orders": "postgres", "cache": "mysql" } } })
    }

    fn keys(work: &TemplateWork) -> Vec<&str> {
        work.queries
            .iter()
            .map(|query| query.key.as_str())
            .collect()
    }

    #[test]
    fn queries_wait_for_discovery_then_run_by_what_it_found() {
        let templates = running(APP);
        let facts = facts();
        let host = Host::new(&facts, "a");

        // Before discovery, only what needs nothing found runs, for each postgres
        // database, every discover block with it.
        let work = work_for(&templates, &host, &Discoveries::new());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].database, "orders");
        assert_eq!(work[0].discover.len(), 2);
        assert_eq!(work[0].discover[0].interval, DEFAULT_DISCOVERY_INTERVAL);
        assert_eq!(work[0].discover[1].interval, Duration::from_secs(10));
        assert!(keys(&work[0]).is_empty(), "the template has a min_version");

        let found = |version: &str, role: &str| {
            let values = json!({ "version": version, "role": role });
            Discoveries::from([(
                (7, "orders".to_string()),
                values.as_object().unwrap().clone(),
            )])
        };
        let work = work_for(&templates, &host, &found("16.4 (Debian 16.4-1)", "primary"));
        assert_eq!(keys(&work[0]), ["always", "standbys", "wal"]);
        assert_eq!(work[0].queries[0].interval, Some(Duration::from_secs(60)));
        assert_eq!(work[0].queries[0].totals, ["one"]);
        assert_eq!(work[0].queries[1].labels, ["application"]);
        assert_eq!(
            work[0].queries[2].sql,
            "SELECT wal_bytes FROM pg_stat_wal AS wal_written"
        );

        let work = work_for(&templates, &host, &found("14.1", "replica"));
        assert_eq!(keys(&work[0]), ["always", "wal"]);
        assert_eq!(work[0].queries[1].sql, "SELECT 0 AS wal_written");

        let work = work_for(&templates, &host, &found("13", "primary"));
        assert_eq!(keys(&work[0]), ["always", "standbys"]);

        // Too old for the template, only discovery runs.
        let work = work_for(&templates, &host, &found("9.6", "primary"));
        assert!(keys(&work[0]).is_empty());
        assert_eq!(work[0].discover.len(), 2);
    }

    #[test]
    fn a_template_thats_off_or_not_for_the_host_sends_nothing() {
        let mut off = maxnines_protocol::templates::parse(APP).unwrap();
        off.enabled = false;
        let templates = RunningTemplates::new([Running {
            id: 7,
            template: off,
            host_ids: BTreeSet::new(),
        }]);
        let facts = facts();
        assert!(work_for(&templates, &Host::new(&facts, "a"), &Discoveries::new()).is_empty());

        let elsewhere = RunningTemplates::new([Running {
            id: 7,
            template: maxnines_protocol::templates::parse(APP).unwrap(),
            host_ids: BTreeSet::from(["b".to_string()]),
        }]);
        assert!(work_for(&elsewhere, &Host::new(&facts, "a"), &Discoveries::new()).is_empty());
        assert_eq!(
            work_for(&elsewhere, &Host::new(&facts, "b"), &Discoveries::new()).len(),
            1
        );
    }
}
