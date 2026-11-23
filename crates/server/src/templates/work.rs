//! What each agent is sent to read for its templates.
//!
//! For each template on and for the host, and each database it runs for there, the
//! agent is sent the template's discover blocks, and the queries that run there now:
//! those whose `since` the version found is at or past and whose `when` holds of
//! what discovery found, each with its SQL filled in for that version. A query that
//! depends on what discovery finds waits until something has been found. When what
//! discovery finds changes, so does what's sent.
//!
//! A template that isn't for a database is sent once for the host, if it reads
//! anything there. What those read is performance counters and the registry, which
//! aren't sent yet, so agents have nothing to run for them so far. Templates for a
//! Windows service aren't sent until then either.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use serde_json::{Map, Value};

use maxnines_protocol::templates::work::{DiscoverWork, MAX_WORK, QueryWork, TemplateWork};
use maxnines_protocol::templates::{
    DEFAULT_DISCOVERY_INTERVAL, Query, Target, Template, Version, fill, parse_duration,
};
use tracing::warn;

use super::hosts::{DatabaseKinds, RunningTemplates};
use crate::metrics::{INSTANCE_LABEL, series_values};
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
    let when = when.map(Condition::compile);
    picked_by(when.as_ref(), since, found)
}

/// [`picked`], with `when` compiled, or not, as it may not compile.
fn picked_by(
    when: Option<&anyhow::Result<Condition>>,
    since: Option<&str>,
    found: Option<&Map<String, Value>>,
) -> bool {
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
        when.as_ref()
            .is_ok_and(|condition| condition.check_values(found))
    })
}

/// The hosts and databases where what a template's discovery found fits a `when`
/// and `since`, as `(host ID, database)`, from what was found on every host.
pub fn picked_databases(
    template_id: i64,
    when: Option<&str>,
    since: Option<&str>,
    found: &BTreeMap<String, Discoveries>,
) -> HashSet<(String, String)> {
    // Compiled once, however many databases it's tried on.
    let when = when.map(Condition::compile);
    let mut picked = HashSet::new();
    for (host, discoveries) in found {
        for ((template, database), values) in discoveries {
            if *template == template_id && picked_by(when.as_ref(), since, Some(values)) {
                picked.insert((host.clone(), database.clone()));
            }
        }
    }
    picked
}

/// Keeps only the series of the databases picked on a host, for a rule whose series
/// have a label for the database. `labels` are the series' labels, in order.
pub fn keep_picked(
    series: &mut Vec<String>,
    labels: &[String],
    host_id: &str,
    picked: &HashSet<(String, String)>,
) {
    let Some(at) = labels.iter().position(|label| label == INSTANCE_LABEL) else {
        return;
    };
    series.retain(|series| {
        series_values(series)
            .get(at)
            .is_some_and(|database| picked.contains(&(host_id.to_string(), database.clone())))
    });
}

fn seconds(text: Option<&String>) -> Option<Duration> {
    text.and_then(|text| parse_duration(text).ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
}

/// What's read for templates on this host, of its `databases`: what its agent is
/// sent, or what the server reads itself for a host with no agent.
pub fn work_for(
    templates: &RunningTemplates,
    host: &Host,
    databases: &DatabaseKinds,
    discoveries: &Discoveries,
) -> Vec<TemplateWork> {
    let mut work = Vec::new();
    for assigned in templates.for_host(host) {
        let template = assigned.template();
        match &template.target {
            Some(Target::Database(_)) => {
                let instances = assigned.instances(host.facts, databases);
                for database in instances.into_iter().flatten() {
                    let found = discoveries.get(&(assigned.id(), database.clone()));
                    work.push(TemplateWork {
                        template: template.key.clone(),
                        discover: discover_work(template),
                        queries: query_work(template, found),
                        database: Some(database),
                    });
                }
            }
            // Counters and the registry are for the Windows services' templates,
            // which agents don't read yet.
            Some(Target::Service(_)) => {}
            // Once on the host, for what it reads there, which is only counters and
            // the registry so far, as SQL needs a database: a template with nothing
            // for the agent to read isn't sent.
            Some(Target::Os(_)) | None => {
                let reads_something =
                    !template.discover.is_empty() || !template.counters.is_empty();
                if reads_something && !assigned.instances(host.facts, databases).is_empty() {
                    work.push(TemplateWork {
                        template: template.key.clone(),
                        database: None,
                        discover: Vec::new(),
                        queries: Vec::new(),
                    });
                }
            }
        }
    }
    // An agent takes so much at once, so the rest isn't sent rather than all of it
    // being refused.
    if work.len() > MAX_WORK {
        warn!(
            host = host.id,
            templates = work.len(),
            "a host has more templates to run than an agent takes, sending the first {MAX_WORK}"
        );
        work.truncate(MAX_WORK);
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
        || query.metrics.iter().any(|metric| metric.since.is_some())
}

/// A query's metrics that are only from a version later than the one found, or
/// from one when none was found.
fn omitted(query: &Query, version: Option<&Version>) -> Vec<String> {
    query
        .metrics
        .iter()
        .filter(|metric| {
            metric
                .since
                .as_deref()
                .is_some_and(|since| match (version, Version::parse(since)) {
                    (Some(at), Some(since)) => *at < since,
                    _ => true,
                })
        })
        .map(|metric| metric.key.clone())
        .collect()
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
            omit: omitted(query, version.as_ref()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::templates::hosts::Running;
    use crate::templates::hosts::agent_databases;

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
            metrics  = { one = { total = true }, two = { since = "15" } }
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

    /// What the agent on a host is sent, of the databases its facts say it has.
    fn work_of(
        templates: &RunningTemplates,
        host: &Host,
        discoveries: &Discoveries,
    ) -> Vec<TemplateWork> {
        work_for(templates, host, &agent_databases(host.facts), discoveries)
    }

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
        let work = work_of(&templates, &host, &Discoveries::new());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].database.as_deref(), Some("orders"));
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
        let work = work_of(&templates, &host, &found("16.4 (Debian 16.4-1)", "primary"));
        assert_eq!(keys(&work[0]), ["always", "standbys", "wal"]);
        assert_eq!(work[0].queries[0].interval, Some(Duration::from_secs(60)));
        assert_eq!(work[0].queries[0].totals, ["one"]);
        assert!(work[0].queries[0].omit.is_empty());
        assert_eq!(work[0].queries[1].labels, ["application"]);
        assert_eq!(
            work[0].queries[2].sql,
            "SELECT wal_bytes FROM pg_stat_wal AS wal_written"
        );

        let work = work_of(&templates, &host, &found("14.1", "replica"));
        assert_eq!(keys(&work[0]), ["always", "wal"]);
        // A metric only from a later version is left out.
        assert_eq!(work[0].queries[0].omit, ["two"]);
        assert_eq!(work[0].queries[1].sql, "SELECT 0 AS wal_written");

        let work = work_of(&templates, &host, &found("13", "primary"));
        assert_eq!(keys(&work[0]), ["always", "standbys"]);

        // Too old for the template, only discovery runs.
        let work = work_of(&templates, &host, &found("9.6", "primary"));
        assert!(keys(&work[0]).is_empty());
        assert_eq!(work[0].discover.len(), 2);
    }

    #[test]
    fn a_template_not_for_a_database_is_sent_once_if_it_reads_anything() {
        let os = |reads: &str| {
            running(&format!(
                r#"template "win" {{
                     name = "Win"
                     os   = ["windows"]
                     {reads}
                   }}"#
            ))
        };
        let windows = json!({ "os": { "family": "windows" } });
        let linux = json!({ "os": { "family": "linux" } });
        let counters = r#"counters "cpu" {
                            object  = "Processor"
                            metrics = { busy = "% Processor Time" }
                          }"#;
        let work = work_of(
            &os(counters),
            &Host::new(&windows, "a"),
            &Discoveries::new(),
        );
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].database, None);
        assert!(work[0].queries.is_empty() && work[0].discover.is_empty());
        // Not on the systems it's for, or with nothing to read.
        assert!(work_of(&os(counters), &Host::new(&linux, "a"), &Discoveries::new()).is_empty());
        assert!(work_of(&os(""), &Host::new(&windows, "a"), &Discoveries::new()).is_empty());
    }

    #[test]
    fn a_host_is_sent_no_more_than_an_agent_takes() {
        let templates = running(APP);
        let databases: Map<String, Value> = (0..=MAX_WORK)
            .map(|number| (format!("db{number}"), json!("postgres")))
            .chain([("two words".to_string(), json!("postgres"))])
            .collect();
        let facts = json!({ "agent": { "databases": databases } });
        let work = work_of(&templates, &Host::new(&facts, "a"), &Discoveries::new());
        assert_eq!(work.len(), MAX_WORK);
        assert!(
            work.iter()
                .all(|one| one.database.as_deref() != Some("two words"))
        );
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
        assert!(work_of(&templates, &Host::new(&facts, "a"), &Discoveries::new()).is_empty());

        let elsewhere = RunningTemplates::new([Running {
            id: 7,
            template: maxnines_protocol::templates::parse(APP).unwrap(),
            host_ids: BTreeSet::from(["b".to_string()]),
        }]);
        assert!(work_of(&elsewhere, &Host::new(&facts, "a"), &Discoveries::new()).is_empty());
        assert_eq!(
            work_of(&elsewhere, &Host::new(&facts, "b"), &Discoveries::new()).len(),
            1
        );
    }
}
