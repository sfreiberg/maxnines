//! What each agent is sent to read for its templates.
//!
//! For each template on and for the host, and each database it runs for there, the
//! agent is sent the template's discover blocks, and the queries that run there now:
//! those whose `since` the version found is at or past and whose `when` holds of
//! what discovery found, each with its SQL filled in for that version. A query that
//! depends on what discovery finds waits until something has been found. When what
//! discovery finds changes, so does what's sent.
//!
//! A template that isn't for a database runs once on the host, and only on Windows,
//! as what it reads is the registry and performance counters: its discover blocks,
//! and its counters blocks picked the same way as queries are.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use serde_json::{Map, Value};

use maxnines_protocol::templates::work::{
    CounterWork, CountersWork, DiscoverWork, Discovered, Instances, JoinWork, MAX_WORK, QueryWork,
    RegistryWork, TemplateErrors, TemplateWork,
};
use maxnines_protocol::templates::{
    Counters, DEFAULT_DISCOVERY_INTERVAL, Metric, Query, Target, Template, Version, fill,
    parse_duration,
};
use tracing::warn;

use super::hosts::{Assigned, DatabaseKinds, RunningTemplates};
use crate::metrics::{INSTANCE_LABEL, series_values};
use crate::models::Database;
use crate::rule_engine::{Condition, Host};

/// What discovery found on one host, by template ID and database, or [`ON_HOST`]
/// for a template that runs once on the host.
pub type Discoveries = HashMap<(i64, String), Map<String, Value>>;

/// What stands for the database of a template that isn't for one, where what its
/// discovery found is kept. No database can be called it, as a name has letters.
pub const ON_HOST: &str = "";

/// Where what's found is kept for a template run for `database`, or on the host.
pub fn instance_of(database: Option<&str>) -> String {
    database.unwrap_or(ON_HOST).to_string()
}

/// Keeps only what discovery found for what's read, by `work`, as a sample can come
/// after what's read changed.
pub fn keep_read(found: &mut Vec<Discovered>, work: &[TemplateWork]) {
    found.retain(|one| is_read(work, &one.template, one.database.as_ref()));
}

/// Keeps only what's said to be going wrong for what's read, by `work`, as
/// [`keep_read`] does what discovery found.
pub fn keep_read_errors(said: &mut Vec<TemplateErrors>, work: &[TemplateWork]) {
    said.retain(|one| is_read(work, &one.template, one.database.as_ref()));
}

fn is_read(work: &[TemplateWork], template: &str, database: Option<&String>) -> bool {
    work.iter()
        .any(|read| read.template == template && read.database.as_ref() == database)
}

/// Forgets what discovery found on a host, and what's going wrong reading it, for
/// anything not in `work`, what the host reads now.
pub async fn forget_unread(database: &Database, host_id: &str, work: &[TemplateWork]) {
    let reads: Vec<(String, String)> = work
        .iter()
        .map(|one| (one.template.clone(), instance_of(one.database.as_deref())))
        .collect();
    if let Err(error) = database.forget_discovered(host_id, &reads).await {
        warn!(
            host_id,
            error = format!("{error:#}"),
            "forgetting what discovery found failed"
        );
    }
    if let Err(error) = database.forget_template_errors(host_id, &reads).await {
        warn!(
            host_id,
            error = format!("{error:#}"),
            "forgetting what's going wrong reading templates failed"
        );
    }
}

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

/// Keeps only the series of what's picked on a host. For a template that runs for
/// each database, `per_database`, that's the series of the databases picked, for a
/// rule whose series have a label for the database, or all of them if any database
/// on the host is picked, for one whose don't. For a template that runs on the host,
/// it's all of them or none, as the host is picked. `labels` are the series' labels,
/// in order.
pub fn keep_picked(
    series: &mut Vec<String>,
    labels: &[String],
    host_id: &str,
    picked: &HashSet<(String, String)>,
    per_database: bool,
) {
    let at = labels.iter().position(|label| label == INSTANCE_LABEL);
    let host_picked = match (per_database, at) {
        (true, Some(at)) => {
            series.retain(|series| {
                series_values(series).get(at).is_some_and(|database| {
                    picked.contains(&(host_id.to_string(), database.clone()))
                })
            });
            return;
        }
        (true, None) => picked.iter().any(|(host, _)| host == host_id),
        (false, _) => picked.contains(&(host_id.to_string(), ON_HOST.to_string())),
    };
    if !host_picked {
        series.clear();
    }
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
        work.extend(assigned_work(assigned, host, databases, discoveries));
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

/// What's read for one template, on and for this host, of its `databases`.
pub fn assigned_work(
    assigned: &Assigned,
    host: &Host,
    databases: &DatabaseKinds,
    discoveries: &Discoveries,
) -> Vec<TemplateWork> {
    let template = assigned.template();
    match &template.target {
        Some(Target::Database(_)) => assigned
            .instances(host.facts, databases)
            .into_iter()
            .flatten()
            .map(|database| {
                let found = discoveries.get(&(assigned.id(), database.clone()));
                database_work(template, &database, found)
            })
            .collect(),
        // Once on the host, for what it reads there, which is the registry and
        // performance counters, as SQL needs a database: only on Windows, and a
        // template with nothing for the agent to read there isn't sent.
        Some(Target::Service(_) | Target::Os(_)) | None => {
            let windows = host.facts["os"]["family"].as_str() == Some("windows");
            if !windows || assigned.instances(host.facts, databases).is_empty() {
                return Vec::new();
            }
            let found = discoveries.get(&(assigned.id(), ON_HOST.to_string()));
            let one = host_work(template, found);
            match one.discover.is_empty() && one.counters.is_empty() {
                true => Vec::new(),
                false => vec![one],
            }
        }
    }
}

/// What's read of one database for a template for its kind, where discovery found
/// `found` there, or nothing yet.
pub fn database_work(
    template: &Template,
    database: &str,
    found: Option<&Map<String, Value>>,
) -> TemplateWork {
    TemplateWork {
        template: template.key.clone(),
        database: Some(database.to_string()),
        discover: discover_work(template),
        queries: query_work(template, found),
        counters: Vec::new(),
    }
}

/// What's read on a Windows host for a template that runs once there, where
/// discovery found `found`, or nothing yet: its registry values and counter sets
/// to look for, and the counters blocks that read now.
pub fn host_work(template: &Template, found: Option<&Map<String, Value>>) -> TemplateWork {
    let discover = template
        .discover
        .iter()
        .filter(|discover| !discover.registry.is_empty() || !discover.counter_sets.is_empty())
        .map(|discover| DiscoverWork {
            key: discover.key.clone(),
            interval: discover_interval(discover.interval.as_ref()),
            sql: None,
            registry: discover
                .registry
                .iter()
                .map(|read| RegistryWork {
                    key: read.key.clone(),
                    values: read.values.clone().into_iter().collect(),
                })
                .collect(),
            counter_sets: discover.counter_sets.clone().into_iter().collect(),
        })
        .collect();
    TemplateWork {
        template: template.key.clone(),
        database: None,
        discover,
        queries: Vec::new(),
        counters: counters_work(template, found),
    }
}

fn discover_interval(interval: Option<&String>) -> Duration {
    seconds(interval).unwrap_or(DEFAULT_DISCOVERY_INTERVAL)
}

fn discover_work(template: &Template) -> Vec<DiscoverWork> {
    template
        .discover
        .iter()
        .filter_map(|discover| {
            Some(DiscoverWork {
                key: discover.key.clone(),
                interval: discover_interval(discover.interval.as_ref()),
                sql: Some(discover.sql.clone()?),
                registry: Vec::new(),
                counter_sets: BTreeMap::new(),
            })
        })
        .collect()
}

/// Whether a query or counters block needs to know what discovery found before it
/// can run, by its `when`, its `since`, its metrics' or the template's version.
fn needs_discovery(
    template: &Template,
    when: Option<&String>,
    since: Option<&String>,
    metrics: &[Metric],
) -> bool {
    when.is_some()
        || since.is_some()
        || template.min_version.is_some()
        || metrics.iter().any(|metric| metric.since.is_some())
}

/// Whether a metric is only from a version later than the one found, or from one
/// when none was found.
fn too_new(metric: &Metric, version: Option<&Version>) -> bool {
    metric
        .since
        .as_deref()
        .is_some_and(|since| match (version, Version::parse(since)) {
            (Some(at), Some(since)) => *at < since,
            _ => true,
        })
}

/// A query's metrics that are only from a version later than the one found, or
/// from one when none was found.
fn omitted(query: &Query, version: Option<&Version>) -> Vec<String> {
    query
        .metrics
        .iter()
        .filter(|metric| too_new(metric, version))
        .map(|metric| metric.key.clone())
        .collect()
}

/// Whether the template is for a version older than the one found, so only its
/// discovery runs.
fn below_min_version(template: &Template, version: Option<&Version>) -> bool {
    matches!(
        (template.min_version.as_deref().and_then(Version::parse), version),
        (Some(oldest), Some(at)) if *at < oldest
    )
}

fn query_work(template: &Template, found: Option<&Map<String, Value>>) -> Vec<QueryWork> {
    let version = found.and_then(version_in);
    if below_min_version(template, version.as_ref()) {
        return Vec::new();
    }
    template
        .queries
        .iter()
        .filter(|query| query.enabled)
        .filter(|query| {
            let needs = needs_discovery(
                template,
                query.when.as_ref(),
                query.since.as_ref(),
                &query.metrics,
            );
            !(needs || !query.fills.is_empty()) || found.is_some()
        })
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

/// A template's counters blocks that read now, picked as queries are, each with
/// only the metrics for the version found.
fn counters_work(template: &Template, found: Option<&Map<String, Value>>) -> Vec<CountersWork> {
    let version = found.and_then(version_in);
    if below_min_version(template, version.as_ref()) {
        return Vec::new();
    }
    template
        .counters
        .iter()
        .filter(|counters| counters.enabled)
        .filter(|counters| {
            let needs = needs_discovery(
                template,
                counters.when.as_ref(),
                counters.since.as_ref(),
                &counters.metrics,
            );
            !needs || found.is_some()
        })
        .filter(|counters| picked(counters.when.as_deref(), counters.since.as_deref(), found))
        .filter_map(|counters| {
            let metrics: Vec<CounterWork> = counters
                .metrics
                .iter()
                .filter(|metric| !too_new(metric, version.as_ref()))
                .filter_map(|metric| {
                    let counter = metric.counter.clone()?;
                    Some(CounterWork {
                        key: metric.key.clone(),
                        // A percentage of several instances is the highest of them.
                        highest: counter.trim_start().starts_with('%')
                            || metric.unit.as_deref() == Some("%"),
                        counter,
                        total: metric.total,
                    })
                })
                .collect();
            if metrics.is_empty() {
                return None;
            }
            Some(CountersWork {
                key: counters.key.clone(),
                object: counters.object.clone(),
                instances: instances_of(counters),
                exclude: counters.exclude.clone(),
                groups: counters.groups.clone().into_iter().collect(),
                join: counters.join.as_ref().map(|join| JoinWork {
                    object: join.object.clone(),
                    pattern: join.pattern.clone(),
                }),
                interval: seconds(counters.interval.as_ref()),
                metrics,
            })
        })
        .collect()
}

/// Which of a counter set's instances a counters block reads.
fn instances_of(counters: &Counters) -> Instances {
    match (&counters.label, &counters.pattern, &counters.instance) {
        (Some(label), _, _) => Instances::Labelled(label.clone()),
        (_, Some(pattern), _) => Instances::Pattern(pattern.clone()),
        (_, _, Some(instance)) => Instances::One(instance.clone()),
        // Joined by groups read from counters alone, it reads every instance.
        _ if counters.join.is_some() => Instances::Pattern(String::new()),
        _ => Instances::None,
    }
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
    fn a_template_not_for_a_database_is_sent_once_to_a_windows_host_if_it_reads_anything() {
        let os = |reads: &str| {
            running(&format!(
                r#"template "win" {{
                     name = "Win"
                     os   = ["windows", "linux"]
                     {reads}
                   }}"#
            ))
        };
        let windows = json!({ "os": { "family": "windows" } });
        let linux = json!({ "os": { "family": "linux" } });
        let counters = r#"counters "cpu" {
                            object  = "Processor"
                            instance = "_Total"
                            metrics = {
                              busy   = "% Processor Time"
                              ticks  = { counter = "Interrupts/sec" }
                              shared = { counter = "Total Thing", total = true }
                            }
                          }"#;
        let work = work_of(
            &os(counters),
            &Host::new(&windows, "a"),
            &Discoveries::new(),
        );
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].database, None);
        assert!(work[0].queries.is_empty() && work[0].discover.is_empty());
        let cpu = &work[0].counters[0];
        assert_eq!(cpu.object, "Processor");
        assert_eq!(cpu.instances, Instances::One("_Total".to_string()));
        let flags: Vec<(&str, bool, bool)> = cpu
            .metrics
            .iter()
            .map(|metric| (metric.key.as_str(), metric.total, metric.highest))
            .collect();
        assert_eq!(
            flags,
            [
                ("busy", false, true),
                ("ticks", false, false),
                ("shared", true, false)
            ]
        );
        // Only Windows has counters, and a template with nothing to read isn't sent.
        assert!(work_of(&os(counters), &Host::new(&linux, "a"), &Discoveries::new()).is_empty());
        assert!(work_of(&os(""), &Host::new(&windows, "a"), &Discoveries::new()).is_empty());
    }

    const IIS: &str = r#"
        template "iis" {
          name    = "IIS"
          service = "W3SVC"
          discover "iis" {
            registry "HKLM\\SOFTWARE\\Microsoft\\InetStp" {
              version = "VersionString"
            }
            counter_sets = { process_v2 = "Process V2" }
          }
          counters "sites" {
            object  = "Web Service"
            label   = "site"
            exclude = ["Default Web Site"]
            metrics = {
              requests = "Total Method Requests/sec"
              newer    = { counter = "New", since = "10" }
            }
          }
          counters "pool_processes" {
            when    = "process_v2"
            object  = "Process V2"
            pattern = "^w3wp:(?<pid>\\d+)$"
            join {
              object  = "W3SVC_W3WP"
              pattern = "^(?<pid>\\d+)_(?<pool>.+)$"
            }
            metrics = { pool_memory = { counter = "Working Set - Private", unit = "bytes" } }
          }
          counters "pool_processes_older" {
            when   = "!process_v2"
            object = "Process"
            groups = { pid = "ID Process" }
            join {
              object  = "W3SVC_W3WP"
              pattern = "^(?<pid>\\d+)_(?<pool>.+)$"
            }
            metrics = { pool_memory = { counter = "Working Set - Private", unit = "bytes" } }
          }
        }
    "#;

    #[test]
    fn a_services_template_is_sent_to_hosts_with_the_service_by_what_discovery_found() {
        let templates = running(IIS);
        let facts = json!({ "os": { "family": "windows" }, "services": ["Dnscache", "w3svc"] });
        let host = Host::new(&facts, "a");
        let keys = |work: &[TemplateWork]| -> Vec<String> {
            work[0]
                .counters
                .iter()
                .map(|counters| counters.key.clone())
                .collect()
        };

        // Before discovery, only what discovery looks for: every counters block
        // waits, the first as one of its metrics has a since.
        let work = work_of(&templates, &host, &Discoveries::new());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].database, None);
        let discover = &work[0].discover[0];
        assert_eq!(discover.sql, None);
        assert_eq!(discover.interval, DEFAULT_DISCOVERY_INTERVAL);
        assert_eq!(discover.registry[0].key, r"HKLM\SOFTWARE\Microsoft\InetStp");
        assert_eq!(discover.registry[0].values["version"], "VersionString");
        assert_eq!(discover.counter_sets["process_v2"], "Process V2");
        assert!(keys(&work).is_empty());
        let found = |values: Value| {
            Discoveries::from([(
                (7, ON_HOST.to_string()),
                values.as_object().unwrap().clone(),
            )])
        };

        let work = work_of(
            &templates,
            &host,
            &found(json!({ "version": "Version 10.0", "process_v2": true })),
        );
        assert_eq!(keys(&work), ["sites", "pool_processes"]);
        let sites = &work[0].counters[0];
        assert_eq!(sites.instances, Instances::Labelled("site".to_string()));
        assert_eq!(sites.exclude, ["Default Web Site"]);
        assert_eq!(sites.metrics.len(), 2);
        let processes = &work[0].counters[1];
        assert_eq!(
            processes.instances,
            Instances::Pattern(r"^w3wp:(?<pid>\d+)$".to_string())
        );
        assert_eq!(processes.join.as_ref().unwrap().object, "W3SVC_W3WP");

        let work = work_of(&templates, &host, &found(json!({ "process_v2": false })));
        assert_eq!(keys(&work), ["sites", "pool_processes_older"]);
        let older = &work[0].counters[1];
        // Joined by a group read from a counter, so every instance is read.
        assert_eq!(older.instances, Instances::Pattern(String::new()));
        assert_eq!(older.groups["pid"], "ID Process");

        // Not on a host without the service.
        let without = json!({ "os": { "family": "windows" }, "services": ["Dnscache"] });
        assert!(work_of(&templates, &Host::new(&without, "a"), &Discoveries::new()).is_empty());
    }

    #[test]
    fn a_rule_for_a_template_on_the_host_keeps_its_series_only_where_picked() {
        let picked = HashSet::from([("a".to_string(), ON_HOST.to_string())]);
        let labels = vec!["pool".to_string()];
        let mut series = vec!["x".to_string(), "y".to_string()];
        keep_picked(&mut series, &labels, "a", &picked, false);
        assert_eq!(series.len(), 2);
        keep_picked(&mut series, &labels, "b", &picked, false);
        assert!(series.is_empty());
    }

    /// A database template's rule whose series aren't each a database's is checked on
    /// a host if any of its databases is picked.
    #[test]
    fn a_rule_for_a_database_template_without_a_series_per_database_keeps_its_host() {
        let picked = HashSet::from([("a".to_string(), "orders".to_string())]);
        let mut series = vec![String::new()];
        keep_picked(&mut series, &[], "a", &picked, true);
        assert_eq!(series, [""]);
        keep_picked(&mut series, &[], "b", &picked, true);
        assert!(series.is_empty());
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
