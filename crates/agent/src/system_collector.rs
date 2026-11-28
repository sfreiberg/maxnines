use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use maxnines_collectors::entries::{Entries, at, percent};
use maxnines_collectors::failed_services::failed_services;
use maxnines_collectors::system::{limits, login_sessions, report};
use maxnines_collectors::tcp::tcp_states;
use maxnines_protocol::entries::Entry;
use serde_json::Value;

use crate::background::Background;
use crate::collector::Collector;

/// How close the host is to its limits, how many people are on it, its TCP
/// connections and services that failed. Updates and a restart waiting are the
/// `updates` collector's.
pub struct SystemCollector {
    background: Background,
}

impl SystemCollector {
    pub fn new(interval: Duration) -> Result<Self> {
        let mut background = Background::new();
        background.repeat(
            interval,
            None,
            || async {
                // Each is asked at once, and reading limits blocks, so it's done
                // away from the other collectors' tasks.
                let (limits, sessions, tcp, failed) = tokio::join!(
                    tokio::task::spawn_blocking(limits),
                    login_sessions(),
                    tcp_states(),
                    failed_services(),
                );
                report(&limits.unwrap_or_default(), sessions, tcp, failed)
            },
            Result::unwrap_or_default,
        )?;
        Ok(Self { background })
    }
}

impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest().pop().unwrap_or_default())
    }

    fn metrics(&self) -> &'static [&'static str] {
        &[
            "system.open_files",
            "system.open_files_used",
            "system.processes",
            "system.processes_used",
            "system.threads",
            "system.threads_used",
            "system.conntrack",
            "system.conntrack_used",
            "system.sessions",
            "system.tcp",
            "system.tcp_total",
            "system.failed_services",
            "system.failed_service_names",
        ]
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        // Each system has its own limits, so the others have nothing.
        for (metric, share, series, field, limit) in LIMITS {
            let (used, most) = (at(output, field), at(output, limit));
            entries.read(metric, &[series], used);
            entries.read(metric, &["Limit"], most);
            entries.number(share, &["Used"], percent(used, most));
        }
        entries.read(
            "system.sessions",
            &["Sessions"],
            at(output, "login_sessions"),
        );
        for (series, field) in TCP_STATES {
            entries.read("system.tcp", &[series], at(output, field));
        }
        entries.read(
            "system.tcp_total",
            &["Connections"],
            at(output, "tcp_connections"),
        );
        // Only Linux and Windows say which services failed.
        entries.read(
            "system.failed_services",
            &["Failed"],
            at(output, "failed_services"),
        );
        entries.read(
            "system.failed_service_names",
            &[],
            at(output, "failed_service_names"),
        );
        entries.done()
    }
}

/// What the host has a limit on: the metric counting it, the metric of how much of
/// the limit is used, what the count's series is called, and what the count and
/// its limit are read from.
const LIMITS: [(&str, &str, &str, &str, &str); 4] = [
    (
        "system.open_files",
        "system.open_files_used",
        "Open",
        "open_files",
        "max_open_files",
    ),
    (
        "system.processes",
        "system.processes_used",
        "Running",
        "processes",
        "max_processes",
    ),
    (
        "system.threads",
        "system.threads_used",
        "Running",
        "threads",
        "max_threads",
    ),
    (
        "system.conntrack",
        "system.conntrack_used",
        "Tracked",
        "conntrack",
        "max_conntrack",
    ),
];

/// The states TCP connections are counted in, as a series is called and as it's
/// read.
const TCP_STATES: [(&str, &str); 4] = [
    ("Established", "tcp_established"),
    ("Listening", "tcp_listening"),
    ("Time wait", "tcp_time_wait"),
    ("Close wait", "tcp_close_wait"),
];

#[cfg(test)]
mod tests {
    use maxnines_collectors::system::Limits;
    use serde_json::json;

    use super::*;
    use crate::collector::test_entries::{every_metric_has_an_entry, said, time};

    /// On so long an interval that what it asks the host is never waited for.
    fn collector() -> SystemCollector {
        SystemCollector::new(Duration::from_secs(3600)).unwrap()
    }

    #[test]
    fn system_entries_are_each_count_its_limit_and_how_much_of_it_is_used() {
        let collector = collector();
        let output = json!({
            "max_open_files": 1000, "open_files": 250,
            "max_processes": 400, "processes": 100,
            "max_threads": null, "threads": null,
            "max_conntrack": 0, "conntrack": 0,
            "login_sessions": 2,
            "tcp_established": 12, "tcp_listening": 5, "tcp_time_wait": 1,
            "tcp_close_wait": 0, "tcp_connections": 20,
            "failed_services": 2, "failed_service_names": "cron.service, nginx.service",
        });
        let entries = collector.entries(&output, time());
        assert_eq!(
            said(&entries),
            [
                ("system.open_files[Open]".to_string(), json!(250)),
                ("system.open_files[Limit]".to_string(), json!(1000)),
                ("system.open_files_used[Used]".to_string(), json!(25.0)),
                ("system.processes[Running]".to_string(), json!(100)),
                ("system.processes[Limit]".to_string(), json!(400)),
                ("system.processes_used[Used]".to_string(), json!(25.0)),
                // Only Linux has a limit on threads.
                ("system.threads[Running]".to_string(), Value::Null),
                ("system.threads[Limit]".to_string(), Value::Null),
                ("system.threads_used[Used]".to_string(), Value::Null),
                // A limit of none has no share of it used.
                ("system.conntrack[Tracked]".to_string(), json!(0)),
                ("system.conntrack[Limit]".to_string(), json!(0)),
                ("system.conntrack_used[Used]".to_string(), Value::Null),
                ("system.sessions[Sessions]".to_string(), json!(2)),
                ("system.tcp[Established]".to_string(), json!(12)),
                ("system.tcp[Listening]".to_string(), json!(5)),
                ("system.tcp[Time wait]".to_string(), json!(1)),
                ("system.tcp[Close wait]".to_string(), json!(0)),
                ("system.tcp_total[Connections]".to_string(), json!(20)),
                ("system.failed_services[Failed]".to_string(), json!(2)),
                (
                    "system.failed_service_names".to_string(),
                    json!("cron.service, nginx.service")
                ),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);
    }

    #[test]
    fn a_system_that_says_nothing_has_nothing_for_each_metric() {
        let collector = collector();
        // A host that could be asked nothing, and one not asked yet.
        let unknown = report(&Limits::default(), None, None, None);
        for output in [unknown, Value::Null] {
            let entries = collector.entries(&output, time());
            assert_eq!(entries.len(), 20);
            assert!(said(&entries).iter().all(|(_, value)| value.is_null()));
            every_metric_has_an_entry(&collector, &entries);
        }
    }

    /// Whether or not the host has been asked by now, what's collected is entries
    /// for exactly the collector's metrics.
    #[test]
    fn what_the_system_really_says_becomes_entries_for_its_metrics() {
        let mut collector = collector();
        let output = collector.collect().unwrap();
        every_metric_has_an_entry(&collector, &collector.entries(&output, time()));
    }
}
