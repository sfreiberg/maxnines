//! Watches the server during a test, through what it says about itself.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

/// The server's own figures at one moment.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Snapshot {
    pub started_ms: i64,
    pub written: u64,
    pub failed: u64,
    pub queued: u64,
    pub queue_capacity: u64,
    pub firing: u64,
    pub alert_pass_age_secs: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub cpu_cores: Option<f64>,
    pub metrics_bytes: Option<u64>,
    pub database_bytes: Option<u64>,
    pub disk_available_bytes: Option<u64>,
}

/// Sizes the server reports as text, like `417.5 MiB`.
pub fn parse_size(text: &str) -> Option<u64> {
    let (number, unit) = text.trim().split_once(' ')?;
    let number: f64 = number.parse().ok()?;
    let factor: u64 = match unit {
        "B" | "bytes" | "byte" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        _ => return None,
    };
    Some((number * factor as f64) as u64)
}

impl Snapshot {
    pub fn read(stats: &Value, now_ms: i64) -> Self {
        let activity = &stats["activity"];
        let process = &stats["process"];
        let size = |name: &str| stats["metrics"][name].as_str().and_then(parse_size);
        let cores = process["cores"].as_f64();
        Self {
            started_ms: stats["started_ms"].as_i64().unwrap_or_default(),
            written: activity["samples_written"].as_u64().unwrap_or_default(),
            failed: activity["samples_failed"].as_u64().unwrap_or_default(),
            queued: activity["samples_queued"].as_u64().unwrap_or_default(),
            queue_capacity: activity["queue_capacity"].as_u64().unwrap_or_default(),
            firing: activity["alerts_firing"].as_u64().unwrap_or_default(),
            alert_pass_age_secs: activity["last_alert_pass_ms"]
                .as_i64()
                .filter(|time| *time > 0)
                .map(|time| (now_ms - time).max(0) as f64 / 1000.0),
            memory_bytes: process["memory_bytes"].as_u64(),
            cpu_cores: process["cpu_percent"]
                .as_f64()
                .zip(cores)
                .map(|(percent, cores)| percent / 100.0 * cores),
            metrics_bytes: size("size").map(|file| file + size("write_ahead_log").unwrap_or(0)),
            database_bytes: stats["database"]["size_bytes"].as_u64(),
            disk_available_bytes: stats["disk"]["available_bytes"].as_u64(),
        }
    }
}

/// One point on the report's charts.
#[derive(Debug, Clone, Serialize)]
pub struct Point {
    pub time_secs: f64,
    pub agents_online: u64,
    pub samples_sent_per_sec: f64,
    pub samples_written_per_sec: f64,
    pub queued: u64,
    pub cpu_cores: Option<f64>,
    pub memory_mb: Option<f64>,
    pub metrics_mb: Option<f64>,
    pub alert_pass_age_secs: Option<f64>,
}

/// Adds up what the server did, across any restarts during the test.
#[derive(Debug, Default)]
pub struct Timeline {
    pub points: Vec<Point>,
    pub written: u64,
    pub failed: u64,
    pub first: Option<Snapshot>,
    pub last: Option<Snapshot>,
    last_sent: u64,
    last_time_secs: f64,
}

impl Timeline {
    pub fn add(&mut self, time: Duration, online: u64, sent: u64, snapshot: Snapshot) {
        let time_secs = time.as_secs_f64();
        let new_written = self.count(&snapshot);

        if self.last.is_some() {
            let seconds = (time_secs - self.last_time_secs).max(0.001);
            self.points.push(Point {
                time_secs,
                agents_online: online,
                samples_sent_per_sec: sent.saturating_sub(self.last_sent) as f64 / seconds,
                samples_written_per_sec: new_written as f64 / seconds,
                queued: snapshot.queued,
                cpu_cores: snapshot.cpu_cores,
                memory_mb: snapshot.memory_bytes.map(|bytes| bytes as f64 / 1e6),
                metrics_mb: snapshot.metrics_bytes.map(|bytes| bytes as f64 / 1e6),
                alert_pass_age_secs: snapshot.alert_pass_age_secs,
            });
        }
        self.last_sent = sent;
        self.last_time_secs = time_secs;
        if self.first.is_none() {
            self.first = Some(snapshot.clone());
        }
        self.last = Some(snapshot);
    }

    /// Takes in what the server finished saving after the test stopped. It counts
    /// towards the totals, but agents leaving isn't part of the load being charted.
    pub fn settle(&mut self, snapshot: Snapshot) {
        self.count(&snapshot);
        self.last = Some(snapshot);
    }

    /// Adds what's new since the last look, and returns how many samples were written.
    fn count(&mut self, snapshot: &Snapshot) -> u64 {
        let (new_written, new_failed) = match &self.last {
            // The server's counts start again when it does.
            Some(last) if last.started_ms != snapshot.started_ms => {
                (snapshot.written, snapshot.failed)
            }
            Some(last) => (
                snapshot.written.saturating_sub(last.written),
                snapshot.failed.saturating_sub(last.failed),
            ),
            None => (0, 0),
        };
        self.written += new_written;
        self.failed += new_failed;
        new_written
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn stats() -> Value {
        json!({
            "started_ms": 1000,
            "process": { "memory_bytes": 2_000_000_000u64, "cpu_percent": 5.0, "cores": 12 },
            "disk": { "available_bytes": 500 },
            "metrics": { "size": "417.5 MiB", "write_ahead_log": "12.5 MiB" },
            "database": { "size_bytes": 28 },
            "activity": {
                "samples_written": 10, "samples_failed": 1, "samples_queued": 2,
                "queue_capacity": 1024, "alerts_firing": 3, "last_alert_pass_ms": 5000,
            },
        })
    }

    #[test]
    fn sizes_are_read_as_the_server_writes_them() {
        assert_eq!(parse_size("1 KiB"), Some(1024));
        assert_eq!(parse_size("1.5 MiB"), Some(1_572_864));
        assert_eq!(parse_size("2 GiB"), Some(2_147_483_648));
        assert_eq!(parse_size("12 B"), Some(12));
        assert_eq!(parse_size("lots"), None);
        assert_eq!(parse_size("1 parsec"), None);
    }

    #[test]
    fn the_servers_figures_are_read() {
        let snapshot = Snapshot::read(&stats(), 7000);

        assert_eq!(snapshot.written, 10);
        assert_eq!(snapshot.queue_capacity, 1024);
        assert_eq!(snapshot.alert_pass_age_secs, Some(2.0));
        assert!((snapshot.cpu_cores.unwrap() - 0.6).abs() < 1e-9);
        assert_eq!(snapshot.metrics_bytes, Some(430 * 1024 * 1024));
    }

    #[test]
    fn missing_parts_stay_empty() {
        let snapshot = Snapshot::read(&json!({ "activity": {} }), 0);

        assert_eq!(snapshot.memory_bytes, None);
        assert_eq!(snapshot.cpu_cores, None);
        assert_eq!(snapshot.alert_pass_age_secs, None);
    }

    fn at(started_ms: i64, written: u64) -> Snapshot {
        Snapshot {
            started_ms,
            written,
            ..Snapshot::default()
        }
    }

    #[test]
    fn writes_are_counted_from_the_start_of_the_test() {
        let mut timeline = Timeline::default();
        timeline.add(Duration::from_secs(0), 0, 0, at(1, 500));
        timeline.add(Duration::from_secs(10), 1, 100, at(1, 600));

        assert_eq!(timeline.written, 100);
        assert_eq!(timeline.points.len(), 1);
        assert_eq!(timeline.points[0].samples_written_per_sec, 10.0);
        assert_eq!(timeline.points[0].samples_sent_per_sec, 10.0);
    }

    #[test]
    fn writes_after_the_test_count_but_are_not_charted() {
        let mut timeline = Timeline::default();
        timeline.add(Duration::from_secs(0), 0, 0, at(1, 0));
        timeline.add(Duration::from_secs(5), 0, 0, at(1, 100));

        timeline.settle(at(1, 150));

        assert_eq!(timeline.written, 150);
        assert_eq!(timeline.points.len(), 1);
    }

    #[test]
    fn a_server_restart_does_not_lose_count() {
        let mut timeline = Timeline::default();
        timeline.add(Duration::from_secs(0), 0, 0, at(1, 0));
        timeline.add(Duration::from_secs(5), 0, 0, at(1, 900));
        timeline.add(Duration::from_secs(10), 0, 0, at(2, 40));
        timeline.add(Duration::from_secs(15), 0, 0, at(2, 50));

        assert_eq!(timeline.written, 950);
    }
}
