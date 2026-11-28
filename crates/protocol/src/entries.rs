//! What an agent reads, as a flat list: each entry is one metric's reading for one
//! series, with when it was taken, and either its value or why there isn't one.
//! Collectors and templates send the same thing, under names from one namespace,
//! `<prefix>.<name>`, where each prefix belongs to one of them.
//!
//! Every run sends an entry for every metric it covers. One that failed puts its
//! error on each, one with nothing to say for a metric sends that metric with
//! neither a value nor an error, and the newest entry for a metric and series is how
//! it stands: an error lasts until an entry without one.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The prefixes of the metrics collectors send, and of what the server and agent
/// say of themselves. A template with metrics of its own can't have one as its key,
/// as its metrics are `<key>.<name>`.
pub const COLLECTOR_PREFIXES: &[&str] = &[
    "agent",
    "apache",
    "check",
    "clock",
    "command",
    "container",
    "counter",
    "cpu",
    "custom",
    "database_account",
    "disk",
    "file",
    "gpu",
    "host",
    "memory",
    "network",
    "nginx",
    "openmetrics",
    "php_fpm",
    "process",
    "raid",
    "sensor",
    "server",
    "service",
    "smart",
    "system",
    "time_sync",
    "top",
    "unifi",
    "updates",
    "zfs",
];

/// Whether collectors send metrics under this prefix.
pub fn is_collector_prefix(prefix: &str) -> bool {
    COLLECTOR_PREFIXES.contains(&prefix)
}

/// A metric's prefix and its name under it, `postgres` and `lag` for `postgres.lag`,
/// or nothing for a name without both.
pub fn split_metric(metric: &str) -> Option<(&str, &str)> {
    metric
        .split_once('.')
        .filter(|(prefix, name)| !prefix.is_empty() && !name.is_empty())
}

/// Everything an agent has read since it last sent. It doesn't say which agent it
/// came from, because the server takes that from the authenticated connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// When it was sent, which is only what tells it apart from the agent's other
    /// samples, for the server to say it has it.
    pub time: DateTime<Utc>,
    pub entries: Vec<Entry>,
}

/// One metric's reading for one series.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Sent", into = "Sent")]
pub struct Entry {
    /// The metric's full name, `<prefix>.<name>`.
    pub metric: String,
    /// The values of the labels that tell this series from the metric's others, in
    /// the order the metric's description names them. Empty for a metric with one
    /// series, and an error has only those the run knew before it failed, such as
    /// the database a template runs for.
    pub series: Vec<String>,
    /// When it was read. Everything one run read has the same time.
    pub time: DateTime<Utc>,
    pub reading: Reading,
}

/// What a run has to say for a metric.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    Value(EntryValue),
    /// Why the run that reads this metric failed.
    Error(String),
    /// The run worked and had nothing for this metric, such as a query with no rows.
    Nothing,
}

/// A value as it's read: a number, a yes or no, or text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EntryValue {
    Bool(bool),
    Number(serde_json::Number),
    Text(String),
}

/// An entry as it's sent, where a value and an error are each there or not.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sent {
    metric: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    series: Vec<String>,
    time: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<EntryValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl TryFrom<Sent> for Entry {
    type Error = String;

    fn try_from(sent: Sent) -> Result<Self, String> {
        let reading = match (sent.value, sent.error) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "{} has a value and an error, and can only have one",
                    sent.metric
                ));
            }
            (Some(value), None) => Reading::Value(value),
            (None, Some(error)) => Reading::Error(error),
            (None, None) => Reading::Nothing,
        };
        Ok(Self {
            metric: sent.metric,
            series: sent.series,
            time: sent.time,
            reading,
        })
    }
}

impl From<Entry> for Sent {
    fn from(entry: Entry) -> Self {
        let (value, error) = match entry.reading {
            Reading::Value(value) => (Some(value), None),
            Reading::Error(error) => (None, Some(error)),
            Reading::Nothing => (None, None),
        };
        Self {
            metric: entry.metric,
            series: entry.series,
            time: entry.time,
            value,
            error,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn at() -> DateTime<Utc> {
        "2026-11-27T18:41:10.311Z".parse().unwrap()
    }

    fn entry(metric: &str, series: &[&str], reading: Reading) -> Entry {
        Entry {
            metric: metric.to_string(),
            series: series.iter().map(|s| s.to_string()).collect(),
            time: at(),
            reading,
        }
    }

    fn number(number: impl Into<serde_json::Number>) -> Reading {
        Reading::Value(EntryValue::Number(number.into()))
    }

    #[test]
    fn an_entry_is_sent_with_its_value_its_error_or_neither() {
        let cases = [
            (
                entry("postgres.lag_bytes", &["main", "replica1"], number(4096)),
                json!({ "metric": "postgres.lag_bytes", "series": ["main", "replica1"],
                        "time": "2026-11-27T18:41:10.311Z", "value": 4096 }),
            ),
            (
                entry(
                    "postgres.size",
                    &["main"],
                    Reading::Error("permission denied".to_string()),
                ),
                json!({ "metric": "postgres.size", "series": ["main"],
                        "time": "2026-11-27T18:41:10.311Z", "error": "permission denied" }),
            ),
            (
                entry("postgres.slot_retained", &["main"], Reading::Nothing),
                json!({ "metric": "postgres.slot_retained", "series": ["main"],
                        "time": "2026-11-27T18:41:10.311Z" }),
            ),
            // A metric with one series says nothing of series.
            (
                entry("updates.pending", &[], number(3)),
                json!({ "metric": "updates.pending", "time": "2026-11-27T18:41:10.311Z",
                        "value": 3 }),
            ),
        ];
        for (entry, sent) in cases {
            assert_eq!(serde_json::to_value(&entry).unwrap(), sent);
            assert_eq!(serde_json::from_value::<Entry>(sent).unwrap(), entry);
        }
    }

    #[test]
    fn a_value_keeps_its_kind() {
        let values = [
            (json!(42), EntryValue::Number(42.into())),
            (json!(-7), EntryValue::Number((-7).into())),
            (
                json!(u64::MAX),
                EntryValue::Number(serde_json::Number::from(u64::MAX)),
            ),
            (
                json!(12.5),
                EntryValue::Number(serde_json::Number::from_f64(12.5).unwrap()),
            ),
            (json!(true), EntryValue::Bool(true)),
            (json!(false), EntryValue::Bool(false)),
            (
                json!("Samsung SSD 990"),
                EntryValue::Text("Samsung SSD 990".to_string()),
            ),
            // Text that looks like something else stays text.
            (json!("42"), EntryValue::Text("42".to_string())),
            (json!("true"), EntryValue::Text("true".to_string())),
        ];
        for (sent, value) in values {
            let read: Entry = serde_json::from_value(json!({
                "metric": "smart.model", "time": "2026-11-27T18:41:10.311Z", "value": sent,
            }))
            .unwrap();
            assert_eq!(read.reading, Reading::Value(value), "{sent}");
            assert_eq!(serde_json::to_value(&read).unwrap()["value"], sent);
        }
    }

    #[test]
    fn an_entry_that_is_not_one_is_refused() {
        let refused = [
            // A value and an error.
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z",
                    "value": 1, "error": "no" }),
            // No metric, and no time.
            json!({ "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "cpu.usage", "value": 1 }),
            // A value that's none of a number, a yes or no, or text.
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z", "value": [1] }),
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z",
                    "value": { "user": 1 } }),
            // Series that isn't a list of text.
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z",
                    "series": "user", "value": 1 }),
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z",
                    "series": [1], "value": 1 }),
            // Something it doesn't know, as a misspelt `error` would otherwise read
            // as nothing to say.
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z",
                    "eror": "no" }),
        ];
        for sent in refused {
            assert!(
                serde_json::from_value::<Entry>(sent.clone()).is_err(),
                "{sent}"
            );
        }
    }

    #[test]
    fn a_null_value_or_error_is_the_same_as_none() {
        let read: Entry = serde_json::from_value(json!({
            "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z",
            "value": Value::Null, "error": Value::Null,
        }))
        .unwrap();
        assert_eq!(read.reading, Reading::Nothing);
    }

    #[test]
    fn a_sample_is_its_time_and_its_entries() {
        let sample = Sample {
            time: "2026-11-27T18:41:15.120Z".parse().unwrap(),
            entries: vec![entry("cpu.usage", &["user"], number(12))],
        };
        let sent = json!({
            "time": "2026-11-27T18:41:15.120Z",
            "entries": [{ "metric": "cpu.usage", "series": ["user"],
                          "time": "2026-11-27T18:41:10.311Z", "value": 12 }],
        });
        assert_eq!(serde_json::to_value(&sample).unwrap(), sent);
        assert_eq!(serde_json::from_value::<Sample>(sent).unwrap(), sample);
    }

    #[test]
    fn a_metric_splits_into_its_prefix_and_name() {
        assert_eq!(split_metric("postgres.lag"), Some(("postgres", "lag")));
        assert_eq!(
            split_metric("network.packets.received"),
            Some(("network", "packets.received"))
        );
        for not_one in ["", "lag", ".lag", "postgres.", "."] {
            assert_eq!(split_metric(not_one), None, "{not_one:?}");
        }
    }

    #[test]
    fn the_collector_prefixes_are_sorted_keys_without_repeats() {
        assert!(COLLECTOR_PREFIXES.is_sorted_by(|a, b| a < b));
        for prefix in COLLECTOR_PREFIXES {
            assert!(crate::templates::is_key(prefix), "{prefix}");
        }
        assert!(is_collector_prefix("cpu"));
        assert!(!is_collector_prefix("postgres"));
    }
}
