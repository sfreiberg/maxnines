//! What an agent reads, as a flat list: each entry is one metric's reading for one
//! series, with when it was taken, and either its value or why there isn't one.
//! Collectors and templates send the same thing, under names from one namespace,
//! `<prefix>.<name>`, where each prefix belongs to one of them: a template's key,
//! or what the server's built-in metrics start with, which it keeps templates'
//! keys clear of.
//!
//! Every run sends an entry for every metric it covers. One that failed puts its
//! error on each, and one with nothing to say for a metric sends that metric with
//! neither a value nor an error. An entry speaks for every series of its metric
//! that its own series starts: a failed query knows the database it ran for and not
//! the rows it didn't get, so its error on `["main"]` is every `["main", ...]`
//! series', and lasts until a newer entry for any of them has none.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::templates::is_key;

/// The longest a metric's whole name can be.
pub const MAX_METRIC_LEN: usize = 255;

/// Whether this can be a metric's name: two or more parts joined by dots, each
/// lowercase letters, digits and underscores, starting with a letter, as a key
/// is, and up to [`MAX_METRIC_LEN`] characters in all. The first part is its
/// prefix, which is a template's key or what a collector's metrics start with.
pub fn is_metric_name(name: &str) -> bool {
    name.len() <= MAX_METRIC_LEN && name.contains('.') && name.split('.').all(is_key)
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
#[serde(from = "SentSample")]
pub struct Sample {
    /// When it was sent, which is only what tells it apart from the agent's other
    /// samples, for the server to say it has it.
    pub time: DateTime<Utc>,
    pub entries: Vec<Entry>,
    /// What it was sent that isn't an entry, which is left out so the rest is kept:
    /// one that can't be read doesn't cost an agent everything sent with it. Never
    /// sent, as an agent has none.
    #[serde(skip_serializing)]
    pub refused: Vec<Refused>,
}

/// Something sent as an entry that isn't one.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    /// The metric it says it's for, if it says.
    pub metric: Option<String>,
    pub why: String,
}

/// A sample as it's sent, each entry still to be read.
#[derive(Deserialize)]
struct SentSample {
    time: DateTime<Utc>,
    entries: Vec<Value>,
}

impl From<SentSample> for Sample {
    fn from(sent: SentSample) -> Self {
        let mut entries = Vec::with_capacity(sent.entries.len());
        let mut refused = Vec::new();
        for entry in sent.entries {
            let metric = entry
                .get("metric")
                .and_then(Value::as_str)
                .map(str::to_string);
            match serde_json::from_value(entry) {
                Ok(entry) => entries.push(entry),
                Err(error) => refused.push(Refused {
                    metric,
                    why: error.to_string(),
                }),
            }
        }
        Self {
            time: sent.time,
            entries,
            refused,
        }
    }
}

/// One metric's reading for one series.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Sent", into = "Sent")]
pub struct Entry {
    /// The metric's full name, `<prefix>.<name>`, which [`is_metric_name`].
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
        if !is_metric_name(&sent.metric) {
            return Err(format!(
                "{:?} isn't a metric's name: two or more parts joined by dots, each of \
                 lowercase letters, digits and underscores, starting with a letter",
                sent.metric
            ));
        }
        if sent
            .error
            .as_deref()
            .is_some_and(|error| error.trim().is_empty())
        {
            return Err(format!("{} has an error that says nothing", sent.metric));
        }
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
    use serde_json::json;

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
            // A name that isn't a prefix and a name under it.
            json!({ "metric": "", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "usage", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": ".usage", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "cpu.", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "cpu..usage", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "CPU.usage", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "cpu.usage!", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            json!({ "metric": "cpu.9lives", "time": "2026-11-27T18:41:10.311Z", "value": 1 }),
            // An error that says nothing.
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z", "error": "" }),
            json!({ "metric": "cpu.usage", "time": "2026-11-27T18:41:10.311Z", "error": "  " }),
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
            "value": null, "error": null,
        }))
        .unwrap();
        assert_eq!(read.reading, Reading::Nothing);
    }

    #[test]
    fn a_sample_is_its_time_and_its_entries() {
        let sample = Sample {
            time: "2026-11-27T18:41:15.120Z".parse().unwrap(),
            entries: vec![entry("cpu.usage", &["user"], number(12))],
            refused: Vec::new(),
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
    fn an_entry_that_cannot_be_read_is_left_out_and_the_rest_are_kept() {
        let sample: Sample = serde_json::from_value(json!({
            "time": "2026-11-27T18:41:15.120Z",
            "entries": [
                { "metric": "cpu.usage", "series": ["user"],
                  "time": "2026-11-27T18:41:10.311Z", "value": 12 },
                { "metric": "cpu.load", "time": "2026-11-27T18:41:10.311Z",
                  "value": 1, "error": "no" },
                { "metric": "Not One", "time": "2026-11-27T18:41:10.311Z", "value": 1 },
                { "time": "2026-11-27T18:41:10.311Z", "value": 1 },
                "nothing like one",
                { "metric": "memory.usage", "time": "2026-11-27T18:41:10.311Z", "value": 61.5 },
            ],
        }))
        .unwrap();
        let kept: Vec<&str> = sample.entries.iter().map(|e| e.metric.as_str()).collect();
        assert_eq!(kept, ["cpu.usage", "memory.usage"]);
        let refused: Vec<(Option<&str>, &str)> = sample
            .refused
            .iter()
            .map(|refused| (refused.metric.as_deref(), refused.why.as_str()))
            .collect();
        assert_eq!(refused.len(), 4, "{refused:?}");
        assert_eq!(refused[0].0, Some("cpu.load"));
        assert!(refused[0].1.contains("a value and an error"), "{refused:?}");
        assert_eq!(refused[1].0, Some("Not One"));
        assert!(
            refused[1].1.contains("isn't a metric's name"),
            "{refused:?}"
        );
        assert_eq!(refused[2].0, None);
        assert!(refused[2].1.contains("metric"), "{refused:?}");
        assert_eq!(refused[3].0, None);
        // What it refused is never sent on.
        assert!(
            serde_json::to_value(&sample)
                .unwrap()
                .get("refused")
                .is_none()
        );
    }

    #[test]
    fn a_sample_that_is_not_one_is_refused_whole() {
        let refused = [
            json!({ "entries": [] }),
            json!({ "time": "2026-11-27T18:41:15.120Z" }),
            json!({ "time": "2026-11-27T18:41:15.120Z", "entries": {} }),
            json!({ "time": "yesterday", "entries": [] }),
        ];
        for sent in refused {
            assert!(
                serde_json::from_value::<Sample>(sent.clone()).is_err(),
                "{sent}"
            );
        }
    }

    #[test]
    fn a_metrics_name_is_two_or_more_keys_joined_by_dots() {
        let long = format!("a.{}", "b".repeat(64));
        let parts = ["part"; 51].join(".");
        assert_eq!(parts.len(), MAX_METRIC_LEN - 1);
        for name in [
            "cpu.usage",
            "network.packets.received",
            "a.b.c.d.e.f",
            "php_fpm.listen_queue",
            "disk_2.io9",
            long.as_str(),
            parts.as_str(),
        ] {
            assert!(is_metric_name(name), "{name:?}");
        }
        let too_long_a_part = format!("a.{}", "b".repeat(65));
        let too_long = ["part"; 52].join(".");
        for name in [
            "",
            "cpu",
            ".",
            ".usage",
            "cpu.",
            "cpu..usage",
            "CPU.usage",
            "cpu.Usage",
            "cpu.usage!",
            "cpu usage.x",
            "cpu.9lives",
            "_cpu.usage",
            "cpu.usage ",
            too_long_a_part.as_str(),
            too_long.as_str(),
        ] {
            assert!(!is_metric_name(name), "{name:?}");
        }
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
}
