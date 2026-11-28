//! Putting what a collector read into entries: one for each metric and series,
//! under the metric's own name.

use chrono::{DateTime, Utc};
use maxnines_protocol::entries::{Entry, EntryValue, Reading};
use serde_json::{Number, Value};

/// The entries of one collection, all read at one time.
pub struct Entries {
    time: DateTime<Utc>,
    entries: Vec<Entry>,
}

impl Entries {
    pub fn at(time: DateTime<Utc>) -> Self {
        Self {
            time,
            entries: Vec::new(),
        }
    }

    /// What was read for a metric and series: a number, a yes or no, or text. Nothing
    /// there, or anything else, says the collection worked and had nothing for it.
    pub fn read(&mut self, metric: &str, series: &[&str], value: &Value) {
        let reading = match value {
            Value::Number(number) => Reading::Value(EntryValue::Number(number.clone())),
            Value::Bool(yes) => Reading::Value(EntryValue::Bool(*yes)),
            Value::String(text) => Reading::Value(EntryValue::Text(text.clone())),
            Value::Null | Value::Array(_) | Value::Object(_) => Reading::Nothing,
        };
        self.put(metric, series, reading);
    }

    /// A number worked out from what was read, or nothing for one that can't be,
    /// such as a share of nothing.
    pub fn number(&mut self, metric: &str, series: &[&str], value: Option<f64>) {
        let reading = match value.and_then(Number::from_f64) {
            Some(number) => Reading::Value(EntryValue::Number(number)),
            None => Reading::Nothing,
        };
        self.put(metric, series, reading);
    }

    /// The collection worked and had nothing for this metric.
    pub fn nothing(&mut self, metric: &str, series: &[&str]) {
        self.put(metric, series, Reading::Nothing);
    }

    /// Why there's nothing for this metric.
    pub fn error(&mut self, metric: &str, series: &[&str], error: &str) {
        self.put(metric, series, Reading::Error(error.to_string()));
    }

    fn put(&mut self, metric: &str, series: &[&str], reading: Reading) {
        debug_assert!(
            maxnines_protocol::entries::is_metric_name(metric),
            "{metric}"
        );
        self.entries.push(Entry {
            metric: metric.to_string(),
            series: series.iter().map(|value| value.to_string()).collect(),
            time: self.time,
            reading,
        });
    }

    pub fn done(self) -> Vec<Entry> {
        self.entries
    }
}

/// What's at a path of names joined by dots in a collector's output, or null where
/// there's nothing.
pub fn at<'a>(output: &'a Value, path: &str) -> &'a Value {
    path.split('.')
        .try_fold(output, |value, name| value.get(name))
        .unwrap_or(&Value::Null)
}

/// `part` as a percentage of `whole`, or nothing when either isn't a number or
/// there's no whole to be a share of.
pub fn percent(part: &Value, whole: &Value) -> Option<f64> {
    let (part, whole) = (part.as_f64()?, whole.as_f64()?);
    (whole > 0.0).then(|| part / whole * 100.0)
}

/// The error every one of a collector's metrics has when collecting failed.
pub fn failed(metrics: &[&str], time: DateTime<Utc>, error: &str) -> Vec<Entry> {
    let mut entries = Entries::at(time);
    for metric in metrics {
        entries.error(metric, &[], error);
    }
    entries.done()
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    pub fn time() -> DateTime<Utc> {
        "2026-11-28T09:00:00Z".parse().unwrap()
    }

    /// Entries as `metric[series, ...]` and what they say, to compare whole.
    pub fn said(entries: &[Entry]) -> Vec<(String, Value)> {
        entries
            .iter()
            .map(|entry| {
                assert_eq!(entry.time, time());
                let name = match entry.series.as_slice() {
                    [] => entry.metric.clone(),
                    series => format!("{}[{}]", entry.metric, series.join(", ")),
                };
                let reading = match &entry.reading {
                    Reading::Value(value) => serde_json::to_value(value).unwrap(),
                    Reading::Error(error) => json!({ "error": error }),
                    Reading::Nothing => Value::Null,
                };
                (name, reading)
            })
            .collect()
    }

    /// Every metric a collector says it reads has an entry, and it has entries for
    /// no others, so a failed collection's errors are on the same metrics.
    pub fn every_metric_has_an_entry(collector: &dyn crate::Collector, entries: &[Entry]) {
        let mut read: Vec<&str> = entries.iter().map(|entry| entry.metric.as_str()).collect();
        read.sort_unstable();
        read.dedup();
        let mut metrics = collector.metrics().to_vec();
        metrics.sort_unstable();
        assert_eq!(read, metrics, "{}", collector.name());
    }

    #[test]
    fn what_was_read_keeps_its_kind_and_anything_else_is_nothing() {
        let mut entries = Entries::at(time());
        entries.read("a.count", &[], &json!(3));
        entries.read("a.share", &["x"], &json!(12.5));
        entries.read("a.up", &["x", "y"], &json!(true));
        entries.read("a.model", &[], &json!("Samsung"));
        entries.read("a.missing", &[], &Value::Null);
        entries.read("a.list", &[], &json!([1]));
        entries.read("a.map", &[], &json!({ "b": 1 }));
        entries.number("a.worked", &[], Some(50.0));
        entries.number("a.unknown", &[], None);
        entries.number("a.endless", &[], Some(f64::INFINITY));
        entries.number("a.not", &[], Some(f64::NAN));
        entries.nothing("a.none", &["x"]);
        entries.error("a.failed", &[], "no");
        assert_eq!(
            said(&entries.done()),
            [
                ("a.count".to_string(), json!(3)),
                ("a.share[x]".to_string(), json!(12.5)),
                ("a.up[x, y]".to_string(), json!(true)),
                ("a.model".to_string(), json!("Samsung")),
                ("a.missing".to_string(), Value::Null),
                ("a.list".to_string(), Value::Null),
                ("a.map".to_string(), Value::Null),
                ("a.worked".to_string(), json!(50.0)),
                ("a.unknown".to_string(), Value::Null),
                ("a.endless".to_string(), Value::Null),
                ("a.not".to_string(), Value::Null),
                ("a.none[x]".to_string(), Value::Null),
                ("a.failed".to_string(), json!({ "error": "no" })),
            ]
        );
    }

    #[test]
    fn a_path_finds_what_is_there_and_null_where_nothing_is() {
        let output = json!({ "load": { "one": 1.5 }, "cores": [1, 2] });
        assert_eq!(at(&output, "load.one"), &json!(1.5));
        assert_eq!(at(&output, "load"), &json!({ "one": 1.5 }));
        for nothing in ["load.two", "none", "load.one.more", "cores.one"] {
            assert_eq!(at(&output, nothing), &Value::Null, "{nothing}");
        }
    }

    #[test]
    fn a_percentage_needs_both_numbers_and_a_whole() {
        assert_eq!(percent(&json!(1), &json!(4)), Some(25.0));
        assert_eq!(percent(&json!(0), &json!(4)), Some(0.0));
        assert_eq!(percent(&json!(1), &json!(0)), None);
        assert_eq!(percent(&Value::Null, &json!(4)), None);
        assert_eq!(percent(&json!(1), &Value::Null), None);
        assert_eq!(percent(&json!("1"), &json!(4)), None);
    }

    #[test]
    fn a_failed_collection_is_an_error_on_each_of_its_metrics() {
        let entries = failed(&["a.one", "a.two"], time(), "couldn't read /proc");
        assert_eq!(
            said(&entries),
            [
                (
                    "a.one".to_string(),
                    json!({ "error": "couldn't read /proc" })
                ),
                (
                    "a.two".to_string(),
                    json!({ "error": "couldn't read /proc" })
                ),
            ]
        );
    }
}
