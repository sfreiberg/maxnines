//! Putting what a collector read into entries: one for each metric and series,
//! under the metric's own name.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use maxnines_protocol::entries::{Entry, EntryValue, Reading};
use serde_json::{Number, Value};

/// What's said of something that failed and gave no reason, as an error has to say
/// something.
pub const NO_REASON: &str = "it failed without saying why";

/// The entries of one reading, all read at one time. A metric and series has one
/// entry: the first said of it is kept, so two items that share a name are one
/// series rather than two entries nothing could tell apart.
pub struct Entries {
    time: DateTime<Utc>,
    entries: Vec<Entry>,
    metrics: HashSet<String>,
    said: HashSet<(String, Vec<String>)>,
}

impl Entries {
    pub fn at(time: DateTime<Utc>) -> Self {
        Self {
            time,
            entries: Vec::new(),
            metrics: HashSet::new(),
            said: HashSet::new(),
        }
    }

    /// What was read for a metric and series: a number, a yes or no, or text. Nothing
    /// there, empty text, or anything else, says the reading worked and had nothing
    /// for it.
    pub fn read(&mut self, metric: &str, series: &[&str], value: &Value) {
        let reading = match value {
            Value::Number(number) => Reading::Value(EntryValue::Number(number.clone())),
            Value::Bool(yes) => Reading::Value(EntryValue::Bool(*yes)),
            Value::String(text) if !text.trim().is_empty() => {
                Reading::Value(EntryValue::Text(text.clone()))
            }
            Value::String(_) | Value::Null | Value::Array(_) | Value::Object(_) => Reading::Nothing,
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

    /// The reading worked and had nothing for this metric.
    pub fn nothing(&mut self, metric: &str, series: &[&str]) {
        self.put(metric, series, Reading::Nothing);
    }

    /// Why there's nothing for this metric. An error that says nothing still is one.
    pub fn error(&mut self, metric: &str, series: &[&str], error: &str) {
        let error = match error.trim() {
            "" => NO_REASON,
            _ => error,
        };
        self.put(metric, series, Reading::Error(error.to_string()));
    }

    /// What was read, or `why` it couldn't be where there's nothing: the error of
    /// each metric an item that couldn't be read has no value for.
    pub fn read_or(&mut self, metric: &str, series: &[&str], value: &Value, why: Option<&str>) {
        match why {
            Some(why) if filled(value).is_null() => self.error(metric, series, why),
            _ => self.read(metric, series, value),
        }
    }

    /// Each item of a list as a series under what its `name` field says: every
    /// metric, read from its field of the item. An item with no name isn't a
    /// series, so it's left out.
    pub fn items(&mut self, items: &Value, name: &str, fields: &[(&str, &str)]) {
        let items = items.as_array().map(Vec::as_slice).unwrap_or_default();
        for item in items {
            let Some(series) = item.get(name).and_then(Value::as_str) else {
                continue;
            };
            for (metric, field) in fields {
                self.read(metric, &[series], at(item, field));
            }
        }
    }

    fn put(&mut self, metric: &str, series: &[&str], reading: Reading) {
        debug_assert!(
            maxnines_protocol::entries::is_metric_name(metric),
            "{metric}"
        );
        // A series with an empty name would be read as no series at all.
        if series.iter().any(|value| value.trim().is_empty()) {
            return;
        }
        let series: Vec<String> = series.iter().map(|value| value.to_string()).collect();
        if !self.said.insert((metric.to_string(), series.clone())) {
            return;
        }
        if !self.metrics.contains(metric) {
            self.metrics.insert(metric.to_string());
        }
        self.entries.push(Entry {
            metric: metric.to_string(),
            series,
            time: self.time,
            reading,
        });
    }

    /// Says each of these metrics has nothing, unless it has an entry already: what
    /// a reading that looked at everything and found no items, or none of the kind
    /// a metric is read from, says of them. Not for a reading of one item among
    /// others, as an entry with no series speaks for every series.
    pub fn fill<Metric: AsRef<str>>(&mut self, metrics: &[Metric]) {
        for metric in metrics {
            if !self.metrics.contains(metric.as_ref()) {
                self.nothing(metric.as_ref(), &[]);
            }
        }
    }

    pub fn done(self) -> Vec<Entry> {
        self.entries
    }
}

/// Every metric of a table of metrics and the fields they're read from, after the
/// ones said or worked out apart from it. `METRICS` has to be how many that is.
pub const fn metrics_of<const METRICS: usize>(
    first: &[&'static str],
    fields: &[(&'static str, &'static str)],
) -> [&'static str; METRICS] {
    assert!(first.len() + fields.len() == METRICS);
    let mut metrics = [""; METRICS];
    let mut at = 0;
    while at < METRICS {
        metrics[at] = if at < first.len() {
            first[at]
        } else {
            fields[at - first.len()].0
        };
        at += 1;
    }
    metrics
}

/// Metric names as a collector says them.
pub fn names(metrics: &[&str]) -> Vec<String> {
    metrics.iter().map(|metric| metric.to_string()).collect()
}

/// What's at a path of names joined by dots in a collector's output, or null where
/// there's nothing.
pub fn at<'a>(output: &'a Value, path: &str) -> &'a Value {
    path.split('.')
        .try_fold(output, |value, name| value.get(name))
        .unwrap_or(&Value::Null)
}

/// What's there, or null for text that's empty, which is how output whose texts are
/// always there says it has none.
pub fn filled(value: &Value) -> &Value {
    match value.as_str() {
        Some(text) if text.trim().is_empty() => &Value::Null,
        _ => value,
    }
}

/// `part` as a percentage of `whole`, or nothing when either isn't a number or
/// there's no whole to be a share of.
pub fn percent(part: &Value, whole: &Value) -> Option<f64> {
    let (part, whole) = (part.as_f64()?, whole.as_f64()?);
    (whole > 0.0).then(|| part / whole * 100.0)
}

/// The error every one of a collector's metrics has when collecting failed.
pub fn failed<Metric: AsRef<str>>(
    metrics: &[Metric],
    time: DateTime<Utc>,
    error: &str,
) -> Vec<Entry> {
    let mut entries = Entries::at(time);
    for metric in metrics {
        entries.error(metric.as_ref(), &[], error);
    }
    entries.done()
}

/// What the tests of collectors' entries share.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
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

    fn read(entries: &[Entry]) -> Vec<String> {
        let mut read: Vec<String> = entries.iter().map(|entry| entry.metric.clone()).collect();
        read.sort_unstable();
        read.dedup();
        read
    }

    /// Every metric a collector says it reads has an entry, and it has entries for
    /// no others, so a failed collection's errors are on the same metrics.
    pub fn every_metric_has_an_entry(collector: &dyn crate::Collector, entries: &[Entry]) {
        let mut metrics = collector.metrics();
        metrics.sort_unstable();
        assert_eq!(read(entries), metrics, "{}", collector.name());
    }

    /// Every entry is for a metric the collector says it reads: what holds of one
    /// item's reading, which has only the metrics its kind of item is read for.
    pub fn every_entry_is_for_its_metrics(collector: &dyn crate::Collector, entries: &[Entry]) {
        let metrics = collector.metrics();
        for metric in read(entries) {
            assert!(metrics.contains(&metric), "{}: {metric}", collector.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::testing::*;
    use super::*;

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
    fn a_metric_without_an_entry_is_filled_in_with_nothing() {
        let mut entries = Entries::at(time());
        entries.read("a.count", &["x"], &json!(3));
        entries.error("a.failed", &["x"], "no");
        entries.fill(&["a.count", "a.failed", "a.missing"]);
        assert_eq!(
            said(&entries.done()),
            [
                ("a.count[x]".to_string(), json!(3)),
                ("a.failed[x]".to_string(), json!({ "error": "no" })),
                ("a.missing".to_string(), Value::Null),
            ]
        );
    }

    #[test]
    fn a_metric_and_series_has_one_entry_and_the_first_is_kept() {
        let mut entries = Entries::at(time());
        entries.read("a.heat", &["core"], &json!(40));
        entries.read("a.heat", &["core"], &json!(50));
        entries.error("a.heat", &["core"], "no");
        entries.read("a.heat", &["other"], &json!(60));
        entries.read("a.heat", &[], &json!(70));
        entries.read("a.speed", &["core"], &json!(80));
        assert_eq!(
            said(&entries.done()),
            [
                ("a.heat[core]".to_string(), json!(40)),
                ("a.heat[other]".to_string(), json!(60)),
                ("a.heat".to_string(), json!(70)),
                ("a.speed[core]".to_string(), json!(80)),
            ]
        );
    }

    /// An empty name would be read as no series at all, which speaks for every one.
    #[test]
    fn a_series_with_an_empty_name_has_no_entry() {
        let mut entries = Entries::at(time());
        entries.read("a.cpu", &[""], &json!(1));
        entries.read("a.cpu", &["  "], &json!(2));
        entries.error("a.cpu", &["page", ""], "no");
        entries.read("a.cpu", &["init"], &json!(3));
        assert_eq!(
            said(&entries.done()),
            [("a.cpu[init]".to_string(), json!(3))]
        );
    }

    #[test]
    fn an_error_that_says_nothing_still_is_one_and_empty_text_is_nothing() {
        let mut entries = Entries::at(time());
        entries.error("a.one", &[], "");
        entries.error("a.two", &[], " \n");
        entries.read("a.model", &[], &json!(""));
        entries.read("a.serial", &[], &json!("  "));
        assert_eq!(
            said(&entries.done()),
            [
                ("a.one".to_string(), json!({ "error": NO_REASON })),
                ("a.two".to_string(), json!({ "error": NO_REASON })),
                ("a.model".to_string(), Value::Null),
                ("a.serial".to_string(), Value::Null),
            ]
        );
        assert_eq!(
            said(&failed(&["a.one"], time(), "")),
            [("a.one".to_string(), json!({ "error": NO_REASON }))]
        );
    }

    #[test]
    fn why_something_could_not_be_read_is_the_error_of_what_it_has_nothing_for() {
        let mut entries = Entries::at(time());
        entries.read_or("a.up", &["x"], &json!(0), Some("refused"));
        entries.read_or("a.took", &["x"], &Value::Null, Some("refused"));
        entries.read_or("a.version", &["x"], &json!(""), Some("refused"));
        entries.read_or("a.size", &["x"], &Value::Null, None);
        assert_eq!(
            said(&entries.done()),
            [
                ("a.up[x]".to_string(), json!(0)),
                ("a.took[x]".to_string(), json!({ "error": "refused" })),
                ("a.version[x]".to_string(), json!({ "error": "refused" })),
                ("a.size[x]".to_string(), Value::Null),
            ]
        );
    }

    #[test]
    fn each_named_item_of_a_list_is_a_series_of_every_metric() {
        const FIELDS: [(&str, &str); 2] = [("a.heat", "celsius"), ("a.limit", "limit.high")];
        const METRICS: [&str; 3] = metrics_of(&["a.share"], &FIELDS);
        assert_eq!(METRICS, ["a.share", "a.heat", "a.limit"]);
        assert_eq!(names(&METRICS), ["a.share", "a.heat", "a.limit"]);

        let items = json!([
            { "label": "core", "celsius": 40, "limit": { "high": 90 } },
            { "celsius": 50 },
            { "label": "", "celsius": 55 },
            { "label": "core", "celsius": 60 },
            { "label": "board", "celsius": 30 },
        ]);
        let mut entries = Entries::at(time());
        entries.items(&items, "label", &FIELDS);
        entries.fill(&METRICS);
        assert_eq!(
            said(&entries.done()),
            [
                ("a.heat[core]".to_string(), json!(40)),
                ("a.limit[core]".to_string(), json!(90)),
                ("a.heat[board]".to_string(), json!(30)),
                ("a.limit[board]".to_string(), Value::Null),
                ("a.share".to_string(), Value::Null),
            ]
        );

        for none in [json!([]), Value::Null, json!({ "label": "core" })] {
            let mut entries = Entries::at(time());
            entries.items(&none, "label", &FIELDS);
            entries.fill(&METRICS);
            let said = said(&entries.done());
            assert_eq!(said.len(), 3, "{none}");
            assert!(said.iter().all(|(_, value)| value.is_null()), "{none}");
        }
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
    fn empty_text_is_nothing_and_everything_else_is_itself() {
        for empty in [json!(""), json!("  ")] {
            assert_eq!(filled(&empty), &Value::Null);
        }
        for kept in [json!("ext4"), json!(0), json!(false), Value::Null] {
            assert_eq!(filled(&kept), &kept);
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
