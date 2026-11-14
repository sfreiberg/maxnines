//! Metrics pages in the Prometheus and OpenMetrics text format, which most
//! software that can be monitored either serves itself or has an exporter for.
//! Each line of a page is a series: a metric, its labels and a number. Agents
//! read these pages on their own hosts, and the server reads them for hosts that
//! have no agent.
//!
//! Every series is reported under its page's name and the line as the page wrote
//! it, such as `localhost:9100 http_requests_total{code="200"}`. Running totals,
//! which is what counters are, become the change since the last sample, as a rate
//! needs. Histograms' buckets are left out, which leaves their sum and count,
//! enough for an average.
//!
//! A page can be any size, so what's kept of it is bounded: it's read in one pass
//! into a short list for each series, and nothing else of it is held between
//! rounds. The lists only become the rows of a sample when one is taken, as a row
//! is several times the size.

use std::collections::HashMap;
use std::time::Duration;

use maxnines_protocol::metrics_page_name;
use serde_json::{Value, json};
use wildmatch::WildMatch;

use crate::{Login, fetch_page};

/// How long a page gets to answer.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// How many series an agent reports, shared equally between its pages. A sample
/// has to fit in one message to the server, and an exporter can list tens of
/// thousands.
pub const MAX_SERIES: usize = 2_000;

/// The longest name an alert rule can pick a series by.
const MAX_NAME_BYTES: usize = 255;

pub const TIMED_OUT: &str = "timed out";
pub const NO_METRICS: &str = "the page has no metrics in the OpenMetrics format";

/// What a page's `# TYPE` line says a metric is, for the kinds that are read
/// differently from a plain number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Histogram,
    Summary,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reported {
    /// A number as it is.
    Level,
    /// A running total, reported as its change.
    Total,
}

/// A page to read, and what to keep of it.
pub struct Page {
    url: String,
    name: String,
    /// The metrics to keep, or all of them when there are none.
    wanted: Vec<WildMatch>,
    max_series: usize,
    /// Sent with every request, for a page that asks who's reading.
    login: Option<Login>,
}

impl Page {
    /// `wanted` are metric names, with `*` and `?` for anything.
    pub fn new(url: String, wanted: &[String], max_series: usize, login: Option<Login>) -> Self {
        Self {
            name: metrics_page_name(&url).to_string(),
            url,
            wanted: wanted.iter().map(|name| WildMatch::new(name)).collect(),
            max_series,
            login,
        }
    }

    /// What the page is called, which each of its series' names starts with.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn wants(&self, metric: &str) -> bool {
        self.wanted.is_empty() || self.wanted.iter().any(|pattern| pattern.matches(metric))
    }

    /// Fetches the page and gives what's kept of it: a row for the page itself,
    /// which says why if it couldn't be read, then each series as a short list for
    /// [`Totals::settle`].
    pub async fn read(&self) -> Vec<Value> {
        let read = match fetch_page(&self.url, TIMEOUT, self.login.as_ref()).await {
            Ok(text) => read(&text, self).map_err(str::to_string),
            Err(error) => Err(format!("{error:#}")),
        };
        read.unwrap_or_else(|error| self.failed(&error))
    }

    /// What's kept of a page that couldn't be read.
    pub fn failed(&self, error: &str) -> Vec<Value> {
        vec![json!({ "name": self.name, "up": 0, "error": error })]
    }
}

fn is_metric_name(name: &str) -> bool {
    let plain = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == ':';
    name.chars().all(plain) && !name.starts_with(|c: char| c.is_ascii_digit()) && !name.is_empty()
}

/// Splits a line into its metric, its labels and what follows. A label's value
/// can hold anything in its quotes, a closing brace included.
fn split_sample(line: &str) -> Option<(&str, &str, &str)> {
    let name_end = line.find(|c: char| c == '{' || c.is_whitespace())?;
    let (metric, rest) = line.split_at(name_end);
    if !is_metric_name(metric) {
        return None;
    }
    if !rest.starts_with('{') {
        return Some((metric, "", rest.trim_start()));
    }
    let (mut quoted, mut escaped) = (false, false);
    for (index, c) in rest.char_indices().skip(1) {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '}' if !quoted => {
                return Some((metric, &rest[1..index], rest[index + 1..].trim_start()));
            }
            _ => {}
        }
    }
    None
}

/// How a line is reported, or `None` for one that isn't: a histogram's buckets,
/// and the time a metric was created.
fn reported(metric: &str, kinds: &HashMap<&str, Kind>) -> Option<Reported> {
    // Prometheus gives a counter's type under its whole name.
    if let Some(kind) = kinds.get(metric) {
        return Some(match kind {
            Kind::Counter => Reported::Total,
            _ => Reported::Level,
        });
    }
    let Some((family, suffix)) = metric.rsplit_once('_') else {
        return Some(Reported::Level);
    };
    match (kinds.get(family), suffix) {
        (Some(Kind::Counter), "total") => Some(Reported::Total),
        (Some(Kind::Histogram | Kind::Summary), "sum" | "count") => Some(Reported::Total),
        (Some(Kind::Histogram), "bucket") => None,
        (Some(Kind::Counter | Kind::Histogram | Kind::Summary), "created") => None,
        _ => Some(Reported::Level),
    }
}

/// What's kept of a page: the row for the page itself, then each series as its
/// name, its number and whether that's a running total.
fn read(text: &str, page: &Page) -> Result<Vec<Value>, &'static str> {
    // Names are borrowed from the page, which outlives this.
    let mut kinds: HashMap<&str, Kind> = HashMap::new();
    // The page's own row goes first, once it's known what was dropped.
    let mut rows = vec![Value::Null];
    let (mut found, mut dropped) = (false, 0_u64);

    for line in text.lines().map(str::trim) {
        if let Some(comment) = line.strip_prefix('#') {
            let mut words = comment.split_whitespace();
            if words.next() == Some("TYPE")
                && let (Some(metric), Some(kind)) = (words.next(), words.next())
            {
                let kind = match kind {
                    "counter" => Kind::Counter,
                    "histogram" | "gaugehistogram" => Kind::Histogram,
                    "summary" => Kind::Summary,
                    _ => Kind::Other,
                };
                kinds.insert(metric, kind);
            }
            continue;
        }
        let Some((metric, labels, rest)) = split_sample(line) else {
            continue;
        };
        // A time can follow the number, and isn't used.
        let number = rest.split_whitespace().next().map(str::parse::<f64>);
        let Some(Ok(number)) = number else {
            continue;
        };
        found = true;
        let Some(reported) = reported(metric, &kinds) else {
            continue;
        };
        // A sample is JSON, which has no way to write infinity.
        if !number.is_finite() || !page.wants(metric) {
            continue;
        }
        let name = if labels.is_empty() {
            format!("{} {metric}", page.name)
        } else {
            format!("{} {metric}{{{labels}}}", page.name)
        };
        if rows.len() > page.max_series || name.len() > MAX_NAME_BYTES {
            dropped += 1;
            continue;
        }
        rows.push(json!([name, number, reported == Reported::Total]));
    }

    if !found {
        return Err(NO_METRICS);
    }
    rows[0] = json!({ "name": page.name, "up": 1, "dropped": dropped });
    Ok(rows)
}

/// The last total seen for each series, which is what turns the next one into a
/// change.
#[derive(Default)]
pub struct Totals(HashMap<String, f64>);

impl Totals {
    /// Turns what's kept of the pages into the rows of a sample. A running total
    /// becomes its change since the last sample, and one seen for the first time is
    /// left out, as it has nothing to compare with. A total that went backwards
    /// started again, which counts as no change.
    ///
    /// Only the totals in this sample are remembered, so a series that's gone, or
    /// a whole page that stopped answering, starts afresh if it comes back.
    pub fn settle(&mut self, kept: Vec<Value>) -> Vec<Value> {
        let mut seen = HashMap::with_capacity(self.0.len());
        let rows = kept
            .into_iter()
            .filter_map(|row| {
                // A page's own row is already as it's sent.
                let Value::Array(series) = row else {
                    return Some(row);
                };
                let Ok([Value::String(name), number, Value::Bool(total)]) =
                    <[Value; 3]>::try_from(series)
                else {
                    return None;
                };
                if !total {
                    return Some(json!({ "name": name, "value": number }));
                }
                let total = number.as_f64()?;
                let (key, last) = match self.0.remove_entry(&name) {
                    Some((key, last)) => (key, Some(last)),
                    None => (name.clone(), None),
                };
                seen.insert(key, total);
                Some(json!({ "name": name, "change": (total - last?).max(0.0) }))
            })
            .collect();
        self.0 = seen;
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"# HELP http_requests_total Requests served.
# TYPE http_requests_total counter
http_requests_total{method="GET",code="200"} 1027 1395066363000
http_requests_total{method="POST",path="/a}b \"c\""} 3
# TYPE temperature_celsius gauge
temperature_celsius 21.5
# TYPE request_seconds histogram
request_seconds_bucket{le="0.1"} 5
request_seconds_bucket{le="+Inf"} 9
request_seconds_sum 1.5
request_seconds_count 9
request_seconds_created 1700000000
# TYPE rpc_seconds summary
rpc_seconds{quantile="0.99"} 0.25
rpc_seconds_count 40
# TYPE queue_depth gauge
queue_depth NaN
queue_limit +Inf
untyped_thing 4
# EOF
"#;

    /// OpenMetrics names a counter's family, and its line adds `_total`.
    const OPENMETRICS: &str = "# TYPE jobs counter
jobs_total 12
jobs_created 1700000000
";

    #[test]
    fn a_page_becomes_a_row_for_itself_and_a_list_for_each_series() {
        let rows = read(PAGE, &page(&[], 100)).unwrap();
        assert_eq!(
            Value::Array(rows),
            json!([
                { "name": "app:9100", "up": 1, "dropped": 0 },
                [r#"app:9100 http_requests_total{method="GET",code="200"}"#, 1027.0, true],
                [r#"app:9100 http_requests_total{method="POST",path="/a}b \"c\""}"#, 3.0, true],
                ["app:9100 temperature_celsius", 21.5, false],
                ["app:9100 request_seconds_sum", 1.5, true],
                ["app:9100 request_seconds_count", 9.0, true],
                [r#"app:9100 rpc_seconds{quantile="0.99"}"#, 0.25, false],
                ["app:9100 rpc_seconds_count", 40.0, true],
                ["app:9100 untyped_thing", 4.0, false],
            ])
        );
    }

    #[test]
    fn a_counter_is_a_total_however_its_type_is_given() {
        let rows = read(OPENMETRICS, &page(&[], 100)).unwrap();
        assert_eq!(rows[1..], [json!(["app:9100 jobs_total", 12.0, true])]);
    }

    #[test]
    fn only_wanted_metrics_are_kept() {
        let rows = read(PAGE, &page(&["http_*", "temperature_celsius"], 100)).unwrap();
        let names: Vec<&str> = rows[1..].iter().filter_map(|row| row[0].as_str()).collect();
        assert_eq!(
            names,
            [
                r#"app:9100 http_requests_total{method="GET",code="200"}"#,
                r#"app:9100 http_requests_total{method="POST",path="/a}b \"c\""}"#,
                "app:9100 temperature_celsius",
            ]
        );
        assert_eq!(rows[0]["dropped"], 0);
    }

    #[test]
    fn series_past_the_limit_are_counted_not_kept() {
        let rows = read(PAGE, &page(&[], 3)).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows[0],
            json!({ "name": "app:9100", "up": 1, "dropped": 5 })
        );

        // A name too long to pick in an alert rule is dropped too.
        let long = format!("thing{{label=\"{}\"}} 1\nthing 2\n", "x".repeat(300));
        let rows = read(&long, &page(&[], 100)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["dropped"], 1);
    }

    #[test]
    fn a_page_of_something_else_has_no_metrics() {
        for other in [
            "<html><body><h1>It works!</h1></body></html>",
            "Active connections: 291\nserver accepts handled requests\n 16630948 16630948 31070465\n",
            "",
        ] {
            assert_eq!(read(other, &page(&[], 100)), Err(NO_METRICS), "{other}");
        }
    }

    fn page(wanted: &[&str], max_series: usize) -> Page {
        let wanted: Vec<String> = wanted.iter().map(|name| name.to_string()).collect();
        Page::new(
            "http://app:9100/metrics".to_string(),
            &wanted,
            max_series,
            None,
        )
    }

    #[test]
    fn a_series_that_went_away_is_forgotten() {
        let mut totals = Totals::default();
        let kept = |names: &[&str]| -> Vec<Value> {
            let mut kept = vec![json!({ "name": "app:9100", "up": 1, "dropped": 0 })];
            kept.extend(names.iter().map(|name| json!([name, 5.0, true])));
            kept.push(json!(["level", 1.5, false]));
            kept
        };

        totals.settle(kept(&["a", "b"]));
        totals.settle(kept(&["b"]));
        assert_eq!(totals.0.len(), 1);

        // Back again, with nothing to compare with.
        assert_eq!(
            totals.settle(kept(&["a", "b"])),
            [
                json!({ "name": "app:9100", "up": 1, "dropped": 0 }),
                json!({ "name": "b", "change": 0.0 }),
                json!({ "name": "level", "value": 1.5 }),
            ]
        );
    }
}
