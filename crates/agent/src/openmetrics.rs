//! Metrics pages in the Prometheus and OpenMetrics text format, which most
//! software that can be monitored either serves itself or has an exporter for.
//! Each line of a page is a series: a metric, its labels and a number.
//!
//! Every series is reported under its page's name and the line as the page wrote
//! it, such as `localhost:9100 http_requests_total{code="200"}`. Running totals,
//! which is what counters are, become the change since the last sample, as the
//! server expects for a rate. Histograms' buckets are left out, which leaves their
//! sum and count, enough for an average.
//!
//! A page can be any size, so what's kept of it is bounded: it's read in one pass
//! into the rows that are sent, and nothing else of it is held between rounds.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use maxnines_checks::fetch_page;
use maxnines_protocol::metrics_page_name;
use serde_json::{Value, json};
use wildmatch::WildMatch;

use crate::background::{Background, probe_all};
use crate::collector::Collector;

const TIMEOUT: Duration = Duration::from_secs(10);

/// How many series the collector reports, shared equally between its pages. A
/// sample has to fit in one message to the server, and an exporter can list tens
/// of thousands.
const MAX_SERIES: usize = 2_000;

/// The longest name an alert rule can pick a series by.
const MAX_NAME_BYTES: usize = 255;

const TIMED_OUT: &str = "timed out";
const NO_METRICS: &str = "the page has no metrics in the OpenMetrics format";

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

struct Page {
    url: String,
    name: String,
    /// The metrics to keep, or all of them when there are none.
    wanted: Arc<[WildMatch]>,
    max_series: usize,
}

impl Page {
    fn wants(&self, metric: &str) -> bool {
        self.wanted.is_empty() || self.wanted.iter().any(|pattern| pattern.matches(metric))
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

/// A page's rows: one for the page itself, then one for each series kept.
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
        rows.push(match reported {
            Reported::Level => json!({ "name": name, "value": number }),
            Reported::Total => json!({ "name": name, "total": number }),
        });
    }

    if !found {
        return Err(NO_METRICS);
    }
    rows[0] = json!({ "name": page.name, "up": 1, "dropped": dropped });
    Ok(rows)
}

async fn read_page(page: Arc<Page>) -> Vec<Value> {
    let read = match fetch_page(&page.url, TIMEOUT).await {
        Ok(text) => read(&text, &page).map_err(str::to_string),
        Err(error) => Err(format!("{error:#}")),
    };
    read.unwrap_or_else(|error| failed(&page, &error))
}

fn failed(page: &Page, error: &str) -> Vec<Value> {
    vec![json!({ "name": page.name, "up": 0, "error": error })]
}

pub struct OpenMetricsCollector {
    background: Background,
    /// The last total seen for each series.
    totals: HashMap<String, f64>,
}

impl OpenMetricsCollector {
    pub fn new(urls: Vec<String>, wanted: &[String], interval: Duration) -> Self {
        let wanted: Arc<[WildMatch]> = wanted.iter().map(|name| WildMatch::new(name)).collect();
        let max_series = MAX_SERIES / urls.len().max(1);
        let pages: Vec<Arc<Page>> = urls
            .into_iter()
            .map(|url| {
                Arc::new(Page {
                    name: metrics_page_name(&url).to_string(),
                    url,
                    wanted: wanted.clone(),
                    max_series,
                })
            })
            .collect();
        let background = Background::start(interval, move || {
            let pages = pages.clone();
            async move {
                let timed_out = |page: &Page| failed(page, TIMED_OUT);
                let rows = probe_all(&pages, interval, TIMEOUT, read_page, timed_out).await;
                Value::Array(rows.into_iter().flatten().collect())
            }
        });
        Self {
            background,
            totals: HashMap::new(),
        }
    }

    /// Swaps each running total for its change since the last sample, and leaves
    /// out a series seen for the first time, which has nothing to compare with. A
    /// total that went backwards started again, which counts as no change.
    ///
    /// Only the totals in this sample are remembered, so a series that's gone, or
    /// a whole page that stopped answering, starts afresh if it comes back.
    fn settle(&mut self, rows: &mut Vec<Value>) {
        let mut seen = HashMap::with_capacity(self.totals.len());
        rows.retain_mut(|row| {
            let Some(fields) = row.as_object_mut() else {
                return false;
            };
            let Some(total) = fields.remove("total").and_then(|total| total.as_f64()) else {
                return true;
            };
            let Some(name) = fields.get("name").and_then(Value::as_str) else {
                return false;
            };
            let (name, last) = match self.totals.remove_entry(name) {
                Some((name, last)) => (name, Some(last)),
                None => (name.to_string(), None),
            };
            seen.insert(name, total);
            if let Some(last) = last {
                fields.insert("change".to_string(), json!((total - last).max(0.0)));
            }
            last.is_some()
        });
        self.totals = seen;
    }
}

impl Collector for OpenMetricsCollector {
    fn name(&self) -> &'static str {
        "openmetrics"
    }

    fn collect(&mut self) -> Result<Value> {
        let mut rows = self.background.latest();
        if let Value::Array(rows) = &mut rows {
            self.settle(rows);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

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

    fn page(wanted: &[&str], max_series: usize) -> Page {
        Page {
            url: String::new(),
            name: "app:9100".to_string(),
            wanted: wanted.iter().map(|name| WildMatch::new(name)).collect(),
            max_series,
        }
    }

    #[test]
    fn a_page_becomes_a_row_for_itself_and_one_for_each_series() {
        let rows = read(PAGE, &page(&[], 100)).unwrap();
        assert_eq!(
            Value::Array(rows),
            json!([
                { "name": "app:9100", "up": 1, "dropped": 0 },
                { "name": r#"app:9100 http_requests_total{method="GET",code="200"}"#, "total": 1027.0 },
                { "name": r#"app:9100 http_requests_total{method="POST",path="/a}b \"c\""}"#, "total": 3.0 },
                { "name": "app:9100 temperature_celsius", "value": 21.5 },
                { "name": "app:9100 request_seconds_sum", "total": 1.5 },
                { "name": "app:9100 request_seconds_count", "total": 9.0 },
                { "name": r#"app:9100 rpc_seconds{quantile="0.99"}"#, "value": 0.25 },
                { "name": "app:9100 rpc_seconds_count", "total": 40.0 },
                { "name": "app:9100 untyped_thing", "value": 4.0 },
            ])
        );
    }

    #[test]
    fn a_counter_is_a_total_however_its_type_is_given() {
        let rows = read(OPENMETRICS, &page(&[], 100)).unwrap();
        assert_eq!(
            rows[1..],
            [json!({ "name": "app:9100 jobs_total", "total": 12.0 })]
        );
    }

    #[test]
    fn only_wanted_metrics_are_kept() {
        let rows = read(PAGE, &page(&["http_*", "temperature_celsius"], 100)).unwrap();
        let names: Vec<&str> = rows[1..]
            .iter()
            .filter_map(|row| row["name"].as_str())
            .collect();
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

    /// A page that answers every request with the body the test has moved it on to.
    struct Served {
        address: String,
        showing: Arc<AtomicUsize>,
    }

    /// Serves the first of `bodies` until told to move on, so what the collector
    /// reads doesn't depend on how fast it reads.
    fn serve(bodies: Vec<&'static str>) -> Served {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let showing = Arc::new(AtomicUsize::new(0));
        let shown = Arc::clone(&showing);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // The whole request goes first: closing with some of it unread makes
                // Windows reset the connection, losing the answer.
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(size) => request.extend_from_slice(&buffer[..size]),
                    }
                }
                let body = bodies[shown.load(Ordering::Relaxed).min(bodies.len() - 1)];
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Served { address, showing }
    }

    fn collect_until(collector: &mut OpenMetricsCollector, done: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let output = collector.collect().unwrap();
            if done(&output) {
                return output;
            }
            assert!(Instant::now() < deadline, "gave up waiting: {output}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn row<'a>(output: &'a Value, name: &str) -> Option<&'a Value> {
        output.as_array()?.iter().find(|row| row["name"] == name)
    }

    #[test]
    fn totals_become_the_change_since_the_last_sample() {
        let first = "# TYPE jobs_total counter\njobs_total 100\n# TYPE restarts_total counter\nrestarts_total 7\nqueue 1\n";
        let second = "# TYPE jobs_total counter\njobs_total 130\n# TYPE restarts_total counter\nrestarts_total 2\nqueue 2\n";
        let served = serve(vec![first, second]);
        let address = &served.address;
        let url = format!("http://{address}/metrics");
        let mut collector = OpenMetricsCollector::new(vec![url], &[], Duration::from_millis(200));
        let named = |series: &str| format!("{address} {series}");

        let output = collect_until(&mut collector, |output| {
            row(output, &named("queue")).is_some_and(|queue| queue["value"] == 1.0)
        });
        assert_eq!(
            row(&output, address),
            Some(&json!({ "name": address, "up": 1, "dropped": 0 }))
        );
        // Nothing to compare with yet.
        assert_eq!(row(&output, &named("jobs_total")), None, "{output}");

        served.showing.store(1, Ordering::Relaxed);
        let output = collect_until(&mut collector, |output| {
            row(output, &named("queue")).is_some_and(|queue| queue["value"] == 2.0)
        });
        assert_eq!(
            row(&output, &named("jobs_total")),
            Some(&json!({ "name": named("jobs_total"), "change": 30.0 }))
        );
        // It went backwards, so whatever it counts started again.
        assert_eq!(
            row(&output, &named("restarts_total")).unwrap()["change"],
            0.0
        );
    }

    #[test]
    fn a_page_that_cannot_be_read_says_why() {
        let address = serve(vec!["<html>It works!</html>"]).address;
        // Nothing can listen on port 0.
        let closed = "127.0.0.1:0";
        let urls = vec![
            format!("http://{address}/metrics"),
            format!("http://{closed}/metrics"),
        ];
        let mut collector = OpenMetricsCollector::new(urls, &[], Duration::from_millis(200));

        let output = collect_until(&mut collector, |output| output.is_array());

        assert_eq!(
            output[0],
            json!({ "name": address, "up": 0, "error": NO_METRICS })
        );
        assert_eq!(output[1]["name"], closed);
        assert_eq!(output[1]["up"], 0);
        assert!(output[1]["error"].is_string(), "{output}");
    }

    #[test]
    fn a_series_that_went_away_is_forgotten() {
        let mut collector = OpenMetricsCollector::new(Vec::new(), &[], Duration::from_secs(3600));
        let sample = |names: &[&str]| -> Vec<Value> {
            names
                .iter()
                .map(|name| json!({ "name": name, "total": 5.0 }))
                .collect()
        };

        collector.settle(&mut sample(&["a", "b"]));
        collector.settle(&mut sample(&["b"]));
        assert_eq!(collector.totals.len(), 1);

        // Back again, with nothing to compare with.
        let mut rows = sample(&["a", "b"]);
        collector.settle(&mut rows);
        assert_eq!(rows, [json!({ "name": "b", "change": 0.0 })]);
    }
}
