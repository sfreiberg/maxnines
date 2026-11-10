//! Web servers' own status pages: Apache's `mod_status`, nginx's `stub_status`
//! and PHP-FPM's pool status. Each collector reads the pages it's told to, or the
//! usual address when it isn't told, and reports what they say as numbers. One
//! request gives everything a page has, however many numbers that is.
//!
//! Running totals, such as requests served, are turned into the change since the
//! last sample here, as the server expects for a rate. A page that stops answering
//! starts afresh when it's back, rather than counting the gap as one burst.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use maxnines_checks::fetch_page;
use maxnines_collectors::system::Change;
use maxnines_protocol::default_status_page;
use serde_json::{Map, Value, json};

use crate::background::{Background, probe_all};
use crate::collector::Collector;

/// A status page is a few lines served by the machine itself, so anything slower
/// than this is a server in trouble.
const TIMEOUT: Duration = Duration::from_secs(10);

const TIMED_OUT: &str = "timed out";
const NOT_APACHE: &str = "the page isn't Apache's machine-readable status page";
const NOT_NGINX: &str = "the page isn't nginx's stub_status page";
const NOT_PHP_FPM: &str = "the page isn't PHP-FPM's status page";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Software {
    Apache,
    Nginx,
    PhpFpm,
}

/// What a page said. Levels are reported as they are, and running totals as the
/// change since the last sample.
#[derive(Debug, Default, PartialEq)]
struct Reading {
    levels: BTreeMap<&'static str, f64>,
    totals: BTreeMap<&'static str, u64>,
}

impl Software {
    pub fn from_collector(name: &str) -> Option<Self> {
        match name {
            "apache" => Some(Self::Apache),
            "nginx" => Some(Self::Nginx),
            "php_fpm" => Some(Self::PhpFpm),
            _ => None,
        }
    }

    fn collector(self) -> &'static str {
        match self {
            Self::Apache => "apache",
            Self::Nginx => "nginx",
            Self::PhpFpm => "php_fpm",
        }
    }

    /// Apache only gives the version meant for programs when asked with `?auto`,
    /// which is easy to leave off, so it's added.
    fn request_url(self, url: &str) -> String {
        if self != Self::Apache {
            return url.to_string();
        }
        let (page, fragment) = url.split_once('#').unwrap_or((url, ""));
        let asked = page
            .split_once('?')
            .is_some_and(|(_, query)| query.split('&').any(|part| part == "auto"));
        let mut request = if asked {
            page.to_string()
        } else if page.contains('?') {
            format!("{page}&auto")
        } else {
            format!("{page}?auto")
        };
        if !fragment.is_empty() {
            request = format!("{request}#{fragment}");
        }
        request
    }

    fn read(self, text: &str) -> Result<Reading, &'static str> {
        match self {
            Self::Apache => read_apache(text),
            Self::Nginx => read_nginx(text),
            Self::PhpFpm => read_php_fpm(text),
        }
    }
}

/// What a page is called on charts: its address without the query, which is
/// only ever options such as `?auto` or `?json`.
fn label(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or(url).to_string()
}

/// `Name: value` lines, by name in lower case.
fn named_values(text: &str) -> BTreeMap<String, &str> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_lowercase(), value.trim()))
        .collect()
}

fn number(values: &BTreeMap<String, &str>, name: &str) -> Option<f64> {
    values
        .get(name)?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

fn total(values: &BTreeMap<String, &str>, name: &str) -> Option<u64> {
    values.get(name)?.parse().ok()
}

impl Reading {
    fn level(&mut self, name: &'static str, value: Option<f64>) {
        if let Some(value) = value {
            self.levels.insert(name, value);
        }
    }

    fn total(&mut self, name: &'static str, value: Option<u64>) {
        if let Some(value) = value {
            self.totals.insert(name, value);
        }
    }
}

/// The page `mod_status` gives with `?auto`. Totals need `ExtendedStatus`, which
/// is on by default, and connections only come from the event MPM.
fn read_apache(text: &str) -> Result<Reading, &'static str> {
    let values = named_values(text);
    let busy = number(&values, "busyworkers").ok_or(NOT_APACHE)?;
    let mut reading = Reading::default();
    reading.level("busy_workers", Some(busy));
    reading.level("idle_workers", number(&values, "idleworkers"));
    // One character per worker slot, whatever it's doing.
    let slots = values
        .get("scoreboard")
        .map(|board| board.chars().count() as f64);
    reading.level("worker_slots", slots.filter(|slots| *slots > 0.0));
    reading.level("connections", number(&values, "connstotal"));
    reading.level("cpu_load", number(&values, "cpuload"));
    let uptime = number(&values, "serveruptimeseconds").or_else(|| number(&values, "uptime"));
    reading.level("uptime_secs", uptime);
    reading.total("requests", total(&values, "total accesses"));
    let bytes = total(&values, "total kbytes").map(|kilobytes| kilobytes.saturating_mul(1024));
    reading.total("bytes", bytes);
    Ok(reading)
}

/// `stub_status`, which looks like this:
///
/// ```text
/// Active connections: 291
/// server accepts handled requests
///  16630948 16630948 31070465
/// Reading: 6 Writing: 179 Waiting: 106
/// ```
fn read_nginx(text: &str) -> Result<Reading, &'static str> {
    let mut reading = Reading::default();
    let mut lines = text.lines().map(str::trim);
    let mut counted = false;
    while let Some(line) = lines.next() {
        if let Some(active) = line.strip_prefix("Active connections:") {
            reading.level("connections", active.trim().parse().ok());
        } else if line == "server accepts handled requests" {
            let counts: Vec<u64> = lines
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|count| count.parse().ok())
                .collect();
            if let [accepted, handled, requests] = counts[..] {
                reading.total("accepted", Some(accepted));
                // Accepted and never handled means nginx ran out of connections.
                reading.total("dropped", Some(accepted.saturating_sub(handled)));
                reading.total("requests", Some(requests));
                counted = true;
            }
        } else if line.starts_with("Reading:") {
            let words: Vec<&str> = line.split_whitespace().collect();
            for pair in words.chunks(2) {
                let [name, value] = pair else { continue };
                let name = match *name {
                    "Reading:" => "reading",
                    "Writing:" => "writing",
                    "Waiting:" => "waiting",
                    _ => continue,
                };
                reading.level(name, value.parse().ok());
            }
        }
    }
    if !counted || !reading.levels.contains_key("connections") {
        return Err(NOT_NGINX);
    }
    Ok(reading)
}

/// A pool's status, as plain text or as JSON with `?json`. Both use the same
/// names, such as `accepted conn`.
fn read_php_fpm(text: &str) -> Result<Reading, &'static str> {
    // JSON's numbers are written out again, so both forms are read the same way.
    let numbers: BTreeMap<String, String>;
    let values: BTreeMap<String, &str> = if text.trim_start().starts_with('{') {
        let json: Map<String, Value> = serde_json::from_str(text).map_err(|_| NOT_PHP_FPM)?;
        numbers = json
            .into_iter()
            .filter(|(_, value)| value.is_number())
            .map(|(name, value)| (name, value.to_string()))
            .collect();
        numbers
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str()))
            .collect()
    } else {
        named_values(text)
    };
    let level = |name: &str| number(&values, name);
    let count = |name: &str| total(&values, name);

    let requests = count("accepted conn").ok_or(NOT_PHP_FPM)?;
    let mut reading = Reading::default();
    reading.total("requests", Some(requests));
    reading.total("max_children_reached", count("max children reached"));
    reading.total("slow_requests", count("slow requests"));
    reading.level("listen_queue", level("listen queue"));
    reading.level("idle_processes", level("idle processes"));
    reading.level("active_processes", level("active processes"));
    reading.level("total_processes", level("total processes"));
    reading.level("uptime_secs", level("start since"));
    Ok(reading)
}

struct Page {
    software: Software,
    url: String,
    label: String,
}

/// One row per page. Totals are kept to one side for [`StatusPageCollector`] to
/// turn into changes.
async fn read_page(page: Arc<Page>) -> Value {
    let read = match fetch_page(&page.software.request_url(&page.url), TIMEOUT).await {
        Ok(text) => page.software.read(&text).map_err(str::to_string),
        Err(error) => Err(format!("{error:#}")),
    };
    match read {
        Ok(reading) => {
            let mut row = json!({ "name": page.label, "up": 1, "totals": reading.totals });
            for (name, value) in reading.levels {
                row[name] = json!(value);
            }
            row
        }
        Err(error) => failed(&page.label, &error),
    }
}

fn failed(label: &str, error: &str) -> Value {
    json!({ "name": label, "up": 0, "error": error })
}

pub struct StatusPageCollector {
    software: Software,
    background: Background,
    /// The last total seen for each page and number.
    totals: BTreeMap<(String, String), Change>,
}

impl StatusPageCollector {
    pub fn new(software: Software, urls: Vec<String>, interval: Duration) -> Self {
        let urls = if urls.is_empty() {
            default_status_page(software.collector())
                .map(str::to_string)
                .into_iter()
                .collect()
        } else {
            urls
        };
        let pages: Vec<Arc<Page>> = urls
            .into_iter()
            .map(|url| {
                Arc::new(Page {
                    software,
                    label: label(&url),
                    url,
                })
            })
            .collect();
        let background = Background::start(interval, move || {
            let pages = pages.clone();
            async move {
                let timed_out = |page: &Page| failed(&page.label, TIMED_OUT);
                Value::Array(probe_all(&pages, interval, TIMEOUT, read_page, timed_out).await)
            }
        });
        Self {
            software,
            background,
            totals: BTreeMap::new(),
        }
    }

    /// Swaps a row's running totals for the change since the last sample. The
    /// first sample of a page has nothing to compare with, so it has none.
    fn settle(&mut self, row: &mut Value) {
        let Some(fields) = row.as_object_mut() else {
            return;
        };
        let name = fields
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let totals = fields.remove("totals");
        let Some(Value::Object(totals)) = totals else {
            self.totals.retain(|(page, _), _| *page != name);
            return;
        };
        for (field, value) in totals {
            let change = self
                .totals
                .entry((name.clone(), field.clone()))
                .or_default()
                .update(value.as_u64());
            if let Some(change) = change {
                fields.insert(field, json!(change));
            }
        }
    }
}

impl Collector for StatusPageCollector {
    fn name(&self) -> &'static str {
        self.software.collector()
    }

    fn collect(&mut self) -> Result<Value> {
        let mut pages = self.background.latest();
        if let Value::Array(rows) = &mut pages {
            for row in rows {
                self.settle(row);
            }
        }
        Ok(pages)
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

    const APACHE: &str = "localhost
ServerVersion: Apache/2.4.62 (Debian)
ServerMPM: event
ServerUptimeSeconds: 86400
Uptime: 86400
Load1: 0.10
Total Accesses: 12000
Total kBytes: 2048
Total Duration: 5000
CPULoad: .0234
ReqPerSec: .138889
BusyWorkers: 3
GracefulWorkers: 0
IdleWorkers: 72
ConnsTotal: 4
ConnsAsyncWriting: 0
ConnsAsyncKeepAlive: 1
ConnsAsyncClosing: 0
Scoreboard: __W_K___.......
";

    const NGINX: &str = "Active connections: 291
server accepts handled requests
 16630948 16630940 31070465
Reading: 6 Writing: 179 Waiting: 106
";

    const PHP_FPM: &str = "pool:                 www
process manager:      dynamic
start time:           08/Nov/2026:09:00:00 +0000
start since:          3600
accepted conn:        5000
listen queue:         2
max listen queue:     9
listen queue len:     511
idle processes:       4
active processes:     1
total processes:      5
max active processes: 5
max children reached: 1
slow requests:        7
";

    fn reading(levels: &[(&'static str, f64)], totals: &[(&'static str, u64)]) -> Reading {
        Reading {
            levels: levels.iter().copied().collect(),
            totals: totals.iter().copied().collect(),
        }
    }

    #[test]
    fn apache_says_how_busy_its_workers_are() {
        assert_eq!(
            read_apache(APACHE).unwrap(),
            reading(
                &[
                    ("busy_workers", 3.0),
                    ("idle_workers", 72.0),
                    ("worker_slots", 15.0),
                    ("connections", 4.0),
                    ("cpu_load", 0.0234),
                    ("uptime_secs", 86400.0),
                ],
                &[("requests", 12000), ("bytes", 2048 * 1024)],
            )
        );
    }

    #[test]
    fn apache_without_extended_status_still_counts_workers() {
        let plain = "BusyWorkers: 1\nIdleWorkers: 9\nScoreboard: W_________\n";
        assert_eq!(
            read_apache(plain).unwrap(),
            reading(
                &[
                    ("busy_workers", 1.0),
                    ("idle_workers", 9.0),
                    ("worker_slots", 10.0)
                ],
                &[],
            )
        );
    }

    #[test]
    fn apache_asked_without_auto_is_asked_with_it() {
        let apache = Software::Apache;
        let asked = |url| apache.request_url(url);
        assert_eq!(
            asked("http://localhost/server-status"),
            "http://localhost/server-status?auto"
        );
        assert_eq!(
            asked("http://localhost/server-status?auto"),
            "http://localhost/server-status?auto"
        );
        assert_eq!(
            asked("http://localhost/server-status?refresh=5"),
            "http://localhost/server-status?refresh=5&auto"
        );
        assert_eq!(
            asked("http://localhost/status?automatic"),
            "http://localhost/status?automatic&auto"
        );
        assert_eq!(
            Software::Nginx.request_url("http://localhost/nginx_status"),
            "http://localhost/nginx_status"
        );
    }

    #[test]
    fn the_page_for_people_is_not_mistaken_for_numbers() {
        let html = "<html><body><h1>Apache Server Status</h1></body></html>";
        assert_eq!(read_apache(html), Err(NOT_APACHE));
        assert_eq!(read_nginx(html), Err(NOT_NGINX));
        assert_eq!(read_php_fpm(html), Err(NOT_PHP_FPM));
        assert_eq!(read_nginx(APACHE), Err(NOT_NGINX));
        assert_eq!(read_php_fpm(NGINX), Err(NOT_PHP_FPM));
    }

    #[test]
    fn nginx_counts_connections_and_what_it_dropped() {
        assert_eq!(
            read_nginx(NGINX).unwrap(),
            reading(
                &[
                    ("connections", 291.0),
                    ("reading", 6.0),
                    ("writing", 179.0),
                    ("waiting", 106.0),
                ],
                &[
                    ("accepted", 16630948),
                    ("dropped", 8),
                    ("requests", 31070465)
                ],
            )
        );
    }

    #[test]
    fn php_fpm_reads_the_same_from_text_and_json() {
        let expected = reading(
            &[
                ("listen_queue", 2.0),
                ("idle_processes", 4.0),
                ("active_processes", 1.0),
                ("total_processes", 5.0),
                ("uptime_secs", 3600.0),
            ],
            &[
                ("requests", 5000),
                ("max_children_reached", 1),
                ("slow_requests", 7),
            ],
        );
        assert_eq!(read_php_fpm(PHP_FPM).unwrap(), expected);
        let json = r#"{"pool":"www","process manager":"dynamic","start time":1762592400,
            "start since":3600,"accepted conn":5000,"listen queue":2,"max listen queue":9,
            "listen queue len":511,"idle processes":4,"active processes":1,
            "total processes":5,"max active processes":5,"max children reached":1,
            "slow requests":7}"#;
        assert_eq!(read_php_fpm(json).unwrap(), expected);
        assert_eq!(read_php_fpm("{ not json"), Err(NOT_PHP_FPM));
    }

    #[test]
    fn pages_are_named_without_their_options() {
        assert_eq!(
            label("http://localhost/server-status?auto"),
            "http://localhost/server-status"
        );
        assert_eq!(
            label("http://127.0.0.1:8080/fpm#x"),
            "http://127.0.0.1:8080/fpm"
        );
    }

    /// A page that answers every request with the body the test has moved it on to.
    struct Served {
        address: String,
        showing: Arc<AtomicUsize>,
    }

    impl Served {
        fn show(&self, body: usize) {
            self.showing.store(body, Ordering::Relaxed);
        }
    }

    /// Serves the first of `bodies`, or nothing if there are none, until told to
    /// move on, so what the collector reads doesn't depend on how fast it reads.
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
                let body = bodies
                    .get(shown.load(Ordering::Relaxed))
                    .or(bodies.last())
                    .copied()
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Served { address, showing }
    }

    fn collect_until(collector: &mut StatusPageCollector, done: impl Fn(&Value) -> bool) -> Value {
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

    #[test]
    fn totals_become_the_change_since_the_last_sample() {
        let first = "Active connections: 1\nserver accepts handled requests\n 10 10 100\nReading: 0 Writing: 1 Waiting: 0\n";
        let second = "Active connections: 2\nserver accepts handled requests\n 15 14 130\nReading: 0 Writing: 1 Waiting: 1\n";
        let served = serve(vec![first, second]);
        let address = &served.address;
        let url = format!("http://{address}/nginx_status");
        let mut collector =
            StatusPageCollector::new(Software::Nginx, vec![url], Duration::from_millis(200));

        let output = collect_until(&mut collector, |output| output[0]["connections"] == 1.0);
        let page = &output[0];
        assert_eq!(page["name"], format!("http://{address}/nginx_status"));
        assert_eq!(page["up"], 1);
        // Nothing to compare with yet.
        assert!(page.get("requests").is_none(), "{page}");
        assert!(page.get("totals").is_none(), "{page}");

        served.show(1);
        let output = collect_until(&mut collector, |output| output[0]["connections"] == 2.0);
        let page = &output[0];
        assert_eq!(page["requests"], 30);
        assert_eq!(page["accepted"], 5);
        assert_eq!(page["dropped"], 1);
    }

    #[test]
    fn a_page_that_cannot_be_read_says_why() {
        let address = serve(vec!["<html>It works!</html>"]).address;
        let url = format!("http://{address}/server-status");
        let mut collector =
            StatusPageCollector::new(Software::Apache, vec![url], Duration::from_millis(200));
        let output = collect_until(&mut collector, |output| output.is_array());
        assert_eq!(output[0]["up"], 0);
        assert_eq!(output[0]["error"], NOT_APACHE);
    }

    #[test]
    fn a_page_that_stops_answering_starts_its_totals_afresh() {
        let address = serve(vec![]).address;
        let page =
            |requests: u64| json!({ "name": "p", "up": 1, "totals": { "requests": requests } });
        let mut collector = StatusPageCollector::new(
            Software::Nginx,
            vec![format!("http://{address}/")],
            Duration::from_secs(3600),
        );
        let mut row = page(100);
        collector.settle(&mut row);
        let mut row = page(150);
        collector.settle(&mut row);
        assert_eq!(row["requests"], 50);

        let mut down = failed("p", TIMED_OUT);
        collector.settle(&mut down);
        let mut row = page(900);
        collector.settle(&mut row);
        assert!(row.get("requests").is_none(), "{row}");
    }
}
