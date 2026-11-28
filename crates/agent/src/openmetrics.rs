//! Reads the OpenMetrics pages a config rule lists, with every sample. How a page
//! is read is in [`maxnines_checks::openmetrics`], which the server shares.
//!
//! A page with nothing to sign in with comes whole from the server. One that asks
//! for a username and password, or a token, is an `openmetrics` block in the
//! agent's own config, with its address and its login, and the server only picks
//! it by name. So a login never comes from the server, never goes to it, and is
//! only ever sent to the address beside it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use maxnines_checks::Login;
use maxnines_checks::openmetrics::{MAX_SERIES, Page, TIMED_OUT, TIMEOUT, Totals};
use maxnines_collectors::entries::{Entries, at, filled};
use maxnines_protocol::entries::Entry;
use maxnines_protocol::{check_metrics_pages, is_page_name};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::background::{Background, FAILED_UNEXPECTEDLY, Missed};
use crate::collector::Collector;

/// How many pages the agent's config can define.
const MAX_DEFINED: usize = 64;

/// A page the agent's config allows, with how to sign in to it: a username and
/// password, or a token. Its series are named by the block's name.
///
/// ```hcl
/// openmetrics "node" {
///   url      = "http://localhost:9100/metrics"
///   username = "metrics"
///   password = env("METRICS_PASSWORD")
/// }
///
/// openmetrics "app" {
///   url   = "https://app.example.com/internal/metrics"
///   token = env("APP_METRICS_TOKEN")
/// }
/// ```
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageDefinition {
    url: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

impl fmt::Debug for PageDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageDefinition")
            .field("url", &self.url)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl PageDefinition {
    /// What to send the page, or what's wrong with what the config gives.
    fn login(&self, page: &str) -> Result<Login> {
        let (username, password) = (self.username.as_deref(), self.password.as_deref());
        if let Some(token) = &self.token {
            ensure!(
                username.is_none() && password.is_none(),
                "page {page:?} signs in with a username and password or a token, not both"
            );
            return Login::token(token).with_context(|| format!("the token for page {page:?}"));
        }
        // Basic authentication ends the username at the first colon.
        let Some(username) = username.filter(|name| !name.is_empty() && !name.contains(':')) else {
            bail!(
                "page {page:?} needs a username, without a colon, or a token. A page with \
                 nothing to sign in with goes in a config rule instead"
            );
        };
        let Some(password) = password.filter(|password| !password.is_empty()) else {
            bail!("page {page:?} needs a password");
        };
        Login::new(username, password)
    }
}

/// The pages the agent's config allows, by name.
pub type PageDefinitions = BTreeMap<String, PageDefinition>;

pub fn check_page_definitions(pages: &PageDefinitions) -> Result<()> {
    ensure!(
        pages.len() <= MAX_DEFINED,
        "the config can define at most {MAX_DEFINED} OpenMetrics pages"
    );
    for (name, page) in pages {
        ensure!(
            is_page_name(name),
            "{name:?} can't name an OpenMetrics page, as a page's name has no spaces"
        );
        check_metrics_pages(std::slice::from_ref(&page.url), &[])
            .with_context(|| format!("OpenMetrics page {name:?}"))?;
        page.login(name)?;
    }
    Ok(())
}

pub struct OpenMetricsCollector {
    background: Background,
}

impl OpenMetricsCollector {
    /// `urls` come whole from the server, and never sign in. `local` picks from
    /// the pages the agent's config defines.
    pub fn new(
        urls: Vec<String>,
        local: &[String],
        wanted: &[String],
        definitions: &PageDefinitions,
        interval: Duration,
    ) -> Result<Self> {
        let max_series = MAX_SERIES / (urls.len() + local.len()).max(1);
        let mut pages: Vec<Arc<Page>> = urls
            .into_iter()
            .map(|url| Arc::new(Page::new(url, wanted, max_series, None)))
            .collect();
        let mut background = Background::new();
        let mut missing = Vec::new();
        for name in local {
            match definitions.get(name) {
                Some(definition) => {
                    let login = definition.login(name)?;
                    let url = definition.url.clone();
                    let page = Page::named(name.clone(), url, wanted, max_series, Some(login));
                    pages.push(Arc::new(page));
                }
                None => missing.push(json!({
                    "name": name,
                    "up": 0,
                    "error": format!("the agent's config has no OpenMetrics page named {name:?}"),
                })),
            }
        }
        for page in pages {
            // Each page's running totals become changes as it's read.
            let mut totals = Totals::default();
            let read = page.clone();
            background.repeat(
                interval,
                Some(TIMEOUT),
                move || {
                    let page = read.clone();
                    async move { page.read().await }
                },
                move |rows| {
                    let rows = rows.unwrap_or_else(|missed| {
                        page.failed(match missed {
                            Missed::OutOfTime => TIMED_OUT,
                            Missed::Panicked => FAILED_UNEXPECTEDLY,
                        })
                    });
                    let read = running_totals(&rows);
                    Value::Array(with_totals(totals.settle(rows), &read))
                },
            )?;
        }
        // Pages a rule asked for that the agent's config doesn't have, which say so
        // with every sample.
        for row in missing {
            background.constant(row);
        }
        Ok(Self { background })
    }
}

impl Collector for OpenMetricsCollector {
    fn name(&self) -> &'static str {
        "openmetrics"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }

    fn metrics(&self) -> &'static [&'static str] {
        &OPENMETRICS_METRICS
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let rows = output.as_array().map(Vec::as_slice).unwrap_or_default();
        let named = rows
            .iter()
            .filter_map(|row| Some((row.get("name")?.as_str()?, row)));
        // Each series is named as its row is: a page by its name, and a line by its
        // page's name and the line, labels and all.
        for (name, row) in named {
            if row.get("up").is_some() {
                // A page that didn't answer is a value of whether it's up, and why
                // is the error of what it would have said of itself.
                entries.read("openmetrics.up", &[name], at(row, "up"));
                let dropped = at(row, "dropped");
                match filled(at(row, "error")).as_str() {
                    Some(why) if dropped.is_null() => {
                        entries.error("openmetrics.dropped", &[name], why);
                    }
                    _ => entries.read("openmetrics.dropped", &[name], dropped),
                }
            } else if row.get("change").is_some() {
                // The running total as the page gave it, not its change.
                entries.read("openmetrics.rate", &[name], at(row, "change_total"));
            } else {
                entries.read("openmetrics.value", &[name], at(row, "value"));
            }
        }
        // With no pages, none read yet, or none with a line of a metric's sort,
        // the metric has nothing.
        entries.fill(&OPENMETRICS_METRICS);
        entries.done()
    }
}

/// A page's metrics: whether it answered and how many series were over the limit,
/// then each of its lines, as a level or as a running total.
const OPENMETRICS_METRICS: [&str; 4] = [
    "openmetrics.up",
    "openmetrics.dropped",
    "openmetrics.value",
    "openmetrics.rate",
];

/// The running totals among what was read of a page, by series, before they're
/// settled into changes. A series listed twice keeps its first, as settling does.
fn running_totals(read: &[Value]) -> HashMap<String, Value> {
    let mut totals = HashMap::new();
    for row in read {
        if let Some([Value::String(name), total, Value::Bool(true)]) =
            row.as_array().map(Vec::as_slice)
        {
            totals.entry(name.clone()).or_insert_with(|| total.clone());
        }
    }
    totals
}

/// A sample's rows, each change with the running total it was worked out from
/// beside it, as `change_total`.
fn with_totals(mut rows: Vec<Value>, totals: &HashMap<String, Value>) -> Vec<Value> {
    for row in &mut rows {
        if row.get("change").is_none() {
            continue;
        }
        let total = row["name"].as_str().and_then(|name| totals.get(name));
        if let Some(total) = total {
            row["change_total"] = total.clone();
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    use maxnines_checks::openmetrics::NO_METRICS;
    use serde_json::json;

    use super::*;
    use crate::collector::test_entries::{every_metric_has_an_entry, said, time};

    /// A page that answers every request with the body the test has moved it on to.
    struct Served {
        address: String,
        showing: Arc<AtomicUsize>,
    }

    /// Serves the first of `bodies` until told to move on, so what the collector
    /// reads doesn't depend on how fast it reads.
    fn serve(bodies: Vec<&'static str>) -> Served {
        serve_to(bodies, None)
    }

    /// As [`serve`], but only to requests with this header, when there is one.
    fn serve_to(bodies: Vec<&'static str>, header: Option<&'static str>) -> Served {
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
                let request = String::from_utf8_lossy(&request).to_lowercase();
                let allowed = header.is_none_or(|header| request.contains(&header.to_lowercase()));
                let (status, body) = if allowed {
                    let body = bodies[shown.load(Ordering::Relaxed).min(bodies.len() - 1)];
                    ("200 OK", body)
                } else {
                    ("401 Unauthorized", "")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    fn totals_become_the_change_since_the_page_was_last_read() {
        let first = "# TYPE jobs_total counter\njobs_total 100\n# TYPE restarts_total counter\nrestarts_total 7\nqueue 1\n";
        let second = "# TYPE jobs_total counter\njobs_total 130\n# TYPE restarts_total counter\nrestarts_total 2\nqueue 2\n";
        let served = serve(vec![first, second]);
        let address = &served.address;
        let url = format!("http://{address}/metrics");
        let mut collector = OpenMetricsCollector::new(
            vec![url],
            &[],
            &[],
            &PageDefinitions::new(),
            Duration::from_millis(200),
        )
        .unwrap();
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
            Some(&json!({ "name": named("jobs_total"), "change": 30.0, "change_total": 130.0 }))
        );
        // It went backwards, so whatever it counts started again.
        let restarts = row(&output, &named("restarts_total")).unwrap();
        assert_eq!(restarts["change"], 0.0);
        assert_eq!(restarts["change_total"], 2.0);
    }

    /// Reading nothing, so nothing is reached.
    fn reading_nothing() -> OpenMetricsCollector {
        let interval = Duration::from_secs(3600);
        OpenMetricsCollector::new(Vec::new(), &[], &[], &PageDefinitions::new(), interval).unwrap()
    }

    #[test]
    fn page_entries_have_a_series_for_each_page_and_each_of_its_lines() {
        let collector = reading_nothing();
        let requests = r#"app:9100 http_requests_total{method="GET",code="200"}"#;
        let output = json!([
            { "name": "app:9100", "up": 1, "dropped": 5 },
            { "name": "app:9100 queue", "value": 1.5 },
            { "name": requests, "change": 30.0, "change_total": 1057.0 },
            // A change with no total beside it has nothing to give.
            { "name": "app:9100 jobs_total", "change": 2.0 },
            // A line whose number isn't one.
            { "name": "app:9100 odd" },
            // A page that didn't answer says why.
            { "name": "node", "up": 0, "error": "timed out" },
            // One without a name can't be told from the others.
            { "value": 2.0 },
        ]);
        let entries = collector.entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said(&entries),
            [
                (of("openmetrics.up[app:9100]"), json!(1)),
                (of("openmetrics.dropped[app:9100]"), json!(5)),
                (of("openmetrics.value[app:9100 queue]"), json!(1.5)),
                // The running total, under the line's own name with its labels.
                (format!("openmetrics.rate[{requests}]"), json!(1057.0)),
                (of("openmetrics.rate[app:9100 jobs_total]"), Value::Null),
                (of("openmetrics.value[app:9100 odd]"), Value::Null),
                // Not answering is what was found, and why is the error of what
                // the page would have said of itself.
                (of("openmetrics.up[node]"), json!(0)),
                (
                    of("openmetrics.dropped[node]"),
                    json!({ "error": "timed out" })
                ),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // A page with no lines kept leaves those metrics with nothing.
        let only_page = json!([{ "name": "app:9100", "up": 1, "dropped": 0 }]);
        let entries = collector.entries(&only_page, time());
        assert_eq!(
            said(&entries),
            [
                (of("openmetrics.up[app:9100]"), json!(1)),
                (of("openmetrics.dropped[app:9100]"), json!(0)),
                (of("openmetrics.value"), Value::Null),
                (of("openmetrics.rate"), Value::Null),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // With no pages, or none read yet, each metric has nothing.
        for output in [json!([]), Value::Null] {
            let none = collector.entries(&output, time());
            assert_eq!(
                said(&none),
                [
                    (of("openmetrics.up"), Value::Null),
                    (of("openmetrics.dropped"), Value::Null),
                    (of("openmetrics.value"), Value::Null),
                    (of("openmetrics.rate"), Value::Null),
                ]
            );
            every_metric_has_an_entry(&collector, &none);
        }
    }

    #[test]
    fn a_change_keeps_the_running_total_it_was_worked_out_from() {
        let page = json!({ "name": "app:9100", "up": 1, "dropped": 0 });
        let read = |jobs: f64| {
            vec![
                page.clone(),
                json!(["app:9100 jobs_total", jobs, true]),
                // Listed twice, which keeps its first.
                json!(["app:9100 jobs_total", 999.0, true]),
                json!(["app:9100 queue", 1.5, false]),
            ]
        };
        let mut totals = Totals::default();
        let mut sample = |jobs: f64| {
            let read = read(jobs);
            let running = running_totals(&read);
            with_totals(totals.settle(read), &running)
        };
        // The first has nothing to compare with, so it isn't there at all.
        assert_eq!(
            sample(100.0),
            [
                page.clone(),
                json!({ "name": "app:9100 queue", "value": 1.5 })
            ]
        );
        let rows = sample(130.0);
        let jobs = rows.iter().find(|row| row["name"] == "app:9100 jobs_total");
        assert_eq!(jobs.unwrap()["change_total"], 130.0, "{rows:?}");

        let collector = reading_nothing();
        let entries = collector.entries(&Value::Array(rows), time());
        assert!(
            said(&entries).contains(&(
                "openmetrics.rate[app:9100 jobs_total]".to_string(),
                json!(130.0)
            )),
            "{entries:?}"
        );
        every_metric_has_an_entry(&collector, &entries);
    }

    #[test]
    fn reading_no_pages_really_collects_nothing_for_each_metric() {
        let mut collector = reading_nothing();
        let output = collector.collect().unwrap();
        assert_eq!(output, json!([]));
        every_metric_has_an_entry(&collector, &collector.entries(&output, time()));
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
        let mut collector = OpenMetricsCollector::new(
            urls,
            &[],
            &[],
            &PageDefinitions::new(),
            Duration::from_millis(200),
        )
        .unwrap();

        let output = collect_until(&mut collector, |output| {
            output.as_array().is_some_and(|rows| rows.len() == 2)
        });

        assert_eq!(
            output[0],
            json!({ "name": address, "up": 0, "error": NO_METRICS })
        );
        assert_eq!(output[1]["name"], closed);
        assert_eq!(output[1]["up"], 0);
        assert!(output[1]["error"].is_string(), "{output}");
    }

    fn defined(url: &str, username: &str, password: &str) -> PageDefinition {
        let filled = |text: &str| Some(text.to_string()).filter(|text| !text.is_empty());
        PageDefinition {
            url: url.to_string(),
            username: filled(username),
            password: filled(password),
            token: None,
        }
    }

    fn with_token(url: &str, token: &str) -> PageDefinition {
        PageDefinition {
            url: url.to_string(),
            token: Some(token.to_string()),
            ..PageDefinition::default()
        }
    }

    fn read(urls: Vec<String>, local: &[&str], definitions: &PageDefinitions) -> Value {
        let local: Vec<String> = local.iter().map(|name| (*name).to_string()).collect();
        let interval = Duration::from_millis(200);
        let mut collector =
            OpenMetricsCollector::new(urls, &local, &[], definitions, interval).unwrap();
        collect_until(&mut collector, |output| output.is_array())
    }

    #[test]
    fn a_page_from_the_agents_config_signs_in_and_is_named_by_its_block() {
        // "metrics:s3cret", as basic authentication sends it.
        let served = serve_to(
            vec!["queue 1\n"],
            Some("authorization: Basic bWV0cmljczpzM2NyZXQ="),
        );
        let url = format!("http://{}/metrics", served.address);
        let definitions =
            PageDefinitions::from([("node".to_string(), defined(&url, "metrics", "s3cret"))]);

        let output = read(Vec::new(), &["node"], &definitions);
        assert_eq!(row(&output, "node").unwrap()["up"], 1, "{output}");
        assert_eq!(row(&output, "node queue").unwrap()["value"], 1.0);

        // The same address given by a rule never gets the login.
        let output = read(vec![url], &[], &definitions);
        assert_eq!(output[0]["error"], "the page returned status 401");
    }

    #[test]
    fn a_page_from_the_agents_config_can_sign_in_with_a_token() {
        let served = serve_to(vec!["queue 1\n"], Some("authorization: Bearer abc.DEF-123"));
        let url = format!("http://{}/metrics", served.address);
        let named =
            |token: &str| PageDefinitions::from([("app".to_string(), with_token(&url, token))]);

        let output = read(Vec::new(), &["app"], &named("abc.DEF-123"));
        assert_eq!(output[0]["up"], 1, "{output}");
        let output = read(Vec::new(), &["app"], &named("another"));
        assert_eq!(output[0]["error"], "the page returned status 401");
    }

    #[test]
    fn a_page_the_config_doesnt_have_says_so() {
        let output = read(Vec::new(), &["nowhere"], &PageDefinitions::new());
        assert_eq!(
            output,
            json!([{ "name": "nowhere", "up": 0, "error": "the agent's config has no OpenMetrics page named \"nowhere\"" }])
        );
    }

    #[test]
    fn a_defined_page_has_an_address_and_one_way_to_sign_in() {
        let one = |name: &str, page: PageDefinition| {
            check_page_definitions(&PageDefinitions::from([(name.to_string(), page)]))
        };
        let url = "http://localhost:9100/metrics";
        one("node", defined(url, "metrics", "s3cret: with a colon")).unwrap();
        // Anything can be in a password, as it's encoded before it's sent.
        one("node", defined(url, "metrics", "line\nbreak é")).unwrap();
        one("app", with_token(url, "abc.DEF-123_~+/=")).unwrap();
        for bad in ["", "two words", "line\nbreak", "caf\u{e9}"] {
            assert!(one("app", with_token(url, bad)).is_err(), "{bad:?}");
        }
        for (name, page, why) in [
            (
                "node",
                defined(url, "", ""),
                "goes in a config rule instead",
            ),
            ("node", defined(url, "a:b", "x"), "without a colon"),
            ("node", defined(url, "metrics", ""), "needs a password"),
            ("two words", defined(url, "metrics", "x"), "no spaces"),
            ("node", defined("localhost:9100", "metrics", "x"), "http://"),
            (
                "node",
                PageDefinition {
                    token: Some("abc".to_string()),
                    ..defined(url, "metrics", "s3cret")
                },
                "not both",
            ),
        ] {
            let error = format!("{:#}", one(name, page).unwrap_err());
            assert!(error.contains(why), "{name}: {error}");
        }
    }

    #[test]
    fn a_password_is_never_printed() {
        let printed = format!("{:?}", defined("http://a/metrics", "metrics", "s3cret"));
        assert!(printed.contains("metrics"), "{printed}");
        assert!(!printed.contains("s3cret"), "{printed}");
    }
}
