//! Reads the OpenMetrics pages a config rule lists, with every sample. How a page
//! is read is in [`maxnines_checks::openmetrics`], which the server shares.
//!
//! A page with nothing to sign in with comes whole from the server. One that asks
//! for a username and password, or a token, is an `openmetrics` block in the
//! agent's own config, with its address and its login, and the server only picks
//! it by name. So a login never comes from the server, never goes to it, and is
//! only ever sent to the address beside it.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use maxnines_checks::Login;
use maxnines_checks::openmetrics::{MAX_SERIES, Page, TIMED_OUT, TIMEOUT, Totals};
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
                    Value::Array(totals.settle(rows))
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
