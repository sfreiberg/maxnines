//! Reads the OpenMetrics pages a config rule lists, with every sample. How a page
//! is read is in [`maxnines_checks::openmetrics`], which the server shares.
//!
//! A page that asks for a username and password gets the ones the agent's own
//! config gives for it, by the page's name. They never come from the server, and
//! never go to it.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};
use maxnines_checks::Login;
use maxnines_checks::openmetrics::{MAX_SERIES, Page, TIMED_OUT, TIMEOUT, Totals};
use maxnines_protocol::metrics_page_name;
use serde::Deserialize;
use serde_json::Value;

use crate::background::{Background, probe_all};
use crate::collector::Collector;

/// How many pages the agent's config can give a login for.
const MAX_LOGINS: usize = 64;

/// A page's username and password, from the agent's own config:
///
/// ```hcl
/// openmetrics "localhost:9100" {
///   username = "metrics"
///   password = env("METRICS_PASSWORD")
/// }
/// ```
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageLogin {
    username: String,
    password: String,
}

impl fmt::Debug for PageLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageLogin")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// The logins the agent's config gives, by the page's name.
pub type Logins = BTreeMap<String, PageLogin>;

pub fn check_logins(logins: &Logins) -> Result<()> {
    ensure!(
        logins.len() <= MAX_LOGINS,
        "at most {MAX_LOGINS} OpenMetrics pages can have a login"
    );
    for (page, login) in logins {
        // What a page is called never has these, so it could never match.
        ensure!(
            !page.is_empty() && !page.contains("://") && !page.contains(['?', '#', ' ']),
            "{page:?} isn't an OpenMetrics page's name, which is its address without \
             http://, like localhost:9100"
        );
        // Basic authentication ends the username at the first colon.
        ensure!(
            !login.username.is_empty() && !login.username.contains(':'),
            "the login for {page:?} needs a username, without a colon"
        );
        ensure!(
            !login.password.is_empty(),
            "the login for {page:?} needs a password"
        );
        Login::new(&login.username, &login.password)?;
    }
    Ok(())
}
pub struct OpenMetricsCollector {
    background: Background,
    totals: Totals,
}

impl OpenMetricsCollector {
    pub fn new(
        urls: Vec<String>,
        wanted: &[String],
        logins: &Logins,
        interval: Duration,
    ) -> Result<Self> {
        let max_series = MAX_SERIES / urls.len().max(1);
        let pages = urls
            .into_iter()
            .map(|url| {
                let login = logins
                    .get(metrics_page_name(&url))
                    .map(|login| Login::new(&login.username, &login.password))
                    .transpose()?;
                Ok(Arc::new(Page::new(url, wanted, max_series, login)))
            })
            .collect::<Result<Vec<_>>>()?;
        let background = Background::start(interval, move || {
            let pages = pages.clone();
            async move {
                let read = |page: Arc<Page>| async move { page.read().await };
                let timed_out = |page: &Page| page.failed(TIMED_OUT);
                let rows = probe_all(&pages, interval, TIMEOUT, read, timed_out).await;
                Value::Array(rows.into_iter().flatten().collect())
            }
        });
        Ok(Self {
            background,
            totals: Totals::default(),
        })
    }
}

impl Collector for OpenMetricsCollector {
    fn name(&self) -> &'static str {
        "openmetrics"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(match self.background.latest() {
            Value::Array(kept) => Value::Array(self.totals.settle(kept)),
            // The first round hasn't finished.
            waiting => waiting,
        })
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
    fn totals_become_the_change_since_the_last_sample() {
        let first = "# TYPE jobs_total counter\njobs_total 100\n# TYPE restarts_total counter\nrestarts_total 7\nqueue 1\n";
        let second = "# TYPE jobs_total counter\njobs_total 130\n# TYPE restarts_total counter\nrestarts_total 2\nqueue 2\n";
        let served = serve(vec![first, second]);
        let address = &served.address;
        let url = format!("http://{address}/metrics");
        let mut collector =
            OpenMetricsCollector::new(vec![url], &[], &Logins::new(), Duration::from_millis(200))
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
        let mut collector =
            OpenMetricsCollector::new(urls, &[], &Logins::new(), Duration::from_millis(200))
                .unwrap();

        let output = collect_until(&mut collector, |output| output.is_array());

        assert_eq!(
            output[0],
            json!({ "name": address, "up": 0, "error": NO_METRICS })
        );
        assert_eq!(output[1]["name"], closed);
        assert_eq!(output[1]["up"], 0);
        assert!(output[1]["error"].is_string(), "{output}");
    }

    fn login(username: &str, password: &str) -> PageLogin {
        PageLogin {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn a_page_gets_the_login_the_agent_has_for_it() {
        // "metrics:s3cret", as basic authentication sends it.
        let served = serve_to(
            vec!["queue 1\n"],
            Some("authorization: Basic bWV0cmljczpzM2NyZXQ="),
        );
        let address = &served.address;
        let url = format!("http://{address}/metrics");
        let read = |logins: Logins| {
            let interval = Duration::from_millis(200);
            let mut collector =
                OpenMetricsCollector::new(vec![url.clone()], &[], &logins, interval).unwrap();
            collect_until(&mut collector, |output| output.is_array())
        };

        let output = read(Logins::from([(
            address.clone(),
            login("metrics", "s3cret"),
        )]));
        assert_eq!(output[0]["up"], 1, "{output}");
        assert_eq!(output[1]["value"], 1.0);

        // A login for some other page isn't sent to this one.
        let other = Logins::from([("localhost:1".to_string(), login("metrics", "s3cret"))]);
        for logins in [Logins::new(), other] {
            let output = read(logins);
            assert_eq!(output[0]["up"], 0, "{output}");
            assert_eq!(output[0]["error"], "the page returned status 401");
        }
    }

    #[test]
    fn logins_need_a_page_a_username_and_a_password() {
        let one = |page: &str, username: &str, password: &str| {
            check_logins(&Logins::from([(
                page.to_string(),
                login(username, password),
            )]))
        };
        one("localhost:9100", "metrics", "s3cret: with a colon").unwrap();
        one("app.example.com/internal", "metrics", "x").unwrap();
        // Anything can be in a password, as it's encoded before it's sent.
        one("localhost:9100", "metrics", "line\nbreak é").unwrap();
        for (page, username, password) in [
            ("http://localhost:9100/metrics", "metrics", "x"),
            ("localhost:9100/metrics?a=b", "metrics", "x"),
            ("", "metrics", "x"),
            ("localhost:9100", "", "x"),
            ("localhost:9100", "a:b", "x"),
            ("localhost:9100", "metrics", ""),
        ] {
            assert!(one(page, username, password).is_err(), "{page} {username}");
        }
    }

    #[test]
    fn a_password_is_never_printed() {
        let printed = format!("{:?}", login("metrics", "s3cret"));
        assert!(printed.contains("metrics"), "{printed}");
        assert!(!printed.contains("s3cret"), "{printed}");
    }
}
