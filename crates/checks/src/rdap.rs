//! When a website's domain registration runs out, asked of its registry over RDAP,
//! the registries' JSON successor to WHOIS. IANA's list says which registry's
//! server answers for each top-level domain.
//!
//! The answer changes about once a year, and registries don't like being asked
//! often, so each domain is asked about at most twice a day however often its
//! check runs, and the list once a day. Asking about the site's own host name,
//! then each name above it, finds the registered domain: a registry knows
//! `example.co.uk`, not `www.example.co.uk` or `co.uk`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;

use crate::fetch_page;

/// Where IANA lists each top-level domain's RDAP server.
pub(crate) const BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";

const LIST_KEPT: Duration = Duration::from_secs(24 * 3600);
const FOUND_KEPT: Duration = Duration::from_secs(12 * 3600);
const MISSING_KEPT: Duration = Duration::from_secs(3600);

/// How long each question gets.
pub(crate) const LIMIT: Duration = Duration::from_secs(10);

/// Each top-level domain a server answers for, with the server.
type Servers = Vec<(Vec<String>, String)>;

/// What's known of a domain: when its registration ends, nothing to look up,
/// such as an address or a name with no registry, or why it couldn't be found.
type Answer = Result<Option<DateTime<Utc>>, String>;

#[derive(Default)]
struct Cache {
    /// Each list, by where it came from: top-level domains and their servers.
    lists: HashMap<String, (Instant, Servers)>,
    /// Each host's answer, by the list it was looked up with.
    hosts: HashMap<(String, String), (Instant, Answer)>,
}

fn cache() -> std::sync::MutexGuard<'static, Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// When `host`'s domain registration ends.
pub(crate) async fn expiry(host: &str) -> Answer {
    expiry_from(BOOTSTRAP, host).await
}

pub(crate) async fn expiry_from(list_url: &str, host: &str) -> Answer {
    let host = host.trim_end_matches('.').to_lowercase();
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return Ok(None);
    }
    let key = (list_url.to_string(), host.clone());
    if let Some((asked, answer)) = cache().hosts.get(&key) {
        let kept = if answer.is_ok() {
            FOUND_KEPT
        } else {
            MISSING_KEPT
        };
        if asked.elapsed() < kept {
            return answer.clone();
        }
    }
    let answer = look_up(list_url, &host).await;
    cache().hosts.insert(key, (Instant::now(), answer.clone()));
    answer
}

async fn look_up(list_url: &str, host: &str) -> Answer {
    let services = servers(list_url).await?;
    let top = host.rsplit('.').next().unwrap_or_default();
    let Some(server) = services
        .iter()
        .find(|(domains, _)| domains.iter().any(|domain| domain == top))
        .map(|(_, server)| server.trim_end_matches('/').to_string())
    else {
        // Not a public name, such as one for an intranet.
        return Ok(None);
    };
    let labels: Vec<&str> = host.split('.').collect();
    // From the whole name up to the one under the top-level domain.
    for start in 0..labels.len().saturating_sub(1) {
        let name = labels[start..].join(".");
        let Ok(text) = fetch_page(&format!("{server}/domain/{name}"), LIMIT, None).await else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        return expiration(&record)
            .map(Some)
            .ok_or_else(|| format!("the registry doesn't say when {name} expires"));
    }
    Err("the domain's registration couldn't be found".to_string())
}

/// The top-level domains each server answers for, from the list.
async fn servers(list_url: &str) -> Result<Servers, String> {
    if let Some((fetched, services)) = cache().lists.get(list_url)
        && fetched.elapsed() < LIST_KEPT
    {
        return Ok(services.clone());
    }
    let text = fetch_page(list_url, LIMIT, None)
        .await
        .map_err(|_| "IANA's list of registries couldn't be read".to_string())?;
    let list: Value = serde_json::from_str(&text)
        .map_err(|_| "IANA's list of registries couldn't be read".to_string())?;
    let services: Servers = list["services"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|service| {
            let domains = service[0]
                .as_array()?
                .iter()
                .filter_map(|domain| Some(domain.as_str()?.to_lowercase()))
                .collect();
            // The first HTTPS server, as the list puts them in order of preference.
            let urls = service[1].as_array()?;
            let server = urls
                .iter()
                .filter_map(Value::as_str)
                .find(|url| url.starts_with("https://"))
                .or_else(|| urls.first()?.as_str())?;
            Some((domains, server.to_string()))
        })
        .collect();
    cache()
        .lists
        .insert(list_url.to_string(), (Instant::now(), services.clone()));
    Ok(services)
}

/// The record's expiration event.
fn expiration(record: &Value) -> Option<DateTime<Utc>> {
    record["events"]
        .as_array()?
        .iter()
        .find(|event| event["eventAction"] == "expiration")
        .and_then(|event| moment(event["eventDate"].as_str()?))
}

/// An RFC 3339 time, such as `2027-08-13T04:00:00Z`, as RDAP's dates are. A
/// registry that leaves the offset out is taken to mean UTC, as a day either way
/// doesn't change how many days are left by more than one.
fn moment(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|time| time.to_utc())
        .or_else(|_| {
            NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f").map(|time| time.and_utc())
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;

    #[test]
    fn times_are_read_with_or_without_an_offset() {
        let at = |seconds| DateTime::from_timestamp(seconds, 0);
        assert_eq!(moment("1970-01-01T00:00:00Z"), at(0));
        assert_eq!(moment("2027-08-13T04:00:00Z"), at(1_818_129_600));
        assert_eq!(moment("2027-08-13T04:00:00"), at(1_818_129_600));
        assert_eq!(
            moment("2024-02-29T12:30:15.123+00:00"),
            DateTime::from_timestamp_millis(1_709_209_815_123)
        );
        assert_eq!(moment("2027-08-13T06:00:00+02:00"), at(1_818_129_600));
        assert_eq!(moment("2027-13-01T00:00:00Z"), None);
        assert_eq!(moment("soon"), None);
    }

    /// A list naming one registry, and that registry, which knows only
    /// `example.test`, served over plain HTTP. Counts what it's asked.
    fn registry() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(size) => request.extend_from_slice(&buffer[..size]),
                    }
                }
                counted.fetch_add(1, Ordering::Relaxed);
                let request = String::from_utf8_lossy(&request);
                let path = request.split(' ').nth(1).unwrap_or_default();
                let (status, body) = match path {
                    "/dns.json" => (
                        "200 OK",
                        format!(
                            r#"{{"services": [[["test"], ["http://{address}/rdap/"]], [["other"], ["http://{address}/elsewhere/"]]]}}"#
                        ),
                    ),
                    "/rdap/domain/example.test" => (
                        "200 OK",
                        r#"{"events": [{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}]}"#.to_string(),
                    ),
                    "/rdap/domain/quiet.test" => ("200 OK", r#"{"events": []}"#.to_string()),
                    _ => ("404 Not Found", String::new()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{address}/dns.json"), asked)
    }

    #[tokio::test]
    async fn a_sites_domain_is_found_by_asking_up_from_its_host() {
        let (list, asked) = registry();
        let expected = Ok(DateTime::from_timestamp(1_818_129_600, 0));
        assert_eq!(expiry_from(&list, "www.shop.example.test").await, expected);
        // The list, then shop.example.test's two misses on the way up, then the hit.
        assert_eq!(asked.load(Ordering::Relaxed), 4);
        // Asked again, it's remembered.
        assert_eq!(expiry_from(&list, "www.shop.example.test").await, expected);
        assert_eq!(asked.load(Ordering::Relaxed), 4);

        let quiet = expiry_from(&list, "quiet.test").await;
        assert_eq!(
            quiet,
            Err("the registry doesn't say when quiet.test expires".to_string())
        );
        let missing = expiry_from(&list, "nobody.test").await;
        assert_eq!(
            missing,
            Err("the domain's registration couldn't be found".to_string())
        );
    }

    #[tokio::test]
    async fn addresses_and_private_names_have_nothing_to_look_up() {
        let (list, asked) = registry();
        for host in [
            "192.0.2.1",
            "::1",
            "intranet",
            "printer.local",
            "db.internal",
        ] {
            assert_eq!(expiry_from(&list, host).await, Ok(None), "{host}");
        }
        // Only the list was needed, to see that .local and .internal aren't in it.
        assert_eq!(asked.load(Ordering::Relaxed), 1);
    }
}
