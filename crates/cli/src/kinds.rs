//! The kinds of thing maxnines lists: how each is fetched, found by name, and shown.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde_json::Value;

use crate::api::Api;
use crate::failure::Failure;
use crate::output::{self, Format, span, text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Kind {
    #[value(alias = "host", alias = "h")]
    Hosts,
    #[value(alias = "alert", alias = "al")]
    Alerts,
    #[value(alias = "silence", alias = "sil")]
    Silences,
    #[value(alias = "check", alias = "ck")]
    Checks,
}

impl Kind {
    pub fn singular(self) -> &'static str {
        match self {
            Self::Hosts => "host",
            Self::Alerts => "alert",
            Self::Silences => "silence",
            Self::Checks => "check",
        }
    }
}

/// What `get` was asked for, besides the kind and names.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Only what's about hosts matching this filter.
    pub filter: Option<String>,
    /// Alerts and silences that have ended, rather than what's happening now.
    pub ended: bool,
}

fn array(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}

fn query(filter: &str) -> String {
    serde_urlencoded::to_string([("filter", filter)]).unwrap_or_default()
}

/// Every host, or those matching `filter`.
pub fn hosts(api: &Api, filter: Option<&str>) -> Result<Vec<Value>> {
    let path = match filter {
        Some(filter) => format!("/hosts?{}", query(filter)),
        None => "/hosts".to_string(),
    };
    Ok(array(api.get(&path)?))
}

/// IDs of the hosts a filter matches, to narrow alerts and checks to them.
fn host_ids(api: &Api, filter: &str) -> Result<BTreeSet<String>> {
    Ok(hosts(api, Some(filter))?
        .iter()
        .map(|host| text(host, "id"))
        .collect())
}

/// Hostnames by ID, for showing what other things are about.
fn hostnames(api: &Api) -> Result<BTreeMap<String, String>> {
    Ok(hosts(api, None)?
        .iter()
        .map(|host| (text(host, "id"), text(host, "hostname")))
        .collect())
}

/// The one host `name` means: its hostname, or the start of its ID. Hostnames needn't
/// be unique, so two by the same name is an error that lists them.
pub fn find_host<'a>(hosts: &'a [Value], name: &str) -> Result<&'a Value, Failure> {
    let named: Vec<&Value> = hosts
        .iter()
        .filter(|host| text(host, "hostname") == name)
        .collect();
    let matches = if named.is_empty() && name.len() >= 4 {
        hosts
            .iter()
            .filter(|host| text(host, "id").starts_with(name))
            .collect()
    } else {
        named
    };
    match matches.as_slice() {
        [host] => Ok(host),
        [] => Err(Failure::not_found(format!(
            "There's no host called {name:?}"
        ))),
        many => {
            let ids: Vec<String> = many
                .iter()
                .map(|host| format!("{}…", &text(host, "id")[..8.min(text(host, "id").len())]))
                .collect();
            Err(Failure::not_found(format!(
                "{} hosts are called {name}: {}. Use the start of an ID instead",
                many.len(),
                ids.join(", ")
            )))
        }
    }
}

/// The one check `name` means: its number, or its name, if no other check has it.
pub fn find_check<'a>(checks: &'a [Value], name: &str) -> Result<&'a Value, Failure> {
    let matches: Vec<&Value> = checks
        .iter()
        .filter(|check| text(check, "id") == name || text(&check["check"], "name") == name)
        .collect();
    match matches.as_slice() {
        [check] => Ok(check),
        [] => Err(Failure::not_found(format!(
            "There's no check called {name:?}"
        ))),
        many => Err(Failure::not_found(format!(
            "{} checks are called {name}: use one's number instead, from maxnines get checks -o wide",
            many.len()
        ))),
    }
}

/// Finds one thing among many by the name it was asked for.
type Finder<'a> = &'a dyn Fn(&[Value], &str) -> Result<Value, Failure>;

fn find_by_id<'a>(items: &'a [Value], name: &str, kind: Kind) -> Result<&'a Value, Failure> {
    items
        .iter()
        .find(|item| text(item, "id") == name)
        .ok_or_else(|| Failure::not_found(format!("There's no {} {name}", kind.singular())))
}

/// Everything of `kind`, as the API gives it, narrowed to `names` if there are any.
pub fn fetch(api: &Api, kind: Kind, names: &[String], options: &Options) -> Result<Vec<Value>> {
    let only = |items: Vec<Value>, find: Finder<'_>| -> Result<Vec<Value>> {
        if names.is_empty() {
            return Ok(items);
        }
        names
            .iter()
            .map(|name| find(&items, name).map_err(Into::into))
            .collect()
    };
    let about = |items: Vec<Value>| -> Result<Vec<Value>> {
        match &options.filter {
            Some(filter) => {
                let ids = host_ids(api, filter)?;
                Ok(items
                    .into_iter()
                    .filter(|item| ids.contains(&text(item, "host_id")))
                    .collect())
            }
            None => Ok(items),
        }
    };
    match kind {
        Kind::Hosts => only(hosts(api, options.filter.as_deref())?, &|items, name| {
            find_host(items, name).cloned()
        }),
        Kind::Alerts => {
            let mut all = api.get("/alerts")?;
            let list = if options.ended {
                all["resolved"].take()
            } else {
                all["open"].take()
            };
            only(about(array(list))?, &|items, name| {
                find_by_id(items, name, kind).cloned()
            })
        }
        Kind::Silences => {
            let mut all = api.get("/silences")?;
            let list = if options.ended {
                all["ended"].take()
            } else {
                all["active"].take()
            };
            only(array(list), &|items, name| {
                find_by_id(items, name, kind).cloned()
            })
        }
        Kind::Checks => only(about(array(api.get("/remote-checks")?))?, &|items, name| {
            find_check(items, name).cloned()
        }),
    }
}

/// Shows what `fetch` found. Gives back how many there were.
pub fn show(
    api: &Api,
    kind: Kind,
    items: &[Value],
    format: Format,
    options: &Options,
) -> Result<String> {
    if format == Format::Json {
        return Ok(output::json(&Value::Array(items.to_vec())));
    }
    if format == Format::Name {
        let names: Vec<String> = items
            .iter()
            .map(|item| {
                let name = match kind {
                    Kind::Hosts => text(item, "hostname"),
                    _ => text(item, "id"),
                };
                format!("{}/{name}", kind.singular())
            })
            .collect();
        return Ok(names.join("\n"));
    }
    if items.is_empty() {
        return Ok(nothing(kind, options).to_string());
    }
    let wide = format == Format::Wide;
    let now = Utc::now();
    let ago = |item: &Value, field: &str| {
        moment(item, field).map_or_else(|| "-".to_string(), |ms| span(now - ms))
    };
    let (headings, rows): (Vec<&str>, Vec<Vec<String>>) = match kind {
        Kind::Hosts => {
            let mut headings = vec!["hostname", "id", "status", "last seen"];
            if wide {
                headings.extend(["kind", "full id"]);
            }
            let rows = items
                .iter()
                .map(|host| {
                    let mut row = vec![
                        text(host, "hostname"),
                        text(host, "id").chars().take(8).collect(),
                        host_status(host),
                        ago(host, "last_seen_at"),
                    ];
                    if wide {
                        row.extend([text(host, "kind"), text(host, "id")]);
                    }
                    row
                })
                .collect();
            (headings, rows)
        }
        Kind::Alerts => {
            let headings = vec!["id", "severity", "rule", "host", "series", "for", "state"];
            let rows = items
                .iter()
                .map(|alert| {
                    let lasted = match moment(alert, "resolved_at") {
                        Some(ended) => span(ended - moment(alert, "started_at").unwrap_or(ended)),
                        None => ago(alert, "started_at"),
                    };
                    vec![
                        text(alert, "id"),
                        text(alert, "severity"),
                        text(alert, "rule_name"),
                        text(alert, "hostname"),
                        text(alert, "series"),
                        lasted,
                        alert_state(alert),
                    ]
                })
                .collect();
            (headings, rows)
        }
        Kind::Silences => {
            let rules = rule_names(api)?;
            let hostnames = hostnames(api)?;
            let headings = vec!["id", "reason", "covers", "ends"];
            let rows = items
                .iter()
                .map(|silence| {
                    let ends = moment(silence, "ends_at").map_or_else(String::new, |ends| {
                        if ends > now {
                            format!("in {}", span(ends - now))
                        } else {
                            format!("{} ago", span(now - ends))
                        }
                    });
                    vec![
                        text(silence, "id"),
                        text(silence, "reason"),
                        covers(silence, &rules, &hostnames),
                        ends,
                    ]
                })
                .collect();
            (headings, rows)
        }
        Kind::Checks => {
            let hostnames = hostnames(api)?;
            let mut headings = vec!["name", "host", "kind", "status"];
            if wide {
                headings.extend(["target", "id"]);
            }
            let rows = items
                .iter()
                .map(|check| {
                    let host = text(check, "host_id");
                    let mut row = vec![
                        text(&check["check"], "name"),
                        hostnames.get(&host).cloned().unwrap_or(host),
                        text(&check["check"], "kind"),
                        check_status(check),
                    ];
                    if wide {
                        row.extend([text(&check["check"], "target"), text(check, "id")]);
                    }
                    row
                })
                .collect();
            (headings, rows)
        }
    };
    Ok(output::table(&headings, &rows))
}

/// What an empty list says.
fn nothing(kind: Kind, options: &Options) -> &'static str {
    match (kind, options.ended) {
        (Kind::Alerts, false) => "No alerts are firing.",
        (Kind::Alerts, true) => "No alerts have resolved lately.",
        (Kind::Silences, false) => "No silences are running.",
        (Kind::Silences, true) => "No silences have ended lately.",
        (Kind::Hosts, _) => "No hosts.",
        (Kind::Checks, _) => "No checks.",
    }
}

fn host_status(host: &Value) -> String {
    match text(host, "state").as_str() {
        "approved" | "" => match text(host, "health").as_str() {
            "not_read" => "not read yet".to_string(),
            "" if host["online"] == Value::Bool(true) => "online".to_string(),
            "" => "offline".to_string(),
            health => health.to_string(),
        },
        state => state.to_string(),
    }
}

/// A moment the API gives as an ISO 8601 time, such as `2026-11-19T01:57:17.828Z`.
/// Nothing if it's missing or empty.
fn moment(item: &Value, field: &str) -> Option<DateTime<Utc>> {
    let text = item[field].as_str()?;
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|time| time.with_timezone(&Utc))
}

fn alert_state(alert: &Value) -> String {
    let mut state = Vec::new();
    if moment(alert, "resolved_at").is_some() {
        state.push("resolved".to_string());
    }
    if let Some(who) = alert["acknowledged_by"].as_str() {
        state.push(format!("acknowledged by {who}"));
    }
    if alert["silence_id"].is_i64() || alert["maintenance_window_id"].is_i64() {
        state.push("silenced".to_string());
    }
    if state.is_empty() {
        "firing".to_string()
    } else {
        state.join(", ")
    }
}

fn check_status(check: &Value) -> String {
    if check["enabled"] == Value::Bool(false) {
        return "paused".to_string();
    }
    match check["latest"]["up"].as_bool() {
        Some(true) => "up".to_string(),
        Some(false) => match check["latest"]["error"].as_str() {
            Some(error) => format!("down: {error}"),
            None => "down".to_string(),
        },
        None => "not run yet".to_string(),
    }
}

/// Alert rules' names by ID.
fn rule_names(api: &Api) -> Result<BTreeMap<i64, String>> {
    Ok(array(api.get("/alert-rules")?)
        .iter()
        .filter_map(|rule| Some((rule["id"].as_i64()?, text(rule, "name"))))
        .collect())
}

/// What a silence covers, in words. One host by ID is shown by its hostname.
fn covers(
    silence: &Value,
    rules: &BTreeMap<i64, String>,
    hostnames: &BTreeMap<String, String>,
) -> String {
    if silence["all_alerts"] == Value::Bool(true) {
        return "every alert".to_string();
    }
    let mut parts = Vec::new();
    if let Some(rule) = silence["rule_id"].as_i64() {
        parts.push(
            rules
                .get(&rule)
                .cloned()
                .unwrap_or_else(|| format!("rule {rule}")),
        );
    }
    let filter = text(silence, "filter");
    match filter.strip_prefix("id=").and_then(|id| hostnames.get(id)) {
        Some(hostname) => parts.push(hostname.clone()),
        None if !filter.is_empty() => parts.push(filter),
        None => {}
    }
    let series = text(silence, "series");
    if !series.is_empty() {
        parts.push(series);
    }
    if parts.is_empty() {
        "every alert".to_string()
    } else {
        parts.join(" · ")
    }
}

/// One thing by name, as the API gives it. An alert or silence that's ended isn't in
/// what's happening now, so it's looked for among those that have ended too.
pub fn find_one(api: &Api, kind: Kind, name: &str) -> Result<Value> {
    match fetch(api, kind, &[name.to_string()], &Options::default()) {
        Ok(mut items) => Ok(items.remove(0)),
        Err(_) if matches!(kind, Kind::Alerts | Kind::Silences) => {
            let ended = Options {
                ended: true,
                ..Options::default()
            };
            Ok(fetch(api, kind, &[name.to_string()], &ended)?.remove(0))
        }
        Err(error) => Err(error),
    }
}

/// Everything about one thing, with what's related, for people to read.
pub fn describe(api: &Api, kind: Kind, name: &str) -> Result<String> {
    if kind != Kind::Hosts {
        return Ok(output::pairs(&output::fields(&find_one(api, kind, name)?)));
    }
    let all = hosts(api, None)?;
    let host = find_host(&all, name)?;
    let id = text(host, "id");
    let facts = api.get(&format!("/hosts/{id}/facts"))?;
    let now = Utc::now();
    let mut lines = vec![
        ("Hostname".to_string(), text(host, "hostname")),
        ("ID".to_string(), id.clone()),
        ("Kind".to_string(), text(host, "kind")),
        (
            "Status".to_string(),
            match moment(host, "last_seen_at") {
                Some(seen) => format!("{}, last seen {} ago", host_status(host), span(now - seen)),
                None => host_status(host),
            },
        ),
    ];
    let alerts = api.get("/alerts")?;
    let firing: Vec<String> = array(alerts["open"].clone())
        .iter()
        .filter(|alert| text(alert, "host_id") == id)
        .map(|alert| {
            format!(
                "{} ({}, {})",
                text(alert, "summary"),
                text(alert, "severity"),
                span(now - moment(alert, "started_at").unwrap_or(now))
            )
        })
        .collect();
    lines.push((
        "Firing".to_string(),
        if firing.is_empty() {
            "nothing".to_string()
        } else {
            firing.join("; ")
        },
    ));
    let mut text = output::pairs(&lines);
    let reported = output::fields(&facts["reported"]);
    if !reported.is_empty() {
        text.push_str("\n\nFacts\n");
        let indented: Vec<(String, String)> = reported
            .into_iter()
            .map(|(name, value)| (format!("  {name}"), value))
            .collect();
        text.push_str(&output::pairs(&indented));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_host_is_found_by_hostname_or_the_start_of_its_id() {
        let hosts = vec![
            json!({"id": "3f2a1c9d4e6b", "hostname": "web-1"}),
            json!({"id": "8be04471aaaa", "hostname": "web-1"}),
            json!({"id": "22ad9264b6eb", "hostname": "db-1"}),
        ];
        assert_eq!(
            text(find_host(&hosts, "db-1").unwrap(), "id"),
            "22ad9264b6eb"
        );
        assert_eq!(
            text(find_host(&hosts, "3f2a").unwrap(), "id"),
            "3f2a1c9d4e6b"
        );
        let twice = find_host(&hosts, "web-1").unwrap_err();
        assert_eq!(twice.code, Failure::NOT_FOUND);
        assert!(
            twice
                .message
                .contains("2 hosts are called web-1: 3f2a1c9d…, 8be04471…"),
            "{}",
            twice.message
        );
        assert_eq!(
            find_host(&hosts, "nope").unwrap_err().code,
            Failure::NOT_FOUND
        );
        // Too short to be the start of an ID.
        assert!(find_host(&hosts, "3f2").is_err());
    }

    #[test]
    fn states_and_cover_read_as_words() {
        assert_eq!(
            alert_state(&json!({"acknowledged_by": "sam@example.com", "silence_id": 3})),
            "acknowledged by sam@example.com, silenced"
        );
        assert_eq!(alert_state(&json!({})), "firing");
        assert_eq!(
            check_status(&json!({"enabled": true, "latest": {"up": false, "error": "refused"}})),
            "down: refused"
        );
        assert_eq!(check_status(&json!({"enabled": false})), "paused");
        assert_eq!(host_status(&json!({"state": "pending"})), "pending");
        assert_eq!(
            host_status(&json!({"state": "approved", "health": "not_read"})),
            "not read yet"
        );
        let rules = BTreeMap::from([(1, "High CPU".to_string())]);
        let hostnames = BTreeMap::from([("9fcd430c".to_string(), "orders-db".to_string())]);
        assert_eq!(
            covers(
                &json!({"rule_id": 1, "filter": "hostname=web*", "series": null}),
                &rules,
                &hostnames
            ),
            "High CPU · hostname=web*"
        );
        assert_eq!(
            covers(
                &json!({"filter": "id=9fcd430c", "series": "Closed port"}),
                &rules,
                &hostnames
            ),
            "orders-db · Closed port"
        );
        assert_eq!(
            covers(&json!({"all_alerts": true}), &rules, &hostnames),
            "every alert"
        );
    }
}
