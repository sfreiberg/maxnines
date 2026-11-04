//! The admin API, which shares the server's port, and the commands that use it.
//! The commands go through the server because it holds the only database
//! connection. The API needs the admin token, because a proxy may expose it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::DateTime;
use maxnines_protocol::auth::{new_nonce, write_private_file};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info};

use crate::config::Config;
use crate::connection::AppState;
use crate::database::FactVersion;
use crate::facts::{FlatFacts, unflatten};
use crate::presence::AgentPresence;
use crate::registration::{AgentRecord, AgentState, hash_token};

/// An agent as admins see it.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentView {
    #[serde(flatten)]
    agent: AgentRecord,
    online: bool,
    last_seen_ms: Option<u64>,
}

/// Facts come in two kinds. `trusted` is what the server knows for itself, and
/// `reported` is only what the agent claims, so it must never decide anything
/// security related.
#[derive(Debug, Serialize, Deserialize)]
pub struct FactsView {
    trusted: TrustedFacts,
    /// Current facts in their natural shape, with lists and nested values.
    reported: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedFacts {
    agent_id: String,
    state: AgentState,
    decided_by: Option<String>,
    online: bool,
    /// Where the latest connection came from, since the server started.
    source_address: Option<IpAddr>,
}

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/admin/agents", get(list))
        .route("/admin/agents/{id}/facts", get(facts))
        .route("/admin/agents/{id}/facts/history", get(facts_history))
        .route("/admin/agents/{id}/approve", post(approve))
        .route("/admin/agents/{id}/revoke", post(revoke))
        .route_layer(middleware::from_fn_with_state(state, require_token))
}

async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match presented {
        Some(token) if hash_token(token) == *state.admin_token_hash => next.run(request).await,
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn list(State(state): State<AppState>) -> Json<Vec<AgentView>> {
    let agents = state.registry.list().await;
    let views = agents
        .into_iter()
        .map(|agent| {
            let presence: Option<AgentPresence> = state.presence.get(&agent.id);
            AgentView {
                online: presence.is_some_and(|p| p.online),
                last_seen_ms: presence.map(|p| p.last_seen_ms),
                agent,
            }
        })
        .collect();
    Json(views)
}

async fn facts(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    let Some(agent) = state.registry.get(&id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let current = match state.database.current_facts(&id).await {
        Ok(current) => current,
        Err(error) => return server_error(&error),
    };

    let presence = state.presence.get(&id);
    Json(FactsView {
        trusted: TrustedFacts {
            agent_id: agent.id,
            state: agent.state,
            decided_by: agent.decided_by,
            online: presence.is_some_and(|p| p.online),
            source_address: presence.map(|p| p.source),
        },
        reported: unflatten(&current.into_iter().map(|f| (f.name, f.value)).collect()),
    })
    .into_response()
}

async fn facts_history(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.database.facts_history(&id).await {
        Ok(history) => Json(history).into_response(),
        Err(error) => server_error(&error),
    }
}

fn server_error(error: &anyhow::Error) -> Response {
    error!(error = format!("{error:#}"), "admin request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn approve(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    decide(&state, &id, AgentState::Approved).await
}

async fn revoke(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    decide(&state, &id, AgentState::Revoked).await
}

async fn decide(state: &AppState, id: &str, decision: AgentState) -> Response {
    match state.registry.decide(id, decision).await {
        Ok(Some(agent)) => Json(agent).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Reads the admin token, creating one on first start so there is nothing to
/// set up. The file is what lets the admin commands in.
pub fn load_or_create_token(path: &Path) -> Result<String> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating folder {}", parent.display()))?;
        }
        let token = new_nonce()?;
        write_private_file(path, token.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        info!(file = %path.display(), "created admin token");
        return Ok(token);
    }
    read_token(path)
}

fn read_token(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading admin token {}", path.display()))?;
    let token = text.trim();
    ensure!(!token.is_empty(), "admin token {} is empty", path.display());
    Ok(token.to_string())
}

/// Where this machine reaches the server, even if it listens on all addresses.
fn local_url(listen: SocketAddr) -> String {
    let mut address = listen;
    if address.ip().is_unspecified() {
        address.set_ip(if listen.is_ipv4() {
            [127, 0, 0, 1].into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    format!("http://{address}")
}

fn explain(error: ureq::Error, url: &str) -> anyhow::Error {
    match error {
        ureq::Error::StatusCode(401) => {
            anyhow::anyhow!("the server refused the admin token")
        }
        ureq::Error::StatusCode(404) => anyhow::anyhow!("no agent with that ID"),
        ureq::Error::StatusCode(code) => anyhow::anyhow!("the server returned status {code}"),
        other => anyhow::Error::new(other).context(format!("is the server running at {url}?")),
    }
}

pub fn print_agents(config: &Config) -> Result<()> {
    let base = local_url(config.listen);
    let token = read_token(&config.admin_token_file)?;

    let mut response = ureq::get(format!("{base}/admin/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    let body = response.body_mut().read_to_string()?;
    let agents: Vec<AgentView> = serde_json::from_str(&body).context("invalid server response")?;

    if agents.is_empty() {
        println!("no agents yet");
        return Ok(());
    }

    println!(
        "{:<32}  {:<9} {:<8} {:<24} HOST",
        "ID", "STATE", "ONLINE", "DECIDED BY"
    );
    for view in agents {
        let agent = view.agent;
        println!(
            "{:<32}  {:<9} {:<8} {:<24} {}",
            agent.id,
            agent.state.as_str(),
            if view.online { "yes" } else { "no" },
            agent.decided_by.as_deref().unwrap_or("-"),
            agent.host,
        );
    }
    Ok(())
}

fn get_json(config: &Config, path: &str) -> Result<String> {
    let base = local_url(config.listen);
    let token = read_token(&config.admin_token_file)?;

    let mut response = ureq::get(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    Ok(response.body_mut().read_to_string()?)
}

pub fn print_facts(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("/admin/agents/{id}/facts"))?;
    let view: Value = serde_json::from_str(&body).context("invalid server response")?;
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

pub fn print_facts_history(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("/admin/agents/{id}/facts/history"))?;
    let history: Vec<FactVersion> =
        serde_json::from_str(&body).context("invalid server response")?;

    if history.is_empty() {
        println!("no facts reported yet");
    }
    for (time, changes) in describe_history(&history) {
        println!("{}", format_time(time));
        for change in changes {
            println!("  {change}");
        }
    }
    Ok(())
}

fn format_time(ms: u64) -> String {
    match DateTime::from_timestamp_millis(ms as i64) {
        Some(time) => time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{ms} ms"),
    }
}

/// Turns stored versions into what happened and when, in order. Comparing whole
/// rebuilt states, not rows, means a list reads as one change even though each
/// of its items is stored separately.
fn describe_history(history: &[FactVersion]) -> BTreeMap<u64, Vec<String>> {
    let mut times: Vec<u64> = history
        .iter()
        .flat_map(|version| [Some(version.valid_from_ms), version.valid_to_ms])
        .flatten()
        .collect();
    times.sort_unstable();
    times.dedup();

    let mut events = BTreeMap::new();
    let mut previous: Option<Value> = None;

    for time in times {
        let facts = facts_at(history, time);
        let state = unflatten(&facts);

        let changes = match &previous {
            None => vec![format!("first report, {} facts", facts.len())],
            Some(before) => {
                let mut changes = Vec::new();
                describe_changes("", Some(before), Some(&state), &mut changes);
                changes
            }
        };
        if !changes.is_empty() {
            events.insert(time, changes);
        }
        previous = Some(state);
    }
    events
}

fn facts_at(history: &[FactVersion], time: u64) -> FlatFacts {
    history
        .iter()
        .filter(|f| f.valid_from_ms <= time && f.valid_to_ms.is_none_or(|end| end > time))
        .map(|f| (f.name.clone(), f.value.clone()))
        .collect()
}

/// Lists are compared whole, because that's how people think of them. A group
/// that appears or disappears is described fact by fact.
fn describe_changes(
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    changes: &mut Vec<String>,
) {
    let fields = |value: Option<&Value>| value.and_then(Value::as_object).cloned();
    let (old_fields, new_fields) = (fields(before), fields(after));

    if old_fields.is_some() && new_fields.is_some()
        || old_fields.is_some() && after.is_none()
        || new_fields.is_some() && before.is_none()
    {
        let (old, new) = (
            old_fields.unwrap_or_default(),
            new_fields.unwrap_or_default(),
        );
        let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        for name in names {
            let child = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            describe_changes(&child, old.get(name), new.get(name), changes);
        }
        return;
    }

    match (before, after) {
        (Some(old), Some(new)) if old != new => changes.push(format!("{path}: {old} -> {new}")),
        (Some(old), None) => changes.push(format!("{path}: removed (was {old})")),
        (None, Some(new)) => changes.push(format!("{path}: added {new}")),
        _ => {}
    }
}

pub fn change_agent(config: &Config, id: &str, action: &str) -> Result<()> {
    let base = local_url(config.listen);
    let token = read_token(&config.admin_token_file)?;

    let result = ureq::post(format!("{base}/admin/agents/{id}/{action}"))
        .header("Authorization", format!("Bearer {token}"))
        .send_empty();
    match result {
        Ok(_) => {
            println!("{action}: {id}");
            Ok(())
        }
        Err(error) => bail!(explain(error, &base)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn version(name: &str, value: Value, from: u64, to: Option<u64>) -> FactVersion {
        FactVersion {
            name: name.to_string(),
            value,
            valid_from_ms: from,
            valid_to_ms: to,
        }
    }

    #[test]
    fn describes_what_happened_from_the_stored_rows() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("os.version", json!("24.04"), 100, Some(300)),
            version("custom.role", json!("web"), 100, Some(300)),
            version("os.version", json!("24.10"), 300, None),
            version("custom.datacenter", json!("fra1"), 300, None),
        ];

        let events = describe_history(&history);

        assert_eq!(events[&100], ["first report, 3 facts"]);
        assert_eq!(
            events[&300],
            [
                r#"custom.datacenter: added "fra1""#,
                r#"custom.role: removed (was "web")"#,
                r#"os.version: "24.04" -> "24.10""#,
            ]
        );
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn a_list_reads_as_one_change() {
        // ["web", "prod", "eu"] became ["prod", "eu"], touching three rows.
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.tags[0]", json!("web"), 100, Some(200)),
            version("custom.tags[1]", json!("prod"), 100, Some(200)),
            version("custom.tags[2]", json!("eu"), 100, Some(200)),
            version("custom.tags[0]", json!("prod"), 200, None),
            version("custom.tags[1]", json!("eu"), 200, None),
        ];

        assert_eq!(
            describe_history(&history)[&200],
            [r#"custom.tags: ["web","prod","eu"] -> ["prod","eu"]"#]
        );
    }

    #[test]
    fn a_fact_that_returns_after_a_gap_is_shown_as_removed_then_added() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.role", json!("web"), 100, Some(200)),
            version("custom.role", json!("db"), 300, None),
        ];

        let events = describe_history(&history);

        assert_eq!(events[&200], [r#"custom.role: removed (was "web")"#]);
        assert_eq!(events[&300], [r#"custom.role: added "db""#]);
    }

    #[test]
    fn a_new_group_of_facts_is_described_fact_by_fact() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.a", json!(1), 200, None),
            version("custom.b.c", json!(2), 200, None),
        ];

        assert_eq!(
            describe_history(&history)[&200],
            ["custom.a: added 1", "custom.b.c: added 2"]
        );
    }

    #[test]
    fn a_type_change_is_shown_as_a_change() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("web.id", json!(1), 100, Some(200)),
            version("web.id", json!("1"), 200, None),
        ];

        assert_eq!(describe_history(&history)[&200], [r#"web.id: 1 -> "1""#]);
    }

    #[test]
    fn a_first_report_is_summarized() {
        let history = [version("a", json!(1), 100, None)];
        assert_eq!(describe_history(&history)[&100], ["first report, 1 facts"]);
    }

    #[test]
    fn formats_times_in_utc() {
        assert_eq!(format_time(1_700_000_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn creates_a_token_once_then_keeps_it() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/admin.token");

        let first = load_or_create_token(&path).unwrap();
        let second = load_or_create_token(&path).unwrap();

        assert_eq!(first, second);
        assert!(first.len() >= 32);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_the_token() {
        use std::os::unix::fs::PermissionsExt;

        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("admin.token");
        load_or_create_token(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_empty_token_file_is_an_error() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("admin.token");
        fs::write(&path, "\n").unwrap();

        assert!(load_or_create_token(&path).is_err());
    }

    #[test]
    fn local_commands_reach_a_server_listening_on_all_addresses() {
        assert_eq!(
            local_url("0.0.0.0:9000".parse().unwrap()),
            "http://127.0.0.1:9000"
        );
        assert_eq!(local_url("[::]:9000".parse().unwrap()), "http://[::1]:9000");
        assert_eq!(
            local_url("10.0.0.1:9000".parse().unwrap()),
            "http://10.0.0.1:9000"
        );
    }
}
