use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::fleet::Health;
use super::{CsrfForm, Page, server_error};
use crate::alerting::Alert;
use crate::app_state::AppState;
use crate::fact_history::{describe_history, format_time};
use crate::facts::{FlatFacts, unflatten};
use crate::metrics::now_ms;
use crate::models::ConfigStatus;
use crate::registration::{AgentRecord, AgentState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/agents", get(index))
        .route("/agents/{id}", get(show))
        .route("/agents/{id}/approve", post(approve))
        .route("/agents/{id}/revoke", post(revoke))
}

#[derive(Serialize)]
struct AgentRow {
    id: String,
    host: String,
    state: &'static str,
    online: bool,
    health: Health,
    os: Option<String>,
    seen: Option<String>,
    config: ConfigState,
}

/// How an agent's running config compares with what it should be running.
#[derive(Serialize)]
struct ConfigState {
    label: &'static str,
    class: &'static str,
}

fn config_state(desired: Option<&str>, reported: Option<&ConfigStatus>) -> ConfigState {
    let (label, class) = match (desired, reported) {
        (_, None) => ("Not reported", "neutral"),
        (_, Some(status)) if status.error.is_some() => ("Rejected", "bad"),
        (Some(version), Some(status)) if version == status.version => ("Up to date", "good"),
        _ => ("Updating", "neutral"),
    };
    ConfigState { label, class }
}

fn text_fact(facts: &FlatFacts, name: &str) -> Option<String> {
    facts.get(name)?.as_str().map(String::from)
}

/// The long version is the one people know, as macOS calls itself Darwin.
fn os_of(facts: &FlatFacts) -> Option<String> {
    text_fact(facts, "os.long_version").or_else(|| {
        match (text_fact(facts, "os.name"), text_fact(facts, "os.version")) {
            (Some(name), Some(version)) => Some(format!("{name} {version}")),
            (name, _) => name,
        }
    })
}

fn fact_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Facts in their natural shape: maps give dotted names, and a list of plain
/// values is one line, however it's stored.
fn fact_rows(prefix: &str, value: &Value, rows: &mut Vec<FactRow>) {
    match value {
        Value::Object(fields) => {
            for (name, field) in fields {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                fact_rows(&path, field, rows);
            }
        }
        Value::Array(items)
            if items
                .iter()
                .all(|item| !item.is_object() && !item.is_array()) =>
        {
            let items: Vec<String> = items.iter().map(fact_text).collect();
            rows.push(FactRow {
                name: prefix.to_string(),
                value: items.join(", "),
            });
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                fact_rows(&format!("{prefix}[{index}]"), item, rows);
            }
        }
        scalar => rows.push(FactRow {
            name: prefix.to_string(),
            value: fact_text(scalar),
        }),
    }
}

/// In the largest unit that makes sense, as "3 minutes ago" reads better than a
/// timestamp when you're only asking whether it's still there.
fn ago(ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(ms) / 1000;
    let plural = |count: u64, unit: &str| match count {
        1 => format!("1 {unit} ago"),
        _ => format!("{count} {unit}s ago"),
    };
    match secs {
        0..60 => "just now".to_string(),
        60..3600 => plural(secs / 60, "minute"),
        3600..86_400 => plural(secs / 3600, "hour"),
        _ => plural(secs / 86_400, "day"),
    }
}

fn format_uptime(secs: u64) -> String {
    let part = |count: u64, unit: &str| match count {
        1 => format!("1 {unit}"),
        _ => format!("{count} {unit}s"),
    };
    let (days, hours, minutes) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if days > 0 {
        format!("{}, {}", part(days, "day"), part(hours, "hour"))
    } else if hours > 0 {
        format!("{}, {}", part(hours, "hour"), part(minutes, "minute"))
    } else {
        part(minutes, "minute")
    }
}

async fn row(
    state: &AppState,
    agent: AgentRecord,
    facts: Option<&FlatFacts>,
    alerts: &[&Alert],
) -> AgentRow {
    let desired = state.config_for(&agent.id).await.ok();
    let reported = state.database.config_status(&agent.id).await.ok().flatten();
    let presence = state.presence.get(&agent.id);
    let online = presence.is_some_and(|p| p.online);

    AgentRow {
        online,
        health: Health::of(online, alerts),
        os: facts.and_then(os_of),
        seen: presence.map(|p| ago(p.last_seen_ms, now_ms() as u64)),
        config: config_state(
            desired.as_ref().map(|d| d.version.as_str()),
            reported.as_ref(),
        ),
        state: agent.state.as_str(),
        id: agent.id,
        host: agent.host,
    }
}

#[derive(Deserialize)]
struct ListParams {
    view: Option<String>,
    filter: Option<String>,
}

#[derive(Serialize)]
struct FilterTab {
    key: &'static str,
    label: &'static str,
    count: usize,
    selected: bool,
}

/// Whether an agent belongs under a filter on the list.
fn matches(filter: &str, agent: &AgentRow) -> bool {
    match filter {
        "online" => agent.online,
        "offline" => !agent.online && agent.state == "approved",
        "revoked" => agent.state == "revoked",
        _ => true,
    }
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
    token: CsrfToken,
) -> Response {
    let data = async {
        let facts = state.database.all_current_facts().await?;
        let alerts = state.database.open_alerts().await?;
        anyhow::Ok((facts, alerts))
    };
    let (facts, open) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };

    let mut waiting = Vec::new();
    let mut agents = Vec::new();
    for agent in state.registry.list().await {
        if agent.is_local() {
            continue;
        }
        let mine: Vec<&Alert> = open.iter().filter(|a| a.agent_id == agent.id).collect();
        let pending = agent.state == AgentState::Pending;
        let row = row(&state, agent.clone(), facts.get(&agent.id), &mine).await;
        if pending {
            waiting.push(row);
        } else {
            agents.push(row);
        }
    }
    agents.sort_by(|a, b| a.health.cmp(&b.health).then_with(|| a.host.cmp(&b.host)));

    let selected = params.filter.as_deref().unwrap_or("all");
    let filters: Vec<FilterTab> = [
        ("all", "All"),
        ("online", "Online"),
        ("offline", "Offline"),
        ("revoked", "Revoked"),
    ]
    .into_iter()
    .map(|(key, label)| FilterTab {
        key,
        label,
        count: agents.iter().filter(|agent| matches(key, agent)).count(),
        selected: key == selected,
    })
    .collect();

    let online = agents.iter().filter(|agent| agent.online).count();
    let total = agents.len();
    agents.retain(|agent| matches(selected, agent));

    Page::new(&state, &token, "agents/index.html")
        .with("agents", &agents)
        .with("waiting", &waiting)
        .with("filters", &filters)
        .with("filter", selected)
        .with("online_count", &online)
        .with("total", &total)
        .with("as_table", &(params.view.as_deref() == Some("table")))
        .render()
}

#[derive(Serialize)]
struct FactRow {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct HistoryEntry {
    time: String,
    changes: Vec<String>,
}

async fn show(State(state): State<AppState>, Path(id): Path<String>, token: CsrfToken) -> Response {
    let found = state.registry.get(&id).await;
    let Some(agent) = found.filter(|agent| !agent.is_local()) else {
        let page = Page::new(&state, &token, "errors/not_found.html");
        return page.with_status(StatusCode::NOT_FOUND).render();
    };
    let open = match state.database.open_alerts().await {
        Ok(open) => open,
        Err(error) => return server_error(&error),
    };
    let alerts: Vec<&Alert> = open.iter().filter(|a| a.agent_id == id).collect();

    let current = match state.database.current_facts(&id).await {
        Ok(current) => current,
        Err(error) => return server_error(&error),
    };
    let history = match state.database.facts_history(&id).await {
        Ok(history) => history,
        Err(error) => return server_error(&error),
    };
    let desired = match state.config_for(&id).await {
        Ok(desired) => desired,
        Err(error) => return server_error(&error),
    };
    let reported = match state.database.config_status(&id).await {
        Ok(reported) => reported,
        Err(error) => return server_error(&error),
    };

    let flat: FlatFacts = current.into_iter().map(|f| (f.name, f.value)).collect();
    let mut facts = Vec::new();
    fact_rows("", &unflatten(&flat), &mut facts);
    let uptime = match state.metrics.latest_output(&id, "host", now_ms()).await {
        Ok(output) => output.and_then(|host| host["uptime_secs"].as_u64()),
        Err(error) => return server_error(&error),
    };
    let presence = state.presence.get(&id);
    let config = serde_json::to_string_pretty(&desired.config).unwrap_or_default();
    let changes: Vec<HistoryEntry> = describe_history(&history)
        .into_iter()
        .rev()
        .map(|(time, changes)| HistoryEntry {
            time: format_time(time),
            changes,
        })
        .collect();

    let row = row(&state, agent.clone(), Some(&flat), &alerts).await;
    Page::new(&state, &token, "agents/show.html")
        .with("agent", &row)
        .with("decided_by", &agent.decided_by)
        .with("has_facts", &!flat.is_empty())
        .with("alerts", &alerts)
        .with("uptime", &uptime.map(format_uptime))
        .with("os", &os_of(&flat))
        .with("source", &presence.map(|p| p.source.to_string()))
        .with("agent_version", &text_fact(&flat, "agent.version"))
        .with("agent_commit", &text_fact(&flat, "agent.commit"))
        .with("facts", &facts)
        .with("config", &config)
        .with("version", &desired.version)
        .with("matched_rules", &desired.matched_rules)
        .with("skipped_collectors", &desired.skipped_collectors)
        .with("reported", &reported)
        .with("history", &changes)
        .render()
}

async fn approve(state: State<AppState>, id: Path<String>, form: CsrfForm) -> Response {
    decide(state, id, form, AgentState::Approved).await
}

async fn revoke(state: State<AppState>, id: Path<String>, form: CsrfForm) -> Response {
    decide(state, id, form, AgentState::Revoked).await
}

async fn decide(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
    decision: AgentState,
) -> Response {
    match state.registry.decide(&id, decision).await {
        Ok(Some(_)) => (form.token, Redirect::to(&format!("/agents/{id}"))).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(version: &str, error: Option<&str>) -> ConfigStatus {
        ConfigStatus {
            version: version.to_string(),
            error: error.map(String::from),
            reported_at_ms: 1,
        }
    }

    #[test]
    fn times_ago_use_the_largest_unit() {
        let now = 100 * 86_400_000;
        assert_eq!(ago(now - 5_000, now), "just now");
        assert_eq!(ago(now - 60_000, now), "1 minute ago");
        assert_eq!(ago(now - 7_200_000, now), "2 hours ago");
        assert_eq!(ago(now - 3 * 86_400_000, now), "3 days ago");
        assert_eq!(ago(now + 5_000, now), "just now");
    }

    #[test]
    fn uptime_reads_naturally() {
        assert_eq!(format_uptime(30), "0 minutes");
        assert_eq!(format_uptime(60), "1 minute");
        assert_eq!(format_uptime(3660), "1 hour, 1 minute");
        assert_eq!(format_uptime(4_603_242), "53 days, 6 hours");
    }

    #[test]
    fn an_os_is_named_with_its_version_when_known() {
        let facts = |list: &[(&str, &str)]| -> FlatFacts {
            list.iter()
                .map(|(name, value)| (name.to_string(), Value::from(*value)))
                .collect()
        };
        let both = facts(&[("os.name", "Ubuntu"), ("os.version", "24.04")]);
        assert_eq!(os_of(&both).as_deref(), Some("Ubuntu 24.04"));
        assert_eq!(
            os_of(&facts(&[("os.name", "Ubuntu")])).as_deref(),
            Some("Ubuntu")
        );
        assert_eq!(os_of(&facts(&[])), None);
        let long = facts(&[
            ("os.name", "Darwin"),
            ("os.long_version", "macOS 26.6.2 Tahoe"),
        ]);
        assert_eq!(os_of(&long).as_deref(), Some("macOS 26.6.2 Tahoe"));
    }

    fn shown(value: Value) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        fact_rows("", &value, &mut rows);
        rows.into_iter().map(|row| (row.name, row.value)).collect()
    }

    #[test]
    fn facts_show_in_their_natural_shape() {
        let rows = shown(serde_json::json!({
            "agent": { "collectors": ["cpu", "disk"], "version": "0.1.0" },
            "cores": 12,
            "disks": [{ "name": "a" }],
        }));
        let pairs = |name: &str, value: &str| (name.to_string(), value.to_string());
        assert_eq!(
            rows,
            [
                pairs("agent.collectors", "cpu, disk"),
                pairs("agent.version", "0.1.0"),
                pairs("cores", "12"),
                pairs("disks[0].name", "a"),
            ]
        );
    }

    #[test]
    fn config_state_compares_desired_with_reported() {
        fn label(desired: Option<&str>, reported: Option<&ConfigStatus>) -> &'static str {
            config_state(desired, reported).label
        }

        assert_eq!(label(Some("a"), None), "Not reported");
        assert_eq!(label(Some("a"), Some(&status("a", None))), "Up to date");
        assert_eq!(label(Some("b"), Some(&status("a", None))), "Updating");
        assert_eq!(label(Some("a"), Some(&status("a", Some("no")))), "Rejected");
    }
}
