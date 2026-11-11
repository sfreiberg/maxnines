use std::collections::BTreeMap;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::fleet::{Health, OsFamily};
use super::host_list::{HostSearch, address, page_number, paginate};
use super::{CsrfForm, Page, server_error, signed_in_user, viewer_zone};
use crate::agent_versions::{self, NEWEST_AGENT_VERSION, VersionState};
use crate::alerting::Alert;
use crate::app_state::{AgentDeletion, AppState};
use crate::fact_history::describe_history;
use crate::facts::{FlatFacts, fact_text, unflatten};
use crate::host_filter::{self, MAX_SUGGESTIONS, PartialValue, Suggestion, suggest_names};
use crate::locations::Locator;
use crate::metric_charts::format_value;
use crate::metrics::Unit;
use crate::metrics::now_ms;
use crate::models::ConfigStatus;
use crate::registration::{AgentRecord, AgentState, short_id};
use crate::rule_engine;
use crate::silences::{ActiveSilences, Cover, SilenceInput};
use crate::times::format_time;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/agents", get(index))
        .route("/agents/filter-options", get(filter_options))
        .route("/agents/{id}", get(show))
        .route("/agents/{id}/approve", post(approve))
        .route("/agents/{id}/revoke", post(revoke))
        .route("/agents/{id}/delete", post(delete))
        .route("/agents/{id}/maintenance", post(start_maintenance))
        .route("/agents/{id}/maintenance/end", post(end_maintenance))
}

#[derive(Serialize)]
struct AgentRow {
    id: String,
    short_id: String,
    host: String,
    state: &'static str,
    online: bool,
    health: Health,
    os: Option<String>,
    os_family: Option<OsFamily>,
    seen: Option<String>,
    config: Option<ConfigState>,
    /// The agent's own version, as it reports it.
    version: Option<String>,
    /// Nothing when it hasn't said, or what it said isn't a version.
    version_state: Option<VersionState>,
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
                exact: None,
            });
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                fact_rows(&format!("{prefix}[{index}]"), item, rows);
            }
        }
        scalar => rows.push(FactRow {
            name: prefix.to_string(),
            value: readable(prefix, scalar).unwrap_or_else(|| fact_text(scalar)),
            exact: readable(prefix, scalar).map(|_| fact_text(scalar)),
        }),
    }
}

/// A size in bytes, as a person would write it, like 48 GiB for a memory total. The
/// exact number is still there to hover over.
fn readable(name: &str, value: &Value) -> Option<String> {
    let bytes = value.as_f64().filter(|_| name.ends_with("_bytes"))?;
    Some(format_value(Unit::Bytes, bytes))
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

pub fn format_uptime(secs: u64) -> String {
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

/// Everything shown about an agent except its config, which takes more working out.
fn row(
    state: &AppState,
    agent: AgentRecord,
    facts: Option<&FlatFacts>,
    health: Health,
) -> AgentRow {
    let presence = state.presence.get(&agent.id);
    let version = facts.and_then(|facts| text_fact(facts, "agent.version"));
    AgentRow {
        version_state: version.as_deref().and_then(agent_versions::compare),
        version,
        online: presence.as_ref().is_some_and(|p| p.online),
        health,
        os: facts.and_then(os_of),
        os_family: facts.and_then(OsFamily::of),
        seen: presence.map(|p| ago(p.last_seen_ms, now_ms() as u64)),
        config: None,
        state: agent.state.as_str(),
        short_id: short_id(&agent.id).to_string(),
        id: agent.id,
        host: agent.host,
    }
}

#[derive(Deserialize)]
struct ListParams {
    view: Option<String>,
    filter: Option<String>,
    q: Option<String>,
    page: Option<String>,
}

#[derive(Serialize)]
struct FilterTab {
    label: &'static str,
    count: usize,
    selected: bool,
    href: String,
}

#[derive(Serialize)]
struct WaitingAgent {
    id: String,
    host: String,
    seen: Option<String>,
}

/// An agent in the list, with only what it takes to sort and count them all.
struct Listed {
    agent: AgentRecord,
    online: bool,
    health: Health,
}

/// Whether an agent belongs under a filter on the list.
fn matches(filter: &str, listed: &Listed) -> bool {
    match filter {
        "online" => listed.online,
        "offline" => !listed.online && listed.agent.state == AgentState::Approved,
        "revoked" => listed.agent.state == AgentState::Revoked,
        _ => true,
    }
}

/// Works out the rows being shown, which is far fewer than the agents there can be.
async fn page_rows(state: &AppState, listed: Vec<Listed>, as_table: bool) -> Result<Vec<AgentRow>> {
    let ids: Vec<&str> = listed.iter().map(|item| item.agent.id.as_str()).collect();
    let facts = state.database.facts_of(&ids).await?;
    let rules = if as_table {
        state.database.list_rules().await?
    } else {
        Vec::new()
    };

    let mut rows = Vec::with_capacity(listed.len());
    for item in listed {
        let id = item.agent.id.clone();
        let mine = facts.get(&id);
        let mut row = row(state, item.agent, mine, item.health);
        if as_table {
            let flat = mine.cloned().unwrap_or_default();
            let desired = rule_engine::resolve(&rules, &unflatten(&flat), &id).ok();
            let reported = state.database.config_status(&id).await.ok().flatten();
            row.config = Some(config_state(
                desired.as_ref().map(|d| d.version.as_str()),
                reported.as_ref(),
            ));
        }
        rows.push(row);
    }
    Ok(rows)
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
    token: CsrfToken,
) -> Response {
    let data = async {
        let search = HostSearch::load(&state, params.q.as_deref()).await?;
        let alerts = state.database.open_alerts().await?;
        anyhow::Ok((search, alerts))
    };
    let (search, open) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };
    let mut alerts: BTreeMap<&str, Vec<&Alert>> = BTreeMap::new();
    for alert in &open {
        alerts.entry(&alert.agent_id).or_default().push(alert);
    }

    let mut waiting = Vec::new();
    let mut listed = Vec::new();
    for agent in state.registry.list().await {
        if agent.is_local() {
            continue;
        }
        let presence = state.presence.get(&agent.id);
        if agent.state == AgentState::Pending {
            // Waiting agents never get as far as presence, so the registry remembers.
            let asked = state.registry.last_asked_ms(&agent.id);
            waiting.push(WaitingAgent {
                seen: asked.map(|ms| ago(ms, now_ms() as u64)),
                id: agent.id,
                host: agent.host,
            });
        } else if search.includes(&agent.id, &agent.host) {
            // A revoked agent's connection closes a moment after it's revoked, and it
            // doesn't count as online in the meantime.
            let online = agent.state == AgentState::Approved && presence.is_some_and(|p| p.online);
            let mine = alerts.get(agent.id.as_str()).map_or(&[][..], Vec::as_slice);
            let health = Health::of(online, mine);
            listed.push(Listed {
                agent,
                online,
                health,
            });
        }
    }
    listed.sort_by(|a, b| {
        a.health
            .cmp(&b.health)
            .then_with(|| a.agent.host.cmp(&b.agent.host))
    });

    let as_table = params.view.as_deref() == Some("table");
    let view = if as_table { "table" } else { "" };
    let selected = params.filter.as_deref().unwrap_or("all");
    let tab = if selected == "all" { "" } else { selected };
    let text = search.text.as_str();
    let filters: Vec<FilterTab> = [
        ("all", "All"),
        ("online", "Online"),
        ("offline", "Offline"),
        ("revoked", "Revoked"),
    ]
    .into_iter()
    .map(|(key, label)| FilterTab {
        label,
        count: listed.iter().filter(|item| matches(key, item)).count(),
        selected: key == selected,
        href: address(
            "/agents",
            &[
                ("filter", if key == "all" { "" } else { key }),
                ("view", view),
                ("q", text),
            ],
        ),
    })
    .collect();

    let online = listed.iter().filter(|item| item.online).count();
    let total = listed
        .iter()
        .filter(|item| item.agent.state == AgentState::Approved)
        .count();
    listed.retain(|item| matches(selected, item));

    let pages = paginate(&mut listed, page_number(params.page.as_deref()), |page| {
        address(
            "/agents",
            &[
                ("filter", tab),
                ("view", view),
                ("q", text),
                ("page", &page.to_string()),
            ],
        )
    });
    let agents = match page_rows(&state, listed, as_table).await {
        Ok(agents) => agents,
        Err(error) => return server_error(&error),
    };

    Page::new(&state, &token, "agents/index.html")
        .with("agents", &agents)
        .with("waiting", &waiting)
        .with("filters", &filters)
        .with("online_count", &online)
        .with("total", &total)
        .with("as_table", &as_table)
        .with("newest_agent_version", NEWEST_AGENT_VERSION)
        .with("pages", &pages)
        .with("search", &search)
        .with("search_path", "/agents")
        .with("keep_tab", tab)
        .with(
            "tiles_href",
            &address("/agents", &[("filter", tab), ("q", text)]),
        )
        .with(
            "table_href",
            &address(
                "/agents",
                &[("filter", tab), ("view", "table"), ("q", text)],
            ),
        )
        .render()
}

#[derive(Deserialize)]
struct OptionParams {
    term: Option<String>,
}

/// What the filter box can offer for the word being typed.
async fn filter_options(
    State(state): State<AppState>,
    Query(params): Query<OptionParams>,
) -> Response {
    let term = params.term.unwrap_or_default();
    match suggestions(&state, &term).await {
        Ok(suggestions) => Json(suggestions).into_response(),
        Err(error) => server_error(&error),
    }
}

pub async fn suggestions(state: &AppState, term: &str) -> anyhow::Result<Vec<Suggestion>> {
    let Some(value) = PartialValue::of(term) else {
        return Ok(suggest_names(term, state.database.fact_names().await?));
    };
    let values = if value.is_host() {
        let wanted = value.partial.to_lowercase();
        let mut hosts: Vec<String> = state
            .registry
            .list()
            .await
            .into_iter()
            .filter(|agent| !agent.is_local() && agent.host.to_lowercase().contains(&wanted))
            .map(|agent| agent.host)
            .collect();
        hosts.sort();
        hosts.truncate(MAX_SUGGESTIONS);
        hosts
    } else if value.is_id() {
        // By the start of the ID or by name, shown as the name so it can be picked.
        let wanted = value.partial.to_lowercase();
        let mut agents: Vec<AgentRecord> = state
            .registry
            .list()
            .await
            .into_iter()
            .filter(|agent| {
                !agent.is_local()
                    && (agent.id.starts_with(&wanted)
                        || agent.host.to_lowercase().contains(&wanted))
            })
            .collect();
        agents.sort_by(|a, b| a.host.cmp(&b.host).then_with(|| a.id.cmp(&b.id)));
        agents.truncate(MAX_SUGGESTIONS);
        return Ok(agents
            .iter()
            .map(|agent| {
                let label = format!("{} ({})", agent.host, short_id(&agent.id));
                value.labelled(&agent.id, label)
            })
            .collect());
    } else {
        state
            .database
            .fact_values(value.fact(), value.partial, MAX_SUGGESTIONS as u64)
            .await?
    };
    Ok(values.iter().map(|text| value.suggestion(text)).collect())
}

#[derive(Serialize)]
struct FactRow {
    name: String,
    value: String,
    /// The value as reported, where it's shown another way.
    exact: Option<String>,
}

#[derive(Serialize)]
struct HistoryEntry {
    time: String,
    changes: Vec<String>,
}

/// Where the map puts a machine, and whether it's by a rule of its own.
#[derive(Serialize)]
struct Location {
    rule_id: i64,
    name: String,
    place: String,
    just_this_one: bool,
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
    let own = match state.metrics.latest_output(&id, "agent", now_ms()).await {
        Ok(output) => output,
        Err(error) => return server_error(&error),
    };
    let own_memory = own
        .as_ref()
        .and_then(|agent| agent["memory_bytes"].as_f64());
    let own_uptime = own.as_ref().and_then(|agent| agent["uptime_secs"].as_u64());
    let uptime = match state.metrics.latest_output(&id, "host", now_ms()).await {
        Ok(output) => output.and_then(|host| host["uptime_secs"].as_u64()),
        Err(error) => return server_error(&error),
    };
    let locator = match Locator::load(&state.database).await {
        Ok(locator) => locator,
        Err(error) => return server_error(&error),
    };
    let own_filter = host_filter::only(&id);
    let location = locator.locate(&id, &agent.host).map(|rule| Location {
        rule_id: rule.id,
        name: rule.rule.name.clone(),
        place: rule.rule.place.clone(),
        just_this_one: rule.rule.filter == own_filter,
    });
    let maintenance = match maintenance_of(&state, &agent).await {
        Ok(maintenance) => maintenance,
        Err(error) => return server_error(&error),
    };
    let choices: Vec<MaintenanceChoice> = MAINTENANCE_CHOICES
        .iter()
        .map(|(secs, label)| MaintenanceChoice {
            secs: *secs,
            label,
            chosen: *secs == DEFAULT_MAINTENANCE_SECS,
        })
        .collect();
    let presence = state.presence.get(&id);
    let config = serde_json::to_string_pretty(&desired.config).unwrap_or_default();
    let zone = viewer_zone();
    let changes: Vec<HistoryEntry> = describe_history(&history)
        .into_iter()
        .rev()
        .map(|(time, changes)| HistoryEntry {
            time: format_time(time, zone),
            changes,
        })
        .collect();

    let online = state.presence.get(&id).is_some_and(|p| p.online);
    let mut row = row(
        &state,
        agent.clone(),
        Some(&flat),
        Health::of(online, &alerts),
    );
    row.config = Some(config_state(
        Some(desired.version.as_str()),
        reported.as_ref(),
    ));
    Page::new(&state, &token, "agents/show.html")
        .with("agent", &row)
        .with("decided_by", &agent.decided_by)
        .with("has_facts", &!flat.is_empty())
        .with("alerts", &alerts)
        .with("uptime", &uptime.map(format_uptime))
        .with("agent_uptime", &own_uptime.map(format_uptime))
        .with(
            "own_memory",
            &own_memory.map(|bytes| format_value(Unit::Bytes, bytes)),
        )
        .with("location", &location)
        .with("maintenance", &maintenance)
        .with("maintenance_choices", &choices)
        .with("os", &os_of(&flat))
        .with("os_family", &OsFamily::of(&flat))
        .with("source", &presence.map(|p| p.source.to_string()))
        .with("newest_agent_version", NEWEST_AGENT_VERSION)
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

/// How long maintenance can be started for from a machine's page, in seconds, with
/// what the page calls each. Anything else goes through Silences.
const MAINTENANCE_CHOICES: [(u64, &str); 6] = [
    (1800, "30 minutes"),
    (3600, "1 hour"),
    (2 * 3600, "2 hours"),
    (4 * 3600, "4 hours"),
    (8 * 3600, "8 hours"),
    (86_400, "1 day"),
];
const DEFAULT_MAINTENANCE_SECS: u64 = 3600;

/// What's holding back this machine's notifications, for its page.
#[derive(Serialize)]
struct Maintenance {
    until: String,
    /// The silence's reason, or the maintenance window's name.
    why: String,
    by: Option<String>,
    /// Started for this machine alone, so its page can end it.
    just_this_one: bool,
    window: bool,
}

#[derive(Serialize)]
struct MaintenanceChoice {
    secs: u64,
    label: &'static str,
    chosen: bool,
}

/// What's keeping all of this machine's alerts quiet, if anything is. A silence
/// for some rules only doesn't count, as the machine isn't quiet.
async fn maintenance_of(state: &AppState, agent: &AgentRecord) -> Result<Option<Maintenance>> {
    let now = now_ms();
    let active = ActiveSilences::load(&state.database, now).await?;
    let Some(cover) = active.covering_machine(&agent.id, &agent.host) else {
        return Ok(None);
    };
    let until = super::local_time(cover.ends_ms());
    Ok(match cover {
        Cover::Silence { id, .. } => {
            let silences = state.database.active_silences(now).await?;
            silences
                .into_iter()
                .find(|silence| silence.id == id)
                .map(|silence| Maintenance {
                    until,
                    just_this_one: silence.filter == host_filter::only(&agent.id),
                    why: silence.reason,
                    by: Some(silence.created_by),
                    window: false,
                })
        }
        Cover::Window { id, .. } => {
            let windows = state.database.list_maintenance_windows().await?;
            windows
                .into_iter()
                .find(|window| window.id == id)
                .map(|window| Maintenance {
                    until,
                    why: window.window.name,
                    by: None,
                    just_this_one: false,
                    window: true,
                })
        }
    })
}

/// Holds back every notification about this machine for a while, with a silence
/// of its own, so the Silences page shows it like any other.
async fn start_maintenance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    let Some(agent) = state
        .registry
        .get(&id)
        .await
        .filter(|agent| !agent.is_local())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let duration_secs = form
        .fields
        .get("duration_secs")
        .and_then(|secs| secs.parse().ok())
        .filter(|secs| MAINTENANCE_CHOICES.iter().any(|(choice, _)| choice == secs));
    let Some(duration_secs) = duration_secs else {
        return (StatusCode::BAD_REQUEST, "Choose how long from the list.").into_response();
    };
    let reason = form.fields.get("reason").map(|reason| reason.trim());
    let reason = match reason {
        Some(reason) if !reason.is_empty() => reason.to_string(),
        _ => format!("Maintenance on {}", agent.host),
    };
    let input = SilenceInput {
        rule_id: None,
        filter: host_filter::only(&agent.id),
        reason,
        duration_secs,
    };
    if let Err(error) = state.check_silence(&input).await {
        return (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response();
    }
    let by = signed_in_user().map_or_else(|| "admin".to_string(), |user| user.email.clone());
    match state.database.create_silence(&input, &by, now_ms()).await {
        Ok(_) => (form.token, Redirect::to(&format!("/agents/{id}"))).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Ends the silences started for this machine alone. Wider ones, and maintenance
/// windows, are left to their own pages.
async fn end_maintenance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    let now = now_ms();
    let silences = match state.database.active_silences(now).await {
        Ok(silences) => silences,
        Err(error) => return server_error(&error),
    };
    let own = host_filter::only(&id);
    for silence in silences
        .iter()
        .filter(|silence| silence.rule_id.is_none() && silence.filter == own)
    {
        if let Err(error) = state.database.end_silence(silence.id, now).await {
            return server_error(&error);
        }
    }
    (form.token, Redirect::to(&format!("/agents/{id}"))).into_response()
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
    let by = signed_in_user().map_or_else(|| "admin".to_string(), |user| user.email.clone());
    match state.registry.decide_as(&id, decision, &by).await {
        Ok(Some(_)) => (form.token, Redirect::to(&format!("/agents/{id}"))).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Only a revoked agent offers this, so it always takes two steps.
async fn delete(State(state): State<AppState>, Path(id): Path<String>, form: CsrfForm) -> Response {
    match state.delete_agent(&id).await {
        Ok(AgentDeletion::Deleted) => (form.token, Redirect::to("/agents")).into_response(),
        Ok(AgentDeletion::NoSuchAgent) => StatusCode::NOT_FOUND.into_response(),
        Ok(AgentDeletion::NotRevoked) => {
            (StatusCode::CONFLICT, "Revoke the agent before deleting it.").into_response()
        }
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
    fn sizes_in_bytes_read_as_sizes_with_the_exact_number_kept() {
        let facts = serde_json::json!({
            "memory": { "total_bytes": 17_179_869_184u64 },
            "cpu": { "logical_cores": 8 },
        });
        let mut rows = Vec::new();
        fact_rows("", &facts, &mut rows);
        let shown: Vec<(&str, &str, Option<&str>)> = rows
            .iter()
            .map(|row| (row.name.as_str(), row.value.as_str(), row.exact.as_deref()))
            .collect();
        assert_eq!(
            shown,
            [
                ("cpu.logical_cores", "8", None),
                ("memory.total_bytes", "16 GiB", Some("17179869184")),
            ]
        );
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
