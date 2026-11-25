use std::collections::BTreeMap;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_csrf::CsrfToken;
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::fleet::{Health, OsFamily};
use super::host_list::{HostSearch, address, page_number, paginate};
use super::{CsrfForm, Page, local_time, recorded_by, server_error, viewer_zone};
use crate::agent_versions::{self, NEWEST_AGENT_VERSION, VersionState};
use crate::alerting::Alert;
use crate::app_state::{AppState, HostDeletion};
use crate::fact_history::describe_history;
use crate::facts::{FlatFacts, fact_text, unflatten};
use crate::host_filter::{self, MAX_SUGGESTIONS, PartialValue, Suggestion, suggest_names};
use crate::locations::Locator;
use crate::metric_charts::format_value;
use crate::metrics::Unit;
use crate::models::ConfigStatus;
use crate::presence::Reach;
use crate::readings::{Array, Arrays, Drive, Drives, FailedServices, TimeSync, Updates};
use crate::registration::{HostRecord, HostState, Upgrade, short_id};
use crate::rule_engine::Host;
use crate::silences::{ActiveSilences, Cover, Silence, SilenceInput};
use crate::times::{self, format_moment, lasting};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/hosts", get(index).post(super::agentless::create))
        .route("/hosts/new", get(super::agentless::new))
        .route("/hosts/{id}/rename", post(super::agentless::rename))
        .route("/hosts/{id}/pages", post(super::agentless::create_page))
        .route("/hosts/{id}/pages/new", get(super::agentless::new_page))
        .route(
            "/hosts/{id}/pages/{page}",
            post(super::agentless::update_page),
        )
        .route(
            "/hosts/{id}/pages/{page}/edit",
            get(super::agentless::edit_page),
        )
        .route(
            "/hosts/{id}/pages/{page}/delete",
            post(super::agentless::delete_page),
        )
        .route("/hosts/filter-options", get(filter_options))
        .route("/hosts/{id}", get(show))
        .route("/hosts/{id}/approve", post(approve))
        .route("/hosts/{id}/revoke", post(revoke))
        .route("/hosts/{id}/delete", post(delete))
        .route("/hosts/{id}/maintenance", post(start_maintenance))
        .route("/hosts/{id}/maintenance/end", post(end_maintenance))
}

#[derive(Serialize)]
struct HostRow {
    id: String,
    short_id: String,
    hostname: String,
    state: &'static str,
    /// Whether the server reads from it itself, as it has no agent.
    agentless: bool,
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
    /// Which side has to be upgraded before the server takes the agent.
    needs_upgrading: Option<Upgrade>,
    /// Why the server refuses the agent, while it does.
    refused: Option<Refused>,
}

/// Why the server refuses a host's agent, for its page.
#[derive(Serialize)]
struct Refused {
    reason: String,
    /// How long it has, such as `3 hours 20 minutes`.
    lasted: String,
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

/// How long a collector says something has been running, as its `uptime_secs`.
fn uptime_of(output: &Value) -> Option<TimeDelta> {
    TimeDelta::try_seconds(output["uptime_secs"].as_i64()?)
}

pub fn format_uptime(uptime: TimeDelta) -> String {
    let part = |count: i64, unit: &str| match count {
        1 => format!("1 {unit}"),
        _ => format!("{count} {unit}s"),
    };
    let secs = uptime.num_seconds().max(0);
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
/// Whether it's online is as `Presence::reach` says, as lists and counts have it.
fn row(
    state: &AppState,
    host: HostRecord,
    facts: Option<&FlatFacts>,
    reach: Reach,
    health: Health,
) -> HostRow {
    let presence = state.presence.get(&host.id);
    let version = facts.and_then(|facts| text_fact(facts, "agent.version"));
    let needs_upgrading = host.needs_upgrading();
    let refused = needs_upgrading
        .and(host.refusal.refused_at)
        .zip(host.refusal.refused_reason.clone())
        .map(|(at, reason)| Refused {
            reason,
            lasted: lasting(times::now() - at),
        });
    HostRow {
        version_state: version.as_deref().and_then(agent_versions::compare),
        version,
        needs_upgrading,
        refused,
        online: reach == Reach::Online,
        health,
        os: facts.and_then(os_of),
        os_family: facts.and_then(OsFamily::of),
        seen: presence
            .and_then(|p| p.last_seen_at)
            .map(|seen| times::ago(seen, times::now())),
        config: None,
        state: host.state.as_str(),
        agentless: host.is_agentless(),
        short_id: short_id(&host.id).to_string(),
        id: host.id,
        hostname: host.hostname,
    }
}

#[derive(Deserialize)]
struct ListParams {
    view: Option<String>,
    /// Which tab: online, offline or revoked.
    status: Option<String>,
    /// A host filter, as typed in the box.
    filter: Option<String>,
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
struct WaitingHost {
    id: String,
    hostname: String,
    seen: Option<String>,
    /// An agent can wait for approval and need upgrading too.
    needs_upgrading: Option<Upgrade>,
}

/// An agent in the list, with only what it takes to sort and count them all.
struct Listed {
    host: HostRecord,
    reach: Reach,
    health: Health,
}

impl Listed {
    fn online(&self) -> bool {
        self.reach == Reach::Online
    }

    /// Neither online nor offline, as nothing is read for it.
    fn not_read(&self) -> bool {
        self.reach == Reach::NotRead
    }
}

/// Whether an agent belongs under a filter on the list.
fn matches(filter: &str, listed: &Listed) -> bool {
    match filter {
        "online" => listed.online(),
        "offline" => {
            !listed.online() && !listed.not_read() && listed.host.state == HostState::Approved
        }
        "revoked" => listed.host.state == HostState::Revoked,
        _ => true,
    }
}

/// Works out the rows being shown, which is far fewer than the agents there can be.
async fn page_rows(state: &AppState, listed: Vec<Listed>, as_table: bool) -> Result<Vec<HostRow>> {
    let ids: Vec<&str> = listed.iter().map(|item| item.host.id.as_str()).collect();
    let facts = state.database.facts_of(&ids).await?;
    let configs = if as_table {
        let rules = state.configs.rules().await?;
        let reported = state.database.config_statuses(&ids).await?;
        Some((rules, reported))
    } else {
        None
    };

    let mut rows = Vec::with_capacity(listed.len());
    for item in listed {
        let id = item.host.id.clone();
        let mine = facts.get(&id);
        let mut row = row(state, item.host, mine, item.reach, item.health);
        if let Some((rules, reported)) = &configs {
            let shape = unflatten(&mine.cloned().unwrap_or_default());
            let desired = rules.resolve(&Host::new(&shape, &id)).ok();
            row.config = Some(config_state(
                desired.as_ref().map(|d| d.version.as_str()),
                reported.get(&id),
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
        let search = HostSearch::load(&state, params.filter.as_deref()).await?;
        let alerts = state.database.open_alerts().await?;
        anyhow::Ok((search, alerts))
    };
    let (search, open) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };
    let mut alerts: BTreeMap<&str, Vec<&Alert>> = BTreeMap::new();
    for alert in &open {
        alerts.entry(&alert.host_id).or_default().push(alert);
    }

    let mut waiting = Vec::new();
    let mut listed = Vec::new();
    for host in state.registry.list().await {
        if host.is_local() {
            continue;
        }
        if host.state == HostState::Pending {
            // Waiting agents never get as far as presence, so the registry remembers.
            let asked = state.registry.last_asked_at(&host.id);
            waiting.push(WaitingHost {
                seen: asked.map(|asked| times::ago(asked, times::now())),
                needs_upgrading: host.needs_upgrading(),
                id: host.id,
                hostname: host.hostname,
            });
        } else if search.includes(&host.id, &host.hostname) {
            let reach = state.presence.reach(&host);
            let mine = alerts.get(host.id.as_str()).map_or(&[][..], Vec::as_slice);
            listed.push(Listed {
                reach,
                health: Health::of(reach, mine),
                host,
            });
        }
    }
    listed.sort_by(|a, b| {
        a.health
            .cmp(&b.health)
            .then_with(|| a.host.hostname.cmp(&b.host.hostname))
    });

    let as_table = params.view.as_deref() == Some("table");
    let view = if as_table { "table" } else { "" };
    let selected = params.status.as_deref().unwrap_or("all");
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
            "/hosts",
            &[
                ("status", if key == "all" { "" } else { key }),
                ("view", view),
                ("filter", text),
            ],
        ),
    })
    .collect();

    let online = listed.iter().filter(|item| item.online()).count();
    let total = listed
        .iter()
        .filter(|item| item.host.state == HostState::Approved && !item.not_read())
        .count();
    listed.retain(|item| matches(selected, item));

    let pages = paginate(&mut listed, page_number(params.page.as_deref()), |page| {
        address(
            "/hosts",
            &[
                ("status", tab),
                ("view", view),
                ("filter", text),
                ("page", &page.to_string()),
            ],
        )
    });
    let hosts = match page_rows(&state, listed, as_table).await {
        Ok(hosts) => hosts,
        Err(error) => return server_error(&error),
    };

    Page::new(&state, &token, "hosts/index.html")
        .with("hosts", &hosts)
        .with("waiting", &waiting)
        .with("filters", &filters)
        .with("online_count", &online)
        .with("total", &total)
        .with("as_table", &as_table)
        .with("newest_agent_version", NEWEST_AGENT_VERSION)
        .with("pages", &pages)
        .with("search", &search)
        .with("search_path", "/hosts")
        .with("keep_tab", tab)
        .with(
            "tiles_href",
            &address("/hosts", &[("status", tab), ("filter", text)]),
        )
        .with(
            "table_href",
            &address(
                "/hosts",
                &[("status", tab), ("view", "table"), ("filter", text)],
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
            .filter(|host| !host.is_local() && host.hostname.to_lowercase().contains(&wanted))
            .map(|host| host.hostname)
            .collect();
        hosts.sort();
        hosts.truncate(MAX_SUGGESTIONS);
        hosts
    } else if value.is_id() {
        // By the start of the ID or by name, shown as the name so it can be picked.
        let wanted = value.partial.to_lowercase();
        let mut hosts: Vec<HostRecord> = state
            .registry
            .list()
            .await
            .into_iter()
            .filter(|host| {
                !host.is_local()
                    && (host.id.starts_with(&wanted)
                        || host.hostname.to_lowercase().contains(&wanted))
            })
            .collect();
        hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname).then_with(|| a.id.cmp(&b.id)));
        hosts.truncate(MAX_SUGGESTIONS);
        return Ok(hosts
            .iter()
            .map(|host| {
                let label = format!("{} ({})", host.hostname, short_id(&host.id));
                value.labelled(&host.id, label)
            })
            .collect());
    } else {
        state
            .database
            .fact_values(value.fact(), value.partial, MAX_SUGGESTIONS)
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

/// Where the map puts a host, and whether it's by a rule of its own.
#[derive(Serialize)]
struct Location {
    rule_id: i64,
    name: String,
    place: Option<String>,
    just_this_one: bool,
}

async fn show(State(state): State<AppState>, Path(id): Path<String>, token: CsrfToken) -> Response {
    let found = state.registry.get(&id).await;
    let Some(host) = found.filter(|host| !host.is_local()) else {
        let page = Page::new(&state, &token, "errors/not_found.html");
        return page.with_status(StatusCode::NOT_FOUND).render();
    };
    let open = match state.database.open_alerts().await {
        Ok(open) => open,
        Err(error) => return server_error(&error),
    };
    let here: Vec<&Alert> = open.iter().filter(|alert| alert.host_id == id).collect();
    let now = crate::times::now();
    let alerts: Vec<OpenAlert> = here
        .iter()
        .map(|&alert| OpenAlert {
            lasted: lasting(now - alert.breached_at),
            began: local_time(alert.breached_at),
            alert,
        })
        .collect();

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
    let own = match state.metrics.latest_output(&id, "agent", now).await {
        Ok(output) => output,
        Err(error) => return server_error(&error),
    };
    let own_memory = own
        .as_ref()
        .and_then(|agent| agent["memory_bytes"].as_f64());
    let own_uptime = own.as_ref().and_then(uptime_of);
    let drives = match Drives::load(&state.metrics, &id, now).await {
        Ok(drives) => drives,
        Err(error) => return server_error(&error),
    };
    let drives_problem = drives.problem.clone();
    let drives: Vec<DriveRow> = drives.drives.iter().map(DriveRow::of).collect();
    let arrays = match Arrays::load(&state.metrics, &id, now).await {
        Ok(arrays) => arrays,
        Err(error) => return server_error(&error),
    };
    let arrays_problems = arrays.problems.clone();
    let arrays: Vec<ArrayRow> = arrays.arrays.iter().map(ArrayRow::of).collect();
    let updates = match Updates::load(&state.metrics, &id, now).await {
        Ok(updates) => updates.map(UpdatesCard::of),
        Err(error) => return server_error(&error),
    };
    let time_sync = match TimeSync::load(&state.metrics, &id, now).await {
        Ok(time_sync) => time_sync.map(TimeSyncCard::of),
        Err(error) => return server_error(&error),
    };
    let failed_services = match FailedServices::load(&state.metrics, &id, now).await {
        Ok(failed) => failed,
        Err(error) => return server_error(&error),
    };
    let uptime = match state.metrics.latest_output(&id, "host", now).await {
        Ok(output) => output.as_ref().and_then(uptime_of),
        Err(error) => return server_error(&error),
    };
    let locator = match Locator::load(&state.database).await {
        Ok(locator) => locator,
        Err(error) => return server_error(&error),
    };
    let own_filter = host_filter::only(&id);
    let location = locator.locate(&id, &host.hostname).map(|rule| Location {
        rule_id: rule.id,
        name: rule.rule.name.clone(),
        place: rule.rule.place.clone(),
        just_this_one: rule.rule.filter.as_ref() == Some(&own_filter),
    });
    let maintenance = match maintenance_of(&state, &host).await {
        Ok(maintenance) => maintenance,
        Err(error) => return server_error(&error),
    };
    let choices = maintenance_choices();
    let presence = state.presence.get(&id);
    let config = serde_json::to_string_pretty(&desired.config).unwrap_or_default();
    let zone = viewer_zone();
    let changes: Vec<HistoryEntry> = describe_history(&history)
        .into_iter()
        .rev()
        .map(|(time, changes)| HistoryEntry {
            time: format_moment(time, zone),
            changes,
        })
        .collect();

    let pages = match super::agentless::page_rows(&state, &id).await {
        Ok(pages) => pages,
        Err(error) => return server_error(&error),
    };
    let checks = match super::agentless::check_rows(&state, &id).await {
        Ok(checks) => checks,
        Err(error) => return server_error(&error),
    };
    let (runs, more_runs) = match super::templates::run_rows(&state, Some(&id), None).await {
        Ok(runs) => runs,
        Err(error) => return server_error(&error),
    };
    let reach = state.presence.reach(&host);
    let health = Health::of(reach, &here);
    let mut row = row(&state, host.clone(), Some(&flat), reach, health);
    row.config = Some(config_state(
        Some(desired.version.as_str()),
        reported.as_ref(),
    ));
    Page::new(&state, &token, "hosts/show.html")
        .with("host", &row)
        .with("pages", &pages)
        .with("checks", &checks)
        .with("runs", &runs)
        .with("more_runs", &more_runs)
        .with("drives", &drives)
        .with("drives_problem", &drives_problem)
        .with("arrays", &arrays)
        .with("arrays_problems", &arrays_problems)
        .with("updates", &updates)
        .with("time_sync", &time_sync)
        .with("failed_services", &failed_services)
        .with("decided_by", &host.decided_by)
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
        // A host with no agent never connected from anywhere.
        .with(
            "source",
            &presence
                .filter(|_| !host.is_agentless())
                .map(|p| p.source.to_string()),
        )
        .with("newest_agent_version", NEWEST_AGENT_VERSION)
        .with("agent_commit", &text_fact(&flat, "agent.commit"))
        .with("agent_protocol", &flat.get("agent.protocol"))
        .with(
            "agent_rust_version",
            &text_fact(&flat, "agent.rust_version"),
        )
        .with("facts", &facts)
        .with("config", &config)
        .with("version", &desired.version)
        .with("matched_rules", &desired.matched_rules)
        .with("skipped_collectors", &desired.skipped_collectors)
        .with("reported", &reported)
        .with("history", &changes)
        .render()
}

/// One drive on a host's page, from its newest SMART reading.
#[derive(Debug, PartialEq, Serialize)]
struct DriveRow {
    /// Its model and serial number, which its series are called.
    name: Option<String>,
    device: String,
    /// Whether it passes its own assessment, if it says.
    healthy: Option<bool>,
    temperature: Option<String>,
    /// Why there's nothing to show, or that it's asleep.
    note: Option<String>,
}

impl DriveRow {
    fn of(drive: &Drive) -> Self {
        let note = if drive.asleep {
            Some("Asleep, so not asked. This is what it last said.".to_string())
        } else {
            drive.note.clone()
        };
        Self {
            name: drive.name.clone(),
            device: drive.device.clone(),
            healthy: drive.healthy,
            temperature: drive
                .temperature_celsius
                .map(|celsius| format_value(Unit::Celsius, celsius)),
            note,
        }
    }
}

/// The thresholds of the built-in RAID and ZFS template's alerts, `templates/raid.hcl`,
/// which an array's badge goes by too, so the page says what the alerts do. A test
/// checks the template has the same. `zfs_full` warns past the first and is
/// critical past the second.
const ZFS_NEARLY_FULL_PERCENT: f64 = 80.0;
const ZFS_FULL_PERCENT: f64 = 90.0;
/// `zfs_scrub_overdue` warns when the last scrub finished longer ago than this.
const ZFS_SCRUB_OVERDUE_HOURS: u64 = 35 * 24;

/// One RAID array or ZFS pool on a host's page, from its newest reading.
#[derive(Debug, PartialEq, Serialize)]
struct ArrayRow {
    name: String,
    /// What it is and how it's laid out, such as `ZFS mirror`.
    what: String,
    /// `good`, `warn` or `bad`, for its badge, and the badge's word.
    badge: &'static str,
    health: &'static str,
    /// Its system's own word for how it is, and the devices that aren't working.
    state: Option<String>,
    not_working: Option<String>,
    note: Option<String>,
    /// A rebuild or scrub running, how far it has got and how fast it goes.
    progress: Option<String>,
    /// How full a ZFS pool is.
    space: Option<String>,
    /// A ZFS pool's errors, when it has any.
    errors: Option<String>,
    /// When a ZFS pool's last scrub finished, and what it repaired.
    last_scrub: Option<String>,
}

impl ArrayRow {
    fn of(array: &Array) -> Self {
        let any = |count: Option<u64>| count.is_some_and(|count| count > 0);
        let used_over = |percent: f64| array.used_percent.is_some_and(|used| used > percent);
        // As the built-in alerts see it, the worst first, leaving out how long
        // each has to last: critical `raid_failed`, `raid_degraded`, `zfs_errors`
        // for data errors and `zfs_full`, then warnings for `raid_rebuilding`,
        // `zfs_errors` for device errors, `zfs_full` and `zfs_scrub_overdue`.
        let (badge, health) = if array.failed {
            ("bad", "Failed")
        } else if array.degraded {
            ("bad", "Degraded")
        } else if any(array.data_errors) {
            ("bad", "Data errors")
        } else if used_over(ZFS_FULL_PERCENT) {
            ("bad", "Nearly full")
        } else if array.rebuilding {
            ("warn", "Rebuilding")
        } else if any(array.read_errors) || any(array.write_errors) || any(array.checksum_errors) {
            ("warn", "Errors")
        } else if used_over(ZFS_NEARLY_FULL_PERCENT) {
            ("warn", "Nearly full")
        } else if array
            .scrub_age_secs
            .is_some_and(|age| age > ZFS_SCRUB_OVERDUE_HOURS * 3600)
        {
            ("warn", "Not scrubbed")
        } else {
            ("good", "Healthy")
        };
        let kind = match array.kind.as_deref() {
            Some("md") => "md",
            Some("zfs") => "ZFS",
            Some("storage_spaces") => "Storage Spaces",
            Some("appleraid") => "AppleRAID",
            _ => "",
        };
        let what = [kind, array.level.as_deref().unwrap_or_default()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let speed = array
            .speed_bytes_per_sec
            .map(|speed| format!(" at {}", format_value(Unit::BytesPerSecond, speed)))
            .unwrap_or_default();
        let done = |percent: Option<f64>| {
            percent
                .map(|percent| format!(" {}", format_value(Unit::Percent, percent)))
                .unwrap_or_default()
        };
        let progress = if array.rebuilding {
            Some(format!("Rebuilding{}{speed}", done(array.rebuild_percent)))
        } else {
            array
                .scrub_percent
                .map(|_| format!("Scrubbing{}{speed}", done(array.scrub_percent)))
        };
        let space = array.used_percent.map(|used| {
            let mut space = format!("{} used", format_value(Unit::Percent, used));
            if let Some(size) = array.size_bytes {
                space = format!("{space} of {}", format_value(Unit::Bytes, size as f64));
            }
            if let Some(fragmentation) = array.fragmentation_percent {
                space = format!(
                    "{space}, {} fragmented",
                    format_value(Unit::Percent, fragmentation)
                );
            }
            space
        });
        let counted = [
            (array.read_errors, "read"),
            (array.write_errors, "write"),
            (array.checksum_errors, "checksum"),
            (array.data_errors, "data"),
        ];
        let errors: Vec<String> = counted
            .iter()
            .filter_map(|(count, kind)| {
                Some(format!("{} {kind}", count.filter(|count| *count > 0)?))
            })
            .collect();
        let errors = (!errors.is_empty()).then(|| errors.join(", "));
        let last_scrub = array.scrub_age_secs.map(|age| {
            let mut said = format!("{} ago", format_value(Unit::Seconds, age as f64));
            if let Some(repaired) = array.scrub_repaired_bytes.filter(|bytes| *bytes > 0) {
                said = format!(
                    "{said}, repaired {}",
                    format_value(Unit::Bytes, repaired as f64)
                );
            }
            if let Some(left) = array.scrub_errors.filter(|errors| *errors > 0) {
                said = format!("{said}, {left} errors left");
            }
            said
        });
        Self {
            name: array.name.clone(),
            what,
            badge,
            health,
            state: array.state.clone(),
            not_working: array.not_working.clone(),
            note: array.note.clone(),
            progress,
            space,
            errors,
            last_scrub,
        }
    }
}

/// Whether a host is up to date, in words for its page.
#[derive(Debug, PartialEq, Serialize)]
struct UpdatesCard {
    /// What was asked, such as apt.
    manager: Option<String>,
    /// How many are waiting, and how many of them are for security if the system
    /// says.
    waiting: Option<String>,
    vulnerable: Option<String>,
    reboot: Option<&'static str>,
    lists_age: Option<String>,
    /// Why nothing could be asked, with what to do about it.
    problem: Option<String>,
    /// What went wrong with part of it.
    note: Option<String>,
}

impl UpdatesCard {
    fn of(updates: Updates) -> Self {
        let waiting = updates.pending.map(|pending| match updates.security {
            Some(security) => format!("{pending}, {security} for security"),
            None => pending.to_string(),
        });
        Self {
            manager: updates.manager,
            waiting,
            vulnerable: updates.vulnerable.map(|count| format!("{count} packages")),
            reboot: updates
                .reboot_required
                .map(|reboot| if reboot { "Yes" } else { "No" }),
            lists_age: updates
                .lists_age_secs
                .map(|secs| format_value(Unit::Seconds, secs as f64)),
            problem: updates.problem,
            note: updates.note,
        }
    }
}

/// Whether a host's clock is kept in sync, in words for its page.
#[derive(Debug, PartialEq, Serialize)]
struct TimeSyncCard {
    synced: Option<&'static str>,
    max_error: Option<String>,
    offset: Option<String>,
    sources: Option<String>,
    /// Why it couldn't be read, or why whether it's synced isn't known.
    problem: Option<String>,
}

impl TimeSyncCard {
    fn of(time_sync: TimeSync) -> Self {
        Self {
            synced: time_sync
                .synced
                .map(|synced| if synced { "Yes" } else { "No" }),
            max_error: time_sync
                .max_error_secs
                .map(|secs| format_value(Unit::Seconds, secs)),
            offset: time_sync
                .offset_secs
                .map(|secs| format_value(Unit::Seconds, secs)),
            sources: time_sync.sources.map(|sources| sources.to_string()),
            problem: time_sync.problem,
        }
    }
}

/// How long maintenance can be started for from a host's page, with what the page
/// calls each. Anything else goes through Silences.
const MAINTENANCE_CHOICES: [(TimeDelta, &str); 6] = [
    (TimeDelta::minutes(30), "30 minutes"),
    (TimeDelta::hours(1), "1 hour"),
    (TimeDelta::hours(2), "2 hours"),
    (TimeDelta::hours(4), "4 hours"),
    (TimeDelta::hours(8), "8 hours"),
    (TimeDelta::days(1), "1 day"),
];
const DEFAULT_MAINTENANCE: TimeDelta = TimeDelta::hours(1);

/// What's holding back notifications about a host, or about one check, for its
/// page.
#[derive(Serialize)]
pub(super) struct Maintenance {
    until: String,
    /// The silence's reason, or the maintenance window's name.
    why: String,
    by: Option<String>,
    /// Started from that page for it alone, so the page can end it.
    just_this_one: bool,
    window: bool,
}

/// One of [`MAINTENANCE_CHOICES`], for a form, which sends how long in seconds.
#[derive(Serialize)]
pub(super) struct MaintenanceChoice {
    secs: i64,
    label: &'static str,
    chosen: bool,
}

/// How long maintenance can be started for from a page.
pub(super) fn maintenance_choices() -> Vec<MaintenanceChoice> {
    MAINTENANCE_CHOICES
        .iter()
        .map(|(length, label)| MaintenanceChoice {
            secs: length.num_seconds(),
            label,
            chosen: *length == DEFAULT_MAINTENANCE,
        })
        .collect()
}

/// How long a page's form asked for, if it's one of the choices.
pub(super) fn maintenance_length(form: &CsrfForm) -> Option<TimeDelta> {
    form.fields
        .get("duration_secs")
        .and_then(|secs| TimeDelta::try_seconds(secs.parse().ok()?))
        .filter(|length| {
            MAINTENANCE_CHOICES
                .iter()
                .any(|(choice, _)| choice == length)
        })
}

/// What's keeping all of this host's alerts quiet, if anything is. A silence
/// for some rules only doesn't count, as the host isn't quiet.
async fn maintenance_of(state: &AppState, host: &HostRecord) -> Result<Option<Maintenance>> {
    let now = times::now();
    let active = ActiveSilences::load(&state.database, now).await?;
    let cover = active.covering_host(&host.id, &host.hostname);
    let own = host_filter::only(&host.id);
    described(state, cover, |silence| {
        silence.filter.as_ref() == Some(&own) && silence.series.is_none()
    })
    .await
}

/// What a cover is, for a page to say. `own` says whether a silence is the one
/// the page itself starts.
pub(super) async fn described(
    state: &AppState,
    cover: Option<Cover>,
    own: impl Fn(&Silence) -> bool,
) -> Result<Option<Maintenance>> {
    let Some(cover) = cover else {
        return Ok(None);
    };
    let now = times::now();
    let until = super::local_time(cover.ends_at());
    Ok(match cover {
        Cover::Silence { id, .. } => {
            let silences = state.database.active_silences(now).await?;
            silences
                .into_iter()
                .find(|silence| silence.id == id)
                .map(|silence| Maintenance {
                    until,
                    just_this_one: own(&silence),
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

/// Holds back every notification about this host for a while, with a silence
/// of its own, so the Silences page shows it like any other.
async fn start_maintenance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    let Some(host) = state
        .registry
        .get(&id)
        .await
        .filter(|host| !host.is_local())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(duration) = maintenance_length(&form) else {
        return (StatusCode::BAD_REQUEST, "Choose how long from the list.").into_response();
    };
    let reason = form.fields.get("reason").map(|reason| reason.trim());
    let reason = match reason {
        Some(reason) if !reason.is_empty() => reason.to_string(),
        _ => format!("Maintenance on {}", host.hostname),
    };
    let input = SilenceInput {
        rule_id: None,
        filter: Some(host_filter::only(&host.id)),
        series: None,
        all_alerts: false,
        reason,
        duration,
    };
    if let Err(error) = state.check_silence(&input).await {
        return (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response();
    }
    let by = recorded_by();
    match state
        .database
        .create_silence(&input, &by, times::now())
        .await
    {
        Ok(_) => (form.token, Redirect::to(&format!("/hosts/{id}"))).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Ends the silences started for this host alone. Wider ones, and maintenance
/// windows, are left to their own pages.
async fn end_maintenance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    let now = times::now();
    let silences = match state.database.active_silences(now).await {
        Ok(silences) => silences,
        Err(error) => return server_error(&error),
    };
    let own = host_filter::only(&id);
    for silence in silences
        .iter()
        .filter(|silence| silence.rule_id.is_none() && silence.filter.as_ref() == Some(&own))
        .filter(|silence| silence.series.is_none())
    {
        if let Err(error) = state.database.end_silence(silence.id, now).await {
            return server_error(&error);
        }
    }
    (form.token, Redirect::to(&format!("/hosts/{id}"))).into_response()
}

async fn approve(state: State<AppState>, id: Path<String>, form: CsrfForm) -> Response {
    decide(state, id, form, HostState::Approved).await
}

async fn revoke(state: State<AppState>, id: Path<String>, form: CsrfForm) -> Response {
    decide(state, id, form, HostState::Revoked).await
}

async fn decide(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
    decision: HostState,
) -> Response {
    let by = recorded_by();
    match state.registry.decide_as(&id, decision, &by).await {
        Ok(Some(_)) => (form.token, Redirect::to(&format!("/hosts/{id}"))).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Only a revoked agent offers this, so it always takes two steps.
async fn delete(State(state): State<AppState>, Path(id): Path<String>, form: CsrfForm) -> Response {
    match state.delete_host(&id).await {
        Ok(HostDeletion::Deleted) => (form.token, Redirect::to("/hosts")).into_response(),
        Ok(HostDeletion::NoSuchHost) => StatusCode::NOT_FOUND.into_response(),
        Ok(HostDeletion::NotRevoked) => {
            (StatusCode::CONFLICT, "Revoke the host before deleting it.").into_response()
        }
        Err(error) => server_error(&error),
    }
}

/// An open alert on the host's page, with how long its problem has lasted.
#[derive(Serialize)]
struct OpenAlert<'a> {
    #[serde(flatten)]
    alert: &'a Alert,
    lasted: String,
    /// When it began, where the viewer is.
    began: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_arrays_badge_goes_by_the_built_in_alerts_thresholds() {
        let templates = crate::templates::built_in::all().unwrap();
        let raid = templates
            .iter()
            .find(|built_in| built_in.template.key == "raid")
            .unwrap();
        let alert = |key: &str| {
            raid.template
                .alerts
                .iter()
                .find(|alert| alert.key == key)
                .unwrap()
        };
        let full = alert("zfs_full");
        assert_eq!(
            full.warning.as_deref(),
            Some(format!("zfs.used > {ZFS_NEARLY_FULL_PERCENT}").as_str())
        );
        assert_eq!(
            full.critical.as_deref(),
            Some(format!("zfs.used > {ZFS_FULL_PERCENT}").as_str())
        );
        assert_eq!(
            alert("zfs_scrub_overdue").warning.as_deref(),
            Some(format!("zfs.scrub_age > duration('{ZFS_SCRUB_OVERDUE_HOURS}h')").as_str())
        );

        let pool = |used: f64, scrubbed_days_ago: u64| {
            let array = Array {
                name: "tank".into(),
                kind: Some("zfs".into()),
                level: Some("mirror".into()),
                state: Some("ONLINE".into()),
                degraded: false,
                failed: false,
                rebuilding: false,
                rebuild_percent: None,
                scrub_percent: None,
                speed_bytes_per_sec: None,
                devices: Some(2),
                working_devices: Some(2),
                not_working: None,
                note: None,
                size_bytes: Some(1 << 30),
                used_percent: Some(used),
                fragmentation_percent: None,
                read_errors: Some(0),
                write_errors: Some(0),
                checksum_errors: Some(0),
                data_errors: Some(0),
                scrub_age_secs: Some(scrubbed_days_ago * 86_400),
                scrub_repaired_bytes: None,
                scrub_errors: None,
            };
            let row = ArrayRow::of(&array);
            (row.badge, row.health)
        };
        assert_eq!(pool(50.0, 1), ("good", "Healthy"));
        assert_eq!(pool(80.0, 35), ("good", "Healthy"));
        assert_eq!(pool(81.0, 1), ("warn", "Nearly full"));
        assert_eq!(pool(91.0, 1), ("bad", "Nearly full"));
        assert_eq!(pool(50.0, 36), ("warn", "Not scrubbed"));
    }

    fn status(version: &str, error: Option<&str>) -> ConfigStatus {
        ConfigStatus {
            version: version.to_string(),
            error: error.map(String::from),
            reported_at: crate::times::from_ms(1),
            skipped_collectors: Vec::new(),
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
    fn uptime_reads_naturally() {
        assert_eq!(format_uptime(TimeDelta::seconds(30)), "0 minutes");
        assert_eq!(format_uptime(TimeDelta::seconds(60)), "1 minute");
        assert_eq!(format_uptime(TimeDelta::seconds(3660)), "1 hour, 1 minute");
        assert_eq!(
            format_uptime(TimeDelta::seconds(4_603_242)),
            "53 days, 6 hours"
        );
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
