use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use maxnines_protocol::{Check, CheckKind};
use serde::{Deserialize, Serialize};

use super::host_list::address;
use super::hosts::{described, maintenance_choices, maintenance_secs};
use super::metrics::{
    CheckRow, RangeParams, check_row, one_series, range_links, selected_range, time_range,
};
use super::{CsrfForm, Page, recorded_by, server_error, viewer_zone};
use crate::alerting::RuleKind;
use crate::app_state::AppState;
use crate::check_history;
use crate::host_filter;
use crate::metric_charts::{self, Chart, Frame};
use crate::metrics::{self, METRICS, Metric, Series, SeriesResult, TimeRange, Unit};
use crate::registration::HostState;
use crate::remote_checks::{
    LOCAL_HOST_ID, LOCAL_HOSTNAME, RemoteCheck, RemoteCheckInput, SignIn, SignInWith,
};
use crate::silences::{ActiveSilences, SilenceInput};

const KINDS: [CheckKind; 12] = [
    CheckKind::Http,
    CheckKind::Tcp,
    CheckKind::Tls,
    CheckKind::Dns,
    CheckKind::Ping,
    CheckKind::Postgres,
    CheckKind::Mysql,
    CheckKind::Redis,
    CheckKind::Ssh,
    CheckKind::Smtp,
    CheckKind::Imap,
    CheckKind::Pop3,
];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/checks", get(index).post(create))
        .route("/checks/new", get(new))
        .route("/checks/{id}", get(show).post(update))
        .route("/checks/{id}/edit", get(edit))
        .route("/checks/{id}/run", post(run_now))
        .route("/checks/{id}/pause", post(pause))
        .route("/checks/{id}/maintenance", post(start_maintenance))
        .route("/checks/{id}/maintenance/end", post(end_maintenance))
        .route("/checks/{id}/delete", post(delete))
}

/// A check as its form shows it, including whatever was just typed.
#[derive(Serialize, Default)]
struct CheckForm {
    /// The host it's about: one with no agent, or the server itself.
    host_id: String,
    name: String,
    kind: String,
    target: String,
    interval_secs: String,
    timeout_secs: String,
    method: String,
    body: String,
    regex: String,
    insecure: bool,
    server: String,
    record: String,
    count: String,
    enabled: bool,
    database: String,
    tls: bool,
    host_key: String,
    /// Website checks look up when their domain expires unless this is off.
    domain_expiry: bool,
    /// How it signs in: none, password or key. Only that one's boxes count.
    sign_in: String,
    username: String,
    password: String,
    password_env: String,
    private_key: String,
    private_key_env: String,
    /// Whether a password or key is saved, which leaving the box empty keeps.
    has_password: bool,
    has_private_key: bool,
}

/// What's left empty on a form isn't set at all.
fn optional(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> Result<Option<T>> {
    optional(text)
        .map(|text| {
            text.parse()
                .ok()
                .with_context(|| format!("{what} has to be a number"))
        })
        .transpose()
}

impl CheckForm {
    fn blank() -> Self {
        Self {
            host_id: LOCAL_HOST_ID.to_string(),
            kind: CheckKind::Http.as_str().to_string(),
            interval_secs: "60".to_string(),
            enabled: true,
            domain_expiry: true,
            ..Self::default()
        }
    }

    fn from_input(input: &RemoteCheckInput) -> Self {
        let check = &input.check;
        let text = |value: &Option<String>| value.clone().unwrap_or_default();
        Self {
            host_id: input.host_id.clone(),
            name: check.name.clone(),
            kind: check.kind.as_str().to_string(),
            target: check.target.clone(),
            interval_secs: input.interval_secs.to_string(),
            timeout_secs: check
                .timeout_secs
                .map(|t| t.to_string())
                .unwrap_or_default(),
            method: text(&check.method),
            body: text(&check.body),
            regex: text(&check.regex),
            insecure: check.insecure == Some(true),
            server: text(&check.server),
            record: text(&check.record),
            count: check.count.map(|c| c.to_string()).unwrap_or_default(),
            enabled: input.enabled,
            database: text(&check.database),
            tls: check.tls == Some(true),
            host_key: text(&check.host_key),
            domain_expiry: check.domain_expiry != Some(false),
            sign_in: input.sign_in.with().as_str().to_string(),
            username: text(&input.sign_in.username),
            password: String::new(),
            password_env: text(&input.sign_in.password_env),
            private_key: String::new(),
            private_key_env: text(&input.sign_in.private_key_env),
            has_password: input.sign_in.password.is_some(),
            has_private_key: input.sign_in.private_key.is_some(),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>, saved: Option<&SignIn>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            // A form without one is from before checks had hosts.
            host_id: optional(&text("host_id")).unwrap_or_else(|| LOCAL_HOST_ID.to_string()),
            name: text("name"),
            kind: text("kind"),
            target: text("target"),
            interval_secs: text("interval_secs"),
            timeout_secs: text("timeout_secs"),
            method: text("method"),
            body: text("body"),
            regex: text("regex"),
            insecure: fields.contains_key("insecure"),
            server: text("server"),
            record: text("record"),
            count: text("count"),
            enabled: fields.contains_key("enabled"),
            database: text("database"),
            tls: fields.contains_key("tls"),
            host_key: text("host_key"),
            domain_expiry: fields.contains_key("domain_expiry"),
            sign_in: text("sign_in"),
            username: text("username"),
            password: text("password"),
            password_env: text("password_env"),
            private_key: text("private_key"),
            private_key_env: text("private_key_env"),
            has_password: saved.is_some_and(|saved| saved.password.is_some()),
            has_private_key: saved.is_some_and(|saved| saved.private_key.is_some()),
        }
    }

    /// The check, and how the form says it signs in. What's typed in the boxes
    /// for another way of signing in is left out.
    fn to_input(&self) -> Result<(RemoteCheckInput, SignInWith)> {
        let Some(kind) = CheckKind::parse(&self.kind) else {
            bail!("choose a kind of check");
        };
        let mut check = Check::new(self.name.trim(), kind, self.target.trim());
        check.timeout_secs = number(&self.timeout_secs, "the timeout")?;
        check.method = optional(&self.method);
        check.body = optional(&self.body);
        check.regex = optional(&self.regex);
        check.insecure = self.insecure.then_some(true);
        check.server = optional(&self.server);
        check.record = optional(&self.record);
        check.count = number(&self.count, "the count")?;
        check.database = optional(&self.database);
        check.tls = self.tls.then_some(true);
        check.host_key = optional(&self.host_key);
        // Only a website check has a domain to look up, and on is how it starts.
        check.domain_expiry = (kind == CheckKind::Http && !self.domain_expiry).then_some(false);
        let interval_secs =
            number(&self.interval_secs, "the interval")?.context("a check needs an interval")?;
        let with = match self.sign_in.as_str() {
            "password" if kind.signs_in() => SignInWith::Password,
            "key" if kind == CheckKind::Ssh => SignInWith::Key,
            _ => SignInWith::None,
        };
        // A password or key is whatever was typed, spaces and all.
        let typed = |text: &str| Some(text.to_string()).filter(|text| !text.is_empty());
        let sign_in = match with {
            SignInWith::None => SignIn::default(),
            SignInWith::Password => SignIn {
                username: optional(&self.username),
                password: typed(&self.password),
                password_env: optional(&self.password_env),
                ..SignIn::default()
            },
            SignInWith::Key => SignIn {
                username: optional(&self.username),
                // Pasted keys often lose their last line break, which they need.
                private_key: optional(&self.private_key).map(|key| format!("{key}\n")),
                private_key_env: optional(&self.private_key_env),
                ..SignIn::default()
            },
        };
        let input = RemoteCheckInput {
            host_id: self.host_id.clone(),
            check,
            interval_secs,
            enabled: self.enabled,
            sign_in,
        };
        Ok((input, with))
    }
}

#[derive(Serialize)]
struct ListRow {
    id: i64,
    /// The host it's about, unless that's the server itself.
    host: Option<HostChoice>,
    name: String,
    kind: &'static str,
    target: String,
    interval_secs: u64,
    enabled: bool,
    latest: Option<CheckRow>,
}

#[derive(Deserialize)]
struct ListParams {
    /// Which tab: down or disabled.
    status: Option<String>,
}

#[derive(Serialize)]
struct FilterTab {
    key: &'static str,
    label: &'static str,
    count: usize,
    selected: bool,
}

fn matches(filter: &str, row: &ListRow) -> bool {
    match filter {
        "down" => row.latest.as_ref().is_some_and(|latest| !latest.up),
        "disabled" => !row.enabled,
        _ => true,
    }
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
    token: CsrfToken,
) -> Response {
    let checks = match state.database.list_remote_checks().await {
        Ok(checks) => checks,
        Err(error) => return server_error(&error),
    };
    let latest = state.check_results.all();
    let hosts = host_choices(&state).await;
    let mut rows: Vec<ListRow> = checks
        .into_iter()
        .map(|check| {
            let input = check.input;
            let about_server = input.host_id == LOCAL_HOST_ID;
            let host = hosts.iter().find(|host| host.id == input.host_id);
            ListRow {
                id: check.id,
                host: host.filter(|_| !about_server).cloned(),
                kind: input.check.kind.as_str(),
                latest: latest.get(&check.id).and_then(check_row),
                name: input.check.name,
                target: input.check.target,
                interval_secs: input.interval_secs,
                enabled: input.enabled,
            }
        })
        .collect();

    let selected = params.status.as_deref().unwrap_or("all");
    let filters: Vec<FilterTab> = [("all", "All"), ("down", "Down"), ("disabled", "Disabled")]
        .into_iter()
        .map(|(key, label)| FilterTab {
            key,
            label,
            count: rows.iter().filter(|row| matches(key, row)).count(),
            selected: key == selected,
        })
        .collect();
    rows.retain(|row| matches(selected, row));

    Page::new(&state, &token, "remote_checks/index.html")
        .with("checks", &rows)
        .with("filters", &filters)
        .render()
}

/// A host a check can be about.
#[derive(Serialize, Clone)]
struct HostChoice {
    id: String,
    hostname: String,
}

/// The server itself, then every host with no agent, by name.
async fn host_choices(state: &AppState) -> Vec<HostChoice> {
    let mut agentless: Vec<HostChoice> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|host| host.is_agentless() && host.state == HostState::Approved)
        .map(|host| HostChoice {
            id: host.id,
            hostname: host.hostname,
        })
        .collect();
    agentless.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    let server = HostChoice {
        id: LOCAL_HOST_ID.to_string(),
        hostname: LOCAL_HOSTNAME.to_string(),
    };
    std::iter::once(server).chain(agentless).collect()
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &CheckForm,
    error: Option<&str>,
) -> Response {
    let kinds: Vec<&str> = KINDS.iter().map(|kind| kind.as_str()).collect();
    let page = Page::new(state, token, "remote_checks/form.html")
        .with("id", &id)
        .with("check", form)
        .with("hosts", &host_choices(state).await)
        // A check that exists goes back to its own page.
        .with(
            "back",
            &id.map_or_else(|| back_to(&form.host_id), |id| format!("/checks/{id}")),
        )
        .with("kinds", &kinds)
        .with("env_prefix", crate::metrics_pages::ENV_PREFIX)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

/// Where a check's form goes when it's done: its host's page, or the list of
/// checks for the server's own.
fn back_to(host_id: &str) -> String {
    if host_id == LOCAL_HOST_ID {
        "/checks".to_string()
    } else {
        format!("/hosts/{host_id}")
    }
}

#[derive(Deserialize)]
struct NewParams {
    /// The host to start with, as its page's link to here gives.
    host: Option<String>,
}

async fn new(
    State(state): State<AppState>,
    Query(params): Query<NewParams>,
    token: CsrfToken,
) -> Response {
    let mut form = CheckForm::blank();
    if let Some(host) = params.host
        && state.agentless_host(&host).await.is_some()
    {
        form.host_id = host;
    }
    form_page(&state, &token, None, &form, None).await
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_remote_check(id).await {
        Ok(Some(check)) => {
            let form = CheckForm::from_input(&check.input);
            form_page(&state, &token, Some(id), &form, None).await
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

/// What a check's response time is made of, as the lines of one chart, in the
/// order they happen after the total.
const PHASES: [(&str, &str); 6] = [
    ("check.response", "Total"),
    ("check.dns", "DNS lookup"),
    ("check.connect", "Connecting"),
    ("check.tls", "TLS handshake"),
    ("check.first_byte", "First byte"),
    ("check.download", "Download"),
];

/// A chart on a check's page.
#[derive(Serialize)]
struct CheckChart {
    chart: Chart,
    /// Where its numbers can be seen as a table, for a chart of one metric.
    table: Option<String>,
}

/// One check's charts: whether it passed, how long it took and where the time
/// went, then whatever else its kind reports. Each metric is its own query, so
/// they run together rather than in turn.
async fn charts(
    state: &AppState,
    host_id: &str,
    name: &str,
    range: TimeRange,
    range_key: &str,
) -> Result<Vec<CheckChart>> {
    let about_checks: Vec<&'static Metric> = METRICS
        .iter()
        .filter(|metric| metric.collector == "checks")
        .collect();
    let mut queries = tokio::task::JoinSet::new();
    for metric in about_checks.iter().copied() {
        let (state, host_id, name) = (state.clone(), host_id.to_string(), name.to_string());
        queries.spawn(async move {
            let found = one_series(&state, &host_id, metric, &name, range).await;
            (metric.name, found)
        });
    }
    let mut found: BTreeMap<&str, SeriesResult> = BTreeMap::new();
    while let Some(finished) = queries.join_next().await {
        let (metric, result) = finished?;
        found.insert(metric, result?);
    }

    let zone = viewer_zone();
    let mut charts = Vec::new();
    let mut add = |chart: Chart, has_table: bool| {
        let table = has_table.then(|| {
            let path = format!("/hosts/{host_id}/metrics/{}", chart.name);
            address(&path, &[("range", range_key), ("series", name)])
        });
        charts.push(CheckChart { chart, table });
    };
    let (Some(up), Some(response)) = (metrics::find("check.up"), metrics::find("check.response"))
    else {
        bail!("the metrics checks report are missing");
    };

    // Whether it passed is always there, even with nothing to show yet.
    let passed = found.remove(up.name).unwrap_or_default();
    add(
        metric_charts::build_as(
            up,
            up.unit,
            "Passing",
            Frame::STANDARD,
            &passed,
            range,
            zone,
        ),
        true,
    );

    let phases: Vec<Series> = PHASES
        .iter()
        .filter_map(|(metric, label)| {
            let series = found.remove(metric)?.series.pop()?;
            Some(Series {
                name: (*label).to_string(),
                points: series.points,
            })
        })
        .collect();
    if !phases.is_empty() {
        let phases = SeriesResult {
            series: phases,
            hidden: 0,
        };
        let frame = Frame::STANDARD;
        let unit = Unit::Milliseconds;
        let chart =
            metric_charts::build_as(response, unit, "Response time", frame, &phases, range, zone);
        add(chart, false);
    }

    for metric in about_checks {
        if let Some(result) = found.remove(metric.name)
            && !result.series.is_empty()
        {
            add(metric_charts::build(metric, &result, range, zone), true);
        }
    }
    Ok(charts)
}

/// How many bars the last day is cut into on a check's page.
const BARS: usize = 48;
const DAY_MS: i64 = 86_400_000;

/// One of the figures across the top of a check's page.
#[derive(Serialize)]
struct Tile {
    label: &'static str,
    value: String,
    note: String,
    /// `good`, `bad` or empty, for the value's colour.
    tone: &'static str,
}

/// How much of a stretch of time a check passed for, as its page puts it.
#[derive(Serialize)]
struct Uptime {
    label: &'static str,
    percent: Option<String>,
    note: String,
    /// `good`, `warn` or `bad`.
    tone: &'static str,
}

/// An alert rule that watches one of a check's metrics.
#[derive(Serialize)]
struct WatchingRule {
    id: i64,
    name: String,
    severity: &'static str,
    /// Whether it also has a condition on facts, which this page doesn't weigh.
    conditional: bool,
}

fn uptime(
    label: &'static str,
    points: &[metrics::Point],
    step_ms: i64,
    ran_for_ms: Option<i64>,
) -> Uptime {
    let found = check_history::availability(points, step_ms, ran_for_ms);
    let note = match found.failures {
        0 => "never failed".to_string(),
        1 => format!(
            "failed once, for about {}",
            check_history::span_text(found.down_ms)
        ),
        times => format!(
            "failed {times} times, for about {}",
            check_history::span_text(found.down_ms)
        ),
    };
    let tone = match found.percent {
        Some(percent) if percent >= 99.9 => "good",
        Some(percent) if percent >= 99.0 => "warn",
        Some(_) => "bad",
        None => "",
    };
    Uptime {
        label,
        percent: found.percent.map(check_history::percent_text),
        note: if found.percent.is_some() {
            note
        } else {
            "nothing run yet".to_string()
        },
        tone,
    }
}

/// The points of whether a check passed, over a stretch of time.
async fn passing(
    state: &AppState,
    host_id: &str,
    name: &str,
    length_ms: i64,
) -> Result<(Vec<metrics::Point>, TimeRange)> {
    let range = time_range(length_ms).context("no such time range")?;
    let up = metrics::find("check.up").context("the metrics checks report are missing")?;
    let mut found = one_series(state, host_id, up, name, range).await?;
    let points = found
        .series
        .pop()
        .map(|series| series.points)
        .unwrap_or_default();
    Ok((points, range))
}

/// "26 s ago", finer than elsewhere, as a check runs every few seconds.
fn ran_text(ran_ms: i64, now_ms: i64) -> String {
    let secs = (now_ms - ran_ms).max(0) / 1000;
    if secs < 60 {
        format!("{secs} s ago")
    } else {
        crate::times::ago(ran_ms as u64, now_ms as u64)
    }
}

/// A check's own page: how it is now, how it's been, and its charts and nobody
/// else's.
async fn show(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<RangeParams>,
    token: CsrfToken,
) -> Response {
    let check = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => check,
        Ok(None) => return not_found(&state, &token),
        Err(error) => return server_error(&error),
    };
    match page(&state, &token, check, &params).await {
        Ok(page) => page,
        Err(error) => server_error(&error),
    }
}

async fn page(
    state: &AppState,
    token: &CsrfToken,
    check: RemoteCheck,
    params: &RangeParams,
) -> Result<Response> {
    let id = check.id;
    let input = check.input;
    let name = &input.check.name;
    let (selected, _, length_ms) = selected_range(params);
    let range = time_range(length_ms).context("no such time range")?;
    let charts = charts(state, &input.host_id, name, range, selected).await?;
    let now = metrics::now_ms();

    let hosts = host_choices(state).await;
    let host = hosts
        .into_iter()
        .find(|host| host.id == input.host_id && host.id != LOCAL_HOST_ID);
    let hostname = host
        .as_ref()
        .map_or(LOCAL_HOSTNAME.to_string(), |host| host.hostname.clone());
    let latest = state.check_results.all().remove(&id).and_then(|result| {
        let row = check_row(&result)?;
        Some((row, result))
    });

    // How it's been: the last day in bars, then longer stretches in figures.
    let (day, day_range) = passing(state, &input.host_id, name, DAY_MS).await?;
    let (week, week_range) = passing(state, &input.host_id, name, 7 * DAY_MS).await?;
    let (month, month_range) = passing(state, &input.host_id, name, 30 * DAY_MS).await?;
    let bars = check_history::slots(&day, day_range.from_ms, day_range.to_ms, BARS);
    // The last day is kept finest. Where it starts after the day does, the check
    // is newer than that, and the time its points cover is how long it's run,
    // which the longer ranges' coarser points can't tell.
    let newer = day
        .first()
        .is_some_and(|first| first.time_ms > day_range.from_ms + day_range.step_ms);
    let ran_for = newer.then(|| day.len() as i64 * day_range.step_ms);
    let uptimes = [
        uptime("Last 24 hours", &day, day_range.step_ms, ran_for),
        uptime("Last 7 days", &week, week_range.step_ms, ran_for),
        uptime("Last 30 days", &month, month_range.step_ms, ran_for),
    ];

    let mut tiles = Vec::new();
    let streak = check_history::streak(&month, month_range.step_ms);
    let status = match (&latest, input.enabled) {
        (_, false) => Tile {
            label: "Status",
            value: "Paused".to_string(),
            note: "isn't run until it's resumed".to_string(),
            tone: "",
        },
        (None, true) => Tile {
            label: "Status",
            value: "Waiting".to_string(),
            note: "hasn't run since the server started".to_string(),
            tone: "",
        },
        (Some((row, _)), true) => {
            // The latest run says how it is; the history says for how long.
            let note = streak
                .filter(|streak| streak.passing == row.up)
                .map(|streak| {
                    let span = check_history::span_text(now - streak.since_ms);
                    let more = if streak.or_longer { " or more" } else { "" };
                    format!("for {span}{more}")
                })
                .unwrap_or_else(|| row.error.clone().unwrap_or_default());
            Tile {
                label: "Status",
                value: if row.up { "Up" } else { "Down" }.to_string(),
                note,
                tone: if row.up { "good" } else { "bad" },
            }
        }
    };
    tiles.push(status);
    tiles.push(Tile {
        label: "Last run",
        value: state
            .check_results
            .ran_ms(id)
            .map_or("Not yet".to_string(), |ran| ran_text(ran, now)),
        note: format!("every {} s, from the server", input.interval_secs),
        tone: "",
    });
    if let Some((row, result)) = &latest {
        if let Some(response) = &row.response {
            let mut parts: Vec<String> = Vec::new();
            if let Some(status) = row.status {
                parts.push(
                    format!("{status} {}", row.protocol.clone().unwrap_or_default())
                        .trim()
                        .to_string(),
                );
            }
            if let Some(tls) = &row.tls_version {
                parts.push(tls.clone());
            }
            tiles.push(Tile {
                label: "Response time",
                value: response.clone(),
                note: parts.join(" · "),
                tone: "",
            });
        }
        if let Some(days) = result["cert_days_left"].as_i64() {
            let until = now + days * DAY_MS;
            tiles.push(Tile {
                label: "Certificate",
                value: format!("{days} day{}", if days == 1 { "" } else { "s" }),
                note: format!("left, until about {}", super::local_date(until)),
                tone: if days < 14 { "bad" } else { "" },
            });
        }
        let username = input
            .sign_in
            .username
            .as_deref()
            .unwrap_or("the default user");
        let signed_in = result["signed_in"].as_bool();
        let sign_in_note = match signed_in {
            Some(true) => format!("signed in as {username}"),
            Some(false) => format!("couldn't sign in as {username}"),
            None => "without signing in".to_string(),
        };
        if let Some(days) = result["domain_days_left"].as_i64() {
            let until = now + days * DAY_MS;
            tiles.push(Tile {
                label: "Domain",
                value: format!("{days} day{}", if days == 1 { "" } else { "s" }),
                note: format!("left, until about {}", super::local_date(until)),
                tone: if days < 30 { "bad" } else { "" },
            });
        }
        if let Some(fingerprint) = result["host_key"].as_str() {
            tiles.push(Tile {
                label: "Host key",
                value: if input.check.host_key.is_some() {
                    "As expected"
                } else {
                    "Not pinned"
                }
                .to_string(),
                note: fingerprint.to_string(),
                tone: "",
            });
            let methods = result["sign_in_methods"].as_str();
            tiles.push(Tile {
                label: "Signing in",
                value: match signed_in {
                    Some(true) => "Signed in",
                    Some(false) => "Refused",
                    None => "Not tried",
                }
                .to_string(),
                note: match (signed_in, methods) {
                    (None, Some(methods)) => format!("offers {methods}"),
                    _ => sign_in_note,
                },
                tone: if signed_in == Some(false) { "bad" } else { "" },
            });
        } else if input.check.kind.signs_in() {
            tiles.push(Tile {
                label: "Server",
                value: result["server_version"]
                    .as_str()
                    .map_or("Answering".to_string(), String::from),
                note: sign_in_note,
                tone: "",
            });
        }
    }

    let alerts: Vec<_> = state
        .database
        .open_alerts()
        .await?
        .into_iter()
        .filter(|alert| alert.host_id == input.host_id && alert.series == *name)
        .collect();
    let rules: Vec<WatchingRule> = state
        .database
        .list_alert_rules()
        .await?
        .into_iter()
        .filter(|rule| {
            let input = &rule.rule;
            input.enabled
                && matches!(input.kind, RuleKind::Metric | RuleKind::Forecast)
                && input
                    .metric
                    .as_deref()
                    .is_some_and(|metric| metric.starts_with("check."))
                && input.watches_series(name)
        })
        .map(|rule| WatchingRule {
            id: rule.id,
            conditional: rule
                .rule
                .condition
                .as_deref()
                .is_some_and(|c| !c.trim().is_empty()),
            name: rule.rule.name,
            severity: rule.rule.severity.as_str(),
        })
        .collect();

    let quiet = ActiveSilences::load(&state.database, now).await?;
    let cover = quiet.covering_series(&input.host_id, &hostname, name);
    let own = host_filter::only(&input.host_id);
    let maintenance = described(state, cover, |silence| {
        silence.rule_id.is_none() && silence.filter == own && silence.series == *name
    })
    .await?;

    Ok(Page::new(state, token, "remote_checks/show.html")
        .with("id", &id)
        .with("name", name)
        .with("kind", input.check.kind.as_str())
        .with("target", &input.check.target)
        .with("enabled", &input.enabled)
        .with("host", &host)
        .with("tiles", &tiles)
        .with("bars", &bars)
        .with("uptimes", &uptimes)
        .with("latest", &latest.as_ref().map(|(row, _)| row))
        .with("alerts", &alerts)
        .with("rules", &rules)
        .with("maintenance", &maintenance)
        .with("maintenance_choices", &maintenance_choices())
        .with("charts", &charts)
        .with("ranges", &range_links(selected))
        .with("range", selected)
        .render())
}

/// The name of the host a check is about, as its results are saved under.
async fn hostname_of(state: &AppState, host_id: &str) -> Option<String> {
    if host_id == LOCAL_HOST_ID {
        return Some(LOCAL_HOSTNAME.to_string());
    }
    state
        .agentless_host(host_id)
        .await
        .map(|host| host.hostname)
}

/// Runs a check once now, in between its usual runs, and waits for it, so the
/// page it goes back to shows what it found.
async fn run_now(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let check = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => check,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let Some(hostname) = hostname_of(&state, &check.input.host_id).await else {
        return not_found(&state, &form.token);
    };
    crate::remote_checks::run(
        &check,
        hostname,
        &state.writer,
        &state.check_results,
        &state.presence,
    )
    .await;
    (form.token, Redirect::to(&format!("/checks/{id}"))).into_response()
}

/// Stops running a check, or starts it again: the same as its form's "Run this
/// check" box.
async fn pause(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let check = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => check,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let mut input = check.input;
    input.enabled = !input.enabled;
    match state.database.update_remote_check(id, &input).await {
        Ok(true) => (form.token, Redirect::to(&format!("/checks/{id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

/// Holds back every notification about this check for a while, with a silence
/// for it alone, as a host's page does for the host.
async fn start_maintenance(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    let check = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => check,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let Some(duration_secs) = maintenance_secs(&form) else {
        return (StatusCode::BAD_REQUEST, "Choose how long from the list.").into_response();
    };
    let name = check.input.check.name;
    let reason = match form.fields.get("reason").map(|reason| reason.trim()) {
        Some(reason) if !reason.is_empty() => reason.to_string(),
        _ => format!("Maintenance on {name}"),
    };
    let input = SilenceInput {
        rule_id: None,
        filter: host_filter::only(&check.input.host_id),
        series: name,
        reason,
        duration_secs,
    };
    if let Err(error) = state.check_silence(&input).await {
        return (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response();
    }
    match state
        .database
        .create_silence(&input, &recorded_by(), metrics::now_ms())
        .await
    {
        Ok(_) => (form.token, Redirect::to(&format!("/checks/{id}"))).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Ends the silences started for this check alone. Wider ones, and maintenance
/// windows, are left to their own pages.
async fn end_maintenance(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    let check = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => check,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let now = metrics::now_ms();
    let silences = match state.database.active_silences(now).await {
        Ok(silences) => silences,
        Err(error) => return server_error(&error),
    };
    let own = host_filter::only(&check.input.host_id);
    for silence in silences.iter().filter(|silence| {
        silence.rule_id.is_none()
            && silence.filter == own
            && silence.series == check.input.check.name
    }) {
        if let Err(error) = state.database.end_silence(silence.id, now).await {
            return server_error(&error);
        }
    }
    (form.token, Redirect::to(&format!("/checks/{id}"))).into_response()
}

/// The check as it would be saved, keeping the password or key of the one it
/// replaces unless given another, or why it can't be.
async fn validate(
    state: &AppState,
    form: &CheckForm,
    saved: Option<&RemoteCheck>,
) -> Result<RemoteCheckInput> {
    let (mut input, with) = form.to_input()?;
    if let Some(saved) = saved {
        input.sign_in = input
            .sign_in
            .keeping_secrets_of(&saved.input.sign_in, Some(with));
    }
    state
        .check_remote_check(&input, saved.map(|saved| saved.id))
        .await?;
    Ok(input)
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let fields = CheckForm::from_fields(&form.fields, None);
    let input = match validate(&state, &fields, None).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, None, &fields, Some(&message)).await;
        }
    };
    match state.database.create_remote_check(&input).await {
        Ok(_) => (form.token, Redirect::to(&back_to(&input.host_id))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let saved = match state.database.get_remote_check(id).await {
        Ok(Some(saved)) => saved,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let fields = CheckForm::from_fields(&form.fields, Some(&saved.input.sign_in));
    let input = match validate(&state, &fields, Some(&saved)).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, Some(id), &fields, Some(&message)).await;
        }
    };
    match state.database.update_remote_check(id, &input).await {
        Ok(true) => (form.token, Redirect::to(&format!("/checks/{id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let back = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => back_to(&check.input.host_id),
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    match state.database.delete_remote_check(id).await {
        Ok(true) => (form.token, Redirect::to(&back)).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> RemoteCheckInput {
        let mut check = Check::new("site", CheckKind::Http, "https://example.com/");
        check.timeout_secs = Some(5);
        check.method = Some("POST".to_string());
        check.body = Some("hello".to_string());
        check.regex = Some("Welcome back".to_string());
        check.insecure = Some(true);
        RemoteCheckInput {
            host_id: "5f0c1d6f2a8e4b7790d3c1a2b4e6f809".to_string(),
            check,
            interval_secs: 120,
            enabled: false,
            sign_in: SignIn::default(),
        }
    }

    #[test]
    fn a_check_survives_the_trip_through_its_form() {
        let original = input();
        assert_eq!(
            CheckForm::from_input(&original).to_input().unwrap().0,
            original
        );

        let mut dns = Check::new("ns", CheckKind::Dns, "example.com");
        dns.server = Some("8.8.8.8".to_string());
        dns.record = Some("MX".to_string());
        let original = RemoteCheckInput {
            host_id: crate::remote_checks::LOCAL_HOST_ID.to_string(),
            check: dns,
            interval_secs: 60,
            enabled: true,
            sign_in: SignIn::default(),
        };
        assert_eq!(
            CheckForm::from_input(&original).to_input().unwrap().0,
            original
        );
    }

    #[test]
    fn a_website_looks_up_its_domain_unless_the_box_is_cleared() {
        let mut form = CheckForm::blank();
        form.name = "site".to_string();
        form.target = "https://example.com/".to_string();
        assert!(form.domain_expiry, "on to start with");
        assert_eq!(form.to_input().unwrap().0.check.domain_expiry, None);
        form.domain_expiry = false;
        let (input, _) = form.to_input().unwrap();
        assert_eq!(input.check.domain_expiry, Some(false));
        assert!(!CheckForm::from_input(&input).domain_expiry);
        // Nothing else has a domain to look up.
        form.kind = "tcp".to_string();
        form.target = "example.com:443".to_string();
        assert_eq!(form.to_input().unwrap().0.check.domain_expiry, None);
    }

    #[test]
    fn empty_options_are_not_set() {
        let mut form = CheckForm::blank();
        form.name = "a".to_string();
        form.target = "https://example.com/".to_string();
        let (input, _) = form.to_input().unwrap();
        assert_eq!(input.check.method, None);
        assert_eq!(input.check.insecure, None);
        assert_eq!(input.check.timeout_secs, None);
        input.check.validate().unwrap();
    }

    #[test]
    fn typing_mistakes_are_explained() {
        let mut form = CheckForm::blank();
        form.timeout_secs = "soon".to_string();
        let error = format!("{:#}", form.to_input().unwrap_err());
        assert!(error.contains("the timeout has to be a number"), "{error}");

        let mut form = CheckForm::blank();
        form.interval_secs = String::new();
        let error = format!("{:#}", form.to_input().unwrap_err());
        assert!(error.contains("needs an interval"), "{error}");

        let mut form = CheckForm::blank();
        form.kind = "gopher".to_string();
        assert!(form.to_input().is_err());
    }
}
