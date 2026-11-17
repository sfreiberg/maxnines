use std::collections::HashSet;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::fleet::OsFamily;
use super::metrics::{
    RangeParams, not_found, range_links, range_reaching, selected_range, time_range,
};
use super::{CsrfForm, Page, local_time, recorded_by, server_error, viewer_zone};
use crate::alert_charts;
use crate::alerting::{Alert, DeliveryProblem, RuleKind, Severity};
use crate::app_state::AppState;
use crate::events::{EventKind, TimelineEvent};
use crate::metric_charts::{self, Frame};
use crate::metrics::{Source, now_ms};
use crate::registration::short_id;
use crate::remote_checks::{FLEET_HOST_ID, LOCAL_HOST_ID};
use crate::silences::{self, ActiveSilences};

/// How many ended alerts the page shows.
const HISTORY: u64 = 50;

/// An alert's page has one chart, drawn as wide as the narrow page so its text is
/// the size it is on the host pages.
const CHART_FRAME: Frame = Frame {
    width: 812.0,
    height: 320.0,
};

/// How many delivery problems the page shows.
pub(super) const PROBLEMS: u64 = 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(index))
        .route("/alerts/{id}", get(show))
        .route("/alerts/{id}/acknowledge", post(acknowledge))
        .route("/alerts/{id}/unacknowledge", post(unacknowledge))
}

#[derive(Serialize)]
struct AlertRow {
    id: i64,
    acknowledged_by: Option<String>,
    host_id: String,
    /// Empty for the fleet and the server, which are one of a kind.
    short_id: String,
    hostname: String,
    os_family: Option<OsFamily>,
    rule_name: String,
    severity: &'static str,
    summary: String,
    started: String,
    resolved: Option<String>,
    reason: Option<String>,
    /// None when its rule has been deleted, leaving a silence nothing to name.
    silence_link: Option<String>,
    silenced_until: Option<String>,
    /// How many actions its rule ran for it.
    actions: u64,
    /// Whether it watches a metric there's a chart of, which an offline alert doesn't.
    chart: bool,
}

/// Where to start a silence for just this alert. Agents choose their own names, which
/// is fine here because it only fills in a form for someone to read.
fn silence_link(alert: &Alert) -> Option<String> {
    let silence = silences::silence_for(alert, "", 0)?;
    let mut fields = Vec::new();
    if let Some(id) = silence.rule_id {
        fields.push(("rule_id", id.to_string()));
    }
    if !silence.filter.is_empty() {
        fields.push(("filter", silence.filter));
    }
    if !silence.series.is_empty() {
        fields.push(("series", silence.series));
    }
    let query = serde_urlencoded::to_string(fields).unwrap_or_default();
    Some(format!("/alerts/silences/new?{query}"))
}

impl From<Alert> for AlertRow {
    fn from(alert: Alert) -> Self {
        Self {
            silence_link: silence_link(&alert),
            silenced_until: None,
            actions: 0,
            chart: false,
            id: alert.id,
            acknowledged_by: alert.acknowledged_by,
            severity: alert.severity.as_str(),
            started: local_time(alert.started_ms),
            resolved: alert.resolved_ms.map(local_time),
            reason: alert.resolved_summary.or(alert.resolve_reason),
            short_id: if alert.host_id == FLEET_HOST_ID || alert.host_id == LOCAL_HOST_ID {
                String::new()
            } else {
                short_id(&alert.host_id).to_string()
            },
            host_id: alert.host_id,
            hostname: alert.hostname,
            os_family: None,
            rule_name: alert.rule_name,
            summary: alert.summary,
        }
    }
}

#[derive(Serialize)]
struct ProblemRow {
    channel: String,
    summary: String,
    event: &'static str,
    failed: bool,
    attempts: i32,
    error: String,
    created: String,
}

impl From<DeliveryProblem> for ProblemRow {
    fn from(problem: DeliveryProblem) -> Self {
        Self {
            event: problem.event.as_str(),
            failed: problem.state == "failed",
            created: local_time(problem.created_ms),
            channel: problem.channel,
            summary: problem.summary,
            attempts: problem.attempts,
            error: problem.error,
        }
    }
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let rows = async {
        let open = state.database.open_alerts().await?;
        let resolved = state.database.resolved_alerts(HISTORY).await?;
        let problems = state.database.delivery_problems(PROBLEMS).await?;
        let silences = ActiveSilences::load(&state.database, now_ms()).await?;
        let charted: HashSet<i64> = state
            .database
            .list_alert_rules()
            .await?
            .into_iter()
            .filter(|rule| rule.rule.kind != RuleKind::Offline)
            .map(|rule| rule.id)
            .collect();
        anyhow::Ok((open, resolved, problems, silences, charted))
    };
    let (open, resolved, problems, silences, charted) = match rows.await {
        Ok(rows) => rows,
        Err(error) => return server_error(&error),
    };
    let ids: Vec<&str> = open
        .iter()
        .chain(&resolved)
        .map(|alert| alert.host_id.as_str())
        .collect();
    let facts = match state.database.facts_of(&ids).await {
        Ok(facts) => facts,
        Err(error) => return server_error(&error),
    };
    let alert_ids: Vec<i64> = open.iter().chain(&resolved).map(|alert| alert.id).collect();
    let actions = match state.database.action_run_counts(&alert_ids).await {
        Ok(actions) => actions,
        Err(error) => return server_error(&error),
    };
    let row = |alert: Alert| AlertRow {
        os_family: facts.get(&alert.host_id).and_then(OsFamily::of),
        actions: actions.get(&alert.id).copied().unwrap_or(0),
        ..AlertRow::from(alert)
    };

    let open: Vec<AlertRow> = open
        .into_iter()
        .map(|alert| {
            let silence = silences
                .covering(&alert)
                .map(|cover| local_time(cover.ends_ms()));
            AlertRow {
                silenced_until: silence,
                chart: alert.rule_id.is_some_and(|id| charted.contains(&id)),
                ..row(alert)
            }
        })
        .collect();
    let resolved: Vec<AlertRow> = resolved.into_iter().map(row).collect();
    let problems: Vec<ProblemRow> = problems
        .into_iter()
        .filter(|problem| problem.state != "sent")
        .map(ProblemRow::from)
        .collect();

    Page::new(&state, &token, "alerts/index.html")
        .with("open", &open)
        .with("resolved", &resolved)
        .with("problems", &problems)
        .render()
}

/// One alert with a chart of just what it watches: its own series, the rule's
/// thresholds, and when it started and ended. The range reaches back past its start
/// unless one is asked for.
async fn show(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<RangeParams>,
    token: CsrfToken,
) -> Response {
    let alert = match state.database.get_alert(id).await {
        Ok(Some(alert)) => alert,
        Ok(None) => return not_found(&state, &token),
        Err(error) => return server_error(&error),
    };
    let now = now_ms();
    let asked = RangeParams {
        range: params
            .range
            .or_else(|| Some(range_reaching(alert.started_ms, now).to_string())),
    };
    let (selected, _, length_ms) = selected_range(&asked);
    let Some(range) = time_range(length_ms) else {
        return not_found(&state, &token);
    };
    let watched = match alert_charts::watched(&state.sources(), &alert, range).await {
        Ok(watched) => watched,
        Err(error) => return server_error(&error),
    };
    let facts = match state.database.facts_of(&[alert.host_id.as_str()]).await {
        Ok(facts) => facts,
        Err(error) => return server_error(&error),
    };

    let zone = viewer_zone();
    let chart = watched.as_ref().map(|watched| {
        let title = match watched.metric.source {
            Source::Fields([_]) => watched.metric.title.to_string(),
            _ if alert.series.is_empty() => watched.metric.title.to_string(),
            _ => format!("{} ({})", watched.metric.title, alert.series),
        };
        // A forecast's level is where it's heading, the same for either severity.
        let forecast = watched.rule.kind == RuleKind::Forecast;
        let levels: Vec<(&'static str, f64)> = watched
            .rule
            .levels()
            .into_iter()
            .map(|(severity, value)| (if forecast { "level" } else { severity.as_str() }, value))
            .collect();
        let mut chart = metric_charts::build_with_thresholds(
            watched.metric,
            watched.unit,
            &title,
            CHART_FRAME,
            &watched.result,
            range,
            zone,
            &levels,
        );
        let moments = [
            Some((alert.started_ms, EventKind::Alert)),
            alert.resolved_ms.map(|time| (time, EventKind::Resolved)),
        ];
        let events: Vec<TimelineEvent> = moments
            .into_iter()
            .flatten()
            .map(|(time_ms, kind)| TimelineEvent {
                time_ms,
                kind,
                title: alert.rule_name.clone(),
                detail: None,
                created_by: None,
                id: None,
            })
            .collect();
        metric_charts::mark(&mut chart, &events, range, zone);
        chart
    });
    // The numbers behind the chart, where a host's page has them.
    let data_link = watched
        .as_ref()
        .filter(|watched| watched.rule.kind != RuleKind::Calculation)
        .filter(|_| alert.host_id != FLEET_HOST_ID)
        .map(|watched| {
            let mut fields = vec![("range", selected.to_string())];
            if !alert.series.is_empty() {
                fields.push(("series", alert.series.clone()));
            }
            let query = serde_urlencoded::to_string(fields).unwrap_or_default();
            format!(
                "/hosts/{}/metrics/{}?{query}",
                alert.host_id, watched.metric.name
            )
        });
    let critical = alert.severity == Severity::Critical;
    let os_family = facts.get(&alert.host_id).and_then(OsFamily::of);
    let row = AlertRow {
        os_family,
        ..AlertRow::from(alert)
    };

    Page::new(&state, &token, "alerts/show.html")
        .with("alert", &row)
        .with("critical", &critical)
        .with("chart", &chart)
        .with("data_link", &data_link)
        .with("ranges", &range_links(selected))
        .with("range", selected)
        .render()
}

async fn acknowledge(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    let by = recorded_by();
    match state.database.acknowledge_alert(id, &by, now_ms()).await {
        Ok(true) => (form.token, Redirect::to("/alerts")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn unacknowledge(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    match state.database.unacknowledge_alert(id).await {
        Ok(true) => (form.token, Redirect::to("/alerts")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
