use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{CsrfForm, Page, server_error, signed_in_user};
use crate::alerting::{Alert, DeliveryProblem};
use crate::app_state::AppState;
use crate::fact_history::format_time;
use crate::host_filter::PartialValue;
use crate::metrics::now_ms;
use crate::remote_checks::FLEET_AGENT_ID;
use crate::silences::ActiveSilences;

/// How many ended alerts the page shows.
const HISTORY: u64 = 50;

/// How many delivery problems the page shows.
const PROBLEMS: u64 = 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(index))
        .route("/alerts/{id}/acknowledge", post(acknowledge))
        .route("/alerts/{id}/unacknowledge", post(unacknowledge))
}

fn time(ms: i64) -> String {
    u64::try_from(ms).map_or_else(|_| String::new(), format_time)
}

#[derive(Serialize)]
struct AlertRow {
    id: i64,
    acknowledged_by: Option<String>,
    agent_id: String,
    host: String,
    rule_name: String,
    severity: &'static str,
    summary: String,
    started: String,
    resolved: Option<String>,
    reason: Option<String>,
    silence_link: String,
    silenced_until: Option<String>,
}

/// Where to start a silence for just this alert. Agents choose their own names, which
/// is fine here because it only fills in a form for someone to read.
fn silence_link(alert: &Alert) -> String {
    let mut fields = Vec::new();
    if let Some(id) = alert.rule_id {
        fields.push(("rule_id", id.to_string()));
    }
    if alert.agent_id != FLEET_AGENT_ID {
        let host = PartialValue::of("hostname=").map(|term| term.suggestion(&alert.host).text);
        fields.extend(host.map(|filter| ("filter", filter)));
    }
    let query = serde_urlencoded::to_string(fields).unwrap_or_default();
    format!("/alerts/silences/new?{query}")
}

impl From<Alert> for AlertRow {
    fn from(alert: Alert) -> Self {
        Self {
            silence_link: silence_link(&alert),
            silenced_until: None,
            id: alert.id,
            acknowledged_by: alert.acknowledged_by,
            severity: alert.severity.as_str(),
            started: time(alert.started_ms),
            resolved: alert.resolved_ms.map(time),
            reason: alert.resolve_reason,
            agent_id: alert.agent_id,
            host: alert.host,
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
    gave_up: bool,
    attempts: i32,
    error: String,
    created: String,
}

impl From<DeliveryProblem> for ProblemRow {
    fn from(problem: DeliveryProblem) -> Self {
        Self {
            event: problem.event.as_str(),
            gave_up: problem.state == "failed",
            created: time(problem.created_ms),
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
        anyhow::Ok((open, resolved, problems, silences))
    };
    let (open, resolved, problems, silences) = match rows.await {
        Ok(rows) => rows,
        Err(error) => return server_error(&error),
    };

    let open: Vec<AlertRow> = open
        .into_iter()
        .map(|alert| {
            let silence = silences
                .covering(&alert)
                .map(|silence| time(silence.ends_ms));
            AlertRow {
                silenced_until: silence,
                ..AlertRow::from(alert)
            }
        })
        .collect();
    let resolved: Vec<AlertRow> = resolved.into_iter().map(AlertRow::from).collect();
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

async fn acknowledge(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    let by = signed_in_user().map_or_else(|| "admin".to_string(), |user| user.email.clone());
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
