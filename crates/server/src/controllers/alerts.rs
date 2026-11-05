use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{Page, server_error};
use crate::alerting::{Alert, DeliveryProblem};
use crate::app_state::AppState;
use crate::fact_history::format_time;

/// How many ended alerts the page shows.
const HISTORY: u64 = 50;

/// How many delivery problems the page shows.
const PROBLEMS: u64 = 20;

pub fn routes() -> Router<AppState> {
    Router::new().route("/alerts", get(index))
}

fn time(ms: i64) -> String {
    u64::try_from(ms).map_or_else(|_| String::new(), format_time)
}

#[derive(Serialize)]
struct AlertRow {
    agent_id: String,
    host: String,
    rule_name: String,
    severity: &'static str,
    summary: String,
    started: String,
    resolved: Option<String>,
    reason: Option<String>,
}

impl From<Alert> for AlertRow {
    fn from(alert: Alert) -> Self {
        Self {
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
        anyhow::Ok((open, resolved, problems))
    };
    let (open, resolved, problems) = match rows.await {
        Ok(rows) => rows,
        Err(error) => return server_error(&error),
    };

    let open: Vec<AlertRow> = open.into_iter().map(AlertRow::from).collect();
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
