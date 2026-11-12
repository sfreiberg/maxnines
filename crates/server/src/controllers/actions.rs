//! Actions as pages: what a host can be asked to run, a button to run one now,
//! and what each run printed, for a host or for an alert.

use std::collections::BTreeMap;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_csrf::CsrfToken;
use maxnines_protocol::actions::{ActionOutcome, DEFAULT_ACTION_TIMEOUT_SECS};
use serde::Serialize;

use super::{CsrfForm, Page, local_time, recorded_by, server_error};
use crate::actions::{ActionRun, NewRun, RUN_BY_HAND, check_timeout};
use crate::app_state::AppState;
use crate::metrics::now_ms;

/// How many of a host's runs its page shows.
const HISTORY: u64 = 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/hosts/{id}/actions", get(host).post(run_now))
        .route("/alerts/{id}/actions", get(alert))
}

/// A run as a page shows it. What an agent sends is only ever shown as text.
#[derive(Serialize)]
pub(super) struct RunRow {
    id: i64,
    action: String,
    /// Why it ran, in words.
    why: String,
    asked: String,
    /// `good`, `bad` or `neutral`, for the badge.
    class: &'static str,
    status: String,
    /// More about how it ended, if there's more to say.
    detail: String,
    /// What it was given, like `disk=/var`.
    given: String,
    output: String,
    truncated: bool,
    waiting: bool,
}

pub(super) fn run_row(run: ActionRun) -> RunRow {
    let why = match (run.run_on.as_str(), &run.requested_by) {
        (RUN_BY_HAND, Some(by)) => format!("Run by {by}"),
        (RUN_BY_HAND, None) => "Run by hand".to_string(),
        ("warning", _) => "Ran when the alert was a warning".to_string(),
        ("critical", _) => "Ran when the alert was critical".to_string(),
        _ => "Ran when the alert started".to_string(),
    };
    let (class, status) = match run.outcome {
        None => ("neutral", "Waiting for the host"),
        Some(ActionOutcome::Succeeded) => ("good", "Succeeded"),
        Some(ActionOutcome::Failed) => ("bad", "Failed"),
        Some(ActionOutcome::TimedOut) => ("bad", "Ran out of time"),
        Some(ActionOutcome::NotDefined) => ("bad", "Not on this host"),
        Some(ActionOutcome::Refused) => ("bad", "Not run"),
    };
    let mut detail = Vec::new();
    if let Some(error) = &run.error {
        detail.push(error.clone());
    }
    if let Some(code) = run.exit_code.filter(|code| *code != 0) {
        detail.push(format!("exit status {code}"));
    }
    if let Some(ms) = run.duration_ms {
        detail.push(format!("took {:.1}s", ms as f64 / 1000.0));
    }
    let given: Vec<String> = run
        .variables
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    RunRow {
        id: run.id,
        action: run.action,
        why,
        asked: local_time(run.requested_ms),
        class,
        status: status.to_string(),
        detail: detail.join(", "),
        given: given.join(" "),
        output: run.output,
        truncated: run.truncated,
        waiting: run.outcome.is_none(),
    }
}

/// An action a host has, for its Run now form.
#[derive(Serialize)]
struct Available {
    name: String,
    /// What has to be typed in for it.
    needs: Vec<String>,
}

async fn host(State(state): State<AppState>, token: CsrfToken, Path(id): Path<String>) -> Response {
    host_page(&state, &token, &id, None).await
}

async fn host_page(state: &AppState, token: &CsrfToken, id: &str, error: Option<&str>) -> Response {
    let Some(host) = state.registry.get(id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let available = match state.database.host_actions(id).await {
        Ok(available) => available,
        Err(error) => return server_error(&error),
    };
    let available: Vec<Available> = available
        .into_iter()
        .map(|(name, needs)| Available { name, needs })
        .collect();
    let runs = match state.database.action_runs_for_host(id, HISTORY).await {
        Ok(runs) => runs,
        Err(error) => return server_error(&error),
    };
    let runs: Vec<RunRow> = runs.into_iter().map(run_row).collect();
    let online = state
        .presence
        .get(id)
        .is_some_and(|presence| presence.online);

    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    Page::new(state, token, "actions/host.html")
        .with("host_id", &host.id)
        .with("hostname", &host.hostname)
        .with("online", &online)
        .with("available", &available)
        .with("runs", &runs)
        .with("default_timeout", &DEFAULT_ACTION_TIMEOUT_SECS)
        .with("error", &error)
        .with_status(status)
        .render()
}

/// Runs one of a host's actions now, for whoever pressed the button.
async fn run_now(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let action = form.fields.get("action").cloned().unwrap_or_default();
    let timeout_secs = match form.fields.get("timeout_secs").map(|secs| secs.trim()) {
        None | Some("") => Ok(DEFAULT_ACTION_TIMEOUT_SECS),
        Some(secs) => secs.parse::<u64>().map_err(|_| ()),
    };
    let timeout_secs = match timeout_secs {
        Ok(secs) if check_timeout(secs).is_ok() => secs,
        _ => {
            let error = "The time limit has to be from 1 to 600 seconds.";
            return host_page(&state, &form.token, &id, Some(error)).await;
        }
    };
    // Each variable has a box of its own, named for it.
    let variables: BTreeMap<String, String> = form
        .fields
        .iter()
        .filter_map(|(name, value)| Some((name.strip_prefix("variable_")?, value.trim())))
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();

    let new = NewRun {
        host_id: id.clone(),
        alert_id: None,
        action,
        run_on: RUN_BY_HAND.to_string(),
        variables,
        requested_by: Some(recorded_by()),
        requested_ms: now_ms(),
        timeout_secs,
    };
    match state.actions.run(new).await {
        Ok(_) => (form.token, Redirect::to(&format!("/hosts/{id}/actions"))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn alert(State(state): State<AppState>, token: CsrfToken, Path(id): Path<i64>) -> Response {
    let alert = match state.database.get_alert(id).await {
        Ok(Some(alert)) => alert,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    let runs = match state.database.action_runs_for_alert(id).await {
        Ok(runs) => runs,
        Err(error) => return server_error(&error),
    };
    let runs: Vec<RunRow> = runs.into_iter().map(run_row).collect();
    Page::new(&state, &token, "actions/alert.html")
        .with("summary", &alert.summary)
        .with("rule_name", &alert.rule_name)
        .with("host_id", &alert.host_id)
        .with("hostname", &alert.hostname)
        .with("started", &local_time(alert.started_ms))
        .with("runs", &runs)
        .render()
}
