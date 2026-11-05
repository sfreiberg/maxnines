use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{CsrfForm, Page, server_error};
use crate::app_state::AppState;
use crate::fact_history::{describe_history, format_time};
use crate::facts::{FlatFacts, unflatten};
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

async fn row(state: &AppState, agent: AgentRecord) -> AgentRow {
    let desired = state.config_for(&agent.id).await.ok();
    let reported = state.database.config_status(&agent.id).await.ok().flatten();

    AgentRow {
        online: state.presence.get(&agent.id).is_some_and(|p| p.online),
        config: config_state(
            desired.as_ref().map(|d| d.version.as_str()),
            reported.as_ref(),
        ),
        state: agent.state.as_str(),
        id: agent.id,
        host: agent.host,
    }
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let mut agents = Vec::new();
    for agent in state.registry.list().await {
        if !agent.is_local() {
            agents.push(row(&state, agent).await);
        }
    }
    Page::new(&state, &token, "agents/index.html")
        .with("agents", &agents)
        .render()
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
    let facts = serde_json::to_string_pretty(&unflatten(&flat)).unwrap_or_default();
    let config = serde_json::to_string_pretty(&desired.config).unwrap_or_default();
    let changes: Vec<HistoryEntry> = describe_history(&history)
        .into_iter()
        .rev()
        .map(|(time, changes)| HistoryEntry {
            time: format_time(time),
            changes,
        })
        .collect();

    let row = row(&state, agent.clone()).await;
    Page::new(&state, &token, "agents/show.html")
        .with("agent", &row)
        .with("decided_by", &agent.decided_by)
        .with("has_facts", &!flat.is_empty())
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
