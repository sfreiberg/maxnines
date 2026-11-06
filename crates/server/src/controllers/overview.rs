use std::sync::atomic::Ordering;

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::metrics::{CheckRow, check_row};
use super::server::count;
use super::{Page, fleet, server_error};
use crate::alerting::Severity;
use crate::app_state::AppState;
use crate::registration::AgentState;

/// How many of each are shown. The page links to the full lists.
const MAX_PROBLEMS: usize = 8;
const MAX_AGENTS: usize = 12;
const MAX_CHECKS: usize = 12;

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index))
}

#[derive(Serialize)]
struct Problem {
    critical: bool,
    summary: String,
}

#[derive(Serialize)]
struct CheckTile {
    name: String,
    latest: Option<CheckRow>,
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let data = async {
        let agents = fleet::rows(&state).await?;
        let alerts = state.database.open_alerts().await?;
        let checks = state.database.list_remote_checks().await?;
        anyhow::Ok((agents, alerts, checks))
    };
    let (mut agents, alerts, checks) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };

    let problem_count = alerts.len();
    let critical_count = alerts
        .iter()
        .filter(|alert| alert.severity == Severity::Critical)
        .count();
    let mut problems: Vec<(bool, String)> = alerts
        .into_iter()
        .map(|alert| (alert.severity == Severity::Critical, alert.summary))
        .collect();
    problems.sort_by_key(|(critical, _)| !critical);
    let problems: Vec<Problem> = problems
        .into_iter()
        .take(MAX_PROBLEMS)
        .map(|(critical, summary)| Problem { critical, summary })
        .collect();

    let agent_count = agents.len();
    let online_count = agents.iter().filter(|agent| agent.online).count();
    agents.truncate(MAX_AGENTS);

    let latest = state.check_results.all();
    let check_count = checks.iter().filter(|check| check.input.enabled).count();
    let mut tiles: Vec<CheckTile> = checks
        .into_iter()
        .filter(|check| check.input.enabled)
        .map(|check| {
            let name = check.input.check.name;
            CheckTile {
                latest: latest.get(&name).and_then(check_row),
                name,
            }
        })
        .collect();
    let results = || tiles.iter().filter_map(|tile| tile.latest.as_ref());
    let checks_up = results().filter(|latest| latest.up).count();
    let checks_down = results().filter(|latest| !latest.up).count();
    // Anything down comes first.
    tiles.sort_by_key(|tile| tile.latest.as_ref().is_none_or(|latest| latest.up));
    tiles.truncate(MAX_CHECKS);

    let waiting = state
        .registry
        .list()
        .await
        .iter()
        .filter(|agent| agent.state == AgentState::Pending)
        .count();

    Page::new(&state, &token, "overview/index.html")
        .with("problems", &problems)
        .with("problem_count", &problem_count)
        .with("critical_count", &critical_count)
        .with("agents", &agents)
        .with("agent_count", &agent_count)
        .with("online_count", &online_count)
        .with("checks", &tiles)
        .with("check_count", &check_count)
        .with("checks_up", &checks_up)
        .with("checks_down", &checks_down)
        .with(
            "samples_written",
            &count(state.status.writes.written.load(Ordering::Relaxed)),
        )
        .with("waiting", &waiting)
        .render()
}
