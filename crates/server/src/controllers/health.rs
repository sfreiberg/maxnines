//! For load balancers and uptime monitors, which have no login. It says whether each
//! part is working and nothing else, so it gives nothing away to a stranger.

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::time::timeout;

use crate::app_state::AppState;
use crate::metrics::now_ms;

/// A database slower than this isn't working, whatever the reason.
const CHECK_LIMIT: Duration = Duration::from_secs(2);

/// Alert rules are checked every 15 seconds, so this means they've stopped.
const ALERTS_STALE_MS: i64 = 60_000;

pub fn routes() -> Router<AppState> {
    Router::new().route("/health", get(show))
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Failing,
}

impl Status {
    fn of(working: bool) -> Self {
        if working { Self::Ok } else { Self::Failing }
    }

    fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

#[derive(Serialize)]
struct Checks {
    database: Status,
    metrics: Status,
    writer: Status,
    alerts: Status,
}

#[derive(Serialize)]
struct Health {
    status: Status,
    checks: Checks,
}

/// Whether rules have run lately. Nothing has to have run just after a start.
fn alerts_running(state: &AppState) -> bool {
    let status = &state.status;
    let last_pass = status.last_alert_pass_ms.load(Ordering::Relaxed);
    now_ms() - last_pass.max(status.started_ms) < ALERTS_STALE_MS
}

async fn show(State(state): State<AppState>) -> Response {
    let database = timeout(CHECK_LIMIT, state.database.is_reachable());
    let metrics = timeout(CHECK_LIMIT, state.metrics.series_count());
    let (database, metrics) = tokio::join!(database, metrics);

    let checks = Checks {
        database: Status::of(database.unwrap_or(false)),
        metrics: Status::of(metrics.is_ok_and(|count| count.is_ok())),
        writer: Status::of(!state.writer.is_closed()),
        alerts: Status::of(alerts_running(&state)),
    };
    let working = checks.database.is_ok()
        && checks.metrics.is_ok()
        && checks.writer.is_ok()
        && checks.alerts.is_ok();
    let code = if working {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let health = Health {
        status: Status::of(working),
        checks,
    };
    (code, Json(health)).into_response()
}
