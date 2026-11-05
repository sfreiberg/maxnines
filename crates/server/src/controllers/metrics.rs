use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};

use super::{Page, server_error};
use crate::app_state::AppState;
use crate::fact_history::format_time;
use crate::metric_charts::{self, Chart, MAX_SERIES};
use crate::metrics::{self, METRICS, Metric, TimeRange, Unit, now_ms};
use crate::registration::{AgentRecord, AgentState};

const HOUR_MS: i64 = 3_600_000;

/// The ranges pages offer: what's in the URL, what's on the link, and its length.
const RANGES: [(&str, &str, i64); 5] = [
    ("1h", "1 hour", HOUR_MS),
    ("6h", "6 hours", 6 * HOUR_MS),
    ("24h", "24 hours", 24 * HOUR_MS),
    ("7d", "7 days", 7 * 24 * HOUR_MS),
    ("30d", "30 days", 30 * 24 * HOUR_MS),
];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(index))
        .route("/agents/{id}/metrics", get(show))
        .route("/agents/{id}/metrics/{metric}", get(data))
}

#[derive(Serialize)]
struct FleetRow {
    id: String,
    host: String,
    online: bool,
    cpu: Option<String>,
    memory: Option<String>,
    disk: Option<String>,
    disk_mount_point: Option<String>,
    updated: Option<String>,
}

fn percent(value: Option<f64>) -> Option<String> {
    value.map(|value| metric_charts::format_value(Unit::Percent, value))
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let mut current = match state.metrics.current(now_ms()).await {
        Ok(current) => current,
        Err(error) => return server_error(&error),
    };

    let agents: Vec<FleetRow> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|agent| agent.state == AgentState::Approved)
        .map(|agent| {
            let values = current.remove(&agent.id).unwrap_or_default();
            FleetRow {
                online: state.presence.get(&agent.id).is_some_and(|p| p.online),
                cpu: percent(values.cpu_percent),
                memory: percent(values.memory_percent),
                disk: percent(values.disk_percent),
                disk_mount_point: values.disk_mount_point,
                updated: u64::try_from(values.time_ms)
                    .ok()
                    .filter(|time| *time > 0)
                    .map(format_time),
                id: agent.id,
                host: agent.host,
            }
        })
        .collect();

    Page::new(&state, &token, "metrics/index.html")
        .with("agents", &agents)
        .render()
}

#[derive(Deserialize)]
struct RangeParams {
    range: Option<String>,
}

#[derive(Serialize)]
struct RangeLink {
    key: &'static str,
    label: &'static str,
    selected: bool,
}

/// A range nobody offered falls back to the shortest.
fn selected_range(params: &RangeParams) -> (&'static str, &'static str, i64) {
    RANGES
        .into_iter()
        .find(|(key, _, _)| params.range.as_deref() == Some(*key))
        .unwrap_or(RANGES[0])
}

fn time_range(length_ms: i64) -> Option<TimeRange> {
    let now = now_ms();
    TimeRange::new(now - length_ms, now)
}

async fn chart(
    state: &AppState,
    agent: &AgentRecord,
    metric: &'static Metric,
    range: TimeRange,
) -> anyhow::Result<Chart> {
    let result = state
        .metrics
        .series(&agent.id, metric, range, MAX_SERIES)
        .await?;
    Ok(metric_charts::build(metric, &result, range))
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<RangeParams>,
    token: CsrfToken,
) -> Response {
    let Some(agent) = state.registry.get(&id).await else {
        return not_found(&state, &token);
    };
    let (selected, _, length_ms) = selected_range(&params);
    let Some(range) = time_range(length_ms) else {
        return not_found(&state, &token);
    };

    let mut charts = Vec::new();
    for metric in METRICS {
        match chart(&state, &agent, metric, range).await {
            Ok(chart) => charts.push(chart),
            Err(error) => return server_error(&error),
        }
    }

    let ranges: Vec<RangeLink> = RANGES
        .into_iter()
        .map(|(key, label, _)| RangeLink {
            key,
            label,
            selected: key == selected,
        })
        .collect();

    Page::new(&state, &token, "metrics/show.html")
        .with("agent_id", &agent.id)
        .with("host", &agent.host)
        .with("charts", &charts)
        .with("ranges", &ranges)
        .with("range", selected)
        .render()
}

/// A chart's numbers as a table, for anyone who can't use the chart.
async fn data(
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
    Query(params): Query<RangeParams>,
    token: CsrfToken,
) -> Response {
    let (Some(agent), Some(metric)) = (state.registry.get(&id).await, metrics::find(&name)) else {
        return not_found(&state, &token);
    };
    let (selected, label, length_ms) = selected_range(&params);
    let Some(range) = time_range(length_ms) else {
        return not_found(&state, &token);
    };

    match chart(&state, &agent, metric, range).await {
        Ok(chart) => Page::new(&state, &token, "metrics/data.html")
            .with("agent_id", &agent.id)
            .with("host", &agent.host)
            .with("chart", &chart)
            .with("range", selected)
            .with("range_label", label)
            .render(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(range: Option<&str>) -> RangeParams {
        RangeParams {
            range: range.map(String::from),
        }
    }

    #[test]
    fn an_offered_range_is_used() {
        assert_eq!(selected_range(&params(Some("7d"))).0, "7d");
    }

    #[test]
    fn anything_else_falls_back_to_the_shortest_range() {
        assert_eq!(selected_range(&params(None)).0, "1h");
        assert_eq!(selected_range(&params(Some("1y"))).0, "1h");
    }
}
