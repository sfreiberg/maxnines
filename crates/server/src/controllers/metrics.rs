use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinSet;

use super::{Page, fleet, server_error};
use crate::app_state::AppState;
use crate::metric_charts::{self, Chart, MAX_SERIES};
use crate::metrics::{self, METRICS, Metric, ShowChart, TimeRange, Unit, now_ms};
use crate::registration::AgentRecord;

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

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    match fleet::rows(&state).await {
        Ok(agents) => Page::new(&state, &token, "metrics/index.html")
            .with("agents", &agents)
            .render(),
        Err(error) => server_error(&error),
    }
}

/// A check's latest result. Agents send this, so nothing about it is trusted to
/// be the right shape: anything unusable is just left blank.
#[derive(Serialize)]
pub struct CheckRow {
    name: String,
    kind: String,
    pub up: bool,
    error: Option<String>,
    response: Option<String>,
    first_byte: Option<String>,
    status: Option<u64>,
    protocol: Option<String>,
    tls_version: Option<String>,
    cert_days_left: Option<i64>,
}

pub fn check_row(check: &Value) -> Option<CheckRow> {
    let text = |name: &str| check[name].as_str().map(String::from);
    let time = |name: &str| {
        let value = check[name].as_f64()?;
        Some(metric_charts::format_value(Unit::Milliseconds, value))
    };
    Some(CheckRow {
        name: text("name")?,
        kind: text("kind").unwrap_or_default(),
        up: check["up"].as_u64() == Some(1),
        error: text("error"),
        response: time("response_ms"),
        first_byte: time("first_byte_ms"),
        status: check["status"].as_u64(),
        protocol: text("protocol"),
        tls_version: text("tls_version"),
        cert_days_left: check["cert_days_left"].as_i64(),
    })
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

    // Each chart is its own query, so they run together rather than in turn.
    let mut queries = JoinSet::new();
    let shown = METRICS.iter().enumerate();
    for (position, metric) in shown.filter(|(_, m)| m.chart != ShowChart::Never) {
        let (state, agent) = (state.clone(), agent.clone());
        queries.spawn(async move {
            let result = chart(&state, &agent, metric, range).await;
            (position, metric, result)
        });
    }

    let mut charts = Vec::new();
    while let Some(finished) = queries.join_next().await {
        match finished {
            Ok((position, metric, Ok(chart)))
                if chart.has_data || metric.chart == ShowChart::Always =>
            {
                charts.push((position, chart));
            }
            Ok((_, _, Ok(_))) => {}
            Ok((_, _, Err(error))) => return server_error(&error),
            Err(error) => return server_error(&error.into()),
        }
    }
    charts.sort_by_key(|(position, _)| *position);
    let charts: Vec<Chart> = charts.into_iter().map(|(_, chart)| chart).collect();

    let ranges: Vec<RangeLink> = RANGES
        .into_iter()
        .map(|(key, label, _)| RangeLink {
            key,
            label,
            selected: key == selected,
        })
        .collect();

    // The server saves its checks one at a time, so no one sample has them all.
    let latest = if agent.is_local() {
        Ok(state.check_results.all().into_values().collect())
    } else {
        let output = state
            .metrics
            .latest_output(&agent.id, "checks", now_ms())
            .await;
        output.map(|output| match output {
            Some(Value::Array(checks)) => checks,
            _ => Vec::new(),
        })
    };
    let checks: Vec<CheckRow> = match latest {
        Ok(checks) => checks.iter().filter_map(check_row).collect(),
        Err(error) => return server_error(&error),
    };

    Page::new(&state, &token, "metrics/show.html")
        .with("checks", &checks)
        .with("is_local", &agent.is_local())
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
