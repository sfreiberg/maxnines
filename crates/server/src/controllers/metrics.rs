use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinSet;

use super::host_list::{HostSearch, address, page_number, paginate};
use super::{Page, fleet, local_time, server_error, viewer_zone};
use crate::app_state::AppState;
use crate::events::TimelineEvent;
use crate::metric_charts::{self, Chart, MAX_SERIES};
use crate::metrics::{self, METRICS, Metric, ShowChart, TimeRange, Unit, now_ms};

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

#[derive(Deserialize)]
struct FleetParams {
    filter: Option<String>,
    page: Option<String>,
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<FleetParams>,
    token: CsrfToken,
) -> Response {
    let data = async {
        let search = HostSearch::load(&state, params.filter.as_deref()).await?;
        let agents = fleet::rows(&state).await?;
        anyhow::Ok((search, agents))
    };
    let (search, mut agents) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };

    agents.retain(|agent| search.includes(&agent.id, &agent.host));
    let pages = paginate(&mut agents, page_number(params.page.as_deref()), |page| {
        address(
            "/metrics",
            &[("filter", &search.text), ("page", &page.to_string())],
        )
    });
    Page::new(&state, &token, "metrics/index.html")
        .with("agents", &agents)
        .with("pages", &pages)
        .with("search", &search)
        .with("search_path", "/metrics")
        .with("keep_tab", "")
        .with("as_table", &false)
        .render()
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

/// A custom metric's latest result. Agents send this, so it's treated the same
/// way as a check's.
#[derive(Serialize)]
struct CustomRow {
    name: String,
    working: bool,
    error: Option<String>,
    value: Option<String>,
}

fn custom_row(metric: &Value) -> Option<CustomRow> {
    Some(CustomRow {
        name: metric["name"].as_str()?.to_string(),
        // Only the command's own item says, and values from one that ran did work.
        working: metric["ok"].as_u64() != Some(0),
        error: metric["error"].as_str().map(String::from),
        value: metric["value"]
            .as_f64()
            .map(|value| metric_charts::format_value(Unit::Number, value)),
    })
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

#[derive(Deserialize, Default)]
pub(super) struct RangeParams {
    pub(super) range: Option<String>,
}

/// What the machine page's address can say: its range, and why a note was refused.
#[derive(Deserialize, Default)]
pub(super) struct ShowParams {
    range: Option<String>,
    event_error: Option<String>,
}

/// One line of a machine's Events list.
#[derive(Serialize)]
struct EventRow {
    id: Option<i64>,
    time: String,
    kind: &'static str,
    kind_label: &'static str,
    title: String,
    detail: Option<String>,
    created_by: Option<String>,
}

fn event_row(event: TimelineEvent) -> EventRow {
    EventRow {
        id: event.id,
        time: local_time(event.time_ms),
        kind: event.kind.as_str(),
        kind_label: event.kind.label(),
        title: event.title,
        detail: event.detail,
        created_by: event.created_by,
    }
}

#[derive(Serialize)]
pub(super) struct RangeLink {
    key: &'static str,
    label: &'static str,
    selected: bool,
}

/// A range nobody offered falls back to the shortest.
pub(super) fn selected_range(params: &RangeParams) -> (&'static str, &'static str, i64) {
    RANGES
        .into_iter()
        .find(|(key, _, _)| params.range.as_deref() == Some(*key))
        .unwrap_or(RANGES[0])
}

pub(super) fn time_range(length_ms: i64) -> Option<TimeRange> {
    let now = now_ms();
    TimeRange::new(now - length_ms, now)
}

async fn chart(
    state: &AppState,
    agent_id: &str,
    metric: &'static Metric,
    range: TimeRange,
    zone: Tz,
) -> anyhow::Result<Chart> {
    let result = state
        .metrics
        .series(agent_id, metric, range, MAX_SERIES)
        .await?;
    Ok(metric_charts::build(metric, &result, range, zone))
}

/// The links for choosing a range, with `selected` marked.
pub(super) fn range_links(selected: &str) -> Vec<RangeLink> {
    RANGES
        .into_iter()
        .map(|(key, label, _)| RangeLink {
            key,
            label,
            selected: key == selected,
        })
        .collect()
}

/// Charts for these metrics, in this order, with their times in `zone`. Each is its
/// own query, so they run together rather than in turn.
pub(super) async fn charts_for(
    state: &AppState,
    agent_id: &str,
    metrics: &[&'static Metric],
    range: TimeRange,
    zone: Tz,
) -> anyhow::Result<Vec<Chart>> {
    let mut queries = JoinSet::new();
    for (position, metric) in metrics.iter().copied().enumerate() {
        let (state, agent_id) = (state.clone(), agent_id.to_string());
        queries.spawn(async move {
            (
                position,
                chart(&state, &agent_id, metric, range, zone).await,
            )
        });
    }

    let mut charts = Vec::with_capacity(metrics.len());
    while let Some(finished) = queries.join_next().await {
        let (position, chart) = finished?;
        charts.push((position, chart?));
    }
    charts.sort_by_key(|(position, _)| *position);
    Ok(charts.into_iter().map(|(_, chart)| chart).collect())
}

pub(super) fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<ShowParams>,
    token: CsrfToken,
) -> Response {
    let Some(agent) = state.registry.get(&id).await else {
        return not_found(&state, &token);
    };
    let range_params = RangeParams {
        range: params.range.clone(),
    };
    let (selected, _, length_ms) = selected_range(&range_params);
    let Some(range) = time_range(length_ms) else {
        return not_found(&state, &token);
    };

    let shown: Vec<&'static Metric> = METRICS
        .iter()
        .filter(|metric| metric.chart != ShowChart::Never)
        .collect();
    let charts = match charts_for(&state, &agent.id, &shown, range, viewer_zone()).await {
        Ok(charts) => charts,
        Err(error) => return server_error(&error),
    };
    let events = match state.timeline(&agent.id, range.from_ms, range.to_ms).await {
        Ok(events) => events,
        Err(error) => return server_error(&error),
    };
    let zone = viewer_zone();
    let charts: Vec<Chart> = charts
        .into_iter()
        .zip(shown)
        .filter(|(chart, metric)| {
            chart.has_data || (metric.chart == ShowChart::Always && !agent.is_local())
        })
        .map(|(mut chart, _)| {
            metric_charts::mark(&mut chart, &events, range, zone);
            chart
        })
        .collect();
    let events: Vec<EventRow> = events.into_iter().map(event_row).collect();

    let ranges = range_links(selected);

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

    // Counters say what they read the same way custom metrics do.
    let mut readings = Vec::new();
    for collector in ["custom", "counters"] {
        match state
            .metrics
            .latest_output(&agent.id, collector, now_ms())
            .await
        {
            Ok(Some(Value::Array(items))) => {
                readings.push(items.iter().filter_map(custom_row).collect::<Vec<_>>());
            }
            Ok(_) => readings.push(Vec::new()),
            Err(error) => return server_error(&error),
        }
    }
    let counters = readings.pop().unwrap_or_default();
    let custom_metrics = readings.pop().unwrap_or_default();

    Page::new(&state, &token, "metrics/show.html")
        .with("checks", &checks)
        .with("custom_metrics", &custom_metrics)
        .with("counters", &counters)
        .with("is_local", &agent.is_local())
        .with("agent_id", &agent.id)
        .with("host", &agent.host)
        .with("charts", &charts)
        .with("events", &events)
        .with("event_error", &params.event_error)
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

    match chart(&state, &agent.id, metric, range, viewer_zone()).await {
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
