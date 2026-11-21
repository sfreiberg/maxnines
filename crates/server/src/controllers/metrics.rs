use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use chrono::TimeDelta;
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinSet;

use super::host_list::{HostSearch, address, page_number, paginate};
use super::{Page, fleet, local_time, server_error, viewer_zone};
use crate::app_state::AppState;
use crate::events::TimelineEvent;
use crate::metric_charts::{self, Chart, MAX_SERIES};
use crate::metrics::{self, METRICS, Metric, SeriesResult, ShowChart, TimeRange, Unit};
use crate::times::{self, Timestamp};

/// The ranges pages offer: what's in the URL, what's on the link, and its length.
const RANGES: [(&str, &str, TimeDelta); 5] = [
    ("1h", "1 hour", TimeDelta::hours(1)),
    ("6h", "6 hours", TimeDelta::hours(6)),
    ("24h", "24 hours", TimeDelta::hours(24)),
    ("7d", "7 days", TimeDelta::days(7)),
    ("30d", "30 days", TimeDelta::days(30)),
];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(index))
        .route("/hosts/{id}/metrics", get(show))
        .route("/hosts/{id}/metrics/{metric}", get(data))
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
        let hosts = fleet::rows(&state).await?;
        anyhow::Ok((search, hosts))
    };
    let (search, mut hosts) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };

    hosts.retain(|host| search.includes(&host.id, &host.hostname));
    let pages = paginate(&mut hosts, page_number(params.page.as_deref()), |page| {
        address(
            "/metrics",
            &[("filter", &search.text), ("page", &page.to_string())],
        )
    });
    Page::new(&state, &token, "metrics/index.html")
        .with("hosts", &hosts)
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
    pub error: Option<String>,
    pub response: Option<String>,
    first_byte: Option<String>,
    pub status: Option<u64>,
    pub protocol: Option<String>,
    pub tls_version: Option<String>,
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

/// A watched service as its host's service manager last described it.
#[derive(Serialize)]
struct ServiceRow {
    name: String,
    running: bool,
    /// The service manager's word for it, when it isn't running.
    state: Option<String>,
}

fn service_row(service: &Value) -> Option<ServiceRow> {
    let running = service["running"].as_u64() == Some(1);
    Some(ServiceRow {
        name: service["name"].as_str()?.to_string(),
        running,
        state: service["state"]
            .as_str()
            .filter(|_| !running)
            .map(String::from),
    })
}

/// A check command's latest result. Agents send this, so it's treated the same
/// way as a check's.
#[derive(Serialize)]
struct CommandRow {
    name: String,
    /// OK, Warning, Critical or Unknown, as the plugin's exit said.
    status: &'static str,
    /// `good`, `warn`, `bad` or `neutral`, for its badge.
    tone: &'static str,
    message: Option<String>,
}

fn command_row(item: &Value) -> Option<CommandRow> {
    // Values are items of their own, without a status.
    let status = item["status"].as_u64()?;
    let (status, tone) = match status {
        0 => ("OK", "good"),
        1 => ("Warning", "warn"),
        2 => ("Critical", "bad"),
        _ => ("Unknown", "neutral"),
    };
    Some(CommandRow {
        name: item["name"].as_str()?.to_string(),
        status,
        tone,
        message: item["message"]
            .as_str()
            .filter(|message| !message.is_empty())
            .map(String::from),
    })
}

/// A database's latest state, from its own row. Rows for what it has several
/// of, such as standbys, are charted instead.
#[derive(Serialize)]
struct DatabaseRow {
    name: String,
    up: bool,
    role: Option<String>,
    version: Option<String>,
    /// Why it couldn't be read, or what of it couldn't be.
    note: Option<String>,
}

/// Each value is stored under the database's kind, such as `postgres.up`, so the
/// kind comes from whichever says whether it's up. A database the agent doesn't
/// have is under `unknown`.
fn database_row(item: &Value) -> Option<DatabaseRow> {
    let fields = item.as_object()?;
    let (kind, up) = fields
        .iter()
        .find_map(|(key, value)| Some((key.strip_suffix(".up")?, value.as_u64()?)))?;
    let text = |key: &str| {
        fields
            .get(&format!("{kind}.{key}"))?
            .as_str()
            .map(String::from)
    };
    Some(DatabaseRow {
        name: item["name"].as_str()?.to_string(),
        up: up == 1,
        role: text("role"),
        version: text("version"),
        note: text("error")
            .or_else(|| text("missing").map(|missing| format!("Couldn't read {missing}"))),
    })
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
        Some(metric_charts::format_value(Unit::Seconds, value))
    };
    Some(CheckRow {
        name: text("name")?,
        kind: text("kind").unwrap_or_default(),
        up: check["up"].as_u64() == Some(1),
        error: text("error"),
        response: time("response_secs"),
        first_byte: time("first_byte_secs"),
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

/// What a chart's data page can be asked for: its range, and one series alone.
#[derive(Deserialize, Default)]
struct DataParams {
    range: Option<String>,
    series: Option<String>,
}

/// Enough to hold every series a host has of one metric, for picking one out.
pub(super) const EVERY_SERIES: usize = 10_000;

/// One series of a metric, or none if the host has no such series in the range.
pub(super) async fn one_series(
    state: &AppState,
    host_id: &str,
    metric: &'static Metric,
    name: &str,
    range: TimeRange,
) -> anyhow::Result<SeriesResult> {
    let mut result = state
        .metrics
        .series(host_id, metric, range, EVERY_SERIES)
        .await?;
    result.series.retain(|series| series.name == name);
    result.hidden = 0;
    Ok(result)
}

/// What the host page's address can say: its range, and why a note was refused.
#[derive(Deserialize, Default)]
pub(super) struct ShowParams {
    range: Option<String>,
    event_error: Option<String>,
}

/// One line of a host's Events list.
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
        time: local_time(event.occurred_at),
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
pub(super) fn selected_range(params: &RangeParams) -> (&'static str, &'static str, TimeDelta) {
    RANGES
        .into_iter()
        .find(|(key, _, _)| params.range.as_deref() == Some(*key))
        .unwrap_or(RANGES[0])
}

/// The shortest range that reaches back to `since` with a quarter as long again
/// before it, to show what led up to it, or the longest when none does.
pub(super) fn range_reaching(since: Timestamp, now: Timestamp) -> &'static str {
    let wanted = (now - since) * 5 / 4;
    RANGES
        .into_iter()
        .find(|(_, _, length)| *length >= wanted)
        .unwrap_or(RANGES[RANGES.len() - 1])
        .0
}

/// The range of this length that ends now.
pub(super) fn time_range(length: TimeDelta) -> Option<TimeRange> {
    TimeRange::ending(times::now(), length)
}

async fn chart(
    state: &AppState,
    host_id: &str,
    metric: &'static Metric,
    range: TimeRange,
    zone: Tz,
) -> anyhow::Result<Chart> {
    let result = state
        .metrics
        .series(host_id, metric, range, MAX_SERIES)
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
    host_id: &str,
    metrics: &[&'static Metric],
    range: TimeRange,
    zone: Tz,
) -> anyhow::Result<Vec<Chart>> {
    let mut queries = JoinSet::new();
    for (position, metric) in metrics.iter().copied().enumerate() {
        let (state, host_id) = (state.clone(), host_id.to_string());
        queries
            .spawn(async move { (position, chart(&state, &host_id, metric, range, zone).await) });
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
    let Some(host) = state.registry.get(&id).await else {
        return not_found(&state, &token);
    };
    let range_params = RangeParams {
        range: params.range.clone(),
    };
    let (selected, _, length) = selected_range(&range_params);
    let Some(range) = time_range(length) else {
        return not_found(&state, &token);
    };

    let shown: Vec<&'static Metric> = METRICS
        .iter()
        .filter(|metric| metric.chart != ShowChart::Never)
        .collect();
    let charts = match charts_for(&state, &host.id, &shown, range, viewer_zone()).await {
        Ok(charts) => charts,
        Err(error) => return server_error(&error),
    };
    let events = match state.timeline(&host.id, range.from, range.to).await {
        Ok(events) => events,
        Err(error) => return server_error(&error),
    };
    let zone = viewer_zone();
    let charts: Vec<Chart> = charts
        .into_iter()
        .zip(shown)
        .filter(|(chart, metric)| {
            // What every agent reports is only worth an empty chart for a host that
            // has an agent.
            let has_agent = !host.is_local() && !host.is_agentless();
            chart.has_data || (metric.chart == ShowChart::Always && has_agent)
        })
        .map(|(mut chart, _)| {
            metric_charts::mark(&mut chart, &events, range, zone);
            chart
        })
        .collect();
    let events: Vec<EventRow> = events.into_iter().map(event_row).collect();

    let ranges = range_links(selected);

    // The server saves its checks one at a time, so no one sample has them all.
    let latest = if host.is_agentless() {
        state.database.list_remote_checks().await.map(|checks| {
            let mut results = state.check_results.all();
            checks
                .into_iter()
                .filter(|check| check.input.host_id == host.id)
                .filter_map(|check| results.remove(&check.id))
                .collect()
        })
    } else {
        let output = state
            .metrics
            .latest_output(&host.id, "checks", times::now())
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
            .latest_output(&host.id, collector, times::now())
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
    let latest = state
        .metrics
        .latest_output(&host.id, "commands", times::now());
    let commands: Vec<CommandRow> = match latest.await {
        Ok(Some(Value::Array(items))) => items.iter().filter_map(command_row).collect(),
        Ok(_) => Vec::new(),
        Err(error) => return server_error(&error),
    };
    let latest = state
        .metrics
        .latest_output(&host.id, "databases", times::now());
    let databases: Vec<DatabaseRow> = match latest.await {
        Ok(Some(Value::Array(items))) => items.iter().filter_map(database_row).collect(),
        Ok(_) => Vec::new(),
        Err(error) => return server_error(&error),
    };
    let latest = state
        .metrics
        .latest_output(&host.id, "services", times::now());
    let services: Vec<ServiceRow> = match latest.await {
        Ok(Some(Value::Array(items))) => items.iter().filter_map(service_row).collect(),
        Ok(_) => Vec::new(),
        Err(error) => return server_error(&error),
    };

    Page::new(&state, &token, "metrics/show.html")
        .with("checks", &checks)
        .with("custom_metrics", &custom_metrics)
        .with("commands", &commands)
        .with("databases", &databases)
        .with("counters", &counters)
        .with("services", &services)
        .with("is_local", &host.is_local())
        .with("host_id", &host.id)
        .with("hostname", &host.hostname)
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
    Query(params): Query<DataParams>,
    token: CsrfToken,
) -> Response {
    let (Some(host), Some(metric)) = (state.registry.get(&id).await, metrics::find(&name)) else {
        return not_found(&state, &token);
    };
    let range_params = RangeParams {
        range: params.range,
    };
    let (selected, label, length) = selected_range(&range_params);
    let Some(range) = time_range(length) else {
        return not_found(&state, &token);
    };

    let zone = viewer_zone();
    let chart = match &params.series {
        Some(series) => one_series(&state, &host.id, metric, series, range)
            .await
            .map(|result| metric_charts::build(metric, &result, range, zone)),
        None => chart(&state, &host.id, metric, range, zone).await,
    };
    match chart {
        Ok(chart) => Page::new(&state, &token, "metrics/data.html")
            .with("host_id", &host.id)
            .with("hostname", &host.hostname)
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
    fn the_range_reaching_a_moment_leaves_room_before_it() {
        let now = times::from_ms(100 * 86_400_000);
        let (minutes, hours, days) = (TimeDelta::minutes, TimeDelta::hours, TimeDelta::days);
        assert_eq!(range_reaching(now - minutes(10), now), "1h");
        assert_eq!(range_reaching(now - minutes(50), now), "6h");
        assert_eq!(range_reaching(now - hours(4), now), "6h");
        assert_eq!(range_reaching(now - hours(18), now), "24h");
        assert_eq!(range_reaching(now - hours(20), now), "7d");
        assert_eq!(range_reaching(now - days(3), now), "7d");
        assert_eq!(range_reaching(now - days(90), now), "30d");
    }

    #[test]
    fn anything_else_falls_back_to_the_shortest_range() {
        assert_eq!(selected_range(&params(None)).0, "1h");
        assert_eq!(selected_range(&params(Some("1y"))).0, "1h");
    }
}
