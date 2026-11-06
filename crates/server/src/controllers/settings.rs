use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;

use serde::Serialize;

use super::agents::format_uptime;
use super::{Page, server_error};
use crate::app_state::AppState;
use crate::fact_history::format_time;
use crate::metric_charts::format_value;
use crate::metrics::{Unit, now_ms};
use crate::server_stats::{self, ServerStats};
use crate::store::StoreStats;

/// Alert rules are checked every 15 seconds, so this means they've stopped.
const ALERT_PASS_STALE_MS: i64 = 60_000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings", get(index))
        .route("/settings/server", get(server))
}

fn bytes(value: f64) -> String {
    format_value(Unit::Bytes, value)
}

fn time(ms: i64) -> String {
    u64::try_from(ms).map_or_else(|_| String::new(), format_time)
}

/// Thousands separated, as these get large.
fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

#[derive(Serialize)]
struct Bar {
    text: String,
    width: f64,
}

fn share(used: f64, total: f64) -> Bar {
    let percent = if total > 0.0 {
        used / total * 100.0
    } else {
        0.0
    };
    Bar {
        text: format!("{} of {}", bytes(used), bytes(total)),
        width: percent.clamp(0.0, 100.0),
    }
}

#[derive(Serialize)]
struct CollectorRow {
    name: String,
    rows: String,
    last_hour: String,
    oldest: String,
    newest: String,
}

#[derive(Serialize)]
struct TableRow {
    name: &'static str,
    rows: String,
}

#[derive(Serialize)]
struct ServerPage {
    version: String,
    commit: String,
    built_at: String,
    started: String,
    uptime: String,
    os: Option<String>,
    process_memory: Option<String>,
    process_cpu: Option<String>,
    open_files: Option<usize>,
    machine_memory: Option<Bar>,
    cores: Option<usize>,
    disk: Option<Bar>,
    disk_mount_point: Option<String>,
    metrics: Option<StoreStats>,
    collectors: Vec<CollectorRow>,
    total_rows: String,
    database_engine: Option<&'static str>,
    database_size: Option<String>,
    database_response: Option<String>,
    latest_migration: Option<String>,
    tables: Vec<TableRow>,
    has_database: bool,
    notifications_waiting: u64,
    notifications_failed: u64,
    samples_written: String,
    samples_failed: u64,
    samples_queued: usize,
    queue_capacity: usize,
    agents_online: usize,
    agents_approved: usize,
    agents_waiting: usize,
    alerts_firing: usize,
    last_alert_pass: Option<String>,
    alert_rules_stalled: bool,
}

fn server_page(stats: ServerStats, now_ms: i64) -> ServerPage {
    let process = stats.process.as_ref();
    let database = stats.database.as_ref();
    let collectors = stats
        .metrics
        .as_ref()
        .map_or(&[][..], |m| m.collectors.as_slice());
    let total_rows: i64 = collectors.iter().map(|collector| collector.rows).sum();
    let activity = &stats.activity;
    let last_pass = activity.last_alert_pass_ms;

    ServerPage {
        started: time(stats.started_ms),
        uptime: format_uptime(stats.uptime_secs),
        process_memory: process.map(|p| bytes(p.memory_bytes as f64)),
        process_cpu: process
            .and_then(|p| p.cpu_percent)
            .map(|cpu| format_value(Unit::Percent, cpu)),
        open_files: process.and_then(|p| p.open_files),
        machine_memory: process.map(|p| {
            share(
                p.machine_memory_used_bytes as f64,
                p.machine_memory_total_bytes as f64,
            )
        }),
        cores: process.map(|p| p.cores),
        disk: stats.disk.as_ref().map(|disk| {
            let used = disk.total_bytes.saturating_sub(disk.available_bytes);
            share(used as f64, disk.total_bytes as f64)
        }),
        disk_mount_point: stats.disk.as_ref().map(|disk| disk.mount_point.clone()),
        collectors: collectors
            .iter()
            .map(|collector| CollectorRow {
                name: collector.name.clone(),
                rows: count(collector.rows.max(0) as u64),
                last_hour: count(collector.rows_last_hour.max(0) as u64),
                oldest: time(collector.oldest_ms),
                newest: time(collector.newest_ms),
            })
            .collect(),
        total_rows: count(total_rows.max(0) as u64),
        database_engine: database.map(|d| d.engine),
        database_size: database
            .and_then(|d| d.size_bytes)
            .map(|size| bytes(size as f64)),
        database_response: database.map(|d| format_value(Unit::Milliseconds, d.response_ms)),
        latest_migration: database.and_then(|d| d.latest_migration.clone()),
        tables: database.map_or_else(Vec::new, |d| {
            d.tables
                .iter()
                .map(|table| TableRow {
                    name: table.name,
                    rows: count(table.rows),
                })
                .collect()
        }),
        has_database: database.is_some(),
        notifications_waiting: database.map_or(0, |d| d.notifications_waiting),
        notifications_failed: database.map_or(0, |d| d.notifications_failed),
        samples_written: count(activity.samples_written),
        samples_failed: activity.samples_failed,
        samples_queued: activity.samples_queued,
        queue_capacity: activity.queue_capacity,
        agents_online: activity.agents_online,
        agents_approved: activity.agents_approved,
        agents_waiting: activity.agents_waiting,
        alerts_firing: activity.alerts_firing,
        last_alert_pass: last_pass.map(time),
        alert_rules_stalled: last_pass.is_some_and(|ms| now_ms - ms > ALERT_PASS_STALE_MS),
        metrics: stats.metrics,
        version: stats.version,
        commit: stats.commit,
        built_at: stats.built_at,
        os: stats.os,
    }
}

async fn server(State(state): State<AppState>, token: CsrfToken) -> Response {
    let stats = server_stats::gather(&state).await;
    Page::new(&state, &token, "settings/server.html")
        .with("server", &server_page(stats, now_ms()))
        .render()
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let counts = async {
        let rules = state.database.list_rules().await?.len();
        let alert_rules = state.database.list_alert_rules().await?.len();
        let api_keys = state.database.list_api_keys().await?.len();
        let channels = state.database.list_channels().await?.len();
        anyhow::Ok((rules, alert_rules, channels, api_keys))
    };
    match counts.await {
        Ok((rules, alert_rules, channels, api_keys)) => {
            Page::new(&state, &token, "settings/index.html")
                .with("rules", &rules)
                .with("alert_rules", &alert_rules)
                .with("api_keys", &api_keys)
                .with("channels", &channels)
                .render()
        }
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_counts_are_separated() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(20_160_000), "20,160,000");
    }

    #[test]
    fn a_share_of_nothing_is_nothing() {
        assert_eq!(share(5.0, 0.0).width, 0.0);
        assert_eq!(share(50.0, 100.0).width, 50.0);
        assert_eq!(share(500.0, 100.0).width, 100.0);
    }
}
