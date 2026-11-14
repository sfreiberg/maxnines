//! How the server itself is doing: what the Server page and admin API report.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use maxnines_collectors::{Collector, WARMUP, host};
use maxnines_protocol::Sample;
use serde::Serialize;
use serde_json::{Value, json};
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System,
};
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::models::DatabaseStats;
use crate::registration::{HostRecord, HostState};
use crate::remote_checks::{LOCAL_HOST_ID, LOCAL_HOSTNAME};
use crate::store::{NewSample, StoreStats, WriteCounts, WriterCommand};

const HOUR_MS: i64 = 3_600_000;

/// What's kept between requests, and what background work reports back.
pub struct ServerStatus {
    pub started_ms: i64,
    pub writes: Arc<WriteCounts>,
    /// How many alerts are firing, for the navigation on every page.
    pub firing: AtomicUsize,
    /// When alert rules were last checked. Zero means not yet.
    pub last_alert_pass_ms: AtomicI64,
    /// Where metrics are kept, to report the space left there.
    data_path: Option<PathBuf>,
    pid: Pid,
    /// CPU use is measured between two looks, so this is kept for the next one.
    system: Mutex<(System, Option<Instant>)>,
}

impl ServerStatus {
    pub fn new(data_path: Option<PathBuf>) -> Result<Self> {
        let mut system = System::new().context("reading system information")?;
        system.refresh_cpu_list(CpuRefreshKind::nothing());
        Ok(Self {
            started_ms: now_ms(),
            writes: Arc::default(),
            firing: AtomicUsize::new(0),
            last_alert_pass_ms: AtomicI64::new(0),
            data_path,
            pid: sysinfo::get_current_pid()
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("finding this process")?,
            system: Mutex::new((system, None)),
        })
    }
}

/// How often the server records its own numbers, as agents do by default.
const RECORD_EVERY: Duration = Duration::from_secs(15);

fn file_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|file| file.len())
}

impl ServerStatus {
    /// The size of the metrics database and its write-ahead log, read from the files
    /// because asking the database what it holds is far slower.
    fn metrics_files(&self) -> (Option<u64>, Option<u64>) {
        let Some(path) = &self.data_path else {
            return (None, None);
        };
        let mut wal = path.clone().into_os_string();
        wal.push(".wal");
        (file_size(path), file_size(Path::new(&wal)))
    }
}

/// Samples counted so far, so each record can say how many are new.
#[derive(Default)]
pub struct Recorded {
    written: u64,
    failed: u64,
    values: u64,
    /// What's read about the host, as an agent would. Nothing needs installing, as
    /// that makes no sense everywhere a server can run, and each keeps state between
    /// reads, which is why these stay here.
    collectors: Vec<Box<dyn Collector + Send>>,
}

impl Recorded {
    /// Also reads the host, rather than only the server.
    pub fn with_host() -> Self {
        match host::all() {
            Ok(collectors) => Self {
                collectors,
                ..Self::default()
            },
            Err(error) => {
                let error = format!("{error:#}");
                warn!(
                    error,
                    "can't read the server's own host, so its charts will be empty"
                );
                Self::default()
            }
        }
    }
}

/// Reads the host, off the async threads as it can be slow. One failing only
/// leaves that one out.
async fn read_host(recorded: &mut Recorded) -> BTreeMap<String, Value> {
    let mut collectors = std::mem::take(&mut recorded.collectors);
    let read = tokio::task::spawn_blocking(move || {
        let mut readings = BTreeMap::new();
        for collector in &mut collectors {
            match catch_unwind(AssertUnwindSafe(|| collector.collect())) {
                Ok(Ok(value)) => {
                    readings.insert(collector.name().to_string(), value);
                }
                Ok(Err(error)) => warn!(
                    collector = collector.name(),
                    error = format!("{error:#}"),
                    "reading the server's own host failed"
                ),
                Err(_) => error!(collector = collector.name(), "collector panicked"),
            }
        }
        (collectors, readings)
    });
    let (collectors, readings) = read.await.unwrap_or_default();
    recorded.collectors = collectors;
    readings
}

/// What the server reports about itself, in the shape an agent would. These are the
/// numbers that are cheap to read, so that watching the server adds little to it.
async fn own_numbers(state: &AppState, recorded: &mut Recorded) -> Value {
    let status = state.status.clone();
    let (process, (metrics_bytes, wal_bytes)) =
        tokio::task::spawn_blocking(move || (process_stats(&status), status.metrics_files()))
            .await
            .unwrap_or((None, (None, None)));

    let status = &state.status;
    let written = status.writes.written.load(Ordering::Relaxed);
    let failed = status.writes.failed.load(Ordering::Relaxed);
    let new_written = written - recorded.written;
    let new_failed = failed - recorded.failed;
    let values = status.writes.values.load(Ordering::Relaxed);
    let new_values = values - recorded.values;
    recorded.written = written;
    recorded.failed = failed;
    recorded.values = values;

    let hosts = state.registry.list().await;
    let real = || hosts.iter().filter(|host| !host.is_local());
    let online = |host: &&HostRecord| state.presence.get(&host.id).is_some_and(|p| p.online);
    json!({
        "memory_bytes": process.as_ref().map(|process| process.memory_bytes),
        "cpu_percent": process.as_ref().and_then(|process| process.cpu_percent),
        "open_files": process.as_ref().and_then(|process| process.open_files),
        "samples_written": new_written,
        "samples_failed": new_failed,
        "values_written": new_values,
        "slowest_write_ms": status.writes.slowest_write_ms.swap(0, Ordering::Relaxed),
        "series": state.metrics.series_count().await.ok(),
        "write_queue": state.writer.max_capacity() - state.writer.capacity(),
        "hosts_online": real().filter(online).count(),
        "hosts_approved": real()
            .filter(|host| host.state == HostState::Approved)
            .count(),
        "hosts_waiting": real()
            .filter(|host| host.state == HostState::Pending)
            .count(),
        "alerts_firing": status.firing.load(Ordering::Relaxed),
        "metrics_database_bytes": metrics_bytes,
        "metrics_wal_bytes": wal_bytes,
        "main_database_bytes": state.database.size().await,
    })
}

pub async fn record_once(state: &AppState, recorded: &mut Recorded) {
    let mut metrics = read_host(recorded).await;
    metrics.insert("server".to_string(), own_numbers(state, recorded).await);
    let sample = Sample {
        timestamp_ms: now_ms() as u64,
        metrics,
    };
    let command = WriterCommand::Save(NewSample {
        host_id: LOCAL_HOST_ID.to_string(),
        hostname: LOCAL_HOSTNAME.to_string(),
        sample,
    });
    if state.writer.send(command).await.is_err() {
        warn!("the metrics writer has stopped, so the server's own numbers were dropped");
    }
}

/// Records the server's own numbers the same way an agent's are, so they get history,
/// charts and alert rules like everything else.
pub fn spawn_recorder(state: AppState) {
    tokio::spawn(async move {
        let mut recorded = tokio::task::spawn_blocking(Recorded::with_host)
            .await
            .unwrap_or_default();
        tokio::time::sleep(WARMUP).await;

        let mut every = tokio::time::interval(RECORD_EVERY);
        every.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            record_once(&state, &mut recorded).await;
        }
    });
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessStats {
    pub memory_bytes: u64,
    /// As a share of the whole host. Empty on the first look since a start.
    pub cpu_percent: Option<f64>,
    pub open_files: Option<usize>,
    pub host_memory_total_bytes: u64,
    pub host_memory_used_bytes: u64,
    pub cores: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiskStats {
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Activity {
    pub hosts_online: usize,
    pub hosts_approved: usize,
    pub hosts_waiting: usize,
    pub samples_written: u64,
    pub samples_failed: u64,
    pub samples_queued: usize,
    pub queue_capacity: usize,
    pub alerts_open: usize,
    pub last_alert_pass_ms: Option<i64>,
}

/// Each part is read on its own, because this matters most when something is
/// failing, and one database being down mustn't hide the rest.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerStats {
    pub version: String,
    pub commit: String,
    pub built_at: String,
    pub started_ms: i64,
    pub uptime_secs: u64,
    pub os: Option<String>,
    pub process: Option<ProcessStats>,
    pub disk: Option<DiskStats>,
    pub metrics: Option<StoreStats>,
    pub database: Option<DatabaseStats>,
    pub activity: Activity,
}

fn process_stats(status: &ServerStatus) -> Option<ProcessStats> {
    let mut guard = status.system.lock().unwrap_or_else(PoisonError::into_inner);
    let (system, last_look) = &mut *guard;

    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    let elapsed = last_look.map(|time| time.elapsed());
    // Looking again too soon gives nonsense, so the last figure stands until then.
    let fresh = elapsed.is_none_or(|time| time >= sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    if fresh {
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[status.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        *last_look = Some(Instant::now());
    }

    let process = system.process(status.pid)?;
    let cores = system.cpus().len().max(1);
    Some(ProcessStats {
        memory_bytes: process.memory(),
        cpu_percent: elapsed.map(|_| f64::from(process.cpu_usage()) / cores as f64),
        open_files: process.open_files(),
        host_memory_total_bytes: system.total_memory(),
        host_memory_used_bytes: system.used_memory(),
        cores,
    })
}

/// The disk holding `path`, which is the one with the longest matching mount
/// point. A new database's file may not exist yet, so its folder can stand in.
fn disk_stats(path: &Path) -> Option<DiskStats> {
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty());
    // Windows' canonical paths start \\?\, which no mount point does.
    let full = dunce::canonicalize(path)
        .or_else(|_| dunce::canonicalize(folder.unwrap_or(Path::new("."))))
        .ok()?;
    let disks = Disks::new_with_refreshed_list().ok()?;
    let disk = disks
        .iter()
        .filter(|disk| full.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())?;
    Some(DiskStats {
        mount_point: disk.mount_point().to_string_lossy().into_owned(),
        total_bytes: disk.total_space(),
        available_bytes: disk.available_space(),
    })
}

fn os_name() -> Option<String> {
    System::long_os_version()
        .ok()
        .or_else(|| System::name().ok())
}

pub async fn gather(state: &AppState) -> ServerStats {
    let status = state.status.clone();
    let now = now_ms();
    let build = maxnines_protocol::build_info!();

    let looked = status.clone();
    let (process, disk) = tokio::task::spawn_blocking(move || {
        let disk = looked.data_path.as_deref().and_then(disk_stats);
        (process_stats(&looked), disk)
    })
    .await
    .unwrap_or((None, None));

    let metrics = state.metrics.stats(now - HOUR_MS).await;
    let database = state.database.stats().await;
    for error in [metrics.as_ref().err(), database.as_ref().err()]
        .into_iter()
        .flatten()
    {
        error!(error = format!("{error:#}"), "reading server stats failed");
    }

    let hosts = state.registry.list().await;
    let real = || hosts.iter().filter(|host| !host.is_local());
    let last_pass = status.last_alert_pass_ms.load(Ordering::Relaxed);
    let capacity = state.writer.max_capacity();

    ServerStats {
        version: build.version.to_string(),
        commit: build.commit.to_string(),
        built_at: build.built_at.to_string(),
        started_ms: status.started_ms,
        uptime_secs: u64::try_from(now - status.started_ms).unwrap_or(0) / 1000,
        os: os_name(),
        process,
        disk,
        metrics: metrics.ok(),
        database: database.ok(),
        activity: Activity {
            hosts_online: real()
                .filter(|host| state.presence.get(&host.id).is_some_and(|p| p.online))
                .count(),
            hosts_approved: real()
                .filter(|host| host.state == HostState::Approved)
                .count(),
            hosts_waiting: real()
                .filter(|host| host.state == HostState::Pending)
                .count(),
            samples_written: status.writes.written.load(Ordering::Relaxed),
            samples_failed: status.writes.failed.load(Ordering::Relaxed),
            samples_queued: capacity - state.writer.capacity(),
            queue_capacity: capacity,
            alerts_open: status.firing.load(Ordering::Relaxed),
            last_alert_pass_ms: (last_pass > 0).then_some(last_pass),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_can_read_its_own_memory() {
        let status = ServerStatus::new(None).unwrap();
        let stats = process_stats(&status).unwrap();

        assert!(stats.memory_bytes > 0);
        assert!(stats.host_memory_total_bytes >= stats.host_memory_used_bytes);
        assert_eq!(
            stats.cpu_percent, None,
            "the first look has nothing to compare"
        );

        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        assert!(process_stats(&status).unwrap().cpu_percent.is_some());
    }

    #[test]
    fn the_disk_is_found_for_a_file_that_does_not_exist_yet() {
        let folder = tempfile::tempdir().unwrap();
        let disk = disk_stats(&folder.path().join("new.duckdb")).unwrap();
        assert!(disk.total_bytes >= disk.available_bytes);
        assert!(disk.total_bytes > 0);
    }
}
