//! How the server itself is doing: what the Server page and admin API report.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::Serialize;
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System,
};
use tracing::error;

use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::models::DatabaseStats;
use crate::registration::AgentState;
use crate::store::{StoreStats, WriteCounts};

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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessStats {
    pub memory_bytes: u64,
    /// As a share of the whole machine. Empty on the first look since a start.
    pub cpu_percent: Option<f64>,
    pub open_files: Option<usize>,
    pub machine_memory_total_bytes: u64,
    pub machine_memory_used_bytes: u64,
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
    pub agents_online: usize,
    pub agents_approved: usize,
    pub agents_waiting: usize,
    pub samples_written: u64,
    pub samples_failed: u64,
    pub samples_queued: usize,
    pub queue_capacity: usize,
    pub alerts_firing: usize,
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
        machine_memory_total_bytes: system.total_memory(),
        machine_memory_used_bytes: system.used_memory(),
        cores,
    })
}

/// The disk holding `path`, which is the one with the longest matching mount
/// point. A new database's file may not exist yet, so its folder can stand in.
fn disk_stats(path: &Path) -> Option<DiskStats> {
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty());
    let full = path
        .canonicalize()
        .or_else(|_| folder.unwrap_or(Path::new(".")).canonicalize())
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

    let agents = state.registry.list().await;
    let real = || agents.iter().filter(|agent| !agent.is_local());
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
            agents_online: real()
                .filter(|agent| state.presence.get(&agent.id).is_some_and(|p| p.online))
                .count(),
            agents_approved: real()
                .filter(|agent| agent.state == AgentState::Approved)
                .count(),
            agents_waiting: real()
                .filter(|agent| agent.state == AgentState::Pending)
                .count(),
            samples_written: status.writes.written.load(Ordering::Relaxed),
            samples_failed: status.writes.failed.load(Ordering::Relaxed),
            samples_queued: capacity - state.writer.capacity(),
            queue_capacity: capacity,
            alerts_firing: status.firing.load(Ordering::Relaxed),
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
        assert!(stats.machine_memory_total_bytes >= stats.machine_memory_used_bytes);
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
