use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use sysinfo::{CpuRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System};

use crate::collector::Collector;

/// What the agent itself is using. It's always on, because an agent is meant to stay
/// small, and people need to be able to see that it does.
pub struct OwnUsageCollector {
    system: System,
    pid: Pid,
    cores: usize,
}

impl OwnUsageCollector {
    pub fn new() -> Result<Self> {
        let mut system = System::new()?;
        system.refresh_cpu_list(CpuRefreshKind::nothing());
        let cores = system.cpus().len().max(1);
        let mut collector = Self {
            system,
            pid: sysinfo::get_current_pid().map_err(|error| anyhow!("{error}"))?,
            cores,
        };
        // CPU use is measured between two looks.
        collector.look();
        Ok(collector)
    }

    fn look(&mut self) {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
    }
}

/// What macOS charges to the agent, which is what Activity Monitor shows. The
/// resident size counts every page of the system's libraries the agent has touched,
/// though they're shared with everything else running, and comes out several times
/// larger.
#[cfg(target_os = "macos")]
fn own_memory() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v2>::uninit();
    // Fills in the whole struct, or fails and leaves it alone.
    let filled = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            usage.as_mut_ptr().cast(),
        )
    };
    (filled == 0).then(|| unsafe { usage.assume_init() }.ri_phys_footprint)
}

/// The agent's share of the memory it has in use, where a page shared with other
/// processes counts as its part of it. Kernels older than 4.14 don't say.
#[cfg(target_os = "linux")]
fn own_memory() -> Option<u64> {
    proportional_bytes(&std::fs::read_to_string("/proc/self/smaps_rollup").ok()?)
}

/// Windows and FreeBSD have nothing as cheap to ask, so they report the resident
/// size.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn own_memory() -> Option<u64> {
    None
}

/// The `Pss:` line of `smaps_rollup`, which is in kilobytes.
#[cfg(any(target_os = "linux", test))]
fn proportional_bytes(rollup: &str) -> Option<u64> {
    let line = rollup.lines().find_map(|line| line.strip_prefix("Pss:"))?;
    let kilobytes: u64 = line.trim().strip_suffix("kB")?.trim().parse().ok()?;
    Some(kilobytes * 1024)
}

impl Collector for OwnUsageCollector {
    fn name(&self) -> &'static str {
        "agent"
    }

    fn collect(&mut self) -> Result<Value> {
        self.look();
        let process = self
            .system
            .process(self.pid)
            .ok_or_else(|| anyhow!("can't find the agent's own process"))?;
        // From when the process started rather than when this collector did, so a
        // restart shows however the agent was started. It's what shows an agent
        // that keeps crashing, which looks like no more than a reconnect otherwise.
        let uptime_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| now.as_secs().saturating_sub(process.start_time()));
        Ok(json!({
            "memory_bytes": own_memory().unwrap_or_else(|| process.memory()),
            // As a share of the whole host, as other CPU figures are.
            "cpu_percent": f64::from(process.cpu_usage()) / self.cores as f64,
            "uptime_secs": uptime_secs,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_reports_what_it_uses() {
        let mut collector = OwnUsageCollector::new().unwrap();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);

        let output = collector.collect().unwrap();

        assert!(output["memory_bytes"].as_u64().unwrap() > 0, "{output}");
        let cpu = output["cpu_percent"].as_f64().unwrap();
        assert!((0.0..=100.0).contains(&cpu), "{output}");
        // This test process started moments ago, not when the host did.
        let uptime = output["uptime_secs"].as_u64().unwrap();
        assert!(uptime < 3600, "{output}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn memory_leaves_out_what_is_shared_with_other_processes() {
        let mut system = System::new().unwrap();
        let pid = sysinfo::get_current_pid().unwrap();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );
        let resident = system.process(pid).unwrap().memory();
        assert!(resident > 0);

        let own = own_memory().unwrap();

        assert!(own > 0);
        // macOS also charges for memory it has compressed, which isn't resident.
        if cfg!(target_os = "linux") {
            assert!(
                own <= resident,
                "{own} is more than the {resident} resident"
            );
        }
    }

    #[test]
    fn proportional_memory_is_read_from_the_rollup() {
        let rollup = "55d0a8a00000-7ffe3a5f2000 ---p 00000000 00:00 0    [rollup]
Rss:                5120 kB
Pss:                3121 kB
Pss_Dirty:          2900 kB
Pss_Anon:           2800 kB
";
        assert_eq!(proportional_bytes(rollup), Some(3121 * 1024));
        assert_eq!(proportional_bytes("Rss: 5120 kB\n"), None);
        assert_eq!(proportional_bytes("Pss: lots kB\n"), None);
    }
}
