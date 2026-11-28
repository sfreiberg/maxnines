use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use maxnines_collectors::entries::{Entries, at, names};
use maxnines_protocol::entries::Entry;
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

/// The agent's private working set, which is what Task Manager shows: the pages it
/// has in memory that no other process can use. The resident size, which counts the
/// system's libraries too, comes out around three times larger.
#[cfg(windows)]
fn own_memory() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX2,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
    let mut counters = PROCESS_MEMORY_COUNTERS_EX2 {
        cb: size,
        ..Default::default()
    };
    // SAFETY: the struct is as big as it's said to be, and the process's own handle
    // needs no closing.
    let filled = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            std::ptr::from_mut(&mut counters).cast(),
            size,
        )
    };
    (filled != 0).then_some(counters.PrivateWorkingSetSize as u64)
}

/// FreeBSD has nothing as cheap to ask, so it reports the resident size.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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
        let started = i64::try_from(process.start_time())
            .ok()
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0));
        let uptime_secs = started.map_or(0, |started| {
            (maxnines_protocol::time::now() - started)
                .num_seconds()
                .max(0)
        });
        Ok(json!({
            "memory_bytes": own_memory().unwrap_or_else(|| process.memory()),
            // As a share of the whole host, as other CPU figures are.
            "cpu_percent": f64::from(process.cpu_usage()) / self.cores as f64,
            "uptime_secs": uptime_secs,
        }))
    }

    fn metrics(&self) -> Vec<String> {
        names(&OWN_METRICS)
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        entries.read("agent.memory", &["Memory"], at(output, "memory_bytes"));
        entries.read("agent.cpu", &["CPU"], at(output, "cpu_percent"));
        entries.read("agent.uptime", &["Uptime"], at(output, "uptime_secs"));
        entries.done()
    }
}

const OWN_METRICS: [&str; 3] = ["agent.memory", "agent.cpu", "agent.uptime"];

#[cfg(test)]
mod tests {
    use maxnines_collectors::entries::testing::{every_metric_has_an_entry, said, time};

    use super::*;

    #[test]
    fn the_agents_entries_are_what_it_uses_and_how_long_it_has_run() {
        let collector = OwnUsageCollector::new().unwrap();
        let output = json!({ "memory_bytes": 9_000_000, "cpu_percent": 0.5, "uptime_secs": 120 });
        let entries = collector.entries(&output, time());
        assert_eq!(
            said(&entries),
            [
                ("agent.memory[Memory]".to_string(), json!(9_000_000)),
                ("agent.cpu[CPU]".to_string(), json!(0.5)),
                ("agent.uptime[Uptime]".to_string(), json!(120)),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // Anything it couldn't say has nothing.
        let bare = collector.entries(&json!({ "uptime_secs": 5 }), time());
        assert_eq!(
            said(&bare),
            [
                ("agent.memory[Memory]".to_string(), Value::Null),
                ("agent.cpu[CPU]".to_string(), Value::Null),
                ("agent.uptime[Uptime]".to_string(), json!(5)),
            ]
        );
        every_metric_has_an_entry(&collector, &bare);
    }

    /// What a real collection says is entries for exactly the collector's metrics.
    #[test]
    fn what_the_agent_really_uses_becomes_entries_for_its_metrics() {
        let mut collector = OwnUsageCollector::new().unwrap();
        let output = collector.collect().unwrap();
        let entries = collector.entries(&output, time());
        every_metric_has_an_entry(&collector, &entries);
        assert!(said(&entries).iter().all(|(_, value)| value.is_number()));
    }

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

    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
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
        if cfg!(any(target_os = "linux", windows)) {
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
