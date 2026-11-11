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
            "memory_bytes": process.memory(),
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
}
