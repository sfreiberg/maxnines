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
        Ok(json!({
            "memory_bytes": process.memory(),
            // As a share of the whole machine, as other CPU figures are.
            "cpu_percent": f64::from(process.cpu_usage()) / self.cores as f64,
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
    }
}
