//! What can be read about a machine from inside it, which needs nothing installed.
//! Agents report these, and so does the server about the machine it's on.

use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};
use sysinfo::{Disks, InterfaceOperationalState, Networks, System};
use systemstat::Platform;

use crate::Collector;
use crate::system::{self, Change, CpuTime};

pub struct HostCollector;

impl Collector for HostCollector {
    fn name(&self) -> &'static str {
        "host"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(json!({
            "uptime_secs": System::uptime().ok(),
            "boot_time_secs": System::boot_time().ok(),
        }))
    }
}

pub struct CpuCollector {
    system: System,
    time: CpuTime,
    context_switches: Change,
    interrupts: Change,
}

impl CpuCollector {
    pub fn new() -> Result<Self> {
        let mut system = System::new()?;
        system.refresh_cpu_usage();
        let mut collector = Self {
            system,
            time: CpuTime::new(),
            context_switches: Change::default(),
            interrupts: Change::default(),
        };
        collector.count();
        Ok(collector)
    }

    /// Gives the changes since the last call, in the same order as the fields.
    fn count(&mut self) -> (Option<u64>, Option<u64>) {
        let counters = system::counters();
        (
            self.context_switches.update(counters.context_switches),
            self.interrupts.update(counters.interrupts),
        )
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn collect(&mut self) -> Result<Value> {
        self.system.refresh_cpu_usage();
        let per_core: Vec<f32> = self.system.cpus().iter().map(|c| c.usage()).collect();
        let load = System::load_average().ok();
        let (context_switches, interrupts) = self.count();

        Ok(json!({
            "usage_percent": self.system.global_cpu_usage(),
            "per_core_percent": per_core,
            "time_percent": self.time.measure(),
            "context_switches": context_switches,
            "interrupts": interrupts,
            "load_average": load.map(|l| json!({
                "one": l.one,
                "five": l.five,
                "fifteen": l.fifteen,
            })),
        }))
    }
}

pub struct MemoryCollector {
    system: System,
    stats: systemstat::System,
    swap_in: Change,
    swap_out: Change,
}

impl MemoryCollector {
    pub fn new() -> Result<Self> {
        let mut collector = Self {
            system: System::new()?,
            stats: systemstat::System::new(),
            swap_in: Change::default(),
            swap_out: Change::default(),
        };
        collector.count();
        Ok(collector)
    }

    /// Gives the changes since the last call, as pages swapped in and out.
    fn count(&mut self) -> (Option<u64>, Option<u64>) {
        let counters = system::counters();
        (
            self.swap_in.update(counters.swap_in_pages),
            self.swap_out.update(counters.swap_out_pages),
        )
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn collect(&mut self) -> Result<Value> {
        self.system.refresh_memory();
        let (swap_in, swap_out) = self.count();
        Ok(json!({
            "detail": system::memory_detail(&self.stats),
            "swap_in_pages": swap_in,
            "swap_out_pages": swap_out,
            "total_bytes": self.system.total_memory(),
            "used_bytes": self.system.used_memory(),
            "available_bytes": self.system.available_memory(),
            "swap_total_bytes": self.system.total_swap(),
            "swap_used_bytes": self.system.used_swap(),
        }))
    }
}

pub struct DiskCollector {
    disks: Disks,
    mount_points: Option<Vec<String>>,
}

impl DiskCollector {
    pub fn new(mount_points: Option<Vec<String>>) -> Result<Self> {
        Ok(Self {
            disks: Disks::new_with_refreshed_list()?,
            mount_points,
        })
    }

    fn wanted(&self, mount_point: &str) -> bool {
        self.mount_points
            .as_ref()
            .is_none_or(|wanted| wanted.iter().any(|m| m == mount_point))
    }
}

impl Collector for DiskCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn collect(&mut self) -> Result<Value> {
        self.disks.refresh(true);

        let disks: Vec<Value> = self
            .disks
            .iter()
            .filter_map(|disk| {
                let mount_point = disk.mount_point().to_string_lossy();
                self.wanted(&mount_point).then(|| {
                    let total = disk.total_space();
                    let available = disk.available_space();
                    let usage = disk.usage();
                    let mut output = json!({
                        "name": disk.name().to_string_lossy(),
                        "mount_point": mount_point,
                        "file_system": disk.file_system().to_string_lossy(),
                        "total_bytes": total,
                        "available_bytes": available,
                        "used_bytes": total.saturating_sub(available),
                        "removable": disk.is_removable(),
                        "read_only": disk.is_read_only(),
                        "kind": disk.kind().to_string(),
                        "read_bytes": usage.read_bytes,
                        "written_bytes": usage.written_bytes,
                    });
                    if let Some((total, free)) = inodes(disk.mount_point()) {
                        output["inodes_total"] = json!(total);
                        output["inodes_used"] = json!(total.saturating_sub(free));
                    }
                    output
                })
            })
            .collect();

        Ok(Value::Array(disks))
    }
}

/// Total and free inodes. A disk can run out of these with plenty of space left.
/// Windows file systems don't have them, and some Unix ones report none.
#[cfg(unix)]
fn inodes(mount_point: &Path) -> Option<(u64, u64)> {
    let stats = rustix::fs::statvfs(mount_point).ok()?;
    (stats.f_files > 0).then_some((stats.f_files, stats.f_ffree))
}

#[cfg(not(unix))]
fn inodes(_mount_point: &Path) -> Option<(u64, u64)> {
    None
}

pub struct NetworkCollector {
    networks: Networks,
}

impl NetworkCollector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            networks: Networks::new_with_refreshed_list()?,
        })
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect(&mut self) -> Result<Value> {
        self.networks.refresh(true);

        let interfaces: serde_json::Map<String, Value> = self
            .networks
            .iter()
            .map(|(name, data)| {
                let stats = json!({
                    "received_bytes": data.received(),
                    "transmitted_bytes": data.transmitted(),
                    "packets_received": data.packets_received(),
                    "packets_transmitted": data.packets_transmitted(),
                    "receive_errors": data.errors_on_received(),
                    "transmit_errors": data.errors_on_transmitted(),
                    "total_received_bytes": data.total_received(),
                    "total_transmitted_bytes": data.total_transmitted(),
                    "total_receive_errors": data.total_errors_on_received(),
                    "total_transmit_errors": data.total_errors_on_transmitted(),
                    "link_up": link_up(data.operational_state()),
                });
                (name.to_string_lossy().into_owned(), stats)
            })
            .collect();

        Ok(Value::Object(interfaces))
    }
}

/// 1 or 0 where the system says, and nothing where it doesn't, so that an
/// interface with no known state can't set off an alert.
fn link_up(state: InterfaceOperationalState) -> Option<u8> {
    match state {
        InterfaceOperationalState::Up => Some(1),
        InterfaceOperationalState::Down | InterfaceOperationalState::LowerLayerDown => Some(0),
        _ => None,
    }
}

/// Everything here that needs no settings, for reporting on the machine as a whole.
pub fn all() -> Result<Vec<Box<dyn Collector + Send>>> {
    Ok(vec![
        Box::new(HostCollector),
        Box::new(CpuCollector::new()?),
        Box::new(MemoryCollector::new()?),
        Box::new(DiskCollector::new(None)?),
        Box::new(NetworkCollector::new()?),
    ])
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn cpu_time_adds_up_to_the_whole_of_the_time_measured() {
        let mut collector = CpuCollector::new().unwrap();
        std::thread::sleep(Duration::from_millis(250));
        let output = collector.collect().unwrap();
        let time = &output["time_percent"];
        let total: f64 = ["user", "nice", "system", "interrupt", "idle"]
            .iter()
            .map(|name| time[name].as_f64().unwrap())
            .sum();
        assert!((99.0..=101.0).contains(&total), "{time}");
    }

    #[test]
    fn each_sample_measures_cpu_time_from_the_one_before() {
        let mut time = CpuTime::new();
        std::thread::sleep(Duration::from_millis(50));
        assert!(time.measure().is_some());
        std::thread::sleep(Duration::from_millis(50));
        assert!(time.measure().is_some());
    }

    #[test]
    fn memory_reports_what_it_is_used_for() {
        let output = MemoryCollector::new().unwrap().collect().unwrap();
        assert!(
            output["detail"]["free_bytes"].as_u64().is_some(),
            "{output}"
        );
    }

    #[test]
    fn link_state_is_only_reported_when_known() {
        assert_eq!(link_up(InterfaceOperationalState::Up), Some(1));
        assert_eq!(link_up(InterfaceOperationalState::Down), Some(0));
        assert_eq!(link_up(InterfaceOperationalState::Unknown), None);
    }

    #[test]
    fn disks_report_their_activity_and_inodes() {
        let mut collector = DiskCollector::new(None).unwrap();
        let output = collector.collect().unwrap();
        let disks = output.as_array().unwrap();

        assert!(!disks.is_empty());
        assert!(disks.iter().all(|disk| disk["read_bytes"].is_u64()));
        if cfg!(unix) {
            assert!(
                disks.iter().any(|disk| disk["inodes_total"].is_u64()),
                "{output}"
            );
        }
    }

    #[test]
    fn interfaces_report_packets_and_errors() {
        let mut collector = NetworkCollector::new().unwrap();
        let output = collector.collect().unwrap();
        let interfaces = output.as_object().unwrap();

        assert!(!interfaces.is_empty());
        for stats in interfaces.values() {
            assert!(stats["packets_received"].is_u64(), "{stats}");
            assert!(stats["receive_errors"].is_u64(), "{stats}");
        }
    }

    #[test]
    fn everything_on_a_machine_can_be_read() {
        for mut collector in all().unwrap() {
            collector.collect().unwrap();
        }
    }
}
