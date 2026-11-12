//! What can be read about a host from inside it, which needs nothing installed.
//! Agents report these, and so does the server about the host it's on.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};
use sysinfo::{Disk, Disks, InterfaceOperationalState, Networks, System};
use systemstat::Platform;

use crate::Collector;
use crate::disk_activity::DiskActivity;
use crate::file_systems;
use crate::interface_drops::{self, Drops};
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
    activity: DiskActivity,
}

impl DiskCollector {
    pub fn new(mount_points: Option<Vec<String>>) -> Result<Self> {
        Ok(Self {
            disks: Disks::new_with_refreshed_list()?,
            mount_points,
            activity: DiskActivity::new(),
        })
    }

    /// Every real file system, unless some are named, which are reported whatever
    /// they are.
    fn wanted(&self, disk: &Disk) -> bool {
        match &self.mount_points {
            Some(wanted) => wanted.iter().any(|m| Path::new(m) == disk.mount_point()),
            None => file_systems::is_real(disk),
        }
    }
}

impl Collector for DiskCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn collect(&mut self) -> Result<Value> {
        self.disks.refresh(true);

        let wanted: Vec<&Disk> = self.disks.iter().filter(|disk| self.wanted(disk)).collect();
        let disks = match self.mount_points {
            Some(_) => wanted,
            None => file_systems::one_per_space(
                wanted,
                |disk| disk.mount_point(),
                |disk| file_systems::shared_space(disk),
            ),
        };
        let activity = self.activity.measure(&disks);
        let disks: Vec<Value> = disks
            .into_iter()
            .map(|disk| {
                let mount_point = disk.mount_point().to_string_lossy();
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
                if let (Some(measured), Some(fields)) =
                    (activity.get(mount_point.as_ref()), output.as_object_mut())
                {
                    measured.add_to(fields);
                }
                output
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

/// Whether an interface is worth reporting, from its addresses. Two kinds aren't:
///
/// - Loopback, which only ever talks to the host itself.
/// - On macOS, one whose only addresses are link-local, which is what it makes
///   for itself for AirDrop and the like. Elsewhere those are kept, as a network
///   card that only carries VLANs or belongs to a bond often has no other.
///
/// One that's idle, or has nothing plugged in, is reported: it may carry traffic
/// later, and one that's missing looks like one that isn't being watched.
fn is_reported(addresses: &[IpAddr], macos: bool) -> bool {
    if addresses.iter().any(IpAddr::is_loopback) {
        return false;
    }
    let link_local = |address: &IpAddr| match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    };
    !(macos && !addresses.is_empty() && addresses.iter().all(link_local))
}

pub struct NetworkCollector {
    networks: Networks,
    /// Drops at the last sample, as the system keeps running totals.
    drops: HashMap<String, Drops>,
}

impl NetworkCollector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            networks: Networks::new_with_refreshed_list()?,
            drops: interface_drops::totals(),
        })
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect(&mut self) -> Result<Value> {
        self.networks.refresh(true);
        let drops = interface_drops::totals();

        let interfaces: serde_json::Map<String, Value> = self
            .networks
            .iter()
            .filter(|(_, data)| {
                let addresses: Vec<IpAddr> = data
                    .ip_networks()
                    .iter()
                    .map(|network| network.addr)
                    .collect();
                is_reported(&addresses, cfg!(target_os = "macos"))
            })
            .map(|(name, data)| {
                let mut stats = json!({
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
                let name = name.to_string_lossy().into_owned();
                let (before, after) = (self.drops.get(&name), drops.get(&name));
                if let (Some(before), Some(after), Some(fields)) =
                    (before, after, stats.as_object_mut())
                {
                    let received = interface_drops::change(before.received, after.received);
                    let sent = interface_drops::change(before.transmitted, after.transmitted);
                    for (field, value) in [("receive_drops", received), ("transmit_drops", sent)] {
                        if let Some(value) = value {
                            fields.insert(field.into(), json!(value));
                        }
                    }
                }
                (name, stats)
            })
            .collect();
        self.drops = drops;

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

/// Everything here that needs no settings, for reporting on the host as a whole.
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
        // Linux also reports iowait and steal, so every part counts.
        let time = &output["time_percent"];
        let total: f64 = time
            .as_object()
            .unwrap()
            .values()
            .map(|part| part.as_f64().unwrap())
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

    #[cfg(target_os = "macos")]
    #[test]
    fn a_mac_reports_its_start_up_disk_once_as_root() {
        let output = DiskCollector::new(None).unwrap().collect().unwrap();
        let mount_points: Vec<&str> = output
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|disk| disk["mount_point"].as_str())
            .collect();
        assert!(mount_points.contains(&"/"), "{output}");
        assert!(!mount_points.contains(&"/System/Volumes/Data"), "{output}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn disks_say_how_hard_they_are_working_from_the_second_sample() {
        let mut collector = DiskCollector::new(None).unwrap();
        let first = collector.collect().unwrap();
        // Linux and macOS keep running totals, so the first sample has nothing to
        // compare with. Windows' counters take their first look when they're set up.
        if cfg!(not(windows)) {
            assert!(
                first
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|disk| disk["read_ops_per_sec"].is_null())
            );
        }

        std::thread::sleep(Duration::from_millis(200));
        let output = collector.collect().unwrap();

        let disks = output.as_array().unwrap();
        assert!(
            disks.iter().any(|disk| disk["read_ops_per_sec"].is_f64()),
            "{output}"
        );
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
    fn only_interfaces_worth_watching_are_reported() {
        let address = |text: &str| text.parse::<IpAddr>().unwrap();
        let lan = [address("192.168.0.155"), address("fe80::1")];
        let link_local = [address("fe80::1"), address("169.254.3.4")];
        let loopback = [address("127.0.0.1"), address("::1")];
        for macos in [false, true] {
            assert!(is_reported(&lan, macos));
            // A bond's or bridge's member, or a port with nothing plugged in yet,
            // has no address of its own.
            assert!(is_reported(&[], macos));
            assert!(!is_reported(&loopback, macos));
        }
        // What macOS makes for AirDrop, and a card that only carries VLANs.
        assert!(!is_reported(&link_local, true));
        assert!(is_reported(&link_local, false));
    }

    #[test]
    fn interfaces_report_packets_and_errors() {
        let mut collector = NetworkCollector::new().unwrap();
        let output = collector.collect().unwrap();
        let interfaces = output.as_object().unwrap();

        assert!(!interfaces.is_empty());
        assert!(!interfaces.contains_key("lo") && !interfaces.contains_key("lo0"));
        for stats in interfaces.values() {
            assert!(stats["packets_received"].is_u64(), "{stats}");
            assert!(stats["receive_errors"].is_u64(), "{stats}");
        }
    }

    #[test]
    fn everything_on_a_host_can_be_read() {
        for mut collector in all().unwrap() {
            collector.collect().unwrap();
        }
    }
}
