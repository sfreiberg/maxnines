//! What can be read about a host from inside it, which needs nothing installed.
//! Agents report these, and so does the server about the host it's on.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use maxnines_protocol::entries::Entry;
use maxnines_protocol::totals::{Change, change};
use serde_json::{Value, json};
use sysinfo::{Disk, Disks, InterfaceOperationalState, Networks, System};
use systemstat::Platform;

use crate::Collector;
use crate::disk_activity::DiskActivity;
use crate::entries::{Entries, at, metrics_of, names, percent};
use crate::file_systems;
use crate::interface_drops::{self, Drops};
use crate::system::{self, CpuTime};

pub struct HostCollector;

impl Collector for HostCollector {
    fn name(&self) -> &'static str {
        "host"
    }

    fn collect(&mut self) -> Result<Value> {
        let booted_at = System::boot_time()
            .ok()
            .and_then(|seconds| DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0));
        Ok(json!({
            "uptime_secs": System::uptime().ok(),
            "booted_at": booted_at,
        }))
    }

    fn metrics(&self) -> Vec<String> {
        names(&["host.uptime", "host.booted_at"])
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        entries.read("host.uptime", &["Uptime"], at(output, "uptime_secs"));
        entries.read("host.booted_at", &[], at(output, "booted_at"));
        entries.done()
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

    /// Reads the context switches and interrupts counted since the host started,
    /// giving for each the change since the last call and then the count itself.
    fn count(&mut self) -> [(Option<u64>, Option<u64>); 2] {
        let (context_switches, interrupts) = system::cpu_counters();
        [
            (
                self.context_switches.update(context_switches),
                context_switches,
            ),
            (self.interrupts.update(interrupts), interrupts),
        ]
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
        let [
            (context_switches, context_switches_total),
            (interrupts, interrupts_total),
        ] = self.count();

        Ok(json!({
            "context_switches_total": context_switches_total,
            "interrupts_total": interrupts_total,
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

    fn metrics(&self) -> Vec<String> {
        names(&[
            "cpu.usage",
            "cpu.cores",
            "cpu.load",
            "cpu.time",
            "cpu.context_switches",
            "cpu.interrupts",
        ])
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        entries.read("cpu.usage", &["CPU"], at(output, "usage_percent"));
        match at(output, "per_core_percent").as_array() {
            Some(cores) if !cores.is_empty() => {
                for (index, core) in cores.iter().enumerate() {
                    entries.read("cpu.cores", &[&index.to_string()], core);
                }
            }
            _ => entries.nothing("cpu.cores", &[]),
        }
        // Windows has no load average.
        for (series, field) in [
            ("1 minute", "load_average.one"),
            ("5 minutes", "load_average.five"),
            ("15 minutes", "load_average.fifteen"),
        ] {
            entries.read("cpu.load", &[series], at(output, field));
        }
        for (series, field) in CPU_TIMES {
            entries.read("cpu.time", &[series], at(output, field));
        }
        // Running totals since the host started.
        entries.read(
            "cpu.context_switches",
            &["Switches"],
            at(output, "context_switches_total"),
        );
        entries.read(
            "cpu.interrupts",
            &["Interrupts"],
            at(output, "interrupts_total"),
        );
        entries.done()
    }
}

/// The kinds of processor time, as a series is called and as it's read.
const CPU_TIMES: [(&str, &str); 7] = [
    ("User", "time_percent.user"),
    ("System", "time_percent.system"),
    ("Nice", "time_percent.nice"),
    ("Interrupt", "time_percent.interrupt"),
    ("I/O wait", "time_percent.iowait"),
    ("Steal", "time_percent.steal"),
    ("Idle", "time_percent.idle"),
];

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

    /// Reads the pages swapped in and out since the host started, giving for each
    /// the change since the last call and then the count itself.
    fn count(&mut self) -> [(Option<u64>, Option<u64>); 2] {
        let (swap_in, swap_out) = system::swap_counters();
        [
            (self.swap_in.update(swap_in), swap_in),
            (self.swap_out.update(swap_out), swap_out),
        ]
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn collect(&mut self) -> Result<Value> {
        self.system.refresh_memory();
        let [(swap_in, swap_in_total), (swap_out, swap_out_total)] = self.count();
        Ok(json!({
            "swap_in_pages_total": swap_in_total,
            "swap_out_pages_total": swap_out_total,
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

    fn metrics(&self) -> Vec<String> {
        names(&[
            "memory.usage",
            "memory.total",
            "memory.used",
            "memory.available",
            "memory.swap_total",
            "memory.swap_used",
            "memory.detail",
            "memory.swap_activity",
        ])
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let memory = percent(at(output, "used_bytes"), at(output, "total_bytes"));
        entries.number("memory.usage", &["Memory"], memory);
        // A host with no swap has no share of it in use.
        let swap = percent(
            at(output, "swap_used_bytes"),
            at(output, "swap_total_bytes"),
        );
        entries.number("memory.usage", &["Swap"], swap);
        for (metric, field) in [
            ("memory.total", "total_bytes"),
            ("memory.used", "used_bytes"),
            ("memory.available", "available_bytes"),
            ("memory.swap_total", "swap_total_bytes"),
            ("memory.swap_used", "swap_used_bytes"),
        ] {
            entries.read(metric, &[], at(output, field));
        }
        // Each system has its own kinds, so the others have nothing.
        for (series, field) in MEMORY_KINDS {
            entries.read("memory.detail", &[series], at(output, field));
        }
        // Running totals since the host started.
        entries.read(
            "memory.swap_activity",
            &["Pages in"],
            at(output, "swap_in_pages_total"),
        );
        entries.read(
            "memory.swap_activity",
            &["Pages out"],
            at(output, "swap_out_pages_total"),
        );
        entries.done()
    }
}

/// The kinds of memory use, as a series is called and as it's read.
const MEMORY_KINDS: [(&str, &str); 13] = [
    ("Active", "detail.active_bytes"),
    ("Inactive", "detail.inactive_bytes"),
    ("Wired", "detail.wired_bytes"),
    ("Cached", "detail.cached_bytes"),
    ("Buffers", "detail.buffers_bytes"),
    ("Slab", "detail.slab_bytes"),
    ("Shared", "detail.shared_bytes"),
    ("Compressed", "detail.compressed_bytes"),
    ("Speculative", "detail.speculative_bytes"),
    ("Purgeable", "detail.purgeable_bytes"),
    ("ZFS cache", "detail.zfs_arc_bytes"),
    ("Page file", "detail.page_file_bytes"),
    ("Free", "detail.free_bytes"),
];

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
                    "read_bytes_total": usage.total_read_bytes,
                    "written_bytes_total": usage.total_written_bytes,
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

    fn metrics(&self) -> Vec<String> {
        names(&DISK_METRICS)
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let disks = output.as_array().map(Vec::as_slice).unwrap_or_default();
        let named = disks
            .iter()
            .filter_map(|disk| Some((disk.get("mount_point")?.as_str()?, disk)));
        for (mount_point, disk) in named {
            let series = [mount_point];
            let used = percent(at(disk, "used_bytes"), at(disk, "total_bytes"));
            entries.number("disk.usage", &series, used);
            let inodes = percent(at(disk, "inodes_used"), at(disk, "inodes_total"));
            entries.number("disk.inodes", &series, inodes);
            for (metric, field) in DISK_FIELDS {
                entries.read(metric, &series, at(disk, field));
            }
        }
        entries.fill(&DISK_METRICS);
        entries.done()
    }
}

/// A disk's metrics that are read as they are, and what each is read from. What's
/// read and written are running totals since the disk appeared.
const DISK_FIELDS: [(&str, &str); 16] = [
    ("disk.total", "total_bytes"),
    ("disk.used", "used_bytes"),
    ("disk.available", "available_bytes"),
    ("disk.read", "read_bytes_total"),
    ("disk.written", "written_bytes_total"),
    ("disk.busy", "busy_percent"),
    ("disk.read_ops", "read_ops_per_sec"),
    ("disk.write_ops", "write_ops_per_sec"),
    ("disk.read_latency", "read_latency_secs"),
    ("disk.write_latency", "write_latency_secs"),
    ("disk.queue", "queue_length"),
    ("disk.device", "name"),
    ("disk.file_system", "file_system"),
    ("disk.kind", "kind"),
    ("disk.removable", "removable"),
    ("disk.read_only", "read_only"),
];

/// Every metric a disk has: those worked out, then those read as they are.
const DISK_METRICS: [&str; 18] = metrics_of(&["disk.usage", "disk.inodes"], &DISK_FIELDS);

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
                    "total_packets_received": data.total_packets_received(),
                    "total_packets_transmitted": data.total_packets_transmitted(),
                    "link_up": link_up(data.operational_state()),
                });
                let name = name.to_string_lossy().into_owned();
                let (before, after) = (self.drops.get(&name), drops.get(&name));
                if let (Some(after), Some(fields)) = (after, stats.as_object_mut()) {
                    let totals = [
                        ("total_receive_drops", after.received),
                        ("total_transmit_drops", after.transmitted),
                    ];
                    for (field, total) in totals {
                        if let Some(total) = total {
                            fields.insert(field.into(), json!(total));
                        }
                    }
                }
                if let (Some(before), Some(after), Some(fields)) =
                    (before, after, stats.as_object_mut())
                {
                    let received = before.received.zip(after.received);
                    let received = received.map(|(last, total)| change(last, total));
                    let sent = before.transmitted.zip(after.transmitted);
                    let sent = sent.map(|(last, total)| change(last, total));
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

    fn metrics(&self) -> Vec<String> {
        names(&NETWORK_METRICS)
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        for (name, interface) in output.as_object().into_iter().flatten() {
            for (metric, field) in NETWORK_FIELDS {
                entries.read(metric, &[name], at(interface, field));
            }
        }
        entries.fill(&NETWORK_METRICS);
        entries.done()
    }
}

/// An interface's metrics, and what each is read from: running totals since the
/// interface appeared, and whether its link is up, where the system says.
const NETWORK_FIELDS: [(&str, &str); 9] = [
    ("network.received", "total_received_bytes"),
    ("network.transmitted", "total_transmitted_bytes"),
    ("network.packets.received", "total_packets_received"),
    ("network.packets.transmitted", "total_packets_transmitted"),
    ("network.errors.received", "total_receive_errors"),
    ("network.errors.transmitted", "total_transmit_errors"),
    ("network.drops.received", "total_receive_drops"),
    ("network.drops.transmitted", "total_transmit_drops"),
    ("network.link", "link_up"),
];

const NETWORK_METRICS: [&str; 9] = metrics_of(&[], &NETWORK_FIELDS);

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
    use crate::entries::testing::{every_metric_has_an_entry, said, time};

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
        // Windows has no figure for truly free memory, only for its page files.
        let reported = if cfg!(windows) {
            "page_file_bytes"
        } else {
            "free_bytes"
        };
        assert!(output["detail"][reported].as_u64().is_some(), "{output}");
    }

    #[test]
    fn cpu_entries_are_its_metrics_with_a_series_for_each_part() {
        let output = json!({
            "usage_percent": 12.5,
            "per_core_percent": [10.0, 15.0],
            "time_percent": { "user": 8.0, "system": 4.5, "idle": 87.5 },
            "context_switches": 40, "context_switches_total": 9000,
            "interrupts": 7, "interrupts_total": 800,
            "load_average": { "one": 1.5, "five": 1.0, "fifteen": 0.5 },
        });
        let collector = CpuCollector::new().unwrap();
        let entries = collector.entries(&output, time());
        assert_eq!(
            said(&entries),
            [
                ("cpu.usage[CPU]".to_string(), json!(12.5)),
                ("cpu.cores[0]".to_string(), json!(10.0)),
                ("cpu.cores[1]".to_string(), json!(15.0)),
                ("cpu.load[1 minute]".to_string(), json!(1.5)),
                ("cpu.load[5 minutes]".to_string(), json!(1.0)),
                ("cpu.load[15 minutes]".to_string(), json!(0.5)),
                ("cpu.time[User]".to_string(), json!(8.0)),
                ("cpu.time[System]".to_string(), json!(4.5)),
                // The kinds this system doesn't tell apart have nothing.
                ("cpu.time[Nice]".to_string(), Value::Null),
                ("cpu.time[Interrupt]".to_string(), Value::Null),
                ("cpu.time[I/O wait]".to_string(), Value::Null),
                ("cpu.time[Steal]".to_string(), Value::Null),
                ("cpu.time[Idle]".to_string(), json!(87.5)),
                // The running totals, not the change since the last sample.
                ("cpu.context_switches[Switches]".to_string(), json!(9000)),
                ("cpu.interrupts[Interrupts]".to_string(), json!(800)),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // Windows has no load average, and a first sample no times.
        let bare = collector.entries(&json!({ "usage_percent": 3.0 }), time());
        let bare = said(&bare);
        assert!(bare.contains(&("cpu.cores".to_string(), Value::Null)));
        assert!(bare.contains(&("cpu.load[1 minute]".to_string(), Value::Null)));
        assert!(bare.contains(&("cpu.interrupts[Interrupts]".to_string(), Value::Null)));
    }

    #[test]
    fn memory_entries_work_out_how_much_is_used() {
        let output = json!({
            "total_bytes": 1000, "used_bytes": 250, "available_bytes": 700,
            "swap_total_bytes": 0, "swap_used_bytes": 0,
            "detail": { "active_bytes": 100, "free_bytes": 600 },
            "swap_in_pages": 1, "swap_in_pages_total": 50,
            "swap_out_pages": 2, "swap_out_pages_total": 60,
        });
        let collector = MemoryCollector::new().unwrap();
        let entries = collector.entries(&output, time());
        let said = said(&entries);
        assert_eq!(said[0], ("memory.usage[Memory]".to_string(), json!(25.0)));
        // With no swap there's no share of it in use.
        assert_eq!(said[1], ("memory.usage[Swap]".to_string(), Value::Null));
        for (name, value) in [
            ("memory.total", json!(1000)),
            ("memory.used", json!(250)),
            ("memory.available", json!(700)),
            ("memory.swap_total", json!(0)),
            ("memory.detail[Active]", json!(100)),
            ("memory.detail[Free]", json!(600)),
            ("memory.detail[Wired]", Value::Null),
            ("memory.swap_activity[Pages in]", json!(50)),
            ("memory.swap_activity[Pages out]", json!(60)),
        ] {
            assert!(
                said.contains(&(name.to_string(), value.clone())),
                "{name}: {said:?}"
            );
        }
        every_metric_has_an_entry(&collector, &entries);
    }

    #[test]
    fn what_disks_interfaces_and_the_host_really_say_becomes_entries_for_their_metrics() {
        let mut disk = DiskCollector::new(None).unwrap();
        let output = disk.collect().unwrap();
        every_metric_has_an_entry(&disk, &disk.entries(&output, time()));
        let mut network = NetworkCollector::new().unwrap();
        let output = network.collect().unwrap();
        every_metric_has_an_entry(&network, &network.entries(&output, time()));
        let mut host = HostCollector;
        let output = host.collect().unwrap();
        let entries = host.entries(&output, time());
        every_metric_has_an_entry(&host, &entries);
        assert!(said(&entries)[0].1.is_number());
    }

    #[test]
    fn disk_entries_have_a_series_for_each_mount_point() {
        let output = json!([
            { "name": "/dev/sda1", "mount_point": "/", "file_system": "ext4", "kind": "SSD",
              "total_bytes": 1000, "available_bytes": 400, "used_bytes": 600,
              "removable": false, "read_only": false,
              "read_bytes": 5, "written_bytes": 6,
              "read_bytes_total": 5000, "written_bytes_total": 6000,
              "inodes_total": 200, "inodes_used": 50,
              "read_ops_per_sec": 1.5, "busy_percent": 12.0 },
            { "name": "C:", "mount_point": "C:\\", "file_system": "NTFS", "kind": "HDD",
              "total_bytes": 0, "available_bytes": 0, "used_bytes": 0,
              "removable": true, "read_only": true },
        ]);
        let collector = DiskCollector::new(None).unwrap();
        let entries = collector.entries(&output, time());
        let said = said(&entries);
        for (name, value) in [
            ("disk.usage[/]", json!(60.0)),
            ("disk.inodes[/]", json!(25.0)),
            ("disk.total[/]", json!(1000)),
            ("disk.used[/]", json!(600)),
            ("disk.available[/]", json!(400)),
            // The running totals, not the change since the last sample.
            ("disk.read[/]", json!(5000)),
            ("disk.written[/]", json!(6000)),
            ("disk.read_ops[/]", json!(1.5)),
            ("disk.busy[/]", json!(12.0)),
            // Not measured on this system, or on a first sample.
            ("disk.queue[/]", Value::Null),
            ("disk.write_latency[/]", Value::Null),
            ("disk.device[/]", json!("/dev/sda1")),
            ("disk.file_system[/]", json!("ext4")),
            ("disk.kind[/]", json!("SSD")),
            ("disk.removable[/]", json!(false)),
            ("disk.read_only[/]", json!(false)),
            // A disk of no size has no share in use, and Windows has no inodes.
            ("disk.usage[C:\\]", Value::Null),
            ("disk.inodes[C:\\]", Value::Null),
            ("disk.read_only[C:\\]", json!(true)),
        ] {
            assert!(
                said.contains(&(name.to_string(), value.clone())),
                "{name}: {said:?}"
            );
        }
        assert_eq!(said.len(), 2 * 18);
        every_metric_has_an_entry(&collector, &entries);

        // With no disks, each metric says it has nothing.
        let none = collector.entries(&json!([]), time());
        assert_eq!(none.len(), 18);
        assert!(none.iter().all(|entry| entry.series.is_empty()));
        every_metric_has_an_entry(&collector, &none);
    }

    #[test]
    fn network_entries_have_a_series_for_each_interface() {
        let output = json!({
            "en0": {
                "received_bytes": 1, "transmitted_bytes": 2,
                "total_received_bytes": 1000, "total_transmitted_bytes": 2000,
                "total_packets_received": 30, "total_packets_transmitted": 40,
                "total_receive_errors": 1, "total_transmit_errors": 0,
                "total_receive_drops": 7, "link_up": 1,
            },
            "en1": { "total_received_bytes": 5 },
        });
        let collector = NetworkCollector::new().unwrap();
        let entries = collector.entries(&output, time());
        let said = said(&entries);
        for (name, value) in [
            ("network.received[en0]", json!(1000)),
            ("network.transmitted[en0]", json!(2000)),
            ("network.packets.received[en0]", json!(30)),
            ("network.packets.transmitted[en0]", json!(40)),
            ("network.errors.received[en0]", json!(1)),
            ("network.errors.transmitted[en0]", json!(0)),
            ("network.drops.received[en0]", json!(7)),
            // Not every system counts both.
            ("network.drops.transmitted[en0]", Value::Null),
            ("network.link[en0]", json!(1)),
            ("network.received[en1]", json!(5)),
            ("network.link[en1]", Value::Null),
        ] {
            assert!(
                said.contains(&(name.to_string(), value.clone())),
                "{name}: {said:?}"
            );
        }
        assert_eq!(said.len(), 2 * 9);
        every_metric_has_an_entry(&collector, &entries);

        let none = collector.entries(&json!({}), time());
        assert_eq!(none.len(), 9);
        every_metric_has_an_entry(&collector, &none);
    }

    #[test]
    fn host_entries_are_how_long_it_has_been_up_and_since_when() {
        let collector = HostCollector;
        let output = json!({ "uptime_secs": 3600, "booted_at": "2026-11-28T08:00:00Z" });
        let entries = collector.entries(&output, time());
        assert_eq!(
            said(&entries),
            [
                ("host.uptime[Uptime]".to_string(), json!(3600)),
                ("host.booted_at".to_string(), json!("2026-11-28T08:00:00Z")),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);
    }

    /// What a real collection says is entries for exactly the collector's metrics.
    #[test]
    fn what_cpu_and_memory_really_collect_becomes_entries_for_their_metrics() {
        let mut cpu = CpuCollector::new().unwrap();
        let output = cpu.collect().unwrap();
        let entries = cpu.entries(&output, time());
        every_metric_has_an_entry(&cpu, &entries);
        assert!(
            said(&entries)
                .iter()
                .any(|(name, value)| name == "cpu.usage[CPU]" && value.is_number())
        );

        let mut memory = MemoryCollector::new().unwrap();
        let output = memory.collect().unwrap();
        let entries = memory.entries(&output, time());
        every_metric_has_an_entry(&memory, &entries);
        let said = said(&entries);
        assert!(
            said.iter()
                .any(|(name, value)| name == "memory.usage[Memory]" && value.is_number())
        );
        assert!(
            said.iter()
                .any(|(name, value)| name == "memory.total" && value.as_u64() > Some(0))
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
