use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use sysinfo::{Disks, Networks, System};

use crate::config::CollectorConfig;

/// How long to wait after building collectors before the first sample.
/// CPU usage is measured between two refreshes, so it needs this gap.
pub const WARMUP: Duration = sysinfo::MINIMUM_CPU_UPDATE_INTERVAL;

/// A source of metrics. Implementations keep state between calls because
/// CPU usage and network deltas are measured against the previous sample.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> Result<Value>;
}

/// The name samples are reported under.
pub fn host_name() -> String {
    System::host_name().unwrap_or_else(|_| "unknown".to_string())
}

pub fn build(name: &str, config: &CollectorConfig) -> Result<Box<dyn Collector>> {
    Ok(match name {
        "host" => Box::new(HostCollector),
        "cpu" => Box::new(CpuCollector::new()?),
        "memory" => Box::new(MemoryCollector::new()?),
        "disk" => Box::new(DiskCollector::new(config.mount_points.clone())?),
        "network" => Box::new(NetworkCollector::new()?),
        other => bail!("unknown collector {other:?}"),
    })
}

struct HostCollector;

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

struct CpuCollector {
    system: System,
}

impl CpuCollector {
    fn new() -> Result<Self> {
        let mut system = System::new()?;
        system.refresh_cpu_usage();
        Ok(Self { system })
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

        Ok(json!({
            "usage_percent": self.system.global_cpu_usage(),
            "per_core_percent": per_core,
            "load_average": load.map(|l| json!({
                "one": l.one,
                "five": l.five,
                "fifteen": l.fifteen,
            })),
        }))
    }
}

struct MemoryCollector {
    system: System,
}

impl MemoryCollector {
    fn new() -> Result<Self> {
        Ok(Self {
            system: System::new()?,
        })
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn collect(&mut self) -> Result<Value> {
        self.system.refresh_memory();
        Ok(json!({
            "total_bytes": self.system.total_memory(),
            "used_bytes": self.system.used_memory(),
            "available_bytes": self.system.available_memory(),
            "swap_total_bytes": self.system.total_swap(),
            "swap_used_bytes": self.system.used_swap(),
        }))
    }
}

struct DiskCollector {
    disks: Disks,
    mount_points: Option<Vec<String>>,
}

impl DiskCollector {
    fn new(mount_points: Option<Vec<String>>) -> Result<Self> {
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
                    json!({
                        "name": disk.name().to_string_lossy(),
                        "mount_point": mount_point,
                        "file_system": disk.file_system().to_string_lossy(),
                        "total_bytes": total,
                        "available_bytes": available,
                        "used_bytes": total.saturating_sub(available),
                        "removable": disk.is_removable(),
                    })
                })
            })
            .collect();

        Ok(Value::Array(disks))
    }
}

struct NetworkCollector {
    networks: Networks,
}

impl NetworkCollector {
    fn new() -> Result<Self> {
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
                    "total_received_bytes": data.total_received(),
                    "total_transmitted_bytes": data.total_transmitted(),
                    "total_receive_errors": data.total_errors_on_received(),
                    "total_transmit_errors": data.total_errors_on_transmitted(),
                });
                (name.to_string_lossy().into_owned(), stats)
            })
            .collect();

        Ok(Value::Object(interfaces))
    }
}
