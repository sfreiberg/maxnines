//! Made-up reports, in the shape real agents send. Values change between samples
//! like real ones, because repeated data compresses better than real data does and
//! would make the database look smaller than it'll be.

use std::collections::BTreeMap;

use maxnines_protocol::COLLECTORS;
use rand::random_range;
use serde_json::{Map, Value, json};

const GIB: u64 = 1024 * 1024 * 1024;

/// What's needed to make up an agent's reports.
#[derive(Clone, Copy)]
pub struct Shape {
    pub cores: usize,
    pub disks: usize,
    pub interfaces: usize,
}

/// One agent's readings, with counters that only go up as real ones do.
pub struct Readings {
    shape: Shape,
    hot: bool,
    disk_bytes: Vec<(u64, u64)>,
    network_bytes: Vec<(u64, u64)>,
    used_memory_percent: f64,
    used_disk_percent: f64,
    uptime_secs: u64,
}

fn percent_near(value: f64, spread: f64) -> f64 {
    (value + random_range(-spread..spread)).clamp(0.0, 100.0)
}

impl Readings {
    pub fn new(shape: Shape, hot: bool) -> Self {
        Self {
            shape,
            hot,
            disk_bytes: vec![(0, 0); shape.disks],
            network_bytes: vec![(0, 0); shape.interfaces],
            used_memory_percent: random_range(20.0..80.0),
            used_disk_percent: random_range(20.0..80.0),
            uptime_secs: random_range(3_600..10_000_000),
        }
    }

    pub fn metrics(&mut self, elapsed_secs: u64) -> BTreeMap<String, Value> {
        self.uptime_secs += elapsed_secs;
        BTreeMap::from([
            ("cpu".to_string(), self.cpu()),
            ("memory".to_string(), self.memory()),
            ("disk".to_string(), self.disk()),
            ("network".to_string(), self.network()),
            ("host".to_string(), self.host()),
        ])
    }

    fn cpu(&self) -> Value {
        let usage = if self.hot {
            99.0
        } else {
            random_range(2.0..60.0)
        };
        let per_core: Vec<f64> = (0..self.shape.cores)
            .map(|_| percent_near(usage, 15.0))
            .collect();
        json!({
            "usage_percent": usage,
            "per_core_percent": per_core,
            "load_average": {
                "one": usage / 20.0,
                "five": usage / 22.0,
                "fifteen": usage / 25.0,
            },
            "time_percent": {
                "user": usage * 0.7,
                "system": usage * 0.3,
                "idle": 100.0 - usage,
                "nice": 0.0,
                "interrupt": 0.0,
            },
            "context_switches": random_range(1_000..50_000),
            "interrupts": random_range(1_000..50_000),
        })
    }

    fn memory(&self) -> Value {
        let total = 32 * GIB;
        let percent = percent_near(self.used_memory_percent, 3.0);
        let used = (total as f64 * percent / 100.0) as u64;
        json!({
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": total - used,
            "swap_total_bytes": 4 * GIB,
            "swap_used_bytes": random_range(0..GIB),
            "swap_in_pages": random_range(0..100),
            "swap_out_pages": random_range(0..100),
        })
    }

    fn disk(&mut self) -> Value {
        let total = 500 * GIB;
        let used = (total as f64 * self.used_disk_percent / 100.0) as u64;
        let disks: Vec<Value> = self
            .disk_bytes
            .iter_mut()
            .enumerate()
            .map(|(index, (read, written))| {
                *read += random_range(0..50_000_000);
                *written += random_range(0..50_000_000);
                let mount_point = match index {
                    0 => "/".to_string(),
                    other => format!("/data{other}"),
                };
                json!({
                    "name": format!("sd{}", char::from(b'a' + (index % 26) as u8)),
                    "mount_point": mount_point,
                    "file_system": "ext4",
                    "kind": "SSD",
                    "total_bytes": total,
                    "used_bytes": used,
                    "available_bytes": total - used,
                    "inodes_total": 30_000_000,
                    "inodes_used": random_range(100_000..2_000_000),
                    "read_bytes": *read,
                    "written_bytes": *written,
                    "read_only": false,
                    "removable": false,
                })
            })
            .collect();
        Value::Array(disks)
    }

    fn network(&mut self) -> Value {
        let mut interfaces = Map::new();
        for (index, (received, transmitted)) in self.network_bytes.iter_mut().enumerate() {
            let (new_received, new_transmitted): (u64, u64) =
                (random_range(0..5_000_000), random_range(0..5_000_000));
            *received += new_received;
            *transmitted += new_transmitted;
            let interface = json!({
                "link_up": 1,
                "received_bytes": new_received,
                "transmitted_bytes": new_transmitted,
                "packets_received": new_received / 1000,
                "packets_transmitted": new_transmitted / 1000,
                "receive_errors": 0,
                "transmit_errors": 0,
                "total_received_bytes": *received,
                "total_transmitted_bytes": *transmitted,
                "total_receive_errors": 0,
                "total_transmit_errors": 0,
            });
            interfaces.insert(format!("eth{index}"), interface);
        }
        Value::Object(interfaces)
    }

    fn host(&self) -> Value {
        json!({ "uptime_secs": self.uptime_secs, "boot_time_secs": 1_700_000_000 })
    }
}

/// Facts that differ between agents, so filters and rules have something to match.
pub fn facts(index: usize, host: &str, build: u64) -> Value {
    let (family, name, version) = match index % 10 {
        0 => ("windows", "Windows Server", "2022"),
        1 => ("freebsd", "FreeBSD", "14.1"),
        2..=4 => ("linux", "Debian GNU/Linux", "12"),
        _ => ("linux", "Ubuntu", "24.04"),
    };
    let role = ["web", "db", "cache", "worker"][index % 4];
    json!({
        "os": {
            "family": family,
            "name": name,
            "version": version,
            "long_version": format!("{name} {version}"),
        },
        "host": { "name": host, "arch": "x86_64" },
        "cpu": { "model": "Simulated CPU", "logical_cores": 8 },
        "memory": { "total_bytes": 32 * GIB },
        "agent": { "version": "loadtest", "collectors": COLLECTORS },
        "custom": { "role": role, "build": build, "tags": ["loadtest", role] },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHAPE: Shape = Shape {
        cores: 4,
        disks: 2,
        interfaces: 3,
    };

    #[test]
    fn samples_have_what_was_asked_for() {
        let metrics = Readings::new(SHAPE, false).metrics(15);

        assert_eq!(
            metrics["cpu"]["per_core_percent"].as_array().unwrap().len(),
            4
        );
        assert_eq!(metrics["disk"].as_array().unwrap().len(), 2);
        assert_eq!(metrics["network"].as_object().unwrap().len(), 3);
        assert_eq!(metrics["disk"][0]["mount_point"], "/");
        assert_eq!(metrics["disk"][1]["mount_point"], "/data1");
    }

    #[test]
    fn only_collectors_the_server_knows_are_reported() {
        let metrics = Readings::new(SHAPE, false).metrics(15);
        for name in metrics.keys() {
            assert!(COLLECTORS.contains(&name.as_str()), "{name}");
        }
    }

    #[test]
    fn counters_only_go_up() {
        let mut readings = Readings::new(SHAPE, false);
        let mut previous = 0;
        for _ in 0..20 {
            let metrics = readings.metrics(15);
            let total = metrics["network"]["eth0"]["total_received_bytes"]
                .as_u64()
                .unwrap();
            assert!(total >= previous);
            previous = total;
        }
    }

    #[test]
    fn values_change_between_samples() {
        let mut readings = Readings::new(SHAPE, false);
        assert_ne!(readings.metrics(15)["cpu"], readings.metrics(15)["cpu"]);
    }

    #[test]
    fn hot_agents_report_high_cpu() {
        let metrics = Readings::new(SHAPE, true).metrics(15);
        assert_eq!(metrics["cpu"]["usage_percent"], 99.0);
        for _ in 0..50 {
            let usage = Readings::new(SHAPE, false).metrics(15)["cpu"]["usage_percent"]
                .as_f64()
                .unwrap();
            assert!(usage < 90.0);
        }
    }

    #[test]
    fn percentages_stay_in_range() {
        for _ in 0..100 {
            let metrics = Readings::new(SHAPE, true).metrics(15);
            for core in metrics["cpu"]["per_core_percent"].as_array().unwrap() {
                assert!((0.0..=100.0).contains(&core.as_f64().unwrap()));
            }
        }
    }

    #[test]
    fn facts_differ_between_agents() {
        let families: std::collections::BTreeSet<String> = (0..10)
            .map(|index| facts(index, "h", 0)["os"]["family"].to_string())
            .collect();
        assert_eq!(families.len(), 3);
    }

    #[test]
    fn a_new_build_changes_the_facts() {
        assert_ne!(facts(1, "h", 1), facts(1, "h", 2));
    }
}
