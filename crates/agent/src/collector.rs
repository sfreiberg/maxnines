use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use maxnines_protocol::{AgentConfig, COLLECTORS, CollectorSettings};
use serde_json::{Value, json};
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessStatus,
    ProcessesToUpdate, System, UpdateKind,
};

/// What this agent can run, reported to the server as a fact.
pub const SUPPORTED: [&str; 6] = COLLECTORS;

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

/// Builds everything a config turns on.
pub fn build_all(config: &AgentConfig) -> Result<Vec<Box<dyn Collector>>> {
    config
        .collectors
        .iter()
        .filter(|(_, settings)| settings.enabled)
        .map(|(name, settings)| build(name, settings))
        .collect()
}

fn build(name: &str, config: &CollectorSettings) -> Result<Box<dyn Collector>> {
    Ok(match name {
        "host" => Box::new(HostCollector),
        "cpu" => Box::new(CpuCollector::new()?),
        "memory" => Box::new(MemoryCollector::new()?),
        "disk" => Box::new(DiskCollector::new(config.mount_points.clone())?),
        "network" => Box::new(NetworkCollector::new()?),
        "processes" => Box::new(ProcessCollector::new(config.names.clone())?),
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

/// Reports on the processes it's told to watch, and only those. A name with
/// nothing running reports a count of 0, which is how a stopped service shows up.
struct ProcessCollector {
    system: System,
    names: Vec<String>,
}

/// What's needed from a process to count it.
struct RunningProcess<'a> {
    name: &'a OsStr,
    exe: Option<&'a Path>,
    cpu_percent: f64,
    memory_bytes: u64,
}

/// Windows adds `.exe`, which nobody thinks of as part of the name.
fn base_name(name: &OsStr) -> String {
    let name = name.to_string_lossy().to_lowercase();
    match name.strip_suffix(".exe") {
        Some(base) => base.to_string(),
        None => name,
    }
}

/// Matches whole names, ignoring case. The file name counts too, as Linux cuts
/// a process's own name to 15 characters.
fn is_named(process: &RunningProcess, wanted: &str) -> bool {
    let wanted = base_name(OsStr::new(wanted));
    base_name(process.name) == wanted
        || process
            .exe
            .and_then(Path::file_name)
            .is_some_and(|file| base_name(file) == wanted)
}

/// One entry per watched name, whether anything matched or not.
fn tally(names: &[String], processes: &[RunningProcess], total_memory: u64) -> Vec<Value> {
    names
        .iter()
        .map(|name| {
            let matching = processes.iter().filter(|process| is_named(process, name));
            let (count, cpu, memory) = matching.fold((0u64, 0.0, 0u64), |totals, process| {
                (
                    totals.0 + 1,
                    totals.1 + process.cpu_percent,
                    totals.2.saturating_add(process.memory_bytes),
                )
            });
            json!({
                "name": name,
                "count": count,
                "cpu_percent": cpu,
                "memory_percent": memory as f64 / total_memory.max(1) as f64 * 100.0,
            })
        })
        .collect()
}

impl ProcessCollector {
    fn new(names: Option<Vec<String>>) -> Result<Self> {
        let mut collector = Self {
            system: System::new()?,
            names: names.unwrap_or_default(),
        };
        collector.system.refresh_cpu_list(CpuRefreshKind::nothing());
        // CPU usage is measured between two refreshes, like the CPU collector's.
        collector.refresh();
        Ok(collector)
    }

    fn refresh(&mut self) {
        self.system
            .refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .without_tasks(),
        );
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "processes"
    }

    fn collect(&mut self) -> Result<Value> {
        self.refresh();

        // A process's usage is per core, so it's scaled to match the CPU chart,
        // where 100% is the whole machine.
        let cores = self.system.cpus().len().max(1) as f64;
        let running: Vec<RunningProcess> = self
            .system
            .processes()
            .values()
            .filter(|process| process.thread_kind().is_none())
            // A crashed service can linger as a zombie, which isn't running.
            .filter(|process| {
                !matches!(
                    process.status(),
                    ProcessStatus::Zombie | ProcessStatus::Dead
                )
            })
            .map(|process| RunningProcess {
                name: process.name(),
                exe: process.exe(),
                cpu_percent: f64::from(process.cpu_usage()) / cores,
                memory_bytes: process.memory(),
            })
            .collect();

        Ok(Value::Array(tally(
            &self.names,
            &running,
            self.system.total_memory(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(collectors: Value) -> AgentConfig {
        serde_json::from_value(json!({ "collectors": collectors })).unwrap()
    }

    #[test]
    fn every_supported_collector_can_be_built() {
        let settings = SUPPORTED.map(|name| (name, json!({})));
        let collectors = Value::Object(
            settings
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
        );

        assert_eq!(
            build_all(&config(collectors)).unwrap().len(),
            SUPPORTED.len()
        );
    }

    #[test]
    fn disabled_collectors_are_left_out() {
        let collectors = json!({ "cpu": {}, "memory": { "enabled": false } });
        let built = build_all(&config(collectors)).unwrap();

        assert_eq!(built.len(), 1);
        assert_eq!(built[0].name(), "cpu");
    }

    fn process<'a>(name: &'a str, exe: Option<&'a str>) -> RunningProcess<'a> {
        RunningProcess {
            name: OsStr::new(name),
            exe: exe.map(Path::new),
            cpu_percent: 2.5,
            memory_bytes: 100,
        }
    }

    fn watching(names: &[&str]) -> Vec<String> {
        names.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn matching_processes_are_added_up() {
        let processes = [
            process("nginx", None),
            process("nginx", None),
            process("sshd", None),
        ];
        let tally = tally(&watching(&["nginx"]), &processes, 1000);

        assert_eq!(
            tally,
            [json!({
                "name": "nginx",
                "count": 2,
                "cpu_percent": 5.0,
                "memory_percent": 20.0,
            })]
        );
    }

    #[test]
    fn a_name_with_nothing_running_reports_zero() {
        let tally = tally(&watching(&["nginx"]), &[process("sshd", None)], 1000);

        assert_eq!(tally[0]["count"], 0);
        assert_eq!(tally[0]["cpu_percent"], 0.0);
    }

    #[test]
    fn only_watched_names_are_reported() {
        let processes = [process("nginx", None), process("secret-thing", None)];
        let tally = tally(&watching(&["nginx"]), &processes, 1000);

        assert_eq!(tally.len(), 1);
        assert!(!Value::Array(tally).to_string().contains("secret-thing"));
    }

    #[test]
    fn names_ignore_case_and_windows_extensions() {
        assert!(is_named(&process("nginx.exe", None), "nginx"));
        assert!(is_named(&process("NGINX.EXE", None), "nginx"));
        assert!(is_named(&process("nginx", None), "nginx.exe"));
        assert!(is_named(&process("Nginx", None), "nginx"));
    }

    #[test]
    fn names_have_to_match_whole() {
        assert!(!is_named(&process("nginx-exporter", None), "nginx"));
        assert!(!is_named(&process("ng", None), "nginx"));
    }

    #[test]
    fn a_name_cut_short_by_linux_still_matches_its_file() {
        let long = process("postgres_export", Some("/usr/bin/postgres_exporter"));
        assert!(is_named(&long, "postgres_exporter"));
    }

    #[test]
    fn a_machine_reporting_no_memory_does_not_divide_by_zero() {
        let tally = tally(&watching(&["nginx"]), &[process("nginx", None)], 0);
        assert_eq!(tally[0]["memory_percent"], 10_000.0);
    }

    #[test]
    fn with_no_names_nothing_is_reported() {
        let mut collector = ProcessCollector::new(None).unwrap();
        assert_eq!(collector.collect().unwrap(), json!([]));
    }

    #[cfg(unix)]
    #[test]
    fn a_process_that_has_exited_does_not_count_as_running() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        // It stays a zombie until it's waited for.
        std::thread::sleep(Duration::from_millis(300));

        let mut collector = ProcessCollector::new(Some(vec!["true".to_string()])).unwrap();
        let output = collector.collect().unwrap();
        child.wait().unwrap();

        assert_eq!(output[0]["count"], 0, "{output}");
    }

    #[test]
    fn this_test_can_see_itself_running() {
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().to_string();
        let mut collector =
            ProcessCollector::new(Some(vec![name, "no-such-process".to_string()])).unwrap();

        let output = collector.collect().unwrap();
        assert!(output[0]["count"].as_u64().unwrap() >= 1, "{output}");
        assert!(
            output[0]["memory_percent"].as_f64().unwrap() > 0.0,
            "{output}"
        );
        assert_eq!(output[1]["count"], 0);
    }

    #[test]
    fn an_unknown_collector_is_an_error() {
        assert!(build_all(&config(json!({ "gpu": {} }))).is_err());
    }
}
