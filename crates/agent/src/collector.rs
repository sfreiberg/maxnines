use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, bail};
use maxnines_protocol::{AgentConfig, COLLECTORS, CollectorSettings};
use serde_json::{Value, json};
use sysinfo::{
    Components, CpuRefreshKind, Process, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate,
    System, UpdateKind,
};

use maxnines_collectors::counters::CounterCollector;
use maxnines_collectors::host::{
    CpuCollector, DiskCollector, HostCollector, MemoryCollector, NetworkCollector,
};
pub use maxnines_collectors::{Collector, WARMUP};

use crate::checks::{CheckCollector, CheckDefinitions};
use crate::commands::{CheckCommands, CommandCollector};
use crate::custom::{CustomCollector, Definitions};
use crate::databases::DatabaseDefinitions;
use crate::files::FileCollector;
use crate::openmetrics::{OpenMetricsCollector, PageDefinitions};
use crate::services::ServiceCollector;
use crate::status_pages::{Software, StatusPageCollector};
use crate::system_collector::SystemCollector;
use crate::templates::TemplateCollector;

/// Only Linux runs containers for real, so that's the only agent that reads them.
const LINUX_ONLY: [&str; 1] = ["containers"];
/// Performance counters are part of Windows.
const WINDOWS_ONLY: [&str; 1] = ["counters"];
/// Only macOS says how busy its GPUs are so far.
const MACOS_ONLY: [&str; 1] = ["gpu"];

/// What this agent can run, reported to the server as a fact.
pub fn supported() -> Vec<&'static str> {
    COLLECTORS
        .into_iter()
        .filter(|name| cfg!(target_os = "linux") || !LINUX_ONLY.contains(name))
        .filter(|name| cfg!(windows) || !WINDOWS_ONLY.contains(name))
        .filter(|name| cfg!(target_os = "macos") || !MACOS_ONLY.contains(name))
        .collect()
}

/// The name samples are reported under: the short name, as the domain is a fact.
pub fn host_name() -> String {
    System::host_name().map_or_else(
        |_| "unknown".to_string(),
        |name| crate::facts::short_name(&name),
    )
}

/// What the agent's own config gives collectors, on top of what the server asks
/// for. The server can pick from these by name, but never sees or changes them.
#[derive(Clone, Copy)]
pub struct Local<'a> {
    pub custom_metrics: &'a Definitions,
    pub check_commands: &'a CheckCommands,
    pub checks: &'a CheckDefinitions,
    pub metrics_pages: &'a PageDefinitions,
    pub databases: &'a DatabaseDefinitions,
}

#[cfg(test)]
impl Local<'static> {
    /// A config that gives nothing.
    pub fn none() -> Self {
        static CUSTOM_METRICS: Definitions = Definitions::new();
        static CHECK_COMMANDS: CheckCommands = CheckCommands::new();
        static CHECKS: CheckDefinitions = CheckDefinitions::new();
        static METRICS_PAGES: PageDefinitions = PageDefinitions::new();
        static DATABASES: DatabaseDefinitions = DatabaseDefinitions::new();
        Self {
            custom_metrics: &CUSTOM_METRICS,
            check_commands: &CHECK_COMMANDS,
            checks: &CHECKS,
            metrics_pages: &METRICS_PAGES,
            databases: &DATABASES,
        }
    }
}

/// What one collector was made from, so a new config that says the same keeps it,
/// with whatever it holds, such as connections and running totals.
#[derive(Debug, Clone, PartialEq)]
pub enum Made {
    /// The config's settings for it.
    Settings {
        name: String,
        settings: Box<CollectorSettings>,
        /// The interval, for a collector that runs on it, so only those are built
        /// again when it changes. See [`runs_on_interval`].
        interval: Option<Duration>,
    },
    /// What templates have it read, which a new config changes in place.
    Templates,
    /// The agent's report on itself, which never changes.
    OwnUsage,
}

impl Made {
    /// The collector's name, for the log.
    pub fn name(&self) -> &str {
        match self {
            Made::Settings { name, .. } => name,
            Made::Templates => "templates",
            Made::OwnUsage => "own usage",
        }
    }
}

/// The collectors that share the process list, which are made again together.
const SHARE_PROCESSES: [&str; 2] = ["processes", "top_processes"];

/// Whether a collector is built with the sample interval, such as one that runs
/// something on a schedule of its own or works out rates per interval. The rest
/// carry on when only the interval changes. [`build`] is given the interval only
/// for these, so one missing from here can't be built at all.
fn runs_on_interval(name: &str) -> bool {
    matches!(
        name,
        "system"
            | "checks"
            | "custom"
            | "commands"
            | "services"
            | "containers"
            | "files"
            | "apache"
            | "nginx"
            | "php_fpm"
            | "openmetrics"
    )
}

/// Everything a config turns on, in order, each with what it's made from, and
/// built only if `keeping`, what the collectors running now were made from, has
/// nothing made the same: one that does is kept, so it's `None` here. Templates are
/// kept whenever they're running, as they take new work in place.
pub type Plan = Vec<(Made, Option<Box<dyn Collector + Send>>)>;

/// Builds what a config turns on that isn't running already. See [`Plan`].
pub fn build_all(config: &AgentConfig, local: Local<'_>, keeping: &[Made]) -> Result<Plan> {
    let enabled = |name: &str| {
        config
            .collectors
            .get(name)
            .is_some_and(|settings| settings.enabled)
    };
    // Only the processes collector needs each program's file.
    let mut processes = Processes {
        table: None,
        files: enabled("processes"),
    };
    let interval = config.interval;
    let made: Vec<Made> = config
        .collectors
        .iter()
        .filter(|(_, settings)| settings.enabled)
        .map(|(name, settings)| Made::Settings {
            name: name.clone(),
            settings: Box::new(settings.clone()),
            interval: runs_on_interval(name).then_some(interval),
        })
        .collect();
    // Those sharing the process list share one, so they're kept only together.
    let sharing = |made: &Made| matches!(made, Made::Settings { name, .. } if SHARE_PROCESSES.contains(&name.as_str()));
    let shared_now: Vec<&Made> = made.iter().filter(|made| sharing(made)).collect();
    let shared_before: Vec<&Made> = keeping.iter().filter(|made| sharing(made)).collect();
    let keep_shared = shared_now == shared_before;

    let mut plan: Plan = Vec::with_capacity(made.len() + 1);
    for made in made {
        let kept = keeping.contains(&made) && (!sharing(&made) || keep_shared);
        let Made::Settings {
            name,
            settings,
            interval,
        } = &made
        else {
            continue;
        };
        let built = match kept {
            true => None,
            false => Some(build(name, settings, local, *interval, &mut processes)?),
        };
        plan.push((made, built));
    }
    if !config.templates.is_empty() {
        let built: Option<Box<dyn Collector + Send>> = match keeping.contains(&Made::Templates) {
            true => None,
            false => Some(Box::new(TemplateCollector::new(
                &config.templates,
                local.databases,
                interval,
            )?)),
        };
        plan.push((Made::Templates, built));
    }
    Ok(plan)
}

/// The process list, read once a sample for both collectors that use it, once the
/// first of them is built.
struct Processes {
    table: Option<SharedProcesses>,
    files: bool,
}

impl Processes {
    fn table(&mut self) -> Result<SharedProcesses> {
        if let Some(table) = &self.table {
            return Ok(table.clone());
        }
        let table = ProcessTable::shared(self.files)?;
        self.table = Some(table.clone());
        Ok(table)
    }
}

/// Builds one collector. `interval` is the sample interval for one that
/// [`runs_on_interval`], and None for the rest.
fn build(
    name: &str,
    config: &CollectorSettings,
    local: Local<'_>,
    interval: Option<Duration>,
    processes: &mut Processes,
) -> Result<Box<dyn Collector + Send>> {
    let every = || {
        interval.ok_or_else(|| anyhow::anyhow!("{name} runs on the interval but wasn't given it"))
    };
    Ok(match name {
        "host" => Box::new(HostCollector),
        "cpu" => Box::new(CpuCollector::new()?),
        "memory" => Box::new(MemoryCollector::new()?),
        "disk" => Box::new(DiskCollector::new(config.mount_points.clone())?),
        "network" => Box::new(NetworkCollector::new()?),
        "processes" => Box::new(ProcessCollector::new(
            config.names.clone().unwrap_or_default(),
            processes.table()?,
        )),
        "top_processes" => Box::new(TopProcessCollector::new(processes.table()?)),
        "counters" => Box::new(CounterCollector::new(
            config.names.clone().unwrap_or_default(),
        )),
        "sensors" => Box::new(SensorCollector::new()?),
        "smart" => Box::new(crate::smart::SmartCollector::new()?),
        "raid" => Box::new(crate::raid::RaidCollector::new()?),
        "updates" => Box::new(crate::updates::UpdatesCollector::new()?),
        "time_sync" => Box::new(maxnines_collectors::time_sync::TimeSyncCollector::new()),
        #[cfg(target_os = "macos")]
        "gpu" => Box::new(maxnines_collectors::gpu::GpuCollector),
        "system" => Box::new(SystemCollector::new(every()?)?),
        "checks" => {
            let checks = config.checks.clone().unwrap_or_default();
            let chosen = config.local_checks.as_deref().unwrap_or_default();
            Box::new(CheckCollector::new(checks, chosen, local.checks, every()?)?)
        }
        "custom" => {
            let names = config.names.clone().unwrap_or_default();
            Box::new(CustomCollector::new(names, local.custom_metrics, every()?)?)
        }
        "commands" => {
            let names = config.names.clone().unwrap_or_default();
            Box::new(CommandCollector::new(
                names,
                local.check_commands,
                every()?,
            )?)
        }
        "services" => {
            let names = config.names.clone().unwrap_or_default();
            Box::new(ServiceCollector::new(names, every()?)?)
        }
        #[cfg(target_os = "linux")]
        "containers" => Box::new(crate::containers::ContainerCollector::new(every()?)?),
        "files" => {
            let paths = config.paths.clone().unwrap_or_default();
            Box::new(FileCollector::new(paths, every()?)?)
        }
        "apache" => status_pages(Software::Apache, config, every()?)?,
        "nginx" => status_pages(Software::Nginx, config, every()?)?,
        "php_fpm" => status_pages(Software::PhpFpm, config, every()?)?,
        "openmetrics" => {
            let urls = config.urls.clone().unwrap_or_default();
            let chosen = config.local_pages.as_deref().unwrap_or_default();
            let wanted = config.names.as_deref().unwrap_or_default();
            let pages = local.metrics_pages;
            Box::new(OpenMetricsCollector::new(
                urls,
                chosen,
                wanted,
                pages,
                every()?,
            )?)
        }
        other => bail!("unknown collector {other:?}"),
    })
}

fn status_pages(
    software: Software,
    config: &CollectorSettings,
    interval: Duration,
) -> Result<Box<dyn Collector + Send>> {
    let urls = config.urls.clone().unwrap_or_default();
    Ok(Box::new(StatusPageCollector::new(
        software, urls, interval,
    )?))
}

/// Some sensors report raw values that aren't temperatures, such as -9200 on
/// Apple hardware. Nothing a host can survive falls outside this.
fn is_plausible(celsius: f32) -> bool {
    (-60.0..=200.0).contains(&celsius)
}

/// Reads temperatures. What's available depends heavily on the host: virtual
/// hosts usually have none, and some readings need extra rights.
struct SensorCollector {
    components: Components,
}

impl SensorCollector {
    fn new() -> Result<Self> {
        Ok(Self {
            components: Components::new_with_refreshed_list()?,
        })
    }
}

impl Collector for SensorCollector {
    fn name(&self) -> &'static str {
        "sensors"
    }

    fn collect(&mut self) -> Result<Value> {
        self.components.refresh(true);
        let sensors: Vec<Value> = self
            .components
            .iter()
            .filter_map(|component| {
                let celsius = component.temperature().filter(|c| is_plausible(*c))?;
                Some(json!({ "label": component.label(), "celsius": celsius }))
            })
            .collect();
        Ok(Value::Array(sensors))
    }
}

/// The process list, read once a sample however many collectors use it. CPU usage
/// is measured between two reads, like the CPU collector's, so it's read once now.
pub struct ProcessTable {
    system: System,
    /// Whether each program's file is wanted too.
    files: bool,
    /// The sample it was last read for, counted by the collectors that use it.
    read_for: u64,
}

type SharedProcesses = Arc<Mutex<ProcessTable>>;

impl ProcessTable {
    fn shared(files: bool) -> Result<SharedProcesses> {
        let mut system = System::new()?;
        system.refresh_cpu_list(CpuRefreshKind::nothing());
        let mut table = Self {
            system,
            files,
            read_for: 0,
        };
        table.read();
        Ok(Arc::new(Mutex::new(table)))
    }

    fn read(&mut self) {
        let kind = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .without_tasks();
        let kind = if self.files {
            kind.with_exe(UpdateKind::OnlyIfNotSet)
        } else {
            kind
        };
        self.system
            .refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    }

    /// What's running for a collector's `sample`th sample. The collectors that share
    /// the list are built together and asked for every sample, so they count alike,
    /// and the first to ask reads it.
    fn running_for(table: &SharedProcesses, sample: u64) -> Vec<RunningProcess> {
        let mut table = table.lock().unwrap_or_else(PoisonError::into_inner);
        if table.read_for < sample {
            table.read();
            table.read_for = sample;
        }
        running(&table.system)
    }
}

/// What's needed from a process to count it, with its names as they're matched.
struct RunningProcess {
    name: String,
    /// The name of its program's file, as Linux cuts a process's own name short.
    file: Option<String>,
    cpu_percent: f64,
    memory_bytes: u64,
}

/// A program's name as it's reported and matched: in lower case, and without the
/// `.exe` Windows adds, which nobody thinks of as part of the name.
pub fn program_name(name: &OsStr) -> String {
    let name = name.to_string_lossy().to_lowercase();
    match name.strip_suffix(".exe") {
        Some(base) => base.to_string(),
        None => name,
    }
}

/// Whether a process is running, leaving out threads and what has exited. A crashed
/// service can linger as a zombie, which isn't running.
pub fn is_running(process: &Process) -> bool {
    process.thread_kind().is_none()
        && !matches!(
            process.status(),
            ProcessStatus::Zombie | ProcessStatus::Dead
        )
}

/// Matches whole names, ignoring case. `wanted` is a [`program_name`].
fn is_named(process: &RunningProcess, wanted: &str) -> bool {
    process.name == wanted || process.file.as_deref() == Some(wanted)
}

/// One entry per watched name, whether anything matched or not.
fn tally(names: &[(String, String)], processes: &[RunningProcess]) -> Vec<Value> {
    names
        .iter()
        .map(|(name, wanted)| {
            let matching = processes.iter().filter(|process| is_named(process, wanted));
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
                "memory_bytes": memory,
            })
        })
        .collect()
}

/// What's running. A process's usage is per core, so it's scaled to match the CPU
/// chart, where 100% is the whole host.
fn running(system: &System) -> Vec<RunningProcess> {
    let cores = system.cpus().len().max(1) as f64;
    system
        .processes()
        .values()
        .filter(|process| is_running(process))
        .map(|process| RunningProcess {
            name: program_name(process.name()),
            file: process.exe().and_then(Path::file_name).map(program_name),
            cpu_percent: f64::from(process.cpu_usage()) / cores,
            memory_bytes: process.memory(),
        })
        .collect()
}

/// Reports on the processes it's told to watch, and only those. A name with
/// nothing running reports a count of 0, which is how a stopped service shows up.
struct ProcessCollector {
    table: SharedProcesses,
    samples: u64,
    /// Each name as it's reported, and as it's matched.
    names: Vec<(String, String)>,
}

impl ProcessCollector {
    fn new(names: Vec<String>, table: SharedProcesses) -> Self {
        let names = names
            .into_iter()
            .map(|name| {
                let wanted = program_name(OsStr::new(&name));
                (name, wanted)
            })
            .collect();
        Self {
            table,
            samples: 0,
            names,
        }
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "processes"
    }

    fn collect(&mut self) -> Result<Value> {
        self.samples += 1;
        let running = ProcessTable::running_for(&self.table, self.samples);
        Ok(Value::Array(tally(&self.names, &running)))
    }
}

/// How many programs each of the top lists keeps.
const TOP: usize = 5;

/// The programs using the most CPU and the most memory, each adding up every process
/// of that name, so twenty workers of one server are one line. Only names are reported,
/// never what a program was started with, which can hold secrets. It's off unless a
/// config rule turns it on, as it says what's running where the processes collector
/// only answers about names it's given.
struct TopProcessCollector {
    table: SharedProcesses,
    samples: u64,
}

impl TopProcessCollector {
    fn new(table: SharedProcesses) -> Self {
        Self { table, samples: 0 }
    }
}

impl Collector for TopProcessCollector {
    fn name(&self) -> &'static str {
        "top_processes"
    }

    fn collect(&mut self) -> Result<Value> {
        self.samples += 1;
        let running = ProcessTable::running_for(&self.table, self.samples);
        Ok(Value::Array(top(running)))
    }
}

/// The top programs by CPU and by memory, together, each once, busiest first.
fn top(processes: Vec<RunningProcess>) -> Vec<Value> {
    let mut programs: HashMap<String, (u64, f64, u64)> = HashMap::new();
    for process in processes {
        let program = programs.entry(process.name).or_default();
        program.0 += 1;
        program.1 += process.cpu_percent;
        program.2 = program.2.saturating_add(process.memory_bytes);
    }
    let mut programs: Vec<(String, (u64, f64, u64))> = programs.into_iter().collect();
    programs.sort_by(|a, b| b.1.1.total_cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
    let mut kept: Vec<String> = programs
        .iter()
        .take(TOP)
        .map(|(name, _)| name.clone())
        .collect();
    programs.sort_by(|a, b| b.1.2.cmp(&a.1.2).then_with(|| a.0.cmp(&b.0)));
    for (name, _) in programs.iter().take(TOP) {
        if !kept.contains(name) {
            kept.push(name.clone());
        }
    }
    let found: HashMap<&String, &(u64, f64, u64)> = programs.iter().map(|(n, v)| (n, v)).collect();
    kept.iter()
        .filter_map(|name| {
            let (count, cpu, memory) = found.get(name)?;
            Some(json!({
                "name": name,
                "count": count,
                "cpu_percent": cpu,
                "memory_bytes": memory,
            }))
        })
        .collect()
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
        let collectors = Value::Object(
            supported()
                .into_iter()
                .map(|name| (name.to_string(), json!({})))
                .collect(),
        );

        assert_eq!(
            build_all(&config(collectors), Local::none(), &[])
                .unwrap()
                .len(),
            supported().len()
        );
    }

    #[test]
    fn disabled_collectors_are_left_out() {
        let collectors = json!({ "cpu": {}, "memory": { "enabled": false } });
        let built = build_all(&config(collectors), Local::none(), &[]).unwrap();

        assert_eq!(built.len(), 1);
        assert_eq!(built[0].1.as_ref().unwrap().name(), "cpu");
    }

    #[test]
    fn only_what_a_new_config_changes_is_built_again() {
        let before =
            config(json!({ "cpu": {}, "disk": { "mount_points": ["/"] }, "processes": {} }));
        let keeping: Vec<Made> = build_all(&before, Local::none(), &[])
            .unwrap()
            .into_iter()
            .map(|(made, _)| made)
            .collect();
        let built = |collectors: Value| {
            let plan = build_all(&config(collectors), Local::none(), &keeping).unwrap();
            plan.iter()
                .filter(|(_, built)| built.is_some())
                .map(|(made, _)| match made {
                    Made::Settings { name, .. } => name.clone(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
        };

        // The same config builds nothing.
        assert!(
            built(json!({ "cpu": {}, "disk": { "mount_points": ["/"] }, "processes": {} }))
                .is_empty()
        );
        // A changed setting builds that one again.
        assert_eq!(
            built(json!({ "cpu": {}, "disk": { "mount_points": ["/data"] }, "processes": {} })),
            ["disk"]
        );
        // Those sharing the process list are built again together.
        assert_eq!(
            built(
                json!({ "cpu": {}, "disk": { "mount_points": ["/"] }, "processes": {}, "top_processes": {} })
            ),
            ["processes", "top_processes"]
        );
        // A new collector is the only one built.
        assert_eq!(
            built(
                json!({ "cpu": {}, "disk": { "mount_points": ["/"] }, "processes": {}, "memory": {} })
            ),
            ["memory"]
        );
    }

    #[test]
    fn a_new_interval_builds_again_only_what_runs_on_it() {
        let before = config(json!({ "cpu": {}, "files": {}, "services": {} }));
        let keeping: Vec<Made> = build_all(&before, Local::none(), &[])
            .unwrap()
            .into_iter()
            .map(|(made, _)| made)
            .collect();
        let mut slower = before.clone();
        slower.interval = Duration::from_secs(60);
        let rebuilt: Vec<String> = build_all(&slower, Local::none(), &keeping)
            .unwrap()
            .into_iter()
            .filter(|(_, built)| built.is_some())
            .filter_map(|(made, _)| match made {
                Made::Settings { name, .. } => Some(name),
                _ => None,
            })
            .collect();

        assert_eq!(rebuilt, ["files", "services"]);
    }

    #[test]
    fn only_collectors_that_run_on_the_interval_are_given_it() {
        for name in supported() {
            let built = build(
                name,
                &serde_json::from_value::<CollectorSettings>(json!({})).unwrap(),
                Local::none(),
                None,
                &mut Processes {
                    table: None,
                    files: false,
                },
            );
            assert_eq!(built.is_err(), runs_on_interval(name), "{name}");
        }
    }

    fn process(name: &str, exe: Option<&str>) -> RunningProcess {
        RunningProcess {
            name: program_name(OsStr::new(name)),
            file: exe
                .and_then(|exe| Path::new(exe).file_name())
                .map(program_name),
            cpu_percent: 2.5,
            memory_bytes: 100,
        }
    }

    fn watching(names: &[&str]) -> Vec<(String, String)> {
        names
            .iter()
            .map(|name| (name.to_string(), program_name(OsStr::new(name))))
            .collect()
    }

    fn processes_watching(names: &[&str]) -> ProcessCollector {
        let names = names.iter().map(ToString::to_string).collect();
        ProcessCollector::new(names, ProcessTable::shared(true).unwrap())
    }

    #[test]
    fn matching_processes_are_added_up() {
        let processes = [
            process("nginx", None),
            process("nginx", None),
            process("sshd", None),
        ];
        let tally = tally(&watching(&["nginx"]), &processes);

        assert_eq!(
            tally,
            [json!({
                "name": "nginx",
                "count": 2,
                "cpu_percent": 5.0,
                "memory_bytes": 200,
            })]
        );
    }

    #[test]
    fn a_name_with_nothing_running_reports_zero() {
        let tally = tally(&watching(&["nginx"]), &[process("sshd", None)]);

        assert_eq!(tally[0]["count"], 0);
        assert_eq!(tally[0]["cpu_percent"], 0.0);
    }

    #[test]
    fn only_watched_names_are_reported() {
        let processes = [process("nginx", None), process("secret-thing", None)];
        let tally = tally(&watching(&["nginx"]), &processes);

        assert_eq!(tally.len(), 1);
        assert!(!Value::Array(tally).to_string().contains("secret-thing"));
    }

    #[test]
    fn a_watched_name_is_reported_as_it_was_given() {
        let tally = tally(&watching(&["NGINX.exe"]), &[process("nginx", None)]);
        assert_eq!(tally[0]["name"], "NGINX.exe");
        assert_eq!(tally[0]["count"], 1);
    }

    #[test]
    fn names_ignore_case_and_windows_extensions() {
        let named = |process: &RunningProcess, wanted: &str| {
            is_named(process, &program_name(OsStr::new(wanted)))
        };
        assert!(named(&process("nginx.exe", None), "nginx"));
        assert!(named(&process("NGINX.EXE", None), "nginx"));
        assert!(named(&process("nginx", None), "nginx.exe"));
        assert!(named(&process("Nginx", None), "nginx"));
        assert!(!named(&process("nginx-exporter", None), "nginx"));
        assert!(!named(&process("ng", None), "nginx"));
    }

    #[test]
    fn a_name_cut_short_by_linux_still_matches_its_file() {
        let long = process("postgres_export", Some("/usr/bin/postgres_exporter"));
        assert!(is_named(&long, "postgres_exporter"));
    }

    #[test]
    fn with_no_names_nothing_is_reported() {
        let mut collector = processes_watching(&[]);
        assert_eq!(collector.collect().unwrap(), json!([]));
    }

    #[cfg(unix)]
    #[test]
    fn a_process_that_has_exited_does_not_count_as_running() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        // Waits for it to exit without reaping it, so it stays a zombie until the
        // collector has looked.
        let pid = rustix::process::Pid::from_child(&child);
        let options =
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT;
        rustix::process::waitid(rustix::process::WaitId::Pid(pid), options).unwrap();

        let mut collector = processes_watching(&["true"]);
        let output = collector.collect().unwrap();
        child.wait().unwrap();

        assert_eq!(output[0]["count"], 0, "{output}");
    }

    #[test]
    fn this_test_can_see_itself_running() {
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().to_string();
        let mut collector = processes_watching(&[&name, "no-such-process"]);

        let output = collector.collect().unwrap();
        assert!(output[0]["count"].as_u64().unwrap() >= 1, "{output}");
        assert!(output[0]["memory_bytes"].as_u64().unwrap() > 0, "{output}");
        assert_eq!(output[1]["count"], 0);
    }

    #[test]
    fn both_process_collectors_read_the_list_once_a_sample() {
        let table = ProcessTable::shared(true).unwrap();
        let mut watched = ProcessCollector::new(Vec::new(), table.clone());
        let mut top = TopProcessCollector::new(table.clone());
        let read_for = || table.lock().unwrap().read_for;

        watched.collect().unwrap();
        assert_eq!(read_for(), 1);
        top.collect().unwrap();
        assert_eq!(read_for(), 1, "the second collector reads it again");
        top.collect().unwrap();
        assert_eq!(read_for(), 2);
        watched.collect().unwrap();
        assert_eq!(read_for(), 2);
    }

    fn using(name: &str, cpu_percent: f64, memory_bytes: u64) -> RunningProcess {
        RunningProcess {
            cpu_percent,
            memory_bytes,
            ..process(name, None)
        }
    }

    #[test]
    fn the_top_programs_add_up_every_process_of_one_name() {
        let processes = vec![
            using("php-fpm", 10.0, 100),
            using("php-fpm", 15.0, 100),
            using("postgres", 20.0, 900),
            using("Chrome.exe", 1.0, 50),
        ];
        let top = top(processes);
        assert_eq!(
            top[0],
            json!({ "name": "php-fpm", "count": 2, "cpu_percent": 25.0, "memory_bytes": 200 })
        );
        assert_eq!(top[1]["name"], "postgres");
        assert_eq!(top[2]["name"], "chrome");
        assert_eq!(top.len(), 3);
    }

    #[test]
    fn the_top_lists_keep_the_busiest_and_the_biggest_once_each() {
        let mut processes: Vec<RunningProcess> = ["a", "b", "c", "d", "e", "f", "g"]
            .iter()
            .enumerate()
            .map(|(i, name)| using(name, 70.0 - i as f64 * 10.0, 10))
            .collect();
        // Idle, but the biggest.
        processes.push(using("cache", 0.0, 10_000));
        let names: Vec<Value> = top(processes)
            .into_iter()
            .map(|program| program["name"].clone())
            .collect();
        assert_eq!(
            names,
            json!(["a", "b", "c", "d", "e", "cache"])
                .as_array()
                .unwrap()
                .clone()
        );
    }

    #[test]
    fn the_top_processes_are_this_hosts_own() {
        let mut collector = TopProcessCollector::new(ProcessTable::shared(false).unwrap());
        let output = collector.collect().unwrap();
        let top = output.as_array().unwrap();
        assert!(!top.is_empty() && top.len() <= 2 * TOP, "{output}");
        assert!(top.iter().all(|program| program["memory_bytes"].is_u64()));
    }

    #[test]
    fn impossible_temperatures_are_left_out() {
        assert!(is_plausible(45.0));
        assert!(is_plausible(-20.0));
        assert!(!is_plausible(-9200.5));
        assert!(!is_plausible(1500.0));
        assert!(!is_plausible(f32::NAN));
    }

    #[test]
    fn sensors_give_a_list_even_when_there_are_none() {
        let mut collector = SensorCollector::new().unwrap();
        assert!(collector.collect().unwrap().is_array());
    }

    #[test]
    fn an_unknown_collector_is_an_error() {
        assert!(build_all(&config(json!({ "nope": {} })), Local::none(), &[]).is_err());
    }
}
