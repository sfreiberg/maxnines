//! What only the operating system can say about itself, which differs by
//! platform. `systemstat` covers memory, and CPU time everywhere but Linux, where
//! `/proc/stat` also gives steal time. The rest comes from `/proc` on Linux and
//! `sysctl` on macOS and FreeBSD.
//!
//! Anything a platform doesn't have is left out rather than reported as zero.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};
use systemstat::{Platform, System};
use tokio::process::Command;
use tokio::time::timeout;

use crate::background::Background;
use crate::collector::Collector;

/// Listing logins is quick when the machine is healthy.
const SESSIONS_TIMEOUT: Duration = Duration::from_secs(10);

/// Running totals from the kernel, which only ever go up.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub context_switches: Option<u64>,
    pub interrupts: Option<u64>,
    pub swap_in_pages: Option<u64>,
    pub swap_out_pages: Option<u64>,
}

/// Turns a running total into the change since last time, which is what the
/// server expects for a rate.
#[derive(Debug, Default)]
pub struct Change(Option<u64>);

impl Change {
    /// The first reading has nothing to compare with. A total that went
    /// backwards means a counter wrapped, which counts as no change.
    pub fn update(&mut self, total: Option<u64>) -> Option<u64> {
        let change = self.0.zip(total).map(|(old, new)| new.saturating_sub(old));
        self.0 = total;
        change
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Limits {
    max_open_files: Option<u64>,
    open_files: Option<u64>,
    max_processes: Option<u64>,
    processes: Option<u64>,
}

/// Measures how CPU time is spent between one call and the next.
#[cfg(not(target_os = "linux"))]
pub struct CpuTime {
    stats: System,
    /// Has a fixed start, so each sample needs a new one.
    started: Option<systemstat::DelayedMeasurement<systemstat::CPULoad>>,
}

#[cfg(not(target_os = "linux"))]
impl CpuTime {
    pub fn new() -> Self {
        let stats = System::new();
        let started = stats.cpu_load_aggregate().ok();
        Self { stats, started }
    }

    pub fn measure(&mut self) -> Option<Value> {
        let load = self.started.as_ref()?.done().ok();
        self.started = self.stats.cpu_load_aggregate().ok();
        let percent = |fraction: f32| fraction * 100.0;
        load.map(|load| {
            json!({
                "user": percent(load.user),
                "nice": percent(load.nice),
                "system": percent(load.system),
                "interrupt": percent(load.interrupt),
                "idle": percent(load.idle),
            })
        })
    }
}

/// `/proc/stat`'s first line, in clock ticks since boot.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CpuTicks {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    interrupt: u64,
    steal: u64,
}

#[cfg(any(target_os = "linux", test))]
impl CpuTicks {
    fn parse(text: &str) -> Option<Self> {
        let line = text.lines().find(|line| line.starts_with("cpu "))?;
        let mut numbers = line.split_whitespace().skip(1).map(str::parse::<u64>);
        let mut next = || numbers.next()?.ok();
        let (user, nice, system, idle) = (next()?, next()?, next()?, next()?);
        let (iowait, irq, softirq) = (next()?, next()?, next()?);
        Some(Self {
            user,
            nice,
            system,
            idle,
            iowait,
            interrupt: irq + softirq,
            // Kernels before 2.6.11 don't have it, and neither do some containers.
            steal: next().unwrap_or(0),
        })
    }

    /// Percentages of the time between two readings. Nothing can be said if no
    /// time passed, or if the counters went backwards.
    fn percent_since(&self, old: &Self) -> Option<Value> {
        let spent = |new: u64, old: u64| new.checked_sub(old);
        let parts = [
            spent(self.user, old.user)?,
            spent(self.nice, old.nice)?,
            spent(self.system, old.system)?,
            spent(self.idle, old.idle)?,
            spent(self.iowait, old.iowait)?,
            spent(self.interrupt, old.interrupt)?,
            spent(self.steal, old.steal)?,
        ];
        let total: u64 = parts.iter().sum();
        if total == 0 {
            return None;
        }
        let percent = |part: u64| part as f64 * 100.0 / total as f64;
        Some(json!({
            "user": percent(parts[0]),
            "nice": percent(parts[1]),
            "system": percent(parts[2]),
            "idle": percent(parts[3]),
            "iowait": percent(parts[4]),
            "interrupt": percent(parts[5]),
            "steal": percent(parts[6]),
        }))
    }
}

/// Measures how CPU time is spent between one call and the next.
#[cfg(target_os = "linux")]
pub struct CpuTime {
    previous: Option<CpuTicks>,
}

#[cfg(target_os = "linux")]
impl CpuTime {
    pub fn new() -> Self {
        Self {
            previous: Self::read(),
        }
    }

    fn read() -> Option<CpuTicks> {
        CpuTicks::parse(&std::fs::read_to_string("/proc/stat").ok()?)
    }

    pub fn measure(&mut self) -> Option<Value> {
        let now = Self::read();
        let time = now
            .zip(self.previous)
            .and_then(|(new, old)| new.percent_since(&old));
        self.previous = now;
        time
    }
}

/// Reads `/proc/stat`'s `ctxt` and `intr` lines. The first number on `intr` is
/// the total, and the rest are per interrupt.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(text: &str) -> (Option<u64>, Option<u64>) {
    let total = |wanted: &str| {
        text.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(wanted)).then(|| words.next()?.parse().ok())?
        })
    };
    (total("ctxt"), total("intr"))
}

/// Reads `/proc/vmstat`'s swap lines, as pages swapped in and out.
#[cfg(any(target_os = "linux", test))]
fn parse_vmstat(text: &str) -> (Option<u64>, Option<u64>) {
    let total = |wanted: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == wanted).then(|| value.trim().parse().ok())?
        })
    };
    (total("pswpin"), total("pswpout"))
}

/// Reads `/proc/loadavg`, whose fourth field is `running/total`. Linux counts every
/// thread here, and it's threads that its limits apply to.
#[cfg(any(target_os = "linux", test))]
fn parse_task_count(text: &str) -> Option<u64> {
    text.split_whitespace()
        .nth(3)?
        .split_once('/')?
        .1
        .parse()
        .ok()
}

/// Reads `/proc/sys/fs/file-nr`, which holds what's allocated, how much of that
/// is unused, and the limit.
#[cfg(any(target_os = "linux", test))]
fn parse_file_nr(text: &str) -> Option<u64> {
    let mut numbers = text.split_whitespace().map(str::parse::<u64>);
    let allocated = numbers.next()?.ok()?;
    let unused = numbers.next()?.ok()?;
    Some(allocated.saturating_sub(unused))
}

#[cfg(target_os = "linux")]
pub fn counters() -> Counters {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let (context_switches, interrupts) = parse_proc_stat(&read("/proc/stat"));
    let (swap_in_pages, swap_out_pages) = parse_vmstat(&read("/proc/vmstat"));
    Counters {
        context_switches,
        interrupts,
        swap_in_pages,
        swap_out_pages,
    }
}

#[cfg(target_os = "linux")]
fn limits() -> Limits {
    let number = |path: &str| std::fs::read_to_string(path).ok()?.trim().parse().ok();
    Limits {
        max_open_files: number("/proc/sys/fs/file-max"),
        open_files: std::fs::read_to_string("/proc/sys/fs/file-nr")
            .ok()
            .and_then(|text| parse_file_nr(&text)),
        // Whichever runs out first.
        max_processes: [
            number("/proc/sys/kernel/pid_max"),
            number("/proc/sys/kernel/threads-max"),
        ]
        .into_iter()
        .flatten()
        .min(),
        processes: std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|text| parse_task_count(&text)),
    }
}

#[cfg(not(target_os = "linux"))]
fn process_count() -> Option<u64> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};

    let mut system = sysinfo::System::new().ok()?;
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    Some(system.processes().len() as u64)
}

/// Reads a whole number, whichever size the kernel declares it as.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn sysctl_number(name: &str) -> Option<u64> {
    use sysctl::{Ctl, CtlValue, Sysctl};

    match Ctl::new(name).ok()?.value().ok()? {
        CtlValue::Int(value) | CtlValue::S32(value) => value.try_into().ok(),
        CtlValue::Long(value) | CtlValue::S64(value) => value.try_into().ok(),
        CtlValue::Uint(value) | CtlValue::U32(value) => Some(value.into()),
        CtlValue::Ulong(value) | CtlValue::U64(value) => Some(value),
        _ => None,
    }
}

#[cfg(target_os = "freebsd")]
pub fn counters() -> Counters {
    Counters {
        context_switches: sysctl_number("vm.stats.sys.v_swtch"),
        interrupts: sysctl_number("vm.stats.sys.v_intr"),
        swap_in_pages: sysctl_number("vm.stats.vm.v_swappgsin"),
        swap_out_pages: sysctl_number("vm.stats.vm.v_swappgsout"),
    }
}

#[cfg(target_os = "freebsd")]
fn limits() -> Limits {
    Limits {
        max_open_files: sysctl_number("kern.maxfiles"),
        open_files: sysctl_number("kern.openfiles"),
        max_processes: sysctl_number("kern.maxproc"),
        processes: process_count(),
    }
}

#[cfg(target_os = "macos")]
fn limits() -> Limits {
    Limits {
        max_open_files: sysctl_number("kern.maxfiles"),
        open_files: sysctl_number("kern.num_files"),
        max_processes: sysctl_number("kern.maxproc"),
        processes: process_count(),
    }
}

/// macOS has no system-wide count of these, and Windows only has them as
/// performance counters.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub fn counters() -> Counters {
    Counters::default()
}

/// Windows has no system-wide limits like these.
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn limits() -> Limits {
    Limits {
        processes: process_count(),
        ..Limits::default()
    }
}

/// What memory is being used for, in the categories each system keeps.
pub fn memory_detail(stats: &System) -> Option<Value> {
    Some(describe_memory(&stats.memory().ok()?.platform_memory))
}

#[cfg(target_os = "linux")]
fn describe_memory(memory: &systemstat::PlatformMemory) -> Value {
    let bytes = |name: &str| memory.meminfo.get(name).map(|size| size.as_u64());
    json!({
        "active_bytes": bytes("Active"),
        "inactive_bytes": bytes("Inactive"),
        "free_bytes": bytes("MemFree"),
        "cached_bytes": bytes("Cached"),
        "buffers_bytes": bytes("Buffers"),
        "slab_bytes": bytes("Slab"),
        "shared_bytes": bytes("Shmem"),
    })
}

#[cfg(target_os = "macos")]
fn describe_memory(memory: &systemstat::PlatformMemory) -> Value {
    json!({
        "active_bytes": memory.active.as_u64(),
        "inactive_bytes": memory.inactive.as_u64(),
        "wired_bytes": memory.wired.as_u64(),
        "free_bytes": memory.free.as_u64(),
        "compressed_bytes": memory.compressor.as_u64(),
        "speculative_bytes": memory.speculative.as_u64(),
        "purgeable_bytes": memory.purgeable.as_u64(),
    })
}

#[cfg(target_os = "freebsd")]
fn describe_memory(memory: &systemstat::PlatformMemory) -> Value {
    json!({
        "active_bytes": memory.active.as_u64(),
        "inactive_bytes": memory.inactive.as_u64(),
        "wired_bytes": memory.wired.as_u64(),
        "free_bytes": memory.free.as_u64(),
        "cached_bytes": memory.cache.as_u64(),
        "zfs_arc_bytes": memory.zfs_arc.as_u64(),
    })
}

#[cfg(windows)]
fn describe_memory(memory: &systemstat::PlatformMemory) -> Value {
    let page_file = memory.total_pagefile.as_u64();
    json!({
        "free_bytes": memory.avail_phys.as_u64(),
        "page_file_bytes": page_file.saturating_sub(memory.avail_pagefile.as_u64()),
    })
}

/// `who` prints one line per session, so one person with two terminals counts
/// twice.
#[cfg(any(unix, test))]
fn count_who(output: &str) -> u64 {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u64
}

/// `quser` prints a heading and then one line per session, in the system's
/// language. With nobody logged in it prints nothing to standard output.
#[cfg(any(windows, test))]
fn count_quser(output: &str) -> u64 {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .skip(1)
        .count() as u64
}

async fn run_quietly(program: &str) -> Option<std::process::Output> {
    let run = Command::new(program)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    timeout(SESSIONS_TIMEOUT, run).await.ok()?.ok()
}

#[cfg(unix)]
async fn login_sessions() -> Option<u64> {
    let output = run_quietly("who").await?;
    output
        .status
        .success()
        .then(|| count_who(&String::from_utf8_lossy(&output.stdout)))
}

/// Home editions don't have `quser`, which leaves this out. It also exits with
/// an error when nobody is logged in, so its exit code says nothing.
#[cfg(windows)]
async fn login_sessions() -> Option<u64> {
    let output = run_quietly("quser").await?;
    Some(count_quser(&String::from_utf8_lossy(&output.stdout)))
}

fn report(limits: &Limits, sessions: Option<u64>) -> Value {
    json!({
        "max_open_files": limits.max_open_files,
        "open_files": limits.open_files,
        "max_processes": limits.max_processes,
        "processes": limits.processes,
        "login_sessions": sessions,
    })
}

/// How close the machine is to its limits, and how many people are on it.
pub struct SystemCollector {
    background: Background,
}

impl SystemCollector {
    pub fn new(interval: Duration) -> Self {
        let background = Background::start(interval, || async {
            report(&limits(), login_sessions().await)
        });
        Self { background }
    }
}

impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_STAT: &str = "\
cpu  6168 11 2935 217451 351 0 96 0 0 0
cpu0 3047 5 1461 108790 175 0 53 0 0 0
intr 1234567 19 0 0 0 0 0
ctxt 7654321
btime 1762300000
processes 4242
procs_running 1
";

    const VMSTAT: &str = "\
nr_free_pages 123456
pswpin 42
pswpout 77
pgpgin 900
";

    #[test]
    fn proc_stat_gives_context_switches_and_the_interrupt_total() {
        assert_eq!(
            parse_proc_stat(PROC_STAT),
            (Some(7_654_321), Some(1_234_567))
        );
    }

    #[test]
    fn missing_or_broken_proc_stat_lines_are_left_out() {
        assert_eq!(parse_proc_stat(""), (None, None));
        assert_eq!(parse_proc_stat("ctxt nonsense\nintr"), (None, None));
    }

    #[test]
    fn vmstat_gives_pages_swapped_in_and_out() {
        assert_eq!(parse_vmstat(VMSTAT), (Some(42), Some(77)));
        assert_eq!(parse_vmstat("nr_free_pages 1"), (None, None));
    }

    #[test]
    fn similar_names_in_vmstat_are_not_confused() {
        assert_eq!(parse_vmstat("pswpin_extra 5\npswpin 6\n").0, Some(6));
    }

    #[test]
    fn cpu_ticks_are_read_from_the_whole_machine_line() {
        let ticks = CpuTicks::parse(PROC_STAT).unwrap();
        assert_eq!(ticks.user, 6168);
        assert_eq!(ticks.idle, 217_451);
        assert_eq!(ticks.iowait, 351);
        assert_eq!(ticks.interrupt, 96);
        assert_eq!(ticks.steal, 0);
        assert_eq!(CpuTicks::parse("cpu0 1 2 3 4 5 6 7 8"), None);
        assert_eq!(CpuTicks::parse("cpu  1 2 x"), None);
    }

    #[test]
    fn steal_is_the_eighth_number() {
        let ticks = CpuTicks::parse("cpu  1 2 3 4 5 6 7 8 9 10\n").unwrap();
        assert_eq!(ticks.steal, 8);
    }

    #[test]
    fn older_kernels_without_steal_still_work() {
        let ticks = CpuTicks::parse("cpu  1 2 3 4 5 6 7\n").unwrap();
        assert_eq!(ticks.interrupt, 13);
        assert_eq!(ticks.steal, 0);
    }

    #[test]
    fn cpu_time_includes_what_a_hypervisor_took() {
        let old = CpuTicks::default();
        let new = CpuTicks {
            user: 40,
            system: 10,
            idle: 20,
            iowait: 5,
            interrupt: 5,
            steal: 20,
            nice: 0,
        };
        let time = new.percent_since(&old).unwrap();
        assert_eq!(time["steal"], 20.0);
        assert_eq!(time["user"], 40.0);
        assert_eq!(time["iowait"], 5.0);
    }

    #[test]
    fn cpu_time_needs_time_to_have_passed_forwards() {
        let ticks = CpuTicks {
            user: 10,
            ..CpuTicks::default()
        };
        assert_eq!(ticks.percent_since(&ticks), None);
        assert_eq!(CpuTicks::default().percent_since(&ticks), None);
    }

    #[test]
    fn loadavg_gives_the_number_of_tasks() {
        assert_eq!(parse_task_count("0.20 0.18 0.12 1/80 11206\n"), Some(80));
        assert_eq!(parse_task_count("0.20 0.18 0.12"), None);
        assert_eq!(parse_task_count(""), None);
    }

    #[test]
    fn open_files_are_those_allocated_and_in_use() {
        assert_eq!(parse_file_nr("3168\t100\t1620200\n"), Some(3068));
        assert_eq!(parse_file_nr("5\t9\t100"), Some(0));
        assert_eq!(parse_file_nr("nonsense"), None);
        assert_eq!(parse_file_nr(""), None);
    }

    #[test]
    fn change_is_measured_from_the_previous_reading() {
        let mut change = Change::default();
        assert_eq!(change.update(Some(100)), None);
        assert_eq!(change.update(Some(130)), Some(30));
        assert_eq!(change.update(Some(130)), Some(0));
    }

    #[test]
    fn a_counter_going_backwards_is_no_change() {
        let mut change = Change::default();
        change.update(Some(100));
        assert_eq!(change.update(Some(5)), Some(0));
        assert_eq!(change.update(Some(8)), Some(3));
    }

    #[test]
    fn a_missing_reading_starts_over() {
        let mut change = Change::default();
        change.update(Some(100));
        assert_eq!(change.update(None), None);
        assert_eq!(change.update(Some(200)), None);
    }

    #[test]
    fn who_prints_a_line_per_login() {
        assert_eq!(count_who(""), 0);
        let output = "sam console Nov  4 09:00\nsam ttys001 Nov  4 09:30\n\n";
        assert_eq!(count_who(output), 2);
    }

    #[test]
    fn quser_prints_a_heading_first() {
        assert_eq!(count_quser(""), 0);
        let output = " USERNAME  SESSIONNAME  ID  STATE\n>sam  console  1  Active\n";
        assert_eq!(count_quser(output), 1);
    }

    #[test]
    fn nothing_is_reported_as_zero_when_a_platform_lacks_it() {
        let report = report(&Limits::default(), None);
        assert_eq!(report["max_open_files"], Value::Null);
        assert_eq!(report["login_sessions"], Value::Null);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_mac_reports_real_limits() {
        let limits = limits();
        let open = limits.open_files.unwrap();
        assert!(
            open > 0 && open < limits.max_open_files.unwrap(),
            "{limits:?}"
        );
        let processes = limits.processes.unwrap();
        assert!(
            processes > 1 && processes < limits.max_processes.unwrap(),
            "{limits:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_macs_memory_categories_fit_inside_its_memory() {
        let detail = memory_detail(&System::new()).unwrap();
        let bytes = |name: &str| detail[name].as_u64().unwrap();
        let total = sysctl_number("hw.memsize").unwrap();
        let counted = bytes("active_bytes")
            + bytes("inactive_bytes")
            + bytes("wired_bytes")
            + bytes("free_bytes")
            + bytes("compressed_bytes");
        assert!(counted > total / 2 && counted <= total, "{detail}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn this_machine_can_count_its_login_sessions() {
        assert!(login_sessions().await.is_some());
    }
}
