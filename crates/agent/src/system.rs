//! What only the operating system can say about itself, which differs by
//! platform. `systemstat` covers CPU time and memory, and the rest comes from
//! `/proc` on Linux and `sysctl` on macOS and FreeBSD.
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
        max_processes: number("/proc/sys/kernel/pid_max"),
    }
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
    }
}

#[cfg(target_os = "macos")]
fn limits() -> Limits {
    Limits {
        max_open_files: sysctl_number("kern.maxfiles"),
        open_files: sysctl_number("kern.num_files"),
        max_processes: sysctl_number("kern.maxproc"),
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
    Limits::default()
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
        assert!(limits.max_processes.unwrap() > 0, "{limits:?}");
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
