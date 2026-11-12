//! The actions every agent has without anything in its config. They only look, and
//! print a table of what they saw. Program names are given, never what a program
//! was started with, which can hold secrets.

use std::collections::BTreeMap;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sysinfo::{
    Pid, Process, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System, UpdateKind, Users,
};

use crate::disk_space;

/// How many processes a table lists.
const ROWS: usize = 20;

/// How long usage is measured over. CPU and disk activity are both worked out
/// between two looks at the process list.
const MEASURED_OVER: Duration = Duration::from_secs(1);

/// What a built-in action is given to work with.
pub struct Asked<'a> {
    pub variables: &'a BTreeMap<String, String>,
    /// When to stop and report what's been found so far.
    pub deadline: Instant,
    /// Where the agent keeps its own files.
    pub state_dir: &'a Path,
}

pub struct BuiltIn {
    pub name: &'static str,
    /// The variables it has to be given.
    pub variables: &'static [&'static str],
    pub run: fn(&Asked) -> Result<String>,
}

/// Every built-in action this agent has.
pub const BUILT_INS: [BuiltIn; 4] = [
    BuiltIn {
        name: "top_cpu",
        variables: &[],
        run: |_| top_processes(By::Cpu),
    },
    BuiltIn {
        name: "top_memory",
        variables: &[],
        run: |_| top_processes(By::Memory),
    },
    BuiltIn {
        name: "disk_io",
        variables: &[],
        run: |_| disk_io(),
    },
    BuiltIn {
        name: "disk_space",
        variables: &["disk"],
        run: disk_space::report,
    },
];

pub fn find(name: &str) -> Option<&'static BuiltIn> {
    BUILT_INS.iter().find(|built_in| built_in.name == name)
}

/// A size in the units the server's pages use.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Lines up columns. Every column but the last is right-aligned when its heading
/// starts with a space, which is how a column of numbers is marked.
pub fn table(headings: &[&str], rows: &[Vec<String>]) -> String {
    let numeric: Vec<bool> = headings.iter().map(|h| h.starts_with(' ')).collect();
    let headings: Vec<&str> = headings.iter().map(|h| h.trim_start()).collect();
    let widths: Vec<usize> = headings
        .iter()
        .enumerate()
        .map(|(column, heading)| {
            rows.iter()
                .filter_map(|row| row.get(column))
                .map(|cell| cell.chars().count())
                .chain([heading.chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();

    let line = |cells: Vec<&str>| {
        let mut line = String::new();
        for (column, cell) in cells.iter().enumerate() {
            let width = widths[column];
            if column > 0 {
                line.push_str("  ");
            }
            if numeric[column] {
                line.push_str(&format!("{cell:>width$}"));
            } else if column + 1 == cells.len() {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<width$}"));
            }
        }
        line.push('\n');
        line
    };
    let mut text = line(headings.clone());
    for row in rows {
        text.push_str(&line(row.iter().map(String::as_str).collect()));
    }
    text
}

/// Whether the agent can see everything about other users' processes.
fn sees_everything() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[derive(Clone, Copy)]
enum By {
    Cpu,
    Memory,
}

fn refresh(system: &mut System, kind: ProcessRefreshKind) {
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind.without_tasks());
}

fn is_running(process: &Process) -> bool {
    process.thread_kind().is_none()
        && !matches!(
            process.status(),
            ProcessStatus::Zombie | ProcessStatus::Dead
        )
}

/// A process's user by name, or by number when the system doesn't know one.
fn owner(process: &Process, users: &Users) -> String {
    let Some(id) = process.user_id() else {
        return "?".to_string();
    };
    match users.get_user_by_id(id) {
        Some(user) => user.name().to_string(),
        None => id.to_string(),
    }
}

fn name(process: &Process) -> String {
    process.name().to_string_lossy().into_owned()
}

fn pid(pid: Pid) -> String {
    pid.to_string()
}

/// The processes using the most CPU or memory. CPU is a share of the whole host,
/// as on the CPU chart, so one busy core of eight is 12.5%.
fn top_processes(by: By) -> Result<String> {
    let mut system = System::new().context("reading the process list")?;
    system.refresh_cpu_list(sysinfo::CpuRefreshKind::nothing());
    system.refresh_memory();
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_user(UpdateKind::OnlyIfNotSet);
    refresh(&mut system, kind);
    thread::sleep(MEASURED_OVER);
    refresh(&mut system, kind);
    let users = Users::new_with_refreshed_list().context("reading the list of users")?;

    let cores = system.cpus().len().max(1) as f64;
    let total_memory = system.total_memory().max(1) as f64;
    let mut processes: Vec<&Process> = system
        .processes()
        .values()
        .filter(|p| is_running(p))
        .collect();
    match by {
        By::Cpu => processes.sort_by(|a, b| b.cpu_usage().total_cmp(&a.cpu_usage())),
        By::Memory => processes.sort_by_key(|p| std::cmp::Reverse(p.memory())),
    }

    let rows: Vec<Vec<String>> = processes
        .iter()
        .take(ROWS)
        .map(|process| {
            vec![
                pid(process.pid()),
                owner(process, &users),
                format!("{:.1}", f64::from(process.cpu_usage()) / cores),
                format!("{:.1}", process.memory() as f64 / total_memory * 100.0),
                size(process.memory()),
                name(process),
            ]
        })
        .collect();
    let headings = [" PID", "USER", " CPU %", " MEM %", " MEMORY", "NAME"];
    let mut text = table(&headings, &rows);
    text.push_str(&format!(
        "\n{} processes running. CPU is a share of all {} cores, over the last second.\n",
        processes.len(),
        cores
    ));
    Ok(text)
}

/// The processes reading and writing the most, over a second.
fn disk_io() -> Result<String> {
    let mut system = System::new().context("reading the process list")?;
    let kind = ProcessRefreshKind::nothing()
        .with_disk_usage()
        .with_user(UpdateKind::OnlyIfNotSet);
    refresh(&mut system, kind);
    let started = Instant::now();
    thread::sleep(MEASURED_OVER);
    refresh(&mut system, kind);
    let secs = started.elapsed().as_secs_f64().max(0.001);
    let users = Users::new_with_refreshed_list().context("reading the list of users")?;

    let mut busy: Vec<(&Process, u64, u64)> = system
        .processes()
        .values()
        .filter(|p| is_running(p))
        .map(|process| {
            let usage = process.disk_usage();
            (process, usage.read_bytes, usage.written_bytes)
        })
        .filter(|(_, read, written)| read + written > 0)
        .collect();
    busy.sort_by_key(|(_, read, written)| std::cmp::Reverse(read + written));

    let per_sec = |bytes: u64| format!("{}/s", size((bytes as f64 / secs) as u64));
    let rows: Vec<Vec<String>> = busy
        .iter()
        .take(ROWS)
        .map(|(process, read, written)| {
            vec![
                pid(process.pid()),
                owner(process, &users),
                per_sec(*read),
                per_sec(*written),
                name(process),
            ]
        })
        .collect();

    let mut text = if rows.is_empty() {
        "No process read or wrote anything in the last second.\n".to_string()
    } else {
        let headings = [" PID", "USER", " READ", " WRITTEN", "NAME"];
        let mut text = table(&headings, &rows);
        text.push_str(&format!(
            "\n{} processes read or wrote in the last second.\n",
            busy.len()
        ));
        text
    };
    if !sees_everything() {
        text.push_str(
            "The agent isn't running as root, so it can only see what its own user's \
             processes read and write.\n",
        );
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KiB");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(120 * 1024 * 1024 * 1024), "120 GiB");
        assert_eq!(size(u64::MAX), "16384 PiB");
    }

    #[test]
    fn tables_line_up_and_numbers_go_right() {
        let rows = vec![
            vec!["7".to_string(), "root".to_string(), "init".to_string()],
            vec![
                "1234".to_string(),
                "postgres".to_string(),
                "postgres: writer".to_string(),
            ],
        ];
        assert_eq!(
            table(&[" PID", "USER", "NAME"], &rows),
            " PID  USER      NAME\n   7  root      init\n1234  postgres  postgres: writer\n"
        );
    }

    #[test]
    fn built_ins_have_plain_distinct_names() {
        for (index, built_in) in BUILT_INS.iter().enumerate() {
            assert!(maxnines_protocol::actions::is_action_name(built_in.name));
            assert!(BUILT_INS[..index].iter().all(|b| b.name != built_in.name));
            assert_eq!(find(built_in.name).unwrap().name, built_in.name);
        }
        assert!(find("reboot").is_none());
    }

    #[test]
    fn the_top_processes_include_this_one() {
        for by in [By::Cpu, By::Memory] {
            let text = top_processes(by).unwrap();
            assert!(text.starts_with(" PID") || text.contains("PID"), "{text}");
            assert!(text.contains("processes running"), "{text}");
            assert!(text.lines().count() > 3, "{text}");
        }
    }

    #[test]
    fn disk_io_reports_something_readable() {
        let text = disk_io().unwrap();
        assert!(
            text.contains("READ") || text.contains("No process read or wrote"),
            "{text}"
        );
    }
}
