//! The `disk_space` action: where the space on a disk is going.
//!
//! It stops by size rather than by depth. The whole disk is read once, and any
//! folder holding a fair share of what's used gets a line of its own, however deep
//! it is, while smaller ones are counted in the folder above. So one huge folder
//! six levels down is found, and a folder of three hundred small ones is one line.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, Metadata, ReadDir};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::builtin_actions::{Asked, size, table};

/// A folder gets its own line when it holds this share of what's used.
const OWN_LINE_SHARE: f64 = 0.02;
/// How many folders are listed, biggest first.
const MAX_LINES: usize = 10;
/// Folders nested deeper than this aren't opened, which also limits how many are
/// open at once.
const MAX_DEPTH: usize = 256;
/// How often the clock is looked at, in files.
const DEADLINE_CHECK_EVERY: u64 = 256;
/// How many unreadable folders and held-open files are named.
const NAMED: usize = 5;
/// Space this small isn't worth a line saying it's missing.
const NOTICEABLE_SHARE: f64 = 0.01;

/// A folder worth a line of its own, and those inside it that are too.
#[derive(Debug)]
struct Folder {
    path: PathBuf,
    /// Everything in it, however deep.
    total: u64,
    inside: Vec<Folder>,
}

/// A folder that's being read.
struct Open {
    path: PathBuf,
    entries: ReadDir,
    /// Its files, and the folders in it too small for their own line.
    own: u64,
    inside: Vec<Folder>,
}

#[derive(Debug)]
struct Scan {
    root: Folder,
    files: u64,
    unreadable: u64,
    /// The first few that couldn't be read.
    unreadable_named: Vec<PathBuf>,
    /// Whether it ran out of time, which leaves the sizes too small.
    stopped: bool,
}

/// Which disk something is on, where the system says.
#[cfg(unix)]
fn disk_of(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev()
}

#[cfg(not(unix))]
fn disk_of(_metadata: &Metadata) -> u64 {
    0
}

/// What something takes up on disk, counting a file with several names once.
#[cfg(unix)]
fn space_used(metadata: &Metadata, linked: &mut HashSet<u64>) -> u64 {
    use std::os::unix::fs::MetadataExt;
    /// How many files with several names are remembered, to count each once.
    const MAX_LINKED_FILES: usize = 1_000_000;

    if !metadata.is_dir() && metadata.nlink() > 1 {
        let first = linked.len() < MAX_LINKED_FILES && linked.insert(metadata.ino());
        if !first {
            return 0;
        }
    }
    // Blocks rather than length, so a sparse file counts for what it really holds.
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn space_used(metadata: &Metadata, _linked: &mut HashSet<u64>) -> u64 {
    if metadata.is_file() {
        metadata.len()
    } else {
        0
    }
}

/// Reads everything under `root` that's on the same disk, without following links.
///
/// Only folders of at least `own_line` are kept apart, which is what stops a disk
/// of millions of folders from filling the agent's memory. When how much is used
/// isn't known, that's a share of what's been found so far instead. It only grows,
/// so nothing big enough in the end is ever folded away, and the number kept apart
/// stays small, as each one has to be a share of everything before it.
fn scan(root: &Path, own_line: Option<u64>, deadline: Instant) -> Result<Scan> {
    let disk = disk_of(&fs::metadata(root)?);
    let entries = fs::read_dir(root)?;
    let mut open = vec![Open {
        path: root.to_path_buf(),
        entries,
        own: 0,
        inside: Vec::new(),
    }];
    let mut linked = HashSet::new();
    let mut found: u64 = 0;
    let mut scan = Scan {
        root: Folder {
            path: root.to_path_buf(),
            total: 0,
            inside: Vec::new(),
        },
        files: 0,
        unreadable: 0,
        unreadable_named: Vec::new(),
        stopped: false,
    };
    let unreadable = |scan: &mut Scan, path: PathBuf| {
        scan.unreadable += 1;
        if scan.unreadable_named.len() < NAMED {
            scan.unreadable_named.push(path);
        }
    };

    loop {
        let depth = open.len();
        let Some(folder) = open.last_mut() else { break };
        let next = if scan.stopped {
            None
        } else {
            folder.entries.next()
        };
        let Some(entry) = next else {
            // Finished: it becomes a line of its own, or part of the folder above.
            let Some(done) = open.pop() else { break };
            let total = done.own + done.inside.iter().map(|f| f.total).sum::<u64>();
            let done = Folder {
                path: done.path,
                total,
                inside: done.inside,
            };
            let own_line = own_line
                .unwrap_or((found as f64 * OWN_LINE_SHARE) as u64)
                .max(1);
            match open.last_mut() {
                Some(above) if total >= own_line => above.inside.push(done),
                Some(above) => above.own += total,
                None => scan.root = done,
            }
            continue;
        };

        scan.files += 1;
        if scan.files.is_multiple_of(DEADLINE_CHECK_EVERY) && Instant::now() >= deadline {
            scan.stopped = true;
            continue;
        }
        let Ok(entry) = entry else { continue };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        // Another disk mounted here is a different disk's space.
        if disk_of(&metadata) != disk {
            continue;
        }
        let space = space_used(&metadata, &mut linked);
        folder.own += space;
        found = found.saturating_add(space);
        if !metadata.is_dir() {
            continue;
        }
        let path = entry.path();
        if depth >= MAX_DEPTH {
            unreadable(&mut scan, path);
            continue;
        }
        match fs::read_dir(&path) {
            Ok(entries) => open.push(Open {
                path,
                entries,
                own: 0,
                inside: Vec::new(),
            }),
            Err(_) => unreadable(&mut scan, path),
        }
    }
    Ok(scan)
}

/// One line of the report.
#[derive(Debug, PartialEq)]
struct Line {
    path: PathBuf,
    /// What's in it, apart from folders with lines of their own.
    own: u64,
    /// Everything in it, for comparing with last time.
    total: u64,
}

fn lines(folder: &Folder, found: &mut Vec<Line>) {
    let inside: u64 = folder.inside.iter().map(|f| f.total).sum();
    found.push(Line {
        path: folder.path.clone(),
        own: folder.total.saturating_sub(inside),
        total: folder.total,
    });
    for folder in &folder.inside {
        lines(folder, found);
    }
}

/// The biggest lines, each big enough to be worth one.
fn biggest(folder: &Folder, own_line: u64) -> Vec<Line> {
    let mut found = Vec::new();
    lines(folder, &mut found);
    found.retain(|line| line.own >= own_line);
    found.sort_by(|a, b| b.own.cmp(&a.own).then_with(|| a.path.cmp(&b.path)));
    found.truncate(MAX_LINES);
    found
}

/// Whether a disk is mounted at exactly this path, going by the system's own list,
/// which is also where disk alerts get their names.
#[cfg(unix)]
fn is_mounted_at(path: &Path) -> bool {
    sysinfo::Disks::new_with_refreshed_list()
        .is_ok_and(|disks| disks.iter().any(|disk| disk.mount_point() == path))
}

/// How much of a disk is used and how big it is, if `path` is where it's mounted.
/// For a folder inside a disk, the disk's numbers would say nothing about it.
#[cfg(unix)]
fn usage(path: &Path) -> Option<(u64, u64)> {
    if !is_mounted_at(path) {
        return None;
    }
    // Free rather than available space, so what's reserved for root isn't
    // reported as missing.
    let disk = rustix::fs::statvfs(path).ok()?;
    let total = disk.f_blocks.saturating_mul(disk.f_frsize);
    let free = disk.f_bfree.saturating_mul(disk.f_frsize);
    Some((total.saturating_sub(free), total))
}

#[cfg(not(unix))]
fn usage(path: &Path) -> Option<(u64, u64)> {
    let disks = sysinfo::Disks::new_with_refreshed_list().ok()?;
    let disk = disks.iter().find(|disk| disk.mount_point() == path)?;
    let total = disk.total_space();
    Some((total.saturating_sub(disk.available_space()), total))
}

/// A file that was deleted while a process still has it open, so its space isn't
/// freed. This is the usual reason a disk is full when its folders don't add up.
#[derive(Debug)]
struct HeldOpen {
    bytes: u64,
    pid: u32,
    process: String,
}

#[cfg(target_os = "linux")]
fn held_open(root: &Path, deadline: Instant) -> Vec<HeldOpen> {
    use std::os::unix::fs::MetadataExt;

    let Ok(disk) = fs::metadata(root).map(|metadata| metadata.dev()) else {
        return Vec::new();
    };
    let Ok(processes) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for process in processes.flatten() {
        if Instant::now() >= deadline {
            break;
        }
        let Some(pid) = process.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        // Another user's process can't be looked into without being root.
        let Ok(open_files) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for file in open_files.flatten() {
            let deleted = fs::read_link(file.path())
                .is_ok_and(|target| target.to_string_lossy().ends_with(" (deleted)"));
            if !deleted {
                continue;
            }
            let Ok(metadata) = fs::metadata(file.path()) else {
                continue;
            };
            let gone = metadata.is_file() && metadata.nlink() == 0 && metadata.dev() == disk;
            if gone && seen.insert(metadata.ino()) {
                let name = fs::read_to_string(process.path().join("comm")).unwrap_or_default();
                found.push(HeldOpen {
                    bytes: metadata.blocks().saturating_mul(512),
                    pid,
                    process: name.trim().to_string(),
                });
            }
        }
    }
    found.sort_by_key(|file| std::cmp::Reverse(file.bytes));
    found
}

#[cfg(not(target_os = "linux"))]
fn held_open(_root: &Path, _deadline: Instant) -> Vec<HeldOpen> {
    Vec::new()
}

/// What the last look at each disk found, kept to say what's grown since.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Remembered {
    #[serde(default)]
    disks: BTreeMap<String, Earlier>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Earlier {
    at_ms: u64,
    /// Everything in each folder that had a line.
    totals: BTreeMap<String, u64>,
}

fn remembered_file(state_dir: &Path) -> PathBuf {
    state_dir.join("disk_space.json")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// How long ago, roughly, in words.
fn ago(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let (count, unit) = match secs {
        0..60 => (secs.max(1), "second"),
        60..3600 => (secs / 60, "minute"),
        3600..172_800 => (secs / 3600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    format!("{count} {unit}{}", if count == 1 { "" } else { "s" })
}

/// How a folder has changed since last time, if it was seen then.
fn change(now: u64, earlier: Option<&Earlier>, path: &str) -> String {
    let Some(earlier) = earlier else {
        return String::new();
    };
    match earlier.totals.get(path) {
        None => "new".to_string(),
        Some(before) if now > *before => format!("+{}", size(now - before)),
        Some(before) if now < *before => format!("-{}", size(before - now)),
        Some(_) => "same".to_string(),
    }
}

/// A number of things, in words.
fn count(number: u64, thing: &str) -> String {
    format!("{number} {thing}{}", if number == 1 { "" } else { "s" })
}

fn share(part: u64, whole: u64) -> String {
    format!("{:.0}%", part as f64 / whole.max(1) as f64 * 100.0)
}

/// Puts everything that was found into words.
fn describe(
    root: &Path,
    scan: &Scan,
    usage: Option<(u64, u64)>,
    own_line: u64,
    earlier: Option<&Earlier>,
    held: &[HeldOpen],
    took: Duration,
) -> String {
    let found = scan.root.total;
    // Shares are of what's used, or of what was found when that isn't known.
    let whole = usage.map_or(found, |(used, _)| used.max(found));
    let shown = biggest(&scan.root, own_line);

    let mut rows: Vec<Vec<String>> = shown
        .iter()
        .map(|line| {
            let path = line.path.to_string_lossy().into_owned();
            vec![
                size(line.own),
                share(line.own, whole),
                change(line.total, earlier, &path),
                path,
            ]
        })
        .collect();
    let rest = found.saturating_sub(shown.iter().map(|line| line.own).sum());
    if rest > 0 {
        rows.push(vec![
            size(rest),
            share(rest, whole),
            String::new(),
            "everything else, in smaller pieces".to_string(),
        ]);
    }
    let missing = whole.saturating_sub(found);
    if missing as f64 >= whole as f64 * NOTICEABLE_SHARE {
        rows.push(vec![
            size(missing),
            share(missing, whole),
            String::new(),
            "not accounted for".to_string(),
        ]);
    }

    let mut text = match usage {
        Some((used, total)) => format!(
            "{}: {} used of {}\n\n",
            root.display(),
            size(used),
            size(total)
        ),
        None => format!("{}: {} found\n\n", root.display(), size(found)),
    };
    if earlier.is_some() {
        text.push_str(&table(&[" SIZE", " SHARE", " CHANGE", "PATH"], &rows));
    } else {
        for row in &mut rows {
            row.remove(2);
        }
        text.push_str(&table(&[" SIZE", " SHARE", "PATH"], &rows));
    }

    text.push_str("\nA folder's size leaves out any folder listed on a line of its own.\n");
    if let Some(earlier) = earlier {
        let since = Duration::from_millis(now_ms().saturating_sub(earlier.at_ms));
        text.push_str(&format!(
            "Changes are since the last look, {} ago, and count everything in the folder.\n",
            ago(since)
        ));
    }
    text.push_str(&format!(
        "Read {} in {}.\n",
        count(scan.files, "file and folder").replace("file and folders", "files and folders"),
        ago(took)
    ));
    if scan.stopped {
        text.push_str(
            "It ran out of time before reading everything, so the sizes are at least this \
             much. Give the action longer to read it all.\n",
        );
    }
    if scan.unreadable > 0 {
        let named: Vec<String> = scan
            .unreadable_named
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        let more = scan.unreadable - named.len() as u64;
        text.push_str(&format!(
            "The agent's user couldn't read {}, so what's in them isn't counted: {}{}.\n",
            count(scan.unreadable, "folder"),
            named.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        ));
    }
    if !held.is_empty() {
        let total: u64 = held.iter().map(|file| file.bytes).sum();
        text.push_str(&format!(
            "\n{} in {} is still held open, and is only freed when these processes close \
             them or stop:\n\n",
            size(total),
            count(held.len() as u64, "deleted file")
        ));
        let rows: Vec<Vec<String>> = held
            .iter()
            .take(NAMED)
            .map(|file| vec![size(file.bytes), file.pid.to_string(), file.process.clone()])
            .collect();
        text.push_str(&table(&[" SIZE", " PID", "NAME"], &rows));
    }
    text
}

pub fn report(asked: &Asked) -> Result<String> {
    let root = asked
        .variables
        .get("disk")
        .context("it needs {disk}, which it wasn't given")?;
    let root = Path::new(root);
    ensure!(root.is_absolute(), "{} isn't a full path", root.display());
    ensure!(root.is_dir(), "{} isn't a folder", root.display());

    let started = Instant::now();
    let usage = usage(root);
    let share_of = |whole: u64| ((whole as f64 * OWN_LINE_SHARE) as u64).max(1);
    let scan = scan(root, usage.map(|(used, _)| share_of(used)), asked.deadline)
        .with_context(|| format!("reading {}", root.display()))?;
    let own_line = share_of(usage.map_or(scan.root.total, |(used, _)| used));
    let held = held_open(root, asked.deadline);

    let file = remembered_file(asked.state_dir);
    let mut remembered: Remembered = fs::read(&file)
        .ok()
        .and_then(|saved| serde_json::from_slice(&saved).ok())
        .unwrap_or_default();
    let name = root.to_string_lossy().into_owned();
    let text = describe(
        root,
        &scan,
        usage,
        own_line,
        remembered.disks.get(&name),
        &held,
        started.elapsed(),
    );

    // A look that ran out of time would make everything seem to have shrunk.
    if !scan.stopped {
        let mut found = Vec::new();
        lines(&scan.root, &mut found);
        let totals = found
            .into_iter()
            .map(|line| (line.path.to_string_lossy().into_owned(), line.total))
            .collect();
        let at_ms = now_ms();
        remembered.disks.insert(name, Earlier { at_ms, totals });
        // Only the comparison next time is lost if this can't be saved.
        if let Ok(saved) = serde_json::to_vec(&remembered) {
            let _ = fs::write(&file, saved);
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// A file that really takes up about this much.
    fn file(path: &Path, kib: u64) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![7u8; (kib * KIB) as usize]).unwrap();
    }

    fn names(lines: &[Line], root: &Path) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                let inside = line.path.strip_prefix(root).unwrap();
                inside.to_string_lossy().replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn a_big_folder_gets_a_line_however_deep_and_small_ones_are_folded_in() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        file(&root.join("var/lib/docker/overlay/abc/diff/big"), 900);
        file(&root.join("var/log/journal/a"), 400);
        for user in 0..30 {
            file(&root.join(format!("home/user{user}/notes")), 16);
        }
        file(&root.join("etc/config"), 4);

        let scan = scan(root, Some(200 * KIB), later()).unwrap();
        assert!(!scan.stopped);
        assert_eq!(scan.unreadable, 0);
        let shown = biggest(&scan.root, 200 * KIB);
        assert_eq!(
            names(&shown, root),
            ["var/lib/docker/overlay/abc/diff", "home", "var/log/journal"]
        );
        // Six levels of folders holding one big one collapse into its line.
        assert!(shown[0].own >= 900 * KIB);
        assert!(shown[1].own >= 30 * 16 * KIB);
        // Everything is counted somewhere.
        assert!(scan.root.total >= (900 + 400 + 480 + 4) * KIB);
        let listed: u64 = shown.iter().map(|line| line.own).sum();
        assert!(scan.root.total - listed < 200 * KIB);
    }

    #[test]
    fn only_the_biggest_few_are_listed() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        for number in 0..MAX_LINES + 5 {
            file(
                &root.join(format!("d{number:02}/f")),
                64 + number as u64 * 8,
            );
        }
        let scan = scan(root, Some(32 * KIB), later()).unwrap();
        let shown = biggest(&scan.root, 32 * KIB);
        assert_eq!(shown.len(), MAX_LINES);
        assert_eq!(names(&shown, root)[0], format!("d{:02}", MAX_LINES + 4));
        assert!(shown.windows(2).all(|pair| pair[0].own >= pair[1].own));
    }

    #[cfg(unix)]
    #[test]
    fn links_are_not_followed_and_a_file_with_two_names_counts_once() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        let elsewhere = tempfile::tempdir().unwrap();
        file(&elsewhere.path().join("huge"), 800);
        file(&root.join("data/real"), 300);
        fs::hard_link(root.join("data/real"), root.join("data/again")).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), root.join("link")).unwrap();

        let scan = scan(root, Some(100 * KIB), later()).unwrap();
        assert!(scan.root.total >= 300 * KIB);
        assert!(scan.root.total < 500 * KIB, "{}", scan.root.total);
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_that_cannot_be_read_is_named() {
        use std::os::unix::fs::PermissionsExt;

        // Root can read anything, so there's nothing to see.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        file(&root.join("private/secret"), 64);
        fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o000)).unwrap();

        let scan = scan(root, Some(KIB), later()).unwrap();
        fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(scan.unreadable, 1);
        assert_eq!(scan.unreadable_named, [root.join("private")]);
        let text = describe(root, &scan, None, KIB, None, &[], Duration::from_secs(2));
        assert!(text.contains("couldn't read 1 folder,"), "{text}");
    }

    #[test]
    fn running_out_of_time_reports_what_was_read() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        for number in 0..DEADLINE_CHECK_EVERY * 3 {
            fs::write(root.join(format!("f{number}")), b"x").unwrap();
        }
        let scan = scan(root, None, Instant::now()).unwrap();
        assert!(scan.stopped);
        assert!(scan.files < DEADLINE_CHECK_EVERY * 3);
        let text = describe(root, &scan, None, KIB, None, &[], Duration::from_secs(2));
        assert!(text.contains("ran out of time"), "{text}");
    }

    #[test]
    fn the_report_adds_up_and_names_what_is_missing() {
        let root = Path::new("/data");
        let scan = Scan {
            root: Folder {
                path: root.to_path_buf(),
                total: 700,
                inside: vec![Folder {
                    path: PathBuf::from("/data/big"),
                    total: 500,
                    inside: Vec::new(),
                }],
            },
            files: 12,
            unreadable: 0,
            unreadable_named: Vec::new(),
            stopped: false,
        };
        let held = [HeldOpen {
            bytes: 4096,
            pid: 77,
            process: "rsyslogd".to_string(),
        }];
        let took = Duration::from_secs(3);
        let text = describe(root, &scan, Some((1000, 2000)), 250, None, &held, took);
        let expected = "\
/data: 1000 B used of 2.0 KiB

 SIZE  SHARE  PATH
500 B    50%  /data/big
200 B    20%  everything else, in smaller pieces
300 B    30%  not accounted for
";
        assert!(text.starts_with(expected), "{text}");
        assert!(
            text.contains("Read 12 files and folders in 3 seconds."),
            "{text}"
        );
        assert!(
            text.contains("4.0 KiB in 1 deleted file is still held open"),
            "{text}"
        );
        assert!(text.contains("rsyslogd"), "{text}");
    }

    #[test]
    fn a_second_look_says_what_changed() {
        let folder = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let root = folder.path();
        file(&root.join("logs/a"), 256);
        file(&root.join("cache/a"), 256);

        let variables = BTreeMap::from([("disk".to_string(), root.display().to_string())]);
        let asked = Asked {
            variables: &variables,
            deadline: later(),
            state_dir: state.path(),
        };
        let first = report(&asked).unwrap();
        assert!(!first.contains("CHANGE"), "{first}");

        file(&root.join("logs/b"), 512);
        fs::remove_dir_all(root.join("cache")).unwrap();
        file(&root.join("fresh/a"), 256);
        let second = report(&asked).unwrap();
        assert!(second.contains("CHANGE"), "{second}");
        let line = |name: &str| {
            let found = second.lines().find(|line| line.ends_with(name));
            found
                .unwrap_or_else(|| panic!("no line for {name} in {second}"))
                .to_string()
        };
        assert!(line("logs").contains('+'), "{second}");
        assert!(line("fresh").contains("new"), "{second}");
        assert!(second.contains("since the last look"), "{second}");
    }

    #[test]
    fn it_needs_a_folder_given_as_a_full_path() {
        let state = tempfile::tempdir().unwrap();
        for disk in [
            None,
            Some("relative/path"),
            Some("/nonexistent/maxnines-test"),
        ] {
            let variables: BTreeMap<String, String> = disk
                .into_iter()
                .map(|disk| ("disk".to_string(), disk.to_string()))
                .collect();
            let asked = Asked {
                variables: &variables,
                deadline: later(),
                state_dir: state.path(),
            };
            assert!(report(&asked).is_err(), "{disk:?}");
        }
    }

    #[test]
    fn times_ago_read_naturally() {
        assert_eq!(ago(Duration::from_secs(0)), "1 second");
        assert_eq!(ago(Duration::from_secs(59)), "59 seconds");
        assert_eq!(ago(Duration::from_secs(60)), "1 minute");
        assert_eq!(ago(Duration::from_secs(3 * 3600)), "3 hours");
        assert_eq!(ago(Duration::from_secs(47 * 3600)), "47 hours");
        assert_eq!(ago(Duration::from_secs(3 * 86_400)), "3 days");
    }
}
