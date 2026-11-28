//! Each software RAID array and ZFS pool on a host: whether it's whole, degraded or
//! failed, whether it's rebuilding or being scrubbed and how far that has got, and
//! for ZFS how full it is and the errors it has seen.
//!
//! Linux's software RAID is read from /proc/mdstat, which anyone may read. ZFS pools,
//! on Linux and FreeBSD, are read with `zpool list` and `zpool status`, which anyone
//! may run where /dev/zfs lets them, as OpenZFS sets it up; an agent that can't open
//! it asks for root through `sudo -n`, as smartctl does. Storage Spaces is read
//! through PowerShell on Windows, and AppleRAID sets with diskutil on macOS.
//!
//! A host with none of these has nothing to report, and isn't told it's missing
//! anything: most hosts have no arrays.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use maxnines_collectors::entries::{Entries, at, filled, metrics_of, names};
use maxnines_protocol::entries::Entry;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::background::{Background, Missed};
use crate::collector::Collector;

/// An array going wrong is worth knowing about within a minute or two.
#[cfg(not(windows))]
const EVERY: Duration = Duration::from_secs(60);
/// Starting PowerShell takes a second of CPU, too much to do every minute.
#[cfg(windows)]
const EVERY: Duration = Duration::from_secs(5 * 60);
/// The first look comes within this, so a new agent shows its arrays soon.
const FIRST_WITHIN: Duration = Duration::from_secs(15);
/// How long one program run gets. `zpool status` waits on a pool whose devices
/// have stopped answering, so each run has a limit of its own, and what was read
/// before it, such as the pools `zpool list` found and their health, is still
/// reported, with a problem saying what ran out of time.
const RUN_LIMIT: Duration = Duration::from_secs(60);
/// How long one look gets, which is longer than the most it runs, two zpool
/// commands, can take, so it's only reached by something going wrong that no run's
/// own limit catches.
const ROUND_LIMIT: Duration = Duration::from_secs(3 * 60);
const _: () = assert!(ROUND_LIMIT.as_secs() > 2 * RUN_LIMIT.as_secs());

pub struct RaidCollector {
    background: Background,
}

impl RaidCollector {
    pub fn new() -> Result<Self> {
        let mut background = Background::new();
        background.repeat_from(FIRST_WITHIN, EVERY, Some(ROUND_LIMIT), read, |found| {
            found.unwrap_or_else(Found::unfinished).to_value()
        })?;
        Ok(Self { background })
    }
}

impl Collector for RaidCollector {
    fn name(&self) -> &'static str {
        "raid"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }

    fn metrics(&self) -> Vec<String> {
        names(&RAID_METRICS)
    }

    fn read(&mut self, _time: DateTime<Utc>) -> Result<Vec<Entry>> {
        Ok(self
            .background
            .read(|result, time| self.entries(result, time)))
    }

    /// One look at every array and pool: a row for each, and for each problem.
    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let Some(rows) = output.as_array() else {
            return Vec::new();
        };
        let mut entries = Entries::at(time);
        for row in rows {
            // What couldn't be asked says why, as the error of the metrics it
            // would have read, whichever arrays or pools those are of.
            if let Some(problem) = filled(at(row, "problem")).as_str() {
                let unread = at(row, "unread").as_str();
                if unread != Some(Unread::Pools.as_str()) {
                    for metric in ARRAY_METRICS {
                        entries.error(metric, &[], problem);
                    }
                }
                if unread != Some(Unread::Arrays.as_str()) {
                    for metric in ZFS_METRICS {
                        entries.error(metric, &[], problem);
                    }
                }
                continue;
            }
            let Some(name) = at(row, "name").as_str() else {
                continue;
            };
            for (metric, field) in RAID_FIELDS {
                entries.read(metric, &[name], at(row, field));
            }
            if at(row, "kind") == "zfs" {
                for (metric, field) in ZFS_FIELDS {
                    entries.read(metric, &[name], at(row, field));
                }
            }
        }
        // With no arrays each metric has nothing, as do ZFS's own on a host whose
        // arrays are all something else.
        entries.fill(&RAID_METRICS);
        entries.done()
    }
}

/// The metrics every array has, and what each is read from: how it is, then what it
/// is and what its system says of it. The devices that aren't working are one text,
/// each with what's wrong with it, as that's all that's known of them.
const RAID_FIELDS: [(&str, &str); 13] = [
    ("raid.degraded", "degraded"),
    ("raid.failed", "failed"),
    ("raid.rebuilding", "rebuilding"),
    ("raid.rebuild_progress", "rebuild_percent"),
    ("raid.scrub_progress", "scrub_percent"),
    ("raid.speed", "speed_bytes_per_sec"),
    ("raid.devices", "devices"),
    ("raid.working_devices", "working_devices"),
    ("raid.kind", "kind"),
    ("raid.level", "level"),
    ("raid.state", "state"),
    ("raid.not_working", "not_working"),
    ("raid.note", "note"),
];

/// What only a ZFS pool has.
const ZFS_FIELDS: [(&str, &str); 10] = [
    ("zfs.size", "size_bytes"),
    ("zfs.used", "used_percent"),
    ("zfs.fragmentation", "fragmentation_percent"),
    ("zfs.read_errors", "read_errors"),
    ("zfs.write_errors", "write_errors"),
    ("zfs.checksum_errors", "checksum_errors"),
    ("zfs.data_errors", "data_errors"),
    ("zfs.scrub_age", "scrub_age_secs"),
    ("zfs.scrub_repaired", "scrub_repaired_bytes"),
    ("zfs.scrub_errors", "scrub_errors"),
];

const ARRAY_METRICS: [&str; 13] = metrics_of(&[], &RAID_FIELDS);
const ZFS_METRICS: [&str; 10] = metrics_of(&[], &ZFS_FIELDS);
/// Every metric: each array's, then each pool's.
const RAID_METRICS: [&str; 23] = metrics_of(&ARRAY_METRICS, &ZFS_FIELDS);

/// What a problem kept from being read, which says which metrics it's the error
/// of.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Unread {
    /// What every array has: something other than ZFS couldn't be asked.
    Arrays,
    /// What only ZFS says: zpool couldn't be asked.
    Pools,
    /// Both, as nothing says which.
    Everything,
}

impl Unread {
    fn as_str(self) -> &'static str {
        match self {
            Self::Arrays => "arrays",
            Self::Pools => "pools",
            Self::Everything => "everything",
        }
    }
}

/// What one look found: each array, and what couldn't be read, by what it was
/// asked with.
#[derive(Debug, Default, PartialEq)]
struct Found {
    arrays: Vec<Array>,
    problems: Vec<(&'static str, Unread, String)>,
}

impl Found {
    /// A look that ran out of time or panicked. What an earlier look found isn't
    /// repeated: an array whose state can't be read now may be the one failing, as
    /// a pool whose devices stopped answering holds zpool up, and repeating how it
    /// last was would hide that.
    fn unfinished(missed: Missed) -> Self {
        let problem = match missed {
            Missed::OutOfTime => format!(
                "The last look at RAID arrays and ZFS pools didn't finish within {} seconds",
                ROUND_LIMIT.as_secs()
            ),
            Missed::Panicked => "The last look at RAID arrays and ZFS pools failed \
                unexpectedly, which the agent's log says more about"
                .to_string(),
        };
        Self {
            arrays: Vec::new(),
            problems: vec![("raid", Unread::Everything, problem)],
        }
    }

    /// A row for each array, and one for each problem, named by what was asked,
    /// which is never an array's name, as each array's series is named by it. Where
    /// a problem and arrays can be read in one look, the names can't be the same:
    /// md arrays are named by their device, under `/dev/`, ZFS pools can't have a
    /// `/` in their names, so the problems on Linux and FreeBSD are named by a
    /// path, and a Storage Spaces virtual disk's name always has its pool's in it,
    /// with a comma between. diskutil is all macOS asks, so a problem there comes
    /// with no sets.
    fn to_value(&self) -> Value {
        let mut rows: Vec<Value> = self.arrays.iter().map(Array::to_value).collect();
        for (asked, unread, problem) in &self.problems {
            rows.push(json!({
                "name": asked,
                "problem": problem,
                "unread": unread.as_str(),
                "arrays": 0,
            }));
        }
        Value::Array(rows)
    }
}

/// One md array, ZFS pool, Storage Spaces virtual disk or AppleRAID set.
#[derive(Debug, Default, PartialEq)]
struct Array {
    name: String,
    /// `md`, `zfs`, `storage_spaces` or `appleraid`.
    kind: &'static str,
    /// How it's laid out, in its system's words: `raid1`, `raidz2`, `Mirror`.
    level: String,
    /// Its system's own word for how it is: `clean`, `DEGRADED`, `OK`.
    state: String,
    /// The devices it's made of, leaving out spares and caches, and how many of
    /// them are working. Left out for a ZFS pool `zpool status` couldn't describe.
    devices: u64,
    working_devices: u64,
    /// Those that aren't, with what's wrong with each.
    not_working: Vec<String>,
    /// Running without all its redundancy.
    degraded: bool,
    /// Unable to serve what's on it.
    failed: bool,
    /// Rebuilding its redundancy: md's resync or recovery, a ZFS resilver, a
    /// Storage Spaces repair, an AppleRAID rebuild.
    rebuilding: bool,
    rebuild_percent: Option<f64>,
    /// How far a scrub, md's check, has got, while one runs.
    scrub_percent: Option<f64>,
    /// How fast the rebuild or scrub goes.
    speed_bytes_per_sec: Option<f64>,
    /// What its system says is wrong, such as zpool's status.
    note: String,
    zfs: Option<Pool>,
}

/// What only ZFS says about a pool.
#[derive(Debug, Default, PartialEq)]
struct Pool {
    /// Whether `zpool status` described it. When it couldn't, all that's known is
    /// what `zpool list` says: its health, size and how full it is.
    described: bool,
    size_bytes: Option<u64>,
    used_percent: Option<f64>,
    fragmentation_percent: Option<f64>,
    read_errors: u64,
    write_errors: u64,
    checksum_errors: u64,
    /// Files or metadata ZFS couldn't repair.
    data_errors: u64,
    /// How long since the last scrub finished, if it was the last scan.
    scrub_age_secs: Option<u64>,
    scrub_repaired_bytes: Option<u64>,
    /// What the last scrub found and couldn't repair.
    scrub_errors: Option<u64>,
}

impl Array {
    /// Its row. The texts are always there, even when empty, as the server keeps a
    /// row's newest text until it's replaced.
    fn to_value(&self) -> Value {
        let mut row = Map::new();
        row.insert("name".into(), json!(self.name));
        row.insert("kind".into(), json!(self.kind));
        row.insert("level".into(), json!(self.level));
        row.insert("state".into(), json!(self.state));
        row.insert("not_working".into(), json!(self.not_working.join(", ")));
        row.insert("note".into(), json!(self.note));
        let described = self.zfs.as_ref().is_none_or(|pool| pool.described);
        if described {
            row.insert("devices".into(), json!(self.devices));
            row.insert("working_devices".into(), json!(self.working_devices));
        }
        row.insert("degraded".into(), json!(u8::from(self.degraded)));
        row.insert("failed".into(), json!(u8::from(self.failed)));
        row.insert("rebuilding".into(), json!(u8::from(self.rebuilding)));
        let mut put = |key: &str, value: Option<f64>| {
            if let Some(value) = value.filter(|value| value.is_finite()) {
                row.insert(key.into(), json!(value));
            }
        };
        put("rebuild_percent", self.rebuild_percent);
        put("scrub_percent", self.scrub_percent);
        put("speed_bytes_per_sec", self.speed_bytes_per_sec);
        if let Some(pool) = &self.zfs {
            put("size_bytes", pool.size_bytes.map(|size| size as f64));
            put("used_percent", pool.used_percent);
            put("fragmentation_percent", pool.fragmentation_percent);
            if !pool.described {
                return Value::Object(row);
            }
            put("read_errors", Some(pool.read_errors as f64));
            put("write_errors", Some(pool.write_errors as f64));
            put("checksum_errors", Some(pool.checksum_errors as f64));
            put("data_errors", Some(pool.data_errors as f64));
            put("scrub_age_secs", pool.scrub_age_secs.map(|age| age as f64));
            put(
                "scrub_repaired_bytes",
                pool.scrub_repaired_bytes.map(|bytes| bytes as f64),
            );
            put(
                "scrub_errors",
                pool.scrub_errors.map(|errors| errors as f64),
            );
        }
        Value::Object(row)
    }
}

async fn read() -> Found {
    let mut found = Found::default();
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/mdstat") {
            Ok(mdstat) => found.arrays.extend(parse_mdstat(&mdstat, |name| {
                std::fs::read_to_string(format!("/sys/block/{name}/md/sync_action")).ok()
            })),
            // md isn't loaded, so there are no arrays.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => found.problems.push((
                "/proc/mdstat",
                Unread::Arrays,
                format!("/proc/mdstat couldn't be read: {error}"),
            )),
        }
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    zfs::read(&mut found).await;
    #[cfg(target_os = "macos")]
    appleraid::read(&mut found).await;
    #[cfg(windows)]
    windows::read(&mut found).await;
    found
}

/// Runs a program for what it prints, within [`RUN_LIMIT`].
async fn run(
    program: &str,
    arguments: &[&str],
) -> std::result::Result<crate::programs::Ran, String> {
    crate::programs::run(program, arguments, RUN_LIMIT).await
}

/// The first line a program said went wrong, or its exit code.
fn failure(program: &str, ran: &crate::programs::Ran) -> String {
    match ran.stderr.lines().find(|line| !line.trim().is_empty()) {
        Some(line) => format!("{program}: {}", line.trim()),
        None => format!("{program} exited with {:?}", ran.code),
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod zfs {
    use super::{Found, Unread, failure, parse_zpool, run};
    use crate::programs::{first_of, refused_by_sudo};

    /// Where each system puts zpool: Linux's packages, and FreeBSD's base system.
    const PLACES: &[&str] = &["/usr/sbin/zpool", "/sbin/zpool", "/usr/local/sbin/zpool"];
    /// Where sudo is: the system's own, or the one packages add on FreeBSD.
    const SUDO: &[&str] = &["/usr/bin/sudo", "/usr/local/bin/sudo"];
    /// What the agent asks zpool, exactly as a sudoers rule has to allow it.
    pub const LIST: &[&str] = &[
        "list",
        "-Hp",
        "-o",
        "name,health,size,fragmentation,capacity",
    ];
    pub const STATUS: &[&str] = &["status", "-p"];

    pub async fn read(found: &mut Found) {
        // ZFS's own device is only there while its module is loaded, which a host
        // without pools needn't have.
        if !std::path::Path::new("/dev/zfs").exists() {
            return;
        }
        let Some(zpool) = first_of(PLACES) else {
            return;
        };
        // zpool opens /dev/zfs to read and write, which OpenZFS lets anyone do; on
        // a host that doesn't, root is asked for.
        let can_open = nix::unistd::access(
            "/dev/zfs",
            nix::unistd::AccessFlags::R_OK | nix::unistd::AccessFlags::W_OK,
        )
        .is_ok();
        let sudo = if can_open { None } else { first_of(SUDO) };
        // Problems are named by zpool's path, as a pool's name can't have a `/`.
        if !can_open && sudo.is_none() {
            found.problems.push((
                zpool,
                Unread::Pools,
                needs_root(zpool, "sudo isn't installed, so"),
            ));
            return;
        }
        let ask = |arguments: &'static [&'static str]| async move {
            let mut words: Vec<&str> = Vec::new();
            let program = match sudo {
                Some(sudo) => {
                    words.extend(["-n", zpool]);
                    sudo
                }
                None => zpool,
            };
            words.extend(arguments);
            match run(program, &words).await {
                Ok(ran) if refused_by_sudo(&ran) => {
                    Err(needs_root(zpool, "sudo didn't allow it, so"))
                }
                Ok(ran) if ran.code == Some(0) => {
                    Ok(String::from_utf8_lossy(&ran.stdout).into_owned())
                }
                Ok(ran) => Err(failure(&format!("zpool {}", arguments[0]), &ran)),
                Err(error) => Err(error),
            }
        };
        let list = match ask(LIST).await {
            Ok(list) => list,
            Err(problem) => {
                found.problems.push((zpool, Unread::Pools, problem));
                return;
            }
        };
        // Without a pool, status has nothing to add.
        if list.trim().is_empty() {
            return;
        }
        // A pool whose devices have stopped answering can hold status up, or make
        // it fail, while list still says how the pool is, so what list says is
        // kept either way.
        let status = match ask(STATUS).await {
            Ok(status) => status,
            Err(problem) => {
                found.problems.push((zpool, Unread::Pools, problem));
                String::new()
            }
        };
        let now = chrono::Local::now().naive_local();
        found.arrays.extend(parse_zpool(&list, &status, now));
    }

    fn needs_root(zpool: &str, why: &str) -> String {
        format!(
            "zpool can't open /dev/zfs as the agent's user, and {why} the agent can't ask for root. \
             Let anyone open /dev/zfs, as OpenZFS does, or let the agent's user run zpool with a \
             sudoers rule such as: maxnines ALL=(root) NOPASSWD: {zpool} {}, {zpool} {}",
            // A comma in a sudoers rule needs a backslash before it.
            LIST.join(" ").replace(',', "\\,"),
            STATUS.join(" ")
        )
    }
}

#[cfg(target_os = "macos")]
mod appleraid {
    use super::{Found, Unread, failure, parse_appleraid, run};

    pub async fn read(found: &mut Found) {
        match run("/usr/sbin/diskutil", &["appleRAID", "list"]).await {
            Ok(ran) if ran.code == Some(0) => {
                found
                    .arrays
                    .extend(parse_appleraid(&String::from_utf8_lossy(&ran.stdout)));
            }
            Ok(ran) => found.problems.push((
                "diskutil appleRAID",
                Unread::Arrays,
                failure("diskutil appleRAID list", &ran),
            )),
            Err(error) => found
                .problems
                .push(("diskutil appleRAID", Unread::Arrays, error)),
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{Found, Unread, failure, parse_storage_spaces, run};

    /// Each Storage Spaces virtual disk, as JSON.
    const SCRIPT: &str = include_str!("raid.ps1");

    pub async fn read(found: &mut Found) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let powershell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        let arguments = ["-NoProfile", "-NonInteractive", "-Command", SCRIPT];
        let problem = match run(&powershell, &arguments).await {
            Err(error) => error,
            Ok(ran) if ran.code == Some(0) => match parse_storage_spaces(&ran.stdout) {
                Ok(arrays) => {
                    found.arrays.extend(arrays);
                    return;
                }
                Err(error) => error,
            },
            Ok(ran) => format!(
                "Storage Spaces couldn't be read: {}",
                failure("PowerShell", &ran)
            ),
        };
        found
            .problems
            .push(("Storage Spaces", Unread::Arrays, problem));
    }
}

/// Every array in /proc/mdstat. `sync_action` says what sysfs says an array, by
/// its kernel name, is doing, which is only asked while /proc/mdstat says it
/// resyncs, as a repair says it's a resync there too.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_mdstat(text: &str, sync_action: impl Fn(&str) -> Option<String>) -> Vec<Array> {
    let mut arrays = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some((name, rest)) = line.split_once(" : ") else {
            continue;
        };
        let name = name.trim();
        if !name.starts_with("md") || name.contains(char::is_whitespace) {
            continue;
        }
        // Its own lines follow, indented, up to a blank one.
        let mut detail = Vec::new();
        while let Some(next) = lines.peek() {
            if next.trim().is_empty() || !next.starts_with(char::is_whitespace) {
                break;
            }
            detail.push(lines.next().unwrap_or_default().trim());
        }
        // An Intel RST (IMSM) or DDF container only holds the metadata of the
        // arrays in it, which are listed beside it as arrays of their own, `super
        // external:/md127/0`. It holds no data itself, and md always shows it
        // inactive, with every device a spare, `super external:imsm`.
        let container = detail.iter().any(|line| {
            line.split_whitespace().any(|word| {
                word.strip_prefix("external:")
                    .is_some_and(|metadata| !metadata.starts_with('/'))
            })
        });
        if !container {
            arrays.push(md_array(name, rest, &detail, &sync_action));
        }
    }
    arrays
}

/// One md array, from its first line, `active raid1 sdb1[1] sda1[0](F)`, and the
/// lines under it.
fn md_array(
    name: &str,
    first: &str,
    detail: &[&str],
    sync_action: &impl Fn(&str) -> Option<String>,
) -> Array {
    let mut words = first.split_whitespace().peekable();
    // `active`, `inactive` when it hasn't started, or `broken`, as newer kernels
    // say of an array that has lost more than it can do without.
    let started = words.next().unwrap_or_default();
    let active = started == "active";
    // `(auto-read-only)` or `(read-only)` can come next.
    while words.peek().is_some_and(|word| word.starts_with('(')) {
        words.next();
    }
    let mut level = String::new();
    let mut listed = Vec::new();
    for word in words {
        if word.contains('[') {
            listed.push(word);
        } else if level.is_empty() {
            level = word.to_string();
        }
    }
    let spare = |device: &&&str| device.ends_with("(S)");
    let faulty = |device: &&&str| device.ends_with("(F)");
    // What's left are its members: a journal isn't one.
    let member = |device: &&&str| !spare(device) && !faulty(device) && !device.contains("(J)");
    // A device's name is what comes before its number in the array.
    let device_name = |device: &str| device.split('[').next().unwrap_or(device).to_string();

    let mut array = Array {
        name: format!("/dev/{name}"),
        kind: "md",
        level: level.clone(),
        ..Array::default()
    };
    let mut not_working: Vec<String> = listed
        .iter()
        .filter(faulty)
        .map(|device| format!("{} failed", device_name(device)))
        .collect();
    let failed_devices = not_working.len() as u64;
    let members = listed.iter().filter(member).count() as u64;

    // `[3/2] [UU_]`: how many devices it should have, how many it has working, and
    // which.
    let counts = detail.iter().find_map(|line| {
        let start = line.rfind(" [")?;
        let (wanted, working) = line[..start]
            .rsplit_once('[')?
            .1
            .strip_suffix(']')?
            .split_once('/')?;
        let map = line[start + 2..].strip_suffix(']')?;
        Some((
            wanted.parse::<u64>().ok()?,
            working.parse::<u64>().ok()?,
            map.to_string(),
        ))
    });
    match &counts {
        Some((wanted, working, _)) => {
            array.devices = *wanted;
            array.working_devices = *working;
        }
        // An inactive array lists what it has found as spares, waiting for the rest.
        None if !active => array.devices = listed.len() as u64,
        // RAID 0 and linear arrays don't count them, as any device gone takes the
        // array with it.
        None => {
            array.devices = members + failed_devices;
            array.working_devices = members;
        }
    }
    // An inactive array doesn't say how many it's waiting for.
    if active {
        // A member that isn't working is being rebuilt onto, as md only takes a
        // device into the array to recover onto it. /proc/mdstat doesn't say which
        // it is: its number is when it was added, not its place in the map.
        let rebuilt_onto = members.saturating_sub(array.working_devices);
        if rebuilt_onto > 0 {
            not_working.push(format!("{rebuilt_onto} rebuilding"));
        }
        let missing = array
            .devices
            .saturating_sub(array.working_devices)
            .saturating_sub(rebuilt_onto)
            .saturating_sub(failed_devices);
        if missing > 0 {
            not_working.push(format!("{missing} missing"));
        }
    }
    array.not_working = not_working;

    // What it's doing: `recovery = 12.6% (…) finish=1.8min speed=1000K/sec`,
    // `resync=DELAYED` while it waits for another array on the same disks, or
    // `resync=PENDING` while it's read-only and waits for its first write to start.
    // md says `reshape`, `check`, `resync` or `recovery`, and a repair is a resync.
    let mut action = None;
    for line in detail {
        for word in ["resync", "recovery", "reshape", "check"] {
            let Some(at) = line.find(word) else { continue };
            let after = line[at + word.len()..].trim_start();
            if let Some(after) = after.strip_prefix('=') {
                let after = after.trim_start();
                let percent = after
                    .split_once('%')
                    .and_then(|(percent, _)| percent.trim().parse::<f64>().ok());
                let speed = line.split_whitespace().find_map(|part| {
                    let kib = part.strip_prefix("speed=")?.strip_suffix("K/sec")?;
                    Some(kib.parse::<f64>().ok()? * 1024.0)
                });
                action = Some((word, after.starts_with("PENDING"), percent, speed));
                break;
            }
        }
        if action.is_some() {
            break;
        }
    }

    let degraded = array.working_devices < array.devices;
    array.failed = !active
        || match &counts {
            Some((wanted, _, map)) => md_failed(&level, *wanted, map, detail),
            None => array.working_devices < array.devices,
        };
    array.degraded = degraded && !array.failed;
    match action {
        // Nothing runs until something writes to it, which can be days.
        Some(("resync", true, ..)) => array.state = "resync pending".to_string(),
        Some((word, _, percent, speed)) => {
            // Only sysfs tells a repair, which rewrites what a check only counts,
            // from a resync.
            let repair =
                word == "resync" && sync_action(name).is_some_and(|said| said.trim() == "repair");
            array.speed_bytes_per_sec = speed;
            if word == "check" || repair {
                array.scrub_percent = percent;
                array.state = if repair { "repairing" } else { "checking" }.to_string();
            } else {
                array.rebuilding = true;
                array.rebuild_percent = percent;
                array.state = match word {
                    "resync" => "resyncing",
                    "recovery" => "recovering",
                    _ => "reshaping",
                }
                .to_string();
            }
        }
        None => {}
    }
    if !active {
        array.state = started.to_string();
    } else if array.failed {
        array.state = "failed".to_string();
    } else if array.state.is_empty() {
        array.state = if degraded { "degraded" } else { "clean" }.to_string();
    }
    array
}

/// Whether an md array with a map of which devices are up, `[UU_]`, has lost more
/// of them than it can do without: all of them for RAID 1, more than one for RAID 4
/// and 5, more than two for RAID 6, and for RAID 10 every copy of something.
fn md_failed(level: &str, devices: u64, map: &str, detail: &[&str]) -> bool {
    let up: Vec<bool> = map.chars().map(|c| c == 'U').collect();
    let down = up.iter().filter(|up| !**up).count() as u64;
    match level {
        "raid1" => down >= devices,
        "raid4" | "raid5" => down > 1,
        "raid6" => down > 2,
        "raid10" => {
            // `2 near-copies`, `2 far-copies` or `2 offset-copies`, each said only
            // when there's more than one, and near and far together for a layout
            // with both.
            let copies = |kind: &str| {
                detail
                    .iter()
                    .find_map(|line| {
                        let words: Vec<&str> = line.split_whitespace().collect();
                        words.windows(2).find_map(|pair| {
                            (pair[1] == kind)
                                .then(|| pair[0].parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(1)
            };
            let near = copies("near-copies");
            let far = copies("far-copies").max(copies("offset-copies"));
            raid10_lost(&up, near, near * far)
        }
        _ => down > 0,
    }
}

/// Whether a RAID 10 has lost every copy of something, as the kernel's raid10
/// `enough()` decides it: each block's copies are on `copies` devices next to each
/// other, wrapping round, and where they start moves on by `near` devices at a time.
/// So 4 devices with 2 near copies keep the same data on devices 0 and 1, and on 2
/// and 3, while with a number of devices that isn't a multiple of the copies, or
/// far or offset copies, every device starts a set of its own, and the sets overlap.
fn raid10_lost(up: &[bool], near: usize, copies: usize) -> bool {
    let devices = up.len();
    if devices == 0 || near == 0 {
        return false;
    }
    let mut first = 0;
    loop {
        if (0..copies).all(|step| !up[(first + step) % devices]) {
            return true;
        }
        first = (first + near) % devices;
        if first == 0 {
            return false;
        }
    }
}

/// Every pool `zpool list` and `zpool status` describe. `now` is the local time,
/// which zpool writes the end of a scrub in.
#[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
fn parse_zpool(list: &str, status: &str, now: chrono::NaiveDateTime) -> Vec<Array> {
    let mut described = parse_zpool_status(status, now);
    let mut pools = Vec::new();
    for line in list.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [name, health, size, fragmentation, capacity] = fields[..] else {
            continue;
        };
        // One status didn't describe, as it failed, has only what list says.
        let mut array = match described.iter().position(|array| array.name == name) {
            Some(at) => described.swap_remove(at),
            None => Array {
                name: name.to_string(),
                kind: "zfs",
                ..Array::default()
            },
        };
        array.state = health.to_string();
        (array.degraded, array.failed) = zfs_health(health);
        let pool = array.zfs.get_or_insert_with(Pool::default);
        pool.size_bytes = size.parse().ok();
        // `-` for a pool too old to say how fragmented it is.
        pool.used_percent = capacity.parse().ok();
        pool.fragmentation_percent = fragmentation.parse().ok();
        pools.push(array);
    }
    pools
}

/// What a pool's health says: whether it's degraded, and whether it has failed.
fn zfs_health(health: &str) -> (bool, bool) {
    match health {
        "ONLINE" => (false, false),
        "DEGRADED" => (true, false),
        // FAULTED, UNAVAIL, SUSPENDED and REMOVED can't be used.
        _ => (false, true),
    }
}

/// Each pool `zpool status -p` describes.
fn parse_zpool_status(text: &str, now: chrono::NaiveDateTime) -> Vec<Array> {
    let mut pools = Vec::new();
    // Each pool starts with `  pool: tank`.
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("pool: ") {
            blocks.push(Vec::new());
        }
        if let Some(block) = blocks.last_mut() {
            block.push(line);
        }
    }
    for block in blocks {
        pools.push(zfs_pool(&block, now));
    }
    pools
}

/// The fields of one pool's status, each with the lines that carry it on: `scan:
/// …`, `config:` and the rest.
fn status_fields<'a>(block: &[&'a str]) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut fields: Vec<(&str, Vec<&str>)> = Vec::new();
    for line in block {
        let trimmed = line.trim_start();
        let field = trimmed.split_once(':').filter(|(key, _)| {
            !key.is_empty()
                && key.chars().all(|c| c.is_ascii_lowercase())
                && !line.starts_with('\t')
        });
        match field {
            Some((key, value)) => fields.push((key, vec![value.trim()])),
            None => {
                if let Some((_, lines)) = fields.last_mut() {
                    lines.push(line);
                }
            }
        }
    }
    fields
}

fn zfs_pool(block: &[&str], now: chrono::NaiveDateTime) -> Array {
    let fields = status_fields(block);
    let field = |key: &str| {
        fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, lines)| lines.as_slice())
            .unwrap_or_default()
    };
    let name = field("pool")
        .first()
        .copied()
        .unwrap_or_default()
        .to_string();
    let state = field("state")
        .first()
        .copied()
        .unwrap_or_default()
        .to_string();
    let joined = |lines: &[&str]| {
        lines
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let (degraded, failed) = zfs_health(&state);
    let mut array = Array {
        name,
        kind: "zfs",
        state,
        degraded,
        failed,
        note: joined(field("status")),
        ..Array::default()
    };
    let mut pool = Pool {
        described: true,
        ..Pool::default()
    };
    read_config(field("config"), &mut array, &mut pool);
    read_scan(&joined(field("scan")), now, &mut array, &mut pool);
    // `No known data errors`, or `2 data errors, use '-v' for a list`.
    let errors = joined(field("errors"));
    pool.data_errors = errors
        .split_whitespace()
        .next()
        .and_then(|count| count.parse().ok())
        .unwrap_or(0);
    array.zfs = Some(pool);
    array
}

/// The device tree under `config:`, a line for each, indented by two spaces a
/// level under a header: the pool itself, its vdevs, and their devices, then each
/// of logs, cache, spares, special and dedup with theirs.
fn read_config(lines: &[&str], array: &mut Array, pool: &mut Pool) {
    struct Line<'a> {
        depth: usize,
        name: &'a str,
        state: Option<&'a str>,
        errors: [u64; 3],
    }
    let parsed: Vec<Line> = lines
        .iter()
        .filter(|line| line.starts_with('\t') && !line.trim().is_empty())
        .map(|line| {
            let line = &line[1..];
            let depth = (line.len() - line.trim_start_matches(' ').len()) / 2;
            let words: Vec<&str> = line.split_whitespace().collect();
            let count = |at: usize| {
                words
                    .get(at)
                    .and_then(|word| word.parse().ok())
                    .unwrap_or(0)
            };
            // A device that's gone is named by its number, followed by `was
            // /dev/sdc1`, where it was.
            let was = words
                .iter()
                .position(|word| *word == "was")
                .and_then(|at| words.get(at + 1).copied());
            Line {
                depth,
                name: was.unwrap_or(words[0]),
                state: words.get(1).copied(),
                errors: [count(2), count(3), count(4)],
            }
        })
        .filter(|line| line.name != "NAME")
        .collect();

    let mut section = "data";
    let mut levels = Vec::new();
    for (at, line) in parsed.iter().enumerate() {
        if line.depth == 0 {
            // The pool itself comes first, then the sections, which have no state.
            if at > 0 {
                section = line.name;
            }
            continue;
        }
        if section == "data" && line.depth == 1 {
            // `mirror-0`, `raidz2-1`, `draid1:2d:4c:0s-0`, or a device on its own.
            let level = match line.name.rsplit_once('-') {
                Some((kind, number))
                    if number.chars().all(|c| c.is_ascii_digit())
                        && ["mirror", "raidz", "draid"]
                            .iter()
                            .any(|kind_of| kind.starts_with(kind_of)) =>
                {
                    kind.split(':').next().unwrap_or(kind).to_string()
                }
                _ => "stripe".to_string(),
            };
            if !levels.contains(&level) {
                levels.push(level);
            }
        }
        // Spares wait and caches only speed reads up, so neither counts.
        if section == "spares" || section == "cache" {
            continue;
        }
        let leaf = parsed
            .get(at + 1)
            .is_none_or(|next| next.depth <= line.depth);
        if !leaf {
            continue;
        }
        array.devices += 1;
        pool.read_errors += line.errors[0];
        pool.write_errors += line.errors[1];
        pool.checksum_errors += line.errors[2];
        match line.state {
            Some("ONLINE") => array.working_devices += 1,
            Some(state) => array.not_working.push(format!("{} {state}", line.name)),
            None => array.not_working.push(line.name.to_string()),
        }
    }
    array.level = levels.join(", ");
}

/// What `scan:` says: a scrub or resilver running, or how the last one ended.
fn read_scan(scan: &str, now: chrono::NaiveDateTime, array: &mut Array, pool: &mut Pool) {
    let percent = scan
        .split_once("% done")
        .and_then(|(before, _)| before.rsplit(' ').next()?.parse::<f64>().ok());
    // `… issued at 50.2M/s`, or in older versions `… scanned at`.
    let speed = ["issued at ", "scanned at "].iter().find_map(|label| {
        let after = scan.split_once(label)?.1;
        let rate = after.split_whitespace().next()?.trim_end_matches(',');
        bytes(rate.strip_suffix("/s")?)
    });
    let running = scan.contains(" in progress since ");
    if running && (scan.starts_with("resilver") || scan.starts_with("rebuild")) {
        array.rebuilding = true;
        array.rebuild_percent = percent;
        array.speed_bytes_per_sec = speed;
    } else if running && scan.starts_with("scrub") {
        array.scrub_percent = percent;
        array.speed_bytes_per_sec = speed;
    } else if let Some(rest) = scan.strip_prefix("scrub repaired ") {
        // `scrub repaired 0B in 00:00:01 with 0 errors on Tue Nov 24 10:00:00 2026`
        let words: Vec<&str> = rest.split_whitespace().collect();
        pool.scrub_repaired_bytes = words
            .first()
            .and_then(|amount| bytes(amount))
            .map(|repaired| repaired as u64);
        pool.scrub_errors = words
            .iter()
            .position(|word| *word == "with")
            .and_then(|at| words.get(at + 1)?.parse().ok());
        // zpool writes when it ended as ctime does, in the host's time zone.
        let ended = rest.split_once(" errors on ").and_then(|(_, ended)| {
            chrono::NaiveDateTime::parse_from_str(ended.trim(), "%a %b %e %H:%M:%S %Y").ok()
        });
        if let Some(ended) = ended {
            pool.scrub_age_secs = Some((now - ended).num_seconds().max(0) as u64);
        }
    }
}

/// An amount as zpool writes it: `1024`, `0B`, `512M`, `1.21G`, in powers of 1024.
fn bytes(text: &str) -> Option<f64> {
    let text = text.trim();
    let split = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: f64 = number.parse().ok()?;
    let power = match unit {
        "" | "B" => 0,
        "K" => 1,
        "M" => 2,
        "G" => 3,
        "T" => 4,
        "P" => 5,
        "E" => 6,
        _ => return None,
    };
    Some(number * 1024f64.powi(power))
}

/// Every set `diskutil appleRAID list` describes, each between lines of `=`, with
/// its fields, then a table of its members.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_appleraid(text: &str) -> Vec<Array> {
    let mut sets = Vec::new();
    let mut current: Option<Array> = None;
    let mut in_members = false;
    for line in text.lines() {
        if line.starts_with("=====") {
            if let Some(set) = current.take() {
                sets.push(finish_appleraid(set));
            }
            in_members = false;
            continue;
        }
        if let Some(name) = line.strip_prefix("Name:") {
            current = Some(Array {
                name: name.trim().to_string(),
                kind: "appleraid",
                ..Array::default()
            });
            continue;
        }
        let Some(set) = current.as_mut() else {
            continue;
        };
        if let Some(level) = line.strip_prefix("Type:") {
            set.level = level.trim().to_string();
        } else if let Some(status) = line.strip_prefix("Status:") {
            set.state = status.trim().to_string();
        } else if line.starts_with("#  DevNode") {
            in_members = true;
        } else if in_members && !line.starts_with("-----") {
            // `0  disk7s1   28621718-…  Online     268369920`, or one that's gone,
            // `-  -none-    DFFF973B-…  Missing/Damaged`.
            let words: Vec<&str> = line.split_whitespace().collect();
            let [_, device, uuid, ref status @ ..] = words[..] else {
                continue;
            };
            let device = if device == "-none-" { uuid } else { device };
            let status = status.join(" ");
            // A spare waits, and isn't part of the set until it's used.
            if status.starts_with("Spare") {
                continue;
            }
            set.devices += 1;
            if status.starts_with("Online") {
                set.working_devices += 1;
                continue;
            }
            if status.contains("Rebuilding") {
                set.rebuilding = true;
                set.rebuild_percent = status.split_whitespace().find_map(|word| {
                    word.trim_matches(|c| c == '(' || c == ')')
                        .strip_suffix('%')?
                        .parse()
                        .ok()
                });
            }
            // The size that follows a member's status isn't part of it.
            let status = status
                .split_whitespace()
                .filter(|word| !word.chars().all(|c| c.is_ascii_digit()))
                .collect::<Vec<_>>()
                .join(" ");
            set.not_working.push(format!("{device} {status}"));
        }
    }
    if let Some(set) = current {
        sets.push(finish_appleraid(set));
    }
    sets
}

/// A set's health, from its status: Online, Degraded, or Offline or Failed.
fn finish_appleraid(mut set: Array) -> Array {
    match set.state.as_str() {
        "Online" => {}
        "Degraded" => set.degraded = true,
        _ => set.failed = true,
    }
    set
}

/// A series named by more than one thing, as the server names one: `Pool1,
/// Mirror1`, with a backslash before a comma or backslash in any of them, so no two
/// lists of names make the same one.
fn series_name(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| part.replace('\\', "\\\\").replace(',', "\\,"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What the collector's PowerShell script printed: each Storage Spaces virtual disk.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_storage_spaces(json: &[u8]) -> std::result::Result<Vec<Array>, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Disk {
        name: Option<String>,
        pool: Option<String>,
        resiliency: Option<String>,
        health_status: Option<String>,
        #[serde(default)]
        operational_status: Vec<String>,
        disks: Option<u64>,
        unhealthy_disks: Option<u64>,
        #[serde(default)]
        jobs: Vec<Job>,
    }
    /// A job running on the virtual disk: a repair, the regeneration Windows runs
    /// itself, or one that only moves data about, such as a rebalance or
    /// optimization.
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Job {
        name: Option<String>,
        percent_complete: Option<f64>,
        bytes_processed: Option<f64>,
        bytes_total: Option<f64>,
    }
    impl Job {
        /// Whether it rebuilds redundancy. Windows names a job by what it does,
        /// after the virtual disk's name on a server of its own, `Mirror1-Repair`,
        /// and on its own in Storage Spaces Direct, `Repair`.
        fn rebuilds(&self) -> bool {
            let name = self.name.as_deref().unwrap_or_default();
            let does = name.rsplit_once('-').map_or(name, |(_, does)| does);
            does == "Repair" || does == "Regeneration"
        }

        /// How far it has got. Its bytes say best: a repair's own percentage can
        /// read 400 before it knows how much there is to do.
        fn percent(&self) -> Option<f64> {
            match (self.bytes_processed, self.bytes_total) {
                (Some(done), Some(total)) if total > 0.0 => Some(100.0 * done / total),
                _ => self.percent_complete.filter(|percent| *percent <= 100.0),
            }
        }
    }
    let text = String::from_utf8_lossy(json);
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let disks: Vec<Disk> = serde_json::from_str(text)
        .map_err(|_| "Storage Spaces weren't read as JSON".to_string())?;
    Ok(disks
        .into_iter()
        .map(|disk| {
            let operational = disk.operational_status;
            let has = |word: &str| operational.iter().any(|status| status == word);
            let health = disk.health_status.unwrap_or_default();
            let devices = disk.disks.unwrap_or(0);
            let unhealthy = disk.unhealthy_disks.unwrap_or(0).min(devices);
            let failed = health == "Unhealthy" || has("Detached") || has("Lost Communication");
            let rebuilds: Vec<&Job> = disk.jobs.iter().filter(|job| job.rebuilds()).collect();
            let rebuilding = has("InService") || !rebuilds.is_empty();
            // With a repair and a regeneration running, the one further behind.
            let rebuild_percent = rebuilds
                .iter()
                .filter_map(|job| job.percent())
                .min_by(f64::total_cmp);
            let degraded = !failed
                && (has("Degraded") || has("Incomplete") || (health == "Warning" && !rebuilding));
            let pool = disk.pool.unwrap_or_default();
            let name = disk.name.unwrap_or_default();
            let mut not_working = Vec::new();
            if unhealthy > 0 {
                not_working.push(format!(
                    "{unhealthy} of {pool}'s {devices} disks not healthy"
                ));
            }
            Array {
                // Virtual disks in different pools can have the same name.
                name: series_name(&[&pool, &name]),
                kind: "storage_spaces",
                level: disk.resiliency.unwrap_or_default(),
                state: operational.join(", "),
                devices,
                working_devices: devices - unhealthy,
                not_working,
                degraded,
                failed,
                rebuilding,
                rebuild_percent,
                ..Array::default()
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use maxnines_collectors::entries::testing::{every_metric_has_an_entry, said, time};

    use super::*;
    use crate::background::testing::read_once;

    /// A collector that never looks at anything.
    fn looking_at_nothing() -> RaidCollector {
        RaidCollector {
            background: Background::new(),
        }
    }

    #[test]
    fn raid_entries_have_a_series_for_each_array_and_pool() {
        let collector = looking_at_nothing();
        let output = json!([
            { "name": "/dev/md0", "kind": "md", "level": "raid1", "state": "recovering",
              "not_working": "1 rebuilding", "note": "", "devices": 2, "working_devices": 1,
              "degraded": 1, "failed": 0, "rebuilding": 1, "rebuild_percent": 12.5,
              "speed_bytes_per_sec": 1048576.0 },
            { "name": "tank", "kind": "zfs", "level": "raidz1", "state": "ONLINE",
              "not_working": "", "note": "", "devices": 3, "working_devices": 3,
              "degraded": 0, "failed": 0, "rebuilding": 0, "scrub_percent": 40.0,
              "size_bytes": 1000.0, "used_percent": 25.0, "fragmentation_percent": 3.0,
              "read_errors": 0.0, "write_errors": 0.0, "checksum_errors": 2.0,
              "data_errors": 0.0, "scrub_age_secs": 3600.0, "scrub_repaired_bytes": 0.0 },
            // One without a name can't be told from the others.
            { "kind": "md", "degraded": 1 },
        ]);
        let entries = collector.entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said(&entries),
            [
                (of("raid.degraded[/dev/md0]"), json!(1)),
                (of("raid.failed[/dev/md0]"), json!(0)),
                (of("raid.rebuilding[/dev/md0]"), json!(1)),
                (of("raid.rebuild_progress[/dev/md0]"), json!(12.5)),
                (of("raid.scrub_progress[/dev/md0]"), Value::Null),
                (of("raid.speed[/dev/md0]"), json!(1048576.0)),
                (of("raid.devices[/dev/md0]"), json!(2)),
                (of("raid.working_devices[/dev/md0]"), json!(1)),
                (of("raid.kind[/dev/md0]"), json!("md")),
                (of("raid.level[/dev/md0]"), json!("raid1")),
                (of("raid.state[/dev/md0]"), json!("recovering")),
                (of("raid.not_working[/dev/md0]"), json!("1 rebuilding")),
                // Text that's empty is nothing to say.
                (of("raid.note[/dev/md0]"), Value::Null),
                (of("raid.degraded[tank]"), json!(0)),
                (of("raid.failed[tank]"), json!(0)),
                (of("raid.rebuilding[tank]"), json!(0)),
                (of("raid.rebuild_progress[tank]"), Value::Null),
                (of("raid.scrub_progress[tank]"), json!(40.0)),
                (of("raid.speed[tank]"), Value::Null),
                (of("raid.devices[tank]"), json!(3)),
                (of("raid.working_devices[tank]"), json!(3)),
                (of("raid.kind[tank]"), json!("zfs")),
                (of("raid.level[tank]"), json!("raidz1")),
                (of("raid.state[tank]"), json!("ONLINE")),
                (of("raid.not_working[tank]"), Value::Null),
                (of("raid.note[tank]"), Value::Null),
                // Only a pool has ZFS's own.
                (of("zfs.size[tank]"), json!(1000.0)),
                (of("zfs.used[tank]"), json!(25.0)),
                (of("zfs.fragmentation[tank]"), json!(3.0)),
                (of("zfs.read_errors[tank]"), json!(0.0)),
                (of("zfs.write_errors[tank]"), json!(0.0)),
                (of("zfs.checksum_errors[tank]"), json!(2.0)),
                (of("zfs.data_errors[tank]"), json!(0.0)),
                (of("zfs.scrub_age[tank]"), json!(3600.0)),
                (of("zfs.scrub_repaired[tank]"), json!(0.0)),
                (of("zfs.scrub_errors[tank]"), Value::Null),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // A look that found no arrays has nothing for each metric.
        let none = collector.entries(&json!([]), time());
        assert_eq!(none.len(), RAID_METRICS.len());
        assert!(
            said(&none)
                .iter()
                .all(|(name, value)| !name.contains('[') && value.is_null())
        );
        every_metric_has_an_entry(&collector, &none);
        // No look yet says nothing at all.
        assert_eq!(collector.entries(&Value::Null, time()), []);
    }

    #[test]
    fn a_look_at_the_arrays_is_handed_over_once() {
        let mut collector = RaidCollector {
            background: Background::holding([Found::default().to_value()]),
        };
        assert_eq!(read_once(&mut collector).len(), RAID_METRICS.len());

        let mut waiting = RaidCollector::new().unwrap();
        assert_eq!(waiting.read(time()).unwrap(), []);
    }

    #[test]
    fn a_host_with_arrays_and_no_pools_has_nothing_for_what_only_zfs_says() {
        let collector = looking_at_nothing();
        let found = Found {
            arrays: vec![Array {
                name: "/dev/md0".into(),
                kind: "md",
                level: "raid1".into(),
                state: "clean".into(),
                devices: 2,
                working_devices: 2,
                ..Array::default()
            }],
            problems: Vec::new(),
        };
        let entries = collector.entries(&found.to_value(), time());
        every_metric_has_an_entry(&collector, &entries);
        let said = said(&entries);
        assert_eq!(said.len(), RAID_METRICS.len());
        assert!(said.contains(&("raid.degraded[/dev/md0]".to_string(), json!(0))));
        assert!(said.contains(&("raid.state[/dev/md0]".to_string(), json!("clean"))));
        for (metric, _) in ZFS_FIELDS {
            assert!(
                said.contains(&(metric.to_string(), Value::Null)),
                "{metric}"
            );
        }
    }

    #[test]
    fn what_could_not_be_asked_is_the_error_of_what_it_would_have_read() {
        let collector = looking_at_nothing();
        let md0 = || Array {
            name: "/dev/md0".into(),
            kind: "md",
            degraded: true,
            ..Array::default()
        };
        // zpool couldn't be asked, while md's arrays were read.
        let found = Found {
            arrays: vec![md0()],
            problems: vec![(
                "/usr/sbin/zpool",
                Unread::Pools,
                "zpool couldn't be run".into(),
            )],
        };
        let entries = collector.entries(&found.to_value(), time());
        every_metric_has_an_entry(&collector, &entries);
        let read = said(&entries);
        assert_eq!(read.len(), RAID_METRICS.len());
        assert!(read.contains(&("raid.degraded[/dev/md0]".to_string(), json!(1))));
        for metric in ZFS_METRICS {
            assert!(
                read.contains(&(
                    metric.to_string(),
                    json!({ "error": "zpool couldn't be run" })
                )),
                "{metric}: {read:?}"
            );
        }
        assert!(read.iter().all(|(name, _)| !name.contains("zpool")));

        // What isn't ZFS couldn't be asked, on a host with no pools.
        let found = Found {
            arrays: Vec::new(),
            problems: vec![(
                "/proc/mdstat",
                Unread::Arrays,
                "/proc/mdstat couldn't be read".into(),
            )],
        };
        let entries = collector.entries(&found.to_value(), time());
        every_metric_has_an_entry(&collector, &entries);
        for (name, value) in said(&entries) {
            let expected = match name.starts_with("raid.") {
                true => json!({ "error": "/proc/mdstat couldn't be read" }),
                false => Value::Null,
            };
            assert_eq!(value, expected, "{name}");
            assert!(!name.contains('['), "{name}");
        }

        // A look that didn't finish could have read anything.
        let unfinished = Found::unfinished(Missed::Panicked).to_value();
        let entries = collector.entries(&unfinished, time());
        every_metric_has_an_entry(&collector, &entries);
        assert_eq!(entries.len(), RAID_METRICS.len());
        for (name, value) in said(&entries) {
            assert!(!name.contains('['), "{name}");
            assert!(value["error"].is_string(), "{name}: {value}");
        }
    }

    /// `zpool list` still says how full a pool is when `zpool status` can't
    /// describe it, and nothing is made up for the rest.
    #[test]
    fn a_pool_status_could_not_describe_has_nothing_for_what_was_not_said() {
        let collector = looking_at_nothing();
        let pools = parse_zpool("tank\tDEGRADED\t1000\t5\t40\n", "", after_capture());
        let found = Found {
            arrays: pools,
            problems: Vec::new(),
        };
        let entries = collector.entries(&found.to_value(), time());
        every_metric_has_an_entry(&collector, &entries);
        let said = said(&entries);
        for (name, value) in [
            ("raid.degraded[tank]", json!(1)),
            ("raid.state[tank]", json!("DEGRADED")),
            ("raid.devices[tank]", Value::Null),
            ("raid.working_devices[tank]", Value::Null),
            ("zfs.size[tank]", json!(1000.0)),
            ("zfs.used[tank]", json!(40.0)),
            ("zfs.fragmentation[tank]", json!(5.0)),
            ("zfs.read_errors[tank]", Value::Null),
            ("zfs.data_errors[tank]", Value::Null),
        ] {
            assert!(
                said.contains(&(name.to_string(), value)),
                "{name}: {said:?}"
            );
        }
    }

    #[test]
    fn a_collector_that_has_looked_at_nothing_collects_nothing_for_each_metric() {
        let mut collector = looking_at_nothing();
        let output = collector.collect().unwrap();
        assert_eq!(output, json!([]));
        every_metric_has_an_entry(&collector, &collector.entries(&output, time()));
    }

    /// What a capture-raid-outputs run kept, under `fixtures/raid/`.
    fn fixture(path: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/raid")
            .join(path);
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"))
    }

    fn named<'a>(arrays: &'a [Array], name: &str) -> &'a Array {
        arrays
            .iter()
            .find(|array| array.name == name)
            .unwrap_or_else(|| panic!("no {name} in {arrays:#?}"))
    }

    /// Ubuntu 22.04's kernel 6.8 and 24.04's 7.0, with mdadm 4.2 and 4.3.
    const MD_SYSTEMS: [&str; 2] = ["ubuntu-22.04", "ubuntu-24.04"];

    /// What /proc/mdstat said at a step, with what sysfs said each array was doing
    /// where that was kept too.
    fn md(system: &str, step: &str) -> Vec<Array> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/raid");
        parse_mdstat(&fixture(&format!("{system}/md/{step}.mdstat")), |name| {
            std::fs::read_to_string(dir.join(format!("{system}/md/{step}.{name}.sync_action"))).ok()
        })
    }

    #[test]
    fn no_md_arrays_is_nothing_to_report() {
        for system in MD_SYSTEMS {
            assert_eq!(md(system, "empty"), [], "{system}");
        }
    }

    #[test]
    fn healthy_md_arrays_of_every_level_are_clean() {
        for system in MD_SYSTEMS {
            let arrays = md(system, "healthy");
            assert_eq!(arrays.len(), 4, "{system}: {arrays:#?}");
            for (name, level, devices) in [
                ("/dev/md0", "raid1", 2),
                ("/dev/md1", "raid5", 3),
                ("/dev/md2", "raid0", 2),
                ("/dev/md3", "raid10", 4),
            ] {
                let array = named(&arrays, name);
                assert_eq!(array.kind, "md");
                assert_eq!(array.level, level, "{system} {name}");
                assert_eq!(array.state, "clean", "{system} {name}");
                assert_eq!(array.devices, devices, "{system} {name}");
                assert_eq!(array.working_devices, devices, "{system} {name}");
                assert!(!array.degraded && !array.failed && !array.rebuilding);
                assert_eq!(array.not_working, Vec::<String>::new());
                assert_eq!(array.rebuild_percent, None);
            }
        }
    }

    #[test]
    fn a_new_md_array_resyncs_and_a_new_raid5_builds_its_parity() {
        for system in MD_SYSTEMS {
            let arrays = md(system, "first-sync");
            let mirror = named(&arrays, "/dev/md0");
            assert_eq!(mirror.state, "resyncing", "{system}");
            assert!(mirror.rebuilding && !mirror.degraded, "{system}");
            assert!(
                mirror
                    .rebuild_percent
                    .is_some_and(|percent| percent > 0.0 && percent < 100.0)
            );
            assert!(
                mirror
                    .speed_bytes_per_sec
                    .is_some_and(|speed| speed > 100_000.0)
            );
            // RAID 5 builds onto its last device, so it has no redundancy until then.
            let parity = named(&arrays, "/dev/md1");
            assert_eq!(parity.state, "recovering", "{system}");
            assert!(
                parity.rebuilding && parity.degraded && !parity.failed,
                "{system}"
            );
            assert_eq!((parity.devices, parity.working_devices), (3, 2));
            assert_eq!(parity.not_working, ["1 rebuilding"]);
        }
    }

    #[test]
    fn an_md_device_failed_then_removed_leaves_its_array_degraded() {
        for system in MD_SYSTEMS {
            let failed = md(system, "raid1-failed");
            let mirror = named(&failed, "/dev/md0");
            assert!(
                mirror.degraded && !mirror.failed && !mirror.rebuilding,
                "{system}"
            );
            assert_eq!(mirror.state, "degraded");
            assert_eq!((mirror.devices, mirror.working_devices), (2, 1));
            assert_eq!(mirror.not_working.len(), 1, "{system}: {mirror:?}");
            assert!(mirror.not_working[0].ends_with(" failed"), "{mirror:?}");

            let removed = md(system, "raid1-degraded");
            let mirror = named(&removed, "/dev/md0");
            assert!(mirror.degraded, "{system}");
            assert_eq!(mirror.not_working, ["1 missing"]);

            let raid10 = md(system, "raid10-degraded");
            let raid10 = named(&raid10, "/dev/md3");
            assert!(raid10.degraded && !raid10.failed, "{system}");
            assert_eq!((raid10.devices, raid10.working_devices), (4, 3));
        }
    }

    #[test]
    fn an_md_device_added_back_is_recovered_onto() {
        for system in MD_SYSTEMS {
            let arrays = md(system, "raid1-recovering");
            let mirror = named(&arrays, "/dev/md0");
            assert_eq!(mirror.state, "recovering", "{system}");
            assert!(mirror.rebuilding && mirror.degraded, "{system}");
            // loop1 is back in the array, being rebuilt onto, not missing.
            assert_eq!(mirror.not_working, ["1 rebuilding"], "{system}");
            assert!(mirror.rebuild_percent.is_some());
            assert!(mirror.speed_bytes_per_sec.is_some());
            assert_eq!(mirror.scrub_percent, None);
        }
    }

    #[test]
    fn an_md_check_is_a_scrub_not_a_rebuild() {
        for system in MD_SYSTEMS {
            let arrays = md(system, "raid5-check");
            let parity = named(&arrays, "/dev/md1");
            assert_eq!(parity.state, "checking", "{system}");
            assert!(!parity.rebuilding && !parity.degraded, "{system}");
            assert!(parity.scrub_percent.is_some_and(|percent| percent < 100.0));
            assert!(parity.speed_bytes_per_sec.is_some());
            assert_eq!(parity.rebuild_percent, None);
        }
    }

    /// /proc/mdstat says a repair is a resync, and only sysfs says it's a repair.
    #[test]
    fn an_md_repair_is_a_scrub_and_a_resync_stays_a_rebuild() {
        for system in MD_SYSTEMS {
            assert!(
                fixture(&format!("{system}/md/raid5-repair.mdstat")).contains("resync ="),
                "{system}"
            );
            let arrays = md(system, "raid5-repair");
            let parity = named(&arrays, "/dev/md1");
            assert_eq!(parity.state, "repairing", "{system}");
            assert!(!parity.rebuilding && !parity.degraded, "{system}");
            assert!(parity.scrub_percent.is_some_and(|percent| percent < 100.0));
            assert!(parity.speed_bytes_per_sec.is_some());
            assert_eq!(parity.rebuild_percent, None);

            // A first resync, which sysfs calls one too.
            let arrays = md(system, "first-sync");
            let mirror = named(&arrays, "/dev/md0");
            assert!(
                mirror.rebuilding && mirror.scrub_percent.is_none(),
                "{system}"
            );
        }
    }

    #[test]
    fn a_resync_pending_until_an_array_is_written_to_isnt_a_rebuild() {
        for system in MD_SYSTEMS {
            assert!(
                fixture(&format!("{system}/md/resync-pending.mdstat")).contains("resync=PENDING"),
                "{system}"
            );
            let arrays = md(system, "resync-pending");
            let mirror = named(&arrays, "/dev/md4");
            assert_eq!(mirror.state, "resync pending", "{system}");
            assert!(!mirror.rebuilding && !mirror.degraded && !mirror.failed);
            assert_eq!(mirror.rebuild_percent, None);
        }
    }

    #[test]
    fn an_intel_rst_container_isnt_an_array_but_the_array_in_it_is() {
        // md127 is the container. mdadm 4.2 on Ubuntu 22.04 made an array in it,
        // md126, while 4.3 on 24.04 made the container alone.
        for system in MD_SYSTEMS {
            let arrays = md(system, "container");
            assert!(
                fixture(&format!("{system}/md/container.mdstat")).contains("md127 : inactive"),
                "{system}"
            );
            assert!(
                arrays.iter().all(|array| array.name != "/dev/md127"),
                "{system}: {arrays:#?}"
            );
        }
        let arrays = md("ubuntu-22.04", "container");
        let held = named(&arrays, "/dev/md126");
        assert_eq!(
            (held.level.as_str(), held.state.as_str()),
            ("raid1", "clean")
        );
        assert!(!held.failed && !held.degraded);
        // As mdadm's own documentation and Intel's show it.
        let mdstat = "Personalities : [raid1]
md126 : active raid1 sda[1] sdb[0]
      976759808 blocks super external:/md127/0 [2/2] [UU]

md127 : inactive sdb[1](S) sda[0](S)
      5288 blocks super external:imsm

md125 : inactive sdd[1](S) sdc[0](S)
      65536 blocks super external:ddf

md2 : inactive sde1[0](S)
      63488 blocks super 1.2

unused devices: <none>
";
        let arrays = parse_mdstat(mdstat, |_| None);
        let names: Vec<&str> = arrays.iter().map(|array| array.name.as_str()).collect();
        assert_eq!(names, ["/dev/md126", "/dev/md2"]);
        let member = named(&arrays, "/dev/md126");
        assert_eq!(member.state, "clean");
        assert!(!member.failed && !member.degraded);
        // An array that's inactive and not a container is still one waiting for
        // its devices.
        assert!(named(&arrays, "/dev/md2").failed);
    }

    #[test]
    fn an_md_spare_waits_uncounted_and_then_takes_over() {
        for system in MD_SYSTEMS {
            let waiting = md(system, "raid5-spare");
            let parity = named(&waiting, "/dev/md1");
            assert_eq!((parity.devices, parity.working_devices), (3, 3), "{system}");
            assert_eq!(parity.state, "clean");

            let taking_over = md(system, "raid5-spare-rebuilding");
            let parity = named(&taking_over, "/dev/md1");
            assert_eq!(parity.state, "recovering", "{system}");
            assert!(parity.degraded && parity.rebuilding);
            // The failed device, and the spare rebuilt onto in its place.
            assert_eq!(parity.not_working.len(), 2, "{parity:?}");
            assert!(parity.not_working[0].ends_with(" failed"));
            assert_eq!(parity.not_working[1], "1 rebuilding");

            let rebuilt = md(system, "raid5-rebuilt");
            assert_eq!(named(&rebuilt, "/dev/md1").state, "clean", "{system}");
        }
    }

    #[test]
    fn an_md_array_waiting_for_its_devices_or_broken_has_failed() {
        for system in MD_SYSTEMS {
            let arrays = md(system, "inactive");
            let waiting = named(&arrays, "/dev/md2");
            assert_eq!(waiting.state, "inactive", "{system}");
            assert!(waiting.failed && !waiting.degraded, "{system}");
            assert_eq!((waiting.devices, waiting.working_devices), (1, 0));
            assert_eq!(waiting.not_working, Vec::<String>::new());
        }
        // A RAID 0 that has lost a device, as newer kernels say.
        let mdstat = "md2 : broken raid0 sdb1[1]
      126976 blocks super 1.2 512k chunks
";
        let broken = parse_mdstat(mdstat, |_| None);
        assert_eq!(broken[0].state, "broken");
        assert!(broken[0].failed);
    }

    #[test]
    fn md_says_an_array_has_failed_once_it_has_lost_more_than_it_can() {
        // md won't fail the last device a RAID 5 needs, so these are as the kernel
        // writes such arrays found at boot.
        let mdstat = "Personalities : [raid1] [raid6] [raid5] [raid4] [raid10]
md1 : active raid5 sdc1[2] sda1[0]
      258048 blocks super 1.2 level 5, 512k chunk, algorithm 2 [4/2] [U_U_]

md5 : active raid6 sde1[4] sdd3[3] sdc3[2]
      258048 blocks super 1.2 level 6, 512k chunk, algorithm 2 [5/3] [__UUU]

md6 : active (auto-read-only) raid1 sdb3[1]
      130048 blocks super 1.2 [2/1] [_U]
        resync=PENDING

unused devices: <none>
";
        let arrays = parse_mdstat(mdstat, |_| None);
        assert!(named(&arrays, "/dev/md1").failed);
        assert_eq!(named(&arrays, "/dev/md1").state, "failed");
        assert!(named(&arrays, "/dev/md5").degraded && !named(&arrays, "/dev/md5").failed);
        let pending = named(&arrays, "/dev/md6");
        assert_eq!(pending.level, "raid1");
        assert!(pending.degraded && !pending.rebuilding);
        assert_eq!(pending.state, "resync pending");
        assert_eq!(pending.rebuild_percent, None);
    }

    /// A RAID 10 with `layout` and a map of which devices are up.
    fn raid10(layout: &str, map: &str) -> Array {
        let devices = map.len() - 2;
        let mdstat = format!(
            "md3 : active raid10 sda1[0]\n      126976 blocks super 1.2 512K chunks {layout} [{devices}/1] {map}\n"
        );
        parse_mdstat(&mdstat, |_| None).remove(0)
    }

    #[test]
    fn a_raid10_has_failed_once_every_copy_of_something_is_gone_as_the_kernel_counts() {
        // Near copies are on devices 0 and 1, and on 2 and 3.
        for map in ["[U__U]", "[_U_U]", "[U_U_]", "[_UU_]"] {
            let array = raid10("2 near-copies", map);
            assert!(array.degraded && !array.failed, "{map}");
        }
        for map in ["[__UU]", "[UU__]", "[____]"] {
            assert!(raid10("2 near-copies", map).failed, "{map}");
        }
        // Far and offset copies are on each device and the next, wrapping round.
        for layout in ["2 far-copies", "2 offset-copies"] {
            assert!(raid10(layout, "[U__U]").failed, "{layout}");
            assert!(raid10(layout, "[_UU_]").failed, "{layout}");
            assert!(raid10(layout, "[U_U_]").degraded, "{layout}");
            assert!(!raid10(layout, "[U_U_]").failed, "{layout}");
        }
        // With 3 devices, sets of 2 near copies overlap: 0 and 1, 2 and 0, 1 and 2.
        assert!(!raid10("2 near-copies", "[U_U]").failed);
        assert!(!raid10("2 near-copies", "[UU_]").failed);
        assert!(raid10("2 near-copies", "[U__]").failed);
        assert!(raid10("2 near-copies", "[__U]").failed);
        // Near and far together: each block on 4 of the 4 devices.
        assert!(!raid10("2 near-copies 2 far-copies", "[U___]").failed);
        // 3 near copies on 6 devices: 0 to 2 and 3 to 5.
        assert!(!raid10("3 near-copies", "[__U__U]").failed);
        assert!(raid10("3 near-copies", "[___UUU]").failed);
    }

    /// OpenZFS 2.1 on Ubuntu 22.04, 2.2 on Ubuntu 24.04 and FreeBSD 14.3, and 2.4 on
    /// FreeBSD 15.0.
    const ZFS_SYSTEMS: [&str; 4] = [
        "ubuntu-22.04",
        "ubuntu-24.04",
        "freebsd-14.3-RELEASE",
        "freebsd-15.0-RELEASE",
    ];

    /// A day after the captures, so a scrub's age is under that.
    fn after_capture() -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 11, 26)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
    }

    fn zfs(system: &str, step: &str) -> Vec<Array> {
        let list = fixture(&format!("{system}/zfs/{step}.list"));
        let status = fixture(&format!("{system}/zfs/{step}.status"));
        parse_zpool(&list, &status, after_capture())
    }

    fn pool(array: &Array) -> &Pool {
        array.zfs.as_ref().expect("a ZFS pool says more")
    }

    #[test]
    fn no_pools_is_nothing_to_report() {
        for system in ZFS_SYSTEMS {
            assert_eq!(zfs(system, "empty"), [], "{system}");
        }
    }

    #[test]
    fn healthy_pools_count_their_devices_but_not_spares_or_caches() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "healthy");
            assert_eq!(pools.len(), 2, "{system}: {pools:#?}");
            let tank = named(&pools, "tank");
            assert_eq!(tank.kind, "zfs");
            assert_eq!(tank.level, "mirror", "{system}");
            assert_eq!(tank.state, "ONLINE");
            // Two in the mirror and the log.
            assert_eq!((tank.devices, tank.working_devices), (3, 3), "{system}");
            assert!(!tank.degraded && !tank.failed && !tank.rebuilding);
            assert_eq!(tank.note, "");
            let tank = pool(tank);
            assert_eq!(tank.size_bytes, Some(1_006_632_960), "{system}");
            assert!(
                tank.used_percent
                    .is_some_and(|used| used > 50.0 && used < 70.0)
            );
            assert!(tank.fragmentation_percent.is_some());
            assert_eq!(
                (tank.read_errors, tank.write_errors, tank.checksum_errors),
                (0, 0, 0)
            );
            assert_eq!(tank.data_errors, 0);
            assert_eq!(tank.scrub_age_secs, None);

            let vault = named(&pools, "vault");
            assert_eq!(vault.level, "raidz1", "{system}");
            assert_eq!((vault.devices, vault.working_devices), (3, 3));
        }
    }

    #[test]
    fn zpool_reads_the_same_for_anyone() {
        for system in ZFS_SYSTEMS {
            let list = fixture(&format!("{system}/zfs/healthy-user.list"));
            let status = fixture(&format!("{system}/zfs/healthy-user.status"));
            assert_eq!(
                parse_zpool(&list, &status, after_capture()),
                zfs(system, "healthy"),
                "{system}"
            );
        }
    }

    #[test]
    fn a_scrub_running_says_how_far_it_has_got_and_a_paused_one_says_nothing() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "scrubbing");
            let tank = named(&pools, "tank");
            assert!(!tank.rebuilding, "{system}");
            assert!(
                tank.scrub_percent
                    .is_some_and(|done| done > 0.0 && done < 100.0),
                "{system}: {tank:?}"
            );
            assert!(
                tank.speed_bytes_per_sec
                    .is_some_and(|speed| speed > 1_000_000.0)
            );

            let pools = zfs(system, "scrub-paused");
            let tank = named(&pools, "tank");
            assert_eq!(tank.scrub_percent, None, "{system}");
            assert_eq!(tank.speed_bytes_per_sec, None);
        }
    }

    #[test]
    fn a_finished_scrub_says_when_and_what_it_found() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "scrubbed");
            let tank = pool(named(&pools, "tank"));
            assert!(
                tank.scrub_age_secs.is_some_and(|age| age < 2 * 86_400),
                "{system}: {tank:?}"
            );
            assert_eq!(tank.scrub_repaired_bytes, Some(0));
            assert_eq!(tank.scrub_errors, Some(0));
        }
    }

    #[test]
    fn a_device_offline_faulted_or_missing_degrades_its_pool() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "offline");
            let vault = named(&pools, "vault");
            assert!(vault.degraded && !vault.failed, "{system}");
            assert_eq!(vault.state, "DEGRADED");
            assert_eq!(vault.not_working, ["/var/tmp/zfs-capture/r2 OFFLINE"]);
            assert_eq!(vault.working_devices, 2);
            assert!(
                vault
                    .note
                    .starts_with("One or more devices has been taken offline")
            );

            let pools = zfs(system, "faulted");
            let tank = named(&pools, "tank");
            assert!(tank.degraded, "{system}");
            assert_eq!(tank.not_working, ["/var/tmp/zfs-capture/m2 FAULTED"]);

            // Named by where it was, rather than its number.
            let pools = zfs(system, "missing");
            let vault = named(&pools, "vault");
            assert!(vault.degraded, "{system}");
            assert_eq!(vault.not_working, ["/var/tmp/zfs-capture/r3 UNAVAIL"]);
        }
    }

    #[test]
    fn a_resilver_is_a_rebuild() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "resilvering");
            let tank = named(&pools, "tank");
            assert!(tank.rebuilding, "{system}");
            assert!(
                tank.rebuild_percent
                    .is_some_and(|done| done > 0.0 && done < 100.0)
            );
            assert!(tank.speed_bytes_per_sec.is_some());
            assert_eq!(tank.scrub_percent, None);

            // A finished resilver says nothing about the last scrub.
            let pools = zfs(system, "resilvered");
            let tank = named(&pools, "tank");
            assert!(!tank.rebuilding, "{system}");
            assert_eq!(pool(tank).scrub_age_secs, None);
        }
    }

    #[test]
    fn damage_a_scrub_repaired_and_damage_it_couldnt_are_both_counted() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "scrub-repaired");
            let tank = pool(named(&pools, "tank"));
            assert!(tank.checksum_errors > 0, "{system}: {tank:?}");
            assert!(tank.scrub_repaired_bytes.is_some_and(|bytes| bytes > 0));
            assert_eq!(tank.scrub_errors, Some(0));
            assert_eq!(tank.data_errors, 0);

            let pools = zfs(system, "data-errors");
            let single = named(&pools, "single");
            assert_eq!(single.level, "stripe", "{system}");
            assert!(single.note.contains("data corruption"), "{single:?}");
            let single = pool(single);
            assert!(single.data_errors > 0, "{system}: {single:?}");
            assert!(single.checksum_errors > 0);
            assert!(single.scrub_errors.is_some_and(|errors| errors > 0));

            // Anyone may count them, if not name the files.
            let list = fixture(&format!("{system}/zfs/data-errors.list"));
            let status = fixture(&format!("{system}/zfs/data-errors-user.status"));
            let pools = parse_zpool(&list, &status, after_capture());
            assert_eq!(
                pool(named(&pools, "single")).data_errors,
                single.data_errors
            );
        }
    }

    #[test]
    fn a_pool_filling_up_says_how_full() {
        for system in ZFS_SYSTEMS {
            let pools = zfs(system, "nearly-full");
            let used = pool(named(&pools, "full")).used_percent.unwrap();
            assert!((80.0..90.0).contains(&used), "{system}: {used}");
            // ZFS keeps at least 128 MiB back, so this 1 GiB pool is as full as
            // it gets well short of 100%.
            let pools = zfs(system, "full");
            let used = pool(named(&pools, "full")).used_percent.unwrap();
            assert!(used >= 85.0, "{system}: {used}");
        }
    }

    #[test]
    fn a_pool_that_cant_be_used_has_failed() {
        for health in ["FAULTED", "UNAVAIL", "SUSPENDED"] {
            assert_eq!(zfs_health(health), (false, true));
        }
        assert_eq!(zfs_health("DEGRADED"), (true, false));
        assert_eq!(zfs_health("ONLINE"), (false, false));
    }

    #[test]
    fn a_scrubs_age_is_from_its_end_in_local_time() {
        let mut array = Array::default();
        let mut pool = Pool::default();
        let now = chrono::NaiveDate::from_ymd_opt(2026, 11, 24)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let scan = "scrub repaired 1.50M in 00:12:01 with 2 errors on Tue Nov  3 10:00:00 2026";
        read_scan(scan, now, &mut array, &mut pool);
        assert_eq!(pool.scrub_age_secs, Some(21 * 86_400 + 2 * 3600));
        assert_eq!(pool.scrub_repaired_bytes, Some(1_572_864));
        assert_eq!(pool.scrub_errors, Some(2));
    }

    #[test]
    fn amounts_are_in_powers_of_1024() {
        assert_eq!(bytes("0B"), Some(0.0));
        assert_eq!(bytes("512"), Some(512.0));
        assert_eq!(bytes("16.0M"), Some(16.0 * 1024.0 * 1024.0));
        assert_eq!(bytes("1.5G"), Some(1.5 * 1024f64.powi(3)));
        assert_eq!(bytes("fast"), None);
    }

    const MACOS: &str = "macos-26.7.2";

    fn appleraid(step: &str) -> Vec<Array> {
        parse_appleraid(&fixture(&format!("{MACOS}/appleraid/{step}.txt")))
    }

    #[test]
    fn appleraid_sets_say_their_members() {
        assert_eq!(appleraid("empty"), []);
        let healthy = appleraid("healthy");
        let set = named(&healthy, "Capture");
        assert_eq!(set.kind, "appleraid");
        assert_eq!(set.level, "Mirror");
        assert_eq!(set.state, "Online");
        assert_eq!((set.devices, set.working_devices), (3, 3));
        assert!(!set.degraded && !set.failed);
    }

    /// macOS 26 takes a mirror offline when a member goes, rather than running on
    /// the rest, and adds a member to repair it as a spare that's never used.
    #[test]
    fn an_appleraid_set_taken_offline_has_failed() {
        let degraded = appleraid("degraded");
        let set = named(&degraded, "Capture");
        assert_eq!(set.state, "Offline");
        assert!(set.failed && !set.degraded);
        assert_eq!((set.devices, set.working_devices), (3, 2));
        assert_eq!(
            set.not_working,
            ["E054E8C6-4E87-4E06-9883-DABD21D5F43D Missing/Damaged"]
        );
        let repaired = appleraid("rebuilding");
        assert_eq!(named(&repaired, "Capture").devices, 3);
        let none_left = appleraid("none-left");
        assert_eq!(named(&none_left, "Capture").working_devices, 0);
    }

    #[test]
    fn an_appleraid_member_rebuilding_says_how_far() {
        let text = "AppleRAID sets (1 found)
===============================================================================
Name:                 Backup
Unique ID:            9A19AF87-3E58-4558-9DE6-56C4E52B2575
Type:                 Mirror
Status:               Degraded
Size:                 2.0 TB (2000054796288 Bytes)
Rebuild:              automatic
Device Node:          disk4
-------------------------------------------------------------------------------
#  DevNode   UUID                                  Status     Size
-------------------------------------------------------------------------------
0  disk2s2   98A3A60A-C66B-4657-AF27-FF829DCA0AC6  Online     2000054796288
1  disk3s2   B1A4FAAE-1636-4509-821F-5341BE14FA34  Rebuilding 2000054796288 (43% complete)
===============================================================================
";
        let sets = parse_appleraid(text);
        let set = named(&sets, "Backup");
        assert!(set.degraded && set.rebuilding && !set.failed);
        assert_eq!(set.rebuild_percent, Some(43.0));
        assert_eq!(set.not_working, ["disk3s2 Rebuilding (43% complete)"]);
    }

    /// Windows Server 2022 and 2025, as the collector's own script printed them.
    const WINDOWS_SYSTEMS: [&str; 2] = ["windows-10.0.20348", "windows-10.0.26100"];

    fn storage_spaces(system: &str, step: &str) -> Vec<Array> {
        let json = fixture(&format!("{system}/storage-spaces/{step}.json"));
        parse_storage_spaces(json.as_bytes()).unwrap()
    }

    #[test]
    fn storage_spaces_virtual_disks_say_their_health() {
        for system in WINDOWS_SYSTEMS {
            assert_eq!(storage_spaces(system, "empty"), [], "{system}");
            let disks = storage_spaces(system, "healthy");
            assert_eq!(disks.len(), 3, "{system}");
            for (name, level) in [
                ("Pool1, Mirror1", "Mirror"),
                ("Pool1, Parity1", "Parity"),
                ("Pool1, Simple1", "Simple"),
            ] {
                let disk = named(&disks, name);
                assert_eq!(disk.kind, "storage_spaces");
                assert_eq!(disk.level, level);
                assert_eq!(disk.state, "OK");
                assert_eq!((disk.devices, disk.working_devices), (4, 4), "{system}");
                assert!(
                    !disk.degraded && !disk.failed && !disk.rebuilding,
                    "{system} {name}"
                );
            }
        }
    }

    #[test]
    fn a_pools_disk_gone_degrades_what_has_redundancy_and_fails_what_hasnt() {
        for system in WINDOWS_SYSTEMS {
            let disks = storage_spaces(system, "disk-gone");
            for name in ["Pool1, Mirror1", "Pool1, Parity1"] {
                let disk = named(&disks, name);
                assert!(disk.degraded && !disk.failed, "{system} {name}: {disk:?}");
                assert_eq!(disk.working_devices, 3);
                assert_eq!(disk.not_working, ["1 of Pool1's 4 disks not healthy"]);
            }
            let simple = named(&disks, "Pool1, Simple1");
            assert!(simple.failed && !simple.degraded, "{system}");
            assert_eq!(simple.state, "No Redundancy, Degraded");
        }
        // Back, but not yet repaired.
        let disks = storage_spaces("windows-10.0.26100", "repaired");
        assert!(named(&disks, "Pool1, Mirror1").degraded);
        assert!(!named(&disks, "Pool1, Simple1").degraded);
    }

    #[test]
    fn a_repair_running_is_a_rebuild_as_far_as_its_bytes_say() {
        let disks = storage_spaces("windows-10.0.26100", "retired-repairing");
        let mirror = named(&disks, "Pool1, Mirror1");
        assert_eq!(mirror.state, "InService");
        assert!(mirror.rebuilding && !mirror.degraded, "{mirror:?}");
        // A repair and a regeneration: the one further behind.
        let percent = mirror.rebuild_percent.unwrap();
        assert!((percent - 100.0 * 136_839_168.0 / 1_073_741_824.0).abs() < 1e-9);
        let parity = named(&disks, "Pool1, Parity1");
        assert!(parity.rebuilding && !parity.degraded);
        assert!(
            parity
                .rebuild_percent
                .is_some_and(|percent| (percent - 71.43).abs() < 0.01)
        );
        assert!(!named(&disks, "Pool1, Simple1").rebuilding);

        let starting = storage_spaces("windows-10.0.20348", "retired-repairing");
        assert_eq!(
            named(&starting, "Pool1, Mirror1").rebuild_percent,
            Some(0.0)
        );

        // Before it knows how much there is, a repair can say it's 400% done.
        let unsure = br#"[{"Name":"Parity1","Pool":"Pool1","Resiliency":"Parity","HealthStatus":"Healthy","OperationalStatus":["OK"],"Disks":4,"UnhealthyDisks":0,"Jobs":[{"Name":"Parity1-Repair","PercentComplete":400,"BytesProcessed":null,"BytesTotal":null}]}]"#;
        let disks = parse_storage_spaces(unsure).unwrap();
        assert!(disks[0].rebuilding);
        assert_eq!(disks[0].rebuild_percent, None);
        assert!(parse_storage_spaces(b"Get-StoragePool : Access denied").is_err());
    }

    #[test]
    fn only_a_repair_or_regeneration_is_a_rebuild_not_a_job_that_moves_data_about() {
        let disk = |jobs: &str| {
            let json = format!(
                r#"[{{"Name":"Mirror1","Pool":"Pool1","Resiliency":"Mirror","HealthStatus":"Healthy","OperationalStatus":["OK"],"Disks":4,"UnhealthyDisks":0,"Jobs":[{jobs}]}}]"#
            );
            parse_storage_spaces(json.as_bytes()).unwrap().remove(0)
        };
        let job = |name: &str, done: u64| {
            format!(
                r#"{{"Name":"{name}","PercentComplete":50,"BytesProcessed":{done},"BytesTotal":1000}}"#
            )
        };
        for name in ["Pool1-Rebalance", "Optimize", "Mirror1-TierOptimization"] {
            let moving = disk(&job(name, 500));
            assert!(!moving.rebuilding && !moving.degraded, "{name}");
            assert_eq!(moving.rebuild_percent, None, "{name}");
        }
        // Storage Spaces Direct names its jobs by what they do alone.
        for name in ["Repair", "Regeneration", "Mirror1-Repair"] {
            assert!(disk(&job(name, 500)).rebuilding, "{name}");
        }
        // Alongside a rebalance, only the repair says how far the rebuild is.
        let both = disk(&format!(
            "{},{}",
            job("Pool1-Rebalance", 100),
            job("Mirror1-Repair", 600)
        ));
        assert_eq!(both.rebuild_percent, Some(60.0));
    }

    #[test]
    fn virtual_disks_of_the_same_name_in_two_pools_are_told_apart() {
        let json = br#"[{"Name":"Data","Pool":"Fast","Disks":2,"UnhealthyDisks":0},{"Name":"Data","Pool":"Slow, big","Disks":4,"UnhealthyDisks":0}]"#;
        let disks = parse_storage_spaces(json).unwrap();
        let names: Vec<&str> = disks.iter().map(|disk| disk.name.as_str()).collect();
        assert_eq!(names, ["Fast, Data", "Slow\\, big, Data"]);
        assert_eq!(series_name(&["a\\", "b"]), "a\\\\, b");
    }

    #[test]
    fn rows_have_every_text_and_problems_have_a_name_no_array_can() {
        let found = Found {
            arrays: md("ubuntu-24.04", "raid1-recovering"),
            problems: vec![(
                "/usr/sbin/zpool",
                Unread::Pools,
                "zpool couldn't be run".into(),
            )],
        };
        let rows = found.to_value();
        let rows = rows.as_array().unwrap();
        let md0 = rows.iter().find(|row| row["name"] == "/dev/md0").unwrap();
        assert_eq!(md0["kind"], "md");
        assert_eq!(md0["note"], "");
        assert_eq!(md0["not_working"], "1 rebuilding");
        assert_eq!(md0["rebuilding"], 1);
        assert_eq!(md0["degraded"], 1);
        assert!(md0.get("size_bytes").is_none());
        assert_eq!(
            rows.last().unwrap(),
            &json!({ "name": "/usr/sbin/zpool", "problem": "zpool couldn't be run", "unread": "pools", "arrays": 0 })
        );
        let pools = Found {
            arrays: zfs("ubuntu-24.04", "data-errors"),
            problems: Vec::new(),
        };
        let rows = pools.to_value();
        let single = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "single")
            .unwrap();
        assert!(single["data_errors"].as_f64().unwrap() > 0.0);
        assert!(single["size_bytes"].as_f64().is_some());
        assert_eq!(Found::default().to_value(), json!([]));
    }

    /// `zpool status` can hang or fail on the very pools that have failed, while
    /// `zpool list` still says how they are.
    #[test]
    fn a_pool_status_couldnt_describe_keeps_what_list_says_and_nothing_more() {
        for system in ZFS_SYSTEMS {
            let list = fixture(&format!("{system}/zfs/missing.list"));
            let pools = parse_zpool(&list, "", after_capture());
            let vault = named(&pools, "vault");
            assert_eq!(vault.state, "DEGRADED", "{system}");
            assert!(vault.degraded && !vault.failed);
            assert!(pool(vault).size_bytes.is_some());
            let row = vault.to_value();
            assert_eq!(row["degraded"], 1);
            assert!(row["used_percent"].is_number(), "{row}");
            // Not that it has no devices or errors, as nothing said.
            for unknown in ["devices", "working_devices", "read_errors", "data_errors"] {
                assert!(row.get(unknown).is_none(), "{system} {unknown}: {row}");
            }
        }
        let suspended = "tank\tSUSPENDED\t1006632960\t-\t-\n";
        let pools = parse_zpool(suspended, "", after_capture());
        assert!(pools[0].failed && !pools[0].degraded);
        assert_eq!(pools[0].state, "SUSPENDED");
    }

    /// Repeating how arrays were before a look that didn't finish would hide one
    /// failing, so it's a problem instead.
    #[test]
    fn a_look_that_doesnt_finish_is_a_problem_and_no_arrays() {
        let rows = Found::unfinished(Missed::OutOfTime).to_value();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "raid");
        assert!(
            rows[0]["problem"]
                .as_str()
                .unwrap()
                .contains("didn't finish within 180 seconds")
        );
        // One that panicked says so instead, rather than blaming the time.
        let rows = Found::unfinished(Missed::Panicked).to_value();
        let problem = rows[0]["problem"].as_str().unwrap();
        assert!(problem.contains("failed unexpectedly"), "{problem}");
        assert!(!problem.contains("seconds"), "{problem}");
    }
}
