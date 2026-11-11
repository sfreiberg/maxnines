//! How hard each disk is working: operations a second, how long each takes, how busy
//! it is and how many wait. Bytes alone can't show a disk is the bottleneck, as one
//! doing small random reads is flat out long before it moves many bytes.
//!
//! Linux and macOS keep running totals, so each sample is worked out from the change
//! since the one before, and the first has nothing to compare with. Windows works out
//! the rates itself, in its performance counters. macOS has no busy time or queue of
//! its own, as its time totals overlap when a disk does several things at once, so
//! those are left out there, as they are on FreeBSD altogether.

use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Instant;

use serde_json::{Map, Value, json};
use sysinfo::Disk;

/// A disk's activity over the time since the last sample.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Activity {
    pub read_ops_per_sec: f64,
    pub write_ops_per_sec: f64,
    /// The average time a read took, or 0 with none.
    pub read_latency_ms: f64,
    pub write_latency_ms: f64,
    pub busy_percent: Option<f64>,
    /// How many operations were waiting or under way, on average.
    pub queue_length: Option<f64>,
}

impl Activity {
    /// Adds itself to a disk's output.
    pub fn add_to(&self, output: &mut Map<String, Value>) {
        let finite = |value: f64| value.is_finite().then_some(value);
        let fields = [
            ("read_ops_per_sec", finite(self.read_ops_per_sec)),
            ("write_ops_per_sec", finite(self.write_ops_per_sec)),
            ("read_latency_ms", finite(self.read_latency_ms)),
            ("write_latency_ms", finite(self.write_latency_ms)),
            ("busy_percent", self.busy_percent.and_then(finite)),
            ("queue_length", self.queue_length.and_then(finite)),
        ];
        for (name, value) in fields {
            if let Some(value) = value {
                output.insert(name.into(), json!(value));
            }
        }
    }
}

/// Running totals since a disk appeared, as Linux and macOS keep them.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Totals {
    pub reads: u64,
    pub writes: u64,
    pub read_ms: f64,
    pub write_ms: f64,
    pub busy_ms: Option<f64>,
    /// The time each operation spent waiting or under way, added up.
    pub queued_ms: Option<f64>,
}

/// What changed between two totals, `elapsed_ms` apart. A total that went backwards,
/// as when a disk is replaced, gives nothing.
pub fn activity(before: &Totals, after: &Totals, elapsed_ms: f64) -> Option<Activity> {
    if elapsed_ms <= 0.0 || after.reads < before.reads || after.writes < before.writes {
        return None;
    }
    let reads = (after.reads - before.reads) as f64;
    let writes = (after.writes - before.writes) as f64;
    let per_op = |ms: f64, ops: f64| if ops > 0.0 { (ms / ops).max(0.0) } else { 0.0 };
    let change = |before: Option<f64>, after: Option<f64>| Some((after? - before?).max(0.0));
    Some(Activity {
        read_ops_per_sec: reads * 1000.0 / elapsed_ms,
        write_ops_per_sec: writes * 1000.0 / elapsed_ms,
        read_latency_ms: per_op(after.read_ms - before.read_ms, reads),
        write_latency_ms: per_op(after.write_ms - before.write_ms, writes),
        busy_percent: change(before.busy_ms, after.busy_ms)
            .map(|busy| (busy / elapsed_ms * 100.0).min(100.0)),
        queue_length: change(before.queued_ms, after.queued_ms).map(|queued| queued / elapsed_ms),
    })
}

/// One device in `/proc/diskstats`: its major and minor numbers and its name.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Device {
    pub major: u64,
    pub minor: u64,
    pub name: String,
}

/// Reads `/proc/diskstats`. Each line has the device's numbers and name, then reads,
/// reads merged, sectors read and time reading, the same four for writes, then
/// operations under way, time busy and time queued.
#[cfg(any(target_os = "linux", test))]
pub fn parse_diskstats(text: &str) -> HashMap<Device, Totals> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let number = |index: usize| fields.get(index)?.parse::<u64>().ok();
            let device = Device {
                major: number(0)?,
                minor: number(1)?,
                name: fields.get(2)?.to_string(),
            };
            let totals = Totals {
                reads: number(3)?,
                read_ms: number(6)? as f64,
                writes: number(7)?,
                write_ms: number(10)? as f64,
                busy_ms: number(12).map(|ms| ms as f64),
                queued_ms: number(13).map(|ms| ms as f64),
            };
            Some((device, totals))
        })
        .collect()
}

/// Keeps what's needed to work out each disk's activity from one sample to the next.
pub struct DiskActivity {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    previous: HashMap<String, (Instant, Totals)>,
    #[cfg(windows)]
    counters: crate::counters::pdh::Counters,
}

impl Default for DiskActivity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl DiskActivity {
    pub fn new() -> Self {
        Self {
            previous: HashMap::new(),
        }
    }

    /// Each disk's activity since the last call, by mount point.
    pub fn measure(&mut self, disks: &[&Disk]) -> HashMap<String, Activity> {
        let now = Instant::now();
        let totals = platform::totals(disks);
        let mut measured = HashMap::new();
        for (mount_point, after) in &totals {
            if let Some((then, before)) = self.previous.get(mount_point) {
                let elapsed = now.duration_since(*then).as_secs_f64() * 1000.0;
                if let Some(activity) = activity(before, after, elapsed) {
                    measured.insert(mount_point.clone(), activity);
                }
            }
        }
        self.previous = totals
            .into_iter()
            .map(|(mount_point, totals)| (mount_point, (now, totals)))
            .collect();
        measured
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::collections::HashMap;
    use std::path::Path;

    use sysinfo::Disk;

    use super::{Device, Totals, parse_diskstats};

    /// The name the kernel uses for a disk's device, following links like
    /// `/dev/mapper/vg-root` to `dm-0`.
    fn kernel_name(device: &str) -> Option<String> {
        let path = Path::new(device);
        if !path.starts_with("/dev") {
            return None;
        }
        let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Some(real.file_name()?.to_string_lossy().into_owned())
    }

    /// The device a file system is on, by the numbers its mount point says, which
    /// works even for a name like `/dev/root` that isn't a file. Some file systems,
    /// like btrfs, give numbers of their own, so the name is tried as well.
    fn device_of<'a>(disk: &Disk, stats: &'a HashMap<Device, Totals>) -> Option<&'a Totals> {
        if let Ok(stat) = rustix::fs::stat(disk.mount_point()) {
            let (major, minor) = (
                u64::from(rustix::fs::major(stat.st_dev)),
                u64::from(rustix::fs::minor(stat.st_dev)),
            );
            let by_number = stats
                .iter()
                .find(|(device, _)| device.major == major && device.minor == minor);
            if let Some((_, totals)) = by_number {
                return Some(totals);
            }
        }
        let name = kernel_name(&disk.name().to_string_lossy())?;
        stats
            .iter()
            .find(|(device, _)| device.name == name)
            .map(|(_, totals)| totals)
    }

    pub fn totals(disks: &[&Disk]) -> HashMap<String, Totals> {
        let text = std::fs::read_to_string("/proc/diskstats").unwrap_or_default();
        let stats = parse_diskstats(&text);
        disks
            .iter()
            .filter_map(|disk| {
                let totals = *device_of(disk, &stats)?;
                Some((disk.mount_point().to_string_lossy().into_owned(), totals))
            })
            .collect()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::collections::HashMap;
    use std::ffi::CString;

    use objc2_core_foundation::{CFDictionary, CFNumber, CFRetained, CFString, CFType};
    use objc2_io_kit::{
        IOBSDNameMatching, IOObjectConformsTo, IOObjectRelease, IORegistryEntryCreateCFProperty,
        IORegistryEntryGetParentEntry, IOServiceGetMatchingService, kIOMainPortDefault,
        kIOServicePlane,
    };
    use sysinfo::Disk;

    use super::Totals;

    const NS_PER_MS: f64 = 1_000_000.0;

    /// How far up from a volume its disk's driver can be. APFS puts a few layers between.
    const MAX_DEPTH: usize = 32;

    /// A name as IOKit takes one: a fixed array, ending with a zero.
    fn io_name(name: &std::ffi::CStr) -> [std::ffi::c_char; 128] {
        let mut array = [0; 128];
        for (place, byte) in array.iter_mut().zip(name.to_bytes().iter().take(127)) {
            *place = *byte as std::ffi::c_char;
        }
        array
    }

    /// The statistics of the driver under a volume, which IOKit keeps for the whole
    /// physical disk, so every volume on one disk reports the same. The way up passes
    /// APFS's own containers and volumes, which keep statistics of a different kind
    /// under the same name, so it stops only at the driver.
    fn statistics(bsd_name: &str) -> Option<Totals> {
        let bsd_name = CString::new(bsd_name).ok()?;
        // SAFETY: the name is a valid C string, and the matching dictionary is
        // handed over to IOServiceGetMatchingService, which releases it.
        let mut entry = unsafe {
            let matching = IOBSDNameMatching(kIOMainPortDefault, 0, bsd_name.as_ptr())?;
            IOServiceGetMatchingService(
                kIOMainPortDefault,
                Some(CFRetained::<CFDictionary>::from(&matching)),
            )
        };
        // IOKit takes names as fixed arrays, and may read all of one.
        let mut plane = io_name(kIOServicePlane);
        let mut driver = io_name(c"IOBlockStorageDriver");
        let (plane, driver) = (&raw mut plane, &raw mut driver);
        let mut found = None;
        for _ in 0..MAX_DEPTH {
            if entry == 0 {
                break;
            }
            // SAFETY: the entry is valid until released, and the names are C strings
            // IOKit only reads.
            if unsafe { IOObjectConformsTo(entry, driver) } {
                let key = CFString::from_static_str("Statistics");
                // SAFETY: as above.
                found = unsafe { IORegistryEntryCreateCFProperty(entry, Some(&key), None, 0) };
                break;
            }
            let mut parent = 0;
            // SAFETY: as above, with somewhere for the parent to go.
            let status = unsafe { IORegistryEntryGetParentEntry(entry, plane, &mut parent) };
            IOObjectRelease(entry);
            entry = if status == 0 { parent } else { 0 };
        }
        if entry != 0 {
            IOObjectRelease(entry);
        }

        let found = found?.downcast::<CFDictionary>().ok()?;
        // SAFETY: IOKit's property dictionaries have strings for keys.
        let found = unsafe { found.cast_unchecked::<CFString, CFType>() };
        let number = |key: &'static str| -> Option<i64> {
            let value = found.get(&CFString::from_static_str(key))?;
            value.downcast::<CFNumber>().ok()?.as_i64()
        };
        Some(Totals {
            reads: u64::try_from(number("Operations (Read)")?).ok()?,
            writes: u64::try_from(number("Operations (Write)")?).ok()?,
            read_ms: number("Total Time (Read)")? as f64 / NS_PER_MS,
            write_ms: number("Total Time (Write)")? as f64 / NS_PER_MS,
            busy_ms: None,
            queued_ms: None,
        })
    }

    pub fn totals(disks: &[&Disk]) -> HashMap<String, Totals> {
        disks
            .iter()
            .filter_map(|disk| {
                let device = crate::file_systems::mounted_from(disk.mount_point())?;
                let totals = statistics(device.strip_prefix("/dev/")?)?;
                Some((disk.mount_point().to_string_lossy().into_owned(), totals))
            })
            .collect()
    }
}

#[cfg(windows)]
impl DiskActivity {
    const COUNTERS: [&str; 6] = [
        r"\LogicalDisk(*)\Disk Reads/sec",
        r"\LogicalDisk(*)\Disk Writes/sec",
        r"\LogicalDisk(*)\Avg. Disk sec/Read",
        r"\LogicalDisk(*)\Avg. Disk sec/Write",
        r"\LogicalDisk(*)\% Idle Time",
        r"\LogicalDisk(*)\Avg. Disk Queue Length",
    ];

    pub fn new() -> Self {
        let paths = Self::COUNTERS.iter().map(ToString::to_string).collect();
        Self {
            counters: crate::counters::pdh::Counters::new(paths),
        }
    }

    /// Each volume's activity, by mount point, from Windows' own counters for it,
    /// which are named by drive letter, like `C:` for `C:\`.
    pub fn measure(&mut self, disks: &[&Disk]) -> HashMap<String, Activity> {
        use crate::counters::Reading;

        let mut by_drive: HashMap<String, [Option<f64>; 6]> = HashMap::new();
        for (index, (_, reading)) in self.counters.read().into_iter().enumerate() {
            let Reading::Values(values) = reading else {
                continue;
            };
            for (path, value) in values {
                if let Some(drive) = instance_of(&path) {
                    by_drive.entry(drive.to_string()).or_default()[index] = Some(value);
                }
            }
        }
        disks
            .iter()
            .filter_map(|disk| {
                let mount_point = disk.mount_point().to_string_lossy().into_owned();
                let drive = mount_point.trim_end_matches('\\');
                let [reads, writes, read_secs, write_secs, idle, queue] = by_drive.get(drive)?;
                let activity = Activity {
                    read_ops_per_sec: (*reads)?,
                    write_ops_per_sec: (*writes)?,
                    read_latency_ms: read_secs.unwrap_or(0.0) * 1000.0,
                    write_latency_ms: write_secs.unwrap_or(0.0) * 1000.0,
                    busy_percent: idle.map(|idle| (100.0 - idle).clamp(0.0, 100.0)),
                    queue_length: *queue,
                };
                Some((mount_point, activity))
            })
            .collect()
    }
}

/// The instance a counter's path names, like `C:` in `\LogicalDisk(C:)\Disk Reads/sec`.
#[cfg(any(windows, test))]
fn instance_of(path: &str) -> Option<&str> {
    let start = path.find('(')? + 1;
    let end = start + path[start..].find(')')?;
    Some(&path[start..end])
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl DiskActivity {
    pub fn new() -> Self {
        Self {}
    }

    pub fn measure(&mut self, _disks: &[&Disk]) -> HashMap<String, Activity> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISKSTATS: &str = "\
 259       0 nvme0n1 120 5 9600 240 300 10 24000 900 2 1000 1140 0 0 0 0
 259       1 nvme0n1p1 3 0 24 1 0 0 0 0 0 4 1
   7       0 loop0 0 0 0 0 0 0 0 0 0 0 0
 252       0 dm-0 100 0 8000 200 280 0 22400 840 0 950 1040
";

    #[test]
    fn diskstats_give_each_devices_totals() {
        let stats = parse_diskstats(DISKSTATS);
        let named = |name: &str| {
            stats
                .iter()
                .find(|(device, _)| device.name == name)
                .map(|(device, totals)| (device.major, device.minor, *totals))
                .unwrap()
        };
        assert_eq!(
            named("nvme0n1").2,
            Totals {
                reads: 120,
                writes: 300,
                read_ms: 240.0,
                write_ms: 900.0,
                busy_ms: Some(1000.0),
                queued_ms: Some(1140.0),
            }
        );
        assert_eq!(
            named("dm-0"),
            (
                252,
                0,
                Totals {
                    reads: 100,
                    writes: 280,
                    read_ms: 200.0,
                    write_ms: 840.0,
                    busy_ms: Some(950.0),
                    queued_ms: Some(1040.0)
                }
            )
        );
        assert_eq!(stats.len(), 4);
    }

    #[test]
    fn activity_is_the_change_over_the_time_between() {
        let before = Totals {
            reads: 100,
            writes: 50,
            read_ms: 200.0,
            write_ms: 100.0,
            busy_ms: Some(1000.0),
            queued_ms: Some(2000.0),
        };
        let after = Totals {
            reads: 400,
            writes: 50,
            read_ms: 800.0,
            write_ms: 100.0,
            busy_ms: Some(1750.0),
            queued_ms: Some(5000.0),
        };

        let activity = activity(&before, &after, 1500.0).unwrap();

        assert_eq!(activity.read_ops_per_sec, 200.0);
        assert_eq!(activity.write_ops_per_sec, 0.0);
        assert_eq!(activity.read_latency_ms, 2.0);
        // No writes means nothing waited for one.
        assert_eq!(activity.write_latency_ms, 0.0);
        assert_eq!(activity.busy_percent, Some(50.0));
        assert_eq!(activity.queue_length, Some(2.0));
    }

    #[test]
    fn busy_never_reads_more_than_all_the_time() {
        let after = Totals {
            busy_ms: Some(5000.0),
            ..Totals::default()
        };
        let before = Totals {
            busy_ms: Some(0.0),
            ..Totals::default()
        };
        assert_eq!(
            activity(&before, &after, 1000.0).unwrap().busy_percent,
            Some(100.0)
        );
    }

    #[test]
    fn a_total_that_went_backwards_gives_nothing() {
        let before = Totals {
            reads: 10,
            ..Totals::default()
        };
        assert_eq!(activity(&before, &Totals::default(), 1000.0), None);
        assert_eq!(activity(&Totals::default(), &before, 0.0), None);
    }

    #[test]
    fn what_a_platform_does_not_have_is_left_out() {
        let mut output = Map::new();
        Activity {
            read_ops_per_sec: 3.0,
            busy_percent: None,
            ..Activity::default()
        }
        .add_to(&mut output);
        assert_eq!(output["read_ops_per_sec"], 3.0);
        assert!(!output.contains_key("busy_percent"));
        assert!(!output.contains_key("queue_length"));
    }

    #[test]
    fn a_counters_instance_is_between_its_brackets() {
        assert_eq!(instance_of(r"\LogicalDisk(C:)\Disk Reads/sec"), Some("C:"));
        assert_eq!(instance_of(r"\Memory\Available MBytes"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn this_machine_measures_its_disks_from_the_second_look() {
        let disks = sysinfo::Disks::new_with_refreshed_list().unwrap();
        let disks: Vec<&Disk> = disks
            .iter()
            .filter(|disk| crate::file_systems::is_real(disk))
            .collect();
        let mut activity = DiskActivity::new();
        activity.measure(&disks);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let measured = activity.measure(&disks);
        // A virtual machine's disks may not say, but the first real disk does.
        let any = measured.values().next();
        if cfg!(not(target_os = "linux")) || std::path::Path::new("/proc/diskstats").exists() {
            assert!(any.is_some(), "{disks:?}");
        }
        for activity in measured.values() {
            assert!(activity.read_ops_per_sec >= 0.0);
        }
    }
}
