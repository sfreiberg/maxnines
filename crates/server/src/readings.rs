//! What a host's newest readings say about it beyond its numbers: its drives, its
//! RAID arrays and ZFS pools, its updates, its clock's sync and its services, from
//! what its collectors last sent. The host's pages
//! and the API both read them from here, so they can't come to say different things.
//! Agents send these, so nothing is trusted to be the right shape: anything unusable
//! is left out or blank.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::metrics::Metrics;
use crate::times::Timestamp;

/// One drive, from the smart collector's newest reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Drive {
    /// Its model and serial number, which its series are called. Nothing for one
    /// smartctl couldn't read, which only has its device.
    pub name: Option<String>,
    pub device: String,
    /// Whether it passes its own assessment, if it says.
    pub healthy: Option<bool>,
    pub temperature_celsius: Option<f64>,
    /// Whether it was asleep, so wasn't asked, and this is what it last said.
    pub asleep: bool,
    /// What the agent noticed about it, such as a USB bridge it doesn't know.
    pub note: Option<String>,
}

/// Each drive the smart collector last read, and why it couldn't read any.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Drives {
    pub drives: Vec<Drive>,
    /// Why it couldn't read them, with what to do about it, such as installing
    /// smartctl.
    pub problem: Option<String>,
}

impl Drives {
    pub fn of(output: Option<&Value>) -> Self {
        let mut drives = Self::default();
        for item in output.and_then(Value::as_array).into_iter().flatten() {
            if let Some(said) = item["problem"].as_str() {
                drives.problem = Some(said.to_string());
                continue;
            }
            // A drive smartctl couldn't read is named by its device alone.
            let named = item["model"].is_string() || item["serial"].is_string();
            drives.drives.push(Drive {
                name: item["name"].as_str().filter(|_| named).map(str::to_string),
                device: item["device"].as_str().unwrap_or_default().to_string(),
                healthy: item["healthy"].as_f64().map(|healthy| healthy >= 1.0),
                temperature_celsius: item["temperature_celsius"].as_f64(),
                asleep: item["asleep"].as_f64().is_some_and(|asleep| asleep >= 1.0),
                note: text(item, "note"),
            });
        }
        drives
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Self> {
        let output = metrics.latest_output(host_id, "smart", now).await?;
        Ok(Self::of(output.as_ref()))
    }
}

/// One md array, ZFS pool, Storage Spaces virtual disk or AppleRAID set, from the
/// raid collector's newest reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Array {
    /// Its own name, which its series are called.
    pub name: String,
    /// `md`, `zfs`, `storage_spaces` or `appleraid`.
    pub kind: Option<String>,
    /// How it's laid out, in its system's words, such as `raid1` or `raidz2`.
    pub level: Option<String>,
    /// Its system's own word for how it is, such as `clean` or `DEGRADED`.
    pub state: Option<String>,
    /// Running without all its redundancy.
    pub degraded: bool,
    /// Unable to serve what's on it.
    pub failed: bool,
    /// Rebuilding its redundancy, and how far it has got, if its system says.
    pub rebuilding: bool,
    pub rebuild_percent: Option<f64>,
    /// How far a scrub has got, while one runs.
    pub scrub_percent: Option<f64>,
    /// How fast the rebuild or scrub goes.
    pub speed_bytes_per_sec: Option<f64>,
    /// The devices it's made of, leaving out spares and caches, and how many of
    /// them are working.
    pub devices: Option<u64>,
    pub working_devices: Option<u64>,
    /// Those that aren't, with what's wrong with each.
    pub not_working: Option<String>,
    /// What its system says is wrong with it.
    pub note: Option<String>,
    /// The rest is only for ZFS pools.
    pub size_bytes: Option<u64>,
    pub used_percent: Option<f64>,
    pub fragmentation_percent: Option<f64>,
    pub read_errors: Option<u64>,
    pub write_errors: Option<u64>,
    pub checksum_errors: Option<u64>,
    /// Files or metadata ZFS couldn't repair.
    pub data_errors: Option<u64>,
    /// How long since the last scrub finished, while the last scan was a scrub.
    pub scrub_age_secs: Option<u64>,
    pub scrub_repaired_bytes: Option<u64>,
    /// What the last scrub found and couldn't repair.
    pub scrub_errors: Option<u64>,
}

/// Each array and pool the raid collector last read, and what it couldn't read.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Arrays {
    pub arrays: Vec<Array>,
    /// Why some couldn't be read, with what to do about it, such as letting the
    /// agent run zpool.
    pub problems: Vec<String>,
}

impl Arrays {
    pub fn of(output: Option<&Value>) -> Self {
        let mut arrays = Self::default();
        for item in output.and_then(Value::as_array).into_iter().flatten() {
            if let Some(said) = text(item, "problem") {
                arrays.problems.push(said);
                continue;
            }
            let Some(name) = item["name"].as_str() else {
                continue;
            };
            let flag = |name: &str| item[name].as_f64().is_some_and(|flag| flag >= 1.0);
            let count = |name: &str| item[name].as_f64().map(|count| count as u64);
            arrays.arrays.push(Array {
                name: name.to_string(),
                kind: text(item, "kind"),
                level: text(item, "level"),
                state: text(item, "state"),
                degraded: flag("degraded"),
                failed: flag("failed"),
                rebuilding: flag("rebuilding"),
                rebuild_percent: item["rebuild_percent"].as_f64(),
                scrub_percent: item["scrub_percent"].as_f64(),
                speed_bytes_per_sec: item["speed_bytes_per_sec"].as_f64(),
                devices: count("devices"),
                working_devices: count("working_devices"),
                not_working: text(item, "not_working"),
                note: text(item, "note"),
                size_bytes: count("size_bytes"),
                used_percent: item["used_percent"].as_f64(),
                fragmentation_percent: item["fragmentation_percent"].as_f64(),
                read_errors: count("read_errors"),
                write_errors: count("write_errors"),
                checksum_errors: count("checksum_errors"),
                data_errors: count("data_errors"),
                scrub_age_secs: count("scrub_age_secs"),
                scrub_repaired_bytes: count("scrub_repaired_bytes"),
                scrub_errors: count("scrub_errors"),
            });
        }
        arrays
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Self> {
        let output = metrics.latest_output(host_id, "raid", now).await?;
        Ok(Self::of(output.as_ref()))
    }
}

/// Whether a host is up to date, from the updates collector's newest reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Updates {
    /// What was asked, such as apt.
    pub manager: Option<String>,
    /// How many updates are waiting.
    pub pending: Option<u64>,
    /// How many of them are for security, if the system says.
    pub security: Option<u64>,
    /// How many installed packages have known vulnerabilities, if the system says.
    pub vulnerable: Option<u64>,
    pub reboot_required: Option<bool>,
    /// How long since the package lists were refreshed.
    pub lists_age_secs: Option<u64>,
    /// Why nothing could be asked, with what to do about it. The numbers are all
    /// empty then.
    pub problem: Option<String>,
    /// What went wrong with part of it.
    pub note: Option<String>,
}

impl Updates {
    pub fn of(output: &Value) -> Option<Self> {
        if !output.is_object() {
            return None;
        }
        // The numbers are all from the newest reading, which always has one.
        let count = |name: &str| output[name].as_f64().map(|count| count as u64);
        Some(Self {
            manager: text(output, "manager"),
            pending: count("pending"),
            security: count("security"),
            vulnerable: count("vulnerable"),
            reboot_required: output["reboot_required"]
                .as_f64()
                .map(|reboot| reboot >= 1.0),
            lists_age_secs: count("lists_age_secs"),
            problem: text(output, "problem"),
            note: text(output, "note"),
        })
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Option<Self>> {
        let output = metrics.latest_output(host_id, "updates", now).await?;
        Ok(output.as_ref().and_then(Self::of))
    }
}

/// Whether a host's time service keeps its clock in sync, from the time_sync
/// collector's newest reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimeSync {
    /// Whether a time service has the clock in sync, if it could be told.
    pub synced: Option<bool>,
    /// The most the clock could be out, by the kernel's reckoning, on Linux, FreeBSD
    /// and macOS.
    pub max_error_secs: Option<f64>,
    /// How far the clock is from its time source, on Windows, while it has one.
    pub offset_secs: Option<f64>,
    /// How many time sources the Windows Time service is using.
    pub sources: Option<u64>,
    /// Why it couldn't be read, or why whether it's synced isn't known.
    pub problem: Option<String>,
}

impl TimeSync {
    pub fn of(output: &Value) -> Option<Self> {
        if !output.is_object() {
            return None;
        }
        // The numbers are all from the newest reading, which always has one.
        let number = |name: &str| output[name].as_f64().filter(|value| value.is_finite());
        Some(Self {
            synced: number("synced").map(|synced| synced >= 1.0),
            max_error_secs: number("max_error_secs"),
            offset_secs: number("offset_secs"),
            sources: number("sources").map(|sources| sources as u64),
            problem: text(output, "problem"),
        })
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Option<Self>> {
        let output = metrics.latest_output(host_id, "time_sync", now).await?;
        Ok(output.as_ref().and_then(Self::of))
    }
}

/// A watched service as its host's service manager last described it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchedService {
    pub name: String,
    pub running: bool,
    /// The service manager's word for it, when it isn't running.
    pub state: Option<String>,
}

impl WatchedService {
    fn of(service: &Value) -> Option<Self> {
        let running = service["running"].as_u64() == Some(1);
        Some(Self {
            name: service["name"].as_str()?.to_string(),
            running,
            state: service["state"]
                .as_str()
                .filter(|_| !running)
                .map(String::from),
        })
    }

    /// Each service the services collector last read, in its order.
    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Vec<Self>> {
        Ok(
            match metrics.latest_output(host_id, "services", now).await? {
                Some(Value::Array(items)) => items.iter().filter_map(Self::of).collect(),
                _ => Vec::new(),
            },
        )
    }
}

/// The services a host last said had stopped with an error, by name, so a count of
/// them always comes with which they are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedServices {
    pub count: u64,
    pub names: Vec<String>,
    /// How many failed past the names the agent sends, which it caps.
    pub unnamed: u64,
}

impl FailedServices {
    /// From the system collector's newest reading, which only counts them on systems
    /// that have such a state, so on others there's nothing to say.
    pub fn of(output: &Value) -> Option<Self> {
        let count = output["failed_services"].as_f64()? as u64;
        // The agent joins them as `a, b and 3 more`.
        let listed = output["failed_service_names"].as_str().unwrap_or_default();
        let listed = match listed.rsplit_once(" and ") {
            Some((named, more))
                if more
                    .strip_suffix(" more")
                    .is_some_and(|more| more.parse::<u64>().is_ok()) =>
            {
                named
            }
            _ => listed,
        };
        let names: Vec<String> = listed
            .split(", ")
            .filter(|name| !name.is_empty())
            .map(String::from)
            .collect();
        Some(Self {
            count,
            unnamed: count.saturating_sub(names.len() as u64),
            names,
        })
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Option<Self>> {
        let output = metrics.latest_output(host_id, "system", now).await?;
        Ok(output.as_ref().and_then(Self::of))
    }
}

/// A field that says something, which an empty one doesn't.
fn text(item: &Value, name: &str) -> Option<String> {
    item[name]
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn failed_services_are_named_with_how_many_went_unnamed() {
        let failed = |count: u64, names: &str| {
            let output = json!({ "failed_services": count, "failed_service_names": names });
            FailedServices::of(&output).unwrap()
        };
        let named = failed(2, "backup.timer, nginx.service");
        assert_eq!(named.names, ["backup.timer", "nginx.service"]);
        assert_eq!(named.unnamed, 0);

        let capped = failed(5, "a.service, b.service and 3 more");
        assert_eq!(capped.names, ["a.service", "b.service"]);
        assert_eq!(capped.unnamed, 3);

        // A name that only looks like the end of the list is still a name.
        let odd = failed(1, "Backup and more");
        assert_eq!(odd.names, ["Backup and more"]);

        let none = failed(0, "");
        assert!(none.names.is_empty());
        assert_eq!(none.count, 0);

        // Systems with no such state don't count them.
        assert_eq!(FailedServices::of(&json!({ "processes": 3 })), None);
    }

    #[test]
    fn time_sync_says_what_the_kernel_or_windows_said() {
        let kernel = TimeSync::of(&json!({ "synced": 1, "max_error_secs": 0.25, "problem": "" }));
        assert_eq!(
            kernel,
            Some(TimeSync {
                synced: Some(true),
                max_error_secs: Some(0.25),
                offset_secs: None,
                sources: None,
                problem: None,
            })
        );
        let windows = TimeSync::of(&json!({
            "synced": 1, "sources": 1, "offset_secs": 0.000134, "problem": ""
        }))
        .unwrap();
        assert_eq!(
            (windows.synced, windows.sources, windows.offset_secs),
            (Some(true), Some(1), Some(0.000134))
        );
        assert_eq!(TimeSync::of(&Value::Null), None);
    }

    #[test]
    fn a_problem_reading_says_what_it_knows() {
        let idle = TimeSync::of(&json!({
            "known": 0, "problem": "The Windows Time service isn't running now"
        }))
        .unwrap();
        assert_eq!((idle.synced, idle.sources), (None, None));
        assert!(idle.problem.is_some());
        let updates = Updates::of(&json!({
            "manager": "pacman", "asked": 0, "problem": "checkupdates isn't installed", "note": "",
        }))
        .unwrap();
        assert_eq!((updates.pending, updates.reboot_required), (None, None));
        assert_eq!(updates.manager.as_deref(), Some("pacman"));
        assert_eq!(updates.note, None);
    }

    #[test]
    fn arrays_say_what_they_are_and_problems_are_kept_apart() {
        let output = json!([
            { "name": "/dev/md0", "kind": "md", "level": "raid1", "state": "recovering",
              "degraded": 1, "failed": 0, "rebuilding": 1, "rebuild_percent": 3.5,
              "speed_bytes_per_sec": 2359296.0, "devices": 2, "working_devices": 1,
              "not_working": "1 rebuilding", "note": "" },
            { "name": "tank", "kind": "zfs", "level": "mirror", "state": "ONLINE",
              "degraded": 0, "failed": 0, "rebuilding": 0, "devices": 3, "working_devices": 3,
              "not_working": "", "note": "", "size_bytes": 1006632960, "used_percent": 86.0,
              "checksum_errors": 3209, "scrub_age_secs": 60 },
            { "name": "/usr/sbin/zpool", "problem": "zpool can't open /dev/zfs", "arrays": 0 },
        ]);
        let arrays = Arrays::of(Some(&output));
        assert_eq!(arrays.problems, ["zpool can't open /dev/zfs"]);
        assert_eq!(arrays.arrays.len(), 2);
        let md = &arrays.arrays[0];
        assert!(md.degraded && md.rebuilding && !md.failed);
        assert_eq!(md.not_working.as_deref(), Some("1 rebuilding"));
        assert_eq!(md.note, None);
        assert_eq!(md.size_bytes, None);
        let tank = &arrays.arrays[1];
        assert_eq!(tank.checksum_errors, Some(3209));
        assert_eq!(tank.used_percent, Some(86.0));
        assert_eq!(tank.not_working, None);
        assert_eq!(Arrays::of(None), Arrays::default());
    }

    #[test]
    fn a_drive_smartctl_could_not_read_goes_by_its_device() {
        let output = json!([
            { "name": "/dev/sdc", "device": "/dev/sdc", "asleep": 1, "note": "" },
            { "name": "WDC WD40EFRX WD-1", "device": "/dev/sda", "model": "WDC WD40EFRX",
              "healthy": 1, "temperature_celsius": 38.0, "asleep": 0, "note": "" },
        ]);
        let drives = Drives::of(Some(&output));
        assert_eq!(drives.problem, None);
        assert_eq!(drives.drives[0].name, None);
        assert!(drives.drives[0].asleep);
        assert_eq!(drives.drives[1].name.as_deref(), Some("WDC WD40EFRX WD-1"));
        assert_eq!(drives.drives[1].healthy, Some(true));
        assert_eq!(drives.drives[1].temperature_celsius, Some(38.0));
    }
}
