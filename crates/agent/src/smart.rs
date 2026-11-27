//! Each drive's SMART health: whether its own assessment passes, its temperature,
//! how long it has been powered on, and the counts that say a drive is failing or
//! wearing out.
//!
//! On Linux, macOS and FreeBSD it's read with smartctl, from smartmontools 7.0 or
//! later, which prints JSON and knows how thousands of drive models report. On Linux
//! and FreeBSD smartctl needs root to open drives, so an agent that gave root up asks
//! for it through `sudo -n`, under a sudoers rule root wrote, as actions do. The
//! helper that keeps root never starts a program, so it isn't asked. macOS lets any
//! user read a drive's SMART health, so there it's run as the agent's own user.
//!
//! On Windows it's read from Windows' own storage counters, with nothing to install.
//!
//! Asking a sleeping disk wakes it, so a disk in standby isn't asked, and keeps what
//! it last said until it wakes.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::background::{Background, Missed};
use crate::collector::Collector;
use crate::programs::Ran;

/// SMART changes slowly, so drives are asked this often.
const EVERY: Duration = Duration::from_secs(15 * 60);
/// The first look comes within this, so a new agent shows its drives soon.
const FIRST_WITHIN: Duration = Duration::from_secs(60);
/// How long one look at every drive gets.
const ROUND_LIMIT: Duration = Duration::from_secs(5 * 60);
/// How long one program run gets.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// The smartctl that first prints JSON.
#[cfg_attr(windows, allow(dead_code))]
const OLDEST: (u32, u32) = (7, 0);

/// The attributes ATA drives report that are kept, by their numbers.
#[cfg_attr(windows, allow(dead_code))]
const REALLOCATED: u64 = 5;
#[cfg_attr(windows, allow(dead_code))]
const PENDING: u64 = 197;
#[cfg_attr(windows, allow(dead_code))]
const UNCORRECTABLE: u64 = 198;
#[cfg_attr(windows, allow(dead_code))]
const CRC_ERRORS: u64 = 199;

pub struct SmartCollector {
    background: Background,
}

impl SmartCollector {
    pub fn new() -> Result<Self> {
        let mut background = Background::new();
        let mut known = Known::default();
        background.repeat_from(FIRST_WITHIN, EVERY, Some(ROUND_LIMIT), read, move |found| {
            known.publish(found)
        })?;
        Ok(Self { background })
    }
}

impl Collector for SmartCollector {
    fn name(&self) -> &'static str {
        "smart"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }
}

/// What one look at every drive found.
#[derive(Debug, PartialEq)]
enum Round {
    /// Nothing could be asked, and why, with what to do about it.
    Problem(String),
    Drives(Vec<Drive>),
}

/// What one drive said.
#[derive(Debug, PartialEq)]
enum Drive {
    /// Its row: a series name, and its values.
    Read { device: String, row: Value },
    /// It's asleep, so it wasn't asked.
    Asleep { device: String },
    /// It couldn't be read, and why.
    Unreadable { device: String, error: String },
}

/// Each drive's last row, by device, so one that's asleep keeps it.
#[derive(Default)]
struct Known {
    rows: BTreeMap<String, Value>,
}

impl Known {
    /// Every row has a number, `asleep`, and its text, `note`, even when empty, as
    /// the server keeps a row's newest text until it's replaced.
    fn publish(&mut self, found: Result<Round, Missed>) -> Value {
        match found {
            // Out of time, or panicked: what was known still stands.
            Err(_) => {}
            Ok(Round::Problem(problem)) => {
                self.rows.clear();
                return json!([{ "name": "smartctl", "problem": problem, "drives": 0 }]);
            }
            Ok(Round::Drives(drives)) => {
                let mut rows = BTreeMap::new();
                for drive in drives {
                    let (device, row) = match drive {
                        Drive::Read { device, mut row } => {
                            row["asleep"] = json!(0);
                            row["note"] = json!("");
                            (device, row)
                        }
                        Drive::Asleep { device } => {
                            let mut row = self.rows.remove(&device).unwrap_or_else(
                                || json!({ "name": device, "device": device, "note": "" }),
                            );
                            row["asleep"] = json!(1);
                            (device, row)
                        }
                        Drive::Unreadable { device, error } => {
                            let row = json!({ "name": device, "device": device, "asleep": 0, "note": error });
                            (device, row)
                        }
                    };
                    rows.insert(device, row);
                }
                self.rows = rows;
            }
        }
        Value::Array(self.rows.values().cloned().collect())
    }
}

async fn read() -> Round {
    #[cfg(unix)]
    {
        smartctl::read().await
    }
    #[cfg(windows)]
    {
        windows::read().await
    }
}

/// Runs a program for what it prints, within [`RUN_LIMIT`].
async fn run(program: &str, arguments: &[&str]) -> std::result::Result<Ran, String> {
    crate::programs::run(program, arguments, RUN_LIMIT).await
}

#[cfg(unix)]
mod smartctl {
    use super::{Drive, Round, parse_drive, parse_scan, parse_version, run};
    use crate::programs::{first_of, refused_by_sudo};

    /// Where each system's packages put smartctl.
    #[cfg(target_os = "linux")]
    const PLACES: &[&str] = &["/usr/sbin/smartctl", "/usr/local/sbin/smartctl"];
    /// Homebrew's, on Apple silicon and on Intel Macs.
    #[cfg(target_os = "macos")]
    const PLACES: &[&str] = &["/opt/homebrew/bin/smartctl", "/usr/local/bin/smartctl"];

    /// Whether opening drives takes root, which macOS doesn't ask of SMART.
    const NEEDS_ROOT: bool = !cfg!(target_os = "macos");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const PLACES: &[&str] = &["/usr/local/sbin/smartctl", "/usr/sbin/smartctl"];

    /// Where sudo is: the system's own, or the one packages add on FreeBSD.
    const SUDO: &[&str] = &["/usr/bin/sudo", "/usr/local/bin/sudo"];

    #[cfg(target_os = "linux")]
    const INSTALL: &str = "apt install smartmontools, or dnf install smartmontools";
    #[cfg(target_os = "macos")]
    const INSTALL: &str = "brew install smartmontools";
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const INSTALL: &str = "pkg install smartmontools";

    pub async fn read() -> Round {
        let Some(smartctl) = first_of(PLACES) else {
            return Round::Problem(format!(
                "smartctl isn't installed. Install smartmontools 7.0 or later: {INSTALL}"
            ));
        };
        match run(smartctl, &["--version"]).await {
            Err(error) => return Round::Problem(error),
            Ok(ran) => match parse_version(&String::from_utf8_lossy(&ran.stdout)) {
                Some(version) if version >= super::OLDEST => {}
                Some((major, minor)) => {
                    return Round::Problem(format!(
                        "smartctl {major}.{minor} is too old to print JSON. Install smartmontools 7.0 or later: {INSTALL}"
                    ));
                }
                None => {
                    return Round::Problem(format!("{smartctl} --version didn't say its version"));
                }
            },
        }

        // Root, or anyone on macOS, reads drives itself; anyone else asks sudo, never
        // for a password.
        let itself = !NEEDS_ROOT || nix::unistd::geteuid().is_root();
        let sudo = if itself { None } else { first_of(SUDO) };
        if !itself && sudo.is_none() {
            return Round::Problem(needs_root(smartctl, "sudo isn't installed, so"));
        }
        let ask = move |arguments: Vec<String>| async move {
            let mut words: Vec<&str> = Vec::new();
            let program = match sudo {
                Some(sudo) => {
                    words.extend(["-n", smartctl]);
                    sudo
                }
                None => smartctl,
            };
            words.extend(arguments.iter().map(String::as_str));
            run(program, &words).await
        };

        let scanned = match ask(vec!["--scan-open".into(), "-j".into()]).await {
            Err(error) => return Round::Problem(error),
            Ok(ran) if refused_by_sudo(&ran) => {
                return Round::Problem(needs_root(smartctl, "sudo didn't allow it, so"));
            }
            Ok(ran) => match parse_scan(&ran.stdout) {
                Ok(devices) => devices,
                Err(error) => return Round::Problem(error),
            },
        };
        let mut drives = Vec::new();
        for device in scanned {
            let arguments = [
                "-j",
                "-a",
                "-n",
                "standby",
                "-d",
                &device.kind,
                &device.name,
            ];
            let drive = match ask(arguments.map(String::from).to_vec()).await {
                Err(error) => Drive::Unreadable {
                    device: device.name,
                    error,
                },
                Ok(ran) => parse_drive(&device.name, &ran.stdout),
            };
            drives.push(drive);
        }
        Round::Drives(drives)
    }

    fn needs_root(smartctl: &str, why: &str) -> String {
        format!(
            "smartctl needs root to read drives, and {why} the agent can't ask for it. \
             Let the agent's user run it with a sudoers rule such as: \
             maxnines ALL=(root) NOPASSWD: {smartctl} --scan-open -j, {smartctl} -j -a -n standby -d *"
        )
    }
}

#[cfg(windows)]
mod windows {
    use super::{Round, parse_windows, run};

    /// Each physical disk with its reliability counters, as JSON, always a list.
    const SCRIPT: &str = "$ErrorActionPreference = 'SilentlyContinue'; \
        ConvertTo-Json -Compress -InputObject @(Get-PhysicalDisk | ForEach-Object { \
        $c = $_ | Get-StorageReliabilityCounter; [pscustomobject]@{ \
        FriendlyName = $_.FriendlyName; SerialNumber = $_.SerialNumber; \
        DeviceId = $_.DeviceId; BusType = [string]$_.BusType; \
        HealthStatus = [string]$_.HealthStatus; Temperature = $c.Temperature; \
        Wear = $c.Wear; PowerOnHours = $c.PowerOnHours } })";

    pub async fn read() -> Round {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let powershell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        let arguments = ["-NoProfile", "-NonInteractive", "-Command", SCRIPT];
        match run(&powershell, &arguments).await {
            Err(error) => Round::Problem(error),
            Ok(ran) => match parse_windows(&ran.stdout) {
                Ok(drives) => Round::Drives(drives),
                Err(error) => Round::Problem(error),
            },
        }
    }
}

#[cfg_attr(windows, allow(dead_code))]
/// The version `smartctl --version` starts with: `smartctl 7.4 2023-08-01 r5530 …`.
fn parse_version(text: &str) -> Option<(u32, u32)> {
    let version = text.lines().next()?.strip_prefix("smartctl ")?;
    let version = version.split_whitespace().next()?;
    let (major, minor) = version.split_once('.')?;
    let minor: String = minor.chars().take_while(char::is_ascii_digit).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// A drive `smartctl --scan-open` found: where it is, and the kind smartctl took it
/// for, which reading it says again so smartctl doesn't have to guess twice.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug, PartialEq)]
struct Scanned {
    name: String,
    kind: String,
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_scan(json: &[u8]) -> std::result::Result<Vec<Scanned>, String> {
    #[derive(Deserialize)]
    struct Scan {
        #[serde(default)]
        devices: Vec<Device>,
    }
    #[derive(Deserialize)]
    struct Device {
        name: String,
        #[serde(rename = "type")]
        kind: String,
        /// Set for one that couldn't be opened, such as a virtual disk.
        open_error: Option<String>,
    }
    let scan: Scan = serde_json::from_slice(json)
        .map_err(|_| "smartctl --scan-open didn't print JSON".to_string())?;
    Ok(scan
        .devices
        .into_iter()
        .filter(|device| device.open_error.is_none())
        .map(|device| Scanned {
            name: device.name,
            kind: device.kind,
        })
        .collect())
}

/// What `smartctl -j -a` printed about one drive.
#[cfg_attr(windows, allow(dead_code))]
fn parse_drive(device: &str, json: &[u8]) -> Drive {
    let Ok(read) = serde_json::from_slice::<Value>(json) else {
        return Drive::Unreadable {
            device: device.to_string(),
            error: "smartctl didn't print JSON".to_string(),
        };
    };
    let messages: Vec<&str> = read["smartctl"]["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|message| message["string"].as_str())
        .collect();
    // smartctl -n standby says `Device is in STANDBY mode, exit(2)`, or SLEEP.
    if messages
        .iter()
        .any(|message| message.starts_with("Device is in ") && message.contains(" mode, exit("))
    {
        return Drive::Asleep {
            device: device.to_string(),
        };
    }
    let model = text(&read["model_name"])
        .or_else(|| text(&read["scsi_model_name"]))
        .unwrap_or_default();
    let serial = text(&read["serial_number"]).unwrap_or_default();
    let health = read["smart_status"]["passed"].as_bool();
    let nvme = &read["nvme_smart_health_information_log"];
    let attributes = attributes(&read);
    if model.is_empty() && health.is_none() && nvme.is_null() && attributes.is_empty() {
        return Drive::Unreadable {
            device: device.to_string(),
            error: messages
                .first()
                .map_or("smartctl couldn't read it", |message| message)
                .to_string(),
        };
    }

    let mut row = Map::new();
    row.insert("name".into(), json!(series_name(&model, &serial, device)));
    row.insert("device".into(), json!(device));
    row.insert("model".into(), json!(model));
    row.insert("serial".into(), json!(serial));
    if let Some(protocol) = text(&read["device"]["protocol"]) {
        row.insert("protocol".into(), json!(protocol));
    }
    if let Some(passed) = health {
        row.insert("healthy".into(), json!(u8::from(passed)));
    }
    let mut put = |key: &str, value: Option<f64>| {
        if let Some(value) = value.filter(|value| value.is_finite()) {
            row.insert(key.into(), json!(value));
        }
    };
    put(
        "temperature_celsius",
        read["temperature"]["current"].as_f64(),
    );
    let hours = read["power_on_time"]["hours"].as_f64();
    let minutes = read["power_on_time"]["minutes"].as_f64().unwrap_or(0.0);
    put(
        "power_on_secs",
        hours.map(|hours| hours * 3600.0 + minutes * 60.0),
    );
    put("power_cycles", read["power_cycle_count"].as_f64());
    put("reallocated", attributes.get(&REALLOCATED).copied());
    put("pending", attributes.get(&PENDING).copied());
    put("uncorrectable", attributes.get(&UNCORRECTABLE).copied());
    put("crc_errors", attributes.get(&CRC_ERRORS).copied());
    if !nvme.is_null() {
        put("used_percent", nvme["percentage_used"].as_f64());
        put("spare_percent", nvme["available_spare"].as_f64());
        put(
            "spare_threshold_percent",
            nvme["available_spare_threshold"].as_f64(),
        );
        put("media_errors", nvme["media_errors"].as_f64());
        put("unsafe_shutdowns", nvme["unsafe_shutdowns"].as_f64());
        put("critical_warning", nvme["critical_warning"].as_f64());
    }
    Drive::Read {
        device: device.to_string(),
        row: Value::Object(row),
    }
}

/// An ATA drive's attributes by number, each its raw count as smartctl reads it.
/// Some drives pack more into an attribute's raw value than the count, which
/// smartctl knows to take apart, so the start of what it writes is used.
#[cfg_attr(windows, allow(dead_code))]
fn attributes(read: &Value) -> BTreeMap<u64, f64> {
    read["ata_smart_attributes"]["table"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|attribute| {
            let id = attribute["id"].as_u64()?;
            let raw = &attribute["raw"];
            let written: String = raw["string"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            let count = written
                .parse::<f64>()
                .ok()
                .or_else(|| raw["value"].as_f64())?;
            Some((id, count))
        })
        .collect()
}

#[cfg_attr(windows, allow(dead_code))]
fn text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

/// What a drive's series are called, which stays the same when the system names
/// its devices differently after a restart: its model and serial number.
fn series_name(model: &str, serial: &str, device: &str) -> String {
    match (model.is_empty(), serial.is_empty()) {
        (false, false) => format!("{model} {serial}"),
        (false, true) => format!("{model} {device}"),
        (true, false) => serial.to_string(),
        (true, true) => device.to_string(),
    }
}

/// What Windows' storage counters said about each physical disk.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows(json: &[u8]) -> std::result::Result<Vec<Drive>, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Disk {
        friendly_name: Option<String>,
        serial_number: Option<String>,
        device_id: Option<Value>,
        bus_type: Option<String>,
        health_status: Option<String>,
        temperature: Option<f64>,
        wear: Option<f64>,
        power_on_hours: Option<f64>,
    }
    let text = String::from_utf8_lossy(json);
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let disks: Vec<Disk> = serde_json::from_str(text)
        .map_err(|_| "Windows' storage counters weren't read as JSON".to_string())?;
    Ok(disks
        .into_iter()
        .map(|disk| {
            let number = match &disk.device_id {
                Some(Value::String(id)) => id.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            let device = format!(r"\\.\PhysicalDrive{number}");
            let model = disk
                .friendly_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let serial = disk
                .serial_number
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let mut row = Map::new();
            row.insert("name".into(), json!(series_name(&model, &serial, &device)));
            row.insert("device".into(), json!(device));
            row.insert("model".into(), json!(model));
            row.insert("serial".into(), json!(serial));
            if let Some(bus) = disk.bus_type {
                row.insert("protocol".into(), json!(bus));
            }
            // Warning is how Windows says a drive predicts its own failure.
            match disk.health_status.as_deref() {
                Some("Healthy") => {
                    row.insert("healthy".into(), json!(1));
                }
                Some("Warning" | "Unhealthy") => {
                    row.insert("healthy".into(), json!(0));
                }
                _ => {}
            }
            let mut put = |key: &str, value: Option<f64>| {
                if let Some(value) = value.filter(|value| value.is_finite()) {
                    row.insert(key.into(), json!(value));
                }
            };
            // Windows says 0 for a temperature it can't read.
            put(
                "temperature_celsius",
                disk.temperature.filter(|celsius| *celsius > 0.0),
            );
            put(
                "power_on_secs",
                disk.power_on_hours.map(|hours| hours * 3600.0),
            );
            put("used_percent", disk.wear);
            Drive::Read {
                device,
                row: Value::Object(row),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A SATA SSD in good health, as smartctl 7.4 prints it.
    const SATA: &str = r#"{
      "json_format_version": [1, 0],
      "smartctl": { "version": [7, 4], "exit_status": 0 },
      "device": { "name": "/dev/sda", "info_name": "/dev/sda [SAT]", "type": "sat", "protocol": "ATA" },
      "model_name": "Samsung SSD 870 EVO 1TB",
      "serial_number": "S6PTNM0T123456A",
      "smart_support": { "available": true, "enabled": true },
      "smart_status": { "passed": true },
      "ata_smart_attributes": { "revision": 1, "table": [
        { "id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100, "thresh": 10, "raw": { "value": 0, "string": "0" } },
        { "id": 9, "name": "Power_On_Hours", "value": 98, "worst": 98, "thresh": 0, "raw": { "value": 8123, "string": "8123" } },
        { "id": 190, "name": "Airflow_Temperature_Cel", "value": 69, "worst": 52, "thresh": 0, "raw": { "value": 31, "string": "31" } },
        { "id": 194, "name": "Temperature_Celsius", "value": 69, "worst": 52, "thresh": 0, "raw": { "value": 197569855519, "string": "31 (Min/Max 18/48)" } },
        { "id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0, "raw": { "value": 0, "string": "0" } },
        { "id": 198, "name": "Offline_Uncorrectable", "value": 100, "worst": 100, "thresh": 0, "raw": { "value": 0, "string": "0" } },
        { "id": 199, "name": "UDMA_CRC_Error_Count", "value": 100, "worst": 100, "thresh": 0, "raw": { "value": 2, "string": "2" } }
      ] },
      "power_on_time": { "hours": 8123 },
      "power_cycle_count": 412,
      "temperature": { "current": 31 }
    }"#;

    /// A hard disk that's failing: its own assessment fails, with sectors moved and
    /// waiting, and smartctl exits with bit 3 set.
    const FAILING: &str = r#"{
      "smartctl": { "version": [7, 3], "exit_status": 8 },
      "device": { "name": "/dev/sdb", "info_name": "/dev/sdb [SAT]", "type": "sat", "protocol": "ATA" },
      "model_name": "WDC WD40EFRX-68N32N0",
      "serial_number": "WD-WCC7K1234567",
      "smart_status": { "passed": false },
      "ata_smart_attributes": { "revision": 16, "table": [
        { "id": 5, "name": "Reallocated_Sector_Ct", "value": 140, "worst": 140, "thresh": 140, "when_failed": "now", "raw": { "value": 1872, "string": "1872" } },
        { "id": 197, "name": "Current_Pending_Sector", "value": 200, "worst": 200, "thresh": 0, "raw": { "value": 24, "string": "24" } },
        { "id": 198, "name": "Offline_Uncorrectable", "value": 200, "worst": 200, "thresh": 0, "raw": { "value": 3, "string": "3" } }
      ] },
      "power_on_time": { "hours": 41234, "minutes": 30 },
      "power_cycle_count": 88,
      "temperature": { "current": 38 }
    }"#;

    /// An NVMe drive, as smartctl 7.4 prints it.
    const NVME: &str = r#"{
      "smartctl": { "version": [7, 4], "exit_status": 0 },
      "device": { "name": "/dev/nvme0", "info_name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe" },
      "model_name": "Samsung SSD 980 PRO 1TB",
      "serial_number": "S5GXNF0R654321B",
      "smart_status": { "passed": true, "nvme": { "value": 0 } },
      "nvme_smart_health_information_log": {
        "critical_warning": 0, "temperature": 41, "available_spare": 100,
        "available_spare_threshold": 10, "percentage_used": 3,
        "data_units_read": 12345678, "data_units_written": 23456789,
        "power_cycles": 1203, "power_on_hours": 5012, "unsafe_shutdowns": 57,
        "media_errors": 0, "num_err_log_entries": 0
      },
      "temperature": { "current": 41 },
      "power_cycle_count": 1203,
      "power_on_time": { "hours": 5012 }
    }"#;

    /// A disk in standby, which smartctl -n standby leaves asleep.
    const ASLEEP: &str = r#"{
      "smartctl": { "version": [7, 4], "exit_status": 2,
        "messages": [ { "string": "Device is in STANDBY mode, exit(2)", "severity": "information" } ] },
      "device": { "name": "/dev/sdc", "info_name": "/dev/sdc [SAT]", "type": "sat", "protocol": "ATA" }
    }"#;

    /// A USB enclosure smartctl can't see through.
    const UNREADABLE: &str = r#"{
      "smartctl": { "version": [7, 4], "exit_status": 1,
        "messages": [ { "string": "/dev/sdd: Unknown USB bridge [0x152d:0x0578 (0x214)]", "severity": "error" } ] }
    }"#;

    const SCAN: &str = r#"{
      "json_format_version": [1, 0],
      "smartctl": { "version": [7, 4], "exit_status": 0 },
      "devices": [
        { "name": "/dev/sda", "info_name": "/dev/sda [SAT]", "type": "sat", "protocol": "ATA" },
        { "name": "/dev/nvme0", "info_name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe" },
        { "name": "/dev/sdz", "info_name": "/dev/sdz", "type": "scsi", "protocol": "SCSI", "open_error": "/dev/sdz: Permission denied" }
      ]
    }"#;

    fn row(drive: Drive) -> Value {
        match drive {
            Drive::Read { row, .. } => row,
            other => panic!("expected a reading, got {other:?}"),
        }
    }

    #[test]
    fn versions_are_read_from_the_first_line() {
        let seven = "smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.5.0] (local build)\nCopyright (C) 2002-23";
        assert_eq!(parse_version(seven), Some((7, 4)));
        assert_eq!(
            parse_version("smartctl 6.6 2017-11-05 r4594 [FreeBSD 11.2]"),
            Some((6, 6))
        );
        assert!(parse_version("smartctl 6.6 2017-11-05").unwrap() < OLDEST);
        assert_eq!(parse_version("usage: smartctl"), None);
    }

    #[test]
    fn a_scan_keeps_the_drives_that_could_be_opened() {
        let scanned = parse_scan(SCAN.as_bytes()).unwrap();
        let names: Vec<(&str, &str)> = scanned
            .iter()
            .map(|drive| (drive.name.as_str(), drive.kind.as_str()))
            .collect();
        assert_eq!(names, [("/dev/sda", "sat"), ("/dev/nvme0", "nvme")]);
        assert!(parse_scan(b"smartctl: invalid option -- 'j'").is_err());
        assert_eq!(parse_scan(br#"{ "smartctl": {} }"#).unwrap(), []);
    }

    #[test]
    fn a_sata_drive_gives_its_health_and_counts() {
        let row = row(parse_drive("/dev/sda", SATA.as_bytes()));
        assert_eq!(
            row,
            json!({
                "name": "Samsung SSD 870 EVO 1TB S6PTNM0T123456A",
                "device": "/dev/sda",
                "model": "Samsung SSD 870 EVO 1TB",
                "serial": "S6PTNM0T123456A",
                "protocol": "ATA",
                "healthy": 1,
                "temperature_celsius": 31.0,
                "power_on_secs": 8123.0 * 3600.0,
                "power_cycles": 412.0,
                "reallocated": 0.0,
                "pending": 0.0,
                "uncorrectable": 0.0,
                "crc_errors": 2.0,
            })
        );
    }

    #[test]
    fn a_failing_drive_says_so() {
        let row = row(parse_drive("/dev/sdb", FAILING.as_bytes()));
        assert_eq!(row["healthy"], 0);
        assert_eq!(row["reallocated"], 1872.0);
        assert_eq!(row["pending"], 24.0);
        assert_eq!(row["uncorrectable"], 3.0);
        assert_eq!(row["power_on_secs"], 41234.0 * 3600.0 + 30.0 * 60.0);
        assert!(row.get("crc_errors").is_none());
    }

    #[test]
    fn an_nvme_drive_gives_its_wear_and_spare() {
        let row = row(parse_drive("/dev/nvme0", NVME.as_bytes()));
        assert_eq!(row["name"], "Samsung SSD 980 PRO 1TB S5GXNF0R654321B");
        assert_eq!(row["healthy"], 1);
        assert_eq!(row["used_percent"], 3.0);
        assert_eq!(row["spare_percent"], 100.0);
        assert_eq!(row["spare_threshold_percent"], 10.0);
        assert_eq!(row["media_errors"], 0.0);
        assert_eq!(row["unsafe_shutdowns"], 57.0);
        assert_eq!(row["critical_warning"], 0.0);
        assert_eq!(row["temperature_celsius"], 41.0);
        assert!(row.get("reallocated").is_none());
    }

    /// What smartctl 7.5 from Homebrew printed for a Mac's own SSD, run as an
    /// ordinary user, with its serial number replaced: it exits 4, as the SSD
    /// doesn't give its error log, but everything else is there.
    #[test]
    fn a_macs_own_ssd_is_read_without_root() {
        let json = include_bytes!("../fixtures/smart/macos-apple-ssd.json");
        let row = row(parse_drive("disk0", json));
        assert_eq!(row["name"], "APPLE SSD AP1024Z 0ba0000000000001");
        assert_eq!(row["healthy"], 1);
        assert_eq!(row["used_percent"], 6.0);
        assert_eq!(row["media_errors"], 0.0);
        assert_eq!(row["unsafe_shutdowns"], 11.0);
        assert_eq!(row["temperature_celsius"], 36.0);
    }

    #[test]
    fn a_sleeping_drive_is_left_asleep_and_keeps_what_it_said() {
        assert_eq!(
            parse_drive("/dev/sdc", ASLEEP.as_bytes()),
            Drive::Asleep {
                device: "/dev/sdc".into()
            }
        );
        let mut known = Known::default();
        let awake = row(parse_drive("/dev/sdc", SATA.as_bytes()));
        known.publish(Ok(Round::Drives(vec![Drive::Read {
            device: "/dev/sdc".into(),
            row: awake.clone(),
        }])));
        let published = known.publish(Ok(Round::Drives(vec![Drive::Asleep {
            device: "/dev/sdc".into(),
        }])));
        let mut asleep = awake;
        asleep["asleep"] = json!(1);
        asleep["note"] = json!("");
        assert_eq!(published, json!([asleep]));
        // Never seen awake, it's listed with nothing to say.
        let mut fresh = Known::default();
        assert_eq!(
            fresh.publish(Ok(Round::Drives(vec![Drive::Asleep {
                device: "/dev/sdc".into()
            }]))),
            json!([{ "name": "/dev/sdc", "device": "/dev/sdc", "asleep": 1, "note": "" }])
        );
    }

    #[test]
    fn a_drive_smartctl_cant_read_says_why() {
        assert_eq!(
            parse_drive("/dev/sdd", UNREADABLE.as_bytes()),
            Drive::Unreadable {
                device: "/dev/sdd".into(),
                error: "/dev/sdd: Unknown USB bridge [0x152d:0x0578 (0x214)]".into()
            }
        );
        assert!(matches!(
            parse_drive("/dev/sdd", b"sudo: a password is required"),
            Drive::Unreadable { .. }
        ));
    }

    #[test]
    fn a_problem_replaces_every_drive_and_running_out_of_time_keeps_them() {
        let mut known = Known::default();
        let drive = Drive::Read {
            device: "/dev/sda".into(),
            row: json!({ "name": "a" }),
        };
        let read = json!([{ "name": "a", "asleep": 0, "note": "" }]);
        assert_eq!(known.publish(Ok(Round::Drives(vec![drive]))), read);
        assert_eq!(known.publish(Err(Missed::OutOfTime)), read);
        let unreadable = Drive::Unreadable {
            device: "/dev/sdd".into(),
            error: "Unknown USB bridge".into(),
        };
        assert_eq!(
            known.publish(Ok(Round::Drives(vec![unreadable]))),
            json!([{ "name": "/dev/sdd", "device": "/dev/sdd", "asleep": 0, "note": "Unknown USB bridge" }])
        );
        let problem = Round::Problem("smartctl isn't installed".into());
        assert_eq!(
            known.publish(Ok(problem)),
            json!([{ "name": "smartctl", "problem": "smartctl isn't installed", "drives": 0 }])
        );
        assert_eq!(known.publish(Err(Missed::OutOfTime)), json!([]));
    }

    #[test]
    fn series_are_named_by_model_and_serial() {
        assert_eq!(series_name("Disk", "123", "/dev/sda"), "Disk 123");
        assert_eq!(series_name("Disk", "", "/dev/sda"), "Disk /dev/sda");
        assert_eq!(series_name("", "123", "/dev/sda"), "123");
        assert_eq!(series_name("", "", "/dev/sda"), "/dev/sda");
    }

    /// As PowerShell prints Get-PhysicalDisk with its reliability counters.
    const WINDOWS: &str = r#"[
      {"FriendlyName":"Samsung SSD 980 PRO 1TB","SerialNumber":"0025_3851_1234_5678.  ","DeviceId":"0","BusType":"NVMe","HealthStatus":"Healthy","Temperature":39,"Wear":2,"PowerOnHours":1234},
      {"FriendlyName":"WDC WD40EFRX-68N32N0","SerialNumber":"WD-WCC7K1234567","DeviceId":"1","BusType":"SATA","HealthStatus":"Warning","Temperature":0,"Wear":null,"PowerOnHours":null},
      {"FriendlyName":"Msft Virtual Disk","SerialNumber":null,"DeviceId":"2","BusType":"SAS","HealthStatus":"Unknown","Temperature":null,"Wear":null,"PowerOnHours":null}
    ]"#;

    #[test]
    fn windows_counters_give_what_they_have() {
        let drives = parse_windows(WINDOWS.as_bytes()).unwrap();
        let rows: Vec<Value> = drives.into_iter().map(row).collect();
        assert_eq!(
            rows[0],
            json!({
                "name": "Samsung SSD 980 PRO 1TB 0025_3851_1234_5678.",
                "device": r"\\.\PhysicalDrive0",
                "model": "Samsung SSD 980 PRO 1TB",
                "serial": "0025_3851_1234_5678.",
                "protocol": "NVMe",
                "healthy": 1,
                "temperature_celsius": 39.0,
                "power_on_secs": 1234.0 * 3600.0,
                "used_percent": 2.0,
            })
        );
        // A drive predicting its own failure isn't healthy, and 0 isn't a temperature.
        assert_eq!(rows[1]["healthy"], 0);
        assert!(rows[1].get("temperature_celsius").is_none());
        // Unknown health says nothing either way.
        assert!(rows[2].get("healthy").is_none());
        assert_eq!(rows[2]["name"], "Msft Virtual Disk \\\\.\\PhysicalDrive2");
        assert_eq!(parse_windows(b"").unwrap(), []);
        assert!(parse_windows(b"Get-PhysicalDisk : Access denied").is_err());
    }
}
