//! Whether a host's time service is keeping its clock in sync, as the host itself
//! knows it, with nothing asked over the network.
//!
//! On Linux, FreeBSD and macOS it's the kernel's own view, read with one system call
//! that changes nothing (`adjtimex` on Linux, `ntp_adjtime` on the others), so it
//! works whichever time service runs: chrony, ntpd, systemd-timesyncd or macOS's
//! timed. Each tells the kernel whether it has the clock in sync, and how far out it
//! could be, which the kernel then grows by half a millisecond every second until the
//! service next corrects it. A service that stops leaves the clock marked synced, so
//! it shows as that error growing. Linux marks the clock unsynced once the error
//! passes 16 seconds.
//!
//! On Windows it's the Windows Time service's performance counters, which Windows
//! has published since Windows 10 1607 and Server 2016: how many time sources it's
//! using, and how far the clock is from them.

use anyhow::Result;
use serde_json::{Map, Value, json};

use crate::Collector;

/// One reading of the clock's sync. A number left out isn't known on this system.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Reading {
    pub synced: Option<bool>,
    /// The most the clock could be out, by the kernel's reckoning.
    pub max_error_secs: Option<f64>,
    /// How far the clock is from its time source, by the Windows Time service's.
    pub offset_secs: Option<f64>,
    /// How many time sources the Windows Time service is using.
    pub sources: Option<u64>,
    /// Why nothing could be read, for the host's page.
    pub problem: Option<String>,
}

impl Reading {
    pub fn to_value(&self) -> Value {
        let mut row = Map::new();
        if let Some(synced) = self.synced {
            row.insert("synced".into(), json!(u8::from(synced)));
        }
        let numbers = [
            ("max_error_secs", self.max_error_secs),
            ("offset_secs", self.offset_secs),
            ("sources", self.sources.map(|sources| sources as f64)),
        ];
        for (name, number) in numbers {
            if let Some(number) = number.filter(|number| number.is_finite()) {
                row.insert(name.into(), json!(number));
            }
        }
        row.insert(
            "problem".into(),
            json!(self.problem.clone().unwrap_or_default()),
        );
        Value::Object(row)
    }
}

/// The kernel's clock status bit saying no time service has the clock in sync, the
/// same on every system that has it.
#[cfg_attr(not(unix), allow(dead_code))]
const STA_UNSYNC: i32 = 0x0040;

/// What a kernel's clock status and maximum error, in microseconds as every kernel
/// keeps it, say.
#[cfg_attr(not(unix), allow(dead_code))]
fn from_kernel(status: i32, max_error_micros: i64) -> Reading {
    Reading {
        synced: Some(status & STA_UNSYNC == 0),
        max_error_secs: Some(max_error_micros as f64 / 1_000_000.0),
        ..Reading::default()
    }
}

/// What the Windows Time service is doing.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Service {
    Running,
    /// Stopped, though it should be running: set to start with Windows, or turned
    /// off.
    Off,
    /// Stopped, and started only when Windows needs it, as it is on many hosts that
    /// aren't in a domain.
    Idle,
    /// Not on this host, or not readable.
    Missing,
}

/// What the Windows Time service's state and counters say: how many time sources
/// it's using, and how far the clock is from them, which Windows counts in
/// microseconds.
#[cfg_attr(not(windows), allow(dead_code))]
fn from_windows(service: Service, sources: Option<f64>, offset_micros: Option<f64>) -> Reading {
    let problem = |problem: &str| Some(problem.to_string());
    match (service, sources) {
        (Service::Running, Some(sources)) => {
            let synced = sources >= 1.0;
            Reading {
                synced: Some(synced),
                sources: Some(sources as u64),
                // With no source, there's nothing to be offset from.
                offset_secs: offset_micros
                    .filter(|_| synced)
                    .map(|micros| micros / 1_000_000.0),
                ..Reading::default()
            }
        }
        (Service::Running, None) => Reading {
            problem: problem(
                "The Windows Time service is running, but its counters couldn't be read",
            ),
            ..Reading::default()
        },
        (Service::Off, _) => Reading {
            synced: Some(false),
            problem: problem("The Windows Time service isn't running"),
            ..Reading::default()
        },
        (Service::Idle, _) => Reading {
            problem: problem(
                "The Windows Time service isn't running now, and Windows starts it only when it's needed, so whether the clock is synced isn't known until it does",
            ),
            ..Reading::default()
        },
        (Service::Missing, _) => Reading {
            synced: Some(false),
            problem: problem("The Windows Time service couldn't be found"),
            ..Reading::default()
        },
    }
}

pub struct TimeSyncCollector {
    #[cfg(windows)]
    counters: windows::Counters,
}

impl TimeSyncCollector {
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            counters: windows::Counters::new(),
        }
    }

    fn read(&mut self) -> Reading {
        #[cfg(unix)]
        {
            kernel::read()
        }
        #[cfg(windows)]
        {
            self.counters.read()
        }
    }
}

impl Default for TimeSyncCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for TimeSyncCollector {
    fn name(&self) -> &'static str {
        "time_sync"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.read().to_value())
    }
}

#[cfg(unix)]
mod kernel {
    use super::{Reading, from_kernel};

    /// Asks the kernel with nothing set, which any user may do.
    pub fn read() -> Reading {
        // SAFETY: an all-zero timex is a valid one that sets nothing.
        let mut timex: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: timex is a valid timex for the kernel to fill in.
        #[cfg(target_os = "linux")]
        let state = unsafe { libc::adjtimex(&mut timex) };
        // SAFETY: as above.
        #[cfg(not(target_os = "linux"))]
        let state = unsafe { libc::ntp_adjtime(&mut timex) };
        if state < 0 {
            return Reading {
                problem: Some(format!(
                    "The kernel wouldn't say whether the clock is synced: {}",
                    std::io::Error::last_os_error()
                )),
                ..Reading::default()
            };
        }
        // A c_long, which is 32 bits on some systems.
        from_kernel(timex.status, timex.maxerror as i64)
    }
}

#[cfg(windows)]
mod windows {
    use windows_sys::Win32::System::Services::{
        SERVICE_AUTO_START, SERVICE_DISABLED, SERVICE_RUNNING,
    };

    use super::{Reading, Service, from_windows};
    use crate::counters::{Reading as Counter, pdh};

    const SOURCES: &str = r"\Windows Time Service\NTP Client Time Source Count";
    const OFFSET: &str = r"\Windows Time Service\Computed Time Offset";

    pub struct Counters {
        counters: pdh::Counters,
    }

    impl Counters {
        pub fn new() -> Self {
            Self {
                counters: pdh::Counters::new(vec![SOURCES.to_string(), OFFSET.to_string()]),
            }
        }

        pub fn read(&mut self) -> Reading {
            let service = match crate::failed_services::windows::service("W32Time") {
                Some((SERVICE_RUNNING, _)) => Service::Running,
                Some((_, SERVICE_AUTO_START | SERVICE_DISABLED)) => Service::Off,
                Some(_) => Service::Idle,
                None => Service::Missing,
            };
            let readings = self.counters.read();
            let value = |path: &str| {
                readings.iter().find(|(read, _)| read == path).and_then(
                    |(_, reading)| match reading {
                        Counter::Values { values, .. } => values.first().map(|(_, value)| *value),
                        Counter::Waiting | Counter::Failed(_) => None,
                    },
                )
            };
            from_windows(service, value(SOURCES), value(OFFSET))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/time_sync")
    }

    /// The source count and offset in what Get-Counter printed, or nothing where it
    /// had no data to return, as with the service stopped.
    fn windows_counters(windows: &str, name: &str) -> (Option<f64>, Option<f64>) {
        let dir = fixtures().join(windows);
        let Ok(json) = std::fs::read_to_string(dir.join(format!("{name}.json"))) else {
            assert!(
                dir.join(format!("{name}.error")).exists(),
                "{windows} {name}"
            );
            return (None, None);
        };
        let samples: Value = serde_json::from_str(&json).unwrap();
        let value = |counter: &str| {
            samples.as_array().unwrap().iter().find_map(|sample| {
                let path = sample["Path"].as_str()?;
                path.ends_with(counter)
                    .then(|| sample["CookedValue"].as_f64())
                    .flatten()
            })
        };
        (
            value(r"\ntp client time source count"),
            value(r"\computed time offset"),
        )
    }

    const WINDOWS: [&str; 2] = ["windows-10.0.20348", "windows-10.0.26100"];

    /// What the kernel said in one capture, as read.c prints it.
    fn kernel(system: &str, name: &str) -> Reading {
        let path = fixtures().join(system).join(format!("{name}.txt"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{path:?}"));
        let field = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_else(|| panic!("{key} in {path:?}"))
        };
        let status = i32::from_str_radix(field("status").trim_start_matches("0x"), 16).unwrap();
        from_kernel(status, field("maxerror").parse().unwrap())
    }

    /// The clock's largest possible error, which every capture has.
    fn error(reading: &Reading) -> f64 {
        reading.max_error_secs.unwrap()
    }

    #[test]
    fn linux_is_synced_by_chrony_and_systemd_timesyncd_within_milliseconds() {
        for system in ["ubuntu-22.04", "ubuntu-24.04"] {
            for name in ["chrony-synced", "chrony-started", "timesyncd-synced"] {
                let reading = kernel(system, name);
                assert_eq!(reading.synced, Some(true), "{system} {name}");
                assert!(error(&reading) < 0.01, "{system} {name}: {reading:?}");
            }
        }
    }

    #[test]
    fn a_stopped_time_service_leaves_the_clock_synced_with_its_error_growing() {
        let services = [
            ("ubuntu-22.04", "chrony"),
            ("ubuntu-24.04", "chrony"),
            ("ubuntu-22.04", "timesyncd"),
            ("ubuntu-24.04", "timesyncd"),
            ("freebsd-14.3-RELEASE", "ntpd"),
            ("freebsd-15.0-RELEASE", "ntpd"),
        ];
        for (system, service) in services {
            let stopped = kernel(system, &format!("{service}-stopped"));
            let later = kernel(system, &format!("{service}-stopped-2m"));
            assert_eq!((stopped.synced, later.synced), (Some(true), Some(true)));
            // Half a millisecond a second, for the two minutes between.
            let grown = error(&later) - error(&stopped);
            assert!(
                (0.055..0.065).contains(&grown),
                "{system} {service}: {grown}"
            );
        }
    }

    #[test]
    fn freebsd_is_unsynced_until_ntpd_has_synced() {
        for system in ["freebsd-14.3-RELEASE", "freebsd-15.0-RELEASE"] {
            let before = kernel(system, "as-found");
            assert_eq!(before.synced, Some(false), "{system}");
            assert!(error(&before) >= 16.0);
            let synced = kernel(system, "ntpd-synced");
            assert_eq!(synced.synced, Some(true), "{system}");
            assert!(error(&synced) < 0.1);
        }
    }

    #[test]
    fn a_mac_with_network_time_off_is_unsynced_until_its_turned_on() {
        let system = "macos-26.7.2";
        for name in ["as-found", "network-time-off", "network-time-off-2m"] {
            let reading = kernel(system, name);
            assert_eq!(reading.synced, Some(false), "{name}");
            // Off for the ten days since the runner's image was made.
            assert!(error(&reading) > 5.0 * 86_400.0, "{name}");
        }
        assert_eq!(kernel(system, "network-time-on-2m").synced, Some(true));
    }

    #[test]
    fn windows_with_a_time_source_is_synced_with_its_offset_in_seconds() {
        for windows in WINDOWS {
            for name in ["as-found", "resynced", "started"] {
                let (sources, offset) = windows_counters(windows, name);
                let reading = from_windows(Service::Running, sources, offset);
                assert_eq!(reading.synced, Some(true), "{windows} {name}");
                assert_eq!(reading.sources, Some(1));
                // w32tm said a tenth of a millisecond or so each time.
                let offset = reading.offset_secs.unwrap();
                assert!(offset > 0.0 && offset < 0.001, "{windows} {name}: {offset}");
                assert_eq!(reading.problem, None);
            }
        }
    }

    #[test]
    fn the_counters_say_nothing_with_the_service_stopped_so_its_state_decides() {
        for windows in WINDOWS {
            let (sources, offset) = windows_counters(windows, "stopped");
            assert_eq!((sources, offset), (None, None));
            // Set to start with Windows, or turned off: it should be running.
            let off = from_windows(Service::Off, sources, offset);
            assert_eq!(off.synced, Some(false));
            assert!(off.problem.unwrap().contains("isn't running"));
            // Started only when needed: not knowing isn't the same as not synced.
            let idle = from_windows(Service::Idle, sources, offset);
            assert_eq!(idle.synced, None);
            assert!(idle.problem.unwrap().contains("isn't known"));
            // Running, yet with nothing to read, says so rather than guessing.
            let unreadable = from_windows(Service::Running, sources, offset);
            assert_eq!((unreadable.synced, unreadable.offset_secs), (None, None));
            assert!(unreadable.problem.is_some());
        }
        assert_eq!(
            from_windows(Service::Missing, None, None).synced,
            Some(false)
        );
    }

    #[test]
    fn windows_with_no_time_source_isnt_synced_and_has_no_offset() {
        let reading = from_windows(Service::Running, Some(0.0), Some(175.0));
        assert_eq!(reading.synced, Some(false));
        assert_eq!((reading.sources, reading.offset_secs), (Some(0), None));
    }

    #[test]
    fn what_is_sent_leaves_out_what_isnt_known() {
        let kernel = from_kernel(0x2001, 48_677).to_value();
        assert_eq!(
            kernel,
            json!({ "synced": 1, "max_error_secs": 0.048677, "problem": "" })
        );
        let idle = from_windows(Service::Idle, None, None).to_value();
        assert_eq!(idle.as_object().unwrap().len(), 1, "{idle}");
    }

    #[test]
    fn this_host_says_how_its_clock_is_kept() {
        let reading = TimeSyncCollector::new().read();
        #[cfg(unix)]
        {
            assert_eq!(reading.problem, None);
            assert!(reading.synced.is_some());
            assert!(reading.max_error_secs.unwrap() >= 0.0);
        }
        #[cfg(windows)]
        assert!(reading.synced.is_some() || reading.problem.is_some());
    }
}
