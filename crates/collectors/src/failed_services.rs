//! Services that should be running but stopped with an error, found without having to
//! name them first.
//!
//! On Linux they're the units systemd says have failed, as `systemctl --failed` lists.
//! On Windows they're services started automatically that stopped with an error code:
//! plenty of Windows' own stop by design once they've done their job, and those stop
//! cleanly. macOS and FreeBSD have no such state to read, so they're left out.

/// Names past this many are left out of the list, though they're still counted.
const MAX_NAMES: usize = 32;

/// Failed services, by name, in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Failed {
    pub names: Vec<String>,
}

impl Failed {
    #[cfg(any(target_os = "linux", windows, test))]
    fn new(mut names: Vec<String>) -> Self {
        names.sort();
        names.dedup();
        Self { names }
    }

    pub fn count(&self) -> usize {
        self.names.len()
    }

    /// Which ones, for reading rather than charting.
    pub fn listed(&self) -> String {
        let mut listed = self
            .names
            .iter()
            .take(MAX_NAMES)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if self.names.len() > MAX_NAMES {
            listed.push_str(&format!(" and {} more", self.names.len() - MAX_NAMES));
        }
        listed
    }
}

/// `systemctl list-units --state=failed --no-legend --plain`: a unit a line, its name
/// first.
#[cfg(any(target_os = "linux", test))]
fn parse_systemctl(text: &str) -> Failed {
    Failed::new(
        text.lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_string)
            .collect(),
    )
}

#[cfg(target_os = "linux")]
pub async fn failed_services() -> Option<Failed> {
    let arguments = ["list-units", "--state=failed", "--no-legend", "--plain"];
    let output = crate::system::run_quietly("systemctl", &arguments).await?;
    output
        .status
        .success()
        .then(|| parse_systemctl(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(windows)]
pub async fn failed_services() -> Option<Failed> {
    windows::failed()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub async fn failed_services() -> Option<Failed> {
    None
}

#[cfg(windows)]
mod windows {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
        SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_QUERY_CONFIG,
        SERVICE_STATE_ALL, SERVICE_STOPPED, SERVICE_WIN32,
    };

    use super::Failed;

    /// Closes a handle when it's no longer needed.
    struct Handle(SC_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle is open and only closed here.
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    /// Reads up to a zero, as Windows' own strings end.
    ///
    /// # Safety
    /// `text` has to be null or point to a string that ends with a zero.
    unsafe fn from_wide(text: *const u16) -> String {
        if text.is_null() {
            return String::new();
        }
        let mut length = 0;
        // SAFETY: the string ends with a zero, so nothing past it is read.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: those `length` characters were just read.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
    }

    fn starts_automatically(manager: &Handle, name: *const u16) -> bool {
        // SAFETY: the manager is open and the name ends with a zero.
        let service = unsafe { OpenServiceW(manager.0, name, SERVICE_QUERY_CONFIG) };
        if service.is_null() {
            return false;
        }
        let service = Handle(service);
        let mut needed = 0u32;
        // SAFETY: asking how much room the config needs, with nowhere to put it.
        unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &mut needed) };
        // In eights, for the config's alignment.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        // SAFETY: the buffer is as big as Windows asked for, and aligned.
        let read = unsafe { QueryServiceConfigW(service.0, config, needed, &mut needed) };
        // SAFETY: Windows filled the config in.
        read != 0 && unsafe { (*config).dwStartType } == SERVICE_AUTO_START
    }

    pub fn failed() -> Option<Failed> {
        let access = SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE;
        // SAFETY: no names means this machine's own service database.
        let manager = unsafe { OpenSCManagerW(null(), null(), access) };
        if manager.is_null() {
            return None;
        }
        let manager = Handle(manager);
        let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
        let enumerate =
            |buffer: *mut u8, size: u32, needed: &mut u32, count: &mut u32, resume: &mut u32| {
                // SAFETY: the manager is open, and the buffer holds `size` bytes.
                unsafe {
                    EnumServicesStatusExW(
                        manager.0,
                        SC_ENUM_PROCESS_INFO,
                        SERVICE_WIN32,
                        SERVICE_STATE_ALL,
                        buffer,
                        size,
                        needed,
                        count,
                        resume,
                        null(),
                    )
                }
            };
        enumerate(null_mut(), 0, &mut needed, &mut count, &mut resume);
        // In eights, for the entries' alignment, with room for a few more services.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8) + 512];
        let size = u32::try_from(buffer.len() * 8).ok()?;
        resume = 0;
        if enumerate(
            buffer.as_mut_ptr().cast(),
            size,
            &mut needed,
            &mut count,
            &mut resume,
        ) == 0
        {
            return None;
        }
        // SAFETY: Windows filled in `count` entries at the start of the buffer.
        let entries = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                count as usize,
            )
        };
        let names = entries
            .iter()
            .filter(|entry| {
                let status = &entry.ServiceStatusProcess;
                status.dwCurrentState == SERVICE_STOPPED && status.dwWin32ExitCode != 0
            })
            .filter(|entry| starts_automatically(&manager, entry.lpServiceName))
            // SAFETY: each name ends with a zero, in the buffer still held.
            .map(|entry| unsafe { from_wide(entry.lpServiceName) })
            .collect();
        Some(Failed::new(names))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemctl_lists_a_failed_unit_a_line() {
        let output = "nginx.service loaded failed failed A high performance web server\n\
                      backup.timer  loaded failed failed Nightly backup\n";
        assert_eq!(
            parse_systemctl(output).names,
            ["backup.timer", "nginx.service"]
        );
        assert_eq!(parse_systemctl("").count(), 0);
    }

    #[test]
    fn a_long_list_says_how_many_more_there_are() {
        let names: Vec<String> = (0..40).map(|n| format!("unit{n:02}")).collect();
        let failed = Failed::new(names);
        assert_eq!(failed.count(), 40);
        assert!(
            failed.listed().ends_with(", unit31 and 8 more"),
            "{}",
            failed.listed()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn this_machine_can_list_its_failed_units() {
        if std::path::Path::new("/run/systemd/system").exists() {
            assert!(failed_services().await.is_some());
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn this_machine_can_list_its_services() {
        assert!(failed_services().await.is_some());
    }
}
