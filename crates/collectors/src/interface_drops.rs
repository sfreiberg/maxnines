//! Packets each network interface dropped, as running totals by interface name. A
//! drop is a packet that arrived or was ready to go but had nowhere to wait, which is
//! a sign the machine can't keep up, where an error is a damaged packet.
//!
//! macOS only counts received packets it dropped, so sent ones are left out there.

use std::collections::HashMap;

/// Received and sent packets dropped since the interface appeared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Drops {
    pub received: Option<u64>,
    pub transmitted: Option<u64>,
}

/// The change since the last totals, which an interface that was reset makes 0.
pub fn change(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    Some(after?.saturating_sub(before?))
}

#[cfg(target_os = "linux")]
pub fn totals() -> HashMap<String, Drops> {
    let Ok(interfaces) = std::fs::read_dir("/sys/class/net") else {
        return HashMap::new();
    };
    interfaces
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let statistics = entry.path().join("statistics");
            let number = |name: &str| {
                std::fs::read_to_string(statistics.join(name))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            };
            let drops = Drops {
                received: number("rx_dropped"),
                transmitted: number("tx_dropped"),
            };
            Some((entry.file_name().to_string_lossy().into_owned(), drops))
        })
        .collect()
}

/// Each interface's link-level entry carries its counters.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn totals() -> HashMap<String, Drops> {
    let mut found = HashMap::new();
    let mut first: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: the list is ours until it's freed below.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return found;
    }
    let mut next = first;
    while !next.is_null() {
        // SAFETY: each entry in the list is valid until the list is freed.
        let entry = unsafe { &*next };
        next = entry.ifa_next;
        let is_link = !entry.ifa_addr.is_null()
            // SAFETY: the address isn't null.
            && i32::from(unsafe { (*entry.ifa_addr).sa_family }) == libc::AF_LINK;
        if !is_link || entry.ifa_data.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a link-level entry's data is the interface's counters, and its name
        // ends with a zero.
        let (data, name) = unsafe {
            (
                &*entry.ifa_data.cast::<libc::if_data>(),
                std::ffi::CStr::from_ptr(entry.ifa_name),
            )
        };
        found.insert(name.to_string_lossy().into_owned(), platform_drops(data));
    }
    // SAFETY: the list came from getifaddrs and isn't used after this.
    unsafe { libc::freeifaddrs(first) };
    found
}

#[cfg(target_os = "macos")]
fn platform_drops(data: &libc::if_data) -> Drops {
    Drops {
        received: Some(u64::from(data.ifi_iqdrops)),
        transmitted: None,
    }
}

#[cfg(target_os = "freebsd")]
fn platform_drops(data: &libc::if_data) -> Drops {
    Drops {
        received: Some(data.ifi_iqdrops),
        transmitted: Some(data.ifi_oqdrops),
    }
}

/// By each interface's alias, which is the name sysinfo gives it, like `Ethernet`.
#[cfg(windows)]
pub fn totals() -> HashMap<String, Drops> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
    };

    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: Windows allocates the table, and it's freed below.
    if unsafe { GetIfTable2(&mut table) } != 0 || table.is_null() {
        return HashMap::new();
    }
    // SAFETY: the table holds `NumEntries` rows, one after another.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let found = rows
        .iter()
        .map(|row| {
            let length = row
                .Alias
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(row.Alias.len());
            let name = String::from_utf16_lossy(&row.Alias[..length]);
            let drops = Drops {
                received: Some(row.InDiscards),
                transmitted: Some(row.OutDiscards),
            };
            (name, drops)
        })
        .collect();
    // SAFETY: the table came from GetIfTable2 and isn't used after this.
    unsafe { FreeMibTable(table.cast()) };
    found
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
pub fn totals() -> HashMap<String, Drops> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_are_the_change_and_a_reset_is_none_rather_than_huge() {
        assert_eq!(change(Some(10), Some(15)), Some(5));
        assert_eq!(change(Some(10), Some(3)), Some(0));
        assert_eq!(change(None, Some(3)), None);
        assert_eq!(change(Some(3), None), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn this_machines_interfaces_count_received_drops() {
        let totals = totals();
        assert!(!totals.is_empty());
        assert!(
            totals.values().any(|drops| drops.received.is_some()),
            "{totals:?}"
        );
    }
}
