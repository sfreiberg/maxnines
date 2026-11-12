//! Packets each network interface dropped, as running totals by interface name. A
//! drop is a packet that arrived or was ready to go but had nowhere to wait, which is
//! a sign the host can't keep up, where an error is a damaged packet.
//!
//! A count that can't be true is left out. The driver for a virtual machine's
//! interface on macOS adds over a billion to its received drops with every packet.

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

/// A count of received packets dropped, if it could be true: each one dropped
/// was first received, so there can't be more of them than that.
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
fn believable(dropped: u64, received: u64) -> Option<u64> {
    (dropped <= received).then_some(dropped)
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

/// Every interface with its counters, as `netstat` reads them, in full-size
/// numbers. The older list has them in 32 bits, which a busy interface overflows.
#[cfg(target_os = "macos")]
pub fn totals() -> HashMap<String, Drops> {
    use std::mem::size_of;

    let mut found = HashMap::new();
    let mut name = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
    let mut ask = |into: *mut libc::c_void, size: &mut usize| {
        // SAFETY: `into` is null, to ask how much there is, or points at `size`
        // bytes that the kernel fills no more than.
        unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as libc::c_uint,
                into,
                size,
                std::ptr::null_mut(),
                0,
            ) == 0
        }
    };
    let mut size = 0;
    if !ask(std::ptr::null_mut(), &mut size) {
        return found;
    }
    // An interface may appear in between, so there's room to spare.
    let mut list = vec![0u8; size + size / 4 + 1024];
    let mut size = list.len();
    if !ask(list.as_mut_ptr().cast(), &mut size) {
        return found;
    }
    let list = &list[..size.min(list.len())];

    // One message after another, each starting with how long it is and what
    // kind it is. Only an interface's own message has its counters.
    let mut rest = list;
    while rest.len() >= size_of::<libc::if_msghdr>() {
        // SAFETY: there are at least this many bytes, and any bytes make a valid
        // header, which is read without assuming where it starts.
        let header: libc::if_msghdr = unsafe { std::ptr::read_unaligned(rest.as_ptr().cast()) };
        let length = usize::from(header.ifm_msglen);
        if length == 0 || length > rest.len() {
            break;
        }
        let is_interface = i32::from(header.ifm_type) == libc::RTM_IFINFO2
            && length >= size_of::<libc::if_msghdr2>();
        if is_interface {
            // SAFETY: the message is at least this long, and is read as above.
            let interface: libc::if_msghdr2 =
                unsafe { std::ptr::read_unaligned(rest.as_ptr().cast()) };
            let counters = interface.ifm_data;
            let mut called = [0 as libc::c_char; libc::IF_NAMESIZE];
            // SAFETY: the buffer is as long as the longest name and its ending zero.
            let named = unsafe {
                !libc::if_indextoname(u32::from(interface.ifm_index), called.as_mut_ptr()).is_null()
            };
            if named {
                // SAFETY: a name that was found ends with a zero inside the buffer.
                let called = unsafe { std::ffi::CStr::from_ptr(called.as_ptr()) };
                let drops = Drops {
                    received: believable(counters.ifi_iqdrops, counters.ifi_ipackets),
                    // What its queue for sending had no room for.
                    transmitted: u64::try_from(interface.ifm_snd_drops).ok(),
                };
                found.insert(called.to_string_lossy().into_owned(), drops);
            }
        }
        rest = &rest[length..];
    }
    found
}

/// Each interface's link-level entry carries its counters.
#[cfg(target_os = "freebsd")]
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

#[cfg(target_os = "freebsd")]
fn platform_drops(data: &libc::if_data) -> Drops {
    Drops {
        received: believable(data.ifi_iqdrops, data.ifi_ipackets),
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

    #[test]
    fn a_count_of_drops_that_cannot_be_true_is_left_out() {
        assert_eq!(believable(0, 0), Some(0));
        assert_eq!(believable(12, 500), Some(12));
        assert_eq!(believable(500, 500), Some(500));
        // What macOS says of a virtual machine's interface that took 629,707 packets.
        assert_eq!(believable(1_723_470_159_561_422, 629_707), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_macs_interfaces_are_named_and_count_what_they_could_not_send() {
        let totals = totals();
        assert!(totals.contains_key("lo0"), "{totals:?}");
        assert!(totals.values().all(|drops| drops.transmitted.is_some()));
        // No interface is said to have dropped more than it could have received.
        for (name, drops) in &totals {
            assert!(drops.received.is_none_or(|count| count < 1 << 40), "{name}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn this_hosts_interfaces_count_received_drops() {
        let totals = totals();
        assert!(!totals.is_empty());
        assert!(
            totals.values().any(|drops| drops.received.is_some()),
            "{totals:?}"
        );
    }
}
