//! Which mounted file systems hold data of their own on a machine's storage.
//!
//! Disk images, loop devices, container layers and the like are mounted like disks,
//! but they're files on another disk, memory, or another file system seen again. A
//! mounted installer would read as a full disk, and a container's layers would
//! repeat the disk under them, so they aren't reported at all.
//!
//! APFS volumes share the space of the container they're in, so on a Mac `/` and
//! `/System/Volumes/Data` are always exactly as full as each other. Only one volume
//! per container is reported, so one disk doesn't alert twice.
//!
//! sysinfo already leaves out network shares and memory file systems such as tmpfs,
//! and on macOS anything the Finder hides, such as the system's own volumes.

use std::collections::HashSet;
use std::path::Path;

use sysinfo::Disk;

/// Whether this is a file system of its own on real storage.
pub fn is_real(disk: &Disk) -> bool {
    // Pseudo file systems hold nothing and report no size.
    disk.total_space() > 0 && !is_stand_in(disk)
}

/// Keeps the first of the file systems that share their space, by mount point,
/// which puts `/` before the rest. Each is also sorted by mount point.
pub fn one_per_space<T>(
    mut disks: Vec<T>,
    mount_point: impl Fn(&T) -> &Path,
    space: impl Fn(&T) -> Option<String>,
) -> Vec<T> {
    disks.sort_by(|a, b| mount_point(a).cmp(mount_point(b)));
    let mut seen = HashSet::new();
    disks.retain(|disk| space(disk).is_none_or(|space| seen.insert(space)));
    disks
}

/// Where a file system's space comes from when it shares it with others: the
/// container, for an APFS volume.
#[cfg(target_os = "macos")]
pub fn shared_space(disk: &Disk) -> Option<String> {
    if disk.file_system() != "apfs" {
        return None;
    }
    let device = mounted_from(disk.mount_point())?;
    apfs_container(&device).map(str::to_owned)
}

#[cfg(not(target_os = "macos"))]
pub fn shared_space(_disk: &Disk) -> Option<String> {
    None
}

/// The container an APFS volume is in, which is the whole disk its name starts
/// with: `/dev/disk3` for `/dev/disk3s5`, or for `/dev/disk3s1s1`, a snapshot of one.
#[cfg(any(target_os = "macos", test))]
fn apfs_container(device: &str) -> Option<&str> {
    let number = device.strip_prefix("/dev/disk")?;
    let digits = number
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(number.len());
    (digits > 0).then(|| &device[..device.len() - number.len() + digits])
}

#[cfg(target_os = "linux")]
fn is_stand_in(disk: &Disk) -> bool {
    linux_stand_in(
        &disk.file_system().to_string_lossy(),
        &disk.name().to_string_lossy(),
        disk.mount_point(),
    )
}

#[cfg(target_os = "freebsd")]
fn is_stand_in(disk: &Disk) -> bool {
    freebsd_stand_in(
        &disk.file_system().to_string_lossy(),
        &mounted_from(disk.mount_point()).unwrap_or_default(),
    )
}

#[cfg(target_os = "macos")]
fn is_stand_in(disk: &Disk) -> bool {
    mounted_from(disk.mount_point())
        .and_then(|device| macos::interconnect(device.strip_prefix("/dev/")?))
        .is_some_and(|interconnect| interconnect == macos::DISK_IMAGE)
}

/// Windows only lists fixed and removable drives, so mounted ISOs are already left
/// out. Attached virtual disks stay, as they're usually somewhere to keep data, like
/// a Dev Drive.
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn is_stand_in(_disk: &Disk) -> bool {
    false
}

/// Loop devices are files mounted as disks, like snaps. Overlays are container
/// layers over another file system, except a container's own root, which is all an
/// agent running in one can see.
#[cfg(any(target_os = "linux", test))]
fn linux_stand_in(file_system: &str, device: &str, mount_point: &Path) -> bool {
    device.starts_with("/dev/loop") || (file_system == "overlay" && mount_point != Path::new("/"))
}

/// Memory disks are memory or files mounted as disks. Null mounts show another file
/// system again somewhere else, as jails do.
#[cfg(any(target_os = "freebsd", test))]
fn freebsd_stand_in(file_system: &str, device: &str) -> bool {
    device.starts_with("/dev/md") || file_system == "nullfs"
}

/// The device a file system is mounted from, like `/dev/disk3s5`.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn mounted_from(mount_point: &Path) -> Option<String> {
    let stats = rustix::fs::statfs(mount_point).ok()?;
    // SAFETY: the kernel fills the name and ends it with a nul.
    let device = unsafe { std::ffi::CStr::from_ptr(stats.f_mntfromname.as_ptr()) };
    Some(device.to_string_lossy().into_owned())
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::CString;

    use objc2_core_foundation::{CFDictionary, CFRetained, CFString, CFType};
    use objc2_io_kit::{
        IOBSDNameMatching, IOObjectRelease, IORegistryEntrySearchCFProperty,
        IOServiceGetMatchingService, kIOMainPortDefault, kIORegistryIterateParents,
        kIORegistryIterateRecursively, kIOServicePlane,
    };

    /// How macOS says a disk is a disk image, which Disk Utility shows as a protocol
    /// of "Disk Image". Mounting a `.dmg` makes one, as does a RAM disk.
    pub const DISK_IMAGE: &str = "Virtual Interface";

    /// How a disk is connected, like `USB`, `PCI-Express` or a disk image. It's on
    /// whichever device under the volume says, so the search goes up from the volume.
    pub fn interconnect(bsd_name: &str) -> Option<String> {
        let bsd_name = CString::new(bsd_name).ok()?;
        // SAFETY: the name is a valid C string, and the matching dictionary is
        // handed over to IOServiceGetMatchingService, which releases it.
        let service = unsafe {
            let matching = IOBSDNameMatching(kIOMainPortDefault, 0, bsd_name.as_ptr())?;
            IOServiceGetMatchingService(
                kIOMainPortDefault,
                Some(CFRetained::<CFDictionary>::from(&matching)),
            )
        };
        if service == 0 {
            return None;
        }
        // SAFETY: the service is valid until released below, and the plane's name
        // is a C string IOKit only reads.
        let protocol = unsafe {
            IORegistryEntrySearchCFProperty(
                service,
                kIOServicePlane.as_ptr().cast_mut().cast(),
                Some(&CFString::from_static_str("Protocol Characteristics")),
                None,
                kIORegistryIterateRecursively | kIORegistryIterateParents,
            )
        };
        IOObjectRelease(service);

        let protocol = protocol?.downcast::<CFDictionary>().ok()?;
        // SAFETY: IOKit's property dictionaries have strings for keys.
        let protocol = unsafe { protocol.cast_unchecked::<CFString, CFType>() };
        let interconnect = protocol.get(&CFString::from_static_str("Physical Interconnect"))?;
        Some(interconnect.downcast::<CFString>().ok()?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_devices_and_container_layers_are_not_disks_on_linux() {
        assert!(!linux_stand_in("ext4", "/dev/nvme0n1p2", Path::new("/")));
        assert!(!linux_stand_in(
            "xfs",
            "/dev/mapper/vg-data",
            Path::new("/data")
        ));
        assert!(!linux_stand_in("ext4", "/dev/md0", Path::new("/raid")));
        assert!(linux_stand_in(
            "ext4",
            "/dev/loop3",
            Path::new("/mnt/image")
        ));
        let layer = Path::new("/var/lib/docker/overlay2/abc/merged");
        assert!(linux_stand_in("overlay", "overlay", layer));
        assert!(!linux_stand_in("overlay", "overlay", Path::new("/")));
    }

    #[test]
    fn memory_disks_and_null_mounts_are_not_disks_on_freebsd() {
        assert!(!freebsd_stand_in("ufs", "/dev/ada0p2"));
        assert!(!freebsd_stand_in("zfs", "zroot/usr/home"));
        assert!(freebsd_stand_in("ufs", "/dev/md0"));
        assert!(freebsd_stand_in("nullfs", "/usr/home"));
    }

    #[test]
    fn apfs_volumes_belong_to_the_whole_disk_they_are_named_after() {
        assert_eq!(apfs_container("/dev/disk3s5"), Some("/dev/disk3"));
        assert_eq!(apfs_container("/dev/disk3s1s1"), Some("/dev/disk3"));
        assert_eq!(apfs_container("/dev/disk12s2"), Some("/dev/disk12"));
        assert_eq!(apfs_container("/dev/disks"), None);
        assert_eq!(apfs_container("map auto_home"), None);
    }

    #[test]
    fn one_file_system_is_kept_for_each_space_and_root_comes_first() {
        let disks = vec![
            ("/System/Volumes/Data", Some("/dev/disk3")),
            ("/Volumes/Media", Some("/dev/disk5")),
            ("/", Some("/dev/disk3")),
            ("/Volumes/Backup", Some("/dev/disk5")),
            ("/Volumes/USB", None),
            ("/Volumes/Other", None),
        ];
        let kept: Vec<&str> = one_per_space(
            disks,
            |(mount_point, _)| Path::new(mount_point),
            |(_, space)| space.map(str::to_owned),
        )
        .into_iter()
        .map(|(mount_point, _)| mount_point)
        .collect();
        assert_eq!(
            kept,
            ["/", "/Volumes/Backup", "/Volumes/Other", "/Volumes/USB"]
        );
    }

    #[test]
    fn the_machine_has_a_real_file_system() {
        let disks = sysinfo::Disks::new_with_refreshed_list().unwrap();
        assert!(disks.iter().any(is_real), "{disks:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_start_up_disk_is_not_a_disk_image() {
        let device = mounted_from(Path::new("/")).unwrap();
        let interconnect = macos::interconnect(device.strip_prefix("/dev/").unwrap()).unwrap();
        assert_ne!(interconnect, macos::DISK_IMAGE);
    }
}
