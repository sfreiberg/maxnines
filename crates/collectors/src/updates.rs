//! Whether a machine is waiting to be restarted, and how many updates it has waiting,
//! as its own package manager sees them. Nothing here reaches out to the internet: the
//! package lists are whatever the machine last fetched on its own schedule.
//!
//! Each is left out where a system can't say: macOS has no flag for a restart, and the
//! update counts of Windows and macOS need their own services, so they're left out for
//! now.

/// Package managers can take a while to work through their lists.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const UPDATES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Updates waiting to be installed, and how many fix security problems, where the
/// package manager says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Updates {
    pub pending: u64,
    pub security: Option<u64>,
}

/// `apt-get -s dist-upgrade` prints an `Inst` line for each package it would install
/// or upgrade, naming where the new one comes from, which says if it's a security fix.
#[cfg(any(target_os = "linux", test))]
fn parse_apt(text: &str) -> Updates {
    let installs: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("Inst "))
        .collect();
    let security = installs
        .iter()
        .filter(|line| line.to_lowercase().contains("security"))
        .count();
    Updates {
        pending: installs.len() as u64,
        security: Some(security as u64),
    }
}

/// `dnf check-update` lists a package a line, as name, version and repository, then
/// any packages being replaced under a heading of their own.
#[cfg(any(target_os = "linux", test))]
fn parse_dnf(text: &str) -> u64 {
    text.lines()
        .take_while(|line| !line.starts_with("Obsoleting"))
        .filter(|line| line.split_whitespace().count() == 3)
        .count() as u64
}

/// `dnf updateinfo list --security` lists an advisory a line, with the package it fixes
/// last. One package can have several.
#[cfg(any(target_os = "linux", test))]
fn parse_dnf_security(text: &str) -> u64 {
    let packages: std::collections::HashSet<&str> = text
        .lines()
        .filter(|line| line.split_whitespace().count() >= 3)
        .filter_map(|line| line.split_whitespace().last())
        .collect();
    packages.len() as u64
}

/// `pkg version -qRL=` lists each package whose version differs from the catalog's.
#[cfg(any(target_os = "freebsd", test))]
fn parse_pkg(text: &str) -> u64 {
    text.lines().filter(|line| !line.trim().is_empty()).count() as u64
}

#[cfg(target_os = "linux")]
fn installed(program: &str) -> bool {
    ["/usr/bin", "/bin", "/usr/sbin"]
        .iter()
        .any(|folder| std::path::Path::new(folder).join(program).exists())
}

/// Debian and Ubuntu leave a file when an update needs a restart. Red Hat and Fedora
/// have a tool that says, by its exit code.
#[cfg(target_os = "linux")]
pub async fn reboot_required() -> Option<bool> {
    if std::path::Path::new("/var/run/reboot-required").exists() {
        return Some(true);
    }
    if installed("dpkg") {
        return Some(false);
    }
    if installed("needs-restarting") {
        let output = crate::system::run_quietly("needs-restarting", &["-r"]).await?;
        return match output.status.code() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        };
    }
    None
}

/// Windows Update and servicing each leave a key while a restart is waiting.
#[cfg(windows)]
pub async fn reboot_required() -> Option<bool> {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
    };

    const KEYS: [&str; 2] = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    ];
    let waiting = KEYS.iter().any(|key| {
        let key: Vec<u16> = key.encode_utf16().chain([0]).collect();
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: the key's name ends with a zero, and the handle has somewhere to go.
        let opened =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.as_ptr(), 0, KEY_READ, &mut handle) };
        if opened == 0 {
            // SAFETY: the key was opened just now.
            unsafe { RegCloseKey(handle) };
        }
        opened == 0
    });
    Some(waiting)
}

/// An updated kernel is installed but not yet the one running.
#[cfg(target_os = "freebsd")]
pub async fn reboot_required() -> Option<bool> {
    let installed = crate::system::run_quietly("freebsd-version", &["-k"]).await?;
    let running = crate::system::run_quietly("freebsd-version", &["-r"]).await?;
    let text =
        |output: &std::process::Output| String::from_utf8_lossy(&output.stdout).trim().to_string();
    (installed.status.success() && running.status.success())
        .then(|| text(&installed) != text(&running))
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", windows)))]
pub async fn reboot_required() -> Option<bool> {
    None
}

#[cfg(target_os = "linux")]
pub async fn pending_updates() -> Option<Updates> {
    use crate::system::run_with_timeout;

    if installed("apt-get") {
        // Only simulates, so it needs no rights and changes nothing.
        let arguments = ["-s", "-o", "Debug::NoLocking=1", "dist-upgrade"];
        let output = run_with_timeout("apt-get", &arguments, UPDATES_TIMEOUT).await?;
        return output
            .status
            .success()
            .then(|| parse_apt(&String::from_utf8_lossy(&output.stdout)));
    }
    let manager = ["dnf", "yum"]
        .into_iter()
        .find(|program| installed(program))?;
    // From what's cached, without fetching. 100 means there are updates.
    let arguments = ["-q", "--cacheonly", "check-update"];
    let output = run_with_timeout(manager, &arguments, UPDATES_TIMEOUT).await?;
    let pending = match output.status.code() {
        Some(0) => 0,
        Some(100) => parse_dnf(&String::from_utf8_lossy(&output.stdout)),
        _ => return None,
    };
    let arguments = ["-q", "--cacheonly", "updateinfo", "list", "--security"];
    let security = run_with_timeout(manager, &arguments, UPDATES_TIMEOUT)
        .await
        .filter(|output| output.status.success())
        .map(|output| parse_dnf_security(&String::from_utf8_lossy(&output.stdout)));
    Some(Updates { pending, security })
}

#[cfg(target_os = "freebsd")]
pub async fn pending_updates() -> Option<Updates> {
    let output =
        crate::system::run_with_timeout("pkg", &["version", "-qRL="], UPDATES_TIMEOUT).await?;
    output.status.success().then(|| Updates {
        pending: parse_pkg(&String::from_utf8_lossy(&output.stdout)),
        security: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub async fn pending_updates() -> Option<Updates> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_counts_each_install_and_the_security_ones() {
        let output = "\
NOTE: This is only a simulation!
Reading package lists...
Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2024a-0ubuntu0.22.04] (2024a-0ubuntu0.22.04.1 Ubuntu:22.04/jammy-updates [all])
Inst libc6 [2.36-9] (2.36-9+deb12u4 Debian-Security:12/stable-security [amd64])
Conf openssl (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates [amd64])
";
        assert_eq!(
            parse_apt(output),
            Updates {
                pending: 3,
                security: Some(2),
            }
        );
        assert_eq!(parse_apt("Reading package lists...\n").pending, 0);
    }

    #[test]
    fn dnf_counts_each_package_before_the_obsoleting_ones() {
        let output = "
kernel.x86_64                  6.8.9-300.fc40           updates
openssl-libs.x86_64            1:3.2.1-6.fc40           updates
Obsoleting Packages
grub2-tools.x86_64             1:2.06-120.fc40          updates
";
        assert_eq!(parse_dnf(output), 2);
    }

    #[test]
    fn dnf_counts_each_package_with_a_security_fix_once() {
        let output = "\
FEDORA-2024-0a1b2c3d4e Important/Sec. openssl-libs-1:3.2.1-6.fc40.x86_64
FEDORA-2024-1b2c3d4e5f Moderate/Sec.  openssl-libs-1:3.2.1-6.fc40.x86_64
FEDORA-2024-2c3d4e5f6a Important/Sec. kernel-6.8.9-300.fc40.x86_64
";
        assert_eq!(parse_dnf_security(output), 2);
    }

    #[test]
    fn pkg_lists_each_package_that_differs() {
        assert_eq!(parse_pkg("curl\nopenssl\n\n"), 2);
        assert_eq!(parse_pkg(""), 0);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_can_say_whether_it_needs_a_restart() {
        assert!(reboot_required().await.is_some());
    }
}
