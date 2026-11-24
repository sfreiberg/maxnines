//! Whether a host is up to date: how many updates are waiting, how many of them
//! fix security problems where the system says so, whether it needs a reboot to
//! finish one, and how old the package lists those answers come from are.
//!
//! Each system is asked through its own package manager, the one its distribution
//! uses: apt on Debian and Ubuntu, dnf (or yum) on Red Hat's family, zypper on
//! SUSE, pacman on Arch and apk on Alpine, pkg on FreeBSD, softwareupdate on macOS
//! and the Windows Update Agent on Windows. None of them is told to fetch new
//! package lists: the system's own timers do that, and how old the lists are is
//! reported, so lists that have stopped being refreshed are noticed.
//!
//! Only dnf needs root, to read the system's own copy of the package lists, so an
//! agent that gave root up asks for it through `sudo -n`, as smartctl does.

use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use serde_json::{Map, Value, json};

use crate::background::Background;
use crate::collector::Collector;
#[cfg(unix)]
use crate::programs::Ran;

/// Updates arrive a few times a day at most, and asking is slow.
const EVERY: Duration = Duration::from_secs(60 * 60);
/// The first look comes within this, so a new agent shows its updates soon.
const FIRST_WITHIN: Duration = Duration::from_secs(2 * 60);
/// How long one look gets. Windows can take minutes to search.
const ROUND_LIMIT: Duration = Duration::from_secs(10 * 60);
/// How long one program run gets.
const RUN_LIMIT: Duration = Duration::from_secs(5 * 60);

pub struct UpdatesCollector {
    background: Background,
}

impl UpdatesCollector {
    pub fn new() -> Result<Self> {
        let mut background = Background::new();
        let mut last = Value::Null;
        background.repeat_from(FIRST_WITHIN, EVERY, Some(ROUND_LIMIT), read, move |found| {
            // Out of time: what was known still stands.
            if let Some(found) = found {
                last = Found::to_value(&found);
            }
            last.clone()
        })?;
        Ok(Self { background })
    }
}

impl Collector for UpdatesCollector {
    fn name(&self) -> &'static str {
        "updates"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self
            .background
            .latest()
            .into_iter()
            .next()
            .unwrap_or(Value::Null))
    }
}

/// What one look found. A number left out wasn't known: the system doesn't say it,
/// or asking failed.
#[derive(Debug, Default, PartialEq)]
struct Found {
    /// What was asked, such as `apt` or `dnf`.
    manager: &'static str,
    pending: Option<u64>,
    security: Option<u64>,
    /// FreeBSD's installed packages with known vulnerabilities.
    vulnerable: Option<u64>,
    reboot_required: Option<bool>,
    lists_age_secs: Option<u64>,
    /// Why nothing could be asked, with what to do about it.
    problem: Option<String>,
    /// What went wrong with part of it.
    notes: Vec<String>,
}

impl Found {
    fn problem(manager: &'static str, problem: impl Into<String>) -> Self {
        Found {
            manager,
            problem: Some(problem.into()),
            ..Found::default()
        }
    }

    /// Its row. The texts are always there, even when empty, as the server keeps a
    /// row's newest text until it's replaced.
    fn to_value(&self) -> Value {
        let mut row = Map::new();
        row.insert("manager".into(), json!(self.manager));
        let numbers = [
            ("pending", self.pending),
            ("security", self.security),
            ("vulnerable", self.vulnerable),
            ("reboot_required", self.reboot_required.map(u64::from)),
            ("lists_age_secs", self.lists_age_secs),
        ];
        for (name, number) in numbers {
            if let Some(number) = number {
                row.insert(name.into(), json!(number));
            }
        }
        row.insert(
            "problem".into(),
            json!(self.problem.clone().unwrap_or_default()),
        );
        row.insert("note".into(), json!(self.notes.join(" ")));
        Value::Object(row)
    }
}

async fn read() -> Found {
    #[cfg(target_os = "linux")]
    {
        linux::read().await
    }
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read().await
    }
    #[cfg(target_os = "macos")]
    {
        macos::read().await
    }
    #[cfg(windows)]
    {
        windows::read().await
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos",
        windows
    )))]
    {
        Found::problem("", "Updates aren't read on this system")
    }
}

/// Runs a program for what it prints, within [`RUN_LIMIT`].
#[cfg(unix)]
async fn run(program: &str, arguments: &[&str]) -> std::result::Result<Ran, String> {
    crate::programs::run(program, arguments, RUN_LIMIT).await
}

/// The first line a program said went wrong, or its exit code.
#[cfg(unix)]
fn failure(program: &str, ran: &Ran) -> String {
    match ran.stderr.lines().find(|line| !line.trim().is_empty()) {
        Some(line) => format!("{program}: {}", line.trim()),
        None => format!("{program} exited with {:?}", ran.code),
    }
}

/// How long ago the newest of these files changed, in seconds.
#[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
fn age_of_newest(files: impl IntoIterator<Item = std::path::PathBuf>) -> Option<u64> {
    let newest = files
        .into_iter()
        .filter_map(|file| std::fs::metadata(file).ok()?.modified().ok())
        .max()?;
    Some(
        SystemTime::now()
            .duration_since(newest)
            .unwrap_or_default()
            .as_secs(),
    )
}

/// The files in `folder`, or in each folder in it with `inside`, whose names pass
/// `wanted`.
#[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
fn files_in(
    folder: &str,
    inside: Option<&str>,
    wanted: impl Fn(&str) -> bool,
) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        match inside {
            None => {
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(&wanted)
                {
                    files.push(path);
                }
            }
            Some(inside) => {
                let file = path.join(inside);
                if file
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(&wanted)
                {
                    files.push(file);
                }
            }
        }
    }
    files
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Lines with something on them.
#[cfg_attr(windows, allow(dead_code))]
fn lines(text: &[u8]) -> impl Iterator<Item = &str> {
    std::str::from_utf8(text)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        Found, age_of_newest, exists, failure, files_in, kernel_needs_reboot, parse_apk, parse_apt,
        parse_checkupdates, parse_dnf_security, parse_dnf_updates, parse_zypper, run,
    };
    use crate::programs::{first_of, refused_by_sudo};

    /// Which package manager a distribution uses, from os-release.
    #[derive(Debug, PartialEq)]
    pub enum Manager {
        Apt,
        Dnf,
        Zypper,
        Pacman,
        Apk,
    }

    /// The distribution's own ID first, then those it says it's like.
    pub fn manager_of(os_release: &str) -> Option<Manager> {
        let field = |name: &str| {
            os_release.lines().find_map(|line| {
                let value = line.strip_prefix(name)?.strip_prefix('=')?;
                Some(
                    value
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_lowercase(),
                )
            })
        };
        let mut ids: Vec<String> = field("ID").into_iter().collect();
        ids.extend(
            field("ID_LIKE")
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string),
        );
        ids.iter().find_map(|id| match id.as_str() {
            "debian" | "ubuntu" => Some(Manager::Apt),
            "rhel" | "fedora" | "centos" | "rocky" | "almalinux" | "amzn" | "ol" => {
                Some(Manager::Dnf)
            }
            "suse" | "opensuse" | "sles" | "opensuse-leap" | "opensuse-tumbleweed" => {
                Some(Manager::Zypper)
            }
            "arch" => Some(Manager::Pacman),
            "alpine" => Some(Manager::Apk),
            _ => None,
        })
    }

    pub async fn read() -> Found {
        let os_release = std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default();
        let mut found = match manager_of(&os_release) {
            Some(Manager::Apt) => apt().await,
            Some(Manager::Dnf) => dnf().await,
            Some(Manager::Zypper) => zypper().await,
            Some(Manager::Pacman) => pacman().await,
            Some(Manager::Apk) => apk().await,
            None => Found::problem(
                "",
                "This distribution's package manager isn't one MaxNines reads: apt, dnf, yum, zypper, pacman or apk",
            ),
        };
        found.reboot_required = reboot_required(found.manager).await;
        found
    }

    async fn apt() -> Found {
        // A simulation needs no root and, told not to, takes no lock, so it never
        // waits for an upgrade that's running.
        let arguments = ["-s", "-o", "Debug::NoLocking=true", "dist-upgrade"];
        let mut found = match run("/usr/bin/apt-get", &arguments).await {
            Err(error) => Found::problem("apt", error),
            Ok(ran) if ran.code != Some(0) => Found::problem("apt", failure("apt-get", &ran)),
            Ok(ran) => {
                let (pending, security) = parse_apt(&ran.stdout);
                Found {
                    manager: "apt",
                    pending: Some(pending),
                    security: Some(security),
                    ..Found::default()
                }
            }
        };
        // apt's daily timer marks each successful refresh; without it, the
        // newest list says.
        found.lists_age_secs = age_of_newest(
            ["/var/lib/apt/periodic/update-success-stamp"]
                .into_iter()
                .map(std::path::PathBuf::from)
                .filter(|stamp| stamp.exists()),
        )
        .or_else(|| {
            age_of_newest(files_in("/var/lib/apt/lists", None, |name| {
                name.ends_with("Release")
            }))
        });
        found
    }

    /// The sudoers rule that lets the agent's user run dnf as it does.
    fn dnf_rule(dnf: &str) -> String {
        format!(
            "maxnines ALL=(root) NOPASSWD: {dnf} -C -q check-update, {dnf} -C -q updateinfo list --security"
        )
    }

    async fn dnf() -> Found {
        let Some(dnf) = first_of(&["/usr/bin/dnf", "/usr/bin/yum"]) else {
            return Found::problem("dnf", "Neither dnf nor yum is installed");
        };
        let manager = if dnf.ends_with("yum") { "yum" } else { "dnf" };
        // Only root reads the system's copy of the package lists; anyone else
        // would get a copy of their own, fetched for them. -C keeps to the copy
        // there is.
        let root = nix::unistd::geteuid().is_root();
        let sudo = if root {
            None
        } else {
            match first_of(&["/usr/bin/sudo"]) {
                Some(sudo) => Some(sudo),
                None => {
                    return Found::problem(
                        manager,
                        format!(
                            "{manager} needs root to read the system's package lists, and sudo isn't installed, so the agent can't ask for it"
                        ),
                    );
                }
            }
        };
        let ask = |arguments: &'static [&'static str]| async move {
            let mut words = Vec::new();
            let program = match sudo {
                Some(sudo) => {
                    words.extend(["-n", dnf]);
                    sudo
                }
                None => dnf,
            };
            words.extend(arguments);
            run(program, &words).await
        };

        let mut found = match ask(&["-C", "-q", "check-update"]).await {
            Err(error) => return Found::problem(manager, error),
            Ok(ran) if refused_by_sudo(&ran) => {
                return Found::problem(
                    manager,
                    format!(
                        "{manager} needs root to read the system's package lists, and sudo didn't allow it. \
                         Let the agent's user run it with a sudoers rule such as: {}",
                        dnf_rule(dnf)
                    ),
                );
            }
            // 100 means there are updates, and 0 that there are none.
            Ok(ran) if ran.code == Some(100) || ran.code == Some(0) => Found {
                manager,
                pending: Some(parse_dnf_updates(&ran.stdout)),
                ..Found::default()
            },
            Ok(ran) => return Found::problem(manager, failure(manager, &ran)),
        };
        match ask(&["-C", "-q", "updateinfo", "list", "--security"]).await {
            Ok(ran) if ran.code == Some(0) => {
                found.security = Some(parse_dnf_security(&ran.stdout));
            }
            Ok(ran) => found.notes.push(format!(
                "Security updates couldn't be counted. {}",
                failure(manager, &ran)
            )),
            Err(error) => found
                .notes
                .push(format!("Security updates couldn't be counted. {error}")),
        }
        let mut lists = files_in("/var/cache/dnf", Some("repodata/repomd.xml"), |_| true);
        lists.extend(files_in(
            "/var/cache/libdnf5",
            Some("repodata/repomd.xml"),
            |_| true,
        ));
        lists.extend(
            ["/var/cache/dnf/last_makecache"]
                .into_iter()
                .map(std::path::PathBuf::from),
        );
        // yum keeps them a level deeper, under its architecture and release.
        for arch in files_in("/var/cache/yum", None, |_| true) {
            for release in files_in(&arch.to_string_lossy(), None, |_| true) {
                lists.extend(files_in(
                    &release.to_string_lossy(),
                    Some("repomd.xml"),
                    |_| true,
                ));
            }
        }
        found.lists_age_secs = age_of_newest(lists.into_iter().filter(|file| file.exists()));
        found
    }

    async fn zypper() -> Found {
        // Reading needs no root, and never refreshing means never asking for it.
        let ask = |what: &'static [&'static str]| async move {
            let mut words = vec!["--non-interactive", "--no-refresh", "--xmlout"];
            words.extend(what);
            run("/usr/bin/zypper", &words).await
        };
        // zypper's informational exit codes start at 100.
        let fine = |ran: &crate::programs::Ran| {
            ran.code == Some(0) || ran.code.is_some_and(|code| code >= 100)
        };
        let mut found = match ask(&["list-updates"]).await {
            Err(error) => return Found::problem("zypper", error),
            Ok(ran) if fine(&ran) => Found {
                manager: "zypper",
                pending: Some(parse_zypper(&ran.stdout)),
                ..Found::default()
            },
            Ok(ran) => return Found::problem("zypper", failure("zypper", &ran)),
        };
        match ask(&["list-patches", "--category", "security"]).await {
            Ok(ran) if fine(&ran) => found.security = Some(parse_zypper(&ran.stdout)),
            Ok(ran) => found.notes.push(format!(
                "Security patches couldn't be counted. {}",
                failure("zypper", &ran)
            )),
            Err(error) => found
                .notes
                .push(format!("Security patches couldn't be counted. {error}")),
        }
        found.lists_age_secs = age_of_newest(
            files_in("/var/cache/zypp/raw", Some("repodata/repomd.xml"), |_| true)
                .into_iter()
                .filter(|file| file.exists()),
        );
        found
    }

    async fn pacman() -> Found {
        if !exists("/usr/bin/checkupdates") {
            return Found::problem(
                "pacman",
                "checkupdates isn't installed. Install it with: pacman -S pacman-contrib",
            );
        }
        // --nosync reads the package lists there are, rather than fetching new ones.
        let mut found = match run("/usr/bin/checkupdates", &["--nosync"]).await {
            Err(error) => Found::problem("pacman", error),
            // 2 means there are none.
            Ok(ran) if ran.code == Some(0) || ran.code == Some(2) => Found {
                manager: "pacman",
                pending: Some(parse_checkupdates(&ran.stdout)),
                ..Found::default()
            },
            Ok(ran) => Found::problem("pacman", failure("checkupdates", &ran)),
        };
        found.lists_age_secs = age_of_newest(files_in("/var/lib/pacman/sync", None, |name| {
            name.ends_with(".db")
        }));
        found
    }

    async fn apk() -> Found {
        let mut found = match run("/sbin/apk", &["--no-network", "list", "--upgradable"]).await {
            Err(error) => Found::problem("apk", error),
            Ok(ran) if ran.code == Some(0) => Found {
                manager: "apk",
                pending: Some(parse_apk(&ran.stdout)),
                ..Found::default()
            },
            Ok(ran) => Found::problem("apk", failure("apk", &ran)),
        };
        found.lists_age_secs = age_of_newest(files_in("/var/cache/apk", None, |name| {
            name.starts_with("APKINDEX.")
        }));
        found
    }

    /// Whether the running kernel is older than the newest installed, or the
    /// system says a reboot is waiting for something else.
    async fn reboot_required(manager: &str) -> Option<bool> {
        let running = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok();
        let mut installed = Vec::new();
        for folder in ["/lib/modules", "/usr/lib/modules"] {
            for path in files_in(folder, Some("modules.dep"), |_| true) {
                if path.exists()
                    && let Some(version) = path
                        .parent()
                        .and_then(|kernel| kernel.file_name())
                        .and_then(|name| name.to_str())
                {
                    installed.push(version.to_string());
                }
            }
        }
        let mut said = running.and_then(|running| kernel_needs_reboot(running.trim(), &installed));
        // Debian and Ubuntu mark what else needs one, such as a new C library.
        if exists("/run/reboot-required") || exists("/var/run/reboot-required") {
            said = Some(true);
        }
        // Red Hat's family has a tool that knows the same.
        if manager == "dnf" || manager == "yum" {
            let tool = "/usr/bin/needs-restarting";
            if exists(tool)
                && let Ok(ran) = run(tool, &["-r"]).await
            {
                match ran.code {
                    Some(1) => said = Some(true),
                    Some(0) => said = Some(said.unwrap_or(false)),
                    _ => {}
                }
            }
        }
        said
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use super::{Found, age_of_newest, failure, files_in, lines, run};

    pub async fn read() -> Found {
        // -U leaves the remote catalogue as it is, and -R compares with it.
        let mut found = match run("/usr/sbin/pkg", &["version", "-vURl", "<"]).await {
            Err(error) => Found::problem("pkg", error),
            Ok(ran) if ran.code == Some(0) => Found {
                manager: "pkg",
                pending: Some(lines(&ran.stdout).count() as u64),
                ..Found::default()
            },
            Ok(ran) => Found::problem("pkg", failure("pkg", &ran)),
        };
        // Packages with known vulnerabilities, from the database the daily
        // security run fetches.
        match run("/usr/sbin/pkg", &["audit", "-q"]).await {
            Ok(ran) if ran.code == Some(0) || (ran.code == Some(1) && ran.stderr.is_empty()) => {
                found.vulnerable = Some(lines(&ran.stdout).count() as u64);
            }
            Ok(ran) => found.notes.push(format!(
                "Vulnerable packages couldn't be counted. {}",
                failure("pkg audit", &ran)
            )),
            Err(error) => found
                .notes
                .push(format!("Vulnerable packages couldn't be counted. {error}")),
        }
        let mut lists = files_in("/var/db/pkg", None, |name| {
            name.starts_with("repo-") && name.ends_with(".sqlite")
        });
        lists.extend(files_in("/var/db/pkg/repos", Some("db"), |_| true));
        found.lists_age_secs = age_of_newest(lists.into_iter().filter(|file| file.exists()));
        // The installed kernel against the running one.
        let installed = run("/bin/freebsd-version", &["-k"]).await;
        let running = run("/bin/freebsd-version", &["-r"]).await;
        if let (Ok(installed), Ok(running)) = (installed, running) {
            let installed = String::from_utf8_lossy(&installed.stdout)
                .trim()
                .to_string();
            let running = String::from_utf8_lossy(&running.stdout).trim().to_string();
            if !installed.is_empty() && !running.is_empty() {
                found.reboot_required = Some(installed != running);
            }
        }
        found
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{Found, failure, parse_softwareupdate, run};

    pub async fn read() -> Found {
        let running = match run("/usr/bin/sw_vers", &["-productVersion"]).await {
            Ok(ran) => String::from_utf8_lossy(&ran.stdout).trim().to_string(),
            Err(_) => String::new(),
        };
        // --no-scan lists what macOS's own daily check last found, without asking
        // Apple again.
        let mut found = match run("/usr/sbin/softwareupdate", &["-l", "--no-scan"]).await {
            Err(error) => Found::problem("softwareupdate", error),
            Ok(ran) if ran.code == Some(0) => Found {
                manager: "softwareupdate",
                pending: Some(parse_softwareupdate(&ran.stdout, &running)),
                ..Found::default()
            },
            Ok(ran) => Found::problem("softwareupdate", failure("softwareupdate", &ran)),
        };
        let checked = run(
            "/usr/bin/defaults",
            &[
                "read",
                "/Library/Preferences/com.apple.SoftwareUpdate",
                "LastSuccessfulDate",
            ],
        )
        .await;
        if let Ok(ran) = checked
            && let Ok(when) = chrono::DateTime::parse_from_str(
                String::from_utf8_lossy(&ran.stdout).trim(),
                "%Y-%m-%d %H:%M:%S %z",
            )
        {
            let age = chrono::Utc::now().signed_duration_since(when).num_seconds();
            found.lists_age_secs = Some(age.max(0) as u64);
        }
        found
    }
}

#[cfg(windows)]
mod windows {
    use super::{Found, parse_windows};

    /// Searches what Windows Update last found, without searching online again,
    /// counts the security updates among it, and says whether a reboot is waiting
    /// and when Windows last searched.
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); \
        $searcher.Online = $false; \
        $found = $searcher.Search('IsInstalled=0 and IsHidden=0 and Type=''Software'''); \
        $security = 0; \
        foreach ($update in $found.Updates) { \
          if ($update.MsrcSeverity -or ($update.Categories | Where-Object { $_.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441' })) { $security++ } }; \
        $reboot = (New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired -or \
          (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') -or \
          (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'); \
        $last = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate; \
        $age = $null; if ($last) { $age = [math]::Max([int64]0, [int64](([datetime]::UtcNow) - $last).TotalSeconds) }; \
        ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ \
          pending = $found.Updates.Count; security = $security; reboot = [bool]$reboot; lists_age_secs = $age })";

    pub async fn read() -> Found {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let powershell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        let arguments = ["-NoProfile", "-NonInteractive", "-Command", SCRIPT];
        match crate::programs::run(&powershell, &arguments, super::RUN_LIMIT).await {
            Err(error) => Found::problem("windows_update", error),
            Ok(ran) if ran.code != Some(0) => Found::problem(
                "windows_update",
                format!(
                    "Windows Update couldn't be asked: {}",
                    ran.stderr.lines().next().unwrap_or("no reason given")
                ),
            ),
            Ok(ran) => parse_windows(&ran.stdout),
        }
    }
}

/// `apt-get -s dist-upgrade`: each package it would install or upgrade is an `Inst`
/// line naming where the new version comes from, such as
/// `Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])`.
/// It's a security update if any of those is a security archive.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_apt(stdout: &[u8]) -> (u64, u64) {
    let mut pending = 0;
    let mut security = 0;
    for line in lines(stdout).filter(|line| line.starts_with("Inst ")) {
        pending += 1;
        let from = line
            .split_once('(')
            .map_or("", |(_, from)| from)
            .to_lowercase();
        if from.contains("-security") || from.contains("debian-security") {
            security += 1;
        }
    }
    (pending, security)
}

/// `dnf -q check-update`: `name.arch version repository` for each update, a long
/// name wrapping its other two onto the next line, then what each obsoletes, which
/// isn't counted again.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_dnf_updates(stdout: &[u8]) -> u64 {
    let mut words = 0;
    for line in lines(stdout) {
        if line.starts_with("Obsoleting") {
            break;
        }
        // Notes such as `Security: kernel-… is an installed security update`.
        if line.contains(": ") {
            continue;
        }
        words += line.split_whitespace().count();
    }
    (words / 3) as u64
}

/// The architectures a package's full name ends with.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ARCHITECTURES: [&str; 9] = [
    ".noarch", ".x86_64", ".aarch64", ".i686", ".ppc64le", ".s390x", ".armv7hl", ".src", ".riscv64",
];

/// `dnf -q updateinfo list --security`: an advisory and a package it fixes on each
/// line, as `RHSA-2024:3306 Moderate/Sec. python3-idna-2.10-7.el9_4.1.noarch`, or in
/// dnf5's table. One package can have several advisories, so packages are counted.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_dnf_security(stdout: &[u8]) -> u64 {
    let mut packages = std::collections::BTreeSet::new();
    for line in lines(stdout) {
        if let Some(package) = line
            .split_whitespace()
            .rfind(|word| ARCHITECTURES.iter().any(|arch| word.ends_with(arch)))
        {
            packages.insert(package.to_string());
        }
    }
    packages.len() as u64
}

/// zypper's `--xmlout`: an `<update …>` element for each update or patch.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_zypper(stdout: &[u8]) -> u64 {
    String::from_utf8_lossy(stdout).matches("<update ").count() as u64
}

/// `checkupdates`: `name old -> new` for each update.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_checkupdates(stdout: &[u8]) -> u64 {
    lines(stdout).filter(|line| line.contains(" -> ")).count() as u64
}

/// `apk list --upgradable`: each package ends `[upgradable from: …]`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_apk(stdout: &[u8]) -> u64 {
    lines(stdout)
        .filter(|line| line.contains("[upgradable from:"))
        .count() as u64
}

/// `softwareupdate -l`: a `* Label:` line for each update, then its title. An
/// upgrade to the next major version of macOS is listed too, but it's an upgrade
/// to choose, not an update waiting, so it isn't counted.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_softwareupdate(stdout: &[u8], running: &str) -> u64 {
    let major = |version: &str| version.split('.').next().unwrap_or_default().to_string();
    let running = major(running);
    let mut pending = 0;
    let mut in_update = false;
    for line in lines(stdout) {
        if line.starts_with("* Label:") {
            in_update = true;
            continue;
        }
        if in_update && let Some(title) = line.strip_prefix("Title: ") {
            in_update = false;
            let version = title
                .split(", ")
                .find_map(|part| part.strip_prefix("Version: "))
                .unwrap_or_default();
            let upgrade =
                title.starts_with("macOS ") && !running.is_empty() && major(version) != running;
            if !upgrade {
                pending += 1;
            }
        }
    }
    pending
}

/// What the PowerShell script printed.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows(stdout: &[u8]) -> Found {
    let Ok(read) = serde_json::from_slice::<Value>(stdout) else {
        return Found::problem("windows_update", "Windows Update's answer wasn't JSON");
    };
    Found {
        manager: "windows_update",
        pending: read["pending"].as_u64(),
        security: read["security"].as_u64(),
        reboot_required: read["reboot"].as_bool(),
        lists_age_secs: read["lists_age_secs"].as_u64(),
        ..Found::default()
    }
}

/// Whether a running kernel needs a reboot, judging by the kernels installed, each
/// named as `uname -r` names them. Its own being gone, as Arch removes it on an
/// upgrade, means a newer one replaced it. Otherwise one of the same kind, such as
/// Ubuntu's `-generic` rather than `-lowlatency`, that's newer means so too. With
/// no kernels to be seen, as in a container, it can't tell.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn kernel_needs_reboot(running: &str, installed: &[String]) -> Option<bool> {
    if installed.is_empty() {
        return None;
    }
    if !installed.iter().any(|kernel| kernel == running) {
        return Some(true);
    }
    let kind = shape(running);
    Some(installed.iter().any(|kernel| {
        shape(kernel) == kind && compare_versions(kernel, running) == std::cmp::Ordering::Greater
    }))
}

/// A version with its numbers taken out, so kernels of one kind look alike.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn shape(version: &str) -> String {
    let mut shape = String::new();
    for c in version.chars() {
        if c.is_ascii_digit() {
            if !shape.ends_with('#') {
                shape.push('#');
            }
        } else {
            shape.push(c);
        }
    }
    shape
}

/// Compares versions part by part, numbers as numbers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(version: &str) -> Vec<(bool, &str)> {
        let mut parts = Vec::new();
        let mut start = 0;
        let bytes = version.as_bytes();
        for i in 1..=bytes.len() {
            if i == bytes.len() || bytes[i].is_ascii_digit() != bytes[start].is_ascii_digit() {
                parts.push((bytes[start].is_ascii_digit(), &version[start..i]));
                start = i;
            }
        }
        parts
    }
    let (a, b) = (parts(a), parts(b));
    for ((a_number, a), (b_number, b)) in a.iter().zip(&b) {
        let order = match (a_number, b_number) {
            (true, true) => {
                let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
                a.len().cmp(&b.len()).then_with(|| a.cmp(b))
            }
            _ => a.cmp(b),
        };
        if order.is_ne() {
            return order;
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ubuntu 22.04 with three upgrades waiting, one of them from the security
    /// archive and one both an update and a security fix.
    const APT: &str = "\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
      Keep also in mind that locking is deactivated,
      so don't depend on the relevance to the real current situation!
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  curl libcurl4 openssl
3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst curl [7.81.0-1ubuntu1.16] (7.81.0-1ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64]) []
Inst libcurl4 [7.81.0-1ubuntu1.16] (7.81.0-1ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64])
Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Conf curl (7.81.0-1ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64])
Conf libcurl4 (7.81.0-1ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64])
Conf openssl (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
";

    #[test]
    fn apt_counts_what_it_would_install_and_which_are_security_fixes() {
        assert_eq!(parse_apt(APT.as_bytes()), (3, 1));
    }

    #[test]
    fn debian_security_archive_counts_as_security() {
        let debian = "Inst libssl3 [3.0.11-1~deb12u1] (3.0.13-1~deb12u1 Debian-Security:12/stable-security [arm64])\n\
                      Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.7/stable [all])\n";
        assert_eq!(parse_apt(debian.as_bytes()), (2, 1));
    }

    #[test]
    fn apt_with_nothing_to_do_counts_nothing() {
        let none = "Reading package lists...\nBuilding dependency tree...\nCalculating upgrade...\n\
                    0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
        assert_eq!(parse_apt(none.as_bytes()), (0, 0));
    }

    /// Rocky 9's dnf, one name long enough to wrap, then what one obsoletes.
    const DNF: &str = "
kernel.x86_64                          5.14.0-427.13.1.el9_4      baseos
openssl.x86_64                         1:3.0.7-27.el9             baseos
python3-some-very-long-package-name-that-wraps.noarch
                                       2.10-7.el9_4.1             appstream
Obsoleting Packages
grub2-tools.x86_64                     1:2.06-77.el9              baseos
    grub2-tools.x86_64                 1:2.06-70.el9              @baseos
";

    #[test]
    fn dnf_counts_each_update_once_even_wrapped() {
        assert_eq!(parse_dnf_updates(DNF.as_bytes()), 3);
        assert_eq!(parse_dnf_updates(b""), 0);
    }

    #[test]
    fn dnf_counts_packages_with_security_advisories_once() {
        let dnf4 = "RHSA-2024:3306 Moderate/Sec.  python3-idna-2.10-7.el9_4.1.noarch\n\
                    RHSA-2024:2732 Important/Sec. kernel-5.14.0-427.13.1.el9_4.x86_64\n\
                    RHSA-2024:2999 Important/Sec. kernel-5.14.0-427.13.1.el9_4.x86_64\n";
        assert_eq!(parse_dnf_security(dnf4.as_bytes()), 2);
        let dnf5 = "Name                  Type     Severity  Package                              Issued\n\
                    FEDORA-2024-1234abcd  security Important openssl-1:3.2.2-3.fc41.x86_64        2024-10-01 00:00:00\n";
        assert_eq!(parse_dnf_security(dnf5.as_bytes()), 1);
    }

    #[test]
    fn zypper_counts_its_update_elements() {
        let xml = r#"<?xml version='1.0'?>
<stream>
<message type="info">Loading repository data...</message>
<update-status version="0.6">
<update-list>
<update kind="package" name="curl" edition="8.6.0-4.1" arch="x86_64"><summary>curl</summary></update>
<update kind="package" name="openssl-3" edition="3.1.4-9.1" arch="x86_64"><summary>openssl</summary></update>
</update-list>
</update-status>
</stream>"#;
        assert_eq!(parse_zypper(xml.as_bytes()), 2);
    }

    #[test]
    fn checkupdates_and_apk_count_their_lines() {
        let arch = "linux 6.11.5.arch1-1 -> 6.11.6.arch1-1\nopenssl 3.4.0-1 -> 3.4.0-2\n";
        assert_eq!(parse_checkupdates(arch.as_bytes()), 2);
        let alpine = "busybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.36.1-r28]\n";
        assert_eq!(parse_apk(alpine.as_bytes()), 1);
    }

    /// As this Mac's softwareupdate printed it, with an upgrade to the next macOS.
    const SOFTWAREUPDATE: &str = "Software Update Tool

Software Update found the following new or updated software:
* Label: Safari27.2TahoeAuto-27.2
\tTitle: Safari, Version: 27.2, Size: 250130KiB, Recommended: YES,
* Label: macOS Tahoe 26.7.3-25G342
\tTitle: macOS Tahoe 26.7.3, Version: 26.7.3, Size: 3107325KiB, Recommended: YES, Action: restart,
* Label: macOS 27.2.1-26B131
\tTitle: macOS 27.2.1, Version: 27.2.1, Size: 11188513KiB, Recommended: YES, Action: restart,
";

    #[test]
    fn softwareupdate_leaves_out_an_upgrade_to_the_next_macos() {
        assert_eq!(parse_softwareupdate(SOFTWAREUPDATE.as_bytes(), "26.7.2"), 2);
        assert_eq!(
            parse_softwareupdate(
                b"Software Update Tool\n\nNo new software available.\n",
                "26.7.2"
            ),
            0
        );
    }

    #[test]
    fn windows_answers_are_read() {
        let found =
            parse_windows(br#"{"pending":4,"security":2,"reboot":true,"lists_age_secs":3600}"#);
        assert_eq!(found.pending, Some(4));
        assert_eq!(found.security, Some(2));
        assert_eq!(found.reboot_required, Some(true));
        assert_eq!(found.lists_age_secs, Some(3600));
        let never =
            parse_windows(br#"{"pending":0,"security":0,"reboot":false,"lists_age_secs":null}"#);
        assert_eq!(never.lists_age_secs, None);
        assert!(parse_windows(b"Exception").problem.is_some());
    }

    #[test]
    fn a_newer_kernel_of_the_same_kind_means_a_reboot() {
        let installed =
            |kernels: &[&str]| kernels.iter().map(|k| k.to_string()).collect::<Vec<_>>();
        let ubuntu = installed(&[
            "6.8.0-45-generic",
            "6.8.0-47-generic",
            "6.8.0-50-lowlatency",
        ]);
        assert_eq!(kernel_needs_reboot("6.8.0-45-generic", &ubuntu), Some(true));
        assert_eq!(
            kernel_needs_reboot("6.8.0-47-generic", &ubuntu),
            Some(false)
        );
        let rocky = installed(&[
            "5.14.0-427.13.1.el9_4.x86_64",
            "5.14.0-427.40.1.el9_4.x86_64",
        ]);
        assert_eq!(
            kernel_needs_reboot("5.14.0-427.13.1.el9_4.x86_64", &rocky),
            Some(true)
        );
        assert_eq!(
            kernel_needs_reboot("5.14.0-427.40.1.el9_4.x86_64", &rocky),
            Some(false)
        );
        // Arch removes the running kernel's modules when it upgrades.
        assert_eq!(
            kernel_needs_reboot("6.11.5-arch1-1", &installed(&["6.11.6-arch1-1"])),
            Some(true)
        );
        assert_eq!(kernel_needs_reboot("6.11.5-arch1-1", &[]), None);
    }

    #[test]
    fn versions_compare_numbers_as_numbers() {
        use std::cmp::Ordering::*;
        assert_eq!(
            compare_versions("6.8.0-100-generic", "6.8.0-99-generic"),
            Greater
        );
        assert_eq!(compare_versions("5.14.0-427.9.1", "5.14.0-427.13.1"), Less);
        assert_eq!(
            compare_versions("6.8.0-45-generic", "6.8.0-45-generic"),
            Equal
        );
    }

    #[test]
    fn a_row_always_has_its_texts() {
        let found = Found {
            manager: "apt",
            pending: Some(3),
            security: Some(1),
            reboot_required: Some(false),
            ..Found::default()
        };
        assert_eq!(
            found.to_value(),
            json!({ "manager": "apt", "pending": 3, "security": 1, "reboot_required": 0, "problem": "", "note": "" })
        );
        let problem = Found::problem("pacman", "checkupdates isn't installed");
        assert_eq!(
            problem.to_value()["problem"],
            "checkupdates isn't installed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn each_distribution_gets_its_own_package_manager() {
        use linux::{Manager, manager_of};
        assert_eq!(
            manager_of("ID=ubuntu\nID_LIKE=debian\n"),
            Some(Manager::Apt)
        );
        assert_eq!(
            manager_of("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"),
            Some(Manager::Dnf)
        );
        assert_eq!(
            manager_of("ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n"),
            Some(Manager::Zypper)
        );
        assert_eq!(
            manager_of("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"),
            Some(Manager::Apt)
        );
        assert_eq!(manager_of("ID=nixos\n"), None);
    }
}
