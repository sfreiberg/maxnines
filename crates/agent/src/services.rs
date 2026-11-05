//! Asks the operating system whether services are running. Each system has its
//! own service manager, so this is the one place that differs by platform. Names
//! are checked by the protocol crate and are never passed through a shell.

use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use crate::background::{Background, Prober};
use crate::collector::Collector;

/// A service manager can stall, but it answers quickly when it's healthy.
const TIMEOUT: Duration = Duration::from_secs(10);

const UNKNOWN: &str = "unknown";

pub struct ServiceCollector {
    background: Background,
}

impl ServiceCollector {
    pub fn new(names: Vec<String>, interval: Duration) -> Self {
        let prober = Prober::new(names, TIMEOUT);
        let background = Background::start(interval, move || {
            let results = prober.round(
                |name| report(name, query(name)),
                |name| report(name, Status::stopped(UNKNOWN)),
            );
            Value::Array(results)
        });
        Self { background }
    }
}

impl Collector for ServiceCollector {
    fn name(&self) -> &'static str {
        "services"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Status {
    running: bool,
    /// The service manager's own word for it.
    state: String,
}

impl Status {
    fn stopped(state: &str) -> Self {
        Self {
            running: false,
            state: state.to_string(),
        }
    }

    fn running(state: &str) -> Self {
        Self {
            running: true,
            state: state.to_string(),
        }
    }
}

fn report(name: &str, status: Status) -> Value {
    json!({
        "name": name,
        "running": u8::from(status.running),
        "state": status.state,
    })
}

/// Reads `systemctl show`. A unit systemd has never heard of still gets an
/// answer, with a load state of `not-found`.
#[cfg(any(target_os = "linux", test))]
fn parse_systemd(output: &str) -> Status {
    let value = |wanted: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix(wanted)?.strip_prefix('='))
            .unwrap_or_default()
    };
    if value("LoadState") == "not-found" {
        return Status::stopped("not found");
    }
    match value("ActiveState") {
        "active" | "reloading" => Status::running(value("ActiveState")),
        "" => Status::stopped(UNKNOWN),
        other => Status::stopped(other),
    }
}

/// Reads `launchctl list <label>`, which only gives a PID while it's running.
#[cfg(any(target_os = "macos", test))]
fn parse_launchd(output: &str) -> Status {
    let has_pid = output
        .lines()
        .any(|line| line.trim_start().starts_with("\"PID\""));
    if has_pid {
        Status::running("running")
    } else {
        Status::stopped("stopped")
    }
}

/// `service <name> status` answers with its exit code, and an rc script that
/// doesn't exist says so on standard error.
#[cfg(any(target_os = "freebsd", test))]
fn parse_rc(success: bool, errors: &str) -> Status {
    if success {
        Status::running("running")
    } else if errors.contains("does not exist") {
        Status::stopped("not found")
    } else {
        Status::stopped("stopped")
    }
}

#[cfg(target_os = "linux")]
fn query(name: &str) -> Status {
    let output = std::process::Command::new("systemctl")
        .args(["show", "--property=LoadState,ActiveState", "--", name])
        .output();
    match output {
        Ok(output) => parse_systemd(&String::from_utf8_lossy(&output.stdout)),
        Err(_) => Status::stopped(UNKNOWN),
    }
}

#[cfg(target_os = "macos")]
fn query(name: &str) -> Status {
    let output = std::process::Command::new("launchctl")
        .args(["list", name])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            parse_launchd(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(_) => Status::stopped("not found"),
        Err(_) => Status::stopped(UNKNOWN),
    }
}

#[cfg(target_os = "freebsd")]
fn query(name: &str) -> Status {
    let output = std::process::Command::new("service")
        .args([name, "status"])
        .output();
    match output {
        Ok(output) => parse_rc(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(_) => Status::stopped(UNKNOWN),
    }
}

#[cfg(windows)]
fn query(name: &str) -> Status {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return Status::stopped(UNKNOWN);
    };
    let Ok(service) = manager.open_service(name, ServiceAccess::QUERY_STATUS) else {
        return Status::stopped("not found");
    };
    match service.query_status().map(|status| status.current_state) {
        Ok(ServiceState::Running) => Status::running("running"),
        Ok(ServiceState::StartPending) => Status::stopped("starting"),
        Ok(ServiceState::Paused) => Status::stopped("paused"),
        Ok(_) => Status::stopped("stopped"),
        Err(_) => Status::stopped(UNKNOWN),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
fn query(_name: &str) -> Status {
    Status::stopped(UNKNOWN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_systemd_unit_is_running() {
        assert_eq!(
            parse_systemd("LoadState=loaded\nActiveState=active\n"),
            Status::running("active")
        );
        assert_eq!(
            parse_systemd("ActiveState=reloading\nLoadState=loaded\n"),
            Status::running("reloading")
        );
    }

    #[test]
    fn any_other_systemd_state_is_not_running() {
        for state in ["inactive", "failed", "activating", "deactivating"] {
            let output = format!("LoadState=loaded\nActiveState={state}\n");
            assert_eq!(parse_systemd(&output), Status::stopped(state));
        }
    }

    #[test]
    fn an_unknown_systemd_unit_says_so() {
        assert_eq!(
            parse_systemd("LoadState=not-found\nActiveState=inactive\n"),
            Status::stopped("not found")
        );
    }

    #[test]
    fn empty_systemd_output_is_not_a_guess() {
        assert_eq!(parse_systemd(""), Status::stopped(UNKNOWN));
    }

    #[test]
    fn a_launchd_job_with_a_pid_is_running() {
        let output = "{\n\t\"Label\" = \"x\";\n\t\"PID\" = 123;\n};\n";
        assert_eq!(parse_launchd(output), Status::running("running"));
    }

    #[test]
    fn a_launchd_job_without_a_pid_is_stopped() {
        let output = "{\n\t\"Label\" = \"x\";\n\t\"LastExitStatus\" = 0;\n};\n";
        assert_eq!(parse_launchd(output), Status::stopped("stopped"));
    }

    #[test]
    fn rc_scripts_answer_with_their_exit_code() {
        assert_eq!(parse_rc(true, ""), Status::running("running"));
        assert_eq!(parse_rc(false, ""), Status::stopped("stopped"));
        assert_eq!(
            parse_rc(false, "nginx does not exist in /etc/rc.d"),
            Status::stopped("not found")
        );
    }

    #[test]
    fn a_report_gives_a_number_to_alert_on() {
        assert_eq!(
            report("nginx", Status::running("active")),
            json!({ "name": "nginx", "running": 1, "state": "active" })
        );
        assert_eq!(report("nginx", Status::stopped("failed"))["running"], 0);
    }

    #[test]
    fn a_service_that_does_not_exist_is_not_running() {
        let status = query("maxnines-no-such-service");
        assert!(!status.running, "{status:?}");
    }
}
