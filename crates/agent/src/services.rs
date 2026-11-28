//! Asks the operating system whether services are running. Each system has its
//! own service manager, so this is the one place that differs by platform. Names
//! are checked by the protocol crate and are never passed through a shell.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use maxnines_collectors::entries::{Entries, at, names};
use maxnines_protocol::entries::Entry;
use serde_json::{Value, json};

use crate::background::{Background, FAILED_UNEXPECTEDLY, rows_of};
use crate::collector::Collector;

/// A service manager can stall, but it answers quickly when it's healthy.
const TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(any(test, not(any(target_os = "macos", target_os = "freebsd"))))]
const UNKNOWN: &str = "unknown";
/// The service manager's own command couldn't be run.
#[cfg(any(unix, windows))]
const NOT_ASKED: &str = "couldn't ask the service manager";

pub struct ServiceCollector {
    background: Background,
}

impl ServiceCollector {
    pub fn new(names: Vec<String>, interval: Duration) -> Result<Self> {
        let mut background = Background::new();
        for name in names {
            let late = report(&name, Status::unknown("timed out"));
            let broke = report(&name, Status::unknown(FAILED_UNEXPECTEDLY));
            let watched = Arc::new(Watched::new(name));
            let reported = watched.clone();
            background.repeat(
                interval,
                Some(TIMEOUT),
                move || {
                    let watched = watched.clone();
                    async move { query(&watched).await }
                },
                move |found| {
                    found.map_or_else(
                        |missed| missed.pick(&late, &broke),
                        |status| report(&reported.name, status),
                    )
                },
            )?;
        }
        Ok(Self { background })
    }
}

impl Collector for ServiceCollector {
    fn name(&self) -> &'static str {
        "services"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }

    fn metrics(&self) -> Vec<String> {
        names(&SERVICE_METRICS)
    }

    fn read(&mut self, _time: DateTime<Utc>) -> Result<Vec<Entry>> {
        Ok(self
            .background
            .read(|result, time| self.entries(result, time)))
    }

    /// What was said of one service, or of each in a list, under its own name
    /// only, as each is asked about apart from the others.
    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let named = rows_of(output)
            .iter()
            .filter_map(|service| Some((service.get("name")?.as_str()?, service)));
        for (name, service) in named {
            let (running, state) = (at(service, "running"), at(service, "state"));
            // One that couldn't be asked about has why as its state, which is the
            // error of both.
            let why = state
                .as_str()
                .filter(|why| running.is_null() && !why.trim().is_empty());
            match why {
                Some(why) => {
                    for metric in SERVICE_METRICS {
                        entries.error(metric, &[name], why);
                    }
                }
                None => {
                    entries.read("service.running", &[name], running);
                    entries.read("service.state", &[name], state);
                }
            }
        }
        entries.done()
    }
}

/// A service's metrics: whether it's running, and the service manager's own word
/// for its state.
const SERVICE_METRICS: [&str; 2] = ["service.running", "service.state"];

/// A service being watched.
struct Watched {
    name: String,
    /// Whether it's still being asked about, as Windows can only be asked with a
    /// call that can't be stopped.
    #[cfg(windows)]
    busy: Arc<std::sync::atomic::AtomicBool>,
}

impl Watched {
    fn new(name: String) -> Self {
        Self {
            name,
            #[cfg(windows)]
            busy: Arc::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Status {
    /// Unknown when the service manager couldn't be asked, or didn't say.
    running: Option<bool>,
    /// The service manager's own word for it, or why it's not known.
    state: String,
}

impl Status {
    fn stopped(state: &str) -> Self {
        Self {
            running: Some(false),
            state: state.to_string(),
        }
    }

    fn running(state: &str) -> Self {
        Self {
            running: Some(true),
            state: state.to_string(),
        }
    }

    fn unknown(why: &str) -> Self {
        Self {
            running: None,
            state: why.to_string(),
        }
    }
}

/// A service that couldn't be asked about says nothing about whether it's running,
/// so it has no `running` value, and an alert on it holds its state.
fn report(name: &str, status: Status) -> Value {
    let mut report = json!({ "name": name, "state": status.state });
    if let Some(running) = status.running {
        report["running"] = json!(u8::from(running));
    }
    report
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
        "" => Status::unknown(UNKNOWN),
        other => Status::stopped(other),
    }
}

/// Reads `launchctl print system/<label>`, which describes one of the system's
/// own services to any user. Its state is the line indented once: the things it
/// listens on have states of their own, further in.
#[cfg(any(target_os = "macos", test))]
fn parse_launchd_system(output: &str) -> Option<Status> {
    let state = output
        .lines()
        .find_map(|line| line.strip_prefix("\tstate = "))?
        .trim();
    Some(match state {
        "running" => Status::running(state),
        other => Status::stopped(other),
    })
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

/// Runs a service manager's command. Dropping this, as a timeout does, kills it.
#[cfg(unix)]
async fn run_command(program: &str, arguments: &[&str]) -> std::io::Result<std::process::Output> {
    tokio::process::Command::new(program)
        .args(arguments)
        .kill_on_drop(true)
        .output()
        .await
}

#[cfg(target_os = "linux")]
async fn query(watched: &Watched) -> Status {
    let name = watched.name.as_str();
    let arguments = ["show", "--property=LoadState,ActiveState", "--", name];
    let output = run_command("systemctl", &arguments).await;
    match output {
        Ok(output) => parse_systemd(&String::from_utf8_lossy(&output.stdout)),
        Err(_) => Status::unknown(NOT_ASKED),
    }
}

/// The system's services first, as those are the ones a host is watched for, and
/// then the agent's own user's: `launchctl list` only ever sees the second kind.
#[cfg(target_os = "macos")]
async fn query(watched: &Watched) -> Status {
    let name = watched.name.as_str();
    let system = format!("system/{name}");
    if let Ok(output) = run_command("launchctl", &["print", &system]).await
        && output.status.success()
        && let Some(status) = parse_launchd_system(&String::from_utf8_lossy(&output.stdout))
    {
        return status;
    }
    let output = run_command("launchctl", &["list", name]).await;
    match output {
        Ok(output) if output.status.success() => {
            parse_launchd(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(_) => Status::stopped("not found"),
        Err(_) => Status::unknown(NOT_ASKED),
    }
}

#[cfg(target_os = "freebsd")]
async fn query(watched: &Watched) -> Status {
    let name = watched.name.as_str();
    let output = run_command("service", &[name, "status"]).await;
    match output {
        Ok(output) => parse_rc(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(_) => Status::unknown(NOT_ASKED),
    }
}

/// Windows only offers a blocking call for this. It can't be stopped once it's
/// started, so a service still stuck from before isn't asked again, and a stalled
/// service manager holds one thread per service rather than adding one each time.
#[cfg(windows)]
async fn query(watched: &Watched) -> Status {
    let Some(busy) = crate::background::Busy::try_start(&watched.busy) else {
        return Status::unknown("timed out");
    };
    let name = watched.name.clone();
    tokio::task::spawn_blocking(move || {
        let _busy = busy;
        query_blocking(&name)
    })
    .await
    .unwrap_or_else(|_| Status::unknown(UNKNOWN))
}

#[cfg(windows)]
fn query_blocking(name: &str) -> Status {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return Status::unknown(NOT_ASKED);
    };
    let Ok(service) = manager.open_service(name, ServiceAccess::QUERY_STATUS) else {
        return Status::stopped("not found");
    };
    match service.query_status().map(|status| status.current_state) {
        Ok(ServiceState::Running) => Status::running("running"),
        Ok(ServiceState::StartPending) => Status::stopped("starting"),
        Ok(ServiceState::Paused) => Status::stopped("paused"),
        Ok(_) => Status::stopped("stopped"),
        Err(_) => Status::unknown(UNKNOWN),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
async fn query(_watched: &Watched) -> Status {
    Status::unknown(UNKNOWN)
}

#[cfg(test)]
mod tests {
    use maxnines_collectors::entries::testing::{
        every_entry_is_for_its_metrics, every_metric_has_an_entry, said, time,
    };

    use super::*;
    use crate::background::testing::{each_is_for_a_series, read_once};

    /// Watching nothing, so nothing is asked of the service manager.
    fn watching_nothing() -> ServiceCollector {
        ServiceCollector::new(Vec::new(), Duration::from_secs(3600)).unwrap()
    }

    #[test]
    fn service_entries_have_a_series_for_each_service() {
        let collector = watching_nothing();
        let output = json!([
            { "name": "nginx", "running": 1, "state": "active" },
            { "name": "cron", "running": 0, "state": "failed" },
            { "name": "sshd", "state": "timed out" },
            // Nothing said of it at all.
            { "name": "ntpd" },
        ]);
        let entries = collector.entries(&output, time());
        assert_eq!(
            said(&entries),
            [
                ("service.running[nginx]".to_string(), json!(1)),
                ("service.state[nginx]".to_string(), json!("active")),
                ("service.running[cron]".to_string(), json!(0)),
                ("service.state[cron]".to_string(), json!("failed")),
                // One that couldn't be asked about has why as its error.
                (
                    "service.running[sshd]".to_string(),
                    json!({ "error": "timed out" })
                ),
                (
                    "service.state[sshd]".to_string(),
                    json!({ "error": "timed out" })
                ),
                ("service.running[ntpd]".to_string(), Value::Null),
                ("service.state[ntpd]".to_string(), Value::Null),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        each_is_for_a_series(&entries);

        // With no services, or none asked about yet, nothing is said, as nothing
        // one service says is about the others.
        for output in [json!([]), Value::Null] {
            assert_eq!(collector.entries(&output, time()), []);
        }
    }

    #[test]
    fn each_services_answer_is_its_own_and_handed_over_once() {
        let mut collector = ServiceCollector {
            background: Background::holding([
                report("nginx", Status::running("active")),
                report("sshd", Status::unknown(NOT_ASKED)),
            ]),
        };
        let read = read_once(&mut collector);
        assert_eq!(read.len(), 4);
        each_is_for_a_series(&read);
        every_entry_is_for_its_metrics(&collector, &read);
        let series: Vec<&str> = read.iter().map(|entry| entry.series[0].as_str()).collect();
        assert_eq!(series, ["nginx", "nginx", "sshd", "sshd"]);
    }

    #[test]
    fn what_a_report_says_becomes_entries() {
        let collector = watching_nothing();
        let output = json!([
            report("nginx", Status::running("active")),
            report("sshd", Status::unknown(NOT_ASKED)),
        ]);
        assert_eq!(
            said(&collector.entries(&output, time())),
            [
                ("service.running[nginx]".to_string(), json!(1)),
                ("service.state[nginx]".to_string(), json!("active")),
                (
                    "service.running[sshd]".to_string(),
                    json!({ "error": NOT_ASKED })
                ),
                (
                    "service.state[sshd]".to_string(),
                    json!({ "error": NOT_ASKED })
                ),
            ]
        );
    }

    #[test]
    fn watching_no_services_collects_and_says_nothing() {
        let mut collector = watching_nothing();
        assert_eq!(collector.collect().unwrap(), json!([]));
        assert_eq!(collector.read(time()).unwrap(), []);
    }

    async fn query_named(name: &str) -> Status {
        query(&Watched::new(name.to_string())).await
    }

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
        assert_eq!(parse_systemd(""), Status::unknown(UNKNOWN));
    }

    #[test]
    fn a_system_launchd_service_says_its_own_state() {
        // As `launchctl print` writes it, with what it listens on further in.
        let print = |state: &str| {
            format!(
                "system/com.example.orders = {{\n\tactive count = 5\n\tstate = {state}\n\n\
                 \tendpoints = {{\n\t\t\"com.example.orders\" = {{\n\t\t\tstate = active\n\t\t}}\n\t}}\n\
                 \tjob state = running\n}}\n"
            )
        };
        assert_eq!(
            parse_launchd_system(&print("running")),
            Some(Status::running("running"))
        );
        assert_eq!(
            parse_launchd_system(&print("not running")),
            Some(Status::stopped("not running"))
        );
        assert_eq!(parse_launchd_system("Bad request.\n"), None);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn this_macs_own_services_are_found_without_being_root() {
        // Every Mac runs this, and `launchctl list` can't see it as a user.
        let found = query_named("com.apple.mDNSResponder.reloaded").await;
        assert_eq!(found, Status::running("running"));
        assert_eq!(
            query_named("com.example.no-such-service").await,
            Status::stopped("not found")
        );
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
    fn a_service_that_could_not_be_asked_about_is_not_called_stopped() {
        assert_eq!(
            report("nginx", Status::unknown("timed out")),
            json!({ "name": "nginx", "state": "timed out" })
        );
    }

    #[tokio::test]
    async fn a_service_that_does_not_exist_is_not_running() {
        let status = query_named("maxnines-no-such-service").await;
        assert_eq!(status.running, Some(false), "{status:?}");
    }
}
