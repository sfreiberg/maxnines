//! Your own metrics, from commands defined in the agent's config file.
//!
//! The commands stay in that file on purpose. The server only chooses which names
//! to collect, so it can never make a host run anything new, even if someone
//! takes it over. Commands run directly, without a shell.
//!
//! A command prints one number, or a JSON object of names and numbers so that one
//! run can report several things. Only those numbers are reported. Other output
//! could hold secrets, so failures are described by fixed messages and nothing else.

use std::collections::BTreeMap;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};
use maxnines_protocol::is_custom_metric_name;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::timeout;

use crate::background::{Background, probe_all};
use crate::collector::Collector;

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_TIMEOUT_SECS: u64 = 60;
const MAX_DEFINITIONS: usize = 64;

/// A number is short, so anything past this is a command doing something else.
const MAX_OUTPUT_BYTES: usize = 4096;

/// How long a command gets to be cleaned up once its own time limit is up.
const GRACE: Duration = Duration::from_secs(1);

const NOT_DEFINED: &str = "not defined on this agent";
const TIMED_OUT: &str = "timed out";
const NOT_STARTED: &str = "couldn't start the command";
const NOT_READ: &str = "couldn't read the command's output";
const TOO_MUCH_OUTPUT: &str = "printed too much";
const NOT_A_NUMBER: &str = "didn't print a number or a JSON object of numbers";

/// How many values one command can report. Each one is a series on the server.
const MAX_VALUES: usize = 32;

/// One `custom_metric` block in the agent's config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomMetric {
    /// The program, then its arguments.
    pub command: Vec<String>,
    pub timeout_secs: Option<u64>,
}

impl CustomMetric {
    fn limit(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS))
    }
}

/// Everything the agent's config defines, by name.
pub type Definitions = BTreeMap<String, CustomMetric>;

pub fn check_definitions(definitions: &Definitions) -> Result<()> {
    ensure!(
        definitions.len() <= MAX_DEFINITIONS,
        "at most {MAX_DEFINITIONS} custom metrics can be defined"
    );
    for (name, metric) in definitions {
        ensure!(
            is_custom_metric_name(name),
            "custom metric name {name:?} can only use letters, digits, ., - and _"
        );
        ensure!(
            metric
                .command
                .first()
                .is_some_and(|program| !program.is_empty()),
            "custom metric {name:?} needs a command"
        );
        ensure!(
            metric
                .timeout_secs
                .is_none_or(|secs| (1..=MAX_TIMEOUT_SECS).contains(&secs)),
            "custom metric {name:?} needs a timeout_secs from 1 to {MAX_TIMEOUT_SECS}"
        );
    }
    Ok(())
}

/// A name the server asked for, and what it means on this agent, if anything.
struct Wanted {
    name: String,
    metric: Option<CustomMetric>,
}

pub struct CustomCollector {
    background: Background,
}

impl CustomCollector {
    pub fn new(names: Vec<String>, definitions: &Definitions, interval: Duration) -> Self {
        let wanted: Vec<Arc<Wanted>> = names
            .into_iter()
            .map(|name| {
                let metric = definitions.get(&name).cloned();
                Arc::new(Wanted { name, metric })
            })
            .collect();
        let longest = wanted
            .iter()
            .filter_map(|item| item.metric.as_ref().map(CustomMetric::limit))
            .max()
            .unwrap_or_default();

        let background = Background::start(interval, move || {
            let wanted = wanted.clone();
            async move {
                let probe = |item: Arc<Wanted>| async move {
                    let result = match &item.metric {
                        Some(metric) => measure(&item.name, metric, metric.limit()).await,
                        None => Err(NOT_DEFINED.to_string()),
                    };
                    report(&item.name, result)
                };
                let failed = |item: &Wanted| report(&item.name, Err(TIMED_OUT.to_string()));
                let results = probe_all(&wanted, interval, longest + GRACE, probe, failed).await;
                Value::Array(results.into_iter().flatten().collect())
            }
        });
        Self { background }
    }
}

impl Collector for CustomCollector {
    fn name(&self) -> &'static str {
        "custom"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

/// What a command printed.
#[derive(Debug, PartialEq)]
enum Reading {
    One(f64),
    /// Full series names and their values.
    Several(BTreeMap<String, f64>),
}

/// One item per series. Whether the command worked goes on an item of its own
/// when there are several values, as a failure can't say which ones it would have
/// given, and it's what an alert watches.
fn report(name: &str, result: Result<Reading, String>) -> Vec<Value> {
    match result {
        Ok(Reading::One(value)) => vec![json!({ "name": name, "ok": 1, "value": value })],
        Ok(Reading::Several(values)) => std::iter::once(json!({ "name": name, "ok": 1 }))
            .chain(
                values
                    .into_iter()
                    .map(|(name, value)| json!({ "name": name, "value": value })),
            )
            .collect(),
        Err(error) => vec![json!({ "name": name, "ok": 0, "error": error })],
    }
}

/// Runs a command and gives what it printed.
async fn measure(name: &str, metric: &CustomMetric, limit: Duration) -> Result<Reading, String> {
    let (program, arguments) = metric
        .command
        .split_first()
        .ok_or_else(|| NOT_STARTED.to_string())?;

    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // Its own group, so that what it starts can be stopped along with it.
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn().map_err(|_| NOT_STARTED.to_string())?;
    let id = child.id();

    match timeout(limit, finish(&mut child)).await {
        Ok(Ok((status, output))) => interpret(name, status, &output),
        Ok(Err(())) => Err(NOT_READ.to_string()),
        Err(_) => {
            stop_group(id);
            Err(TIMED_OUT.to_string())
        }
    }
}

/// Reads a little more than is allowed, to tell when there was too much. Closing
/// the output first stops a command that's still writing from waiting on it.
async fn finish(child: &mut Child) -> Result<(ExitStatus, Vec<u8>), ()> {
    let stdout = child.stdout.take().ok_or(())?;
    let mut output = Vec::new();
    stdout
        .take(MAX_OUTPUT_BYTES as u64 + 1)
        .read_to_end(&mut output)
        .await
        .map_err(|_| ())?;
    let status = child.wait().await.map_err(|_| ())?;
    Ok((status, output))
}

fn interpret(name: &str, status: ExitStatus, output: &[u8]) -> Result<Reading, String> {
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(TOO_MUCH_OUTPUT.to_string());
    }
    if !status.success() {
        return Err(match status.code() {
            Some(code) => format!("exited with status {code}"),
            None => "was stopped by a signal".to_string(),
        });
    }
    parse_output(name, output).ok_or_else(|| NOT_A_NUMBER.to_string())
}

fn parse_output(name: &str, output: &[u8]) -> Option<Reading> {
    let text = std::str::from_utf8(output).ok()?.trim();
    if let Ok(value) = text.parse::<f64>() {
        return value.is_finite().then_some(Reading::One(value));
    }

    let values: BTreeMap<String, f64> = serde_json::from_str(text).ok()?;
    if values.is_empty() || values.len() > MAX_VALUES {
        return None;
    }
    let named: BTreeMap<String, f64> = values
        .into_iter()
        .map(|(key, value)| (format!("{name}.{key}"), value))
        .collect();
    named
        .keys()
        .all(|name| is_custom_metric_name(name))
        .then_some(Reading::Several(named))
}

/// Dropping the child only stops the command, not what it started.
#[cfg(unix)]
pub(crate) fn stop_group(id: Option<u32>) {
    use rustix::process::{Pid, Signal, kill_process_group};

    let group = id
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    if let Some(group) = group {
        // It may have just finished by itself, which is fine.
        let _ = kill_process_group(group, Signal::KILL);
    }
}

#[cfg(not(unix))]
pub(crate) fn stop_group(_id: Option<u32>) {}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::time::Instant;

    use super::*;

    fn metric(command: &[&str]) -> CustomMetric {
        CustomMetric {
            command: command.iter().map(ToString::to_string).collect(),
            timeout_secs: None,
        }
    }

    fn definitions(entries: &[(&str, CustomMetric)]) -> Definitions {
        entries
            .iter()
            .map(|(name, metric)| (name.to_string(), metric.clone()))
            .collect()
    }

    fn one(output: &[u8]) -> Option<f64> {
        match parse_output("m", output)? {
            Reading::One(value) => Some(value),
            Reading::Several(_) => None,
        }
    }

    #[test]
    fn numbers_are_read_however_they_are_written() {
        assert_eq!(one(b"12\n"), Some(12.0));
        assert_eq!(one(b"  -1.5  \n"), Some(-1.5));
        assert_eq!(one(b"2e3"), Some(2000.0));
    }

    #[test]
    fn anything_else_is_not_a_number() {
        for output in [
            &b""[..],
            b"ok",
            b"12 items",
            b"1\n2\n",
            b"NaN",
            b"inf",
            b"-inf",
            b"\xff\xfe",
        ] {
            assert_eq!(parse_output("m", output), None, "{output:?}");
        }
    }

    #[test]
    fn a_json_object_gives_several_values_under_the_metric_name() {
        let output = br#"{ "depth": 12, "oldest.secs": 3.5 }"#;
        let expected = BTreeMap::from([
            ("queue.depth".to_string(), 12.0),
            ("queue.oldest.secs".to_string(), 3.5),
        ]);
        assert_eq!(
            parse_output("queue", output),
            Some(Reading::Several(expected))
        );
    }

    #[test]
    fn json_that_is_not_a_flat_object_of_numbers_is_refused() {
        for output in [
            &br#"{}"#[..],
            br#"[1, 2]"#,
            br#"{ "a": "text" }"#,
            br#"{ "a": { "b": 1 } }"#,
            br#"{ "a": null }"#,
            br#"{ "two words": 1 }"#,
            br#"{ "<!here>": 1 }"#,
        ] {
            assert_eq!(parse_output("m", output), None, "{output:?}");
        }
    }

    #[test]
    fn a_name_too_long_for_a_series_is_refused() {
        let output = format!(r#"{{ "{}": 1 }}"#, "x".repeat(64));
        assert_eq!(parse_output("m", output.as_bytes()), None);
    }

    #[test]
    fn there_is_a_limit_on_values() {
        let fields = |count: usize| {
            let fields: Vec<String> = (0..count).map(|i| format!(r#""v{i}": 1"#)).collect();
            format!("{{ {} }}", fields.join(", "))
        };
        assert!(parse_output("m", fields(MAX_VALUES).as_bytes()).is_some());
        assert!(parse_output("m", fields(MAX_VALUES + 1).as_bytes()).is_none());
    }

    #[test]
    fn a_report_has_the_value_or_the_problem() {
        assert_eq!(
            report("a", Ok(Reading::One(2.5))),
            [json!({ "name": "a", "ok": 1, "value": 2.5 })]
        );
        assert_eq!(
            report("a", Err("broke".to_string())),
            [json!({ "name": "a", "ok": 0, "error": "broke" })]
        );
    }

    #[test]
    fn several_values_report_that_the_command_worked_on_its_own_item() {
        let values = BTreeMap::from([("a.x".to_string(), 1.0)]);
        assert_eq!(
            report("a", Ok(Reading::Several(values))),
            [
                json!({ "name": "a", "ok": 1 }),
                json!({ "name": "a.x", "value": 1.0 }),
            ]
        );
    }

    #[test]
    fn sensible_definitions_are_accepted() {
        let mut slow = metric(&["/bin/true"]);
        slow.timeout_secs = Some(MAX_TIMEOUT_SECS);
        check_definitions(&definitions(&[("queue.depth-1_a", slow)])).unwrap();
    }

    #[test]
    fn bad_definitions_are_refused() {
        let good = metric(&["/bin/true"]);
        let timed = |secs| CustomMetric {
            timeout_secs: Some(secs),
            ..good.clone()
        };
        for (name, bad) in [
            ("no command", metric(&[])),
            ("empty program", metric(&[""])),
            ("no time", timed(0)),
            ("too long", timed(MAX_TIMEOUT_SECS + 1)),
        ] {
            let name = name.replace(' ', "_");
            let refused = check_definitions(&definitions(&[(&name, bad)]));
            assert!(refused.is_err(), "{name}");
        }

        for name in ["", "two words", "-flag", "a/b", "a;b"] {
            let refused = check_definitions(&definitions(&[(name, good.clone())]));
            assert!(refused.is_err(), "{name:?}");
        }
    }

    #[test]
    fn there_is_a_limit_on_definitions() {
        let many: Definitions = (0..=MAX_DEFINITIONS)
            .map(|index| (format!("m{index}"), metric(&["/bin/true"])))
            .collect();
        assert!(check_definitions(&many).is_err());
    }

    #[test]
    fn a_timeout_defaults_to_ten_seconds() {
        assert_eq!(metric(&["x"]).limit(), Duration::from_secs(10));
    }

    #[cfg(unix)]
    mod running {
        use std::thread;

        use super::*;

        const LIMIT: Duration = Duration::from_secs(5);

        async fn shell(script: &str) -> Result<Reading, String> {
            measure("m", &metric(&["/bin/sh", "-c", script]), LIMIT).await
        }

        fn wait_until(condition: impl Fn() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !condition() {
                assert!(Instant::now() < deadline, "it never happened");
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn is_running(pid: &str) -> bool {
            std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        }

        #[tokio::test]
        async fn a_command_gives_the_number_it_prints() {
            assert_eq!(shell("echo 42.5").await, Ok(Reading::One(42.5)));
        }

        #[tokio::test]
        async fn a_command_can_give_several_values_in_one_run() {
            let result = shell(r#"echo '{"depth": 3}'"#).await;
            let expected = BTreeMap::from([("m.depth".to_string(), 3.0)]);
            assert_eq!(result, Ok(Reading::Several(expected)));
        }

        #[tokio::test]
        async fn arguments_are_not_read_by_a_shell() {
            let folder = tempfile::tempdir().unwrap();
            let marker = folder.path().join("ran");
            let attack = format!("1; touch {}", marker.display());

            let result = measure("m", &metric(&["/bin/echo", &attack]), LIMIT).await;

            assert_eq!(result, Err(NOT_A_NUMBER.to_string()));
            assert!(!marker.exists());
        }

        #[tokio::test]
        async fn a_failing_command_reports_its_status_and_not_its_output() {
            assert_eq!(
                shell("echo secret; echo secret >&2; exit 3").await,
                Err("exited with status 3".to_string())
            );
        }

        #[tokio::test]
        async fn other_output_is_never_reported() {
            assert_eq!(
                shell("echo password=secret").await,
                Err(NOT_A_NUMBER.to_string())
            );
        }

        #[tokio::test]
        async fn only_standard_output_is_read() {
            assert_eq!(shell("echo noise >&2; echo 7").await, Ok(Reading::One(7.0)));
        }

        #[tokio::test]
        async fn a_program_that_is_not_there_says_so() {
            let result = measure("m", &metric(&["/no/such/program"]), LIMIT).await;
            assert_eq!(result, Err(NOT_STARTED.to_string()));
        }

        #[tokio::test]
        async fn a_killed_command_says_so() {
            assert_eq!(
                shell("kill -9 $$").await,
                Err("was stopped by a signal".to_string())
            );
        }

        #[tokio::test]
        async fn a_stuck_command_times_out() {
            let started = Instant::now();
            let stuck = metric(&["/bin/sleep", "30"]);
            let result = measure("m", &stuck, Duration::from_millis(100)).await;
            assert_eq!(result, Err(TIMED_OUT.to_string()));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[tokio::test]
        async fn a_timeout_also_stops_what_the_command_started() {
            let folder = tempfile::tempdir().unwrap();
            let file = folder.path().join("pid");
            // Written in one go, so it's never read half done.
            let script = format!(
                "sleep 30 & echo $! > {file}.new; mv {file}.new {file}; wait",
                file = file.display()
            );

            // Long enough for a busy host to start the shell and what it starts.
            let stuck = metric(&["/bin/sh", "-c", &script]);
            let result = measure("m", &stuck, Duration::from_secs(2)).await;

            assert_eq!(result, Err(TIMED_OUT.to_string()));
            let pid = std::fs::read_to_string(&file).unwrap();
            assert!(!pid.trim().is_empty());
            wait_until(|| !is_running(pid.trim()));
        }

        #[tokio::test]
        async fn a_flood_of_output_is_cut_off() {
            let started = Instant::now();
            assert_eq!(
                measure("m", &metric(&["/usr/bin/yes"]), LIMIT).await,
                Err(TOO_MUCH_OUTPUT.to_string())
            );
            assert!(started.elapsed() < LIMIT);
        }

        #[tokio::test]
        async fn output_up_to_the_limit_is_read() {
            let padded = format!("printf '%{MAX_OUTPUT_BYTES}s' 5");
            assert_eq!(shell(&padded).await, Ok(Reading::One(5.0)));
        }

        fn latest(collector: &mut CustomCollector, name: &str) -> Option<Value> {
            let results = collector.collect().unwrap();
            results
                .as_array()?
                .iter()
                .find(|item| item["name"] == name)
                .cloned()
        }

        #[test]
        fn only_the_names_the_server_asks_for_are_run() {
            let folder = tempfile::tempdir().unwrap();
            let marker = folder.path().join("ran");
            let touch = format!("touch {}; echo 1", marker.display());
            let defined = definitions(&[
                ("wanted", metric(&["/bin/echo", "3"])),
                ("other", metric(&["/bin/sh", "-c", &touch])),
            ]);

            let names = vec!["wanted".to_string()];
            let mut collector = CustomCollector::new(names, &defined, Duration::from_millis(20));
            wait_until(|| collector.background_has_results());

            assert_eq!(
                latest(&mut collector, "wanted").unwrap()["value"].as_f64(),
                Some(3.0)
            );
            assert_eq!(latest(&mut collector, "other"), None);
            assert!(!marker.exists());
        }

        #[test]
        fn a_name_the_agent_does_not_define_is_never_run() {
            let names = vec!["/bin/sh".to_string()];
            let mut collector =
                CustomCollector::new(names, &Definitions::new(), Duration::from_millis(20));
            wait_until(|| collector.background_has_results());
            assert_eq!(
                latest(&mut collector, "/bin/sh").unwrap()["error"],
                NOT_DEFINED
            );
        }

        impl CustomCollector {
            fn background_has_results(&self) -> bool {
                self.background
                    .latest()
                    .as_array()
                    .is_some_and(|list| !list.is_empty())
            }
        }
    }
}
