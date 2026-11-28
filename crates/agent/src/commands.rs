//! Check commands: monitoring plugins in the Nagios style, defined in the agent's
//! config file. Thousands of these exist for software MaxNines doesn't know,
//! and most teams have a few of their own.
//!
//! As with custom metrics, the commands stay in that file, and the server only
//! chooses which names to run, so it can never make a host run anything new.
//! Commands run directly, without a shell.
//!
//! A plugin says how things are by how it exits: 0 OK, 1 warning, 2 critical and
//! 3 unknown. The first line it prints says why, and anything after a `|` on it,
//! or on a later line, is performance data: `label=value[unit];warn;crit;min;max`,
//! separated by spaces. The status, that first line and the values are reported.

use std::collections::BTreeMap;
use std::process::ExitStatus;
use std::time::Duration;

use crate::background::{Background, FAILED_UNEXPECTEDLY, rows_of};
use crate::collector::Collector;
use crate::custom::{Failure, run_command};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use maxnines_collectors::entries::{Entries, at, filled, names};
use maxnines_protocol::entries::Entry;
use maxnines_protocol::is_custom_metric_name;
use serde::Deserialize;
use serde_json::{Value, json};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_DEFINITIONS: usize = 64;

/// What's read of a plugin's output, as Nagios itself reads no more.
const MAX_OUTPUT_BYTES: usize = 8192;

/// How much of the first line is kept to say why.
const MAX_MESSAGE_CHARS: usize = 256;

/// How many values one plugin can report. Each one is a series on the server.
const MAX_VALUES: usize = 32;

/// How long a plugin gets to be cleaned up once its own time limit is up.
const GRACE: Duration = Duration::from_secs(1);

const OK: u8 = 0;
#[cfg(test)]
const WARNING: u8 = 1;
#[cfg(all(test, unix))]
const CRITICAL: u8 = 2;
const UNKNOWN: u8 = 3;

const NOT_DEFINED: &str = "not defined on this agent";

/// One `check_command` block in the agent's config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckCommand {
    /// The program, then its arguments.
    pub command: Vec<String>,
    #[serde(
        rename = "timeout_secs",
        default,
        with = "maxnines_protocol::time::optional_seconds"
    )]
    pub timeout: Option<Duration>,
}

impl CheckCommand {
    fn limit(&self) -> Duration {
        self.timeout.unwrap_or(DEFAULT_TIMEOUT)
    }
}

/// Everything the agent's config defines, by name.
pub type CheckCommands = BTreeMap<String, CheckCommand>;

pub fn check_commands(commands: &CheckCommands) -> Result<()> {
    ensure!(
        commands.len() <= MAX_DEFINITIONS,
        "at most {MAX_DEFINITIONS} check commands can be defined"
    );
    for (name, command) in commands {
        ensure!(
            is_custom_metric_name(name),
            "check command name {name:?} can only use letters, digits, ., - and _"
        );
        ensure!(
            command
                .command
                .first()
                .is_some_and(|program| !program.is_empty()),
            "check command {name:?} needs a command"
        );
        ensure!(
            command
                .timeout
                .is_none_or(|timeout| (Duration::from_secs(1)..=MAX_TIMEOUT).contains(&timeout)),
            "check command {name:?} needs a timeout_secs from 1 to {}",
            MAX_TIMEOUT.as_secs()
        );
    }
    Ok(())
}

pub struct CommandCollector {
    background: Background,
}

impl CommandCollector {
    pub fn new(names: Vec<String>, commands: &CheckCommands, interval: Duration) -> Result<Self> {
        let mut background = Background::new();
        for name in names {
            let Some(command) = commands.get(&name).cloned() else {
                background.constant(Value::Array(Outcome::problem(NOT_DEFINED).report(&name)));
                continue;
            };
            let late = Value::Array(Outcome::problem(&Failure::TimedOut.to_string()).report(&name));
            let broke = Value::Array(Outcome::problem(FAILED_UNEXPECTEDLY).report(&name));
            let limit = command.limit();
            background.repeat(
                interval,
                Some(limit + GRACE),
                move || {
                    let command = command.command.clone();
                    async move { run(&command, limit).await }
                },
                move |found| match found {
                    Ok(outcome) => Value::Array(outcome.report(&name)),
                    Err(missed) => missed.pick(&late, &broke),
                },
            )?;
        }
        Ok(Self { background })
    }
}

impl Collector for CommandCollector {
    fn name(&self) -> &'static str {
        "commands"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }

    fn metrics(&self) -> Vec<String> {
        names(&COMMAND_METRICS)
    }

    fn read(&mut self, _time: DateTime<Utc>) -> Result<Vec<Entry>> {
        Ok(self
            .background
            .read(|result, time| self.entries(result, time)))
    }

    /// One plugin's run, or each item of a list, under the plugin's own names
    /// only, as each runs apart from the others.
    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let named = rows_of(output)
            .iter()
            .filter_map(|item| Some((item.get("name")?.as_str()?, item)));
        for (name, item) in named {
            // A plugin's own item has its status, and each of its values is an item
            // of its own without one.
            if item.get("status").is_none() {
                entries.read("command.value", &[name], at(item, "value"));
                continue;
            }
            // One that couldn't be run is unknown, which is a status like any
            // other, and its message says why.
            entries.read("command.status", &[name], at(item, "status"));
            entries.read("command.ok", &[name], at(item, "ok"));
            entries.read("command.message", &[name], at(item, "message"));
            // Why it couldn't be run is also the error of the values it didn't
            // give. Its own item says something of them every time, so the error
            // ends when it runs again.
            let why = filled(at(item, "error")).as_str();
            entries.read_or("command.value", &[name], &Value::Null, why);
        }
        entries.done()
    }
}

/// A plugin's metrics: how it exited, whether that was OK, the first line it
/// printed, and each value of its performance data.
const COMMAND_METRICS: [&str; 4] = [
    "command.status",
    "command.ok",
    "command.message",
    "command.value",
];

/// How a plugin's run went.
#[derive(Debug, PartialEq)]
struct Outcome {
    status: u8,
    /// The first line it printed, or what went wrong running it.
    message: String,
    /// Its performance data, by label, in seconds and bytes where it gave a unit
    /// of time or size.
    values: BTreeMap<String, f64>,
    /// Whether it couldn't be run at all, where a plugin that ran and said
    /// something is wrong, or that it doesn't know, did its job.
    failed: bool,
}

impl Outcome {
    /// It couldn't be run, which says nothing about what it checks.
    fn problem(message: &str) -> Self {
        Self {
            status: UNKNOWN,
            message: message.to_string(),
            values: BTreeMap::new(),
            failed: true,
        }
    }

    /// One item for the plugin, then one per value, named by the plugin and label
    /// joined by a dot, as a custom metric's several values are. A plugin that
    /// couldn't be run has why as its `error` too, as a custom metric does.
    fn report(self, name: &str) -> Vec<Value> {
        let mut own = json!({
            "name": name,
            "status": self.status,
            "ok": u8::from(self.status == OK),
            "message": self.message,
        });
        if self.failed {
            own["error"] = json!(self.message);
        }
        std::iter::once(own)
            .chain(
                self.values.into_iter().map(
                    |(label, value)| json!({ "name": format!("{name}.{label}"), "value": value }),
                ),
            )
            .collect()
    }
}

/// Runs a plugin, reading as much of what it prints as Nagios itself would.
async fn run(command: &[String], limit: Duration) -> Outcome {
    match run_command(command, limit, MAX_OUTPUT_BYTES as u64).await {
        Ok((status, output)) => interpret(status, &output),
        Err(failure) => Outcome::problem(&failure.to_string()),
    }
}

fn interpret(status: ExitStatus, output: &[u8]) -> Outcome {
    let text = String::from_utf8_lossy(output);
    let (message, values) = parse_output(&text);
    let status = match status.code() {
        Some(code @ 0..=3) => code as u8,
        // Anything else, or being stopped by a signal, is unknown, as for Nagios.
        _ => UNKNOWN,
    };
    Outcome {
        status,
        message,
        values,
        failed: false,
    }
}

/// The first line's text, and the performance data from it and any later lines.
fn parse_output(text: &str) -> (String, BTreeMap<String, f64>) {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default();
    let (message, first_data) = first.split_once('|').unwrap_or((first, ""));
    let mut data = vec![first_data];
    // Long output: performance data starts after a `|` on a later line, and runs
    // to the end.
    let mut rest_data = false;
    for line in lines {
        if rest_data {
            data.push(line);
        } else if let Some((_, after)) = line.split_once('|') {
            rest_data = true;
            data.push(after);
        }
    }
    let mut values = BTreeMap::new();
    for chunk in data {
        // A label given twice, as from unquoted spaces the guidelines don't allow,
        // keeps its first value rather than the two being mixed up as one series.
        for (label, value) in performance_data(chunk) {
            if values.len() < MAX_VALUES {
                values.entry(label).or_insert(value);
            }
        }
    }
    let message: String = message.trim().chars().take(MAX_MESSAGE_CHARS).collect();
    (message, values)
}

/// `label=value[unit];warn;crit;min;max`, separated by spaces. A label with spaces
/// is quoted with `'`, and `''` inside the quotes is one quote. Anything that
/// doesn't fit is left out.
fn performance_data(text: &str) -> Vec<(String, f64)> {
    let mut found = Vec::new();
    let mut rest = text.trim();
    while !rest.is_empty() {
        let (label, after) = if let Some(quoted) = rest.strip_prefix('\'') {
            let mut label = String::new();
            let mut chars = quoted.char_indices();
            let mut end = None;
            while let Some((index, c)) = chars.next() {
                if c == '\'' {
                    if quoted[index + 1..].starts_with('\'') {
                        label.push('\'');
                        chars.next();
                    } else {
                        end = Some(index + 1);
                        break;
                    }
                } else {
                    label.push(c);
                }
            }
            let Some(end) = end else { break };
            (label, &quoted[end..])
        } else {
            let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            match rest[..token_end].find('=') {
                Some(at) => (rest[..at].to_string(), &rest[at..]),
                // A word with no value isn't part of the next one's label.
                None => {
                    rest = rest[token_end..].trim_start();
                    continue;
                }
            }
        };
        // A quoted label with no value is left out up to the next space, as a word
        // is, so what follows a quote closed too early isn't read as its own value.
        let Some(after) = after.strip_prefix('=') else {
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            rest = after[end..].trim_start();
            continue;
        };
        let end = after.find(char::is_whitespace).unwrap_or(after.len());
        let field = &after[..end];
        rest = after[end..].trim_start();
        let reading = field.split(';').next().unwrap_or_default();
        if let Some(value) = reading_value(reading)
            && is_label(&label)
        {
            found.push((label, value));
        }
    }
    found
}

/// A label that can be part of a series' name.
fn is_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 128 && label.chars().all(|c| !c.is_control() && c != '=')
}

/// The number, in seconds or bytes when its unit is one of time or size. `U` and
/// anything that isn't a number are left out.
fn reading_value(reading: &str) -> Option<f64> {
    let split = reading
        .find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E')))
        .unwrap_or(reading.len());
    let (number, unit) = reading.split_at(split);
    let value: f64 = number
        .parse()
        .ok()
        .filter(|value: &f64| value.is_finite())?;
    let scale = match unit {
        "" | "%" | "c" | "s" | "B" => 1.0,
        "ms" => 1e-3,
        "us" => 1e-6,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some(value * scale)
}

#[cfg(test)]
mod tests {
    use maxnines_collectors::entries::testing::{
        every_entry_is_for_its_metrics, every_metric_has_an_entry, said, time,
    };

    use super::*;
    use crate::background::testing::{each_is_for_a_series, read_once};

    /// Running nothing, so no program is started.
    fn running_nothing() -> CommandCollector {
        CommandCollector::new(Vec::new(), &CheckCommands::new(), Duration::from_secs(3600)).unwrap()
    }

    #[test]
    fn command_entries_have_a_series_for_each_plugin_and_each_of_its_values() {
        let collector = running_nothing();
        let output = json!([
            { "name": "load", "status": 1, "ok": 0, "message": "LOAD WARNING" },
            { "name": "load.load1", "value": 4.5 },
            // It printed nothing to say why.
            { "name": "raid", "status": 0, "ok": 1, "message": "" },
            // One that couldn't be run is unknown, and says why.
            { "name": "backup", "status": 3, "ok": 0, "message": "timed out",
              "error": "timed out" },
            // One that ran and said it doesn't know did its job.
            { "name": "ups", "status": 3, "ok": 0, "message": "UPS UNKNOWN" },
            // A status with nothing else said.
            { "name": "odd", "status": 2 },
            // A value that isn't a number.
            { "name": "odd.size" },
            // One without a name can't be told from the others.
            { "status": 0, "ok": 1 },
        ]);
        let entries = collector.entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said(&entries),
            [
                (of("command.status[load]"), json!(1)),
                (of("command.ok[load]"), json!(0)),
                (of("command.message[load]"), json!("LOAD WARNING")),
                (of("command.value[load]"), Value::Null),
                (of("command.value[load.load1]"), json!(4.5)),
                (of("command.status[raid]"), json!(0)),
                (of("command.ok[raid]"), json!(1)),
                (of("command.message[raid]"), Value::Null),
                (of("command.value[raid]"), Value::Null),
                // Why is the error of the values it didn't give, too.
                (of("command.status[backup]"), json!(3)),
                (of("command.ok[backup]"), json!(0)),
                (of("command.message[backup]"), json!("timed out")),
                (of("command.value[backup]"), json!({ "error": "timed out" })),
                (of("command.status[ups]"), json!(3)),
                (of("command.ok[ups]"), json!(0)),
                (of("command.message[ups]"), json!("UPS UNKNOWN")),
                (of("command.value[ups]"), Value::Null),
                (of("command.status[odd]"), json!(2)),
                (of("command.ok[odd]"), Value::Null),
                (of("command.message[odd]"), Value::Null),
                (of("command.value[odd]"), Value::Null),
                (of("command.value[odd.size]"), Value::Null),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);
        each_is_for_a_series(&entries);

        // With no plugins, or none run yet, nothing is said, as nothing one
        // plugin says is about the others.
        for output in [json!([]), Value::Null] {
            assert_eq!(collector.entries(&output, time()), []);
        }
    }

    #[test]
    fn each_plugins_run_is_its_own_and_handed_over_once() {
        let worked = Outcome {
            status: WARNING,
            message: "LOAD WARNING".to_string(),
            values: BTreeMap::from([("load1".to_string(), 4.5)]),
            failed: false,
        };
        let mut collector = CommandCollector {
            background: Background::holding([
                Value::Array(worked.report("load")),
                Value::Array(Outcome::problem(NOT_DEFINED).report("gone")),
            ]),
        };
        let read = read_once(&mut collector);
        assert_eq!(read.len(), 5 + 4);
        each_is_for_a_series(&read);
        every_entry_is_for_its_metrics(&collector, &read);
    }

    #[test]
    fn what_a_plugin_reports_becomes_entries() {
        let collector = running_nothing();
        let worked = Outcome {
            status: OK,
            message: "DISK OK".to_string(),
            values: BTreeMap::from([("/".to_string(), 2048.0)]),
            failed: false,
        };
        let mut output = worked.report("disk");
        output.extend(Outcome::problem(NOT_DEFINED).report("gone"));
        let entries = collector.entries(&Value::Array(output), time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said(&entries),
            [
                (of("command.status[disk]"), json!(0)),
                (of("command.ok[disk]"), json!(1)),
                (of("command.message[disk]"), json!("DISK OK")),
                (of("command.value[disk]"), Value::Null),
                (of("command.value[disk./]"), json!(2048.0)),
                (of("command.status[gone]"), json!(3)),
                (of("command.ok[gone]"), json!(0)),
                (of("command.message[gone]"), json!(NOT_DEFINED)),
                (of("command.value[gone]"), json!({ "error": NOT_DEFINED })),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);
        each_is_for_a_series(&entries);
    }

    #[test]
    fn running_no_plugins_collects_and_says_nothing() {
        let mut collector = running_nothing();
        assert_eq!(collector.collect().unwrap(), json!([]));
        assert_eq!(collector.read(time()).unwrap(), []);
    }

    fn command(command: &[&str]) -> CheckCommand {
        CheckCommand {
            command: command.iter().map(ToString::to_string).collect(),
            timeout: None,
        }
    }

    #[test]
    fn the_first_line_says_why_and_performance_data_gives_values() {
        let (message, values) = parse_output(
            "DISK OK - free space: / 3326 MB (56%); | /=2643MB;5948;5958;0;5968 'root inodes'=12%;80;90\n",
        );
        assert_eq!(message, "DISK OK - free space: / 3326 MB (56%);");
        assert_eq!(
            values,
            BTreeMap::from([
                ("/".to_string(), 2643.0 * 1024.0 * 1024.0),
                ("root inodes".to_string(), 12.0),
            ])
        );
    }

    #[test]
    fn long_output_can_carry_more_performance_data() {
        let output = "PING OK - loss 0% | rta=0.5ms\nline two\nline three | pl=0%\nloss=1;2\n";
        let (message, values) = parse_output(output);
        assert_eq!(message, "PING OK - loss 0%");
        assert_eq!(values["rta"], 0.0005);
        assert_eq!(values["pl"], 0.0);
        assert_eq!(values["loss"], 1.0);
    }

    #[test]
    fn odd_performance_data_is_left_out_but_the_rest_kept() {
        let values = performance_data("a=U b=12xyz c= 'it''s'=3s d=-1.5 'unclosed=4");
        assert_eq!(values, [("it's".to_string(), 3.0), ("d".to_string(), -1.5)]);
        // A word without a value is left out alone, not joined to the next label.
        let values = performance_data("junk pl=5% rta=0.1ms");
        assert_eq!(
            values,
            [("pl".to_string(), 5.0), ("rta".to_string(), 0.0001)]
        );
        let values = performance_data("'some note' pl=5%");
        assert_eq!(values, [("pl".to_string(), 5.0)]);
        let values = performance_data("'disk /'used=5 pl=5%");
        assert_eq!(values, [("pl".to_string(), 5.0)]);
        assert!(performance_data("no values here").is_empty());
        // Unquoted spaces give one label twice, which keeps its first value.
        let (_, values) = parse_output("OK | Total Memory=5MB Free Memory=3MB");
        assert_eq!(
            values,
            BTreeMap::from([("Memory".to_string(), 5.0 * 1024.0 * 1024.0)])
        );
    }

    #[test]
    fn units_of_time_and_size_become_seconds_and_bytes() {
        assert_eq!(reading_value("250ms"), Some(0.25));
        assert_eq!(reading_value("2KB"), Some(2048.0));
        assert_eq!(reading_value("75%"), Some(75.0));
        assert_eq!(reading_value("1200c"), Some(1200.0));
        assert_eq!(reading_value("NaN"), None);
    }

    #[test]
    fn a_long_message_is_cut_short() {
        let (message, _) = parse_output(&"x".repeat(1000));
        assert_eq!(message.chars().count(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn a_report_has_the_status_then_each_value() {
        let outcome = Outcome {
            status: WARNING,
            message: "LOAD WARNING".to_string(),
            values: BTreeMap::from([("load1".to_string(), 4.5)]),
            failed: false,
        };
        assert_eq!(
            outcome.report("load"),
            [
                json!({ "name": "load", "status": 1, "ok": 0, "message": "LOAD WARNING" }),
                json!({ "name": "load.load1", "value": 4.5 }),
            ]
        );
        // One that couldn't be run says why as its error too.
        assert_eq!(
            Outcome::problem(NOT_DEFINED).report("gone"),
            [
                json!({ "name": "gone", "status": 3, "ok": 0, "message": NOT_DEFINED, "error": NOT_DEFINED })
            ]
        );
    }

    #[test]
    fn definitions_are_checked() {
        let defined = |name: &str, definition: CheckCommand| {
            check_commands(&CheckCommands::from([(name.to_string(), definition)]))
        };
        defined("raid", command(&["/usr/lib/nagios/plugins/check_raid"])).unwrap();
        assert!(defined("raid", command(&[])).is_err());
        assert!(defined("two words", command(&["/bin/true"])).is_err());
        let slow = CheckCommand {
            timeout: Some(MAX_TIMEOUT + Duration::from_secs(1)),
            ..command(&["/bin/true"])
        };
        assert!(defined("raid", slow).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_plugins_exit_code_is_its_status() {
        let script = |code: u8| {
            command(&[
                "/bin/sh",
                "-c",
                &format!("echo 'THING CRITICAL - broke | errors=3'; exit {code}"),
            ])
        };
        for (code, status) in [
            (0, OK),
            (1, WARNING),
            (2, CRITICAL),
            (3, UNKNOWN),
            (7, UNKNOWN),
        ] {
            let script = script(code);
            let outcome = run(&script.command, script.limit()).await;
            assert_eq!(outcome.status, status, "{code}");
            assert_eq!(outcome.message, "THING CRITICAL - broke");
            assert_eq!(outcome.values["errors"], 3.0);
        }
    }

    /// More than is kept, which is read to the end rather than the pipe closed on
    /// it, so it ends as it means to and not by the signal that closing sends.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_plugin_that_prints_a_lot_keeps_its_status() {
        let script = command(&[
            "/bin/sh",
            "-c",
            "echo 'BIG CRITICAL - broke'; head -c 200000 /dev/zero | tr '\\0' a; echo; exit 2",
        ]);
        let outcome = run(&script.command, script.limit()).await;
        assert_eq!(outcome.status, CRITICAL, "{}", outcome.message);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_plugin_that_cannot_run_or_takes_too_long_is_unknown() {
        let missing = command(&["/no/such/plugin"]);
        let missing = run(&missing.command, missing.limit()).await;
        assert!(missing.failed);
        assert_eq!(
            (missing.status, missing.message),
            (UNKNOWN, Failure::NotStarted.to_string())
        );
        let slow = CheckCommand {
            timeout: Some(Duration::from_secs(1)),
            ..command(&["/bin/sleep", "30"])
        };
        let started = std::time::Instant::now();
        let outcome = run(&slow.command, slow.limit()).await;
        assert_eq!(
            (outcome.status, outcome.message),
            (UNKNOWN, Failure::TimedOut.to_string())
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
