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

use crate::background::Background;
use crate::collector::Collector;
use crate::custom::{Failure, run_command};
use anyhow::{Result, ensure};
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
            let limit = command.limit();
            background.repeat(
                interval,
                Some(limit + GRACE),
                move || {
                    let command = command.command.clone();
                    async move { run(&command, limit).await }
                },
                move |found| match found {
                    Some(outcome) => Value::Array(outcome.report(&name)),
                    None => late.clone(),
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
}

/// How a plugin's run went.
#[derive(Debug, PartialEq)]
struct Outcome {
    status: u8,
    /// The first line it printed, or what went wrong running it.
    message: String,
    /// Its performance data, by label, in seconds and bytes where it gave a unit
    /// of time or size.
    values: BTreeMap<String, f64>,
}

impl Outcome {
    /// It couldn't be run, which says nothing about what it checks.
    fn problem(message: &str) -> Self {
        Self {
            status: UNKNOWN,
            message: message.to_string(),
            values: BTreeMap::new(),
        }
    }

    /// One item for the plugin, then one per value, named by the plugin and label
    /// joined by a dot, as a custom metric's several values are.
    fn report(self, name: &str) -> Vec<Value> {
        let own = json!({
            "name": name,
            "status": self.status,
            "ok": u8::from(self.status == OK),
            "message": self.message,
        });
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
        for (label, value) in performance_data(chunk) {
            if values.len() < MAX_VALUES {
                values.insert(label, value);
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
            match rest.find('=') {
                Some(at) => (rest[..at].to_string(), &rest[at..]),
                None => break,
            }
        };
        let Some(after) = after.strip_prefix('=') else {
            break;
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
    use super::*;

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
        assert!(performance_data("no values here").is_empty());
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
        };
        assert_eq!(
            outcome.report("load"),
            [
                json!({ "name": "load", "status": 1, "ok": 0, "message": "LOAD WARNING" }),
                json!({ "name": "load.load1", "value": 4.5 }),
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

    #[cfg(unix)]
    #[tokio::test]
    async fn a_plugin_that_cannot_run_or_takes_too_long_is_unknown() {
        let missing = command(&["/no/such/plugin"]);
        let missing = run(&missing.command, missing.limit()).await;
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
