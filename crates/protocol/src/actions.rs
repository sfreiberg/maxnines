//! Actions: things a host can be asked to run, such as listing its busiest
//! processes or restarting a service, whose output goes back to the server.
//!
//! The server only ever names an action. What it runs is built into the agent or
//! written in the agent's own config, so the server can never make a host run
//! anything new, even if someone takes it over. What the server can add is a few
//! values from the alert the action runs for, like which disk is filling up.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// What an action can be told about the alert it runs for. A command uses one by
/// writing its name in braces, like `{disk}`. Anything else in braces is left as
/// it is, so a command can still hold `{print}` or JSON.
pub const ACTION_VARIABLES: [&str; 12] = [
    // What the alert is about, under the name its metric gives it.
    "disk",
    "interface",
    "process",
    "container",
    "check",
    // The same, whatever kind of thing it is.
    "series",
    "hostname",
    "rule",
    "severity",
    "metric",
    "value",
    "threshold",
];

/// How long an action gets when the server doesn't say.
pub const DEFAULT_ACTION_TIMEOUT_SECS: u64 = 30;
/// Scanning a big disk takes minutes, but nothing should run for longer than this.
pub const MAX_ACTION_TIMEOUT_SECS: u64 = 600;

/// How much of an action's output is kept. The rest is dropped, and the result
/// says so.
pub const MAX_ACTION_OUTPUT_BYTES: usize = 64 * 1024;

const MAX_ACTION_NAME_LEN: usize = 64;
const MAX_VARIABLE_LEN: usize = 255;

/// A name is used in fact names, so it can't hold a dot.
pub fn is_action_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ACTION_NAME_LEN
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Each `{name}` in a piece of text, and what's around them. `Err` holds text to
/// keep as it is, and `Ok` a variable's name.
fn pieces(text: &str) -> Vec<Result<&'static str, &str>> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let variable = after.find('}').and_then(|close| {
            ACTION_VARIABLES
                .iter()
                .find(|name| **name == &after[..close])
        });
        match variable {
            Some(name) => {
                if open > 0 {
                    found.push(Err(&rest[..open]));
                }
                found.push(Ok(*name));
                rest = &after[name.len() + 1..];
            }
            None => {
                found.push(Err(&rest[..=open]));
                rest = after;
            }
        }
    }
    if !rest.is_empty() {
        found.push(Err(rest));
    }
    found
}

/// The variables a command uses, each once, in the order they're listed above.
pub fn variables_used(command: &[String]) -> Vec<&'static str> {
    ACTION_VARIABLES
        .into_iter()
        .filter(|name| {
            command
                .iter()
                .flat_map(|argument| pieces(argument))
                .any(|piece| piece == Ok(*name))
        })
        .collect()
}

/// A value is only ever part of one argument and never goes through a shell, so
/// it can't add a command. It could still break a terminal, so that's refused.
pub fn check_variable(name: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_VARIABLE_LEN,
        "{{{name}}} needs a value of at most {MAX_VARIABLE_LEN} characters"
    );
    ensure!(
        !value.chars().any(char::is_control),
        "{{{name}}} can't hold control characters"
    );
    Ok(())
}

/// A command with its variables filled in. Each value stays inside the argument
/// that named it, and can't start one with a dash, which the command could take
/// for an option.
pub fn fill_variables(
    command: &[String],
    variables: &BTreeMap<String, String>,
) -> Result<Vec<String>> {
    command
        .iter()
        .map(|argument| {
            let mut filled = String::new();
            for piece in pieces(argument) {
                match piece {
                    Err(text) => filled.push_str(text),
                    Ok(name) => {
                        let Some(value) = variables.get(name) else {
                            bail!("it needs {{{name}}}, which it wasn't given");
                        };
                        check_variable(name, value)?;
                        ensure!(
                            !(filled.is_empty() && value.starts_with('-')),
                            "{{{name}}} can't start an argument with a dash"
                        );
                        filled.push_str(value);
                    }
                }
            }
            Ok(filled)
        })
        .collect()
}

/// How running an action went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    /// It ran and reported success.
    Succeeded,
    /// It ran and reported failure, or couldn't be started.
    Failed,
    /// It was stopped for taking too long. What it had printed is kept.
    TimedOut,
    /// This agent has no action of that name.
    NotDefined,
    /// It wasn't run, because of what it was asked with or how busy the agent is.
    Refused,
}

impl ActionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::NotDefined => "not_defined",
            Self::Refused => "refused",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Succeeded,
            Self::Failed,
            Self::TimedOut,
            Self::NotDefined,
            Self::Refused,
        ]
        .into_iter()
        .find(|outcome| outcome.as_str() == text)
    }
}

/// What an agent says once an action is over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    /// The `id` the server asked with.
    pub id: String,
    pub outcome: ActionOutcome,
    /// What the command exited with, if it ran to the end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Why, when the outcome alone doesn't say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What it printed, to standard output and then to standard error.
    #[serde(default)]
    pub output: String,
    /// Whether it printed more than is kept.
    #[serde(default)]
    pub truncated: bool,
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(arguments: &[&str]) -> Vec<String> {
        arguments.iter().map(|a| (*a).to_string()).collect()
    }

    fn variables(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn action_names_are_plain() {
        for name in ["disk_hogs", "restart-nginx", "a1"] {
            assert!(is_action_name(name), "{name}");
        }
        for name in ["", "a.b", "-a", "a b", "a/b", &"a".repeat(65)] {
            assert!(!is_action_name(name), "{name}");
        }
    }

    #[test]
    fn a_command_says_which_variables_it_uses() {
        let hogs = command(&["du", "--max-depth={series}", "{disk}", "{disk}"]);
        assert_eq!(variables_used(&hogs), ["disk", "series"]);
        assert!(variables_used(&command(&["systemctl", "restart", "nginx"])).is_empty());
    }

    #[test]
    fn only_known_names_in_braces_are_variables() {
        let awk = command(&["awk", "{print}", "{ \"a\": {disk} }", "{disk", "{}"]);
        assert_eq!(variables_used(&awk), ["disk"]);
        let filled = fill_variables(&awk, &variables(&[("disk", "/var")])).unwrap();
        assert_eq!(filled, ["awk", "{print}", "{ \"a\": /var }", "{disk", "{}"]);
    }

    #[test]
    fn a_value_stays_inside_its_argument() {
        let hogs = command(&["du", "--path={disk}", "{disk}"]);
        let filled = fill_variables(&hogs, &variables(&[("disk", "/my disk; rm -rf /")])).unwrap();
        assert_eq!(
            filled,
            ["du", "--path=/my disk; rm -rf /", "/my disk; rm -rf /"]
        );
    }

    #[test]
    fn a_missing_or_unsafe_value_is_refused() {
        let hogs = command(&["du", "{disk}"]);
        let error = fill_variables(&hogs, &variables(&[])).unwrap_err();
        assert!(error.to_string().contains("{disk}"), "{error}");

        for bad in ["", "--delete", "a\nb", "a\u{1b}[2J", &"a".repeat(256)] {
            assert!(
                fill_variables(&hogs, &variables(&[("disk", bad)])).is_err(),
                "{bad:?}"
            );
        }
        // Values nothing uses aren't looked at, and a dash is fine after other text.
        fill_variables(&hogs, &variables(&[("disk", "/"), ("value", "\n")])).unwrap();
        let below = command(&["notify", "--value={value}"]);
        let filled = fill_variables(&below, &variables(&[("value", "-3")])).unwrap();
        assert_eq!(filled, ["notify", "--value=-3"]);
    }

    #[test]
    fn outcomes_have_names() {
        for outcome in [
            ActionOutcome::Succeeded,
            ActionOutcome::Failed,
            ActionOutcome::TimedOut,
            ActionOutcome::NotDefined,
            ActionOutcome::Refused,
        ] {
            assert_eq!(ActionOutcome::parse(outcome.as_str()), Some(outcome));
            let json = serde_json::to_value(outcome).unwrap();
            assert_eq!(json, outcome.as_str());
        }
        assert_eq!(ActionOutcome::parse("exploded"), None);
    }
}
