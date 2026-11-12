//! Runs actions the server asks for, by name, and gives back what they printed.
//!
//! As with custom metrics, the commands stay in the agent's config file on purpose:
//! the server can only pick from what's defined here, and add a few values from the
//! alert an action runs for. Commands run directly, without a shell, and each value
//! stays inside the argument that names it.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use maxnines_protocol::actions::{
    ActionOutcome, ActionResult, MAX_ACTION_OUTPUT_BYTES, MAX_ACTION_TIMEOUT_SECS, fill_variables,
    is_action_name, variables_used,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::info;

use crate::custom::stop_group;

const MAX_DEFINITIONS: usize = 64;

/// How many actions can be waiting for the one that's running. An alert storm
/// shouldn't leave a host working through a backlog long after it's over.
const MAX_WAITING: usize = 8;

/// One `action` block in the agent's config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// The program, then its arguments, which can name variables like `{disk}`.
    pub command: Vec<String>,
}

/// Everything the agent's config defines, by name.
pub type Actions = BTreeMap<String, Action>;

pub fn check_actions(actions: &Actions) -> Result<()> {
    ensure!(
        actions.len() <= MAX_DEFINITIONS,
        "at most {MAX_DEFINITIONS} actions can be defined"
    );
    for (name, action) in actions {
        ensure!(
            is_action_name(name),
            "action name {name:?} can only use letters, digits, - and _"
        );
        let Some((program, _)) = action.command.split_first() else {
            anyhow::bail!("action {name:?} needs a command");
        };
        ensure!(!program.is_empty(), "action {name:?} needs a command");
        // Otherwise the server would be choosing what runs.
        ensure!(
            variables_used(std::slice::from_ref(program)).is_empty(),
            "action {name:?} can only use variables in its arguments, not its program"
        );
    }
    Ok(())
}

/// What this agent can be asked to run, for its facts: every name, and for those
/// that use them, which variables each needs. Only names, as with custom metrics.
pub fn facts(actions: &Actions) -> (Value, Value) {
    let names: Vec<&String> = actions.keys().collect();
    let variables: BTreeMap<&String, Vec<&str>> = actions
        .iter()
        .map(|(name, action)| (name, variables_used(&action.command)))
        .filter(|(_, used)| !used.is_empty())
        .collect();
    (json!(names), json!(variables))
}

/// Runs one action at a time, so a host that's already struggling isn't given
/// several heavy jobs at once.
pub struct Runner {
    actions: Actions,
    turn: Semaphore,
    waiting: AtomicUsize,
}

/// How a run ended, before it's given the server's `id`.
struct Ended {
    outcome: ActionOutcome,
    exit_code: Option<i32>,
    error: Option<String>,
    output: Vec<u8>,
}

impl Ended {
    fn without_running(outcome: ActionOutcome, error: impl Into<String>) -> Self {
        Self {
            outcome,
            exit_code: None,
            error: Some(error.into()),
            output: Vec::new(),
        }
    }
}

impl Runner {
    pub fn new(actions: Actions) -> Arc<Self> {
        Arc::new(Self {
            actions,
            turn: Semaphore::new(1),
            waiting: AtomicUsize::new(0),
        })
    }

    /// Always gives a result, whatever goes wrong.
    pub async fn run(
        &self,
        id: String,
        name: &str,
        variables: &BTreeMap<String, String>,
        timeout_secs: u64,
    ) -> ActionResult {
        let started = Instant::now();
        let ended = self.take_turn(name, variables, timeout_secs).await;
        let (output, truncated) = text(ended.output);
        info!(
            action = name,
            outcome = ended.outcome.as_str(),
            "ran an action for the server"
        );
        ActionResult {
            id,
            outcome: ended.outcome,
            exit_code: ended.exit_code,
            error: ended.error,
            output,
            truncated,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }

    async fn take_turn(
        &self,
        name: &str,
        variables: &BTreeMap<String, String>,
        timeout_secs: u64,
    ) -> Ended {
        let Some(action) = self.actions.get(name) else {
            return Ended::without_running(ActionOutcome::NotDefined, "not defined on this agent");
        };
        let command = match fill_variables(&action.command, variables) {
            Ok(command) => command,
            Err(error) => return Ended::without_running(ActionOutcome::Refused, error.to_string()),
        };
        if !(1..=MAX_ACTION_TIMEOUT_SECS).contains(&timeout_secs) {
            return Ended::without_running(
                ActionOutcome::Refused,
                format!("the time limit has to be from 1 to {MAX_ACTION_TIMEOUT_SECS} seconds"),
            );
        }

        if self.waiting.fetch_add(1, Ordering::Relaxed) >= MAX_WAITING {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            return Ended::without_running(
                ActionOutcome::Refused,
                "too many actions are already waiting to run",
            );
        }
        let turn = self.turn.acquire().await;
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        let Ok(_turn) = turn else {
            return Ended::without_running(ActionOutcome::Refused, "the agent is stopping");
        };
        run_command(&command, Duration::from_secs(timeout_secs)).await
    }
}

/// Reads until the end or until there's more than is kept, then lets go, so a
/// command that's still printing isn't left waiting for someone to read it.
async fn read_some(reader: Option<impl AsyncRead + Unpin>, kept: &mut Vec<u8>) {
    if let Some(reader) = reader {
        let limit = MAX_ACTION_OUTPUT_BYTES as u64 + 1;
        // What was read before an error is still worth having.
        let _ = reader.take(limit).read_to_end(kept).await;
    }
}

async fn run_command(command: &[String], limit: Duration) -> Ended {
    let Some((program, arguments)) = command.split_first() else {
        return Ended::without_running(ActionOutcome::Failed, "it has no command");
    };
    let mut starting = Command::new(program);
    starting
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Its own group, so that what it starts can be stopped along with it.
    #[cfg(unix)]
    starting.process_group(0);

    let mut child = match starting.spawn() {
        Ok(child) => child,
        Err(error) => {
            let error = format!("couldn't start the command: {error}");
            return Ended::without_running(ActionOutcome::Failed, error);
        }
    };
    let id = child.id();
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());

    // Kept out here, so what was printed before running out of time survives.
    let (mut printed, mut complained) = (Vec::new(), Vec::new());
    let finishing = async {
        tokio::join!(
            read_some(stdout, &mut printed),
            read_some(stderr, &mut complained)
        );
        child.wait().await
    };
    let finished = timeout(limit, finishing).await;
    if finished.is_err() {
        stop_group(id);
    }

    if !complained.is_empty() {
        if printed.last().is_some_and(|last| *last != b'\n') {
            printed.push(b'\n');
        }
        printed.extend(complained);
    }
    let (outcome, exit_code, error) = match finished {
        Err(_) => (ActionOutcome::TimedOut, None, None),
        Ok(Err(error)) => (
            ActionOutcome::Failed,
            None,
            Some(format!("couldn't wait for the command: {error}")),
        ),
        Ok(Ok(status)) if status.success() => (ActionOutcome::Succeeded, status.code(), None),
        Ok(Ok(status)) => match status.code() {
            Some(code) => (ActionOutcome::Failed, Some(code), None),
            None => (
                ActionOutcome::Failed,
                None,
                Some("it was stopped by a signal".to_string()),
            ),
        },
    };
    Ended {
        outcome,
        exit_code,
        error,
        output: printed,
    }
}

/// What was printed as text, cut to what's kept, and whether anything was cut.
fn text(mut output: Vec<u8>) -> (String, bool) {
    let truncated = output.len() > MAX_ACTION_OUTPUT_BYTES;
    output.truncate(MAX_ACTION_OUTPUT_BYTES);
    let mut text = String::from_utf8_lossy(&output).into_owned();
    // Replacing a character cut in half can leave it a little over.
    while text.len() > MAX_ACTION_OUTPUT_BYTES {
        text.pop();
    }
    (text, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(command: &[&str]) -> Action {
        Action {
            command: command.iter().map(|part| (*part).to_string()).collect(),
        }
    }

    fn actions(defined: &[(&str, &[&str])]) -> Actions {
        defined
            .iter()
            .map(|(name, command)| ((*name).to_string(), action(command)))
            .collect()
    }

    fn variables(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn definitions_are_checked() {
        check_actions(&actions(&[("disk_hogs", &["du", "{disk}"])])).unwrap();
        for (name, command) in [
            ("a.b", &["true"][..]),
            ("", &["true"]),
            ("a", &[]),
            ("a", &[""]),
            ("a", &["{series}"]),
            ("a", &["/bin/{process}"]),
        ] {
            assert!(
                check_actions(&actions(&[(name, command)])).is_err(),
                "{name:?} {command:?}"
            );
        }
    }

    #[test]
    fn facts_name_each_action_and_the_variables_it_needs() {
        let defined = actions(&[
            ("disk_hogs", &["du", "{disk}"]),
            ("restart_nginx", &["systemctl", "restart", "nginx"]),
        ]);
        let (names, needed) = facts(&defined);
        assert_eq!(names, json!(["disk_hogs", "restart_nginx"]));
        assert_eq!(needed, json!({ "disk_hogs": ["disk"] }));
    }

    #[test]
    fn output_is_cut_to_what_is_kept() {
        assert_eq!(text(b"hello".to_vec()), ("hello".to_string(), false));
        let (kept, truncated) = text(vec![b'a'; MAX_ACTION_OUTPUT_BYTES + 1]);
        assert_eq!(kept.len(), MAX_ACTION_OUTPUT_BYTES);
        assert!(truncated);
        // Not text at all, and a character cut in half at the end.
        let mut bytes = vec![0xff; 10];
        bytes.extend(vec![b'a'; MAX_ACTION_OUTPUT_BYTES - 11]);
        bytes.extend("é".as_bytes());
        let (kept, truncated) = text(bytes);
        assert!(kept.len() <= MAX_ACTION_OUTPUT_BYTES);
        assert!(truncated);
    }

    #[tokio::test]
    async fn an_unknown_action_is_not_run() {
        let runner = Runner::new(Actions::new());
        let result = runner.run("1".into(), "nope", &variables(&[]), 5).await;
        assert_eq!(result.id, "1");
        assert_eq!(result.outcome, ActionOutcome::NotDefined);
        assert_eq!(result.output, "");
    }

    #[cfg(unix)]
    mod commands {
        use super::*;

        async fn run(command: &[&str], given: &[(&str, &str)], secs: u64) -> ActionResult {
            let runner = Runner::new(actions(&[("a", command)]));
            runner.run("7".into(), "a", &variables(given), secs).await
        }

        #[tokio::test]
        async fn an_action_gives_back_what_it_printed() {
            let script = "echo out; echo problem >&2";
            let result = run(&["/bin/sh", "-c", script], &[], 5).await;
            assert_eq!(result.outcome, ActionOutcome::Succeeded);
            assert_eq!(result.exit_code, Some(0));
            assert_eq!(result.output, "out\nproblem\n");
            assert!(!result.truncated);
            assert_eq!(result.error, None);
        }

        #[tokio::test]
        async fn a_failing_action_says_how_it_exited() {
            let result = run(&["/bin/sh", "-c", "echo no; exit 3"], &[], 5).await;
            assert_eq!(result.outcome, ActionOutcome::Failed);
            assert_eq!(result.exit_code, Some(3));
            assert_eq!(result.output, "no\n");
        }

        #[tokio::test]
        async fn a_command_that_is_not_there_fails_without_running() {
            let result = run(&["/nonexistent/maxnines-test"], &[], 5).await;
            assert_eq!(result.outcome, ActionOutcome::Failed);
            let error = result.error.unwrap();
            assert!(error.starts_with("couldn't start the command"), "{error}");
        }

        #[tokio::test]
        async fn a_value_is_one_argument_however_it_reads() {
            // The shell here is the action's own. The value is its first argument.
            let script = "printf '%s|' \"$#\" \"$1\"";
            let command = ["/bin/sh", "-c", script, "sh", "{disk}"];
            let result = run(&command, &[("disk", "/my disk; echo hacked")], 5).await;
            assert_eq!(result.outcome, ActionOutcome::Succeeded);
            assert_eq!(result.output, "1|/my disk; echo hacked|");
        }

        #[tokio::test]
        async fn a_missing_or_unsafe_value_is_refused_without_running() {
            let command = ["/bin/echo", "{disk}"];
            for given in [&[][..], &[("disk", "-n")], &[("disk", "a\nb")]] {
                let result = run(&command, given, 5).await;
                assert_eq!(result.outcome, ActionOutcome::Refused, "{given:?}");
                assert_eq!(result.output, "");
            }
            let result = run(&command, &[("disk", "/")], 0).await;
            assert_eq!(result.outcome, ActionOutcome::Refused);
            let result = run(&command, &[("disk", "/")], MAX_ACTION_TIMEOUT_SECS + 1).await;
            assert_eq!(result.outcome, ActionOutcome::Refused);
        }

        #[tokio::test]
        async fn an_action_that_takes_too_long_is_stopped_with_what_it_printed() {
            let started = Instant::now();
            // The sleep is a child of the shell, which has to be stopped too.
            let result = run(
                &["/bin/sh", "-c", "echo before; sleep 30; echo after"],
                &[],
                1,
            )
            .await;
            assert_eq!(result.outcome, ActionOutcome::TimedOut);
            assert_eq!(result.output, "before\n");
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[tokio::test]
        async fn too_much_output_is_cut_without_waiting_for_the_rest() {
            let script = "while :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done";
            let started = Instant::now();
            let result = run(&["/bin/sh", "-c", script], &[], 20).await;
            assert!(result.truncated);
            assert_eq!(result.output.len(), MAX_ACTION_OUTPUT_BYTES);
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[tokio::test]
        async fn actions_run_one_at_a_time() {
            let folder = tempfile::tempdir().unwrap();
            let lock = folder.path().join("lock");
            // Fails if another copy is between making and removing the folder.
            let script = "mkdir \"$1\" || exit 9; sleep 0.2; rmdir \"$1\"";
            let command = ["/bin/sh", "-c", script, "sh", lock.to_str().unwrap()];
            let runner = Runner::new(actions(&[("a", &command)]));

            let none = variables(&[]);
            let runs = (0..4).map(|i| runner.run(i.to_string(), "a", &none, 10));
            for result in futures_util::future::join_all(runs).await {
                assert_eq!(result.outcome, ActionOutcome::Succeeded, "{result:?}");
            }
        }

        #[tokio::test]
        async fn a_long_queue_of_actions_is_refused() {
            let runner = Runner::new(actions(&[("a", &["/bin/sleep", "0.1"])]));
            let none = variables(&[]);
            let runs = (0..MAX_WAITING + 5).map(|i| runner.run(i.to_string(), "a", &none, 10));
            let results = futures_util::future::join_all(runs).await;
            let refused = results
                .iter()
                .filter(|result| result.outcome == ActionOutcome::Refused)
                .count();
            // One runs while the rest wait, and the waiting ones still get a turn.
            assert_eq!(refused, 4, "{results:?}");
        }
    }
}
