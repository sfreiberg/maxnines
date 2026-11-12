//! Runs actions the server asks for, by name, and gives back what they printed.
//!
//! As with custom metrics, the commands stay in the agent's config file on purpose:
//! the server can only pick from what's defined here, and add a few values from the
//! alert an action runs for. Commands run directly, without a shell, and each value
//! stays inside the argument that names it.
//!
//! A command always runs as the agent's own user. One that needs more goes through
//! `sudo`, so that what it may do is written in the system's own rules, by root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use maxnines_protocol::actions::{
    ActionOutcome, ActionResult, MAX_ACTION_OUTPUT_BYTES, MAX_ACTION_TIMEOUT_SECS, check_variable,
    fill_variables, is_action_name, variables_used,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::info;

use crate::builtin_actions::{self, Asked, BUILT_INS, BuiltIn};
use crate::custom::stop_group;
use crate::privileges;

const MAX_DEFINITIONS: usize = 64;

/// How long a built-in action gets to write up what it found once its time is up.
const BUILT_IN_GRACE: Duration = Duration::from_secs(5);

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
        ensure!(
            builtin_actions::find(name).is_none(),
            "action name {name:?} is already a built-in action's"
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

/// What this agent can be asked to run, for its facts: every name, built in or
/// defined here, and for those that use them, which variables each needs. Only
/// names, as with custom metrics.
pub fn facts(actions: &Actions, built_ins: bool) -> (Value, Value) {
    let built_ins = BUILT_INS.iter().filter(|_| built_ins);
    let mut variables: BTreeMap<&str, Vec<&str>> = built_ins
        .map(|built_in| (built_in.name, built_in.variables.to_vec()))
        .collect();
    for (name, action) in actions {
        variables.insert(name, variables_used(&action.command));
    }
    let names: Vec<&str> = variables.keys().copied().collect();
    variables.retain(|_, used| !used.is_empty());
    (json!(names), json!(variables))
}

/// How a run ended, before it's given the server's `id`. This is also what the
/// privileged helper answers with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ended {
    pub outcome: ActionOutcome,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    /// What it printed, cut to what's kept.
    pub output: String,
    pub truncated: bool,
}

impl Ended {
    pub fn without_running(outcome: ActionOutcome, error: impl Into<String>) -> Self {
        Self {
            outcome,
            exit_code: None,
            error: Some(error.into()),
            output: String::new(),
            truncated: false,
        }
    }

    fn refused(error: impl Into<String>) -> Self {
        Self::without_running(ActionOutcome::Refused, error)
    }
}

/// What can be run here, and how. The agent has one, and so does its privileged
/// helper. The helper's has no commands in it: it never starts a program.
pub struct Executor {
    actions: Actions,
    /// Whether the actions built into the agent can be asked for.
    built_ins: bool,
    /// Where this process keeps its own files. The helper's is a folder of its
    /// own, as one the agent's user can write to is no place for root to write.
    state_dir: Option<PathBuf>,
}

/// What was asked for, once it's been found and checked.
enum Found {
    /// A command from the config, with what it was given filled in.
    Command(Vec<String>),
    BuiltIn(&'static BuiltIn),
}

impl Executor {
    pub fn new(actions: Actions, built_ins: bool, state_dir: Option<&Path>) -> Self {
        Self {
            actions,
            built_ins,
            state_dir: state_dir.map(Path::to_path_buf),
        }
    }

    /// Finds an action and checks what it was asked with, or says why not.
    fn find(
        &self,
        name: &str,
        variables: &BTreeMap<String, String>,
        timeout_secs: u64,
    ) -> Result<Found, Ended> {
        let built_in = builtin_actions::find(name).filter(|_| self.built_ins);
        let found = match (self.actions.get(name), built_in) {
            (Some(action), _) => fill_variables(&action.command, variables).map(Found::Command),
            (None, Some(built_in)) => {
                check_given(built_in.variables, variables).map(|()| Found::BuiltIn(built_in))
            }
            (None, None) => {
                let error = "not defined on this agent";
                return Err(Ended::without_running(ActionOutcome::NotDefined, error));
            }
        };
        let found = found.map_err(|error| Ended::refused(error.to_string()))?;
        if !(1..=MAX_ACTION_TIMEOUT_SECS).contains(&timeout_secs) {
            let error =
                format!("the time limit has to be from 1 to {MAX_ACTION_TIMEOUT_SECS} seconds");
            return Err(Ended::refused(error));
        }
        Ok(found)
    }

    /// Runs what `find` found as whoever this process is, handing the built-ins
    /// that see more as root to the privileged helper, if there is one.
    async fn run_here(
        &self,
        found: Found,
        name: &str,
        variables: &BTreeMap<String, String>,
        timeout_secs: u64,
    ) -> Ended {
        let limit = Duration::from_secs(timeout_secs);
        match found {
            Found::Command(command) => run_command(&command, limit).await,
            Found::BuiltIn(built_in) => {
                if built_in.privileged
                    && let Some(helper) = privileges::helper()
                    && let Some(ended) = helper.ask(name, variables, timeout_secs).await
                {
                    return ended;
                }
                // Without the helper it still runs, and says what it couldn't see.
                run_built_in(built_in, variables, limit, self.state_dir.clone()).await
            }
        }
    }

    /// Runs an action for the agent, as the privileged helper. Only the built-ins
    /// that see more as root are run. Anything else is the agent's to run itself,
    /// so nothing the agent asks for gets a program started as root.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub async fn run_privileged(
        &self,
        name: &str,
        variables: &BTreeMap<String, String>,
        timeout_secs: u64,
    ) -> Ended {
        let found = match self.find(name, variables, timeout_secs) {
            Ok(found) => found,
            Err(ended) => return ended,
        };
        let limit = Duration::from_secs(timeout_secs);
        match found {
            Found::BuiltIn(built_in) if built_in.privileged => {
                run_built_in(built_in, variables, limit, self.state_dir.clone()).await
            }
            Found::BuiltIn(_) | Found::Command(_) => Ended::refused("it's the agent's to run"),
        }
    }
}

/// Runs one action at a time, so a host that's already struggling isn't given
/// several heavy jobs at once.
pub struct Runner {
    executor: Executor,
    turn: Semaphore,
    waiting: AtomicUsize,
}

impl Runner {
    pub fn new(actions: Actions, built_ins: bool, state_dir: &Path) -> Arc<Self> {
        Arc::new(Self {
            executor: Executor::new(actions, built_ins, Some(state_dir)),
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
            output: ended.output,
            truncated: ended.truncated,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }

    async fn take_turn(
        &self,
        name: &str,
        variables: &BTreeMap<String, String>,
        timeout_secs: u64,
    ) -> Ended {
        // Checked before waiting, so a request that can't run doesn't take a place.
        let found = match self.executor.find(name, variables, timeout_secs) {
            Ok(found) => found,
            Err(ended) => return ended,
        };
        if self.waiting.fetch_add(1, Ordering::Relaxed) >= MAX_WAITING {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            return Ended::refused("too many actions are already waiting to run");
        }
        let turn = self.turn.acquire().await;
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        let Ok(_turn) = turn else {
            return Ended::refused("the agent is stopping");
        };
        let executor = &self.executor;
        executor
            .run_here(found, name, variables, timeout_secs)
            .await
    }
}

/// Built-in actions run inside the process, on a thread of their own. They watch
/// the time themselves, as a thread can't be stopped from outside.
async fn run_built_in(
    built_in: &'static BuiltIn,
    variables: &BTreeMap<String, String>,
    limit: Duration,
    state_dir: Option<PathBuf>,
) -> Ended {
    let variables = variables.clone();
    let deadline = Instant::now() + limit;
    let work = tokio::task::spawn_blocking(move || {
        (built_in.run)(&Asked {
            variables: &variables,
            deadline,
            state_dir: state_dir.as_deref(),
        })
    });
    let (outcome, error, output) = match timeout(limit + BUILT_IN_GRACE, work).await {
        Err(_) => (ActionOutcome::TimedOut, None, String::new()),
        Ok(Err(_)) => (
            ActionOutcome::Failed,
            Some("it crashed".to_string()),
            String::new(),
        ),
        Ok(Ok(Err(error))) => (
            ActionOutcome::Failed,
            Some(format!("{error:#}")),
            String::new(),
        ),
        Ok(Ok(Ok(output))) => (ActionOutcome::Succeeded, None, output),
    };
    let (output, truncated) = text(output.into_bytes());
    Ended {
        outcome,
        exit_code: None,
        error,
        output,
        truncated,
    }
}

/// A built-in action has to be given what it needs, as a command does.
fn check_given(needed: &[&str], variables: &BTreeMap<String, String>) -> Result<()> {
    for name in needed {
        let Some(value) = variables.get(*name) else {
            anyhow::bail!("it needs {{{name}}}, which it wasn't given");
        };
        check_variable(name, value)?;
    }
    Ok(())
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

/// Runs a command as whoever this process is.
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
    let (output, truncated) = text(printed);
    Ended {
        outcome,
        exit_code,
        error,
        output,
        truncated,
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

    fn runner(actions: Actions, built_ins: bool) -> Arc<Runner> {
        Runner::new(actions, built_ins, tempfile::tempdir().unwrap().path())
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
            ("top_cpu", &["true"]),
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
        let (names, needed) = facts(&defined, false);
        assert_eq!(names, json!(["disk_hogs", "restart_nginx"]));
        assert_eq!(needed, json!({ "disk_hogs": ["disk"] }));

        let (names, needed) = facts(&defined, true);
        let mut expected = vec![
            "disk_hogs",
            "disk_io",
            "disk_space",
            "restart_nginx",
            "top_cpu",
            "top_memory",
        ];
        // Where the system can say which process holds a socket.
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            expected.insert(0, "connections");
        }
        assert_eq!(names, json!(expected));
        assert_eq!(
            needed,
            json!({ "disk_hogs": ["disk"], "disk_space": ["disk"] })
        );
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
        let runner = runner(Actions::new(), true);
        let result = runner.run("1".into(), "nope", &variables(&[]), 5).await;
        assert_eq!(result.id, "1");
        assert_eq!(result.outcome, ActionOutcome::NotDefined);
        assert_eq!(result.output, "");
    }

    #[tokio::test]
    async fn a_built_in_action_runs_without_being_defined() {
        let runner = runner(Actions::new(), true);
        let none = variables(&[]);
        let result = runner.run("1".into(), "top_memory", &none, 30).await;
        assert_eq!(result.outcome, ActionOutcome::Succeeded, "{result:?}");
        assert!(result.output.contains("processes running"), "{result:?}");
    }

    #[tokio::test]
    async fn a_built_in_action_is_refused_without_what_it_needs() {
        let runner = runner(Actions::new(), true);
        let none = variables(&[]);
        let result = runner.run("1".into(), "disk_space", &none, 30).await;
        assert_eq!(result.outcome, ActionOutcome::Refused, "{result:?}");
        assert!(result.error.unwrap().contains("{disk}"));

        let nowhere = variables(&[("disk", "/nonexistent/maxnines-test")]);
        let result = runner.run("2".into(), "disk_space", &nowhere, 30).await;
        assert_eq!(result.outcome, ActionOutcome::Failed, "{result:?}");
    }

    #[tokio::test]
    async fn built_in_actions_can_be_turned_off() {
        let runner = runner(Actions::new(), false);
        let none = variables(&[]);
        let result = runner.run("1".into(), "top_cpu", &none, 30).await;
        assert_eq!(result.outcome, ActionOutcome::NotDefined);
    }

    #[cfg(unix)]
    mod commands {
        use super::*;

        async fn run(command: &[&str], given: &[(&str, &str)], secs: u64) -> ActionResult {
            let runner = runner(actions(&[("a", command)]), true);
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
            let runner = runner(actions(&[("a", &command)]), true);

            let none = variables(&[]);
            let runs = (0..4).map(|i| runner.run(i.to_string(), "a", &none, 10));
            for result in futures_util::future::join_all(runs).await {
                assert_eq!(result.outcome, ActionOutcome::Succeeded, "{result:?}");
            }
        }

        #[tokio::test]
        async fn a_long_queue_of_actions_is_refused() {
            let runner = runner(actions(&[("a", &["/bin/sleep", "0.1"])]), true);
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
