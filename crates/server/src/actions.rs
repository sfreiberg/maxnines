//! Actions: asking a host's agent to run something, for an alert or for a person,
//! and keeping what it printed.
//!
//! The server only names an action and passes a few values from the alert. What
//! runs is built into the agent or written in its own config, and each agent says
//! which actions it has in its facts, so nothing is asked of a host that lacks it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
use maxnines_protocol::ServerMessage;
use maxnines_protocol::actions::{
    ActionOutcome, ActionResult, DEFAULT_ACTION_TIMEOUT_SECS, MAX_ACTION_TIMEOUT_SECS,
    check_variable, is_action_name,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::alerting::{Alert, AlertRule, AlertRuleInput, RuleKind, Severity};
use crate::metrics::{Metric, Source};
use crate::models::Database;

/// How many actions one rule can run.
pub const MAX_RULE_ACTIONS: usize = 8;

/// How many requests can wait for one agent's connection to take them.
const REQUEST_QUEUE_SIZE: usize = 16;

/// How long past its time limit an action's answer is waited for, which covers
/// waiting its turn on the agent and the trip back.
const ANSWER_GRACE_MS: i64 = 60_000;

/// Who asked for a run that a person started.
pub const RUN_BY_HAND: &str = "manual";

/// When in an alert's life a rule's action runs. Each runs once per alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOn {
    /// When the alert starts, whatever it starts at.
    First,
    /// The first time the alert is a warning.
    Warning,
    /// The first time the alert is critical, whether it starts there or gets there.
    Critical,
}

impl RunOn {
    pub const ALL: [Self; 3] = [Self::First, Self::Warning, Self::Critical];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|run_on| run_on.as_str() == text)
    }

    /// Whether this is the moment, for an alert that just started or changed to
    /// `severity`.
    fn is_due(self, started: bool, severity: Severity) -> bool {
        match self {
            Self::First => started,
            Self::Warning => severity == Severity::Warning,
            Self::Critical => severity == Severity::Critical,
        }
    }
}

fn first() -> RunOn {
    RunOn::First
}

/// One action an alert rule runs on the alert's host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleAction {
    /// The action's name, as agents report it.
    pub action: String,
    #[serde(default = "first")]
    pub run_on: RunOn,
    /// How long it gets. 30 seconds if left out.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl RuleAction {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(DEFAULT_ACTION_TIMEOUT_SECS)
    }
}

pub fn check_timeout(secs: u64) -> Result<()> {
    ensure!(
        (1..=MAX_ACTION_TIMEOUT_SECS).contains(&secs),
        "an action's time limit has to be from 1 to {MAX_ACTION_TIMEOUT_SECS} seconds"
    );
    Ok(())
}

/// Checks a rule's actions by themselves. Whether any host has them, and whether
/// the rule's alerts can give them what they need, is [`check_against_hosts`].
pub fn check_rule_actions(rule: &AlertRuleInput) -> Result<()> {
    let actions = &rule.actions;
    if actions.is_empty() {
        return Ok(());
    }
    ensure!(
        matches!(rule.kind, RuleKind::Metric | RuleKind::Forecast),
        "only a metric or forecast rule can run actions, as they run on the alert's host"
    );
    ensure!(
        actions.len() <= MAX_RULE_ACTIONS,
        "a rule can run at most {MAX_RULE_ACTIONS} actions"
    );
    for (index, wanted) in actions.iter().enumerate() {
        let name = &wanted.action;
        ensure!(is_action_name(name), "{name:?} isn't an action's name");
        check_timeout(wanted.timeout())?;
        let again = actions[..index]
            .iter()
            .any(|other| other.action == *name && other.run_on == wanted.run_on);
        ensure!(
            !again,
            "the action {name:?} is listed twice for the same moment"
        );
    }
    Ok(())
}

/// What each action needs to be given, by name, across every host that has it.
pub type KnownActions = BTreeMap<String, Vec<String>>;

/// Checks a rule's actions against what hosts report: each has to exist on some
/// host, and need nothing this rule's alerts can't give.
pub fn check_against_hosts(rule: &AlertRuleInput, known: &KnownActions) -> Result<()> {
    let given = rule_variables(rule);
    for wanted in &rule.actions {
        let name = &wanted.action;
        let Some(needed) = known.get(name) else {
            anyhow::bail!("no host has an action called {name:?}");
        };
        for variable in needed {
            ensure!(
                given.contains(&variable.as_str()),
                "the action {name:?} needs {{{variable}}}, which this rule's alerts don't have"
            );
        }
    }
    Ok(())
}

/// What a metric's series are, as an action's variable, where they're one of the
/// kinds actions know about.
pub fn series_variable(metric: &Metric) -> Option<&'static str> {
    if matches!(metric.source, Source::Fields(_)) {
        return None;
    }
    match (metric.name, metric.collector) {
        // Only these two are named by where the disk is mounted.
        ("disk.usage" | "disk.inodes", _) => Some("disk"),
        (_, "network") => Some("interface"),
        (_, "containers") => Some("container"),
        (_, "checks") => Some("check"),
        (_, "processes" | "top_processes") => Some("process"),
        _ => None,
    }
}

/// Which variables an alert from this rule can give an action.
pub fn rule_variables(rule: &AlertRuleInput) -> Vec<&'static str> {
    let mut given = vec!["hostname", "rule", "severity", "value"];
    if rule.threshold.is_some() {
        given.push("threshold");
    }
    if let Some(metric) = rule.metric() {
        given.push("metric");
        if !matches!(metric.source, Source::Fields(_)) {
            given.push("series");
        }
        given.extend(series_variable(metric));
    }
    given
}

/// The values an alert gives an action. Ones without a value are left out.
pub fn alert_variables(rule: &AlertRuleInput, alert: &Alert) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let mut set = |name: &str, value: String| {
        if !value.is_empty() {
            values.insert(name.to_string(), value);
        }
    };
    set("hostname", alert.hostname.clone());
    set("rule", alert.rule_name.clone());
    set("severity", alert.severity.as_str().to_string());
    if let Some(value) = alert.value {
        set("value", value.to_string());
    }
    if let Some(threshold) = rule.threshold {
        set("threshold", threshold.to_string());
    }
    if let Some(metric) = rule.metric() {
        set("metric", metric.name.to_string());
        set("series", alert.series.clone());
        if let Some(kind) = series_variable(metric) {
            set(kind, alert.series.clone());
        }
    }
    values
}

/// One time an action was asked for, and how it went once that's known.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActionRun {
    pub id: i64,
    pub host_id: String,
    /// The alert it ran for, if it wasn't started by a person.
    pub alert_id: Option<i64>,
    pub action: String,
    /// `first`, `warning` or `critical` for an alert's, and `manual` for a person's.
    pub run_on: String,
    /// What it was given.
    pub variables: BTreeMap<String, String>,
    /// Who asked, for one a person started.
    pub requested_by: Option<String>,
    pub requested_ms: i64,
    pub timeout_secs: u64,
    /// Empty until the agent answers or is given up on.
    pub outcome: Option<ActionOutcome>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub output: String,
    pub truncated: bool,
    pub duration_ms: Option<u64>,
    pub finished_ms: Option<i64>,
}

/// What's needed to ask for an action.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRun {
    pub host_id: String,
    pub alert_id: Option<i64>,
    pub action: String,
    pub run_on: String,
    pub variables: BTreeMap<String, String>,
    pub requested_by: Option<String>,
    pub requested_ms: i64,
    pub timeout_secs: u64,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    pub outcome: ActionOutcome,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub output: String,
    pub truncated: bool,
    pub duration_ms: Option<u64>,
}

impl Finished {
    /// For one the agent was never asked to run, or never answered.
    fn without_running(outcome: ActionOutcome, error: impl Into<String>) -> Self {
        Self {
            outcome,
            exit_code: None,
            error: Some(error.into()),
            output: String::new(),
            truncated: false,
            duration_ms: None,
        }
    }
}

/// An agent's connection, as far as asking it for actions goes.
struct Link {
    connection: u64,
    requests: mpsc::Sender<String>,
}

/// Asks connected agents to run actions, and records how each went.
pub struct Actions {
    database: Database,
    links: Mutex<HashMap<String, Link>>,
    connections: Mutex<u64>,
}

impl Actions {
    pub fn new(database: Database) -> Arc<Self> {
        Arc::new(Self {
            database,
            links: Mutex::default(),
            connections: Mutex::new(0),
        })
    }

    /// Called when an agent connects. Gives what to send it, and a number to
    /// hand back when the connection ends.
    pub fn connected(&self, host_id: &str) -> (u64, mpsc::Receiver<String>) {
        let connection = {
            let mut connections = self.connections.lock().unwrap();
            *connections += 1;
            *connections
        };
        let (requests, receiver) = mpsc::channel(REQUEST_QUEUE_SIZE);
        let link = Link {
            connection,
            requests,
        };
        self.links.lock().unwrap().insert(host_id.to_string(), link);
        (connection, receiver)
    }

    /// Ignored if the agent has already reconnected on a newer connection.
    pub fn disconnected(&self, host_id: &str, connection: u64) {
        let mut links = self.links.lock().unwrap();
        if links
            .get(host_id)
            .is_some_and(|link| link.connection == connection)
        {
            links.remove(host_id);
        }
    }

    /// Records a run and asks the host's agent for it. Always leaves a record:
    /// one that can't be asked for is finished at once, saying why.
    pub async fn run(&self, mut new: NewRun) -> Result<i64> {
        let available = self.database.host_actions(&new.host_id).await?;
        let needed = available.get(&new.action);
        // Only what it needs leaves the server.
        if let Some(needed) = needed {
            new.variables.retain(|name, _| needed.contains(name));
        }
        let id = self.database.create_action_run(&new).await?;

        let refusal = match needed {
            None => Some(Finished::without_running(
                ActionOutcome::NotDefined,
                "this host's agent doesn't have it",
            )),
            Some(needed) => self.ask(id, &new, needed),
        };
        if let Some(finished) = refusal {
            let now_ms = new.requested_ms;
            self.database
                .finish_action_run(id, &new.host_id, &finished, now_ms)
                .await?;
        } else {
            info!(
                host_id = new.host_id,
                action = new.action,
                "asked for an action"
            );
        }
        Ok(id)
    }

    /// Sends the request, or says why it can't be sent.
    fn ask(&self, id: i64, new: &NewRun, needed: &[String]) -> Option<Finished> {
        let refused = |why: String| Some(Finished::without_running(ActionOutcome::Refused, why));
        for name in needed {
            let Some(value) = new.variables.get(name) else {
                return refused(format!("it needs {{{name}}}, which there's no value for"));
            };
            if let Err(error) = check_variable(name, value) {
                return refused(error.to_string());
            }
        }
        let message = ServerMessage::RunAction {
            id: id.to_string(),
            action: new.action.clone(),
            variables: new.variables.clone(),
            timeout_secs: new.timeout_secs,
        };
        let Ok(text) = serde_json::to_string(&message) else {
            return refused("the request couldn't be written".to_string());
        };
        let links = self.links.lock().unwrap();
        let Some(link) = links.get(&new.host_id) else {
            return refused("the host's agent isn't connected".to_string());
        };
        match link.requests.try_send(text) {
            Ok(()) => None,
            Err(_) => refused("too many actions are waiting to be sent to this host".to_string()),
        }
    }

    /// Records an agent's answer. One for a run that isn't waiting, or isn't that
    /// host's, is ignored, so an agent can only answer for itself.
    pub async fn finished(&self, host_id: &str, result: ActionResult, now_ms: i64) -> Result<()> {
        let Ok(id) = result.id.parse::<i64>() else {
            warn!(host_id, "ignoring an action result with an invalid ID");
            return Ok(());
        };
        let finished = Finished {
            outcome: result.outcome,
            exit_code: result.exit_code,
            error: result.error,
            output: result.output,
            truncated: result.truncated,
            duration_ms: Some(result.duration_ms),
        };
        let recorded = self
            .database
            .finish_action_run(id, host_id, &finished, now_ms)
            .await?;
        if !recorded {
            warn!(
                host_id,
                id, "ignoring an action result nothing is waiting for"
            );
        }
        Ok(())
    }

    /// Finishes runs whose agents never answered, so nothing waits for ever.
    pub async fn give_up_on_unanswered(&self, now_ms: i64) -> Result<()> {
        for run in self.database.unanswered_action_runs().await? {
            let limit_ms = i64::try_from(run.timeout_secs)
                .unwrap_or(i64::MAX / 1000)
                .saturating_mul(1000);
            if now_ms - run.requested_ms < limit_ms + ANSWER_GRACE_MS {
                continue;
            }
            let finished =
                Finished::without_running(ActionOutcome::Failed, "the agent never answered");
            self.database
                .finish_action_run(run.id, &run.host_id, &finished, now_ms)
                .await?;
        }
        Ok(())
    }

    /// Runs whichever of a rule's actions are due, for an alert that just started
    /// or changed severity. Each runs once per alert.
    pub async fn run_for_alert(
        &self,
        rule: &AlertRule,
        alert: &Alert,
        started: bool,
        now_ms: i64,
    ) -> Result<()> {
        for wanted in &rule.rule.actions {
            if !wanted.run_on.is_due(started, alert.severity) {
                continue;
            }
            let run_on = wanted.run_on.as_str();
            if self
                .database
                .has_action_run(alert.id, &wanted.action, run_on)
                .await?
            {
                continue;
            }
            let new = NewRun {
                host_id: alert.host_id.clone(),
                alert_id: Some(alert.id),
                action: wanted.action.clone(),
                run_on: run_on.to_string(),
                variables: alert_variables(&rule.rule, alert),
                requested_by: None,
                requested_ms: now_ms,
                timeout_secs: wanted.timeout(),
            };
            self.run(new).await?;
        }
        Ok(())
    }
}
