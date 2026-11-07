//! Decides when alerts start and end. Runs on a timer inside the server, and
//! only ever acts on what it can see now: readings from the metrics store and
//! which agents are connected.
//!
//! Open alerts are saved, so a restart doesn't repeat them. How long a problem
//! has lasted so far is only held in memory, so a restart starts that wait again.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};

use crate::alerting::{Alert, AlertRule, NewAlert, RuleKind, clean};
use crate::calculations::{
    self, Calculation, Grouping, Question, SMALLEST_STEP_MS, Sources, over_window,
};
use crate::facts::unflatten;
use crate::metrics::{self, Metrics, NewestReading, TimeRange, now_ms};
use crate::models::Database;
use crate::presence::Presence;
use crate::registration::{AgentRecord, AgentState, Registry};
use crate::remote_checks::{FLEET_AGENT_ID, FLEET_HOST};
use crate::rule_engine;
use crate::server_stats::ServerStatus;

/// How often rules are checked. Matches the default sample interval.
const INTERVAL: Duration = Duration::from_secs(15);

/// Nobody is connected just after a start, and agents take a moment to come
/// back. Without this, every restart would look like the whole fleet going down.
const STARTUP_GRACE_MS: i64 = 120_000;

/// An agent can report as many disks or interfaces as it likes, and each series
/// can be its own alert. No real machine needs more than this.
const MAX_SERIES_PER_AGENT: usize = 64;

/// A calculation can have a line for every machine, and each can be its own alert.
const MAX_CALCULATION_LINES: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    rule_id: i64,
    agent_id: String,
    series: String,
}

impl Key {
    fn of(alert: &Alert) -> Option<Self> {
        Some(Self {
            rule_id: alert.rule_id?,
            agent_id: alert.agent_id.clone(),
            series: alert.series.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Change {
    Fire,
    Resolve,
}

/// How long something has been wrong, or right again.
#[derive(Debug, Default)]
struct Tracker {
    breached_since: Option<i64>,
    clear_since: Option<i64>,
    /// Each sample is only counted once, as checks run more often than some
    /// agents report.
    last_sample_ms: Option<i64>,
}

impl Tracker {
    /// A problem has to last `hold_ms` to fire, and be gone that long to resolve,
    /// so something hovering around a threshold doesn't send a stream of alerts.
    fn observe(
        &mut self,
        breached: bool,
        now_ms: i64,
        hold_ms: i64,
        firing: bool,
    ) -> Option<Change> {
        if breached {
            self.clear_since = None;
            let since = *self.breached_since.get_or_insert(now_ms);
            (!firing && now_ms - since >= hold_ms).then_some(Change::Fire)
        } else {
            self.breached_since = None;
            let since = *self.clear_since.get_or_insert(now_ms);
            (firing && now_ms - since >= hold_ms).then_some(Change::Resolve)
        }
    }
}

/// Everything one pass looks at, loaded once.
struct Snapshot {
    now_ms: i64,
    in_grace: bool,
    rules: BTreeMap<i64, AlertRule>,
    agents: BTreeMap<String, AgentRecord>,
    facts: BTreeMap<String, Value>,
    /// By metric and agent. A metric that couldn't be read is missing, which
    /// says nothing about whether anything is wrong.
    readings: BTreeMap<&'static str, BTreeMap<String, Vec<NewestReading>>>,
}

impl Snapshot {
    /// A condition that can't be evaluated doesn't match, as with config rules.
    fn rule_applies(&self, rule: &AlertRule, agent_id: &str) -> bool {
        let Some(condition) = &rule.rule.condition else {
            return true;
        };
        let facts = self.facts.get(agent_id).unwrap_or(&Value::Null);
        rule_engine::evaluate(condition, facts, agent_id).unwrap_or(false)
    }

    /// Why an open alert that nothing checked this time should end, if it should.
    /// Missing data is never a reason: the agent may just be offline, and that's
    /// exactly when a disk alert shouldn't quietly close itself.
    fn reason_to_close(&self, alert: &Alert) -> Option<&'static str> {
        let Some(rule) = alert
            .rule_id
            .and_then(|id| self.rules.get(&id))
            .filter(|rule| rule.rule.enabled)
        else {
            return Some("The rule was deleted or disabled");
        };
        // Checking a calculation deals with its own alerts. Getting here means it
        // couldn't be read, which says nothing about whether anything is wrong.
        if rule.rule.kind == RuleKind::Calculation {
            return None;
        }
        if !self.agents.contains_key(&alert.agent_id) {
            return Some("The agent is no longer approved");
        }
        if !self.rule_applies(rule, &alert.agent_id) {
            return Some("The rule no longer applies to this agent");
        }
        match rule.rule.kind {
            RuleKind::Offline if self.in_grace => None,
            RuleKind::Offline => Some("The rule changed"),
            RuleKind::Calculation => None,
            RuleKind::Metric => {
                let metric = rule.rule.metric()?;
                let readings = self.readings.get(metric.name)?;
                readings
                    .contains_key(&alert.agent_id)
                    .then_some("This series is no longer reported")
            }
        }
    }
}

pub struct Evaluator {
    database: Database,
    registry: Arc<Registry>,
    presence: Arc<Presence>,
    metrics: Metrics,
    /// Told how each pass went, for the navigation and the Server page.
    status: Arc<ServerStatus>,
    started_ms: i64,
    trackers: HashMap<Key, Tracker>,
}

impl Evaluator {
    pub fn new(
        database: Database,
        registry: Arc<Registry>,
        presence: Arc<Presence>,
        metrics: Metrics,
        status: Arc<ServerStatus>,
        started_ms: i64,
    ) -> Self {
        Self {
            database,
            registry,
            presence,
            metrics,
            status,
            started_ms,
            trackers: HashMap::new(),
        }
    }

    /// Runs until the server stops. Each pass is its own task, so a panic costs
    /// that pass and the next one starts as usual.
    pub fn spawn(self) -> JoinHandle<()> {
        let evaluator = Arc::new(Mutex::new(self));
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(INTERVAL);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                let evaluator = evaluator.clone();
                let pass =
                    tokio::spawn(async move { evaluator.lock().await.evaluate(now_ms()).await });
                match pass.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        error!(error = format!("{error:#}"), "checking alert rules failed");
                    }
                    Err(error) => error!(%error, "checking alert rules panicked"),
                }
            }
        })
    }

    async fn snapshot(&self, now_ms: i64) -> Result<Snapshot> {
        let rules: BTreeMap<i64, AlertRule> = self
            .database
            .list_alert_rules()
            .await?
            .into_iter()
            .map(|rule| (rule.id, rule))
            .collect();

        let agents = self
            .registry
            .list()
            .await
            .into_iter()
            .filter(|agent| agent.state == AgentState::Approved)
            .map(|agent| (agent.id.clone(), agent))
            .collect();

        let active = || rules.values().filter(|rule| rule.rule.enabled);

        let needs_facts = active().any(|rule| rule.rule.condition.is_some());
        let facts = if needs_facts {
            let all = self.database.all_current_facts().await?;
            all.iter()
                .map(|(agent, facts)| (agent.clone(), unflatten(facts)))
                .collect()
        } else {
            BTreeMap::new()
        };

        let wanted: BTreeSet<&'static str> = active()
            .filter(|rule| rule.rule.kind == RuleKind::Metric)
            .filter_map(|rule| rule.rule.metric())
            .map(|metric| metric.name)
            .collect();
        let mut readings = BTreeMap::new();
        for name in wanted {
            let metric = metrics::find(name).context("unknown metric")?;
            match self.metrics.newest(metric, now_ms).await {
                Ok(rows) => {
                    let mut by_agent: BTreeMap<String, Vec<NewestReading>> = BTreeMap::new();
                    for row in rows {
                        by_agent.entry(row.agent_id.clone()).or_default().push(row);
                    }
                    readings.insert(name, by_agent);
                }
                Err(error) => {
                    error!(
                        metric = name,
                        error = format!("{error:#}"),
                        "reading metrics for alerts failed"
                    );
                }
            }
        }

        Ok(Snapshot {
            now_ms,
            in_grace: now_ms - self.started_ms < STARTUP_GRACE_MS,
            rules,
            agents,
            facts,
            readings,
        })
    }

    /// Checks every rule once. Stopping partway is safe, as anything not done
    /// this time still needs doing next time.
    pub async fn evaluate(&mut self, now_ms: i64) -> Result<()> {
        let snapshot = self.snapshot(now_ms).await?;
        let open_alerts = self.database.open_alerts().await?;
        let mut open: HashMap<Key, Alert> = HashMap::new();
        let mut orphans = Vec::new();
        for alert in open_alerts {
            match Key::of(&alert) {
                Some(key) => {
                    open.insert(key, alert);
                }
                None => orphans.push(alert),
            }
        }

        let mut checked = HashSet::new();
        for rule in snapshot.rules.values().filter(|rule| rule.rule.enabled) {
            if rule.rule.kind == RuleKind::Calculation {
                if !snapshot.in_grace {
                    self.check_calculation(rule, &snapshot, &mut open, &mut checked)
                        .await?;
                }
                continue;
            }
            for agent in snapshot.agents.values() {
                if !snapshot.rule_applies(rule, &agent.id) {
                    continue;
                }
                match rule.rule.kind {
                    RuleKind::Offline if snapshot.in_grace || agent.is_local() => {}
                    RuleKind::Offline => {
                        self.check_offline(rule, agent, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    RuleKind::Metric => {
                        self.check_metric(rule, agent, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    RuleKind::Calculation => {}
                }
            }
        }

        for alert in orphans {
            self.close(&alert, now_ms, "The rule was deleted or disabled")
                .await?;
        }
        for (key, alert) in &open {
            if !checked.contains(key)
                && let Some(reason) = snapshot.reason_to_close(alert)
            {
                self.close(alert, now_ms, reason).await?;
            }
        }

        self.trackers.retain(|key, _| checked.contains(key));
        let firing = self.database.open_alerts().await?.len();
        self.status.firing.store(firing, Ordering::Relaxed);
        self.status
            .last_alert_pass_ms
            .store(now_ms, Ordering::Relaxed);
        Ok(())
    }

    async fn check_offline(
        &mut self,
        rule: &AlertRule,
        agent: &AgentRecord,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let key = Key {
            rule_id: rule.id,
            agent_id: agent.id.clone(),
            series: String::new(),
        };
        checked.insert(key.clone());

        // An agent that hasn't connected since the start has been gone at least
        // that long, and may have been offline before it.
        let presence = self.presence.get(&agent.id);
        let online = presence.is_some_and(|p| p.online);
        let since = presence.map_or(self.started_ms, |p| p.since_ms as i64);

        let tracker = self.trackers.entry(key.clone()).or_default();
        if online {
            tracker.clear_since = Some(since);
        } else {
            tracker.breached_since = Some(since);
        }
        let hold_ms = hold_ms(rule);
        let change = tracker.observe(!online, snapshot.now_ms, hold_ms, open.contains_key(&key));

        let summary = rule.rule.offline_summary(&clean(&agent.host));
        let host = clean(&agent.host);
        self.apply(change, rule, &host, key, None, summary, snapshot, open)
            .await
    }

    /// The lines of a calculation with a number for each, or nothing if it couldn't
    /// be read, which says nothing about whether anything is wrong.
    async fn calculated_lines(
        &self,
        rule: &AlertRule,
        question: &Question,
        now_ms: i64,
    ) -> Option<Vec<(String, f64)>> {
        let window_ms = i64::try_from(rule.rule.window()).unwrap_or(i64::MAX / 1000) * 1000;
        let range = TimeRange::new(now_ms - window_ms - SMALLEST_STEP_MS, now_ms)?;
        let sources = Sources {
            database: &self.database,
            registry: &self.registry,
            metrics: &self.metrics,
        };
        let result =
            match calculations::answer(&sources, question, range, MAX_CALCULATION_LINES).await {
                Ok(result) => result,
                Err(error) => {
                    let error = format!("{error:#}");
                    error!(rule = rule.rule.name, error, "reading a calculation failed");
                    return None;
                }
            };

        let mut lines: Vec<(String, f64)> = result
            .series
            .iter()
            .filter_map(|series| {
                let value = over_window(question.calculation, &series.points)?;
                Some((clean(&series.name), value))
            })
            .collect();
        // Nothing reporting is exactly what a rule counting machines is there to catch.
        if lines.is_empty()
            && question.calculation == Calculation::Count
            && question.grouping == Grouping::Nothing
        {
            lines.push((question.metric.title.to_string(), 0.0));
        }
        Some(lines)
    }

    async fn check_calculation(
        &mut self,
        rule: &AlertRule,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let (Some(comparison), Some(threshold)) = (rule.rule.comparison, rule.rule.threshold)
        else {
            return Ok(());
        };
        let question = match rule.rule.question() {
            Ok(question) => question,
            Err(error) => {
                error!(
                    rule = rule.rule.name,
                    error, "a saved rule doesn't make sense"
                );
                return Ok(());
            }
        };
        let Some(lines) = self
            .calculated_lines(rule, &question, snapshot.now_ms)
            .await
        else {
            return Ok(());
        };

        let key_of = |line: &str| Key {
            rule_id: rule.id,
            agent_id: FLEET_AGENT_ID.to_string(),
            series: line.to_string(),
        };
        for (line, value) in &lines {
            let key = key_of(line);
            checked.insert(key.clone());

            let tracker = self.trackers.entry(key.clone()).or_default();
            let firing = open.contains_key(&key);
            let breached = comparison.is_breached(*value, threshold);
            let change = tracker.observe(breached, snapshot.now_ms, hold_ms(rule), firing);

            let summary = rule.rule.calculation_summary(&question, line, *value)?;
            self.apply(
                change,
                rule,
                FLEET_HOST,
                key,
                Some(*value),
                summary,
                snapshot,
                open,
            )
            .await?;
        }

        // A line that's gone while others carry on has stopped being reported. With
        // nothing at all, the alert stays open, as it does for an agent that's gone.
        if !lines.is_empty() {
            let gone: Vec<Key> = open
                .keys()
                .filter(|key| key.rule_id == rule.id && !checked.contains(*key))
                .cloned()
                .collect();
            for key in gone {
                if let Some(alert) = open.remove(&key) {
                    self.close(&alert, snapshot.now_ms, "This line is no longer reported")
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn check_metric(
        &mut self,
        rule: &AlertRule,
        agent: &AgentRecord,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let metric = rule.rule.metric().context("unknown metric")?;
        let (Some(comparison), Some(threshold)) = (rule.rule.comparison, rule.rule.threshold)
        else {
            return Ok(());
        };
        let Some(readings) = snapshot
            .readings
            .get(metric.name)
            .and_then(|by_agent| by_agent.get(&agent.id))
        else {
            return Ok(());
        };

        let watched = readings
            .iter()
            .map(|reading| (clean(&reading.series), reading))
            .filter(|(series, _)| rule.rule.watches_series(series))
            .take(MAX_SERIES_PER_AGENT);

        for (series, reading) in watched {
            let key = Key {
                rule_id: rule.id,
                agent_id: agent.id.clone(),
                series: series.clone(),
            };
            checked.insert(key.clone());

            let tracker = self.trackers.entry(key.clone()).or_default();
            if tracker.last_sample_ms == Some(reading.time_ms) {
                continue;
            }
            let firing = open.contains_key(&key);
            let breached = comparison.is_breached(reading.value, threshold);
            let change = tracker.observe(breached, snapshot.now_ms, hold_ms(rule), firing);
            tracker.last_sample_ms = Some(reading.time_ms);

            let host = clean(&agent.host);
            let summary = rule
                .rule
                .metric_summary(metric, &host, &series, reading.value)?;
            self.apply(
                change,
                rule,
                &host,
                key,
                Some(reading.value),
                summary,
                snapshot,
                open,
            )
            .await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply(
        &self,
        change: Option<Change>,
        rule: &AlertRule,
        host: &str,
        key: Key,
        value: Option<f64>,
        summary: String,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
    ) -> Result<()> {
        match change {
            None => Ok(()),
            Some(Change::Resolve) => {
                if let Some(alert) = open.remove(&key) {
                    self.close(&alert, snapshot.now_ms, "The problem cleared")
                        .await?;
                }
                Ok(())
            }
            Some(Change::Fire) => {
                let new = NewAlert {
                    rule_id: rule.id,
                    rule_name: rule.rule.name.clone(),
                    severity: rule.rule.severity,
                    agent_id: key.agent_id,
                    host: host.to_string(),
                    series: key.series,
                    value,
                    summary,
                    started_ms: snapshot.now_ms,
                };
                self.database.fire_alert(&new, &rule.rule.channels).await?;
                info!(rule = rule.rule.name, host, "alert fired");
                Ok(())
            }
        }
    }

    async fn close(&self, alert: &Alert, now_ms: i64, reason: &str) -> Result<()> {
        self.database
            .resolve_alert(alert.id, now_ms, reason)
            .await?;
        info!(
            rule = alert.rule_name,
            agent = alert.agent_id,
            reason,
            "alert resolved"
        );
        Ok(())
    }
}

fn hold_ms(rule: &AlertRule) -> i64 {
    i64::try_from(rule.rule.for_secs).unwrap_or(i64::MAX / 1000) * 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_has_to_last_before_it_fires() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(true, 0, 60, false), None);
        assert_eq!(tracker.observe(true, 59, 60, false), None);
        assert_eq!(tracker.observe(true, 60, 60, false), Some(Change::Fire));
    }

    #[test]
    fn a_problem_that_goes_away_starts_the_wait_again() {
        let mut tracker = Tracker::default();
        tracker.observe(true, 0, 60, false);
        assert_eq!(tracker.observe(false, 30, 60, false), None);
        assert_eq!(tracker.observe(true, 40, 60, false), None);
        assert_eq!(tracker.observe(true, 99, 60, false), None);
        assert_eq!(tracker.observe(true, 100, 60, false), Some(Change::Fire));
    }

    #[test]
    fn with_no_wait_a_problem_fires_at_once() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(true, 0, 0, false), Some(Change::Fire));
    }

    #[test]
    fn an_alert_already_firing_does_not_fire_again() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(true, 0, 0, true), None);
        assert_eq!(tracker.observe(true, 100, 0, true), None);
    }

    #[test]
    fn a_problem_has_to_stay_gone_before_it_resolves() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(false, 0, 60, true), None);
        assert_eq!(tracker.observe(false, 59, 60, true), None);
        assert_eq!(tracker.observe(false, 60, 60, true), Some(Change::Resolve));
    }

    #[test]
    fn a_problem_coming_back_starts_the_wait_to_resolve_again() {
        let mut tracker = Tracker::default();
        tracker.observe(false, 0, 60, true);
        tracker.observe(true, 30, 60, true);
        assert_eq!(tracker.observe(false, 40, 60, true), None);
        assert_eq!(tracker.observe(false, 99, 60, true), None);
        assert_eq!(tracker.observe(false, 100, 60, true), Some(Change::Resolve));
    }

    #[test]
    fn nothing_resolves_when_nothing_is_firing() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(false, 0, 0, false), None);
        assert_eq!(tracker.observe(false, 100, 0, false), None);
    }
}
