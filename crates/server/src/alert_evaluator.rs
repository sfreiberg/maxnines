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

use crate::alerting::{
    Alert, AlertRule, NewAlert, RULE_GONE_REASON, RuleKind, Severity, SeverityChange, clean,
};
use crate::calculations::{
    self, Calculation, Grouping, Question, SMALLEST_STEP_MS, Sources, over_window,
};
use crate::facts::unflatten;
use crate::metrics::{self, Metrics, NewestReading, TimeRange, Trend, now_ms};
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

/// How often forecasts read their metrics again. Reading hours of every disk is
/// work, and a line through hours barely moves in a few minutes.
const FORECAST_EVERY_MS: i64 = 5 * 60_000;
/// A line through fewer readings than this, or through less than half of how far
/// back the rule looks, isn't trusted to say anything.
const MIN_FORECAST_SAMPLES: u64 = 10;
/// A series not heard from for this long has no forecast, as with any missing
/// reading, which says nothing about whether anything is wrong.
const FORECAST_FRESH_MS: i64 = 10 * 60_000;

/// What a forecast reads: a metric over how far back it looks.
type TrendKey = (&'static str, u64);

/// Trends by agent, and when they were read.
#[derive(Clone)]
struct Trends {
    read_ms: i64,
    by_agent: Arc<BTreeMap<String, Vec<Trend>>>,
}

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
    Fire(Severity),
    /// An open alert getting worse, or better without being over.
    Become(Severity),
    Resolve,
}

/// How long one level of a problem has lasted, or been gone.
#[derive(Debug, Default)]
struct Hold {
    breached_since: Option<i64>,
    clear_since: Option<i64>,
}

impl Hold {
    fn observe(&mut self, breached: bool, now_ms: i64) {
        if breached {
            self.clear_since = None;
            self.breached_since.get_or_insert(now_ms);
        } else {
            self.breached_since = None;
            self.clear_since.get_or_insert(now_ms);
        }
    }

    fn breached_for(&self, now_ms: i64, hold_ms: i64) -> bool {
        self.breached_since
            .is_some_and(|since| now_ms - since >= hold_ms)
    }

    fn clear_for(&self, now_ms: i64, hold_ms: i64) -> bool {
        self.clear_since
            .is_some_and(|since| now_ms - since >= hold_ms)
    }
}

/// How long each of a rule's levels has been crossed, or not.
#[derive(Debug, Default)]
struct Tracker {
    /// One for each level, mildest first.
    holds: Vec<Hold>,
    /// Each sample is only counted once, as checks run more often than some
    /// agents report.
    last_sample_ms: Option<i64>,
}

impl Tracker {
    /// The hold for a rule with one level, which an offline rule sets for itself.
    fn only_hold(&mut self) -> &mut Hold {
        self.holds.resize_with(1, Hold::default);
        &mut self.holds[0]
    }

    /// Takes whether each of a rule's levels is crossed now, mildest first, and
    /// what the alert is at, if it's open. A level has to last `hold_ms` to count,
    /// and be gone that long to stop counting, so something hovering around a
    /// threshold doesn't send a stream of notifications. The alert is at the worst
    /// level that counts, and resolves when the mildest stops counting.
    fn observe(
        &mut self,
        levels: &[(Severity, bool)],
        now_ms: i64,
        hold_ms: i64,
        open: Option<Severity>,
    ) -> Option<Change> {
        self.holds.resize_with(levels.len(), Hold::default);
        for (hold, (_, breached)) in self.holds.iter_mut().zip(levels) {
            hold.observe(*breached, now_ms);
        }
        let worst = |counts: &dyn Fn(&Hold) -> bool| {
            levels
                .iter()
                .zip(&self.holds)
                .rev()
                .find(|(_, hold)| counts(hold))
                .map(|((severity, _), _)| *severity)
        };
        let lasted = worst(&|hold| hold.breached_for(now_ms, hold_ms));

        let Some(current) = open else {
            return lasted.map(Change::Fire);
        };
        if self
            .holds
            .first()
            .is_some_and(|mildest| mildest.clear_for(now_ms, hold_ms))
        {
            return Some(Change::Resolve);
        }
        if let Some(lasted) = lasted
            && lasted > current
        {
            return Some(Change::Become(lasted));
        }
        // Better, once the worse levels have been gone long enough.
        let remaining = worst(&|hold| !hold.clear_for(now_ms, hold_ms));
        remaining
            .filter(|remaining| *remaining < current)
            .map(Change::Become)
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
    /// For forecasts, the same way.
    trends: HashMap<TrendKey, Trends>,
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
            return Some(RULE_GONE_REASON);
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
            RuleKind::Metric | RuleKind::Forecast => {
                // The agent still reports the metric, so one of three things has
                // happened to this series.
                let metric = rule.rule.metric()?;
                let reported = if rule.rule.kind == RuleKind::Forecast {
                    let trends = self.trends.get(&(metric.name, rule.rule.window()))?;
                    let trends = trends.by_agent.get(&alert.agent_id)?;
                    trends
                        .iter()
                        .any(|trend| clean(&trend.series) == alert.series)
                } else {
                    let readings = self.readings.get(metric.name)?.get(&alert.agent_id)?;
                    readings
                        .iter()
                        .any(|reading| clean(&reading.series) == alert.series)
                };
                Some(if !reported {
                    "This series is no longer reported"
                } else if !rule.rule.watches_series(&alert.series) {
                    "The rule no longer covers this series"
                } else {
                    "This agent reports more series than a rule can watch"
                })
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
    /// Kept between passes, as forecasts read less often than rules are checked.
    trends: HashMap<TrendKey, Trends>,
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
            trends: HashMap::new(),
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

    async fn snapshot(&mut self, now_ms: i64) -> Result<Snapshot> {
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

        let forecasts: BTreeSet<TrendKey> = active()
            .filter(|rule| rule.rule.kind == RuleKind::Forecast)
            .filter_map(|rule| Some((rule.rule.metric()?.name, rule.rule.window())))
            .collect();
        self.trends.retain(|key, _| forecasts.contains(key));
        for key in forecasts {
            self.read_trends(key, now_ms).await?;
        }

        Ok(Snapshot {
            now_ms,
            in_grace: now_ms - self.started_ms < STARTUP_GRACE_MS,
            rules,
            agents,
            facts,
            readings,
            trends: self.trends.clone(),
        })
    }

    /// Reads which way a metric has been heading, if it's been long enough since
    /// the last time. If it can't be read, the forecast is missing until it can be.
    async fn read_trends(&mut self, key: TrendKey, now_ms: i64) -> Result<()> {
        let fresh = self
            .trends
            .get(&key)
            .is_some_and(|trends| (0..FORECAST_EVERY_MS).contains(&(now_ms - trends.read_ms)));
        if fresh {
            return Ok(());
        }
        let (name, window_secs) = key;
        let metric = metrics::find(name).context("unknown metric")?;
        let window_ms = i64::try_from(window_secs).unwrap_or(i64::MAX / 1000) * 1000;
        match self
            .metrics
            .trends(metric, now_ms - window_ms, now_ms)
            .await
        {
            Ok(rows) => {
                let mut by_agent: BTreeMap<String, Vec<Trend>> = BTreeMap::new();
                for row in rows {
                    by_agent.entry(row.agent_id.clone()).or_default().push(row);
                }
                let trends = Trends {
                    read_ms: now_ms,
                    by_agent: Arc::new(by_agent),
                };
                self.trends.insert(key, trends);
            }
            Err(error) => {
                self.trends.remove(&key);
                error!(
                    metric = name,
                    error = format!("{error:#}"),
                    "reading metrics for forecasts failed"
                );
            }
        }
        Ok(())
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
                    RuleKind::Forecast => {
                        self.check_forecast(rule, agent, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    RuleKind::Calculation => {}
                }
            }
        }

        for alert in orphans {
            self.close(&alert, now_ms, RULE_GONE_REASON).await?;
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
        let hold = tracker.only_hold();
        if online {
            hold.breached_since = None;
            hold.clear_since = Some(since);
        } else {
            hold.clear_since = None;
            hold.breached_since = Some(since);
        }
        let levels = [(rule.rule.severity, !online)];
        let current = open.get(&key).map(|alert| alert.severity);
        let change = tracker.observe(&levels, snapshot.now_ms, hold_ms(rule), current);

        let host = clean(&agent.host);
        let summary = rule.rule.offline_summary(&host);
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
        let Some(comparison) = rule.rule.comparison else {
            return Ok(());
        };
        let thresholds = rule.rule.levels();
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
            let current = open.get(&key).map(|alert| alert.severity);
            let levels = crossed(&thresholds, comparison, *value);
            let change = tracker.observe(&levels, snapshot.now_ms, hold_ms(rule), current);

            let summary = match change.as_ref().and_then(Change::severity) {
                Some(severity) => rule
                    .rule
                    .calculation_summary(&question, line, *value, severity)?,
                None => String::new(),
            };
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
        let Some(comparison) = rule.rule.comparison else {
            return Ok(());
        };
        let thresholds = rule.rule.levels();
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
            let current = open.get(&key).map(|alert| alert.severity);
            let levels = crossed(&thresholds, comparison, reading.value);
            let change = tracker.observe(&levels, snapshot.now_ms, hold_ms(rule), current);
            tracker.last_sample_ms = Some(reading.time_ms);

            let host = clean(&agent.host);
            let summary = match change.as_ref().and_then(Change::severity) {
                Some(severity) => {
                    rule.rule
                        .metric_summary(metric, &host, &series, reading.value, severity)?
                }
                None => String::new(),
            };
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

    async fn check_forecast(
        &mut self,
        rule: &AlertRule,
        agent: &AgentRecord,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let metric = rule.rule.metric().context("unknown metric")?;
        let (Some(comparison), Some(level)) = (rule.rule.comparison, rule.rule.threshold) else {
            return Ok(());
        };
        let Some(trends) = snapshot.trends.get(&(metric.name, rule.rule.window())) else {
            return Ok(());
        };
        let Some(agent_trends) = trends.by_agent.get(&agent.id) else {
            return Ok(());
        };
        let window_ms = i64::try_from(rule.rule.window()).unwrap_or(i64::MAX / 1000) * 1000;
        let watched = agent_trends
            .iter()
            .map(|trend| (clean(&trend.series), trend))
            .filter(|(series, _)| rule.rule.watches_series(series))
            .take(MAX_SERIES_PER_AGENT);

        for (series, trend) in watched {
            let key = Key {
                rule_id: rule.id,
                agent_id: agent.id.clone(),
                series: series.clone(),
            };
            checked.insert(key.clone());
            let trusted = trend.samples >= MIN_FORECAST_SAMPLES
                && trends.read_ms - trend.first_ms >= window_ms / 2
                && trends.read_ms - trend.time_ms <= FORECAST_FRESH_MS;
            let tracker = self.trackers.entry(key.clone()).or_default();
            if !trusted || tracker.last_sample_ms == Some(trend.time_ms) {
                continue;
            }
            let eta = eta_secs(trend, level, comparison, snapshot.now_ms);
            let levels: Vec<(Severity, bool)> = rule
                .rule
                .forecast_levels()
                .into_iter()
                .map(|(severity, secs)| (severity, eta.is_some_and(|eta| eta <= secs)))
                .collect();
            let current = open.get(&key).map(|alert| alert.severity);
            let change = tracker.observe(&levels, snapshot.now_ms, hold_ms(rule), current);
            tracker.last_sample_ms = Some(trend.time_ms);

            let host = clean(&agent.host);
            let summary = match (change.as_ref().and_then(Change::severity), eta) {
                (Some(_), Some(eta)) => rule.rule.forecast_summary(
                    metric,
                    &host,
                    &series,
                    trend.value,
                    trend.slope_per_ms,
                    eta,
                )?,
                _ => String::new(),
            };
            self.apply(
                change,
                rule,
                &host,
                key,
                Some(trend.value),
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
            Some(Change::Become(severity)) => {
                let Some(alert) = open.get(&key) else {
                    return Ok(());
                };
                let change = SeverityChange {
                    alert_id: alert.id,
                    severity,
                    value,
                    summary,
                    now_ms: snapshot.now_ms,
                };
                let channels = self.channels_for(rule).await?;
                if self.database.change_severity(&change, &channels).await? {
                    info!(
                        rule = rule.rule.name,
                        host,
                        severity = severity.as_str(),
                        "alert changed severity"
                    );
                }
                Ok(())
            }
            Some(Change::Fire(severity)) => {
                let new = NewAlert {
                    rule_id: rule.id,
                    rule_name: rule.rule.name.clone(),
                    severity,
                    agent_id: key.agent_id,
                    host: host.to_string(),
                    series: key.series,
                    value,
                    summary,
                    started_ms: snapshot.now_ms,
                };
                let channels = self.channels_for(rule).await?;
                self.database.fire_alert(&new, &channels).await?;
                info!(rule = rule.rule.name, host, "alert fired");
                Ok(())
            }
        }
    }

    /// Read when needed, so a channel added since the rule was saved hears too.
    async fn channels_for(&self, rule: &AlertRule) -> Result<Vec<i64>> {
        Ok(if rule.rule.all_channels {
            let every = self.database.list_channels().await?;
            every.into_iter().map(|channel| channel.id).collect()
        } else {
            rule.rule.channels.clone()
        })
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

impl Change {
    /// What the alert is at afterwards, if it's still open.
    fn severity(&self) -> Option<Severity> {
        match self {
            Self::Fire(severity) | Self::Become(severity) => Some(*severity),
            Self::Resolve => None,
        }
    }
}

/// Which of a rule's levels a value crosses, mildest first.
fn crossed(
    thresholds: &[(Severity, f64)],
    comparison: crate::alerting::Comparison,
    value: f64,
) -> Vec<(Severity, bool)> {
    thresholds
        .iter()
        .map(|(severity, threshold)| (*severity, comparison.is_breached(value, *threshold)))
        .collect()
}

/// How long from `now_ms` until a series reaches `level`, carrying on the way it
/// has been going. Nothing if it's heading the other way or not moving, and none
/// if it's already there.
fn eta_secs(
    trend: &Trend,
    level: f64,
    comparison: crate::alerting::Comparison,
    now_ms: i64,
) -> Option<u64> {
    if comparison.is_breached(trend.value, level) || trend.value == level {
        return Some(0);
    }
    let towards = match comparison {
        crate::alerting::Comparison::Above => trend.slope_per_ms,
        crate::alerting::Comparison::Below => -trend.slope_per_ms,
    };
    if towards.is_nan() || towards <= 0.0 {
        return None;
    }
    let from_newest_ms = (level - trend.value).abs() / towards;
    let from_now_ms = from_newest_ms - (now_ms - trend.time_ms) as f64;
    if !from_now_ms.is_finite() {
        return None;
    }
    // Saturates for something so slow it's of no interest.
    Some((from_now_ms.max(0.0) / 1000.0).ceil() as u64)
}

fn hold_ms(rule: &AlertRule) -> i64 {
    i64::try_from(rule.rule.for_secs).unwrap_or(i64::MAX / 1000) * 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Severity = Severity::Warning;
    const C: Severity = Severity::Critical;
    const FIRING: Option<Severity> = Some(C);

    /// A rule with one level.
    fn one(breached: bool) -> [(Severity, bool); 1] {
        [(C, breached)]
    }

    /// A rule with a warning and a critical level, and a value crossing as many.
    fn two(crossed: usize) -> [(Severity, bool); 2] {
        [(W, crossed >= 1), (C, crossed >= 2)]
    }

    #[test]
    fn a_problem_has_to_last_before_it_fires() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(true), 0, 60, None), None);
        assert_eq!(tracker.observe(&one(true), 59, 60, None), None);
        assert_eq!(
            tracker.observe(&one(true), 60, 60, None),
            Some(Change::Fire(C))
        );
    }

    #[test]
    fn a_problem_that_goes_away_starts_the_wait_again() {
        let mut tracker = Tracker::default();
        tracker.observe(&one(true), 0, 60, None);
        assert_eq!(tracker.observe(&one(false), 30, 60, None), None);
        assert_eq!(tracker.observe(&one(true), 40, 60, None), None);
        assert_eq!(tracker.observe(&one(true), 99, 60, None), None);
        assert_eq!(
            tracker.observe(&one(true), 100, 60, None),
            Some(Change::Fire(C))
        );
    }

    #[test]
    fn with_no_wait_a_problem_fires_at_once() {
        let mut tracker = Tracker::default();
        assert_eq!(
            tracker.observe(&one(true), 0, 0, None),
            Some(Change::Fire(C))
        );
    }

    #[test]
    fn an_alert_already_firing_does_not_fire_again() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(true), 0, 0, FIRING), None);
        assert_eq!(tracker.observe(&one(true), 100, 0, FIRING), None);
    }

    #[test]
    fn a_problem_has_to_stay_gone_before_it_resolves() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(false), 0, 60, FIRING), None);
        assert_eq!(tracker.observe(&one(false), 59, 60, FIRING), None);
        assert_eq!(
            tracker.observe(&one(false), 60, 60, FIRING),
            Some(Change::Resolve)
        );
    }

    #[test]
    fn a_problem_coming_back_starts_the_wait_to_resolve_again() {
        let mut tracker = Tracker::default();
        tracker.observe(&one(false), 0, 60, FIRING);
        tracker.observe(&one(true), 30, 60, FIRING);
        assert_eq!(tracker.observe(&one(false), 40, 60, FIRING), None);
        assert_eq!(tracker.observe(&one(false), 99, 60, FIRING), None);
        assert_eq!(
            tracker.observe(&one(false), 100, 60, FIRING),
            Some(Change::Resolve)
        );
    }

    #[test]
    fn nothing_resolves_when_nothing_is_firing() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(false), 0, 0, None), None);
        assert_eq!(tracker.observe(&one(false), 100, 0, None), None);
    }

    #[test]
    fn the_worst_level_that_has_lasted_fires() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&two(2), 0, 60, None), None);
        assert_eq!(
            tracker.observe(&two(2), 60, 60, None),
            Some(Change::Fire(C))
        );

        let mut tracker = Tracker::default();
        tracker.observe(&two(1), 0, 60, None);
        assert_eq!(tracker.observe(&two(2), 30, 60, None), None);
        // The warning has lasted, but the critical level hasn't yet.
        assert_eq!(
            tracker.observe(&two(2), 60, 60, None),
            Some(Change::Fire(W))
        );
        assert_eq!(tracker.observe(&two(2), 89, 60, Some(W)), None);
        assert_eq!(
            tracker.observe(&two(2), 90, 60, Some(W)),
            Some(Change::Become(C))
        );
    }

    #[test]
    fn a_critical_alert_eases_once_the_critical_level_has_been_gone_long_enough() {
        let mut tracker = Tracker::default();
        tracker.observe(&two(2), 0, 60, FIRING);
        assert_eq!(tracker.observe(&two(1), 10, 60, FIRING), None);
        assert_eq!(tracker.observe(&two(2), 20, 60, FIRING), None);
        assert_eq!(tracker.observe(&two(1), 30, 60, FIRING), None);
        assert_eq!(tracker.observe(&two(1), 89, 60, FIRING), None);
        assert_eq!(
            tracker.observe(&two(1), 90, 60, FIRING),
            Some(Change::Become(W))
        );
        assert_eq!(tracker.observe(&two(1), 200, 60, Some(W)), None);
    }

    #[test]
    fn an_alert_resolves_when_the_mildest_level_has_been_gone_long_enough() {
        let mut tracker = Tracker::default();
        tracker.observe(&two(2), 0, 60, FIRING);
        assert_eq!(tracker.observe(&two(0), 10, 60, FIRING), None);
        // Straight from critical, without easing first.
        assert_eq!(
            tracker.observe(&two(0), 70, 60, FIRING),
            Some(Change::Resolve)
        );
    }

    #[test]
    fn a_warning_does_not_ease_or_resolve_while_it_lasts() {
        let mut tracker = Tracker::default();
        for now in [0, 100, 1000] {
            assert_eq!(tracker.observe(&two(1), now, 60, Some(W)), None);
        }
    }

    fn trend(value: f64, per_hour: f64, time_ms: i64) -> Trend {
        Trend {
            agent_id: "a".to_string(),
            series: "/".to_string(),
            time_ms,
            value,
            first_ms: 0,
            samples: 100,
            slope_per_ms: per_hour / 3_600_000.0,
        }
    }

    #[test]
    fn eta_carries_the_line_on_from_the_newest_reading() {
        use crate::alerting::Comparison::{Above, Below};
        let hour = 3_600_000;
        assert_eq!(
            eta_secs(&trend(90.0, 2.0, 0), 100.0, Above, 0),
            Some(5 * 3600)
        );
        // An hour after the reading, an hour of it has gone.
        assert_eq!(
            eta_secs(&trend(90.0, 2.0, 0), 100.0, Above, hour),
            Some(4 * 3600)
        );
        assert_eq!(
            eta_secs(&trend(90.0, 2.0, 0), 100.0, Above, 9 * hour),
            Some(0)
        );
        assert_eq!(eta_secs(&trend(90.0, 0.0, 0), 100.0, Above, 0), None);
        assert_eq!(eta_secs(&trend(90.0, -2.0, 0), 100.0, Above, 0), None);
        assert_eq!(eta_secs(&trend(100.0, -2.0, 0), 100.0, Above, 0), Some(0));
        assert_eq!(
            eta_secs(&trend(20.0, -5.0, 0), 10.0, Below, 0),
            Some(2 * 3600)
        );
        assert_eq!(eta_secs(&trend(20.0, 5.0, 0), 10.0, Below, 0), None);
        assert_eq!(eta_secs(&trend(5.0, 5.0, 0), 10.0, Below, 0), Some(0));
        assert_eq!(eta_secs(&trend(90.0, f64::NAN, 0), 100.0, Above, 0), None);
        assert_eq!(eta_secs(&trend(0.0, 1e-300, 0), 100.0, Above, 0), None);
    }
}
