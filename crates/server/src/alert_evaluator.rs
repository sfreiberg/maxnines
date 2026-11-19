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
use chrono::TimeDelta;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};

use crate::actions::Actions;
use crate::alerting::{
    Alert, AlertRule, NewAlert, RULE_GONE_REASON, RuleKind, Severity, SeverityChange, clean,
};
use crate::calculations::{
    self, Calculation, Grouping, Question, SMALLEST_STEP, Sources, over_window,
};
use crate::facts::{FlatFacts, unflatten};
use crate::metrics::{self, Metrics, NewestReading, TimeRange, Trend};
use crate::models::Database;
use crate::presence::Presence;
use crate::registration::{HostRecord, HostState, Registry};
use crate::remote_checks::{FLEET_HOST_ID, FLEET_HOSTNAME};
use crate::rule_engine;
use crate::server_stats::ServerStatus;
use crate::times::{self, Timestamp};

/// How often rules are checked. Matches the default sample interval.
const INTERVAL: Duration = Duration::from_secs(15);

/// How long after an agent reconnects to check rules, so its offline alert
/// resolves within moments rather than at the next pass.
const RECONNECT_SETTLE: Duration = Duration::from_secs(1);

/// Nobody is connected just after a start, and agents take a moment to come
/// back. Without this, every restart would look like the whole fleet going down.
const STARTUP_GRACE: TimeDelta = TimeDelta::minutes(2);

/// An agent can report as many disks or interfaces as it likes, and each series
/// can be its own alert. No real host needs more than this.
const MAX_SERIES_PER_HOST: usize = 64;

/// A calculation can have a line for every host, and each can be its own alert.
const MAX_CALCULATION_LINES: usize = 500;

/// How often forecasts read their metrics again. Reading hours of every disk is
/// work, and a line through hours barely moves in a few minutes.
const FORECAST_EVERY: TimeDelta = TimeDelta::minutes(5);
/// A line through fewer readings than this, or through less than half of how far
/// back the rule looks, isn't trusted to say anything.
const MIN_FORECAST_SAMPLES: u64 = 10;
/// A series not heard from for this long has no forecast, as with any missing
/// reading, which says nothing about whether anything is wrong.
const FORECAST_FRESH: TimeDelta = TimeDelta::minutes(10);

/// A no-metrics rule waits at least this many of an agent's intervals, so a host set to
/// send a sample every ten minutes isn't silent between them. A first sample can take
/// up to an interval longer than the rest, and a write can be held back to batch it,
/// so this many means samples really have stopped, not that one is late.
const MISSED_SAMPLES: i32 = 3;

/// What a forecast reads: a metric over how far back it looks.
type TrendKey = (&'static str, TimeDelta);

/// Trends by agent, and when they were read.
#[derive(Clone)]
struct Trends {
    read_at: Timestamp,
    by_host: Arc<BTreeMap<String, Vec<Trend>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    rule_id: i64,
    host_id: String,
    /// None for the host as a whole.
    series: Option<String>,
}

/// A reading's series as an alert keeps it. A metric reported once for the whole host
/// has a series with no name, and its alerts have none.
fn alert_series(series: &str) -> Option<String> {
    (!series.is_empty()).then(|| series.to_string())
}

impl Key {
    fn of(alert: &Alert) -> Self {
        Self {
            rule_id: alert.rule_id,
            host_id: alert.host_id.clone(),
            series: alert.series.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Change {
    Fire(Severity),
    /// An open alert getting worse, or better without being over.
    Become(Severity),
    Resolve,
}

/// How long one level of a problem has lasted.
#[derive(Debug, Default)]
struct Hold {
    breached_since: Option<Timestamp>,
}

impl Hold {
    fn observe(&mut self, breached: bool, now: Timestamp) {
        if breached {
            self.breached_since.get_or_insert(now);
        } else {
            self.breached_since = None;
        }
    }

    fn is_breached(&self) -> bool {
        self.breached_since.is_some()
    }

    fn breached_for(&self, now: Timestamp, hold: TimeDelta) -> bool {
        self.breached_since.is_some_and(|since| now - since >= hold)
    }
}

/// How long each of a rule's levels has been crossed, or not.
#[derive(Debug, Default)]
struct Tracker {
    /// One for each level, mildest first.
    holds: Vec<Hold>,
    /// Each sample is only counted once, as checks run more often than some
    /// agents report. For a no-metrics rule, the newest sample seen from the host.
    last_sample: Option<Timestamp>,
}

impl Tracker {
    /// When the problem began: the earliest any of its levels was crossed, and has
    /// been since.
    fn breached_since(&self) -> Option<Timestamp> {
        self.holds
            .iter()
            .filter_map(|hold| hold.breached_since)
            .min()
    }

    /// The hold for a rule with one level, which an offline rule sets for itself.
    fn only_hold(&mut self) -> &mut Hold {
        self.holds.resize_with(1, Hold::default);
        &mut self.holds[0]
    }

    /// Takes whether each of a rule's levels is crossed now, mildest first, and
    /// what the alert is at, if it's open. A level has to last `hold` to count,
    /// so a passing moment doesn't alert, and stops counting the moment it's gone:
    /// a recovery is said at once, and something going back and forth is seen
    /// doing it, not hidden behind a wait. The alert is at the worst level that
    /// counts, and resolves when the mildest is gone.
    fn observe(
        &mut self,
        levels: &[(Severity, bool)],
        now: Timestamp,
        hold: TimeDelta,
        open: Option<Severity>,
    ) -> Option<Change> {
        self.holds.resize_with(levels.len(), Hold::default);
        for (level, (_, breached)) in self.holds.iter_mut().zip(levels) {
            level.observe(*breached, now);
        }
        let worst = |counts: &dyn Fn(&Hold) -> bool| {
            levels
                .iter()
                .zip(&self.holds)
                .rev()
                .find(|(_, hold)| counts(hold))
                .map(|((severity, _), _)| *severity)
        };
        let lasted = worst(&|level| level.breached_for(now, hold));

        let Some(current) = open else {
            return lasted.map(Change::Fire);
        };
        if self
            .holds
            .first()
            .is_some_and(|mildest| !mildest.is_breached())
        {
            return Some(Change::Resolve);
        }
        if let Some(lasted) = lasted
            && lasted > current
        {
            return Some(Change::Become(lasted));
        }
        // Better, as soon as the worse levels are gone.
        let remaining = worst(&Hold::is_breached);
        remaining
            .filter(|remaining| *remaining < current)
            .map(Change::Become)
    }
}

/// Everything one pass looks at, loaded once.
struct Snapshot {
    now: Timestamp,
    in_grace: bool,
    rules: BTreeMap<i64, AlertRule>,
    hosts: BTreeMap<String, HostRecord>,
    facts: BTreeMap<String, Value>,
    /// By metric and agent. A metric that couldn't be read is missing, which
    /// says nothing about whether anything is wrong.
    readings: BTreeMap<&'static str, BTreeMap<String, Vec<NewestReading>>>,
    /// For forecasts, the same way.
    trends: HashMap<TrendKey, Trends>,
    /// For no-metrics rules, when each host's newest current sample was taken. None
    /// if that couldn't be read, which says nothing about whether anything is wrong.
    last_samples: Option<BTreeMap<String, Timestamp>>,
}

impl Snapshot {
    /// A condition that can't be evaluated doesn't match, as with config rules.
    fn rule_applies(&self, rule: &AlertRule, host_id: &str) -> bool {
        let Some(condition) = &rule.rule.condition else {
            return true;
        };
        let facts = self.facts.get(host_id).unwrap_or(&Value::Null);
        rule_engine::evaluate(condition, facts, host_id).unwrap_or(false)
    }

    /// Why an open alert that nothing checked this time should end, if it should.
    /// Missing data is never a reason: the agent may just be offline, and that's
    /// exactly when a disk alert shouldn't quietly close itself.
    fn reason_to_close(&self, alert: &Alert) -> Option<&'static str> {
        let Some(rule) = self
            .rules
            .get(&alert.rule_id)
            .filter(|rule| rule.rule.enabled)
        else {
            return Some(RULE_GONE_REASON);
        };
        // Checking a calculation deals with its own alerts. Getting here means it
        // couldn't be read, which says nothing about whether anything is wrong.
        if rule.rule.kind == RuleKind::Calculation {
            return None;
        }
        if !self.hosts.contains_key(&alert.host_id) {
            return Some("The host is no longer approved");
        }
        if !self.rule_applies(rule, &alert.host_id) {
            return Some("The rule no longer applies to this host");
        }
        match rule.rule.kind {
            RuleKind::Offline if self.in_grace => None,
            RuleKind::Offline => Some("The rule changed"),
            // Only a connected agent is checked. One that's gone, or not back yet after
            // a restart, still isn't sending anything: the offline rule says it's gone,
            // and this alert ends once its samples are stored again.
            RuleKind::NoMetrics => None,
            RuleKind::Calculation => None,
            RuleKind::Metric | RuleKind::Forecast => {
                // The agent still reports the metric, so one of three things has
                // happened to this series.
                let metric = rule.rule.metric()?;
                let reported = if rule.rule.kind == RuleKind::Forecast {
                    let trends = self.trends.get(&(metric.name, rule.rule.window()))?;
                    let trends = trends.by_host.get(&alert.host_id)?;
                    trends
                        .iter()
                        .any(|trend| alert_series(&clean(&trend.series)) == alert.series)
                } else {
                    let readings = self.readings.get(metric.name)?.get(&alert.host_id)?;
                    readings
                        .iter()
                        .any(|reading| alert_series(&clean(&reading.series)) == alert.series)
                };
                Some(if !reported {
                    "This series is no longer reported"
                } else if !rule
                    .rule
                    .watches_series(alert.series.as_deref().unwrap_or_default())
                {
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
    /// Runs what a rule asks for on an alert's host.
    actions: Arc<Actions>,
    started_at: Timestamp,
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
        actions: Arc<Actions>,
        started_at: Timestamp,
    ) -> Self {
        Self {
            database,
            registry,
            presence,
            metrics,
            status,
            actions,
            started_at,
            trackers: HashMap::new(),
            trends: HashMap::new(),
        }
    }

    /// Runs until the server stops. Each pass is its own task, so a panic costs
    /// that pass and the next one starts as usual.
    pub fn spawn(self) -> JoinHandle<()> {
        let presence = self.presence.clone();
        let evaluator = Arc::new(Mutex::new(self));
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(INTERVAL);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = timer.tick() => {}
                    () = presence.came_online.notified() => {
                        // Agents come back together after a network blip or a
                        // restart, so one pass covers all that arrive meanwhile.
                        tokio::time::sleep(RECONNECT_SETTLE).await;
                        timer.reset();
                    }
                }
                let evaluator = evaluator.clone();
                let pass =
                    tokio::spawn(
                        async move { evaluator.lock().await.evaluate(times::now()).await },
                    );
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

    async fn snapshot(&mut self, now: Timestamp) -> Result<Snapshot> {
        let rules: BTreeMap<i64, AlertRule> = self
            .database
            .list_alert_rules()
            .await?
            .into_iter()
            .map(|rule| (rule.id, rule))
            .collect();

        let hosts = self
            .registry
            .list()
            .await
            .into_iter()
            .filter(|host| host.state == HostState::Approved)
            .map(|host| (host.id.clone(), host))
            .collect();

        let active = || rules.values().filter(|rule| rule.rule.enabled);

        let needs_facts = active().any(|rule| rule.rule.condition.is_some());
        let facts = if needs_facts {
            let all = self.database.all_current_facts().await?;
            all.iter()
                .map(|(host, facts)| (host.clone(), unflatten(facts)))
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
            match self.metrics.newest(metric, now).await {
                Ok(rows) => {
                    let mut by_host: BTreeMap<String, Vec<NewestReading>> = BTreeMap::new();
                    for row in rows {
                        by_host.entry(row.host_id.clone()).or_default().push(row);
                    }
                    readings.insert(name, by_host);
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
            self.read_trends(key, now).await?;
        }

        let watches_samples = active().any(|rule| rule.rule.kind == RuleKind::NoMetrics);
        let last_samples = if watches_samples {
            self.read_last_samples(now).await
        } else {
            None
        };

        Ok(Snapshot {
            now,
            in_grace: now - self.started_at < STARTUP_GRACE,
            rules,
            hosts,
            facts,
            readings,
            trends: self.trends.clone(),
            last_samples,
        })
    }

    /// When each host's newest current sample was taken, in one query for them all.
    /// If it can't be read, no-metrics rules wait until it can.
    async fn read_last_samples(&self, now: Timestamp) -> Option<BTreeMap<String, Timestamp>> {
        match self.metrics.last_samples(now).await {
            Ok(rows) => Some(
                rows.into_iter()
                    .map(|row| (row.host_id, row.time))
                    .collect(),
            ),
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    "reading when hosts last sent samples failed"
                );
                None
            }
        }
    }

    /// How often an agent is set to send a sample, by the config rules that apply to
    /// it now, or nothing if its config can't be worked out.
    async fn interval(&self, host_id: &str) -> Result<Option<TimeDelta>> {
        let rules = self.database.list_rules().await?;
        let facts: FlatFacts = self
            .database
            .current_facts(host_id)
            .await?
            .into_iter()
            .map(|fact| (fact.name, fact.value))
            .collect();
        let resolved = rule_engine::resolve(&rules, &unflatten(&facts), host_id);
        Ok(resolved
            .ok()
            .and_then(|resolved| TimeDelta::from_std(resolved.config.interval).ok()))
    }

    /// Reads which way a metric has been heading, if it's been long enough since
    /// the last time. If it can't be read, the forecast is missing until it can be.
    async fn read_trends(&mut self, key: TrendKey, now: Timestamp) -> Result<()> {
        let fresh = self.trends.get(&key).is_some_and(|trends| {
            (TimeDelta::zero()..FORECAST_EVERY).contains(&(now - trends.read_at))
        });
        if fresh {
            return Ok(());
        }
        let (name, window) = key;
        let metric = metrics::find(name).context("unknown metric")?;
        match self.metrics.trends(metric, now - window, now).await {
            Ok(rows) => {
                let mut by_host: BTreeMap<String, Vec<Trend>> = BTreeMap::new();
                for row in rows {
                    by_host.entry(row.host_id.clone()).or_default().push(row);
                }
                let trends = Trends {
                    read_at: now,
                    by_host: Arc::new(by_host),
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
    pub async fn evaluate(&mut self, now: Timestamp) -> Result<()> {
        let snapshot = self.snapshot(now).await?;
        let open_alerts = self.database.open_alerts().await?;
        let mut open: HashMap<Key, Alert> = open_alerts
            .into_iter()
            .map(|alert| (Key::of(&alert), alert))
            .collect();

        let mut checked = HashSet::new();
        for rule in snapshot.rules.values().filter(|rule| rule.rule.enabled) {
            if rule.rule.kind == RuleKind::Calculation {
                if !snapshot.in_grace {
                    self.check_calculation(rule, &snapshot, &mut open, &mut checked)
                        .await?;
                }
                continue;
            }
            for host in snapshot.hosts.values() {
                if !snapshot.rule_applies(rule, &host.id) {
                    continue;
                }
                match rule.rule.kind {
                    RuleKind::Offline if host.is_local() => {}
                    RuleKind::Offline => {
                        self.check_offline(rule, host, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    // The server reads what it has of these hosts itself, so there's
                    // no agent whose samples could stop.
                    RuleKind::NoMetrics if host.is_local() || host.is_agentless() => {}
                    RuleKind::NoMetrics => {
                        self.check_no_metrics(rule, host, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    RuleKind::Metric => {
                        self.check_metric(rule, host, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    RuleKind::Forecast => {
                        self.check_forecast(rule, host, &snapshot, &mut open, &mut checked)
                            .await?;
                    }
                    RuleKind::Calculation => {}
                }
            }
        }

        for (key, alert) in &open {
            if !checked.contains(key)
                && let Some(reason) = snapshot.reason_to_close(alert)
            {
                self.close(alert, now, reason, None).await?;
            }
        }

        self.actions.give_up_on_unanswered(now).await?;
        self.trackers.retain(|key, _| checked.contains(key));
        let firing = self.database.open_alerts().await?.len();
        self.status.firing.store(firing, Ordering::Relaxed);
        self.status.alert_pass_finished(now);
        Ok(())
    }

    async fn check_offline(
        &mut self,
        rule: &AlertRule,
        host: &HostRecord,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let key = Key {
            rule_id: rule.id,
            host_id: host.id.clone(),
            series: None,
        };
        checked.insert(key.clone());

        // An agent that hasn't connected since the start has been gone at least
        // that long, and may have been offline before it.
        let presence = self.presence.get(&host.id);
        // A host with no agent is only as present as what the server reads from it,
        // so one with nothing to read, or not read yet, is neither on nor off.
        if host.is_agentless() && presence.is_none() {
            return Ok(());
        }
        let online = presence.is_some_and(|p| p.online);
        let since = presence.map_or(self.started_at, |p| p.since);
        // Just after a start, an agent that isn't back yet may only be slow to
        // reconnect, so it's left as it was. One that is back is certainly online.
        if snapshot.in_grace && !online {
            return Ok(());
        }

        let tracker = self.trackers.entry(key.clone()).or_default();
        let hold = tracker.only_hold();
        hold.breached_since = (!online).then_some(since);
        let levels = [(rule.rule.severity, !online)];
        let current = open.get(&key).map(|alert| alert.severity);
        let change = tracker.observe(&levels, snapshot.now, rule.rule.hold, current);

        let hostname = clean(&host.hostname);
        let summary = match change {
            Some(Change::Resolve) => crate::alerting::AlertRuleInput::online_summary(&hostname),
            _ => crate::alerting::AlertRuleInput::offline_summary(&hostname),
        };
        self.apply(change, rule, &hostname, key, None, summary, snapshot, open)
            .await
    }

    /// Alerts on a connected agent whose samples have stopped being stored, as when the
    /// server refuses everything it sends. One that isn't connected is the offline
    /// rule's to alert on, so it's left alone.
    async fn check_no_metrics(
        &mut self,
        rule: &AlertRule,
        host: &HostRecord,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let Some(presence) = self.presence.get(&host.id).filter(|p| p.online) else {
            return Ok(());
        };
        let key = Key {
            rule_id: rule.id,
            host_id: host.id.clone(),
            series: None,
        };
        checked.insert(key.clone());
        let Some(last_samples) = &snapshot.last_samples else {
            return Ok(());
        };

        // A sample is only current for a few minutes, so the newest one seen is kept
        // while the agent stays connected, for one that sends less often than that.
        let tracker = self.trackers.entry(key.clone()).or_default();
        if let Some(&taken) = last_samples.get(&host.id) {
            tracker.last_sample = tracker.last_sample.max(Some(taken));
        }
        let newest = tracker.last_sample;
        // The silence began with the newest sample, or with connecting if none has
        // come since, as an agent that was away can't have sent anything meanwhile.
        let since = newest.map_or(presence.since, |taken| taken.max(presence.since));
        let quiet_for = snapshot.now - since;
        let silent = match open.get(&key) {
            // It's over once anything newer than the silence is stored, even if the
            // agent has reconnected since, which starts the count above again.
            Some(alert) => !newest.is_some_and(|taken| taken > alert.breached_at),
            // One that sends seldom gets a few of its intervals too. They're only
            // worked out for a host quiet for longer than the hold, which is rare.
            None if quiet_for >= rule.rule.hold => match self.interval(&host.id).await? {
                Some(every) => quiet_for >= every * MISSED_SAMPLES,
                None => true,
            },
            None => false,
        };

        let tracker = self.trackers.entry(key.clone()).or_default();
        let hold = tracker.only_hold();
        hold.breached_since = silent.then_some(since);
        let levels = [(rule.rule.severity, silent)];
        let current = open.get(&key).map(|alert| alert.severity);
        let change = tracker.observe(&levels, snapshot.now, rule.rule.hold, current);
        // Just after a start, agents are still reconnecting and sending what they
        // kept meanwhile, so nothing starts. Samples arriving still end an alert.
        if snapshot.in_grace && matches!(change, Some(Change::Fire(_))) {
            return Ok(());
        }

        let hostname = clean(&host.hostname);
        let summary = match change {
            Some(Change::Resolve) => {
                crate::alerting::AlertRuleInput::metrics_again_summary(&hostname)
            }
            _ => crate::alerting::AlertRuleInput::no_metrics_summary(&hostname),
        };
        self.apply(change, rule, &hostname, key, None, summary, snapshot, open)
            .await
    }

    /// The lines of a calculation with a number for each, or nothing if it couldn't
    /// be read, which says nothing about whether anything is wrong.
    async fn calculated_lines(
        &self,
        rule: &AlertRule,
        question: &Question,
        now: Timestamp,
    ) -> Option<Vec<(String, f64)>> {
        let range = TimeRange::ending(now, rule.rule.window() + SMALLEST_STEP)?;
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
        // Nothing reporting is exactly what a rule counting hosts is there to catch.
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
        let Some(lines) = self.calculated_lines(rule, &question, snapshot.now).await else {
            return Ok(());
        };

        let key_of = |line: &str| Key {
            rule_id: rule.id,
            host_id: FLEET_HOST_ID.to_string(),
            series: alert_series(line),
        };
        for (line, value) in &lines {
            let key = key_of(line);
            checked.insert(key.clone());

            let tracker = self.trackers.entry(key.clone()).or_default();
            let current = open.get(&key).map(|alert| alert.severity);
            let levels = crossed(&thresholds, comparison, *value);
            let change = tracker.observe(&levels, snapshot.now, rule.rule.hold, current);

            let summary = match change {
                Some(Change::Resolve) => rule
                    .rule
                    .calculation_cleared_summary(&question, line, *value)?,
                Some(Change::Fire(severity) | Change::Become(severity)) => rule
                    .rule
                    .calculation_summary(&question, line, *value, severity)?,
                None => String::new(),
            };
            self.apply(
                change,
                rule,
                FLEET_HOSTNAME,
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
                    let reason = "This line is no longer reported";
                    self.close(&alert, snapshot.now, reason, None).await?;
                }
            }
        }
        Ok(())
    }

    async fn check_metric(
        &mut self,
        rule: &AlertRule,
        host: &HostRecord,
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
            .and_then(|by_host| by_host.get(&host.id))
        else {
            return Ok(());
        };

        let watched = readings
            .iter()
            .map(|reading| (clean(&reading.series), reading))
            .filter(|(series, _)| rule.rule.watches_series(series))
            .take(MAX_SERIES_PER_HOST);
        // What the collector last sent, read once and only if an alert needs its words.
        let described = metrics::described(metric);
        let mut output = None;

        for (series, reading) in watched {
            let key = Key {
                rule_id: rule.id,
                host_id: host.id.clone(),
                series: alert_series(&series),
            };
            checked.insert(key.clone());

            let tracker = self.trackers.entry(key.clone()).or_default();
            if tracker.last_sample == Some(reading.time) {
                continue;
            }
            let current = open.get(&key).map(|alert| alert.severity);
            let levels = crossed(&thresholds, comparison, reading.value);
            let change = tracker.observe(&levels, snapshot.now, rule.rule.hold, current);
            tracker.last_sample = Some(reading.time);

            let hostname = clean(&host.hostname);
            // Said in the collector's own words where it has them, such as a
            // service that's failed, as the alert starts, while it lasts, and as
            // it clears.
            let breached = levels.iter().any(|(_, breached)| *breached);
            let resolving = matches!(change, Some(Change::Resolve));
            let says = change.is_some() || (current.is_some() && breached);
            let state = match described.filter(|_| says) {
                Some(described) => {
                    if output.is_none() {
                        let latest =
                            self.metrics
                                .latest_output(&host.id, metric.collector, snapshot.now);
                        output = Some(latest.await.ok().flatten().unwrap_or(Value::Null));
                    }
                    let state =
                        described.state_of(output.as_ref().unwrap_or(&Value::Null), &series);
                    state.map(|state| {
                        crate::alerting::AlertRuleInput::state_summary(
                            described.noun,
                            &hostname,
                            &series,
                            &state,
                        )
                    })
                }
                None => None,
            };
            let summary = match (change.as_ref().and_then(Change::severity), state) {
                (None, Some(state)) if resolving => state,
                (None, None) if resolving => {
                    rule.rule
                        .metric_cleared_summary(metric, &hostname, &series, reading.value)?
                }
                (Some(_), Some(state)) => state,
                (Some(severity), None) => {
                    rule.rule
                        .metric_summary(metric, &hostname, &series, reading.value, severity)?
                }
                // Its state changed while it stayed down, which nobody needs telling.
                (None, Some(state)) => {
                    if let Some(alert) = open.get_mut(&key)
                        && alert.summary != state
                    {
                        self.database.reword_alert(alert.id, &state).await?;
                        alert.summary = state;
                    }
                    String::new()
                }
                (None, None) => String::new(),
            };
            self.apply(
                change,
                rule,
                &hostname,
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
        host: &HostRecord,
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
        let Some(host_trends) = trends.by_host.get(&host.id) else {
            return Ok(());
        };
        let window = rule.rule.window();
        let watched = host_trends
            .iter()
            .map(|trend| (clean(&trend.series), trend))
            .filter(|(series, _)| rule.rule.watches_series(series))
            .take(MAX_SERIES_PER_HOST);

        for (series, trend) in watched {
            let key = Key {
                rule_id: rule.id,
                host_id: host.id.clone(),
                series: alert_series(&series),
            };
            checked.insert(key.clone());
            let trusted = trend.samples >= MIN_FORECAST_SAMPLES
                && trends.read_at - trend.first_time >= window / 2
                && trends.read_at - trend.time <= FORECAST_FRESH;
            let tracker = self.trackers.entry(key.clone()).or_default();
            if !trusted || tracker.last_sample == Some(trend.time) {
                continue;
            }
            let eta = eta(trend, level, comparison, snapshot.now);
            let levels: Vec<(Severity, bool)> = rule
                .rule
                .forecast_levels()
                .into_iter()
                .map(|(severity, soon)| (severity, eta.is_some_and(|eta| eta <= soon)))
                .collect();
            let current = open.get(&key).map(|alert| alert.severity);
            let change = tracker.observe(&levels, snapshot.now, rule.rule.hold, current);
            tracker.last_sample = Some(trend.time);

            let hostname = clean(&host.hostname);
            let summary = match (change.as_ref().and_then(Change::severity), eta) {
                _ if matches!(change, Some(Change::Resolve)) => {
                    rule.rule.forecast_cleared_summary(
                        metric,
                        &hostname,
                        &series,
                        trend.value,
                        trend.slope_per_sec,
                        eta,
                    )?
                }
                (Some(_), Some(eta)) => rule.rule.forecast_summary(
                    metric,
                    &hostname,
                    &series,
                    trend.value,
                    trend.slope_per_sec,
                    eta,
                )?,
                _ => String::new(),
            };
            self.apply(
                change,
                rule,
                &hostname,
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
        hostname: &str,
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
                    let now = Some(summary.as_str()).filter(|summary| !summary.is_empty());
                    self.close(&alert, snapshot.now, "The problem cleared", now)
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
                    changed_at: snapshot.now,
                };
                let channels = self.channels_for(rule).await?;
                if self.database.change_severity(&change, &channels).await? {
                    info!(
                        rule = rule.rule.name,
                        hostname,
                        severity = severity.as_str(),
                        "alert changed severity"
                    );
                    let alert = Alert {
                        severity,
                        value: value.or(alert.value),
                        ..alert.clone()
                    };
                    self.run_actions(rule, &alert, false, snapshot.now).await;
                }
                Ok(())
            }
            Some(Change::Fire(severity)) => {
                // A level only counts once it's held, so a problem has always begun
                // by the time its alert fires.
                let breached_at = self
                    .trackers
                    .get(&key)
                    .and_then(Tracker::breached_since)
                    .unwrap_or(snapshot.now);
                let new = NewAlert {
                    rule_id: rule.id,
                    severity,
                    host_id: key.host_id,
                    series: key.series,
                    value,
                    summary,
                    started_at: snapshot.now,
                    breached_at,
                };
                let channels = self.channels_for(rule).await?;
                let id = self.database.fire_alert(&new, &channels).await?;
                info!(rule = rule.rule.name, hostname, "alert fired");
                if let Some(alert) = self.database.get_alert(id).await? {
                    self.run_actions(rule, &alert, true, snapshot.now).await;
                }
                Ok(())
            }
        }
    }

    /// Asks the alert's host for whatever the rule runs at this point. A failure
    /// here is logged and left, as the alert itself has already been saved.
    async fn run_actions(&self, rule: &AlertRule, alert: &Alert, started: bool, now: Timestamp) {
        let asked = self.actions.run_for_alert(rule, alert, started, now);
        if let Err(error) = asked.await {
            error!(
                rule = rule.rule.name,
                error = format!("{error:#}"),
                "asking for an alert's actions failed"
            );
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

    /// Ends an alert for `reason`, saying where things stand now if the problem
    /// cleared.
    async fn close(
        &self,
        alert: &Alert,
        now: Timestamp,
        reason: &str,
        summary: Option<&str>,
    ) -> Result<()> {
        self.database
            .resolve_alert(alert.id, now, reason, summary)
            .await?;
        info!(
            rule = alert.rule_name,
            host = alert.host_id,
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

/// How long from `now` until a series reaches `level`, carrying on the way it has
/// been going, to the second. Nothing if it's heading the other way or not moving,
/// and none if it's already there.
fn eta(
    trend: &Trend,
    level: f64,
    comparison: crate::alerting::Comparison,
    now: Timestamp,
) -> Option<TimeDelta> {
    if comparison.is_breached(trend.value, level) || trend.value == level {
        return Some(TimeDelta::zero());
    }
    let towards = match comparison {
        crate::alerting::Comparison::Above => trend.slope_per_sec,
        crate::alerting::Comparison::Below => -trend.slope_per_sec,
    };
    if towards.is_nan() || towards <= 0.0 {
        return None;
    }
    let from_newest = (level - trend.value).abs() / towards;
    let since_newest = (now - trend.time).num_milliseconds() as f64 / 1000.0;
    let from_now = (from_newest - since_newest).max(0.0).ceil();
    // Something so slow it would take longer than a moment can be away is of no
    // interest, and neither is anything that isn't a number.
    if !from_now.is_finite() || from_now >= TimeDelta::MAX.num_seconds() as f64 {
        return None;
    }
    Some(TimeDelta::seconds(from_now as i64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::times::from_ms;

    /// The moment `seconds` into the tests' time.
    fn at(seconds: i64) -> Timestamp {
        from_ms(1_795_000_000_000 + seconds * 1000)
    }

    fn secs(seconds: i64) -> TimeDelta {
        TimeDelta::seconds(seconds)
    }

    const W: Severity = Severity::Warning;
    const C: Severity = Severity::Critical;
    const FIRING: Option<Severity> = Some(C);

    /// A rule with one level.
    #[test]
    fn a_problem_breached_when_its_first_level_was_crossed() {
        let mut tracker = Tracker::default();
        let levels = |warning, critical| [(W, warning), (C, critical)];
        assert_eq!(
            tracker.observe(&levels(true, false), at(1), secs(60), None),
            None
        );
        assert_eq!(tracker.breached_since(), Some(at(1)));
        // Worse later, it still breached when it first went wrong.
        tracker.observe(&levels(true, true), at(30), secs(60), None);
        assert_eq!(
            tracker.observe(&levels(true, true), at(61), secs(60), None),
            Some(Change::Fire(W))
        );
        assert_eq!(tracker.breached_since(), Some(at(1)));
        // Once it's fine, there's nothing breached.
        tracker.observe(&levels(false, false), at(70), secs(60), Some(W));
        assert_eq!(tracker.breached_since(), None);
    }

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
        assert_eq!(tracker.observe(&one(true), at(0), secs(60), None), None);
        assert_eq!(tracker.observe(&one(true), at(59), secs(60), None), None);
        assert_eq!(
            tracker.observe(&one(true), at(60), secs(60), None),
            Some(Change::Fire(C))
        );
    }

    #[test]
    fn a_problem_that_goes_away_starts_the_wait_again() {
        let mut tracker = Tracker::default();
        tracker.observe(&one(true), at(0), secs(60), None);
        assert_eq!(tracker.observe(&one(false), at(30), secs(60), None), None);
        assert_eq!(tracker.observe(&one(true), at(40), secs(60), None), None);
        assert_eq!(tracker.observe(&one(true), at(99), secs(60), None), None);
        assert_eq!(
            tracker.observe(&one(true), at(100), secs(60), None),
            Some(Change::Fire(C))
        );
    }

    #[test]
    fn with_no_wait_a_problem_fires_at_once() {
        let mut tracker = Tracker::default();
        assert_eq!(
            tracker.observe(&one(true), at(0), secs(0), None),
            Some(Change::Fire(C))
        );
    }

    #[test]
    fn an_alert_already_firing_does_not_fire_again() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(true), at(0), secs(0), FIRING), None);
        assert_eq!(tracker.observe(&one(true), at(100), secs(0), FIRING), None);
    }

    #[test]
    fn a_problem_that_is_gone_resolves_at_once() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(true), at(0), secs(60), FIRING), None);
        assert_eq!(
            tracker.observe(&one(false), at(1), secs(60), FIRING),
            Some(Change::Resolve)
        );
    }

    #[test]
    fn a_problem_that_comes_and_goes_is_said_each_time_it_lasts() {
        let mut tracker = Tracker::default();
        tracker.observe(&one(true), at(0), secs(60), None);
        assert_eq!(
            tracker.observe(&one(true), at(60), secs(60), None),
            Some(Change::Fire(C))
        );
        assert_eq!(
            tracker.observe(&one(false), at(70), secs(60), FIRING),
            Some(Change::Resolve)
        );
        // Back again, it has to last all over again.
        assert_eq!(tracker.observe(&one(true), at(80), secs(60), None), None);
        assert_eq!(tracker.observe(&one(true), at(139), secs(60), None), None);
        assert_eq!(
            tracker.observe(&one(true), at(140), secs(60), None),
            Some(Change::Fire(C))
        );
        // One that never lasts never alerts.
        let mut tracker = Tracker::default();
        for now in (0..600).step_by(20) {
            assert_eq!(
                tracker.observe(&one(now % 40 == 0), at(now), secs(60), None),
                None
            );
        }
    }

    #[test]
    fn nothing_resolves_when_nothing_is_firing() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&one(false), at(0), secs(0), None), None);
        assert_eq!(tracker.observe(&one(false), at(100), secs(0), None), None);
    }

    #[test]
    fn the_worst_level_that_has_lasted_fires() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(&two(2), at(0), secs(60), None), None);
        assert_eq!(
            tracker.observe(&two(2), at(60), secs(60), None),
            Some(Change::Fire(C))
        );

        let mut tracker = Tracker::default();
        tracker.observe(&two(1), at(0), secs(60), None);
        assert_eq!(tracker.observe(&two(2), at(30), secs(60), None), None);
        // The warning has lasted, but the critical level hasn't yet.
        assert_eq!(
            tracker.observe(&two(2), at(60), secs(60), None),
            Some(Change::Fire(W))
        );
        assert_eq!(tracker.observe(&two(2), at(89), secs(60), Some(W)), None);
        assert_eq!(
            tracker.observe(&two(2), at(90), secs(60), Some(W)),
            Some(Change::Become(C))
        );
    }

    #[test]
    fn a_critical_alert_eases_as_soon_as_the_critical_level_is_gone() {
        let mut tracker = Tracker::default();
        tracker.observe(&two(2), at(0), secs(60), FIRING);
        assert_eq!(
            tracker.observe(&two(1), at(10), secs(60), FIRING),
            Some(Change::Become(W))
        );
        assert_eq!(tracker.observe(&two(1), at(200), secs(60), Some(W)), None);
        // Critical again has to last before it counts again.
        assert_eq!(tracker.observe(&two(2), at(210), secs(60), Some(W)), None);
        assert_eq!(
            tracker.observe(&two(2), at(270), secs(60), Some(W)),
            Some(Change::Become(C))
        );
    }

    #[test]
    fn an_alert_resolves_as_soon_as_the_mildest_level_is_gone() {
        let mut tracker = Tracker::default();
        tracker.observe(&two(2), at(0), secs(60), FIRING);
        // Straight from critical, without easing first.
        assert_eq!(
            tracker.observe(&two(0), at(10), secs(60), FIRING),
            Some(Change::Resolve)
        );
    }

    #[test]
    fn a_warning_does_not_ease_or_resolve_while_it_lasts() {
        let mut tracker = Tracker::default();
        for now in [0, 100, 1000] {
            assert_eq!(tracker.observe(&two(1), at(now), secs(60), Some(W)), None);
        }
    }

    fn trend(value: f64, per_hour: f64) -> Trend {
        Trend {
            host_id: "a".to_string(),
            series: "/".to_string(),
            time: at(0),
            value,
            first_time: at(-3600),
            samples: 100,
            slope_per_sec: per_hour / 3600.0,
        }
    }

    #[test]
    fn eta_carries_the_line_on_from_the_newest_reading() {
        use crate::alerting::Comparison::{Above, Below};
        let hours = |count| Some(TimeDelta::hours(count));
        assert_eq!(eta(&trend(90.0, 2.0), 100.0, Above, at(0)), hours(5));
        // An hour after the reading, an hour of it has gone.
        assert_eq!(eta(&trend(90.0, 2.0), 100.0, Above, at(3600)), hours(4));
        assert_eq!(eta(&trend(90.0, 2.0), 100.0, Above, at(9 * 3600)), hours(0));
        assert_eq!(eta(&trend(90.0, 0.0), 100.0, Above, at(0)), None);
        assert_eq!(eta(&trend(90.0, -2.0), 100.0, Above, at(0)), None);
        assert_eq!(
            eta(&trend(100.0, -2.0), 100.0, Above, at(0)),
            Some(TimeDelta::zero())
        );
        assert_eq!(eta(&trend(20.0, -5.0), 10.0, Below, at(0)), hours(2));
        assert_eq!(eta(&trend(20.0, 5.0), 10.0, Below, at(0)), None);
        assert_eq!(
            eta(&trend(5.0, 5.0), 10.0, Below, at(0)),
            Some(TimeDelta::zero())
        );
        assert_eq!(eta(&trend(90.0, f64::NAN), 100.0, Above, at(0)), None);
        assert_eq!(eta(&trend(0.0, 1e-300), 100.0, Above, at(0)), None);
    }
}
