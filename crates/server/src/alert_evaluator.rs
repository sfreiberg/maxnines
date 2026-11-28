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
use cel::Value as CelValue;
use chrono::TimeDelta;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};

use crate::actions::Actions;
use crate::agent_configs::AgentConfigs;
use crate::alert_conditions::{
    Conditions, Heading, Inputs, MetricUse, Values, Variable, bind_value, facts_value, kind_of_unit,
};
use crate::alerting::{
    Alert, AlertRule, AlertRuleInput, NewAlert, RULE_GONE_REASON, Severity, SeverityChange,
    SummaryValues, TemplateValues, clean, short_name, subject,
};
use crate::app_state::AppState;
use crate::calculations::{
    self, Calculation, Grouping, Question, SMALLEST_STEP, Sources, over_window,
};
use crate::catalog::Catalog;
use crate::facts::{FlatFacts, unflatten};
use crate::metric_charts::format_value;
use crate::metrics::{
    self, INSTANCE_LABEL, Metric, Metrics, NewestReading, TimeRange, Trend, series_values,
};
use crate::models::{Database, HeldLevel};
use crate::presence::Presence;
use crate::registration::{HostRecord, HostState, Registry};
use crate::remote_checks::{FLEET_HOST_ID, FLEET_HOSTNAME};
use crate::rule_engine::{Condition, Host};
use crate::server_stats::ServerStatus;
use crate::templates::hosts::RunningTemplates;
use crate::templates::work::{self as template_work, Discoveries};
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

/// A connected host isn't `reporting` once it has sent nothing for this many of its
/// intervals, so one set to send a sample every ten minutes isn't silent between
/// them. A first sample can take up to an interval longer than the rest, and a
/// write can be held back to batch it, so this many means samples really have
/// stopped, not that one is late.
const MISSED_SAMPLES: i32 = 3;
/// Nor for less than this, however often it sends, so how often isn't worked out
/// for every host on every pass.
const MIN_SILENCE: TimeDelta = TimeDelta::minutes(1);

/// What a forecast reads: a metric over how far back it looks.
type TrendKey = (String, TimeDelta);

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
pub(crate) enum Change {
    Fire(Severity),
    /// An open alert getting worse, or better without being over.
    Become(Severity),
    Resolve,
}

/// Trackers kept through a pass though nothing checked them, as what would have
/// couldn't be worked out: all of a rule's, or a rule's on some hosts.
#[derive(Default)]
struct Kept {
    rules: HashSet<i64>,
    hosts: HashMap<i64, HashSet<String>>,
}

impl Kept {
    fn covers(&self, key: &Key) -> bool {
        self.rules.contains(&key.rule_id)
            || self
                .hosts
                .get(&key.rule_id)
                .is_some_and(|hosts| hosts.contains(&key.host_id))
    }
}

/// How long one level of a problem has lasted.
#[derive(Debug, Default)]
struct Hold {
    breached_since: Option<Timestamp>,
}

impl Hold {
    /// `began` is when the problem began, if it's new: now, unless something says it
    /// was earlier, such as when a host went offline.
    fn observe(&mut self, breached: bool, began: Timestamp) {
        if breached {
            self.breached_since.get_or_insert(began);
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

/// What a rule was last worked out on for a host or series: the newest reading's
/// time, and whether the host was online and reporting.
type Stamp = (Timestamp, bool, bool);

/// How long each of a rule's levels has been crossed, or not.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    /// One for each level, mildest first.
    holds: Vec<Hold>,
    /// Which level each of `holds` is.
    severities: Vec<Severity>,
    /// Since when each level was crossed before the server restarted, until the
    /// first check after it says whether it still is.
    restored: BTreeMap<Severity, Timestamp>,
    /// Each sample is only counted once, as checks run more often than some
    /// agents report.
    last_stamp: Option<Stamp>,
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

    /// Since when each level has been crossed, for keeping through a restart.
    fn held(&self) -> impl Iterator<Item = (Severity, Timestamp)> + '_ {
        let crossed = self
            .severities
            .iter()
            .zip(&self.holds)
            .filter_map(|(severity, hold)| Some((*severity, hold.breached_since?)));
        crossed.chain(
            self.restored
                .iter()
                .map(|(severity, since)| (*severity, *since)),
        )
    }

    /// Takes whether each of a rule's levels is crossed now, mildest first, and
    /// what the alert is at, if it's open. A level has to last `hold` to count,
    /// so a passing moment doesn't alert, and stops counting the moment it's gone:
    /// a recovery is said at once, and something going back and forth is seen
    /// doing it, not hidden behind a wait. The alert is at the worst level that
    /// counts, and resolves when the mildest is gone.
    #[cfg(test)]
    fn observe(
        &mut self,
        levels: &[(Severity, bool)],
        now: Timestamp,
        hold: TimeDelta,
        open: Option<Severity>,
    ) -> Option<Change> {
        let began = vec![now; levels.len()];
        self.observe_from(levels, &began, now, hold, open)
    }

    /// As [`Self::observe`], with when each level's problem began if it's new.
    pub(crate) fn observe_from(
        &mut self,
        levels: &[(Severity, bool)],
        began: &[Timestamp],
        now: Timestamp,
        hold: TimeDelta,
        open: Option<Severity>,
    ) -> Option<Change> {
        // Each level keeps its own hold, by severity, so a rule changed to have
        // fewer levels or others never hands one level's wait to another.
        let severities: Vec<Severity> = levels.iter().map(|(severity, _)| *severity).collect();
        if severities != self.severities {
            let mut before: Vec<(Severity, Hold)> = self
                .severities
                .iter()
                .copied()
                .zip(std::mem::take(&mut self.holds))
                .collect();
            self.holds = severities
                .iter()
                .map(|severity| {
                    before
                        .iter()
                        .position(|(had, _)| had == severity)
                        .map(|at| before.swap_remove(at).1)
                        .unwrap_or_default()
                })
                .collect();
            self.severities = severities;
        }
        // Carried on from before a restart, and kept only if it still holds now.
        if !self.restored.is_empty() {
            for (hold, (severity, _)) in self.holds.iter_mut().zip(levels) {
                if let Some(since) = self.restored.remove(severity) {
                    hold.breached_since = Some(since);
                }
            }
            self.restored.clear();
        }
        for ((level, (_, breached)), began) in self.holds.iter_mut().zip(levels).zip(began) {
            level.observe(*breached, *began);
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

/// Whether a host is there, and since when, as `online` and `reporting` are. None
/// when it can't be told, such as for a host with no agent that hasn't been read.
#[derive(Debug, Clone, Copy)]
struct Seen {
    yes: bool,
    since: Timestamp,
}

/// What a host reports of the series an alert is about.
#[derive(Debug, Default)]
struct Reported {
    /// Any series of the metrics the rule is worked out for each of.
    any: bool,
    /// The alert's own.
    this: bool,
    /// The alert's own, with readings that are checked, such as a forecast that's
    /// trusted.
    checked: bool,
}

/// Everything one pass looks at, loaded once.
struct Snapshot {
    now: Timestamp,
    in_grace: bool,
    /// The metrics there are, as the rules' conditions were read against.
    catalog: Arc<Catalog>,
    rules: BTreeMap<i64, AlertRule>,
    /// Each enabled rule's conditions, read as it was loaded.
    conditions: HashMap<i64, Arc<Conditions>>,
    /// For each template's alert, the template's metrics its summaries show that its
    /// conditions don't use.
    shown: HashMap<i64, Vec<Arc<Metric>>>,
    hosts: BTreeMap<String, HostRecord>,
    /// For each rule with a condition for which hosts, the hosts it applies to.
    applies: HashMap<i64, HashSet<String>>,
    /// For each template that says which hosts it's for, those hosts, by the
    /// template's ID.
    template_hosts: HashMap<i64, HashSet<String>>,
    /// For each template's rule with a `when` or `since`, the hosts and databases
    /// what discovery found there picks, by the rule's ID.
    picked: HashMap<i64, HashSet<(String, String)>>,
    /// Each host's facts, ready for conditions, if any condition uses them.
    facts: HashMap<String, CelValue>,
    /// By metric and agent. A metric that couldn't be read is missing, which
    /// says nothing about whether anything is wrong.
    readings: BTreeMap<String, BTreeMap<String, Vec<NewestReading>>>,
    /// For forecasts, the same way.
    trends: HashMap<TrendKey, Trends>,
    /// Whether each host is online, and reporting if a rule asks. Reporting is none
    /// if it couldn't be read.
    online: HashMap<String, Seen>,
    reporting: Option<HashMap<String, Seen>>,
}

impl Snapshot {
    fn rule_applies(&self, rule: &AlertRule, host_id: &str) -> bool {
        let template_is_for = rule.template.as_ref().is_none_or(|template| {
            self.template_hosts
                .get(&template.id)
                .is_none_or(|hosts| hosts.contains(host_id))
        });
        let discovery_picks = self
            .picked
            .get(&rule.id)
            .is_none_or(|picked| picked.iter().any(|(host, _)| host == host_id));
        template_is_for
            && discovery_picks
            && (rule.rule.applies_to.is_none()
                || self
                    .applies
                    .get(&rule.id)
                    .is_some_and(|hosts| hosts.contains(host_id)))
    }

    /// The trusted trends of a metric on a host, as a forecast reads them.
    fn trusted_trends(&self, rule: &AlertRuleInput, metric: &str, host_id: &str) -> Vec<&Trend> {
        let Some(trends) = self.trends.get(&(metric.to_string(), rule.window())) else {
            return Vec::new();
        };
        let window = rule.window();
        trends
            .by_host
            .get(host_id)
            .map(|trends_of_host| {
                trends_of_host
                    .iter()
                    .filter(|trend| {
                        trend.samples >= MIN_FORECAST_SAMPLES
                            && trends.read_at - trend.first_time >= window / 2
                            && trends.read_at - trend.time <= FORECAST_FRESH
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What the host reports of the series a rule works out for each one, as far as
    /// an alert about `series` goes.
    fn reports_series(
        &self,
        rule: &AlertRuleInput,
        fanned: &[&MetricUse],
        alert: &Alert,
    ) -> Reported {
        let mut reported = Reported::default();
        for used in fanned {
            // Each series reported, and whether it's one that's checked.
            let series: Vec<(String, bool)> = if used.forecast {
                let key = (used.metric.name.clone(), rule.window());
                let Some(trends) = self.trends.get(&key) else {
                    continue;
                };
                let Some(trends) = trends.by_host.get(&alert.host_id) else {
                    continue;
                };
                let trusted = self.trusted_trends(rule, &used.metric.name, &alert.host_id);
                trends
                    .iter()
                    .map(|trend| {
                        let checked = trusted.iter().any(|each| each.series == trend.series);
                        (clean(&trend.series), checked)
                    })
                    .collect()
            } else {
                let Some(readings) = self
                    .readings
                    .get(&used.metric.name)
                    .and_then(|by_host| by_host.get(&alert.host_id))
                else {
                    continue;
                };
                readings
                    .iter()
                    .map(|reading| (clean(&reading.series), true))
                    .collect()
            };
            reported.any |= !series.is_empty();
            for (name, checked) in series {
                if alert_series(&name) == alert.series {
                    reported.this = true;
                    reported.checked |= checked;
                }
            }
        }
        reported
    }

    /// Why an open alert that nothing checked this time should end, if it should.
    /// Missing data is never a reason: the agent may just be offline, and that's
    /// exactly when a disk alert shouldn't quietly close itself.
    fn reason_to_close(&self, alert: &Alert) -> Option<&'static str> {
        let Some(rule) = self.rules.get(&alert.rule_id).filter(|rule| rule.runs()) else {
            return Some(RULE_GONE_REASON);
        };
        // Checking a calculation deals with its own alerts. Getting here means it
        // couldn't be read, which says nothing about whether anything is wrong.
        if rule.rule.is_calculation() {
            return None;
        }
        if !self.hosts.contains_key(&alert.host_id) {
            return Some("The host is no longer approved");
        }
        if !self.rule_applies(rule, &alert.host_id) {
            return Some("The rule no longer applies to this host");
        }
        let conditions = self.conditions.get(&rule.id)?;
        let fanned = conditions.series_sources();
        match (fanned.is_empty(), &alert.series) {
            (true, None) => None,
            (true, Some(_)) | (false, None) => Some("The rule changed"),
            (false, Some(_)) => {
                let reported = self.reports_series(&rule.rule, &fanned, alert);
                if reported.any && !reported.this {
                    Some("This series is no longer reported")
                } else if reported.checked {
                    Some("This agent reports more series than a rule can watch")
                } else {
                    // Reported but not trusted yet, as a forecast that's stale.
                    None
                }
            }
        }
    }
}

/// For each rule's condition for which hosts, by the rule's ID, the hosts it's true
/// of. Each condition is compiled once, and each host's facts made ready for
/// conditions once. One that can't be compiled or evaluated isn't true, as with
/// config rules.
fn hosts_each_applies_to(
    conditions: &[(i64, String)],
    host_ids: &[String],
    facts: &BTreeMap<String, FlatFacts>,
) -> HashMap<i64, HashSet<String>> {
    let compiled: Vec<(i64, Condition)> = conditions
        .iter()
        .filter_map(|(id, text)| Some((*id, Condition::compile(text).ok()?)))
        .collect();
    let mut applies: HashMap<i64, HashSet<String>> = HashMap::new();
    for id in host_ids {
        let shape = facts.get(id).map_or(Value::Null, unflatten);
        let host = Host::new(&shape, id);
        for (rule, condition) in &compiled {
            if condition.check(&host).unwrap_or(false) {
                applies.entry(*rule).or_default().insert(id.clone());
            }
        }
    }
    applies
}

/// For each of these template rules, by ID, the hosts and databases where what
/// discovery found fits its `when` and `since`.
fn picked_by_discovery(
    rules: &[&AlertRule],
    found: &BTreeMap<String, Discoveries>,
) -> HashMap<i64, HashSet<(String, String)>> {
    rules
        .iter()
        .filter_map(|rule| {
            let link = rule.template.as_ref()?;
            let picked = template_work::picked_databases(
                link.id,
                link.when.as_deref(),
                link.since.as_deref(),
                found,
            );
            Some((rule.id, picked))
        })
        .collect()
}

/// For each of these templates, by ID, the hosts it's for. Without facts, only
/// hosts given it by hand count.
fn hosts_each_template_is_for(
    templates: &RunningTemplates,
    narrowed: &BTreeSet<i64>,
    host_ids: &[String],
    facts: Option<&BTreeMap<String, FlatFacts>>,
) -> HashMap<i64, HashSet<String>> {
    let mut is_for: HashMap<i64, HashSet<String>> =
        narrowed.iter().map(|id| (*id, HashSet::new())).collect();
    for id in host_ids {
        let shape = facts
            .and_then(|facts| facts.get(id))
            .map_or(Value::Null, unflatten);
        let host = Host::new(&shape, id);
        for template in narrowed.iter().filter_map(|id| templates.get(*id)) {
            if template.is_for(&host) {
                is_for.entry(template.id()).or_default().insert(id.clone());
            }
        }
    }
    is_for
}

/// Each host's facts as conditions see them.
fn facts_for_conditions(
    host_ids: &[String],
    facts: &BTreeMap<String, FlatFacts>,
) -> HashMap<String, CelValue> {
    host_ids
        .iter()
        .map(|id| {
            let shape = facts.get(id).map_or(Value::Null, unflatten);
            (id.clone(), facts_value(&shape))
        })
        .collect()
}

/// What one host, or one of its series, gives a rule's conditions.
struct Gathered {
    metrics: BTreeMap<String, Values<f64>>,
    headings: BTreeMap<String, Values<Heading>>,
    /// The newest reading among them, if there's any.
    newest: Option<Timestamp>,
    /// The first metric's reading, as alerts keep it.
    value: Option<f64>,
    /// What summaries can show, in each metric's unit.
    shown: Vec<(String, Value)>,
    /// What a template's alert's summaries can show besides.
    template: Option<TemplateValues>,
}

/// Where a forecast starts from now: the line through the past, carried on to now.
fn heading_now(trend: &Trend, now: Timestamp) -> Heading {
    let since_newest = (now - trend.time).num_milliseconds() as f64 / 1000.0;
    Heading {
        value: trend.value + trend.slope_per_sec * since_newest,
        slope_per_sec: trend.slope_per_sec,
    }
}

fn shown_each(conditions: &Conditions, metric: &Metric, each: &BTreeMap<String, f64>) -> Value {
    Value::Object(
        each.iter()
            .map(|(series, value)| (series.clone(), json!(conditions.format(metric, *value))))
            .collect(),
    )
}

pub struct Evaluator {
    database: Database,
    /// What agents are set to run, for how often they send samples.
    configs: Arc<AgentConfigs>,
    registry: Arc<Registry>,
    presence: Arc<Presence>,
    metrics: Metrics,
    /// Told how each pass went, for the navigation and the Server page.
    status: Arc<ServerStatus>,
    /// Runs what a rule asks for on an alert's host.
    actions: Arc<Actions>,
    started_at: Timestamp,
    trackers: HashMap<Key, Tracker>,
    /// Each copy someone has of a template's rule, with the rule it's used in place
    /// of, as of the last pass, so what one was watching is handed to the other
    /// when a copy is made or deleted.
    copies: HashMap<i64, i64>,
    /// Kept between passes, as forecasts read less often than rules are checked.
    trends: HashMap<TrendKey, Trends>,
    /// The newest sample seen from each host while it stays connected, as a sample
    /// is only current for a few minutes and some hosts send less often than that.
    newest_samples: HashMap<String, Timestamp>,
    /// When each host that isn't `reporting` went quiet. It's quiet until something
    /// newer than that is stored, even if it reconnects meanwhile.
    silences: HashMap<String, Timestamp>,
    /// Whether `silences` has been given those of the alerts open as the server
    /// started.
    silences_restored: bool,
    /// Whether `trackers` has been given the levels kept as crossed before the
    /// server started.
    holds_restored: bool,
    /// What's kept through this pass though it wasn't checked, emptied as it ends.
    kept: Kept,
    /// The levels as last saved, so only what changed is written.
    saved_holds: HashSet<HeldLevel>,
}

impl Evaluator {
    pub fn new(state: &AppState, started_at: Timestamp) -> Self {
        Self {
            database: state.database.clone(),
            configs: state.configs.clone(),
            registry: state.registry.clone(),
            presence: state.presence.clone(),
            metrics: state.metrics.clone(),
            status: state.status.clone(),
            actions: state.actions.clone(),
            started_at,
            trackers: HashMap::new(),
            copies: HashMap::new(),
            trends: HashMap::new(),
            newest_samples: HashMap::new(),
            silences: HashMap::new(),
            silences_restored: false,
            holds_restored: false,
            kept: Kept::default(),
            saved_holds: HashSet::new(),
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

    async fn snapshot(&mut self, now: Timestamp, open: &HashMap<Key, Alert>) -> Result<Snapshot> {
        let rules: BTreeMap<i64, AlertRule> = self
            .database
            .list_alert_rules()
            .await?
            .into_iter()
            .map(|rule| (rule.id, rule))
            .collect();

        let hosts: BTreeMap<String, HostRecord> = self
            .registry
            .list()
            .await
            .into_iter()
            .filter(|host| host.state == HostState::Approved)
            .map(|host| (host.id.clone(), host))
            .collect();

        // Saving a rule checks its conditions can be read, so one that can't was
        // saved some other way, and is left alone rather than stopping every rule.
        let catalog = self.database.catalog();
        let mut conditions: HashMap<i64, Arc<Conditions>> = HashMap::new();
        for rule in rules.values().filter(|rule| rule.runs()) {
            match &rule.conditions {
                Some(read) => {
                    conditions.insert(rule.id, read.clone());
                }
                None => error!(
                    rule = rule.rule.name,
                    error = format!(
                        "{:#}",
                        rule.rule
                            .conditions(&rule.names(&catalog))
                            .err()
                            .unwrap_or_else(|| anyhow::anyhow!("unknown"))
                    ),
                    "a saved rule's conditions can't be read"
                ),
            }
        }
        let active = || {
            rules
                .values()
                .filter(|rule| conditions.contains_key(&rule.id))
        };
        let uses =
            |variable: Variable| active().any(|rule| conditions[&rule.id].uses_variable(variable));

        let applies_to: Vec<(i64, String)> = active()
            .filter_map(|rule| Some((rule.id, rule.rule.applies_to.clone()?)))
            .collect();
        let wants_facts = uses(Variable::Facts);
        // A template's alerts are only for the hosts the template is for.
        let templates = self.database.running_templates();
        let narrowed: BTreeSet<i64> = active()
            .filter_map(|rule| Some(rule.template.as_ref()?.id))
            .filter(|id| templates.get(*id).is_some_and(|t| t.is_narrowed()))
            .collect();
        let templates_use_facts = narrowed
            .iter()
            .any(|id| templates.get(*id).is_some_and(|t| t.uses_facts()));
        let picking: Vec<&AlertRule> = active().filter(|rule| rule.picks_by_discovery()).collect();
        let picked = match picking.is_empty() {
            true => HashMap::new(),
            false => picked_by_discovery(&picking, self.database.all_discoveries().await?.as_ref()),
        };
        let ids: Vec<String> = hosts.keys().cloned().collect();
        let (applies, facts, template_hosts) =
            if applies_to.is_empty() && !wants_facts && !templates_use_facts {
                let template_hosts = hosts_each_template_is_for(&templates, &narrowed, &ids, None);
                (HashMap::new(), HashMap::new(), template_hosts)
            } else {
                let facts = self.database.all_current_facts().await?;
                // Every condition against every host is work for a thread of its own.
                tokio::task::spawn_blocking(move || {
                    let applies = hosts_each_applies_to(&applies_to, &ids, &facts);
                    let shaped = match wants_facts {
                        true => facts_for_conditions(&ids, &facts),
                        false => HashMap::new(),
                    };
                    let template_hosts =
                        hosts_each_template_is_for(&templates, &narrowed, &ids, Some(&facts));
                    (applies, shaped, template_hosts)
                })
                .await
                .context("checking alert rules' conditions")?
            };

        let host_rules = || active().filter(|rule| !rule.rule.is_calculation());
        let shown: HashMap<i64, Vec<Arc<Metric>>> = host_rules()
            .filter_map(|rule| {
                let used = conditions[&rule.id].read_metrics();
                let mut shown = rule.rule.summary_metrics(&catalog, rule.template_key()?);
                shown.retain(|metric| !used.contains_key(&metric.name));
                Some((rule.id, shown))
            })
            .collect();
        let mut wanted: BTreeMap<String, Arc<Metric>> = host_rules()
            .flat_map(|rule| conditions[&rule.id].read_metrics())
            .collect();
        for metric in shown.values().flatten() {
            wanted.insert(metric.name.clone(), metric.clone());
        }
        let mut readings = BTreeMap::new();
        for (name, metric) in wanted {
            match self.metrics.newest(&metric, now).await {
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

        let forecasts: BTreeMap<TrendKey, Arc<Metric>> = host_rules()
            .flat_map(|rule| {
                let window = rule.rule.window();
                conditions[&rule.id]
                    .forecast_metrics()
                    .into_iter()
                    .map(move |(name, metric)| ((name, window), metric))
            })
            .collect();
        self.trends.retain(|key, _| forecasts.contains_key(key));
        for (key, metric) in forecasts {
            self.read_trends(key, &metric, now).await?;
        }

        let online: HashMap<String, Seen> = hosts
            .values()
            .filter_map(|host| Some((host.id.clone(), self.online(host)?)))
            .collect();
        let reporting = match uses(Variable::Reporting) {
            true => {
                // The alerts of rules about reporting that are open, by when each began.
                let quiet_before: Vec<(String, Timestamp)> = open
                    .values()
                    .filter(|alert| {
                        conditions
                            .get(&alert.rule_id)
                            .is_some_and(|read| read.uses_variable(Variable::Reporting))
                    })
                    .map(|alert| (alert.host_id.clone(), alert.breached_at))
                    .collect();
                self.reporting(&hosts, &online, &quiet_before, now).await
            }
            false => Some(HashMap::new()),
        };

        Ok(Snapshot {
            now,
            in_grace: now - self.started_at < STARTUP_GRACE,
            catalog,
            rules,
            conditions,
            shown,
            hosts,
            applies,
            template_hosts,
            picked,
            facts,
            readings,
            trends: self.trends.clone(),
            online,
            reporting,
        })
    }

    /// Whether a host is online, and since when. The server reads itself, so it's
    /// always there, and a host with no agent is only as present as what the server
    /// reads from it, so one with nothing read yet is neither on nor off.
    fn online(&self, host: &HostRecord) -> Option<Seen> {
        if host.is_local() {
            return Some(Seen {
                yes: true,
                since: self.started_at,
            });
        }
        let presence = self.presence.get(&host.id);
        if host.is_agentless() && presence.is_none() {
            return None;
        }
        // An agent that hasn't connected since the start has been gone at least
        // that long, and may have been offline before it.
        Some(Seen {
            yes: presence.is_some_and(|p| p.online),
            since: presence.map_or(self.started_at, |p| p.since),
        })
    }

    /// Whether each host's samples are arriving, and since when they stopped if they
    /// aren't, or nothing if when hosts last sent can't be read. A connected host isn't
    /// reporting once it's sent nothing for a few of its intervals, and then until
    /// something newer than its silence is stored, even if it reconnects meanwhile. A
    /// host that's away keeps what it was as it went: one that had gone quiet stays
    /// quiet, and any other is reporting, as its going is `online`'s to say. The server
    /// reads itself and hosts with no agent, so theirs never stop.
    async fn reporting(
        &mut self,
        hosts: &BTreeMap<String, HostRecord>,
        online: &HashMap<String, Seen>,
        quiet_before: &[(String, Timestamp)],
        now: Timestamp,
    ) -> Option<HashMap<String, Seen>> {
        let last_samples = self.read_last_samples(now).await?;
        // Silences are only held in memory, so after a start, those of alerts still
        // open carry on from when each began, for hosts whose samples say they're
        // quiet: a rule using `reporting` can be about something else, as
        // `reporting && cpu.usage > 90` is, about a host that's sending. One that
        // sent anything after its alert began has its silence ended below anyway,
        // however long the server was down.
        if !self.silences_restored {
            for (host_id, began) in quiet_before {
                if self.quiet_lately(host_id, &last_samples, now).await {
                    self.silences.entry(host_id.clone()).or_insert(*began);
                }
            }
            self.silences_restored = true;
        }
        self.newest_samples
            .retain(|id, _| online.get(id).is_some_and(|seen| seen.yes));
        self.silences.retain(|id, _| hosts.contains_key(id));
        let mut reporting = HashMap::new();
        for host in hosts.values() {
            if host.is_local() || host.is_agentless() {
                let always = Seen {
                    yes: true,
                    since: self.started_at,
                };
                reporting.insert(host.id.clone(), always);
                continue;
            }
            let Some(connected) = online.get(&host.id).filter(|seen| seen.yes) else {
                let as_it_went = match self.silences.get(&host.id) {
                    Some(&began) => Seen {
                        yes: false,
                        since: began,
                    },
                    None => Seen {
                        yes: true,
                        since: self.started_at,
                    },
                };
                reporting.insert(host.id.clone(), as_it_went);
                continue;
            };
            let newest = self.newest_samples.get(&host.id).copied();
            let newest = newest.max(last_samples.get(&host.id).copied());
            if let Some(newest) = newest {
                self.newest_samples.insert(host.id.clone(), newest);
            }
            if let Some(&began) = self.silences.get(&host.id) {
                if newest.is_some_and(|taken| taken > began) {
                    self.silences.remove(&host.id);
                } else {
                    let quiet = Seen {
                        yes: false,
                        since: began,
                    };
                    reporting.insert(host.id.clone(), quiet);
                    continue;
                }
            }
            // The silence began with the newest sample, or with connecting if none
            // has come since, as an agent that was away can't have sent anything.
            let since = newest.map_or(connected.since, |taken| taken.max(connected.since));
            let silent = self.silent_for(&host.id, now - since).await;
            if silent {
                self.silences.insert(host.id.clone(), since);
            }
            let seen = Seen {
                yes: !silent,
                since,
            };
            reporting.insert(host.id.clone(), seen);
        }
        Some(reporting)
    }

    /// When each host's newest current sample was taken, in one query for them all.
    /// If it can't be read, `reporting` waits until it can.
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
    /// Whether a host has sent nothing for as long as a silence has to be, as
    /// [`Self::reporting`] tells a quiet host.
    async fn quiet_lately(
        &self,
        host_id: &str,
        last_samples: &BTreeMap<String, Timestamp>,
        now: Timestamp,
    ) -> bool {
        match last_samples.get(host_id) {
            Some(&taken) => self.silent_for(host_id, now - taken).await,
            None => true,
        }
    }

    /// Whether this long without a sample makes a host quiet: at least
    /// [`MIN_SILENCE`], and a few of its intervals.
    async fn silent_for(&self, host_id: &str, quiet_for: TimeDelta) -> bool {
        quiet_for >= MIN_SILENCE
            && match self.interval(host_id).await {
                Some(every) => quiet_for >= every * MISSED_SAMPLES,
                None => true,
            }
    }

    /// How often a host sends, as its config says.
    async fn interval(&self, host_id: &str) -> Option<TimeDelta> {
        match self.configs.config_for(host_id).await {
            Ok(resolved) => TimeDelta::from_std(resolved.config.interval).ok(),
            Err(error) => {
                let error = format!("{error:#}");
                error!(
                    host_id,
                    error, "working out how often a host sends samples failed"
                );
                None
            }
        }
    }

    /// Reads which way a metric has been heading, if it's been long enough since
    /// the last time. If it can't be read, the forecast is missing until it can be.
    async fn read_trends(
        &mut self,
        key: TrendKey,
        metric: &Arc<Metric>,
        now: Timestamp,
    ) -> Result<()> {
        let fresh = self.trends.get(&key).is_some_and(|trends| {
            (TimeDelta::zero()..FORECAST_EVERY).contains(&(now - trends.read_at))
        });
        if fresh {
            return Ok(());
        }
        let window = key.1;
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
                    metric = metric.name,
                    error = format!("{error:#}"),
                    "reading metrics for forecasts failed"
                );
            }
        }
        Ok(())
    }

    /// Checks every rule once. Stopping partway is safe, as anything not done
    /// this time still needs doing next time.
    /// When someone makes a copy of a template's rule, or deletes one, the rule
    /// that's used changes while the problems it was watching carry on: their open
    /// alerts are moved in the database, and here how long each has lasted is moved
    /// with them, and an alert read just before the move is taken as the new rule's.
    fn hand_over(&mut self, rules: &BTreeMap<i64, AlertRule>, open: &mut HashMap<Key, Alert>) {
        let copies: HashMap<i64, i64> = rules
            .values()
            .filter_map(|rule| Some((rule.id, rule.template.as_ref()?.replaces_id?)))
            .collect();
        // From the rule that was used to the one that is now.
        let mut moved: HashMap<i64, i64> = copies
            .iter()
            .map(|(copy, original)| (*original, *copy))
            .collect();
        for (copy, original) in &self.copies {
            if !rules.contains_key(copy) && rules.contains_key(original) {
                moved.insert(*copy, *original);
            }
        }
        self.copies = copies;
        if moved.is_empty() {
            return;
        }
        let stale: Vec<Key> = self
            .trackers
            .keys()
            .filter(|key| moved.contains_key(&key.rule_id))
            .cloned()
            .collect();
        for key in stale {
            if let Some(tracker) = self.trackers.remove(&key) {
                let now_under = Key {
                    rule_id: moved[&key.rule_id],
                    ..key
                };
                self.trackers.entry(now_under).or_insert(tracker);
            }
        }
        let stale: Vec<Key> = open
            .keys()
            .filter(|key| moved.contains_key(&key.rule_id))
            .cloned()
            .collect();
        for key in stale {
            if let Some(mut alert) = open.remove(&key) {
                alert.rule_id = moved[&key.rule_id];
                open.entry(Key::of(&alert)).or_insert(alert);
            }
        }
    }

    pub async fn evaluate(&mut self, now: Timestamp) -> Result<()> {
        if !self.holds_restored {
            self.restore_holds().await?;
        }
        let open_alerts = self.database.open_alerts().await?;
        let mut open: HashMap<Key, Alert> = open_alerts
            .into_iter()
            .map(|alert| (Key::of(&alert), alert))
            .collect();
        let snapshot = self.snapshot(now, &open).await?;
        self.hand_over(&snapshot.rules, &mut open);

        let mut checked = HashSet::new();
        for rule in snapshot.rules.values() {
            let Some(conditions) = snapshot.conditions.get(&rule.id) else {
                continue;
            };
            if rule.rule.is_calculation() {
                let worked_out = !snapshot.in_grace
                    && self
                        .check_calculation(rule, conditions, &snapshot, &mut open, &mut checked)
                        .await?;
                // What it was waiting for waits on, whatever stopped it being worked
                // out now, as what's held from before a restart is only kept while
                // it's tracked.
                if !worked_out {
                    self.kept.rules.insert(rule.id);
                }
                continue;
            }
            for host in snapshot.hosts.values() {
                if snapshot.rule_applies(rule, &host.id) {
                    self.check_host(rule, conditions, host, &snapshot, &mut open, &mut checked)
                        .await?;
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
        let kept = std::mem::take(&mut self.kept);
        self.trackers
            .retain(|key, _| checked.contains(key) || kept.covers(key));
        self.save_holds().await?;
        let firing = self.database.open_alert_count().await?;
        self.status
            .firing
            .store(usize::try_from(firing)?, Ordering::Relaxed);
        self.status.alert_pass_finished(now);
        Ok(())
    }

    /// Carries on the waits that were going on when the server stopped, so a rule
    /// that waits days isn't started over by a restart. Each one is only kept if
    /// its level is still crossed when it's next checked, and one for a rule, host
    /// or series that's gone is dropped after the first pass, as it isn't checked.
    async fn restore_holds(&mut self) -> Result<()> {
        let held = self.database.alert_holds().await?;
        for level in &held {
            let key = Key {
                rule_id: level.rule_id,
                host_id: level.host_id.clone(),
                series: level.series.clone(),
            };
            let tracker = self.trackers.entry(key).or_default();
            tracker.restored.insert(level.severity, level.since);
        }
        self.saved_holds = held.into_iter().collect();
        self.holds_restored = true;
        Ok(())
    }

    /// Writes down which levels are crossed and since when, as far as that has
    /// changed since the last pass.
    async fn save_holds(&mut self) -> Result<()> {
        let held: HashSet<HeldLevel> = self
            .trackers
            .iter()
            .flat_map(|(key, tracker)| {
                tracker.held().map(|(severity, since)| HeldLevel {
                    rule_id: key.rule_id,
                    host_id: key.host_id.clone(),
                    series: key.series.clone(),
                    severity,
                    since,
                })
            })
            .collect();
        if held == self.saved_holds {
            return Ok(());
        }
        let place = |level: &HeldLevel| {
            (
                level.rule_id,
                level.host_id.clone(),
                level.series.clone(),
                level.severity,
            )
        };
        let still: HashSet<_> = held.iter().map(place).collect();
        let ended: Vec<HeldLevel> = self
            .saved_holds
            .iter()
            .filter(|level| !still.contains(&place(level)))
            .cloned()
            .collect();
        let changed: Vec<HeldLevel> = held.difference(&self.saved_holds).cloned().collect();
        self.database.save_alert_holds(&ended, &changed).await?;
        self.saved_holds = held;
        Ok(())
    }

    /// Works a rule out for one host, and for each of its series where the rule's
    /// metrics have one for each disk, interface or such.
    async fn check_host(
        &mut self,
        rule: &AlertRule,
        conditions: &Conditions,
        host: &HostRecord,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<()> {
        let uses_online = conditions.uses_variable(Variable::Online);
        let uses_reporting = conditions.uses_variable(Variable::Reporting);
        let online = snapshot.online.get(&host.id).copied();
        let reporting = snapshot
            .reporting
            .as_ref()
            .and_then(|reporting| reporting.get(&host.id))
            .copied();
        // What can't be told isn't guessed at: whatever is open stays open, and
        // whatever is waiting to count waits on.
        if (uses_online && online.is_none()) || (uses_reporting && reporting.is_none()) {
            for key in open
                .keys()
                .filter(|key| key.rule_id == rule.id && key.host_id == host.id)
            {
                checked.insert(key.clone());
            }
            self.kept
                .hosts
                .entry(rule.id)
                .or_default()
                .insert(host.id.clone());
            return Ok(());
        }
        let is_online = online.is_none_or(|seen| seen.yes);
        let is_reporting = reporting.is_none_or(|seen| seen.yes);

        let fanned = conditions.series_sources();
        let mut series: Vec<String> = Vec::new();
        for used in &fanned {
            let names: Vec<String> = if used.forecast {
                snapshot
                    .trusted_trends(&rule.rule, &used.metric.name, &host.id)
                    .iter()
                    .map(|trend| clean(&trend.series))
                    .collect()
            } else {
                self.readings_of(snapshot, &used.metric, &host.id)
                    .iter()
                    .map(|reading| clean(&reading.series))
                    .collect()
            };
            for name in names {
                if !series.contains(&name) {
                    series.push(name);
                }
            }
        }
        if fanned.is_empty() {
            series.push(String::new());
        }
        // Only the databases discovery picks, for a rule that's for some of them.
        if let Some(picked) = snapshot.picked.get(&rule.id) {
            let per_database = rule.template.as_ref().is_some_and(|link| link.per_database);
            template_work::keep_picked(
                &mut series,
                conditions.series_labels(),
                &host.id,
                picked,
                per_database,
            );
        }
        series.truncate(MAX_SERIES_PER_HOST);

        let hostname = clean(&host.hostname);
        let facts = snapshot
            .facts
            .get(&host.id)
            .cloned()
            .unwrap_or(CelValue::Null);
        let described = conditions
            .primary()
            .filter(|primary| !primary.bracketed && !primary.forecast)
            .and_then(|primary| metrics::described(&primary.metric));
        // What the collector last sent, read once and only if an alert needs its words.
        let mut output = None;

        for series in series {
            let key = Key {
                rule_id: rule.id,
                host_id: host.id.clone(),
                series: alert_series(&series),
            };
            checked.insert(key.clone());
            // Missing data says nothing about whether anything is wrong.
            let Some(mut gathered) = self.gather(rule, conditions, &host.id, &series, snapshot)
            else {
                continue;
            };
            let tracker = self.trackers.entry(key.clone()).or_default();
            if let Some(newest) = gathered.newest {
                let stamp = (newest, is_online, is_reporting);
                if tracker.last_stamp == Some(stamp) {
                    continue;
                }
                tracker.last_stamp = Some(stamp);
            }

            let inputs_with = |online: bool, reporting: bool| Inputs {
                facts: facts.clone(),
                hostname: &hostname,
                series: &series,
                online,
                reporting,
                value: None,
                metrics: gathered.metrics.clone(),
                headings: gathered.headings.clone(),
            };
            let levels = holds(conditions, &inputs_with(is_online, is_reporting));
            // A problem that's there because the host went offline or stopped
            // sending began when it did, not when it was noticed.
            let mut began = vec![snapshot.now; levels.len()];
            let gone_since = [(online, is_online), (reporting, is_reporting)]
                .into_iter()
                .filter_map(|(seen, is_it)| seen.filter(|_| !is_it))
                .map(|seen| seen.since)
                .min();
            if let Some(since) = gone_since
                && levels.iter().any(|(_, breached)| *breached)
            {
                let otherwise = holds(conditions, &inputs_with(true, true));
                for ((began, (_, now)), (_, then)) in began.iter_mut().zip(&levels).zip(&otherwise)
                {
                    if *now && !*then {
                        *began = since.min(*began);
                    }
                }
            }
            let current = open.get(&key).map(|alert| alert.severity);
            let tracker = self.trackers.entry(key.clone()).or_default();
            let change =
                tracker.observe_from(&levels, &began, snapshot.now, rule.rule.hold, current);
            // Just after a start, agents are still reconnecting and sending what they
            // kept meanwhile, so nothing about being there starts. Anything can end.
            if snapshot.in_grace
                && (uses_online || uses_reporting)
                && matches!(change, Some(Change::Fire(_)))
            {
                // Looked at again once the wait is over, though nothing new comes.
                tracker.last_stamp = None;
                continue;
            }

            let primary = conditions.primary();
            let subject =
                primary.map(|primary| subject(&primary.metric, &series, primary.picked.as_deref()));
            let values = SummaryValues {
                hostname: hostname.clone(),
                series: series.clone(),
                value: primary
                    .zip(gathered.value)
                    .map(|(primary, value)| conditions.format(&primary.metric, value)),
                metrics: gathered.shown.clone(),
                template: gathered.template.take(),
            };
            // Said in the collector's own words where it has them, such as a
            // service that's failed, as the alert starts, while it lasts, and as
            // it clears, unless the rule says what to say.
            let breached = levels.iter().any(|(_, breached)| *breached);
            let resolving = matches!(change, Some(Change::Resolve));
            let says = change.is_some() || (current.is_some() && breached);
            let state = match described.filter(|_| says && rule.rule.summary.is_none()) {
                Some(described) => {
                    let metric = primary
                        .map(|primary| &primary.metric)
                        .context("no metric")?;
                    if output.is_none() {
                        let latest =
                            self.metrics
                                .latest_output(&host.id, &metric.collector, snapshot.now);
                        output = Some(latest.await.ok().flatten().unwrap_or(Value::Null));
                    }
                    let state =
                        described.state_of(output.as_ref().unwrap_or(&Value::Null), &series);
                    state.map(|state| {
                        AlertRuleInput::state_summary(described.noun, &hostname, &series, &state)
                    })
                }
                None => None,
            };
            let summary = match (change.as_ref().and_then(Change::severity), state) {
                (None, Some(state)) if resolving => state,
                (None, None) if resolving => rule
                    .rule
                    .resolved_summary_for(&values, subject.as_deref())
                    .unwrap_or_default(),
                (Some(_), Some(state)) => state,
                (Some(_), None) => rule.rule.summary_for(&values, subject.as_deref()),
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
                gathered.value,
                summary,
                snapshot,
                open,
            )
            .await?;
        }
        Ok(())
    }

    fn readings_of<'a>(
        &self,
        snapshot: &'a Snapshot,
        metric: &Metric,
        host_id: &str,
    ) -> &'a [NewestReading] {
        snapshot
            .readings
            .get(&metric.name)
            .and_then(|by_host| by_host.get(host_id))
            .map_or(&[], Vec::as_slice)
    }

    /// What a host gives a rule's conditions for one of its series, or nothing if
    /// a metric they use has no reading for it.
    fn gather(
        &self,
        rule: &AlertRule,
        conditions: &Conditions,
        host_id: &str,
        series: &str,
        snapshot: &Snapshot,
    ) -> Option<Gathered> {
        let mut gathered = Gathered {
            metrics: BTreeMap::new(),
            headings: BTreeMap::new(),
            newest: None,
            value: None,
            shown: Vec::new(),
            template: None,
        };
        let mut seen: Vec<(&str, bool)> = Vec::new();
        for used in conditions.uses() {
            let metric = &used.metric;
            let name = &metric.name;
            if seen.contains(&(name.as_str(), used.forecast)) {
                continue;
            }
            seen.push((name, used.forecast));
            // A metric with one series has it whatever the series looked at is, and
            // one with a series for each disk or such has the one looked at, or for
            // a template's with fewer labels, the one that goes with it.
            let looked_at = conditions.series_of(metric, series);
            let wanted = |name: &str| metric.is_single() || clean(name) == looked_at;
            let first = gathered.value.is_none()
                && gathered.metrics.is_empty()
                && gathered.headings.is_empty();
            let is_shown =
                |gathered: &Gathered| gathered.shown.iter().any(|(shown, _)| shown == name);
            if used.forecast {
                let trends = snapshot.trusted_trends(&rule.rule, name, host_id);
                let newest = trends.iter().map(|trend| trend.time).max()?;
                gathered.newest = gathered.newest.max(Some(newest));
                let bound = if used.bracketed {
                    let each: BTreeMap<String, Heading> = trends
                        .iter()
                        .map(|trend| (clean(&trend.series), heading_now(trend, snapshot.now)))
                        .collect();
                    let now: BTreeMap<String, f64> = trends
                        .iter()
                        .map(|trend| (clean(&trend.series), trend.value))
                        .collect();
                    if first {
                        gathered.value = used
                            .picked
                            .as_ref()
                            .and_then(|picked| now.get(picked).copied());
                    }
                    // What summaries show of it, unless its readings are there too.
                    if !is_shown(&gathered) {
                        gathered
                            .shown
                            .push((name.clone(), shown_each(conditions, metric, &now)));
                    }
                    Values::Each(each)
                } else {
                    let trend = trends.iter().find(|trend| wanted(&trend.series))?;
                    if first {
                        gathered.value = Some(trend.value);
                    }
                    if !is_shown(&gathered) {
                        gathered
                            .shown
                            .push((name.clone(), json!(conditions.format(metric, trend.value))));
                    }
                    Values::One(heading_now(trend, snapshot.now))
                };
                gathered.headings.insert(name.clone(), bound);
                continue;
            }
            let readings = self.readings_of(snapshot, metric, host_id);
            let newest = readings.iter().map(|reading| reading.time).max()?;
            if used.bracketed {
                let each: BTreeMap<String, f64> = readings
                    .iter()
                    .map(|reading| (clean(&reading.series), reading.value))
                    .collect();
                gathered.newest = gathered.newest.max(Some(newest));
                if first {
                    gathered.value = used
                        .picked
                        .as_ref()
                        .and_then(|picked| each.get(picked).copied());
                }
                gathered.shown.retain(|(shown, _)| shown != name);
                gathered
                    .shown
                    .push((name.clone(), shown_each(conditions, metric, &each)));
                gathered.metrics.insert(name.clone(), Values::Each(each));
            } else {
                let reading = readings.iter().find(|reading| wanted(&reading.series))?;
                gathered.newest = gathered.newest.max(Some(reading.time));
                if first {
                    gathered.value = Some(reading.value);
                }
                gathered.shown.retain(|(shown, _)| shown != name);
                gathered.shown.push((
                    name.clone(),
                    json!(conditions.format(metric, reading.value)),
                ));
                gathered
                    .metrics
                    .insert(name.clone(), Values::One(reading.value));
            }
        }
        gathered.template = rule
            .template_key()
            .map(|key| self.template_values(rule, conditions, key, host_id, series, snapshot));
        Some(gathered)
    }

    /// What a template's alert's summaries can show beside what any rule's can: what
    /// the template ran for, the labels of the series looked at, and the template's
    /// metrics the summaries name that the conditions don't use, each as the series
    /// that goes with the one looked at has it. One with no reading is left out.
    fn template_values(
        &self,
        rule: &AlertRule,
        conditions: &Conditions,
        key: &str,
        host_id: &str,
        series: &str,
        snapshot: &Snapshot,
    ) -> TemplateValues {
        let mut labels: serde_json::Map<String, Value> = conditions
            .series_labels()
            .iter()
            .cloned()
            .zip(series_values(series).into_iter().map(Value::from))
            .collect();
        let instance = labels.remove(INSTANCE_LABEL);
        let mut values = serde_json::Map::new();
        for metric in snapshot.shown.get(&rule.id).into_iter().flatten() {
            let looked_at = conditions.series_of(metric, series);
            // One with labels the series looked at doesn't have has no one series
            // that goes with it.
            let narrower = metric
                .labels()
                .iter()
                .all(|label| conditions.series_labels().contains(label));
            let reading = self
                .readings_of(snapshot, metric, host_id)
                .iter()
                .find(|reading| narrower && clean(&reading.series) == looked_at);
            if let Some(reading) = reading {
                let short = short_name(metric, key).to_string();
                values.insert(short, json!(metric.format(reading.value)));
            }
        }
        TemplateValues {
            prefix: key.to_string(),
            metrics: values,
            instance: instance
                .and_then(|instance| instance.as_str().map(str::to_string))
                .unwrap_or_default(),
            labels,
        }
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
            lines.push((question.metric.title.clone(), 0.0));
        }
        Some(lines)
    }

    async fn check_calculation(
        &mut self,
        rule: &AlertRule,
        conditions: &Conditions,
        snapshot: &Snapshot,
        open: &mut HashMap<Key, Alert>,
        checked: &mut HashSet<Key>,
    ) -> Result<bool> {
        let question = match rule.rule.question(&snapshot.catalog) {
            Ok(question) => question,
            Err(error) => {
                error!(
                    rule = rule.rule.name,
                    error, "a saved rule doesn't make sense"
                );
                return Ok(false);
            }
        };
        let Some(lines) = self.calculated_lines(rule, &question, snapshot.now).await else {
            return Ok(false);
        };

        let unit = question.unit();
        let key_of = |line: &str| Key {
            rule_id: rule.id,
            host_id: FLEET_HOST_ID.to_string(),
            series: alert_series(line),
        };
        for (line, value) in &lines {
            let key = key_of(line);
            checked.insert(key.clone());

            let inputs = Inputs {
                facts: CelValue::Null,
                hostname: FLEET_HOSTNAME,
                series: line,
                online: true,
                reporting: true,
                value: Some(bind_value(kind_of_unit(unit), *value)),
                metrics: BTreeMap::new(),
                headings: BTreeMap::new(),
            };
            let levels = holds(conditions, &inputs);
            let tracker = self.trackers.entry(key.clone()).or_default();
            let current = open.get(&key).map(|alert| alert.severity);
            let began = vec![snapshot.now; levels.len()];
            let change =
                tracker.observe_from(&levels, &began, snapshot.now, rule.rule.hold, current);

            let subject = match question.grouping {
                Grouping::Nothing => format!(
                    "{} of {}",
                    question.calculation.label(),
                    question.metric.title
                ),
                _ => line.clone(),
            };
            let values = SummaryValues {
                hostname: FLEET_HOSTNAME.to_string(),
                series: line.clone(),
                value: Some(format_value(unit, *value)),
                metrics: Vec::new(),
                template: None,
            };
            let summary = match change {
                Some(Change::Resolve) => rule
                    .rule
                    .resolved_summary_for(&values, Some(&subject))
                    .unwrap_or_default(),
                Some(Change::Fire(_) | Change::Become(_)) => {
                    rule.rule.summary_for(&values, Some(&subject))
                }
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
        Ok(true)
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
                // A rule deleted since this pass read it fires nothing.
                let Some(id) = self.database.fire_alert(&new, &channels).await? else {
                    return Ok(());
                };
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

/// Whether each of a rule's conditions holds, mildest first.
pub(crate) fn holds(conditions: &Conditions, inputs: &Inputs) -> Vec<(Severity, bool)> {
    let bindings = inputs.bind(conditions);
    conditions
        .levels()
        .into_iter()
        .map(|(severity, condition)| (severity, condition.holds(&bindings)))
        .collect()
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
    fn a_level_taken_out_of_a_rule_hands_its_wait_to_no_other() {
        let mut tracker = Tracker::default();
        tracker.observe(&two(1), at(0), secs(1800), None);
        // The warning's gone from the rule, and the critical level is new.
        assert_eq!(
            tracker.observe(&one(true), at(7200), secs(1800), None),
            None
        );
        assert_eq!(
            tracker.observe(&one(true), at(9000), secs(1800), None),
            Some(Change::Fire(C))
        );
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

    #[test]
    fn a_forecast_starts_from_the_line_carried_on_to_now() {
        let trend = Trend {
            host_id: "a".to_string(),
            series: "/".to_string(),
            time: at(0),
            value: 90.0,
            first_time: at(-3600),
            samples: 100,
            slope_per_sec: 2.0 / 3600.0,
        };
        assert_eq!(
            heading_now(&trend, at(0)),
            Heading {
                value: 90.0,
                slope_per_sec: 2.0 / 3600.0
            }
        );
        // An hour after the reading, it's moved on by an hour.
        assert_eq!(heading_now(&trend, at(3600)).value, 92.0);
    }
}
