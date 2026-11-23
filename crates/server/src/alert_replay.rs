//! How often a rule would have alerted over the last day, worked out from what's
//! stored, so its conditions can be tried before it's saved, on its form or through
//! the API.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow};
use cel::Value as CelValue;
use chrono::TimeDelta;
use futures_util::{StreamExt, stream};
use serde::Serialize;
use serde_json::Value;

use crate::alert_conditions::{
    Conditions, Heading, Inputs, Values, Variable, bind_value, facts_value, kind_of_unit,
};
use crate::alert_evaluator::{Change, Tracker, holds};
use crate::alerting::{AlertRuleInput, Severity, TemplateLink, clean};
use crate::calculations::{self, Calculation, Grouping, Sources, over_window};
use crate::facts::unflatten;
use crate::metric_charts::MAX_SERIES;
use crate::metrics::{Metric, TimeRange};
use crate::registration::HostState;
use crate::remote_checks::FLEET_HOSTNAME;
use crate::rule_engine::{Condition, Host};
use crate::templates::work::{keep_picked, picked_databases};
use crate::times::Timestamp;

/// How far back a rule is tried.
pub const REPLAY_LENGTH: TimeDelta = TimeDelta::hours(24);
/// Reading a day of every metric of every host is work, so a big fleet is tried on
/// some of it.
const MAX_HOSTS: usize = 100;
/// As many series as a host can have alerts for.
const MAX_SERIES_PER_HOST: usize = 64;
/// How many reads of stored metrics run at once.
const READS_AT_ONCE: usize = 8;
/// A forecast is drawn through at least this many stored steps, from at least half
/// of how far back the rule looks, as the live one is through enough readings.
const MIN_FORECAST_STEPS: usize = 3;

/// What a rule would have done on one host, or one line of a calculation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Replayed {
    pub name: String,
    /// How many times it would have started as a warning.
    pub warned: usize,
    /// How many times it would have started critical, or become it.
    pub critical: usize,
}

/// What a rule would have done over the last day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Replay {
    /// Only the hosts or lines it would have alerted on, the most first.
    pub alerted: Vec<Replayed>,
    pub warned: usize,
    pub critical: usize,
    /// How many hosts or lines had something stored to try it on.
    pub tried: usize,
    /// How long each stored step it was tried on is.
    pub step_minutes: i64,
    /// Why the answer may differ from what would happen.
    pub notes: Vec<String>,
}

/// One series' readings by when, for one metric of one host.
type Readings = BTreeMap<String, BTreeMap<Timestamp, f64>>;

/// Counts how often a rule's conditions would have alerted on a run of moments, with
/// its wait before firing, and whether there were any moments at all.
fn count<'a>(
    conditions: &Conditions,
    hold: TimeDelta,
    moments: impl Iterator<Item = (Timestamp, Inputs<'a>)>,
) -> (usize, usize, bool) {
    let mut tracker = Tracker::default();
    let mut open: Option<Severity> = None;
    let (mut warned, mut critical, mut tried) = (0, 0, false);
    for (at, inputs) in moments {
        tried = true;
        let levels = holds(conditions, &inputs);
        let began = vec![at; levels.len()];
        match tracker.observe_from(&levels, &began, at, hold, open) {
            Some(Change::Fire(severity)) => {
                match severity {
                    Severity::Warning => warned += 1,
                    Severity::Critical => critical += 1,
                }
                open = Some(severity);
            }
            Some(Change::Become(severity)) => {
                if severity == Severity::Critical {
                    critical += 1;
                }
                open = Some(severity);
            }
            Some(Change::Resolve) => open = None,
            None => {}
        }
    }
    (warned, critical, tried)
}

/// Works out how often `rule`, whose conditions are `conditions`, would have alerted
/// over the day before `now`. It's tried on each stored step's average, so a moment
/// too short to change one may not show, and it can't know what was connected, so
/// `online` and `reporting` are true.
pub async fn replay(
    sources: &Sources<'_>,
    rule: &AlertRuleInput,
    template: Option<&TemplateLink>,
    conditions: Conditions,
    now: Timestamp,
) -> Result<Replay> {
    let conditions = Arc::new(conditions);
    let mut notes = Vec::new();
    if conditions.uses_variable(Variable::Online) || conditions.uses_variable(Variable::Reporting) {
        notes.push(
            "Whether hosts were online and reporting isn't kept, so this takes it that they were."
                .to_string(),
        );
    }
    if !conditions.forecast_metrics().is_empty() {
        notes.push(format!(
            "forecast() is drawn through the stored steps, from {MIN_FORECAST_STEPS} or more of them."
        ));
    }
    // From further back, so the first moments have a window or a line behind them.
    let lead = match rule.is_calculation() || !conditions.forecast_metrics().is_empty() {
        true => rule.window(),
        false => TimeDelta::zero(),
    };
    let range = TimeRange::ending(now, REPLAY_LENGTH + lead).context("no time to try it on")?;
    let since = now - REPLAY_LENGTH;
    let (mut replayed, tried) = if rule.is_calculation() {
        replay_calculation(sources, rule, conditions, range, since).await?
    } else {
        replay_hosts(
            sources, rule, template, conditions, range, since, &mut notes,
        )
        .await?
    };
    replayed.sort_by(|a, b| {
        (b.warned + b.critical)
            .cmp(&(a.warned + a.critical))
            .then(a.name.cmp(&b.name))
    });
    Ok(Replay {
        warned: replayed.iter().map(|each| each.warned).sum(),
        critical: replayed.iter().map(|each| each.critical).sum(),
        alerted: replayed,
        tried,
        step_minutes: range.step.num_minutes(),
        notes,
    })
}

/// Only those that would have alerted, and how many were tried.
fn alerted(each: Vec<(Replayed, bool)>) -> (Vec<Replayed>, usize) {
    let tried = each.iter().filter(|(_, tried)| *tried).count();
    let alerted = each
        .into_iter()
        .map(|(replayed, _)| replayed)
        .filter(|each| each.warned + each.critical > 0)
        .collect();
    (alerted, tried)
}

/// Each line of the calculation at each stored step from `since`, over the rule's
/// window as the live rule works it out. With nothing reporting, a count with one
/// line for everything is 0, as it is live.
async fn replay_calculation(
    sources: &Sources<'_>,
    rule: &AlertRuleInput,
    conditions: Arc<Conditions>,
    range: TimeRange,
    since: Timestamp,
) -> Result<(Vec<Replayed>, usize)> {
    let question = rule
        .question(&sources.database.catalog())
        .map_err(|error| anyhow!("{error}"))?;
    let result = calculations::answer(sources, &question, range, MAX_SERIES).await?;
    let window = rule.window();
    let hold = rule.hold;
    let counts_nothing =
        question.calculation == Calculation::Count && question.grouping == Grouping::Nothing;
    let mut lines: Vec<(String, Vec<crate::metrics::Point>)> = result
        .series
        .into_iter()
        .map(|line| (line.name, line.points))
        .collect();
    if lines.is_empty() && counts_nothing {
        lines.push((question.metric.title.clone(), Vec::new()));
    }
    let moments: Vec<Timestamp> = (0..)
        .map(|step| range.from + range.step * step)
        .take_while(|at| *at <= range.to)
        .filter(|at| *at >= since)
        .collect();
    let unit = question.unit();
    let calculation = question.calculation;
    let each = tokio::task::spawn_blocking(move || {
        lines
            .iter()
            .map(|(name, points)| {
                let values = moments.iter().filter_map(|at| {
                    let within: Vec<_> = points
                        .iter()
                        .filter(|point| point.time > *at - window && point.time <= *at)
                        .copied()
                        .collect();
                    let value = over_window(calculation, &within)
                        .or_else(|| counts_nothing.then_some(0.0))?;
                    let inputs = Inputs {
                        facts: CelValue::Null,
                        hostname: FLEET_HOSTNAME,
                        series: name,
                        online: true,
                        reporting: true,
                        value: Some(bind_value(kind_of_unit(unit), value)),
                        metrics: BTreeMap::new(),
                        headings: BTreeMap::new(),
                    };
                    Some((*at, inputs))
                });
                let (warned, critical, tried) = count(&conditions, hold, values);
                let name = match counts_nothing || name.is_empty() {
                    true => FLEET_HOSTNAME.to_string(),
                    false => clean(name),
                };
                let replayed = Replayed {
                    name,
                    warned,
                    critical,
                };
                (replayed, tried)
            })
            .collect::<Vec<_>>()
    })
    .await
    .context("trying the rule")?;
    Ok(alerted(each))
}

async fn replay_hosts(
    sources: &Sources<'_>,
    rule: &AlertRuleInput,
    template: Option<&TemplateLink>,
    conditions: Arc<Conditions>,
    range: TimeRange,
    since: Timestamp,
    notes: &mut Vec<String>,
) -> Result<(Vec<Replayed>, usize)> {
    let mut hosts: Vec<_> = sources
        .registry
        .list()
        .await
        .into_iter()
        .filter(|host| host.state == HostState::Approved)
        .collect();
    let ids: Vec<&str> = hosts.iter().map(|host| host.id.as_str()).collect();
    let mut facts = sources.database.facts_of(&ids).await?;
    let applies_to = rule
        .applies_to
        .as_deref()
        .map(Condition::compile)
        .transpose()?;
    let shaped: HashMap<String, Value> = hosts
        .iter()
        .map(|host| {
            let flat = facts.remove(&host.id).unwrap_or_default();
            (host.id.clone(), unflatten(&flat))
        })
        .collect();
    hosts.retain(|host| {
        applies_to.as_ref().is_none_or(|condition| {
            let host = Host::new(&shaped[&host.id], &host.id);
            condition.check(&host).unwrap_or(false)
        })
    });
    // A template's alert is only for the hosts the template is for, and with a
    // `when` or `since`, only for the databases what discovery found picks.
    let mut picked = None;
    if let Some(link) = template {
        let templates = sources.database.running_templates();
        if let Some(assigned) = templates.get(link.id) {
            if !assigned.template().enabled {
                notes.push(
                    "Its template is off, so it isn't checked now: this is what it would do were it on."
                        .to_string(),
                );
            }
            hosts.retain(|host| assigned.is_for(&Host::new(&shaped[&host.id], &host.id)));
        }
        if link.when.is_some() || link.since.is_some() {
            let found = sources.database.all_discoveries().await?;
            let databases =
                picked_databases(link.id, link.when.as_deref(), link.since.as_deref(), &found);
            hosts.retain(|host| databases.iter().any(|(id, _)| *id == host.id));
            notes.push(
                "It's tried on the databases where what discovery last found fits its when or since."
                    .to_string(),
            );
            picked = Some((databases, link.per_database));
        }
    }
    if hosts.len() > MAX_HOSTS {
        notes.push(format!(
            "It's tried on {MAX_HOSTS} of the {} hosts it covers.",
            hosts.len()
        ));
        hosts.truncate(MAX_HOSTS);
    }

    // Every metric of every host, a few reads at a time.
    let wanted: BTreeMap<String, Arc<Metric>> = conditions
        .uses()
        .map(|used| (used.metric.name.clone(), used.metric.clone()))
        .collect();
    let reads: Vec<(String, Arc<Metric>)> = hosts
        .iter()
        .flat_map(|host| {
            wanted
                .values()
                .map(|metric| (host.id.clone(), metric.clone()))
        })
        .collect();
    // Made before they're run, so the stream holds nothing borrowed.
    let reading: Vec<_> = reads
        .into_iter()
        .map(|(host_id, metric)| {
            let metrics = sources.metrics.clone();
            async move {
                let result = metrics
                    .series(&host_id, &metric, range, MAX_SERIES_PER_HOST)
                    .await?;
                anyhow::Ok((host_id, metric.name.clone(), by_time(&result.series)))
            }
        })
        .collect();
    let read: Vec<Result<(String, String, Readings)>> = stream::iter(reading)
        .buffer_unordered(READS_AT_ONCE)
        .collect()
        .await;
    let mut by_host: HashMap<String, BTreeMap<String, Readings>> = HashMap::new();
    for each in read {
        let (host_id, name, readings) = each?;
        by_host.entry(host_id).or_default().insert(name, readings);
    }

    // Working it out is work for a thread of its own.
    let hold = rule.hold;
    let window = rule.window();
    let tried: Vec<(String, String, CelValue, BTreeMap<String, Readings>)> = hosts
        .iter()
        .map(|host| {
            let facts = facts_value(&shaped[&host.id]);
            let readings = by_host.remove(&host.id).unwrap_or_default();
            (host.id.clone(), clean(&host.hostname), facts, readings)
        })
        .collect();
    let each = tokio::task::spawn_blocking(move || {
        tried
            .iter()
            .map(|(host_id, hostname, facts, readings)| {
                let past = Past {
                    readings,
                    window,
                    since,
                };
                let picked = picked
                    .as_ref()
                    .map(|(picked, per_database)| (host_id.as_str(), picked, *per_database));
                let (warned, critical, tried) =
                    replay_host(&conditions, hold, &past, facts, hostname, picked);
                let replayed = Replayed {
                    name: hostname.clone(),
                    warned,
                    critical,
                };
                (replayed, tried)
            })
            .collect::<Vec<_>>()
    })
    .await
    .context("trying the rule")?;
    Ok(alerted(each))
}

fn by_time(series: &[crate::metrics::Series]) -> Readings {
    series
        .iter()
        .map(|series| {
            let points = series.points.iter().map(|point| (point.time, point.avg));
            (clean(&series.name), points.collect())
        })
        .collect()
}

/// What's stored of a host's metrics, and the moments to try a rule at.
struct Past<'a> {
    readings: &'a BTreeMap<String, Readings>,
    /// How far back a forecast's line is drawn.
    window: TimeDelta,
    /// The first moment tried.
    since: Timestamp,
}

impl Past<'_> {
    /// Where a series was heading at `at`: the line through its steps over the
    /// window, carried on from the step then.
    fn heading(&self, points: &BTreeMap<Timestamp, f64>, at: Timestamp) -> Option<Heading> {
        let value = *points.get(&at)?;
        let steps: Vec<(f64, f64)> = points
            .range(at - self.window..=at)
            .map(|(time, value)| ((*time - at).num_milliseconds() as f64 / 1000.0, *value))
            .collect();
        let first = steps.first()?.0;
        if steps.len() < MIN_FORECAST_STEPS || -first < self.window.as_seconds_f64() / 2.0 {
            return None;
        }
        let count = steps.len() as f64;
        let mean_x = steps.iter().map(|(x, _)| x).sum::<f64>() / count;
        let mean_y = steps.iter().map(|(_, y)| y).sum::<f64>() / count;
        let spread: f64 = steps.iter().map(|(x, _)| (x - mean_x).powi(2)).sum();
        let together: f64 = steps.iter().map(|(x, y)| (x - mean_x) * (y - mean_y)).sum();
        Some(Heading {
            value,
            slope_per_sec: together / spread,
        })
    }
}

/// The host a rule is tried on, the hosts and databases discovery picks for it, and
/// whether its template runs for each database.
type PickedOn<'a> = (&'a str, &'a HashSet<(String, String)>, bool);

/// How often a rule would have alerted on one host, each of its series counted, and
/// whether there was anything to try it on.
fn replay_host(
    conditions: &Conditions,
    hold: TimeDelta,
    past: &Past,
    facts: &CelValue,
    hostname: &str,
    picked: Option<PickedOn<'_>>,
) -> (usize, usize, bool) {
    let readings = past.readings;
    let fanned = conditions.series_sources();
    let mut series: Vec<String> = Vec::new();
    for used in &fanned {
        for name in readings
            .get(&used.metric.name)
            .into_iter()
            .flat_map(BTreeMap::keys)
        {
            if !series.contains(name) {
                series.push(name.clone());
            }
        }
    }
    if fanned.is_empty() {
        series.push(String::new());
    }
    if let Some((host_id, picked, per_database)) = picked {
        keep_picked(
            &mut series,
            conditions.series_labels(),
            host_id,
            picked,
            per_database,
        );
    }
    series.truncate(MAX_SERIES_PER_HOST);
    let times: BTreeSet<Timestamp> = readings
        .values()
        .flat_map(|by_series| by_series.values())
        .flat_map(|points| points.keys().copied())
        .filter(|at| *at >= past.since)
        .collect();

    let (mut warned, mut critical, mut tried) = (0, 0, false);
    for series in &series {
        let moments = times.iter().filter_map(|at| {
            let mut metrics = BTreeMap::new();
            let mut headings = BTreeMap::new();
            for used in conditions.uses() {
                let by_series = readings.get(&used.metric.name)?;
                let one = || match used.metric.is_single() {
                    true => by_series.values().next(),
                    false => by_series.get(&conditions.series_of(&used.metric, series)),
                };
                if used.forecast {
                    let bound = match used.bracketed {
                        true => Values::Each(
                            by_series
                                .iter()
                                .filter_map(|(name, points)| {
                                    Some((name.clone(), past.heading(points, *at)?))
                                })
                                .collect(),
                        ),
                        false => Values::One(past.heading(one()?, *at)?),
                    };
                    headings.insert(used.metric.name.clone(), bound);
                } else {
                    let bound = match used.bracketed {
                        true => Values::Each(
                            by_series
                                .iter()
                                .filter_map(|(name, points)| Some((name.clone(), *points.get(at)?)))
                                .collect(),
                        ),
                        false => Values::One(*one()?.get(at)?),
                    };
                    metrics.insert(used.metric.name.clone(), bound);
                }
            }
            let inputs = Inputs {
                facts: facts.clone(),
                hostname,
                series,
                online: true,
                reporting: true,
                value: None,
                metrics,
                headings,
            };
            Some((*at, inputs))
        });
        let (more_warned, more_critical, more_tried) = count(conditions, hold, moments);
        warned += more_warned;
        critical += more_critical;
        tried |= more_tried;
    }
    (warned, critical, tried)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert_conditions::Scope;
    use crate::times::from_ms;

    fn at(minute: i64) -> Timestamp {
        from_ms(1_795_000_000_000 + minute * 60_000)
    }

    fn disk(points: &[(&str, &[f64])]) -> BTreeMap<String, Readings> {
        let by_series = points
            .iter()
            .map(|(series, values)| {
                let by_time = values
                    .iter()
                    .enumerate()
                    .map(|(step, value)| (at(step as i64 * 10), *value))
                    .collect();
                (series.to_string(), by_time)
            })
            .collect();
        BTreeMap::from([("disk.usage".to_string(), by_series)])
    }

    fn past<'a>(readings: &'a BTreeMap<String, Readings>) -> Past<'a> {
        Past {
            readings,
            window: TimeDelta::hours(1),
            since: at(0),
        }
    }

    #[test]
    fn each_time_a_problem_starts_counts_once_at_its_worst() {
        let conditions = Conditions::compile(
            Some("disk.usage > 80"),
            Some("disk.usage > 90"),
            Scope::Hosts,
            &crate::alert_conditions::Names::built_in(),
        )
        .unwrap();
        let readings = disk(&[
            ("/", &[50.0, 85.0, 85.0, 95.0, 50.0, 85.0, 50.0]),
            ("/data", &[50.0, 95.0, 95.0, 95.0, 50.0, 50.0, 50.0]),
        ]);
        let none = CelValue::Null;
        let counted = replay_host(
            &conditions,
            TimeDelta::zero(),
            &past(&readings),
            &none,
            "web-1",
            None,
        );
        // `/` warns twice and goes critical once; `/data` is critical from the start.
        assert_eq!(counted, (2, 2, true));

        // Waiting 15 minutes, only what lasted that long counts.
        let counted = replay_host(
            &conditions,
            TimeDelta::minutes(15),
            &past(&readings),
            &none,
            "web-1",
            None,
        );
        assert_eq!(counted, (1, 1, true));

        // With nothing stored, nothing is tried.
        let nothing = BTreeMap::new();
        let counted = replay_host(
            &conditions,
            TimeDelta::zero(),
            &past(&nothing),
            &none,
            "web-1",
            None,
        );
        assert_eq!(counted, (0, 0, false));
    }

    #[test]
    fn a_forecast_is_drawn_through_the_steps_before_each() {
        let conditions = Conditions::compile(
            None,
            Some("forecast(disk.usage, duration('4h')) >= 100"),
            Scope::Hosts,
            &crate::alert_conditions::Names::built_in(),
        )
        .unwrap();
        // Rising 6% an hour from 70%: at 76% it's on course to be full within 4 hours.
        let rising: Vec<f64> = (0..8).map(|step| 70.0 + step as f64).collect();
        let readings = disk(&[("/", &rising)]);
        let none = CelValue::Null;
        let counted = replay_host(
            &conditions,
            TimeDelta::zero(),
            &past(&readings),
            &none,
            "web-1",
            None,
        );
        assert_eq!(counted, (0, 1, true));
        // Steady, it never is.
        let readings = disk(&[("/", &[90.0; 8])]);
        let counted = replay_host(
            &conditions,
            TimeDelta::zero(),
            &past(&readings),
            &none,
            "web-1",
            None,
        );
        assert_eq!(counted, (0, 0, true));
    }
}
