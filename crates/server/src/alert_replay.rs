//! How often a rule would have alerted over the last day, worked out from what's
//! stored, so its conditions can be tried on the form before it's saved.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use cel::Value as CelValue;
use chrono::TimeDelta;
use serde::Serialize;
use serde_json::Value;

use crate::alert_conditions::{Conditions, Inputs, Values, Variable, bind_value};
use crate::alert_evaluator::{Change, Tracker, holds};
use crate::alerting::{AlertRuleInput, Severity, clean};
use crate::calculations::{self, Grouping, Sources};
use crate::facts::unflatten;
use crate::metric_charts::MAX_SERIES;
use crate::metrics::{Point, Source, TimeRange};
use crate::registration::HostState;
use crate::remote_checks::FLEET_HOSTNAME;
use crate::rule_engine::{Condition, Host};
use crate::times::Timestamp;

/// How far back a rule is tried.
pub const REPLAY_LENGTH: TimeDelta = TimeDelta::hours(24);
/// Reading a day of every metric of every host is work, so a big fleet is tried on
/// some of it.
const MAX_HOSTS: usize = 100;
/// As many series as a host can have alerts for.
const MAX_SERIES_PER_HOST: usize = 64;

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
    /// How many hosts or lines it was tried on.
    pub tried: usize,
    /// How long each reading stands for.
    pub step_minutes: i64,
    /// What it couldn't try, and why the answer may differ from what happens.
    pub notes: Vec<String>,
}

/// One series' readings by when, for one metric of one host.
type Readings = BTreeMap<String, BTreeMap<Timestamp, f64>>;

/// Counts how often a rule's conditions would have alerted on a run of readings,
/// with its wait before firing, given each moment's inputs.
fn count<'a>(
    conditions: &Conditions,
    hold: TimeDelta,
    moments: impl Iterator<Item = (Timestamp, Inputs<'a>)>,
) -> (usize, usize) {
    let mut tracker = Tracker::default();
    let mut open: Option<Severity> = None;
    let (mut warned, mut critical) = (0, 0);
    for (at, inputs) in moments {
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
    (warned, critical)
}

/// Works out how often `rule` would have alerted over the day before `now`. It's
/// tried on each stored step's average, so a moment too short to change one may not
/// show, and it can't know what was connected, so `online` and `reporting` are true.
pub async fn replay(
    sources: &Sources<'_>,
    rule: &AlertRuleInput,
    now: Timestamp,
) -> Result<Replay> {
    let conditions = rule.conditions()?;
    let range = TimeRange::ending(now, REPLAY_LENGTH)
        .ok_or_else(|| anyhow::anyhow!("no time to try it on"))?;
    let mut notes = Vec::new();
    if !conditions.forecast_metrics().is_empty() {
        notes.push("forecast() can't be tried on the past, so this leaves it out.".to_string());
    }
    if conditions.uses_variable(Variable::Online) || conditions.uses_variable(Variable::Reporting) {
        notes.push(
            "Whether hosts were online and reporting isn't kept, so this takes it that they were."
                .to_string(),
        );
    }
    let mut replayed = if rule.is_calculation() {
        replay_calculation(sources, rule, &conditions, range).await?
    } else if conditions.forecast_metrics().is_empty() {
        replay_hosts(sources, rule, &conditions, range, &mut notes).await?
    } else {
        Vec::new()
    };
    let tried = replayed.len();
    replayed.retain(|each| each.warned + each.critical > 0);
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

async fn replay_calculation(
    sources: &Sources<'_>,
    rule: &AlertRuleInput,
    conditions: &Conditions,
    range: TimeRange,
) -> Result<Vec<Replayed>> {
    let question = rule
        .question()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let result = calculations::answer(sources, &question, range, MAX_SERIES).await?;
    let unit = question.unit();
    Ok(result
        .series
        .iter()
        .map(|line| {
            let name = match question.grouping {
                Grouping::Nothing => FLEET_HOSTNAME.to_string(),
                _ => clean(&line.name),
            };
            let moments = line.points.iter().map(|point| {
                let inputs = Inputs {
                    facts: CelValue::Null,
                    hostname: FLEET_HOSTNAME,
                    series: &line.name,
                    online: true,
                    reporting: true,
                    value: Some(bind_value(unit, point.avg)),
                    metrics: BTreeMap::new(),
                    headings: BTreeMap::new(),
                };
                (point.time, inputs)
            });
            let (warned, critical) = count(conditions, rule.hold, moments);
            Replayed {
                name,
                warned,
                critical,
            }
        })
        .collect())
}

async fn replay_hosts(
    sources: &Sources<'_>,
    rule: &AlertRuleInput,
    conditions: &Conditions,
    range: TimeRange,
    notes: &mut Vec<String>,
) -> Result<Vec<Replayed>> {
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
    if hosts.len() > MAX_HOSTS {
        notes.push(format!(
            "It's tried on {MAX_HOSTS} of the {} hosts it covers.",
            hosts.len()
        ));
        hosts.truncate(MAX_HOSTS);
    }

    let wanted: BTreeSet<&'static str> = conditions.read_metrics();
    let mut replayed = Vec::new();
    for host in &hosts {
        let mut readings: BTreeMap<&'static str, Readings> = BTreeMap::new();
        for name in &wanted {
            let Some(metric) = crate::metrics::find(name) else {
                continue;
            };
            let result = sources
                .metrics
                .series(&host.id, metric, range, MAX_SERIES_PER_HOST)
                .await?;
            readings.insert(metric.name, by_time(&result.series));
        }
        let facts = cel::to_value(&shaped[&host.id]).unwrap_or(CelValue::Null);
        let hostname = clean(&host.hostname);
        let (warned, critical) = replay_host(conditions, rule.hold, &readings, &facts, &hostname);
        replayed.push(Replayed {
            name: hostname,
            warned,
            critical,
        });
    }
    Ok(replayed)
}

fn by_time(series: &[crate::metrics::Series]) -> Readings {
    series
        .iter()
        .map(|series| {
            let points = series
                .points
                .iter()
                .map(|point: &Point| (point.time, point.avg));
            (clean(&series.name), points.collect())
        })
        .collect()
}

/// How often a rule would have alerted on one host, each of its series counted.
fn replay_host(
    conditions: &Conditions,
    hold: TimeDelta,
    readings: &BTreeMap<&'static str, Readings>,
    facts: &CelValue,
    hostname: &str,
) -> (usize, usize) {
    let fanned = conditions.fanned_out();
    let mut series: Vec<String> = Vec::new();
    for used in &fanned {
        for name in readings
            .get(used.metric.name)
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
    series.truncate(MAX_SERIES_PER_HOST);
    let times: BTreeSet<Timestamp> = readings
        .values()
        .flat_map(|by_series| by_series.values())
        .flat_map(|points| points.keys().copied())
        .collect();

    let (mut warned, mut critical) = (0, 0);
    for series in &series {
        let moments = times.iter().filter_map(|at| {
            let mut metrics = BTreeMap::new();
            for used in conditions.uses().filter(|used| !used.forecast) {
                let by_series = readings.get(used.metric.name)?;
                let bound = if used.bracketed {
                    let each: BTreeMap<String, f64> = by_series
                        .iter()
                        .filter_map(|(name, points)| Some((name.clone(), *points.get(at)?)))
                        .collect();
                    Values::Each(each)
                } else {
                    let points = match used.metric.source {
                        Source::Fields(_) => by_series.values().next()?,
                        _ => by_series.get(series)?,
                    };
                    Values::One(*points.get(at)?)
                };
                metrics.insert(used.metric.name, bound);
            }
            let inputs = Inputs {
                facts: facts.clone(),
                hostname,
                series,
                online: true,
                reporting: true,
                value: None,
                metrics,
                headings: BTreeMap::new(),
            };
            Some((*at, inputs))
        });
        let (more_warned, more_critical) = count(conditions, hold, moments);
        warned += more_warned;
        critical += more_critical;
    }
    (warned, critical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert_conditions::Scope;
    use crate::times::from_ms;

    fn at(minute: i64) -> Timestamp {
        from_ms(1_795_000_000_000 + minute * 60_000)
    }

    fn disk(points: &[(&str, &[f64])]) -> BTreeMap<&'static str, Readings> {
        let by_series = points
            .iter()
            .map(|(series, values)| {
                let by_time = values
                    .iter()
                    .enumerate()
                    .map(|(minute, value)| (at(minute as i64 * 10), *value))
                    .collect();
                (series.to_string(), by_time)
            })
            .collect();
        BTreeMap::from([("disk.usage", by_series)])
    }

    #[test]
    fn each_time_a_problem_starts_counts_once_at_its_worst() {
        let conditions = Conditions::compile(
            Some("disk.usage > 80"),
            Some("disk.usage > 90"),
            Scope::Hosts,
        )
        .unwrap();
        let readings = disk(&[
            ("/", &[50.0, 85.0, 85.0, 95.0, 50.0, 85.0, 50.0]),
            ("/data", &[50.0, 95.0, 95.0, 95.0, 50.0, 50.0, 50.0]),
        ]);
        let none = CelValue::Null;
        let counted = replay_host(&conditions, TimeDelta::zero(), &readings, &none, "web-1");
        // `/` warns twice and goes critical once; `/data` is critical from the start.
        assert_eq!(counted, (2, 2));

        // Waiting 15 minutes, only what lasted that long counts.
        let counted = replay_host(
            &conditions,
            TimeDelta::minutes(15),
            &readings,
            &none,
            "web-1",
        );
        assert_eq!(counted, (1, 1));
    }
}
