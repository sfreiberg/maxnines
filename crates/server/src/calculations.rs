//! Questions about a whole group of machines rather than one, such as the average CPU
//! of every Linux host. Dashboards ask these, and so do alert rules.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::controllers::host_list::HostSearch;
use crate::host_filter::HostFilter;
use crate::metrics::{Metric, Metrics, Point, SeriesResult, TimeRange, Unit, find};
use crate::models::Database;
use crate::registration::{AgentState, Registry};

/// What a line stands for when a machine hasn't reported the fact it's grouped by.
const NO_VALUE: &str = "(none)";
/// The shortest moment machines are combined over. Agents report at their own times,
/// so a shorter one would only hold some of them, and a sum or count would jump around.
pub const SMALLEST_STEP_MS: i64 = 60_000;
const FACT_PREFIX: &str = "fact:";
const MAX_FACT_NAME_LEN: usize = 200;
const MAX_FILTER_LEN: usize = 500;

/// How values are combined. Each series is averaged within a moment first, so a
/// machine reporting more often doesn't count for more, and a sample stored twice
/// changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Calculation {
    Avg,
    Sum,
    Min,
    Max,
    Count,
}

impl Calculation {
    pub const ALL: [Self; 5] = [Self::Avg, Self::Sum, Self::Min, Self::Max, Self::Count];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Avg => "avg",
            Self::Sum => "sum",
            Self::Min => "min",
            Self::Max => "max",
            Self::Count => "count",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Avg => "Average",
            Self::Sum => "Sum",
            Self::Min => "Lowest",
            Self::Max => "Highest",
            Self::Count => "How many are reporting",
        }
    }
}

/// What gets a line of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grouping {
    /// One line for everything.
    Nothing,
    Host,
    /// Each of a metric's own series, such as a disk's mount point.
    Series,
    /// Each value of a fact, such as each operating system.
    Fact(String),
}

impl Grouping {
    /// As it's kept, which `fact:` says is a fact's name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "" | "nothing" => Some(Self::Nothing),
            "host" => Some(Self::Host),
            "series" => Some(Self::Series),
            _ => {
                let name = text.strip_prefix(FACT_PREFIX)?.trim();
                let usable = !name.is_empty() && name.len() <= MAX_FACT_NAME_LEN;
                usable.then(|| Self::Fact(name.to_string()))
            }
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            Self::Nothing => "nothing".to_string(),
            Self::Host => "host".to_string(),
            Self::Series => "series".to_string(),
            Self::Fact(name) => format!("{FACT_PREFIX}{name}"),
        }
    }
}

/// A machine, and which line it counts towards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub agent_id: String,
    pub group: String,
}

/// A calculation with its machines worked out, for the metrics store to answer.
#[derive(Debug, Clone)]
pub struct CalculationQuery {
    pub metric: &'static Metric,
    pub range: TimeRange,
    pub calculation: Calculation,
    pub members: Vec<Member>,
    /// A line per series, instead of a line per group of machines.
    pub by_series: bool,
    /// Keep this many lines, starting with the highest.
    pub max_lines: usize,
}

/// The question itself, as dashboards and rules keep it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub metric: &'static Metric,
    pub calculation: Calculation,
    pub grouping: Grouping,
    /// Which machines, in the same form as the filter on the host list.
    pub filter: String,
}

impl Question {
    /// From what someone chose. The error says what's wrong, to show them.
    pub fn new(
        metric: &str,
        calculation: &str,
        group_by: &str,
        filter: &str,
    ) -> Result<Self, String> {
        let metric = find(metric).ok_or("Choose a metric from the list.")?;
        let calculation = Calculation::parse(calculation).ok_or("Choose how to combine values.")?;
        let grouping = Grouping::parse(group_by).ok_or("Choose what gets its own line.")?;
        if filter.len() > MAX_FILTER_LEN {
            return Err(format!(
                "A filter can be up to {MAX_FILTER_LEN} characters."
            ));
        }
        HostFilter::parse(filter)?;
        Ok(Self {
            metric,
            calculation,
            grouping,
            filter: filter.trim().to_string(),
        })
    }

    /// What the result is measured in, as a count isn't in the metric's own unit.
    pub fn unit(&self) -> Unit {
        match self.calculation {
            Calculation::Count => Unit::Number,
            _ => self.metric.unit,
        }
    }
}

fn fact_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The approved machines a filter picks, each with its line. The server itself isn't
/// one of them, as it isn't part of the fleet.
async fn members(sources: &Sources<'_>, question: &Question) -> Result<Vec<Member>> {
    let search = HostSearch::from_database(sources.database, Some(&question.filter)).await?;
    if let Some(error) = &search.error {
        bail!("{error}");
    }
    let facts = match &question.grouping {
        Grouping::Fact(name) => Some((name, sources.database.facts_named(&[name]).await?)),
        _ => None,
    };

    let agents = sources.registry.list().await;
    let chosen = agents.into_iter().filter(|agent| {
        agent.state == AgentState::Approved
            && !agent.is_local()
            && search.includes(&agent.id, &agent.host)
    });
    Ok(chosen
        .map(|agent| {
            let group = match (&question.grouping, &facts) {
                (Grouping::Host, _) => agent.host.clone(),
                (_, Some((name, facts))) => facts
                    .get(&agent.id)
                    .and_then(|facts| facts.get(*name))
                    .map_or_else(|| NO_VALUE.to_string(), fact_text),
                _ => question.metric.title.to_string(),
            };
            Member {
                agent_id: agent.id,
                group,
            }
        })
        .collect())
}

/// Where answers come from.
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    pub database: &'a Database,
    pub registry: &'a Registry,
    pub metrics: &'a Metrics,
}

/// One number for a whole window. A low or high stands for the worst moment, and
/// anything else for how it went on the whole.
pub fn over_window(calculation: Calculation, points: &[Point]) -> Option<f64> {
    let values = || points.iter().map(|point| point.avg);
    match calculation {
        Calculation::Min => values().reduce(f64::min),
        Calculation::Max => values().reduce(f64::max),
        _ if points.is_empty() => None,
        _ => Some(values().sum::<f64>() / points.len() as f64),
    }
}

/// Answers a question over a range of time.
pub async fn answer(
    sources: &Sources<'_>,
    question: &Question,
    range: TimeRange,
    max_lines: usize,
) -> Result<SeriesResult> {
    let members = members(sources, question).await?;
    if members.is_empty() {
        return Ok(SeriesResult::default());
    }
    sources
        .metrics
        .calculate(CalculationQuery {
            metric: question.metric,
            range,
            calculation: question.calculation,
            members,
            by_series: question.grouping == Grouping::Series,
            max_lines,
        })
        .await
}

/// The distinct groups, in a fixed order, with each member's place among them.
pub fn numbered(members: &[Member]) -> (Vec<&str>, Vec<usize>) {
    let groups: BTreeSet<&str> = members.iter().map(|member| member.group.as_str()).collect();
    let names: Vec<&str> = groups.into_iter().collect();
    let places = members
        .iter()
        .map(|member| {
            names
                .binary_search(&member.group.as_str())
                .unwrap_or_default()
        })
        .collect();
    (names, places)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn points(values: &[f64]) -> Vec<Point> {
        values
            .iter()
            .map(|value| Point {
                time_ms: 0,
                avg: *value,
                min: *value,
                max: *value,
            })
            .collect()
    }

    #[test]
    fn a_window_comes_down_to_one_number() {
        let values = points(&[10.0, 20.0, 60.0]);
        assert_eq!(over_window(Calculation::Avg, &values), Some(30.0));
        assert_eq!(over_window(Calculation::Sum, &values), Some(30.0));
        assert_eq!(over_window(Calculation::Count, &values), Some(30.0));
        assert_eq!(over_window(Calculation::Min, &values), Some(10.0));
        assert_eq!(over_window(Calculation::Max, &values), Some(60.0));
        assert_eq!(over_window(Calculation::Avg, &[]), None);
    }

    #[test]
    fn calculations_survive_being_saved() {
        for calculation in Calculation::ALL {
            assert_eq!(Calculation::parse(calculation.as_str()), Some(calculation));
        }
        assert_eq!(Calculation::parse("drop table"), None);
    }

    #[test]
    fn groupings_survive_being_saved() {
        for grouping in [
            Grouping::Nothing,
            Grouping::Host,
            Grouping::Series,
            Grouping::Fact("os.name".to_string()),
        ] {
            assert_eq!(Grouping::parse(&grouping.as_text()), Some(grouping));
        }
        assert_eq!(Grouping::parse("fact:"), None);
        assert_eq!(Grouping::parse("everything"), None);
    }

    #[test]
    fn a_question_has_to_make_sense() {
        assert!(Question::new("cpu.usage", "avg", "host", "os=linux").is_ok());
        assert!(Question::new("nope", "avg", "host", "").is_err());
        assert!(Question::new("cpu.usage", "median", "host", "").is_err());
        assert!(Question::new("cpu.usage", "avg", "colour", "").is_err());
        assert!(Question::new("cpu.usage", "avg", "host", "\"unfinished").is_err());
        assert!(Question::new("cpu.usage", "avg", "host", &"x".repeat(501)).is_err());
    }

    #[test]
    fn a_count_is_a_plain_number_whatever_it_counts() {
        let count = Question::new("cpu.usage", "count", "host", "").unwrap();
        assert_eq!(count.unit(), Unit::Number);
        let average = Question::new("cpu.usage", "avg", "host", "").unwrap();
        assert_eq!(average.unit(), Unit::Percent);
    }

    #[test]
    fn groups_are_numbered_once_each() {
        let member = |group: &str| Member {
            agent_id: "a".to_string(),
            group: group.to_string(),
        };

        let members = [member("web"), member("db"), member("web")];
        let (names, places) = numbered(&members);

        assert_eq!(names, ["db", "web"]);
        assert_eq!(places, [1, 0, 1]);
    }

    #[test]
    fn fact_values_read_as_text() {
        assert_eq!(fact_text(&Value::String("linux".to_string())), "linux");
        assert_eq!(fact_text(&serde_json::json!(12)), "12");
    }
}
