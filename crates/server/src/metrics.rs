//! What can be asked of stored metrics. The web pages and the admin API both
//! read through here, and alerting will too.
//!
//! The catalog is a fixed list, so what's queried never comes from a request or
//! an agent. Only agent IDs and times do, and those are bound as parameters.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::store::MetricsReader;

/// The most points a series is split into. Charts can't show more than this
/// anyway, so asking for more only costs time.
const MAX_POINTS: i64 = 240;

/// Bucket sizes in seconds. The smallest matches the default sample interval.
const STEPS_SECS: [i64; 14] = [
    15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400,
];

const DAY_MS: i64 = 86_400_000;

/// The longest range one query can cover.
const MAX_RANGE_MS: i64 = 366 * DAY_MS;

/// The end of the year 9999, well inside what the database can store.
const MAX_TIME_MS: i64 = 253_402_300_799_000;

/// How old a sample can be and still count as an agent's current values.
const CURRENT_WINDOW_MS: i64 = 5 * 60 * 1000;

/// An agent's clock can run a little fast, but a sample dated far in the future
/// would otherwise stay "current" until that date.
const CLOCK_SKEW_MS: i64 = 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Percent,
    Number,
    BytesPerSecond,
}

/// How a number is read from a collector's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    Field(&'static str),
    /// `part` as a percentage of `whole`.
    Percent {
        part: &'static str,
        whole: &'static str,
    },
    /// A count since the previous sample, turned into a rate per second.
    Rate(&'static str),
}

/// How a collector's output divides into series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A fixed set of named series.
    Fields(&'static [(&'static str, Reading)]),
    /// A list with one series per item, named by the item's `name` field.
    Items {
        name: &'static str,
        reading: Reading,
    },
    /// A map with one series per key.
    Entries(Reading),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Metric {
    pub name: &'static str,
    pub title: &'static str,
    pub unit: Unit,
    pub collector: &'static str,
    #[serde(skip)]
    pub source: Source,
}

pub const METRICS: &[Metric] = &[
    Metric {
        name: "cpu.usage",
        title: "CPU usage",
        unit: Unit::Percent,
        collector: "cpu",
        source: Source::Fields(&[("CPU", Reading::Field("$.usage_percent"))]),
    },
    Metric {
        name: "cpu.load",
        title: "Load average",
        unit: Unit::Number,
        collector: "cpu",
        source: Source::Fields(&[
            ("1 minute", Reading::Field("$.load_average.one")),
            ("5 minutes", Reading::Field("$.load_average.five")),
            ("15 minutes", Reading::Field("$.load_average.fifteen")),
        ]),
    },
    Metric {
        name: "memory.usage",
        title: "Memory usage",
        unit: Unit::Percent,
        collector: "memory",
        source: Source::Fields(&[
            (
                "Memory",
                Reading::Percent {
                    part: "$.used_bytes",
                    whole: "$.total_bytes",
                },
            ),
            (
                "Swap",
                Reading::Percent {
                    part: "$.swap_used_bytes",
                    whole: "$.swap_total_bytes",
                },
            ),
        ]),
    },
    Metric {
        name: "disk.usage",
        title: "Disk usage",
        unit: Unit::Percent,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Percent {
                part: "$.used_bytes",
                whole: "$.total_bytes",
            },
        },
    },
    Metric {
        name: "network.received",
        title: "Network received",
        unit: Unit::BytesPerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.received_bytes")),
    },
    Metric {
        name: "network.transmitted",
        title: "Network sent",
        unit: Unit::BytesPerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmitted_bytes")),
    },
    Metric {
        name: "process.count",
        title: "Running processes",
        unit: Unit::Number,
        collector: "processes",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.count"),
        },
    },
    Metric {
        name: "process.cpu",
        title: "Process CPU usage",
        unit: Unit::Percent,
        collector: "processes",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.cpu_percent"),
        },
    },
    Metric {
        name: "process.memory",
        title: "Process memory usage",
        unit: Unit::Percent,
        collector: "processes",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.memory_percent"),
        },
    },
];

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

pub fn find(name: &str) -> Option<&'static Metric> {
    METRICS.iter().find(|metric| metric.name == name)
}

impl Metric {
    /// Most agents aren't set up to watch processes, and a page of empty charts
    /// about them says nothing.
    pub fn is_optional(&self) -> bool {
        self.collector == "processes"
    }

    /// Where a series sits in the catalog, for metrics with fixed series.
    pub fn position(&self, series: &str) -> Option<usize> {
        match self.source {
            Source::Fields(fields) => fields.iter().position(|(name, _)| *name == series),
            _ => None,
        }
    }
}

/// A span of time, split into buckets of `step_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub from_ms: i64,
    pub to_ms: i64,
    pub step_ms: i64,
}

impl TimeRange {
    /// Returns nothing for a range that's backwards, empty, or too long.
    pub fn new(from_ms: i64, to_ms: i64) -> Option<Self> {
        let valid = 0 <= from_ms
            && from_ms < to_ms
            && to_ms <= MAX_TIME_MS
            && to_ms - from_ms <= MAX_RANGE_MS;
        valid.then(|| Self {
            from_ms,
            to_ms,
            step_ms: step_for(to_ms - from_ms),
        })
    }
}

fn step_for(range_ms: i64) -> i64 {
    let wanted = (range_ms + MAX_POINTS - 1) / MAX_POINTS;
    STEPS_SECS
        .iter()
        .map(|secs| secs * 1000)
        .find(|step| *step >= wanted)
        .unwrap_or_else(|| (wanted + DAY_MS - 1) / DAY_MS * DAY_MS)
}

#[derive(Debug, Clone, Copy)]
pub struct SeriesQuery<'a> {
    pub agent_id: &'a str,
    pub metric: &'static Metric,
    pub range: TimeRange,
    /// Keep this many series, starting with the highest.
    pub max_series: usize,
}

/// One bucket of a series.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Point {
    pub time_ms: i64,
    pub avg: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Series {
    pub name: String,
    pub points: Vec<Point>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SeriesResult {
    pub series: Vec<Series>,
    /// Series left out by `max_series`.
    pub hidden: usize,
}

/// The newest sample from one collector on one agent.
#[derive(Debug, Clone, PartialEq)]
pub struct LatestSample {
    pub agent_id: String,
    pub collector: String,
    pub time_ms: i64,
    pub data: Value,
}

/// An agent's headline numbers.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CurrentValues {
    pub time_ms: i64,
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    /// The fullest disk.
    pub disk_percent: Option<f64>,
    pub disk_mount_point: Option<String>,
}

fn percent(part: &Value, whole: &Value) -> Option<f64> {
    let (part, whole) = (part.as_f64()?, whole.as_f64()?);
    (whole > 0.0).then(|| part / whole * 100.0)
}

/// Agents send what they like, so anything unusable is left as unknown.
fn fullest_disk(data: &Value) -> Option<(f64, String)> {
    data.as_array()?
        .iter()
        .filter_map(|disk| {
            let used = percent(&disk["used_bytes"], &disk["total_bytes"])?;
            Some((used, disk["mount_point"].as_str()?.to_string()))
        })
        .max_by(|a, b| a.0.total_cmp(&b.0))
}

/// A series' newest value.
#[derive(Debug, Clone, PartialEq)]
pub struct NewestReading {
    pub agent_id: String,
    pub series: String,
    pub time_ms: i64,
    pub value: f64,
}

fn current_values(samples: Vec<LatestSample>) -> BTreeMap<String, CurrentValues> {
    let mut agents: BTreeMap<String, CurrentValues> = BTreeMap::new();
    for sample in samples {
        let values = agents.entry(sample.agent_id).or_default();
        values.time_ms = values.time_ms.max(sample.time_ms);

        match sample.collector.as_str() {
            "cpu" => values.cpu_percent = sample.data["usage_percent"].as_f64(),
            "memory" => {
                values.memory_percent =
                    percent(&sample.data["used_bytes"], &sample.data["total_bytes"]);
            }
            "disk" => {
                if let Some((used, mount_point)) = fullest_disk(&sample.data) {
                    values.disk_percent = Some(used);
                    values.disk_mount_point = Some(mount_point);
                }
            }
            _ => {}
        }
    }
    agents
}

/// Reads stored metrics. Queries run off the async threads, and a panic in one
/// only fails that request.
#[derive(Clone)]
pub struct Metrics {
    reader: Arc<dyn MetricsReader>,
}

impl Metrics {
    pub fn new(reader: Arc<dyn MetricsReader>) -> Self {
        Self { reader }
    }

    pub async fn series(
        &self,
        agent_id: &str,
        metric: &'static Metric,
        range: TimeRange,
        max_series: usize,
    ) -> Result<SeriesResult> {
        let reader = self.reader.clone();
        let agent_id = agent_id.to_string();

        let mut result = tokio::task::spawn_blocking(move || {
            reader.series(&SeriesQuery {
                agent_id: &agent_id,
                metric,
                range,
                max_series,
            })
        })
        .await
        .context("reading metrics")??;

        result
            .series
            .sort_by_key(|series| metric.position(&series.name));
        Ok(result)
    }

    /// The newest value of each series, across every agent.
    pub async fn newest(&self, metric: &'static Metric, now_ms: i64) -> Result<Vec<NewestReading>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            reader.newest(metric, now_ms - CURRENT_WINDOW_MS, now_ms + CLOCK_SKEW_MS)
        })
        .await
        .context("reading metrics")?
    }

    pub async fn current(&self, now_ms: i64) -> Result<BTreeMap<String, CurrentValues>> {
        let reader = self.reader.clone();
        let samples = tokio::task::spawn_blocking(move || {
            reader.latest(now_ms - CURRENT_WINDOW_MS, now_ms + CLOCK_SKEW_MS)
        })
        .await
        .context("reading metrics")??;

        Ok(current_values(samples))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const HOUR_MS: i64 = 3_600_000;

    fn sample(agent_id: &str, collector: &str, time_ms: i64, data: Value) -> LatestSample {
        LatestSample {
            agent_id: agent_id.to_string(),
            collector: collector.to_string(),
            time_ms,
            data,
        }
    }

    #[test]
    fn every_metric_has_a_unique_name_and_can_be_found() {
        for metric in METRICS {
            assert_eq!(find(metric.name), Some(metric));
        }
        assert_eq!(find("cpu.nonsense"), None);
    }

    #[test]
    fn the_step_keeps_a_range_within_the_point_limit() {
        for (range_ms, step_ms) in [
            (HOUR_MS, 15_000),
            (6 * HOUR_MS, 120_000),
            (24 * HOUR_MS, 600_000),
            (7 * DAY_MS, 3_600_000),
            (30 * DAY_MS, 10_800_000),
            (MAX_RANGE_MS, 2 * DAY_MS),
        ] {
            assert_eq!(step_for(range_ms), step_ms, "{range_ms}");
            assert!(range_ms / step_ms <= MAX_POINTS, "{range_ms}");
        }
    }

    #[test]
    fn a_tiny_range_still_gets_the_smallest_step() {
        assert_eq!(step_for(1), 15_000);
    }

    #[test]
    fn ranges_that_make_no_sense_are_refused() {
        assert!(TimeRange::new(0, HOUR_MS).is_some());
        assert!(TimeRange::new(HOUR_MS, HOUR_MS).is_none(), "empty");
        assert!(TimeRange::new(HOUR_MS, 0).is_none(), "backwards");
        assert!(TimeRange::new(-1, HOUR_MS).is_none(), "before 1970");
        assert!(TimeRange::new(0, MAX_RANGE_MS + 1).is_none(), "too long");
        assert!(TimeRange::new(MAX_TIME_MS - 1, MAX_TIME_MS + 1).is_none());
        assert!(TimeRange::new(i64::MIN, i64::MAX).is_none());
    }

    #[test]
    fn fixed_series_have_a_catalog_position_and_others_do_not() {
        let load = find("cpu.load").unwrap();
        assert_eq!(load.position("15 minutes"), Some(2));
        assert_eq!(find("disk.usage").unwrap().position("/"), None);
    }

    #[test]
    fn current_values_combine_an_agents_collectors() {
        let values = current_values(vec![
            sample("a", "cpu", 10, json!({ "usage_percent": 12.5 })),
            sample(
                "a",
                "memory",
                30,
                json!({ "used_bytes": 1, "total_bytes": 4 }),
            ),
            sample(
                "a",
                "disk",
                20,
                json!([
                    { "mount_point": "/", "used_bytes": 1, "total_bytes": 10 },
                    { "mount_point": "/data", "used_bytes": 9, "total_bytes": 10 },
                ]),
            ),
            sample("a", "network", 40, json!({})),
            sample("a", "host", 5, json!({})),
        ]);

        assert_eq!(
            values["a"],
            CurrentValues {
                time_ms: 40,
                cpu_percent: Some(12.5),
                memory_percent: Some(25.0),
                disk_percent: Some(90.0),
                disk_mount_point: Some("/data".to_string()),
            }
        );
    }

    #[test]
    fn output_of_the_wrong_shape_is_left_as_unknown() {
        let values = current_values(vec![
            sample("a", "cpu", 1, json!({ "usage_percent": "lots" })),
            sample(
                "a",
                "memory",
                1,
                json!({ "used_bytes": 1, "total_bytes": 0 }),
            ),
            sample(
                "a",
                "disk",
                1,
                json!([7, { "mount_point": 3, "used_bytes": 1, "total_bytes": 2 }]),
            ),
            sample("b", "disk", 1, json!({ "mount_point": "/" })),
        ]);

        assert_eq!(
            values["a"],
            CurrentValues {
                time_ms: 1,
                ..CurrentValues::default()
            }
        );
        assert_eq!(values["b"].disk_percent, None);
    }
}
