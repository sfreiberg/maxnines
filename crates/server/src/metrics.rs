//! What can be asked of stored metrics. The web pages, the API and alerting all
//! read through here.
//!
//! The catalog is a fixed list, so what's queried never comes from a request or
//! an agent. Only agent IDs and times do, and those are bound as parameters.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::store::{MetricsReader, StoreStats};

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
    PerSecond,
    Bytes,
    Seconds,
    Milliseconds,
    Celsius,
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
    #[serde(skip)]
    pub chart: ShowChart,
}

/// Whether an agent's page shows a chart for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowChart {
    Always,
    /// Most agents won't report this, and a page of empty charts says nothing.
    WithData,
    /// Good to alert on, but not to look at, such as a line per interface that
    /// sits at 1 all day. It can still be queried.
    Never,
}

pub const METRICS: &[Metric] = &[
    Metric {
        name: "cpu.usage",
        title: "CPU usage",
        unit: Unit::Percent,
        collector: "cpu",
        source: Source::Fields(&[("CPU", Reading::Field("$.usage_percent"))]),
        chart: ShowChart::Always,
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
        chart: ShowChart::Always,
    },
    Metric {
        name: "cpu.time",
        title: "CPU time",
        unit: Unit::Percent,
        collector: "cpu",
        source: Source::Fields(&[
            ("User", Reading::Field("$.time_percent.user")),
            ("System", Reading::Field("$.time_percent.system")),
            ("Nice", Reading::Field("$.time_percent.nice")),
            ("Interrupt", Reading::Field("$.time_percent.interrupt")),
            ("I/O wait", Reading::Field("$.time_percent.iowait")),
            ("Steal", Reading::Field("$.time_percent.steal")),
            ("Idle", Reading::Field("$.time_percent.idle")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "cpu.context_switches",
        title: "Context switches",
        unit: Unit::PerSecond,
        collector: "cpu",
        source: Source::Fields(&[("Switches", Reading::Rate("$.context_switches"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "cpu.interrupts",
        title: "Interrupts",
        unit: Unit::PerSecond,
        collector: "cpu",
        source: Source::Fields(&[("Interrupts", Reading::Rate("$.interrupts"))]),
        chart: ShowChart::WithData,
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
        chart: ShowChart::Always,
    },
    Metric {
        name: "memory.detail",
        title: "Memory breakdown",
        unit: Unit::Bytes,
        collector: "memory",
        source: Source::Fields(&[
            ("Active", Reading::Field("$.detail.active_bytes")),
            ("Inactive", Reading::Field("$.detail.inactive_bytes")),
            ("Wired", Reading::Field("$.detail.wired_bytes")),
            ("Cached", Reading::Field("$.detail.cached_bytes")),
            ("Buffers", Reading::Field("$.detail.buffers_bytes")),
            ("Slab", Reading::Field("$.detail.slab_bytes")),
            ("Shared", Reading::Field("$.detail.shared_bytes")),
            ("Compressed", Reading::Field("$.detail.compressed_bytes")),
            ("Speculative", Reading::Field("$.detail.speculative_bytes")),
            ("Purgeable", Reading::Field("$.detail.purgeable_bytes")),
            ("ZFS cache", Reading::Field("$.detail.zfs_arc_bytes")),
            ("Page file", Reading::Field("$.detail.page_file_bytes")),
            ("Free", Reading::Field("$.detail.free_bytes")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "memory.swap_activity",
        title: "Swap activity",
        unit: Unit::PerSecond,
        collector: "memory",
        source: Source::Fields(&[
            ("Pages in", Reading::Rate("$.swap_in_pages")),
            ("Pages out", Reading::Rate("$.swap_out_pages")),
        ]),
        chart: ShowChart::WithData,
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
        chart: ShowChart::Always,
    },
    Metric {
        name: "network.received",
        title: "Network received",
        unit: Unit::BytesPerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.received_bytes")),
        chart: ShowChart::Always,
    },
    Metric {
        name: "network.transmitted",
        title: "Network sent",
        unit: Unit::BytesPerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmitted_bytes")),
        chart: ShowChart::Always,
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
        chart: ShowChart::WithData,
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
        chart: ShowChart::WithData,
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
        chart: ShowChart::WithData,
    },
    Metric {
        name: "disk.read",
        title: "Disk reads",
        unit: Unit::BytesPerSecond,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Rate("$.read_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "disk.written",
        title: "Disk writes",
        unit: Unit::BytesPerSecond,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Rate("$.written_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "disk.inodes",
        title: "Inode usage",
        unit: Unit::Percent,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Percent {
                part: "$.inodes_used",
                whole: "$.inodes_total",
            },
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "network.packets.received",
        title: "Packets received",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.packets_received")),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "network.packets.transmitted",
        title: "Packets sent",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.packets_transmitted")),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "network.errors.received",
        title: "Receive errors",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.receive_errors")),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "network.errors.transmitted",
        title: "Send errors",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmit_errors")),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "network.link",
        title: "Network link up",
        unit: Unit::Number,
        collector: "network",
        source: Source::Entries(Reading::Field("$.link_up")),
        chart: ShowChart::Never,
    },
    Metric {
        name: "sensor.temperature",
        title: "Temperature",
        unit: Unit::Celsius,
        collector: "sensors",
        source: Source::Items {
            name: "$.label",
            reading: Reading::Field("$.celsius"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.up",
        title: "Checks passing",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.response",
        title: "Check response time",
        unit: Unit::Milliseconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.response_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.cert_days",
        title: "Certificate days left",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.cert_days_left"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.first_byte",
        title: "Time to first byte",
        unit: Unit::Milliseconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.first_byte_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.dns",
        title: "DNS lookup time",
        unit: Unit::Milliseconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.dns_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.connect",
        title: "Connection time",
        unit: Unit::Milliseconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connect_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.tls",
        title: "TLS handshake time",
        unit: Unit::Milliseconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.tls_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.download",
        title: "Download time",
        unit: Unit::Milliseconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.download_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.size",
        title: "Page size",
        unit: Unit::Bytes,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.content_length"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "check.status",
        title: "HTTP status",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.status"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "check.records",
        title: "DNS records returned",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.records"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "check.packet_loss",
        title: "Packet loss",
        unit: Unit::Percent,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.packet_loss_percent"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "service.running",
        title: "Services running",
        unit: Unit::Number,
        collector: "services",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.running"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "system.open_files",
        title: "Open files",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[
            ("Open", Reading::Field("$.open_files")),
            ("Limit", Reading::Field("$.max_open_files")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "system.open_files_used",
        title: "Open file limit used",
        unit: Unit::Percent,
        collector: "system",
        source: Source::Fields(&[(
            "Used",
            Reading::Percent {
                part: "$.open_files",
                whole: "$.max_open_files",
            },
        )]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "system.processes",
        title: "Processes",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[
            ("Running", Reading::Field("$.processes")),
            ("Limit", Reading::Field("$.max_processes")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "system.processes_used",
        title: "Process limit used",
        unit: Unit::Percent,
        collector: "system",
        source: Source::Fields(&[(
            "Used",
            Reading::Percent {
                part: "$.processes",
                whole: "$.max_processes",
            },
        )]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "system.sessions",
        title: "Login sessions",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Sessions", Reading::Field("$.login_sessions"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.memory",
        title: "Server memory",
        unit: Unit::Bytes,
        collector: "server",
        source: Source::Fields(&[("Memory", Reading::Field("$.memory_bytes"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.cpu",
        title: "Server CPU",
        unit: Unit::Percent,
        collector: "server",
        source: Source::Fields(&[("CPU", Reading::Field("$.cpu_percent"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.samples",
        title: "Samples saved",
        unit: Unit::PerSecond,
        collector: "server",
        source: Source::Fields(&[
            ("Saved", Reading::Rate("$.samples_written")),
            ("Failed", Reading::Rate("$.samples_failed")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.write_queue",
        title: "Write queue",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Waiting", Reading::Field("$.write_queue"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.agents",
        title: "Agents",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[
            ("Online", Reading::Field("$.agents_online")),
            ("Approved", Reading::Field("$.agents_approved")),
            ("Waiting", Reading::Field("$.agents_waiting")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.alerts",
        title: "Alerts firing",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Firing", Reading::Field("$.alerts_firing"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.database_size",
        title: "Database size",
        unit: Unit::Bytes,
        collector: "server",
        source: Source::Fields(&[
            ("Metrics", Reading::Field("$.metrics_database_bytes")),
            ("Write-ahead log", Reading::Field("$.metrics_wal_bytes")),
            ("Main", Reading::Field("$.main_database_bytes")),
        ]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.open_files",
        title: "Server open files",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Open", Reading::Field("$.open_files"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "custom.value",
        title: "Custom metrics",
        unit: Unit::Number,
        collector: "custom",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.value"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "custom.ok",
        title: "Custom metric working",
        unit: Unit::Number,
        collector: "custom",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.ok"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "file.exists",
        title: "File exists",
        unit: Unit::Number,
        collector: "files",
        source: Source::Items {
            name: "$.path",
            reading: Reading::Field("$.exists"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "file.size",
        title: "File size",
        unit: Unit::Bytes,
        collector: "files",
        source: Source::Items {
            name: "$.path",
            reading: Reading::Field("$.size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "file.age",
        title: "Time since file changed",
        unit: Unit::Seconds,
        collector: "files",
        source: Source::Items {
            name: "$.path",
            reading: Reading::Field("$.age_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "host.uptime",
        title: "Uptime",
        unit: Unit::Seconds,
        collector: "host",
        source: Source::Fields(&[("Uptime", Reading::Field("$.uptime_secs"))]),
        chart: ShowChart::Never,
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

/// When an agent last sent anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastSample {
    pub agent_id: String,
    pub time_ms: i64,
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

/// A series' newest value.
#[derive(Debug, Clone, PartialEq)]
pub struct NewestReading {
    pub agent_id: String,
    pub series: String,
    pub time_ms: i64,
    pub value: f64,
}

/// What the headline numbers come from.
const CPU_USAGE: &str = "cpu.usage";
const MEMORY_USAGE: &str = "memory.usage";
const DISK_USAGE: &str = "disk.usage";
const CPU_SERIES: &str = "CPU";
const MEMORY_SERIES: &str = "Memory";

/// Only agents that have sent something have values.
fn current_values(
    last_samples: Vec<LastSample>,
    cpu: Vec<NewestReading>,
    memory: Vec<NewestReading>,
    disks: Vec<NewestReading>,
) -> BTreeMap<String, CurrentValues> {
    let mut agents: BTreeMap<String, CurrentValues> = last_samples
        .into_iter()
        .map(|sample| {
            let values = CurrentValues {
                time_ms: sample.time_ms,
                ..CurrentValues::default()
            };
            (sample.agent_id, values)
        })
        .collect();

    for reading in cpu.into_iter().filter(|cpu| cpu.series == CPU_SERIES) {
        if let Some(values) = agents.get_mut(&reading.agent_id) {
            values.cpu_percent = Some(reading.value);
        }
    }
    for reading in memory
        .into_iter()
        .filter(|memory| memory.series == MEMORY_SERIES)
    {
        if let Some(values) = agents.get_mut(&reading.agent_id) {
            values.memory_percent = Some(reading.value);
        }
    }
    for disk in disks {
        if let Some(values) = agents.get_mut(&disk.agent_id)
            && values
                .disk_percent
                .is_none_or(|fullest| disk.value > fullest)
        {
            values.disk_percent = Some(disk.value);
            values.disk_mount_point = Some(disk.series);
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

    pub async fn stats(&self, hour_ago_ms: i64) -> Result<StoreStats> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || reader.stats(hour_ago_ms))
            .await
            .context("reading metrics")?
    }

    /// What one of an agent's collectors last sent.
    pub async fn latest_output(
        &self,
        agent_id: &str,
        collector: &str,
        now_ms: i64,
    ) -> Result<Option<Value>> {
        let reader = self.reader.clone();
        let (agent_id, collector) = (agent_id.to_string(), collector.to_string());
        tokio::task::spawn_blocking(move || {
            reader.latest_output(
                &agent_id,
                &collector,
                now_ms - CURRENT_WINDOW_MS,
                now_ms + CLOCK_SKEW_MS,
            )
        })
        .await
        .context("reading metrics")?
    }

    pub async fn current(&self, now_ms: i64) -> Result<BTreeMap<String, CurrentValues>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            let (since_ms, until_ms) = (now_ms - CURRENT_WINDOW_MS, now_ms + CLOCK_SKEW_MS);
            let newest = |name| {
                let metric = find(name).context("unknown metric")?;
                reader.newest(metric, since_ms, until_ms)
            };
            Ok(current_values(
                reader.last_samples(since_ms, until_ms)?,
                newest(CPU_USAGE)?,
                newest(MEMORY_USAGE)?,
                newest(DISK_USAGE)?,
            ))
        })
        .await
        .context("reading metrics")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: i64 = 3_600_000;

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

    fn reading(agent_id: &str, series: &str, value: f64) -> NewestReading {
        NewestReading {
            agent_id: agent_id.to_string(),
            series: series.to_string(),
            time_ms: 1,
            value,
        }
    }

    fn last(agent_id: &str, time_ms: i64) -> LastSample {
        LastSample {
            agent_id: agent_id.to_string(),
            time_ms,
        }
    }

    #[test]
    fn current_values_combine_an_agents_headline_numbers() {
        let values = current_values(
            vec![last("a", 40)],
            vec![reading("a", "CPU", 12.5)],
            vec![reading("a", "Memory", 25.0), reading("a", "Swap", 80.0)],
            vec![reading("a", "/", 10.0), reading("a", "/data", 90.0)],
        );

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
    fn an_agent_with_nothing_to_show_still_has_a_time() {
        let values = current_values(vec![last("a", 1)], Vec::new(), Vec::new(), Vec::new());

        assert_eq!(
            values["a"],
            CurrentValues {
                time_ms: 1,
                ..CurrentValues::default()
            }
        );
    }

    #[test]
    fn readings_for_agents_that_sent_nothing_lately_are_left_out() {
        let cpu = vec![reading("gone", "CPU", 5.0)];
        let values = current_values(Vec::new(), cpu, Vec::new(), Vec::new());

        assert!(values.is_empty());
    }
}
