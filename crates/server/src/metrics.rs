//! What can be asked of stored metrics. The web pages, the API and alerting all
//! read through here.
//!
//! What's queried never comes from a request or an agent: it's a metric named here
//! in code, or one of a template's, whose names are checked as the template is
//! saved. [`crate::catalog::Catalog`] has both. Only agent IDs and times come from
//! requests, and those are bound as parameters.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta};
use maxnines_protocol::templates::work::ACCOUNTS;
use serde::Serialize;
use serde_json::Value;

use crate::calculations::CalculationQuery;
use crate::store::{MetricsReader, StoreStats, latest_sample};
use crate::times::Timestamp;

/// The most points a series is split into. Charts can't show more than this
/// anyway, so asking for more only costs time.
const MAX_POINTS: i32 = 240;

/// Bucket sizes. The smallest matches the default sample interval.
const STEPS: [TimeDelta; 14] = [
    TimeDelta::seconds(15),
    TimeDelta::seconds(30),
    TimeDelta::minutes(1),
    TimeDelta::minutes(2),
    TimeDelta::minutes(5),
    TimeDelta::minutes(10),
    TimeDelta::minutes(15),
    TimeDelta::minutes(30),
    TimeDelta::hours(1),
    TimeDelta::hours(2),
    TimeDelta::hours(3),
    TimeDelta::hours(6),
    TimeDelta::hours(12),
    TimeDelta::days(1),
];

/// The longest range one query can cover.
const MAX_RANGE: TimeDelta = TimeDelta::days(366);

/// How old a sample can be and still count as an agent's current values.
const CURRENT_WINDOW: TimeDelta = TimeDelta::minutes(5);

/// An agent's clock can run a little fast, but a sample dated far in the future
/// would otherwise stay "current" until that date.
const CLOCK_SKEW: TimeDelta = TimeDelta::minutes(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Percent,
    Number,
    BytesPerSecond,
    PerSecond,
    Bytes,
    Seconds,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A template's metric: one stored number, with a series for each set of labels.
    Labelled(Labelled),
}

/// How a template's metric is stored: by its key, under the template's collector,
/// each series told apart by its labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labelled {
    /// What it's stored as: the metric's key, `lag` for `postgres.lag`.
    pub field: String,
    /// The labels that tell its series apart, in the order a series' name gives
    /// their values: what the template runs for first, then the query's or
    /// counters' own.
    pub labels: Vec<String>,
    /// A running total, which is read as a rate each second.
    pub total: bool,
}

/// The label a template's series has for what the template ran for, such as the
/// name of a database.
pub const INSTANCE_LABEL: &str = "instance";

/// What comes between the labels' values in a series' name.
const SERIES_SEPARATOR: &str = ", ";

/// The name of a series with these values for its labels: `main, slot_a`. A comma
/// or backslash in a value has a backslash before it, so the values can be told
/// apart again. The stores name series the same way.
pub fn series_name<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let escaped: Vec<String> = values
        .into_iter()
        .map(|value| value.replace('\\', "\\\\").replace(',', "\\,"))
        .collect();
    escaped.join(SERIES_SEPARATOR)
}

/// The values a series' name gives for its labels, in order.
pub fn series_values(series: &str) -> Vec<String> {
    if series.is_empty() {
        return Vec::new();
    }
    let mut values = vec![String::new()];
    let mut chars = series.chars().peekable();
    while let Some(c) = chars.next() {
        let current = values.last_mut().expect("there's always one");
        match c {
            '\\' => current.extend(chars.next()),
            ',' if chars.peek() == Some(&' ') => {
                chars.next();
                values.push(String::new());
            }
            other => current.push(other),
        }
    }
    values
}

/// What a metric's values are to a condition. A template's query can have columns
/// whose type only the database knows, so theirs isn't known until a condition says
/// how it uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Number,
    /// A length of time, compared with `duration('5m')`.
    Seconds,
    /// True or false, stored as 1 or 0.
    Flag,
    Unknown,
}

/// A metric the server reads that's named here in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticMetric {
    pub name: &'static str,
    pub title: &'static str,
    pub unit: Unit,
    pub collector: &'static str,
    pub source: Source,
    pub chart: ShowChart,
}

/// A metric that can be read: one named here in code, or one of a template's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Metric {
    pub name: String,
    pub title: String,
    pub unit: Unit,
    pub collector: String,
    /// What a template says about it.
    pub description: Option<String>,
    /// The key of the template it's from, for one of a template's.
    pub template: Option<String>,
    #[serde(skip)]
    pub kind: Kind,
    #[serde(skip)]
    pub source: Source,
    #[serde(skip)]
    pub chart: ShowChart,
}

impl From<&StaticMetric> for Metric {
    fn from(metric: &StaticMetric) -> Self {
        Self {
            name: metric.name.to_string(),
            title: metric.title.to_string(),
            unit: metric.unit,
            collector: metric.collector.to_string(),
            description: None,
            template: None,
            kind: match metric.unit {
                Unit::Seconds => Kind::Seconds,
                _ => Kind::Number,
            },
            source: metric.source.clone(),
            chart: metric.chart,
        }
    }
}

/// For a metric that only says whether something is working, the word its
/// collector gives for the state it's in, which says far more than 0 does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Described {
    /// What each series is, such as `Service`.
    pub noun: &'static str,
    /// Where an item's state is, and the number that says it's working.
    pub state: &'static str,
    pub working: &'static str,
}

/// How a metric's series describe themselves, for the few that do.
pub fn described(metric: &Metric) -> Option<Described> {
    let described = |noun, working| Described {
        noun,
        state: "state",
        working,
    };
    match metric.name.as_str() {
        "service.running" => Some(described("Service", "running")),
        "container.up" => Some(described("Container", "up")),
        _ => None,
    }
}

impl Described {
    /// The state of the item called `series` in what the collector last sent,
    /// unless it's working by now.
    pub fn state_of(&self, output: &Value, series: &str) -> Option<String> {
        let item = output.as_array()?.iter().find(|item| {
            item["name"]
                .as_str()
                .is_some_and(|name| crate::alerting::clean(name) == series)
        })?;
        if item[self.working].as_u64() == Some(1) {
            return None;
        }
        let state = crate::alerting::clean(item[self.state].as_str()?);
        (!state.trim().is_empty()).then(|| state.chars().take(MAX_STATE_CHARS).collect())
    }
}

/// A service manager's word for a state is a word or two.
const MAX_STATE_CHARS: usize = 60;

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

pub const METRICS: &[StaticMetric] = &[
    StaticMetric {
        name: "cpu.usage",
        title: "CPU usage",
        unit: Unit::Percent,
        collector: "cpu",
        source: Source::Fields(&[("CPU", Reading::Field("$.usage_percent"))]),
        chart: ShowChart::Always,
    },
    // So one busy core shows on a host with many, where it barely moves the total.
    // Agents send a plain list, so each core is named by its number, from 0. A chart
    // keeps the busiest.
    StaticMetric {
        name: "cpu.cores",
        title: "CPU usage by core",
        unit: Unit::Percent,
        collector: "cpu",
        source: Source::Items {
            name: "$.index",
            reading: Reading::Field("$.per_core_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "cpu.load",
        title: "Load average",
        unit: Unit::Number,
        collector: "cpu",
        source: Source::Fields(&[
            ("1 minute", Reading::Field("$.load_average.one")),
            ("5 minutes", Reading::Field("$.load_average.five")),
            ("15 minutes", Reading::Field("$.load_average.fifteen")),
        ]),
        // Windows has no load average, so its agents send none.
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
        name: "cpu.context_switches",
        title: "Context switches",
        unit: Unit::PerSecond,
        collector: "cpu",
        source: Source::Fields(&[("Switches", Reading::Rate("$.context_switches"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "cpu.interrupts",
        title: "Interrupts",
        unit: Unit::PerSecond,
        collector: "cpu",
        source: Source::Fields(&[("Interrupts", Reading::Rate("$.interrupts"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
        name: "network.received",
        title: "Network received",
        unit: Unit::BytesPerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.received_bytes")),
        chart: ShowChart::Always,
    },
    StaticMetric {
        name: "network.transmitted",
        title: "Network sent",
        unit: Unit::BytesPerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmitted_bytes")),
        chart: ShowChart::Always,
    },
    // The programs using the most, by name, when a config rule turns this on.
    StaticMetric {
        name: "top.cpu",
        title: "Top processes by CPU",
        unit: Unit::Percent,
        collector: "top_processes",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.cpu_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "top.memory",
        title: "Top processes by memory",
        unit: Unit::Bytes,
        collector: "top_processes",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.memory_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
        name: "process.memory",
        title: "Process memory usage",
        unit: Unit::Bytes,
        collector: "processes",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.memory_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
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
    // How hard each disk is working, which bytes alone can't show. macOS has no busy
    // time or queue, and FreeBSD reports none of these yet.
    StaticMetric {
        name: "disk.busy",
        title: "Disk busy",
        unit: Unit::Percent,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.busy_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "disk.read_ops",
        title: "Disk read operations",
        unit: Unit::PerSecond,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.read_ops_per_sec"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "disk.write_ops",
        title: "Disk write operations",
        unit: Unit::PerSecond,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.write_ops_per_sec"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "disk.read_latency",
        title: "Disk read latency",
        unit: Unit::Seconds,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.read_latency_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "disk.write_latency",
        title: "Disk write latency",
        unit: Unit::Seconds,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.write_latency_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "disk.queue",
        title: "Disk queue length",
        unit: Unit::Number,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.queue_length"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
        name: "network.packets.received",
        title: "Packets received",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.packets_received")),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "network.packets.transmitted",
        title: "Packets sent",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.packets_transmitted")),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "network.errors.received",
        title: "Receive errors",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.receive_errors")),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "network.errors.transmitted",
        title: "Send errors",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmit_errors")),
        chart: ShowChart::WithData,
    },
    // Packets with nowhere to wait, which means the host isn't keeping up.
    StaticMetric {
        name: "network.drops.received",
        title: "Received packets dropped",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.receive_drops")),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "network.drops.transmitted",
        title: "Sent packets dropped",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmit_drops")),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "network.link",
        title: "Network link up",
        unit: Unit::Number,
        collector: "network",
        source: Source::Entries(Reading::Field("$.link_up")),
        chart: ShowChart::Never,
    },
    // Worked out by the server, which asks each agent what its clock says. How
    // far apart they are, whichever is ahead.
    StaticMetric {
        name: "clock.difference",
        title: "Clock difference from the server",
        unit: Unit::Seconds,
        collector: crate::clock::COLLECTOR,
        source: Source::Fields(&[("Difference", Reading::Field("$.difference_secs"))]),
        chart: ShowChart::WithData,
    },
    // Only macOS reports these so far.
    StaticMetric {
        name: "gpu.usage",
        title: "GPU usage",
        unit: Unit::Percent,
        collector: "gpu",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.usage_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "gpu.memory",
        title: "GPU memory used",
        unit: Unit::Bytes,
        collector: "gpu",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.memory_used_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    // Each drive's SMART readings, named by its model and serial number.
    StaticMetric {
        name: "smart.healthy",
        title: "Drive healthy",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.healthy"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "smart.temperature",
        title: "Drive temperature",
        unit: Unit::Celsius,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.temperature_celsius"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.power_on",
        title: "Drive power-on time",
        unit: Unit::Seconds,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.power_on_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.power_cycles",
        title: "Drive power cycles",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.power_cycles"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.reallocated",
        title: "Drive reallocated sectors",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.reallocated"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.pending",
        title: "Drive sectors waiting to be reallocated",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pending"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.uncorrectable",
        title: "Drive uncorrectable sectors",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.uncorrectable"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.crc_errors",
        title: "Drive cable errors",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.crc_errors"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.used",
        title: "Drive life used",
        unit: Unit::Percent,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.used_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.spare",
        title: "Drive spare left",
        unit: Unit::Percent,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.spare_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.spare_threshold",
        title: "Drive spare threshold",
        unit: Unit::Percent,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.spare_threshold_percent"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "smart.media_errors",
        title: "Drive media errors",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.media_errors"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.unsafe_shutdowns",
        title: "Drive unsafe shutdowns",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.unsafe_shutdowns"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "smart.critical_warning",
        title: "Drive critical warning",
        unit: Unit::Number,
        collector: "smart",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.critical_warning"),
        },
        chart: ShowChart::Never,
    },
    // Whether a host is up to date, from its own package manager.
    StaticMetric {
        name: "updates.pending",
        title: "Updates waiting",
        unit: Unit::Number,
        collector: "updates",
        source: Source::Fields(&[("Updates", Reading::Field("$.pending"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "updates.security",
        title: "Security updates waiting",
        unit: Unit::Number,
        collector: "updates",
        source: Source::Fields(&[("Security updates", Reading::Field("$.security"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "updates.vulnerable",
        title: "Packages with known vulnerabilities",
        unit: Unit::Number,
        collector: "updates",
        source: Source::Fields(&[("Vulnerable packages", Reading::Field("$.vulnerable"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "updates.reboot_required",
        title: "Reboot required",
        unit: Unit::Number,
        collector: "updates",
        source: Source::Fields(&[("Reboot required", Reading::Field("$.reboot_required"))]),
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "updates.lists_age",
        title: "Package lists age",
        unit: Unit::Seconds,
        collector: "updates",
        source: Source::Fields(&[("Package lists", Reading::Field("$.lists_age_secs"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
        name: "check.response",
        title: "Check response time",
        unit: Unit::Seconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.response_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
        name: "check.first_byte",
        title: "Time to first byte",
        unit: Unit::Seconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.first_byte_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.dns",
        title: "DNS lookup time",
        unit: Unit::Seconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.dns_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.connect",
        title: "Connection time",
        unit: Unit::Seconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connect_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.tls",
        title: "TLS handshake time",
        unit: Unit::Seconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.tls_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.download",
        title: "Download time",
        unit: Unit::Seconds,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.download_secs"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
        name: "check.domain_days",
        title: "Domain days left",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.domain_days_left"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.password_sign_in",
        title: "SSH offers password sign-in",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.password_sign_in"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    // Memcached's own figures, from its stats. A check keeps nothing between runs,
    // so hits and evictions are counted since Memcached last started.
    StaticMetric {
        name: "check.hit_rate",
        title: "Cache hit rate",
        unit: Unit::Percent,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.hit_rate_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.memory_used",
        title: "Cache memory used",
        unit: Unit::Bytes,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.memory_used_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.memory_usage",
        title: "Cache memory used of its limit",
        unit: Unit::Percent,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Percent {
                part: "$.memory_used_bytes",
                whole: "$.memory_limit_bytes",
            },
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.evictions",
        title: "Cache evictions",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.evictions"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "check.connections",
        title: "Open connections",
        unit: Unit::Number,
        collector: "checks",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connections"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
        name: "container.up",
        title: "Containers up",
        unit: Unit::Number,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.cpu",
        title: "Container CPU usage",
        unit: Unit::Percent,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.cpu_percent"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.memory",
        title: "Container memory",
        unit: Unit::Bytes,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.memory_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.memory_limit",
        title: "Container memory of its limit",
        unit: Unit::Percent,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Percent {
                part: "$.memory_bytes",
                whole: "$.memory_limit_bytes",
            },
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.received",
        title: "Container network received",
        unit: Unit::BytesPerSecond,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.received_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.sent",
        title: "Container network sent",
        unit: Unit::BytesPerSecond,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.sent_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.read",
        title: "Container disk reads",
        unit: Unit::BytesPerSecond,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.read_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.written",
        title: "Container disk writes",
        unit: Unit::BytesPerSecond,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.written_bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "container.restarts",
        title: "Container restarts",
        unit: Unit::Number,
        collector: "containers",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.restarts"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
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
    // Only Linux sends threads, as its limit is on them rather than on processes.
    StaticMetric {
        name: "system.threads",
        title: "Threads",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[
            ("Running", Reading::Field("$.threads")),
            ("Limit", Reading::Field("$.max_threads")),
        ]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "system.threads_used",
        title: "Thread limit used",
        unit: Unit::Percent,
        collector: "system",
        source: Source::Fields(&[(
            "Used",
            Reading::Percent {
                part: "$.threads",
                whole: "$.max_threads",
            },
        )]),
        chart: ShowChart::WithData,
    },
    // Linux's firewall table of connections, which drops new ones when it's full.
    StaticMetric {
        name: "system.conntrack",
        title: "Tracked connections",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[
            ("Tracked", Reading::Field("$.conntrack")),
            ("Limit", Reading::Field("$.max_conntrack")),
        ]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "system.conntrack_used",
        title: "Connection tracking table used",
        unit: Unit::Percent,
        collector: "system",
        source: Source::Fields(&[(
            "Used",
            Reading::Percent {
                part: "$.conntrack",
                whole: "$.max_conntrack",
            },
        )]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "system.sessions",
        title: "Login sessions",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Sessions", Reading::Field("$.login_sessions"))]),
        chart: ShowChart::WithData,
    },
    // Connections piling up in TIME_WAIT use up ports, and ones in CLOSE_WAIT are
    // usually a program that never closed them.
    StaticMetric {
        name: "system.tcp",
        title: "TCP connections",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[
            ("Established", Reading::Field("$.tcp_established")),
            ("Listening", Reading::Field("$.tcp_listening")),
            ("Time wait", Reading::Field("$.tcp_time_wait")),
            ("Close wait", Reading::Field("$.tcp_close_wait")),
        ]),
        chart: ShowChart::WithData,
    },
    // Services that should be running but stopped with an error, on Linux and Windows,
    // without having to name them first.
    StaticMetric {
        name: "system.failed_services",
        title: "Failed services",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Failed", Reading::Field("$.failed_services"))]),
        chart: ShowChart::WithData,
    },
    // Looked at every 15 minutes, from the host's own package lists.
    StaticMetric {
        name: "system.updates",
        title: "Updates waiting",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[
            ("All", Reading::Field("$.pending_updates")),
            ("Security", Reading::Field("$.security_updates")),
        ]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "system.reboot_required",
        title: "Restart needed",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Restart needed", Reading::Field("$.reboot_required"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "system.tcp_total",
        title: "All TCP connections",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Connections", Reading::Field("$.tcp_connections"))]),
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "server.metrics",
        title: "Metrics per second",
        unit: Unit::PerSecond,
        collector: "server",
        source: Source::Fields(&[("Metrics", Reading::Rate("$.values_written"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.memory",
        title: "Server memory",
        unit: Unit::Bytes,
        collector: "server",
        source: Source::Fields(&[("Memory", Reading::Field("$.memory_bytes"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.cpu",
        title: "Server CPU",
        unit: Unit::Percent,
        collector: "server",
        source: Source::Fields(&[("CPU", Reading::Field("$.cpu_percent"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.samples",
        title: "Samples per second",
        unit: Unit::PerSecond,
        collector: "server",
        source: Source::Fields(&[
            ("Saved", Reading::Rate("$.samples_written")),
            ("Failed", Reading::Rate("$.samples_failed")),
        ]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.write_queue",
        title: "Write queue",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Waiting", Reading::Field("$.write_queue"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.write_time",
        title: "Slowest write",
        unit: Unit::Seconds,
        collector: "server",
        source: Source::Fields(&[("Slowest", Reading::Field("$.slowest_write_secs"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.series",
        title: "Series stored",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Series", Reading::Field("$.series"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.hosts",
        title: "Hosts",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[
            ("Online", Reading::Field("$.hosts_online")),
            ("Approved", Reading::Field("$.hosts_approved")),
            ("Waiting", Reading::Field("$.hosts_waiting")),
        ]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "server.alerts",
        title: "Open alerts",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Open", Reading::Field("$.alerts_firing"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
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
    StaticMetric {
        name: "server.open_files",
        title: "Server open files",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Open", Reading::Field("$.open_files"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "apache.up",
        title: "Apache status page up",
        unit: Unit::Number,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "apache.requests",
        title: "Apache requests",
        unit: Unit::PerSecond,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.requests"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "apache.traffic",
        title: "Apache traffic",
        unit: Unit::BytesPerSecond,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.bytes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "apache.worker_usage",
        title: "Apache workers in use",
        unit: Unit::Percent,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Percent {
                part: "$.busy_workers",
                whole: "$.worker_slots",
            },
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "apache.busy_workers",
        title: "Apache busy workers",
        unit: Unit::Number,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.busy_workers"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "apache.idle_workers",
        title: "Apache idle workers",
        unit: Unit::Number,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.idle_workers"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "apache.connections",
        title: "Apache connections",
        unit: Unit::Number,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connections"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "apache.cpu_load",
        title: "Apache CPU load",
        unit: Unit::Percent,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.cpu_load"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "apache.uptime",
        title: "Apache uptime",
        unit: Unit::Seconds,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "nginx.up",
        title: "nginx status page up",
        unit: Unit::Number,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "nginx.connections",
        title: "nginx connections",
        unit: Unit::Number,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connections"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "nginx.requests",
        title: "nginx requests",
        unit: Unit::PerSecond,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.requests"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "nginx.accepted",
        title: "nginx connections accepted",
        unit: Unit::PerSecond,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.accepted"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "nginx.dropped",
        title: "nginx connections dropped",
        unit: Unit::PerSecond,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.dropped"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "nginx.reading",
        title: "nginx connections reading",
        unit: Unit::Number,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.reading"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "nginx.writing",
        title: "nginx connections writing",
        unit: Unit::Number,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.writing"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "nginx.waiting",
        title: "nginx connections waiting",
        unit: Unit::Number,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.waiting"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "php_fpm.up",
        title: "PHP-FPM status page up",
        unit: Unit::Number,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "php_fpm.requests",
        title: "PHP-FPM requests",
        unit: Unit::PerSecond,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.requests"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "php_fpm.active_processes",
        title: "PHP-FPM active processes",
        unit: Unit::Number,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.active_processes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "php_fpm.idle_processes",
        title: "PHP-FPM idle processes",
        unit: Unit::Number,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.idle_processes"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "php_fpm.total_processes",
        title: "PHP-FPM processes",
        unit: Unit::Number,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.total_processes"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "php_fpm.listen_queue",
        title: "PHP-FPM requests waiting",
        unit: Unit::Number,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.listen_queue"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "php_fpm.max_children_reached",
        title: "PHP-FPM process limit reached",
        unit: Unit::PerSecond,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.max_children_reached"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "php_fpm.slow_requests",
        title: "PHP-FPM slow requests",
        unit: Unit::PerSecond,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.slow_requests"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "php_fpm.uptime",
        title: "PHP-FPM uptime",
        unit: Unit::Seconds,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    // Whatever a page in the Prometheus or OpenMetrics format lists, each line a
    // series named by its page and the line. They measure all sorts of things, so
    // they're numbers here: levels as they are, and running totals as rates.
    StaticMetric {
        name: "openmetrics.up",
        title: "OpenMetrics page up",
        unit: Unit::Number,
        collector: "openmetrics",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "openmetrics.value",
        title: "OpenMetrics values",
        unit: Unit::Number,
        collector: "openmetrics",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.value"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "openmetrics.rate",
        title: "OpenMetrics rates",
        unit: Unit::PerSecond,
        collector: "openmetrics",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.change"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "openmetrics.dropped",
        title: "OpenMetrics series over the limit",
        unit: Unit::Number,
        collector: "openmetrics",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.dropped"),
        },
        chart: ShowChart::Never,
    },
    // What the account each database a template reads is signed in as may do
    // beyond reading, a 1 or a 0 by the database's name. MaxNines only reads, but
    // an account that could do more could be misused, so it's an alert.
    StaticMetric {
        name: "database_account.overprivileged",
        title: "Database account can do more than read",
        unit: Unit::Number,
        collector: ACCOUNTS,
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.overprivileged"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "database_account.superuser",
        title: "Database account is a superuser",
        unit: Unit::Number,
        collector: ACCOUNTS,
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.superuser"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "database_account.writes",
        title: "Database account can change data",
        unit: Unit::Number,
        collector: ACCOUNTS,
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.writes"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "database_account.manages",
        title: "Database account can manage accounts",
        unit: Unit::Number,
        collector: ACCOUNTS,
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.manages"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "database_account.server_files",
        title: "Database account can reach server files",
        unit: Unit::Number,
        collector: ACCOUNTS,
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.server_files"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
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
    StaticMetric {
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
    // Monitoring plugins in the Nagios style: 0 OK, 1 warning, 2 critical, 3 unknown,
    // and whatever performance data they give.
    StaticMetric {
        name: "command.status",
        title: "Check command status",
        unit: Unit::Number,
        collector: "commands",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.status"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "command.ok",
        title: "Check command passing",
        unit: Unit::Number,
        collector: "commands",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.ok"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "command.value",
        title: "Check command values",
        unit: Unit::Number,
        collector: "commands",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.value"),
        },
        chart: ShowChart::WithData,
    },
    // Windows performance counters, each by its path. They measure all sorts of things,
    // so they're numbers here, and the busiest are charted together.
    StaticMetric {
        name: "counter.value",
        title: "Performance counters",
        unit: Unit::Number,
        collector: "counters",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.value"),
        },
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "counter.ok",
        title: "Performance counter working",
        unit: Unit::Number,
        collector: "counters",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.ok"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "counter.dropped",
        title: "Performance counter instances over the limit",
        unit: Unit::Number,
        collector: "counters",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.dropped"),
        },
        chart: ShowChart::Never,
    },
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
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
    StaticMetric {
        name: "agent.memory",
        title: "Agent memory",
        unit: Unit::Bytes,
        collector: "agent",
        source: Source::Fields(&[("Memory", Reading::Field("$.memory_bytes"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "agent.cpu",
        title: "Agent CPU",
        unit: Unit::Percent,
        collector: "agent",
        source: Source::Fields(&[("CPU", Reading::Field("$.cpu_percent"))]),
        chart: ShowChart::WithData,
    },
    // A UniFi device, read through its console by a UniFi check, each device a
    // host of its own. See crate::unifi.
    StaticMetric {
        name: "unifi.up",
        title: "UniFi device up",
        unit: Unit::Number,
        collector: "unifi",
        source: Source::Fields(&[("Up", Reading::Field("$.up"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.uptime",
        title: "UniFi device uptime",
        unit: Unit::Seconds,
        collector: "unifi",
        source: Source::Fields(&[("Uptime", Reading::Field("$.uptime_secs"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.cpu",
        title: "UniFi device CPU usage",
        unit: Unit::Percent,
        collector: "unifi",
        source: Source::Fields(&[("CPU", Reading::Field("$.cpu_percent"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.memory",
        title: "UniFi device memory usage",
        unit: Unit::Percent,
        collector: "unifi",
        source: Source::Fields(&[("Memory", Reading::Field("$.memory_percent"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.load",
        title: "UniFi device load average",
        unit: Unit::Number,
        collector: "unifi",
        source: Source::Fields(&[
            ("1 minute", Reading::Field("$.load_average.one")),
            ("5 minutes", Reading::Field("$.load_average.five")),
            ("15 minutes", Reading::Field("$.load_average.fifteen")),
        ]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.uplink_received",
        title: "UniFi uplink received",
        unit: Unit::BytesPerSecond,
        collector: "unifi",
        source: Source::Fields(&[("Received", Reading::Field("$.uplink_received_bytes"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.uplink_sent",
        title: "UniFi uplink sent",
        unit: Unit::BytesPerSecond,
        collector: "unifi",
        source: Source::Fields(&[("Sent", Reading::Field("$.uplink_sent_bytes"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.clients",
        title: "UniFi clients connected",
        unit: Unit::Number,
        collector: "unifi",
        source: Source::Fields(&[("Clients", Reading::Field("$.clients"))]),
        chart: ShowChart::WithData,
    },
    StaticMetric {
        name: "unifi.firmware_update",
        title: "UniFi firmware update available",
        unit: Unit::Number,
        collector: "unifi",
        source: Source::Fields(&[("Update available", Reading::Field("$.firmware_update"))]),
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "agent.uptime",
        title: "Agent uptime",
        unit: Unit::Seconds,
        collector: "agent",
        source: Source::Fields(&[("Uptime", Reading::Field("$.uptime_secs"))]),
        chart: ShowChart::Never,
    },
    StaticMetric {
        name: "host.uptime",
        title: "Uptime",
        unit: Unit::Seconds,
        collector: "host",
        source: Source::Fields(&[("Uptime", Reading::Field("$.uptime_secs"))]),
        chart: ShowChart::Never,
    },
];

/// The metrics named here in code, as they're read.
pub fn built_in() -> &'static [Arc<Metric>] {
    static BUILT_IN: LazyLock<Vec<Arc<Metric>>> = LazyLock::new(|| {
        METRICS
            .iter()
            .map(|metric| Arc::new(metric.into()))
            .collect()
    });
    &BUILT_IN
}

/// One of the metrics named here in code, which is all this finds: what a
/// template adds is only in a [`crate::catalog::Catalog`].
pub fn find(name: &str) -> Option<Arc<Metric>> {
    static BY_NAME: LazyLock<HashMap<&'static str, Arc<Metric>>> = LazyLock::new(|| {
        METRICS
            .iter()
            .zip(built_in())
            .map(|(metric, read)| (metric.name, read.clone()))
            .collect()
    });
    BY_NAME.get(name).cloned()
}

impl Metric {
    /// Where a series sits in the catalog, for metrics with fixed series.
    pub fn position(&self, series: &str) -> Option<usize> {
        match &self.source {
            Source::Fields(fields) => fields.iter().position(|(name, _)| *name == series),
            _ => None,
        }
    }

    /// Whether it has one value for a host whatever series is looked at, rather
    /// than a series for each disk, database or such.
    pub fn is_single(&self) -> bool {
        match &self.source {
            Source::Fields(_) => true,
            Source::Labelled(labelled) => labelled.labels.is_empty(),
            Source::Items { .. } | Source::Entries(_) => false,
        }
    }

    /// The labels of a template's metric, or none for any other.
    pub fn labels(&self) -> &[String] {
        match &self.source {
            Source::Labelled(labelled) => &labelled.labels,
            _ => &[],
        }
    }

    /// A value as people read it, in its unit, with yes or no for a flag.
    pub fn format(&self, value: f64) -> String {
        match self.kind {
            Kind::Flag => match value != 0.0 {
                true => "yes".to_string(),
                false => "no".to_string(),
            },
            Kind::Seconds => crate::metric_charts::format_value(Unit::Seconds, value),
            Kind::Number | Kind::Unknown => crate::metric_charts::format_value(self.unit, value),
        }
    }
}

/// A span of time, split into buckets of `step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub from: Timestamp,
    pub to: Timestamp,
    pub step: TimeDelta,
}

impl TimeRange {
    /// Returns nothing for a range that's backwards, empty, too long, or outside what
    /// the stores can hold.
    pub fn new(from: Timestamp, to: Timestamp) -> Option<Self> {
        let valid = DateTime::UNIX_EPOCH <= from
            && from < to
            && to <= latest_sample()
            && to - from <= MAX_RANGE;
        valid.then(|| Self {
            from,
            to,
            step: step_for(to - from),
        })
    }

    /// The range of this length that ends now.
    pub fn ending(now: Timestamp, length: TimeDelta) -> Option<Self> {
        Self::new(now.checked_sub_signed(length)?, now)
    }
}

/// The smallest step that splits `range` into no more than [`MAX_POINTS`], or whole
/// days for ranges longer than the steps offered.
fn step_for(range: TimeDelta) -> TimeDelta {
    let wanted = range / MAX_POINTS;
    STEPS
        .into_iter()
        .find(|step| *step >= wanted)
        .unwrap_or_else(|| TimeDelta::days((wanted.num_seconds() + 86_399) / 86_400))
}

#[derive(Debug, Clone, Copy)]
pub struct SeriesQuery<'a> {
    pub host_id: &'a str,
    pub metric: &'a Metric,
    pub range: TimeRange,
    /// Keep this many series, starting with the highest.
    pub max_series: usize,
}

/// One bucket of a series, at the moment it starts.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Point {
    pub time: Timestamp,
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
    pub host_id: String,
    pub time: Timestamp,
}

/// An agent's headline numbers, from the sample it sent last.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CurrentValues {
    pub last_sample_at: Timestamp,
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    /// The fullest disk.
    pub disk_percent: Option<f64>,
    pub disk_mount_point: Option<String>,
}

impl CurrentValues {
    fn at(last_sample_at: Timestamp) -> Self {
        Self {
            last_sample_at,
            cpu_percent: None,
            memory_percent: None,
            disk_percent: None,
            disk_mount_point: None,
        }
    }
}

/// A series' newest value.
#[derive(Debug, Clone, PartialEq)]
pub struct NewestReading {
    pub host_id: String,
    pub series: String,
    pub time: Timestamp,
    pub value: f64,
}

/// Which way a series has been heading: its newest value, and the slope of the
/// straight line that fits its readings best.
#[derive(Debug, Clone, PartialEq)]
pub struct Trend {
    pub host_id: String,
    pub series: String,
    /// The newest reading.
    pub time: Timestamp,
    pub value: f64,
    /// The oldest reading, so a line through a few minutes isn't trusted for days.
    pub first_time: Timestamp,
    pub samples: u64,
    /// How much the value changes each second.
    pub slope_per_sec: f64,
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
    let mut hosts: BTreeMap<String, CurrentValues> = last_samples
        .into_iter()
        .map(|sample| (sample.host_id, CurrentValues::at(sample.time)))
        .collect();

    for reading in cpu.into_iter().filter(|cpu| cpu.series == CPU_SERIES) {
        if let Some(values) = hosts.get_mut(&reading.host_id) {
            values.cpu_percent = Some(reading.value);
        }
    }
    for reading in memory
        .into_iter()
        .filter(|memory| memory.series == MEMORY_SERIES)
    {
        if let Some(values) = hosts.get_mut(&reading.host_id) {
            values.memory_percent = Some(reading.value);
        }
    }
    for disk in disks {
        if let Some(values) = hosts.get_mut(&disk.host_id)
            && values
                .disk_percent
                .is_none_or(|fullest| disk.value > fullest)
        {
            values.disk_percent = Some(disk.value);
            values.disk_mount_point = Some(disk.series);
        }
    }
    hosts
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
        host_id: &str,
        metric: &Arc<Metric>,
        range: TimeRange,
        max_series: usize,
    ) -> Result<SeriesResult> {
        let reader = self.reader.clone();
        let host_id = host_id.to_string();
        let metric = metric.clone();
        let read = metric.clone();

        let mut result = tokio::task::spawn_blocking(move || {
            reader.series(&SeriesQuery {
                host_id: &host_id,
                metric: &read,
                range,
                max_series,
            })
        })
        .await
        .context("reading metrics")??;

        result
            .series
            .sort_by_key(|series| metric.position(&series.name));
        // A template's metric with one series for the whole host has nothing to
        // name it by, so it's called what the metric is, as the built-in ones are.
        if matches!(metric.source, Source::Labelled(_)) && metric.is_single() {
            for series in &mut result.series {
                if series.name.is_empty() {
                    series.name = metric.title.clone();
                }
            }
        }
        Ok(result)
    }

    /// The newest value of each series, across every agent.
    pub async fn newest(&self, metric: &Arc<Metric>, now: Timestamp) -> Result<Vec<NewestReading>> {
        let reader = self.reader.clone();
        let metric = metric.clone();
        tokio::task::spawn_blocking(move || {
            reader.newest(&metric, now - CURRENT_WINDOW, now + CLOCK_SKEW)
        })
        .await
        .context("reading metrics")?
    }

    /// When each host last sent a sample that's still current, by the host's clock.
    pub async fn last_samples(&self, now: Timestamp) -> Result<Vec<LastSample>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            reader.last_samples(now - CURRENT_WINDOW, now + CLOCK_SKEW)
        })
        .await
        .context("reading metrics")?
    }

    /// Which way each series of a metric has been heading between two times,
    /// across every agent.
    pub async fn trends(
        &self,
        metric: &Arc<Metric>,
        since: Timestamp,
        until: Timestamp,
    ) -> Result<Vec<Trend>> {
        let reader = self.reader.clone();
        let metric = metric.clone();
        tokio::task::spawn_blocking(move || reader.trends(&metric, since, until))
            .await
            .context("reading metrics")?
    }

    pub async fn stats(&self, hour_ago: Timestamp) -> Result<StoreStats> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || reader.stats(hour_ago))
            .await
            .context("reading metrics")?
    }

    /// What one of an agent's collectors last sent.
    pub async fn latest_output(
        &self,
        host_id: &str,
        collector: &str,
        now: Timestamp,
    ) -> Result<Option<Value>> {
        let reader = self.reader.clone();
        let (host_id, collector) = (host_id.to_string(), collector.to_string());
        tokio::task::spawn_blocking(move || {
            reader.latest_output(&host_id, &collector, now - CURRENT_WINDOW, now + CLOCK_SKEW)
        })
        .await
        .context("reading metrics")?
    }

    pub async fn calculate(&self, query: CalculationQuery) -> Result<SeriesResult> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || reader.calculate(&query)).await?
    }

    pub async fn series_count(&self) -> Result<u64> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || reader.series_count()).await?
    }

    pub async fn current(&self, now: Timestamp) -> Result<BTreeMap<String, CurrentValues>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            let (since, until) = (now - CURRENT_WINDOW, now + CLOCK_SKEW);
            let newest = |name| {
                let metric = find(name).context("unknown metric")?;
                reader.newest(&metric, since, until)
            };
            Ok(current_values(
                reader.last_samples(since, until)?,
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

    use crate::times::from_ms;

    const HOUR: TimeDelta = TimeDelta::hours(1);
    const DAY: TimeDelta = TimeDelta::days(1);

    #[test]
    fn a_service_or_container_that_is_down_says_what_state_it_is_in() {
        let described_of = |name: &str| find(name).and_then(|metric| described(&metric));
        let services = described_of("service.running").unwrap();
        assert_eq!(services.noun, "Service");
        let output = serde_json::json!([
            { "name": "nginx.service", "running": 0, "state": "failed" },
            { "name": "sshd.service", "running": 1, "state": "active" },
            { "name": "bad.service", "running": 0, "state": "fail\ned\u{7}" },
            { "name": "quiet.service", "running": 0 },
            { "name": "long.service", "running": 0, "state": "x".repeat(500) },
        ]);
        let state = |series: &str| services.state_of(&output, series);
        assert_eq!(state("nginx.service").as_deref(), Some("failed"));
        // One that's working by now has nothing to say, and nor has one unheard of.
        assert_eq!(state("sshd.service"), None);
        assert_eq!(state("other.service"), None);
        assert_eq!(state("quiet.service"), None);
        // An agent chooses the word, so it loses what could forge a line.
        assert_eq!(state("bad.service").as_deref(), Some("failed"));
        assert_eq!(state("long.service").map(|state| state.len()), Some(60));
        assert_eq!(services.state_of(&Value::Null, "nginx.service"), None);

        let containers = described_of("container.up").unwrap();
        let output = serde_json::json!([{ "name": "web", "up": 0, "state": "exited" }]);
        assert_eq!(containers.noun, "Container");
        assert_eq!(
            containers.state_of(&output, "web").as_deref(),
            Some("exited")
        );
        assert!(described_of("cpu.usage").is_none());
    }

    #[test]
    fn every_metric_has_a_unique_name_and_can_be_found() {
        assert_eq!(built_in().len(), METRICS.len());
        for metric in built_in() {
            assert_eq!(find(&metric.name).as_ref(), Some(metric));
        }
        assert_eq!(find("cpu.nonsense"), None);
    }

    #[test]
    fn the_step_keeps_a_range_within_the_point_limit() {
        for (range, step) in [
            (HOUR, TimeDelta::seconds(15)),
            (HOUR * 6, TimeDelta::minutes(2)),
            (HOUR * 24, TimeDelta::minutes(10)),
            (DAY * 7, HOUR),
            (DAY * 30, HOUR * 3),
            (MAX_RANGE, DAY * 2),
        ] {
            assert_eq!(step_for(range), step, "{range}");
            assert!(
                range.num_milliseconds() / step.num_milliseconds() <= i64::from(MAX_POINTS),
                "{range}"
            );
        }
    }

    #[test]
    fn a_tiny_range_still_gets_the_smallest_step() {
        assert_eq!(step_for(TimeDelta::milliseconds(1)), TimeDelta::seconds(15));
    }

    #[test]
    fn ranges_that_make_no_sense_are_refused() {
        let start = DateTime::UNIX_EPOCH;
        let millisecond = TimeDelta::milliseconds(1);
        assert!(TimeRange::new(start, start + HOUR).is_some());
        assert!(
            TimeRange::new(start + HOUR, start + HOUR).is_none(),
            "empty"
        );
        assert!(TimeRange::new(start + HOUR, start).is_none(), "backwards");
        assert!(
            TimeRange::new(start - millisecond, start + HOUR).is_none(),
            "before 1970"
        );
        assert!(
            TimeRange::new(start, start + MAX_RANGE + millisecond).is_none(),
            "too long"
        );
        let latest = latest_sample();
        assert!(TimeRange::new(latest - HOUR, latest).is_some());
        assert!(TimeRange::new(latest - HOUR, latest + millisecond).is_none());
        assert!(TimeRange::new(Timestamp::MIN_UTC, Timestamp::MAX_UTC).is_none());
    }

    #[test]
    fn fixed_series_have_a_catalog_position_and_others_do_not() {
        let load = find("cpu.load").unwrap();
        assert_eq!(load.position("15 minutes"), Some(2));
        assert_eq!(find("disk.usage").unwrap().position("/"), None);
    }

    fn reading(host_id: &str, series: &str, value: f64) -> NewestReading {
        NewestReading {
            host_id: host_id.to_string(),
            series: series.to_string(),
            time: from_ms(1),
            value,
        }
    }

    fn last(host_id: &str, time_ms: i64) -> LastSample {
        LastSample {
            host_id: host_id.to_string(),
            time: from_ms(time_ms),
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
                last_sample_at: from_ms(40),
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

        assert_eq!(values["a"], CurrentValues::at(from_ms(1)));
    }

    #[test]
    fn readings_for_agents_that_sent_nothing_lately_are_left_out() {
        let cpu = vec![reading("gone", "CPU", 5.0)];
        let values = current_values(Vec::new(), cpu, Vec::new(), Vec::new());

        assert!(values.is_empty());
    }
}
