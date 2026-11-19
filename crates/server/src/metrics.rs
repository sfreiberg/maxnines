//! What can be asked of stored metrics. The web pages, the API and alerting all
//! read through here.
//!
//! The catalog is a fixed list, so what's queried never comes from a request or
//! an agent. Only agent IDs and times do, and those are bound as parameters.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta};
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
    match metric.name {
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

pub const METRICS: &[Metric] = &[
    Metric {
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
    Metric {
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
        // Windows has no load average, so its agents send none.
        chart: ShowChart::WithData,
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
    // The programs using the most, by name, when a config rule turns this on.
    Metric {
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
    Metric {
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
    // How hard each disk is working, which bytes alone can't show. macOS has no busy
    // time or queue, and FreeBSD reports none of these yet.
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
        name: "disk.read_latency",
        title: "Disk read latency",
        unit: Unit::Milliseconds,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.read_latency_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "disk.write_latency",
        title: "Disk write latency",
        unit: Unit::Milliseconds,
        collector: "disk",
        source: Source::Items {
            name: "$.mount_point",
            reading: Reading::Field("$.write_latency_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
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
    // Packets with nowhere to wait, which means the host isn't keeping up.
    Metric {
        name: "network.drops.received",
        title: "Received packets dropped",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.receive_drops")),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "network.drops.transmitted",
        title: "Sent packets dropped",
        unit: Unit::PerSecond,
        collector: "network",
        source: Source::Entries(Reading::Rate("$.transmit_drops")),
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
    // Worked out by the server, which asks each agent what its clock says. How
    // far apart they are, whichever is ahead.
    Metric {
        name: "clock.difference",
        title: "Clock difference from the server",
        unit: Unit::Seconds,
        collector: "clock",
        source: Source::Fields(&[("Difference", Reading::Field("$.difference_secs"))]),
        chart: ShowChart::WithData,
    },
    // Only macOS reports these so far.
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    // Only Linux sends threads, as its limit is on them rather than on processes.
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
        name: "system.sessions",
        title: "Login sessions",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Sessions", Reading::Field("$.login_sessions"))]),
        chart: ShowChart::WithData,
    },
    // Connections piling up in TIME_WAIT use up ports, and ones in CLOSE_WAIT are
    // usually a program that never closed them.
    Metric {
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
    Metric {
        name: "system.failed_services",
        title: "Failed services",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Failed", Reading::Field("$.failed_services"))]),
        chart: ShowChart::WithData,
    },
    // Looked at every 15 minutes, from the host's own package lists.
    Metric {
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
    Metric {
        name: "system.reboot_required",
        title: "Restart needed",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Restart needed", Reading::Field("$.reboot_required"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "system.tcp_total",
        title: "All TCP connections",
        unit: Unit::Number,
        collector: "system",
        source: Source::Fields(&[("Connections", Reading::Field("$.tcp_connections"))]),
        chart: ShowChart::Never,
    },
    Metric {
        name: "server.metrics",
        title: "Metrics per second",
        unit: Unit::PerSecond,
        collector: "server",
        source: Source::Fields(&[("Metrics", Reading::Rate("$.values_written"))]),
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
        title: "Samples per second",
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
        name: "server.write_time",
        title: "Slowest write",
        unit: Unit::Milliseconds,
        collector: "server",
        source: Source::Fields(&[("Slowest", Reading::Field("$.slowest_write_ms"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "server.series",
        title: "Series stored",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Series", Reading::Field("$.series"))]),
        chart: ShowChart::WithData,
    },
    Metric {
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
    Metric {
        name: "server.alerts",
        title: "Open alerts",
        unit: Unit::Number,
        collector: "server",
        source: Source::Fields(&[("Open", Reading::Field("$.alerts_firing"))]),
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
        name: "apache.up",
        title: "Apache status page answering",
        unit: Unit::Number,
        collector: "apache",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
        name: "nginx.up",
        title: "nginx status page answering",
        unit: Unit::Number,
        collector: "nginx",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
        name: "php_fpm.up",
        title: "PHP-FPM status page answering",
        unit: Unit::Number,
        collector: "php_fpm",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
        name: "openmetrics.up",
        title: "OpenMetrics page answering",
        unit: Unit::Number,
        collector: "openmetrics",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
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
    Metric {
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
    Metric {
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
    // Databases an agent's config defines and a rule picks, or a server check
    // reads. Each kind's rows are grouped under it, so its values are its own,
    // such as `pg.connections`. Each is a series by the database's name, or
    // by its name and what it's of, such as `orders standby replica1`. Running
    // totals are rates.
    // PostgreSQL.
    Metric {
        name: "pg.up",
        title: "PostgreSQL answering",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.uptime",
        title: "PostgreSQL uptime",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.connections",
        title: "PostgreSQL connections",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.connections"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.connections_used",
        title: "PostgreSQL connections used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.connections_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.oldest_transaction",
        title: "PostgreSQL oldest transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.oldest_transaction_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.oldest_query",
        title: "PostgreSQL oldest query",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.oldest_query_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.rollbacks",
        title: "PostgreSQL rollbacks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.rollbacks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.deadlocks",
        title: "PostgreSQL deadlocks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.deadlocks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.cache_hit",
        title: "PostgreSQL cache hit rate",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.cache_hit"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.replica",
        title: "PostgreSQL is a replica",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.replica"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.receiving",
        title: "PostgreSQL replica receiving",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.receiving"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.lag",
        title: "PostgreSQL replication lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.size",
        title: "PostgreSQL database size",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.running_queries",
        title: "PostgreSQL queries running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.running_queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.idle_in_transaction",
        title: "PostgreSQL sessions idle in a transaction",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.idle_in_transaction"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.lock_waits",
        title: "PostgreSQL sessions waiting on locks",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.lock_waits"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.oldest_idle_in_transaction",
        title: "PostgreSQL longest idle in a transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.oldest_idle_in_transaction_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.transactions",
        title: "PostgreSQL transactions",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.transactions"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.temp_written",
        title: "PostgreSQL temporary files written",
        unit: Unit::BytesPerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.temp_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.conflicts",
        title: "PostgreSQL queries cancelled by replication",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.conflicts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.checksum_failures",
        title: "PostgreSQL checksum failures",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.checksum_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.checkpoints_timed",
        title: "PostgreSQL scheduled checkpoints",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.checkpoints_timed"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.checkpoints_requested",
        title: "PostgreSQL requested checkpoints",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.checkpoints_requested"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.wal_written",
        title: "PostgreSQL WAL written",
        unit: Unit::BytesPerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.wal_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.wal_size",
        title: "PostgreSQL WAL on disk",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.wal_size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.xid_age",
        title: "PostgreSQL oldest transaction ID age",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.xid_age"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.mxid_age",
        title: "PostgreSQL oldest multixact ID age",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.mxid_age"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.prepared",
        title: "PostgreSQL prepared transactions",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.prepared"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.oldest_prepared",
        title: "PostgreSQL oldest prepared transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.oldest_prepared_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.standbys",
        title: "PostgreSQL standbys",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.standbys"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.synchronous_standbys",
        title: "PostgreSQL synchronous standbys",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.synchronous_standbys"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.lag_bytes",
        title: "PostgreSQL standby lag in bytes",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.lag_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.streaming",
        title: "PostgreSQL standby streaming",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.streaming"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.last_received",
        title: "PostgreSQL time since the replica heard from its primary",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.last_received_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.replay_backlog",
        title: "PostgreSQL WAL received but not replayed",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.replay_backlog_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.replay_paused",
        title: "PostgreSQL replay paused",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.replay_paused"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.timeline",
        title: "PostgreSQL timeline",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.timeline"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.slot_in_use",
        title: "PostgreSQL replication slot in use",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.in_use"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.slot_retained",
        title: "PostgreSQL WAL kept by replication slots",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.retained_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.slot_headroom",
        title: "PostgreSQL WAL a slot can still keep",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.headroom_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.slot_lost",
        title: "PostgreSQL replication slot lost",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.lost"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.archive_failing",
        title: "PostgreSQL archiving failing",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.archive_failing"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.archive_waiting",
        title: "PostgreSQL WAL files waiting to be archived",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.archive_waiting"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "pg.archived",
        title: "PostgreSQL WAL files archived",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.archived"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.archive_failures",
        title: "PostgreSQL archiving failures",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.archive_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.subscription_running",
        title: "PostgreSQL subscription running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.pg.running"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "pg.subscription_errors",
        title: "PostgreSQL subscription errors",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.pg.errors"),
        },
        chart: ShowChart::Never,
    },
    // MySQL.
    Metric {
        name: "mysql.up",
        title: "MySQL answering",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.uptime",
        title: "MySQL uptime",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.connections",
        title: "MySQL connections",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.connections"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.connections_used",
        title: "MySQL connections used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.connections_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.refused",
        title: "MySQL connections refused at the limit",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.refused"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.queries",
        title: "MySQL queries",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.oldest_transaction",
        title: "MySQL oldest transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.oldest_transaction_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.oldest_query",
        title: "MySQL oldest query",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.oldest_query_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.rollbacks",
        title: "MySQL rollbacks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.rollbacks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.deadlocks",
        title: "MySQL deadlocks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.deadlocks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.cache_hit",
        title: "MySQL cache hit rate",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.cache_hit"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.replica",
        title: "MySQL is a replica",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.replica"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.receiving",
        title: "MySQL replica receiving",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.receiving"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.lag",
        title: "MySQL replication lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.size",
        title: "MySQL database size",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.running_queries",
        title: "MySQL queries running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.running_queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.slow_queries",
        title: "MySQL slow queries",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.slow_queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.commits",
        title: "MySQL commits",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.commits"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.aborted_connects",
        title: "MySQL failed connection attempts",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.aborted_connects"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.tmp_disk_tables",
        title: "MySQL temporary tables on disk",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.tmp_disk_tables"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.pool_dirty",
        title: "MySQL buffer pool dirty",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.pool_dirty"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.pool_waits",
        title: "MySQL waits for a free buffer page",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.pool_waits"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.lock_waits",
        title: "MySQL row lock waits",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.lock_waits"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.history_length",
        title: "MySQL undo history length",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.history_length"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.open_transactions",
        title: "MySQL open transactions",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.open_transactions"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.read_only",
        title: "MySQL read only",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.read_only"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.super_read_only",
        title: "MySQL super read only",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.super_read_only"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.applying",
        title: "MySQL replica applying",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.applying"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.relay_log",
        title: "MySQL relay log size",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.relay_log_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.replication_errno",
        title: "MySQL replication error code",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.replication_errno"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.semi_sync",
        title: "MySQL semi-synchronous replication on",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.semi_sync"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.semi_sync_clients",
        title: "MySQL semi-synchronous replicas",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.semi_sync_clients"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.semi_sync_misses",
        title: "MySQL commits not acknowledged by a replica",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.semi_sync_misses"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.group_members",
        title: "MySQL group members",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.group_members"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.group_online",
        title: "MySQL group members online",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.group_online"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.member_online",
        title: "MySQL group member online",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.member_online"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.applier_queue",
        title: "MySQL group applier queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.applier_queue"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.certifier_queue",
        title: "MySQL group certifier queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.certifier_queue"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.group_conflicts",
        title: "MySQL group conflicts",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.group_conflicts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_primary",
        title: "Galera cluster primary",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_primary"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_size",
        title: "Galera cluster size",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_size"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.galera_ready",
        title: "Galera node ready",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_ready"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_connected",
        title: "Galera node connected",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_connected"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_synced",
        title: "Galera node synced",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_synced"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_receive_queue",
        title: "Galera receive queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_receive_queue"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.galera_send_queue",
        title: "Galera send queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.galera_send_queue"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_cert_failures",
        title: "Galera certification failures",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.galera_cert_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mysql.galera_flow_paused",
        title: "Galera paused for flow control",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mysql.galera_flow_paused"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mysql.binlog_size",
        title: "MySQL binary logs on disk",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mysql.binlog_size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    // MongoDB.
    Metric {
        name: "mongodb.up",
        title: "MongoDB answering",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.uptime",
        title: "MongoDB uptime",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.connections",
        title: "MongoDB connections",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.connections"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.connections_used",
        title: "MongoDB connections used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.connections_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.refused",
        title: "MongoDB connections refused at the limit",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mongodb.refused"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.oldest_query",
        title: "MongoDB oldest query",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.oldest_query_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.replica",
        title: "MongoDB is a replica",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.replica"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.receiving",
        title: "MongoDB replica receiving",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.receiving"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.lag",
        title: "MongoDB replication lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.size",
        title: "MongoDB database size",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.operations",
        title: "MongoDB operations",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mongodb.operations"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.read_latency",
        title: "MongoDB read latency",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.reads_latency_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.write_latency",
        title: "MongoDB write latency",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.writes_latency_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.queued_reads",
        title: "MongoDB reads queued",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.queued_reads"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.queued_writes",
        title: "MongoDB writes queued",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.queued_writes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.read_tickets",
        title: "MongoDB read tickets free",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.read_tickets"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.write_tickets",
        title: "MongoDB write tickets free",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.write_tickets"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.cache_used",
        title: "MongoDB cache used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.cache_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.cache_dirty",
        title: "MongoDB cache dirty",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.cache_dirty"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.cursors_open",
        title: "MongoDB cursors open",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.cursors_open"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.cursors_timed_out",
        title: "MongoDB cursors timed out",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mongodb.cursors_timed_out"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.asserts",
        title: "MongoDB assertions",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.mongodb.asserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.memory",
        title: "MongoDB memory in use",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.memory_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.flow_control_lagged",
        title: "MongoDB held back by flow control",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.flow_control_lagged"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.members",
        title: "MongoDB replica set members",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.members"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.members_healthy",
        title: "MongoDB replica set members healthy",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.members_healthy"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.has_primary",
        title: "MongoDB replica set has a primary",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.has_primary"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.term",
        title: "MongoDB election term",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.term"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.majority_lag",
        title: "MongoDB majority commit lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.majority_lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.member_healthy",
        title: "MongoDB member healthy",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.member_healthy"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.member_lag",
        title: "MongoDB member lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.member_lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "mongodb.oplog_window",
        title: "MongoDB oplog window",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mongodb.oplog_window_secs"),
        },
        chart: ShowChart::WithData,
    },
    // ClickHouse.
    Metric {
        name: "clickhouse.up",
        title: "ClickHouse answering",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.uptime",
        title: "ClickHouse uptime",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.connections",
        title: "ClickHouse connections",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.connections"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.connections_used",
        title: "ClickHouse connections used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.connections_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.queries",
        title: "ClickHouse queries",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.oldest_query",
        title: "ClickHouse oldest query",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.oldest_query_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.lag",
        title: "ClickHouse replication lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.size",
        title: "ClickHouse database size",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.running_queries",
        title: "ClickHouse queries running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.running_queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.queries_used",
        title: "ClickHouse queries running of the most allowed",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.queries_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.preempted_queries",
        title: "ClickHouse queries held back by priority",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.preempted_queries"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.interserver_connections",
        title: "ClickHouse connections between servers",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.interserver_connections"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.selects",
        title: "ClickHouse selects",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.selects"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.inserts",
        title: "ClickHouse inserts",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.inserts"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.failed_queries",
        title: "ClickHouse failed queries",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.failed_queries"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.failed_selects",
        title: "ClickHouse failed selects",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.failed_selects"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.failed_inserts",
        title: "ClickHouse failed inserts",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.failed_inserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.latency",
        title: "ClickHouse average query time",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.latency_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.select_latency",
        title: "ClickHouse average select time",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.select_latency_ms"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.insert_latency",
        title: "ClickHouse average insert time",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.insert_latency_ms"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.inserted_rows",
        title: "ClickHouse rows inserted",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.inserted_rows"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.inserted_bytes",
        title: "ClickHouse bytes inserted",
        unit: Unit::BytesPerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.inserted_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.rows_per_insert",
        title: "ClickHouse rows per insert",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.rows_per_insert"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.max_parts",
        title: "ClickHouse most parts in a partition",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.max_parts_per_partition"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.parts_used",
        title: "ClickHouse most parts in a partition of where inserts slow",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.parts_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.parts_total",
        title: "ClickHouse parts in total",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.parts_total"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.delayed_inserts",
        title: "ClickHouse inserts being slowed",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.delayed_inserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.inserts_delayed",
        title: "ClickHouse inserts slowed for too many parts",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.inserts_delayed"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.insert_delay",
        title: "ClickHouse time inserts were slowed, ms per second",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.insert_delay_ms"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.rejected_inserts",
        title: "ClickHouse inserts refused for too many parts",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.rejected_inserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.pending_async_inserts",
        title: "ClickHouse inserts waiting to be batched",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.pending_async_inserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.failed_async_inserts",
        title: "ClickHouse batched inserts failed",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.failed_async_inserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.async_queue_age",
        title: "ClickHouse oldest insert waiting to be batched",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.async_queue_oldest_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.memory",
        title: "ClickHouse memory in use",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.memory_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.memory_used",
        title: "ClickHouse memory used of its limit",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.memory_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.merge_memory",
        title: "ClickHouse memory used by merges and mutations",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.merge_memory_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.memory_limit_exceeded",
        title: "ClickHouse queries over their memory limit",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.memory_limit_exceeded"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.overcommit_wait",
        title: "ClickHouse time waiting for memory, ms per second",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.overcommit_wait_ms"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.merges_running",
        title: "ClickHouse merges running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.merges_running"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.pool_used",
        title: "ClickHouse background pool used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.pool_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.pool_tasks",
        title: "ClickHouse background pool tasks",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.pool_tasks"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.mutations_pending",
        title: "ClickHouse mutations pending",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.mutations_pending"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.mutations_failing",
        title: "ClickHouse mutations failing",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.mutations_failing"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.mutations_delayed",
        title: "ClickHouse mutations slowed",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.mutations_delayed"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.mutations_rejected",
        title: "ClickHouse mutations refused",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.mutations_rejected"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.dictionaries_failing",
        title: "ClickHouse dictionaries failing",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.dictionaries_failing"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.detached_parts",
        title: "ClickHouse detached parts",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.detached_parts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.detached_broken",
        title: "ClickHouse parts detached as broken",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.detached_broken"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.backups_failed",
        title: "ClickHouse backups and restores failed",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.backups_failed"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.errors",
        title: "ClickHouse errors",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.error_count"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.buffer_flush_errors",
        title: "ClickHouse buffer table flush failures",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.buffer_flush_errors"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.slow_reads",
        title: "ClickHouse slow disk reads",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.slow_reads"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.read_failures",
        title: "ClickHouse failed disk reads",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.read_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.write_failures",
        title: "ClickHouse failed disk writes",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.write_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.readonly_replicas",
        title: "ClickHouse read-only replicas",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.readonly_replicas"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.replicated_tables",
        title: "ClickHouse replicated tables",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.replicated_tables"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.readonly_tables",
        title: "ClickHouse replicated tables read only",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.readonly_tables"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.expired_sessions",
        title: "ClickHouse tables that lost Keeper",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.expired_sessions"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.tables_missing_replicas",
        title: "ClickHouse tables missing a replica",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.tables_missing_replicas"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.log_lag",
        title: "ClickHouse replication log entries behind",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.max_log_lag"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.replication_queue",
        title: "ClickHouse replication queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.replication_queue"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.max_replication_queue",
        title: "ClickHouse longest replication queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.max_replication_queue"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.inserts_in_queue",
        title: "ClickHouse inserts waiting to replicate",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.inserts_in_queue"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.merges_in_queue",
        title: "ClickHouse merges waiting to replicate",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.max_merges_in_queue"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.future_parts",
        title: "ClickHouse parts still to appear",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.max_future_parts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.parts_to_check",
        title: "ClickHouse parts waiting to be checked",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.max_parts_to_check"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.oldest_queue_entry",
        title: "ClickHouse oldest replication queue entry",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.oldest_queue_entry_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.queue_stuck",
        title: "ClickHouse replication queue entries stuck",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.queue_stuck"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.queue_failing",
        title: "ClickHouse replication queue entries failing",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.queue_failing"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.queue_update_errors",
        title: "ClickHouse replicas failing to update their queue",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.queue_update_errors"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.relative_lag",
        title: "ClickHouse replica lag behind the freshest",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.relative_lag_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.lost_parts",
        title: "ClickHouse parts lost",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.lost_parts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.fetches_running",
        title: "ClickHouse parts being fetched",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.fetches_running"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.longest_fetch",
        title: "ClickHouse longest fetch",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.longest_fetch_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.failed_fetches",
        title: "ClickHouse failed fetches",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.failed_fetches"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.failed_part_checks",
        title: "ClickHouse failed part checks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.failed_part_checks"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.data_loss",
        title: "ClickHouse data lost on a replica",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.data_loss"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.merge_differs",
        title: "ClickHouse merges that differ from a replica",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.merge_differs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.mutation_differs",
        title: "ClickHouse mutations that differ from a replica",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.mutation_differs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.partial_shutdowns",
        title: "ClickHouse replicated tables shut down",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.partial_shutdowns"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distributed_files",
        title: "ClickHouse Distributed files waiting",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.distributed_files"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.distributed_bytes",
        title: "ClickHouse Distributed bytes waiting",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.distributed_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distributed_broken_files",
        title: "ClickHouse Distributed files broken",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.distributed_broken_files"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distributed_retries",
        title: "ClickHouse connections to shards retried",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.distributed_retries"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distributed_failures",
        title: "ClickHouse connections to shards failed",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.distributed_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distributed_rejected",
        title: "ClickHouse Distributed inserts refused",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.distributed_rejected"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distributed_insert_failures",
        title: "ClickHouse Distributed inserts failed",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.distributed_insert_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distribution_blocked",
        title: "ClickHouse Distributed queues blocked",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.distribution_blocked"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.distribution_errors",
        title: "ClickHouse Distributed queue errors",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.distribution_errors"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.cluster_errors",
        title: "ClickHouse recent errors reaching other replicas",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.cluster_errors"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_connected",
        title: "ClickHouse connected to Keeper",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_connected"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_session",
        title: "ClickHouse Keeper session age",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_session_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_sessions",
        title: "ClickHouse Keeper sessions",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_sessions"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_sessions_expired",
        title: "ClickHouse Keeper sessions expired",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_sessions_expired"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_requests",
        title: "ClickHouse Keeper requests in flight",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_requests"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_latency",
        title: "ClickHouse Keeper average wait",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_latency_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.keeper_hardware_errors",
        title: "ClickHouse Keeper connection errors",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.keeper_hardware_errors"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_user_errors",
        title: "ClickHouse Keeper request errors",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.clickhouse.keeper_user_errors"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_leader",
        title: "ClickHouse embedded Keeper is leader",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_leader"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_synced_followers",
        title: "ClickHouse embedded Keeper synced followers",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_synced_followers"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_memory_limit_hit",
        title: "ClickHouse embedded Keeper over its memory limit",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_memory_limit_hit"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_clients",
        title: "ClickHouse embedded Keeper clients",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_clients"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.keeper_outstanding",
        title: "ClickHouse embedded Keeper requests waiting",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.keeper_outstanding"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.disk_free",
        title: "ClickHouse disk free",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.disk_free_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.disk_used",
        title: "ClickHouse disk used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.disk_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.disk_broken",
        title: "ClickHouse disk broken",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.disk_broken"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.disk_read_only",
        title: "ClickHouse disk read only",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.disk_read_only"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.query_p50",
        title: "ClickHouse median query time",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.p50_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.query_p95",
        title: "ClickHouse 95th percentile query time",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.p95_ms"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "clickhouse.query_p99",
        title: "ClickHouse 99th percentile query time",
        unit: Unit::Milliseconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.p99_ms"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "clickhouse.queries_failed_5m",
        title: "ClickHouse queries failed in five minutes",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.clickhouse.failed_5m"),
        },
        chart: ShowChart::Never,
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
    // Monitoring plugins in the Nagios style: 0 OK, 1 warning, 2 critical, 3 unknown,
    // and whatever performance data they give.
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
    Metric {
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
        name: "agent.memory",
        title: "Agent memory",
        unit: Unit::Bytes,
        collector: "agent",
        source: Source::Fields(&[("Memory", Reading::Field("$.memory_bytes"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "agent.cpu",
        title: "Agent CPU",
        unit: Unit::Percent,
        collector: "agent",
        source: Source::Fields(&[("CPU", Reading::Field("$.cpu_percent"))]),
        chart: ShowChart::WithData,
    },
    Metric {
        name: "agent.uptime",
        title: "Agent uptime",
        unit: Unit::Seconds,
        collector: "agent",
        source: Source::Fields(&[("Uptime", Reading::Field("$.uptime_secs"))]),
        chart: ShowChart::Never,
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
    pub metric: &'static Metric,
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
        metric: &'static Metric,
        range: TimeRange,
        max_series: usize,
    ) -> Result<SeriesResult> {
        let reader = self.reader.clone();
        let host_id = host_id.to_string();

        let mut result = tokio::task::spawn_blocking(move || {
            reader.series(&SeriesQuery {
                host_id: &host_id,
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
    pub async fn newest(
        &self,
        metric: &'static Metric,
        now: Timestamp,
    ) -> Result<Vec<NewestReading>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            reader.newest(metric, now - CURRENT_WINDOW, now + CLOCK_SKEW)
        })
        .await
        .context("reading metrics")?
    }

    /// Which way each series of a metric has been heading between two times,
    /// across every agent.
    pub async fn trends(
        &self,
        metric: &'static Metric,
        since: Timestamp,
        until: Timestamp,
    ) -> Result<Vec<Trend>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || reader.trends(metric, since, until))
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
                reader.newest(metric, since, until)
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
        let services = find("service.running").and_then(described).unwrap();
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

        let containers = find("container.up").and_then(described).unwrap();
        let output = serde_json::json!([{ "name": "web", "up": 0, "state": "exited" }]);
        assert_eq!(containers.noun, "Container");
        assert_eq!(
            containers.state_of(&output, "web").as_deref(),
            Some("exited")
        );
        assert!(find("cpu.usage").and_then(described).is_none());
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
