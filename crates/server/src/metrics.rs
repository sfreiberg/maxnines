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

use crate::calculations::CalculationQuery;
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
    // Databases an agent's config defines and a rule picks. Each is a series by
    // the database's name, or by its name and what it's of, such as `orders
    // standby replica1`. Running totals are rates. What every kind has is a
    // database metric, so it charts every database together.
    Metric {
        name: "database.up",
        title: "Database answering",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.up"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "database.uptime",
        title: "Database uptime",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.uptime_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "database.connections",
        title: "Database connections",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connections"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.connections_used",
        title: "Database connections used",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.connections_used"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.refused",
        title: "Database connections refused at the limit",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.refused"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "database.oldest_transaction",
        title: "Database oldest transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.oldest_transaction_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.oldest_query",
        title: "Database oldest query",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.oldest_query_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.rollbacks",
        title: "Database rollbacks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.rollbacks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.deadlocks",
        title: "Database deadlocks",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.deadlocks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.cache_hit",
        title: "Database cache hit rate",
        unit: Unit::Percent,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.cache_hit"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.replica",
        title: "Database is a replica",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.replica"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "database.receiving",
        title: "Database replica receiving",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.receiving"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "database.lag",
        title: "Database replication lag",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.lag_secs"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.size",
        title: "Database size",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    // Only PostgreSQL has these.
    Metric {
        name: "postgres.active",
        title: "PostgreSQL active queries",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.active"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.idle_in_transaction",
        title: "PostgreSQL sessions idle in a transaction",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.idle_in_transaction"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.waiting_on_locks",
        title: "PostgreSQL sessions waiting on locks",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.waiting_on_locks"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.oldest_idle_in_transaction",
        title: "PostgreSQL longest idle in a transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.oldest_idle_in_transaction_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.transactions",
        title: "PostgreSQL transactions",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.transactions"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.temp_written",
        title: "PostgreSQL temporary files written",
        unit: Unit::BytesPerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.temp_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.conflicts",
        title: "PostgreSQL queries cancelled by replication",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.conflicts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.checksum_failures",
        title: "PostgreSQL checksum failures",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.checksum_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.checkpoints_timed",
        title: "PostgreSQL scheduled checkpoints",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.checkpoints_timed"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.checkpoints_requested",
        title: "PostgreSQL requested checkpoints",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.checkpoints_requested"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.wal_written",
        title: "PostgreSQL WAL written",
        unit: Unit::BytesPerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.wal_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.wal_size",
        title: "PostgreSQL WAL on disk",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.wal_size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.xid_age",
        title: "PostgreSQL oldest transaction ID age",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.xid_age"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.mxid_age",
        title: "PostgreSQL oldest multixact ID age",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.mxid_age"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.prepared",
        title: "PostgreSQL prepared transactions",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.prepared"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.oldest_prepared",
        title: "PostgreSQL oldest prepared transaction",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.oldest_prepared_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.standbys",
        title: "PostgreSQL standbys",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.standbys"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.synchronous_standbys",
        title: "PostgreSQL synchronous standbys",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.synchronous_standbys"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.lag_bytes",
        title: "PostgreSQL standby lag in bytes",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.lag_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.streaming",
        title: "PostgreSQL standby streaming",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.streaming"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.last_received",
        title: "PostgreSQL time since the replica heard from its primary",
        unit: Unit::Seconds,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.last_received_secs"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.replay_backlog",
        title: "PostgreSQL WAL received but not replayed",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.replay_backlog_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.replay_paused",
        title: "PostgreSQL replay paused",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.replay_paused"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.timeline",
        title: "PostgreSQL timeline",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.timeline"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.slot_in_use",
        title: "PostgreSQL replication slot in use",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.in_use"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.slot_retained",
        title: "PostgreSQL WAL kept by replication slots",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.retained_bytes"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.slot_headroom",
        title: "PostgreSQL WAL a slot can still keep",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.headroom_bytes"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.slot_lost",
        title: "PostgreSQL replication slot lost",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.lost"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.archive_failing",
        title: "PostgreSQL archiving failing",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.archive_failing"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.archive_waiting",
        title: "PostgreSQL WAL files waiting to be archived",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.archive_waiting"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "postgres.archived",
        title: "PostgreSQL WAL files archived",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.archived"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.archive_failures",
        title: "PostgreSQL archiving failures",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.archive_failures"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.subscription_running",
        title: "PostgreSQL subscription running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.running"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "postgres.subscription_errors",
        title: "PostgreSQL subscription errors",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.errors"),
        },
        chart: ShowChart::Never,
    },
    // Only MySQL and MariaDB have these, Galera's included.
    Metric {
        name: "mysql.threads_running",
        title: "MySQL queries running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.threads_running"),
        },
        chart: ShowChart::WithData,
    },
    Metric {
        name: "database.queries",
        title: "Database queries",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.queries"),
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
            reading: Reading::Rate("$.slow_queries"),
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
            reading: Reading::Rate("$.commits"),
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
            reading: Reading::Rate("$.aborted_connects"),
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
            reading: Reading::Rate("$.tmp_disk_tables"),
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
            reading: Reading::Field("$.pool_dirty"),
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
            reading: Reading::Rate("$.pool_waits"),
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
            reading: Reading::Field("$.lock_waits"),
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
            reading: Reading::Field("$.history_length"),
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
            reading: Reading::Field("$.open_transactions"),
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
            reading: Reading::Field("$.read_only"),
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
            reading: Reading::Field("$.super_read_only"),
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
            reading: Reading::Field("$.applying"),
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
            reading: Reading::Field("$.relay_log_bytes"),
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
            reading: Reading::Field("$.replication_errno"),
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
            reading: Reading::Field("$.semi_sync"),
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
            reading: Reading::Field("$.semi_sync_clients"),
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
            reading: Reading::Rate("$.semi_sync_misses"),
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
            reading: Reading::Field("$.group_members"),
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
            reading: Reading::Field("$.group_online"),
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
            reading: Reading::Field("$.member_online"),
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
            reading: Reading::Field("$.applier_queue"),
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
            reading: Reading::Field("$.certifier_queue"),
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
            reading: Reading::Rate("$.group_conflicts"),
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
            reading: Reading::Field("$.galera_primary"),
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
            reading: Reading::Field("$.galera_size"),
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
            reading: Reading::Field("$.galera_ready"),
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
            reading: Reading::Field("$.galera_connected"),
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
            reading: Reading::Field("$.galera_synced"),
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
            reading: Reading::Field("$.galera_receive_queue"),
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
            reading: Reading::Field("$.galera_send_queue"),
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
            reading: Reading::Rate("$.galera_cert_failures"),
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
            reading: Reading::Rate("$.galera_flow_paused"),
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
            reading: Reading::Field("$.binlog_size_bytes"),
        },
        chart: ShowChart::WithData,
    },
    // Only MongoDB has these.
    Metric {
        name: "mongodb.operations",
        title: "MongoDB operations",
        unit: Unit::PerSecond,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Rate("$.operations"),
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
            reading: Reading::Field("$.reads_latency_ms"),
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
            reading: Reading::Field("$.writes_latency_ms"),
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
            reading: Reading::Field("$.queued_reads"),
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
            reading: Reading::Field("$.queued_writes"),
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
            reading: Reading::Field("$.read_tickets"),
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
            reading: Reading::Field("$.write_tickets"),
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
            reading: Reading::Field("$.cache_used"),
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
            reading: Reading::Field("$.cache_dirty"),
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
            reading: Reading::Field("$.cursors_open"),
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
            reading: Reading::Rate("$.cursors_timed_out"),
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
            reading: Reading::Rate("$.asserts"),
        },
        chart: ShowChart::Never,
    },
    Metric {
        name: "mongodb.resident",
        title: "MongoDB memory in use",
        unit: Unit::Bytes,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.resident_bytes"),
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
            reading: Reading::Field("$.flow_control_lagged"),
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
            reading: Reading::Field("$.members"),
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
            reading: Reading::Field("$.members_healthy"),
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
            reading: Reading::Field("$.has_primary"),
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
            reading: Reading::Field("$.term"),
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
            reading: Reading::Field("$.majority_lag_secs"),
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
            reading: Reading::Field("$.member_healthy"),
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
            reading: Reading::Field("$.member_lag_secs"),
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
            reading: Reading::Field("$.oplog_window_secs"),
        },
        chart: ShowChart::WithData,
    },
    // Only ClickHouse has these.
    Metric {
        name: "clickhouse.running_queries",
        title: "ClickHouse queries running",
        unit: Unit::Number,
        collector: "databases",
        source: Source::Items {
            name: "$.name",
            reading: Reading::Field("$.running_queries"),
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
            reading: Reading::Field("$.queries_used"),
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
            reading: Reading::Field("$.preempted_queries"),
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
            reading: Reading::Field("$.interserver_connections"),
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
            reading: Reading::Rate("$.selects"),
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
            reading: Reading::Rate("$.inserts"),
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
            reading: Reading::Rate("$.failed_queries"),
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
            reading: Reading::Rate("$.failed_selects"),
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
            reading: Reading::Rate("$.failed_inserts"),
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
            reading: Reading::Field("$.latency_ms"),
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
            reading: Reading::Field("$.select_latency_ms"),
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
            reading: Reading::Field("$.insert_latency_ms"),
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
            reading: Reading::Rate("$.inserted_rows"),
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
            reading: Reading::Rate("$.inserted_bytes"),
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
            reading: Reading::Field("$.rows_per_insert"),
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
            reading: Reading::Field("$.max_parts_per_partition"),
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
            reading: Reading::Field("$.parts_used"),
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
            reading: Reading::Field("$.parts_total"),
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
            reading: Reading::Field("$.delayed_inserts"),
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
            reading: Reading::Rate("$.inserts_delayed"),
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
            reading: Reading::Rate("$.insert_delay_ms"),
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
            reading: Reading::Rate("$.rejected_inserts"),
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
            reading: Reading::Field("$.pending_async_inserts"),
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
            reading: Reading::Rate("$.failed_async_inserts"),
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
            reading: Reading::Field("$.async_queue_oldest_secs"),
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
            reading: Reading::Field("$.memory_bytes"),
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
            reading: Reading::Field("$.memory_used"),
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
            reading: Reading::Field("$.merge_memory_bytes"),
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
            reading: Reading::Rate("$.memory_limit_exceeded"),
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
            reading: Reading::Rate("$.overcommit_wait_ms"),
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
            reading: Reading::Field("$.merges_running"),
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
            reading: Reading::Field("$.pool_used"),
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
            reading: Reading::Field("$.pool_tasks"),
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
            reading: Reading::Field("$.mutations_pending"),
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
            reading: Reading::Field("$.mutations_failing"),
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
            reading: Reading::Rate("$.mutations_delayed"),
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
            reading: Reading::Rate("$.mutations_rejected"),
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
            reading: Reading::Field("$.dictionaries_failing"),
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
            reading: Reading::Field("$.detached_parts"),
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
            reading: Reading::Field("$.detached_broken"),
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
            reading: Reading::Field("$.backups_failed"),
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
            reading: Reading::Rate("$.error_count"),
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
            reading: Reading::Rate("$.buffer_flush_errors"),
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
            reading: Reading::Rate("$.slow_reads"),
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
            reading: Reading::Rate("$.read_failures"),
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
            reading: Reading::Rate("$.write_failures"),
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
            reading: Reading::Field("$.readonly_replicas"),
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
            reading: Reading::Field("$.replicated_tables"),
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
            reading: Reading::Field("$.readonly_tables"),
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
            reading: Reading::Field("$.expired_sessions"),
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
            reading: Reading::Field("$.tables_missing_replicas"),
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
            reading: Reading::Field("$.max_log_lag"),
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
            reading: Reading::Field("$.replication_queue"),
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
            reading: Reading::Field("$.max_replication_queue"),
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
            reading: Reading::Field("$.inserts_in_queue"),
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
            reading: Reading::Field("$.max_merges_in_queue"),
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
            reading: Reading::Field("$.max_future_parts"),
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
            reading: Reading::Field("$.max_parts_to_check"),
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
            reading: Reading::Field("$.oldest_queue_entry_secs"),
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
            reading: Reading::Field("$.queue_stuck"),
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
            reading: Reading::Field("$.queue_failing"),
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
            reading: Reading::Field("$.queue_update_errors"),
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
            reading: Reading::Field("$.relative_lag_secs"),
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
            reading: Reading::Rate("$.lost_parts"),
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
            reading: Reading::Field("$.fetches_running"),
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
            reading: Reading::Field("$.longest_fetch_secs"),
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
            reading: Reading::Rate("$.failed_fetches"),
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
            reading: Reading::Rate("$.failed_part_checks"),
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
            reading: Reading::Rate("$.data_loss"),
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
            reading: Reading::Rate("$.merge_differs"),
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
            reading: Reading::Rate("$.mutation_differs"),
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
            reading: Reading::Rate("$.partial_shutdowns"),
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
            reading: Reading::Field("$.distributed_files"),
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
            reading: Reading::Field("$.distributed_bytes"),
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
            reading: Reading::Field("$.distributed_broken_files"),
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
            reading: Reading::Rate("$.distributed_retries"),
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
            reading: Reading::Rate("$.distributed_failures"),
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
            reading: Reading::Rate("$.distributed_rejected"),
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
            reading: Reading::Rate("$.distributed_insert_failures"),
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
            reading: Reading::Field("$.distribution_blocked"),
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
            reading: Reading::Field("$.distribution_errors"),
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
            reading: Reading::Field("$.cluster_errors"),
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
            reading: Reading::Field("$.keeper_connected"),
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
            reading: Reading::Field("$.keeper_session_secs"),
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
            reading: Reading::Field("$.keeper_sessions"),
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
            reading: Reading::Field("$.keeper_sessions_expired"),
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
            reading: Reading::Field("$.keeper_requests"),
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
            reading: Reading::Field("$.keeper_latency_ms"),
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
            reading: Reading::Rate("$.keeper_hardware_errors"),
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
            reading: Reading::Rate("$.keeper_user_errors"),
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
            reading: Reading::Field("$.keeper_leader"),
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
            reading: Reading::Field("$.keeper_synced_followers"),
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
            reading: Reading::Field("$.keeper_memory_limit_hit"),
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
            reading: Reading::Field("$.keeper_clients"),
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
            reading: Reading::Field("$.keeper_outstanding"),
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
            reading: Reading::Field("$.disk_free_bytes"),
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
            reading: Reading::Field("$.disk_used"),
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
            reading: Reading::Field("$.disk_broken"),
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
            reading: Reading::Field("$.disk_read_only"),
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
            reading: Reading::Field("$.p50_ms"),
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
            reading: Reading::Field("$.p95_ms"),
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
            reading: Reading::Field("$.p99_ms"),
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
            reading: Reading::Field("$.failed_5m"),
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
        name: "commands.status",
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
        name: "commands.ok",
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
        name: "commands.value",
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
        name: "counters.value",
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
        name: "counters.ok",
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
    pub host_id: &'a str,
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
    pub host_id: String,
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
    pub host_id: String,
    pub series: String,
    pub time_ms: i64,
    pub value: f64,
}

/// Which way a series has been heading: its newest value, and the slope of the
/// straight line that fits its readings best.
#[derive(Debug, Clone, PartialEq)]
pub struct Trend {
    pub host_id: String,
    pub series: String,
    /// The newest reading.
    pub time_ms: i64,
    pub value: f64,
    /// The oldest reading, so a line through a few minutes isn't trusted for days.
    pub first_ms: i64,
    pub samples: u64,
    /// How much the value changes each millisecond.
    pub slope_per_ms: f64,
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
        .map(|sample| {
            let values = CurrentValues {
                time_ms: sample.time_ms,
                ..CurrentValues::default()
            };
            (sample.host_id, values)
        })
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
    pub async fn newest(&self, metric: &'static Metric, now_ms: i64) -> Result<Vec<NewestReading>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            reader.newest(metric, now_ms - CURRENT_WINDOW_MS, now_ms + CLOCK_SKEW_MS)
        })
        .await
        .context("reading metrics")?
    }

    /// Which way each series of a metric has been heading between two times,
    /// across every agent.
    pub async fn trends(
        &self,
        metric: &'static Metric,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Vec<Trend>> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || reader.trends(metric, since_ms, until_ms))
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
        host_id: &str,
        collector: &str,
        now_ms: i64,
    ) -> Result<Option<Value>> {
        let reader = self.reader.clone();
        let (host_id, collector) = (host_id.to_string(), collector.to_string());
        tokio::task::spawn_blocking(move || {
            reader.latest_output(
                &host_id,
                &collector,
                now_ms - CURRENT_WINDOW_MS,
                now_ms + CLOCK_SKEW_MS,
            )
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

    fn reading(host_id: &str, series: &str, value: f64) -> NewestReading {
        NewestReading {
            host_id: host_id.to_string(),
            series: series.to_string(),
            time_ms: 1,
            value,
        }
    }

    fn last(host_id: &str, time_ms: i64) -> LastSample {
        LastSample {
            host_id: host_id.to_string(),
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
