//! Reading what a host is doing, for anything that runs on one.

pub mod counters;
pub mod disk_activity;
pub mod entries;
pub mod failed_services;
mod file_systems;
#[cfg(target_os = "macos")]
pub mod gpu;
pub mod host;
pub mod host_templates;
pub mod interface_drops;
pub mod system;
pub mod tcp;
pub mod time_sync;
#[cfg(windows)]
mod windows_text;

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use maxnines_protocol::entries::Entry;
use serde_json::Value;

/// How long to wait after building collectors before the first sample.
/// CPU usage is measured between two refreshes, so it needs this gap.
pub const WARMUP: Duration = sysinfo::MINIMUM_CPU_UPDATE_INTERVAL;

/// A source of metrics. Implementations keep state between calls because
/// CPU usage and network deltas are measured against the previous sample.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> Result<Value>;

    /// The metrics it reads here, each of which has an entry from every collection:
    /// what [`Collector::entries`] says of it, or the error when collecting failed.
    fn metrics(&self) -> &'static [&'static str] {
        &[]
    }

    /// What it collected, as entries under its metrics' names, all read at `time`.
    /// A metric it has nothing for has an entry saying so.
    fn entries(&self, _output: &Value, _time: DateTime<Utc>) -> Vec<Entry> {
        Vec::new()
    }

    /// Whether what it collects is a map whose entries each go into the sample
    /// under their own names, rather than all of it under its name, as templates'
    /// rows go under each template's.
    fn spreads(&self) -> bool {
        false
    }

    /// It, as what it is, for a collector a new config changes in place rather than
    /// building again.
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}
