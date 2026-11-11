//! Reading what a machine is doing, for anything that runs on one.

pub mod counters;
pub mod disk_activity;
pub mod failed_services;
mod file_systems;
pub mod interface_drops;
pub mod machine;
pub mod system;
pub mod tcp;

use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

/// How long to wait after building collectors before the first sample.
/// CPU usage is measured between two refreshes, so it needs this gap.
pub const WARMUP: Duration = sysinfo::MINIMUM_CPU_UPDATE_INTERVAL;

/// A source of metrics. Implementations keep state between calls because
/// CPU usage and network deltas are measured against the previous sample.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> Result<Value>;
}
