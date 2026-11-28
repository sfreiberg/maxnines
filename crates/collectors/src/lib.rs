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

    /// The metrics it reads here. Each has the error when collecting failed, and
    /// what [`Collector::entries`] says of it otherwise. A collector's own, as
    /// templates' are named by the config, so they aren't known until it's built.
    fn metrics(&self) -> Vec<String> {
        Vec::new()
    }

    /// What one reading said, as entries under its metrics' names, all read at
    /// `time`: what [`Collector::collect`] returned, or one result of a collector
    /// that reads on its own schedule. A metric the reading looked for and found
    /// nothing for has an entry saying so.
    fn entries(&self, _output: &Value, _time: DateTime<Utc>) -> Vec<Entry> {
        Vec::new()
    }

    /// What it has read since it was last asked, each entry with the time it was
    /// read, and none twice. A collector that reads when asked reads now, at
    /// `time`. One that reads on its own schedule hands over what it has finished
    /// since, with the time each was finished, and nothing when that's nothing.
    fn read(&mut self, time: DateTime<Utc>) -> Result<Vec<Entry>> {
        let output = self.collect()?;
        // Nothing yet, which isn't the same as finding nothing.
        if output.is_null() {
            return Ok(Vec::new());
        }
        Ok(self.entries(&output, time))
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

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use serde_json::json;

    use super::*;
    use crate::entries::testing::{said, time};
    use crate::entries::{Entries, names};

    /// Gives what it's told to, as a collector that reads when asked.
    struct Told(Option<Value>);

    impl Collector for Told {
        fn name(&self) -> &'static str {
            "told"
        }

        fn collect(&mut self) -> Result<Value> {
            match &self.0 {
                Some(output) => Ok(output.clone()),
                None => bail!("couldn't read it"),
            }
        }

        fn metrics(&self) -> Vec<String> {
            names(&["told.count"])
        }

        fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
            let mut entries = Entries::at(time);
            entries.read("told.count", &[], &output["count"]);
            entries.done()
        }
    }

    #[test]
    fn reading_gives_the_entries_of_what_was_just_collected() {
        let read = Told(Some(json!({ "count": 3 }))).read(time()).unwrap();
        assert_eq!(said(&read), [("told.count".to_string(), json!(3))]);
        // Looked and found nothing, which is said.
        let read = Told(Some(json!({}))).read(time()).unwrap();
        assert_eq!(said(&read), [("told.count".to_string(), Value::Null)]);
    }

    /// Nothing yet isn't the same as finding nothing, which would end every error
    /// and series the metric has.
    #[test]
    fn a_collector_with_nothing_yet_has_no_entries() {
        assert_eq!(Told(Some(Value::Null)).read(time()).unwrap(), []);
    }

    #[test]
    fn a_collection_that_failed_is_an_error_to_whoever_asked() {
        let error = Told(None).read(time()).unwrap_err();
        assert_eq!(error.to_string(), "couldn't read it");
    }
}
