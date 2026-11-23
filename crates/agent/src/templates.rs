//! Reads what templates have this agent read: for each database a template runs
//! for, its discover blocks and queries, as the server worked them out for this
//! host, and on Windows, for a template that runs once on the host, its registry
//! values, counter sets and performance counters. How databases are read is in
//! [`maxnines_checks::templates::reader`], which the server shares for hosts with
//! no agent: a task for each database, on the background runtime. How the host is
//! read is in [`maxnines_collectors::host_templates`], as each sample is taken. A
//! sample takes what's been read since the last one.
//!
//! A new config changes each database's task only as much as its work changed: one
//! whose work is the same carries on, and one whose work changed keeps its
//! connection, what it found, and the running totals of each query whose SQL is
//! the same. A template on the host keeps its counters, and their running totals,
//! for each counters block that's the same.

use std::time::Duration;

use anyhow::Result;
use maxnines_checks::templates::reader::{Reader, Results};
use maxnines_collectors::host_templates::HostTemplates;
use maxnines_protocol::templates::work::{DISCOVERED, TemplateWork, collector_of};
use serde_json::{Value, json};

use crate::background::runtime;
use crate::collector::Collector;
use crate::databases::DatabaseDefinitions;

pub struct TemplateCollector {
    reader: Reader,
    results: Results,
    host: HostTemplates,
    /// How often a sample is taken.
    interval: Duration,
}

impl TemplateCollector {
    /// Starts reading `work`, each query every `interval` unless it says. A database
    /// the agent's config doesn't define is reported as down.
    pub fn new(
        work: &[TemplateWork],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Result<Self> {
        let reader = Reader::new();
        let mut collector = Self {
            results: reader.results(),
            reader,
            host: HostTemplates::default(),
            interval,
        };
        collector.update(work, definitions, interval)?;
        Ok(collector)
    }

    /// Changes what's read to `work`: a database's task whose work is the same
    /// carries on, one whose work changed is told, and the rest stop or start. If
    /// it fails, nothing has changed.
    pub fn update(
        &mut self,
        work: &[TemplateWork],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Result<()> {
        let runtime = runtime()?;
        self.interval = interval;
        self.host.update(work);
        self.reader.update(work, interval, &runtime, |name| {
            definitions
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("the agent's config has no database by that name"))
                .and_then(|definition| definition.database(name))
        });
        Ok(())
    }
}

impl Collector for TemplateCollector {
    fn name(&self) -> &'static str {
        "templates"
    }

    fn spreads(&self) -> bool {
        true
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn collect(&mut self) -> Result<Value> {
        let mut entries = self.results.take();
        let host = self.host.collect(self.interval);
        for (template, rows) in host.rows {
            let read = entries
                .entry(collector_of(&template))
                .or_insert_with(|| json!([]));
            if let Value::Array(all) = read {
                all.extend(rows);
            }
        }
        if !host.discovered.is_empty() {
            let found = entries.entry(DISCOVERED).or_insert_with(|| json!([]));
            if let Value::Array(all) = found {
                all.extend(
                    host.discovered
                        .into_iter()
                        .filter_map(|one| serde_json::to_value(one).ok()),
                );
            }
        }
        Ok(match entries.is_empty() {
            // Nothing read yet.
            true => Value::Null,
            false => Value::Object(entries),
        })
    }
}

#[cfg(test)]
mod tests {
    use maxnines_protocol::templates::work::DiscoverWork;

    use super::*;

    // How databases are read is tested with the reader, in maxnines_checks.

    #[test]
    fn a_database_the_config_does_not_define_is_down() {
        let work = TemplateWork {
            template: "pg".to_string(),
            database: Some("nowhere".to_string()),
            discover: vec![DiscoverWork {
                key: "server".to_string(),
                interval: Duration::from_secs(3600),
                sql: Some("SELECT 1 AS one".to_string()),
                registry: Vec::new(),
                counter_sets: Default::default(),
            }],
            queries: Vec::new(),
            counters: Vec::new(),
        };
        let mut collector =
            TemplateCollector::new(&[work], &DatabaseDefinitions::new(), Duration::from_secs(1))
                .unwrap();
        let output = collector.collect().unwrap();
        assert_eq!(
            output["template.pg"],
            json!([{ "labels": { "instance": "nowhere" }, "up": 0 }])
        );
        assert!(output.get(DISCOVERED).is_none());
    }
}
