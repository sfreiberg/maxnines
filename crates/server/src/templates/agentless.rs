//! What the server reads for templates on hosts with no agent, from each database
//! check that reads stats, as an agent reads the databases its config has. The
//! check's name is the database's, and its kind decides which database templates
//! are for it, as long as the template is for the host too.
//!
//! It's worked out the same way as an agent's work, with the same limits, read
//! with the same reader agents use, and what's read is saved as a sample from the
//! check's host each time the check runs, after what discovery found is taken out
//! and kept, and each template's `value` metrics are worked out, as for an agent's.
//! What's read changes when templates, the checks or what discovery found change,
//! and at least once a minute, for a change of the host's facts.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use maxnines_checks::databases::{self as stats, is_database};
use maxnines_checks::templates::reader::{Reader, Results};
use maxnines_protocol::Sample;
use maxnines_protocol::templates::work::{DISCOVERED, Discovered, TemplateWork};
use serde_json::{Map, Value};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tracing::warn;

use super::hosts::{DatabaseKinds, RunningTemplates};
use super::values::{LastSent, QueryValues, strip_queries, work_out};
use super::work::{Discoveries, work_for};
use crate::facts::{FlatFacts, unflatten};
use crate::models::Database;
use crate::remote_checks::RemoteCheck;
use crate::rule_engine::Host;
use crate::store::{NewSample, WriterCommand};
use crate::times;

/// How long what's read is kept without being worked out again, so a change of a
/// host's facts, which nothing else says, is seen.
const REWORK_EVERY: Duration = Duration::from_secs(60);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one database check has read for templates.
struct CheckReads {
    reader: Reader,
    /// What it reads now.
    sent: Arc<Mutex<Vec<TemplateWork>>>,
    /// When each series of a template's rows was last saved, for rates.
    last_sent: Arc<Mutex<LastSent>>,
}

/// A check that reads a database's stats, as what it reads is worked out from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReadCheck {
    id: i64,
    host_id: String,
    name: String,
    /// What kind of database it is.
    kind: &'static str,
}

/// What was worked out, and what from.
struct Worked {
    templates: Arc<RunningTemplates>,
    discoveries: Arc<BTreeMap<String, Discoveries>>,
    checks: Vec<ReadCheck>,
    at: Instant,
    /// By check ID.
    work: HashMap<i64, Vec<TemplateWork>>,
}

/// What templates have the server read on hosts with no agent.
#[derive(Default)]
pub struct AgentlessTemplates {
    /// By check ID.
    checks: HashMap<i64, CheckReads>,
    worked: Option<Worked>,
}

impl AgentlessTemplates {
    /// Reads what templates have read through `checks`, those on `agentless`
    /// hosts, by ID, that read a database's stats, and stops what isn't read any
    /// more.
    pub async fn keep(
        &mut self,
        database: &Database,
        checks: &[RemoteCheck],
        agentless: &BTreeMap<String, String>,
    ) -> Result<()> {
        let reading: Vec<&RemoteCheck> = checks
            .iter()
            .filter(|check| {
                check.input.enabled
                    && check.input.read_stats
                    && is_database(check.input.check.kind)
                    && agentless.contains_key(&check.input.host_id)
            })
            .collect();
        let mut read: Vec<ReadCheck> = reading
            .iter()
            .map(|check| ReadCheck {
                id: check.id,
                host_id: check.input.host_id.clone(),
                name: check.input.check.name.clone(),
                kind: check.input.check.kind.as_str(),
            })
            .collect();
        read.sort();
        let templates = database.running_templates();
        let discoveries = database.all_discoveries().await?;
        let current = self.worked.as_ref().is_some_and(|worked| {
            Arc::ptr_eq(&worked.templates, &templates)
                && Arc::ptr_eq(&worked.discoveries, &discoveries)
                && worked.checks == read
                && worked.at.elapsed() < REWORK_EVERY
        });
        if !current {
            let before: BTreeSet<String> = self
                .worked
                .as_ref()
                .map(|worked| worked.checks.iter().map(|c| c.host_id.clone()).collect())
                .unwrap_or_default();
            let work = work_out_all(database, &templates, &discoveries, &read, before).await?;
            self.worked = Some(Worked {
                templates,
                discoveries,
                checks: read,
                at: Instant::now(),
                work,
            });
        }
        let Some(worked) = &self.worked else {
            return Ok(());
        };

        let ids: BTreeSet<i64> = reading.iter().map(|check| check.id).collect();
        self.checks.retain(|id, _| ids.contains(id));
        let runtime = Handle::current();
        for check in reading {
            let work = worked.work.get(&check.id).cloned().unwrap_or_default();
            let reads = self.checks.entry(check.id).or_insert_with(|| CheckReads {
                reader: Reader::new(),
                sent: Arc::default(),
                last_sent: Arc::default(),
            });
            // A login that can't be had now is down until it can.
            reads
                .reader
                .update(&work, check.input.interval, &runtime, |_| {
                    let credentials = check
                        .input
                        .sign_in
                        .credentials()
                        .map_err(|why| anyhow!(why))?;
                    Ok(stats::Database {
                        check: check.input.check.clone(),
                        credentials: credentials.unwrap_or_default(),
                    })
                });
            *lock(&reads.sent) = work;
        }
        Ok(())
    }

    /// What a check has read for templates, to save when it runs, if it reads any.
    pub fn reads(&self, check_id: i64) -> Option<ReadSoFar> {
        let reads = self.checks.get(&check_id)?;
        Some(ReadSoFar {
            results: reads.reader.results(),
            sent: reads.sent.clone(),
            last_sent: reads.last_sent.clone(),
        })
    }
}

/// Works out what each check reads, by check ID, from what templates there are and
/// what discovery found, and forgets what discovery found for anything not read
/// any more, on these hosts or those read `before`.
async fn work_out_all(
    database: &Database,
    templates: &RunningTemplates,
    discoveries: &BTreeMap<String, Discoveries>,
    read: &[ReadCheck],
    before: BTreeSet<String>,
) -> Result<HashMap<i64, Vec<TemplateWork>>> {
    let mut by_host: BTreeMap<&str, Vec<&ReadCheck>> = BTreeMap::new();
    for check in read {
        by_host.entry(&check.host_id).or_default().push(check);
    }
    let mut work = HashMap::new();
    let empty = Discoveries::new();
    for (host_id, checks) in &by_host {
        let facts: FlatFacts = database
            .current_facts(host_id)
            .await?
            .into_iter()
            .map(|fact| (fact.name, fact.value))
            .collect();
        let facts = unflatten(&facts);
        let host = Host::new(&facts, host_id);
        let databases: DatabaseKinds = checks
            .iter()
            .map(|check| (check.name.clone(), check.kind.to_string()))
            .collect();
        let found = discoveries.get(*host_id).unwrap_or(&empty);
        let all = work_for(templates, &host, &databases, found);
        forget_others(database, host_id, &all).await;
        for check in checks {
            let mine: Vec<TemplateWork> = all
                .iter()
                .filter(|one| one.database.as_deref() == Some(check.name.as_str()))
                .cloned()
                .collect();
            work.insert(check.id, mine);
        }
    }
    // A host read before and not now has nothing read.
    for host_id in before {
        if !by_host.contains_key(host_id.as_str()) {
            forget_others(database, &host_id, &[]).await;
        }
    }
    Ok(work)
}

/// Forgets what discovery found on a host for anything not in `work`.
async fn forget_others(database: &Database, host_id: &str, work: &[TemplateWork]) {
    let reads: Vec<(String, String)> = work
        .iter()
        .filter_map(|one| Some((one.template.clone(), one.database.clone()?)))
        .collect();
    if let Err(error) = database.forget_discovered(host_id, &reads).await {
        warn!(
            host_id,
            error = format!("{error:#}"),
            "forgetting what discovery found failed"
        );
    }
}

/// What one check has read for templates since it last ran.
pub struct ReadSoFar {
    results: Results,
    sent: Arc<Mutex<Vec<TemplateWork>>>,
    last_sent: Arc<Mutex<LastSent>>,
}

impl ReadSoFar {
    /// Saves what's been read as a sample from the check's host, keeping what
    /// discovery found apart, as an agent's sample would be.
    pub async fn save(self, to: Saving<'_>) {
        let templates = to.database.running_templates();
        let entries = self.results.take();
        save_read(
            entries,
            &self.sent,
            &self.last_sent,
            templates.worked_out(),
            to,
        )
        .await;
    }
}

/// Where what's read is saved: as samples from a host, by its ID and name.
pub struct Saving<'a> {
    pub database: &'a Database,
    pub writer: &'a mpsc::Sender<WriterCommand>,
    pub host_id: String,
    pub hostname: String,
}

/// Saves what's been read, as a sample's `entries`, from a host: what discovery
/// found for what's still read, by `sent`, is kept with the host, and the rest is
/// saved as its metrics, with the `value` metrics of `values` worked out.
pub async fn save_read(
    entries: Map<String, Value>,
    sent: &Mutex<Vec<TemplateWork>>,
    last_sent: &Mutex<LastSent>,
    values: &[QueryValues],
    to: Saving<'_>,
) {
    if entries.is_empty() {
        return;
    }
    let Saving {
        database,
        writer,
        host_id,
        hostname,
    } = to;
    let mut sample = Sample {
        time: times::now(),
        metrics: entries.into_iter().collect(),
    };
    if let Some(found) = sample.metrics.remove(DISCOVERED) {
        match serde_json::from_value::<Vec<Discovered>>(found) {
            Ok(mut found) => {
                // Only for what's still read, as what's read may have changed.
                {
                    let sent = lock(sent);
                    found.retain(|one| {
                        sent.iter().any(|work| {
                            work.template == one.template
                                && work.database.as_deref() == Some(one.database.as_str())
                        })
                    });
                }
                if let Err(error) = database
                    .save_discovered(&host_id, &found, sample.time)
                    .await
                {
                    warn!(
                        host_id,
                        error = format!("{error:#}"),
                        "saving what discovery found failed"
                    );
                }
            }
            Err(error) => warn!(host_id, %error, "skipping what discovery found"),
        }
    }
    if !values.is_empty() {
        work_out(&mut sample, values, &lock(sent), &mut lock(last_sent));
    }
    strip_queries(&mut sample);
    let command = WriterCommand::Save(NewSample {
        host_id,
        hostname,
        sample,
    });
    if writer.send(command).await.is_err() {
        warn!("the metrics writer has stopped, so what templates read was dropped");
    }
}
