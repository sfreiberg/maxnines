//! Checks the server runs itself, against remote sites, with the same code agents
//! use. Each is about a host: one with no agent, or the server itself, which is
//! a built-in host. Results are saved as samples from that host, so charts and
//! alert rules treat them like anything else.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, ensure};
use maxnines_protocol::{Check, Sample};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::metrics::now_ms;
use crate::models::Database;
use crate::presence::{Presence, Reached};
use crate::registration::{HostState, Registry};
use crate::store::{NewSample, WriterCommand};

/// The built-in agent's ID. See the migration that creates it.
pub const LOCAL_HOST_ID: &str = "server";

pub const LOCAL_HOSTNAME: &str = "MaxNines server";
/// The built-in agent alerts about a group of hosts belong to.
pub const FLEET_HOST_ID: &str = "fleet";
pub const FLEET_HOSTNAME: &str = "Fleet";

/// How often to look for checks that are due.
const TICK: Duration = Duration::from_secs(5);

const MIN_INTERVAL_SECS: u64 = 10;
const MAX_INTERVAL_SECS: u64 = 86_400;

/// How many checks run at once. Anything over this waits its turn.
const MAX_RUNNING: usize = 32;

/// A check the server runs, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCheck {
    pub id: i64,
    #[serde(flatten)]
    pub input: RemoteCheckInput,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCheckInput {
    /// The host it's about. Left out, it's the server itself.
    #[serde(default = "local_host_id")]
    pub host_id: String,
    pub check: Check,
    /// How often it runs.
    pub interval_secs: u64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

fn local_host_id() -> String {
    LOCAL_HOST_ID.to_string()
}

pub fn check_input(input: &RemoteCheckInput) -> Result<()> {
    input.check.validate()?;
    ensure!(
        input.check.interval_secs.is_none(),
        "a remote check's interval goes beside the check, as interval_secs"
    );
    ensure!(
        (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&input.interval_secs),
        "the interval has to be from {MIN_INTERVAL_SECS} to {MAX_INTERVAL_SECS} seconds"
    );
    Ok(())
}

/// How each check last went, by name. Only kept in memory, as the history is in
/// the metrics store and this refills within one interval.
#[derive(Default)]
pub struct LatestResults {
    results: Mutex<BTreeMap<String, Value>>,
}

impl LatestResults {
    fn set(&self, name: &str, result: Value) {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.insert(name.to_string(), result);
    }

    /// Forgets checks that no longer exist.
    fn keep_only(&self, names: &BTreeSet<&str>) {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.retain(|name, _| names.contains(name.as_str()));
    }

    pub fn all(&self) -> BTreeMap<String, Value> {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub struct Scheduler {
    database: Database,
    writer: mpsc::Sender<WriterCommand>,
    registry: Arc<Registry>,
    presence: Arc<Presence>,
    results: Arc<LatestResults>,
    slots: Arc<Semaphore>,
    /// When each check is next due, by ID.
    next_run: HashMap<i64, i64>,
}

impl Scheduler {
    pub fn new(
        database: Database,
        writer: mpsc::Sender<WriterCommand>,
        registry: Arc<Registry>,
        presence: Arc<Presence>,
        results: Arc<LatestResults>,
    ) -> Self {
        Self {
            database,
            writer,
            registry,
            presence,
            results,
            slots: Arc::new(Semaphore::new(MAX_RUNNING)),
            next_run: HashMap::new(),
        }
    }

    /// Runs until the server stops. A database failure skips one tick.
    pub fn spawn(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(TICK);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                if let Err(error) = self.start_due(now_ms()).await {
                    error!(error = format!("{error:#}"), "starting checks failed");
                }
            }
        })
    }

    /// Starts everything that's due, without waiting for any of it, and returns
    /// what it started so that tests can wait for them. A check that panics only
    /// loses its own run.
    pub async fn start_due(&mut self, now_ms: i64) -> Result<Vec<JoinHandle<()>>> {
        let checks = self.database.list_remote_checks().await?;
        let names: BTreeSet<&str> = checks
            .iter()
            .map(|check| check.input.check.name.as_str())
            .collect();
        self.results.keep_only(&names);

        // A host with no agent is as present as its checks and pages say.
        let agentless: BTreeMap<String, String> = self
            .registry
            .list()
            .await
            .into_iter()
            .filter(|host| host.is_agentless() && host.state == HostState::Approved)
            .map(|host| (host.id, host.hostname))
            .collect();
        let about_hosts: HashSet<i64> = checks
            .iter()
            .filter(|check| check.input.enabled && agentless.contains_key(&check.input.host_id))
            .map(|check| check.id)
            .collect();
        self.presence.keep_checks(&about_hosts);

        let mut started = Vec::new();
        for check in checks {
            let due = *self.next_run.get(&check.id).unwrap_or(&now_ms);
            if !check.input.enabled || due > now_ms {
                continue;
            }
            let hostname = match agentless.get(&check.input.host_id) {
                Some(hostname) => hostname.clone(),
                None if check.input.host_id == LOCAL_HOST_ID => LOCAL_HOSTNAME.to_string(),
                // Its host isn't one the server runs checks for any more.
                None => continue,
            };
            let interval_ms = i64::try_from(check.input.interval_secs)?.saturating_mul(1000);
            self.next_run.insert(check.id, now_ms + interval_ms);
            started.push(self.start(check, hostname));
        }
        Ok(started)
    }

    fn start(&self, check: RemoteCheck, hostname: String) -> JoinHandle<()> {
        let (slots, writer) = (self.slots.clone(), self.writer.clone());
        let (results, presence) = (self.results.clone(), self.presence.clone());
        tokio::spawn(async move {
            let Ok(_slot) = slots.acquire_owned().await else {
                return;
            };
            let host_id = check.input.host_id;
            let result = maxnines_checks::run(&check.input.check).await;
            results.set(&check.input.check.name, result.clone());
            if host_id != LOCAL_HOST_ID {
                presence.reached(&host_id, Reached::Check(check.id), result["up"] == 1);
            }
            save(&writer, host_id, hostname, result).await;
        })
    }
}

async fn save(
    writer: &mpsc::Sender<WriterCommand>,
    host_id: String,
    hostname: String,
    result: Value,
) {
    let sample = Sample {
        timestamp_ms: now_ms() as u64,
        metrics: BTreeMap::from([("checks".to_string(), json!([result]))]),
    };
    let command = WriterCommand::Save(NewSample {
        host_id,
        hostname,
        sample,
    });
    if writer.send(command).await.is_err() {
        warn!("the metrics writer has stopped, so a check result was dropped");
    }
}

#[cfg(test)]
mod tests {
    use maxnines_protocol::CheckKind;

    use super::*;

    fn input(interval_secs: u64) -> RemoteCheckInput {
        RemoteCheckInput {
            host_id: crate::remote_checks::LOCAL_HOST_ID.to_string(),
            check: Check::new("a", CheckKind::Tcp, "example.com:80"),
            interval_secs,
            enabled: true,
        }
    }

    #[test]
    fn intervals_are_limited() {
        check_input(&input(60)).unwrap();
        check_input(&input(MIN_INTERVAL_SECS)).unwrap();
        assert!(check_input(&input(MIN_INTERVAL_SECS - 1)).is_err());
        assert!(check_input(&input(MAX_INTERVAL_SECS + 1)).is_err());

        // Only one place says how often it runs.
        let mut inside = input(60);
        inside.check.interval_secs = Some(300);
        assert!(check_input(&inside).is_err());
    }

    #[test]
    fn the_check_itself_is_validated() {
        let mut bad = input(60);
        bad.check.target = "no port".to_string();
        assert!(check_input(&bad).is_err());
    }

    #[test]
    fn results_for_deleted_checks_are_forgotten() {
        let results = LatestResults::default();
        results.set("a", json!(1));
        results.set("b", json!(2));
        results.keep_only(&BTreeSet::from(["b"]));
        assert_eq!(results.all().len(), 1);
        assert_eq!(results.all()["b"], 2);
    }
}
