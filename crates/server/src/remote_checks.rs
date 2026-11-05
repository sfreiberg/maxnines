//! Checks the server runs itself, against remote sites, with the same code agents
//! use. Results are saved as samples from a built-in agent, so charts and alert
//! rules treat them like anything else.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use crate::store::WriterCommand;

/// The built-in agent's ID. See the migration that creates it.
pub const LOCAL_AGENT_ID: &str = "server";

const LOCAL_HOST: &str = "MaxNines server";

/// How often to look for checks that are due.
const TICK: Duration = Duration::from_secs(5);

const MIN_INTERVAL_SECS: u64 = 10;
const MAX_INTERVAL_SECS: u64 = 86_400;

/// How many checks run at once. Each holds a thread, and anything over this waits.
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
    pub check: Check,
    /// How often it runs.
    pub interval_secs: u64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

pub fn check_input(input: &RemoteCheckInput) -> Result<()> {
    input.check.validate()?;
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
    results: Arc<LatestResults>,
    slots: Arc<Semaphore>,
    /// When each check is next due, by ID.
    next_run: HashMap<i64, i64>,
}

impl Scheduler {
    pub fn new(
        database: Database,
        writer: mpsc::Sender<WriterCommand>,
        results: Arc<LatestResults>,
    ) -> Self {
        Self {
            database,
            writer,
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

        let mut started = Vec::new();
        for check in &checks {
            let input = &check.input;
            let due = *self.next_run.get(&check.id).unwrap_or(&now_ms);
            if !input.enabled || due > now_ms {
                continue;
            }
            let interval_ms = i64::try_from(input.interval_secs)?.saturating_mul(1000);
            self.next_run.insert(check.id, now_ms + interval_ms);
            started.push(self.start(input.check.clone()));
        }
        Ok(started)
    }

    fn start(&self, check: Check) -> JoinHandle<()> {
        let (slots, writer) = (self.slots.clone(), self.writer.clone());
        let results = self.results.clone();
        tokio::spawn(async move {
            let Ok(_slot) = slots.acquire_owned().await else {
                return;
            };
            let name = check.name.clone();
            let finished = tokio::task::spawn_blocking(move || maxnines_checks::run(&check)).await;
            let Ok(result) = finished else {
                error!(check = name, "a check panicked");
                return;
            };
            results.set(&name, result.clone());
            save(&writer, result).await;
        })
    }
}

async fn save(writer: &mpsc::Sender<WriterCommand>, result: Value) {
    let sample = Sample {
        timestamp_ms: now_ms() as u64,
        metrics: BTreeMap::from([("checks".to_string(), json!([result]))]),
    };
    let command = WriterCommand::Save {
        agent_id: LOCAL_AGENT_ID.to_string(),
        host: LOCAL_HOST.to_string(),
        sample,
    };
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
