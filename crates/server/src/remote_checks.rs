//! Checks the server runs itself, against remote sites, with the same code agents
//! use. Each is about a host: one with no agent, or the server itself, which is
//! a built-in host. Results are saved as samples from that host, so charts and
//! alert rules treat them like anything else.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use maxnines_checks::Credentials;
use maxnines_protocol::{Check, CheckKind, Sample};
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
    /// How a check that signs in does so. Its secrets can be set, but are never
    /// shown or given back.
    #[serde(flatten)]
    pub sign_in: SignIn,
}

/// How a check signs in: a username, and a password or, for SSH, a private key,
/// each typed in or named as an environment variable of the server's.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SignIn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
    /// In OpenSSH's format, without a passphrase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_env: Option<String>,
}

impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn")
            .field("username", &self.username)
            .field("password_env", &self.password_env)
            .field("private_key_env", &self.private_key_env)
            .finish_non_exhaustive()
    }
}

/// How a check signs in, as a form or a request says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInWith {
    None,
    Password,
    Key,
}

impl SignInWith {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Password => "password",
            Self::Key => "key",
        }
    }
}

/// The longest private key kept, which fits a 16,384-bit RSA key.
const MAX_KEY_LEN: usize = 16_384;
const MAX_PASSWORD_LEN: usize = 1024;
const MAX_USERNAME_LEN: usize = 255;

impl SignIn {
    /// How it signs in, going by what it has.
    pub fn with(&self) -> SignInWith {
        if self.private_key.is_some() || self.private_key_env.is_some() {
            SignInWith::Key
        } else if self.username.is_some() || self.password.is_some() || self.password_env.is_some()
        {
            SignInWith::Password
        } else {
            SignInWith::None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.with() == SignInWith::None
    }

    /// Keeps the password or key a check already has when a change doesn't give
    /// one, as they're never shown to be typed again. `asked` is how the change
    /// says to sign in, when it says. Signing in another way, or not at all, lets
    /// go of what was saved.
    pub fn keeping_secrets_of(mut self, saved: &SignIn, asked: Option<SignInWith>) -> Self {
        let gives_password = self.password.is_some() || self.password_env.is_some();
        let gives_key = self.private_key.is_some() || self.private_key_env.is_some();
        match asked.unwrap_or_else(|| self.with()) {
            SignInWith::Password if !gives_password => {
                self.password.clone_from(&saved.password);
                self.password_env.clone_from(&saved.password_env);
            }
            SignInWith::Key if !gives_key => {
                self.private_key.clone_from(&saved.private_key);
                self.private_key_env.clone_from(&saved.private_key_env);
            }
            _ => {}
        }
        self
    }

    /// The credentials to sign in with, read from the environment where they're
    /// named, or why they can't be had.
    pub fn credentials(&self) -> Result<Option<Credentials>, String> {
        if self.is_empty() {
            return Ok(None);
        }
        let secret = |typed: &Option<String>, variable: &Option<String>| match (typed, variable) {
            (Some(typed), _) => Ok(Some(typed.clone())),
            (None, Some(variable)) => std::env::var(variable)
                .map(Some)
                .map_err(|_| format!("the environment variable {variable} isn't set")),
            (None, None) => Ok(None),
        };
        Ok(Some(Credentials {
            username: self.username.clone(),
            password: secret(&self.password, &self.password_env)?,
            private_key: secret(&self.private_key, &self.private_key_env)?,
        }))
    }

    fn validate(&self, kind: CheckKind) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        ensure!(
            kind.signs_in(),
            "only database, Redis, SSH and mail checks sign in"
        );
        if let Some(username) = &self.username {
            ensure!(
                !username.is_empty()
                    && username.len() <= MAX_USERNAME_LEN
                    && !username.chars().any(char::is_control),
                "the username can't be empty or over {MAX_USERNAME_LEN} characters"
            );
        }
        let variable = |name: &Option<String>| -> Result<()> {
            if let Some(name) = name {
                ensure!(
                    crate::metrics_pages::is_secret_variable(name),
                    "the environment variable has to start with {}, followed by capital \
                     letters, digits or _",
                    crate::metrics_pages::ENV_PREFIX
                );
            }
            Ok(())
        };
        variable(&self.password_env)?;
        variable(&self.private_key_env)?;
        match self.with() {
            SignInWith::Key => {
                ensure!(kind == CheckKind::Ssh, "only SSH checks sign in with a key");
                ensure!(
                    self.username.is_some(),
                    "signing in with a key needs a username"
                );
                ensure!(
                    self.password.is_none() && self.password_env.is_none(),
                    "sign in with a password or a key, not both"
                );
                ensure!(
                    !(self.private_key.is_some() && self.private_key_env.is_some()),
                    "give the key or the environment variable that holds it, not both"
                );
                if let Some(key) = &self.private_key {
                    ensure!(
                        key.len() <= MAX_KEY_LEN && key.contains("PRIVATE KEY"),
                        "the private key has to be in OpenSSH's format, as ssh-keygen \
                         writes it"
                    );
                }
            }
            SignInWith::Password => {
                ensure!(
                    !(self.password.is_some() && self.password_env.is_some()),
                    "give the password or the environment variable that holds it, not both"
                );
                if let Some(password) = &self.password {
                    ensure!(
                        !password.is_empty() && password.len() <= MAX_PASSWORD_LEN,
                        "the password can't be empty or over {MAX_PASSWORD_LEN} characters"
                    );
                }
                // Redis before version 6 has a password and no usernames. The rest
                // need someone to sign in as.
                if kind != CheckKind::Redis {
                    ensure!(self.username.is_some(), "signing in needs a username");
                }
                if kind != CheckKind::Postgres && kind != CheckKind::Mysql {
                    ensure!(
                        self.password.is_some() || self.password_env.is_some(),
                        "signing in needs a password"
                    );
                }
            }
            SignInWith::None => bail!("nothing to sign in with"),
        }
        Ok(())
    }
}

fn default_enabled() -> bool {
    true
}

fn local_host_id() -> String {
    LOCAL_HOST_ID.to_string()
}

pub fn check_input(input: &RemoteCheckInput) -> Result<()> {
    input.check.validate()?;
    input.sign_in.validate(input.check.kind)?;
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

/// How each check last went, by its ID, as two hosts can each have a check of the
/// same name. Only kept in memory, as the history is in the metrics store and this
/// refills within one interval.
#[derive(Default)]
pub struct LatestResults {
    results: Mutex<BTreeMap<i64, Value>>,
    /// When each last ran.
    ran_ms: Mutex<BTreeMap<i64, i64>>,
}

impl LatestResults {
    fn set(&self, id: i64, result: Value) {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.insert(id, result);
        let mut ran_ms = self.ran_ms.lock().unwrap_or_else(PoisonError::into_inner);
        ran_ms.insert(id, now_ms());
    }

    /// When a check last ran, if it has since the server started.
    pub fn ran_ms(&self, id: i64) -> Option<i64> {
        let ran_ms = self.ran_ms.lock().unwrap_or_else(PoisonError::into_inner);
        ran_ms.get(&id).copied()
    }

    /// Forgets checks that no longer exist.
    fn keep_only(&self, ids: &BTreeSet<i64>) {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.retain(|id, _| ids.contains(id));
        let mut ran_ms = self.ran_ms.lock().unwrap_or_else(PoisonError::into_inner);
        ran_ms.retain(|id, _| ids.contains(id));
    }

    pub fn all(&self) -> BTreeMap<i64, Value> {
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
        let ids: BTreeSet<i64> = checks.iter().map(|check| check.id).collect();
        self.results.keep_only(&ids);

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
            run(&check, hostname, &writer, &results, &presence).await;
        })
    }
}

/// Runs a check once and keeps what it found: as its latest result, as what's
/// known of its host, and in the metrics store. The scheduler does this when a
/// check is due, and a person can ask for it in between.
pub async fn run(
    check: &RemoteCheck,
    hostname: String,
    writer: &mpsc::Sender<WriterCommand>,
    results: &LatestResults,
    presence: &Presence,
) {
    let host_id = &check.input.host_id;
    // A password or key named as an environment variable is read each time, so
    // a changed one is used without restarting.
    let result = match check.input.sign_in.credentials() {
        Ok(credentials) => {
            maxnines_checks::run_signed_in(&check.input.check, credentials.as_ref()).await
        }
        Err(why) => maxnines_checks::failed_report(&check.input.check, &why),
    };
    results.set(check.id, result.clone());
    // One that's turned off says nothing about whether its host is there.
    if host_id != LOCAL_HOST_ID && check.input.enabled {
        presence.reached(host_id, Reached::Check(check.id), result["up"] == 1);
    }
    save(writer, host_id.clone(), hostname, result).await;
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
            sign_in: Default::default(),
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
        results.set(1, json!(1));
        results.set(2, json!(2));
        results.keep_only(&BTreeSet::from([2]));
        assert_eq!(results.all().len(), 1);
        assert_eq!(results.all()[&2], 2);
    }
}
