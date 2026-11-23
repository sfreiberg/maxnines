//! Checks the server runs itself, against remote sites, with the same code agents
//! use. Each is about a host with no agent, made for it if it's added without one.
//! Results are saved as samples from that host, so charts and alert rules treat them
//! like anything else.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use chrono::TimeDelta;
use maxnines_checks::Credentials;
use maxnines_checks::databases::{self as stats, Reader, Settle, by_kind, is_database};
use maxnines_protocol::{Check, CheckKind, DATABASE_EXTRAS, Sample};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::heartbeats::{self, Pings};
use crate::models::Database;
use crate::presence::{Presence, Reached};
use crate::registration::{HostState, Registry};
use crate::store::{NewSample, WriterCommand};
use crate::templates::agentless::{AgentlessTemplates, Saving};
use crate::times::{self, Timestamp};

/// The built-in host the server records its own metrics under. See the migration
/// that creates it. No check is ever about it.
pub const LOCAL_HOST_ID: &str = "server";

pub const LOCAL_HOSTNAME: &str = "MaxNines server";
/// The built-in agent alerts about a group of hosts belong to.
pub const FLEET_HOST_ID: &str = "fleet";
pub const FLEET_HOSTNAME: &str = "Fleet";

/// How often to look for checks that are due.
const TICK: Duration = Duration::from_secs(5);

const MIN_INTERVAL: Duration = Duration::from_secs(10);
const MAX_INTERVAL: Duration = Duration::from_secs(86_400);

/// How often a heartbeat can be expected, from cron's finest to monthly work.
const MIN_PERIOD: Duration = Duration::from_secs(60);
const MAX_PERIOD: Duration = Duration::from_secs(31 * 86_400);
/// How late a heartbeat's ping can be.
const MAX_GRACE: Duration = Duration::from_secs(7 * 86_400);

/// How many checks run at once. Anything over this waits its turn.
pub const MAX_RUNNING: usize = 32;

/// A check the server runs, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCheck {
    pub id: i64,
    #[serde(flatten)]
    pub input: RemoteCheckInput,
    /// A heartbeat's token, which the address it's pinged at holds. Only those who
    /// can change the check are shown it, and it's kept out of the audit log.
    #[serde(skip)]
    pub ping_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCheckInput {
    /// The host it's about, which is always one with no agent. A request gives it
    /// beside the check, or leaves it out for a new host to be made for the check.
    #[serde(skip_deserializing)]
    pub host_id: String,
    pub check: Check,
    /// How often it runs, or for a heartbeat, how often it should be pinged.
    #[serde(rename = "interval_secs", with = "maxnines_protocol::time::seconds")]
    pub interval: Duration,
    /// For a heartbeat: how much later than its interval a ping can come before
    /// it's down. None is none.
    #[serde(
        rename = "grace_secs",
        with = "maxnines_protocol::time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub grace: Option<Duration>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// For a database: also read its health and replication, as an agent reads
    /// a database its config defines, saved as samples from the check's host.
    #[serde(default)]
    pub read_stats: bool,
    /// What else to read from a database, beyond the usual.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extras: Vec<String>,
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
            "only database, Redis, SSH, mail and FTP checks sign in"
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

pub fn check_input(input: &RemoteCheckInput) -> Result<()> {
    input.check.validate()?;
    input.sign_in.validate(input.check.kind)?;
    ensure!(
        input.check.interval.is_none(),
        "a remote check's interval goes beside the check, as interval_secs"
    );
    let heartbeat = input.check.kind == CheckKind::Heartbeat;
    let (shortest, longest) = if heartbeat {
        (MIN_PERIOD, MAX_PERIOD)
    } else {
        (MIN_INTERVAL, MAX_INTERVAL)
    };
    ensure!(
        (shortest..=longest).contains(&input.interval),
        "the interval has to be from {} to {} seconds",
        shortest.as_secs(),
        longest.as_secs()
    );
    if let Some(grace) = input.grace {
        ensure!(heartbeat, "only a heartbeat has a grace time");
        ensure!(
            grace <= MAX_GRACE,
            "the grace time can be at most {} seconds",
            MAX_GRACE.as_secs()
        );
    }
    ensure!(
        !input.read_stats || is_database(input.check.kind),
        "only database checks can read a database's stats"
    );
    ensure!(
        input.read_stats || input.extras.is_empty(),
        "extras are only read along with a database's stats"
    );
    for (index, extra) in input.extras.iter().enumerate() {
        ensure!(
            DATABASE_EXTRAS.contains(&extra.as_str()),
            "{extra:?} isn't something that can be read from a database, which are: {}",
            DATABASE_EXTRAS.join(", ")
        );
        ensure!(
            !input.extras[..index].contains(extra),
            "{extra:?} is given twice"
        );
    }
    Ok(())
}

/// How each check last went, by its ID, as two hosts can each have a check of the
/// same name. Only kept in memory, as the history is in the metrics store and this
/// refills within one interval.
#[derive(Default)]
pub struct LatestResults {
    results: Mutex<BTreeMap<i64, Value>>,
    /// When each last ran.
    ran_at: Mutex<BTreeMap<i64, Timestamp>>,
}

impl LatestResults {
    fn set(&self, id: i64, result: Value) {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.insert(id, result);
        let mut ran_at = self.ran_at.lock().unwrap_or_else(PoisonError::into_inner);
        ran_at.insert(id, times::now());
    }

    /// When a check last ran, if it has since the server started.
    pub fn ran_at(&self, id: i64) -> Option<Timestamp> {
        let ran_at = self.ran_at.lock().unwrap_or_else(PoisonError::into_inner);
        ran_at.get(&id).copied()
    }

    /// Forgets checks that no longer exist.
    fn keep_only(&self, ids: &BTreeSet<i64>) {
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        results.retain(|id, _| ids.contains(id));
        let mut ran_at = self.ran_at.lock().unwrap_or_else(PoisonError::into_inner);
        ran_at.retain(|id, _| ids.contains(id));
    }

    /// A check's last result and when it ran, if it has since the server started.
    pub fn latest(&self, id: i64) -> Option<(Value, Timestamp)> {
        let result = self
            .results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()?;
        Some((result, self.ran_at(id)?))
    }

    pub fn all(&self) -> BTreeMap<i64, Value> {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A database's stats, read alongside its check. The reader keeps its
/// connection between runs, so it's only made again when what it reads, or how
/// it signs in, changes.
struct StatsReader {
    input: RemoteCheckInput,
    credentials: Option<Credentials>,
    reader: Arc<tokio::sync::Mutex<(Reader, Settle)>>,
}

pub struct Scheduler {
    database: Database,
    writer: mpsc::Sender<WriterCommand>,
    registry: Arc<Registry>,
    presence: Arc<Presence>,
    results: Arc<LatestResults>,
    slots: Arc<Semaphore>,
    /// When each check is next due, by ID, and how it was then. A check that's been
    /// changed since is run at once, with its new interval from then on.
    next_run: HashMap<i64, (Timestamp, RemoteCheckInput)>,
    /// For each check that reads a database's stats, by ID.
    readers: HashMap<i64, StatsReader>,
    /// What templates have read through those checks.
    templates: AgentlessTemplates,
    /// Each heartbeat that's on, by ID.
    watched: HashMap<i64, Watched>,
    /// When the scheduler started, which a heartbeat never pinged counts from.
    started_at: Timestamp,
    /// Whether it's yet to look at the checks, so what it finds is what was there
    /// when the server started.
    first_pass: bool,
}

/// How a heartbeat is being watched.
struct Watched {
    input: RemoteCheckInput,
    /// When it began being watched as it is now, which a run that's due counts
    /// from if that's later than its last ping: since it was added, changed or
    /// resumed. Nothing for one there when the server started, so a restart never
    /// gives a run that's late more time.
    since: Option<Timestamp>,
    /// When its result was last saved, whether it was up then, and when it had
    /// last been pinged.
    saved: Option<(Timestamp, bool, Option<Timestamp>)>,
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
            readers: HashMap::new(),
            templates: AgentlessTemplates::default(),
            watched: HashMap::new(),
            started_at: times::now(),
            first_pass: true,
        }
    }

    /// Runs until the server stops. A database failure skips one tick.
    pub fn spawn(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(TICK);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                if let Err(error) = self.start_due(times::now()).await {
                    error!(error = format!("{error:#}"), "starting checks failed");
                }
            }
        })
    }

    /// Starts everything that's due, without waiting for any of it, and returns
    /// what it started so that tests can wait for them. A check that panics only
    /// loses its own run.
    pub async fn start_due(&mut self, now: Timestamp) -> Result<Vec<JoinHandle<()>>> {
        let checks = self.database.list_remote_checks().await?;
        let ids: BTreeSet<i64> = checks.iter().map(|check| check.id).collect();
        self.results.keep_only(&ids);
        self.next_run.retain(|id, _| ids.contains(id));
        self.keep_readers(&checks);
        let watching: BTreeSet<i64> = checks
            .iter()
            .filter(|check| is_heartbeat(check) && check.input.enabled)
            .map(|check| check.id)
            .collect();
        self.watched.retain(|id, _| watching.contains(id));
        let pings = if watching.is_empty() {
            HashMap::new()
        } else {
            self.database.heartbeat_pings().await?
        };

        // A host with no agent is as present as its checks and pages say.
        let agentless: BTreeMap<String, String> = self.registry.read(|hosts| {
            hosts
                .values()
                .filter(|host| host.is_agentless() && host.state == HostState::Approved)
                .map(|host| (host.id.clone(), host.hostname.clone()))
                .collect()
        });
        let about_hosts: HashMap<i64, String> = checks
            .iter()
            .filter(|check| check.input.enabled && agentless.contains_key(&check.input.host_id))
            .map(|check| (check.id, check.input.host_id.clone()))
            .collect();
        self.presence.keep_checks(&about_hosts);
        // What templates read is kept apart, so a failure there holds up no checks.
        if let Err(error) = self
            .templates
            .keep(&self.database, &checks, &agentless)
            .await
        {
            warn!(
                error = format!("{error:#}"),
                "working out what templates read on hosts with no agent failed"
            );
        }

        let mut started = Vec::new();
        for check in checks {
            if is_heartbeat(&check) {
                if let Some(hostname) = agentless.get(&check.input.host_id)
                    && check.input.enabled
                {
                    let pings = pings.get(&check.id).cloned().unwrap_or_default();
                    self.watch(&check, hostname.clone(), &pings, now).await;
                }
                continue;
            }
            let due = self
                .next_run
                .get(&check.id)
                .filter(|(_, then)| *then == check.input)
                .map_or(now, |(due, _)| *due);
            if !check.input.enabled || due > now {
                continue;
            }
            // Its host isn't one the server runs checks for any more.
            let Some(hostname) = agentless.get(&check.input.host_id).cloned() else {
                continue;
            };
            let interval = TimeDelta::from_std(check.input.interval)?;
            self.next_run
                .insert(check.id, (now + interval, check.input.clone()));
            // Waiting for a slot here, not in the run, keeps checks slower than their
            // interval from piling up: the next pass starts once one is free.
            let Ok(slot) = self.slots.clone().acquire_owned().await else {
                break;
            };
            started.push(self.start(check, hostname, slot));
        }
        self.first_pass = false;
        Ok(started)
    }

    /// Works out how a heartbeat is now, and saves that when it's changed, when it's
    /// been pinged, and otherwise every so often, so its charts and its host carry
    /// on between pings however far apart they are.
    async fn watch(
        &mut self,
        check: &RemoteCheck,
        hostname: String,
        pings: &Pings,
        now: Timestamp,
    ) {
        let first_pass = self.first_pass;
        let watched = self.watched.entry(check.id).or_insert_with(|| Watched {
            input: check.input.clone(),
            since: (!first_pass).then_some(now),
            saved: None,
        });
        if watched.input != check.input {
            watched.input = check.input.clone();
            watched.since = Some(now);
        }
        let since = watched.since.unwrap_or(match pings.pinged_at {
            // Its last ping is what counts.
            Some(_) => Timestamp::MIN_UTC,
            None => self.started_at,
        });
        let result = heartbeats::status(check, pings, since, now);
        let up = result["up"] == 1;
        let due = watched.saved.is_none_or(|(saved_at, was_up, pinged_at)| {
            was_up != up
                || pinged_at != pings.pinged_at
                || now - saved_at >= heartbeats::REPORT_EVERY
        });
        if !due {
            return;
        }
        watched.saved = Some((now, up, pings.pinged_at));
        keep(
            check,
            hostname,
            result,
            &self.writer,
            &self.results,
            &self.presence,
        )
        .await;
    }

    /// A reader for each enabled check that reads stats, made again when its
    /// check or login changes, and dropped, closing its connection, when it goes.
    fn keep_readers(&mut self, checks: &[RemoteCheck]) {
        let wanted: HashMap<i64, &RemoteCheck> = checks
            .iter()
            .filter(|check| check.input.enabled && check.input.read_stats)
            .map(|check| (check.id, check))
            .collect();
        self.readers.retain(|id, _| wanted.contains_key(id));
        for (id, check) in wanted {
            // A login that can't be had now is tried again with the next tick.
            let credentials = check.input.sign_in.credentials().ok().flatten();
            let current = self
                .readers
                .get(&id)
                .is_some_and(|kept| kept.input == check.input && kept.credentials == credentials);
            if current {
                continue;
            }
            let database = stats::Database {
                check: check.input.check.clone(),
                credentials: credentials.clone().unwrap_or_default(),
            };
            let reader = Reader::new(&check.input.check.name, database, &check.input.extras);
            self.readers.insert(
                id,
                StatsReader {
                    input: check.input.clone(),
                    credentials,
                    reader: Arc::new(tokio::sync::Mutex::new((reader, Settle::default()))),
                },
            );
        }
    }

    /// Runs a check, holding one of the slots until it's done.
    fn start(
        &self,
        check: RemoteCheck,
        hostname: String,
        slot: OwnedSemaphorePermit,
    ) -> JoinHandle<()> {
        let writer = self.writer.clone();
        let (results, presence) = (self.results.clone(), self.presence.clone());
        let reader = self.readers.get(&check.id).map(|kept| kept.reader.clone());
        let templates = self.templates.reads(check.id);
        let database = self.database.clone();
        tokio::spawn(async move {
            let _slot = slot;
            run(&check, hostname.clone(), &writer, &results, &presence).await;
            if let Some(reader) = reader {
                read_stats(&check, hostname.clone(), &writer, &reader).await;
            }
            if let Some(templates) = templates {
                let to = Saving {
                    database: &database,
                    writer: &writer,
                    host_id: check.input.host_id.clone(),
                    hostname,
                };
                templates.save(to).await;
            }
        })
    }
}

/// Reads a database's stats and saves them as its host's, as an agent's would be.
async fn read_stats(
    check: &RemoteCheck,
    hostname: String,
    writer: &mpsc::Sender<WriterCommand>,
    reader: &tokio::sync::Mutex<(Reader, Settle)>,
) {
    let limit = maxnines_checks::limit(&check.input.check).min(stats::TIMEOUT);
    let mut reading = reader.lock().await;
    let (reader, settle) = &mut *reading;
    let rows = settle.settle(reader.read(limit).await);
    let host_id = check.input.host_id.clone();
    save(writer, host_id, hostname, "databases", by_kind(rows)).await;
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
    // A password or key named as an environment variable is read each time, so
    // a changed one is used without restarting.
    let result = match check.input.sign_in.credentials() {
        Ok(credentials) => {
            maxnines_checks::run_signed_in(&check.input.check, credentials.as_ref()).await
        }
        Err(why) => maxnines_checks::failed_report(&check.input.check, &why),
    };
    keep(check, hostname, result, writer, results, presence).await;
}

/// Keeps what a check found: as its latest result, as what's known of its host,
/// and in the metrics store.
pub async fn keep(
    check: &RemoteCheck,
    hostname: String,
    result: Value,
    writer: &mpsc::Sender<WriterCommand>,
    results: &LatestResults,
    presence: &Presence,
) {
    let host_id = &check.input.host_id;
    results.set(check.id, result.clone());
    // One that's turned off says nothing about whether its host is there.
    if check.input.enabled {
        presence.reached(host_id, Reached::Check(check.id), result["up"] == 1);
    }
    save(writer, host_id.clone(), hostname, "checks", json!([result])).await;
}

fn is_heartbeat(check: &RemoteCheck) -> bool {
    check.input.check.kind == CheckKind::Heartbeat
}

async fn save(
    writer: &mpsc::Sender<WriterCommand>,
    host_id: String,
    hostname: String,
    collector: &str,
    output: Value,
) {
    let sample = Sample {
        time: times::now(),
        metrics: BTreeMap::from([(collector.to_string(), output)]),
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

    fn input(interval: Duration) -> RemoteCheckInput {
        RemoteCheckInput {
            host_id: "5f0c1d6f2a8e4b7790d3c1a2b4e6f809".to_string(),
            check: Check::new("a", CheckKind::Tcp, "example.com:80"),
            interval,
            enabled: true,
            read_stats: false,
            extras: Vec::new(),
            sign_in: Default::default(),
            grace: None,
        }
    }

    #[test]
    fn a_heartbeat_is_expected_from_every_minute_to_monthly_with_some_grace() {
        let mut heartbeat = input(Duration::from_secs(3600));
        heartbeat.check = Check::new("backup", CheckKind::Heartbeat, "");
        heartbeat.grace = Some(Duration::from_secs(300));
        check_input(&heartbeat).unwrap();
        heartbeat.interval = MAX_PERIOD;
        check_input(&heartbeat).unwrap();
        heartbeat.interval = Duration::from_secs(30);
        assert!(check_input(&heartbeat).is_err());
        heartbeat.interval = MIN_PERIOD;
        heartbeat.grace = Some(MAX_GRACE + Duration::from_secs(1));
        assert!(check_input(&heartbeat).is_err());

        // Only a heartbeat has a grace time.
        let mut site = input(Duration::from_secs(60));
        site.grace = Some(Duration::from_secs(60));
        assert!(check_input(&site).is_err());
    }

    #[test]
    fn intervals_are_limited() {
        let second = Duration::from_secs(1);
        check_input(&input(second * 60)).unwrap();
        check_input(&input(MIN_INTERVAL)).unwrap();
        assert!(check_input(&input(MIN_INTERVAL - second)).is_err());
        assert!(check_input(&input(MAX_INTERVAL + second)).is_err());

        // Only one place says how often it runs.
        let mut inside = input(second * 60);
        inside.check.interval = Some(second * 300);
        assert!(check_input(&inside).is_err());
    }

    #[test]
    fn the_check_itself_is_validated() {
        let mut bad = input(Duration::from_secs(60));
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
