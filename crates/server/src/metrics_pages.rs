//! OpenMetrics pages the server reads itself, for hosts with no agent. They're
//! read with the same code agents use, and saved as samples from their host, so
//! charts and alert rules treat them like anything else.
//!
//! An agentless host is online while any of its pages answers, or any check
//! the server runs against it passes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, ensure};
use maxnines_checks::Login;
use maxnines_checks::openmetrics::{Page, Totals};
use maxnines_protocol::{Sample, check_metrics_pages, metrics_page_name};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::metrics::now_ms;
use crate::models::Database;
use crate::presence::{Presence, Reached};
use crate::registration::{HostKind, HostState, Registry};
use crate::store::{NewSample, WriterCommand};

/// How often to look for pages that are due.
const TICK: Duration = Duration::from_secs(5);

pub const MIN_INTERVAL_SECS: u64 = 10;
pub const MAX_INTERVAL_SECS: u64 = 86_400;

/// How many pages are read at once. Anything over this waits its turn.
const MAX_RUNNING: usize = 32;

/// How many series are kept from one page. Nothing here has to fit in a message,
/// as an agent's sample does, but an exporter can still list tens of thousands.
const MAX_SERIES: usize = 2_000;

/// How many pages one host can have.
pub const MAX_PAGES: usize = 16;

/// What the database's columns hold.
const MAX_SETTING_LEN: usize = 255;
const MAX_SECRET_LEN: usize = 1024;

/// The only environment variables a page's password or token can come from. Anyone
/// who can add a page chooses where they're sent, so without this they could have
/// the server hand over anything in its environment, such as its database's URL.
pub const ENV_PREFIX: &str = "MAXNINES_SECRET_";

/// A page the server reads, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricsPage {
    pub id: i64,
    pub host_id: String,
    pub input: MetricsPageInput,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsPageInput {
    pub url: String,
    /// The metrics to keep, with `*` and `?` for anything. Empty keeps them all.
    #[serde(default)]
    pub names: Vec<String>,
    /// How often it's read.
    pub interval_secs: u64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// For a page that asks who's reading, with one of the two below.
    #[serde(default)]
    pub username: Option<String>,
    /// The password as typed in.
    #[serde(default)]
    pub password: Option<String>,
    /// The server's environment variable that holds the password.
    #[serde(default)]
    pub password_env: Option<String>,
    /// For a page that asks for a token instead: the token as typed in.
    #[serde(default)]
    pub token: Option<String>,
    /// The server's environment variable that holds the token.
    #[serde(default)]
    pub token_env: Option<String>,
}

/// How a page is signed in to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignIn {
    None,
    Password,
    Token,
}

impl SignIn {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Password => "password",
            Self::Token => "token",
        }
    }
}

fn default_enabled() -> bool {
    true
}

impl fmt::Debug for MetricsPageInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsPageInput")
            .field("url", &self.url)
            .field("names", &self.names)
            .field("interval_secs", &self.interval_secs)
            .field("enabled", &self.enabled)
            .field("username", &self.username)
            .field("password_env", &self.password_env)
            .field("token_env", &self.token_env)
            .finish_non_exhaustive()
    }
}

impl MetricsPageInput {
    /// What the page is called, which each of its series' names starts with.
    pub fn name(&self) -> &str {
        metrics_page_name(&self.url)
    }

    /// How the page is signed in to, going by what it has.
    pub fn sign_in(&self) -> SignIn {
        if self.username.is_some() {
            SignIn::Password
        } else if self.token.is_some() || self.token_env.is_some() {
            SignIn::Token
        } else {
            SignIn::None
        }
    }

    /// Keeps the password or token a page already has when a change doesn't give
    /// one, as they're never shown to be typed again. `asked` is how the change
    /// says to sign in, when it says, as a token has nothing else to go by.
    /// Signing in another way, or not at all, lets go of what was saved.
    pub fn keeping_secrets_of(mut self, saved: &MetricsPageInput, asked: Option<SignIn>) -> Self {
        let gives_password = self.password.is_some() || self.password_env.is_some();
        let gives_token = self.token.is_some() || self.token_env.is_some();
        match asked.unwrap_or_else(|| self.sign_in()) {
            SignIn::Password if !gives_password => {
                self.password.clone_from(&saved.password);
                self.password_env.clone_from(&saved.password_env);
            }
            SignIn::Token if !gives_token => {
                self.token.clone_from(&saved.token);
                self.token_env.clone_from(&saved.token_env);
            }
            _ => {}
        }
        self
    }

    /// The login to send, or why there isn't one to send when there should be.
    fn login(&self) -> Result<Option<Login>, String> {
        let secret = |typed: &Option<String>, variable: &Option<String>| match (typed, variable) {
            (Some(typed), _) => Ok(typed.clone()),
            (None, Some(variable)) => std::env::var(variable)
                .map_err(|_| format!("the environment variable {variable} isn't set")),
            (None, None) => Ok(String::new()),
        };
        let login = match self.sign_in() {
            SignIn::None => return Ok(None),
            SignIn::Password => {
                let username = self.username.as_deref().unwrap_or_default();
                Login::new(username, &secret(&self.password, &self.password_env)?)
            }
            SignIn::Token => Login::token(&secret(&self.token, &self.token_env)?),
        };
        login.map(Some).map_err(|error| format!("{error:#}"))
    }
}

fn is_secret_variable(name: &str) -> bool {
    let plain = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_';
    name.strip_prefix(ENV_PREFIX)
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(plain))
        && name.len() <= MAX_SETTING_LEN
}

/// A password or token, which comes from exactly one of two places.
fn check_secret(what: &str, typed: Option<&String>, variable: Option<&String>) -> Result<()> {
    match (typed, variable) {
        (Some(_), Some(_)) => {
            anyhow::bail!("give the {what} or the environment variable that holds it, not both")
        }
        (None, None) => anyhow::bail!("signing in needs a {what}"),
        (Some(typed), None) => ensure!(
            !typed.is_empty() && typed.len() <= MAX_SECRET_LEN,
            "the {what} can't be empty or over {MAX_SECRET_LEN} characters"
        ),
        (None, Some(variable)) => ensure!(
            is_secret_variable(variable),
            "the environment variable has to start with {ENV_PREFIX}, followed by capital \
             letters, digits or _"
        ),
    }
    Ok(())
}

pub fn check_input(input: &MetricsPageInput) -> Result<()> {
    check_metrics_pages(std::slice::from_ref(&input.url), &input.names)?;
    ensure!(
        (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&input.interval_secs),
        "the interval has to be from {MIN_INTERVAL_SECS} to {MAX_INTERVAL_SECS} seconds"
    );

    let (password, password_env) = (input.password.as_ref(), input.password_env.as_ref());
    let (token, token_env) = (input.token.as_ref(), input.token_env.as_ref());
    let gives_token = token.is_some() || token_env.is_some();
    let Some(username) = &input.username else {
        ensure!(
            password.is_none() && password_env.is_none(),
            "a password needs a username to go with it"
        );
        if gives_token {
            check_secret("token", token, token_env)?;
        }
        if let Some(token) = token {
            Login::token(token)?;
        }
        return Ok(());
    };
    ensure!(
        !gives_token,
        "a page is signed in to with a username and password or with a token, not both"
    );
    // Basic authentication ends the username at the first colon.
    ensure!(
        !username.is_empty() && !username.contains(':') && username.len() <= MAX_SETTING_LEN,
        "the username can't be empty, hold a colon or be over {MAX_SETTING_LEN} characters"
    );
    if password.is_none() && password_env.is_none() {
        anyhow::bail!("a username needs a password to go with it");
    }
    check_secret("password", password, password_env)
}

/// Whether a page signs in the way its change said it would, when it said.
pub fn check_sign_in(input: &MetricsPageInput, asked: Option<SignIn>) -> Result<()> {
    let Some(asked) = asked else {
        return Ok(());
    };
    ensure!(
        input.sign_in() == asked,
        match asked {
            SignIn::None =>
                "a page that isn't signed in to can't have a username, password or token",
            SignIn::Password => "signing in with a password needs a username",
            SignIn::Token =>
                "signing in with a token needs the token, or the environment \
                              variable that holds it",
        }
    );
    Ok(())
}

/// Whether a host's pages can be told apart, as their series are named by them.
pub fn check_names<'a>(pages: impl IntoIterator<Item = &'a MetricsPageInput>) -> Result<()> {
    let mut seen = HashSet::new();
    let mut count = 0;
    for page in pages {
        count += 1;
        ensure!(
            seen.insert(page.name()),
            "two of this host's pages would both be called {:?}",
            page.name()
        );
    }
    ensure!(
        count <= MAX_PAGES,
        "a host can have at most {MAX_PAGES} pages"
    );
    Ok(())
}

/// What's remembered between reads. Only kept in memory, as it refills within one
/// interval of each page.
#[derive(Default)]
pub struct PageReads(Mutex<Reads>);

#[derive(Default)]
struct Reads {
    /// Each page's running totals, by its ID.
    totals: HashMap<i64, Totals>,
    /// How each page's last read went: the page's own row, which says whether it
    /// answered and why not.
    results: HashMap<i64, Value>,
    /// Pages that were changed since they were last read, to read again now.
    changed: HashSet<i64>,
}

impl PageReads {
    fn reads(&self) -> std::sync::MutexGuard<'_, Reads> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How a page's last read went, if it's been read since the server started.
    pub fn result(&self, page_id: i64) -> Option<Value> {
        let reads = self.reads();
        reads.results.get(&page_id).cloned()
    }

    /// Forgets how a page's last read went, as the page has been changed and that
    /// no longer says anything about it, and has it read again at once.
    pub fn changed(&self, page_id: i64) {
        let mut reads = self.reads();
        reads.results.remove(&page_id);
        reads.changed.insert(page_id);
    }

    fn take_changed(&self) -> HashSet<i64> {
        std::mem::take(&mut self.reads().changed)
    }

    /// Forgets pages that are gone or turned off.
    fn keep_only(&self, pages: &HashSet<i64>) {
        let mut reads = self.reads();
        reads.totals.retain(|id, _| pages.contains(id));
        reads.results.retain(|id, _| pages.contains(id));
    }

    /// Takes what was kept of a page and gives the rows to save, with whether the
    /// page answered.
    fn settle(&self, page: &MetricsPage, kept: Vec<Value>) -> (Vec<Value>, bool) {
        let mut reads = self.reads();
        let result = kept.first().cloned().unwrap_or_default();
        let answered = result["up"] == 1;
        reads.results.insert(page.id, result);
        let rows = reads.totals.entry(page.id).or_default().settle(kept);
        (rows, answered)
    }
}

pub struct Scheduler {
    database: Database,
    writer: mpsc::Sender<WriterCommand>,
    registry: Arc<Registry>,
    presence: Arc<Presence>,
    slots: Arc<Semaphore>,
    reads: Arc<PageReads>,
    /// When each page is next due, by ID.
    next_run: HashMap<i64, i64>,
}

impl Scheduler {
    pub fn new(
        database: Database,
        writer: mpsc::Sender<WriterCommand>,
        registry: Arc<Registry>,
        presence: Arc<Presence>,
        reads: Arc<PageReads>,
    ) -> Self {
        Self {
            database,
            writer,
            registry,
            presence,
            slots: Arc::new(Semaphore::new(MAX_RUNNING)),
            reads,
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
                    error!(error = format!("{error:#}"), "reading metrics pages failed");
                }
            }
        })
    }

    /// Starts reading everything that's due, without waiting for any of it, and
    /// returns what it started so that tests can wait for them.
    pub async fn start_due(&mut self, now_ms: i64) -> Result<Vec<JoinHandle<()>>> {
        let hostnames: BTreeMap<String, String> = self
            .registry
            .list()
            .await
            .into_iter()
            .filter(|host| host.kind == HostKind::Agentless && host.state == HostState::Approved)
            .map(|host| (host.id, host.hostname))
            .collect();
        let pages: Vec<MetricsPage> = self
            .database
            .list_metrics_pages()
            .await?
            .into_iter()
            .filter(|page| page.input.enabled && hostnames.contains_key(&page.host_id))
            .collect();

        let reading: HashSet<i64> = pages.iter().map(|page| page.id).collect();
        let changed = self.reads.take_changed();
        self.next_run
            .retain(|id, _| reading.contains(id) && !changed.contains(id));
        self.reads.keep_only(&reading);
        self.presence.keep_pages(&reading);

        let mut started = Vec::new();
        for page in pages {
            let due = *self.next_run.get(&page.id).unwrap_or(&now_ms);
            if due > now_ms {
                continue;
            }
            let interval_ms = i64::try_from(page.input.interval_secs)?.saturating_mul(1000);
            self.next_run.insert(page.id, now_ms + interval_ms);
            let hostname = hostnames[&page.host_id].clone();
            started.push(self.start(page, hostname));
        }
        Ok(started)
    }

    fn start(&self, page: MetricsPage, hostname: String) -> JoinHandle<()> {
        let (slots, writer) = (self.slots.clone(), self.writer.clone());
        let (reads, presence) = (self.reads.clone(), self.presence.clone());
        tokio::spawn(async move {
            let Ok(_slot) = slots.acquire_owned().await else {
                return;
            };
            let kept = read(&page.input).await;
            let (rows, answered) = reads.settle(&page, kept);
            presence.reached(&page.host_id, Reached::Page(page.id), answered);
            save(&writer, page.host_id, hostname, rows).await;
        })
    }
}

/// What's kept of a page, as [`Page::read`] gives it.
async fn read(input: &MetricsPageInput) -> Vec<Value> {
    match input.login() {
        Ok(login) => {
            Page::new(input.url.clone(), &input.names, MAX_SERIES, login)
                .read()
                .await
        }
        Err(error) => vec![json!({ "name": input.name(), "up": 0, "error": error })],
    }
}

async fn save(
    writer: &mpsc::Sender<WriterCommand>,
    host_id: String,
    hostname: String,
    rows: Vec<Value>,
) {
    let sample = Sample {
        timestamp_ms: now_ms() as u64,
        metrics: BTreeMap::from([("openmetrics".to_string(), Value::Array(rows))]),
    };
    let command = WriterCommand::Save(NewSample {
        host_id,
        hostname,
        sample,
    });
    if writer.send(command).await.is_err() {
        warn!("the metrics writer has stopped, so a page's metrics were dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> MetricsPageInput {
        MetricsPageInput {
            url: "http://db.example.com:9187/metrics".to_string(),
            names: vec!["pg_*".to_string()],
            interval_secs: 60,
            enabled: true,
            username: None,
            password: None,
            password_env: None,
            token: None,
            token_env: None,
        }
    }

    fn with_token(token: Option<&str>, variable: Option<&str>) -> MetricsPageInput {
        MetricsPageInput {
            token: token.map(str::to_string),
            token_env: variable.map(str::to_string),
            ..input()
        }
    }

    fn with_login(password: Option<&str>, variable: Option<&str>) -> MetricsPageInput {
        MetricsPageInput {
            username: Some("metrics".to_string()),
            password: password.map(str::to_string),
            password_env: variable.map(str::to_string),
            ..input()
        }
    }

    #[test]
    fn a_page_is_checked_as_an_agent_would_check_it() {
        check_input(&input()).unwrap();
        for (url, names) in [
            ("db.example.com:9187/metrics", "pg_*"),
            ("http://reader:secret@db.example.com/metrics", "pg_*"),
            ("http://db.example.com/metrics", "pg up"),
        ] {
            let bad = MetricsPageInput {
                url: url.to_string(),
                names: vec![names.to_string()],
                ..input()
            };
            assert!(check_input(&bad).is_err(), "{url} {names}");
        }
        for interval_secs in [MIN_INTERVAL_SECS - 1, MAX_INTERVAL_SECS + 1] {
            let bad = MetricsPageInput {
                interval_secs,
                ..input()
            };
            assert!(check_input(&bad).is_err(), "{interval_secs}");
        }
    }

    #[test]
    fn a_login_is_a_username_with_one_way_to_get_its_password() {
        check_input(&with_login(Some("s3cret"), None)).unwrap();
        check_input(&with_login(None, Some("MAXNINES_SECRET_DB_METRICS"))).unwrap();

        assert!(check_input(&with_login(None, None)).is_err());
        assert!(check_input(&with_login(Some("a"), Some("MAXNINES_SECRET_A"))).is_err());
        assert!(check_input(&with_login(Some(""), None)).is_err());
        let nobody = MetricsPageInput {
            username: None,
            ..with_login(Some("s3cret"), None)
        };
        assert!(check_input(&nobody).is_err());
        let colon = MetricsPageInput {
            username: Some("a:b".to_string()),
            ..with_login(Some("s3cret"), None)
        };
        assert!(check_input(&colon).is_err());
    }

    #[test]
    fn only_variables_set_aside_for_secrets_can_be_read() {
        for variable in [
            "DATABASE_URL",
            "PATH",
            "MAXNINES_SECRET_",
            "maxnines_secret_x",
        ] {
            let error = check_input(&with_login(None, Some(variable))).unwrap_err();
            assert!(
                error.to_string().contains(ENV_PREFIX),
                "{variable}: {error}"
            );
        }
    }

    #[test]
    fn a_password_comes_from_where_the_page_says() {
        assert!(input().login().unwrap().is_none());
        assert!(with_login(Some("s3cret"), None).login().unwrap().is_some());
        // Nothing in this test's environment starts like this.
        let unset = with_login(None, Some("MAXNINES_SECRET_NEVER_SET"));
        assert_eq!(
            unset.login().unwrap_err(),
            "the environment variable MAXNINES_SECRET_NEVER_SET isn't set"
        );
        // Cargo sets this one for every test.
        let set = with_login(None, Some("CARGO_PKG_NAME"));
        assert!(set.login().unwrap().is_some());
    }

    #[test]
    fn a_change_without_a_password_keeps_the_one_saved() {
        let saved = with_login(Some("s3cret"), None);

        let kept = with_login(None, None).keeping_secrets_of(&saved, None);
        assert_eq!(kept.password.as_deref(), Some("s3cret"));

        let replaced =
            with_login(None, Some("MAXNINES_SECRET_DB")).keeping_secrets_of(&saved, None);
        assert_eq!(replaced.password, None);
        assert_eq!(replaced.password_env.as_deref(), Some("MAXNINES_SECRET_DB"));

        // No username, no login.
        let removed = input().keeping_secrets_of(&saved, None);
        assert_eq!((removed.password, removed.password_env), (None, None));
    }

    #[test]
    fn a_token_comes_from_one_place_and_is_only_kept_when_asked() {
        check_input(&with_token(Some("abc.DEF-123"), None)).unwrap();
        check_input(&with_token(None, Some("MAXNINES_SECRET_APP_TOKEN"))).unwrap();
        assert!(check_input(&with_token(Some("a"), Some("MAXNINES_SECRET_A"))).is_err());
        assert!(check_input(&with_token(Some("two words"), None)).is_err());
        assert!(check_input(&with_token(None, Some("DATABASE_URL"))).is_err());
        let both = MetricsPageInput {
            token: Some("abc".to_string()),
            ..with_login(Some("s3cret"), None)
        };
        let error = check_input(&both).unwrap_err().to_string();
        assert!(error.contains("not both"), "{error}");

        let saved = with_token(Some("abc"), None);
        assert_eq!(saved.sign_in(), SignIn::Token);
        assert!(saved.login().unwrap().is_some());
        // Nothing says to keep it, so a change with no token has none.
        assert_eq!(input().keeping_secrets_of(&saved, None).token, None);
        let kept = input().keeping_secrets_of(&saved, Some(SignIn::Token));
        assert_eq!(kept.token.as_deref(), Some("abc"));
        let dropped = input().keeping_secrets_of(&saved, Some(SignIn::None));
        assert_eq!(dropped.token, None);
        // Moving to a password lets go of it, and has none of its own to keep.
        let moved = with_login(None, None).keeping_secrets_of(&saved, Some(SignIn::Password));
        assert_eq!(
            (moved.token.as_ref(), moved.password.as_ref()),
            (None, None)
        );
        assert!(check_input(&moved).is_err());

        let unset = with_token(None, Some("MAXNINES_SECRET_NEVER_SET"));
        assert_eq!(
            unset.login().unwrap_err(),
            "the environment variable MAXNINES_SECRET_NEVER_SET isn't set"
        );
    }

    #[test]
    fn a_change_signs_in_the_way_it_said() {
        check_sign_in(&input(), None).unwrap();
        check_sign_in(&input(), Some(SignIn::None)).unwrap();
        check_sign_in(&with_token(Some("abc"), None), Some(SignIn::Token)).unwrap();
        check_sign_in(&with_login(Some("x"), None), Some(SignIn::Password)).unwrap();
        assert!(check_sign_in(&input(), Some(SignIn::Token)).is_err());
        assert!(check_sign_in(&input(), Some(SignIn::Password)).is_err());
        assert!(check_sign_in(&with_token(Some("abc"), None), Some(SignIn::None)).is_err());
    }

    #[test]
    fn a_token_is_never_printed() {
        let printed = format!("{:?}", with_token(Some("abc.DEF-123"), None));
        assert!(!printed.contains("abc.DEF-123"), "{printed}");
    }

    #[test]
    fn a_password_is_never_printed() {
        let printed = format!("{:?}", with_login(Some("s3cret"), None));
        assert!(printed.contains("metrics"), "{printed}");
        assert!(!printed.contains("s3cret"), "{printed}");
    }

    #[test]
    fn a_hosts_pages_need_different_names() {
        let other = MetricsPageInput {
            url: "http://db.example.com:9100/metrics".to_string(),
            ..input()
        };
        check_names([&input(), &other]).unwrap();
        // The same page, as far as its series' names go.
        let same = MetricsPageInput {
            url: "https://db.example.com:9187/metrics?x=1".to_string(),
            ..input()
        };
        assert!(check_names([&input(), &same]).is_err());

        let many: Vec<MetricsPageInput> = (0..=MAX_PAGES)
            .map(|port| MetricsPageInput {
                url: format!("http://db.example.com:{}/metrics", 9000 + port),
                ..input()
            })
            .collect();
        assert!(check_names(&many).is_err());
    }

    #[test]
    fn a_read_is_remembered_until_its_page_is_gone() {
        let page = |id: i64| MetricsPage {
            id,
            host_id: "a".to_string(),
            input: input(),
        };
        let up = || {
            vec![
                json!({ "name": "db", "up": 1, "dropped": 0 }),
                json!(["db x", 1.0, false]),
            ]
        };
        let down = || vec![json!({ "name": "db", "up": 0, "error": "timed out" })];
        let reads = PageReads::default();

        let (rows, answered) = reads.settle(&page(1), up());
        assert!(answered);
        assert_eq!(rows[1], json!({ "name": "db x", "value": 1.0 }));
        assert!(!reads.settle(&page(2), down()).1);
        assert_eq!(reads.result(2).unwrap()["error"], "timed out");
        assert_eq!(reads.result(9), None);

        reads.keep_only(&HashSet::from([1]));
        assert_eq!(reads.result(2), None);
        assert!(reads.result(1).is_some());

        // A page that's changed is as good as not read, until it is again.
        reads.changed(1);
        assert_eq!(reads.result(1), None);
        assert_eq!(reads.take_changed(), HashSet::from([1]));
        assert!(reads.take_changed().is_empty());
    }
}
