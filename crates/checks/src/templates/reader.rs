//! Reads what templates have something read, for agents and for the server alike:
//! for each database a template runs for, its discover blocks and queries, as the
//! server worked them out for that host. How each statement is run is in
//! [`super::Session`].
//!
//! Each database is a task of its own, with one connection, running each discover
//! block and query when it's due. Discovery runs first, then on its own schedule,
//! and again whenever the connection had to be opened, as the database may have
//! restarted. A database that doesn't answer is tried once each time a growing wait
//! runs out, and one that has nothing due is checked every sample, so `up` is
//! always as recent as a sample. What the account it signs in as may do beyond
//! reading is read each time it connects, and every few minutes. What's been read
//! since it was last taken is given as a sample's entries: each template's rows
//! under `template.<key>`, whether each database answered as `up`, what discovery
//! found under `discovered`, which the server uses to work out what to read next,
//! and each database's account under `database_accounts`.
//!
//! New work changes each task only as much as its work changed: one whose work is
//! the same carries on, and one whose work changed keeps its connection, what it
//! found, and the running totals of each query whose SQL is the same. One whose
//! database is now somewhere else, or signed in to differently, starts again.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::Result;
use maxnines_protocol::templates::work::{
    ACCOUNT, ACCOUNTS, CONNECTING, DISCOVERED, Discovered, ERRORS, TemplateErrors, TemplateWork,
    check_statement, collector_of, error_text, part_name,
};
use serde_json::{Map, Value, json};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until};
use tracing::warn;

use super::{INSTANCE_LABEL, Privileges, Session, Totals, discovered, metric_rows, picked};
use crate::databases::{Database, TIMEOUT};
use crate::jitter;

/// What's been read since it was last taken.
#[derive(Default)]
struct Read {
    /// Each template's rows, by its key.
    rows: BTreeMap<String, Vec<Value>>,
    /// Whether each database answered last time, by template and database.
    up: BTreeMap<(String, String), bool>,
    discovered: Vec<Discovered>,
    /// What each database's account may do beyond reading, by the database's name,
    /// once it's been read.
    accounts: BTreeMap<String, Privileges>,
    /// What's going wrong, for each template and database whose errors changed.
    errors: Vec<TemplateErrors>,
}

impl Read {
    /// Says what's going wrong reading a template for a database now, in place of
    /// anything said of it that hasn't been taken yet.
    fn say_errors(&mut self, template: &str, database: &str, errors: BTreeMap<String, String>) {
        self.errors.retain(|said| {
            (said.template.as_str(), said.database.as_deref()) != (template, Some(database))
        });
        self.errors.push(TemplateErrors {
            template: template.to_string(),
            database: Some(database.to_string()),
            errors,
        });
    }
}

/// How long after failing to reach a database it's tried again, at first, and at
/// most, each wait twice the last. A discover block that fails is tried again on the
/// same waits, up to its interval.
#[cfg(not(test))]
pub const FIRST_RETRY: Duration = Duration::from_secs(5);
#[cfg(not(test))]
pub const MAX_RETRY: Duration = Duration::from_secs(60);
#[cfg(test)]
pub const FIRST_RETRY: Duration = Duration::from_millis(100);
#[cfg(test)]
pub const MAX_RETRY: Duration = Duration::from_millis(400);
/// What's run to see a database still answers when nothing else has for a while.
const ALIVE: &str = "SELECT 1";
/// How often what the account may do is read again while connected, so taking a
/// privilege away shows within minutes.
const ACCOUNT_EVERY: Duration = Duration::from_secs(5 * 60);

/// What one database's task is told to do: its work, and how often a sample is.
type Told = (TemplateWork, Duration);

/// One database's task.
struct Task {
    told: watch::Sender<Told>,
    /// Where it reads, and how it signs in, as it was started with.
    database: Database,
    running: AbortHandle,
}

/// What's been read, shared by the tasks that read it and whoever takes it.
#[derive(Clone, Default)]
pub struct Results(Arc<Mutex<Read>>);

impl Results {
    fn lock(&self) -> MutexGuard<'_, Read> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes what's been read since the last time, as a sample's entries: nothing
    /// before anything's been read.
    pub fn take(&self) -> Map<String, Value> {
        let mut read = self.lock();
        let mut rows = std::mem::take(&mut read.rows);
        for ((template, database), up) in &read.up {
            rows.entry(template.clone()).or_default().push(json!({
                "labels": { INSTANCE_LABEL: database },
                "up": u8::from(*up),
            }));
        }
        let mut entries: Map<String, Value> = rows
            .into_iter()
            .map(|(template, rows)| (collector_of(&template), Value::Array(rows)))
            .collect();
        if !read.accounts.is_empty() {
            let accounts = read.accounts.iter().map(|(database, account)| {
                json!({
                    "name": database,
                    "overprivileged": u8::from(account.overprivileged()),
                    "superuser": u8::from(account.superuser),
                    "writes": u8::from(account.writes),
                    "manages": u8::from(account.manages),
                    "server_files": u8::from(account.server_files),
                })
            });
            entries.insert(ACCOUNTS.to_string(), accounts.collect());
        }
        let errors = std::mem::take(&mut read.errors);
        if !errors.is_empty() {
            let errors = errors
                .iter()
                .filter_map(|one| serde_json::to_value(one).ok());
            entries.insert(ERRORS.to_string(), errors.collect());
        }
        let found = std::mem::take(&mut read.discovered);
        if !found.is_empty() {
            let found = found.into_iter().map(|one| {
                json!({ "template": one.template, "database": one.database, "values": one.values })
            });
            entries.insert(DISCOVERED.to_string(), found.collect());
        }
        entries
    }
}

/// Reads the work it's given, a task for each template and database.
#[derive(Default)]
pub struct Reader {
    results: Results,
    /// By template and database.
    tasks: HashMap<(String, String), Task>,
    /// Why each template and database that can't be read can't, as last said, so
    /// it's said once until it changes.
    unreadable: HashMap<(String, String), String>,
}

impl Reader {
    pub fn new() -> Self {
        Self::default()
    }

    /// What's been read, to take as samples are made.
    pub fn results(&self) -> Results {
        self.results.clone()
    }

    /// Changes what's read to `work`, each query every `every` unless it says, on
    /// `runtime`. `database` says where each database is, by its name, and how to
    /// sign in to it: one it can't say is reported as down. A database's task
    /// whose work is the same carries on, one whose work changed is told, one whose
    /// database changed starts again, and the rest stop or start.
    pub fn update(
        &mut self,
        work: &[TemplateWork],
        every: Duration,
        runtime: &Handle,
        database: impl Fn(&str) -> Result<Database>,
    ) {
        let mut wanted: HashMap<(String, String), &TemplateWork> = HashMap::new();
        for one in work {
            // Only a database template has anything to read so far.
            if let Some(name) = &one.database {
                wanted.insert((one.template.clone(), name.clone()), one);
            }
        }
        let mut found: HashMap<String, Result<Database>> = HashMap::new();
        for (_, name) in wanted.keys() {
            found.entry(name.clone()).or_insert_with(|| database(name));
        }
        // What isn't wanted any more, or is somewhere else now, stops, and says
        // nothing more: its task finds whoever told it gone before it says anything.
        self.unreadable.retain(|key, _| {
            found
                .get(&key.1)
                .is_some_and(|now| now.is_err() && wanted.contains_key(key))
        });
        self.tasks.retain(|key, task| {
            let keep = wanted.contains_key(key)
                && found
                    .get(&key.1)
                    .is_some_and(|now| now.as_ref().is_ok_and(|now| *now == task.database));
            if !keep {
                task.running.abort();
            }
            keep
        });
        {
            let mut read = self.results.lock();
            read.up.retain(|key, _| wanted.contains_key(key));
            read.accounts
                .retain(|database, _| wanted.keys().any(|(_, name)| name == database));
        }

        for (key, one) in wanted {
            if let Some(task) = self.tasks.get(&key) {
                let told = (one.clone(), every);
                task.told.send_if_modified(|current| {
                    let changed = *current != told;
                    *current = told;
                    changed
                });
                continue;
            }
            let (template, name) = &key;
            match &found[name] {
                Ok(database) => {
                    let (told, listening) = watch::channel((one.clone(), every));
                    let running = runtime.spawn(run(
                        listening,
                        name.clone(),
                        Session::new(database.clone()),
                        self.results.clone(),
                    ));
                    self.tasks.insert(
                        key,
                        Task {
                            told,
                            database: database.clone(),
                            running: running.abort_handle(),
                        },
                    );
                }
                Err(error) => {
                    let error = format!("{error:#}");
                    let mut read = self.results.lock();
                    if self.unreadable.get(&key) != Some(&error) {
                        warn!(
                            template,
                            database = name,
                            error,
                            "a template can't read a database"
                        );
                        let errors = BTreeMap::from([(CONNECTING.to_string(), error_text(&error))]);
                        read.say_errors(template, name, errors);
                        self.unreadable.insert(key.clone(), error);
                    }
                    read.up.insert(key, false);
                }
            }
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        for task in self.tasks.values() {
            task.running.abort();
        }
    }
}

/// When one discover block runs next, how long it waits after failing, and what
/// it found last, if it's found anything yet.
struct DiscoverAt {
    at: Instant,
    retry: Duration,
    found: Option<Map<String, Value>>,
}

impl DiscoverAt {
    fn now(now: Instant) -> Self {
        Self {
            at: now,
            retry: FIRST_RETRY,
            found: None,
        }
    }
}

/// When one query runs next, and its running totals.
struct QueryAt {
    at: Instant,
    totals: Totals,
}

/// Where a database's task is with what it was told, carried over when it's told
/// something new as much as what it does is the same.
struct Schedule {
    work: TemplateWork,
    every: Duration,
    discover: Vec<DiscoverAt>,
    queries: Vec<QueryAt>,
}

/// What every discover block found, together, or nothing if none has found
/// anything yet.
fn found_by(blocks: &[DiscoverAt]) -> Option<Map<String, Value>> {
    let mut all: Option<Map<String, Value>> = None;
    for block in blocks {
        if let Some(found) = &block.found {
            all.get_or_insert_with(Map::new).extend(
                found
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
        }
    }
    all
}

impl Schedule {
    fn new((work, every): Told, now: Instant, before: Option<Self>) -> Self {
        let mut before = before;
        let discover = work
            .discover
            .iter()
            .map(|discover| {
                // The same block keeps its place and what it found; a new or
                // changed one runs now, and what one that's gone found goes with it.
                let same = before.as_mut().and_then(|before| {
                    let index = before
                        .work
                        .discover
                        .iter()
                        .position(|old| old == discover)?;
                    Some(std::mem::replace(
                        &mut before.discover[index],
                        DiscoverAt::now(now),
                    ))
                });
                same.unwrap_or_else(|| DiscoverAt::now(now))
            })
            .collect();
        let queries = work
            .queries
            .iter()
            .map(|query| {
                let interval = query.interval.unwrap_or(every);
                let same = before.as_mut().and_then(|before| {
                    let index = before
                        .work
                        .queries
                        .iter()
                        .position(|old| old.key == query.key && old.sql == query.sql)?;
                    let kept = std::mem::replace(
                        &mut before.queries[index],
                        QueryAt {
                            at: now,
                            totals: Totals::default(),
                        },
                    );
                    let old = before.work.queries[index].interval.unwrap_or(before.every);
                    // Its totals carry on; it keeps its time unless that changed.
                    let at = match old == interval {
                        true => kept.at,
                        false => now + jitter(interval.min(every)),
                    };
                    Some(QueryAt {
                        at,
                        totals: kept.totals,
                    })
                });
                // A new one starts at a random point in its first interval, as
                // samples do.
                same.unwrap_or_else(|| QueryAt {
                    at: now + jitter(interval.min(every)),
                    totals: Totals::default(),
                })
            })
            .collect();
        Self {
            work,
            every,
            discover,
            queries,
        }
    }
}

/// Reads one database for whatever templates have it read, for as long as it's
/// wanted, taking each change of what it's told as it comes.
///
/// While the database doesn't answer, nothing is run: it's tried once each time a
/// wait runs out, the waits growing to [`MAX_RETRY`], and `up` says so. Once it
/// answers, and whenever it has to be connected to again, as after a restart,
/// discovery runs at once. A discover block that fails is tried again sooner than
/// its interval. With nothing due for a while, the connection is checked every
/// sample, so `up` is always as recent as a sample.
async fn run(
    mut told: watch::Receiver<Told>,
    database: String,
    mut session: Session,
    results: Results,
) {
    let start = Instant::now();
    let mut schedule = Schedule::new(told.borrow_and_update().clone(), start, None);
    // What was last said discovery found.
    let mut said: Option<Map<String, Value>> = None;
    let mut errors: BTreeMap<String, String> = BTreeMap::new();
    // What was last said is going wrong: nothing yet, so the first round says it,
    // even that all's well, in place of anything said before it started.
    let mut said_errors: Option<BTreeMap<String, String>> = None;
    let mut connections = 0;
    let mut retry_at = start;
    let mut retry = FIRST_RETRY;
    let mut check_at = start;
    let mut account_at = start;

    loop {
        let now = Instant::now();
        let Schedule {
            work,
            every,
            discover: discover_at,
            queries: query_at,
        } = &mut schedule;
        let every = *every;
        let key = (work.template.clone(), database.clone());
        let mut discovered_now = false;
        let mut account = None;
        let mut rows = Vec::new();
        // One try at reaching it each time the wait runs out, whatever's due.
        let reachable = session.is_up() || {
            if now >= retry_at {
                match session.open(TIMEOUT).await {
                    Ok(()) => {
                        retry = FIRST_RETRY;
                        errors.remove(CONNECTING);
                    }
                    Err(error) => {
                        note(work, &database, CONNECTING, &error, &mut errors);
                        retry_at = Instant::now() + retry;
                        retry = (retry * 2).min(MAX_RETRY);
                    }
                }
                check_at = Instant::now() + every;
            }
            session.is_up()
        };
        if reachable {
            // Connected anew, so it may have restarted: discover again, now.
            if session.connections() != connections {
                connections = session.connections();
                discover_at.iter_mut().for_each(|block| block.at = now);
                account_at = now;
            }
            if account_at <= now && session.is_up() {
                match session.privileges().await {
                    Ok(privileges) => {
                        account = Some(privileges);
                        errors.remove(ACCOUNT);
                    }
                    Err(error) => note(work, &database, ACCOUNT, &error, &mut errors),
                }
                account_at = now + ACCOUNT_EVERY;
                check_at = now + every;
            }
            for (block, discover) in discover_at.iter_mut().zip(&work.discover) {
                // A database's discover blocks all have SQL, as work is checked.
                let Some(sql) = &discover.sql else {
                    continue;
                };
                if block.at > now || !session.is_up() {
                    continue;
                }
                match session.run(sql, TIMEOUT).await {
                    Ok(rows) => {
                        block.found = Some(discovered(&rows));
                        discovered_now = true;
                        errors.remove(&part_name("discover", &discover.key));
                        block.at = now + discover.interval;
                        block.retry = FIRST_RETRY;
                    }
                    Err(error) => {
                        let part = part_name("discover", &discover.key);
                        note(work, &database, &part, &error, &mut errors);
                        // Sooner than its interval, as what it finds is waited on.
                        block.at = now + block.retry.min(discover.interval);
                        block.retry = (block.retry * 2).min(MAX_RETRY);
                    }
                }
                check_at = now + every;
            }
            for (at, query) in query_at.iter_mut().zip(&work.queries) {
                if at.at > now || !session.is_up() {
                    continue;
                }
                at.at = now + query.interval.unwrap_or(every);
                let ran = match check_statement(&query.key, &query.sql) {
                    Ok(()) => session.run(&query.sql, TIMEOUT).await,
                    Err(refused) => Err(refused),
                };
                match ran {
                    Ok(read) => {
                        let read = picked(read, query);
                        rows.extend(metric_rows(&read, query, &database, &mut at.totals));
                        errors.remove(&part_name("query", &query.key));
                    }
                    Err(error) => {
                        let part = part_name("query", &query.key);
                        note(work, &database, &part, &error, &mut errors);
                    }
                }
                check_at = now + every;
            }
            // Nothing ran for a while, so see that it still answers.
            if now >= check_at && session.is_up() {
                if let Err(error) = session.run(ALIVE, TIMEOUT).await {
                    note(work, &database, CONNECTING, &error, &mut errors);
                }
                check_at = now + every;
            }
            if !session.is_up() {
                retry_at = Instant::now() + retry;
                retry = (retry * 2).min(MAX_RETRY);
            }
        }
        // Said again whenever discovery ran, and when what was found changes as
        // what it's told to discover does.
        let found = found_by(discover_at);
        let say = found.is_some() && (discovered_now || found != said);
        {
            let mut read = results.lock();
            // Whoever told it to read has stopped it, and may have forgotten what it
            // said, so it says nothing more. Asked while holding what's read, so it
            // can't say anything after that's forgotten.
            if told.has_changed().is_err() {
                return;
            }
            read.rows
                .entry(work.template.clone())
                .or_default()
                .extend(rows);
            read.up.insert(key.clone(), session.is_up());
            if let Some(account) = account {
                read.accounts.insert(database.clone(), account);
            }
            // Only what's still read, as what it's told to read may have changed.
            errors.retain(|part, _| still_read(work, part));
            if said_errors.as_ref() != Some(&errors) {
                read.say_errors(&key.0, &key.1, errors.clone());
                said_errors = Some(errors.clone());
            }
            if say && let Some(found) = &found {
                read.discovered
                    .retain(|d| (&d.template, d.database.as_ref()) != (&key.0, Some(&key.1)));
                read.discovered.push(Discovered {
                    template: key.0.clone(),
                    database: Some(database.clone()),
                    values: found.clone(),
                });
            }
        }
        if say {
            said = found;
        }

        let next = match session.is_up() {
            true => discover_at
                .iter()
                .map(|block| block.at)
                .chain(query_at.iter().map(|query| query.at))
                .chain([check_at, account_at])
                .min()
                .unwrap_or(check_at),
            // Nothing runs until it answers again.
            false => retry_at,
        };
        tokio::select! {
            () = sleep_until(next) => {}
            changed = told.changed() => {
                if changed.is_err() {
                    // Whoever wanted it read has gone.
                    return;
                }
                let now = Instant::now();
                let new = told.borrow_and_update().clone();
                schedule = Schedule::new(new, now, Some(schedule));
            }
        }
    }
}

/// Whether what an error is about is still read by `work`.
fn still_read(work: &TemplateWork, part: &str) -> bool {
    part == CONNECTING
        || part == ACCOUNT
        || work
            .discover
            .iter()
            .any(|discover| part == part_name("discover", &discover.key))
        || work
            .queries
            .iter()
            .any(|query| part == part_name("query", &query.key))
}

/// Says what went wrong with a statement, once until it changes, as it's likely
/// to go wrong the same way every time.
fn note(
    work: &TemplateWork,
    database: &str,
    key: &str,
    error: &anyhow::Error,
    errors: &mut BTreeMap<String, String>,
) {
    let text = error_text(&format!("{error:#}"));
    if errors.get(key) != Some(&text) {
        warn!(
            template = work.template,
            database,
            statement = key,
            error = text,
            "a template's SQL failed"
        );
        errors.insert(key.to_string(), text);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use anyhow::anyhow;
    use maxnines_protocol::templates::work::{DiscoverWork, QueryWork};
    use maxnines_protocol::{Check, CheckKind};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    use super::*;
    use crate::Credentials;

    fn work(database: &str) -> TemplateWork {
        TemplateWork {
            template: "pg".to_string(),
            database: Some(database.to_string()),
            discover: vec![DiscoverWork {
                key: "server".to_string(),
                interval: Duration::from_secs(3600),
                sql: Some(
                    "SELECT current_setting('server_version') AS version, \
                     pg_is_in_recovery() AS replica"
                        .to_string(),
                ),
                registry: Vec::new(),
                counter_sets: Default::default(),
            }],
            queries: vec![QueryWork {
                key: "throughput".to_string(),
                sql: "SELECT datname AS name, xact_commit AS commits, numbackends AS backends \
                      FROM pg_stat_database WHERE datname = 'postgres'"
                    .to_string(),
                interval: None,
                labels: vec!["name".to_string()],
                columns: Default::default(),
                totals: vec!["commits".to_string()],
                omit: Vec::new(),
            }],
            counters: Vec::new(),
        }
    }

    /// The throwaway PostgreSQL tests use, from `MAXNINES_TEST_CHECK_POSTGRES` as
    /// `host:port username [password]`, reached at `target` if given.
    fn real(target: Option<&str>) -> Option<Database> {
        let value = std::env::var("MAXNINES_TEST_CHECK_POSTGRES").ok()?;
        let mut words = value.split_whitespace();
        let (real, username) = (words.next()?, words.next()?);
        Some(Database {
            check: Check::new("main", CheckKind::Postgres, target.unwrap_or(real)),
            credentials: Credentials {
                username: Some(username.to_string()),
                password: words.next().map(String::from),
                private_key: None,
            },
        })
    }

    fn reading(work: &[TemplateWork], every: Duration, database: &Database) -> Reader {
        let mut reader = Reader::new();
        reader.update(work, every, &Handle::current(), |_| Ok(database.clone()));
        reader
    }

    /// Takes what's read until `done` says it has what it waits for.
    async fn take_until(results: &Results, done: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut all = Map::new();
        loop {
            for (name, value) in results.take() {
                match (all.get_mut(&name), value) {
                    (Some(Value::Array(rows)), Value::Array(more)) => rows.extend(more),
                    (_, value) => {
                        all.insert(name, value);
                    }
                }
            }
            let so_far = Value::Object(all.clone());
            if done(&so_far) {
                return so_far;
            }
            assert!(Instant::now() < deadline, "{so_far}");
            sleep(Duration::from_millis(50)).await;
        }
    }

    fn has(output: &Value, column: &str) -> bool {
        output["template.pg"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row.get(column).is_some()))
    }

    fn says_up(output: &Value, up: u8) -> bool {
        output["template.pg"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["up"] == up))
    }

    #[tokio::test]
    async fn a_database_that_can_not_be_said_is_down() {
        let mut reader = Reader::new();
        reader.update(
            &[work("nowhere")],
            Duration::from_secs(1),
            &Handle::current(),
            |_| Err(anyhow!("no database by that name")),
        );
        let output = Value::Object(reader.results().take());
        assert_eq!(
            output["template.pg"],
            json!([{ "labels": { "instance": "nowhere" }, "up": 0 }])
        );
        assert!(output.get(DISCOVERED).is_none());
        assert_eq!(
            output[ERRORS],
            json!([{
                "template": "pg",
                "database": "nowhere",
                "errors": { "connecting": "no database by that name" },
            }])
        );
    }

    #[tokio::test]
    async fn what_goes_wrong_is_sent_as_it_changes_and_cleared_once_right() {
        let Some(database) = real(None) else {
            return;
        };
        let every = Duration::from_millis(200);
        let mut broken = work("main");
        broken.queries[0].key = "broken".to_string();
        broken.queries[0].sql = "SELECT nope AS commits".to_string();
        let mut reader = reading(&[broken], every, &database);
        let results = reader.results();
        // First that nothing's wrong yet, as nothing has run, then the query's error.
        let says_broken = |output: &Value| {
            output[ERRORS].as_array().is_some_and(|said| {
                said.iter()
                    .any(|one| one["errors"].get("query broken").is_some())
            })
        };
        let output = take_until(&results, says_broken).await;
        let said = output[ERRORS].as_array().unwrap().last().unwrap().clone();
        assert_eq!(
            (&said["template"], &said["database"]),
            (&json!("pg"), &json!("main"))
        );
        let error = said["errors"]["query broken"].as_str().unwrap_or_default();
        assert!(error.contains("nope"), "{output}");

        // Said once, not every round.
        sleep(every * 3).await;
        assert!(Value::from(results.take()).get(ERRORS).is_none());

        // Right again: all's well is said.
        reader.update(&[work("main")], every, &Handle::current(), |_| {
            Ok(database.clone())
        });
        let output = take_until(&results, |output| output.get(ERRORS).is_some()).await;
        assert_eq!(
            output[ERRORS],
            json!([{"template": "pg", "database": "main", "errors": {}}])
        );
    }

    /// Passes connections on to `to` once `forward` is set, and closes them until
    /// then, counting each one.
    async fn gate(to: String) -> (String, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let forward = Arc::new(AtomicBool::new(false));
        let tries = Arc::new(AtomicUsize::new(0));
        let (forwarding, counting) = (forward.clone(), tries.clone());
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                counting.fetch_add(1, Ordering::SeqCst);
                if !forwarding.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(mut server) = TcpStream::connect(&to).await else {
                    continue;
                };
                tokio::spawn(async move {
                    tokio::io::copy_bidirectional(&mut client, &mut server)
                        .await
                        .ok();
                });
            }
        });
        (address, forward, tries)
    }

    #[tokio::test]
    async fn a_database_down_at_the_start_is_retried_then_discovered_at_once() {
        let Some(real) = real(None) else {
            return;
        };
        let (address, forward, tries) = gate(real.check.target.clone()).await;
        let database = Database {
            check: Check::new("main", CheckKind::Postgres, &address),
            ..real
        };
        // Discovery is an hour apart, and the queries too, so only retrying and
        // the check every sample connect.
        let mut work = work("main");
        work.queries[0].interval = Some(Duration::from_secs(3600));
        let reader = reading(&[work], Duration::from_millis(200), &database);
        let results = reader.results();

        // Down: said so, and tried once a wait, not once a statement.
        let down = take_until(&results, |output| says_up(output, 0)).await;
        assert!(down.get(DISCOVERED).is_none(), "{down}");
        sleep(Duration::from_secs(1)).await;
        // 100, 200, 400, 400ms waits in a second, and the first try.
        assert!(tries.load(Ordering::SeqCst) <= 6, "{tries:?}");

        // Up again: discovered at once, not an hour later.
        forward.store(true, Ordering::SeqCst);
        let up = take_until(&results, |output| output.get(DISCOVERED).is_some()).await;
        assert!(up[DISCOVERED][0]["values"]["version"].is_string(), "{up}");
    }

    #[tokio::test]
    async fn a_database_with_nothing_to_run_still_says_whether_it_answers() {
        let Some(database) = real(None) else {
            return;
        };
        let nothing = TemplateWork {
            discover: Vec::new(),
            queries: Vec::new(),
            ..work("main")
        };
        let reader = reading(&[nothing], Duration::from_millis(200), &database);
        take_until(&reader.results(), |output| says_up(output, 1)).await;
    }

    #[tokio::test]
    async fn what_each_databases_account_may_do_is_sent_once_read() {
        let Some(database) = real(None) else {
            return;
        };
        let reader = reading(&[work("main")], Duration::from_millis(200), &database);
        let results = reader.results();
        let output = take_until(&results, |output| output.get(ACCOUNTS).is_some()).await;
        // The tests sign in as the throwaway server's superuser.
        assert_eq!(
            output[ACCOUNTS],
            json!([{
                "name": "main",
                "overprivileged": 1,
                "superuser": 1,
                "writes": 1,
                "manages": 1,
                "server_files": 1,
            }])
        );
        // It's given every time, not only when it's read.
        assert_eq!(Value::from(results.take())[ACCOUNTS], output[ACCOUNTS]);
    }

    #[tokio::test]
    async fn new_work_keeps_the_connection_what_was_found_and_running_totals() {
        let Some(database) = real(None) else {
            return;
        };
        let every = Duration::from_millis(200);
        let mut reader = reading(&[work("main")], every, &database);
        let results = reader.results();
        take_until(&results, |output| has(output, "commits")).await;

        // Discovery found a version, say, and the server sends a query more.
        let mut more = work("main");
        more.queries.push(QueryWork {
            key: "sessions".to_string(),
            sql: "SELECT count(*) AS sessions FROM pg_stat_activity".to_string(),
            interval: None,
            labels: Vec::new(),
            columns: Default::default(),
            totals: Vec::new(),
            omit: Vec::new(),
        });
        reader.update(&[more], every, &Handle::current(), |_| Ok(database.clone()));
        let after = take_until(&results, |output| has(output, "sessions")).await;
        let rows = after["template.pg"].as_array().unwrap();
        // The same query's totals carried on, so it's never without its change,
        // and nothing was discovered again, as the connection's the same.
        assert!(
            rows.iter()
                .filter(|row| row.get("backends").is_some())
                .all(|row| row.get("commits").is_some()),
            "{rows:?}"
        );
        assert!(after.get(DISCOVERED).is_none(), "{after}");

        // Work no longer wanted stops, and says nothing more.
        reader.update(&[], every, &Handle::current(), |_| Ok(database.clone()));
        sleep(Duration::from_millis(300)).await;
        results.take();
        assert!(results.take().is_empty());
    }

    /// What a discover block that's gone found goes with it, and what one that ran
    /// again found is what it finds now, not added to what it found before.
    #[tokio::test]
    async fn what_discovery_found_is_what_its_blocks_find_now() {
        let Some(database) = real(None) else {
            return;
        };
        let every = Duration::from_millis(200);
        let mut both = work("main");
        both.discover.push(DiscoverWork {
            key: "role".to_string(),
            interval: Duration::from_secs(3600),
            sql: Some("SELECT 'primary' AS role".to_string()),
            registry: Vec::new(),
            counter_sets: Default::default(),
        });
        let mut reader = reading(std::slice::from_ref(&both), every, &database);
        let results = reader.results();
        let found = |output: &Value| output[DISCOVERED][0]["values"].clone();
        let first = take_until(&results, |output| output.get(DISCOVERED).is_some()).await;
        assert_eq!(found(&first)["role"], json!("primary"), "{first}");
        assert!(found(&first).get("version").is_some(), "{first}");

        // The role block goes, so what it found goes too, at once.
        reader.update(&[work("main")], every, &Handle::current(), |_| {
            Ok(database.clone())
        });
        let after = take_until(&results, |output| output.get(DISCOVERED).is_some()).await;
        assert!(found(&after).get("role").is_none(), "{after}");
        assert!(found(&after).get("version").is_some(), "{after}");

        // A changed block runs again, and what it finds now replaces what it found.
        let mut changed = work("main");
        changed.discover[0].sql = Some("SELECT 'replica' AS role".to_string());
        reader.update(&[changed], every, &Handle::current(), |_| {
            Ok(database.clone())
        });
        let again = take_until(&results, |output| output.get(DISCOVERED).is_some()).await;
        assert_eq!(found(&again), json!({ "role": "replica" }), "{again}");
    }

    #[tokio::test]
    async fn a_database_somewhere_else_now_is_read_afresh() {
        let Some(database) = real(None) else {
            return;
        };
        let every = Duration::from_millis(200);
        let mut reader = reading(&[work("main")], every, &database);
        let results = reader.results();
        take_until(&results, |output| output.get(DISCOVERED).is_some()).await;

        // The same server by another address, as a check's target changed: read
        // there from then on, and discovered again, as it may be another server.
        let (address, forward, tries) = gate(database.check.target.clone()).await;
        forward.store(true, Ordering::SeqCst);
        let moved = Database {
            check: Check::new("main", CheckKind::Postgres, &address),
            ..database.clone()
        };
        reader.update(&[work("main")], every, &Handle::current(), |_| {
            Ok(moved.clone())
        });
        take_until(&results, |output| output.get(DISCOVERED).is_some()).await;
        assert!(tries.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn a_real_database_is_discovered_and_read_with_totals_as_changes() {
        let Some(database) = real(None) else {
            return;
        };
        let reader = reading(&[work("main")], Duration::from_millis(200), &database);
        // Two reads of the query, so its running total has a change.
        let output = take_until(&reader.results(), |output| has(output, "commits")).await;
        let found = &output[DISCOVERED][0];
        assert_eq!(
            (&found["template"], &found["database"]),
            (&json!("pg"), &json!("main"))
        );
        assert!(found["values"]["version"].is_string(), "{found}");
        assert_eq!(found["values"]["replica"], false);
        let rows = output["template.pg"].as_array().unwrap();
        let read = rows
            .iter()
            .find(|row| row.get("commits").is_some())
            .unwrap();
        assert_eq!(
            read["labels"],
            json!({ "instance": "main", "name": "postgres" })
        );
        assert!(read["backends"].as_f64().unwrap() >= 1.0, "{read}");
        assert!(rows.iter().any(|row| row["up"] == 1), "{rows:?}");
        // The first read of a total has no change to give.
        let first = rows
            .iter()
            .find(|row| row.get("backends").is_some())
            .unwrap();
        assert!(first.get("commits").is_none(), "{first}");
    }
}
