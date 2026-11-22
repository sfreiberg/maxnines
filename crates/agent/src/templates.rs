//! Reads what templates have this agent read: for each database a template runs
//! for, its discover blocks and queries, as the server worked them out for this
//! host. How each statement is run is in [`maxnines_checks::templates`], which the
//! server shares.
//!
//! Each database is a task of its own on the background runtime, with one
//! connection, running each discover block and query when it's due. Discovery runs
//! first, then on its own schedule, and again whenever the connection had to be
//! opened, as the database may have restarted. A database that doesn't answer is
//! tried once each time a growing wait runs out, and one that has nothing due is
//! checked every sample, so `up` is always as recent as a sample. A sample takes
//! what's been read since the last one: each template's rows under
//! `template.<key>`, whether each database answered as `up`, and what discovery
//! found under `discovered`, which the server uses to work out what to send next.
//!
//! A new config changes each task only as much as its work changed: one whose work
//! is the same carries on, and one whose work changed keeps its connection, what it
//! found, and the running totals of each query whose SQL is the same.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Result;
use maxnines_checks::databases::TIMEOUT;
use maxnines_checks::templates::{INSTANCE_LABEL, Session, Totals, discovered, metric_rows};
use maxnines_protocol::templates::work::{DISCOVERED, Discovered, TemplateWork, collector_of};
use serde_json::{Map, Value, json};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until};
use tracing::warn;

use crate::background::{jitter, runtime};
use crate::collector::Collector;
use crate::databases::DatabaseDefinitions;

/// What's been read since the last sample.
#[derive(Default)]
struct Read {
    /// Each template's rows, by its key.
    rows: BTreeMap<String, Vec<Value>>,
    /// Whether each database answered last time, by template and database.
    up: BTreeMap<(String, String), bool>,
    discovered: Vec<Discovered>,
}

/// How long after failing to reach a database it's tried again, at first, and at
/// most, each wait twice the last. A discover block that fails is tried again on the
/// same waits, up to its interval.
#[cfg(not(test))]
const FIRST_RETRY: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const MAX_RETRY: Duration = Duration::from_secs(60);
#[cfg(test)]
const FIRST_RETRY: Duration = Duration::from_millis(100);
#[cfg(test)]
const MAX_RETRY: Duration = Duration::from_millis(400);
/// What's run to see a database still answers when nothing else has for a while.
const ALIVE: &str = "SELECT 1";
/// What errors reaching a database are noted under.
const CONNECTING: &str = "connecting";

/// What one database's task is told to do: its work, and how often a sample is.
type Told = (TemplateWork, Duration);

/// One database's task.
struct Task {
    told: watch::Sender<Told>,
    running: AbortHandle,
}

pub struct TemplateCollector {
    read: Arc<Mutex<Read>>,
    /// By template and database.
    tasks: HashMap<(String, String), Task>,
}

impl TemplateCollector {
    /// Starts reading `work`, each query every `interval` unless it says. A database
    /// the agent's config doesn't define is reported as down.
    pub fn new(
        work: &[TemplateWork],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Result<Self> {
        let mut collector = Self {
            read: Arc::new(Mutex::new(Read::default())),
            tasks: HashMap::new(),
        };
        collector.update(work, definitions, interval)?;
        Ok(collector)
    }

    /// Changes what's read to `work`: a database's task whose work is the same
    /// carries on, one whose work changed is told, and the rest stop or start.
    pub fn update(
        &mut self,
        work: &[TemplateWork],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Result<()> {
        let mut wanted: HashMap<(String, String), &TemplateWork> = HashMap::new();
        for one in work {
            // Only a database template has anything this agent can read so far.
            if let Some(name) = &one.database {
                wanted.insert((one.template.clone(), name.clone()), one);
            }
        }
        // What isn't wanted any more stops, and says nothing more.
        self.tasks.retain(|key, task| {
            let keep = wanted.contains_key(key);
            if !keep {
                task.running.abort();
            }
            keep
        });
        lock(&self.read)
            .up
            .retain(|key, _| wanted.contains_key(key));

        for (key, one) in wanted {
            if let Some(task) = self.tasks.get(&key) {
                let told = (one.clone(), interval);
                task.told.send_if_modified(|current| {
                    let changed = *current != told;
                    *current = told;
                    changed
                });
                continue;
            }
            let (template, name) = &key;
            let database = definitions
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("the agent's config has no database by that name"))
                .and_then(|definition| definition.database(name));
            match database {
                Ok(database) => {
                    let (told, listening) = watch::channel((one.clone(), interval));
                    let running = runtime()?.spawn(run(
                        listening,
                        name.clone(),
                        Session::new(database),
                        self.read.clone(),
                    ));
                    let running = running.abort_handle();
                    self.tasks.insert(key, Task { told, running });
                }
                Err(error) => {
                    warn!(
                        template,
                        database = name,
                        error = format!("{error:#}"),
                        "a template can't read a database"
                    );
                    lock(&self.read).up.insert(key, false);
                }
            }
        }
        Ok(())
    }
}

impl Drop for TemplateCollector {
    fn drop(&mut self) {
        for task in self.tasks.values() {
            task.running.abort();
        }
    }
}

fn lock(read: &Mutex<Read>) -> std::sync::MutexGuard<'_, Read> {
    read.lock().unwrap_or_else(PoisonError::into_inner)
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
        let mut read = lock(&self.read);
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
        let found = std::mem::take(&mut read.discovered);
        if !found.is_empty() {
            entries.insert(DISCOVERED.to_string(), serde_json::to_value(found)?);
        }
        Ok(match entries.is_empty() {
            // Nothing read yet.
            true => Value::Null,
            false => Value::Object(entries),
        })
    }
}

/// When one discover block runs next, and how long it waits after failing.
struct DiscoverAt {
    at: Instant,
    retry: Duration,
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

impl Schedule {
    fn new((work, every): Told, now: Instant, before: Option<Self>) -> Self {
        let mut before = before;
        let discover = work
            .discover
            .iter()
            .map(|discover| {
                // The same block keeps its place; a new or changed one runs now.
                let same = before.as_mut().and_then(|before| {
                    let index = before
                        .work
                        .discover
                        .iter()
                        .position(|old| old == discover)?;
                    Some(std::mem::replace(
                        &mut before.discover[index],
                        DiscoverAt {
                            at: now,
                            retry: FIRST_RETRY,
                        },
                    ))
                });
                same.unwrap_or(DiscoverAt {
                    at: now,
                    retry: FIRST_RETRY,
                })
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

/// Reads one database for whatever templates have it read, for as long as the
/// config has it read, taking each change of what it's told as it comes.
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
    read: Arc<Mutex<Read>>,
) {
    let start = Instant::now();
    let mut schedule = Schedule::new(told.borrow_and_update().clone(), start, None);
    let mut found = Map::new();
    let mut errors: BTreeMap<String, String> = BTreeMap::new();
    let mut connections = 0;
    let mut retry_at = start;
    let mut retry = FIRST_RETRY;
    let mut check_at = start;

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
            }
            for (block, discover) in discover_at.iter_mut().zip(&work.discover) {
                if block.at > now || !session.is_up() {
                    continue;
                }
                match session.run(&discover.sql, TIMEOUT).await {
                    Ok(rows) => {
                        found.extend(discovered(&rows));
                        discovered_now = true;
                        errors.remove(&discover.key);
                        block.at = now + discover.interval;
                        block.retry = FIRST_RETRY;
                    }
                    Err(error) => {
                        note(work, &database, &discover.key, &error, &mut errors);
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
                match session.run(&query.sql, TIMEOUT).await {
                    Ok(read) => {
                        rows.extend(metric_rows(&read, query, &database, &mut at.totals));
                        errors.remove(&query.key);
                    }
                    Err(error) => note(work, &database, &query.key, &error, &mut errors),
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
        {
            let mut read = lock(&read);
            read.rows
                .entry(work.template.clone())
                .or_default()
                .extend(rows);
            read.up.insert(key.clone(), session.is_up());
            if discovered_now {
                read.discovered
                    .retain(|d| (&d.template, &d.database) != (&key.0, &key.1));
                read.discovered.push(Discovered {
                    template: work.template.clone(),
                    database: database.clone(),
                    values: found.clone(),
                });
            }
        }

        let next = match session.is_up() {
            true => discover_at
                .iter()
                .map(|block| block.at)
                .chain(query_at.iter().map(|query| query.at))
                .chain([check_at])
                .min()
                .unwrap_or(check_at),
            // Nothing runs until it answers again.
            false => retry_at,
        };
        tokio::select! {
            () = sleep_until(next) => {}
            changed = told.changed() => {
                if changed.is_err() {
                    // The collector's gone.
                    return;
                }
                let now = Instant::now();
                let new = told.borrow_and_update().clone();
                schedule = Schedule::new(new, now, Some(schedule));
            }
        }
    }
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
    let text = format!("{error:#}");
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
    use std::thread;
    use std::time::Duration;

    use maxnines_protocol::templates::work::{DiscoverWork, QueryWork};

    use super::*;

    fn work(database: &str) -> TemplateWork {
        TemplateWork {
            template: "pg".to_string(),
            database: Some(database.to_string()),
            discover: vec![DiscoverWork {
                key: "server".to_string(),
                interval: Duration::from_secs(3600),
                sql: "SELECT current_setting('server_version') AS version, \
                      pg_is_in_recovery() AS replica"
                    .to_string(),
            }],
            queries: vec![QueryWork {
                key: "throughput".to_string(),
                sql: "SELECT datname AS name, xact_commit AS commits, numbackends AS backends \
                      FROM pg_stat_database WHERE datname = 'postgres'"
                    .to_string(),
                interval: None,
                labels: vec!["name".to_string()],
                totals: vec!["commits".to_string()],
                omit: Vec::new(),
            }],
        }
    }

    /// Collects until `done` says it has what it waits for.
    fn collect_until(collector: &mut TemplateCollector, done: impl Fn(&Value) -> bool) -> Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut all = Map::new();
        loop {
            if let Value::Object(entries) = collector.collect().unwrap() {
                for (name, value) in entries {
                    match (all.get_mut(&name), value) {
                        (Some(Value::Array(rows)), Value::Array(more)) => rows.extend(more),
                        (_, value) => {
                            all.insert(name, value);
                        }
                    }
                }
            }
            let so_far = Value::Object(all.clone());
            if done(&so_far) {
                return so_far;
            }
            assert!(std::time::Instant::now() < deadline, "{so_far}");
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn a_database_the_config_does_not_define_is_down() {
        let mut collector = TemplateCollector::new(
            &[work("nowhere")],
            &DatabaseDefinitions::new(),
            Duration::from_secs(1),
        )
        .unwrap();
        let output = collector.collect().unwrap();
        assert_eq!(
            output["template.pg"],
            json!([{ "labels": { "instance": "nowhere" }, "up": 0 }])
        );
        assert!(output.get(DISCOVERED).is_none());
    }

    /// The throwaway PostgreSQL tests use, as `host:port username`.
    fn real() -> Option<DatabaseDefinitions> {
        let value = std::env::var("MAXNINES_TEST_CHECK_POSTGRES").ok()?;
        let mut words = value.split_whitespace();
        let (target, username) = (words.next()?, words.next()?);
        let definition = serde_json::from_value(json!({
            "kind": "postgres",
            "target": target,
            "username": username,
            "password": words.next(),
        }))
        .unwrap();
        Some(DatabaseDefinitions::from([(
            "main".to_string(),
            definition,
        )]))
    }

    /// Passes connections on to `to` once `forward` is set, and closes them until
    /// then, counting each one.
    fn gate(
        to: String,
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let forward = Arc::new(AtomicBool::new(false));
        let tries = Arc::new(AtomicUsize::new(0));
        let (forwarding, counting) = (forward.clone(), tries.clone());
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                counting.fetch_add(1, Ordering::SeqCst);
                if !forwarding.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(server) = TcpStream::connect(&to) else {
                    continue;
                };
                let (mut a, mut b) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                let (mut c, mut d) = (client, server);
                thread::spawn(move || std::io::copy(&mut a, &mut b));
                thread::spawn(move || std::io::copy(&mut d, &mut c));
            }
        });
        (address, forward, tries)
    }

    #[test]
    fn a_database_down_at_the_start_is_retried_then_discovered_at_once() {
        use std::sync::atomic::Ordering;
        let Ok(real) = std::env::var("MAXNINES_TEST_CHECK_POSTGRES") else {
            return;
        };
        let mut words = real.split_whitespace();
        let (target, username) = (words.next().unwrap(), words.next().unwrap());
        let (address, forward, tries) = gate(target.to_string());
        let definition = serde_json::from_value(json!({
            "kind": "postgres",
            "target": address,
            "username": username,
            "password": words.next(),
        }))
        .unwrap();
        let definitions = DatabaseDefinitions::from([("main".to_string(), definition)]);
        // Discovery is an hour apart, and the queries too, so only retrying and
        // the check every sample connect.
        let mut work = work("main");
        work.queries[0].interval = Some(Duration::from_secs(3600));
        let mut collector =
            TemplateCollector::new(&[work], &definitions, Duration::from_millis(200)).unwrap();

        // Down: said so, and tried once a wait, not once a statement.
        let down = collect_until(&mut collector, |output| {
            output["template.pg"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["up"] == 0))
        });
        assert!(down.get(DISCOVERED).is_none(), "{down}");
        thread::sleep(Duration::from_secs(1));
        // 100, 200, 400, 400ms waits in a second, and the first try.
        assert!(tries.load(Ordering::SeqCst) <= 6, "{tries:?}");

        // Up again: discovered at once, not an hour later.
        forward.store(true, Ordering::SeqCst);
        let up = collect_until(&mut collector, |output| output.get(DISCOVERED).is_some());
        assert!(up[DISCOVERED][0]["values"]["version"].is_string(), "{up}");
    }

    #[test]
    fn a_database_with_nothing_to_run_still_says_whether_it_answers() {
        let Some(definitions) = real() else {
            return;
        };
        let nothing = TemplateWork {
            discover: Vec::new(),
            queries: Vec::new(),
            ..work("main")
        };
        let mut collector =
            TemplateCollector::new(&[nothing], &definitions, Duration::from_millis(200)).unwrap();
        collect_until(&mut collector, |output| {
            output["template.pg"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["up"] == 1))
        });
    }

    #[test]
    fn new_work_keeps_the_connection_what_was_found_and_running_totals() {
        let Some(definitions) = real() else {
            return;
        };
        let every = Duration::from_millis(200);
        let mut collector = TemplateCollector::new(&[work("main")], &definitions, every).unwrap();
        collect_until(&mut collector, |output| {
            output["template.pg"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row.get("commits").is_some()))
        });

        // Discovery found a version, say, and the server sends a query more.
        let mut more = work("main");
        more.queries.push(QueryWork {
            key: "sessions".to_string(),
            sql: "SELECT count(*) AS sessions FROM pg_stat_activity".to_string(),
            interval: None,
            labels: Vec::new(),
            totals: Vec::new(),
            omit: Vec::new(),
        });
        collector.update(&[more], &definitions, every).unwrap();
        let after = collect_until(&mut collector, |output| {
            output["template.pg"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row.get("sessions").is_some()))
        });
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

        // Work no longer sent stops, and says nothing more.
        collector.update(&[], &definitions, every).unwrap();
        thread::sleep(Duration::from_millis(300));
        collector.collect().unwrap();
        assert_eq!(collector.collect().unwrap(), Value::Null);
    }

    #[test]
    fn a_real_database_is_discovered_and_read_with_totals_as_changes() {
        let Some(definitions) = real() else {
            return;
        };
        let mut collector =
            TemplateCollector::new(&[work("main")], &definitions, Duration::from_millis(200))
                .unwrap();
        // Two reads of the query, so its running total has a change.
        let output = collect_until(&mut collector, |output| {
            output["template.pg"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row.get("commits").is_some()))
        });
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
