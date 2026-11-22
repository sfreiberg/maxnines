//! Reads what templates have this agent read: for each database a template runs
//! for, its discover blocks and queries, as the server worked them out for this
//! host. How each statement is run is in [`maxnines_checks::templates`], which the
//! server shares.
//!
//! Each database is a task of its own on the background runtime, with one
//! connection, running each discover block and query when it's due. Discovery runs
//! first, then on its own schedule, and again whenever the connection had to be
//! opened again, as the database may have restarted. A sample takes what's been
//! read since the last one: each template's rows under `template.<key>`, whether
//! each database answered as `up`, and what discovery found under `discovered`,
//! which the server uses to work out what to send next.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Result;
use maxnines_checks::databases::TIMEOUT;
use maxnines_checks::templates::{INSTANCE_LABEL, Session, Totals, discovered, metric_rows};
use maxnines_protocol::templates::work::{DISCOVERED, Discovered, TemplateWork, collector_of};
use serde_json::{Map, Value, json};
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

pub struct TemplateCollector {
    read: Arc<Mutex<Read>>,
    tasks: Vec<AbortHandle>,
}

impl TemplateCollector {
    /// Starts reading `work`, each query every `interval` unless it says. A database
    /// the agent's config doesn't define is reported as down.
    pub fn new(
        work: &[TemplateWork],
        definitions: &DatabaseDefinitions,
        interval: Duration,
    ) -> Result<Self> {
        let read = Arc::new(Mutex::new(Read::default()));
        let mut tasks = Vec::new();
        for one in work {
            // Only a database template has anything this agent can read so far.
            let Some(name) = &one.database else {
                continue;
            };
            let key = (one.template.clone(), name.clone());
            let database = definitions
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("the agent's config has no database by that name"))
                .and_then(|definition| definition.database(name));
            match database {
                Ok(database) => {
                    let task = runtime()?.spawn(run(
                        one.clone(),
                        name.clone(),
                        Session::new(database),
                        interval,
                        read.clone(),
                    ));
                    tasks.push(task.abort_handle());
                }
                Err(error) => {
                    warn!(
                        template = one.template,
                        database = name,
                        error = format!("{error:#}"),
                        "a template can't read a database"
                    );
                    lock(&read).up.insert(key, false);
                }
            }
        }
        Ok(Self { read, tasks })
    }
}

impl Drop for TemplateCollector {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
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

/// Reads one database for one template, for as long as the config lasts.
async fn run(
    work: TemplateWork,
    database: String,
    mut session: Session,
    every: Duration,
    read: Arc<Mutex<Read>>,
) {
    let start = Instant::now();
    let mut discover_at = vec![start; work.discover.len()];
    // Queries start at a random point in their first interval, as samples do.
    let mut query_at: Vec<Instant> = work
        .queries
        .iter()
        .map(|query| start + jitter(query.interval.unwrap_or(every).min(every)))
        .collect();
    let mut totals: Vec<Totals> = work.queries.iter().map(|_| Totals::default()).collect();
    let mut found = Map::new();
    let mut errors: BTreeMap<String, String> = BTreeMap::new();
    let mut connections = 0;
    let key = (work.template.clone(), database.clone());

    loop {
        let now = Instant::now();
        let mut discovered_now = false;
        // Once the database doesn't answer, the rest wait for the next round.
        let mut unreachable = false;
        for (index, discover) in work.discover.iter().enumerate() {
            if discover_at[index] > now || unreachable {
                continue;
            }
            discover_at[index] = now + discover.interval;
            match session.run(&discover.sql, TIMEOUT).await {
                Ok(rows) => {
                    found.extend(discovered(&rows));
                    discovered_now = true;
                    errors.remove(&discover.key);
                }
                Err(error) => {
                    unreachable = !session.is_up();
                    note(&work, &database, &discover.key, &error, &mut errors);
                }
            }
        }
        let mut rows = Vec::new();
        for (index, query) in work.queries.iter().enumerate() {
            if query_at[index] > now || unreachable {
                continue;
            }
            query_at[index] = now + query.interval.unwrap_or(every);
            match session.run(&query.sql, TIMEOUT).await {
                Ok(read) => {
                    rows.extend(metric_rows(&read, query, &database, &mut totals[index]));
                    errors.remove(&query.key);
                }
                Err(error) => {
                    unreachable = !session.is_up();
                    note(&work, &database, &query.key, &error, &mut errors);
                }
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

        // Connected again, so the database may have restarted: discover again.
        if connections > 0 && session.connections() > connections {
            discover_at.iter_mut().for_each(|at| *at = Instant::now());
        }
        connections = session.connections();
        let next = discover_at
            .iter()
            .chain(&query_at)
            .min()
            .copied()
            // With nothing to run, it only says whether the database answers.
            .unwrap_or_else(|| Instant::now() + every);
        sleep_until(next).await;
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
