use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result};
use duckdb::types::{TimeUnit, ToSqlOutput, ValueRef};
use duckdb::{Config, Connection, Transaction, appender_params_from_iter, params};
use maxnines_protocol::Sample;
use serde_json::Value;
use tracing::warn;

use super::flatten::{DataType, ENTRY_LABEL, Reported, Top, flatten};
use super::{CollectorStats, MetricsReader, NewSample, Store, StoreStats};
use crate::calculations::{Calculation, CalculationQuery, numbered};
use crate::metrics::{
    LastSample, METRICS, Metric, NewestReading, Point, Reading, Series, SeriesQuery, SeriesResult,
    Source,
};

/// A schema change. SeaORM doesn't support DuckDB, so this mirrors how its
/// migrations work: each one runs once, in order, and is recorded.
struct Migration {
    name: &'static str,
    sql: &'static str,
}

/// Every schema change, in order. Applied ones are recorded in the database, so
/// never edit one that has shipped: add a new one instead.
const MIGRATIONS: &[Migration] = &[Migration {
    name: "0001_create_tables",
    sql: include_str!("migrations/0001_create_tables.sql"),
}];

/// Only the bookkeeping table is created outside a migration, because it is
/// what records them.
const CREATE_MIGRATIONS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS schema_migrations (
        name       VARCHAR   PRIMARY KEY,
        applied_at TIMESTAMP NOT NULL
    );
";

/// Agents choose these names and how many series they have, so each is limited to
/// stop one agent filling the database or the server's memory.
const MAX_NAME_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 2048;
const MAX_SERIES_PER_AGENT: usize = 100_000;

const HOUR_MS: i64 = 3_600_000;

/// The most rows sorted at once, so that sorting fits in memory on any size of fleet.
const MAX_TIDY_ROWS: i64 = 1_000_000;

/// What identifies a series: its metric, its agent and its labels in one string.
type SeriesKey = (i32, i32, String);

/// Everything needed to turn a value into rows without asking the database. The
/// writer is the only thing that adds to these tables, so it can keep the whole list.
#[derive(Default)]
struct Names {
    collectors: HashMap<String, i32>,
    metrics: HashMap<(i32, String), (i32, DataType)>,
    agents: HashMap<String, i32>,
    series: HashMap<SeriesKey, i64>,
    series_per_agent: HashMap<i32, usize>,
    next_series: i64,
    /// Text that's current, so that only a change is written.
    texts: HashMap<i64, String>,
    /// Which series have current text, with the labels of what each describes, by
    /// agent and collector, for noticing when one stops being reported.
    text_series: HashMap<(i32, i32), HashMap<i64, String>>,
    /// Agents already warned about, so a noisy one doesn't fill the log.
    over_limit: HashSet<i32>,
}

fn labels_key(labels: &[(String, String)]) -> String {
    let mut key = String::new();
    for (name, value) in labels {
        key.push_str(name);
        key.push('\0');
        key.push_str(value);
        key.push('\0');
    }
    key
}

impl Names {
    fn load(connection: &Connection) -> Result<Self> {
        let mut names = Self::default();
        let mut statement = connection.prepare("SELECT id, name FROM collectors")?;
        for row in statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))? {
            let (id, name): (i32, String) = row?;
            names.collectors.insert(name, id);
        }

        let mut statement =
            connection.prepare("SELECT id, collector_id, name, data_type FROM metrics")?;
        let rows = statement.query_map([], |row| {
            let (id, collector, name, data_type): (i32, i32, String, String) =
                (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
            Ok(((collector, name), (id, DataType::parse(&data_type))))
        })?;
        for row in rows {
            let (key, value) = row?;
            names.metrics.insert(key, value);
        }

        let mut statement = connection.prepare("SELECT id, agent_id FROM agents")?;
        for row in statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))? {
            let (id, agent_id): (i32, String) = row?;
            names.agents.insert(agent_id, id);
        }

        let mut labels: HashMap<i64, Vec<(String, String)>> = HashMap::new();
        let mut statement = connection
            .prepare("SELECT series_id, name, value FROM series_labels ORDER BY rowid")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?))
        })?;
        for row in rows {
            let (id, name, value) = row?;
            labels.entry(id).or_default().push((name, value));
        }

        let collector_of: HashMap<i32, i32> = names
            .metrics
            .iter()
            .map(|((collector, _), (metric, _))| (*metric, *collector))
            .collect();
        let mut owners: HashMap<i64, ((i32, i32), String)> = HashMap::new();
        let mut statement = connection.prepare("SELECT id, metric_id, agent FROM series")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?))
        })?;
        for row in rows {
            let (id, metric, agent): (i64, i32, i32) = row?;
            let key = labels
                .get(&id)
                .map_or_else(String::new, |labels| labels_key(labels));
            if let Some(collector) = collector_of.get(&metric) {
                owners.insert(id, ((agent, *collector), key.clone()));
            }
            names.series.insert((metric, agent, key), id);
            *names.series_per_agent.entry(agent).or_default() += 1;
            names.next_series = names.next_series.max(id + 1);
        }

        let mut statement = connection.prepare(
            "SELECT series_id, arg_max_null(value, time) FROM texts GROUP BY series_id
             HAVING arg_max_null(value, time) IS NOT NULL",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (id, text) = row?;
            if let Some((owner, item)) = owners.get(&id) {
                let current = names.text_series.entry(*owner).or_default();
                current.insert(id, item.clone());
            }
            names.texts.insert(id, text);
        }
        Ok(names)
    }
}

/// What a batch of samples adds, gathered first so it can be written in one go.
#[derive(Default)]
struct Rows {
    collectors: Vec<(i32, String)>,
    metrics: Vec<(i32, i32, String, DataType)>,
    now_float: Vec<i32>,
    agents: Vec<(i32, String)>,
    series: Vec<(i64, i32, i32)>,
    labels: Vec<(i64, String, String)>,
    numbers: Vec<(i64, i32, i64, f64)>,
    texts: Vec<(i64, i64, Option<String>)>,
}

impl Names {
    fn collector(&mut self, name: &str, rows: &mut Rows) -> i32 {
        if let Some(id) = self.collectors.get(name) {
            return *id;
        }
        let id = i32::try_from(self.collectors.len()).unwrap_or(i32::MAX) + 1;
        self.collectors.insert(name.to_string(), id);
        rows.collectors.push((id, name.to_string()));
        id
    }

    fn agent(&mut self, agent_id: &str, rows: &mut Rows) -> i32 {
        if let Some(id) = self.agents.get(agent_id) {
            return *id;
        }
        let id = i32::try_from(self.agents.len()).unwrap_or(i32::MAX) + 1;
        self.agents.insert(agent_id.to_string(), id);
        rows.agents.push((id, agent_id.to_string()));
        id
    }

    /// JSON can't always tell `5` from `5.0`, so a metric that's ever had a fraction
    /// stays a float. Types other than that are whatever it first was.
    fn metric(&mut self, collector: i32, name: &str, kind: DataType, rows: &mut Rows) -> i32 {
        let next = i32::try_from(self.metrics.len()).unwrap_or(i32::MAX) + 1;
        let key = (collector, name.to_string());
        if let Some((id, known)) = self.metrics.get_mut(&key) {
            if *known == DataType::Int && kind == DataType::Float {
                *known = DataType::Float;
                rows.now_float.push(*id);
            }
            return *id;
        }
        self.metrics.insert(key, (next, kind));
        rows.metrics.push((next, collector, name.to_string(), kind));
        next
    }

    /// `None` once an agent has as many series as it's allowed.
    fn series(
        &mut self,
        metric: i32,
        agent: i32,
        labels: &[(String, String)],
        rows: &mut Rows,
    ) -> Option<i64> {
        let key = (metric, agent, labels_key(labels));
        if let Some(id) = self.series.get(&key) {
            return Some(*id);
        }
        let count = self.series_per_agent.entry(agent).or_default();
        if *count >= MAX_SERIES_PER_AGENT {
            if self.over_limit.insert(agent) {
                warn!(
                    agent,
                    "an agent reached the limit on series, ignoring new ones"
                );
            }
            return None;
        }
        *count += 1;
        let id = self.next_series.max(1);
        self.next_series = id + 1;
        self.series.insert(key, id);
        rows.series.push((id, metric, agent));
        for (name, value) in labels {
            rows.labels.push((id, name.clone(), value.clone()));
        }
        Some(id)
    }

    fn add_sample(&mut self, new: &NewSample, rows: &mut Rows) -> Result<()> {
        let time = microseconds(&new.sample)?;
        let agent = self.agent(&new.agent_id, rows);
        for (name, output) in &new.sample.metrics {
            if name.len() > MAX_NAME_BYTES {
                continue;
            }
            let collector = self.collector(name, rows);
            let mut reported = HashSet::new();
            let mut items = HashSet::new();
            for reading in flatten(output, top_of(name)) {
                let too_long = reading.metric.len() > MAX_NAME_BYTES
                    || reading.labels.iter().any(|(name, value)| {
                        name.len() > MAX_NAME_BYTES || value.len() > MAX_NAME_BYTES
                    });
                if too_long {
                    continue;
                }
                let item = labels_key(&reading.labels);
                items.insert(item.clone());
                let kind = match reading.value {
                    Reported::Number(_, kind) => kind,
                    Reported::Text(_) => DataType::Text,
                };
                let metric = self.metric(collector, &reading.metric, kind, rows);
                let Some(series) = self.series(metric, agent, &reading.labels, rows) else {
                    continue;
                };
                match reading.value {
                    Reported::Number(value, _) => rows.numbers.push((time, metric, series, value)),
                    Reported::Text(text) => {
                        let text = shortened(text);
                        reported.insert(series);
                        if self.texts.get(&series).is_none_or(|known| known != text) {
                            self.texts.insert(series, text.to_string());
                            rows.texts.push((time, series, Some(text.to_string())));
                            let current = self.text_series.entry((agent, collector)).or_default();
                            current.insert(series, item);
                        }
                    }
                }
            }

            // Something that was reported and isn't any more, like a check's error. A
            // sample may only cover some items, so only the ones in it can have changed.
            if let Some(current) = self.text_series.get_mut(&(agent, collector)) {
                current.retain(|series, item| {
                    let gone = items.contains(item) && !reported.contains(series);
                    if gone {
                        self.texts.remove(series);
                        rows.texts.push((time, *series, None));
                    }
                    !gone
                });
            }
        }
        Ok(())
    }
}

/// The catalog knows which collectors report a map of things.
fn top_of(collector: &str) -> Top {
    let has_entries = METRICS
        .iter()
        .any(|metric| metric.collector == collector && matches!(metric.source, Source::Entries(_)));
    if has_entries {
        Top::Entries
    } else {
        Top::Fields
    }
}

/// Cut at a character boundary, as text can be anything.
fn shortened(text: &str) -> &str {
    if text.len() <= MAX_TEXT_BYTES {
        return text;
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn timestamp(microseconds: i64) -> ToSqlOutput<'static> {
    ToSqlOutput::Borrowed(ValueRef::Timestamp(TimeUnit::Microsecond, microseconds))
}

/// Each appender is flushed by hand, because dropping one hides any failure.
fn write_rows(transaction: &Transaction<'_>, rows: &Rows) -> Result<()> {
    if !rows.collectors.is_empty() {
        let mut appender = transaction.appender("collectors")?;
        for (id, name) in &rows.collectors {
            appender.append_row(params![id, name])?;
        }
        appender.flush()?;
    }
    if !rows.metrics.is_empty() {
        let mut appender = transaction.appender("metrics")?;
        for (id, collector, name, kind) in &rows.metrics {
            appender.append_row(params![id, collector, name, kind.as_str()])?;
        }
        appender.flush()?;
    }
    if !rows.agents.is_empty() {
        let mut appender = transaction.appender("agents")?;
        for (id, agent_id) in &rows.agents {
            appender.append_row(params![id, agent_id])?;
        }
        appender.flush()?;
    }
    if !rows.series.is_empty() {
        let mut appender = transaction.appender("series")?;
        for (id, metric, agent) in &rows.series {
            appender.append_row(params![id, metric, agent])?;
        }
        appender.flush()?;
    }
    if !rows.labels.is_empty() {
        let mut appender = transaction.appender("series_labels")?;
        for (series, name, value) in &rows.labels {
            appender.append_row(params![series, name, value])?;
        }
        appender.flush()?;
    }
    for metric in &rows.now_float {
        transaction.execute(
            "UPDATE metrics SET data_type = ? WHERE id = ?",
            params![DataType::Float.as_str(), metric],
        )?;
    }
    if !rows.numbers.is_empty() {
        let mut appender = transaction.appender("samples_recent")?;
        for (time, metric, series, value) in &rows.numbers {
            let row = [
                timestamp(*time),
                ToSqlOutput::Borrowed(ValueRef::Int(*metric)),
                ToSqlOutput::Borrowed(ValueRef::BigInt(*series)),
                ToSqlOutput::Borrowed(ValueRef::Double(*value)),
            ];
            appender.append_row(appender_params_from_iter(row))?;
        }
        appender.flush()?;
    }
    if !rows.texts.is_empty() {
        let mut appender = transaction.appender("texts")?;
        for (time, series, text) in &rows.texts {
            let value = text
                .as_deref()
                .map_or(ValueRef::Null, |text| ValueRef::Text(text.as_bytes()));
            let row = [
                timestamp(*time),
                ToSqlOutput::Borrowed(ValueRef::BigInt(*series)),
                ToSqlOutput::Borrowed(value),
            ];
            appender.append_row(appender_params_from_iter(row))?;
        }
        appender.flush()?;
    }
    Ok(())
}

pub struct DuckDbStore {
    connection: Connection,
    names: Names,
}

impl DuckDbStore {
    pub fn open(path: &Path, memory_limit: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating folder {}", parent.display()))?;
        }
        let config = Config::default()
            .max_memory(memory_limit)
            .with_context(|| format!("invalid DuckDB memory_limit {memory_limit:?}"))?;
        let connection = Connection::open_with_flags(path, config)
            .with_context(|| format!("opening DuckDB database {}", path.display()))?;
        Self::with_connection(connection)
    }

    fn with_connection(mut connection: Connection) -> Result<Self> {
        migrate(&mut connection, MIGRATIONS)?;
        let names = Names::load(&connection).context("loading metric names")?;
        Ok(Self { connection, names })
    }

    /// Moves part of a finished hour into the sorted table, in one transaction, so
    /// nothing can be lost or seen twice. A piece at a time, so that writes aren't kept
    /// waiting and a bigger fleet doesn't need more memory. Series are moved in order,
    /// so each one's rows stay together however many pieces its metric takes.
    fn tidy_up_to(&mut self, now_ms: i64, max_rows: i64) -> Result<bool> {
        let hour_start = now_ms / HOUR_MS * HOUR_MS;
        let found = self.connection.query_row(
            "SELECT metric_id, epoch_ms(date_trunc('hour', time)) FROM samples_recent
             WHERE time < epoch_ms($1::BIGINT) LIMIT 1",
            params![hour_start],
            |row| Ok((row.get::<_, i32>(0)?, row.get::<_, i64>(1)?)),
        );
        let (metric, hour) = match found {
            Ok(found) => found,
            Err(duckdb::Error::QueryReturnedNoRows) => return Ok(false),
            Err(error) => return Err(error.into()),
        };

        let chosen = "WHERE metric_id = $1
                        AND time >= epoch_ms($2::BIGINT) AND time < epoch_ms($3::BIGINT)";
        let (rows, first, last): (i64, i64, i64) = self.connection.query_row(
            &format!(
                "SELECT count(*), min(series_id), max(series_id) FROM samples_recent {chosen}"
            ),
            params![metric, hour, hour + HOUR_MS],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let pieces = (rows + max_rows - 1) / max_rows;
        let up_to = first + (last - first) / pieces.max(1);

        let piece = format!("{chosen} AND series_id <= $4");
        let values = params![metric, hour, hour + HOUR_MS, up_to];
        // A series can only have one value at a moment, so anything more is a sample
        // sent twice, which the writer can't catch after a restart. That covers rows
        // that arrived late for an hour already sorted too.
        let already_sorted = format!(
            "SELECT series_id, time FROM samples
             WHERE metric_id = {metric}
               AND time >= epoch_ms({hour}::BIGINT)
               AND time < epoch_ms({next_hour}::BIGINT)
               AND series_id BETWEEN {first} AND {up_to}",
            next_hour = hour + HOUR_MS,
        );
        let transaction = self.connection.transaction()?;
        transaction.execute(
            &format!(
                "INSERT INTO samples
                 SELECT DISTINCT ON (series_id, time) r.*
                 FROM samples_recent r
                 ANTI JOIN ({already_sorted}) sorted USING (series_id, time)
                 {piece}
                 ORDER BY series_id, time"
            ),
            values,
        )?;
        transaction.execute(&format!("DELETE FROM samples_recent {piece}"), values)?;
        transaction.commit()?;
        Ok(true)
    }

    fn write_samples(&mut self, samples: &[NewSample]) -> Result<()> {
        let mut rows = Rows::default();
        for new in samples {
            self.names.add_sample(new, &mut rows)?;
        }
        let transaction = self.connection.transaction()?;
        write_rows(&transaction, &rows)?;
        transaction.commit()?;
        Ok(())
    }
}

/// Applies anything not yet recorded. Each migration and its record commit
/// together, so a failure leaves no half-applied change.
fn migrate(connection: &mut Connection, migrations: &[Migration]) -> Result<()> {
    connection
        .execute_batch(CREATE_MIGRATIONS_TABLE)
        .context("creating migrations table")?;

    for migration in migrations {
        let applied: i64 = connection.query_row(
            "SELECT count(*) FROM schema_migrations WHERE name = ?",
            params![migration.name],
            |row| row.get(0),
        )?;
        if applied > 0 {
            continue;
        }

        let transaction = connection.transaction()?;
        transaction
            .execute_batch(migration.sql)
            .with_context(|| format!("applying migration {}", migration.name))?;
        transaction.execute(
            "INSERT INTO schema_migrations VALUES (?, now()::TIMESTAMP)",
            params![migration.name],
        )?;
        transaction.commit()?;
    }
    Ok(())
}

impl Store for DuckDbStore {
    fn write(&mut self, samples: &[NewSample]) -> Result<()> {
        let result = self.write_samples(samples);
        if result.is_err() {
            // What was remembered for this batch never reached the database.
            self.names = Names::load(&self.connection).context("reloading metric names")?;
        }
        result
    }

    fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
        Ok(Arc::new(DuckDbReader {
            connection: Mutex::new(self.connection.try_clone()?),
        }))
    }

    fn tidy(&mut self, now_ms: i64) -> Result<bool> {
        self.tidy_up_to(now_ms, MAX_TIDY_ROWS)
    }

    /// Readers can outlive this connection, which would otherwise leave recent
    /// writes for the next start to replay.
    fn close(&mut self) -> Result<()> {
        self.connection
            .execute_batch("FORCE CHECKPOINT")
            .context("saving recent writes")
    }
}

/// Agents send this, so it can be anything.
fn microseconds(sample: &Sample) -> Result<i64> {
    i64::try_from(sample.timestamp_ms)
        .ok()
        .and_then(|milliseconds| milliseconds.checked_mul(1000))
        .context("timestamp out of range")
}

/// Reads on connections of its own, so a slow query doesn't hold up writes and
/// queries don't wait for each other.
struct DuckDbReader {
    connection: Mutex<Connection>,
}

impl DuckDbReader {
    fn connection(&self) -> Result<Connection> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(connection.try_clone()?)
    }
}

/// Anything beyond this is skipped, along with NaN and infinity, which compare
/// as larger. No real reading is this big, and an agent could otherwise send
/// values that overflow when added up, which fails the whole query.
const LARGEST_VALUE: &str = "1e300";

/// Which rows a reading of a metric covers. `agent` is `None` for every agent.
struct Scope {
    agent: Option<i32>,
    time: &'static str,
}

/// The number of a stored metric, which is what the sorted samples are found by.
fn metric_id(connection: &Connection, collector: &str, path: &str) -> Result<Option<i32>> {
    let found = connection.query_row(
        "SELECT m.id FROM metrics m JOIN collectors c ON c.id = m.collector_id
         WHERE c.name = ? AND m.name = ?",
        params![collector, path.trim_start_matches("$.")],
        |row| row.get(0),
    );
    match found {
        Ok(id) => Ok(Some(id)),
        Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// What a series is called in a result.
enum Naming<'a> {
    Fixed(&'a str),
    Label(&'a str),
}

/// One stored metric as rows of `agent_id`, `t`, `series` and `v`. Metric and agent
/// numbers and the names here come from the catalog, never from a request or an agent.
fn stored_values(
    connection: &Connection,
    metric: &Metric,
    path: &str,
    naming: &Naming<'_>,
    scope: &Scope,
) -> Result<String> {
    let Some(id) = metric_id(connection, metric.collector, path)? else {
        // Nothing has reported it yet. This still takes the query's parameters.
        return Ok(format!(
            "SELECT NULL::VARCHAR AS agent_id, 0::BIGINT AS t,
                    NULL::VARCHAR AS series, NULL::DOUBLE AS v
             FROM all_samples s WHERE false AND {}",
            scope.time
        ));
    };
    let (name, label) = match naming {
        Naming::Fixed(name) => (format!("'{name}'"), String::new()),
        Naming::Label(label) => (
            "l.value".to_string(),
            format!("JOIN series_labels l ON l.series_id = se.id AND l.name = '{label}'"),
        ),
    };
    let agent = scope
        .agent
        .map_or_else(String::new, |agent| format!("AND se.agent = {agent}"));
    Ok(format!(
        "SELECT a.agent_id, epoch_ms(s.time) AS t, {name} AS series, s.value AS v
         FROM all_samples s
         JOIN series se ON se.id = s.series_id
         JOIN agents a ON a.id = se.agent
         {label}
         WHERE s.metric_id = {id} {agent} AND {time}",
        time = scope.time,
    ))
}

fn reading_values(
    connection: &Connection,
    metric: &Metric,
    reading: Reading,
    naming: &Naming<'_>,
    scope: &Scope,
) -> Result<String> {
    match reading {
        Reading::Field(path) | Reading::Rate(path) => {
            stored_values(connection, metric, path, naming, scope)
        }
        Reading::Percent { part, whole } => Ok(format!(
            "SELECT p.agent_id, p.t, p.series, p.v / NULLIF(w.v, 0) * 100 AS v
             FROM ({}) p JOIN ({}) w USING (agent_id, t, series)",
            stored_values(connection, metric, part, naming, scope)?,
            stored_values(connection, metric, whole, naming, scope)?,
        )),
    }
}

/// One row per value, as `agent_id`, `t`, `series` and `v`.
fn readings(connection: &Connection, metric: &Metric, scope: &Scope) -> Result<String> {
    match metric.source {
        Source::Fields(fields) => {
            let selects = fields
                .iter()
                .map(|(name, field)| {
                    reading_values(connection, metric, *field, &Naming::Fixed(name), scope)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(selects.join(" UNION ALL "))
        }
        Source::Items { name, reading } => {
            let label = Naming::Label(name.trim_start_matches("$."));
            reading_values(connection, metric, reading, &label, scope)
        }
        Source::Entries(reading) => reading_values(
            connection,
            metric,
            reading,
            &Naming::Label(ENTRY_LABEL),
            scope,
        ),
    }
}

fn is_rate(source: Source) -> bool {
    match source {
        Source::Fields(fields) => fields
            .iter()
            .any(|(_, reading)| matches!(reading, Reading::Rate(_))),
        Source::Items { reading, .. } | Source::Entries(reading) => {
            matches!(reading, Reading::Rate(_))
        }
    }
}

/// Parameters: from, to, step, and how many series to keep.
fn series_sql(connection: &Connection, metric: &Metric, agent: i32) -> Result<String> {
    let rate = is_rate(metric.source);
    // Each value covers the time since the sample before it. The first in the
    // range has nothing to compare with, so it's dropped.
    let values = if rate {
        "SELECT t, series,
                v * 1000.0 / NULLIF(t - lag(t) OVER (PARTITION BY series ORDER BY t), 0) AS v
         FROM readings"
    } else {
        "SELECT t, series, v FROM readings"
    };
    // An idle interface says nothing, but a CPU at 0% does.
    let having = if rate { "HAVING max(v) > 0" } else { "" };
    let scope = Scope {
        agent: Some(agent),
        time: "s.time >= epoch_ms($1::BIGINT) AND s.time < epoch_ms($2::BIGINT)",
    };

    Ok(format!(
        "WITH readings AS ({readings}),
         computed AS ({values}),
         usable AS (
             SELECT t, series, v FROM computed
             WHERE series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}
         ),
         ranked AS (
             SELECT series,
                    row_number() OVER (ORDER BY avg(v) DESC, series) AS position,
                    count(*) OVER () AS total
             FROM usable GROUP BY series {having}
         )
         SELECT series, t // $3::BIGINT * $3::BIGINT AS bucket, avg(v), min(v), max(v), total
         FROM usable JOIN ranked USING (series)
         WHERE position <= $4::BIGINT
         GROUP BY series, bucket, total
         ORDER BY series, bucket",
        readings = readings(connection, metric, &scope)?,
    ))
}

/// Parameters: from, to, step, and how many lines to keep. `members` is pairs of an
/// agent's number and the number of its group, so nothing here comes from a request.
fn calculation_sql(
    connection: &Connection,
    query: &CalculationQuery,
    members: &[(i32, usize)],
) -> Result<String> {
    let values = if is_rate(query.metric.source) {
        "SELECT agent_id, t, series,
                v * 1000.0 / NULLIF(
                    t - lag(t) OVER (PARTITION BY agent_id, series ORDER BY t), 0
                ) AS v
         FROM readings"
    } else {
        "SELECT agent_id, t, series, v FROM readings"
    };
    let scope = Scope {
        agent: None,
        time: "s.time >= epoch_ms($1::BIGINT) AND s.time < epoch_ms($2::BIGINT)",
    };
    let members: Vec<String> = members
        .iter()
        .map(|(agent, group)| format!("({agent}, {group})"))
        .collect();
    let line = if query.by_series {
        "series"
    } else {
        "grp::VARCHAR"
    };
    let combined = match query.calculation {
        Calculation::Avg => "avg(v)",
        Calculation::Sum => "sum(v)",
        Calculation::Min => "min(v)",
        Calculation::Max => "max(v)",
        Calculation::Count => "count(*)::DOUBLE",
    };

    Ok(format!(
        "WITH members(agent, grp) AS (VALUES {members}),
         readings AS ({readings}),
         computed AS ({values}),
         usable AS (
             SELECT agent_id, t, series, v FROM computed
             WHERE series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}
         ),
         per_series AS (
             SELECT m.grp, u.agent_id, u.series,
                    u.t // $3::BIGINT * $3::BIGINT AS bucket, avg(u.v) AS v
             FROM usable u
             JOIN agents a ON a.agent_id = u.agent_id
             JOIN members m ON m.agent = a.id
             GROUP BY m.grp, u.agent_id, u.series, bucket
         ),
         combined AS (
             SELECT {line} AS line, bucket, {combined} AS v
             FROM per_series GROUP BY line, bucket
         ),
         ranked AS (
             SELECT line,
                    row_number() OVER (ORDER BY avg(v) DESC, line) AS position,
                    count(*) OVER () AS total
             FROM combined GROUP BY line
         )
         SELECT line, bucket, v, total
         FROM combined JOIN ranked USING (line)
         WHERE position <= $4::BIGINT
         ORDER BY line, bucket",
        members = members.join(", "),
        readings = readings(connection, query.metric, &scope)?,
    ))
}

/// Parameters: from and to.
fn newest_sql(connection: &Connection, metric: &Metric) -> Result<String> {
    let values = if is_rate(metric.source) {
        "SELECT agent_id, t, series,
                v * 1000.0 / NULLIF(
                    t - lag(t) OVER (PARTITION BY agent_id, series ORDER BY t), 0
                ) AS v
         FROM readings"
    } else {
        "SELECT agent_id, t, series, v FROM readings"
    };
    let scope = Scope {
        agent: None,
        time: "s.time >= epoch_ms($1::BIGINT) AND s.time <= epoch_ms($2::BIGINT)",
    };

    Ok(format!(
        "WITH readings AS ({readings}),
         computed AS ({values})
         SELECT agent_id, series, max(t), arg_max(v, t)
         FROM computed
         WHERE series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}
         GROUP BY agent_id, series
         ORDER BY agent_id, series",
        readings = readings(connection, metric, &scope)?,
    ))
}

/// The number of an agent the store has heard from.
fn agent_number(connection: &Connection, agent_id: &str) -> Result<Option<i32>> {
    let found = connection.query_row(
        "SELECT id FROM agents WHERE agent_id = ?",
        params![agent_id],
        |row| row.get(0),
    );
    match found {
        Ok(id) => Ok(Some(id)),
        Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Whole numbers come back as whole numbers, as agents sent them.
fn stored_number(number: f64, data_type: DataType) -> Value {
    const LARGEST_EXACT: f64 = 9_007_199_254_740_992.0;
    if data_type == DataType::Bool {
        Value::from(number != 0.0)
    } else if number.fract() == 0.0 && number.abs() < LARGEST_EXACT {
        Value::from(number as i64)
    } else {
        Value::from(number)
    }
}

/// A series of a collector, as its ID, field name, data type and label.
type StoredSeries = (i64, String, DataType, Option<(String, String)>);

/// One thing a collector reported on, as its label and its fields.
#[derive(Default)]
struct Item {
    label: Option<(String, String)>,
    fields: serde_json::Map<String, Value>,
}

/// Puts a collector's latest values back together, keeping items in the order they
/// were first seen.
fn rebuilt_output(
    series: &[StoredSeries],
    numbers: &HashMap<i64, f64>,
    texts: &HashMap<i64, String>,
) -> Option<Value> {
    // An item with no number in the latest sample wasn't in it.
    let current: HashSet<&Option<(String, String)>> = series
        .iter()
        .filter(|(id, ..)| numbers.contains_key(id))
        .map(|(_, _, _, label)| label)
        .collect();

    let mut items: BTreeMap<String, (i64, Item)> = BTreeMap::new();
    let current_series = series.iter().filter(|(.., label)| current.contains(label));
    for (id, field, data_type, label) in current_series {
        let value = match (numbers.get(id), texts.get(id)) {
            (Some(number), _) => stored_number(*number, *data_type),
            (None, Some(text)) => Value::from(text.clone()),
            (None, None) => continue,
        };
        let key = label
            .as_ref()
            .map_or_else(String::new, |(_, value)| value.clone());
        let (first, item) = items.entry(key).or_insert_with(|| {
            let item = Item {
                label: label.clone(),
                ..Item::default()
            };
            (*id, item)
        });
        *first = (*first).min(*id);
        item.fields.insert(field.clone(), value);
    }
    if items.is_empty() {
        return None;
    }

    let mut items: Vec<(i64, Item)> = items.into_values().collect();
    items.sort_by_key(|(first, _)| *first);
    if items.len() == 1 && items[0].1.label.is_none() {
        return items.pop().map(|(_, item)| Value::Object(item.fields));
    }
    let rebuilt = items.into_iter().map(|(_, mut item)| {
        if let Some((name, value)) = item.label {
            item.fields.insert(name, Value::from(value));
        }
        Value::Object(item.fields)
    });
    Some(Value::Array(rebuilt.collect()))
}

impl MetricsReader for DuckDbReader {
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult> {
        let connection = self.connection()?;
        let Some(agent) = agent_number(&connection, query.agent_id)? else {
            return Ok(SeriesResult::default());
        };
        let mut statement = connection.prepare(&series_sql(&connection, query.metric, agent)?)?;
        let range = query.range;
        let rows = statement.query_map(
            params![
                range.from_ms,
                range.to_ms,
                range.step_ms,
                i64::try_from(query.max_series)?,
            ],
            |row| {
                let point = Point {
                    time_ms: row.get(1)?,
                    avg: row.get(2)?,
                    min: row.get(3)?,
                    max: row.get(4)?,
                };
                Ok((row.get::<_, String>(0)?, point, row.get::<_, i64>(5)?))
            },
        )?;

        let mut result = SeriesResult::default();
        let mut total = 0;
        for row in rows {
            let (name, point, series_total) = row?;
            total = usize::try_from(series_total)?;
            match result.series.last_mut() {
                Some(series) if series.name == name => series.points.push(point),
                _ => result.series.push(Series {
                    name,
                    points: vec![point],
                }),
            }
        }
        result.hidden = total.saturating_sub(result.series.len());
        Ok(result)
    }

    fn last_samples(&self, since_ms: i64, until_ms: i64) -> Result<Vec<LastSample>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT a.agent_id, epoch_ms(newest.time)
             FROM (
                 SELECT se.agent, max(s.time) AS time
                 FROM all_samples s JOIN series se ON se.id = s.series_id
                 WHERE s.time >= epoch_ms($1::BIGINT) AND s.time <= epoch_ms($2::BIGINT)
                 GROUP BY se.agent
             ) newest JOIN agents a ON a.id = newest.agent",
        )?;
        let rows = statement.query_map(params![since_ms, until_ms], |row| {
            Ok(LastSample {
                agent_id: row.get(0)?,
                time_ms: row.get(1)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn latest_output(
        &self,
        agent_id: &str,
        collector: &str,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Option<Value>> {
        let connection = self.connection()?;
        let Some(agent) = agent_number(&connection, agent_id)? else {
            return Ok(None);
        };

        let mut statement = connection.prepare(
            "SELECT se.id, m.name, m.data_type, l.name, l.value
             FROM series se
             JOIN metrics m ON m.id = se.metric_id
             JOIN collectors c ON c.id = m.collector_id
             LEFT JOIN series_labels l ON l.series_id = se.id
             WHERE se.agent = ? AND c.name = ?
             ORDER BY se.id",
        )?;
        let rows = statement.query_map(params![agent, collector], |row| {
            let label: Option<(String, String)> = match (row.get(3)?, row.get(4)?) {
                (Some(name), Some(value)) => Some((name, value)),
                _ => None,
            };
            let data_type: String = row.get(2)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                DataType::parse(&data_type),
                label,
            ))
        })?;
        let series: Vec<_> = rows.collect::<Result<_, _>>()?;
        let Some(ids) = series
            .iter()
            .map(|(id, ..)| id.to_string())
            .reduce(|ids, id| format!("{ids}, {id}"))
        else {
            return Ok(None);
        };

        // Series numbers come from the database itself.
        let mut statement = connection.prepare(&format!(
            "WITH chosen AS (
                 SELECT time, series_id, value FROM all_samples
                 WHERE series_id IN ({ids})
                   AND time >= epoch_ms($1::BIGINT) AND time <= epoch_ms($2::BIGINT)
             )
             SELECT series_id, value FROM chosen
             WHERE time = (SELECT max(time) FROM chosen)"
        ))?;
        let rows = statement.query_map(params![since_ms, until_ms], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })?;
        let numbers: HashMap<i64, f64> = rows.collect::<Result<_, _>>()?;

        let mut statement = connection.prepare(&format!(
            "SELECT series_id, arg_max_null(value, time) FROM texts
             WHERE series_id IN ({ids}) AND time <= epoch_ms($1::BIGINT)
             GROUP BY series_id"
        ))?;
        let rows = statement.query_map(params![until_ms], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        let mut texts = HashMap::new();
        for row in rows {
            let (id, text) = row?;
            if let Some(text) = text {
                texts.insert(id, text);
            }
        }
        if numbers.is_empty() {
            return Ok(None);
        }
        Ok(rebuilt_output(&series, &numbers, &texts))
    }

    fn newest(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<NewestReading>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(&newest_sql(&connection, metric)?)?;
        let rows = statement.query_map(params![since_ms, until_ms], |row| {
            Ok(NewestReading {
                agent_id: row.get(0)?,
                series: row.get(1)?,
                time_ms: row.get(2)?,
                value: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn calculate(&self, query: &CalculationQuery) -> Result<SeriesResult> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT agent_id, id FROM agents")?;
        let numbers: HashMap<String, i32> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<duckdb::Result<_>>()?;

        let (groups, places) = numbered(&query.members);
        let members: Vec<(i32, usize)> = query
            .members
            .iter()
            .zip(places)
            .filter_map(|(member, place)| Some((*numbers.get(&member.agent_id)?, place)))
            .collect();
        if members.is_empty() {
            return Ok(SeriesResult::default());
        }

        let mut statement = connection.prepare(&calculation_sql(&connection, query, &members)?)?;
        let range = query.range;
        let rows = statement.query_map(
            params![
                range.from_ms,
                range.to_ms,
                range.step_ms,
                query.max_lines as i64
            ],
            |row| {
                let line: String = row.get(0)?;
                let time_ms: i64 = row.get(1)?;
                let value: f64 = row.get(2)?;
                let total: i64 = row.get(3)?;
                Ok((line, time_ms, value, total))
            },
        )?;

        let name_of = |line: &str| match line.parse::<usize>() {
            Ok(place) if !query.by_series => groups.get(place).map(ToString::to_string),
            _ => Some(line.to_string()),
        };
        let mut result = SeriesResult::default();
        let mut shown_of_total = 0;
        for row in rows {
            let (line, time_ms, value, total) = row?;
            shown_of_total = total;
            let point = Point {
                time_ms,
                avg: value,
                min: value,
                max: value,
            };
            let name = name_of(&line).unwrap_or_default();
            match result.series.last_mut() {
                Some(series) if series.name == name => series.points.push(point),
                _ => result.series.push(Series {
                    name,
                    points: vec![point],
                }),
            }
        }
        result.series.sort_by(|a, b| a.name.cmp(&b.name));
        let total = usize::try_from(shown_of_total)?;
        result.hidden = total.saturating_sub(result.series.len());
        Ok(result)
    }

    fn series_count(&self) -> Result<u64> {
        let connection = self.connection()?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM series", [], |row| row.get(0))?;
        Ok(count.try_into()?)
    }

    fn stats(&self, hour_ago_ms: i64) -> Result<StoreStats> {
        let connection = self.connection()?;
        let (size, write_ahead_log, memory_used, memory_limit) = connection.query_row(
            "SELECT database_size, wal_size, memory_usage, memory_limit
             FROM pragma_database_size()",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;

        let mut statement = connection.prepare(
            "SELECT c.name, sum(total)::BIGINT, sum(recent)::BIGINT,
                    epoch_ms(min(oldest)), epoch_ms(max(newest))
             FROM (
                 SELECT metric_id, count(*) AS total,
                        count(*) FILTER (WHERE time >= epoch_ms($1::BIGINT)) AS recent,
                        min(time) AS oldest, max(time) AS newest
                 FROM all_samples GROUP BY metric_id
             ) counted
             JOIN metrics m ON m.id = counted.metric_id
             JOIN collectors c ON c.id = m.collector_id
             GROUP BY c.name ORDER BY c.name",
        )?;
        let rows = statement.query_map(params![hour_ago_ms], |row| {
            Ok(CollectorStats {
                name: row.get(0)?,
                rows: row.get(1)?,
                rows_last_hour: row.get(2)?,
                oldest_ms: row.get(3)?,
                newest_ms: row.get(4)?,
            })
        })?;

        Ok(StoreStats {
            engine: "DuckDB",
            size,
            write_ahead_log,
            memory_used,
            memory_limit,
            collectors: rows.collect::<Result<_, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use super::*;
    use crate::calculations::Member;
    use crate::metrics::{METRICS, TimeRange, find};

    fn sample() -> Sample {
        Sample {
            timestamp_ms: 1_700_000_000_123,
            metrics: BTreeMap::from([
                ("cpu".to_string(), json!({ "usage_percent": 12.5 })),
                ("disk".to_string(), json!([{ "mount_point": "/" }])),
            ]),
        }
    }

    fn in_memory() -> DuckDbStore {
        DuckDbStore::with_connection(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn new_sample(agent_id: &str, host: &str, sample: &Sample) -> NewSample {
        NewSample {
            agent_id: agent_id.to_string(),
            host: host.to_string(),
            sample: sample.clone(),
        }
    }

    fn write_one(
        store: &mut DuckDbStore,
        agent_id: &str,
        host: &str,
        sample: &Sample,
    ) -> Result<()> {
        store.write(&[new_sample(agent_id, host, sample)])
    }

    fn write_metric(
        store: &mut DuckDbStore,
        agent: &str,
        time_ms: u64,
        collector: &str,
        data: Value,
    ) {
        let sample = Sample {
            timestamp_ms: time_ms,
            metrics: BTreeMap::from([(collector.to_string(), data)]),
        };
        write_one(store, agent, "host", &sample).unwrap();
    }

    fn query(store: &DuckDbStore, agent_id: &str, metric: &str, max_series: usize) -> SeriesResult {
        store
            .reader()
            .unwrap()
            .series(&SeriesQuery {
                agent_id,
                metric: find(metric).unwrap(),
                range: TimeRange::new(0, HOUR_MS).unwrap(),
                max_series,
            })
            .unwrap()
    }

    fn names(result: &SeriesResult) -> Vec<&str> {
        result.series.iter().map(|s| s.name.as_str()).collect()
    }

    fn averages(series: &Series) -> Vec<f64> {
        series.points.iter().map(|point| point.avg).collect()
    }

    #[test]
    fn values_in_a_bucket_are_summarized_together() {
        let mut store = in_memory();
        for (time_ms, usage) in [(1000, 10.0), (2000, 30.0), (16_000, 50.0)] {
            write_metric(
                &mut store,
                "a",
                time_ms,
                "cpu",
                json!({ "usage_percent": usage }),
            );
        }

        let result = query(&store, "a", "cpu.usage", 8);

        assert_eq!(names(&result), ["CPU"]);
        assert_eq!(
            result.series[0].points,
            [
                Point {
                    time_ms: 0,
                    avg: 20.0,
                    min: 10.0,
                    max: 30.0
                },
                Point {
                    time_ms: 15_000,
                    avg: 50.0,
                    min: 50.0,
                    max: 50.0
                },
            ]
        );
    }

    #[test]
    fn a_metric_can_have_several_fixed_series() {
        let mut store = in_memory();
        let load = json!({ "load_average": { "one": 1.0, "five": 2.0, "fifteen": 3.0 } });
        write_metric(&mut store, "a", 1000, "cpu", load);

        let result = query(&store, "a", "cpu.load", 8);

        assert_eq!(names(&result), ["1 minute", "15 minutes", "5 minutes"]);
        assert_eq!(averages(&result.series[1]), [3.0]);
    }

    #[test]
    fn a_platform_without_a_value_has_no_series_for_it() {
        let mut store = in_memory();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "load_average": null }),
        );
        assert!(query(&store, "a", "cpu.load", 8).series.is_empty());
    }

    #[test]
    fn usage_is_a_percentage_and_nothing_to_use_is_not_zero() {
        let mut store = in_memory();
        let memory = json!({
            "used_bytes": 1, "total_bytes": 4, "swap_used_bytes": 0, "swap_total_bytes": 0,
        });
        write_metric(&mut store, "a", 1000, "memory", memory);

        let result = query(&store, "a", "memory.usage", 8);

        assert_eq!(names(&result), ["Memory"]);
        assert_eq!(averages(&result.series[0]), [25.0]);
    }

    #[test]
    fn each_disk_is_a_series() {
        let mut store = in_memory();
        let disks = json!([
            { "mount_point": "/", "used_bytes": 1, "total_bytes": 2 },
            { "mount_point": "/data", "used_bytes": 3, "total_bytes": 4 },
        ]);
        write_metric(&mut store, "a", 1000, "disk", disks);

        let result = query(&store, "a", "disk.usage", 8);

        assert_eq!(names(&result), ["/", "/data"]);
        assert_eq!(averages(&result.series[1]), [75.0]);
    }

    #[test]
    fn network_counts_become_rates_using_the_time_between_samples() {
        let mut store = in_memory();
        for (time_ms, bytes) in [(0, 999_999), (10_000, 5000), (30_000, 20_000)] {
            let data = json!({ "en0": { "received_bytes": bytes, "transmitted_bytes": 0 } });
            write_metric(&mut store, "a", time_ms, "network", data);
        }

        let result = query(&store, "a", "network.received", 8);

        // The first has nothing before it, so nothing says what time it covers.
        assert_eq!(names(&result), ["en0"]);
        assert_eq!(averages(&result.series[0]), [500.0, 1000.0]);
    }

    #[test]
    fn an_idle_interface_is_left_out_without_counting_as_hidden() {
        let mut store = in_memory();
        for time_ms in [0, 15_000, 30_000] {
            let data = json!({
                "en0": { "received_bytes": 10 },
                "utun3": { "received_bytes": 0 },
            });
            write_metric(&mut store, "a", time_ms, "network", data);
        }

        let result = query(&store, "a", "network.received", 8);

        assert_eq!(names(&result), ["en0"]);
        assert_eq!(result.hidden, 0);
    }

    #[test]
    fn names_chosen_by_agents_are_kept_exactly() {
        let mut store = in_memory();
        let odd = [
            "eth0.100",
            "$.x",
            "we\"ird",
            "'; DROP TABLE metrics; --",
            "ünï",
        ];
        for time_ms in [0, 15_000] {
            let entries: serde_json::Map<String, Value> = odd
                .iter()
                .map(|name| (name.to_string(), json!({ "received_bytes": 10 })))
                .collect();
            write_metric(&mut store, "a", time_ms, "network", Value::Object(entries));
        }

        let result = query(&store, "a", "network.received", 8);

        let mut expected = odd.to_vec();
        expected.sort_unstable();
        assert_eq!(names(&result), expected);
        assert!(row_count(&store) > 0);
    }

    #[test]
    fn output_of_the_wrong_shape_is_skipped() {
        let mut store = in_memory();
        for data in [
            json!("text"),
            json!(null),
            json!([1, 2]),
            json!(7),
            json!({ "a": 1 }),
        ] {
            for collector in ["cpu", "memory", "disk", "network"] {
                write_metric(&mut store, "a", 1000, collector, data.clone());
                write_metric(&mut store, "a", 2000, collector, data.clone());
            }
        }

        for metric in METRICS {
            assert_eq!(query(&store, "a", metric.name, 8), SeriesResult::default());
        }
    }

    #[test]
    fn a_good_item_survives_bad_items_beside_it() {
        let mut store = in_memory();
        let disks = json!([
            7,
            { "used_bytes": 1, "total_bytes": 2 },
            { "mount_point": "/", "used_bytes": "x", "total_bytes": 2 },
            { "mount_point": "/ok", "used_bytes": 1, "total_bytes": 2 },
        ]);
        write_metric(&mut store, "a", 1000, "disk", disks);

        assert_eq!(names(&query(&store, "a", "disk.usage", 8)), ["/ok"]);
    }

    #[test]
    fn numbers_that_are_not_finite_are_skipped() {
        let mut store = in_memory();
        for (time_ms, usage) in [
            (1000, json!("NaN")),
            (2000, json!("inf")),
            (3000, json!(5.0)),
        ] {
            write_metric(
                &mut store,
                "a",
                time_ms,
                "cpu",
                json!({ "usage_percent": usage }),
            );
        }

        let result = query(&store, "a", "cpu.usage", 8);

        assert_eq!(averages(&result.series[0]), [5.0]);
    }

    #[test]
    fn numbers_too_large_to_add_up_are_skipped() {
        let mut store = in_memory();
        for (time_ms, usage) in [(1000, 1.7e308), (2000, 1.7e308), (3000, 5.0)] {
            let data = json!({ "usage_percent": usage });
            write_metric(&mut store, "a", time_ms, "cpu", data);
        }

        let result = query(&store, "a", "cpu.usage", 8);

        assert_eq!(averages(&result.series[0]), [5.0]);
    }

    #[test]
    fn a_query_only_sees_its_agent_and_its_time_range() {
        let mut store = in_memory();
        let cpu = || json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 1000, "cpu", cpu());
        write_metric(&mut store, "b", 1000, "cpu", cpu());
        write_metric(&mut store, "a", HOUR_MS as u64, "cpu", cpu());

        let result = query(&store, "a", "cpu.usage", 8);

        assert_eq!(result.series[0].points.len(), 1);
        assert_eq!(
            query(&store, "' OR 1=1 --", "cpu.usage", 8),
            SeriesResult::default()
        );
    }

    #[test]
    fn only_the_highest_series_are_kept_and_the_rest_are_counted() {
        let mut store = in_memory();
        let disks: Vec<Value> = (0..12)
            .map(|index| {
                json!({ "mount_point": format!("/{index:02}"), "used_bytes": index, "total_bytes": 100 })
            })
            .collect();
        write_metric(&mut store, "a", 1000, "disk", Value::Array(disks));

        let result = query(&store, "a", "disk.usage", 3);

        assert_eq!(names(&result), ["/09", "/10", "/11"]);
        assert_eq!(result.hidden, 9);
    }

    #[test]
    fn last_samples_give_each_agents_newest_time_from_any_collector() {
        let mut store = in_memory();
        let cpu = || json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 1000, "cpu", cpu());
        write_metric(&mut store, "a", 2000, "memory", json!({ "used_bytes": 1 }));
        write_metric(&mut store, "b", 1500, "cpu", cpu());

        let mut last = store.reader().unwrap().last_samples(0, 5000).unwrap();
        last.sort_by_key(|sample| sample.agent_id.clone());

        assert_eq!(
            last,
            [
                LastSample {
                    agent_id: "a".to_string(),
                    time_ms: 2000
                },
                LastSample {
                    agent_id: "b".to_string(),
                    time_ms: 1500
                },
            ]
        );
    }

    #[test]
    fn last_samples_ignore_what_is_outside_their_window() {
        let mut store = in_memory();
        let cpu = || json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "old", 1000, "cpu", cpu());
        write_metric(&mut store, "now", 5000, "cpu", cpu());
        write_metric(&mut store, "future", 9000, "cpu", cpu());

        let last = store.reader().unwrap().last_samples(2000, 8000).unwrap();

        assert_eq!(last.len(), 1);
        assert_eq!(last[0].agent_id, "now");
    }

    fn latest_output(store: &DuckDbStore, agent: &str, collector: &str) -> Option<Value> {
        let reader = store.reader().unwrap();
        reader.latest_output(agent, collector, 0, 9000).unwrap()
    }

    #[test]
    fn the_latest_output_keeps_text_and_whole_numbers_as_they_were_sent() {
        let mut store = in_memory();
        let old = json!([{ "name": "site", "kind": "http", "up": 1 }]);
        write_metric(&mut store, "a", 1000, "checks", old);
        let checks = json!([
            {
                "name": "site", "kind": "http", "up": 0, "error": "<refused>",
                "status": 503, "cert_days_left": -2, "response_ms": 12.5,
                "protocol": "HTTP/2", "cert_valid": false,
            },
            { "name": "dns", "kind": "dns", "up": 1 },
        ]);
        write_metric(&mut store, "a", 2000, "checks", checks);

        let output = latest_output(&store, "a", "checks").unwrap();

        assert_eq!(
            output,
            json!([
                {
                    "name": "site", "kind": "http", "up": 0, "error": "<refused>",
                    "status": 503, "cert_days_left": -2, "response_ms": 12.5,
                    "protocol": "HTTP/2", "cert_valid": false,
                },
                { "name": "dns", "kind": "dns", "up": 1 },
            ])
        );
        assert_eq!(output[0]["status"].as_u64(), Some(503));
    }

    #[test]
    fn the_latest_output_of_one_thing_is_an_object() {
        let mut store = in_memory();
        write_metric(&mut store, "a", 1000, "host", json!({ "uptime_secs": 90 }));

        let output = latest_output(&store, "a", "host").unwrap();

        assert_eq!(output, json!({ "uptime_secs": 90 }));
    }

    #[test]
    fn the_latest_output_is_only_ever_this_agents_and_recent() {
        let mut store = in_memory();
        let custom = |name| json!([{ "name": name, "ok": 1, "value": 1.5 }]);
        write_metric(&mut store, "a", 1000, "custom", custom("mine"));
        write_metric(&mut store, "b", 2000, "custom", custom("theirs"));
        write_metric(&mut store, "a", 20_000, "custom", custom("too new"));

        let output = latest_output(&store, "a", "custom").unwrap();

        assert_eq!(output[0]["name"], "mine");
        assert_eq!(output[0]["value"], 1.5);
        assert_eq!(latest_output(&store, "c", "custom"), None);
        assert_eq!(latest_output(&store, "a", "nonsense"), None);
    }

    #[test]
    fn reads_see_writes_and_work_while_writes_continue() {
        let mut store = in_memory();
        let reader = store.reader().unwrap();

        let reads = std::thread::spawn(move || {
            for _ in 0..200 {
                reader.last_samples(0, HOUR_MS).unwrap();
            }
            reader
        });
        for time_ms in 0..200 {
            write_metric(
                &mut store,
                "a",
                time_ms,
                "cpu",
                json!({ "usage_percent": 1.0 }),
            );
        }
        let reader = reads.join().unwrap();

        assert_eq!(reader.last_samples(0, HOUR_MS).unwrap()[0].time_ms, 199);
    }

    #[test]
    fn closing_saves_recent_writes_even_with_a_reader_open() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("m.duckdb");
        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        let reader = store.reader().unwrap();
        write_one(&mut store, "a", "h", &sample()).unwrap();
        assert!(path.with_extension("duckdb.wal").exists());

        store.close().unwrap();

        assert!(!path.with_extension("duckdb.wal").exists());
        assert_eq!(reader.last_samples(0, 2_000_000_000_000).unwrap().len(), 1);
    }

    /// How many numbers are saved, sorted or not.
    fn row_count(store: &DuckDbStore) -> i64 {
        store
            .connection
            .query_row("SELECT count(*) FROM all_samples", [], |row| row.get(0))
            .unwrap()
    }

    fn newest(store: &DuckDbStore, metric: &str, since: i64, until: i64) -> Vec<NewestReading> {
        store
            .reader()
            .unwrap()
            .newest(find(metric).unwrap(), since, until)
            .unwrap()
    }

    fn values(readings: &[NewestReading]) -> Vec<(&str, &str, i64, f64)> {
        readings
            .iter()
            .map(|r| (r.agent_id.as_str(), r.series.as_str(), r.time_ms, r.value))
            .collect()
    }

    #[test]
    fn newest_gives_each_agents_latest_value() {
        let mut store = in_memory();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 10.0 }),
        );
        write_metric(
            &mut store,
            "a",
            2000,
            "cpu",
            json!({ "usage_percent": 20.0 }),
        );
        write_metric(
            &mut store,
            "b",
            1500,
            "cpu",
            json!({ "usage_percent": 30.0 }),
        );

        assert_eq!(
            values(&newest(&store, "cpu.usage", 0, HOUR_MS)),
            [("a", "CPU", 2000, 20.0), ("b", "CPU", 1500, 30.0)]
        );
    }

    #[test]
    fn newest_keeps_each_series_apart() {
        let mut store = in_memory();
        let disk = |used: u64| {
            json!([
                { "mount_point": "/", "total_bytes": 100, "used_bytes": used },
                { "mount_point": "/data", "total_bytes": 100, "used_bytes": 50 },
            ])
        };
        write_metric(&mut store, "a", 1000, "disk", disk(10));
        write_metric(&mut store, "a", 2000, "disk", disk(20));

        assert_eq!(
            values(&newest(&store, "disk.usage", 0, HOUR_MS)),
            [("a", "/", 2000, 20.0), ("a", "/data", 2000, 50.0)]
        );
    }

    #[test]
    fn newest_ignores_samples_outside_its_window() {
        let mut store = in_memory();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 10.0 }),
        );
        write_metric(
            &mut store,
            "a",
            2000,
            "cpu",
            json!({ "usage_percent": 20.0 }),
        );
        write_metric(
            &mut store,
            "a",
            3000,
            "cpu",
            json!({ "usage_percent": 30.0 }),
        );

        assert_eq!(
            values(&newest(&store, "cpu.usage", 1500, 2500)),
            [("a", "CPU", 2000, 20.0)]
        );
    }

    #[test]
    fn newest_turns_counts_into_rates_per_agent() {
        let mut store = in_memory();
        let count = |bytes: u64| json!({ "en0": { "received_bytes": bytes } });
        write_metric(&mut store, "a", 10_000, "network", count(1000));
        write_metric(&mut store, "a", 20_000, "network", count(5000));
        // Sampled between the other agent's, which mustn't affect its rate.
        write_metric(&mut store, "b", 15_000, "network", count(100));
        write_metric(&mut store, "b", 16_000, "network", count(100));

        assert_eq!(
            values(&newest(&store, "network.received", 0, HOUR_MS)),
            [("a", "en0", 20_000, 500.0), ("b", "en0", 16_000, 100.0)]
        );
    }

    #[test]
    fn newest_needs_two_samples_for_a_rate() {
        let mut store = in_memory();
        let data = json!({ "en0": { "received_bytes": 1000 } });
        write_metric(&mut store, "a", 10_000, "network", data);

        assert!(newest(&store, "network.received", 0, HOUR_MS).is_empty());
    }

    #[test]
    fn newest_skips_values_that_are_not_usable_numbers() {
        let mut store = in_memory();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 10.0 }),
        );
        write_metric(
            &mut store,
            "a",
            2000,
            "cpu",
            json!({ "usage_percent": "lots" }),
        );
        write_metric(
            &mut store,
            "a",
            3000,
            "cpu",
            json!({ "usage_percent": 1.7e308 }),
        );
        write_metric(&mut store, "b", 1000, "cpu", json!({ "other": 1 }));

        assert_eq!(
            values(&newest(&store, "cpu.usage", 0, HOUR_MS)),
            [("a", "CPU", 1000, 10.0)]
        );
    }

    #[test]
    fn newest_handles_names_agents_choose() {
        let mut store = in_memory();
        let count = |bytes: u64| json!({ "eth0.100": { "received_bytes": bytes } });
        write_metric(&mut store, "a", 10_000, "network", count(100));
        write_metric(&mut store, "a", 20_000, "network", count(100));

        let readings = newest(&store, "network.received", 0, HOUR_MS);
        assert_eq!(readings[0].series, "eth0.100");
    }

    #[test]
    fn process_metrics_keep_each_watched_name_apart() {
        let mut store = in_memory();
        let data = json!([
            { "name": "nginx", "count": 3, "cpu_percent": 1.5, "memory_percent": 2.5 },
            { "name": "postgres", "count": 0, "cpu_percent": 0.0, "memory_percent": 0.0 },
        ]);
        write_metric(&mut store, "a", 1000, "processes", data);

        assert_eq!(
            values(&newest(&store, "process.count", 0, HOUR_MS)),
            [("a", "nginx", 1000, 3.0), ("a", "postgres", 1000, 0.0)]
        );
        assert_eq!(newest(&store, "process.cpu", 0, HOUR_MS)[0].value, 1.5);
        assert_eq!(newest(&store, "process.memory", 0, HOUR_MS)[0].value, 2.5);
        assert_eq!(
            names(&query(&store, "a", "process.count", 10)),
            ["nginx", "postgres"]
        );
    }

    #[test]
    fn cpu_and_memory_detail_read_what_the_agent_sends() {
        let mut store = in_memory();
        let cpu = |switches: u64| {
            json!({
                "time_percent": { "user": 20.0, "system": 5.0, "iowait": 7.5, "idle": 67.5 },
                "context_switches": switches,
            })
        };
        write_metric(&mut store, "a", 1000, "cpu", cpu(100));
        write_metric(&mut store, "a", 11_000, "cpu", cpu(500));
        let memory = json!({
            "detail": { "active_bytes": 2048, "free_bytes": 1024 },
            "swap_in_pages": 30,
        });
        write_metric(&mut store, "a", 1000, "memory", memory);

        let time = newest(&store, "cpu.time", 0, HOUR_MS);
        let reading = |name: &str| time.iter().find(|r| r.series == name).map(|r| r.value);
        assert_eq!(reading("User"), Some(20.0));
        assert_eq!(reading("I/O wait"), Some(7.5));
        assert_eq!(reading("Interrupt"), None);

        let rate = query(&store, "a", "cpu.context_switches", 10);
        assert_eq!(rate.series[0].points.last().unwrap().avg, 50.0);

        let detail = newest(&store, "memory.detail", 0, HOUR_MS);
        assert_eq!(
            values(&detail),
            [("a", "Active", 1000, 2048.0), ("a", "Free", 1000, 1024.0)]
        );
        assert_eq!(names(&query(&store, "a", "memory.detail", 10)).len(), 2);
    }

    #[test]
    fn limits_and_sessions_read_what_the_agent_sends() {
        let mut store = in_memory();
        let data = json!({
            "open_files": 250, "max_open_files": 1000,
            "processes": 1024, "max_processes": 4096, "login_sessions": 2,
        });
        write_metric(&mut store, "a", 1000, "system", data);

        assert_eq!(
            newest(&store, "system.open_files_used", 0, HOUR_MS)[0].value,
            25.0
        );
        assert_eq!(
            newest(&store, "system.processes_used", 0, HOUR_MS)[0].value,
            25.0
        );
        assert_eq!(newest(&store, "system.sessions", 0, HOUR_MS)[0].value, 2.0);
        assert_eq!(
            names(&query(&store, "a", "system.open_files", 10)),
            ["Limit", "Open"]
        );
    }

    #[test]
    fn a_broken_custom_metric_has_no_value_but_can_be_alerted_on() {
        let mut store = in_memory();
        let data = json!([
            { "name": "queue", "ok": 1, "value": 12.5 },
            { "name": "broken", "ok": 0, "error": "timed out" },
        ]);
        write_metric(&mut store, "a", 1000, "custom", data);

        assert_eq!(
            values(&newest(&store, "custom.value", 0, HOUR_MS)),
            [("a", "queue", 1000, 12.5)]
        );
        assert_eq!(
            values(&newest(&store, "custom.ok", 0, HOUR_MS)),
            [("a", "broken", 1000, 0.0), ("a", "queue", 1000, 1.0)]
        );
    }

    #[test]
    fn a_platform_without_a_limit_reports_no_percentage() {
        let mut store = in_memory();
        let data = json!({ "open_files": null, "max_open_files": null, "login_sessions": 1 });
        write_metric(&mut store, "a", 1000, "system", data);
        assert!(newest(&store, "system.open_files_used", 0, HOUR_MS).is_empty());
    }

    #[test]
    fn new_metrics_read_what_the_agent_sends() {
        let mut store = in_memory();
        let disk = |read: u64| {
            json!([{
                "mount_point": "/", "read_bytes": read, "written_bytes": 500,
                "inodes_total": 1000, "inodes_used": 250,
            }])
        };
        write_metric(&mut store, "a", 10_000, "disk", disk(0));
        write_metric(&mut store, "a", 20_000, "disk", disk(1000));
        let network = |packets: u64| {
            json!({ "en0": {
                "packets_received": packets, "packets_transmitted": 20, "receive_errors": 5,
                "transmit_errors": 0, "link_up": 1,
            } })
        };
        write_metric(&mut store, "a", 10_000, "network", network(0));
        write_metric(&mut store, "a", 20_000, "network", network(50));
        let sensors = json!([{ "label": "CPU die", "celsius": 54.5 }]);
        write_metric(&mut store, "a", 20_000, "sensors", sensors);
        let checks = json!([
            {
                "name": "site", "up": 1, "response_ms": 12.5, "cert_days_left": 30,
                "first_byte_ms": 8.0, "dns_ms": 1.0, "connect_ms": 2.0, "tls_ms": 3.0,
                "download_ms": 4.0, "content_length": 512, "status": 200,
                "records": 2, "packet_loss_percent": 20.0,
            },
            { "name": "db", "up": 0, "error": "couldn't connect" },
        ]);
        write_metric(&mut store, "a", 20_000, "checks", checks);
        let services = json!([{ "name": "nginx", "running": 1, "state": "active" }]);
        write_metric(&mut store, "a", 20_000, "services", services);
        let files = json!([
            { "path": "/b", "exists": 1, "size_bytes": 2048, "age_secs": 60.0 },
            { "path": "/gone", "exists": 0 },
            { "path": "/nfs", "error": "timed out" },
        ]);
        write_metric(&mut store, "a", 20_000, "files", files);

        let value = |metric: &str, series: &str| {
            let readings = newest(&store, metric, 0, HOUR_MS);
            let found = readings.iter().find(|r| r.series == series);
            found.map(|r| r.value)
        };
        assert_eq!(value("disk.read", "/"), Some(100.0));
        assert_eq!(value("disk.written", "/"), Some(50.0));
        assert_eq!(value("disk.inodes", "/"), Some(25.0));
        assert_eq!(value("network.packets.received", "en0"), Some(5.0));
        assert_eq!(value("network.packets.transmitted", "en0"), Some(2.0));
        assert_eq!(value("network.errors.received", "en0"), Some(0.5));
        assert_eq!(value("network.errors.transmitted", "en0"), Some(0.0));
        assert_eq!(value("network.link", "en0"), Some(1.0));
        assert_eq!(value("sensor.temperature", "CPU die"), Some(54.5));
        assert_eq!(value("check.up", "site"), Some(1.0));
        assert_eq!(value("check.up", "db"), Some(0.0));
        assert_eq!(value("check.response", "site"), Some(12.5));
        assert_eq!(
            value("check.response", "db"),
            None,
            "a failed check has no time"
        );
        assert_eq!(value("check.cert_days", "site"), Some(30.0));
        assert_eq!(value("check.first_byte", "site"), Some(8.0));
        assert_eq!(value("check.dns", "site"), Some(1.0));
        assert_eq!(value("check.connect", "site"), Some(2.0));
        assert_eq!(value("check.tls", "site"), Some(3.0));
        assert_eq!(value("check.download", "site"), Some(4.0));
        assert_eq!(value("check.size", "site"), Some(512.0));
        assert_eq!(value("check.status", "site"), Some(200.0));
        assert_eq!(value("check.records", "site"), Some(2.0));
        assert_eq!(value("check.packet_loss", "site"), Some(20.0));
        assert_eq!(value("service.running", "nginx"), Some(1.0));
        assert_eq!(value("file.exists", "/b"), Some(1.0));
        assert_eq!(value("file.exists", "/gone"), Some(0.0));
        assert_eq!(
            value("file.exists", "/nfs"),
            None,
            "a timeout isn't an answer"
        );
        assert_eq!(value("file.size", "/b"), Some(2048.0));
        assert_eq!(value("file.age", "/b"), Some(60.0));
    }

    #[test]
    fn every_metric_can_be_read_across_agents() {
        let store = in_memory();
        for metric in METRICS {
            assert!(
                newest(&store, metric.name, 0, HOUR_MS).is_empty(),
                "{}",
                metric.name
            );
        }
    }

    #[test]
    fn stats_count_what_each_collector_has_stored() {
        let mut store = in_memory();
        let cpu = || json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 1000, "cpu", cpu());
        write_metric(&mut store, "a", 5000, "cpu", cpu());
        write_metric(&mut store, "b", 9000, "cpu", cpu());
        let disks = json!([{ "mount_point": "/", "used_bytes": 1 }]);
        write_metric(&mut store, "a", 2000, "disk", disks);

        let stats = store.reader().unwrap().stats(4000).unwrap();

        assert_eq!(stats.engine, "DuckDB");
        assert!(!stats.memory_limit.is_empty());
        assert_eq!(
            stats.collectors,
            [
                CollectorStats {
                    name: "cpu".to_string(),
                    rows: 3,
                    rows_last_hour: 2,
                    oldest_ms: 1000,
                    newest_ms: 9000,
                },
                CollectorStats {
                    name: "disk".to_string(),
                    rows: 1,
                    rows_last_hour: 0,
                    oldest_ms: 2000,
                    newest_ms: 2000,
                },
            ]
        );
    }

    fn calculate(
        store: &DuckDbStore,
        metric: &str,
        calculation: Calculation,
        members: &[(&str, &str)],
        by_series: bool,
    ) -> SeriesResult {
        let query = CalculationQuery {
            metric: find(metric).unwrap(),
            range: TimeRange::new(0, 3_600_000).unwrap(),
            calculation,
            members: members
                .iter()
                .map(|(agent_id, group)| Member {
                    agent_id: agent_id.to_string(),
                    group: group.to_string(),
                })
                .collect(),
            by_series,
            max_lines: 8,
        };
        store.reader().unwrap().calculate(&query).unwrap()
    }

    fn line(series: &Series) -> Vec<f64> {
        series.points.iter().map(|point| point.avg).collect()
    }

    /// Two machines at 10% and 30%, and a third at 80% on its own.
    fn three_machines() -> DuckDbStore {
        let mut store = in_memory();
        for (agent, usage) in [("a", 10.0), ("b", 30.0), ("c", 80.0)] {
            write_metric(
                &mut store,
                agent,
                1000,
                "cpu",
                json!({ "usage_percent": usage }),
            );
        }
        store
    }

    #[test]
    fn machines_are_combined_into_one_line() {
        let store = three_machines();
        let everyone = [("a", "All"), ("b", "All"), ("c", "All")];

        for (calculation, expected) in [
            (Calculation::Avg, 40.0),
            (Calculation::Sum, 120.0),
            (Calculation::Min, 10.0),
            (Calculation::Max, 80.0),
            (Calculation::Count, 3.0),
        ] {
            let result = calculate(&store, "cpu.usage", calculation, &everyone, false);
            assert_eq!(result.series.len(), 1);
            assert_eq!(result.series[0].name, "All");
            assert_eq!(line(&result.series[0]), [expected], "{calculation:?}");
        }
    }

    #[test]
    fn machines_can_be_grouped_into_a_line_each() {
        let store = three_machines();
        let members = [("a", "web"), ("b", "web"), ("c", "db")];

        let result = calculate(&store, "cpu.usage", Calculation::Avg, &members, false);

        assert_eq!(result.series[0].name, "db");
        assert_eq!(line(&result.series[0]), [80.0]);
        assert_eq!(result.series[1].name, "web");
        assert_eq!(line(&result.series[1]), [20.0]);
    }

    #[test]
    fn only_the_machines_asked_for_count() {
        let store = three_machines();
        let result = calculate(&store, "cpu.usage", Calculation::Sum, &[("a", "x")], false);
        assert_eq!(line(&result.series[0]), [10.0]);
    }

    #[test]
    fn a_machine_nothing_has_been_heard_from_is_left_out() {
        let store = three_machines();
        let result = calculate(
            &store,
            "cpu.usage",
            Calculation::Sum,
            &[("nobody", "x")],
            false,
        );
        assert!(result.series.is_empty());
    }

    #[test]
    fn a_metrics_own_series_can_each_have_a_line() {
        let mut store = in_memory();
        let disks = |used: f64| {
            json!([
                { "mount_point": "/", "used_bytes": used, "total_bytes": 100.0 },
                { "mount_point": "/data", "used_bytes": 50.0, "total_bytes": 100.0 },
            ])
        };
        write_metric(&mut store, "a", 1000, "disk", disks(10.0));
        write_metric(&mut store, "b", 1000, "disk", disks(30.0));

        let members = [("a", "All"), ("b", "All")];
        let result = calculate(&store, "disk.usage", Calculation::Avg, &members, true);

        assert_eq!(result.series[0].name, "/");
        assert_eq!(line(&result.series[0]), [20.0]);
        assert_eq!(result.series[1].name, "/data");
        assert_eq!(line(&result.series[1]), [50.0]);
    }

    #[test]
    fn a_sample_stored_twice_does_not_change_a_sum() {
        let mut store = three_machines();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 10.0 }),
        );

        let everyone = [("a", "All"), ("b", "All"), ("c", "All")];
        let result = calculate(&store, "cpu.usage", Calculation::Sum, &everyone, false);

        assert_eq!(line(&result.series[0]), [120.0]);
    }

    #[test]
    fn the_highest_lines_are_kept_when_there_are_too_many() {
        let mut store = in_memory();
        let mut members = Vec::new();
        for number in 0..10 {
            let (agent, usage) = (format!("agent-{number}"), f64::from(number));
            write_metric(
                &mut store,
                &agent,
                1000,
                "cpu",
                json!({ "usage_percent": usage }),
            );
            members.push(agent);
        }

        let members: Vec<(&str, &str)> = members.iter().map(|a| (a.as_str(), a.as_str())).collect();
        let result = calculate(&store, "cpu.usage", Calculation::Avg, &members, false);

        assert_eq!(result.series.len(), 8);
        assert_eq!(result.hidden, 2);
        assert!(!result.series.iter().any(|series| series.name == "agent-0"));
    }

    #[test]
    fn rates_are_worked_out_per_machine_before_being_combined() {
        let mut store = in_memory();
        for (agent, per_sample) in [("a", 10.0), ("b", 30.0)] {
            for time in [10_000, 20_000] {
                let eth = json!({ "eth0": { "received_bytes": per_sample } });
                write_metric(&mut store, agent, time, "network", eth);
            }
        }

        let everyone = [("a", "All"), ("b", "All")];
        let result = calculate(
            &store,
            "network.received",
            Calculation::Sum,
            &everyone,
            false,
        );

        // 10 and 30 bytes over 10 seconds.
        assert_eq!(line(&result.series[0]), [4.0]);
    }

    fn stored_rows(store: &DuckDbStore) -> i64 {
        store
            .connection
            .query_row("SELECT count(*) FROM all_samples", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn a_sample_sent_twice_is_stored_once_after_tidying() {
        let mut store = in_memory();
        for agent in ["a", "a", "b"] {
            write_metric(
                &mut store,
                agent,
                1000,
                "cpu",
                json!({ "usage_percent": 5.0 }),
            );
        }
        write_metric(
            &mut store,
            "a",
            2000,
            "cpu",
            json!({ "usage_percent": 6.0 }),
        );
        assert_eq!(stored_rows(&store), 4);

        while store.tidy(HOUR_MS * 2).unwrap() {}

        assert_eq!(
            stored_rows(&store),
            3,
            "a's repeat is gone, and nothing else"
        );
    }

    #[test]
    fn a_repeat_arriving_after_its_hour_was_tidied_is_dropped_too() {
        let mut store = in_memory();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 5.0 }),
        );
        while store.tidy(HOUR_MS * 2).unwrap() {}

        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 5.0 }),
        );
        write_metric(
            &mut store,
            "a",
            3000,
            "cpu",
            json!({ "usage_percent": 7.0 }),
        );
        while store.tidy(HOUR_MS * 2).unwrap() {}

        assert_eq!(
            stored_rows(&store),
            2,
            "the late sample stays, the repeat doesn't"
        );
    }

    #[test]
    fn series_are_counted_once_however_often_they_report() {
        let mut store = in_memory();
        let reader = store.reader().unwrap();
        assert_eq!(reader.series_count().unwrap(), 0);

        for time in [1000, 2000] {
            let cpu = json!({ "usage_percent": 1.0, "load": 2.0 });
            write_metric(&mut store, "a", time, "cpu", cpu);
        }

        assert_eq!(reader.series_count().unwrap(), 2);
    }

    #[test]
    fn stats_work_on_an_empty_database() {
        let stats = in_memory().reader().unwrap().stats(0).unwrap();
        assert!(stats.collectors.is_empty());
    }

    #[test]
    fn stores_a_row_for_each_number_a_sample_holds() {
        let mut store = in_memory();
        write_one(&mut store, "agent-1", "web-1", &sample()).unwrap();
        // The usage from cpu. The disk has a mount point and nothing else.
        assert_eq!(row_count(&store), 1);
    }

    #[test]
    fn a_collector_nobody_has_heard_of_needs_no_schema_change() {
        let mut store = in_memory();
        let output = json!({
            "connections": 12, "cache": { "hit_rate": 0.95 }, "healthy": true,
            "version": "16.2",
        });

        write_metric(&mut store, "a", 1000, "postgres_plugin", output);

        let known: Vec<(String, String)> = store
            .connection
            .prepare(
                "SELECT m.name, m.data_type FROM metrics m
                 JOIN collectors c ON c.id = m.collector_id
                 WHERE c.name = 'postgres_plugin' ORDER BY m.name",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            known,
            [
                ("cache.hit_rate".to_string(), "float".to_string()),
                ("connections".to_string(), "int".to_string()),
                ("healthy".to_string(), "bool".to_string()),
                ("version".to_string(), "text".to_string()),
            ]
        );
        assert_eq!(row_count(&store), 3);
    }

    #[test]
    fn a_metric_that_shows_a_fraction_is_a_float_from_then_on() {
        let mut store = in_memory();
        write_metric(&mut store, "a", 1000, "cpu", json!({ "usage_percent": 5 }));
        write_metric(
            &mut store,
            "a",
            2000,
            "cpu",
            json!({ "usage_percent": 5.5 }),
        );
        write_metric(&mut store, "a", 3000, "cpu", json!({ "usage_percent": 6 }));

        let kind: String = store
            .connection
            .query_row("SELECT data_type FROM metrics", [], |row| row.get(0))
            .unwrap();

        assert_eq!(kind, "float");
        assert_eq!(
            averages(&query(&store, "a", "cpu.usage", 8).series[0]).len(),
            1
        );
    }

    fn text_rows(store: &DuckDbStore) -> Vec<Option<String>> {
        store
            .connection
            .prepare("SELECT value FROM texts ORDER BY time")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn text_is_only_saved_when_it_changes() {
        let mut store = in_memory();
        let service = |state| json!([{ "name": "nginx", "running": 1, "state": state }]);
        for (time_ms, state) in [(1000, "active"), (2000, "active"), (3000, "failed")] {
            write_metric(&mut store, "a", time_ms, "services", service(state));
        }

        assert_eq!(
            text_rows(&store),
            [Some("active".to_string()), Some("failed".to_string())]
        );
    }

    #[test]
    fn text_that_stops_being_reported_is_gone_rather_than_stuck() {
        let mut store = in_memory();
        let failing = json!([{ "name": "site", "up": 0, "error": "refused" }]);
        let working = json!([{ "name": "site", "up": 1 }]);
        write_metric(&mut store, "a", 1000, "checks", failing.clone());
        write_metric(&mut store, "a", 2000, "checks", working.clone());

        assert_eq!(
            latest_output(&store, "a", "checks").unwrap(),
            json!([{ "name": "site", "up": 1 }])
        );
        assert_eq!(text_rows(&store), [Some("refused".to_string()), None]);

        write_metric(&mut store, "a", 3000, "checks", failing.clone());
        assert_eq!(
            latest_output(&store, "a", "checks").unwrap()[0]["error"],
            "refused"
        );
    }

    #[test]
    fn one_agent_cannot_flood_the_store() {
        let mut store = in_memory();
        store.names.series_per_agent.insert(1, MAX_SERIES_PER_AGENT);
        store.names.agents.insert("noisy".to_string(), 1);

        write_metric(
            &mut store,
            "noisy",
            1000,
            "cpu",
            json!({ "usage_percent": 1.0 }),
        );
        write_metric(
            &mut store,
            "calm",
            1000,
            "cpu",
            json!({ "usage_percent": 1.0 }),
        );

        assert_eq!(row_count(&store), 1, "only the calm agent's");
    }

    #[test]
    fn names_and_text_that_are_too_long_are_limited() {
        let mut store = in_memory();
        let long = "x".repeat(MAX_NAME_BYTES + 1);
        write_metric(&mut store, "a", 1000, "cpu", json!({ long.clone(): 1 }));
        let disks = json!([{ "mount_point": long, "used_bytes": 1 }]);
        write_metric(&mut store, "a", 1000, "disk", disks);
        assert_eq!(row_count(&store), 0);

        let error = "é".repeat(MAX_TEXT_BYTES);
        let check = json!([{ "name": "site", "up": 0, "error": error }]);
        write_metric(&mut store, "a", 1000, "checks", check);

        let saved = text_rows(&store)[0].clone().unwrap();
        assert!(saved.len() <= MAX_TEXT_BYTES);
    }

    #[test]
    fn a_sample_covering_some_items_leaves_the_others_alone() {
        let mut store = in_memory();
        let check = |name, error| json!([{ "name": name, "up": 0, "error": error }]);
        // The server saves its own checks one at a time.
        for time_ms in [1000, 2000, 3000] {
            write_metric(
                &mut store,
                "server",
                time_ms,
                "checks",
                check("a", "refused"),
            );
            write_metric(
                &mut store,
                "server",
                time_ms + 1,
                "checks",
                check("b", "timed out"),
            );
        }

        assert_eq!(
            text_rows(&store),
            [Some("refused".to_string()), Some("timed out".to_string())]
        );
    }

    #[test]
    fn something_no_longer_reported_is_left_out_of_the_latest_output() {
        let mut store = in_memory();
        let failing = json!([
            { "name": "a", "up": 0, "error": "refused" },
            { "name": "b", "up": 1 },
        ]);
        write_metric(&mut store, "a", 1000, "checks", failing);
        write_metric(
            &mut store,
            "a",
            2000,
            "checks",
            json!([{ "name": "b", "up": 1 }]),
        );

        let output = latest_output(&store, "a", "checks").unwrap();

        assert_eq!(output, json!([{ "name": "b", "up": 1 }]));
    }

    #[test]
    fn text_that_cleared_stays_cleared_across_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("m.duckdb");
        let failing = json!([{ "name": "site", "up": 0, "error": "refused" }]);
        let working = json!([{ "name": "site", "up": 1 }]);

        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        write_metric(&mut store, "a", 1000, "checks", failing.clone());
        write_metric(&mut store, "a", 2000, "checks", working.clone());
        store.close().unwrap();
        drop(store);

        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        write_metric(&mut store, "a", 3000, "checks", working);
        assert_eq!(text_rows(&store).len(), 2, "nothing new to say");
        write_metric(&mut store, "a", 4000, "checks", failing);

        assert_eq!(text_rows(&store).len(), 3, "the same error again is news");
    }

    #[test]
    fn nothing_is_forgotten_across_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("m.duckdb");
        let service = |state| json!([{ "name": "nginx", "running": 1, "state": state }]);

        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        write_metric(&mut store, "a", 1000, "services", service("active"));
        store.close().unwrap();
        drop(store);

        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        write_metric(&mut store, "a", 2000, "services", service("active"));
        write_metric(&mut store, "b", 2000, "services", service("active"));

        let series: i64 = store
            .connection
            .query_row("SELECT count(*) FROM series", [], |row| row.get(0))
            .unwrap();
        let ids: i64 = store
            .connection
            .query_row("SELECT count(DISTINCT id) FROM series", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(series, ids, "no series was added twice");
        assert_eq!(series, 4, "two agents, each with a number and a text");
        assert_eq!(
            text_rows(&store).len(),
            2,
            "unchanged text isn't saved again"
        );
    }

    #[test]
    fn a_failed_write_forgets_what_it_learned() {
        let mut store = in_memory();
        store
            .connection
            .execute_batch("DROP TABLE samples_recent CASCADE")
            .unwrap_or_default();
        let result = write_one(&mut store, "a", "h", &sample());
        assert!(result.is_err());
        assert!(store.names.agents.is_empty());
    }

    fn sorted_count(store: &DuckDbStore) -> i64 {
        store
            .connection
            .query_row("SELECT count(*) FROM samples", [], |row| row.get(0))
            .unwrap()
    }

    fn tidy_all(store: &mut DuckDbStore, now_ms: i64) {
        while store.tidy(now_ms).unwrap() {}
    }

    #[test]
    fn tidying_moves_finished_hours_and_loses_nothing() {
        let mut store = in_memory();
        for minute in 0..150u32 {
            let usage = json!({ "usage_percent": f64::from(minute) });
            let memory = json!({ "used_bytes": 1, "total_bytes": 4 });
            write_metric(
                &mut store,
                "a",
                u64::from(minute) * 60_000,
                "cpu",
                usage.clone(),
            );
            write_metric(
                &mut store,
                "b",
                u64::from(minute) * 60_000,
                "memory",
                memory,
            );
        }
        let before = query(&store, "a", "cpu.usage", 8);
        let total = row_count(&store);

        tidy_all(&mut store, 150 * 60_000);

        assert_eq!(row_count(&store), total);
        // Two metrics of memory and one of cpu, for the two finished hours.
        assert_eq!(sorted_count(&store), 120 * 3);
        assert_eq!(query(&store, "a", "cpu.usage", 8), before);
    }

    #[test]
    fn a_big_hour_is_tidied_in_pieces_that_keep_each_series_together() {
        let mut store = in_memory();
        for minute in 0..20 {
            for agent in ["a", "b", "c", "d", "e"] {
                let usage = json!({ "usage_percent": 1.0 });
                write_metric(&mut store, agent, minute * 60_000, "cpu", usage);
            }
        }
        let before = query(&store, "c", "cpu.usage", 8);

        let mut moves = 0;
        while store.tidy_up_to(2 * HOUR_MS, 30).unwrap() {
            moves += 1;
        }

        assert!(moves >= 3, "{moves}");
        assert_eq!(sorted_count(&store), 100);
        assert_eq!(query(&store, "c", "cpu.usage", 8), before);
        let order: Vec<i64> = store
            .connection
            .prepare("SELECT series_id FROM samples ORDER BY rowid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(order.is_sorted(), "{order:?}");
    }

    #[test]
    fn tidying_leaves_the_current_hour_and_future_samples_alone() {
        let mut store = in_memory();
        let cpu = json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 3_700_000, "cpu", cpu.clone());
        write_metric(&mut store, "a", 99_000_000, "cpu", cpu);

        assert!(!store.tidy(3_800_000).unwrap());

        assert_eq!(sorted_count(&store), 0);
        assert_eq!(row_count(&store), 2);
    }

    #[test]
    fn a_late_sample_is_tidied_when_it_arrives() {
        let mut store = in_memory();
        let cpu = json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 1000, "cpu", cpu.clone());
        tidy_all(&mut store, 2 * HOUR_MS);
        // An agent coming back with samples it kept while it was offline.
        write_metric(&mut store, "a", 2000, "cpu", cpu);

        tidy_all(&mut store, 2 * HOUR_MS);

        assert_eq!(sorted_count(&store), 2);
        assert_eq!(row_count(&store), 2);
    }

    #[test]
    fn a_tidy_that_fails_changes_nothing() {
        let mut store = in_memory();
        let cpu = json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 1000, "cpu", cpu);
        store
            .connection
            .execute_batch(
                "DROP VIEW all_samples; DROP TABLE samples;
                 CREATE TABLE samples (time TIMESTAMP, metric_id INTEGER, series_id BIGINT,
                                       value DOUBLE CHECK (value > 5));
                 CREATE VIEW all_samples AS
                     SELECT * FROM samples UNION ALL SELECT * FROM samples_recent;",
            )
            .unwrap();

        assert!(store.tidy(2 * HOUR_MS).is_err());

        assert_eq!(row_count(&store), 1);
    }

    #[test]
    fn stored_values_can_be_queried() {
        let mut store = in_memory();
        write_one(&mut store, "agent-1", "web-1", &sample()).unwrap();

        let (time, agent_id, metric, value): (String, String, String, f64) = store
            .connection
            .query_row(
                "SELECT s.time::VARCHAR, a.agent_id, m.name, s.value FROM all_samples s
                 JOIN series se ON se.id = s.series_id
                 JOIN agents a ON a.id = se.agent
                 JOIN metrics m ON m.id = s.metric_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(time, "2023-11-14 22:13:20.123");
        assert_eq!(agent_id, "agent-1");
        assert_eq!(metric, "usage_percent");
        assert_eq!(value, 12.5);
    }

    #[test]
    fn rejects_out_of_range_timestamps() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = u64::MAX;

        assert!(write_one(&mut store, "agent-1", "web-1", &bad).is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn rejects_timestamps_too_large_to_store() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = i64::MAX as u64;

        assert!(write_one(&mut store, "agent-1", "web-1", &bad).is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn writes_several_samples_at_once() {
        let mut store = in_memory();
        let mut second = sample();
        second.timestamp_ms += 1000;

        store
            .write(&[
                new_sample("agent-1", "web-1", &sample()),
                new_sample("agent-2", "web-2", &second),
            ])
            .unwrap();

        let saved: Vec<(i64, String)> = store
            .connection
            .prepare(
                "SELECT epoch_ms(s.time), a.agent_id FROM all_samples s
                 JOIN series se ON se.id = s.series_id JOIN agents a ON a.id = se.agent
                 ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            saved,
            [
                (1_700_000_000_123, "agent-1".to_string()),
                (1_700_000_001_123, "agent-2".to_string())
            ]
        );
    }

    #[test]
    fn a_bad_sample_stores_none_of_its_batch() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = u64::MAX;

        let result = store.write(&[
            new_sample("agent-1", "web-1", &sample()),
            new_sample("agent-1", "web-1", &bad),
        ]);

        assert!(result.is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn a_failure_partway_through_a_sample_stores_none_of_it() {
        let mut store = in_memory();
        // Names are written first, then this rejects the numbers.
        store
            .connection
            .execute_batch(
                "DROP VIEW all_samples; DROP TABLE samples_recent;
                 CREATE TABLE samples_recent (time TIMESTAMP, metric_id INTEGER,
                                              series_id BIGINT, value DOUBLE CHECK (value > 99));
                 CREATE VIEW all_samples AS
                     SELECT * FROM samples UNION ALL SELECT * FROM samples_recent;",
            )
            .unwrap();

        assert!(write_one(&mut store, "agent-1", "web-1", &sample()).is_err());

        let series: i64 = store
            .connection
            .query_row("SELECT count(*) FROM series", [], |row| row.get(0))
            .unwrap();
        assert_eq!(series, 0);
        assert_eq!(row_count(&store), 0);
    }

    /// Something from every collector, with every kind of value.
    fn every_collector() -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "cpu".to_string(),
                json!({
                    "usage_percent": 12.5,
                    "per_core_percent": [10.0, 15.0],
                    "time_percent": { "user": 8.0, "system": 4.5, "idle": 87.5, "iowait": 0.0 },
                    "load_average": { "one": 1.5, "five": 1.25, "fifteen": 1.0 },
                    "context_switches": 5000,
                    "interrupts": 700,
                }),
            ),
            (
                "memory".to_string(),
                json!({
                    "total_bytes": 400, "used_bytes": 100, "available_bytes": 300,
                    "swap_total_bytes": 50, "swap_used_bytes": 5,
                    "swap_in_pages": 1, "swap_out_pages": 2,
                    "detail": { "active_bytes": 40, "free_bytes": 60 },
                }),
            ),
            (
                "host".to_string(),
                json!({ "uptime_secs": 90, "boot_time_secs": 10 }),
            ),
            (
                "system".to_string(),
                json!({
                    "open_files": 10, "max_open_files": 100, "processes": 20,
                    "max_processes": 200, "login_sessions": 2,
                }),
            ),
            (
                "disk".to_string(),
                json!([{
                    "name": "sda", "mount_point": "/", "file_system": "ext4", "kind": "SSD",
                    "total_bytes": 100, "used_bytes": 25, "available_bytes": 75,
                    "inodes_total": 10, "inodes_used": 1, "read_bytes": 500,
                    "written_bytes": 600, "read_only": false, "removable": true,
                }]),
            ),
            (
                "network".to_string(),
                json!({ "eth0.100": {
                    "received_bytes": 100, "transmitted_bytes": 200, "packets_received": 3,
                    "packets_transmitted": 4, "receive_errors": 5, "transmit_errors": 6,
                    "link_up": 1, "total_received_bytes": 1000,
                } }),
            ),
            (
                "processes".to_string(),
                json!([{ "name": "nginx", "count": 2, "cpu_percent": 5.0, "memory_percent": 1.5 }]),
            ),
            (
                "sensors".to_string(),
                json!([{ "label": "CPU die", "celsius": 55.5 }]),
            ),
            (
                "services".to_string(),
                json!([{ "name": "sshd", "running": 1, "state": "active" }]),
            ),
            (
                "files".to_string(),
                json!([
                    {
                        "path": "/var/log", "exists": 1, "is_folder": true, "age_secs": 30,
                        "size_bytes": 500, "entries": 4,
                    },
                    { "path": "/gone", "error": "not allowed" },
                ]),
            ),
            (
                "custom".to_string(),
                json!([
                    { "name": "queue", "ok": 1, "value": 7.5 },
                    { "name": "broken", "ok": 0, "error": "exit 1" },
                ]),
            ),
            (
                "checks".to_string(),
                json!([{
                    "name": "site", "kind": "http", "up": 1, "response_ms": 12.5, "dns_ms": 1.0,
                    "connect_ms": 2.0, "tls_ms": 3.0, "first_byte_ms": 4.0, "download_ms": 2.5,
                    "status": 200, "protocol": "HTTP/2", "content_length": 512,
                    "compressed": true, "regex_matched": true, "tls_version": "TLS 1.3",
                    "cert_valid": true, "hostname_valid": true, "cert_not_before": 100,
                    "cert_not_after": 900, "cert_days_left": 30, "records": 2,
                    "packet_loss_percent": 0.0, "rtt_min_ms": 1.0, "rtt_max_ms": 2.0,
                    "rtt_stddev_ms": 0.5,
                }]),
            ),
        ])
    }

    #[test]
    fn every_collector_can_be_read_back() {
        let mut store = in_memory();
        let sample = Sample {
            timestamp_ms: 1000,
            metrics: every_collector(),
        };

        write_one(&mut store, "a", "h", &sample).unwrap();

        let readable = METRICS
            .iter()
            .filter(|metric| !is_rate(metric.source))
            .filter(|metric| !query(&store, "a", metric.name, 8).series.is_empty())
            .count();
        assert!(readable > 25, "{readable}");
        let host = latest_output(&store, "a", "host").unwrap();
        assert_eq!(host, json!({ "uptime_secs": 90, "boot_time_secs": 10 }));
    }

    #[test]
    fn data_survives_reopening_and_creates_parent_folders() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/maxnines.duckdb");

        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        write_one(&mut store, "agent-1", "web-1", &sample()).unwrap();
        drop(store);

        let mut reopened = DuckDbStore::open(&path, "1GB").unwrap();
        write_one(&mut reopened, "agent-1", "web-1", &sample()).unwrap();
        assert_eq!(row_count(&reopened), 2);
    }

    fn applied_migrations(connection: &Connection) -> i64 {
        connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn table_exists(connection: &Connection, name: &str) -> bool {
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM information_schema.tables WHERE table_name = ?",
                params![name],
                |row| row.get(0),
            )
            .unwrap();
        count > 0
    }

    const FIRST: Migration = Migration {
        name: "first",
        sql: "CREATE TABLE first (id INTEGER)",
    };
    const SECOND: Migration = Migration {
        name: "second",
        sql: "CREATE TABLE second (id INTEGER)",
    };

    #[test]
    fn a_new_database_gets_every_migration_recorded() {
        let store = in_memory();
        assert_eq!(
            applied_migrations(&store.connection),
            MIGRATIONS.len() as i64
        );
    }

    #[test]
    fn a_migration_only_runs_once() {
        let mut connection = Connection::open_in_memory().unwrap();

        migrate(&mut connection, &[FIRST]).unwrap();
        // Running it again would fail, because the table already exists.
        migrate(&mut connection, &[FIRST]).unwrap();

        assert_eq!(applied_migrations(&connection), 1);
    }

    #[test]
    fn a_new_migration_applies_to_an_existing_database() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection, &[FIRST]).unwrap();

        migrate(&mut connection, &[FIRST, SECOND]).unwrap();

        assert!(table_exists(&connection, "second"));
        assert_eq!(applied_migrations(&connection), 2);
    }

    #[test]
    fn a_failed_migration_changes_nothing_and_stops_later_ones() {
        let mut connection = Connection::open_in_memory().unwrap();
        let broken = Migration {
            name: "broken",
            sql: "CREATE TABLE partial (id INTEGER); THIS IS NOT SQL;",
        };

        assert!(migrate(&mut connection, &[FIRST, broken, SECOND]).is_err());

        assert_eq!(applied_migrations(&connection), 1);
        assert!(!table_exists(&connection, "partial"));
        assert!(!table_exists(&connection, "second"));
    }

    #[test]
    fn migrations_are_not_repeated_after_reopening() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("db");

        DuckDbStore::open(&path, "1GB").unwrap();
        let store = DuckDbStore::open(&path, "1GB").unwrap();

        assert_eq!(
            applied_migrations(&store.connection),
            MIGRATIONS.len() as i64
        );
    }

    #[test]
    fn applies_the_memory_limit() {
        let folder = tempfile::tempdir().unwrap();
        let store = DuckDbStore::open(&folder.path().join("db"), "512MB").unwrap();

        let limit: String = store
            .connection
            .query_row("SELECT current_setting('memory_limit')", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(limit, "488.2 MiB");
    }

    #[test]
    fn enforces_the_memory_limit() {
        // With no temp folder DuckDB can't spill, so the limit has to hold.
        let config = Config::default()
            .max_memory("20MB")
            .unwrap()
            .with("temp_directory", "")
            .unwrap();
        let connection = Connection::open_in_memory_with_flags(config).unwrap();

        // Sorting about 100 MB of unique strings needs them all at once.
        let error = connection
            .query_row(
                "SELECT count(*) FROM (
                     SELECT md5(i::VARCHAR) || md5((i + 1)::VARCHAR) || md5((i + 2)::VARCHAR) AS s
                     FROM range(1000000) t(i) ORDER BY s
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_err();

        assert!(error.to_string().contains("Out of Memory"), "{error}");
    }

    #[test]
    fn rejects_an_invalid_memory_limit() {
        let folder = tempfile::tempdir().unwrap();
        assert!(DuckDbStore::open(&folder.path().join("db"), "lots").is_err());
    }
}
