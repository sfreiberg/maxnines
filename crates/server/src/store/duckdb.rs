use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result};
use duckdb::types::{TimeUnit, ToSqlOutput, ValueRef};
use duckdb::{Config, Connection, Transaction, appender_params_from_iter, params};
use maxnines_protocol::Sample;
use serde_json::Value;
use tracing::warn;

use super::flatten::{DataType, ENTRY_LABEL, Reported, flatten};
use super::rollups::{
    EXPIRE_EVERY_MS, FIVE_MINUTES_MS, HOUR_MS, RATE_LEAD_MS, Retention, Tier,
    full_resolution_cutoff, hour_of, hours_to_redo, is_due, metric_names, tier_for,
};
use super::shared::{
    MAX_NAME_BYTES, MAX_SERIES_PER_HOST, labels_key, rebuilt_output, shortened, top_of,
};
use super::{CollectorStats, MetricsReader, NewSample, Store, StoreStats};
use crate::calculations::{Calculation, CalculationQuery, SMALLEST_STEP_MS, numbered};
use crate::metrics::{
    LastSample, METRICS, Metric, NewestReading, Point, Reading, Series, SeriesQuery, SeriesResult,
    Source, Trend, now_ms,
};

/// A schema change. SeaORM doesn't support DuckDB, so this mirrors how its
/// migrations work: each one runs once, in order, and is recorded.
struct Migration {
    name: &'static str,
    sql: &'static str,
}

/// Every schema change, in order. Applied ones are recorded in the database, so
/// never edit one that has shipped: add a new one instead.
const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "0001_create_tables",
        sql: include_str!("migrations/0001_create_tables.sql"),
    },
    Migration {
        name: "0002_create_rollups",
        sql: include_str!("migrations/0002_create_rollups.sql"),
    },
    Migration {
        name: "0003_five_minute_rollups",
        sql: include_str!("migrations/0003_five_minute_rollups.sql"),
    },
    Migration {
        name: "0004_rename_agents_to_hosts",
        sql: include_str!("migrations/0004_rename_agents_to_hosts.sql"),
    },
];

/// Only the bookkeeping table is created outside a migration, because it is
/// what records them.
const CREATE_MIGRATIONS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS schema_migrations (
        name       VARCHAR   PRIMARY KEY,
        applied_at TIMESTAMP NOT NULL
    );
";

/// The most rows sorted at once, so that sorting fits in memory on any size of fleet.
const MAX_TIDY_ROWS: i64 = 250_000;

/// What identifies a series: its metric, its agent and its labels in one string.
type SeriesKey = (i32, i32, String);

/// Everything needed to turn a value into rows without asking the database. The
/// writer is the only thing that adds to these tables, so it can keep the whole list.
#[derive(Default)]
struct Names {
    collectors: HashMap<String, i32>,
    metrics: HashMap<(i32, String), (i32, DataType)>,
    hosts: HashMap<String, i32>,
    series: HashMap<SeriesKey, i64>,
    series_per_host: HashMap<i32, usize>,
    next_series: i64,
    /// Text that's current, so that only a change is written.
    texts: HashMap<i64, String>,
    /// Which series have current text, with the labels of what each describes, by
    /// agent and collector, for noticing when one stops being reported.
    text_series: HashMap<(i32, i32), HashMap<i64, String>>,
    /// Agents already warned about, so a noisy one doesn't fill the log.
    over_limit: HashSet<i32>,
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

        let mut statement = connection.prepare("SELECT id, host_id FROM hosts")?;
        for row in statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))? {
            let (id, host_id): (i32, String) = row?;
            names.hosts.insert(host_id, id);
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
        let mut statement = connection.prepare("SELECT id, metric_id, host FROM series")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?))
        })?;
        for row in rows {
            let (id, metric, host): (i64, i32, i32) = row?;
            let key = labels
                .get(&id)
                .map_or_else(String::new, |labels| labels_key(labels));
            if let Some(collector) = collector_of.get(&metric) {
                owners.insert(id, ((host, *collector), key.clone()));
            }
            names.series.insert((metric, host, key), id);
            *names.series_per_host.entry(host).or_default() += 1;
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
    hosts: Vec<(i32, String)>,
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

    /// Numbered after the highest, as a deleted agent leaves a gap that counting
    /// them would fill with a number still in use.
    fn host(&mut self, host_id: &str, rows: &mut Rows) -> i32 {
        if let Some(id) = self.hosts.get(host_id) {
            return *id;
        }
        let id = self
            .hosts
            .values()
            .max()
            .map_or(1, |highest| highest.saturating_add(1));
        self.hosts.insert(host_id.to_string(), id);
        rows.hosts.push((id, host_id.to_string()));
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
        host: i32,
        labels: &[(String, String)],
        rows: &mut Rows,
    ) -> Option<i64> {
        let key = (metric, host, labels_key(labels));
        if let Some(id) = self.series.get(&key) {
            return Some(*id);
        }
        let count = self.series_per_host.entry(host).or_default();
        if *count >= MAX_SERIES_PER_HOST {
            if self.over_limit.insert(host) {
                warn!(
                    host,
                    "a host reached the limit on series, ignoring new ones"
                );
            }
            return None;
        }
        *count += 1;
        let id = self.next_series.max(1);
        self.next_series = id + 1;
        self.series.insert(key, id);
        rows.series.push((id, metric, host));
        for (name, value) in labels {
            rows.labels.push((id, name.clone(), value.clone()));
        }
        Some(id)
    }

    fn add_sample(&mut self, new: &NewSample, rows: &mut Rows) -> Result<()> {
        let time = microseconds(&new.sample)?;
        let host = self.host(&new.host_id, rows);
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
                let Some(series) = self.series(metric, host, &reading.labels, rows) else {
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
                            let current = self.text_series.entry((host, collector)).or_default();
                            current.insert(series, item);
                        }
                    }
                }
            }

            // Something that was reported and isn't any more, like a check's error. A
            // sample may only cover some items, so only the ones in it can have changed.
            if let Some(current) = self.text_series.get_mut(&(host, collector)) {
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
    if !rows.hosts.is_empty() {
        let mut appender = transaction.appender("hosts")?;
        for (id, host_id) in &rows.hosts {
            appender.append_row(params![id, host_id])?;
        }
        appender.flush()?;
    }
    if !rows.series.is_empty() {
        let mut appender = transaction.appender("series")?;
        for (id, metric, host) in &rows.series {
            appender.append_row(params![id, metric, host])?;
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
    /// What's in the catalog tables. Empty after a failed write whose reload also
    /// failed, so that the next write loads it afresh rather than trusting names
    /// the rolled-back write added, which would leave samples pointing nowhere.
    names: Option<Names>,
    retention: Retention,
    /// How far each metric is rolled up, as kept in `rollup_progress`.
    progress: HashMap<String, i64>,
    /// Hours to roll up again, as kept in `rollup_redo`.
    redo: BTreeSet<i64>,
    /// When to next look for old data to delete.
    next_expiry_ms: i64,
}

impl DuckDbStore {
    pub fn open(path: &Path, memory_limit: &str, retention: Retention) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating folder {}", parent.display()))?;
        }
        let config = Config::default()
            .max_memory(memory_limit)
            .with_context(|| format!("invalid DuckDB memory_limit {memory_limit:?}"))?;
        let connection = Connection::open_with_flags(path, config)
            .with_context(|| format!("opening DuckDB database {}", path.display()))?;
        Self::with_connection(connection, retention)
    }

    fn with_connection(mut connection: Connection, retention: Retention) -> Result<Self> {
        migrate(&mut connection, MIGRATIONS)?;
        let names = Names::load(&connection).context("loading metric names")?;
        let mut statement =
            connection.prepare("SELECT metric, done_until_ms FROM rollup_progress")?;
        let progress = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<duckdb::Result<_>>()?;
        let mut statement = connection.prepare("SELECT hour_ms FROM rollup_redo")?;
        let redo = statement
            .query_map([], |row| row.get(0))?
            .collect::<duckdb::Result<_>>()?;
        drop(statement);
        Ok(Self {
            connection,
            names: Some(names),
            retention,
            progress,
            redo,
            next_expiry_ms: 0,
        })
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

    /// In one transaction, so an agent is either all there or all gone.
    fn delete_host_rows(&mut self, host_id: &str) -> Result<()> {
        let transaction = self.connection.transaction()?;
        let host: i32 = match transaction.query_row(
            "SELECT id FROM hosts WHERE host_id = ?",
            params![host_id],
            |row| row.get(0),
        ) {
            Ok(host) => host,
            Err(duckdb::Error::QueryReturnedNoRows) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for table in ["samples", "samples_recent", "texts", "series_labels"] {
            transaction.execute(
                &format!(
                    "DELETE FROM {table} WHERE series_id IN (SELECT id FROM series WHERE host = ?)"
                ),
                params![host],
            )?;
        }
        for table in ["rollups_five_minute", "rollups_hour"] {
            transaction.execute(
                &format!("DELETE FROM {table} WHERE host = ?"),
                params![host],
            )?;
        }
        transaction.execute("DELETE FROM series WHERE host = ?", params![host])?;
        transaction.execute("DELETE FROM hosts WHERE id = ?", params![host])?;
        transaction.commit()?;
        Ok(())
    }

    fn write_samples(&mut self, samples: &[NewSample]) -> Result<()> {
        if self.names.is_none() {
            let names = Names::load(&self.connection).context("reloading metric names")?;
            self.names = Some(names);
        }
        let names = self.names.as_mut().context("loading metric names")?;
        let mut rows = Rows::default();
        for new in samples {
            names.add_sample(new, &mut rows)?;
        }
        let late = self.late_hours(&rows);
        let transaction = self.connection.transaction()?;
        write_rows(&transaction, &rows)?;
        for hour in &late {
            transaction.execute("INSERT INTO rollup_redo VALUES (?)", params![hour])?;
        }
        transaction.commit()?;
        self.redo.extend(late);
        Ok(())
    }

    /// Hours these rows land in that are already rolled up, and not yet waiting to be
    /// rolled up again.
    fn late_hours(&self, rows: &Rows) -> BTreeSet<i64> {
        let Some(rolled_up_until) = self.progress.values().max().copied() else {
            return BTreeSet::new();
        };
        let times = rows.numbers.iter().map(|(time, ..)| time.div_euclid(1000));
        let full_since = now_ms() - self.retention.full_ms;
        let mut hours = hours_to_redo(times, rolled_up_until, full_since);
        hours.retain(|hour| !self.redo.contains(hour));
        hours
    }

    /// Every catalog metric is rolled up this far, or `None` if one hasn't started.
    fn rolled_up_until(&self) -> Option<i64> {
        metric_names()
            .map(|name| self.progress.get(name).copied())
            .min()
            .flatten()
    }

    /// Rolls up the next finished hour for every metric that's reached it, in one
    /// transaction with their progress. Hours without a single sample are skipped
    /// over, so a gap costs nothing.
    fn roll_up_next(&mut self, now_ms: i64) -> Result<bool> {
        let start = metric_names()
            .map(|name| self.progress.get(name).copied().unwrap_or(i64::MIN))
            .min()
            .unwrap_or(i64::MIN);
        let first: Option<i64> = self
            .connection
            .query_row(
                "SELECT epoch_ms(min(time)) FROM all_samples WHERE time >= epoch_ms($1::BIGINT)",
                params![start.max(0)],
                |row| row.get(0),
            )
            .context("finding the first sample to roll up")?;
        let Some(first) = first else {
            return Ok(false);
        };
        let hour = start.max(hour_of(first));
        if !is_due(hour, now_ms) {
            return Ok(false);
        }
        let due: Vec<&'static Metric> = METRICS
            .iter()
            .filter(|metric| {
                self.progress
                    .get(metric.name)
                    .is_none_or(|done| *done <= hour)
            })
            .collect();

        let transaction = self.connection.transaction()?;
        for metric in &due {
            roll_up_hour(&transaction, metric, hour)?;
            transaction.execute(
                "DELETE FROM rollup_progress WHERE metric = ?",
                params![metric.name],
            )?;
            transaction.execute(
                "INSERT INTO rollup_progress VALUES (?, ?)",
                params![metric.name, hour + HOUR_MS],
            )?;
        }
        transaction.commit()?;
        for metric in due {
            self.progress
                .insert(metric.name.to_string(), hour + HOUR_MS);
        }
        Ok(true)
    }

    /// Rolls up the earliest hour that got samples after it was rolled up, again.
    fn redo_next(&mut self) -> Result<bool> {
        let Some(hour) = self.redo.first().copied() else {
            return Ok(false);
        };
        let transaction = self.connection.transaction()?;
        for metric in METRICS {
            if self
                .progress
                .get(metric.name)
                .is_some_and(|done| *done > hour)
            {
                for table in ["rollups_five_minute", "rollups_hour"] {
                    transaction.execute(
                        &format!(
                            "DELETE FROM {table} WHERE metric = ?
                             AND time >= epoch_ms($2::BIGINT) AND time < epoch_ms($3::BIGINT)"
                        ),
                        params![metric.name, hour, hour + HOUR_MS],
                    )?;
                }
                roll_up_hour(&transaction, metric, hour)?;
            }
        }
        transaction.execute("DELETE FROM rollup_redo WHERE hour_ms = ?", params![hour])?;
        transaction.commit()?;
        self.redo.remove(&hour);
        Ok(true)
    }

    /// Deletes what's older than it's kept for, once an hour. Samples go only once
    /// they're rolled up, and text only once something newer replaced it, as text is
    /// only saved when it changes.
    fn expire(&mut self, now_ms: i64) -> Result<bool> {
        if now_ms < self.next_expiry_ms {
            return Ok(false);
        }
        let cutoff = full_resolution_cutoff(
            now_ms,
            &self.retention,
            self.rolled_up_until(),
            self.redo.first().copied(),
        );
        let transaction = self.connection.transaction()?;
        // Nothing is from before 1970, and a time much further back can't be compared.
        if let Some(cutoff) = cutoff.filter(|cutoff| *cutoff > 0) {
            for table in ["samples", "samples_recent"] {
                transaction.execute(
                    &format!("DELETE FROM {table} WHERE time < epoch_ms($1::BIGINT)"),
                    params![cutoff],
                )?;
            }
            transaction.execute(
                "DELETE FROM texts WHERE time < epoch_ms($1::BIGINT)
                 AND (series_id, time) NOT IN (SELECT series_id, max(time) FROM texts GROUP BY series_id)",
                params![cutoff],
            )?;
        }
        let kept = [
            ("rollups_five_minute", Some(self.retention.five_minute_ms)),
            ("rollups_hour", self.retention.hour_ms),
        ];
        for (table, kept_ms) in kept {
            let cutoff = kept_ms.map(|kept_ms| now_ms.saturating_sub(kept_ms));
            if let Some(cutoff) = cutoff.filter(|cutoff| *cutoff > 0) {
                transaction.execute(
                    &format!("DELETE FROM {table} WHERE time < epoch_ms($1::BIGINT)"),
                    params![cutoff],
                )?;
            }
        }
        transaction.commit()?;
        self.next_expiry_ms = now_ms + EXPIRE_EVERY_MS;
        Ok(false)
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
            // What was remembered for this batch never reached the database. If
            // that can't be reloaded now, the next write does it first.
            self.names = Names::load(&self.connection).ok();
        }
        result
    }

    fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
        Ok(Arc::new(DuckDbReader {
            connection: Mutex::new(self.connection.try_clone()?),
            retention: self.retention,
        }))
    }

    /// Sorting comes first, as it keeps up with what's arriving. Then hours to roll up
    /// again, as charts are wrong until they are, then new hours, then deleting.
    fn tidy(&mut self, now_ms: i64) -> Result<bool> {
        Ok(self.tidy_up_to(now_ms, MAX_TIDY_ROWS)?
            || self.redo_next()?
            || self.roll_up_next(now_ms)?
            || self.expire(now_ms)?)
    }

    fn delete_host(&mut self, host_id: &str) -> Result<()> {
        let result = self
            .delete_host_rows(host_id)
            .context("deleting a host's metrics");
        // Loaded again rather than worked out, as the agent touched most of what's
        // remembered. If that fails, the next write loads it first.
        self.names = Names::load(&self.connection).ok();
        result
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
    retention: Retention,
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
    host: Option<i32>,
    time: String,
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

/// One stored metric as rows of `host_id`, `t`, `series` and `v`. Metric and host
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
            "SELECT NULL::VARCHAR AS host_id, 0::BIGINT AS t,
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
    let host = scope
        .host
        .map_or_else(String::new, |host| format!("AND se.host = {host}"));
    Ok(format!(
        "SELECT a.host_id, epoch_ms(s.time) AS t, {name} AS series, s.value AS v
         FROM all_samples s
         JOIN series se ON se.id = s.series_id
         JOIN hosts a ON a.id = se.host
         {label}
         WHERE s.metric_id = {id} {host} AND {time}",
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
            "SELECT p.host_id, p.t, p.series, p.v / NULLIF(w.v, 0) * 100 AS v
             FROM ({}) p JOIN ({}) w USING (host_id, t, series)",
            stored_values(connection, metric, part, naming, scope)?,
            stored_values(connection, metric, whole, naming, scope)?,
        )),
    }
}

/// One row per value, as `host_id`, `t`, `series` and `v`.
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

/// Each reading of a metric as a `computed` table of agent, time, series and value,
/// with counts made rates. A rate needs the sample before it, so the first is `NULL`.
fn computed_with(connection: &Connection, metric: &Metric, scope: &Scope) -> Result<String> {
    let values = if is_rate(metric.source) {
        "SELECT host_id, t, series,
                v * 1000.0 / NULLIF(
                    t - lag(t) OVER (PARTITION BY host_id, series ORDER BY t), 0
                ) AS v
         FROM readings"
    } else {
        "SELECT host_id, t, series, v FROM readings"
    };
    Ok(format!(
        "WITH readings AS ({readings}),
         computed AS ({values})",
        readings = readings(connection, metric, scope)?,
    ))
}

/// Parameters: from and to, both included.
fn computed_sql(connection: &Connection, metric: &Metric) -> Result<String> {
    let scope = Scope {
        host: None,
        time: "s.time >= epoch_ms($1::BIGINT) AND s.time <= epoch_ms($2::BIGINT)".to_string(),
    };
    computed_with(connection, metric, &scope)
}

/// How far a metric is rolled up, if it's started.
fn rolled_up_until(connection: &Connection, metric: &Metric) -> Result<Option<i64>> {
    let found = connection.query_row(
        "SELECT done_until_ms FROM rollup_progress WHERE metric = ?",
        params![metric.name],
        |row| row.get(0),
    );
    match found {
        Ok(done) => Ok(Some(done)),
        Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Parameters: from and to. Rows of `host_id`, `t`, `series`, `low`, `high`, `summed`
/// and `samples`: rolled up for what is, at `tier`, and each sample after that, as a
/// row of its own. Rates read a little before the start, as each needs the sample
/// before it.
fn cells_sql(
    connection: &Connection,
    metric: &Metric,
    host: Option<i32>,
    tier: Tier,
    done: Option<i64>,
) -> Result<String> {
    let rolled = tier.table().zip(done);
    let samples_from = match rolled {
        Some((_, done)) => format!("greatest($1::BIGINT, {done})"),
        None => "$1::BIGINT".to_string(),
    };
    let lead = if is_rate(metric.source) {
        RATE_LEAD_MS
    } else {
        0
    };
    let scope = Scope {
        host,
        time: format!(
            "s.time >= epoch_ms({samples_from} - {lead}) AND s.time < epoch_ms($2::BIGINT)"
        ),
    };
    let mut cells = format!(
        "SELECT host_id, t, series, v AS low, v AS high, v AS summed, 1::BIGINT AS samples
         FROM ({computed} SELECT * FROM computed)
         WHERE t >= {samples_from} AND series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}",
        computed = computed_with(connection, metric, &scope)?,
    );
    if let Some((table, done)) = rolled {
        let host = host.map_or_else(String::new, |host| format!("AND r.host = {host}"));
        // The name comes from the catalog, never from a request.
        cells.push_str(&format!(
            " UNION ALL
             SELECT a.host_id, epoch_ms(r.time) AS t, r.series, r.low, r.high, r.summed,
                    r.samples
             FROM {table} r JOIN hosts a ON a.id = r.host
             WHERE r.metric = '{name}' {host}
               AND r.time >= epoch_ms($1::BIGINT)
               AND r.time < epoch_ms(least($2::BIGINT, {done}))",
            name = metric.name,
        ));
    }
    Ok(cells)
}

/// Parameters: from, to, step, and how many series to keep.
fn series_sql(
    connection: &Connection,
    metric: &Metric,
    host: i32,
    tier: Tier,
    done: Option<i64>,
) -> Result<String> {
    // An idle interface says nothing, but a CPU at 0% does.
    let having = if is_rate(metric.source) {
        "HAVING max(high) > 0"
    } else {
        ""
    };
    Ok(format!(
        "WITH cells AS ({cells}),
         ranked AS (
             SELECT series,
                    row_number() OVER (ORDER BY sum(summed) / sum(samples) DESC, series)
                        AS position,
                    count(*) OVER () AS total
             FROM cells GROUP BY series {having}
         )
         SELECT series, t // $3::BIGINT * $3::BIGINT AS bucket,
                sum(summed) / sum(samples), min(low), max(high), total
         FROM cells JOIN ranked USING (series)
         WHERE position <= $4::BIGINT
         GROUP BY series, bucket, total
         ORDER BY series, bucket",
        cells = cells_sql(connection, metric, Some(host), tier, done)?,
    ))
}

/// Parameters: from, to, step, and how many lines to keep. A moment still filling up
/// is left out, as it would look like hosts disappearing. `members` is pairs of an
/// agent's number and the number of its group, so nothing here comes from a request.
fn calculation_sql(
    connection: &Connection,
    query: &CalculationQuery,
    members: &[(i32, usize)],
    tier: Tier,
    done: Option<i64>,
) -> Result<String> {
    let members: Vec<String> = members
        .iter()
        .map(|(host, group)| format!("({host}, {group})"))
        .collect();
    let line = if query.by_series {
        "series"
    } else {
        "grp::VARCHAR"
    };
    // Named lines measure different things, like memory and swap, so they can't be
    // combined. Lines of the same thing, like each disk, can. These names come from
    // the catalog, never from a request.
    let only_main_line = match query.metric.source {
        Source::Fields([(name, _), _, ..]) if !query.by_series => format!("AND series = '{name}'"),
        _ => String::new(),
    };
    let combined = match query.calculation {
        Calculation::Avg => "avg(v)",
        Calculation::Sum => "sum(v)",
        Calculation::Min => "min(v)",
        Calculation::Max => "max(v)",
        Calculation::Count => "count(*)::DOUBLE",
    };

    Ok(format!(
        "WITH members(host, grp) AS (VALUES {members}),
         cells AS ({cells}),
         per_series AS (
             SELECT m.grp, u.host_id, u.series,
                    u.t // $3::BIGINT * $3::BIGINT AS bucket,
                    sum(u.summed) / sum(u.samples) AS v
             FROM cells u
             JOIN hosts a ON a.host_id = u.host_id
             JOIN members m ON m.host = a.id
             WHERE true {only_main_line}
             GROUP BY m.grp, u.host_id, u.series, bucket
         ),
         combined AS (
             SELECT {line} AS line, bucket, {combined} AS v
             FROM per_series
             WHERE bucket + $3::BIGINT <= $2::BIGINT
             GROUP BY line, bucket
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
        cells = cells_sql(connection, query.metric, None, tier, done)?,
    ))
}

/// Rolls up one hour of a metric: each 5 minutes from the samples, and then the hour
/// from those. Reads from a little before the hour, for the first rate's sample before.
fn roll_up_hour(connection: &Connection, metric: &Metric, hour: i64) -> Result<()> {
    let end = hour + HOUR_MS;
    let lead = if is_rate(metric.source) {
        RATE_LEAD_MS
    } else {
        0
    };
    let scope = Scope {
        host: None,
        time: format!(
            "s.time >= epoch_ms({}::BIGINT) AND s.time < epoch_ms({end}::BIGINT)",
            hour - lead
        ),
    };
    // The name comes from the catalog, never from a request.
    connection
        .execute(
            &format!(
                "INSERT INTO rollups_five_minute
             SELECT '{name}', a.id, c.series, epoch_ms(c.bucket)::TIMESTAMP,
                    min(c.v), max(c.v), sum(c.v), count(*)
             FROM (
                 {computed}
                 SELECT host_id, series, v,
                        t // {FIVE_MINUTES_MS} * {FIVE_MINUTES_MS} AS bucket
                 FROM computed
                 WHERE series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}
                   AND t >= {hour} AND t < {end}
             ) c JOIN hosts a ON a.host_id = c.host_id
             GROUP BY a.id, c.series, c.bucket",
                name = metric.name,
                computed = computed_with(connection, metric, &scope)?,
            ),
            [],
        )
        .with_context(|| format!("rolling up 5 minutes of {}", metric.name))?;
    connection
        .execute(
            "INSERT INTO rollups_hour
         SELECT metric, host, series, epoch_ms($2::BIGINT)::TIMESTAMP,
                min(low), max(high), sum(summed), sum(samples)::BIGINT
         FROM rollups_five_minute
         WHERE metric = $1 AND time >= epoch_ms($2::BIGINT) AND time < epoch_ms($3::BIGINT)
         GROUP BY metric, host, series",
            params![metric.name, hour, end],
        )
        .with_context(|| format!("rolling up the hour of {}", metric.name))?;
    Ok(())
}

fn newest_sql(connection: &Connection, metric: &Metric) -> Result<String> {
    Ok(format!(
        "{computed}
         SELECT host_id, series, max(t), arg_max(v, t)
         FROM computed
         WHERE series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}
         GROUP BY host_id, series
         ORDER BY host_id, series",
        computed = computed_sql(connection, metric)?,
    ))
}

/// Each series' newest value and the slope of the line that fits it best, by least
/// squares. Times are counted from the start, as milliseconds since 1970 are big
/// enough to cost the fit its precision.
fn trends_sql(connection: &Connection, metric: &Metric) -> Result<String> {
    Ok(format!(
        "{computed}
         SELECT host_id, series, max(t), arg_max(v, t), min(t), count(*),
                regr_slope(v, (t - $1::BIGINT)::DOUBLE)
         FROM computed
         WHERE series IS NOT NULL AND abs(v) <= {LARGEST_VALUE}
         GROUP BY host_id, series
         HAVING max(t) > min(t)
         ORDER BY host_id, series",
        computed = computed_sql(connection, metric)?,
    ))
}

/// The number of an agent the store has heard from.
fn host_number(connection: &Connection, host_id: &str) -> Result<Option<i32>> {
    let found = connection.query_row(
        "SELECT id FROM hosts WHERE host_id = ?",
        params![host_id],
        |row| row.get(0),
    );
    match found {
        Ok(id) => Ok(Some(id)),
        Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl MetricsReader for DuckDbReader {
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult> {
        let connection = self.connection()?;
        let Some(host) = host_number(&connection, query.host_id)? else {
            return Ok(SeriesResult::default());
        };
        let range = query.range;
        let tier = tier_for(range.step_ms, range.from_ms, now_ms(), &self.retention);
        let done = rolled_up_until(&connection, query.metric)?;
        let mut statement =
            connection.prepare(&series_sql(&connection, query.metric, host, tier, done)?)?;
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
            "SELECT a.host_id, epoch_ms(newest.time)
             FROM (
                 SELECT se.host, max(s.time) AS time
                 FROM all_samples s JOIN series se ON se.id = s.series_id
                 WHERE s.time >= epoch_ms($1::BIGINT) AND s.time <= epoch_ms($2::BIGINT)
                 GROUP BY se.host
             ) newest JOIN hosts a ON a.id = newest.host",
        )?;
        let rows = statement.query_map(params![since_ms, until_ms], |row| {
            Ok(LastSample {
                host_id: row.get(0)?,
                time_ms: row.get(1)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn latest_output(
        &self,
        host_id: &str,
        collector: &str,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Option<Value>> {
        let connection = self.connection()?;
        let Some(host) = host_number(&connection, host_id)? else {
            return Ok(None);
        };

        let mut statement = connection.prepare(
            "SELECT se.id, m.name, m.data_type, l.name, l.value
             FROM series se
             JOIN metrics m ON m.id = se.metric_id
             JOIN collectors c ON c.id = m.collector_id
             LEFT JOIN series_labels l ON l.series_id = se.id
             WHERE se.host = ? AND c.name = ?
             ORDER BY se.id",
        )?;
        let rows = statement.query_map(params![host, collector], |row| {
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
                host_id: row.get(0)?,
                series: row.get(1)?,
                time_ms: row.get(2)?,
                value: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn trends(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<Trend>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(&trends_sql(&connection, metric)?)?;
        let rows = statement.query_map(params![since_ms, until_ms], |row| {
            Ok((
                Trend {
                    host_id: row.get(0)?,
                    series: row.get(1)?,
                    time_ms: row.get(2)?,
                    value: row.get(3)?,
                    first_ms: row.get(4)?,
                    samples: row.get(5)?,
                    slope_per_ms: 0.0,
                },
                row.get::<_, Option<f64>>(6)?,
            ))
        })?;
        let mut trends = Vec::new();
        for row in rows {
            let (trend, slope) = row?;
            if let Some(slope) = slope.filter(|slope| slope.is_finite()) {
                trends.push(Trend {
                    slope_per_ms: slope,
                    ..trend
                });
            }
        }
        Ok(trends)
    }

    fn calculate(&self, query: &CalculationQuery) -> Result<SeriesResult> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT host_id, id FROM hosts")?;
        let numbers: HashMap<String, i32> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<duckdb::Result<_>>()?;

        let (groups, places) = numbered(&query.members);
        let members: Vec<(i32, usize)> = query
            .members
            .iter()
            .zip(places)
            .filter_map(|(member, place)| Some((*numbers.get(&member.host_id)?, place)))
            .collect();
        if members.is_empty() {
            return Ok(SeriesResult::default());
        }

        let range = query.range;
        let step = range.step_ms.max(SMALLEST_STEP_MS);
        let tier = tier_for(step, range.from_ms, now_ms(), &self.retention);
        let done = rolled_up_until(&connection, query.metric)?;
        let mut statement =
            connection.prepare(&calculation_sql(&connection, query, &members, tier, done)?)?;
        let rows = statement.query_map(
            params![range.from_ms, range.to_ms, step, query.max_lines as i64],
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
                rows: Some(row.get(1)?),
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
            total_rows: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use super::super::shared::MAX_TEXT_BYTES;
    use super::*;
    use crate::calculations::Member;
    use crate::metrics::{METRICS, TimeRange, find};

    type TestStore = DuckDbStore;

    include!("contract_tests.rs");

    fn sample() -> Sample {
        Sample {
            timestamp_ms: 1_700_000_000_123,
            metrics: BTreeMap::from([
                ("cpu".to_string(), json!({ "usage_percent": 12.5 })),
                ("disk".to_string(), json!([{ "mount_point": "/" }])),
            ]),
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
                    rows: Some(3),
                    rows_last_hour: 2,
                    oldest_ms: 1000,
                    newest_ms: 9000,
                },
                CollectorStats {
                    name: "disk".to_string(),
                    rows: Some(1),
                    rows_last_hour: 0,
                    oldest_ms: 2000,
                    newest_ms: 2000,
                },
            ]
        );
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

    fn with_retention(retention: Retention) -> DuckDbStore {
        DuckDbStore::with_connection(Connection::open_in_memory().unwrap(), retention).unwrap()
    }

    fn in_memory() -> DuckDbStore {
        DuckDbStore::with_connection(
            Connection::open_in_memory().unwrap(),
            Retention::KEEP_EVERYTHING,
        )
        .unwrap()
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

    /// A failed write rolls back what it added to the catalog. If the catalog can't
    /// be reloaded either, the store must not keep trusting those names: the next
    /// write would skip adding them and leave samples pointing at nothing.
    #[test]
    fn a_catalog_that_could_not_be_reloaded_is_loaded_again_before_the_next_write() {
        let folder = tempfile::tempdir().unwrap();
        let mut store =
            DuckDbStore::open(&folder.path().join("m.duckdb"), "1GB", Retention::default())
                .unwrap();
        write_one(&mut store, "a", "h", &sample()).unwrap();
        let newcomer = Sample {
            timestamp_ms: 1_700_000_001_000,
            metrics: BTreeMap::from([("memory".to_string(), json!({ "used_percent": 40.0 }))]),
        };

        // Adding a collector and reloading the catalog both need this table.
        let hide = "ALTER TABLE collectors RENAME TO collectors_away";
        store.connection.execute_batch(hide).unwrap();
        assert!(write_one(&mut store, "a", "h", &newcomer).is_err());
        assert!(store.names.is_none());
        let restore = "ALTER TABLE collectors_away RENAME TO collectors";
        store.connection.execute_batch(restore).unwrap();

        write_one(&mut store, "a", "h", &newcomer).unwrap();

        let reader = store.reader().unwrap();
        let latest = reader
            .latest_output("a", "memory", 0, 2_000_000_000_000)
            .unwrap();
        let latest = latest.expect("the sample should be readable");
        assert_eq!(latest["used_percent"].as_f64(), Some(40.0));
    }

    #[test]
    fn closing_saves_recent_writes_even_with_a_reader_open() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("m.duckdb");
        let mut store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
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

    fn stored_rows(store: &DuckDbStore) -> i64 {
        store
            .connection
            .query_row("SELECT count(*) FROM all_samples", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn deleting_an_agent_leaves_no_rows_of_it_in_any_table() {
        let mut store = in_memory();
        for host in ["gone", "kept"] {
            let checks = json!([{ "name": "site", "kind": "http", "up": 0, "error": "no" }]);
            write_metric(&mut store, host, 1000, "checks", checks);
        }
        tidy_all(&mut store, 2 * HOUR_MS);
        write_metric(
            &mut store,
            "gone",
            HOUR_MS as u64 + 1,
            "cpu",
            json!({ "usage_percent": 1 }),
        );

        store.delete_host("gone").unwrap();

        let count = |sql: &str| -> i64 {
            store
                .connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(count("SELECT count(*) FROM hosts"), 1);
        let kept = count("SELECT count(*) FROM series");
        assert_eq!(count("SELECT count(*) FROM series WHERE host = 2"), kept);
        for table in ["samples", "samples_recent", "texts", "series_labels"] {
            let orphans = count(&format!(
                "SELECT count(*) FROM {table} WHERE series_id NOT IN (SELECT id FROM series)"
            ));
            assert_eq!(orphans, 0, "{table}");
        }
        assert!(
            count("SELECT count(*) FROM samples") > 0,
            "the other host's"
        );
    }

    #[test]
    fn a_sample_sent_twice_is_stored_once_after_tidying() {
        let mut store = in_memory();
        for host in ["a", "a", "b"] {
            write_metric(
                &mut store,
                host,
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
    fn stores_a_row_for_each_number_a_sample_holds() {
        let mut store = in_memory();
        write_one(&mut store, "host-1", "web-1", &sample()).unwrap();
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
        store
            .names
            .as_mut()
            .unwrap()
            .series_per_host
            .insert(1, MAX_SERIES_PER_HOST);
        store
            .names
            .as_mut()
            .unwrap()
            .hosts
            .insert("noisy".to_string(), 1);

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

        assert_eq!(row_count(&store), 1, "only the calm host's");
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
    fn text_that_cleared_stays_cleared_across_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("m.duckdb");
        let failing = json!([{ "name": "site", "up": 0, "error": "refused" }]);
        let working = json!([{ "name": "site", "up": 1 }]);

        let mut store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
        write_metric(&mut store, "a", 1000, "checks", failing.clone());
        write_metric(&mut store, "a", 2000, "checks", working.clone());
        store.close().unwrap();
        drop(store);

        let mut store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
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

        let mut store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
        write_metric(&mut store, "a", 1000, "services", service("active"));
        store.close().unwrap();
        drop(store);

        let mut store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
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
        assert_eq!(series, 4, "two hosts, each with a number and a text");
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
        assert!(store.names.as_ref().unwrap().hosts.is_empty());
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
            for host in ["a", "b", "c", "d", "e"] {
                let usage = json!({ "usage_percent": 1.0 });
                write_metric(&mut store, host, minute * 60_000, "cpu", usage);
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
        write_one(&mut store, "host-1", "web-1", &sample()).unwrap();

        let (time, host_id, metric, value): (String, String, String, f64) = store
            .connection
            .query_row(
                "SELECT s.time::VARCHAR, a.host_id, m.name, s.value FROM all_samples s
                 JOIN series se ON se.id = s.series_id
                 JOIN hosts a ON a.id = se.host
                 JOIN metrics m ON m.id = s.metric_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(time, "2023-11-14 22:13:20.123");
        assert_eq!(host_id, "host-1");
        assert_eq!(metric, "usage_percent");
        assert_eq!(value, 12.5);
    }

    #[test]
    fn rejects_out_of_range_timestamps() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = u64::MAX;

        assert!(write_one(&mut store, "host-1", "web-1", &bad).is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn rejects_timestamps_too_large_to_store() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = i64::MAX as u64;

        assert!(write_one(&mut store, "host-1", "web-1", &bad).is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn writes_several_samples_at_once() {
        let mut store = in_memory();
        let mut second = sample();
        second.timestamp_ms += 1000;

        store
            .write(&[
                new_sample("host-1", "web-1", &sample()),
                new_sample("host-2", "web-2", &second),
            ])
            .unwrap();

        let saved: Vec<(i64, String)> = store
            .connection
            .prepare(
                "SELECT epoch_ms(s.time), a.host_id FROM all_samples s
                 JOIN series se ON se.id = s.series_id JOIN hosts a ON a.id = se.host
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
                (1_700_000_000_123, "host-1".to_string()),
                (1_700_000_001_123, "host-2".to_string())
            ]
        );
    }

    #[test]
    fn a_bad_sample_stores_none_of_its_batch() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = u64::MAX;

        let result = store.write(&[
            new_sample("host-1", "web-1", &sample()),
            new_sample("host-1", "web-1", &bad),
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

        assert!(write_one(&mut store, "host-1", "web-1", &sample()).is_err());

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
        let output = latest_output(&store, "a", "host").unwrap();
        assert_eq!(output, json!({ "uptime_secs": 90, "boot_time_secs": 10 }));
    }

    #[test]
    fn data_survives_reopening_and_creates_parent_folders() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/maxnines.duckdb");

        let mut store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
        write_one(&mut store, "host-1", "web-1", &sample()).unwrap();
        drop(store);

        let mut reopened = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
        write_one(&mut reopened, "host-1", "web-1", &sample()).unwrap();
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
    fn agents_become_hosts_keeping_every_row() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection, &MIGRATIONS[..3]).unwrap();
        connection
            .execute_batch(
                "INSERT INTO agents VALUES (1, 'abc');
                 INSERT INTO collectors VALUES (3, 'server');
                 INSERT INTO metrics VALUES (5, 3, 'agents_online', 'int');
                 INSERT INTO rollup_progress VALUES ('server.agents', 10);
                 INSERT INTO rollups_hour
                 VALUES ('server.agents', 1, 'Online', TIMESTAMP '2026-11-01', 1, 2, 3, 4);
                 INSERT INTO series VALUES (7, 1, 1);
                 INSERT INTO rollups_hour
                 VALUES ('cpu.usage', 1, 'CPU', TIMESTAMP '2026-11-01', 1, 2, 3, 4);
                 INSERT INTO rollups_five_minute
                 VALUES ('cpu.usage', 1, 'CPU', TIMESTAMP '2026-11-01', 1, 2, 3, 4);",
            )
            .unwrap();

        migrate(&mut connection, MIGRATIONS).unwrap();

        let count = |sql: &str| -> i64 { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(
            count("SELECT count(*) FROM hosts WHERE host_id = 'abc' AND id = 1"),
            1
        );
        assert_eq!(count("SELECT count(*) FROM series WHERE host = 1"), 1);
        assert_eq!(count("SELECT count(*) FROM rollups_hour WHERE host = 1"), 2);
        assert_eq!(
            count("SELECT count(*) FROM rollups_five_minute WHERE host = 1"),
            1
        );
        assert!(!table_exists(&connection, "agents"));
        assert_eq!(
            count("SELECT count(*) FROM metrics WHERE name = 'hosts_online'"),
            1
        );
        let renamed = "SELECT count(*) FROM rollups_hour WHERE metric = 'server.hosts'";
        assert_eq!(count(renamed), 1);
        let progress = "SELECT count(*) FROM rollup_progress WHERE metric = 'server.hosts'";
        assert_eq!(count(progress), 1);
    }

    #[test]
    fn minute_rollups_become_exactly_the_five_minute_ones() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection, &MIGRATIONS[..2]).unwrap();
        // Six minutes: five in the first span, with a spike, and one in the next.
        for minute in 0..6i64 {
            let high = if minute == 2 { 100.0 } else { 20.0 };
            connection
                .execute(
                    "INSERT INTO rollups_minute
                     VALUES ('cpu.usage', 1, 'CPU', epoch_ms($1::BIGINT)::TIMESTAMP,
                             10.0, $2, $3, 4)",
                    params![minute * 60_000, high, 4.0 * 15.0 + minute as f64],
                )
                .unwrap();
        }

        migrate(&mut connection, MIGRATIONS).unwrap();

        assert!(!table_exists(&connection, "rollups_minute"));
        let mut statement = connection
            .prepare(
                "SELECT epoch_ms(time), low, high, summed, samples FROM rollups_five_minute
                 ORDER BY time",
            )
            .unwrap();
        let spans: Vec<(i64, f64, f64, f64, i64)> = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<duckdb::Result<_>>()
            .unwrap();
        assert_eq!(
            spans,
            [
                (0, 10.0, 100.0, 5.0 * 60.0 + 10.0, 20),
                (300_000, 10.0, 20.0, 65.0, 4),
            ]
        );
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

        DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();
        let store = DuckDbStore::open(&path, "1GB", Retention::default()).unwrap();

        assert_eq!(
            applied_migrations(&store.connection),
            MIGRATIONS.len() as i64
        );
    }

    #[test]
    fn applies_the_memory_limit() {
        let folder = tempfile::tempdir().unwrap();
        let store =
            DuckDbStore::open(&folder.path().join("db"), "512MiB", Retention::default()).unwrap();

        let limit: String = store
            .connection
            .query_row("SELECT current_setting('memory_limit')", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(limit, "512.0 MiB");
    }

    #[test]
    fn rejects_an_invalid_memory_limit() {
        let folder = tempfile::tempdir().unwrap();
        assert!(
            DuckDbStore::open(&folder.path().join("db"), "lots", Retention::default()).is_err()
        );
    }
}
