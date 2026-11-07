//! Metrics in ClickHouse, for fleets too big for DuckDB. Everything's kept by name
//! rather than by number, because ClickHouse compresses sorted repeats to almost
//! nothing and works best without joins. It sorts and drops repeated samples itself
//! when it merges, so there's no upkeep to do here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, bail};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::{Builder, Runtime};
use tracing::warn;

use super::flatten::{DataType, ENTRY_LABEL, Reported, flatten};
use super::shared::{
    MAX_NAME_BYTES, MAX_SERIES_PER_AGENT, StoredSeries, labels_key, rebuilt_output, shortened,
    top_of,
};
use super::{CollectorStats, LATEST_SAMPLE_MS, MetricsReader, NewSample, Store, StoreStats};
use crate::calculations::{Calculation, CalculationQuery, SMALLEST_STEP_MS, numbered};
use crate::metrics::{
    LastSample, Metric, NewestReading, Point, Reading, Series, SeriesQuery, SeriesResult, Source,
};

/// Anything beyond this is skipped, as in the other stores.
const LARGEST_VALUE: &str = "1e300";

/// Picking machines lists them all, which can be longer than ClickHouse's default.
const MAX_QUERY_BYTES: &str = "67108864";

/// Tables are made here, as ClickHouse has no transactions to make them all at once,
/// so each statement can safely run again. Months keep partitions to a number that
/// can't grow out of hand, whatever times agents send. The hour in the sort order lets
/// a query for what's recent skip everything older.
const MIGRATIONS: &[(&str, &[&str])] = &[(
    "0001_create_tables",
    &[
        "CREATE TABLE IF NOT EXISTS samples (
             metric String,
             agent  String,
             labels Map(String, String),
             time   DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
             value  Float64 CODEC(Gorilla, ZSTD(1)),
             kind   String
         )
         ENGINE = ReplacingMergeTree
         PARTITION BY toStartOfMonth(time)
         ORDER BY (metric, toStartOfHour(time), agent, labels, time)",
        // Text, only when it changes. Nothing means it stopped being reported.
        "CREATE TABLE IF NOT EXISTS texts (
             metric String,
             agent  String,
             labels Map(String, String),
             time   DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
             value  Nullable(String)
         )
         ENGINE = ReplacingMergeTree
         PARTITION BY toStartOfMonth(time)
         ORDER BY (agent, metric, labels, time)",
        // What exists, to limit what an agent can create without reading the samples.
        "CREATE TABLE IF NOT EXISTS series (
             agent  String,
             metric String,
             labels Map(String, String)
         )
         ENGINE = ReplacingMergeTree
         ORDER BY (agent, metric, labels)",
        // When each agent reported, so asking who's current doesn't read the samples.
        "CREATE TABLE IF NOT EXISTS reports (
             time  DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
             agent String
         )
         ENGINE = ReplacingMergeTree
         PARTITION BY toStartOfMonth(time)
         ORDER BY (time, agent)",
    ],
)];

/// One runtime for every store, as the client is async and stores aren't. It's never
/// shut down, because that isn't allowed from the async code a store can be dropped in.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("clickhouse")
            .enable_all()
            .build()
            .expect("starting the ClickHouse runtime")
    })
}

fn wait<T>(work: impl Future<Output = T>) -> T {
    runtime().block_on(work)
}

/// Text for a query. What goes through this comes from the catalog or the server's own
/// list of agents, but agents chose their IDs' labels, so nothing is taken on trust.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

type Labels = BTreeMap<String, String>;

#[derive(Row, Serialize)]
struct SampleRow {
    metric: String,
    agent: String,
    labels: Labels,
    time: i64,
    value: f64,
    kind: &'static str,
}

#[derive(Row, Serialize)]
struct TextRow {
    metric: String,
    agent: String,
    labels: Labels,
    time: i64,
    value: Option<String>,
}

#[derive(Row, Serialize, Deserialize)]
struct SeriesRow {
    agent: String,
    metric: String,
    labels: Labels,
}

#[derive(Row, Serialize)]
struct ReportRow {
    time: i64,
    agent: String,
}

/// What a batch of samples adds, gathered first so it can be written in one go.
#[derive(Default)]
struct Rows {
    samples: Vec<SampleRow>,
    texts: Vec<TextRow>,
    series: Vec<SeriesRow>,
    reports: Vec<ReportRow>,
    /// How to take back what was remembered, if writing these fails.
    undo: Vec<Undo>,
}

/// Something remembered for a batch that may never reach the database.
enum Undo {
    Series {
        agent: String,
        print: u64,
    },
    Text {
        print: u64,
        previous: Option<String>,
    },
    Cleared {
        print: u64,
        text: Option<String>,
        owner: (String, String),
        series: TextSeries,
    },
}

/// A series, as a number for this server's own bookkeeping. It's never stored.
fn fingerprint(agent: &str, metric: &str, labels: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    (agent, metric, labels).hash(&mut hasher);
    hasher.finish()
}

/// What the writer has to remember between samples.
#[derive(Default)]
struct Memory {
    series: HashMap<String, HashSet<u64>>,
    /// Text that's current, so that only a change is written.
    texts: HashMap<u64, String>,
    /// Which series have current text, by agent and collector, with what each describes,
    /// for noticing when one stops being reported.
    text_series: HashMap<(String, String), HashMap<u64, TextSeries>>,
    over_limit: HashSet<String>,
}

#[derive(Clone)]
struct TextSeries {
    metric: String,
    labels: Labels,
    item: String,
}

fn labelled(labels: &[(String, String)]) -> Labels {
    labels.iter().cloned().collect()
}

impl Memory {
    /// False once an agent has as many series as it's allowed.
    fn allow(
        &mut self,
        agent: &str,
        metric: &str,
        labels: &[(String, String)],
        rows: &mut Rows,
    ) -> bool {
        let print = fingerprint(agent, metric, &labels_key(labels));
        let known = self.series.entry(agent.to_string()).or_default();
        if known.contains(&print) {
            return true;
        }
        if known.len() >= MAX_SERIES_PER_AGENT {
            if self.over_limit.insert(agent.to_string()) {
                warn!(
                    agent,
                    "an agent reached the limit on series, ignoring new ones"
                );
            }
            return false;
        }
        known.insert(print);
        rows.undo.push(Undo::Series {
            agent: agent.to_string(),
            print,
        });
        rows.series.push(SeriesRow {
            agent: agent.to_string(),
            metric: metric.to_string(),
            labels: labelled(labels),
        });
        true
    }

    fn add_sample(&mut self, new: &NewSample, rows: &mut Rows) -> Result<()> {
        let time = i64::try_from(new.sample.timestamp_ms)
            .ok()
            .filter(|_| new.sample.timestamp_ms <= LATEST_SAMPLE_MS)
            .context("timestamp out of range")?;
        let agent = new.agent_id.as_str();
        rows.reports.push(ReportRow {
            time,
            agent: agent.to_string(),
        });

        for (collector, output) in &new.sample.metrics {
            if collector.len() > MAX_NAME_BYTES {
                continue;
            }
            let mut reported = HashSet::new();
            let mut items = HashSet::new();
            for reading in flatten(output, top_of(collector)) {
                let too_long = reading.metric.len() > MAX_NAME_BYTES
                    || reading.labels.iter().any(|(name, value)| {
                        name.len() > MAX_NAME_BYTES || value.len() > MAX_NAME_BYTES
                    });
                if too_long {
                    continue;
                }
                let item = labels_key(&reading.labels);
                items.insert(item.clone());
                let metric = format!("{collector}.{}", reading.metric);
                if !self.allow(agent, &metric, &reading.labels, rows) {
                    continue;
                }
                match reading.value {
                    Reported::Number(value, kind) => rows.samples.push(SampleRow {
                        metric,
                        agent: agent.to_string(),
                        labels: labelled(&reading.labels),
                        time,
                        value,
                        kind: kind.as_str(),
                    }),
                    Reported::Text(text) => {
                        let text = shortened(text);
                        let print = fingerprint(agent, &metric, &item);
                        reported.insert(print);
                        if self.texts.get(&print).is_none_or(|known| known != text) {
                            let previous = self.texts.insert(print, text.to_string());
                            rows.undo.push(Undo::Text { print, previous });
                            let labels = labelled(&reading.labels);
                            rows.texts.push(TextRow {
                                metric: metric.clone(),
                                agent: agent.to_string(),
                                labels: labels.clone(),
                                time,
                                value: Some(text.to_string()),
                            });
                            self.text_series
                                .entry((agent.to_string(), collector.clone()))
                                .or_default()
                                .insert(
                                    print,
                                    TextSeries {
                                        metric,
                                        labels,
                                        item,
                                    },
                                );
                        }
                    }
                }
            }

            // Something that was reported and isn't any more, like a check's error. A
            // sample may only cover some items, so only the ones in it can have changed.
            let key = (agent.to_string(), collector.clone());
            if let Some(current) = self.text_series.get_mut(&key) {
                current.retain(|print, series| {
                    let gone = items.contains(&series.item) && !reported.contains(print);
                    if gone {
                        rows.undo.push(Undo::Cleared {
                            print: *print,
                            text: self.texts.remove(print),
                            owner: key.clone(),
                            series: series.clone(),
                        });
                        rows.texts.push(TextRow {
                            metric: series.metric.clone(),
                            agent: agent.to_string(),
                            labels: series.labels.clone(),
                            time,
                            value: None,
                        });
                    }
                    !gone
                });
            }
        }
        Ok(())
    }
}

impl Memory {
    /// Latest first, so that things end up as they started.
    fn take_back(&mut self, undo: Vec<Undo>) {
        for step in undo.into_iter().rev() {
            match step {
                Undo::Series { agent, print } => {
                    if let Some(known) = self.series.get_mut(&agent) {
                        known.remove(&print);
                    }
                }
                Undo::Text { print, previous } => match previous {
                    Some(text) => {
                        self.texts.insert(print, text);
                    }
                    None => {
                        self.texts.remove(&print);
                    }
                },
                Undo::Cleared {
                    print,
                    text,
                    owner,
                    series,
                } => {
                    if let Some(text) = text {
                        self.texts.insert(print, text);
                    }
                    self.text_series
                        .entry(owner)
                        .or_default()
                        .insert(print, series);
                }
            }
        }
    }
}

#[derive(Row, Deserialize)]
struct CurrentText {
    agent: String,
    metric: String,
    labels: Labels,
    value: String,
}

/// Puts labels back in the form the writer compares them in.
fn labels_of(labels: &Labels) -> Vec<(String, String)> {
    labels
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// `argMax` skips nothing-values, and text that's cleared is one, so they go in a tuple
/// to count as the newest value.
async fn load_memory(client: &Client) -> Result<Memory> {
    let mut memory = Memory::default();
    let series: Vec<SeriesRow> = client
        .query("SELECT agent, metric, labels FROM series FINAL")
        .fetch_all()
        .await
        .context("loading series")?;
    for row in series {
        let print = fingerprint(
            &row.agent,
            &row.metric,
            &labels_key(&labels_of(&row.labels)),
        );
        memory.series.entry(row.agent).or_default().insert(print);
    }

    let texts: Vec<CurrentText> = client
        .query(
            "SELECT agent, metric, labels, assumeNotNull(newest) AS value FROM (
                 SELECT agent, metric, labels, argMax(tuple(value), time).1 AS newest
                 FROM texts GROUP BY agent, metric, labels
             ) WHERE newest IS NOT NULL",
        )
        .fetch_all()
        .await
        .context("loading text")?;
    for row in texts {
        let item = labels_key(&labels_of(&row.labels));
        let print = fingerprint(&row.agent, &row.metric, &item);
        let collector = row.metric.split('.').next().unwrap_or_default().to_string();
        memory.texts.insert(print, row.value);
        let series = TextSeries {
            metric: row.metric,
            labels: row.labels,
            item,
        };
        memory
            .text_series
            .entry((row.agent, collector))
            .or_default()
            .insert(print, series);
    }
    Ok(memory)
}

async fn migrate(client: &Client) -> Result<()> {
    client
        .query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 name String,
                 applied_at DateTime DEFAULT now()
             ) ENGINE = MergeTree ORDER BY name",
        )
        .execute()
        .await
        .context("creating the migrations table")?;

    for (name, statements) in MIGRATIONS {
        let applied: u64 = client
            .query("SELECT count() FROM schema_migrations WHERE name = ?")
            .bind(*name)
            .fetch_one()
            .await?;
        if applied > 0 {
            continue;
        }
        for statement in *statements {
            client
                .query_raw(statement)
                .execute()
                .await
                .with_context(|| format!("applying migration {name}"))?;
        }
        client
            .query("INSERT INTO schema_migrations (name) VALUES (?)")
            .bind(*name)
            .execute()
            .await?;
    }
    Ok(())
}

pub struct ClickHouseStore {
    client: Client,
    memory: Memory,
}

impl ClickHouseStore {
    /// Can be called from anywhere, so it does its waiting on a thread of its own.
    pub fn open(
        url: &str,
        database: &str,
        user: Option<&str>,
        password_file: Option<&Path>,
    ) -> Result<Self> {
        let mut client = Client::default().with_url(url);
        if let Some(user) = user {
            client = client.with_user(user);
        }
        if let Some(path) = password_file {
            let password = std::fs::read_to_string(path)
                .with_context(|| format!("reading password file {}", path.display()))?;
            client = client.with_password(password.trim());
        }
        let database = database.to_string();
        std::thread::scope(|scope| {
            let opening = scope.spawn(|| {
                wait(async {
                    client
                        .query_raw(&format!("CREATE DATABASE IF NOT EXISTS `{database}`"))
                        .execute()
                        .await
                        .context("reaching ClickHouse")?;
                    let client = client.clone().with_database(&database);
                    migrate(&client).await?;
                    let memory = load_memory(&client).await?;
                    anyhow::Ok(Self { client, memory })
                })
            });
            opening
                .join()
                .unwrap_or_else(|_| bail!("opening ClickHouse panicked"))
        })
    }

    async fn insert<T>(&self, table: &str, rows: &[T]) -> Result<()>
    where
        T: Row + Serialize + for<'a> clickhouse::RowWrite<Value<'a> = T>,
    {
        if rows.is_empty() {
            return Ok(());
        }
        // ClickHouse wants few, large inserts. It gathers ours up, and waiting for it
        // means a sample really is stored by the time the agent hears so.
        let mut insert = self
            .client
            .clone()
            .with_setting("async_insert", "1")
            .with_setting("wait_for_async_insert", "1")
            .insert::<T>(table)
            .await?;
        for row in rows {
            insert.write(row).await?;
        }
        insert.end().await?;
        Ok(())
    }

    async fn write_rows(&self, rows: &Rows) -> Result<()> {
        self.insert("series", &rows.series).await?;
        self.insert("texts", &rows.texts).await?;
        self.insert("samples", &rows.samples).await?;
        self.insert("reports", &rows.reports).await
    }
}

impl Store for ClickHouseStore {
    fn write(&mut self, samples: &[NewSample]) -> Result<()> {
        let mut rows = Rows::default();
        for new in samples {
            if let Err(error) = self.memory.add_sample(new, &mut rows) {
                self.memory.take_back(rows.undo);
                return Err(error);
            }
        }
        let result = wait(self.write_rows(&rows));
        if result.is_err() {
            // None of it may have reached the database, so it all has to go again.
            self.memory.take_back(rows.undo);
        }
        result
    }

    fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
        Ok(Arc::new(ClickHouseReader {
            client: self.client.clone(),
        }))
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The stored name of a reading.
fn stored_name(metric: &Metric, path: &str) -> String {
    format!("{}.{}", metric.collector, path.trim_start_matches("$."))
}

/// What a series is called in a result.
enum Naming<'a> {
    Fixed(&'a str),
    Label(&'a str),
}

impl Naming<'_> {
    fn expression(&self) -> String {
        match self {
            Self::Fixed(name) => quoted(name),
            Self::Label(label) => format!("labels[{}]", quoted(label)),
        }
    }

    fn filter(&self) -> String {
        match self {
            Self::Fixed(_) => String::new(),
            Self::Label(label) => format!("AND mapContains(labels, {})", quoted(label)),
        }
    }
}

/// One reading of a metric as rows of `agent`, `t`, `series` and `v`. `scope` narrows
/// down the rows, and is always worked out here.
fn reading_values(metric: &Metric, reading: Reading, naming: &Naming<'_>, scope: &str) -> String {
    let series = naming.expression();
    let filter = naming.filter();
    match reading {
        Reading::Field(path) | Reading::Rate(path) => format!(
            "SELECT agent, toUnixTimestamp64Milli(time) AS t, {series} AS series, value AS v
             FROM samples WHERE metric = {name} {filter} AND {scope}",
            name = quoted(&stored_name(metric, path)),
        ),
        Reading::Percent { part, whole } => {
            let part = quoted(&stored_name(metric, part));
            let whole = quoted(&stored_name(metric, whole));
            format!(
                "SELECT agent, toUnixTimestamp64Milli(time) AS t, {series} AS series,
                        avgIf(value, metric = {part}) / nullIf(avgIf(value, metric = {whole}), 0) * 100 AS v
                 FROM samples WHERE metric IN ({part}, {whole}) {filter} AND {scope}
                 GROUP BY agent, t, series
                 HAVING countIf(metric = {part}) > 0 AND countIf(metric = {whole}) > 0"
            )
        }
    }
}

/// One row per value, as `agent`, `t`, `series` and `v`.
fn readings(metric: &Metric, scope: &str) -> String {
    match metric.source {
        Source::Fields(fields) => fields
            .iter()
            .map(|(name, reading)| reading_values(metric, *reading, &Naming::Fixed(name), scope))
            .collect::<Vec<_>>()
            .join(" UNION ALL "),
        Source::Items { name, reading } => {
            let label = Naming::Label(name.trim_start_matches("$."));
            reading_values(metric, reading, &label, scope)
        }
        Source::Entries(reading) => {
            reading_values(metric, reading, &Naming::Label(ENTRY_LABEL), scope)
        }
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

/// Readings as values, with counts turned into rates. Each value covers the time since
/// the sample before it, so the first has nothing to compare with and is dropped.
fn computed(metric: &Metric, scope: &str) -> String {
    let readings = readings(metric, scope);
    let value = if is_rate(metric.source) {
        "v * 1000.0 / nullIf(t - lagInFrame(toNullable(t)) OVER (
             PARTITION BY agent, series ORDER BY t
             ROWS BETWEEN 1 PRECEDING AND CURRENT ROW
         ), 0)"
    } else {
        "v"
    };
    format!(
        "SELECT agent, t, series, toFloat64(assumeNotNull(v2)) AS v FROM (
             SELECT agent, t, series, {value} AS v2 FROM ({readings})
         ) WHERE v2 IS NOT NULL AND abs(v2) <= {LARGEST_VALUE}"
    )
}

fn time_between(from_ms: i64, to_ms: i64, upper: &str) -> String {
    format!(
        "time >= fromUnixTimestamp64Milli(toInt64({from_ms}), 'UTC')
         AND time {upper} fromUnixTimestamp64Milli(toInt64({to_ms}), 'UTC')"
    )
}

#[derive(Row, Deserialize)]
struct PointRow {
    series: String,
    bucket: i64,
    avg: f64,
    min: f64,
    max: f64,
    total: u64,
}

#[derive(Row, Deserialize)]
struct LineRow {
    line: String,
    bucket: i64,
    value: f64,
    total: u64,
}

#[derive(Row, Deserialize)]
struct LastRow {
    agent: String,
    time_ms: i64,
}

#[derive(Row, Deserialize)]
struct NewestRow {
    agent: String,
    series: String,
    time_ms: i64,
    value: f64,
}

#[derive(Row, Deserialize)]
struct LatestRow {
    metric: String,
    labels: Labels,
    value: f64,
    kind: String,
}

#[derive(Row, Deserialize)]
struct LatestText {
    metric: String,
    labels: Labels,
    value: Option<String>,
}

#[derive(Row, Deserialize)]
struct KnownSeries {
    metric: String,
    labels: Labels,
}

#[derive(Row, Deserialize)]
struct CollectorRow {
    name: String,
    rows: u64,
    oldest_ms: i64,
    newest_ms: i64,
}

#[derive(Row, Deserialize)]
struct SizeRow {
    size: String,
    rows: u64,
}

struct ClickHouseReader {
    client: Client,
}

impl MetricsReader for ClickHouseReader {
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult> {
        let range = query.range;
        let scope = format!(
            "agent = {} AND {}",
            quoted(query.agent_id),
            time_between(range.from_ms, range.to_ms, "<")
        );
        // An idle interface says nothing, but a CPU at 0% does.
        let having = if is_rate(query.metric.source) {
            "WHERE peak > 0"
        } else {
            ""
        };
        // Ranked in one pass, as ClickHouse would work a `WITH` out again for each use.
        let sql = format!(
            "SELECT series, bucket, low_v AS min, high_v AS max, mean_v AS avg,
                    toUInt64(lines) AS total
             FROM (
                 SELECT *, max(position) OVER () AS lines FROM (
                     SELECT *, dense_rank() OVER (ORDER BY overall DESC, series) AS position
                     FROM (
                         SELECT *,
                                sum(sum_v) OVER (PARTITION BY series)
                                    / sum(rows_v) OVER (PARTITION BY series) AS overall,
                                max(high_v) OVER (PARTITION BY series) AS peak
                         FROM (
                             SELECT series, toInt64(intDiv(t, {step}) * {step}) AS bucket,
                                    avg(v) AS mean_v, min(v) AS low_v, max(v) AS high_v,
                                    sum(v) AS sum_v, count() AS rows_v
                             FROM ({values})
                             GROUP BY series, bucket
                         )
                     ) {having}
                 )
             )
             WHERE position <= {max_series}
             ORDER BY series, bucket",
            values = computed(query.metric, &scope),
            step = range.step_ms,
            max_series = query.max_series,
        );
        let rows: Vec<PointRow> = wait(self.client.query_raw(&sql).fetch_all())?;

        let mut result = SeriesResult::default();
        let mut total = 0;
        for row in rows {
            total = row.total as usize;
            let point = Point {
                time_ms: row.bucket,
                avg: row.avg,
                min: row.min,
                max: row.max,
            };
            match result.series.last_mut() {
                Some(series) if series.name == row.series => series.points.push(point),
                _ => result.series.push(Series {
                    name: row.series,
                    points: vec![point],
                }),
            }
        }
        result.hidden = total.saturating_sub(result.series.len());
        Ok(result)
    }

    fn last_samples(&self, since_ms: i64, until_ms: i64) -> Result<Vec<LastSample>> {
        let sql = format!(
            "SELECT agent, toInt64(toUnixTimestamp64Milli(max(time))) AS time_ms
             FROM reports WHERE {} GROUP BY agent",
            time_between(since_ms, until_ms, "<=")
        );
        let rows: Vec<LastRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        Ok(rows
            .into_iter()
            .map(|row| LastSample {
                agent_id: row.agent,
                time_ms: row.time_ms,
            })
            .collect())
    }

    fn latest_output(
        &self,
        agent_id: &str,
        collector: &str,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Option<Value>> {
        let agent = quoted(agent_id);
        let prefix = quoted(&format!("{collector}."));
        let sql = format!(
            "SELECT metric, labels FROM series FINAL
             WHERE agent = {agent} AND startsWith(metric, {prefix}) ORDER BY metric"
        );
        let known: Vec<KnownSeries> = wait(self.client.query_raw(&sql).fetch_all())?;
        if known.is_empty() {
            return Ok(None);
        }
        let metrics = known
            .iter()
            .map(|series| quoted(&series.metric))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");

        let scope = format!(
            "metric IN ({metrics}) AND agent = {agent} AND {}",
            time_between(since_ms, until_ms, "<=")
        );
        let sql = format!(
            "SELECT metric, labels, value, kind FROM samples WHERE {scope}
             AND time = (SELECT max(time) FROM samples WHERE {scope})"
        );
        let latest: Vec<LatestRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        if latest.is_empty() {
            return Ok(None);
        }

        let sql = format!(
            "SELECT metric, labels, argMax(tuple(value), time).1 AS value FROM texts
             WHERE agent = {agent} AND startsWith(metric, {prefix})
               AND time <= fromUnixTimestamp64Milli(toInt64({until_ms}), 'UTC')
             GROUP BY metric, labels"
        );
        let current: Vec<LatestText> = wait(self.client.query_raw(&sql).fetch_all())?;

        // Stored by name, so numbers stand in for them just to put the output together.
        let field = |metric: &str| metric[collector.len() + 1..].to_string();
        let key = |metric: &str, labels: &Labels| (metric.to_string(), labels.clone());
        let places: HashMap<(String, Labels), i64> = known
            .iter()
            .enumerate()
            .map(|(place, series)| (key(&series.metric, &series.labels), place as i64))
            .collect();
        let numbers: HashMap<i64, f64> = latest
            .iter()
            .filter_map(|row| Some((*places.get(&key(&row.metric, &row.labels))?, row.value)))
            .collect();
        let kinds: HashMap<i64, DataType> = latest
            .iter()
            .filter_map(|row| {
                let place = *places.get(&key(&row.metric, &row.labels))?;
                Some((place, DataType::parse(&row.kind)))
            })
            .collect();
        let texts: HashMap<i64, String> = current
            .into_iter()
            .filter_map(|row| {
                let place = *places.get(&key(&row.metric, &row.labels))?;
                Some((place, row.value?))
            })
            .collect();
        let series: Vec<StoredSeries> = known
            .iter()
            .enumerate()
            .map(|(place, series)| {
                let place = place as i64;
                let kind = kinds.get(&place).copied().unwrap_or(DataType::Text);
                let label = series.labels.iter().next();
                let label = label.map(|(name, value)| (name.clone(), value.clone()));
                (place, field(&series.metric), kind, label)
            })
            .collect();
        Ok(rebuilt_output(&series, &numbers, &texts))
    }

    fn newest(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<NewestReading>> {
        let scope = time_between(since_ms, until_ms, "<=");
        let sql = format!(
            "SELECT agent, series, toInt64(max(t)) AS time_ms, argMax(v, t) AS value
             FROM ({values})
             GROUP BY agent, series
             ORDER BY agent, series",
            values = computed(metric, &scope),
        );
        let rows: Vec<NewestRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        Ok(rows
            .into_iter()
            .map(|row| NewestReading {
                agent_id: row.agent,
                series: row.series,
                time_ms: row.time_ms,
                value: row.value,
            })
            .collect())
    }

    fn calculate(&self, query: &CalculationQuery) -> Result<SeriesResult> {
        if query.members.is_empty() {
            return Ok(SeriesResult::default());
        }
        let (groups, places) = numbered(&query.members);
        let agents: Vec<String> = query
            .members
            .iter()
            .map(|member| quoted(&member.agent_id))
            .collect();
        let agents = agents.join(", ");

        let range = query.range;
        let step = range.step_ms.max(SMALLEST_STEP_MS);
        let scope = format!(
            "has(chosen, agent) AND {}",
            time_between(range.from_ms, range.to_ms, "<")
        );
        // The list of machines is by far the longest part of the query, so it's only
        // written once, and the list of groups only if there's more than one.
        let (places, line) = if query.by_series {
            (String::new(), "series".to_string())
        } else if groups.len() == 1 {
            (String::new(), "'0'".to_string())
        } else {
            let places: Vec<String> = places.iter().map(ToString::to_string).collect();
            (
                format!(", [{}] AS places", places.join(", ")),
                "toString(transform(agent, chosen, places, 0))".to_string(),
            )
        };
        // Named lines measure different things, like memory and swap, so they can't be
        // combined. Lines of the same thing, like each disk, can.
        let only_main_line = match query.metric.source {
            Source::Fields([(name, _), _, ..]) if !query.by_series => {
                format!("AND series = {}", quoted(name))
            }
            _ => String::new(),
        };
        let combined = match query.calculation {
            Calculation::Avg => "avg(v)",
            Calculation::Sum => "sum(v)",
            Calculation::Min => "min(v)",
            Calculation::Max => "max(v)",
            Calculation::Count => "toFloat64(count())",
        };
        // Ranked in one pass, as ClickHouse would work a `WITH` out again for each use.
        let sql = format!(
            "WITH [{agents}] AS chosen{places}
             SELECT line, toInt64(bucket) AS bucket, toFloat64(combined) AS value,
                    toUInt64(lines) AS total
             FROM (
                 SELECT *, max(position) OVER () AS lines FROM (
                     SELECT *, dense_rank() OVER (ORDER BY overall DESC, line) AS position
                     FROM (
                         SELECT *, avg(combined) OVER (PARTITION BY line) AS overall
                         FROM (
                             SELECT line, bucket, {combined} AS combined FROM (
                                 SELECT {line} AS line, agent, series,
                                        intDiv(t, {step}) * {step} AS bucket, avg(v) AS v
                                 FROM ({values})
                                 WHERE 1 {only_main_line}
                                 GROUP BY line, agent, series, bucket
                             )
                             WHERE bucket + {step} <= {to_ms}
                             GROUP BY line, bucket
                         )
                     )
                 )
             )
             WHERE position <= {max_lines}
             ORDER BY line, bucket",
            values = computed(query.metric, &scope),
            to_ms = range.to_ms,
            max_lines = query.max_lines,
        );
        let rows: Vec<LineRow> = wait(
            self.client
                .query_raw(&sql)
                .with_setting("max_query_size", MAX_QUERY_BYTES)
                .fetch_all(),
        )?;

        let name_of = |line: &str| match line.parse::<usize>() {
            Ok(place) if !query.by_series => groups.get(place).map(ToString::to_string),
            _ => Some(line.to_string()),
        };
        let mut result = SeriesResult::default();
        let mut total = 0;
        for row in rows {
            total = row.total as usize;
            let point = Point {
                time_ms: row.bucket,
                avg: row.value,
                min: row.value,
                max: row.value,
            };
            let name = name_of(&row.line).unwrap_or_default();
            match result.series.last_mut() {
                Some(series) if series.name == name => series.points.push(point),
                _ => result.series.push(Series {
                    name,
                    points: vec![point],
                }),
            }
        }
        result.series.sort_by(|a, b| a.name.cmp(&b.name));
        result.hidden = total.saturating_sub(result.series.len());
        Ok(result)
    }

    fn series_count(&self) -> Result<u64> {
        let count = self
            .client
            .query("SELECT count() FROM (SELECT DISTINCT agent, metric, labels FROM series)")
            .fetch_one();
        Ok(wait(count)?)
    }

    /// Sizes come from ClickHouse's own records of its files, which cost nothing to read.
    /// Rows by collector only cover the last hour, as a count of everything would read
    /// every metric on every look at the Server page.
    fn stats(&self, hour_ago_ms: i64) -> Result<StoreStats> {
        let size: SizeRow = wait(
            self.client
                .query(
                    "SELECT formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows
                     FROM system.parts WHERE active AND database = currentDatabase()
                       AND table = 'samples'",
                )
                .fetch_one(),
        )?;
        let memory_used: String = wait(
            self.client
                .query(
                    "SELECT formatReadableSize(value) FROM system.metrics
                     WHERE metric = 'MemoryTracking'",
                )
                .fetch_one(),
        )?;
        let sql = format!(
            "SELECT splitByChar('.', metric)[1] AS name, count() AS rows,
                    toInt64(toUnixTimestamp64Milli(min(time))) AS oldest_ms,
                    toInt64(toUnixTimestamp64Milli(max(time))) AS newest_ms
             FROM samples
             WHERE time >= fromUnixTimestamp64Milli(toInt64({hour_ago_ms}), 'UTC')
             GROUP BY name ORDER BY name"
        );
        let collectors: Vec<CollectorRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        let collectors = collectors
            .into_iter()
            .map(|row| {
                let rows = i64::try_from(row.rows).unwrap_or(i64::MAX);
                CollectorStats {
                    name: row.name,
                    rows,
                    rows_last_hour: rows,
                    oldest_ms: row.oldest_ms,
                    newest_ms: row.newest_ms,
                }
            })
            .collect();
        Ok(StoreStats {
            engine: "ClickHouse",
            size: size.size,
            write_ahead_log: "None".to_string(),
            memory_used,
            memory_limit: "Set by ClickHouse".to_string(),
            collectors,
            total_rows: i64::try_from(size.rows).ok(),
        })
    }
}

#[cfg(test)]
mod quoting {
    use super::quoted;

    #[test]
    fn text_can_not_break_out_of_its_quotes() {
        assert_eq!(quoted("plain"), "'plain'");
        assert_eq!(quoted("it's"), r"'it\'s'");
        assert_eq!(quoted(r"back\"), r"'back\\'");
        assert_eq!(quoted(r"\' OR 1=1"), r"'\\\' OR 1=1'");
    }
}

#[cfg(all(test, feature = "clickhouse-tests"))]
mod tests {
    use std::collections::BTreeMap;

    use maxnines_protocol::Sample;
    use serde_json::{Value, json};

    use super::*;
    use crate::calculations::Member;
    use crate::metrics::{METRICS, TimeRange, find};

    type TestStore = ClickHouseStore;

    const HOUR_MS: i64 = 3_600_000;

    fn url() -> String {
        std::env::var("MAXNINES_TEST_CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18123".to_string())
    }

    /// A name of its own for every test, as tests run at the same time.
    fn new_database() -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("test_{}_{next}", std::process::id())
    }

    fn opened(database: &str) -> TestStore {
        ClickHouseStore::open(&url(), database, None, None).unwrap()
    }

    fn in_memory() -> TestStore {
        opened(&new_database())
    }

    include!("contract_tests.rs");

    fn count(store: &TestStore, sql: &str) -> u64 {
        wait(store.client.query(sql).fetch_one()).unwrap()
    }

    #[test]
    fn a_sample_sent_twice_is_stored_once_after_merging() {
        let mut store = in_memory();
        for agent in ["a", "a", "b"] {
            let cpu = json!({ "usage_percent": 5.0 });
            write_metric(&mut store, agent, 1000, "cpu", cpu);
        }

        wait(store.client.query("OPTIMIZE TABLE samples FINAL").execute()).unwrap();

        assert_eq!(count(&store, "SELECT count() FROM samples"), 2);
    }

    #[test]
    fn one_agent_cannot_flood_the_store() {
        let mut store = in_memory();
        let full: HashSet<u64> = (0..MAX_SERIES_PER_AGENT as u64).collect();
        store.memory.series.insert("noisy".to_string(), full);

        for agent in ["noisy", "calm"] {
            let cpu = json!({ "usage_percent": 1.0 });
            write_metric(&mut store, agent, 1000, "cpu", cpu);
        }

        assert_eq!(count(&store, "SELECT count() FROM samples"), 1);
    }

    #[test]
    fn a_write_that_fails_leaves_everything_to_go_again() {
        let mut store = in_memory();
        let good = store.client.clone();
        let failing = json!([{ "name": "site", "up": 0, "error": "refused" }]);
        let working = json!([{ "name": "site", "up": 1 }]);
        write_metric(&mut store, "a", 1000, "checks", failing);

        store.client = good.clone().with_url("http://127.0.0.1:1");
        let sample = Sample {
            timestamp_ms: 2000,
            metrics: BTreeMap::from([
                ("checks".to_string(), working.clone()),
                ("cpu".to_string(), json!({ "usage_percent": 1.0 })),
            ]),
        };
        assert!(write_one(&mut store, "a", "host", &sample).is_err());

        store.client = good;
        write_one(&mut store, "a", "host", &sample).unwrap();

        assert_eq!(
            count(
                &store,
                "SELECT count() FROM series WHERE metric = 'cpu.usage_percent'"
            ),
            1
        );
        let reader = store.reader().unwrap();
        let output = reader
            .latest_output("a", "checks", 0, 5000)
            .unwrap()
            .unwrap();
        assert_eq!(
            output,
            json!([{ "name": "site", "up": 1 }]),
            "the error cleared"
        );
    }

    #[test]
    fn a_time_too_far_away_for_clickhouse_is_refused() {
        let mut store = in_memory();
        let sample = Sample {
            timestamp_ms: u64::MAX,
            metrics: BTreeMap::new(),
        };
        assert!(write_one(&mut store, "a", "host", &sample).is_err());
    }

    #[test]
    fn text_that_cleared_stays_cleared_across_a_restart() {
        let database = new_database();
        let failing = json!([{ "name": "site", "up": 0, "error": "refused" }]);
        let working = json!([{ "name": "site", "up": 1 }]);

        let mut store = opened(&database);
        write_metric(&mut store, "a", 1000, "checks", failing.clone());
        write_metric(&mut store, "a", 2000, "checks", working.clone());
        drop(store);

        let mut store = opened(&database);
        write_metric(&mut store, "a", 3000, "checks", working);
        assert_eq!(count(&store, "SELECT count() FROM texts"), 2, "nothing new");
        write_metric(&mut store, "a", 4000, "checks", failing);

        assert_eq!(count(&store, "SELECT count() FROM texts"), 3, "news again");
    }

    #[test]
    fn text_that_cleared_is_not_shown_as_current() {
        let mut store = in_memory();
        let failing = json!([{ "name": "site", "up": 0, "error": "refused" }]);
        let working = json!([{ "name": "site", "up": 1 }]);
        write_metric(&mut store, "a", 1000, "checks", failing);
        write_metric(&mut store, "a", 2000, "checks", working);

        let reader = store.reader().unwrap();
        let output = reader
            .latest_output("a", "checks", 0, 5000)
            .unwrap()
            .unwrap();

        assert_eq!(output, json!([{ "name": "site", "up": 1 }]));
    }

    #[test]
    fn series_are_remembered_across_a_restart() {
        let database = new_database();
        let cpu = || json!({ "usage_percent": 1.0 });

        let mut store = opened(&database);
        write_metric(&mut store, "a", 1000, "cpu", cpu());
        drop(store);

        let store = opened(&database);
        assert_eq!(store.memory.series["a"].len(), 1);
    }

    #[test]
    fn migrations_are_not_repeated_after_reopening() {
        let database = new_database();
        opened(&database);
        let store = opened(&database);
        assert_eq!(
            count(&store, "SELECT count() FROM schema_migrations"),
            MIGRATIONS.len() as u64
        );
    }

    #[test]
    fn stats_report_size_and_the_last_hour() {
        let mut store = in_memory();
        let cpu = || json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "a", 1000, "cpu", cpu());
        write_metric(&mut store, "a", 5000, "cpu", cpu());
        write_metric(&mut store, "a", 9000, "cpu", cpu());

        let stats = store.reader().unwrap().stats(4000).unwrap();

        assert_eq!(stats.engine, "ClickHouse");
        assert_eq!(stats.total_rows, Some(3));
        assert_eq!(stats.collectors[0].name, "cpu");
        assert_eq!(stats.collectors[0].rows_last_hour, 2);
    }

    #[test]
    fn a_password_stays_out_of_errors() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("password");
        std::fs::write(&path, "hunter2-not-in-logs\n").unwrap();

        let error = ClickHouseStore::open(&url(), "x", Some("nobody"), Some(&path))
            .err()
            .expect("that user doesn't exist");

        assert!(!format!("{error:#}").contains("hunter2"), "{error:#}");
    }

    #[test]
    fn a_server_that_can_not_be_reached_says_so() {
        let result = ClickHouseStore::open("http://127.0.0.1:1", "x", None, None);
        let error = result.err().expect("nothing's listening there");
        assert!(
            format!("{error:#}").contains("reaching ClickHouse"),
            "{error:#}"
        );
    }
}
