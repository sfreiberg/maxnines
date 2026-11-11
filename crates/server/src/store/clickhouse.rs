//! Metrics in ClickHouse, for fleets too big for DuckDB. Everything's kept by name
//! rather than by number, because ClickHouse compresses sorted repeats to almost
//! nothing and works best without joins. It sorts and drops repeated samples itself
//! when it merges, so the only upkeep is rolling up and deleting what's too old.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::{Builder, Runtime};
use tracing::warn;

use super::flatten::{DataType, ENTRY_LABEL, Reported, flatten};
use super::rollups::{
    EXPIRE_EVERY_MS, FIVE_MINUTES_MS, HOUR_MS, RATE_LEAD_MS, Retention, Tier,
    full_resolution_cutoff, hour_of, hours_to_redo, is_due, metric_names, tier_for,
};
use super::shared::{
    MAX_NAME_BYTES, MAX_SERIES_PER_HOST, StoredSeries, labels_key, rebuilt_output, shortened,
    top_of,
};
use super::{CollectorStats, LATEST_SAMPLE_MS, MetricsReader, NewSample, Store, StoreStats};
use crate::calculations::{Calculation, CalculationQuery, SMALLEST_STEP_MS, numbered};
use crate::metrics::{
    LastSample, METRICS, Metric, NewestReading, Point, Reading, Series, SeriesQuery, SeriesResult,
    Source, Trend, now_ms,
};

/// Anything beyond this is skipped, as in the other stores.
const LARGEST_VALUE: &str = "1e300";

const BATCH_EVERY: Duration = Duration::from_secs(1);

/// Picking hosts lists them all, which can be longer than ClickHouse's default.
const MAX_QUERY_BYTES: &str = "67108864";

/// Tables are made here, as ClickHouse has no transactions to make them all at once,
/// so each statement can safely run again. Months keep partitions to a number that
/// can't grow out of hand, whatever times agents send. The hour in the sort order lets
/// a query for what's recent skip everything older.
const MIGRATIONS: &[(&str, &[&str])] = &[
    (
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
    ),
    (
        "0002_create_rollups",
        &[
            // What each chart in the catalog showed, a minute and an hour at a time, as
            // the lowest, highest and total value and how many there were. An hour
            // rolled up again is written again with a higher version, which replaces
            // the old rows when ClickHouse merges them, and reads say FINAL until then.
            "CREATE TABLE IF NOT EXISTS rollups_minute (
                 metric  LowCardinality(String),
                 agent   String,
                 series  String,
                 time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
                 low     Float64,
                 high    Float64,
                 summed  Float64,
                 samples UInt64,
                 version UInt64
             )
             ENGINE = ReplacingMergeTree(version)
             PARTITION BY toStartOfMonth(time)
             ORDER BY (metric, agent, series, time)",
            "CREATE TABLE IF NOT EXISTS rollups_hour (
                 metric  LowCardinality(String),
                 agent   String,
                 series  String,
                 time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
                 low     Float64,
                 high    Float64,
                 summed  Float64,
                 samples UInt64,
                 version UInt64
             )
             ENGINE = ReplacingMergeTree(version)
             PARTITION BY toStartOfYear(time)
             ORDER BY (metric, agent, series, time)",
            // How far each metric is rolled up: every hour before this, in milliseconds.
            "CREATE TABLE IF NOT EXISTS rollup_progress (
                 metric        String,
                 done_until_ms Int64,
                 version       UInt64
             )
             ENGINE = ReplacingMergeTree(version)
             ORDER BY metric",
            // Hours that got samples after they were rolled up, to roll up again.
            "CREATE TABLE IF NOT EXISTS rollup_redo (hour_ms Int64)
             ENGINE = ReplacingMergeTree
             ORDER BY hour_ms",
        ],
    ),
    (
        "0003_five_minute_rollups",
        &[
            // Rollups of 5 minutes instead of 1, which are as fine as a chart of 20 hours
            // or more can show and take a fifth of the space. Made from the minutes
            // already rolled up, which gives exactly what rolling up the samples again
            // would. Each statement can run again: the minutes are only dropped last,
            // and an empty table stands in for them if that's already happened.
            "CREATE TABLE IF NOT EXISTS rollups_five_minute (
                 metric  LowCardinality(String),
                 agent   String,
                 series  String,
                 time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
                 low     Float64,
                 high    Float64,
                 summed  Float64,
                 samples UInt64,
                 version UInt64
             )
             ENGINE = ReplacingMergeTree(version)
             PARTITION BY toStartOfMonth(time)
             ORDER BY (metric, agent, series, time)",
            "CREATE TABLE IF NOT EXISTS rollups_minute AS rollups_five_minute",
            "INSERT INTO rollups_five_minute
             SELECT metric, agent, series, toStartOfFiveMinutes(time) AS span,
                    min(low), max(high), sum(summed), sum(samples), max(version)
             FROM rollups_minute FINAL
             GROUP BY metric, agent, series, span",
            "DROP TABLE IF EXISTS rollups_minute",
        ],
    ),
    (
        "0004_rename_agents_to_hosts",
        &[
            // The computer being watched is a host everywhere, so the column that said
            // agent says host. ClickHouse can't rename a column in a table's sort order,
            // so each table is copied into one made the new way, column for column, and
            // the two swapped. Each table's steps can run again from the start: the copy
            // is dropped first, which before the swap is a partial copy and after it is
            // the old table, whose rows are already in the new one.
            "DROP TABLE IF EXISTS samples_hosts",
            "CREATE TABLE samples_hosts (
             metric String,
             host   String,
             labels Map(String, String),
             time   DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
             value  Float64 CODEC(Gorilla, ZSTD(1)),
             kind   String
         )
         ENGINE = ReplacingMergeTree
         PARTITION BY toStartOfMonth(time)
         ORDER BY (metric, toStartOfHour(time), host, labels, time)",
            "INSERT INTO samples_hosts
             SELECT * REPLACE (multiIf(metric = 'server.agents_online', 'server.hosts_online', metric = 'server.agents_approved', 'server.hosts_approved', metric = 'server.agents_waiting', 'server.hosts_waiting', metric) AS metric)
             FROM samples SETTINGS max_partitions_per_insert_block = 0",
            "EXCHANGE TABLES samples AND samples_hosts",
            "DROP TABLE samples_hosts",
            "DROP TABLE IF EXISTS texts_hosts",
            "CREATE TABLE texts_hosts (
             metric String,
             host   String,
             labels Map(String, String),
             time   DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
             value  Nullable(String)
         )
         ENGINE = ReplacingMergeTree
         PARTITION BY toStartOfMonth(time)
         ORDER BY (host, metric, labels, time)",
            "INSERT INTO texts_hosts SELECT * FROM texts SETTINGS max_partitions_per_insert_block = 0",
            "EXCHANGE TABLES texts AND texts_hosts",
            "DROP TABLE texts_hosts",
            "DROP TABLE IF EXISTS series_hosts",
            "CREATE TABLE series_hosts (
             host   String,
             metric String,
             labels Map(String, String)
         )
         ENGINE = ReplacingMergeTree
         ORDER BY (host, metric, labels)",
            "INSERT INTO series_hosts
             SELECT * REPLACE (multiIf(metric = 'server.agents_online', 'server.hosts_online', metric = 'server.agents_approved', 'server.hosts_approved', metric = 'server.agents_waiting', 'server.hosts_waiting', metric) AS metric)
             FROM series SETTINGS max_partitions_per_insert_block = 0",
            "EXCHANGE TABLES series AND series_hosts",
            "DROP TABLE series_hosts",
            "DROP TABLE IF EXISTS reports_hosts",
            "CREATE TABLE reports_hosts (
             time DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
             host String
         )
         ENGINE = ReplacingMergeTree
         PARTITION BY toStartOfMonth(time)
         ORDER BY (time, host)",
            "INSERT INTO reports_hosts SELECT * FROM reports SETTINGS max_partitions_per_insert_block = 0",
            "EXCHANGE TABLES reports AND reports_hosts",
            "DROP TABLE reports_hosts",
            "DROP TABLE IF EXISTS rollups_five_minute_hosts",
            "CREATE TABLE rollups_five_minute_hosts (
                 metric  LowCardinality(String),
                 host    String,
                 series  String,
                 time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
                 low     Float64,
                 high    Float64,
                 summed  Float64,
                 samples UInt64,
                 version UInt64
             )
             ENGINE = ReplacingMergeTree(version)
             PARTITION BY toStartOfMonth(time)
             ORDER BY (metric, host, series, time)",
            "INSERT INTO rollups_five_minute_hosts
             SELECT * REPLACE (if(metric = 'server.agents', 'server.hosts', metric) AS metric)
             FROM rollups_five_minute SETTINGS max_partitions_per_insert_block = 0",
            "EXCHANGE TABLES rollups_five_minute AND rollups_five_minute_hosts",
            "DROP TABLE rollups_five_minute_hosts",
            "DROP TABLE IF EXISTS rollups_hour_hosts",
            "CREATE TABLE rollups_hour_hosts (
                 metric  LowCardinality(String),
                 host    String,
                 series  String,
                 time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
                 low     Float64,
                 high    Float64,
                 summed  Float64,
                 samples UInt64,
                 version UInt64
             )
             ENGINE = ReplacingMergeTree(version)
             PARTITION BY toStartOfYear(time)
             ORDER BY (metric, host, series, time)",
            "INSERT INTO rollups_hour_hosts
             SELECT * REPLACE (if(metric = 'server.agents', 'server.hosts', metric) AS metric)
             FROM rollups_hour SETTINGS max_partitions_per_insert_block = 0",
            "EXCHANGE TABLES rollups_hour AND rollups_hour_hosts",
            "DROP TABLE rollups_hour_hosts",
            // The server's own count of hosts keeps its rollups and how far they got.
            "INSERT INTO rollup_progress
             SELECT 'server.hosts', done_until_ms, version FROM rollup_progress FINAL
             WHERE metric = 'server.agents'",
        ],
    ),
];

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
    host: String,
    labels: Labels,
    time: i64,
    value: f64,
    kind: &'static str,
}

#[derive(Row, Serialize)]
struct TextRow {
    metric: String,
    host: String,
    labels: Labels,
    time: i64,
    value: Option<String>,
}

#[derive(Row, Serialize, Deserialize)]
struct SeriesRow {
    host: String,
    metric: String,
    labels: Labels,
}

#[derive(Row, Serialize)]
struct ReportRow {
    time: i64,
    host: String,
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
        host: String,
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
fn fingerprint(host: &str, metric: &str, labels: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    (host, metric, labels).hash(&mut hasher);
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
    /// For an agent whose rows have been deleted.
    fn forget(&mut self, host: &str) {
        let texts = self
            .text_series
            .iter()
            .filter(|((owner, _), _)| owner == host)
            .flat_map(|(_, series)| series.keys().copied());
        let prints: Vec<u64> = self
            .series
            .remove(host)
            .unwrap_or_default()
            .into_iter()
            .chain(texts)
            .collect();
        for print in prints {
            self.texts.remove(&print);
        }
        self.text_series.retain(|(owner, _), _| owner != host);
        self.over_limit.remove(host);
    }

    /// False once an agent has as many series as it's allowed.
    fn allow(
        &mut self,
        host: &str,
        metric: &str,
        labels: &[(String, String)],
        rows: &mut Rows,
    ) -> bool {
        let print = fingerprint(host, metric, &labels_key(labels));
        let known = self.series.entry(host.to_string()).or_default();
        if known.contains(&print) {
            return true;
        }
        if known.len() >= MAX_SERIES_PER_HOST {
            if self.over_limit.insert(host.to_string()) {
                warn!(
                    host,
                    "a host reached the limit on series, ignoring new ones"
                );
            }
            return false;
        }
        known.insert(print);
        rows.undo.push(Undo::Series {
            host: host.to_string(),
            print,
        });
        rows.series.push(SeriesRow {
            host: host.to_string(),
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
        let host = new.host_id.as_str();
        rows.reports.push(ReportRow {
            time,
            host: host.to_string(),
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
                if !self.allow(host, &metric, &reading.labels, rows) {
                    continue;
                }
                match reading.value {
                    Reported::Number(value, kind) => rows.samples.push(SampleRow {
                        metric,
                        host: host.to_string(),
                        labels: labelled(&reading.labels),
                        time,
                        value,
                        kind: kind.as_str(),
                    }),
                    Reported::Text(text) => {
                        let text = shortened(text);
                        let print = fingerprint(host, &metric, &item);
                        reported.insert(print);
                        if self.texts.get(&print).is_none_or(|known| known != text) {
                            let previous = self.texts.insert(print, text.to_string());
                            rows.undo.push(Undo::Text { print, previous });
                            let labels = labelled(&reading.labels);
                            rows.texts.push(TextRow {
                                metric: metric.clone(),
                                host: host.to_string(),
                                labels: labels.clone(),
                                time,
                                value: Some(text.to_string()),
                            });
                            self.text_series
                                .entry((host.to_string(), collector.clone()))
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
            let key = (host.to_string(), collector.clone());
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
                            host: host.to_string(),
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
                Undo::Series { host, print } => {
                    if let Some(known) = self.series.get_mut(&host) {
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
    host: String,
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
        .query("SELECT host, metric, labels FROM series FINAL")
        .fetch_all()
        .await
        .context("loading series")?;
    for row in series {
        let print = fingerprint(&row.host, &row.metric, &labels_key(&labels_of(&row.labels)));
        memory.series.entry(row.host).or_default().insert(print);
    }

    let texts: Vec<CurrentText> = client
        .query(
            "SELECT host, metric, labels, assumeNotNull(newest) AS value FROM (
                 SELECT host, metric, labels, argMax(tuple(value), time).1 AS newest
                 FROM texts GROUP BY host, metric, labels
             ) WHERE newest IS NOT NULL",
        )
        .fetch_all()
        .await
        .context("loading text")?;
    for row in texts {
        let item = labels_key(&labels_of(&row.labels));
        let print = fingerprint(&row.host, &row.metric, &item);
        let collector = row.metric.split('.').next().unwrap_or_default().to_string();
        memory.texts.insert(print, row.value);
        let series = TextSeries {
            metric: row.metric,
            labels: row.labels,
            item,
        };
        memory
            .text_series
            .entry((row.host, collector))
            .or_default()
            .insert(print, series);
    }
    Ok(memory)
}

async fn migrate(client: &Client, migrations: &[(&str, &[&str])]) -> Result<()> {
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

    for (name, statements) in migrations {
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
    retention: Retention,
    /// How far each metric is rolled up, as kept in `rollup_progress`.
    progress: HashMap<String, i64>,
    /// Hours to roll up again, as kept in `rollup_redo`.
    redo: BTreeSet<i64>,
    /// When to next look for old data to delete.
    next_expiry_ms: i64,
    /// The last version rollups were written with, as each has to be higher.
    version: u64,
}

#[derive(Row, Deserialize)]
struct ProgressRow {
    metric: String,
    done_until_ms: i64,
}

#[derive(Row, Serialize, Deserialize)]
struct RedoRow {
    hour_ms: i64,
}

#[derive(Row, Serialize)]
struct NewProgress {
    metric: String,
    done_until_ms: i64,
    version: u64,
}

impl ClickHouseStore {
    /// Can be called from anywhere, so it does its waiting on a thread of its own.
    pub fn open(
        url: &str,
        database: &str,
        user: Option<&str>,
        password_file: Option<&Path>,
        retention: Retention,
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
                    migrate(&client, MIGRATIONS).await?;
                    let memory = load_memory(&client).await?;
                    let progress: Vec<ProgressRow> = client
                        .query("SELECT metric, done_until_ms FROM rollup_progress FINAL")
                        .fetch_all()
                        .await?;
                    let redo: Vec<RedoRow> = client
                        .query("SELECT hour_ms FROM rollup_redo FINAL")
                        .fetch_all()
                        .await?;
                    anyhow::Ok(Self {
                        client,
                        memory,
                        retention,
                        progress: progress
                            .into_iter()
                            .map(|row| (row.metric, row.done_until_ms))
                            .collect(),
                        redo: redo.into_iter().map(|row| row.hour_ms).collect(),
                        next_expiry_ms: 0,
                        version: 0,
                    })
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
        let mut insert = self.client.insert::<T>(table).await?;
        for row in rows {
            insert.write(row).await?;
        }
        insert.end().await?;
        Ok(())
    }

    /// Samples first and the list of series last, so a delete that fails partway
    /// still knows what's left to delete when it's tried again.
    async fn delete_rows(&self, host_id: &str) -> Result<()> {
        let tables = [
            "samples",
            "texts",
            "reports",
            "rollups_five_minute",
            "rollups_hour",
            "series",
        ];
        for table in tables {
            self.client
                .query(&format!("DELETE FROM {table} WHERE host = ?"))
                .bind(host_id)
                .execute()
                .await
                .with_context(|| format!("deleting a host's {table}"))?;
        }
        Ok(())
    }

    async fn write_rows(&self, rows: &Rows) -> Result<()> {
        self.insert("series", &rows.series).await?;
        self.insert("texts", &rows.texts).await?;
        self.insert("samples", &rows.samples).await?;
        self.insert("reports", &rows.reports).await
    }
}

impl ClickHouseStore {
    /// Higher than any before, so a rollup written again replaces the old one.
    fn next_version(&mut self) -> u64 {
        self.version = self
            .version
            .saturating_add(1)
            .max(u64::try_from(now_ms()).unwrap_or(0));
        self.version
    }

    /// Hours these rows land in that are already rolled up, and not yet waiting to be
    /// rolled up again.
    fn late_hours(&self, rows: &Rows) -> BTreeSet<i64> {
        let Some(rolled_up_until) = self.progress.values().max().copied() else {
            return BTreeSet::new();
        };
        let times = rows.samples.iter().map(|row| row.time);
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

    /// Rolls up one hour of a metric: each 5 minutes from the samples, and then the hour
    /// from those.
    async fn roll_up_hour(&self, metric: &Metric, hour: i64, version: u64) -> Result<()> {
        let end = hour + HOUR_MS;
        let lead = if is_rate(metric.source) {
            RATE_LEAD_MS
        } else {
            0
        };
        let name = quoted(metric.name);
        let sql = format!(
            "INSERT INTO rollups_five_minute
                 (metric, host, series, time, low, high, summed, samples, version)
             SELECT {name}, host, series,
                    fromUnixTimestamp64Milli(
                        toInt64(intDiv(t, {FIVE_MINUTES_MS}) * {FIVE_MINUTES_MS}), 'UTC'
                    ) AS span,
                    min(v), max(v), sum(v), count(), {version}
             FROM ({values})
             WHERE t >= {hour} AND t < {end}
             GROUP BY host, series, span",
            values = computed(metric, &time_between(hour - lead, end, "<")),
        );
        self.client
            .query_raw(&sql)
            .execute()
            .await
            .with_context(|| format!("rolling up 5 minutes of {}", metric.name))?;
        let sql = format!(
            "INSERT INTO rollups_hour
                 (metric, host, series, time, low, high, summed, samples, version)
             SELECT metric, host, series, fromUnixTimestamp64Milli(toInt64({hour}), 'UTC'),
                    min(low), max(high), sum(summed), sum(samples), {version}
             FROM rollups_five_minute FINAL
             WHERE metric = {name} AND {}
             GROUP BY metric, host, series",
            time_between(hour, end, "<"),
        );
        self.client
            .query_raw(&sql)
            .execute()
            .await
            .with_context(|| format!("rolling up the hour of {}", metric.name))
    }

    /// Rolls up the next finished hour for every metric that's reached it. Hours
    /// without a single sample are skipped over, so a gap costs nothing. Without
    /// transactions, a rollup that stops partway is simply done again.
    fn roll_up_next(&mut self, now_ms: i64) -> Result<bool> {
        let start = metric_names()
            .map(|name| self.progress.get(name).copied().unwrap_or(i64::MIN))
            .min()
            .unwrap_or(i64::MIN);
        let sql = format!(
            "SELECT toUnixTimestamp64Milli(minOrNull(time))
             FROM samples WHERE time >= fromUnixTimestamp64Milli(toInt64({}), 'UTC')",
            start.max(0)
        );
        let first: Option<i64> = wait(self.client.query_raw(&sql).fetch_one())
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
        let version = self.next_version();
        let progress: Vec<NewProgress> = due
            .iter()
            .map(|metric| NewProgress {
                metric: metric.name.to_string(),
                done_until_ms: hour + HOUR_MS,
                version,
            })
            .collect();
        wait(async {
            for metric in &due {
                self.roll_up_hour(metric, hour, version).await?;
            }
            self.insert("rollup_progress", &progress).await
        })?;
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
        let version = self.next_version();
        let done: Vec<&'static Metric> = METRICS
            .iter()
            .filter(|metric| {
                self.progress
                    .get(metric.name)
                    .is_some_and(|done| *done > hour)
            })
            .collect();
        wait(async {
            for metric in done {
                self.roll_up_hour(metric, hour, version).await?;
            }
            self.client
                .query("DELETE FROM rollup_redo WHERE hour_ms = ?")
                .bind(hour)
                .execute()
                .await
                .context("noting an hour was rolled up again")
        })?;
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
        let mut statements = Vec::new();
        // Nothing is from before 1970, and a time much further back can't be compared.
        if let Some(cutoff) = cutoff.filter(|cutoff| *cutoff > 0) {
            let before = format!("time < fromUnixTimestamp64Milli(toInt64({cutoff}), 'UTC')");
            statements.push(format!("DELETE FROM samples WHERE {before}"));
            statements.push(format!("DELETE FROM reports WHERE {before}"));
            statements.push(format!(
                "DELETE FROM texts WHERE {before}
                 AND (host, metric, labels, time) NOT IN (
                     SELECT host, metric, labels, max(time) FROM texts
                     GROUP BY host, metric, labels
                 )"
            ));
        }
        let kept = [
            ("rollups_five_minute", Some(self.retention.five_minute_ms)),
            ("rollups_hour", self.retention.hour_ms),
        ];
        for (table, kept_ms) in kept {
            let cutoff = kept_ms.map(|kept_ms| now_ms.saturating_sub(kept_ms));
            if let Some(cutoff) = cutoff.filter(|cutoff| *cutoff > 0) {
                statements.push(format!(
                    "DELETE FROM {table}
                     WHERE time < fromUnixTimestamp64Milli(toInt64({cutoff}), 'UTC')"
                ));
            }
        }
        wait(async {
            for statement in &statements {
                self.client
                    .query_raw(statement)
                    .execute()
                    .await
                    .context("deleting old metrics")?;
            }
            anyhow::Ok(())
        })?;
        self.next_expiry_ms = now_ms + EXPIRE_EVERY_MS;
        Ok(false)
    }
}

impl Store for ClickHouseStore {
    /// ClickHouse wants few, large inserts, about one a second.
    fn batch_every(&self) -> Duration {
        BATCH_EVERY
    }

    fn write(&mut self, samples: &[NewSample]) -> Result<()> {
        let mut rows = Rows::default();
        for new in samples {
            if let Err(error) = self.memory.add_sample(new, &mut rows) {
                self.memory.take_back(rows.undo);
                return Err(error);
            }
        }
        // Noted first, so an hour can't be left out: if the samples then fail, the hour
        // is only rolled up again with nothing new.
        let late = self.late_hours(&rows);
        if !late.is_empty() {
            let redo: Vec<RedoRow> = late.iter().map(|hour| RedoRow { hour_ms: *hour }).collect();
            if let Err(error) = wait(self.insert("rollup_redo", &redo)) {
                self.memory.take_back(rows.undo);
                return Err(error);
            }
            self.redo.extend(late);
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
            retention: self.retention,
        }))
    }

    /// Hours to roll up again come first, as charts are wrong until they are, then new
    /// hours, then deleting.
    fn tidy(&mut self, now_ms: i64) -> Result<bool> {
        Ok(self.redo_next()? || self.roll_up_next(now_ms)? || self.expire(now_ms)?)
    }

    fn delete_host(&mut self, host_id: &str) -> Result<()> {
        wait(self.delete_rows(host_id))?;
        self.memory.forget(host_id);
        Ok(())
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
            "SELECT host, toUnixTimestamp64Milli(time) AS t, {series} AS series, value AS v
             FROM samples WHERE metric = {name} {filter} AND {scope}",
            name = quoted(&stored_name(metric, path)),
        ),
        Reading::Percent { part, whole } => {
            let part = quoted(&stored_name(metric, part));
            let whole = quoted(&stored_name(metric, whole));
            format!(
                "SELECT host, toUnixTimestamp64Milli(time) AS t, {series} AS series,
                        avgIf(value, metric = {part}) / nullIf(avgIf(value, metric = {whole}), 0) * 100 AS v
                 FROM samples WHERE metric IN ({part}, {whole}) {filter} AND {scope}
                 GROUP BY host, t, series
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
             PARTITION BY host, series ORDER BY t
             ROWS BETWEEN 1 PRECEDING AND CURRENT ROW
         ), 0)"
    } else {
        "v"
    };
    format!(
        "SELECT host, t, series, toFloat64(assumeNotNull(v2)) AS v FROM (
             SELECT host, t, series, {value} AS v2 FROM ({readings})
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
    host: String,
    time_ms: i64,
}

#[derive(Row, Deserialize)]
struct NewestRow {
    host: String,
    series: String,
    time_ms: i64,
    value: f64,
}

#[derive(Row, Deserialize)]
struct TrendRow {
    host: String,
    series: String,
    time_ms: i64,
    value: f64,
    first_ms: i64,
    samples: u64,
    slope: f64,
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
    retention: Retention,
}

impl ClickHouseReader {
    /// How far a metric is rolled up, if it's started.
    fn rolled_up_until(&self, metric: &Metric) -> Result<Option<i64>> {
        let found: Vec<i64> = wait(
            self.client
                .query("SELECT done_until_ms FROM rollup_progress FINAL WHERE metric = ?")
                .bind(metric.name)
                .fetch_all(),
        )?;
        Ok(found.first().copied())
    }
}

/// Rows of `agent`, `t`, `series`, `low`, `high`, `summed` and `samples` between two
/// times: rolled up for what is, at `tier`, and each sample after that, as a row of its
/// own. `agents` narrows them down, and is always worked out here. Rates read a little
/// before the start, as each needs the sample before it.
fn cells(
    metric: &Metric,
    hosts: &str,
    (from_ms, to_ms): (i64, i64),
    tier: Tier,
    done: Option<i64>,
) -> String {
    let rolled = tier.table().zip(done);
    let samples_from = rolled.map_or(from_ms, |(_, done)| from_ms.max(done));
    let lead = if is_rate(metric.source) {
        RATE_LEAD_MS
    } else {
        0
    };
    let scope = format!(
        "{hosts} AND {}",
        time_between(samples_from - lead, to_ms, "<")
    );
    let mut cells = format!(
        "SELECT host, t, series, v AS low, v AS high, v AS summed, toUInt64(1) AS samples
         FROM ({values}) WHERE t >= {samples_from}",
        values = computed(metric, &scope),
    );
    if let Some((table, done)) = rolled {
        cells.push_str(&format!(
            " UNION ALL
             SELECT host, toInt64(toUnixTimestamp64Milli(time)) AS t, series, low, high,
                    summed, samples
             FROM {table} FINAL
             WHERE metric = {name} AND {hosts} AND {}",
            time_between(from_ms, to_ms.min(done), "<"),
            name = quoted(metric.name),
        ));
    }
    cells
}

impl MetricsReader for ClickHouseReader {
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult> {
        let range = query.range;
        let tier = tier_for(range.step_ms, range.from_ms, now_ms(), &self.retention);
        let done = self.rolled_up_until(query.metric)?;
        let host = format!("host = {}", quoted(query.host_id));
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
                                    sum(summed) / sum(samples) AS mean_v,
                                    min(low) AS low_v, max(high) AS high_v,
                                    sum(summed) AS sum_v, sum(samples) AS rows_v
                             FROM ({cells})
                             GROUP BY series, bucket
                         )
                     ) {having}
                 )
             )
             WHERE position <= {max_series}
             ORDER BY series, bucket",
            cells = cells(
                query.metric,
                &host,
                (range.from_ms, range.to_ms),
                tier,
                done
            ),
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
            "SELECT host, toInt64(toUnixTimestamp64Milli(max(time))) AS time_ms
             FROM reports WHERE {} GROUP BY host",
            time_between(since_ms, until_ms, "<=")
        );
        let rows: Vec<LastRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        Ok(rows
            .into_iter()
            .map(|row| LastSample {
                host_id: row.host,
                time_ms: row.time_ms,
            })
            .collect())
    }

    fn latest_output(
        &self,
        host_id: &str,
        collector: &str,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Option<Value>> {
        let host = quoted(host_id);
        let prefix = quoted(&format!("{collector}."));
        let sql = format!(
            "SELECT metric, labels FROM series FINAL
             WHERE host = {host} AND startsWith(metric, {prefix}) ORDER BY metric"
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
            "metric IN ({metrics}) AND host = {host} AND {}",
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
             WHERE host = {host} AND startsWith(metric, {prefix})
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
            "SELECT host, series, toInt64(max(t)) AS time_ms, argMax(v, t) AS value
             FROM ({values})
             GROUP BY host, series
             ORDER BY host, series",
            values = computed(metric, &scope),
        );
        let rows: Vec<NewestRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        Ok(rows
            .into_iter()
            .map(|row| NewestReading {
                host_id: row.host,
                series: row.series,
                time_ms: row.time_ms,
                value: row.value,
            })
            .collect())
    }

    /// Times are counted from the start, as milliseconds since 1970 are big enough
    /// to cost the fit its precision.
    fn trends(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<Trend>> {
        let scope = time_between(since_ms, until_ms, "<=");
        let sql = format!(
            "SELECT host, series, toInt64(max(t)) AS time_ms, argMax(v, t) AS value,
                    toInt64(min(t)) AS first_ms, count() AS samples,
                    tupleElement(simpleLinearRegression(toFloat64(t - {since_ms}), v), 1) AS slope
             FROM ({values})
             GROUP BY host, series
             HAVING time_ms > first_ms
             ORDER BY host, series",
            values = computed(metric, &scope),
        );
        let rows: Vec<TrendRow> = wait(self.client.query_raw(&sql).fetch_all())?;
        Ok(rows
            .into_iter()
            .filter(|row| row.slope.is_finite())
            .map(|row| Trend {
                host_id: row.host,
                series: row.series,
                time_ms: row.time_ms,
                value: row.value,
                first_ms: row.first_ms,
                samples: row.samples,
                slope_per_ms: row.slope,
            })
            .collect())
    }

    fn calculate(&self, query: &CalculationQuery) -> Result<SeriesResult> {
        if query.members.is_empty() {
            return Ok(SeriesResult::default());
        }
        let (groups, places) = numbered(&query.members);
        let hosts: Vec<String> = query
            .members
            .iter()
            .map(|member| quoted(&member.host_id))
            .collect();
        let hosts = hosts.join(", ");

        let range = query.range;
        let step = range.step_ms.max(SMALLEST_STEP_MS);
        let tier = tier_for(step, range.from_ms, now_ms(), &self.retention);
        let done = self.rolled_up_until(query.metric)?;
        // The list of hosts is by far the longest part of the query, so it's only
        // written once, and the list of groups only if there's more than one.
        let (places, line) = if query.by_series {
            (String::new(), "series".to_string())
        } else if groups.len() == 1 {
            (String::new(), "'0'".to_string())
        } else {
            let places: Vec<String> = places.iter().map(ToString::to_string).collect();
            (
                format!(", [{}] AS places", places.join(", ")),
                "toString(transform(host, chosen, places, 0))".to_string(),
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
            "WITH [{hosts}] AS chosen{places}
             SELECT line, toInt64(bucket) AS bucket, toFloat64(combined) AS value,
                    toUInt64(lines) AS total
             FROM (
                 SELECT *, max(position) OVER () AS lines FROM (
                     SELECT *, dense_rank() OVER (ORDER BY overall DESC, line) AS position
                     FROM (
                         SELECT *, avg(combined) OVER (PARTITION BY line) AS overall
                         FROM (
                             SELECT line, bucket, {combined} AS combined FROM (
                                 SELECT {line} AS line, host, series,
                                        intDiv(t, {step}) * {step} AS bucket,
                                        sum(summed) / sum(samples) AS v
                                 FROM ({cells})
                                 WHERE 1 {only_main_line}
                                 GROUP BY line, host, series, bucket
                             )
                             WHERE bucket + {step} <= {to_ms}
                             GROUP BY line, bucket
                         )
                     )
                 )
             )
             WHERE position <= {max_lines}
             ORDER BY line, bucket",
            cells = cells(
                query.metric,
                "has(chosen, host)",
                (range.from_ms, range.to_ms),
                tier,
                done
            ),
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
            .query("SELECT count() FROM (SELECT DISTINCT host, metric, labels FROM series)")
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
                CollectorStats {
                    name: row.name,
                    // Counting all time per collector would scan the whole table.
                    rows: None,
                    rows_last_hour: i64::try_from(row.rows).unwrap_or(i64::MAX),
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

    /// A name of its own for every test, as tests run at the same time. Process IDs
    /// come round again and databases are left behind, so it has when this run
    /// started in it too, or a later run could find an old run's rows.
    fn new_database() -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        static RUN: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
            let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
            since.map_or(0, |since| since.as_secs())
        });
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("test_{}_{}_{next}", *RUN, std::process::id())
    }

    fn opened(database: &str) -> TestStore {
        ClickHouseStore::open(&url(), database, None, None, Retention::KEEP_EVERYTHING).unwrap()
    }

    fn with_retention(retention: Retention) -> TestStore {
        ClickHouseStore::open(&url(), &new_database(), None, None, retention).unwrap()
    }

    fn in_memory() -> TestStore {
        opened(&new_database())
    }

    include!("contract_tests.rs");

    fn count(store: &TestStore, sql: &str) -> u64 {
        wait(store.client.query(sql).fetch_one()).unwrap()
    }

    const HOST_TABLES: [&str; 6] = [
        "samples",
        "texts",
        "series",
        "reports",
        "rollups_hour",
        "rollups_five_minute",
    ];

    #[test]
    fn agents_become_hosts_keeping_every_row_even_after_stopping_part_way() {
        let database = new_database();
        let client = Client::default().with_url(url());
        let (_, rename) = MIGRATIONS[3];
        // Stopped just after the first table was swapped, before its old one went.
        let swapped = rename
            .iter()
            .position(|statement| statement.starts_with("EXCHANGE"))
            .unwrap();
        wait(async {
            client
                .query_raw(&format!("CREATE DATABASE IF NOT EXISTS `{database}`"))
                .execute()
                .await?;
            let client = client.clone().with_database(&database);
            migrate(&client, &MIGRATIONS[..3]).await?;
            let time = "fromUnixTimestamp64Milli(toInt64(60000), 'UTC')";
            for sql in [
                format!("INSERT INTO samples VALUES ('cpu.usage', 'a', map(), {time}, 1, 'n')"),
                format!("INSERT INTO texts VALUES ('os', 'a', map(), {time}, 'Linux')"),
                "INSERT INTO series VALUES ('a', 'cpu.usage', map())".to_string(),
                format!("INSERT INTO reports VALUES ({time}, 'a')"),
                format!("INSERT INTO rollups_hour VALUES ('cpu.usage', 'a', 'CPU', {time}, 1, 2, 3, 4, 1)"),
                format!(
                    "INSERT INTO rollups_five_minute VALUES ('cpu.usage', 'a', 'CPU', {time}, 1, 2, 3, 4, 1)"
                ),
                format!("INSERT INTO samples VALUES ('server.agents_online', 'server', map(), {time}, 1, 'n')"),
                format!("INSERT INTO rollups_hour VALUES ('server.agents', 'server', 'Online', {time}, 1, 2, 3, 4, 1)"),
                "INSERT INTO rollup_progress VALUES ('server.agents', 60000, 1)".to_string(),
            ] {
                client.query_raw(&sql).execute().await?;
            }
            for statement in &rename[..=swapped] {
                client.query_raw(statement).execute().await?;
            }
            anyhow::Ok(())
        })
        .unwrap();

        let store = opened(&database);

        for table in HOST_TABLES {
            let sql = format!("SELECT count() FROM {table} WHERE host = 'a'");
            assert_eq!(count(&store, &sql), 1, "{table}");
        }
        let left = count(
            &store,
            "SELECT count() FROM system.columns
             WHERE database = currentDatabase() AND name = 'agent'",
        );
        assert_eq!(left, 0, "no table still has the old column");
        for sql in [
            "SELECT count() FROM samples WHERE metric = 'server.hosts_online'",
            "SELECT count() FROM rollups_hour WHERE metric = 'server.hosts'",
            "SELECT count() FROM rollup_progress FINAL WHERE metric = 'server.hosts'",
        ] {
            assert_eq!(count(&store, sql), 1, "{sql}");
        }
        let copies = count(
            &store,
            "SELECT count() FROM system.tables
             WHERE database = currentDatabase() AND name LIKE '%_hosts'",
        );
        assert_eq!(copies, 0);
    }

    #[test]
    fn minute_rollups_become_exactly_the_five_minute_ones() {
        let database = new_database();
        let client = Client::default().with_url(url());
        wait(async {
            client
                .query_raw(&format!("CREATE DATABASE IF NOT EXISTS `{database}`"))
                .execute()
                .await?;
            let client = client.clone().with_database(&database);
            migrate(&client, &MIGRATIONS[..2]).await?;
            // Six minutes: five in the first span, with a spike, and one in the next.
            for minute in 0..6i64 {
                let high = if minute == 2 { 100.0 } else { 20.0 };
                let sql = format!(
                    "INSERT INTO rollups_minute VALUES ('cpu.usage', 'a', 'CPU',
                     fromUnixTimestamp64Milli(toInt64({}), 'UTC'), 10, {high}, {}, 4, 1)",
                    minute * 60_000,
                    60 + minute
                );
                client.query_raw(&sql).execute().await?;
            }
            anyhow::Ok(())
        })
        .unwrap();

        let store = opened(&database);

        let spans: Vec<(i64, f64, f64, f64, u64)> = wait(
            store
                .client
                .query(
                    "SELECT toInt64(toUnixTimestamp64Milli(time)), low, high, summed, samples
                     FROM rollups_five_minute FINAL ORDER BY time",
                )
                .fetch_all(),
        )
        .unwrap();
        assert_eq!(
            spans,
            [
                (0, 10.0, 100.0, 5.0 * 60.0 + 10.0, 20),
                (300_000, 10.0, 20.0, 65.0, 4),
            ]
        );
        let left = count(
            &store,
            "SELECT count() FROM system.tables
             WHERE database = currentDatabase() AND name = 'rollups_minute'",
        );
        assert_eq!(left, 0);
    }

    #[test]
    fn a_sample_sent_twice_is_stored_once_after_merging() {
        let mut store = in_memory();
        for host in ["a", "a", "b"] {
            let cpu = json!({ "usage_percent": 5.0 });
            write_metric(&mut store, host, 1000, "cpu", cpu);
        }

        wait(store.client.query("OPTIMIZE TABLE samples FINAL").execute()).unwrap();

        assert_eq!(count(&store, "SELECT count() FROM samples"), 2);
    }

    #[test]
    fn deleting_an_agent_forgets_it_in_memory_and_in_every_table() {
        let mut store = in_memory();
        for host in ["gone", "kept"] {
            let checks = json!([{ "name": "site", "kind": "http", "up": 0, "error": "no" }]);
            write_metric(&mut store, host, 1000, "checks", checks);
        }
        store.memory.over_limit.insert("gone".to_string());

        store.delete_host("gone").unwrap();

        for table in ["samples", "texts", "series", "reports"] {
            let sql = format!("SELECT count() FROM {table} WHERE host = 'gone'");
            assert_eq!(count(&store, &sql), 0, "{table}");
            let sql = format!("SELECT count() FROM {table} WHERE host = 'kept'");
            assert!(count(&store, &sql) > 0, "{table}");
        }
        assert!(!store.memory.series.contains_key("gone"));
        assert!(store.memory.series.contains_key("kept"));
        assert!(
            store
                .memory
                .text_series
                .keys()
                .all(|(host, _)| host == "kept")
        );
        let kept_texts: usize = store.memory.text_series.values().map(HashMap::len).sum();
        assert_eq!(store.memory.texts.len(), kept_texts);
        assert!(store.memory.over_limit.is_empty());
    }

    #[test]
    fn one_agent_cannot_flood_the_store() {
        let mut store = in_memory();
        let full: HashSet<u64> = (0..MAX_SERIES_PER_HOST as u64).collect();
        store.memory.series.insert("noisy".to_string(), full);

        for host in ["noisy", "calm"] {
            let cpu = json!({ "usage_percent": 1.0 });
            write_metric(&mut store, host, 1000, "cpu", cpu);
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

        let error = ClickHouseStore::open(
            &url(),
            "x",
            Some("nobody"),
            Some(&path),
            Retention::default(),
        )
        .err()
        .expect("that user doesn't exist");

        assert!(!format!("{error:#}").contains("hunter2"), "{error:#}");
    }

    #[test]
    fn a_server_that_can_not_be_reached_says_so() {
        let result =
            ClickHouseStore::open("http://127.0.0.1:1", "x", None, None, Retention::default());
        let error = result.err().expect("nothing's listening there");
        assert!(
            format!("{error:#}").contains("reaching ClickHouse"),
            "{error:#}"
        );
    }
}
