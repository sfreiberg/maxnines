use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result};
use duckdb::{Config, Connection, params};
use maxnines_protocol::Sample;
use tracing::debug;

use super::{MetricsReader, Store};
use crate::metrics::{
    LatestSample, Metric, Point, Reading, Series, SeriesQuery, SeriesResult, Source,
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
    name: "0001_create_metrics",
    // One row per collector per sample. `data` holds the collector's output, so
    // new collectors and fields need no schema change.
    sql: "
        CREATE TABLE metrics (
            time      TIMESTAMP NOT NULL,
            agent_id  VARCHAR   NOT NULL,
            host      VARCHAR   NOT NULL,
            collector VARCHAR   NOT NULL,
            data      JSON      NOT NULL
        );
    ",
}];

/// Only the bookkeeping table is created outside a migration, because it is
/// what records them.
const CREATE_MIGRATIONS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS schema_migrations (
        name       VARCHAR   PRIMARY KEY,
        applied_at TIMESTAMP NOT NULL
    );
";

const INSERT_METRIC: &str = "
    INSERT INTO metrics (time, agent_id, host, collector, data)
    VALUES (epoch_ms(?::BIGINT), ?, ?, ?, ?::JSON)
";

pub struct DuckDbStore {
    connection: Connection,
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
        Ok(Self { connection })
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
    fn write(&mut self, agent_id: &str, host: &str, sample: &Sample) -> Result<()> {
        let timestamp_ms = i64::try_from(sample.timestamp_ms).context("timestamp out of range")?;

        let transaction = self.connection.transaction()?;
        {
            let mut insert = transaction.prepare(INSERT_METRIC)?;
            for (collector, data) in &sample.metrics {
                insert.execute(params![
                    timestamp_ms,
                    agent_id,
                    host,
                    collector,
                    data.to_string()
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
        Ok(Arc::new(DuckDbReader {
            connection: Mutex::new(self.connection.try_clone()?),
        }))
    }

    /// Readers can outlive this connection, which would otherwise leave recent
    /// writes for the next start to replay.
    fn close(&mut self) -> Result<()> {
        self.connection
            .execute_batch("FORCE CHECKPOINT")
            .context("saving recent writes")
    }
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

/// The SQL for a number at `path`. `TRY_CAST` leaves anything else as NULL, as
/// agents can send any JSON.
fn number(json: &str, path: &str) -> String {
    format!("TRY_CAST({json}->>'{path}' AS DOUBLE)")
}

fn reading(json: &str, reading: Reading) -> String {
    match reading {
        Reading::Field(path) | Reading::Rate(path) => number(json, path),
        Reading::Percent { part, whole } => format!(
            "{} / NULLIF({}, 0) * 100",
            number(json, part),
            number(json, whole)
        ),
    }
}

/// One row per value, as `t`, `series` and `v`. Everything here comes from the
/// metric catalog. `json_each` is used for keys because agents choose them, and
/// a name like `eth0.100` would be misread as a path.
fn readings(source: Source) -> String {
    match source {
        Source::Fields(fields) => fields
            .iter()
            .map(|(name, field)| {
                format!(
                    "SELECT t, '{name}' AS series, {} AS v FROM samples",
                    self::reading("data", *field)
                )
            })
            .collect::<Vec<_>>()
            .join(" UNION ALL "),
        Source::Items { name, reading } => format!(
            "SELECT t, item.value->>'{name}' AS series, {} AS v
             FROM samples, json_each(samples.data) AS item",
            self::reading("item.value", reading)
        ),
        Source::Entries(reading) => format!(
            "SELECT t, item.key AS series, {} AS v
             FROM samples, json_each(samples.data) AS item",
            self::reading("item.value", reading)
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

/// Parameters: agent, collector, from, to, step, and how many series to keep.
fn series_sql(metric: &Metric) -> String {
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

    format!(
        "WITH samples AS (
             SELECT epoch_ms(time) AS t, data FROM metrics
             WHERE agent_id = $1 AND collector = $2
               AND time >= epoch_ms($3::BIGINT) AND time < epoch_ms($4::BIGINT)
         ),
         readings AS ({readings}),
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
         SELECT series, t // $5::BIGINT * $5::BIGINT AS bucket, avg(v), min(v), max(v), total
         FROM usable JOIN ranked USING (series)
         WHERE position <= $6::BIGINT
         GROUP BY series, bucket, total
         ORDER BY series, bucket",
        readings = readings(metric.source),
    )
}

impl MetricsReader for DuckDbReader {
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(&series_sql(query.metric))?;
        let range = query.range;
        let rows = statement.query_map(
            params![
                query.agent_id,
                query.metric.collector,
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

    fn latest(&self, since_ms: i64, until_ms: i64) -> Result<Vec<LatestSample>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT agent_id, collector, epoch_ms(max(time)), arg_max(data, time)::VARCHAR
             FROM metrics
             WHERE time >= epoch_ms($1::BIGINT) AND time <= epoch_ms($2::BIGINT)
             GROUP BY agent_id, collector",
        )?;
        let rows = statement.query_map(params![since_ms, until_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut samples = Vec::new();
        for row in rows {
            let (agent_id, collector, time_ms, data) = row?;
            match serde_json::from_str(&data) {
                Ok(data) => samples.push(LatestSample {
                    agent_id,
                    collector,
                    time_ms,
                    data,
                }),
                Err(error) => debug!(%error, agent_id, collector, "skipped an unreadable sample"),
            }
        }
        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use super::*;
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

    const HOUR_MS: i64 = 3_600_000;

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
        store.write(agent, "host", &sample).unwrap();
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
    fn latest_gives_the_newest_sample_of_each_collector() {
        let mut store = in_memory();
        write_metric(
            &mut store,
            "a",
            1000,
            "cpu",
            json!({ "usage_percent": 1.0 }),
        );
        write_metric(
            &mut store,
            "a",
            2000,
            "cpu",
            json!({ "usage_percent": 2.0 }),
        );
        write_metric(&mut store, "a", 1500, "memory", json!({ "used_bytes": 1 }));
        write_metric(
            &mut store,
            "b",
            1000,
            "cpu",
            json!({ "usage_percent": 3.0 }),
        );

        let mut latest = store.reader().unwrap().latest(0, 5000).unwrap();
        latest.sort_by_key(|sample| (sample.agent_id.clone(), sample.collector.clone()));

        assert_eq!(latest.len(), 3);
        assert_eq!(latest[0].time_ms, 2000);
        assert_eq!(latest[0].data, json!({ "usage_percent": 2.0 }));
        assert_eq!(latest[1].collector, "memory");
        assert_eq!(latest[2].agent_id, "b");
    }

    #[test]
    fn latest_ignores_samples_outside_its_window() {
        let mut store = in_memory();
        let cpu = || json!({ "usage_percent": 1.0 });
        write_metric(&mut store, "old", 1000, "cpu", cpu());
        write_metric(&mut store, "now", 5000, "cpu", cpu());
        write_metric(&mut store, "future", 9000, "cpu", cpu());

        let latest = store.reader().unwrap().latest(2000, 8000).unwrap();

        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].agent_id, "now");
    }

    #[test]
    fn reads_see_writes_and_work_while_writes_continue() {
        let mut store = in_memory();
        let reader = store.reader().unwrap();

        let reads = std::thread::spawn(move || {
            for _ in 0..200 {
                reader.latest(0, HOUR_MS).unwrap();
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

        assert_eq!(reader.latest(0, HOUR_MS).unwrap()[0].time_ms, 199);
    }

    #[test]
    fn closing_saves_recent_writes_even_with_a_reader_open() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("m.duckdb");
        let mut store = DuckDbStore::open(&path, "1GB").unwrap();
        let reader = store.reader().unwrap();
        store.write("a", "h", &sample()).unwrap();
        assert!(path.with_extension("duckdb.wal").exists());

        store.close().unwrap();

        assert!(!path.with_extension("duckdb.wal").exists());
        assert_eq!(reader.latest(0, 2_000_000_000_000).unwrap().len(), 2);
    }

    fn row_count(store: &DuckDbStore) -> i64 {
        store
            .connection
            .query_row("SELECT count(*) FROM metrics", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn stores_one_row_per_collector() {
        let mut store = in_memory();
        store.write("agent-1", "web-1", &sample()).unwrap();
        assert_eq!(row_count(&store), 2);
    }

    #[test]
    fn stored_values_can_be_queried() {
        let mut store = in_memory();
        store.write("agent-1", "web-1", &sample()).unwrap();

        let (time, agent_id, host, usage): (String, String, String, String) = store
            .connection
            .query_row(
                "SELECT time::VARCHAR, agent_id, host, data->>'$.usage_percent'
                 FROM metrics WHERE collector = 'cpu'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(time, "2023-11-14 22:13:20.123");
        assert_eq!(agent_id, "agent-1");
        assert_eq!(host, "web-1");
        assert_eq!(usage, "12.5");
    }

    #[test]
    fn rejects_out_of_range_timestamps() {
        let mut store = in_memory();
        let mut bad = sample();
        bad.timestamp_ms = u64::MAX;

        assert!(store.write("agent-1", "web-1", &bad).is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn a_failure_partway_through_a_sample_stores_none_of_it() {
        let mut store = in_memory();
        // "cpu" inserts first, then this rejects "disk".
        store
            .connection
            .execute_batch(
                "DROP TABLE metrics;
                 CREATE TABLE metrics (
                     time      TIMESTAMP NOT NULL,
                     agent_id  VARCHAR   NOT NULL,
                     host      VARCHAR   NOT NULL,
                     collector VARCHAR   NOT NULL CHECK (collector <> 'disk'),
                     data      JSON      NOT NULL
                 );",
            )
            .unwrap();

        assert!(store.write("agent-1", "web-1", &sample()).is_err());
        assert_eq!(row_count(&store), 0);
    }

    #[test]
    fn data_survives_reopening_and_creates_parent_folders() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/maxnines.duckdb");

        DuckDbStore::open(&path, "1GB")
            .unwrap()
            .write("agent-1", "web-1", &sample())
            .unwrap();

        let mut reopened = DuckDbStore::open(&path, "1GB").unwrap();
        reopened.write("agent-1", "web-1", &sample()).unwrap();
        assert_eq!(row_count(&reopened), 4);
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
