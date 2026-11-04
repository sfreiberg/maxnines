use std::path::Path;

use anyhow::{Context, Result};
use duckdb::{Config, Connection, params};
use maxnines_protocol::Sample;

use super::Store;

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
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

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
