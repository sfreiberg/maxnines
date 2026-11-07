//! How the database is doing, for the server page. Nothing here mentions the
//! connection URL, because it can hold a password.

use std::time::Instant;

use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, PaginatorTrait, QueryFilter,
    Statement,
};
use serde::Serialize;

use super::{
    Database, agent, agent_fact, alert, alert_rule, config_rule, notification,
    notification_channel, remote_check,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableCount {
    pub name: &'static str,
    pub rows: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DatabaseStats {
    pub engine: &'static str,
    pub size_bytes: Option<i64>,
    /// How long a trip to the database took just now.
    pub response_ms: f64,
    pub latest_migration: Option<String>,
    pub tables: Vec<TableCount>,
    pub notifications_waiting: u64,
    pub notifications_failed: u64,
}

fn engine_name(backend: DatabaseBackend) -> &'static str {
    match backend {
        DatabaseBackend::Sqlite => "SQLite",
        DatabaseBackend::Postgres => "PostgreSQL",
        DatabaseBackend::MySql => "MySQL",
        _ => "Unknown",
    }
}

fn size_query(backend: DatabaseBackend) -> Option<&'static str> {
    match backend {
        DatabaseBackend::Sqlite => {
            Some("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()")
        }
        DatabaseBackend::Postgres => Some("SELECT pg_database_size(current_database())"),
        DatabaseBackend::MySql => Some(
            "SELECT CAST(COALESCE(SUM(data_length + index_length), 0) AS SIGNED)
             FROM information_schema.tables WHERE table_schema = DATABASE()",
        ),
        _ => None,
    }
}

impl Database {
    /// Only for what's reported about this database. A size that can't be read
    /// isn't worth losing the rest over, as some hosts restrict these views.
    /// How big the database is, for databases that can say.
    pub async fn size(&self) -> Option<i64> {
        self.size_bytes(self.connection.get_database_backend())
            .await
    }

    async fn size_bytes(&self, backend: DatabaseBackend) -> Option<i64> {
        let sql = size_query(backend)?;
        let statement = Statement::from_string(backend, sql);
        let row = self.connection.query_one_raw(statement).await.ok()??;
        row.try_get_by_index(0).ok()
    }

    async fn latest_migration(&self, backend: DatabaseBackend) -> Result<Option<String>> {
        let sql = "SELECT version FROM seaql_migrations ORDER BY version DESC LIMIT 1";
        let row = self
            .connection
            .query_one_raw(Statement::from_string(backend, sql))
            .await
            .context("reading the schema version")?;
        row.map(|row| row.try_get_by_index(0))
            .transpose()
            .context("reading the schema version")
    }

    /// Whether the database answers a real question, as a closed connection pool or a
    /// missing table can still answer a ping.
    pub async fn is_reachable(&self) -> bool {
        agent::Entity::find().one(&self.connection).await.is_ok()
    }

    pub async fn stats(&self) -> Result<DatabaseStats> {
        let backend = self.connection.get_database_backend();

        let started = Instant::now();
        self.connection
            .ping()
            .await
            .context("reaching the database")?;
        let response_ms = started.elapsed().as_secs_f64() * 1000.0;

        let connection = &self.connection;
        let notifications = |state: &'static str| {
            notification::Entity::find()
                .filter(notification::Column::State.eq(state))
                .count(connection)
        };
        let tables = vec![
            TableCount {
                name: "Agents",
                rows: agent::Entity::find().count(connection).await?,
            },
            TableCount {
                name: "Facts",
                rows: agent_fact::Entity::find().count(connection).await?,
            },
            TableCount {
                name: "Config rules",
                rows: config_rule::Entity::find().count(connection).await?,
            },
            TableCount {
                name: "Alert rules",
                rows: alert_rule::Entity::find().count(connection).await?,
            },
            TableCount {
                name: "Alerts",
                rows: alert::Entity::find().count(connection).await?,
            },
            TableCount {
                name: "Notification channels",
                rows: notification_channel::Entity::find()
                    .count(connection)
                    .await?,
            },
            TableCount {
                name: "Notifications",
                rows: notification::Entity::find().count(connection).await?,
            },
            TableCount {
                name: "Server checks",
                rows: remote_check::Entity::find().count(connection).await?,
            },
        ];

        Ok(DatabaseStats {
            engine: engine_name(backend),
            size_bytes: self.size_bytes(backend).await,
            response_ms,
            latest_migration: self.latest_migration(backend).await?,
            tables,
            notifications_waiting: notifications("pending").await?,
            notifications_failed: notifications("failed").await?,
        })
    }
}
