//! PostgreSQL's health, load and replication, from its statistics views. Every
//! query works for an account in `pg_monitor`; without it, other sessions'
//! details and some views are hidden, which is noted rather than failing.
//!
//! Queries differ by version, chosen from `server_version_num`. Version 13 and
//! later are what's aimed at, and older ones leave out what they don't have.

use anyhow::{Context, Result};
use maxnines_protocol::Check;
use tokio::task::JoinHandle;
use tokio_postgres::Client;

use super::Rows;
use crate::Credentials;
use crate::sign_in::{pg_short, postgres_client};

pub(super) struct Postgres {
    client: Client,
    version: i32,
    running: JoinHandle<()>,
}

impl Drop for Postgres {
    fn drop(&mut self) {
        self.running.abort();
    }
}

impl Postgres {
    pub(super) async fn connect(check: &Check, credentials: &Credentials) -> Result<Self> {
        let (client, running) =
            postgres_client(check, credentials, check.tls == Some(true)).await?;
        // A read that goes wrong never holds anything up for long, and never
        // writes.
        client
            .batch_execute(
                "SET statement_timeout = '5s'; SET lock_timeout = '1s'; \
                 SET default_transaction_read_only = on",
            )
            .await
            .map_err(pg_short)?;
        let row = client
            .query_one("SELECT current_setting('server_version_num')::int4", &[])
            .await
            .map_err(pg_short)?;
        Ok(Self {
            client,
            version: row.try_get(0)?,
            running,
        })
    }

    pub(super) async fn read(&self, rows: &mut Rows, extras: &[String]) -> Result<()> {
        let replica = self.server(rows).await?;
        self.sessions(rows).await;
        self.throughput(rows).await;
        self.housekeeping(rows).await;
        if replica {
            self.replica(rows).await;
        } else {
            self.standbys(rows).await;
        }
        self.slots(rows).await;
        self.archiving(rows).await;
        self.subscriptions(rows).await;
        if extras.iter().any(|extra| extra == "sizes") {
            self.sizes(rows).await;
        }
        Ok(())
    }

    /// The one query that has to work, as it says the server answers. Whether
    /// it's a replica decides what else is asked.
    async fn server(&self, rows: &mut Rows) -> Result<bool> {
        let row = self
            .client
            .query_one(
                "SELECT current_setting('server_version'),
                        extract(epoch FROM now() - pg_postmaster_start_time())::float8,
                        pg_is_in_recovery(),
                        (current_setting('max_connections')::int4
                         - current_setting('superuser_reserved_connections')::int4)::float8,
                        pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')",
                &[],
            )
            .await
            .map_err(pg_short)
            .context("reading the server's state")?;
        let replica: bool = row.try_get(2)?;
        let main = &mut rows.main;
        main.set("version", row.try_get::<_, String>(0)?);
        main.set("uptime_secs", row.try_get::<_, f64>(1)?);
        main.set("role", if replica { "replica" } else { "primary" });
        main.flag("replica", replica);
        main.set("max_connections", row.try_get::<_, f64>(3)?);
        if !row.try_get::<_, bool>(4)? {
            rows.missed(
                "other sessions",
                "the account can't see them; grant it pg_monitor",
            );
        }
        Ok(replica)
    }

    async fn sessions(&self, rows: &mut Rows) {
        let found = self
            .client
            .query_one(
                "SELECT count(*)::float8,
                        count(*) FILTER (WHERE state = 'active')::float8,
                        count(*) FILTER (WHERE state LIKE 'idle in transaction%')::float8,
                        count(*) FILTER (WHERE wait_event_type = 'Lock')::float8,
                        coalesce(extract(epoch FROM max(now() - xact_start)), 0)::float8,
                        coalesce(extract(epoch FROM max(now() - query_start)
                            FILTER (WHERE state = 'active')), 0)::float8,
                        coalesce(extract(epoch FROM max(now() - state_change)
                            FILTER (WHERE state LIKE 'idle in transaction%')), 0)::float8
                 FROM pg_stat_activity
                 WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()",
                &[],
            )
            .await;
        let row = match found {
            Ok(row) => row,
            Err(error) => return rows.missed("sessions", pg_short(error)),
        };
        let number = |index: usize| row.try_get::<_, f64>(index).ok();
        let main = &mut rows.main;
        main.maybe("connections", number(0));
        if let (Some(used), Some(max)) = (number(0), main.fields["max_connections"].as_f64())
            && max > 0.0
        {
            main.set("connections_used", used / max * 100.0);
        }
        main.maybe("running_queries", number(1));
        main.maybe("idle_in_transaction", number(2));
        main.maybe("lock_waits", number(3));
        main.maybe("oldest_transaction_secs", number(4));
        main.maybe("oldest_query_secs", number(5));
        main.maybe("oldest_idle_in_transaction_secs", number(6));
    }

    /// Running totals across every database on the server.
    async fn throughput(&self, rows: &mut Rows) {
        let checksums = if self.version >= 120_000 {
            "coalesce(sum(checksum_failures), 0)::float8"
        } else {
            "0::float8"
        };
        let query = format!(
            "SELECT sum(xact_commit + xact_rollback)::float8, sum(xact_rollback)::float8,
                    sum(blks_read)::float8, sum(blks_hit)::float8, sum(temp_bytes)::float8,
                    sum(deadlocks)::float8, sum(conflicts)::float8, {checksums}
             FROM pg_stat_database"
        );
        match self.client.query_one(&query, &[]).await {
            Ok(row) => {
                let number = |index: usize| row.try_get::<_, f64>(index).ok();
                let main = &mut rows.main;
                main.total("transactions", number(0));
                main.total("rollbacks", number(1));
                main.total("_blocks_hit", number(3));
                if let (Some(read), Some(hit)) = (number(2), number(3)) {
                    main.total("_blocks_wanted", Some(read + hit));
                }
                main.average("cache_hit", "_blocks_hit", "_blocks_wanted", 100.0);
                main.total("temp_bytes", number(4));
                main.total("deadlocks", number(5));
                main.total("conflicts", number(6));
                main.total("checksum_failures", number(7));
            }
            Err(error) => rows.missed("database statistics", pg_short(error)),
        }

        // Moved to a view of its own in 17.
        let checkpoints = if self.version >= 170_000 {
            "SELECT num_timed::float8, num_requested::float8 FROM pg_stat_checkpointer"
        } else {
            "SELECT checkpoints_timed::float8, checkpoints_req::float8 FROM pg_stat_bgwriter"
        };
        match self.client.query_one(checkpoints, &[]).await {
            Ok(row) => {
                rows.main.total("checkpoints_timed", row.try_get(0).ok());
                rows.main
                    .total("checkpoints_requested", row.try_get(1).ok());
            }
            Err(error) => rows.missed("checkpoints", pg_short(error)),
        }

        if self.version >= 140_000 {
            match self
                .client
                .query_one("SELECT wal_bytes::float8 FROM pg_stat_wal", &[])
                .await
            {
                Ok(row) => rows.main.total("wal_bytes", row.try_get(0).ok()),
                Err(error) => rows.missed("WAL statistics", pg_short(error)),
            }
        }
    }

    /// What, left alone, ends up stopping the server: transaction IDs running
    /// out, and transactions prepared and never finished.
    async fn housekeeping(&self, rows: &mut Rows) {
        match self
            .client
            .query_one(
                "SELECT coalesce(max(age(datfrozenxid)), 0)::float8,
                        coalesce(max(mxid_age(datminmxid)), 0)::float8
                 FROM pg_database WHERE datallowconn",
                &[],
            )
            .await
        {
            Ok(row) => {
                rows.main.maybe("xid_age", row.try_get::<_, f64>(0).ok());
                rows.main.maybe("mxid_age", row.try_get::<_, f64>(1).ok());
            }
            Err(error) => rows.missed("transaction ID age", pg_short(error)),
        }
        match self
            .client
            .query_one(
                "SELECT count(*)::float8,
                        coalesce(extract(epoch FROM max(now() - prepared)), 0)::float8
                 FROM pg_prepared_xacts",
                &[],
            )
            .await
        {
            Ok(row) => {
                rows.main.maybe("prepared", row.try_get::<_, f64>(0).ok());
                rows.main
                    .maybe("oldest_prepared_secs", row.try_get::<_, f64>(1).ok());
            }
            Err(error) => rows.missed("prepared transactions", pg_short(error)),
        }
    }

    /// On a primary, each standby streaming from it.
    async fn standbys(&self, rows: &mut Rows) {
        let found = self
            .client
            .query(
                "SELECT coalesce(nullif(application_name, ''), host(client_addr), 'unnamed'),
                        state, sync_state,
                        pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)::float8,
                        extract(epoch FROM replay_lag)::float8
                 FROM pg_stat_replication",
                &[],
            )
            .await;
        let standbys = match found {
            Ok(standbys) => standbys,
            Err(error) => return rows.missed("standbys", pg_short(error)),
        };
        let mut synchronous = 0;
        for standby in &standbys {
            let name: String = standby.try_get(0).unwrap_or_default();
            let state: Option<String> = standby.try_get(1).ok().flatten();
            let sync: Option<String> = standby.try_get(2).ok().flatten();
            let is_sync = matches!(sync.as_deref(), Some("sync" | "quorum"));
            synchronous += usize::from(is_sync);
            let row = rows.add("standby", &name);
            row.maybe("state", state.clone());
            row.flag("streaming", state.as_deref() == Some("streaming"));
            row.flag("synchronous", is_sync);
            row.maybe(
                "lag_bytes",
                standby.try_get::<_, Option<f64>>(3).ok().flatten(),
            );
            // Unknown until it's replayed something, and again once it's caught up
            // with nothing new, when bytes behind say it's caught up.
            row.maybe(
                "lag_secs",
                standby.try_get::<_, Option<f64>>(4).ok().flatten(),
            );
        }
        rows.main.set("standbys", standbys.len());
        rows.main.set("synchronous_standbys", synchronous);
    }

    /// On a replica, how far behind it is, and whether it's still receiving.
    async fn replica(&self, rows: &mut Rows) {
        let paused = if self.version >= 140_000 {
            "pg_get_wal_replay_pause_state() <> 'not paused'"
        } else {
            "pg_is_wal_replay_paused()"
        };
        // The time since the last transaction replayed is only lag while there's
        // more to replay. With all of it replayed, an idle primary would
        // otherwise look further and further behind.
        let query = format!(
            "SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0
                         ELSE greatest(0, extract(epoch FROM now()
                                       - pg_last_xact_replay_timestamp())) END::float8,
                    pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())::float8,
                    {paused}"
        );
        match self.client.query_one(&query, &[]).await {
            Ok(row) => {
                let main = &mut rows.main;
                main.maybe("lag_secs", row.try_get::<_, Option<f64>>(0).ok().flatten());
                main.maybe(
                    "replay_backlog_bytes",
                    row.try_get::<_, Option<f64>>(1).ok().flatten(),
                );
                main.maybe(
                    "replay_paused",
                    row.try_get::<_, bool>(2).ok().map(u8::from),
                );
            }
            Err(error) => rows.missed("replay", pg_short(error)),
        }

        // Caught up says nothing if nothing's arriving, so whether it's still
        // receiving matters as much.
        match self
            .client
            .query_opt(
                "SELECT status,
                        extract(epoch FROM now() - last_msg_receipt_time)::float8,
                        received_tli::float8
                 FROM pg_stat_wal_receiver",
                &[],
            )
            .await
        {
            Ok(Some(row)) => {
                let status: Option<String> = row.try_get(0).ok().flatten();
                let main = &mut rows.main;
                main.flag("receiving", status.as_deref() == Some("streaming"));
                main.maybe(
                    "last_received_secs",
                    row.try_get::<_, Option<f64>>(1).ok().flatten(),
                );
                main.maybe("timeline", row.try_get::<_, Option<f64>>(2).ok().flatten());
            }
            Ok(None) => rows.main.flag("receiving", false),
            Err(error) => rows.missed("WAL receiver", pg_short(error)),
        }
    }

    async fn slots(&self, rows: &mut Rows) {
        let position = "CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()
                             ELSE pg_current_wal_lsn() END";
        let (status, headroom, lost) = match self.version {
            170_000.. => (
                "wal_status",
                "safe_wal_size::float8",
                "invalidation_reason IS NOT NULL OR wal_status = 'lost'",
            ),
            130_000.. => ("wal_status", "safe_wal_size::float8", "wal_status = 'lost'"),
            _ => ("NULL::text", "NULL::float8", "false"),
        };
        let query = format!(
            "SELECT slot_name::text, active, {status}, {headroom},
                    pg_wal_lsn_diff({position}, restart_lsn)::float8, {lost}
             FROM pg_replication_slots WHERE NOT temporary"
        );
        let slots = match self.client.query(&query, &[]).await {
            Ok(slots) => slots,
            Err(error) => return rows.missed("replication slots", pg_short(error)),
        };
        for slot in &slots {
            let name: String = slot.try_get(0).unwrap_or_default();
            let row = rows.add("slot", &name);
            row.maybe("in_use", slot.try_get::<_, bool>(1).ok().map(u8::from));
            row.maybe(
                "wal_status",
                slot.try_get::<_, Option<String>>(2).ok().flatten(),
            );
            // Unlimited unless max_slot_wal_keep_size is set.
            row.maybe(
                "headroom_bytes",
                slot.try_get::<_, Option<f64>>(3).ok().flatten(),
            );
            row.maybe(
                "retained_bytes",
                slot.try_get::<_, Option<f64>>(4).ok().flatten(),
            );
            row.maybe(
                "lost",
                slot.try_get::<_, Option<bool>>(5)
                    .ok()
                    .flatten()
                    .map(u8::from),
            );
        }
    }

    /// Only when archiving is on, as otherwise there's nothing to say.
    async fn archiving(&self, rows: &mut Rows) {
        let on = self
            .client
            .query_one(
                "SELECT current_setting('archive_mode') IN ('on', 'always')",
                &[],
            )
            .await;
        if !on.is_ok_and(|row| row.try_get::<_, bool>(0).unwrap_or(false)) {
            return;
        }
        match self
            .client
            .query_one(
                "SELECT archived_count::float8, failed_count::float8,
                        coalesce(last_failed_time > coalesce(last_archived_time, '-infinity'),
                                 false)
                 FROM pg_stat_archiver",
                &[],
            )
            .await
        {
            Ok(row) => {
                let main = &mut rows.main;
                main.total("archived", row.try_get(0).ok());
                main.total("archive_failures", row.try_get(1).ok());
                main.maybe(
                    "archive_failing",
                    row.try_get::<_, bool>(2).ok().map(u8::from),
                );
            }
            Err(error) => return rows.missed("archiving", pg_short(error)),
        }
        if self.version >= 120_000 {
            match self
                .client
                .query_one(
                    "SELECT count(*)::float8 FROM pg_ls_archive_statusdir()
                     WHERE name LIKE '%.ready'",
                    &[],
                )
                .await
            {
                Ok(row) => rows
                    .main
                    .maybe("archive_waiting", row.try_get::<_, f64>(0).ok()),
                Err(error) => rows.missed("files waiting to be archived", pg_short(error)),
            }
        }
    }

    /// Logical replication into the database signed in to.
    async fn subscriptions(&self, rows: &mut Rows) {
        if self.version < 100_000 {
            return;
        }
        let errors = if self.version >= 150_000 {
            "(SELECT (apply_error_count + sync_error_count)::float8
              FROM pg_stat_subscription_stats t WHERE t.subid = s.oid)"
        } else {
            "NULL::float8"
        };
        let query = format!(
            "SELECT s.subname::text,
                    EXISTS (SELECT 1 FROM pg_stat_subscription w
                            WHERE w.subid = s.oid AND w.pid IS NOT NULL AND w.relid IS NULL),
                    {errors}
             FROM pg_subscription s
             WHERE s.subenabled
               AND s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())"
        );
        let subscriptions = match self.client.query(&query, &[]).await {
            Ok(subscriptions) => subscriptions,
            Err(error) => return rows.missed("subscriptions", pg_short(error)),
        };
        for subscription in &subscriptions {
            let name: String = subscription.try_get(0).unwrap_or_default();
            let row = rows.add("subscription", &name);
            row.maybe(
                "running",
                subscription.try_get::<_, bool>(1).ok().map(u8::from),
            );
            row.total(
                "errors",
                subscription.try_get::<_, Option<f64>>(2).ok().flatten(),
            );
        }
    }

    /// Opt-in: each database's size, and the WAL kept on disk.
    async fn sizes(&self, rows: &mut Rows) {
        match self
            .client
            .query(
                "SELECT datname::text, pg_database_size(oid)::float8 FROM pg_database
                 WHERE datallowconn AND has_database_privilege(oid, 'CONNECT')",
                &[],
            )
            .await
        {
            Ok(databases) => {
                for database in &databases {
                    let name: String = database.try_get(0).unwrap_or_default();
                    let size = database.try_get::<_, f64>(1).ok();
                    rows.add("database", &name).maybe("size_bytes", size);
                }
            }
            Err(error) => rows.missed("database sizes", pg_short(error)),
        }
        match self
            .client
            .query_one(
                "SELECT coalesce(sum(size), 0)::float8 FROM pg_ls_waldir()",
                &[],
            )
            .await
        {
            Ok(row) => rows
                .main
                .maybe("wal_size_bytes", row.try_get::<_, f64>(0).ok()),
            Err(error) => rows.missed("WAL size", pg_short(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use maxnines_protocol::CheckKind;
    use serde_json::Value;

    use super::super::{Database, Reader, Settle};
    use crate::Credentials;

    /// A real server, as `host:port username`, such as the throwaway one tests
    /// use, signed in to with a role in pg_monitor or a superuser.
    fn real() -> Option<Database> {
        let value = std::env::var("MAXNINES_TEST_CHECK_POSTGRES").ok()?;
        let mut words = value.split_whitespace();
        let (target, username) = (words.next()?, words.next()?);
        Some(Database {
            check: maxnines_protocol::Check::new("real", CheckKind::Postgres, target),
            credentials: Credentials {
                username: Some(username.to_string()),
                password: words.next().map(String::from),
                private_key: None,
            },
        })
    }

    fn row<'a>(rows: &'a [Value], name: &str) -> &'a Value {
        rows.iter()
            .find(|row| row["name"] == name)
            .unwrap_or_else(|| panic!("no row {name}: {rows:?}"))
    }

    #[tokio::test]
    async fn a_real_server_is_read() {
        let Some(database) = real() else {
            return;
        };
        let extras = vec!["sizes".to_string()];
        let mut reader = Reader::new("main", database, &extras);
        let mut settle = Settle::default();
        let first = settle.settle(reader.read(Duration::from_secs(10)).await);
        let main = row(&first, "main");
        assert_eq!(main["up"], 1, "{first:?}");
        assert_eq!(main["role"], "primary");
        assert!(main["version"].is_string());
        for field in ["connections", "connections_used", "xid_age", "uptime_secs"] {
            assert!(main[field].is_number(), "{field}: {main}");
        }
        assert!(main.get("missing").is_none(), "{main}");
        assert!(main.get("totals").is_none(), "{main}");
        row(&first, "main database postgres");

        // The second round has changes, kept on the same connection.
        let second = settle.settle(reader.read(Duration::from_secs(10)).await);
        let main = row(&second, "main");
        assert!(main["transactions"].as_f64().unwrap() >= 0.0, "{main}");
        assert!(main.get("_blocks_wanted").is_none(), "{main}");
    }
}
