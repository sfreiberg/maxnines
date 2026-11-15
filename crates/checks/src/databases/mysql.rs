//! MySQL's and MariaDB's health, load and replication. Most of it comes from
//! one `SHOW GLOBAL STATUS`, which any account can run. Transactions and queries
//! need `PROCESS`, and replication `REPLICATION CLIENT`, or `REPLICA MONITOR` on
//! MariaDB 10.5.9 and later.
//!
//! The two have drifted apart: MySQL 8.0.22 renamed `SLAVE` to `REPLICA` and
//! `Master` to `Source` in replication's statements and fields, 8.4 dropped the
//! old names, and MariaDB kept most of them. Fields are found under either name.

use std::collections::HashMap;

use anyhow::{Context, Result};
use maxnines_protocol::Check;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Row, Value};

use super::Rows;
use crate::Credentials;
use crate::sign_in::{mysql_connection, short};

/// Errors that mean a feature isn't there, rather than that the account can't
/// see it: no such table, unknown table, and binary logging off.
const ABSENT: [u16; 3] = [1146, 1109, 1381];

pub(super) struct Mysql {
    connection: Conn,
    mariadb: bool,
    /// As a number, such as 80_036 for 8.0.36.
    version: u32,
}

/// A number from a status or variable value, which are all text.
fn number(text: Option<&String>) -> Option<f64> {
    text?.trim().parse().ok()
}

fn is_on(text: Option<&String>) -> bool {
    text.is_some_and(|text| matches!(text.to_ascii_uppercase().as_str(), "ON" | "YES" | "1"))
}

/// A value of any type as text, as replication status mixes them.
fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::NULL => None,
        Value::Bytes(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Value::Int(number) => Some(number.to_string()),
        Value::UInt(number) => Some(number.to_string()),
        Value::Float(number) => Some(number.to_string()),
        Value::Double(number) => Some(number.to_string()),
        other => Some(other.as_sql(true)),
    }
}

/// A row's fields by name.
fn fields(row: &Row) -> HashMap<String, String> {
    row.columns_ref()
        .iter()
        .enumerate()
        .filter_map(|(index, column)| {
            let value = as_text(row.as_ref(index)?)?;
            Some((column.name_str().into_owned(), value))
        })
        .collect()
}

/// The first of these names a row has, as fields were renamed between versions.
fn either<'a>(fields: &'a HashMap<String, String>, names: &[&str]) -> Option<&'a String> {
    names.iter().find_map(|name| fields.get(*name))
}

/// The server's own words for what went wrong, without the driver's wrapping.
fn my_short(error: mysql_async::Error) -> anyhow::Error {
    match error {
        mysql_async::Error::Server(server) => short(server.message),
        other => short(other),
    }
}

/// The server's own error code, if it gave one.
fn code(error: &mysql_async::Error) -> Option<u16> {
    match error {
        mysql_async::Error::Server(server) => Some(server.code),
        _ => None,
    }
}

impl Mysql {
    pub(super) async fn connect(check: &Check, credentials: &Credentials) -> Result<Self> {
        let mut connection = mysql_connection(check, credentials).await?;
        let version: Option<String> = connection
            .query_first("SELECT VERSION()")
            .await
            .map_err(my_short)?;
        let version = version.unwrap_or_default();
        let mariadb = version.to_ascii_lowercase().contains("mariadb");
        let mut parts = version
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|part| part.parse::<u32>().ok());
        let (major, minor, patch) = (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        );
        // A read that goes wrong never holds anything up for long, and never
        // writes.
        let limit = if mariadb {
            "SET SESSION max_statement_time = 5"
        } else {
            "SET SESSION max_execution_time = 5000"
        };
        for setting in [limit, "SET SESSION TRANSACTION READ ONLY"] {
            connection.query_drop(setting).await.map_err(my_short)?;
        }
        Ok(Self {
            connection,
            mariadb,
            version: major * 10_000 + minor * 100 + patch,
        })
    }

    /// Notes what couldn't be read, unless it's simply not there, such as
    /// replication tables on a server that doesn't use them.
    fn missed(rows: &mut Rows, what: &str, error: &mysql_async::Error) {
        if !code(error).is_some_and(|code| ABSENT.contains(&code)) {
            let message = match error {
                mysql_async::Error::Server(server) => server.message.clone(),
                other => other.to_string(),
            };
            rows.missed(what, message);
        }
    }

    async fn pairs(&mut self, query: &str) -> Result<HashMap<String, String>, mysql_async::Error> {
        let pairs: Vec<(String, Option<String>)> = self.connection.query(query).await?;
        Ok(pairs
            .into_iter()
            .filter_map(|(name, value)| Some((name.to_ascii_lowercase(), value?)))
            .collect())
    }

    async fn rows(
        &mut self,
        query: &str,
    ) -> Result<Vec<HashMap<String, String>>, mysql_async::Error> {
        let rows: Vec<Row> = self.connection.query(query).await?;
        Ok(rows.iter().map(fields).collect())
    }

    pub(super) async fn read(&mut self, rows: &mut Rows, extras: &[String]) -> Result<()> {
        let status = self
            .pairs("SHOW GLOBAL STATUS")
            .await
            .map_err(my_short)
            .context("reading the server's status")?;
        let variables = self
            .pairs(
                "SHOW GLOBAL VARIABLES WHERE Variable_name IN \
                 ('version', 'max_connections', 'read_only', 'super_read_only')",
            )
            .await
            .map_err(my_short)
            .context("reading the server's settings")?;
        self.server(rows, &status, &variables);
        self.innodb(rows, &status).await;
        self.activity(rows).await;
        self.replication(rows).await;
        self.semi_sync(rows, &status);
        if !self.mariadb {
            self.group(rows).await;
        }
        self.galera(rows, &status);
        if extras.iter().any(|extra| extra == "sizes") {
            self.sizes(rows).await;
        }
        Ok(())
    }

    fn server(
        &self,
        rows: &mut Rows,
        status: &HashMap<String, String>,
        variables: &HashMap<String, String>,
    ) {
        let get = |name: &str| number(status.get(name));
        let main = &mut rows.main;
        main.maybe("version", variables.get("version").cloned());
        main.maybe("uptime_secs", get("uptime"));
        let connected = get("threads_connected");
        main.maybe("connections", connected);
        let max = number(variables.get("max_connections"));
        if let (Some(connected), Some(max)) = (connected, max)
            && max > 0.0
        {
            main.set("connections_used", connected / max * 100.0);
        }
        main.maybe("threads_running", get("threads_running"));
        main.total("queries", get("questions"));
        main.total("slow_queries", get("slow_queries"));
        main.total("refused", get("connection_errors_max_connections"));
        main.total("aborted_connects", get("aborted_connects"));
        main.total("tmp_disk_tables", get("created_tmp_disk_tables"));
        main.total("commits", get("com_commit"));
        main.total("rollbacks", get("com_rollback"));
        main.flag("read_only", is_on(variables.get("read_only")));
        // MariaDB has no such setting.
        if let Some(super_read_only) = variables.get("super_read_only") {
            main.flag("super_read_only", is_on(Some(super_read_only)));
        }
    }

    async fn innodb(&mut self, rows: &mut Rows, status: &HashMap<String, String>) {
        let get = |name: &str| number(status.get(name));
        let main = &mut rows.main;
        let (requests, reads) = (
            get("innodb_buffer_pool_read_requests"),
            get("innodb_buffer_pool_reads"),
        );
        main.total("pool_requests", requests);
        if let (Some(requests), Some(reads)) = (requests, reads) {
            main.total("pool_hits", Some((requests - reads).max(0.0)));
        }
        main.average("cache_hit", "pool_hits", "pool_requests", 100.0);
        if let (Some(dirty), Some(total)) = (
            get("innodb_buffer_pool_pages_dirty"),
            get("innodb_buffer_pool_pages_total"),
        ) && total > 0.0
        {
            main.set("pool_dirty", dirty / total * 100.0);
        }
        main.total("pool_waits", get("innodb_buffer_pool_wait_free"));
        main.maybe("lock_waits", get("innodb_row_lock_current_waits"));

        // MariaDB counts these in its status. MySQL keeps them among InnoDB's
        // own metrics, which take PROCESS.
        let (deadlocks, history) = (get("innodb_deadlocks"), get("innodb_history_list_length"));
        if deadlocks.is_some() && history.is_some() {
            main.total("deadlocks", deadlocks);
            main.maybe("history_length", history);
            return;
        }
        match self
            .pairs(
                "SELECT NAME, COUNT FROM information_schema.INNODB_METRICS \
                 WHERE NAME IN ('lock_deadlocks', 'trx_rseg_history_len')",
            )
            .await
        {
            Ok(metrics) => {
                let main = &mut rows.main;
                main.total("deadlocks", number(metrics.get("lock_deadlocks")));
                main.maybe(
                    "history_length",
                    number(metrics.get("trx_rseg_history_len")),
                );
            }
            Err(error) => Self::missed(rows, "InnoDB metrics", &error),
        }
    }

    /// The oldest transaction and query, which need PROCESS to see others'.
    async fn activity(&mut self, rows: &mut Rows) {
        let found: Result<Option<(f64, f64)>, _> = self
            .connection
            .query_first(
                "SELECT COUNT(*), COALESCE(MAX(TIMESTAMPDIFF(SECOND, trx_started, NOW())), 0) \
                 FROM information_schema.innodb_trx",
            )
            .await;
        match found {
            Ok(Some((open, oldest))) => {
                rows.main.set("open_transactions", open);
                rows.main.set("oldest_transaction_secs", oldest);
            }
            Ok(None) => {}
            Err(error) => Self::missed(rows, "transactions", &error),
        }
        // performance_schema's list doesn't take a global lock, from 8.0.22.
        let list = if !self.mariadb && self.version >= 80_022 {
            "performance_schema.processlist"
        } else {
            "information_schema.PROCESSLIST"
        };
        let query = format!(
            "SELECT COALESCE(MAX(TIME), 0) FROM {list} \
             WHERE COMMAND = 'Query' AND ID <> CONNECTION_ID() AND USER <> 'system user'"
        );
        match self.connection.query_first::<f64, _>(query).await {
            Ok(oldest) => rows.main.maybe("oldest_query_secs", oldest),
            Err(error) => Self::missed(rows, "queries", &error),
        }
    }

    /// As a replica, each channel it replicates from. The unnamed one, which is
    /// all most have, goes on the server's own row.
    async fn replication(&mut self, rows: &mut Rows) {
        let statement = if self.mariadb {
            if self.version >= 100_501 {
                "SHOW ALL REPLICAS STATUS"
            } else {
                "SHOW ALL SLAVES STATUS"
            }
        } else if self.version >= 80_022 {
            "SHOW REPLICA STATUS"
        } else {
            "SHOW SLAVE STATUS"
        };
        let channels = match self.rows(statement).await {
            Ok(channels) => channels,
            Err(error) => return Self::missed(rows, "replication", &error),
        };
        rows.main.flag("replica", !channels.is_empty());
        for channel in &channels {
            let name = either(channel, &["Channel_Name", "Connection_name"])
                .cloned()
                .unwrap_or_default();
            let row = if name.is_empty() {
                &mut rows.main
            } else {
                rows.add("channel", &name)
            };
            let receiving = either(channel, &["Replica_IO_Running", "Slave_IO_Running"]);
            row.maybe("receiver", receiving.cloned());
            row.flag(
                "receiving",
                receiving.is_some_and(|state| state.eq_ignore_ascii_case("yes")),
            );
            row.flag(
                "applying",
                is_on(either(
                    channel,
                    &["Replica_SQL_Running", "Slave_SQL_Running"],
                )),
            );
            // NULL while it's stopped, which isn't a number of seconds behind.
            // A delayed replica is behind on purpose, by its delay.
            let behind = number(either(
                channel,
                &["Seconds_Behind_Source", "Seconds_Behind_Master"],
            ));
            let delay = number(channel.get("SQL_Delay")).unwrap_or(0.0);
            row.maybe("lag_secs", behind.map(|behind| (behind - delay).max(0.0)));
            row.maybe("relay_log_bytes", number(channel.get("Relay_Log_Space")));
            let errors = [
                ("Last_IO_Errno", "Last_IO_Error"),
                ("Last_SQL_Errno", "Last_SQL_Error"),
            ];
            let failing = errors
                .iter()
                .find(|(errno, _)| number(channel.get(*errno)).is_some_and(|errno| errno != 0.0));
            match failing {
                Some((errno, error)) => {
                    row.maybe("replication_errno", number(channel.get(*errno)));
                    row.maybe(
                        "replication_error",
                        channel.get(*error).map(|error| short(error).to_string()),
                    );
                }
                None => row.set("replication_errno", 0),
            }
        }
    }

    /// Semi-synchronous replication, under the names the plugin in use gives.
    fn semi_sync(&self, rows: &mut Rows, status: &HashMap<String, String>) {
        for side in ["source", "master"] {
            let get = |name: &str| status.get(&format!("rpl_semi_sync_{side}_{name}"));
            let Some(on) = get("status") else {
                continue;
            };
            let main = &mut rows.main;
            main.flag("semi_sync", is_on(Some(on)));
            main.maybe("semi_sync_clients", number(get("clients")));
            main.total("semi_sync_misses", number(get("no_tx")));
            return;
        }
    }

    /// Group Replication, as in an InnoDB Cluster: every member as this one sees
    /// them, and this one's queues.
    async fn group(&mut self, rows: &mut Rows) {
        let members = match self
            .rows(
                "SELECT MEMBER_HOST, MEMBER_PORT, MEMBER_STATE, MEMBER_ROLE, \
                 MEMBER_ID = @@server_uuid AS ITSELF \
                 FROM performance_schema.replication_group_members",
            )
            .await
        {
            Ok(members) => members,
            Err(error) => return Self::missed(rows, "Group Replication", &error),
        };
        // A table with one OFFLINE row means the plugin is there but unused.
        let used = members.iter().any(|member| {
            member
                .get("MEMBER_STATE")
                .is_some_and(|state| state != "OFFLINE")
        });
        if !used {
            return;
        }
        let online = members
            .iter()
            .filter(|member| member.get("MEMBER_STATE").map(String::as_str) == Some("ONLINE"))
            .count();
        rows.main.set("group_members", members.len());
        rows.main.set("group_online", online);
        for member in &members {
            let state = member.get("MEMBER_STATE").cloned();
            if is_on(member.get("ITSELF")) {
                rows.main.maybe("group_state", state.clone());
                rows.main
                    .maybe("group_role", member.get("MEMBER_ROLE").cloned());
            }
            let name = format!(
                "{}:{}",
                member.get("MEMBER_HOST").map_or("", String::as_str),
                member.get("MEMBER_PORT").map_or("", String::as_str)
            );
            let row = rows.add("member", &name);
            row.flag("member_online", state.as_deref() == Some("ONLINE"));
            row.maybe("member_state", state);
            row.maybe("member_role", member.get("MEMBER_ROLE").cloned());
        }
        match self
            .rows(
                "SELECT COUNT_TRANSACTIONS_REMOTE_IN_APPLIER_QUEUE AS APPLIER, \
                 COUNT_TRANSACTIONS_IN_QUEUE AS CERTIFIER, \
                 COUNT_CONFLICTS_DETECTED AS CONFLICTS \
                 FROM performance_schema.replication_group_member_stats \
                 WHERE MEMBER_ID = @@server_uuid",
            )
            .await
        {
            Ok(found) => {
                if let Some(own) = found.first() {
                    let main = &mut rows.main;
                    main.maybe("applier_queue", number(own.get("APPLIER")));
                    main.maybe("certifier_queue", number(own.get("CERTIFIER")));
                    main.total("group_conflicts", number(own.get("CONFLICTS")));
                }
            }
            Err(error) => Self::missed(rows, "Group Replication queues", &error),
        }
    }

    /// Galera, as in MariaDB Galera Cluster and Percona XtraDB Cluster.
    fn galera(&self, rows: &mut Rows, status: &HashMap<String, String>) {
        let get = |name: &str| status.get(&format!("wsrep_{name}"));
        let Some(cluster) = get("cluster_status") else {
            return;
        };
        let main = &mut rows.main;
        main.flag("galera_primary", cluster.eq_ignore_ascii_case("primary"));
        main.maybe("galera_size", number(get("cluster_size")));
        main.flag("galera_ready", is_on(get("ready")));
        main.flag("galera_connected", is_on(get("connected")));
        main.maybe("galera_state", get("local_state_comment").cloned());
        // 4 is Synced.
        main.flag("galera_synced", number(get("local_state")) == Some(4.0));
        main.maybe("galera_receive_queue", number(get("local_recv_queue_avg")));
        main.maybe("galera_send_queue", number(get("local_send_queue_avg")));
        main.total("galera_cert_failures", number(get("local_cert_failures")));
        // Nanoseconds paused, in hundredths of a second, so its rate is the
        // percentage of the time replication was paused for flow control.
        main.total(
            "galera_flow_paused",
            number(get("flow_control_paused_ns")).map(|paused| paused / 1e7),
        );
    }

    /// Opt-in: each schema's size, and the binary logs kept.
    async fn sizes(&mut self, rows: &mut Rows) {
        match self
            .pairs(
                "SELECT table_schema, CAST(SUM(data_length + index_length) AS CHAR) \
                 FROM information_schema.tables \
                 WHERE table_schema NOT IN \
                 ('information_schema', 'performance_schema', 'sys', 'mysql') \
                 GROUP BY table_schema",
            )
            .await
        {
            Ok(schemas) => {
                let mut schemas: Vec<_> = schemas.into_iter().collect();
                schemas.sort();
                for (name, size) in schemas {
                    rows.add("database", &name)
                        .maybe("size_bytes", number(Some(&size)));
                }
            }
            Err(error) => Self::missed(rows, "database sizes", &error),
        }
        match self.rows("SHOW BINARY LOGS").await {
            Ok(logs) => {
                let size: f64 = logs
                    .iter()
                    .filter_map(|log| number(log.get("File_size")))
                    .sum();
                rows.main.set("binlog_size_bytes", size);
            }
            Err(error) => Self::missed(rows, "binary logs", &error),
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

    /// A real server, as `host:port username [password]`.
    fn real() -> Option<Database> {
        let value = std::env::var("MAXNINES_TEST_CHECK_MYSQL").ok()?;
        let mut words = value.split_whitespace();
        let (target, username) = (words.next()?, words.next()?);
        Some(Database {
            check: maxnines_protocol::Check::new("real", CheckKind::Mysql, target),
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
        assert!(main["version"].is_string());
        for field in [
            "connections",
            "connections_used",
            "uptime_secs",
            "oldest_query_secs",
        ] {
            assert!(main[field].is_number(), "{field}: {main}");
        }
        assert_eq!(main["replica"], 0);
        assert!(main.get("missing").is_none(), "{main}");

        let second = settle.settle(reader.read(Duration::from_secs(10)).await);
        let main = row(&second, "main");
        assert!(main["queries"].as_f64().unwrap() >= 1.0, "{main}");
        assert!(main["binlog_size_bytes"].is_number(), "{main}");
    }
}
