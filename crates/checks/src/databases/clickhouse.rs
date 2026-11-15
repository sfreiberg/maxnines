//! ClickHouse's health, load and replication, read over its HTTP interface,
//! which the checks' own HTTP client already speaks, so no driver is added.
//! Every query is a GET, which ClickHouse only lets read, against its `system`
//! tables, which an account with `SELECT ON system.*` can read.
//!
//! A password goes in basic authentication, so it's only sent over plain HTTP
//! to the host itself, and anywhere else over HTTPS.

use std::net::IpAddr;

use anyhow::{Result, anyhow, bail, ensure};
use maxnines_protocol::{Check, CheckKind};
use serde_json::{Map, Value};

use super::Rows;
use crate::{Credentials, Findings, Login, decompress, host_and_port, request};

/// ClickHouse's codes for a table or database that isn't there, as in an older
/// version, which isn't worth a note.
const ABSENT: [u32; 2] = [60, 81];

/// What a query got back, or ClickHouse's own reason it didn't.
struct Failure {
    code: Option<u32>,
    message: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) struct Clickhouse {
    /// Such as `https://db.example.com:8443`.
    base: String,
    insecure: Option<bool>,
    timeout_secs: Option<u64>,
    login: Option<Login>,
}

/// A query's text, made safe to go in an address.
fn encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// A number, as ClickHouse writes 64 bit ones in quotes.
fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

impl Clickhouse {
    pub(crate) fn new(check: &Check, credentials: &Credentials) -> Result<Self> {
        let (host, port) = host_and_port(&check.target)?;
        let tls = check.tls == Some(true);
        let password = credentials.password.as_deref().filter(|p| !p.is_empty());
        ensure!(
            password.is_none() || tls || is_loopback(&host),
            "a password is only sent over plain HTTP to the host itself, so set tls for \
             one elsewhere"
        );
        let login = match (credentials.username.as_deref(), password) {
            (Some(username), password) => Some(Login::new(username, password.unwrap_or(""))?),
            (None, Some(password)) => Some(Login::new("default", password)?),
            (None, None) => None,
        };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Ok(Self {
            base: format!("{}://{host}:{port}", if tls { "https" } else { "http" }),
            insecure: check.insecure,
            timeout_secs: check.timeout_secs,
            login,
        })
    }

    async fn get(&self, path: &str) -> Result<(u16, String), Failure> {
        let mut check = Check::new(
            "clickhouse",
            CheckKind::Http,
            &format!("{}{path}", self.base),
        );
        check.insecure = self.insecure;
        check.timeout_secs = self.timeout_secs;
        let answer = request(&check, &mut Findings::default(), self.login.as_ref())
            .await
            .map_err(|error| Failure {
                code: None,
                message: format!("{error:#}"),
            })?;
        let body = if answer.compressed {
            decompress(&answer.body).ok_or(Failure {
                code: None,
                message: "its answer couldn't be unpacked".to_string(),
            })?
        } else {
            answer.body
        };
        Ok((answer.status, String::from_utf8_lossy(&body).into_owned()))
    }

    /// Whether it answers, without signing in.
    pub(crate) async fn ping(&self) -> Result<()> {
        let (status, body) = self
            .get("/ping")
            .await
            .map_err(|error| anyhow!("{error}"))?;
        ensure!(
            status == 200 && body.trim() == "Ok.",
            "it didn't answer as ClickHouse does"
        );
        Ok(())
    }

    /// A query's rows, each by column name.
    async fn query(&self, sql: &str) -> Result<Vec<Map<String, Value>>, Failure> {
        let path = format!(
            "/?query={}&max_execution_time=5",
            encoded(&format!("{sql} FORMAT JSON"))
        );
        let (status, body) = self.get(&path).await?;
        if status != 200 {
            // Such as "Code: 497. DB::Exception: maxnines: Not enough privileges…".
            let first = body.lines().next().unwrap_or_default();
            let code = first
                .strip_prefix("Code: ")
                .and_then(|rest| rest.split('.').next())
                .and_then(|code| code.parse().ok());
            let message = first
                .split_once("DB::Exception: ")
                .map_or(first, |(_, message)| message);
            let message = message.split(". (").next().unwrap_or(message);
            let message = if message.is_empty() {
                format!("it returned status {status}")
            } else {
                message.chars().take(200).collect()
            };
            return Err(Failure { code, message });
        }
        let answer: Value = serde_json::from_str(&body).map_err(|_| Failure {
            code: None,
            message: "it didn't answer as ClickHouse does".to_string(),
        })?;
        Ok(answer["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row.as_object().cloned())
            .collect())
    }

    /// The one row a query gives.
    async fn one(&self, sql: &str) -> Result<Map<String, Value>, Failure> {
        self.query(sql).await?.into_iter().next().ok_or(Failure {
            code: None,
            message: "it gave nothing back".to_string(),
        })
    }

    /// The version, which also says it can be signed in to and queried.
    pub(crate) async fn version(&self) -> Result<String> {
        let row = self
            .one("SELECT version() AS version")
            .await
            .map_err(|error| anyhow!("{error}"))?;
        match row.get("version") {
            Some(Value::String(version)) => Ok(version.clone()),
            _ => bail!("it didn't say its version"),
        }
    }

    fn missed(rows: &mut Rows, what: &str, failure: &Failure) {
        if !failure.code.is_some_and(|code| ABSENT.contains(&code)) {
            rows.missed(what, failure);
        }
    }

    pub(super) async fn read(&self, rows: &mut Rows, extras: &[String]) -> Result<()> {
        let server = self
            .one("SELECT version() AS version, uptime() AS uptime")
            .await
            .map_err(|error| anyhow!("reading the server's state: {error}"))?;
        rows.main
            .maybe("version", server.get("version").and_then(Value::as_str));
        rows.main.maybe("uptime_secs", number(server.get("uptime")));

        self.current(rows).await;
        self.events(rows).await;
        self.asynchronous(rows).await;
        self.replicas(rows).await;
        self.mutations(rows).await;
        self.disks(rows).await;
        if extras.iter().any(|extra| extra == "sizes") {
            self.sizes(rows).await;
        }
        Ok(())
    }

    /// What's going on now: queries, connections, merges and inserts held back.
    async fn current(&self, rows: &mut Rows) {
        let found = self
            .query(
                "SELECT metric, value FROM system.metrics WHERE metric IN \
                 ('Query', 'TCPConnection', 'HTTPConnection', 'MySQLConnection', \
                 'PostgreSQLConnection', 'InterserverConnection', 'Merge', \
                 'DelayedInserts', 'ReadonlyReplica')",
            )
            .await;
        let metrics = match found {
            Ok(metrics) => metrics,
            Err(failure) => return Self::missed(rows, "current metrics", &failure),
        };
        let get = |name: &str| {
            metrics
                .iter()
                .find(|row| row.get("metric").and_then(Value::as_str) == Some(name))
                .and_then(|row| number(row.get("value")))
        };
        let main = &mut rows.main;
        let connections: f64 = [
            "TCPConnection",
            "HTTPConnection",
            "MySQLConnection",
            "PostgreSQLConnection",
        ]
        .iter()
        .filter_map(|name| get(name))
        .sum();
        main.set("connections", connections);
        main.maybe("running_queries", get("Query"));
        main.maybe("merges_running", get("Merge"));
        main.maybe("delayed_inserts", get("DelayedInserts"));
        main.maybe("readonly_replicas", get("ReadonlyReplica"));
    }

    /// Running totals since it started.
    async fn events(&self, rows: &mut Rows) {
        let found = self
            .query(
                "SELECT event, value FROM system.events WHERE event IN \
                 ('Query', 'SelectQuery', 'InsertQuery', 'FailedQuery', 'InsertedRows', \
                 'InsertedBytes', 'RejectedInserts', 'DelayedInserts')",
            )
            .await;
        let events = match found {
            Ok(events) => events,
            Err(failure) => return Self::missed(rows, "events", &failure),
        };
        let get = |name: &str| {
            events
                .iter()
                .find(|row| row.get("event").and_then(Value::as_str) == Some(name))
                .and_then(|row| number(row.get("value")))
                // An event that's never happened isn't listed.
                .or(Some(0.0))
        };
        let main = &mut rows.main;
        main.total("queries", get("Query"));
        main.total("selects", get("SelectQuery"));
        main.total("inserts", get("InsertQuery"));
        main.total("failed_queries", get("FailedQuery"));
        main.total("inserted_rows", get("InsertedRows"));
        main.total("inserted_bytes", get("InsertedBytes"));
        main.total("rejected_inserts", get("RejectedInserts"));
        main.total("inserts_delayed", get("DelayedInserts"));
    }

    /// What ClickHouse works out in the background, such as the most parts in one
    /// partition, which refuses inserts at `parts_to_throw_insert`, 300 by default.
    async fn asynchronous(&self, rows: &mut Rows) {
        let found = self
            .query(
                "SELECT metric, value FROM system.asynchronous_metrics WHERE metric IN \
                 ('MaxPartCountForPartition', 'ReplicasMaxAbsoluteDelay', 'MemoryResident')",
            )
            .await;
        let metrics = match found {
            Ok(metrics) => metrics,
            Err(failure) => return Self::missed(rows, "background metrics", &failure),
        };
        let get = |name: &str| {
            metrics
                .iter()
                .find(|row| row.get("metric").and_then(Value::as_str) == Some(name))
                .and_then(|row| number(row.get("value")))
        };
        let main = &mut rows.main;
        main.maybe("max_parts_per_partition", get("MaxPartCountForPartition"));
        main.maybe("memory_bytes", get("MemoryResident"));
        // The furthest behind of its replicated tables.
        if let Some(delay) = get("ReplicasMaxAbsoluteDelay") {
            main.set("lag_secs", delay);
        }
    }

    /// Replicated tables: how many can't take writes, have lost their session
    /// with Keeper, or are missing replicas, and the work queued for them.
    async fn replicas(&self, rows: &mut Rows) {
        let found = self
            .one(
                "SELECT count() AS tables, countIf(is_readonly) AS readonly, \
                 countIf(is_session_expired) AS expired, sum(queue_size) AS queue, \
                 sum(inserts_in_queue) AS inserts, \
                 countIf(active_replicas < total_replicas) AS missing \
                 FROM system.replicas",
            )
            .await;
        match found {
            Ok(replicas) => {
                let tables = number(replicas.get("tables")).unwrap_or(0.0);
                if tables == 0.0 {
                    return;
                }
                let main = &mut rows.main;
                main.set("replicated_tables", tables);
                main.maybe("readonly_tables", number(replicas.get("readonly")));
                main.maybe("expired_sessions", number(replicas.get("expired")));
                main.maybe("replication_queue", number(replicas.get("queue")));
                main.maybe("inserts_in_queue", number(replicas.get("inserts")));
                main.maybe("tables_missing_replicas", number(replicas.get("missing")));
            }
            Err(failure) => Self::missed(rows, "replicated tables", &failure),
        }
    }

    /// Mutations still to finish, and ones that keep failing.
    async fn mutations(&self, rows: &mut Rows) {
        match self
            .one(
                "SELECT count() AS pending, countIf(latest_fail_reason != '') AS failing \
                 FROM system.mutations WHERE NOT is_done",
            )
            .await
        {
            Ok(mutations) => {
                rows.main
                    .maybe("mutations_pending", number(mutations.get("pending")));
                rows.main
                    .maybe("mutations_failing", number(mutations.get("failing")));
            }
            Err(failure) => Self::missed(rows, "mutations", &failure),
        }
        match self
            .one("SELECT max(elapsed) AS oldest FROM system.processes WHERE is_initial_query")
            .await
        {
            Ok(processes) => {
                let oldest = number(processes.get("oldest")).unwrap_or(0.0);
                rows.main.set("oldest_query_secs", oldest);
            }
            Err(failure) => Self::missed(rows, "queries", &failure),
        }
    }

    async fn disks(&self, rows: &mut Rows) {
        let found = self
            .query("SELECT name, free_space, total_space FROM system.disks")
            .await;
        let disks = match found {
            Ok(disks) => disks,
            Err(failure) => return Self::missed(rows, "disks", &failure),
        };
        for disk in &disks {
            let Some(name) = disk.get("name").and_then(Value::as_str) else {
                continue;
            };
            let (free, total) = (
                number(disk.get("free_space")),
                number(disk.get("total_space")),
            );
            let row = rows.add("disk", name);
            row.maybe("disk_free_bytes", free);
            if let (Some(free), Some(total)) = (free, total)
                && total > 0.0
            {
                row.set("disk_used", (total - free) / total * 100.0);
            }
        }
    }

    /// Opt-in: each database's size on disk.
    async fn sizes(&self, rows: &mut Rows) {
        let found = self
            .query(
                "SELECT database, sum(bytes_on_disk) AS size FROM system.parts \
                 WHERE active GROUP BY database ORDER BY database",
            )
            .await;
        match found {
            Ok(databases) => {
                for database in &databases {
                    if let Some(name) = database.get("database").and_then(Value::as_str) {
                        let size = number(database.get("size"));
                        rows.add("database", name).maybe("size_bytes", size);
                    }
                }
            }
            Err(failure) => Self::missed(rows, "database sizes", &failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{Database, Reader, Settle};
    use super::*;

    #[test]
    fn queries_are_safe_in_an_address() {
        assert_eq!(
            encoded("SELECT 1 FORMAT JSON"),
            "SELECT%201%20FORMAT%20JSON"
        );
        assert_eq!(encoded("a='b'&c"), "a%3D%27b%27%26c");
    }

    #[test]
    fn a_password_only_goes_in_the_clear_to_the_host_itself() {
        let login = Credentials {
            username: Some("maxnines".to_string()),
            password: Some("s3cret".to_string()),
            private_key: None,
        };
        let check = |target: &str, tls: bool| {
            let mut check = Check::new("events", CheckKind::Clickhouse, target);
            check.tls = tls.then_some(true);
            check
        };
        assert!(Clickhouse::new(&check("127.0.0.1:8123", false), &login).is_ok());
        assert!(Clickhouse::new(&check("localhost:8123", false), &login).is_ok());
        assert!(Clickhouse::new(&check("db.example.com:8443", true), &login).is_ok());
        let error = Clickhouse::new(&check("db.example.com:8123", false), &login)
            .err()
            .unwrap();
        assert!(error.to_string().contains("set tls"), "{error}");
        // Nothing secret to send, so plain HTTP is fine anywhere.
        let username_only = Credentials {
            password: None,
            ..login
        };
        assert!(Clickhouse::new(&check("db.example.com:8123", false), &username_only).is_ok());
    }

    /// A real server, as `host:port [username [password]]`, on its HTTP port.
    fn real() -> Option<Database> {
        let value = std::env::var("MAXNINES_TEST_CHECK_CLICKHOUSE").ok()?;
        let mut words = value.split_whitespace();
        let target = words.next()?;
        Some(Database {
            check: Check::new("real", CheckKind::Clickhouse, target),
            credentials: Credentials {
                username: words.next().map(String::from),
                password: words.next().map(String::from),
                private_key: None,
            },
        })
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
        let main = &first[0];
        assert_eq!(main["up"], 1, "{first:?}");
        assert!(main["version"].is_string());
        for field in ["connections", "uptime_secs", "max_parts_per_partition"] {
            assert!(main[field].is_number(), "{field}: {main}");
        }
        assert!(main.get("missing").is_none(), "{main}");
        assert!(first.iter().any(|row| row["name"] == "main disk default"));
        let second = settle.settle(reader.read(Duration::from_secs(10)).await);
        assert!(second[0]["queries"].as_f64().unwrap() >= 1.0, "{second:?}");
    }
}
