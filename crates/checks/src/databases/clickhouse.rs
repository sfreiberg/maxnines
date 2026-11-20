//! ClickHouse's health, load and replication, read over its HTTP interface,
//! which the checks' own HTTP client already speaks, so no driver is added.
//! Every query is a GET, which ClickHouse only lets read, against its `system`
//! tables, which an account with `SELECT ON system.*` can read.
//!
//! A password goes in basic authentication, so it's only sent over plain HTTP
//! to the host itself, and anywhere else over HTTPS.
//!
//! A round's queries share one connection, which is closed when the round ends,
//! as ClickHouse closes connections left idle for as long as there is between
//! rounds.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail, ensure};
use maxnines_protocol::{Check, CheckKind};
use serde_json::{Map, Value};

use super::Rows;
use crate::{Credentials, Findings, Login, WebConnection, decompress, host_and_port, open_web};

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
    timeout: Option<Duration>,
    login: Option<Login>,
    /// What's read every few minutes, kept for the samples in between.
    slow: Option<Slow>,
    /// The memory it can have: its control group's, if it's in one, and the
    /// machine's.
    memory: (Option<f64>, Option<f64>),
    /// Whether errors have been read before, after which a code that turns up
    /// is new.
    errors_read: bool,
    /// The connection this round's queries go over, once one is open.
    connection: Option<WebConnection>,
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
            timeout: check.timeout,
            login,
            slow: None,
            memory: (None, None),
            errors_read: false,
            connection: None,
        })
    }

    async fn get(&mut self, path: &str) -> Result<(u16, String), Failure> {
        let mut check = Check::new(
            "clickhouse",
            CheckKind::Http,
            &format!("{}{path}", self.base),
        );
        check.insecure = self.insecure;
        check.timeout = self.timeout;
        let failed = |error: anyhow::Error| Failure {
            code: None,
            message: format!("{error:#}"),
        };
        let mut findings = Findings::default();
        let kept = match self.connection.take() {
            Some(mut open) => open.is_ready().await.then_some(open),
            None => None,
        };
        let mut connection = match kept {
            Some(open) => open,
            None => open_web(&check, &mut findings).await.map_err(failed)?,
        };
        let answer = connection
            .send(&check, &mut findings, self.login.as_ref())
            .await
            .map_err(failed)?;
        // Only one that worked is used again.
        self.connection = Some(connection);
        let body = if answer.compressed {
            decompress(&answer.body)
                .ok_or(Failure {
                    code: None,
                    message: "its answer couldn't be unpacked".to_string(),
                })?
                .0
        } else {
            answer.body
        };
        Ok((answer.status, String::from_utf8_lossy(&body).into_owned()))
    }

    /// Whether it answers, without signing in.
    pub(crate) async fn ping(&mut self) -> Result<()> {
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
    async fn query(&mut self, sql: &str) -> Result<Vec<Map<String, Value>>, Failure> {
        // No settings go with it: an account limited to reading, as it should be,
        // can't change them, and its own profile sets its limits.
        let path = format!("/?query={}", encoded(&format!("{sql} FORMAT JSON")));
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
    async fn one(&mut self, sql: &str) -> Result<Map<String, Value>, Failure> {
        self.query(sql).await?.into_iter().next().ok_or(Failure {
            code: None,
            message: "it gave nothing back".to_string(),
        })
    }

    /// The version, which also says it can be signed in to and queried.
    pub(crate) async fn version(&mut self) -> Result<String> {
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

    pub(super) async fn read(&mut self, rows: &mut Rows, extras: &[String]) -> Result<()> {
        let read = self.read_round(rows, extras).await;
        self.connection = None;
        read
    }

    async fn read_round(&mut self, rows: &mut Rows, extras: &[String]) -> Result<()> {
        let server = self
            .one("SELECT version() AS version, uptime() AS uptime")
            .await
            .map_err(|error| anyhow!("reading the server's state: {error}"))?;
        rows.main
            .maybe("version", server.get("version").and_then(Value::as_str));
        rows.main.maybe("uptime_secs", number(server.get("uptime")));

        // What costs more is read every few minutes, and repeated in between.
        if self
            .slow
            .as_ref()
            .is_none_or(|slow| slow.read.elapsed() >= SLOW_EVERY)
        {
            let mut slow = Rows::new(&rows.main.name);
            slow.main.fields.clear();
            let limits = self.slow_reads(&mut slow).await;
            self.slow = Some(Slow {
                read: Instant::now(),
                limits,
                rows: slow,
            });
        }

        self.current(rows).await;
        self.events(rows).await;
        self.asynchronous(rows).await;
        self.replicas(rows).await;
        self.keeper(rows).await;
        self.work(rows).await;
        self.errors(rows).await;
        self.disks(rows).await;
        if let Some(slow) = &self.slow {
            rows.main.fields.extend(slow.rows.main.fields.clone());
            rows.others.extend(slow.rows.others.iter().cloned());
            for note in &slow.rows.missing {
                rows.note(note.clone());
            }
            self.against_limits(rows, &slow.limits);
        }
        if extras.iter().any(|extra| extra == "sizes") {
            self.sizes(rows).await;
        }
        if extras.iter().any(|extra| extra == "queries") {
            self.latency(rows).await;
        }
        Ok(())
    }

    /// Named values from one of the tables that list them as rows, such as
    /// `system.metrics`, with an event that's never happened as 0.
    async fn named(
        &mut self,
        rows: &mut Rows,
        what: &str,
        sql: &str,
    ) -> Option<HashMap<String, f64>> {
        match self.query(sql).await {
            Ok(found) => Some(
                found
                    .iter()
                    .filter_map(|row| {
                        let name = row.get("name")?.as_str()?.to_string();
                        Some((name, number(row.get("value"))?))
                    })
                    .collect(),
            ),
            Err(failure) => {
                Self::missed(rows, what, &failure);
                None
            }
        }
    }

    /// What's going on now: queries, connections, memory, background pools,
    /// Distributed tables' backlog and the Keeper session.
    async fn current(&mut self, rows: &mut Rows) {
        let sql = format!(
            "SELECT metric AS name, value FROM system.metrics WHERE metric IN ({}) \
             OR metric LIKE 'Background%Pool%'",
            quoted(&CURRENT)
        );
        let Some(metrics) = self.named(rows, "current metrics", &sql).await else {
            return;
        };
        let get = |name: &str| metrics.get(name).copied();
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
        main.maybe("interserver_connections", get("InterserverConnection"));
        // An insert waiting to be batched counts as a query from 26.3, when
        // inserts are batched by default.
        let pending = get("PendingAsyncInsert").unwrap_or(0.0);
        main.maybe(
            "running_queries",
            get("Query").map(|running| (running - pending).max(0.0)),
        );
        main.maybe("pending_async_inserts", get("PendingAsyncInsert"));
        main.maybe("preempted_queries", get("QueryPreempted"));
        main.maybe("merges_running", get("Merge"));
        main.maybe("delayed_inserts", get("DelayedInserts"));
        main.maybe("readonly_replicas", get("ReadonlyReplica"));
        main.maybe("memory_tracked_bytes", get("MemoryTracking"));
        main.maybe("merge_memory_bytes", get("MergesMutationsMemoryTracking"));
        main.maybe("distributed_files", get("DistributedFilesToInsert"));
        main.maybe(
            "distributed_broken_files",
            get("BrokenDistributedFilesToInsert"),
        );
        main.maybe("distributed_bytes", get("DistributedBytesToInsert"));
        main.maybe("fetches_running", get("ReplicatedFetch"));
        main.maybe("keeper_sessions", get("ZooKeeperSession"));
        main.maybe("keeper_sessions_expired", get("ZooKeeperSessionExpired"));
        main.maybe("keeper_requests", get("ZooKeeperRequest"));
        main.maybe("keeper_clients", get("KeeperAliveConnections"));
        main.maybe("keeper_outstanding", get("KeeperOutstandingRequests"));

        // Each pool's tasks against its size, from the pairs it reports.
        let mut pools: Vec<(String, f64, f64)> = metrics
            .iter()
            .filter_map(|(name, tasks)| {
                let pool = name.strip_prefix("Background")?.strip_suffix("PoolTask")?;
                let size = metrics.get(&format!("Background{pool}PoolSize"))?;
                Some((words(pool), *tasks, *size))
            })
            .collect();
        pools.sort_by(|a, b| a.0.cmp(&b.0));
        for (pool, tasks, size) in pools {
            let row = rows.add("pool", &pool);
            row.set("pool_tasks", tasks);
            row.set("pool_size", size);
            if size > 0.0 {
                row.set("pool_used", tasks / size * 100.0);
            }
        }
    }

    /// Running totals since it started.
    async fn events(&mut self, rows: &mut Rows) {
        let sql = format!(
            "SELECT event AS name, value FROM system.events WHERE event IN ({}, \
             'MemoryOvercommitWaitTimeMicroseconds')",
            quoted(&EVENTS.map(|(event, _)| event))
        );
        let Some(events) = self.named(rows, "events", &sql).await else {
            return;
        };
        let main = &mut rows.main;
        for (event, field) in EVENTS {
            // An event that's never happened isn't listed.
            main.total(field, Some(events.get(event).copied().unwrap_or(0.0)));
        }
        // Microseconds over how many, in milliseconds.
        main.average("latency_ms", "_query_time", "queries", 0.001);
        main.average("select_latency_ms", "_select_time", "selects", 0.001);
        main.average("insert_latency_ms", "_insert_time", "inserts", 0.001);
        main.average("rows_per_insert", "inserted_rows", "inserts", 1.0);
        main.average(
            "keeper_latency_ms",
            "_keeper_wait",
            "_keeper_transactions",
            0.001,
        );
        // In milliseconds, so its rate is milliseconds waited each second.
        let waited = events
            .get("MemoryOvercommitWaitTimeMicroseconds")
            .copied()
            .unwrap_or(0.0);
        main.total("overcommit_wait_ms", Some(waited / 1000.0));
    }

    /// What ClickHouse works out in the background, such as the most parts in one
    /// partition, which slows inserts at `parts_to_delay_insert`.
    async fn asynchronous(&mut self, rows: &mut Rows) {
        let sql = format!(
            "SELECT metric AS name, value FROM system.asynchronous_metrics \
             WHERE metric IN ({})",
            quoted(&ASYNCHRONOUS)
        );
        let Some(metrics) = self.named(rows, "background metrics", &sql).await else {
            return;
        };
        let get = |name: &str| metrics.get(name).copied();
        let main = &mut rows.main;
        main.maybe("max_parts_per_partition", get("MaxPartCountForPartition"));
        main.maybe("parts_total", get("TotalPartsOfMergeTreeTables"));
        main.maybe("memory_bytes", get("MemoryResident"));
        // The furthest behind of its replicated tables that can take writes.
        main.maybe("lag_secs", get("ReplicasMaxAbsoluteDelay"));
        main.maybe("relative_lag_secs", get("ReplicasMaxRelativeDelay"));
        main.maybe("max_replication_queue", get("ReplicasMaxQueueSize"));
        main.maybe("max_inserts_in_queue", get("ReplicasMaxInsertsInQueue"));
        // Only when Keeper runs inside this server.
        let role = [
            ("KeeperIsLeader", "leader"),
            ("KeeperIsFollower", "follower"),
            ("KeeperIsStandalone", "standalone"),
        ]
        .into_iter()
        .find(|(name, _)| get(name) == Some(1.0));
        if let Some((_, role)) = role {
            main.set("keeper_role", role);
            main.flag("keeper_leader", role == "leader");
            main.maybe("keeper_synced_followers", get("KeeperSyncedFollowers"));
            main.maybe(
                "keeper_memory_limit_hit",
                get("KeeperIsExceedingMemorySoftLimitHit"),
            );
        }
        self.memory = (get("CGroupMemoryTotal"), get("OSMemoryTotal"));
    }

    /// Replicated tables, without the columns that ask Keeper for every table.
    async fn replicas(&mut self, rows: &mut Rows) {
        let found = self
            .one(
                "SELECT count() AS tables, countIf(is_readonly) AS readonly, \
                 countIf(is_session_expired) AS expired, sum(queue_size) AS queue, \
                 sum(inserts_in_queue) AS inserts, max(merges_in_queue) AS merges, \
                 max(future_parts) AS future, max(parts_to_check) AS to_check, \
                 sum(lost_part_count) AS lost, \
                 countIf(last_queue_update_exception != '') AS update_errors, \
                 max(if(queue_size > 0, now() - queue_oldest_time, 0)) AS oldest \
                 FROM system.replicas",
            )
            .await;
        let replicas = match found {
            Ok(replicas) => replicas,
            Err(failure) => return Self::missed(rows, "replicated tables", &failure),
        };
        if number(replicas.get("tables")).unwrap_or(0.0) == 0.0 {
            return;
        }
        let get = |key: &str| number(replicas.get(key));
        let main = &mut rows.main;
        main.maybe("replicated_tables", get("tables"));
        main.maybe("readonly_tables", get("readonly"));
        main.maybe("expired_sessions", get("expired"));
        main.maybe("replication_queue", get("queue"));
        main.maybe("inserts_in_queue", get("inserts"));
        main.maybe("max_merges_in_queue", get("merges"));
        main.maybe("max_future_parts", get("future"));
        main.maybe("max_parts_to_check", get("to_check"));
        main.total("lost_parts", get("lost"));
        main.maybe("queue_update_errors", get("update_errors"));
        main.maybe("oldest_queue_entry_secs", get("oldest"));

        // Entries tried over and over, and the newest reason one failed.
        match self
            .one(
                "SELECT countIf(num_tries > 100 OR num_postponed > 1000) AS stuck, \
                 countIf(last_exception != '') AS failing, \
                 argMax(last_exception, last_exception_time) AS reason \
                 FROM system.replication_queue",
            )
            .await
        {
            Ok(queue) => {
                let main = &mut rows.main;
                main.maybe("queue_stuck", number(queue.get("stuck")));
                main.maybe("queue_failing", number(queue.get("failing")));
                let reason = queue.get("reason").and_then(Value::as_str).unwrap_or("");
                if !reason.is_empty() {
                    let reason: String = reason
                        .lines()
                        .next()
                        .unwrap_or(reason)
                        .chars()
                        .take(200)
                        .collect();
                    main.set("replication_error", reason);
                }
            }
            Err(failure) => Self::missed(rows, "replication queue", &failure),
        }
        match self
            .one("SELECT max(elapsed) AS longest FROM system.replicated_fetches")
            .await
        {
            Ok(fetches) => rows
                .main
                .maybe("longest_fetch_secs", number(fetches.get("longest"))),
            Err(failure) => Self::missed(rows, "fetches", &failure),
        }
    }

    /// Its session with Keeper or ZooKeeper, from 23.5, and how many replicas
    /// of other shards it's recently failed to reach.
    async fn keeper(&mut self, rows: &mut Rows) {
        match self
            .one(
                "SELECT count() AS sessions, countIf(is_expired) AS expired, \
                 min(session_uptime_elapsed_seconds) AS uptime \
                 FROM system.zookeeper_connection",
            )
            .await
        {
            Ok(connection) => {
                let sessions = number(connection.get("sessions")).unwrap_or(0.0);
                if sessions > 0.0 {
                    let expired = number(connection.get("expired")).unwrap_or(0.0);
                    rows.main.flag("keeper_connected", expired == 0.0);
                    rows.main
                        .maybe("keeper_session_secs", number(connection.get("uptime")));
                }
            }
            Err(failure) => Self::missed(rows, "Keeper connection", &failure),
        }
        match self
            .one("SELECT sum(errors_count) AS errors FROM system.clusters")
            .await
        {
            Ok(clusters) => rows
                .main
                .maybe("cluster_errors", number(clusters.get("errors"))),
            Err(failure) => Self::missed(rows, "clusters", &failure),
        }
    }

    /// Mutations still to finish and failing, the longest query, and
    /// dictionaries that won't load.
    async fn work(&mut self, rows: &mut Rows) {
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
        match self
            .one(
                "SELECT countIf(status IN ('FAILED', 'FAILED_AND_RELOADING') \
                 OR last_exception != '') AS failing FROM system.dictionaries",
            )
            .await
        {
            Ok(dictionaries) => {
                rows.main
                    .maybe("dictionaries_failing", number(dictionaries.get("failing")));
            }
            Err(failure) => Self::missed(rows, "dictionaries", &failure),
        }
    }

    /// Errors by code, for the codes worth knowing about. ClickHouse's own docs
    /// warn that others can rise while queries succeed.
    async fn errors(&mut self, rows: &mut Rows) {
        let names: Vec<&str> = ERRORS.iter().map(|(name, _)| *name).collect();
        let sql = format!(
            "SELECT name, sum(value) AS value FROM system.errors \
             WHERE name IN ({}) GROUP BY name",
            quoted(&names)
        );
        let Some(errors) = self.named(rows, "errors", &sql).await else {
            return;
        };
        // Only codes that have happened are listed. One that first happens after
        // the first read had been 0, so it counts from there.
        for (name, kind) in ERRORS {
            let Some(count) = errors.get(name).copied() else {
                continue;
            };
            let row = rows.add("error", name);
            row.set("error_kind", kind);
            row.total("error_count", Some(count));
            if self.errors_read {
                row.set("from_zero", true);
            }
        }
        self.errors_read = true;
    }

    async fn disks(&mut self, rows: &mut Rows) {
        // Every column, as `is_broken` and `is_read_only` only came later.
        let found = self.query("SELECT * FROM system.disks").await;
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
            row.maybe("disk_broken", number(disk.get("is_broken")));
            row.maybe("disk_read_only", number(disk.get("is_read_only")));
        }
    }

    /// Every few minutes: its limits, what asks Keeper about every replicated
    /// table, and what lists files on disk. Gives the limits, kept to compare
    /// what's read every sample against.
    async fn slow_reads(&mut self, rows: &mut Rows) -> Limits {
        let mut limits = Limits::default();
        let settings = self
            .named(
                rows,
                "server settings",
                "SELECT name, value FROM system.server_settings WHERE name IN \
                 ('max_concurrent_queries', 'max_connections', 'max_server_memory_usage', \
                 'max_server_memory_usage_to_ram_ratio')",
            )
            .await
            .unwrap_or_default();
        limits.queries = settings
            .get("max_concurrent_queries")
            .copied()
            .filter(|max| *max > 0.0);
        limits.connections = settings
            .get("max_connections")
            .copied()
            .filter(|max| *max > 0.0);
        limits.memory = settings.get("max_server_memory_usage").copied();
        limits.memory_ratio = settings
            .get("max_server_memory_usage_to_ram_ratio")
            .copied();
        let parts = self
            .named(
                rows,
                "MergeTree settings",
                "SELECT name, value FROM system.merge_tree_settings \
                 WHERE name IN ('parts_to_delay_insert', 'parts_to_throw_insert')",
            )
            .await
            .unwrap_or_default();
        limits.parts = parts
            .get("parts_to_delay_insert")
            .copied()
            .filter(|max| *max > 0.0);
        rows.main.maybe("parts_to_delay_insert", limits.parts);
        rows.main.maybe(
            "parts_to_throw_insert",
            parts.get("parts_to_throw_insert").copied(),
        );

        match self
            .one(
                "SELECT count() AS tables, countIf(active_replicas < total_replicas) AS missing, \
                 max(log_max_index - log_pointer) AS log_lag FROM system.replicas",
            )
            .await
        {
            Ok(replicas) if number(replicas.get("tables")).unwrap_or(0.0) > 0.0 => {
                rows.main
                    .maybe("tables_missing_replicas", number(replicas.get("missing")));
                rows.main
                    .maybe("max_log_lag", number(replicas.get("log_lag")));
            }
            Ok(_) => {}
            Err(failure) => Self::missed(rows, "replicas' Keeper state", &failure),
        }

        match self
            .query("SELECT reason, count() AS parts FROM system.detached_parts GROUP BY reason")
            .await
        {
            Ok(detached) => {
                let mut total = 0.0;
                let mut investigate = 0.0;
                for group in &detached {
                    let count = number(group.get("parts")).unwrap_or(0.0);
                    let reason = group.get("reason").and_then(Value::as_str).unwrap_or("");
                    // Ones on their way somewhere aren't worth counting.
                    if matches!(reason, "attaching" | "deleting" | "tmp-fetch") {
                        continue;
                    }
                    total += count;
                    if is_broken_reason(reason) {
                        investigate += count;
                    }
                }
                rows.main.set("detached_parts", total);
                rows.main.set("detached_broken", investigate);
            }
            Err(failure) => Self::missed(rows, "detached parts", &failure),
        }

        match self
            .one(
                "SELECT countIf(is_blocked) AS blocked, sum(error_count) AS errors \
                 FROM system.distribution_queue",
            )
            .await
        {
            Ok(queue) => {
                rows.main
                    .maybe("distribution_blocked", number(queue.get("blocked")));
                rows.main
                    .maybe("distribution_errors", number(queue.get("errors")));
            }
            Err(failure) => Self::missed(rows, "distribution queue", &failure),
        }

        match self
            .one(
                "SELECT max(dateDiff('second', first_update, now())) AS oldest \
                 FROM system.asynchronous_inserts",
            )
            .await
        {
            Ok(inserts) => {
                rows.main.set(
                    "async_queue_oldest_secs",
                    number(inserts.get("oldest")).unwrap_or(0.0),
                );
            }
            Err(failure) => Self::missed(rows, "async insert queue", &failure),
        }

        match self
            .one(
                "SELECT countIf(status IN ('BACKUP_FAILED', 'RESTORE_FAILED')) AS failed \
                 FROM system.backups",
            )
            .await
        {
            Ok(backups) => rows
                .main
                .maybe("backups_failed", number(backups.get("failed"))),
            Err(failure) => Self::missed(rows, "backups", &failure),
        }
        limits
    }

    /// What's read every sample against the limits read every few minutes.
    fn against_limits(&self, rows: &mut Rows, limits: &Limits) {
        let main = &mut rows.main;
        let field = |main: &super::Row, key: &str| main.fields.get(key).and_then(Value::as_f64);
        if let (Some(running), Some(max)) = (field(main, "running_queries"), limits.queries) {
            main.set("queries_used", running / max * 100.0);
        }
        if let (Some(connections), Some(max)) = (field(main, "connections"), limits.connections) {
            main.set("connections_used", connections / max * 100.0);
        }
        if let (Some(parts), Some(max)) = (field(main, "max_parts_per_partition"), limits.parts) {
            main.set("parts_used", parts / max * 100.0);
        }
        // There's no metric for the current limit, so it's worked out as
        // ClickHouse does at its simplest: a share of the memory it can have, or
        // the limit it's given if that's less.
        let (cgroup, os) = self.memory;
        let available = cgroup.filter(|total| *total > 0.0).or(os);
        let estimate = match (available, limits.memory_ratio) {
            (Some(available), Some(ratio)) if ratio > 0.0 => Some(available * ratio),
            (Some(available), _) => Some(available),
            _ => None,
        };
        let limit = match (estimate, limits.memory.filter(|limit| *limit > 0.0)) {
            (Some(estimate), Some(set)) => Some(estimate.min(set)),
            (estimate, set) => estimate.or(set),
        };
        if let (Some(used), Some(limit)) = (field(main, "memory_tracked_bytes"), limit)
            && limit > 0.0
        {
            main.set("memory_limit_bytes", limit);
            main.set("memory_used", used / limit * 100.0);
        }
    }

    /// Opt-in: each database's size on disk.
    async fn sizes(&mut self, rows: &mut Rows) {
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

    /// Opt-in: how long queries took over the last five minutes, by kind, and
    /// how many failed, from `system.query_log`, which can be large. Its newest
    /// rows can be 7.5 seconds from being written, so those are left for later,
    /// and this account's own queries are left out.
    async fn latency(&mut self, rows: &mut Rows) {
        let found = self
            .query(
                "SELECT query_kind AS kind, \
                 countIf(type = 'QueryFinish') AS finished, \
                 countIf(type IN ('ExceptionBeforeStart', 'ExceptionWhileProcessing')) AS failed, \
                 quantilesIf(0.5, 0.95, 0.99)(query_duration_ms, type = 'QueryFinish') AS took \
                 FROM system.query_log \
                 WHERE event_date >= toDate(now() - INTERVAL 6 MINUTE) \
                 AND event_time > now() - INTERVAL 315 SECOND \
                 AND event_time <= now() - INTERVAL 15 SECOND \
                 AND type != 'QueryStart' AND is_initial_query AND user != currentUser() \
                 GROUP BY query_kind ORDER BY query_kind",
            )
            .await;
        let kinds = match found {
            Ok(kinds) => kinds,
            Err(failure) => return Self::missed(rows, "query log", &failure),
        };
        for kind in &kinds {
            let name = kind.get("kind").and_then(Value::as_str).unwrap_or("");
            let name = if name.is_empty() { "other" } else { name };
            let row = rows.add("queries", &name.to_lowercase());
            row.maybe("finished_5m", number(kind.get("finished")));
            row.maybe("failed_5m", number(kind.get("failed")));
            if let Some(Value::Array(took)) = kind.get("took") {
                for (field, value) in ["p50_ms", "p95_ms", "p99_ms"].iter().zip(took) {
                    // No finished queries leaves them as nan.
                    if let Some(value) = number(Some(value)).filter(|value| value.is_finite()) {
                        row.set(field, value);
                    }
                }
            }
        }
    }
}

/// How often what costs more is read.
const SLOW_EVERY: Duration = Duration::from_secs(300);

/// What's read every few minutes, and when.
struct Slow {
    read: Instant,
    limits: Limits,
    rows: Rows,
}

/// The server's limits, to compare what's read every sample against.
#[derive(Default)]
struct Limits {
    queries: Option<f64>,
    connections: Option<f64>,
    parts: Option<f64>,
    memory: Option<f64>,
    memory_ratio: Option<f64>,
}

/// From `system.metrics`, beyond the background pools.
const CURRENT: [&str; 22] = [
    "Query",
    "PendingAsyncInsert",
    "QueryPreempted",
    "TCPConnection",
    "HTTPConnection",
    "MySQLConnection",
    "PostgreSQLConnection",
    "InterserverConnection",
    "Merge",
    "DelayedInserts",
    "ReadonlyReplica",
    "MemoryTracking",
    "MergesMutationsMemoryTracking",
    "DistributedFilesToInsert",
    "BrokenDistributedFilesToInsert",
    "DistributedBytesToInsert",
    "ReplicatedFetch",
    "ZooKeeperSession",
    "ZooKeeperSessionExpired",
    "ZooKeeperRequest",
    "KeeperAliveConnections",
    "KeeperOutstandingRequests",
];

/// From `system.events`, each with the total it becomes. One starting with `_`
/// is only there for an average.
const EVENTS: [(&str, &str); 36] = [
    ("Query", "queries"),
    ("SelectQuery", "selects"),
    ("InsertQuery", "inserts"),
    ("FailedQuery", "failed_queries"),
    ("FailedSelectQuery", "failed_selects"),
    ("FailedInsertQuery", "failed_inserts"),
    ("QueryTimeMicroseconds", "_query_time"),
    ("SelectQueryTimeMicroseconds", "_select_time"),
    ("InsertQueryTimeMicroseconds", "_insert_time"),
    ("InsertedRows", "inserted_rows"),
    ("InsertedBytes", "inserted_bytes"),
    ("RejectedInserts", "rejected_inserts"),
    ("DelayedInserts", "inserts_delayed"),
    ("DelayedInsertsMilliseconds", "insert_delay_ms"),
    ("QueryMemoryLimitExceeded", "memory_limit_exceeded"),
    ("DelayedMutations", "mutations_delayed"),
    ("RejectedMutations", "mutations_rejected"),
    ("ReplicatedPartFailedFetches", "failed_fetches"),
    ("ReplicatedPartChecksFailed", "failed_part_checks"),
    ("ReplicatedDataLoss", "data_loss"),
    ("DataAfterMergeDiffersFromReplica", "merge_differs"),
    ("DataAfterMutationDiffersFromReplica", "mutation_differs"),
    ("ReplicaPartialShutdown", "partial_shutdowns"),
    ("DistributedConnectionFailTry", "distributed_retries"),
    ("DistributedConnectionFailAtAll", "distributed_failures"),
    ("DistributedRejectedInserts", "distributed_rejected"),
    (
        "DistributedAsyncInsertionFailures",
        "distributed_insert_failures",
    ),
    ("ZooKeeperHardwareExceptions", "keeper_hardware_errors"),
    ("ZooKeeperUserExceptions", "keeper_user_errors"),
    ("ZooKeeperWaitMicroseconds", "_keeper_wait"),
    ("ZooKeeperTransactions", "_keeper_transactions"),
    ("FailedAsyncInsertQuery", "failed_async_inserts"),
    ("StorageBufferErrorOnFlush", "buffer_flush_errors"),
    ("SlowRead", "slow_reads"),
    ("ReadBufferFromFileDescriptorReadFailed", "read_failures"),
    ("WriteBufferFromFileDescriptorWriteFailed", "write_failures"),
];

/// From `system.asynchronous_metrics`. None of these are keyed, so they keep
/// their names when 26.8 moves keyed ones into `key_values`.
const ASYNCHRONOUS: [&str; 14] = [
    "MaxPartCountForPartition",
    "TotalPartsOfMergeTreeTables",
    "MemoryResident",
    "ReplicasMaxAbsoluteDelay",
    "ReplicasMaxRelativeDelay",
    "ReplicasMaxQueueSize",
    "ReplicasMaxInsertsInQueue",
    "CGroupMemoryTotal",
    "OSMemoryTotal",
    "KeeperIsLeader",
    "KeeperIsFollower",
    "KeeperIsStandalone",
    "KeeperSyncedFollowers",
    "KeeperIsExceedingMemorySoftLimitHit",
];

/// The error codes worth knowing about, each with what sort of trouble it is.
/// Others, such as a query being cancelled, happen in normal running.
const ERRORS: [(&str, &str); 27] = [
    ("MEMORY_LIMIT_EXCEEDED", "capacity"),
    ("CANNOT_ALLOCATE_MEMORY", "capacity"),
    ("TOO_MANY_SIMULTANEOUS_QUERIES", "capacity"),
    ("SERVER_OVERLOADED", "capacity"),
    ("NOT_ENOUGH_SPACE", "capacity"),
    ("TOO_MANY_PARTS", "capacity"),
    ("TOO_MANY_PARTITIONS", "capacity"),
    ("TOO_MANY_MUTATIONS", "capacity"),
    ("CHECKSUM_DOESNT_MATCH", "integrity"),
    ("CORRUPTED_DATA", "integrity"),
    ("POTENTIALLY_BROKEN_DATA_PART", "integrity"),
    ("CANNOT_FSYNC", "integrity"),
    ("KEEPER_EXCEPTION", "replication"),
    ("NO_ZOOKEEPER", "replication"),
    ("TABLE_IS_READ_ONLY", "replication"),
    ("NO_REPLICA_HAS_PART", "replication"),
    ("REPLICA_IS_NOT_IN_QUORUM", "replication"),
    ("ALL_REPLICAS_ARE_STALE", "replication"),
    ("ALL_CONNECTION_TRIES_FAILED", "distributed"),
    ("DISTRIBUTED_TOO_MANY_PENDING_BYTES", "distributed"),
    ("DISTRIBUTED_BROKEN_BATCH_INFO", "distributed"),
    ("DISTRIBUTED_BROKEN_BATCH_FILES", "distributed"),
    ("LOGICAL_ERROR", "bug"),
    ("CANNOT_LOAD_CONFIG", "bug"),
    ("DICTIONARIES_WAS_NOT_LOADED", "bug"),
    ("S3_ERROR", "bug"),
    ("AUTHENTICATION_FAILED", "security"),
];

/// Whether a detached part was set aside because something was wrong with it,
/// as opposed to a person or a move doing it.
fn is_broken_reason(reason: &str) -> bool {
    reason.starts_with("broken")
        || reason.ends_with("-not-byte-identical")
        || matches!(reason, "covered-by-broken" | "noquorum" | "unexpected")
}

/// Names as a list for `IN (…)`. They're all fixed here, never from outside.
fn quoted(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `MergesAndMutations` as `merges and mutations`.
fn words(name: &str) -> String {
    let mut words = String::new();
    for character in name.chars() {
        if character.is_ascii_uppercase() && !words.is_empty() {
            words.push(' ');
        }
        words.push(character.to_ascii_lowercase());
    }
    words
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

    /// A round's queries go over one connection, which ends with the round.
    #[tokio::test]
    async fn a_rounds_queries_share_one_connection() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut reader = BufReader::new(socket);
                    loop {
                        // Each request is a GET, so it ends with its headers.
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match reader.read_line(&mut line).await {
                                Ok(0) | Err(_) => return,
                                Ok(_) if line == "\r\n" => break,
                                Ok(_) => {}
                            }
                        }
                        let body = r#"{"data": [{"version": "24.8.1", "uptime": 5}]}"#;
                        let answer = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        if reader.get_mut().write_all(answer.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let check = Check::new("events", CheckKind::Clickhouse, &address.to_string());
        let mut clickhouse = Clickhouse::new(&check, &Credentials::default()).unwrap();
        for round in 1..=2 {
            let mut rows = Rows::new("events");
            clickhouse.read(&mut rows, &[]).await.unwrap();
            assert_eq!(rows.main.fields["version"], "24.8.1");
            assert_eq!(accepted.load(Ordering::Relaxed), round);
        }
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
