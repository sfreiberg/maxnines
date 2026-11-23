//! MongoDB's health, load and replication. Most of it comes from one
//! `serverStatus`, and replica sets from `replSetGetStatus`. An account with
//! the `clusterMonitor` role can run both, and read the oplog's window too.
//!
//! What `serverStatus` holds moves between versions, and Atlas's smaller tiers
//! leave some of it out, so every field is read where it might be and skipped
//! where it isn't.

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use maxnines_protocol::Check;
use mongodb::Client;
use mongodb::bson::{Bson, Document, doc};

use super::Rows;
use crate::Credentials;
use crate::sign_in::{mongodb_client, mongodb_error};

pub(super) struct Mongodb {
    client: Client,
}

/// A field some way down, such as `["connections", "current"]`.
fn at<'a>(document: &'a Document, path: &[&str]) -> Option<&'a Bson> {
    let (last, parents) = path.split_last()?;
    let mut current = document;
    for key in parents {
        current = current.get_document(key).ok()?;
    }
    current.get(last)
}

fn number(value: Option<&Bson>) -> Option<f64> {
    match value? {
        Bson::Int32(number) => Some(f64::from(*number)),
        Bson::Int64(number) => Some(*number as f64),
        Bson::Double(number) => Some(*number),
        Bson::Boolean(flag) => Some(f64::from(u8::from(*flag))),
        _ => None,
    }
}

fn moment(value: Option<&Bson>) -> Option<DateTime<Utc>> {
    match value? {
        Bson::DateTime(time) => DateTime::from_timestamp_millis(time.timestamp_millis()),
        _ => None,
    }
}

/// How far `later` is ahead of `earlier`, in seconds, as lag is reported. Behind
/// counts as not lagging at all.
fn seconds_ahead(later: DateTime<Utc>, earlier: DateTime<Utc>) -> f64 {
    (later - earlier).max(TimeDelta::zero()).as_seconds_f64()
}

fn text(value: Option<&Bson>) -> Option<String> {
    value?.as_str().map(String::from)
}

/// The server's code for a command it wouldn't run, such as 13 for
/// unauthorised, or 76 for not being in a replica set.
fn refused_with(error: &mongodb::error::Error) -> Option<i32> {
    match &*error.kind {
        mongodb::error::ErrorKind::Command(command) => Some(command.code),
        _ => None,
    }
}

impl Mongodb {
    pub(super) async fn connect(check: &Check, credentials: &Credentials) -> Result<Self> {
        let client = mongodb_client(check, Some(credentials))?;
        // The driver connects on first use, so this is where it signs in.
        client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
            .map_err(|error| mongodb_error(&error))?;
        Ok(Self { client })
    }

    pub(super) async fn read(&self, rows: &mut Rows, extras: &[String]) -> Result<()> {
        let admin = self.client.database("admin");
        let status = match admin.run_command(doc! { "serverStatus": 1 }).await {
            Ok(status) => status,
            // It answered and let the account in, so it's up, but there's
            // nothing else to read until the account is given more.
            Err(error) if refused_with(&error) == Some(13) => {
                rows.missed("server status", "the account needs the clusterMonitor role");
                // Anyone can ask its version.
                if let Ok(built) = admin.run_command(doc! { "buildInfo": 1 }).await {
                    rows.main.maybe("version", text(built.get("version")));
                }
                return Ok(());
            }
            Err(error) => {
                return Err(mongodb_error(&error)).context("reading the server's status");
            }
        };
        let in_set = self.server(rows, &status);
        if in_set {
            self.replica_set(rows).await;
            self.oplog(rows).await;
        }
        self.operations(rows).await;
        if extras.iter().any(|extra| extra == "sizes") {
            self.sizes(rows).await;
        }
        Ok(())
    }

    /// What `serverStatus` says. Whether it's in a replica set decides what else
    /// is asked.
    fn server(&self, rows: &mut Rows, status: &Document) -> bool {
        let get = |path: &[&str]| number(at(status, path));
        let main = &mut rows.main;
        main.maybe("version", text(status.get("version")));
        main.maybe("uptime_secs", get(&["uptime"]));

        let (current, available) = (
            get(&["connections", "current"]),
            get(&["connections", "available"]),
        );
        main.maybe("connections", current);
        if let (Some(current), Some(available)) = (current, available)
            && current + available > 0.0
        {
            main.set("connections_used", current / (current + available) * 100.0);
        }
        // Only from 6.3.
        main.total("refused", get(&["connections", "rejected"]));

        for (kind, path) in [("reads", "reads"), ("writes", "writes")] {
            main.total(
                &format!("_{kind}_latency"),
                get(&["opLatencies", path, "latency"]),
            );
            main.total(&format!("_{kind}_done"), get(&["opLatencies", path, "ops"]));
            // Microseconds in total over how many, in seconds.
            main.average(
                &format!("{kind}_latency_secs"),
                &format!("_{kind}_latency"),
                &format!("_{kind}_done"),
                1e-6,
            );
        }
        main.maybe(
            "queued_reads",
            get(&["globalLock", "currentQueue", "readers"]),
        );
        main.maybe(
            "queued_writes",
            get(&["globalLock", "currentQueue", "writers"]),
        );
        // Tickets moved in 8.0.
        for kind in ["read", "write"] {
            let available = get(&["queues", "execution", kind, "available"])
                .or_else(|| get(&["wiredTiger", "concurrentTransactions", kind, "available"]));
            main.maybe(&format!("{kind}_tickets"), available);
        }

        let cache = |key: &str| get(&["wiredTiger", "cache", key]);
        if let (Some(used), Some(dirty), Some(most)) = (
            cache("bytes currently in the cache"),
            cache("tracked dirty bytes in the cache"),
            cache("maximum bytes configured"),
        ) && most > 0.0
        {
            main.set("cache_used", used / most * 100.0);
            main.set("cache_dirty", dirty / most * 100.0);
        }
        main.maybe("cursors_open", get(&["metrics", "cursor", "open", "total"]));
        main.total("cursors_timed_out", get(&["metrics", "cursor", "timedOut"]));
        if let (Some(regular), Some(warning)) =
            (get(&["asserts", "regular"]), get(&["asserts", "warning"]))
        {
            main.total("asserts", Some(regular + warning));
        }
        // In megabytes.
        main.maybe(
            "memory_bytes",
            get(&["mem", "resident"]).map(|mb| mb * 1_048_576.0),
        );
        main.maybe("flow_control_lagged", get(&["flowControl", "isLagged"]));

        let operations = ["insert", "query", "update", "delete", "getmore", "command"];
        let counted: Vec<(&str, Option<f64>)> = operations
            .iter()
            .map(|operation| (*operation, get(&["opcounters", operation])))
            .collect();
        for (operation, count) in counted {
            if count.is_some() {
                rows.add("operation", operation).total("operations", count);
            }
        }

        let process = text(status.get("process")).unwrap_or_default();
        let set = text(at(status, &["repl", "setName"]));
        let role = if process.contains("mongos") {
            "router"
        } else if set.is_none() {
            "standalone"
        } else if number(at(status, &["repl", "isWritablePrimary"]))
            .or_else(|| number(at(status, &["repl", "ismaster"])))
            == Some(1.0)
        {
            "primary"
        } else if number(at(status, &["repl", "secondary"])) == Some(1.0) {
            "secondary"
        } else if number(at(status, &["repl", "arbiterOnly"])) == Some(1.0) {
            "arbiter"
        } else {
            "other"
        };
        let main = &mut rows.main;
        main.set("role", role);
        main.flag("replica", role == "secondary");
        main.maybe("replica_set", set.clone());
        set.is_some()
    }

    /// The replica set as this member sees it: who's healthy, who's primary,
    /// and how far behind each secondary is.
    async fn replica_set(&self, rows: &mut Rows) {
        let found = self
            .client
            .database("admin")
            .run_command(doc! { "replSetGetStatus": 1 })
            .await;
        let status = match found {
            Ok(status) => status,
            Err(error) => return rows.missed("replica set", mongodb_error(&error)),
        };
        let Ok(members) = status.get_array("members") else {
            return;
        };
        let members: Vec<&Document> = members.iter().filter_map(Bson::as_document).collect();
        let primary = members
            .iter()
            .find(|member| number(member.get("state")) == Some(1.0));
        let newest = |member: &Document| moment(member.get("optimeDate"));
        // With no primary, lag is against whichever member is furthest on.
        let leader = primary
            .and_then(|primary| newest(primary))
            .or_else(|| members.iter().filter_map(|member| newest(member)).max());
        let healthy = members
            .iter()
            .filter(|member| number(member.get("health")) == Some(1.0))
            .count();

        let main = &mut rows.main;
        main.set("members", members.len());
        main.set("members_healthy", healthy);
        main.flag("has_primary", primary.is_some());
        main.maybe("term", number(status.get("term")));
        if let (Some(applied), Some(committed)) = (
            moment(at(&status, &["optimes", "lastAppliedWallTime"])),
            moment(at(&status, &["optimes", "lastCommittedWallTime"])),
        ) && primary.is_some_and(|primary| primary.get_bool("self").unwrap_or(false))
        {
            main.set("majority_lag_secs", seconds_ahead(applied, committed));
        }

        for member in &members {
            let name = text(member.get("name")).unwrap_or_default();
            let healthy = number(member.get("health")) == Some(1.0);
            let state = text(member.get("stateStr"));
            let secondary = number(member.get("state")) == Some(2.0);
            // A member that's down reports a time from 1970, which isn't lag.
            let lag = match (leader, newest(member)) {
                (Some(leader), Some(own)) if healthy && secondary => {
                    Some(seconds_ahead(leader, own))
                }
                _ => None,
            };
            if member.get_bool("self").unwrap_or(false) && secondary {
                let main = &mut rows.main;
                main.maybe("lag_secs", lag);
                let source = text(status.get("syncSourceHost")).unwrap_or_default();
                main.flag("receiving", !source.is_empty());
            }
            let row = rows.add("member", &name);
            row.flag("member_healthy", healthy);
            row.maybe("member_state", state);
            row.maybe("member_lag_secs", lag);
        }
    }

    /// How long the oplog covers: how long a secondary can be away and catch up
    /// without copying everything again.
    async fn oplog(&self, rows: &mut Rows) {
        let oplog = self
            .client
            .database("local")
            .collection::<Document>("oplog.rs");
        let end = |order: i32| {
            oplog
                .find_one(doc! {})
                .sort(doc! { "$natural": order })
                .projection(doc! { "ts": 1, "_id": 0 })
        };
        let (first, last) = match (end(1).await, end(-1).await) {
            (Ok(first), Ok(last)) => (first, last),
            (Err(error), _) | (_, Err(error)) => {
                return rows.missed("the oplog", mongodb_error(&error));
            }
        };
        let written_at = |entry: Option<Document>| match entry?.get("ts")? {
            Bson::Timestamp(stamp) => DateTime::from_timestamp(i64::from(stamp.time), 0),
            _ => None,
        };
        if let (Some(first), Some(last)) = (written_at(first), written_at(last)) {
            rows.main
                .set("oplog_window_secs", seconds_ahead(last, first));
        }
    }

    /// The longest-running operation a client asked for.
    async fn operations(&self, rows: &mut Rows) {
        let pipeline = [
            doc! { "$currentOp": { "allUsers": true, "idleConnections": false } },
            doc! { "$match": { "active": true, "client": { "$exists": true } } },
            doc! { "$group": { "_id": Bson::Null, "oldest": { "$max": "$secs_running" } } },
        ];
        let found = self.client.database("admin").aggregate(pipeline).await;
        let mut cursor = match found {
            Ok(cursor) => cursor,
            Err(error) => {
                // Without the right to see others' operations, there's nothing to
                // say, which isn't worth a note on its own.
                if refused_with(&error) != Some(13) {
                    rows.missed("operations", mongodb_error(&error));
                }
                return;
            }
        };
        let oldest = match cursor.advance().await {
            Ok(true) => cursor
                .deserialize_current()
                .ok()
                .and_then(|group| number(group.get("oldest"))),
            _ => None,
        };
        rows.main.set("oldest_query_secs", oldest.unwrap_or(0.0));
    }

    /// Opt-in: each database's size on disk.
    async fn sizes(&self, rows: &mut Rows) {
        let found = self
            .client
            .database("admin")
            .run_command(doc! { "listDatabases": 1 })
            .await;
        let listed = match found {
            Ok(listed) => listed,
            Err(error) => return rows.missed("database sizes", mongodb_error(&error)),
        };
        let Ok(databases) = listed.get_array("databases") else {
            return;
        };
        for database in databases.iter().filter_map(Bson::as_document) {
            let Some(name) = text(database.get("name")) else {
                continue;
            };
            let size = number(database.get("sizeOnDisk"));
            rows.add("database", &name).maybe("size_bytes", size);
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

    /// A real server, as `host:port [username password]`.
    fn real() -> Option<Database> {
        let value = std::env::var("MAXNINES_TEST_CHECK_MONGODB").ok()?;
        let mut words = value.split_whitespace();
        let target = words.next()?;
        Some(Database {
            check: maxnines_protocol::Check::new("real", CheckKind::Mongodb, target),
            credentials: Credentials {
                username: words.next().map(String::from),
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
        let mut reader = Reader::new("main", database, &extras).unwrap();
        let mut settle = Settle::default();
        let first = settle.settle(reader.read(Duration::from_secs(10)).await);
        let main = row(&first, "main");
        assert_eq!(main["up"], 1, "{first:?}");
        assert!(main["version"].is_string());
        for field in [
            "connections",
            "connections_used",
            "uptime_secs",
            "cache_used",
        ] {
            assert!(main[field].is_number(), "{field}: {main}");
        }
        row(&first, "main database admin");

        let second = settle.settle(reader.read(Duration::from_secs(10)).await);
        let commands = row(&second, "main operation command");
        assert!(
            commands["operations"].as_f64().unwrap() >= 1.0,
            "{second:?}"
        );
    }
}
