//! Reads a database's health, load and replication, for the `databases`
//! collector on agents and for hosts without an agent on the server.
//!
//! A [`Reader`] keeps its connection open between rounds, so each round costs a
//! few queries rather than a sign-in, and opens a new one when the old one stops
//! working. ClickHouse, read over HTTP, has one for each round instead. Each round gives rows: one for the database itself, named as it's
//! defined, and one for each thing it has several of, such as standbys or
//! replication slots, named after it. A sample groups rows by their database's
//! kind, as `{"postgres": [...], "mysql": [...]}`, so each kind's values are its
//! own, such as `postgres.connections`. Running totals in a row go under `totals`,
//! and a [`Settle`] turns them into the change since the last sample. A total
//! whose name starts with `_` is only there to work out an average, and goes
//! once it has.

pub(crate) mod clickhouse;
mod mongodb;
mod mysql;
mod postgres;

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use maxnines_protocol::totals::change;
use maxnines_protocol::{Check, CheckKind};
use serde_json::{Map, Value, json};
use tokio::time::timeout;

use crate::Credentials;
use crate::sign_in::short;

/// How long a round gets, unless the caller asks for less.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The most notes of what couldn't be read that a round keeps.
const MAX_MISSING: usize = 4;

/// Whether this kind of check is a database whose stats can be read.
pub fn is_database(kind: CheckKind) -> bool {
    matches!(
        kind,
        CheckKind::Postgres | CheckKind::Mysql | CheckKind::Mongodb | CheckKind::Clickhouse
    )
}

/// Where a database is and how to sign in to it.
#[derive(Clone, PartialEq, Eq)]
pub struct Database {
    /// The kind, where to reach it, and its options, as a check would have them.
    pub check: Check,
    pub credentials: Credentials,
}

/// A connection that's open.
enum Open {
    Postgres(postgres::Postgres),
    Mysql(mysql::Mysql),
    Mongodb(mongodb::Mongodb),
    /// Boxed, as it holds what it's read between rounds, and its connection.
    Clickhouse(Box<clickhouse::Clickhouse>),
}

pub struct Reader {
    name: String,
    database: Database,
    extras: Vec<String>,
    open: Option<Open>,
}

impl Reader {
    pub fn new(name: &str, database: Database, extras: &[String]) -> Self {
        Self {
            name: name.to_string(),
            database,
            extras: extras.to_vec(),
            open: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// What its rows are grouped under: its kind.
    pub fn kind(&self) -> &'static str {
        self.database.check.kind.as_str()
    }

    /// One round of rows, which always has the database's own row, saying why
    /// if it couldn't be read.
    pub async fn read(&mut self, limit: Duration) -> Vec<Value> {
        let outcome = match timeout(limit, self.read_or_reconnect()).await {
            Ok(outcome) => outcome,
            Err(_) => Err(anyhow!("timed out")),
        };
        match outcome {
            Ok(rows) => rows,
            Err(error) => {
                // Whatever state it was left in, the next round starts afresh.
                self.open = None;
                vec![json!({ "name": self.name, "up": 0, "error": format!("{error:#}") })]
            }
        }
        .into_iter()
        .map(|mut row| {
            row["kind"] = json!(self.kind());
            row
        })
        .collect()
    }

    /// A connection kept from an earlier round may have been closed since, such
    /// as by the server restarting, which is no reason to say it's down.
    async fn read_or_reconnect(&mut self) -> Result<Vec<Value>> {
        let reused = self.open.is_some();
        match self.read_once().await {
            Err(_) if reused => {
                self.open = None;
                self.read_once().await
            }
            outcome => outcome,
        }
    }

    async fn read_once(&mut self) -> Result<Vec<Value>> {
        if self.open.is_none() {
            self.open = Some(self.connect().await?);
        }
        let mut rows = Rows::new(&self.name);
        let extras = &self.extras;
        match self.open.as_mut() {
            Some(Open::Postgres(open)) => open.read(&mut rows, extras).await?,
            Some(Open::Mysql(open)) => open.read(&mut rows, extras).await?,
            Some(Open::Mongodb(open)) => open.read(&mut rows, extras).await?,
            Some(Open::Clickhouse(open)) => open.read(&mut rows, extras).await?,
            None => bail!("not connected"),
        }
        Ok(rows.finish())
    }

    async fn connect(&self) -> Result<Open> {
        let Database { check, credentials } = &self.database;
        match check.kind {
            CheckKind::Postgres => Ok(Open::Postgres(
                postgres::Postgres::connect(check, credentials).await?,
            )),
            CheckKind::Mysql => Ok(Open::Mysql(
                mysql::Mysql::connect(check, credentials).await?,
            )),
            CheckKind::Mongodb => Ok(Open::Mongodb(
                mongodb::Mongodb::connect(check, credentials).await?,
            )),
            CheckKind::Clickhouse => Ok(Open::Clickhouse(Box::new(clickhouse::Clickhouse::new(
                check,
                credentials,
            )?))),
            other => bail!("{} isn't a database", other.as_str()),
        }
    }
}

/// One row: what it's called, its values, its running totals, and averages
/// worked out from the change in two totals.
#[derive(Clone)]
struct Row {
    name: String,
    fields: Map<String, Value>,
    totals: Map<String, Value>,
    averages: Vec<Value>,
}

impl Row {
    fn new(name: String) -> Self {
        Self {
            name,
            fields: Map::new(),
            totals: Map::new(),
            averages: Vec::new(),
        }
    }

    fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.fields.insert(key.to_string(), value.into());
    }

    /// A value that may not be known, such as one the account can't see.
    fn maybe(&mut self, key: &str, value: Option<impl Into<Value>>) {
        if let Some(value) = value {
            self.set(key, value);
        }
    }

    fn flag(&mut self, key: &str, on: bool) {
        self.set(key, u8::from(on));
    }

    fn total(&mut self, key: &str, total: Option<f64>) {
        if let Some(total) = total {
            self.totals.insert(key.to_string(), json!(total));
        }
    }

    /// `key` becomes `scale` times the change in `part` over the change in
    /// `whole`, once there's a change to go on.
    fn average(&mut self, key: &str, part: &str, whole: &str, scale: f64) {
        self.averages.push(json!([key, part, whole, scale]));
    }

    fn into_value(self) -> Value {
        let mut fields = self.fields;
        fields.insert("name".to_string(), json!(self.name));
        if !self.totals.is_empty() {
            fields.insert("totals".to_string(), Value::Object(self.totals));
        }
        if !self.averages.is_empty() {
            fields.insert("averages".to_string(), Value::Array(self.averages));
        }
        Value::Object(fields)
    }
}

/// The rows of one round: the database's own, and the rest.
struct Rows {
    main: Row,
    others: Vec<Row>,
    /// What couldn't be read, such as for want of a privilege, which doesn't
    /// stop the rest.
    missing: Vec<String>,
}

impl Rows {
    fn new(name: &str) -> Self {
        let mut main = Row::new(name.to_string());
        main.set("up", 1);
        Self {
            main,
            others: Vec::new(),
            missing: Vec::new(),
        }
    }

    /// A row for one of several things, such as `orders standby replica1`.
    fn add(&mut self, what: &str, which: &str) -> &mut Row {
        let name = format!("{} {what} {which}", self.main.name);
        self.others.push(Row::new(name));
        self.others.last_mut().expect("just added")
    }

    /// Notes what couldn't be read, and why.
    fn missed(&mut self, what: &str, error: impl std::fmt::Display) {
        self.note(format!("{what}: {}", short(error)));
    }

    /// Keeps a note of what couldn't be read, up to as many as are shown.
    fn note(&mut self, note: String) {
        if self.missing.len() < MAX_MISSING {
            self.missing.push(note);
        }
    }

    fn finish(mut self) -> Vec<Value> {
        if !self.missing.is_empty() {
            self.main.set("missing", self.missing.join("; "));
        }
        std::iter::once(self.main)
            .chain(self.others)
            .map(Row::into_value)
            .collect()
    }
}

/// A sample of rows, grouped by the kind each says it's of, which is taken out of
/// the row. A row that doesn't say is under `unknown`.
pub fn by_kind(rows: Vec<Value>) -> Value {
    let mut grouped = Map::new();
    for mut row in rows {
        let kind = match row.as_object_mut().and_then(|fields| fields.remove("kind")) {
            Some(Value::String(kind)) => kind,
            _ => "unknown".to_string(),
        };
        if let Value::Array(rows) = grouped.entry(kind).or_insert_with(|| json!([])) {
            rows.push(row);
        }
    }
    Value::Object(grouped)
}

/// The last total seen for each row, which turns the next into a change.
#[derive(Default)]
pub struct Settle(HashMap<(String, String), f64>);

impl Settle {
    /// Turns a round's rows into a sample's. Each total becomes its change since
    /// the last sample, and is left out the first time, with nothing to compare
    /// with. One that went backwards started again, as after a restart, which
    /// counts as no change. Only the totals in these rows are kept, so a row
    /// that's gone starts afresh if it comes back.
    pub fn settle(&mut self, rows: Vec<Value>) -> Vec<Value> {
        let mut seen = HashMap::with_capacity(self.0.len());
        let rows = rows
            .into_iter()
            .map(|mut row| {
                let name = row["name"].as_str().unwrap_or_default().to_string();
                let Value::Object(fields) = &mut row else {
                    return row;
                };
                let mut changes = Map::new();
                // A row that's new since the last read, whose totals were 0 then.
                let from_zero = fields.remove("from_zero").is_some();
                if let Some(Value::Object(totals)) = fields.remove("totals") {
                    for (key, total) in totals {
                        let Some(total) = total.as_f64() else {
                            continue;
                        };
                        let key = (name.clone(), key);
                        let last = self.0.get(&key).copied().or(from_zero.then_some(0.0));
                        if let Some(last) = last {
                            changes.insert(key.1.clone(), json!(change(last, total)));
                        }
                        seen.insert(key, total);
                    }
                }
                if let Some(Value::Array(averages)) = fields.remove("averages") {
                    for average in averages {
                        let (Some(key), Some(part), Some(whole), Some(scale)) = (
                            average[0].as_str(),
                            changes.get(average[1].as_str().unwrap_or_default()),
                            changes.get(average[2].as_str().unwrap_or_default()),
                            average[3].as_f64(),
                        ) else {
                            continue;
                        };
                        let (Some(part), Some(whole)) = (part.as_f64(), whole.as_f64()) else {
                            continue;
                        };
                        if whole > 0.0 {
                            fields.insert(key.to_string(), json!(part / whole * scale));
                        }
                    }
                }
                fields.extend(changes.into_iter().filter(|(key, _)| !key.starts_with('_')));
                row
            })
            .collect();
        self.0 = seen;
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_become_changes_and_averages_come_from_them() {
        let round = |hit: f64, asked: f64, other: f64| {
            let mut rows = Rows::new("orders");
            rows.main.total("hit", Some(hit));
            rows.main.total("_asked", Some(asked));
            rows.main.average("hit_rate", "hit", "_asked", 100.0);
            rows.add("standby", "b").total("sent", Some(other));
            rows.finish()
        };
        let mut settle = Settle::default();
        let first = settle.settle(round(90.0, 100.0, 5.0));
        // Nothing to compare with yet.
        assert_eq!(first[0], json!({ "name": "orders", "up": 1 }));
        assert_eq!(first[1], json!({ "name": "orders standby b" }));

        let second = settle.settle(round(180.0, 200.0, 3.0));
        assert_eq!(second[0]["hit"], 90.0);
        assert_eq!(second[0]["hit_rate"], 90.0);
        // Only there for the average.
        assert!(second[0].get("_asked").is_none());
        // It went backwards, so it started again.
        assert_eq!(second[1]["sent"], 0.0);
    }

    #[test]
    fn a_new_row_counts_its_totals_from_zero_when_told_to() {
        let mut settle = Settle::default();
        let mut rows = Rows::new("events");
        rows.main.total("seen", Some(1.0));
        settle.settle(rows.finish());
        let mut rows = Rows::new("events");
        rows.main.total("seen", Some(1.0));
        let new = rows.add("error", "TOO_MANY_PARTS");
        new.total("error_count", Some(3.0));
        new.set("from_zero", true);
        let settled = settle.settle(rows.finish());
        assert_eq!(
            settled[1],
            json!({ "name": "events error TOO_MANY_PARTS", "error_count": 3.0 })
        );
    }

    #[test]
    fn rows_are_grouped_by_their_kind() {
        let rows = vec![
            json!({ "name": "orders", "kind": "postgres", "connections": 3 }),
            json!({ "name": "orders standby b", "kind": "postgres" }),
            json!({ "name": "shop", "kind": "mysql", "connections": 5 }),
            json!({ "name": "nowhere", "up": 0 }),
        ];
        assert_eq!(
            by_kind(rows),
            json!({
                "postgres": [{ "name": "orders", "connections": 3 }, { "name": "orders standby b" }],
                "mysql": [{ "name": "shop", "connections": 5 }],
                "unknown": [{ "name": "nowhere", "up": 0 }],
            })
        );
    }

    #[test]
    fn what_couldnt_be_read_is_noted_without_stopping_the_rest() {
        let mut rows = Rows::new("orders");
        rows.missed(
            "replication slots",
            "permission denied for view pg_replication_slots",
        );
        rows.main.set("connections", 3);
        let rows = rows.finish();
        assert_eq!(rows[0]["connections"], 3);
        assert_eq!(
            rows[0]["missing"],
            "replication slots: permission denied for view pg_replication_slots"
        );
    }

    #[tokio::test]
    async fn a_database_that_isnt_there_says_why() {
        let mut check = Check::new("orders", CheckKind::Postgres, "127.0.0.1:0");
        check.timeout = Some(Duration::from_secs(2));
        let database = Database {
            check,
            credentials: Credentials {
                username: Some("maxnines".to_string()),
                ..Credentials::default()
            },
        };
        let mut reader = Reader::new("orders", database, &[]);
        let rows = reader.read(Duration::from_secs(2)).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["up"], 0);
        assert_eq!(rows[0]["kind"], "postgres");
        assert!(rows[0]["error"].is_string(), "{rows:?}");
    }
}
