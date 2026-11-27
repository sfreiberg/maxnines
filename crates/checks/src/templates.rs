//! Runs a template's SQL against a database, for agents and for the server reading
//! databases on hosts with no agent. What to run comes from the server,
//! already worked out for the database: see [`maxnines_protocol::templates::work`].
//!
//! Each statement runs on its own in a read-only transaction, with a time limit on
//! the statement and on the whole round. On PostgreSQL one that worked commits,
//! which changes nothing, as nothing could be written, but leaves the server's own
//! count of rollbacks, which a template reads, as it was. A SELECT is run as a
//! prepared statement, which a database only takes one statement at a time for, so
//! SQL with a second statement after a `;` is refused by the database itself.
//! MySQL and MariaDB only take some SHOW statements prepared, so theirs go as plain
//! text, which would run a second statement, and so are refused here if they have a
//! `;` anywhere but at the end. ClickHouse takes one statement at a time anyway.
//! What the account may read is up to whoever gave it to MaxNines.
//!
//! MongoDB isn't SQL, so a template asks it with one command, written as JSON,
//! run on the database its `$db` says, or `admin`, with the same time limit, and a
//! cursor it leaves open closed. Its reply is read by [`from_reply`]: the fields
//! each column names, from each of the rows the query says it has. MongoDB has no
//! read-only sessions, so what a command may do is the account's to say. Nor is
//! Redis, which a template asks with one of its commands, sent as its words, whose
//! reply is made a document for [`from_reply`] to read as MongoDB's is: see
//! [`redis`]. Again, what a command may do is the account's to say.
//!
//! What the account it signs in as may do is read as [`Privileges`], so an account
//! that can change things can be reported, though it's still used.
//!
//! A [`Session`] keeps its connection open between rounds, and opens a new one when
//! the old one stops working, counting each time it does, so whoever runs it can
//! tell the database may have restarted and run discovery again.

use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use maxnines_protocol::CheckKind;
use maxnines_protocol::templates::work::{QUERY_FIELD, QueryWork};
use maxnines_protocol::templates::{Path, check_command, is_show, parse_path};
use maxnines_protocol::totals::change;
use serde_json::{Map, Value, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_postgres::types::{FromSql, Type};

use crate::databases::Database;
use crate::sign_in::{
    mongodb_client, mongodb_error, mysql_connection, pg_short, postgres_client, short,
};

mod privileges;
pub mod reader;
pub mod redis;
pub use privileges::Privileges;

/// How long one statement gets before the database stops it.
pub const STATEMENT_LIMIT: Duration = Duration::from_secs(5);

/// The label every series of a database template has, saying which database.
pub const INSTANCE_LABEL: &str = "instance";

/// What one column of one row held.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Bool(bool),
    Number(f64),
    /// A length of time, such as a PostgreSQL interval or a MySQL time.
    Seconds(f64),
    Text(String),
    /// Anything else, such as a date from SQL, which a template can't use.
    Other,
    /// A MongoDB command's whole reply, which [`from_reply`] reads the columns of.
    Reply(Box<mongodb::bson::Document>),
}

/// A row's columns, by name, in order.
pub type Row = Vec<(String, Cell)>;

enum Open {
    Postgres {
        client: tokio_postgres::Client,
        running: JoinHandle<()>,
    },
    Mysql {
        connection: Box<mysql_async::Conn>,
        /// MariaDB, which answers to some things differently.
        mariadb: bool,
    },
    /// Over its HTTP interface, where every statement is a GET, which ClickHouse
    /// only lets read.
    Clickhouse(Box<crate::databases::clickhouse::Clickhouse>),
    Mongodb(mongodb::Client),
    Redis {
        connection: ::redis::aio::MultiplexedConnection,
        /// Whether the account was found unable to read what it may do on this
        /// connection, so it isn't asked again.
        account_hidden: bool,
    },
}

impl Drop for Open {
    fn drop(&mut self) {
        if let Self::Postgres { running, .. } = self {
            running.abort();
        }
    }
}

/// A database a template reads, with its connection kept between rounds.
pub struct Session {
    database: Database,
    open: Option<Open>,
    connections: u64,
}

impl Session {
    pub fn new(database: Database) -> Self {
        Self {
            database,
            open: None,
            connections: 0,
        }
    }

    /// How many times it's connected, which goes up when it has to connect again,
    /// such as after the database restarted.
    pub fn connections(&self) -> u64 {
        self.connections
    }

    /// Whether the last statement found the database answering.
    pub fn is_up(&self) -> bool {
        self.open.is_some()
    }

    /// Connects, in `limit` at most, unless it is already.
    pub async fn open(&mut self, limit: Duration) -> Result<()> {
        if self.open.is_some() {
            return Ok(());
        }
        let open = timeout(limit, self.connect())
            .await
            .map_err(|_| anyhow!("timed out"))??;
        self.open = Some(open);
        self.connections += 1;
        Ok(())
    }

    /// The rows one statement gives, in `limit` at most, connecting first if it
    /// has to.
    pub async fn run(&mut self, sql: &str, limit: Duration) -> Result<Vec<Row>> {
        match timeout(limit, self.run_or_reconnect(sql)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                // Whatever state it was left in, the next round starts afresh.
                self.open = None;
                Err(anyhow!("timed out"))
            }
        }
    }

    /// A connection kept from an earlier round may have closed since, such as by
    /// the database restarting, which is no reason to say it's down.
    async fn run_or_reconnect(&mut self, sql: &str) -> Result<Vec<Row>> {
        let reused = self.open.is_some();
        let outcome = self.run_once(sql).await;
        // The database turning the statement down says it's there, with nothing
        // more to ask it.
        if outcome.as_ref().is_err_and(|error| error.is::<Answered>()) {
            return outcome;
        }
        if outcome.is_err() && !self.alive().await {
            self.open = None;
            if reused {
                return self.run_once(sql).await;
            }
        }
        outcome
    }

    async fn alive(&mut self) -> bool {
        match &mut self.open {
            Some(Open::Postgres { client, .. }) => !client.is_closed(),
            Some(Open::Mysql { connection, .. }) => {
                use mysql_async::prelude::Queryable;
                connection.ping().await.is_ok()
            }
            Some(Open::Clickhouse(clickhouse)) => clickhouse.ping().await.is_ok(),
            Some(Open::Mongodb(client)) => mongodb_ping(client).await.is_ok(),
            Some(Open::Redis { connection, .. }) => redis::run(connection, &redis::sent(&["PING"]))
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Sees that it still answers, in `limit` at most, as a statement that reads
    /// nothing would: `SELECT 1`, or MongoDB's `ping`, or Redis' `PING`.
    pub async fn ping(&mut self, limit: Duration) -> Result<()> {
        match self.database.check.kind {
            CheckKind::Mongodb => self.run(r#"{ "ping": 1 }"#, limit).await.map(drop),
            CheckKind::Redis => self.run(&redis::sent(&["PING"]), limit).await.map(drop),
            _ => self.run("SELECT 1", limit).await.map(drop),
        }
    }

    async fn connect(&self) -> Result<Open> {
        let Database { check, credentials } = &self.database;
        match check.kind {
            CheckKind::Postgres => {
                let (client, running) =
                    postgres_client(check, credentials, check.tls == Some(true)).await?;
                client
                    .batch_execute("SET default_transaction_read_only = on")
                    .await
                    .map_err(pg_short)?;
                Ok(Open::Postgres { client, running })
            }
            CheckKind::Mysql => {
                use mysql_async::prelude::Queryable;
                let mut connection = mysql_connection(check, credentials).await?;
                let version: Option<String> = connection
                    .query_first("SELECT VERSION()")
                    .await
                    .map_err(short)?;
                let ms = STATEMENT_LIMIT.as_millis();
                let mariadb = version.is_some_and(|v| v.to_lowercase().contains("mariadb"));
                let limit = match mariadb {
                    true => format!("SET SESSION max_statement_time = {}", ms / 1000),
                    false => format!("SET SESSION max_execution_time = {ms}"),
                };
                // A statement that ends a transaction, as MySQL's DDL does, starts
                // another that's read-only too.
                for setting in [limit.as_str(), "SET SESSION TRANSACTION READ ONLY"] {
                    connection.query_drop(setting).await.map_err(short)?;
                }
                Ok(Open::Mysql {
                    connection: Box::new(connection),
                    mariadb,
                })
            }
            CheckKind::Clickhouse => {
                let mut clickhouse =
                    crate::databases::clickhouse::Clickhouse::new(check, credentials)?;
                // Which also says it can be signed in to and asked anything.
                clickhouse.limit_statements(STATEMENT_LIMIT).await?;
                Ok(Open::Clickhouse(Box::new(clickhouse)))
            }
            CheckKind::Mongodb => {
                let client = mongodb_client(check, Some(credentials))?;
                // The driver connects on first use, so this is where it signs in.
                mongodb_ping(&client).await?;
                Ok(Open::Mongodb(client))
            }
            CheckKind::Redis => Ok(Open::Redis {
                connection: redis::connect(&self.database).await?,
                account_hidden: false,
            }),
            other => bail!("templates can't read {} yet", other.as_str()),
        }
    }

    async fn run_once(&mut self, sql: &str) -> Result<Vec<Row>> {
        if self.open.is_none() {
            self.open = Some(self.connect().await?);
            self.connections += 1;
        }
        match self.open.as_mut() {
            Some(Open::Postgres { client, .. }) => run_postgres(client, sql).await,
            Some(Open::Mysql { connection, .. }) => run_mysql(connection, sql).await,
            Some(Open::Clickhouse(clickhouse)) => clickhouse.typed_rows(sql).await,
            Some(Open::Mongodb(client)) => run_mongodb(client, sql).await,
            Some(Open::Redis { connection, .. }) => redis::run(connection, sql).await,
            None => bail!("not connected"),
        }
    }
}

async fn mongodb_ping(client: &mongodb::Client) -> Result<()> {
    use mongodb::bson::doc;
    client
        .database("admin")
        .run_command(doc! { "ping": 1 })
        .await
        .map_err(|error| mongodb_error(&error))?;
    Ok(())
}

/// What one MongoDB command, written as JSON, gives: its whole reply, as one row of
/// one cell, for [`from_reply`] to read. It runs on the database its `$db` says,
/// and MongoDB stops it after [`STATEMENT_LIMIT`] unless it gives a limit of its
/// own. A cursor it leaves open, as one with more than a batch does, is closed.
async fn run_mongodb(client: &mongodb::Client, text: &str) -> Result<Vec<Row>> {
    use mongodb::bson::{Bson, Document, doc};
    let (_, database) = check_command(text).map_err(|error| anyhow!("the command {error}"))?;
    // Read in the order it's written, as a command's name comes first.
    let mut command: Document = serde_json::from_str(text)?;
    command.remove("$db");
    if !command.contains_key("maxTimeMS") {
        let limit = i64::try_from(STATEMENT_LIMIT.as_millis()).unwrap_or(i64::MAX);
        command.insert("maxTimeMS", limit);
    }
    let database = client.database(&database);
    let reply = database.run_command(command).await.map_err(|error| {
        let answered = matches!(*error.kind, mongodb::error::ErrorKind::Command(_));
        answered_if(answered, mongodb_error(&error))
    })?;
    let cursor = reply.get_document("cursor").ok();
    let open = cursor.and_then(|cursor| match cursor.get("id") {
        Some(Bson::Int64(id)) if *id != 0 => Some(*id),
        _ => None,
    });
    let collection = cursor
        .and_then(|cursor| cursor.get_str("ns").ok())
        .and_then(|ns| ns.split_once('.'))
        .map(|(_, collection)| collection.to_string());
    if let (Some(id), Some(collection)) = (open, collection) {
        // Nothing reads the rest, which the server would keep until it timed out.
        let _ = database
            .run_command(doc! { "killCursors": collection, "cursors": [id] })
            .await;
    }
    Ok(vec![vec![(
        REPLY.to_string(),
        Cell::Reply(Box::new(reply)),
    )]])
}

/// What the one cell of a MongoDB or Redis command's rows is called.
const REPLY: &str = "reply";

/// A MongoDB or Redis command's rows as a template reads them: the fields each
/// column names, by its [`Path`], in each row the query has, which `rows` says, or
/// each document of a cursor's first batch, or the whole reply. A list's items are
/// rows, and a document's fields each a row of its name, `k`, and its value, `v`,
/// as MongoDB's own `$objectToArray` has them, as are the fields of a document
/// that `[field=value]` keeps. Rows that aren't a reply's are as they are.
pub fn from_reply(
    rows: Vec<Row>,
    columns: &IndexMap<String, String>,
    rows_at: Option<&str>,
) -> Vec<Row> {
    use mongodb::bson::{Bson, Document, doc};
    let reply = match rows.as_slice() {
        [row] => match row.as_slice() {
            [(_, Cell::Reply(reply))] => reply,
            _ => return rows,
        },
        _ => return rows,
    };
    let owned: Vec<Document>;
    let documents: Vec<&Document> = match rows_at.map(parse_path) {
        Some(Ok(path)) => match at(reply, reply, &path) {
            Some(At::Value(Bson::Array(items))) => {
                owned = items
                    .iter()
                    .map(|item| match item {
                        Bson::Document(document) => document.clone(),
                        other => doc! { "v": other.clone() },
                    })
                    .collect();
                owned.iter().collect()
            }
            Some(At::Value(Bson::Document(document))) => {
                owned = document
                    .iter()
                    .map(|(name, value)| doc! { "k": name, "v": value.clone() })
                    .collect();
                owned.iter().collect()
            }
            Some(At::Kept(kept)) => kept,
            Some(At::Fields(kept)) => {
                owned = kept
                    .into_iter()
                    .map(|(name, value)| doc! { "k": name, "v": value.clone() })
                    .collect();
                owned.iter().collect()
            }
            _ => Vec::new(),
        },
        Some(Err(_)) => Vec::new(),
        None => match reply
            .get_document("cursor")
            .ok()
            .and_then(|cursor| cursor.get_array("firstBatch").ok())
        {
            Some(batch) => batch.iter().filter_map(Bson::as_document).collect(),
            None => vec![reply.as_ref()],
        },
    };
    let paths: Vec<(&String, Option<Path>)> = columns
        .iter()
        .map(|(name, path)| (name, parse_path(path).ok()))
        .collect();
    documents
        .into_iter()
        .map(|document| {
            paths
                .iter()
                .map(|(name, path)| {
                    let cell = path
                        .as_ref()
                        .and_then(|path| at(document, reply, path))
                        .map_or(Cell::Null, At::cell);
                    ((*name).clone(), cell)
                })
                .collect()
        })
        .collect()
}

/// Where a [`Path`] leads in a MongoDB reply.
enum At<'a> {
    Document(&'a mongodb::bson::Document),
    Value(&'a mongodb::bson::Bson),
    /// The documents of a list that `[field=value]` kept.
    Kept(Vec<&'a mongodb::bson::Document>),
    /// The fields of a document that `[field=value]` kept, by name.
    Fields(Vec<(&'a str, &'a mongodb::bson::Document)>),
}

impl At<'_> {
    /// What a column reads there: a list is how many it holds, and a date or a
    /// MongoDB timestamp the seconds since 1970, to work lengths of time out from.
    fn cell(self) -> Cell {
        use mongodb::bson::Bson;
        let value = match self {
            Self::Kept(kept) => return Cell::Number(kept.len() as f64),
            Self::Fields(kept) => return Cell::Number(kept.len() as f64),
            Self::Document(_) => return Cell::Other,
            Self::Value(value) => value,
        };
        match value {
            Bson::Null | Bson::Undefined => Cell::Null,
            Bson::Boolean(yes) => Cell::Bool(*yes),
            Bson::Int32(number) => Cell::Number(f64::from(*number)),
            Bson::Int64(number) => Cell::Number(*number as f64),
            Bson::Double(number) => Cell::Number(*number),
            Bson::Decimal128(number) => {
                number.to_string().parse().map_or(Cell::Other, Cell::Number)
            }
            Bson::String(text) => Cell::Text(text.clone()),
            Bson::DateTime(time) => Cell::Number(time.timestamp_millis() as f64 / 1000.0),
            Bson::Timestamp(stamp) => Cell::Number(f64::from(stamp.time)),
            Bson::Array(items) => Cell::Number(items.len() as f64),
            _ => Cell::Other,
        }
    }
}

/// Follows a path from a row, or from the whole reply for one starting `$.`.
fn at<'a>(
    row: &'a mongodb::bson::Document,
    reply: &'a mongodb::bson::Document,
    path: &Path,
) -> Option<At<'a>> {
    use mongodb::bson::Bson;
    let mut here = At::Document(if path.from_reply { reply } else { row });
    for step in &path.steps {
        let document = match here {
            At::Document(document) | At::Value(Bson::Document(document)) => document,
            At::Kept(kept) => *kept.first()?,
            At::Fields(kept) => kept.first()?.1,
            At::Value(_) => return None,
        };
        let value = document.get(&step.field)?;
        here = match &step.only {
            None => At::Value(value),
            Some((field, wanted)) => {
                let keeps = |item: &&mongodb::bson::Document| {
                    item.get(field).is_some_and(|value| is(value, wanted))
                };
                match value {
                    Bson::Array(items) => At::Kept(
                        items
                            .iter()
                            .filter_map(Bson::as_document)
                            .filter(keeps)
                            .collect(),
                    ),
                    Bson::Document(document) => At::Fields(
                        document
                            .iter()
                            .filter_map(|(name, value)| Some((name.as_str(), value.as_document()?)))
                            .filter(|(_, item)| keeps(item))
                            .collect(),
                    ),
                    _ => return None,
                }
            }
        };
    }
    Some(here)
}

/// Whether a field is what `[field=value]` says: the same text, yes or no, or
/// number.
fn is(value: &mongodb::bson::Bson, wanted: &str) -> bool {
    use mongodb::bson::Bson;
    let number = |number: f64| wanted.parse::<f64>().is_ok_and(|wanted| wanted == number);
    match value {
        Bson::String(text) => text == wanted,
        Bson::Boolean(yes) => wanted.parse::<bool>().is_ok_and(|wanted| wanted == *yes),
        Bson::Int32(n) => number(f64::from(*n)),
        Bson::Int64(n) => number(*n as f64),
        Bson::Double(n) => number(*n),
        _ => false,
    }
}

/// A statement the database turned down itself, such as for a privilege the account
/// hasn't got, which says the connection is fine.
#[derive(Debug)]
pub(crate) struct Answered(String);

impl std::fmt::Display for Answered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for Answered {}

/// `error` as it's said, marked as the database's own answer when it is one.
pub(crate) fn answered_if(answered: bool, error: anyhow::Error) -> anyhow::Error {
    match answered {
        true => anyhow::Error::new(Answered(error.to_string())),
        false => error,
    }
}

fn pg_statement(error: tokio_postgres::Error) -> anyhow::Error {
    answered_if(error.as_db_error().is_some(), pg_short(error))
}

fn mysql_statement(error: mysql_async::Error) -> anyhow::Error {
    answered_if(matches!(error, mysql_async::Error::Server(_)), short(error))
}

async fn run_postgres(client: &tokio_postgres::Client, sql: &str) -> Result<Vec<Row>> {
    client
        .batch_execute(&format!(
            "BEGIN READ ONLY; SET LOCAL statement_timeout = {}; SET LOCAL lock_timeout = 1000",
            STATEMENT_LIMIT.as_millis()
        ))
        .await
        .map_err(pg_short)?;
    let outcome = async {
        let statement = client.prepare(sql).await.map_err(pg_statement)?;
        let rows = client.query(&statement, &[]).await.map_err(pg_statement)?;
        let names: Vec<String> = statement
            .columns()
            .iter()
            .map(|column| column.name().to_string())
            .collect();
        let mut read = Vec::with_capacity(rows.len());
        for row in rows {
            let mut cells = Vec::with_capacity(names.len());
            for (index, name) in names.iter().enumerate() {
                cells.push((name.clone(), row.try_get::<_, Cell>(index)?));
            }
            read.push(cells);
        }
        anyhow::Ok(read)
    }
    .await;
    // Nothing was written, as nothing could be in a read-only transaction. A read
    // that worked commits, as one outside a transaction would, so the server's own
    // count of rollbacks, which a template reads, isn't one for each statement it
    // runs. One that failed is rolled back either way.
    let end = if outcome.is_ok() {
        "COMMIT"
    } else {
        "ROLLBACK"
    };
    // A statement that failed says why, even if what ends the transaction fails
    // too, as it does once the connection has gone.
    let ended = client.batch_execute(end).await.map_err(pg_short);
    let read = outcome?;
    ended?;
    Ok(read)
}

impl<'a> FromSql<'a> for Cell {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        let cell = if *ty == Type::BOOL {
            Cell::Bool(bool::from_sql(ty, raw)?)
        } else if *ty == Type::INT2 {
            Cell::Number(f64::from(i16::from_sql(ty, raw)?))
        } else if *ty == Type::INT4 {
            Cell::Number(f64::from(i32::from_sql(ty, raw)?))
        } else if *ty == Type::INT8 {
            Cell::Number(i64::from_sql(ty, raw)? as f64)
        } else if *ty == Type::OID {
            Cell::Number(f64::from(u32::from_sql(ty, raw)?))
        } else if *ty == Type::FLOAT4 {
            Cell::Number(f64::from(f32::from_sql(ty, raw)?))
        } else if *ty == Type::FLOAT8 {
            Cell::Number(f64::from_sql(ty, raw)?)
        } else if *ty == Type::NUMERIC {
            numeric(raw).map_or(Cell::Other, Cell::Number)
        } else if *ty == Type::INTERVAL {
            interval(raw).map_or(Cell::Other, Cell::Seconds)
        } else if [
            Type::TEXT,
            Type::VARCHAR,
            Type::BPCHAR,
            Type::NAME,
            Type::UNKNOWN,
        ]
        .contains(ty)
        {
            Cell::Text(std::str::from_utf8(raw)?.to_string())
        } else {
            Cell::Other
        };
        Ok(cell)
    }

    fn from_sql_null(_: &Type) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Cell::Null)
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

/// PostgreSQL's binary numeric: how many base-10000 digits, the weight of the
/// first, the sign, the scale, then the digits.
fn numeric(raw: &[u8]) -> Option<f64> {
    let word = |at: usize| Some([*raw.get(at)?, *raw.get(at + 1)?]);
    let digits = i16::from_be_bytes(word(0)?);
    let weight = i16::from_be_bytes(word(2)?);
    let sign = u16::from_be_bytes(word(4)?);
    // Not a number, or infinite.
    if sign == 0xC000 || sign >= 0xD000 {
        return None;
    }
    let mut value = 0.0;
    for index in 0..usize::try_from(digits).ok()? {
        let digit = i16::from_be_bytes(word(8 + index * 2)?);
        let power = i32::from(weight) - i32::try_from(index).ok()?;
        value += f64::from(digit) * 10_000_f64.powi(power);
    }
    Some(if sign == 0x4000 { -value } else { value })
}

/// PostgreSQL's binary interval: microseconds, days and months, a month being
/// thirty days as PostgreSQL's own `extract(epoch …)` has it.
fn interval(raw: &[u8]) -> Option<f64> {
    let micros = i64::from_be_bytes(raw.get(0..8)?.try_into().ok()?);
    let days = i32::from_be_bytes(raw.get(8..12)?.try_into().ok()?);
    let months = i32::from_be_bytes(raw.get(12..16)?.try_into().ok()?);
    Some(micros as f64 / 1e6 + f64::from(days) * 86_400.0 + f64::from(months) * 30.0 * 86_400.0)
}

/// One statement, read-only as the whole session is, with no transaction of its own
/// to commit or roll back, as MySQL counts both, and a template reads those counts.
async fn run_mysql(connection: &mut mysql_async::Conn, sql: &str) -> Result<Vec<Row>> {
    use mysql_async::prelude::Queryable;
    // MySQL takes only some SHOW statements prepared, such as not SHOW WARNINGS,
    // and MariaDB before 10.6 fewer, so a SHOW goes as plain text, which runs every
    // statement it's given: one with a `;` before its end could run another.
    let show = is_show(sql);
    let sql = sql.trim_end().trim_end_matches(';');
    if show && sql.contains(';') {
        bail!("a SHOW statement can't have a ; before its end");
    }
    let read: Vec<mysql_async::Row> = match show {
        true => connection.query(sql).await,
        false => connection.exec(sql, ()).await,
    }
    .map_err(mysql_statement)?;
    Ok(read.into_iter().map(mysql_row).collect())
}

fn mysql_row(row: mysql_async::Row) -> Row {
    use mysql_async::Value as My;
    use mysql_async::consts::ColumnType;

    let columns = row.columns();
    columns
        .iter()
        .zip(row.unwrap())
        .map(|(column, value)| {
            let cell = match value {
                My::NULL => Cell::Null,
                My::Int(number) => Cell::Number(number as f64),
                My::UInt(number) => Cell::Number(number as f64),
                My::Float(number) => Cell::Number(f64::from(number)),
                My::Double(number) => Cell::Number(number),
                My::Time(negative, days, hours, minutes, seconds, micros) => {
                    let secs = f64::from(days) * 86_400.0
                        + f64::from(hours) * 3_600.0
                        + f64::from(minutes) * 60.0
                        + f64::from(seconds)
                        + f64::from(micros) / 1e6;
                    Cell::Seconds(if negative { -secs } else { secs })
                }
                My::Date(..) => Cell::Other,
                // As a prepared statement gives decimals, and plain text gives
                // everything.
                My::Bytes(bytes) => match column.column_type() {
                    ColumnType::MYSQL_TYPE_DECIMAL
                    | ColumnType::MYSQL_TYPE_NEWDECIMAL
                    | ColumnType::MYSQL_TYPE_TINY
                    | ColumnType::MYSQL_TYPE_SHORT
                    | ColumnType::MYSQL_TYPE_INT24
                    | ColumnType::MYSQL_TYPE_LONG
                    | ColumnType::MYSQL_TYPE_LONGLONG
                    | ColumnType::MYSQL_TYPE_YEAR
                    | ColumnType::MYSQL_TYPE_FLOAT
                    | ColumnType::MYSQL_TYPE_DOUBLE => String::from_utf8_lossy(&bytes)
                        .parse()
                        .map_or(Cell::Other, Cell::Number),
                    ColumnType::MYSQL_TYPE_TIME => mysql_time(&String::from_utf8_lossy(&bytes))
                        .map_or(Cell::Other, Cell::Seconds),
                    ColumnType::MYSQL_TYPE_BIT => Cell::Number(
                        bytes
                            .iter()
                            .fold(0_u64, |total, byte| (total << 8) | u64::from(*byte))
                            as f64,
                    ),
                    _ => Cell::Text(String::from_utf8_lossy(&bytes).into_owned()),
                },
            };
            (column.name_str().into_owned(), cell)
        })
        .collect()
}

/// A MySQL time written out, as `[-]838:59:59.000000`, in seconds.
fn mysql_time(text: &str) -> Option<f64> {
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let mut parts = text.split(':');
    let hours: f64 = parts.next()?.parse().ok()?;
    let minutes: f64 = parts.next()?.parse().ok()?;
    let seconds: f64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let secs = hours * 3_600.0 + minutes * 60.0 + seconds;
    Some(if negative { -secs } else { secs })
}

/// A SHOW statement's rows as a template reads them: only the columns it names,
/// each under the name it gives it, with yes and no as true and false and numbers
/// written as text as numbers, and rows with the same labels added up, such as
/// every binary log's size. Any other statement's rows are as they are.
pub fn picked(rows: Vec<Row>, query: &QueryWork) -> Vec<Row> {
    if is_reply(&rows) {
        return from_reply(rows, &query.columns, query.rows.as_deref());
    }
    if query.columns.is_empty() {
        return rows;
    }
    let labels = |row: &Row| -> Vec<LabelKey> {
        query
            .labels
            .iter()
            .map(|label| {
                let found = row.iter().find(|(name, _)| name == label);
                found.map_or(LabelKey::Null, |(_, cell)| LabelKey::of(cell))
            })
            .collect()
    };
    // By their labels, so rows to add up are found at once however many there are.
    let mut picked: IndexMap<Vec<LabelKey>, Row> = IndexMap::new();
    for row in rows {
        let one: Row = query
            .columns
            .iter()
            .map(|(name, column)| {
                let found = row
                    .iter()
                    .find(|(have, _)| have.eq_ignore_ascii_case(column))
                    .map_or(Cell::Null, |(_, cell)| cell.clone());
                let cell = match query.labels.contains(name) {
                    true => found,
                    false => shown_as_value(found),
                };
                (name.clone(), cell)
            })
            .collect();
        match picked.entry(labels(&one)) {
            indexmap::map::Entry::Occupied(mut seen) => {
                for ((_, total), (_, cell)) in seen.get_mut().iter_mut().zip(one) {
                    if let (Cell::Number(total), Cell::Number(more)) = (total, cell) {
                        *total += more;
                    }
                }
            }
            indexmap::map::Entry::Vacant(new) => {
                new.insert(one);
            }
        }
    }
    picked.into_values().collect()
}

/// A label's cell as something rows can be grouped by, equal where the cells are.
#[derive(PartialEq, Eq, Hash)]
enum LabelKey {
    Null,
    Bool(bool),
    Number(u64),
    Seconds(u64),
    Text(String),
    Other,
}

impl LabelKey {
    fn of(cell: &Cell) -> Self {
        // Zero is zero whatever its sign, as the cells compare.
        let bits = |number: f64| if number == 0.0 { 0 } else { number.to_bits() };
        match cell {
            Cell::Null => Self::Null,
            Cell::Bool(value) => Self::Bool(*value),
            Cell::Number(number) => Self::Number(bits(*number)),
            Cell::Seconds(seconds) => Self::Seconds(bits(*seconds)),
            Cell::Text(text) => Self::Text(text.clone()),
            Cell::Other | Cell::Reply(_) => Self::Other,
        }
    }
}

/// Whether rows are a MongoDB command's reply.
pub fn is_reply(rows: &[Row]) -> bool {
    matches!(rows, [row] if matches!(row.as_slice(), [(_, Cell::Reply(_))]))
}

/// What a SHOW statement says in words as a template can read it: yes or no, or a
/// number. A replica's connection still being made isn't one that's up.
fn shown_as_value(cell: Cell) -> Cell {
    let Cell::Text(text) = cell else {
        return cell;
    };
    match text.trim().to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" => Cell::Bool(true),
        "no" | "off" | "false" | "connecting" => Cell::Bool(false),
        other => other.parse().map_or(Cell::Text(text), Cell::Number),
    }
}

/// What discovery found: the first row's columns, by name.
pub fn discovered(rows: &[Row]) -> Map<String, Value> {
    let Some(row) = rows.first() else {
        return Map::new();
    };
    row.iter()
        .filter_map(|(name, cell)| {
            let value = match cell {
                Cell::Null => Value::Null,
                Cell::Bool(yes) => json!(yes),
                Cell::Number(number) | Cell::Seconds(number) => json!(number),
                Cell::Text(text) => json!(text),
                Cell::Other | Cell::Reply(_) => return None,
            };
            Some((name.clone(), value))
        })
        .collect()
}

/// Each running total's last reading, by its series and column, which turns the
/// next into the change since.
#[derive(Debug, Default)]
pub struct Totals(HashMap<String, f64>);

/// A query's rows as a template's sample has them: each row's numbers, yes or no
/// as 1 or 0 and lengths of time in seconds, labelled by the database and the
/// query's label columns. Running totals are the change since the last read, so
/// the first read leaves them out. Text that isn't a label, NULLs and the columns the
/// query says to leave out give nothing. Each row says which query it's from.
pub fn metric_rows(
    rows: &[Row],
    query: &QueryWork,
    database: &str,
    totals: &mut Totals,
) -> Vec<Value> {
    let mut seen = HashMap::new();
    let mut read = Vec::with_capacity(rows.len());
    for row in rows {
        let mut labels = Map::new();
        labels.insert(INSTANCE_LABEL.to_string(), json!(database));
        for label in &query.labels {
            let value = match row
                .iter()
                .find(|(name, _)| name == label)
                .map(|(_, cell)| cell)
            {
                Some(Cell::Text(text)) => text.clone(),
                Some(Cell::Number(number) | Cell::Seconds(number)) => number.to_string(),
                Some(Cell::Bool(yes)) => yes.to_string(),
                _ => String::new(),
            };
            labels.insert(label.clone(), json!(value));
        }
        let series = Value::Object(labels.clone()).to_string();
        let mut numbers = Map::new();
        for (name, cell) in row {
            if query.labels.contains(name)
                || query.omit.contains(name)
                || name == INSTANCE_LABEL
                || name == "labels"
                || name == QUERY_FIELD
            {
                continue;
            }
            let value = match cell {
                Cell::Bool(yes) => f64::from(u8::from(*yes)),
                Cell::Number(number) | Cell::Seconds(number) => *number,
                _ => continue,
            };
            if !value.is_finite() {
                continue;
            }
            if query.totals.contains(name) {
                let key = format!("{series}\n{name}");
                let last = totals.0.get(&key).copied();
                seen.insert(key, value);
                match last {
                    Some(last) => numbers.insert(name.clone(), json!(change(last, value))),
                    None => continue,
                };
            } else {
                numbers.insert(name.clone(), json!(value));
            }
        }
        if !numbers.is_empty() {
            numbers.insert("labels".to_string(), Value::Object(labels));
            numbers.insert(QUERY_FIELD.to_string(), json!(query.key));
            read.push(Value::Object(numbers));
        }
    }
    // A series that's gone starts again from nothing if it comes back.
    totals.0 = seen;
    read
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Credentials;

    #[test]
    fn numbers_and_lengths_of_time_read_from_postgres_binary() {
        // 12345.678: digits 1, 2345, 6780; weight 1; positive; scale 3.
        let mut raw = Vec::new();
        for word in [3_i16, 1, 0, 3, 1, 2345, 6780] {
            raw.extend(word.to_be_bytes());
        }
        assert!((numeric(&raw).unwrap() - 12_345.678).abs() < 1e-9);
        raw[4..6].copy_from_slice(&0x4000_u16.to_be_bytes());
        assert!((numeric(&raw).unwrap() + 12_345.678).abs() < 1e-9);
        raw[4..6].copy_from_slice(&0xC000_u16.to_be_bytes());
        assert_eq!(numeric(&raw), None);

        let mut raw = Vec::new();
        raw.extend(1_500_000_i64.to_be_bytes());
        raw.extend(1_i32.to_be_bytes());
        raw.extend(0_i32.to_be_bytes());
        assert_eq!(interval(&raw), Some(86_401.5));
    }

    fn query(labels: &[&str], totals: &[&str]) -> QueryWork {
        QueryWork {
            key: "q".to_string(),
            sql: "SELECT".to_string(),
            rows: None,
            interval: None,
            labels: labels.iter().map(|l| (*l).to_string()).collect(),
            columns: Default::default(),
            totals: totals.iter().map(|t| (*t).to_string()).collect(),
            omit: vec!["later".to_string()],
        }
    }

    fn row(cells: &[(&str, Cell)]) -> Row {
        cells
            .iter()
            .map(|(name, cell)| ((*name).to_string(), cell.clone()))
            .collect()
    }

    #[test]
    fn rows_become_labelled_numbers_with_totals_as_changes() {
        let query = query(&["slot"], &["sent"]);
        let mut totals = Totals::default();
        let round = |sent: f64, totals: &mut Totals| {
            let rows = [
                row(&[
                    ("slot", Cell::Text("a".into())),
                    ("active", Cell::Bool(true)),
                    ("lag", Cell::Seconds(2.5)),
                    ("sent", Cell::Number(sent)),
                    ("note", Cell::Text("words".into())),
                    ("later", Cell::Number(5.0)),
                    ("gone", Cell::Null),
                ]),
                row(&[("slot", Cell::Text("b".into())), ("lag", Cell::Null)]),
            ];
            metric_rows(&rows, &query, "orders", totals)
        };
        // The first read has no change to give, and a row with nothing is left out.
        assert_eq!(
            round(100.0, &mut totals),
            [json!({
                "labels": { "instance": "orders", "slot": "a" },
                "_query": "q",
                "active": 1.0,
                "lag": 2.5,
            })]
        );
        assert_eq!(round(130.0, &mut totals)[0]["sent"], 30.0);
        // A total that went back started again.
        assert_eq!(round(10.0, &mut totals)[0]["sent"], 0.0);
    }

    #[test]
    fn discovery_finds_the_first_rows_columns() {
        let rows = [row(&[
            ("version", Cell::Text("16.4".into())),
            ("replica", Cell::Bool(false)),
            ("when", Cell::Other),
        ])];
        assert_eq!(
            Value::Object(discovered(&rows)),
            json!({ "version": "16.4", "replica": false })
        );
        assert!(discovered(&[]).is_empty());
    }

    /// A MongoDB reply, as a command's rows hold it.
    fn reply(document: mongodb::bson::Document) -> Vec<Row> {
        vec![vec![(REPLY.to_string(), Cell::Reply(Box::new(document)))]]
    }

    fn named(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs
            .iter()
            .map(|(name, path)| (name.to_string(), path.to_string()))
            .collect()
    }

    #[test]
    fn a_mongodb_reply_is_read_as_its_columns_say() {
        use mongodb::bson::{DateTime, Timestamp, doc};
        let at = |secs: i64| DateTime::from_millis(secs * 1000);
        let status = doc! {
            "connections": { "current": 3, "available": 97_i64 },
            "repl": { "secondary": false, "setName": "rs0" },
            "mem": { "resident": 2.5 },
            "oplog": { "latestOptime": Timestamp { time: 1_000, increment: 1 } },
            "opcounters": { "insert": 5, "query": 7 },
            "members": [
                { "name": "a:1", "state": 1, "health": 1.0, "optimeDate": at(100), "self": true },
                { "name": "b:1", "state": 2, "health": 1.0, "optimeDate": at(90) },
                { "name": "c:1", "state": 8, "health": 0.0, "optimeDate": at(0) },
            ],
        };
        // One row, the whole reply.
        let rows = from_reply(
            reply(status.clone()),
            &named(&[
                ("connections", "connections.current"),
                ("available", "connections.available"),
                ("replica", "repl.secondary"),
                ("set", "repl.setName"),
                ("_resident", "mem.resident"),
                ("latest", "oplog.latestOptime"),
                ("members", "members"),
                ("healthy", "members[health=1]"),
                ("primaries", "members[state=1]"),
                ("leader", "members[state=1].optimeDate"),
                ("me", "members[self=true].name"),
                ("missing", "connections.rejected"),
                ("nested", "connections"),
            ]),
            None,
        );
        assert_eq!(
            rows,
            vec![vec![
                ("connections".to_string(), Cell::Number(3.0)),
                ("available".to_string(), Cell::Number(97.0)),
                ("replica".to_string(), Cell::Bool(false)),
                ("set".to_string(), Cell::Text("rs0".to_string())),
                ("_resident".to_string(), Cell::Number(2.5)),
                ("latest".to_string(), Cell::Number(1000.0)),
                ("members".to_string(), Cell::Number(3.0)),
                ("healthy".to_string(), Cell::Number(2.0)),
                ("primaries".to_string(), Cell::Number(1.0)),
                ("leader".to_string(), Cell::Number(100.0)),
                ("me".to_string(), Cell::Text("a:1".to_string())),
                ("missing".to_string(), Cell::Null),
                ("nested".to_string(), Cell::Other),
            ]]
        );

        // A row for each of a list's items, with the whole reply under `$.`.
        let members = from_reply(
            reply(status.clone()),
            &named(&[
                ("member", "name"),
                ("optime", "optimeDate"),
                ("leader", "$.members[state=1].optimeDate"),
            ]),
            Some("members"),
        );
        assert_eq!(members.len(), 3);
        assert_eq!(members[1][0].1, Cell::Text("b:1".to_string()));
        assert_eq!(members[1][1].1, Cell::Number(90.0));
        assert_eq!(members[1][2].1, Cell::Number(100.0));
        // Or only the items kept.
        let secondaries = from_reply(
            reply(status.clone()),
            &named(&[("member", "name")]),
            Some("members[state=2]"),
        );
        assert_eq!(
            secondaries,
            vec![vec![("member".to_string(), Cell::Text("b:1".to_string()))]]
        );
        // A row for each of a document's fields.
        let operations = from_reply(
            reply(status),
            &named(&[("operation", "k"), ("count", "v")]),
            Some("opcounters"),
        );
        assert_eq!(
            operations,
            vec![
                vec![
                    ("operation".to_string(), Cell::Text("insert".to_string())),
                    ("count".to_string(), Cell::Number(5.0))
                ],
                vec![
                    ("operation".to_string(), Cell::Text("query".to_string())),
                    ("count".to_string(), Cell::Number(7.0))
                ],
            ]
        );
        // A cursor's first batch is its rows.
        let cursor = doc! { "cursor": { "id": 0_i64, "ns": "admin.$cmd.aggregate", "firstBatch": [{ "oldest": 4 }, { "oldest": 9 }] }, "ok": 1.0 };
        let oldest = from_reply(reply(cursor), &named(&[("oldest", "oldest")]), None);
        assert_eq!(oldest.len(), 2);
        assert_eq!(oldest[1][0].1, Cell::Number(9.0));
        // Rows that aren't a reply's are left as they are.
        let sql = vec![vec![("one".to_string(), Cell::Number(1.0))]];
        assert_eq!(
            from_reply(sql.clone(), &named(&[("one", "two")]), None),
            sql
        );
    }

    /// A statement PostgreSQL turns down is its answer, which needs no ping to see
    /// the connection is still there. A real one, from
    /// `MAXNINES_TEST_CHECK_POSTGRES`, as `host:port username [password]`.
    #[tokio::test]
    async fn a_statement_the_database_turns_down_is_its_answer() {
        let Ok(value) = std::env::var("MAXNINES_TEST_CHECK_POSTGRES") else {
            return;
        };
        let mut words = value.split_whitespace();
        let target = words.next().unwrap();
        let mut session = Session::new(Database {
            check: maxnines_protocol::Check::new("real", CheckKind::Postgres, target),
            credentials: Credentials {
                username: words.next().map(String::from),
                password: words.next().map(String::from),
                private_key: None,
            },
        });
        session.run("SELECT 1", LIMIT).await.unwrap();
        for _ in 0..2 {
            let error = session
                .run("SELECT * FROM no_such_table", LIMIT)
                .await
                .unwrap_err();
            assert!(error.is::<Answered>(), "{error:#}");
            assert!(error.to_string().contains("no_such_table"), "{error:#}");
        }
        session.run("SELECT 1", LIMIT).await.unwrap();
        assert_eq!(session.connections(), 1);

        // One that can't be reached never is.
        let mut nowhere = Session::new(Database {
            check: maxnines_protocol::Check::new("nowhere", CheckKind::Postgres, "127.0.0.1:1"),
            credentials: Credentials::default(),
        });
        let error = nowhere.run("SELECT 1", LIMIT).await.unwrap_err();
        assert!(!error.is::<Answered>(), "{error:#}");
    }

    /// This session's commits and rollbacks, as MySQL counts them.
    async fn mysql_counts(session: &mut Session) -> Vec<Vec<Row>> {
        let mut both = Vec::new();
        for name in ["Com_rollback", "Com_commit"] {
            let sql = format!("SHOW SESSION STATUS LIKE '{name}'");
            both.push(session.run(&sql, LIMIT).await.unwrap());
        }
        both
    }

    /// Reading adds nothing to MySQL's own counts of commits and rollbacks, which a
    /// template reads. A real one, from `MAXNINES_TEST_CHECK_MYSQL`, as `host:port
    /// username [password]`.
    #[tokio::test]
    async fn reading_mysql_neither_commits_nor_rolls_back() {
        let Ok(value) = std::env::var("MAXNINES_TEST_CHECK_MYSQL") else {
            return;
        };
        let mut words = value.split_whitespace();
        let target = words.next().unwrap();
        let mut session = Session::new(Database {
            check: maxnines_protocol::Check::new("real", CheckKind::Mysql, target),
            credentials: Credentials {
                username: words.next().map(String::from),
                password: words.next().map(String::from),
                private_key: None,
            },
        });
        let before = mysql_counts(&mut session).await;
        for _ in 0..3 {
            session.run("SELECT 1", LIMIT).await.unwrap();
        }
        assert_eq!(mysql_counts(&mut session).await, before);
        // Still read-only.
        let error = session
            .run("SELECT * FROM mysql.user FOR UPDATE", LIMIT)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("READ ONLY"), "{error:#}");
    }

    /// A real MongoDB, from `MAXNINES_TEST_CHECK_MONGODB`, as `host:port [username
    /// password]`, which the tests read and never change.
    fn real_mongodb() -> Option<Session> {
        let value = std::env::var("MAXNINES_TEST_CHECK_MONGODB").ok()?;
        let mut words = value.split_whitespace();
        Some(Session::new(Database {
            check: maxnines_protocol::Check::new("real", CheckKind::Mongodb, words.next()?),
            credentials: Credentials {
                username: words.next().map(String::from),
                password: words.next().map(String::from),
                private_key: None,
            },
        }))
    }

    #[tokio::test]
    async fn a_real_mongodb_is_asked_commands() {
        let Some(mut session) = real_mongodb() else {
            return;
        };
        let rows = session.run(r#"{ "buildInfo": 1 }"#, LIMIT).await.unwrap();
        let found = discovered(&from_reply(rows, &named(&[("version", "version")]), None));
        assert!(found["version"].is_string(), "{found:?}");
        assert_eq!(session.connections(), 1);

        // A command whose cursor is left open, which is closed, as nothing reads
        // the rest of it.
        let rows = session
            .run(
                r#"{ "aggregate": 1, "$db": "admin", "pipeline": [{ "$currentOp": { "idleConnections": true } }], "cursor": { "batchSize": 1 } }"#,
                LIMIT,
            )
            .await
            .unwrap();
        let [row] = rows.as_slice() else {
            panic!("{rows:?}");
        };
        let Cell::Reply(reply) = &row[0].1 else {
            panic!("{row:?}");
        };
        let id = reply.get_document("cursor").unwrap().get_i64("id").unwrap();
        assert_ne!(id, 0, "{reply:?}");
        let more = session
            .run(
                &format!(r#"{{ "getMore": {{ "$numberLong": "{id}" }}, "collection": "$cmd.aggregate" }}"#),
                LIMIT,
            )
            .await
            .unwrap_err();
        assert!(format!("{more}").contains("cursor"), "{more}");

        // MongoDB stops one that runs too long, and says why.
        let error = session
            .run(
                r#"{ "aggregate": 1, "pipeline": [{ "$currentOp": {} }], "cursor": {}, "maxTimeMS": 1 }"#,
                LIMIT,
            )
            .await;
        if let Err(error) = error {
            assert!(!format!("{error}").is_empty());
        }
        // What isn't a command isn't run.
        let error = session.run("SELECT 1", LIMIT).await.unwrap_err();
        assert!(format!("{error}").contains("isn't one command"), "{error}");
        session.ping(LIMIT).await.unwrap();
        assert_eq!(session.connections(), 1);

        let privileges = session.privileges().await.unwrap();
        // Whatever the account is, a superuser may do anything.
        assert!(!privileges.superuser || privileges.writes && privileges.manages);
    }

    /// A real server, from `MAXNINES_TEST_CHECK_POSTGRES` or `_MYSQL`, as
    /// `host:port username [password]`.
    fn real(variable: &str, kind: CheckKind) -> Option<Session> {
        let value = std::env::var(variable).ok()?;
        let mut words = value.split_whitespace();
        let (target, username) = (words.next()?, words.next()?);
        Some(Session::new(Database {
            check: maxnines_protocol::Check::new("real", kind, target),
            credentials: Credentials {
                username: Some(username.to_string()),
                password: words.next().map(String::from),
                private_key: None,
            },
        }))
    }

    const LIMIT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn a_real_postgres_is_read_and_can_not_be_written() {
        let Some(mut session) = real("MAXNINES_TEST_CHECK_POSTGRES", CheckKind::Postgres) else {
            return;
        };
        let rows = session
            .run(
                "SELECT current_setting('server_version') AS version, \
                        pg_is_in_recovery() AS replica, \
                        interval '1 minute 30 seconds' AS waited, \
                        12.5::numeric AS ratio, 7::int8 AS count, NULL::int AS nothing",
                LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(session.connections(), 1);
        let found = discovered(&rows);
        assert!(found["version"].is_string(), "{found:?}");
        assert_eq!(found["replica"], false);
        assert_eq!(found["waited"], 90.0);
        assert_eq!(found["ratio"], 12.5);
        assert_eq!(found["count"], 7.0);
        assert_eq!(found["nothing"], Value::Null);

        // Nothing can be written, and only one statement runs at a time.
        let error = session
            .run("CREATE TABLE maxnines_should_not_exist (id int)", LIMIT)
            .await
            .unwrap_err();
        assert!(format!("{error}").contains("read-only"), "{error}");
        let error = session.run("SELECT 1; SELECT 2", LIMIT).await.unwrap_err();
        assert!(format!("{error}").contains("multiple commands"), "{error}");
        // Neither cost the connection.
        session.run("SELECT 1 AS one", LIMIT).await.unwrap();
        assert_eq!(session.connections(), 1);
        assert!(session.is_up());

        // A SHOW runs as any statement does.
        let shown = session.run("SHOW server_version", LIMIT).await.unwrap();
        assert!(matches!(&shown[0][0].1, Cell::Text(_)), "{shown:?}");

        // A statement that runs too long is stopped by the database.
        let error = session.run("SELECT pg_sleep(30)", LIMIT).await.unwrap_err();
        assert!(format!("{error}").contains("statement timeout"), "{error}");
    }

    #[test]
    fn a_mysql_time_written_out_is_seconds() {
        assert_eq!(mysql_time("00:01:30"), Some(90.0));
        assert_eq!(mysql_time("-838:59:59.5"), Some(-3_020_399.5));
        assert_eq!(mysql_time("01:30"), None);
        assert_eq!(mysql_time("soon"), None);
    }

    #[test]
    fn a_show_statements_columns_are_picked_named_and_added_up() {
        let mut query = query(&["channel"], &[]);
        query.columns = [
            ("channel", "Channel_Name"),
            ("receiving", "Replica_IO_Running"),
            ("behind", "Seconds_Behind_Source"),
        ]
        .into_iter()
        .map(|(name, column)| (name.to_string(), column.to_string()))
        .collect();
        let row = |channel: &str, running: &str, behind: Cell| -> Row {
            vec![
                ("Channel_Name".to_string(), Cell::Text(channel.to_string())),
                (
                    "Replica_IO_Running".to_string(),
                    Cell::Text(running.to_string()),
                ),
                ("Seconds_Behind_Source".to_string(), behind),
                ("Exec_Source_Log_Pos".to_string(), Cell::Number(1.0)),
            ]
        };
        let rows = picked(
            vec![
                row("", "Yes", Cell::Text("3".to_string())),
                row("east", "Connecting", Cell::Null),
            ],
            &query,
        );
        assert_eq!(
            rows,
            [
                vec![
                    ("channel".to_string(), Cell::Text(String::new())),
                    ("receiving".to_string(), Cell::Bool(true)),
                    ("behind".to_string(), Cell::Number(3.0)),
                ],
                vec![
                    ("channel".to_string(), Cell::Text("east".to_string())),
                    ("receiving".to_string(), Cell::Bool(false)),
                    ("behind".to_string(), Cell::Null),
                ],
            ]
        );

        // Rows with the same labels add up, as every binary log's size does.
        let mut logs = query.clone();
        logs.labels.clear();
        logs.columns = [("binlog_size".to_string(), "File_size".to_string())]
            .into_iter()
            .collect();
        let log = |size: f64| -> Row { vec![("File_size".to_string(), Cell::Number(size))] };
        assert_eq!(
            picked(vec![log(100.0), log(23.0)], &logs),
            [vec![("binlog_size".to_string(), Cell::Number(123.0))]]
        );
    }

    #[tokio::test]
    async fn a_real_mysql_runs_show_statements() {
        let Some(mut session) = real("MAXNINES_TEST_CHECK_MYSQL", CheckKind::Mysql) else {
            return;
        };
        let rows = session.run("SHOW BINARY LOGS", LIMIT).await.unwrap();
        let mut query = query(&[], &[]);
        query.columns = [("binlog_size".to_string(), "File_size".to_string())]
            .into_iter()
            .collect();
        let picked = picked(rows, &query);
        assert_eq!(picked.len(), 1, "{picked:?}");
        assert!(
            matches!(picked[0][0].1, Cell::Number(size) if size > 0.0),
            "{picked:?}"
        );
        // A replica's status runs too, with no rows on a server that isn't one.
        session.run("SHOW REPLICA STATUS", LIMIT).await.unwrap();
        // So does one neither takes as a prepared statement, with its numbers as
        // numbers, and one ending in a `;`.
        let warnings = session.run("SHOW WARNINGS", LIMIT).await.unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let counted = session.run("SHOW COUNT(*) WARNINGS;", LIMIT).await.unwrap();
        assert_eq!(counted[0][0].1, Cell::Number(0.0), "{counted:?}");
        // Plain text runs every statement it's given, so a second is refused.
        let error = session
            .run("SHOW WARNINGS; SET SESSION TRANSACTION READ WRITE", LIMIT)
            .await
            .unwrap_err();
        assert!(format!("{error}").contains("can't have a ;"), "{error}");
        assert_eq!(session.connections(), 1);
    }

    #[tokio::test]
    async fn a_real_clickhouse_is_read_and_can_not_be_written() {
        let Some(mut session) = real("MAXNINES_TEST_CHECK_CLICKHOUSE", CheckKind::Clickhouse)
        else {
            return;
        };
        let rows = session
            .run(
                "SELECT version() AS version, uptime() AS uptime, true AS yes, \
                 toUInt8(1) AS flag, 12.5 AS ratio, toInt64(-7) AS count, \
                 0 / 0 AS not_a_number, CAST(NULL, 'Nullable(UInt64)') AS nothing, \
                 today() AS day",
                LIMIT,
            )
            .await
            .unwrap();
        let found = discovered(&rows);
        assert!(found["version"].is_string(), "{found:?}");
        assert!(found["uptime"].as_f64().unwrap() >= 0.0, "{found:?}");
        assert_eq!(found["yes"], true);
        assert_eq!(found["flag"], 1.0);
        assert_eq!(found["ratio"], 12.5);
        assert_eq!(found["count"], -7.0);
        assert_eq!(found["not_a_number"], Value::Null);
        assert_eq!(found["nothing"], Value::Null);
        // A date isn't anything a template can use.
        assert!(found.get("day").is_none(), "{found:?}");

        // Every statement is a GET, which ClickHouse only lets read.
        let error = session
            .run(
                "CREATE TABLE maxnines_should_not_exist (id UInt8) ENGINE = Memory",
                LIMIT,
            )
            .await
            .unwrap_err();
        assert!(format!("{error}").contains("readonly"), "{error}");
        session.run("SELECT 1 AS one", LIMIT).await.unwrap();
        assert!(session.is_up());
        let shown = session.run("SHOW DATABASES", LIMIT).await.unwrap();
        assert!(!shown.is_empty());
        // SQL that ends in a `;` or a comment runs as it would anywhere else.
        session.run("SELECT 1 AS one;", LIMIT).await.unwrap();
        session
            .run("SELECT 1 AS one -- a note", LIMIT)
            .await
            .unwrap();

        // A statement that runs too long is stopped by ClickHouse, rather than left
        // running once the round gives up on it.
        let error = session
            .run(
                "SELECT count() AS found FROM numbers(1000000000000) WHERE sipHash64(number) = 0",
                LIMIT,
            )
            .await
            .unwrap_err();
        assert!(format!("{error}").contains("Timeout exceeded"), "{error}");
    }

    #[tokio::test]
    async fn a_real_mysql_is_read_and_can_not_be_written() {
        let Some(mut session) = real("MAXNINES_TEST_CHECK_MYSQL", CheckKind::Mysql) else {
            return;
        };
        let rows = session
            .run(
                "SELECT VERSION() AS version, 1 = 1 AS yes, CAST(12.5 AS DECIMAL(5,2)) AS ratio, \
                        SEC_TO_TIME(90) AS waited, NULL AS nothing",
                LIMIT,
            )
            .await
            .unwrap();
        let found = discovered(&rows);
        assert!(found["version"].is_string(), "{found:?}");
        assert_eq!(found["yes"], 1.0);
        assert_eq!(found["ratio"], 12.5);
        assert_eq!(found["waited"], 90.0);
        assert_eq!(found["nothing"], Value::Null);

        let error = session
            .run(
                "CREATE TABLE mysql.maxnines_should_not_exist (id int)",
                LIMIT,
            )
            .await
            .unwrap_err();
        assert!(
            format!("{error}").to_lowercase().contains("read only"),
            "{error}"
        );
        assert!(session.run("SELECT 1; SELECT 2", LIMIT).await.is_err());
        session.run("SELECT 1 AS one", LIMIT).await.unwrap();
        assert_eq!(session.connections(), 1);

        let error = session
            .run("SELECT SLEEP(30) AS slept FROM DUAL", LIMIT)
            .await;
        // MySQL stops a SELECT that runs too long, and says it was interrupted, as
        // MariaDB does in its own words.
        match error {
            Err(error) => {
                let text = format!("{error}");
                assert!(
                    text.contains("execution time") || text.contains("max_statement_time"),
                    "{text}"
                );
            }
            Ok(rows) => assert_eq!(discovered(&rows)["slept"], 1.0, "SLEEP says 1 when stopped"),
        }
    }
}
