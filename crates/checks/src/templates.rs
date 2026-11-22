//! Runs a template's SQL against a database, for agents and, later, for the server
//! reading databases on hosts with no agent. What to run comes from the server,
//! already worked out for the database: see [`maxnines_protocol::templates::work`].
//!
//! Each statement runs on its own in a read-only transaction that's rolled back
//! after, with a time limit on the statement and on the whole round. It's run as a
//! prepared statement, which a database only takes one statement at a time for, so
//! SQL with a second statement after a `;` is refused by the database itself. What
//! the account may read is up to whoever gave it to MaxNines.
//!
//! A [`Session`] keeps its connection open between rounds, and opens a new one when
//! the old one stops working, counting each time it does, so whoever runs it can
//! tell the database may have restarted and run discovery again.

use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use maxnines_protocol::CheckKind;
use maxnines_protocol::templates::work::QueryWork;
use maxnines_protocol::totals::change;
use serde_json::{Map, Value, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_postgres::types::{FromSql, Type};

use crate::databases::Database;
use crate::sign_in::{mysql_connection, pg_short, postgres_client, short};

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
    /// Anything else, such as a date, which a template can't use.
    Other,
}

/// A row's columns, by name, in order.
pub type Row = Vec<(String, Cell)>;

enum Open {
    Postgres {
        client: tokio_postgres::Client,
        running: JoinHandle<()>,
    },
    Mysql(Box<mysql_async::Conn>),
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
            Some(Open::Mysql(connection)) => {
                use mysql_async::prelude::Queryable;
                connection.ping().await.is_ok()
            }
            None => false,
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
                let limit = match version.is_some_and(|v| v.to_lowercase().contains("mariadb")) {
                    true => format!("SET SESSION max_statement_time = {}", ms / 1000),
                    false => format!("SET SESSION max_execution_time = {ms}"),
                };
                // A statement that ends a transaction, as MySQL's DDL does, starts
                // another that's read-only too.
                for setting in [limit.as_str(), "SET SESSION TRANSACTION READ ONLY"] {
                    connection.query_drop(setting).await.map_err(short)?;
                }
                Ok(Open::Mysql(Box::new(connection)))
            }
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
            Some(Open::Mysql(connection)) => run_mysql(connection, sql).await,
            None => bail!("not connected"),
        }
    }
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
        let statement = client.prepare(sql).await.map_err(pg_short)?;
        let rows = client.query(&statement, &[]).await.map_err(pg_short)?;
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
    // Nothing was written, as nothing could be, so there's nothing to keep.
    client.batch_execute("ROLLBACK").await.map_err(pg_short)?;
    outcome
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

async fn run_mysql(connection: &mut mysql_async::Conn, sql: &str) -> Result<Vec<Row>> {
    use mysql_async::prelude::Queryable;
    connection
        .query_drop("START TRANSACTION READ ONLY")
        .await
        .map_err(short)?;
    let outcome: Result<Vec<mysql_async::Row>> = connection.exec(sql, ()).await.map_err(short);
    connection.query_drop("ROLLBACK").await.map_err(short)?;
    Ok(outcome?.into_iter().map(mysql_row).collect())
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
                My::Bytes(bytes) => match column.column_type() {
                    ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL => {
                        String::from_utf8_lossy(&bytes)
                            .parse()
                            .map_or(Cell::Other, Cell::Number)
                    }
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
                Cell::Other => return None,
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
/// query says to leave out give nothing.
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
            interval: None,
            labels: labels.iter().map(|l| (*l).to_string()).collect(),
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
            [json!({ "labels": { "instance": "orders", "slot": "a" }, "active": 1.0, "lag": 2.5 })]
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

        // A statement that runs too long is stopped by the database.
        let error = session.run("SELECT pg_sleep(30)", LIMIT).await.unwrap_err();
        assert!(format!("{error}").contains("statement timeout"), "{error}");
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
        // MySQL stops a SELECT that runs too long, and says it was interrupted.
        match error {
            Err(error) => assert!(format!("{error}").contains("execution time"), "{error}"),
            Ok(rows) => assert_eq!(discovered(&rows)["slept"], 1.0, "SLEEP says 1 when stopped"),
        }
    }
}
