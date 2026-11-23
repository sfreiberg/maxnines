//! ClickHouse over its HTTP interface, which the checks' own HTTP client already
//! speaks, so no driver is added: for its sign-in check, and for templates, which
//! read its health from its `system` tables, as the built-in `clickhouse` template
//! does. Every query is a GET, which ClickHouse only lets read.
//!
//! A password goes in basic authentication, so it's only sent over plain HTTP
//! to the host itself, and anywhere else over HTTPS.
//!
//! Statements share one connection while it's open, and a new one is opened when
//! ClickHouse has closed it, as it does with one left idle.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail, ensure};
use maxnines_protocol::{Check, CheckKind};
use serde_json::{Map, Value};

use crate::templates::{Cell, Row};
use crate::{Credentials, Findings, Login, WebConnection, decompress, host_and_port, open_web};

/// What a query got back, or ClickHouse's own reason it didn't.
struct Failure {
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

/// A value as a template's cell, by its column's type, which may be wrapped as
/// `Nullable(…)` or `LowCardinality(…)`. A number that isn't one, such as NaN,
/// which ClickHouse writes as null, is nothing.
fn cell(kind: &str, value: Option<&Value>) -> Cell {
    let mut kind = kind;
    for wrapper in ["Nullable(", "LowCardinality("] {
        while let Some(inner) = kind.strip_prefix(wrapper).and_then(|k| k.strip_suffix(')')) {
            kind = inner;
        }
    }
    match value {
        None | Some(Value::Null) => Cell::Null,
        Some(Value::Bool(yes)) => Cell::Bool(*yes),
        Some(value) if kind == "Bool" => Cell::Bool(number(Some(value)).is_some_and(|n| n != 0.0)),
        Some(value)
            if ["Int", "UInt", "Float", "Decimal"]
                .iter()
                .any(|start| kind.starts_with(start)) =>
        {
            number(Some(value)).map_or(Cell::Null, Cell::Number)
        }
        Some(Value::String(text))
            if kind == "String" || kind.starts_with("FixedString") || kind.starts_with("Enum") =>
        {
            Cell::Text(text.clone())
        }
        Some(_) => Cell::Other,
    }
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
        let answer = self.answer(sql).await?;
        Ok(answer["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row.as_object().cloned())
            .collect())
    }

    /// A template's statement's rows, each cell as the type ClickHouse says its
    /// column is: true or false, a number, text, or nothing.
    pub(crate) async fn typed_rows(&mut self, sql: &str) -> Result<Vec<Row>> {
        let answer = self.answer(sql).await.map_err(|error| anyhow!("{error}"))?;
        let columns: Vec<(String, String)> = answer["meta"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|column| {
                let name = column["name"].as_str()?.to_string();
                Some((name, column["type"].as_str()?.to_string()))
            })
            .collect();
        let rows = answer["data"].as_array().cloned().unwrap_or_default();
        Ok(rows
            .iter()
            .map(|row| {
                columns
                    .iter()
                    .map(|(name, kind)| (name.clone(), cell(kind, row.get(name))))
                    .collect()
            })
            .collect())
    }

    /// The whole of what a query gets back, which says its columns' types as well
    /// as its rows.
    async fn answer(&mut self, sql: &str) -> Result<Value, Failure> {
        // No settings go with it: an account limited to reading, as it should be,
        // can't change them, and its own profile sets its limits.
        let path = format!("/?query={}", encoded(&format!("{sql} FORMAT JSON")));
        let (status, body) = self.get(&path).await?;
        if status != 200 {
            // Such as "Code: 497. DB::Exception: maxnines: Not enough privileges…".
            let first = body.lines().next().unwrap_or_default();
            let message = first
                .split_once("DB::Exception: ")
                .map_or(first, |(_, message)| message);
            let message = message.split(". (").next().unwrap_or(message);
            let message = if message.is_empty() {
                format!("it returned status {status}")
            } else {
                message.chars().take(200).collect()
            };
            return Err(Failure { message });
        }
        serde_json::from_str(&body).map_err(|_| Failure {
            message: "it didn't answer as ClickHouse does".to_string(),
        })
    }

    /// The one row a query gives.
    async fn one(&mut self, sql: &str) -> Result<Map<String, Value>, Failure> {
        self.query(sql).await?.into_iter().next().ok_or(Failure {
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
}

#[cfg(test)]
mod tests {
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

    /// A template's statements go over one connection, kept between them.
    #[tokio::test]
    async fn statements_share_one_connection() {
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
                        let body = r#"{"meta": [{"name": "version", "type": "String"},
                                                {"name": "uptime", "type": "UInt32"}],
                                       "data": [{"version": "24.8.1", "uptime": 5}]}"#;
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
        for _ in 0..2 {
            let rows = clickhouse
                .typed_rows("SELECT version() AS version, uptime() AS uptime")
                .await
                .unwrap();
            assert_eq!(
                rows,
                [vec![
                    ("version".to_string(), Cell::Text("24.8.1".to_string())),
                    ("uptime".to_string(), Cell::Number(5.0)),
                ]]
            );
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cells_follow_their_columns_types() {
        use serde_json::json;
        assert_eq!(
            cell("Nullable(UInt64)", Some(&json!("12"))),
            Cell::Number(12.0)
        );
        assert_eq!(cell("Float64", Some(&Value::Null)), Cell::Null);
        assert_eq!(cell("Bool", Some(&json!(true))), Cell::Bool(true));
        assert_eq!(
            cell("LowCardinality(String)", Some(&json!("merges"))),
            Cell::Text("merges".to_string())
        );
        assert_eq!(cell("Date", Some(&json!("2026-11-22"))), Cell::Other);
    }
}
