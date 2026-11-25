//! Redis, which a template asks with its own commands, such as `INFO server`, sent
//! as their words, so nothing in them is read as more than one command. Each reply
//! is made a document, as MongoDB's are, for [`super::from_reply`] to read the
//! fields a query's columns name:
//!
//! - INFO's, a document for each `# Section`, by its name in lower case, of its
//!   `name:value` lines, a value of `name=value` pairs, as `db0:keys=12,expires=3`,
//!   being a document of its own;
//! - a map's, or the names and values `CONFIG GET` lists, by name;
//! - anything else's as one field, `value`.
//!
//! A number written as text is a number, and the words INFO says how things went
//! in, `ok` and `up`, are true, as `err` and `down` are false. So are `yes` and
//! `no`, as `CONFIG GET` says them. Valkey answers as Redis does.

use anyhow::{Result, anyhow, bail};
use maxnines_protocol::templates::{read_redis_command, redis_command_sent};
use mongodb::bson::{Bson, Document};
use redis::aio::MultiplexedConnection;

use super::{Cell, Privileges, REPLY, Row, STATEMENT_LIMIT};
use crate::databases::Database;
use crate::sign_in::{redis_client, short};

/// Connects and signs in, as the account in `database` if it has one, which Redis
/// does as part of connecting.
pub(super) async fn connect(database: &Database) -> Result<MultiplexedConnection> {
    let client = redis_client(&database.check, Some(&database.credentials))?;
    // The round's own time limit covers connecting.
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(None)
        .set_response_timeout(Some(STATEMENT_LIMIT));
    client
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .map_err(short)
}

/// A command's words as they're sent, for the commands MaxNines asks itself.
pub(super) fn sent(words: &[&str]) -> String {
    redis_command_sent(
        &words
            .iter()
            .map(|word| (*word).to_string())
            .collect::<Vec<_>>(),
    )
}

/// What one command, as its words are sent, gives: its reply made a document, as
/// one row of one cell, for [`super::from_reply`] to read.
pub(super) async fn run(connection: &mut MultiplexedConnection, text: &str) -> Result<Vec<Row>> {
    let words = read_redis_command(text).map_err(|error| anyhow!("the command {error}"))?;
    let mut command = redis::cmd(&words[0]);
    for word in &words[1..] {
        command.arg(word);
    }
    let value: redis::Value = command.query_async(connection).await.map_err(short)?;
    let reply = reply(&words, value);
    Ok(vec![vec![(
        REPLY.to_string(),
        Cell::Reply(Box::new(reply)),
    )]])
}

/// A command's reply as a document, by what the command was.
fn reply(words: &[String], value: redis::Value) -> Document {
    use redis::Value;
    let named = |at: usize, name: &str| words.get(at).is_some_and(|w| w.eq_ignore_ascii_case(name));
    match value {
        Value::BulkString(bytes) if named(0, "INFO") => info(&String::from_utf8_lossy(&bytes)),
        Value::VerbatimString { text, .. } if named(0, "INFO") => info(&text),
        Value::Map(pairs) => pairs
            .into_iter()
            .map(|(name, value)| (text(&name), bson(value)))
            .collect(),
        Value::Array(items) if named(0, "CONFIG") && named(1, "GET") => {
            let mut items = items.into_iter();
            let mut document = Document::new();
            while let (Some(name), Some(value)) = (items.next(), items.next()) {
                document.insert(text(&name), bson(value));
            }
            document
        }
        other => {
            let mut document = Document::new();
            document.insert("value", bson(other));
            document
        }
    }
}

/// What INFO says, as a document of its sections, each of its fields.
pub fn info(text: &str) -> Document {
    let mut all = Document::new();
    let mut section = Document::new();
    let mut name = String::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(heading) = line.strip_prefix('#') {
            let done = std::mem::take(&mut section);
            if !name.is_empty() || !done.is_empty() {
                all.insert(std::mem::take(&mut name), done);
            }
            name = heading.trim().to_lowercase();
        } else if let Some((field, value)) = line.split_once(':') {
            section.insert(field, field_value(value));
        }
    }
    if !name.is_empty() || !section.is_empty() {
        all.insert(name, section);
    }
    all
}

/// One of INFO's values: a document of `name=value` pairs, or a word.
fn field_value(value: &str) -> Bson {
    let pairs: Option<Document> = value
        .split(',')
        .map(|pair| {
            pair.split_once('=')
                .map(|(name, value)| (name.to_string(), word(value)))
        })
        .collect();
    match pairs {
        Some(pairs) if value.contains('=') => Bson::Document(pairs),
        _ => word(value),
    }
}

/// A word as a template reads it: a number, true or false, or text.
fn word(text: &str) -> Bson {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let number = !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        && digits.chars().filter(|c| *c == '.').count() <= 1
        && !digits.starts_with('.')
        && !digits.ends_with('.');
    if number && let Ok(number) = text.parse::<f64>() {
        return match text.parse::<i64>() {
            Ok(whole) => Bson::Int64(whole),
            Err(_) => Bson::Double(number),
        };
    }
    match text {
        "ok" | "up" | "yes" => Bson::Boolean(true),
        "err" | "down" | "no" => Bson::Boolean(false),
        _ => Bson::String(text.to_string()),
    }
}

fn text(value: &redis::Value) -> String {
    match value {
        redis::Value::BulkString(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        redis::Value::SimpleString(text) | redis::Value::VerbatimString { text, .. } => {
            text.clone()
        }
        redis::Value::Int(number) => number.to_string(),
        other => format!("{other:?}"),
    }
}

fn bson(value: redis::Value) -> Bson {
    use redis::Value;
    match value {
        Value::Nil => Bson::Null,
        Value::Int(number) => Bson::Int64(number),
        Value::Double(number) => Bson::Double(number),
        Value::Boolean(yes) => Bson::Boolean(yes),
        Value::Okay => Bson::Boolean(true),
        Value::Array(items) | Value::Set(items) => {
            Bson::Array(items.into_iter().map(bson).collect())
        }
        Value::Map(pairs) => Bson::Document(
            pairs
                .into_iter()
                .map(|(name, value)| (text(&name), bson(value)))
                .collect(),
        ),
        Value::Attribute { data, .. } => bson(*data),
        other => word(&text(&other)),
    }
}

/// What the account may do beyond reading, from its ACL rules, as `ACL GETUSER`
/// gives them. Redis before 6 has no accounts, so whoever has the password may do
/// anything. An account that may read accounts may read every one's password
/// hashes, so it manages them, and one that may not is one Redis limits, which is
/// all that can be told of it. `hidden` is whether that was found before on this
/// connection, so it isn't asked again, as Redis notes each refusal in its ACL
/// LOG: it's asked again on the next connection.
pub(super) async fn privileges(
    connection: &mut MultiplexedConnection,
    username: Option<&str>,
    hidden: &mut bool,
) -> Result<Privileges> {
    if *hidden {
        return Ok(Privileges::default());
    }
    let asked: redis::RedisResult<redis::Value> = redis::cmd("ACL")
        .arg("GETUSER")
        .arg(username.unwrap_or("default"))
        .query_async(connection)
        .await;
    let answer = match asked {
        Ok(answer) => answer,
        Err(error) if error.code() == Some("NOPERM") => {
            *hidden = true;
            return Ok(Privileges::default());
        }
        Err(error) if error.to_string().to_lowercase().contains("unknown command") => {
            return Ok(Privileges {
                superuser: true,
                writes: true,
                manages: true,
                server_files: true,
            });
        }
        Err(error) => return Err(short(error)),
    };
    // Its names and values, listed as CONFIG GET lists them.
    let fields = reply(&["CONFIG".to_string(), "GET".to_string()], answer);
    let Ok(rules) = fields.get_str("commands") else {
        bail!("Redis didn't say what the account may do");
    };
    Ok(acl_privileges(rules))
}

/// What ACL rules, such as `+@all -@dangerous`, let an account do, each in turn.
/// Anything taken away means it can't do everything.
fn acl_privileges(rules: &str) -> Privileges {
    let mut found = Privileges {
        manages: true,
        ..Privileges::default()
    };
    for rule in rules.split_whitespace() {
        let on = rule.starts_with('+');
        match rule.trim_start_matches(['+', '-']) {
            "@all" => {
                found.superuser = on;
                found.writes = on;
                found.server_files = on;
            }
            "@write" => found.writes = on,
            "@admin" | "@dangerous" | "config" | "config|set" => found.server_files = on,
            _ => {}
        }
        if !on {
            found.superuser = false;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use indexmap::IndexMap;
    use maxnines_protocol::CheckKind;
    use mongodb::bson::doc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;
    use crate::Credentials;
    use crate::templates::{Session, from_reply};

    /// What real Redis 8.12 said to INFO, captured by `fixtures/redis/capture.sh`.
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../../fixtures/redis/", $name, ".info"))
        };
    }

    fn named(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs
            .iter()
            .map(|(name, path)| (name.to_string(), path.to_string()))
            .collect()
    }

    /// The columns read from INFO's reply, by their names, from the rows `rows`
    /// says.
    fn read(text: &str, columns: &[(&str, &str)], rows: Option<&str>) -> Vec<Vec<(String, Cell)>> {
        let reply = vec![vec![(REPLY.to_string(), Cell::Reply(Box::new(info(text))))]];
        from_reply(reply, &named(columns), rows)
    }

    fn one(text: &str, path: &str) -> Cell {
        read(text, &[("it", path)], None)[0][0].1.clone()
    }

    #[test]
    fn info_is_a_document_of_its_sections() {
        let standalone = info(fixture!("standalone"));
        let server = standalone.get_document("server").unwrap();
        assert_eq!(server.get_str("redis_version").unwrap(), "8.12.0");
        // Every section, even an empty one, by its name in lower case.
        for section in [
            "clients",
            "memory",
            "persistence",
            "stats",
            "replication",
            "keyspace",
            "modules",
        ] {
            assert!(
                standalone.contains_key(section),
                "{section}: {standalone:?}"
            );
        }
        assert_eq!(
            one(fixture!("standalone"), "memory.maxmemory"),
            Cell::Number(0.0)
        );
        assert_eq!(
            one(fixture!("standalone"), "replication.role"),
            Cell::Text("master".into())
        );
        assert_eq!(
            one(fixture!("standalone"), "memory.mem_fragmentation_ratio"),
            Cell::Number(
                info(fixture!("standalone"))
                    .get_document("memory")
                    .unwrap()
                    .get_f64("mem_fragmentation_ratio")
                    .unwrap()
            )
        );
        assert_eq!(
            one(fixture!("standalone"), "persistence.rdb_last_bgsave_status"),
            Cell::Bool(true)
        );
        assert_eq!(
            one(
                fixture!("bgsave-failed"),
                "persistence.rdb_last_bgsave_status"
            ),
            Cell::Bool(false)
        );
        // A limit, and keys evicted to keep under it.
        assert_eq!(
            one(fixture!("maxmemory"), "memory.maxmemory"),
            Cell::Number(4_194_304.0)
        );
        assert_eq!(
            one(fixture!("maxmemory"), "stats.evicted_keys"),
            Cell::Number(832.0)
        );
        assert_eq!(
            one(fixture!("maxmemory"), "memory.maxmemory_policy"),
            Cell::Text("allkeys-lru".into())
        );
        // A replica, its link up and down.
        assert_eq!(
            one(fixture!("replica"), "replication.role"),
            Cell::Text("slave".into())
        );
        assert_eq!(
            one(fixture!("replica"), "replication.master_link_status"),
            Cell::Bool(true)
        );
        assert_eq!(
            one(
                fixture!("replica-link-down"),
                "replication.master_link_status"
            ),
            Cell::Bool(false)
        );
        assert_eq!(
            one(
                fixture!("replica-link-down"),
                "replication.master_last_io_seconds_ago"
            ),
            Cell::Number(-1.0)
        );
        // What isn't there is nothing.
        assert_eq!(
            one(fixture!("standalone"), "replication.master_link_status"),
            Cell::Null
        );
    }

    #[test]
    fn each_database_in_the_keyspace_is_a_row() {
        let columns = [("db", "k"), ("keys", "v.keys"), ("expires", "v.expires")];
        let rows = read(fixture!("standalone"), &columns, Some("keyspace"));
        assert_eq!(
            rows,
            [
                vec![
                    ("db".to_string(), Cell::Text("db0".into())),
                    ("keys".to_string(), Cell::Number(12.0)),
                    ("expires".to_string(), Cell::Number(2.0)),
                ],
                vec![
                    ("db".to_string(), Cell::Text("db3".into())),
                    ("keys".to_string(), Cell::Number(2.0)),
                    ("expires".to_string(), Cell::Number(1.0)),
                ],
            ]
        );
    }

    #[test]
    fn each_replica_streaming_from_a_primary_is_a_row() {
        let columns = [
            ("replica", "v.ip"),
            ("port", "v.port"),
            ("lag", "v.lag"),
            ("offset", "v.offset"),
            ("primary", "$.replication.master_repl_offset"),
        ];
        let rows = read(
            fixture!("maxmemory"),
            &columns,
            Some("replication[state=online]"),
        );
        assert_eq!(
            rows,
            [vec![
                ("replica".to_string(), Cell::Text("127.0.0.1".into())),
                ("port".to_string(), Cell::Number(56380.0)),
                ("lag".to_string(), Cell::Number(0.0)),
                ("offset".to_string(), Cell::Number(60.0)),
                ("primary".to_string(), Cell::Number(10_057_467.0)),
            ]]
        );
        // How many are kept, and none where there are none.
        assert_eq!(
            one(fixture!("primary"), "replication[state=online]"),
            Cell::Number(1.0)
        );
        assert_eq!(
            one(fixture!("standalone"), "replication[state=online]"),
            Cell::Number(0.0)
        );
        assert!(
            read(
                fixture!("replica"),
                &columns,
                Some("replication[state=online]")
            )
            .is_empty()
        );
        // Going on past them reads the first.
        assert_eq!(
            one(fixture!("primary"), "replication[state=online].port"),
            Cell::Number(56380.0)
        );
    }

    #[test]
    fn other_replies_are_documents_too() {
        let words = |text: &str| text.split(' ').map(String::from).collect::<Vec<_>>();
        let listed = redis::Value::Array(vec![
            redis::Value::BulkString(b"maxmemory".to_vec()),
            redis::Value::BulkString(b"0".to_vec()),
            redis::Value::BulkString(b"appendonly".to_vec()),
            redis::Value::BulkString(b"no".to_vec()),
        ]);
        assert_eq!(
            reply(&words("CONFIG GET maxmemory appendonly"), listed),
            doc! { "maxmemory": 0_i64, "appendonly": false }
        );
        assert_eq!(
            reply(&words("DBSIZE"), redis::Value::Int(14)),
            doc! { "value": 14_i64 }
        );
        let map = redis::Value::Map(vec![(
            redis::Value::SimpleString("server".into()),
            redis::Value::BulkString(b"redis".to_vec()),
        )]);
        assert_eq!(reply(&words("HELLO"), map), doc! { "server": "redis" });
    }

    /// Accounts a fake Redis has: a name, its password, and the commands it may run.
    type Accounts = &'static [(&'static str, &'static str, &'static [&'static str])];

    /// Enough of Redis for a template: AUTH, as an ACL user or the default one,
    /// PING, INFO, which says what `info` holds, and ACL GETUSER, which only
    /// accounts that may run it can, counting how often it's asked.
    async fn fake_redis(
        accounts: Accounts,
        info: &'static str,
        asked: Arc<AtomicUsize>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let asked = asked.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = socket.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut user: Option<&(&str, &str, &[&str])> = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let Some(count) = line.trim().strip_prefix('*') else {
                            return;
                        };
                        let mut words = Vec::new();
                        for _ in 0..count.parse::<usize>().unwrap_or(0) {
                            let mut size = String::new();
                            reader.read_line(&mut size).await.unwrap();
                            let size: usize = size.trim().trim_start_matches('$').parse().unwrap();
                            let mut word = vec![0; size + 2];
                            reader.read_exact(&mut word).await.unwrap();
                            word.truncate(size);
                            words.push(String::from_utf8(word).unwrap());
                        }
                        let command = words[0].to_lowercase();
                        let bulk = |text: &str| format!("${}\r\n{text}\r\n", text.len());
                        let answer = match command.as_str() {
                            "auth" => {
                                let (name, password) = match words.as_slice() {
                                    [_, password] => ("default", password.as_str()),
                                    [_, name, password] => (name.as_str(), password.as_str()),
                                    _ => ("", ""),
                                };
                                user = accounts.iter().find(|a| (a.0, a.1) == (name, password));
                                match user {
                                    Some(_) => "+OK\r\n".to_string(),
                                    None => "-WRONGPASS invalid username-password pair or user is disabled.\r\n".to_string(),
                                }
                            }
                            _ if user.is_none() => {
                                "-NOAUTH Authentication required.\r\n".to_string()
                            }
                            _ if !user.unwrap().2.contains(&command.as_str()) => {
                                if command == "acl" {
                                    asked.fetch_add(1, Ordering::SeqCst);
                                }
                                format!(
                                    "-NOPERM User {} has no permissions to run the '{command}' command\r\n",
                                    user.unwrap().0
                                )
                            }
                            "ping" => "+PONG\r\n".to_string(),
                            "info" => bulk(info),
                            "acl" => {
                                asked.fetch_add(1, Ordering::SeqCst);
                                // flags, commands and keys, as Redis lists them.
                                "*6\r\n$5\r\nflags\r\n*1\r\n$2\r\non\r\n$8\r\ncommands\r\n\
                                 $5\r\n+@all\r\n$4\r\nkeys\r\n$2\r\n~*\r\n"
                                    .to_string()
                            }
                            _ => "-ERR unknown command\r\n".to_string(),
                        };
                        if writer.write_all(answer.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        address
    }

    fn session(address: SocketAddr, username: Option<&str>, password: &str) -> Session {
        Session::new(Database {
            check: maxnines_protocol::Check::new("cache", CheckKind::Redis, &address.to_string()),
            credentials: Credentials {
                username: username.map(String::from),
                password: Some(password.to_string()),
                private_key: None,
            },
        })
    }

    const LIMIT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn an_acl_user_that_can_only_run_info_reads_it() {
        const ACCOUNTS: Accounts = &[("maxnines", "s3cret", &["info", "ping"])];
        let asked = Arc::new(AtomicUsize::new(0));
        let address = fake_redis(ACCOUNTS, fixture!("primary"), asked.clone()).await;
        let mut redis = session(address, Some("maxnines"), "s3cret");
        let rows = redis.run(&sent(&["INFO"]), LIMIT).await.unwrap();
        let found = crate::templates::discovered(&from_reply(
            rows,
            &named(&[("role", "replication.role")]),
            None,
        ));
        assert_eq!(found["role"], "master");
        redis.ping(LIMIT).await.unwrap();
        assert_eq!(redis.connections(), 1);

        // It can't read what it may do, which is all that can be told of it, and
        // it isn't asked again on the same connection, as Redis logs each refusal.
        assert_eq!(redis.privileges().await.unwrap(), Privileges::default());
        assert_eq!(redis.privileges().await.unwrap(), Privileges::default());
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        // What it isn't allowed says so.
        let error = redis
            .run(&sent(&["CONFIG", "GET", "maxmemory"]), LIMIT)
            .await
            .unwrap_err();
        assert!(format!("{error}").contains("no permissions"), "{error}");
        // What isn't a Redis command's words isn't sent.
        let error = redis.run("INFO", LIMIT).await.unwrap_err();
        assert!(
            format!("{error}").contains("isn't a Redis command"),
            "{error}"
        );

        // The wrong password signs nothing in.
        let error = session(address, Some("maxnines"), "guess")
            .run(&sent(&["INFO"]), LIMIT)
            .await
            .unwrap_err();
        assert!(
            format!("{error}").contains("authentication failed"),
            "{error}"
        );
        assert!(!format!("{error}").contains("guess"), "{error}");
    }

    #[tokio::test]
    async fn the_default_user_that_may_do_anything_is_said_to() {
        const ACCOUNTS: Accounts = &[("default", "s3cret", &["info", "ping", "acl"])];
        let asked = Arc::new(AtomicUsize::new(0));
        let address = fake_redis(ACCOUNTS, fixture!("standalone"), asked.clone()).await;
        let mut redis = session(address, None, "s3cret");
        let privileges = redis.privileges().await.unwrap();
        assert!(
            privileges.superuser && privileges.overprivileged(),
            "{privileges:?}"
        );
        // Asked every time, as it can be.
        redis.privileges().await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_password_is_only_sent_without_tls_to_the_host_itself() {
        let mut redis = session(
            "192.0.2.1:6379".parse().unwrap(),
            Some("maxnines"),
            "s3cret",
        );
        let error = redis.run(&sent(&["INFO"]), LIMIT).await.unwrap_err();
        assert!(format!("{error}").contains("set tls"), "{error}");
    }

    /// A real Redis, from `MAXNINES_TEST_CHECK_REDIS`, as `host:port [username]
    /// password`, which the test reads and never changes.
    #[tokio::test]
    async fn a_real_redis_is_read() {
        let Ok(value) = std::env::var("MAXNINES_TEST_CHECK_REDIS") else {
            return;
        };
        let words: Vec<&str> = value.split_whitespace().collect();
        let (address, username, password) = match words.as_slice() {
            [address, password] => (*address, None, *password),
            [address, username, password] => (*address, Some(*username), *password),
            _ => panic!("MAXNINES_TEST_CHECK_REDIS is host:port [username] password"),
        };
        let mut redis = session(address.parse().unwrap(), username, password);
        let rows = redis.run(&sent(&["INFO"]), LIMIT).await.unwrap();
        let found = crate::templates::discovered(&from_reply(
            rows,
            &named(&[
                ("version", "server.redis_version"),
                ("limit", "memory.maxmemory"),
            ]),
            None,
        ));
        assert!(found["version"].is_string(), "{found:?}");
        assert!(found["limit"].is_number(), "{found:?}");
        let keyspace = redis
            .run(&sent(&["INFO", "keyspace"]), LIMIT)
            .await
            .unwrap();
        let reply = from_reply(keyspace, &named(&[("db", "k")]), Some("keyspace"));
        assert!(
            reply
                .iter()
                .all(|row| matches!(&row[0].1, Cell::Text(db) if db.starts_with("db")))
        );
        redis.ping(LIMIT).await.unwrap();
        // Whatever the account is, it can be told, or it's one Redis limits.
        redis.privileges().await.unwrap();
        assert_eq!(redis.connections(), 1);
    }

    #[test]
    fn acl_rules_say_what_an_account_may_do() {
        let all = acl_privileges("+@all");
        assert!(all.superuser && all.writes && all.manages && all.server_files);
        let safer = acl_privileges("+@all -@dangerous");
        assert!(!safer.superuser && safer.writes && !safer.server_files);
        let reads = acl_privileges("-@all +info +ping +acl|getuser");
        assert!(!reads.superuser && !reads.writes && !reads.server_files);
        // It can read every account, so it manages them.
        assert!(reads.manages);
        assert!(acl_privileges("-@all +@write").writes);
    }

    #[test]
    fn words_are_numbers_flags_or_text() {
        assert_eq!(word("12"), Bson::Int64(12));
        assert_eq!(word("-1"), Bson::Int64(-1));
        assert_eq!(word("1.99"), Bson::Double(1.99));
        assert_eq!(word("ok"), Bson::Boolean(true));
        assert_eq!(word("down"), Bson::Boolean(false));
        for text in ["8.12.0", "nan", "inf", "1e5", "", ".5", "master", "4.00M"] {
            assert_eq!(word(text), Bson::String(text.to_string()), "{text}");
        }
    }
}
