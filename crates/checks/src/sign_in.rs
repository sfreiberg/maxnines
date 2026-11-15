//! Checks of servers that are signed in to: PostgreSQL, MySQL and MariaDB, Redis,
//! MongoDB and SSH. Without a username and password, or a key for SSH, each checks only
//! what it can without signing in.
//!
//! A database's driver sends the password as part of connecting, before anything
//! here could look at the certificate, so a certificate that can't be trusted
//! stops the connection during its handshake, unless the check was told not to
//! mind. Then nothing secret goes to a server that isn't the one meant.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail, ensure};
use maxnines_protocol::Check;
use rustls::ClientConfig;
use rustls::client::WebPkiServerVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Findings, RecordingVerifier, connect, elapsed_ms, host_and_port, resolve, trusted_roots,
};

/// How to sign in. Usernames aren't secret; the rest never leaves the check.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    /// For SSH: a private key in OpenSSH's format, without a passphrase.
    pub private_key: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    pub(crate) fn is_empty(&self) -> bool {
        self.username.is_none() && self.password.is_none() && self.private_key.is_none()
    }
}

/// TLS for a driver: the certificate checked as for a site, or not at all for a
/// check told not to mind.
fn driver_tls(insecure: bool) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let config = if insecure {
        let real = WebPkiServerVerifier::builder_with_provider(Arc::new(trusted_roots()), provider)
            .build()
            .context("setting up TLS")?;
        // Notes what's wrong and carries on regardless, which is what was asked.
        let verifier = Arc::new(RecordingVerifier {
            real,
            outcome: Arc::new(Mutex::new(None)),
        });
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(trusted_roots())
            .with_no_client_auth()
    };
    Ok(config)
}

/// A driver's error in a few words. Some of them repeat the connection's
/// settings, so only their own description is kept, never the whole chain.
pub(crate) fn short(error: impl fmt::Display) -> anyhow::Error {
    let text = error.to_string();
    let text = text.lines().next().unwrap_or_default();
    anyhow!("{}", text.chars().take(200).collect::<String>())
}

/// PostgreSQL's own words for what went wrong, which its driver keeps a level
/// down behind "db error".
pub(crate) fn pg_short(error: tokio_postgres::Error) -> anyhow::Error {
    match error.as_db_error() {
        Some(database) => short(database.message()),
        None => short(error),
    }
}

/// Opens a plain connection, timing the lookup and connecting as other checks do.
async fn open(check: &Check, findings: &mut Findings) -> Result<tokio::net::TcpStream> {
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    connect(&addresses, findings).await
}

pub(crate) async fn check_postgres(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let Some(credentials) = credentials.filter(|given| !given.is_empty()) else {
        // Asks whether it would talk TLS, which any PostgreSQL server answers
        // with one letter before anyone signs in.
        let mut socket = open(check, findings).await?;
        socket
            .write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])
            .await?;
        let mut answer = [0u8; 1];
        socket
            .read_exact(&mut answer)
            .await
            .context("it closed the connection, so it isn't PostgreSQL")?;
        ensure!(
            matches!(answer[0], b'S' | b'N'),
            "it didn't answer as PostgreSQL does"
        );
        findings.tls_offered = Some(answer[0] == b'S');
        return Ok(());
    };
    let started = Instant::now();
    let (client, running) = postgres_client(check, credentials, false).await?;
    findings.connect_ms = Some(elapsed_ms(started));
    let version = client
        .query_one("SHOW server_version", &[])
        .await
        .map_err(pg_short)?;
    findings.server_version = version.try_get::<_, String>(0).ok();
    findings.signed_in = Some(true);
    drop(client);
    let _ = running.await;
    Ok(())
}

/// Signs in to PostgreSQL, over TLS whenever the server offers it, or only over
/// TLS when it's `required`. The connection runs as a task of its own until the
/// client is dropped.
pub(crate) async fn postgres_client(
    check: &Check,
    credentials: &Credentials,
    required: bool,
) -> Result<(tokio_postgres::Client, tokio::task::JoinHandle<()>)> {
    use tokio_postgres::config::SslMode;

    let (host, port) = host_and_port(&check.target)?;
    let username = credentials
        .username
        .as_deref()
        .context("signing in needs a username")?;
    let mut config = tokio_postgres::Config::new();
    config
        .host(&host)
        .port(port)
        .user(username)
        .dbname(check.database.as_deref().unwrap_or("postgres"))
        .application_name("maxnines")
        .ssl_mode(if required {
            SslMode::Require
        } else {
            SslMode::Prefer
        });
    if let Some(password) = &credentials.password {
        config.password(password);
    }
    let tls =
        tokio_postgres_rustls::MakeRustlsConnect::new(driver_tls(check.insecure == Some(true))?);
    let (client, connection) = config.connect(tls).await.map_err(pg_short)?;
    let running = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((client, running))
}

pub(crate) async fn check_mysql(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let Some(credentials) = credentials.filter(|given| !given.is_empty()) else {
        // The server speaks first, saying its version, before anyone signs in.
        let mut socket = open(check, findings).await?;
        let mut header = [0u8; 4];
        socket
            .read_exact(&mut header)
            .await
            .context("it closed the connection without a greeting")?;
        let length =
            usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
        ensure!(
            (1..=1024).contains(&length),
            "it didn't greet as MySQL does"
        );
        let mut greeting = vec![0u8; length];
        socket.read_exact(&mut greeting).await?;
        if greeting[0] == 0xff {
            // An error instead, such as this address not being allowed in.
            let message = String::from_utf8_lossy(greeting.get(3..).unwrap_or_default());
            let message: String = message.chars().take(200).collect();
            bail!("it refused the connection: {message}");
        }
        ensure!(greeting[0] == 10, "it didn't greet as MySQL does");
        let end = greeting[1..]
            .iter()
            .position(|byte| *byte == 0)
            .context("it didn't greet as MySQL does")?;
        findings.server_version = Some(String::from_utf8_lossy(&greeting[1..=end]).into_owned());
        return Ok(());
    };
    let started = Instant::now();
    let mut connection = mysql_connection(check, credentials).await?;
    findings.connect_ms = Some(elapsed_ms(started));
    use mysql_async::prelude::Queryable;
    let version: Option<String> = connection
        .query_first("SELECT VERSION()")
        .await
        .map_err(short)?;
    findings.server_version = version;
    findings.signed_in = Some(true);
    let _ = connection.disconnect().await;
    Ok(())
}

/// ClickHouse, over its HTTP interface: whether it answers its ping, or, signed
/// in, its version.
pub(crate) async fn check_clickhouse(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    use crate::databases::clickhouse::Clickhouse;

    // Looked up and connected to as other checks do, so a closed port fails at
    // once with the usual words.
    drop(open(check, findings).await?);
    match credentials.filter(|given| !given.is_empty()) {
        None => {
            Clickhouse::new(check, &Credentials::default())?
                .ping()
                .await
        }
        Some(credentials) => {
            let version = Clickhouse::new(check, credentials)?.version().await?;
            findings.server_version = Some(version);
            findings.signed_in = Some(true);
            Ok(())
        }
    }
}

/// Signs in to MySQL or MariaDB, over TLS when the check says to.
pub(crate) async fn mysql_connection(
    check: &Check,
    credentials: &Credentials,
) -> Result<mysql_async::Conn> {
    let (host, port) = host_and_port(&check.target)?;
    let username = credentials
        .username
        .as_deref()
        .context("signing in needs a username")?;
    let mut options = mysql_async::OptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port)
        .user(Some(username))
        .pass(credentials.password.clone())
        .prefer_socket(false);
    if check.tls == Some(true) {
        let tls = mysql_async::SslOpts::default()
            .with_danger_accept_invalid_certs(check.insecure == Some(true));
        options = options.ssl_opts(tls);
    }
    mysql_async::Conn::new(options).await.map_err(short)
}

pub(crate) async fn check_redis(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let (host, port) = host_and_port(&check.target)?;
    let address = if check.tls == Some(true) {
        redis::ConnectionAddr::TcpTls {
            host,
            port,
            insecure: check.insecure == Some(true),
            tls_params: None,
        }
    } else {
        redis::ConnectionAddr::Tcp(host, port)
    };
    let mut settings = redis::RedisConnectionInfo::default().set_skip_set_lib_name();
    let signing_in = credentials.filter(|given| !given.is_empty());
    if let Some(credentials) = signing_in {
        let password = credentials
            .password
            .as_deref()
            .context("signing in needs a password")?;
        settings = settings.set_password(password);
        if let Some(username) = &credentials.username {
            settings = settings.set_username(username);
        }
    }
    let info = redis::IntoConnectionInfo::into_connection_info(address)
        .map_err(short)?
        .set_redis_settings(settings);
    let client = redis::Client::open(info).map_err(short)?;
    let started = Instant::now();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(short)?;
    findings.connect_ms = Some(elapsed_ms(started));
    let pong: redis::RedisResult<String> = redis::cmd("PING").query_async(&mut connection).await;
    match pong {
        Ok(_) => {}
        // It answered, as Redis, but wants signing in first: up, as far as can be
        // told without signing in.
        Err(error) if signing_in.is_none() && error.code() == Some("NOAUTH") => return Ok(()),
        Err(error) => return Err(short(error)),
    }
    let info: String = redis::cmd("INFO")
        .arg("server")
        .query_async(&mut connection)
        .await
        .map_err(short)?;
    findings.server_version = info
        .lines()
        .find_map(|line| line.strip_prefix("redis_version:"))
        .map(|version| version.trim().to_string());
    if signing_in.is_some() {
        findings.signed_in = Some(true);
    }
    Ok(())
}

pub(crate) async fn check_mongodb(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    use mongodb::bson::doc;

    // Looked up and connected to as other checks do, which also fails at once
    // where nothing listens, instead of when the driver gives up looking.
    drop(open(check, findings).await?);
    let signing_in = credentials.filter(|given| !given.is_empty());
    let client = mongodb_client(check, signing_in)?;
    let admin = client.database("admin");
    // Anyone may ping, so without a login this says it answers as MongoDB, and
    // with one, connecting has signed in.
    let pinged = admin.run_command(doc! { "ping": 1 }).await;
    let result = match pinged {
        Ok(_) => {
            // Some servers tell anyone their version, others only those signed in.
            let built = admin.run_command(doc! { "buildInfo": 1 }).await;
            findings.server_version = built
                .ok()
                .and_then(|info| info.get_str("version").ok().map(String::from));
            if signing_in.is_some() {
                findings.signed_in = Some(true);
            }
            Ok(())
        }
        Err(error) => Err(mongodb_error(&error)),
    };
    client.shutdown().await;
    result
}

/// A client for the one server a check names, signed in to if it's given a
/// login. Nothing's sent until it's first used.
pub(crate) fn mongodb_client(
    check: &Check,
    credentials: Option<&Credentials>,
) -> Result<mongodb::Client> {
    use mongodb::options::{ClientOptions, Credential, ServerAddress, Tls, TlsOptions};

    let (host, port) = host_and_port(&check.target)?;
    let limit = crate::limit(check);
    let mut options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host,
            port: Some(port),
        }])
        .build();
    // This one server, as it is, rather than whichever member of its replica set
    // the driver would otherwise go looking for.
    options.direct_connection = Some(true);
    options.app_name = Some("maxnines".to_string());
    options.connect_timeout = Some(limit);
    // The driver waits this long for a server that answers as MongoDB, then says
    // why it didn't, which it can only do before the check runs out of time.
    options.server_selection_timeout = Some(limit * 4 / 5);
    options.max_pool_size = Some(1);
    options.retry_reads = Some(false);
    if check.tls == Some(true) {
        let tls = TlsOptions::builder()
            .allow_invalid_certificates(check.insecure == Some(true))
            .build();
        options.tls = Some(Tls::Enabled(tls));
    }
    if let Some(credentials) = credentials.filter(|given| !given.is_empty()) {
        let username = credentials
            .username
            .clone()
            .context("signing in needs a username")?;
        let password = credentials
            .password
            .clone()
            .context("signing in needs a password")?;
        let source = check
            .database
            .clone()
            .unwrap_or_else(|| "admin".to_string());
        options.credential = Some(
            Credential::builder()
                .username(username)
                .password(password)
                .source(source)
                .build(),
        );
    }
    mongodb::Client::with_options(options).map_err(short)
}

/// The driver's error in a few words. Not finding the server comes with a
/// description of everything it tried, of which only the reason matters.
pub(crate) fn mongodb_error(error: &mongodb::error::Error) -> anyhow::Error {
    use mongodb::error::ErrorKind;
    match &*error.kind {
        ErrorKind::Authentication { message, .. } => {
            short(format!("it didn't accept the login: {message}"))
        }
        // The message repeats the whole command, which says nothing more.
        ErrorKind::Command(command) if command.code == 13 => {
            anyhow!("the account isn't allowed to ({})", command.code_name)
        }
        ErrorKind::Command(command) => short(&command.message),
        ErrorKind::ServerSelection { message, .. } => {
            // Such as "… Error: Kind: I/O error: Connection refused (os error
            // 61), labels: {} } ] }".
            let reason = message
                .rsplit_once("Error: ")
                .map(|(_, reason)| reason)
                .unwrap_or(message);
            let reason = reason
                .trim_start_matches("Kind: ")
                .split(", labels:")
                .next()
                .unwrap_or(reason);
            if reason.contains("wire protocol") {
                return anyhow!("it didn't answer as MongoDB does");
            }
            short(reason)
        }
        _ => short(error),
    }
}

/// Takes whatever key the server offers, noting it, as the check compares it
/// with the one it was told to expect once connected.
struct KeyNoter {
    seen: Arc<Mutex<Option<String>>>,
}

impl russh::client::Handler for KeyNoter {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = key
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(fingerprint);
        Ok(true)
    }
}

pub(crate) async fn check_ssh(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let socket = open(check, findings).await?;
    let seen = Arc::new(Mutex::new(None));
    let noter = KeyNoter { seen: seen.clone() };
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect_stream(config, socket, noter)
        .await
        .map_err(short)?;
    let key = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    findings.host_key = key.clone();
    // Before anything secret goes to it: a different key isn't the server meant.
    if let Some(expected) = &check.host_key {
        ensure!(
            key.as_deref() == Some(expected.as_str()),
            "its host key isn't the one expected"
        );
    }

    let result = match credentials.filter(|given| !given.is_empty()) {
        None => {
            // Asking with no credentials makes it list the ways it accepts.
            match session.authenticate_none("maxnines").await.map_err(short)? {
                russh::client::AuthResult::Success => {
                    findings.sign_in_methods = Some("none needed".to_string());
                }
                russh::client::AuthResult::Failure {
                    remaining_methods, ..
                } => {
                    let names: Vec<&str> = remaining_methods.iter().map(<&str>::from).collect();
                    findings.password_sign_in = Some(u8::from(names.contains(&"password")));
                    findings.sign_in_methods = Some(names.join(", "));
                }
            }
            Ok(())
        }
        Some(credentials) => {
            let username = credentials
                .username
                .as_deref()
                .context("signing in needs a username")?;
            let outcome = if let Some(pem) = &credentials.private_key {
                let key = russh::keys::decode_secret_key(pem, None)
                    .map_err(|_| anyhow!("the private key couldn't be read"))?;
                let hash = session
                    .best_supported_rsa_hash()
                    .await
                    .map_err(short)?
                    .flatten();
                let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash);
                session.authenticate_publickey(username, key).await
            } else {
                let password = credentials
                    .password
                    .as_deref()
                    .context("signing in needs a password or a private key")?;
                session.authenticate_password(username, password).await
            };
            if outcome.map_err(short)?.success() {
                findings.signed_in = Some(true);
                Ok(())
            } else {
                findings.signed_in = Some(false);
                Err(anyhow!(
                    "it didn't accept the username and its password or key"
                ))
            }
        }
    };
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    result
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use maxnines_protocol::CheckKind;
    use serde_json::Value;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;
    use crate::run_signed_in;

    /// Made for these tests with ssh-keygen, and used for nothing else.
    const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAB99nrYQk+/nYtnTbIiPL9foeIin2Zuz6/JzHdMY6x6QAAAJjXJLHv1ySx\n7wAAAAtzc2gtZWQyNTUxOQAAACAB99nrYQk+/nYtnTbIiPL9foeIin2Zuz6/JzHdMY6x6Q\nAAAEAIbYu2uOxRiqZJta5kjeML6CJE0GVnmCr3Threer9h3gH32ethCT7+di2dNsiI8v1+\nh4iKfZm7Pr8nMd0xjrHpAAAAEm1heG5pbmVzIHRlc3QgaG9zdAECAw==\n-----END OPENSSH PRIVATE KEY-----";
    const HOST_KEY_FINGERPRINT: &str = "SHA256:A7r2YBOrZvG4u2ZeDCi5DagR8JhWYqOeNsxmHM8VSTM";
    const CLIENT_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACD7rOxNzO8fVgCgw0gcX+7leMPzi/QYZypG1c7i6eRk4wAAAJha8HnJWvB5\nyQAAAAtzc2gtZWQyNTUxOQAAACD7rOxNzO8fVgCgw0gcX+7leMPzi/QYZypG1c7i6eRk4w\nAAAECwi5rr+zfbkwIiXnrpu+0OHjnU8uri5pqk5ePJaszf3fus7E3M7x9WAKDDSBxf7uV4\nw/OL9BhnKkbVzuLp5GTjAAAAFG1heG5pbmVzIHRlc3QgY2xpZW50AQ==\n-----END OPENSSH PRIVATE KEY-----";

    fn check(kind: CheckKind, address: SocketAddr) -> Check {
        Check::new("test", kind, &address.to_string())
    }

    fn login(username: &str, password: &str) -> Credentials {
        Credentials {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            private_key: None,
        }
    }

    /// Answers each connection with what `reply` does with it.
    async fn serve<F, Fut>(reply: F) -> SocketAddr
    where
        F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let reply = Arc::new(reply);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(reply(socket));
            }
        });
        address
    }

    async fn run(check: &Check, credentials: Option<&Credentials>) -> Value {
        run_signed_in(check, credentials).await
    }

    #[tokio::test]
    async fn postgres_is_recognised_without_signing_in() {
        let address = serve(|mut socket| async move {
            let mut request = [0u8; 8];
            if socket.read_exact(&mut request).await.is_ok()
                && request[4..] == [0x04, 0xd2, 0x16, 0x2f]
            {
                let _ = socket.write_all(b"S").await;
            }
        })
        .await;
        let result = run(&check(CheckKind::Postgres, address), None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["tls_offered"], true);
        assert!(result.get("signed_in").is_none(), "{result}");

        // Something else on the port, which just hangs up.
        let other = serve(|socket| async move { drop(socket) }).await;
        let result = run(&check(CheckKind::Postgres, other), None).await;
        assert_eq!(result["up"], 0, "{result}");
    }

    #[tokio::test]
    async fn mysql_says_its_version_before_anyone_signs_in() {
        let greeting = |payload: &'static [u8]| {
            move |mut socket: tokio::net::TcpStream| async move {
                let length = payload.len() as u8;
                let mut packet = vec![length, 0, 0, 0];
                packet.extend_from_slice(payload);
                let _ = socket.write_all(&packet).await;
            }
        };
        let address = serve(greeting(b"\x0a8.4.3\x00\x01\x00\x00\x00")).await;
        let result = run(&check(CheckKind::Mysql, address), None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["server_version"], "8.4.3");

        let refused = serve(greeting(b"\xff\x6a\x04Host '10.0.0.9' is not allowed")).await;
        let result = run(&check(CheckKind::Mysql, refused), None).await;
        assert_eq!(result["up"], 0);
        assert_eq!(
            result["error"],
            "it refused the connection: Host '10.0.0.9' is not allowed"
        );
    }

    /// Enough of Redis for a check: PING, AUTH with one password, and INFO.
    async fn fake_redis(password: Option<&'static str>) -> SocketAddr {
        serve(move |socket| async move {
            let (reader, mut writer) = socket.into_split();
            let mut reader = BufReader::new(reader);
            let mut signed_in = password.is_none();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let Some(count) = line.trim().strip_prefix('*') else {
                    return;
                };
                let mut parts = Vec::new();
                for _ in 0..count.parse::<usize>().unwrap_or(0) {
                    let mut size = String::new();
                    reader.read_line(&mut size).await.unwrap();
                    let mut part = String::new();
                    reader.read_line(&mut part).await.unwrap();
                    parts.push(part.trim_end().to_string());
                }
                let command = parts.first().map(|c| c.to_uppercase()).unwrap_or_default();
                let reply = match command.as_str() {
                    "AUTH" if Some(parts.last().map(String::as_str).unwrap_or("")) == password => {
                        signed_in = true;
                        "+OK\r\n".to_string()
                    }
                    "AUTH" => "-WRONGPASS invalid username-password pair\r\n".to_string(),
                    _ if !signed_in => "-NOAUTH Authentication required.\r\n".to_string(),
                    "PING" => "+PONG\r\n".to_string(),
                    "INFO" => {
                        let body = "# Server\r\nredis_version:7.4.1\r\n";
                        format!("${}\r\n{body}\r\n", body.len())
                    }
                    _ => "+OK\r\n".to_string(),
                };
                if writer.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
            }
        })
        .await
    }

    #[tokio::test]
    async fn redis_answers_and_signs_in() {
        let open = fake_redis(None).await;
        let result = run(&check(CheckKind::Redis, open), None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["server_version"], "7.4.1");

        let locked = fake_redis(Some("s3cret")).await;
        // It answers as Redis does, so it's there, though it wants signing in.
        let result = run(&check(CheckKind::Redis, locked), None).await;
        assert_eq!(result["up"], 1, "{result}");
        let result = run(
            &check(CheckKind::Redis, locked),
            Some(&login("default", "s3cret")),
        )
        .await;
        assert_eq!(
            (&result["up"], &result["signed_in"]),
            (&Value::from(1), &Value::from(true)),
            "{result}"
        );
        let result = run(
            &check(CheckKind::Redis, locked),
            Some(&login("default", "guess")),
        )
        .await;
        assert_eq!(result["up"], 0, "{result}");
        assert!(!result.to_string().contains("guess"), "{result}");
    }

    struct TestServer;

    impl russh::server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(if (user, password) == ("monitor", "s3cret") {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: russh::server::VerifiedPublicKey<'_>,
        ) -> Result<russh::server::Auth, Self::Error> {
            let expected = russh::keys::decode_secret_key(CLIENT_KEY, None).unwrap();
            let same = key.public_key.key_data() == expected.public_key().key_data();
            Ok(if user == "monitor" && same {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }
    }

    async fn ssh_server() -> SocketAddr {
        let config = Arc::new(russh::server::Config {
            keys: vec![russh::keys::decode_secret_key(HOST_KEY, None).unwrap()],
            auth_rejection_time: std::time::Duration::from_millis(1),
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            ..Default::default()
        });
        serve(move |socket| {
            let config = config.clone();
            async move {
                if let Ok(running) = russh::server::run_stream(config, socket, TestServer).await {
                    let _ = running.await;
                }
            }
        })
        .await
    }

    #[tokio::test]
    async fn ssh_reports_its_key_and_how_it_can_be_signed_in_to() {
        let address = ssh_server().await;
        let plain = check(CheckKind::Ssh, address);
        let result = run(&plain, None).await;
        assert_eq!(result["up"], 1, "{result}");
        assert_eq!(result["host_key"], HOST_KEY_FINGERPRINT);
        let methods = result["sign_in_methods"].as_str().unwrap();
        assert!(
            methods.contains("password") && methods.contains("publickey"),
            "{methods}"
        );
        assert_eq!(result["password_sign_in"], 1);

        let mut pinned = plain.clone();
        pinned.host_key = Some(HOST_KEY_FINGERPRINT.to_string());
        assert_eq!(run(&pinned, None).await["up"], 1);
        pinned.host_key = Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        let result = run(&pinned, Some(&login("monitor", "s3cret"))).await;
        assert_eq!(result["up"], 0);
        assert_eq!(result["error"], "its host key isn't the one expected");
        assert!(
            result.get("signed_in").is_none(),
            "nothing was tried: {result}"
        );
    }

    #[tokio::test]
    async fn ssh_signs_in_with_a_password_or_a_key() {
        let address = ssh_server().await;
        let ssh = check(CheckKind::Ssh, address);
        let result = run(&ssh, Some(&login("monitor", "s3cret"))).await;
        assert_eq!(result["signed_in"], true, "{result}");
        assert_eq!(result["up"], 1);

        let result = run(&ssh, Some(&login("monitor", "guess"))).await;
        assert_eq!(
            (&result["up"], &result["signed_in"]),
            (&Value::from(0), &Value::from(false)),
            "{result}"
        );

        let keyed = Credentials {
            username: Some("monitor".to_string()),
            password: None,
            private_key: Some(CLIENT_KEY.to_string()),
        };
        let result = run(&ssh, Some(&keyed)).await;
        assert_eq!(result["signed_in"], true, "{result}");
        assert!(!result.to_string().contains("PRIVATE KEY"), "{result}");
    }

    /// Real servers, where the environment says where to find them, as
    /// `host:port username`, with no password needed.
    /// A real server named by an environment variable, as `host:port username`,
    /// with the password after the username for servers that ask for one.
    fn real(variable: &str) -> Option<(String, Credentials)> {
        let value = std::env::var(variable).ok()?;
        let mut words = value.split_whitespace();
        let (target, username) = (words.next()?, words.next()?);
        let credentials = Credentials {
            username: Some(username.to_string()),
            password: words.next().map(String::from),
            ..Credentials::default()
        };
        Some((target.to_string(), credentials))
    }

    #[tokio::test]
    async fn real_databases_are_signed_in_to() {
        for (variable, kind) in [
            ("MAXNINES_TEST_CHECK_POSTGRES", CheckKind::Postgres),
            ("MAXNINES_TEST_CHECK_MYSQL", CheckKind::Mysql),
            ("MAXNINES_TEST_CHECK_MONGODB", CheckKind::Mongodb),
        ] {
            let Some((target, credentials)) = real(variable) else {
                continue;
            };
            let check = Check::new("real", kind, &target);
            let result = run(&check, None).await;
            assert_eq!(result["up"], 1, "{variable} without signing in: {result}");
            let result = run(&check, Some(&credentials)).await;
            assert_eq!(result["signed_in"], true, "{variable}: {result}");
            assert!(result["server_version"].is_string(), "{result}");
            let mut wrong = credentials.clone();
            wrong.username = Some("nobody_at_all".to_string());
            let result = run(&check, Some(&wrong)).await;
            assert_eq!(result["up"], 0, "{variable} as nobody: {result}");
        }
    }

    #[tokio::test]
    async fn mongodb_that_isnt_there_says_why_in_a_few_words() {
        let check = Check::new("test", CheckKind::Mongodb, "127.0.0.1:0");
        let result = run(&check, None).await;
        assert_eq!(result["up"], 0, "{result}");
        let error = result["error"].as_str().unwrap();
        assert!(error.contains("connect"), "{error}");
    }

    #[tokio::test]
    async fn something_else_isnt_taken_for_mongodb() {
        let address = serve(|mut socket| async move {
            let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await;
        })
        .await;
        let mut check = check(CheckKind::Mongodb, address);
        check.timeout_secs = Some(2);
        let result = run(&check, Some(&login("monitor", "s3cret"))).await;
        assert_eq!(result["up"], 0, "{result}");
        assert!(result.get("signed_in").is_none(), "{result}");
        // Saying so, rather than running out of time.
        let error = result["error"].as_str().unwrap();
        assert_eq!(error, "it didn't answer as MongoDB does");
    }

    #[test]
    fn credentials_are_never_printed() {
        let printed = format!("{:?}", login("monitor", "s3cret"));
        assert!(
            printed.contains("monitor") && !printed.contains("s3cret"),
            "{printed}"
        );
    }
}
