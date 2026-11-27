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

use anyhow::{Context, Result, anyhow, bail, ensure};
use maxnines_protocol::{Check, CheckKind};
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Findings, RecordingVerifier, connect, host_and_port, provider, resolve, trusted_roots,
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

/// What a check says when a server won't upgrade to TLS, rather than send it a
/// password in the clear.
pub(crate) const TLS_NOT_OFFERED: &str = "it doesn't offer TLS, so the password wasn't sent";

/// What a check of a server that can't upgrade to TLS, and takes a password as it
/// is, says for one that isn't on its own host and isn't set to use TLS.
pub(crate) const TLS_NEEDED_ELSEWHERE: &str =
    "a password is only sent without TLS to the host itself, so set tls for one elsewhere";

/// The username and password a check of `kind` signs in with, if it was given any,
/// with what its kind needs. An empty one is none, and a username or password left
/// out where the kind can do without is empty.
pub(crate) fn username_and_password(
    credentials: Option<&Credentials>,
    kind: CheckKind,
) -> Result<Option<(&str, &str)>> {
    let Some(credentials) = credentials.filter(|given| !given.is_empty()) else {
        return Ok(None);
    };
    let needs = kind
        .sign_in()
        .context("this kind of check never signs in")?;
    let username = match credentials
        .username
        .as_deref()
        .filter(|username| !username.is_empty())
    {
        Some(given) => given,
        None if !needs.username => "",
        None => bail!("signing in needs a username"),
    };
    let password = match credentials
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        Some(given) => given,
        None if !needs.password => "",
        None => bail!("signing in needs a password"),
    };
    Ok(Some((username, password)))
}

/// Why a check can never sign in with what it's given, as its kind needs, if it
/// can't, so the mistake is turned down when it's saved or read from the agent's
/// config, rather than failing every time the check runs. `username` and `secret`
/// say whether each is given, the secret being a password, or a key where the kind
/// takes one.
pub fn sign_in_problem(check: &Check, username: bool, secret: bool) -> Option<&'static str> {
    let needs = check.kind.sign_in()?;
    if !username && !secret {
        return needs.required.then_some(SIGN_IN_REQUIRED);
    }
    let on_its_own_host = || host_and_port(&check.target).is_ok_and(|(host, _)| is_loopback(&host));
    if needs.username && !username {
        Some("signing in needs a username")
    } else if needs.password && !secret {
        Some(match needs.key {
            true => "signing in needs a password or a private key",
            false => "signing in needs a password",
        })
    } else if needs.password_in_clear && secret && check.tls != Some(true) && !on_its_own_host() {
        Some(TLS_NEEDED_ELSEWHERE)
    } else {
        None
    }
}

/// Why a MySQL or MariaDB check has to sign in: one that only reads the greeting and
/// hangs up counts, as a load balancer's does, toward MySQL blocking the host it's
/// checked from, after `max_connect_errors` in a row.
pub const SIGN_IN_REQUIRED: &str = "a MySQL or MariaDB check has to sign in with a username, \
    as MySQL counts a check that only reads its greeting toward blocking the host it's checked from";

/// A database turning down the account and password it was given, as opposed to
/// anything else going wrong, so the check says the login was refused, as mail, SSH,
/// LDAP and MQTT checks do.
#[derive(Debug)]
pub(crate) struct LoginRefused(String);

impl fmt::Display for LoginRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoginRefused {}

/// `error` as it's said, marked as a refused login when it's one.
pub(crate) fn login_refused_if(refused: bool, error: anyhow::Error) -> anyhow::Error {
    match refused {
        true => anyhow::Error::new(LoginRefused(error.to_string())),
        false => error,
    }
}

/// TLS for a driver: the certificate checked as for a site, or not at all for a
/// check told not to mind.
fn driver_tls(insecure: bool) -> Result<ClientConfig> {
    let builder =
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let config = if insecure {
        // Notes what's wrong and carries on regardless, which is what was asked.
        let (verifier, _) = RecordingVerifier::new()?;
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
/// A driver's own connection is opened after this one, so that what's timed is
/// the same for every kind of check, and a closed port fails at once with the
/// usual words.
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
        let offered = answer[0] == b'S';
        findings.tls_offered = Some(offered);
        ensure!(
            offered || check.tls != Some(true),
            "it doesn't offer TLS, which the check requires"
        );
        return Ok(());
    };
    drop(open(check, findings).await?);
    let (client, running) = postgres_client(check, credentials, check.tls == Some(true)).await?;
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
    let (client, connection) = config.connect(tls).await.map_err(|error| {
        use tokio_postgres::error::SqlState;
        let refused = error.as_db_error().is_some_and(|database| {
            [
                SqlState::INVALID_PASSWORD,
                SqlState::INVALID_AUTHORIZATION_SPECIFICATION,
            ]
            .contains(database.code())
        });
        login_refused_if(refused, pg_short(error))
    })?;
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
        bail!(SIGN_IN_REQUIRED);
    };
    drop(open(check, findings).await?);
    let mut connection = mysql_connection(check, credentials).await?;
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
    mysql_async::Conn::new(options).await.map_err(mysql_failure)
}

/// What went wrong signing in to MySQL, as a check says it.
fn mysql_failure(error: mysql_async::Error) -> anyhow::Error {
    match &error {
        // Access denied, by password or, over the socket, by who's asking.
        mysql_async::Error::Server(server) if matches!(server.code, 1045 | 1698) => {
            login_refused_if(true, short(error))
        }
        // MySQL answers a user it hasn't got as if it had one, signing in a way
        // picked for it, sometimes sha256_password, which the driver can't use. An
        // account that really signs in that way can't be signed in to either, so
        // it's refused all the same, saying which it could be.
        mysql_async::Error::Driver(mysql_async::DriverError::UnknownAuthPlugin { name })
            if name == "sha256_password" =>
        {
            login_refused_if(true, anyhow!("{UNSUPPORTED_SHA256}"))
        }
        _ => short(error),
    }
}

/// What a MySQL check says when it's asked to sign in with sha256_password.
const UNSUPPORTED_SHA256: &str = "MySQL asked to sign in with sha256_password, which isn't \
    supported: there's no such account, or it signs in that way, which \
    caching_sha2_password replaced";

/// Whether a host is this machine itself, which a password can be sent to without
/// TLS, as it never crosses a network.
pub(crate) fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// A Redis client that signs in with `credentials`, if they have anything: a
/// password, for Redis before 6 or its default user, or an ACL user and its
/// password. TLS is only used when the check says so. Redis takes a password as
/// it is, so one is only sent without TLS to the host itself.
pub(crate) fn redis_client(
    check: &Check,
    credentials: Option<&Credentials>,
) -> Result<redis::Client> {
    let (host, port) = host_and_port(&check.target)?;
    let tls = check.tls == Some(true);
    let mut settings = redis::RedisConnectionInfo::default().set_skip_set_lib_name();
    if let Some(credentials) = credentials.filter(|given| !given.is_empty()) {
        let password = credentials
            .password
            .as_deref()
            .context("signing in needs a password")?;
        ensure!(tls || is_loopback(&host), TLS_NEEDED_ELSEWHERE);
        settings = settings.set_password(password);
        if let Some(username) = &credentials.username {
            settings = settings.set_username(username);
        }
    }
    let address = if tls {
        redis::ConnectionAddr::TcpTls {
            host,
            port,
            insecure: check.insecure == Some(true),
            tls_params: None,
        }
    } else {
        redis::ConnectionAddr::Tcp(host, port)
    };
    let info = redis::IntoConnectionInfo::into_connection_info(address)
        .map_err(short)?
        .set_redis_settings(settings);
    redis::Client::open(info).map_err(short)
}

pub(crate) async fn check_redis(
    check: &Check,
    credentials: Option<&Credentials>,
    findings: &mut Findings,
) -> Result<()> {
    let signing_in = credentials.filter(|given| !given.is_empty());
    let client = redis_client(check, signing_in)?;
    drop(open(check, findings).await?);
    // The check's own time limit covers it all, rather than the driver's, which
    // gives connecting a second and each answer half of one, too little for a
    // server far away or busy saving.
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(None)
        .set_response_timeout(None);
    let mut connection = client
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .map_err(|error| {
            let refused = error.kind() == redis::ErrorKind::AuthenticationFailed
                || error.code() == Some("WRONGPASS");
            login_refused_if(refused, short(error))
        })?;
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
        ErrorKind::Authentication { message, .. } => login_refused_if(
            true,
            short(format!("it didn't accept the login: {message}")),
        ),
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
                    // Keyboard-interactive is how a password is usually asked for through
                    // PAM, which FreeBSD and many Linux systems do in place of
                    // `password`, so either takes one.
                    let takes_password = names
                        .iter()
                        .any(|name| matches!(*name, "password" | "keyboard-interactive"));
                    findings.password_sign_in = Some(u8::from(takes_password));
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

    /// A login is taken as the kind's description says it needs one.
    #[test]
    fn a_login_needs_what_its_kind_says() {
        let given = |username: Option<&str>, password: Option<&str>| Credentials {
            username: username.map(str::to_string),
            password: password.map(str::to_string),
            private_key: None,
        };
        fn login(
            kind: CheckKind,
            credentials: &Credentials,
        ) -> Result<Option<(&str, &str)>, String> {
            username_and_password(Some(credentials), kind).map_err(|error| error.to_string())
        }
        // Redis before version 6 has no usernames.
        let redis = given(None, Some("s3cret"));
        assert_eq!(login(CheckKind::Redis, &redis), Ok(Some(("", "s3cret"))));
        assert_eq!(
            login(CheckKind::Ldap, &redis),
            Err("signing in needs a username".to_string())
        );
        // A broker can let a username in alone.
        let alone = given(Some("monitor"), None);
        assert_eq!(login(CheckKind::Mqtt, &alone), Ok(Some(("monitor", ""))));
        assert_eq!(
            login(CheckKind::Ldap, &alone),
            Err("signing in needs a password".to_string())
        );
        // ClickHouse's password goes in plain HTTP without TLS, so it's turned down
        // when a check is saved, rather than every time it runs.
        let elsewhere = Check::new("ch", CheckKind::Clickhouse, "db.example.com:8123");
        assert_eq!(
            sign_in_problem(&elsewhere, true, true),
            Some(TLS_NEEDED_ELSEWHERE)
        );
        let here = Check::new("ch", CheckKind::Clickhouse, "127.0.0.1:8123");
        assert_eq!(sign_in_problem(&here, true, true), None);
        // Its `default` user has no password unless one is set, wherever it is.
        assert_eq!(sign_in_problem(&elsewhere, true, false), None);
        assert_eq!(
            login(CheckKind::Clickhouse, &alone),
            Ok(Some(("monitor", "")))
        );
    }

    #[test]
    fn mysql_asking_for_sha256_password_is_a_refused_login_it_cant_use() {
        let asked = mysql_async::Error::Driver(mysql_async::DriverError::UnknownAuthPlugin {
            name: "sha256_password".to_string(),
        });
        let error = mysql_failure(asked);
        assert!(error.is::<LoginRefused>());
        assert!(error.to_string().contains("isn't supported"), "{error}");
        let other = mysql_async::Error::Driver(mysql_async::DriverError::UnknownAuthPlugin {
            name: "authentication_ldap_sasl".to_string(),
        });
        assert!(!mysql_failure(other).is::<LoginRefused>());
    }

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

    /// MySQL counts a client that only reads its greeting and hangs up toward
    /// blocking its host, so a check never does, and is never run without a login.
    #[tokio::test]
    async fn mysql_is_never_checked_without_signing_in() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let greeted = Arc::new(AtomicBool::new(false));
        let seen = greeted.clone();
        let address = serve(move |_socket| {
            let seen = seen.clone();
            async move { seen.store(true, Ordering::Relaxed) }
        })
        .await;
        let result = run(&check(CheckKind::Mysql, address), None).await;
        assert_eq!(result["up"], 0, "{result}");
        assert_eq!(result["error"], SIGN_IN_REQUIRED);
        assert!(!greeted.load(Ordering::Relaxed), "it connected");
        let mysql = check(CheckKind::Mysql, address);
        assert_eq!(
            sign_in_problem(&mysql, false, false),
            Some(SIGN_IN_REQUIRED)
        );
        assert_eq!(sign_in_problem(&mysql, true, false), None);
    }

    /// Enough of Redis for a check: PING, AUTH with one password, and INFO.
    async fn fake_redis(password: Option<&'static str>) -> SocketAddr {
        slow_redis(password, std::time::Duration::ZERO).await
    }

    /// As [`fake_redis`], taking `delay` over each answer, as a busy one does.
    async fn slow_redis(password: Option<&'static str>, delay: std::time::Duration) -> SocketAddr {
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
                tokio::time::sleep(delay).await;
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
        assert_eq!(result["signed_in"], false, "{result}");
        assert!(!result.to_string().contains("guess"), "{result}");
    }

    /// Slower than the driver's own half a second, well within the check's limit.
    #[tokio::test]
    async fn a_slow_redis_is_up() {
        let slow = slow_redis(None, std::time::Duration::from_millis(800)).await;
        let result = run(&check(CheckKind::Redis, slow), None).await;
        assert_eq!(result["up"], 1, "{result}");
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
        ssh_server_offering(russh::server::Config::default().methods).await
    }

    /// One offering only these ways to sign in.
    async fn ssh_server_offering(methods: russh::MethodSet) -> SocketAddr {
        let config = Arc::new(russh::server::Config {
            methods,
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

    /// A password asked for through PAM, as FreeBSD does by default, counts.
    #[tokio::test]
    async fn ssh_that_takes_passwords_through_keyboard_interactive_offers_them() {
        use russh::MethodKind;
        let pam = ssh_server_offering(
            [MethodKind::PublicKey, MethodKind::KeyboardInteractive][..].into(),
        )
        .await;
        let result = run(&check(CheckKind::Ssh, pam), None).await;
        assert_eq!(result["password_sign_in"], 1, "{result}");

        let keys = ssh_server_offering([MethodKind::PublicKey][..].into()).await;
        let result = run(&check(CheckKind::Ssh, keys), None).await;
        assert_eq!(result["password_sign_in"], 0, "{result}");
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
            ("MAXNINES_TEST_CHECK_CLICKHOUSE", CheckKind::Clickhouse),
        ] {
            let Some((target, credentials)) = real(variable) else {
                continue;
            };
            let check = Check::new("real", kind, &target);
            let result = run(&check, None).await;
            // MySQL is never checked without signing in.
            let up = u8::from(kind != CheckKind::Mysql);
            assert_eq!(result["up"], up, "{variable} without signing in: {result}");
            let result = run(&check, Some(&credentials)).await;
            assert_eq!(result["signed_in"], true, "{variable}: {result}");
            assert!(result["server_version"].is_string(), "{result}");
            // A user it hasn't got, and a wrong password for one it has, except on
            // PostgreSQL, which may trust whoever connects from the machine itself.
            let known = credentials.username.as_deref().unwrap();
            let usernames = match kind {
                CheckKind::Postgres => vec!["nobody_at_all"],
                _ => vec!["nobody_at_all", known],
            };
            for username in usernames {
                let wrong = Credentials {
                    username: Some(username.to_string()),
                    password: Some("wrong".to_string()),
                    ..credentials.clone()
                };
                let result = run(&check, Some(&wrong)).await;
                assert_eq!(result["up"], 0, "{variable} as {username}: {result}");
                assert_eq!(
                    result["signed_in"], false,
                    "{variable} as {username}: {result}"
                );
            }
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
        // Like a real SSH server, it stays connected, reading what it's sent. One
        // that closed at once would be reset on Windows, as what the driver sent
        // was never read, and the driver would only see the connection go.
        let address = serve(|mut socket| async move {
            let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await;
            let mut sent = Vec::new();
            let _ = socket.read_to_end(&mut sent).await;
        })
        .await;
        let mut check = check(CheckKind::Mongodb, address);
        check.timeout = Some(std::time::Duration::from_secs(2));
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
