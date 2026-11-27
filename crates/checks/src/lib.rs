//! Tries reaching things, to see if they're up and how quickly. Agents run these
//! from where they are, and the server runs them against remote sites directly.
//! Each stage of a web request is timed separately, so a slow site can be told apart from slow
//! DNS, and whatever was learned before a failure is still reported.
//!
//! Errors only ever say what kind of failure it was, as a URL can hold a password.

pub mod databases;
mod ftp;
mod ldap;
mod mail;
mod memcached;
mod mqtt;
pub mod openmetrics;
#[cfg(windows)]
mod ping;
mod rdap;
mod sign_in;
pub mod templates;
#[cfg(test)]
mod test_tls;
pub mod unifi;

pub use sign_in::{Credentials, sign_in_problem};

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::process::Stdio;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use flate2::read::GzDecoder;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, HOST, HeaderName, HeaderValue, USER_AGENT,
};
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use maxnines_protocol::{Check, CheckKind, DEFAULT_CHECK_TIMEOUT, Target};
use regex_lite::Regex;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, ProtocolVersion,
    RootCertStore, SignatureScheme,
};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
#[cfg(unix)]
use tokio::process::Command;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::parse_x509_certificate;

/// A name can have several addresses, and one that's gone shouldn't use up the
/// whole time limit before the others are tried.
const CONNECT_ATTEMPT: Duration = Duration::from_secs(5);

/// How much of a page is read. It's only measured and searched, never kept.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// What a page fetched for a collector is refused for, when it's bigger than is read.
const TOO_BIG: &str = "the page is bigger than the 10 MiB that's read";

/// What's put in the logs of sites being checked.
const AGENT_NAME: &str = concat!("MaxNines-Agent/", env!("CARGO_PKG_VERSION"));

const DNS_PORT: u16 = 53;

/// The largest answer a plain UDP lookup returns.
const DNS_BUFFER_BYTES: usize = 4096;

/// The host a check reaches, as a name for a host to keep it under: the host in a
/// website's address, what's before the port for a target given as `host:port`, and
/// the name itself for DNS and ping. An IPv6 address comes without its brackets, and
/// a name is in lower case, as hostnames are.
pub fn host_reached(check: &Check) -> String {
    let target = check.target.as_str();
    let host = match check.kind.target() {
        Target::Url | Target::Console => Uri::from_str(target)
            .ok()
            .and_then(|uri| uri.host().map(String::from))
            .unwrap_or_else(|| target.to_string()),
        Target::HostPort => target
            .rsplit_once(':')
            .map_or(target, |(host, _port)| host)
            .to_string(),
        Target::Hostname => target.to_string(),
        // It reaches nothing, so its host is named after the work it watches.
        Target::None => check.name.clone(),
    };
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase()
}

/// A random length of time up to `limit`, to start something at a random point in
/// its first interval, so things started together don't all run at once.
pub fn jitter(limit: Duration) -> Duration {
    limit.mul_f64(rand::random())
}

/// How long a check gets. A slower answer counts as down.
pub fn limit(check: &Check) -> Duration {
    check.timeout.unwrap_or(DEFAULT_CHECK_TIMEOUT)
}

fn timed_out() -> anyhow::Error {
    anyhow!("timed out")
}

/// What a check found out. Stage times are how long each stage took on its own,
/// so together they add up to about `response_secs`.
#[derive(Debug, Default, Serialize)]
struct Findings {
    response_secs: Option<f64>,
    dns_secs: Option<f64>,
    connect_secs: Option<f64>,
    tls_secs: Option<f64>,
    first_byte_secs: Option<f64>,
    download_secs: Option<f64>,
    status: Option<u16>,
    protocol: Option<String>,
    content_length: Option<usize>,
    compressed: Option<bool>,
    regex_matched: Option<bool>,
    tls_version: Option<String>,
    cert_valid: Option<bool>,
    hostname_valid: Option<bool>,
    cert_valid_from: Option<DateTime<Utc>>,
    cert_valid_until: Option<DateTime<Utc>>,
    cert_days_left: Option<i64>,
    records: Option<usize>,
    /// postgres, mail, ftp and ldap: whether it offers TLS, asked without signing in.
    tls_offered: Option<bool>,
    /// What the server says it is, such as 16.4 or 8.4.3.
    server_version: Option<String>,
    /// Whether it signed in, when it was given a way to.
    signed_in: Option<bool>,
    /// ssh: the SHA-256 fingerprint of the server's host key.
    host_key: Option<String>,
    /// ssh: the ways it offers to sign in, when not signing in.
    sign_in_methods: Option<String>,
    /// ssh: 1 if it offers signing in with a password, which an alert can watch.
    password_sign_in: Option<u8>,
    /// http: when the site's domain registration runs out, and how many days
    /// that leaves, or why that couldn't be found out.
    domain_expires_at: Option<DateTime<Utc>>,
    domain_days_left: Option<i64>,
    domain_error: Option<String>,
    /// memcached: since it started, the share of reads it had the key for, and how
    /// many keys it's dropped to make room.
    hit_rate_percent: Option<f64>,
    evictions: Option<u64>,
    /// memcached: the memory its keys take, and how much they're allowed.
    memory_used_bytes: Option<u64>,
    memory_limit_bytes: Option<u64>,
    /// memcached: how many connections it has open, this one included.
    connections: Option<u64>,
    /// ldap: reading the entry the directory's data starts at, once signed in.
    search_secs: Option<f64>,
    /// mqtt: a test message going to the broker and coming back.
    round_trip_secs: Option<f64>,
    packet_loss_percent: Option<f64>,
    rtt_min_secs: Option<f64>,
    rtt_max_secs: Option<f64>,
    rtt_stddev_secs: Option<f64>,
}

/// A server closing the connection where an answer was due.
#[derive(Debug)]
pub(crate) struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("it closed the connection")
    }
}

impl std::error::Error for Closed {}

/// What a check without TLS says of a server that hung up on its first request
/// without answering it, which is what a port that only takes TLS does.
pub(crate) const TLS_ONLY: &str = "it closed the connection without answering, which a port that only takes TLS does \
     when tls isn't set";

/// What a check without TLS says of a server that answered it in TLS.
pub(crate) const TLS_ANSWER: &str = "it answered in TLS, so it needs tls set";

/// Whether `bytes` start as a TLS record does, which is how a port that only takes
/// TLS answers what isn't, with an alert.
pub(crate) fn starts_as_tls(bytes: &[u8]) -> bool {
    // An alert's content type, then the record's version, 3.x.
    bytes.starts_with(&[0x15, 0x03])
}

/// Whether `error` is the server hanging up, by closing the connection or
/// resetting it.
pub(crate) fn hung_up(error: &anyhow::Error) -> bool {
    use std::io::ErrorKind;
    error.is::<Closed>()
        || error.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
            )
        })
}

fn elapsed_secs(since: Instant) -> f64 {
    since.elapsed().as_secs_f64()
}

fn report(check: &Check, findings: Findings, result: Result<()>) -> Value {
    let mut output = serde_json::to_value(&findings).unwrap_or_else(|_| json!({}));
    if let Some(fields) = output.as_object_mut() {
        fields.retain(|_, value| !value.is_null());
        fields.insert("name".to_string(), json!(check.name));
        fields.insert("kind".to_string(), json!(check.kind.as_str()));
        fields.insert("up".to_string(), json!(u8::from(result.is_ok())));
        if let Err(error) = result {
            fields.insert("error".to_string(), json!(format!("{error:#}")));
        }
    }
    output
}

/// What to report for a check that never finished, such as one left stuck by
/// the system's resolver.
pub fn timed_out_report(check: &Check) -> Value {
    report(check, Findings::default(), Err(timed_out()))
}

/// What to report for a check that couldn't be run, saying why.
pub fn failed_report(check: &Check, why: &str) -> Value {
    report(check, Findings::default(), Err(anyhow!("{why}")))
}

/// Runs a check, until it's done or out of time. Always gives a result, and
/// whatever was learned before running out of time is kept.
pub async fn run(check: &Check) -> Value {
    run_signed_in(check, None).await
}

/// As [`run`], signing in with these where the check's kind can.
pub async fn run_signed_in(check: &Check, credentials: Option<&Credentials>) -> Value {
    let started = Instant::now();
    let mut findings = Findings::default();
    let work = async {
        match check.kind {
            CheckKind::Tcp => check_tcp(check, &mut findings).await,
            CheckKind::Http => check_http(check, &mut findings).await,
            CheckKind::Tls => check_tls(check, &mut findings).await,
            CheckKind::Dns => check_dns(check, &mut findings).await,
            CheckKind::Ping => check_ping(check, &mut findings).await,
            CheckKind::Postgres => sign_in::check_postgres(check, credentials, &mut findings).await,
            CheckKind::Mysql => sign_in::check_mysql(check, credentials, &mut findings).await,
            CheckKind::Redis => sign_in::check_redis(check, credentials, &mut findings).await,
            CheckKind::Memcached => memcached::check_memcached(check, &mut findings).await,
            CheckKind::Mongodb => sign_in::check_mongodb(check, credentials, &mut findings).await,
            CheckKind::Clickhouse => {
                sign_in::check_clickhouse(check, credentials, &mut findings).await
            }
            CheckKind::Ssh => sign_in::check_ssh(check, credentials, &mut findings).await,
            CheckKind::Smtp => mail::check_smtp(check, credentials, &mut findings).await,
            CheckKind::Imap => mail::check_imap(check, credentials, &mut findings).await,
            CheckKind::Pop3 => mail::check_pop3(check, credentials, &mut findings).await,
            CheckKind::Ftp => ftp::check_ftp(check, credentials, &mut findings).await,
            CheckKind::Ldap => ldap::check_ldap(check, credentials, &mut findings).await,
            CheckKind::Mqtt => mqtt::check_mqtt(check, credentials, &mut findings).await,
            CheckKind::Heartbeat => Err(anyhow!(
                "a heartbeat is pinged at the server rather than run"
            )),
            CheckKind::Unifi => Err(anyhow!(
                "a UniFi check is read by the server, with its API key"
            )),
            CheckKind::Unknown => Err(anyhow!(CheckKind::UNKNOWN_MESSAGE)),
        }
    };
    let result = timeout(limit(check), work)
        .await
        .unwrap_or_else(|_| Err(timed_out()));
    if result.is_ok() {
        findings.response_secs = Some(elapsed_secs(started));
    }
    // After the timing, and never counting against the check: a registry being
    // slow or unsure says nothing about the site.
    if check.kind == CheckKind::Http && check.domain_expiry != Some(false) {
        let left = limit(check).saturating_sub(started.elapsed());
        domain_expiry(check, left, &mut findings).await;
    }
    report(check, findings, result)
}

/// Looks up when the site's domain registration runs out, in whatever's left of
/// the check's time, so a check never takes longer than its limit. A lookup that
/// takes longer carries on by itself, and the next run finds its answer
/// remembered.
async fn domain_expiry(check: &Check, left: Duration, findings: &mut Findings) {
    let Some(host) = Uri::from_str(&check.target)
        .ok()
        .and_then(|uri| uri.host().map(String::from))
    else {
        return;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let lookup = tokio::spawn(async move { rdap::expiry(&host).await });
    let answer = match timeout(left, lookup).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) => Err("the registry couldn't be asked".to_string()),
        Err(_) => Err("the registry didn't answer in time".to_string()),
    };
    match answer {
        Ok(Some(expires)) => {
            findings.domain_expires_at = Some(expires);
            findings.domain_days_left = Some(days_left(expires, maxnines_protocol::time::now()));
        }
        Ok(None) => {}
        Err(why) => findings.domain_error = Some(why),
    }
}

/// What a page that asks who's reading is sent: a username and password, or a
/// token, as the header that carries them.
#[derive(Clone)]
pub struct Login {
    name: HeaderName,
    value: HeaderValue,
}

impl Login {
    /// A username and password, sent as basic authentication.
    pub fn new(username: &str, password: &str) -> Result<Self> {
        use base64::Engine;
        let both =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        Self::header(&format!("Basic {both}")).context("invalid username or password")
    }

    /// A token, sent as a bearer token.
    pub fn token(token: &str) -> Result<Self> {
        // Anything else would end the header early or never match what was issued.
        ensure!(
            !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "a token can't be empty, or hold spaces or anything but plain letters, digits \
             and punctuation"
        );
        Self::header(&format!("Bearer {token}"))
    }

    /// An API key, sent in the `X-API-KEY` header, as UniFi's Network API takes it.
    pub fn api_key(key: &str) -> Result<Self> {
        ensure!(
            !key.is_empty() && key.bytes().all(|byte| byte.is_ascii_graphic()),
            "an API key can't be empty, or hold spaces or anything but plain letters, \
             digits and punctuation"
        );
        Self::named(HeaderName::from_static("x-api-key"), key)
    }

    fn header(value: &str) -> Result<Self> {
        Self::named(AUTHORIZATION, value)
    }

    fn named(name: HeaderName, value: &str) -> Result<Self> {
        let mut value = HeaderValue::from_str(value).map_err(|_| anyhow!("invalid header"))?;
        // Keeps it out of anything that prints headers.
        value.set_sensitive(true);
        Ok(Self { name, value })
    }
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Login")
    }
}

/// Fetches a page for a collector to read, such as a web server's status page,
/// and gives its text. Only a successful answer counts, and the certificate is
/// checked as it is for a web check. A login is only ever sent to the page asked
/// for, as redirects aren't followed.
pub async fn fetch_page(url: &str, limit: Duration, login: Option<&Login>) -> Result<String> {
    let check = Check::new("page", CheckKind::Http, url);
    let work = async {
        let answer = request(&check, &mut Findings::default(), login).await?;
        let status = answer.status;
        ensure!(
            (200..300).contains(&status),
            "the page returned status {status}"
        );
        // A page cut short would be read as if it ended there.
        ensure!(!answer.cut, TOO_BIG);
        tokio::task::spawn_blocking(move || {
            let body = if answer.compressed {
                let (body, cut) =
                    decompress(&answer.body).context("the page couldn't be unpacked")?;
                ensure!(!cut, TOO_BIG);
                body
            } else {
                answer.body
            };
            String::from_utf8(body).map_err(|_| anyhow!("the page isn't text"))
        })
        .await
        .map_err(|_| anyhow!("the request failed"))?
    };
    timeout(limit, work)
        .await
        .unwrap_or_else(|_| Err(timed_out()))
}

fn host_and_port(target: &str) -> Result<(String, u16)> {
    let (host, port) = target.rsplit_once(':').context("no port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host.to_string(), port.parse().context("invalid port")?))
}

async fn resolve(host: &str, port: u16, findings: &mut Findings) -> Result<Vec<SocketAddr>> {
    let started = Instant::now();
    let addresses: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|_| anyhow!("the name wasn't found"))?
        .collect();
    findings.dns_secs = Some(elapsed_secs(started));
    ensure!(!addresses.is_empty(), "the name wasn't found");
    Ok(addresses)
}

/// Tries each address, as only some of a name's may answer.
async fn connect(addresses: &[SocketAddr], findings: &mut Findings) -> Result<TcpStream> {
    let started = Instant::now();
    for address in addresses {
        if let Ok(Ok(stream)) = timeout(CONNECT_ATTEMPT, TcpStream::connect(address)).await {
            findings.connect_secs = Some(elapsed_secs(started));
            return Ok(stream);
        }
    }
    bail!("couldn't connect")
}

async fn check_tcp(check: &Check, findings: &mut Findings) -> Result<()> {
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    connect(&addresses, findings).await?;
    Ok(())
}

/// What the real check of a certificate said, and the certificates it rests on:
/// the path from the site's own to a trusted root, or the site's own alone when
/// there's no such path. A server can send more than the path, such as an old
/// cross-signed certificate, which says nothing about the site.
#[derive(Debug, Default)]
struct Verdict {
    error: Option<TlsError>,
    path: Vec<CertificateDer<'static>>,
}

/// Lets a handshake finish whatever the certificate's like, so that a site with a
/// bad one can still have its certificate's dates and name read, and remembers what
/// the real check said. Nothing is sent over the connection afterwards unless the
/// check was told not to mind, as a request can carry a secret.
#[derive(Debug)]
struct RecordingVerifier {
    real: Arc<WebPkiServerVerifier>,
    outcome: Arc<Mutex<Verdict>>,
}

impl RecordingVerifier {
    fn new() -> Result<(Arc<Self>, Arc<Mutex<Verdict>>)> {
        let outcome = Arc::new(Mutex::new(Verdict::default()));
        let verifier = Arc::new(Self {
            real: site_verifier()?,
            outcome: outcome.clone(),
        });
        Ok((verifier, outcome))
    }
}

/// The certificates from the site's own to a trusted root, which is what the
/// real check just accepted.
fn verified_path(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> Option<Vec<CertificateDer<'static>>> {
    let certificate = webpki::EndEntityCert::try_from(end_entity).ok()?;
    let path = certificate
        .verify_for_usage(
            provider().signature_verification_algorithms.all,
            webpki_roots::TLS_SERVER_ROOTS,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .ok()?;
    let path = std::iter::once(end_entity.clone().into_owned())
        .chain(
            path.intermediate_certificates()
                .map(|certificate| certificate.der().clone().into_owned()),
        )
        .collect();
    Some(path)
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let result = self.real.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let path = match result {
            Ok(_) => verified_path(end_entity, intermediates, now),
            Err(_) => None,
        };
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner) = Verdict {
            error: result.err(),
            path: path.unwrap_or_else(|| vec![end_entity.clone().into_owned()]),
        };
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.real.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.real.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.real.supported_verify_schemes()
    }
}

fn version_name(version: Option<ProtocolVersion>) -> Option<String> {
    match version? {
        ProtocolVersion::TLSv1_2 => Some("TLS 1.2".to_string()),
        ProtocolVersion::TLSv1_3 => Some("TLS 1.3".to_string()),
        other => Some(format!("{other:?}")),
    }
}

fn describe_certificate_problem(error: &TlsError) -> &'static str {
    match error {
        TlsError::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. },
        ) => "the certificate has expired",
        TlsError::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => "the certificate is for a different name",
        _ => "the certificate isn't trusted",
    }
}

/// Reads the dates across the certificates the site rests on, as any of them
/// expiring breaks it. So the start is the latest and the end is the earliest.
fn read_dates(chain: &[CertificateDer<'_>], now: DateTime<Utc>, findings: &mut Findings) {
    for certificate in chain {
        let Ok((_, parsed)) = parse_x509_certificate(certificate) else {
            continue;
        };
        let validity = parsed.validity();
        let (Some(start), Some(end)) = (
            DateTime::from_timestamp(validity.not_before.timestamp(), 0),
            DateTime::from_timestamp(validity.not_after.timestamp(), 0),
        ) else {
            continue;
        };
        findings.cert_valid_from = findings.cert_valid_from.max(Some(start));
        findings.cert_valid_until = Some(findings.cert_valid_until.map_or(end, |e| e.min(end)));
    }
    findings.cert_days_left = findings.cert_valid_until.map(|end| days_left(end, now));
}

/// Whole days until `expires`, rounded down, so it's -1 as soon as it's passed.
fn days_left(expires: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    let left = expires - now;
    let days = left.num_days();
    // Counting whole days rounds towards zero, which would leave a moment past the
    // end with 0 days left rather than -1.
    if left < TimeDelta::days(days) {
        days - 1
    } else {
        days
    }
}

fn tls_config(verifier: Arc<RecordingVerifier>) -> Result<ClientConfig> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// The cryptography every connection uses, made once.
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: LazyLock<Arc<CryptoProvider>> =
        LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));
    PROVIDER.clone()
}

/// The roots certificates are checked against, made once rather than for every
/// connection.
fn trusted_roots() -> Arc<RootCertStore> {
    static ROOTS: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
        Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    });
    ROOTS.clone()
}

/// The check a site's certificate gets, made once.
fn site_verifier() -> Result<Arc<WebPkiServerVerifier>> {
    static VERIFIER: LazyLock<Option<Arc<WebPkiServerVerifier>>> = LazyLock::new(|| {
        WebPkiServerVerifier::builder_with_provider(trusted_roots(), provider())
            .build()
            .ok()
    });
    VERIFIER.clone().context("setting up TLS")
}

/// A connection, and what's wrong with its certificate if anything is.
struct Secured {
    stream: TlsStream<TcpStream>,
    problem: Option<&'static str>,
}

async fn secure(
    host: &str,
    socket: TcpStream,
    alpn: &[&[u8]],
    findings: &mut Findings,
) -> Result<Secured> {
    let name = ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid host name"))?;
    let (verifier, outcome) = RecordingVerifier::new()?;
    let mut config = tls_config(verifier)?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    let started = Instant::now();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name.clone(), socket)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut => timed_out(),
            _ => anyhow!("the TLS handshake failed"),
        })?;
    findings.tls_secs = Some(elapsed_secs(started));

    let (_, connection) = stream.get_ref();
    findings.tls_version = version_name(connection.protocol_version());
    let chain = connection.peer_certificates().unwrap_or_default();
    findings.hostname_valid = chain.first().and_then(|certificate| {
        let parsed = ParsedCertificate::try_from(certificate).ok()?;
        Some(rustls::client::verify_server_name(&parsed, &name).is_ok())
    });

    let Verdict { error, path } =
        std::mem::take(&mut *outcome.lock().unwrap_or_else(PoisonError::into_inner));
    read_dates(&path, maxnines_protocol::time::now(), findings);
    findings.cert_valid = Some(error.is_none());
    let problem = error.as_ref().map(describe_certificate_problem);
    Ok(Secured { stream, problem })
}

/// Fails a check over its certificate, unless it's been told not to mind.
fn certificate_verdict(check: &Check, problem: Option<&'static str>) -> Result<()> {
    match problem {
        Some(problem) if check.insecure != Some(true) => bail!(problem),
        _ => Ok(()),
    }
}

async fn check_tls(check: &Check, findings: &mut Findings) -> Result<()> {
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    let secured = secure(&host, socket, &[], findings).await?;
    certificate_verdict(check, secured.problem)
}

/// Where requests go on an open web connection.
enum Sender {
    Http1(http1::SendRequest<Full<Bytes>>),
    Http2(http2::SendRequest<Full<Bytes>>),
}

/// A web connection that's open, which can carry several requests one after
/// another. What keeps it going stops when it's dropped, so a request given up
/// on, as when a check runs out of time, leaves nothing running.
pub(crate) struct WebConnection {
    sender: Sender,
    running: tokio::task::JoinHandle<()>,
}

impl Drop for WebConnection {
    fn drop(&mut self) {
        self.running.abort();
    }
}

impl WebConnection {
    /// Speaks HTTP over a connection that's ready for it.
    async fn start<S>(stream: S, use_http2: bool) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let failed = |_| anyhow!("the request failed");
        let (sender, running) = if use_http2 {
            let (sender, connection) = http2::handshake(TokioExecutor::new(), io)
                .await
                .map_err(failed)?;
            let running = tokio::spawn(async move {
                let _ = connection.await;
            });
            (Sender::Http2(sender), running)
        } else {
            let (sender, connection) = http1::handshake(io).await.map_err(failed)?;
            let running = tokio::spawn(async move {
                let _ = connection.await;
            });
            (Sender::Http1(sender), running)
        };
        Ok(Self { sender, running })
    }

    /// Whether another request can go, which it can't once the server has closed
    /// the connection.
    pub(crate) async fn is_ready(&mut self) -> bool {
        match &mut self.sender {
            Sender::Http1(sender) => sender.ready().await.is_ok(),
            Sender::Http2(sender) => sender.ready().await.is_ok(),
        }
    }

    /// Sends a check's request and reads the answer, timing the wait for it to
    /// start and the download.
    pub(crate) async fn send(
        &mut self,
        check: &Check,
        findings: &mut Findings,
        login: Option<&Login>,
    ) -> Result<Answer> {
        let uri = target_uri(check)?;
        let use_http2 = matches!(self.sender, Sender::Http2(_));
        let request = build_request(check, &uri, use_http2, login)?;
        let failed = |_| anyhow!("the request failed");
        let sent = Instant::now();
        let mut response = match &mut self.sender {
            Sender::Http1(sender) => {
                sender.ready().await.map_err(failed)?;
                sender.send_request(request).await.map_err(failed)?
            }
            Sender::Http2(sender) => {
                sender.ready().await.map_err(failed)?;
                sender.send_request(request).await.map_err(failed)?
            }
        };
        findings.first_byte_secs = Some(elapsed_secs(sent));

        let downloading = Instant::now();
        findings.protocol = Some(format!("{:?}", response.version()));
        let status = response.status().as_u16();
        findings.status = Some(status);
        let compressed = response
            .headers()
            .get(CONTENT_ENCODING)
            .is_some_and(|encoding| encoding.as_bytes().eq_ignore_ascii_case(b"gzip"));
        findings.compressed = Some(compressed);

        let (body, cut) = read_body(&mut response).await?;
        findings.download_secs = Some(elapsed_secs(downloading));
        Ok(Answer {
            status,
            compressed,
            body,
            cut,
        })
    }
}

fn build_request(
    check: &Check,
    uri: &Uri,
    use_http2: bool,
    login: Option<&Login>,
) -> Result<Request<Full<Bytes>>> {
    let method = check.method.as_deref().unwrap_or("GET");
    let method = Method::from_str(method).map_err(|_| anyhow!("invalid method"))?;
    let host = uri.host().context("no host")?;
    let host_header = match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    let target = if use_http2 {
        let scheme = uri.scheme_str().unwrap_or("https");
        format!("{scheme}://{host_header}{path}")
    } else {
        path.to_string()
    };

    let body = check.body.clone().unwrap_or_default();
    let mut request = Request::builder()
        .method(method)
        .uri(target)
        .header(HOST, host_header)
        .header(USER_AGENT, AGENT_NAME)
        .header(ACCEPT_ENCODING, "gzip");
    if let Some(Login { name, value }) = login {
        request = request.header(name, value);
    }
    request
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| anyhow!("invalid request"))
}

/// The body, up to the limit, and whether there was more than that.
async fn read_body(response: &mut Response<Incoming>) -> Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    while bytes.len() <= MAX_BODY_BYTES {
        let Some(frame) = response.body_mut().frame().await else {
            return Ok((bytes, false));
        };
        let frame = frame.map_err(|_| anyhow!("the response was cut off"))?;
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
    }
    bytes.truncate(MAX_BODY_BYTES);
    Ok((bytes, true))
}

/// A small file can unpack to something enormous, so this stops at the limit, and
/// says whether there was more.
fn decompress(bytes: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut unpacked = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut unpacked)
        .ok()?;
    let cut = unpacked.len() > MAX_BODY_BYTES;
    unpacked.truncate(MAX_BODY_BYTES);
    Some((unpacked, cut))
}

/// Gives a page's size and, if asked, whether it matches.
fn examine(
    body: Vec<u8>,
    compressed: bool,
    pattern: Option<String>,
) -> Result<(usize, Option<bool>)> {
    let body = if compressed {
        decompress(&body)
            .context("the page couldn't be unpacked")?
            .0
    } else {
        body
    };
    let matched = pattern
        .map(|pattern| {
            let regex = Regex::new(&pattern).map_err(|_| anyhow!("invalid regex"))?;
            anyhow::Ok(regex.is_match(&String::from_utf8_lossy(&body)))
        })
        .transpose()?;
    Ok((body.len(), matched))
}

/// What came back from a web request.
struct Answer {
    status: u16,
    compressed: bool,
    body: Vec<u8>,
    /// Whether the body went on past what's read.
    cut: bool,
}

fn target_uri(check: &Check) -> Result<Uri> {
    check
        .target
        .parse()
        .map_err(|_| anyhow!("the request failed"))
}

/// Opens a web connection to a check's site, timing each stage, and checking the
/// certificate before anything is sent.
pub(crate) async fn open_web(check: &Check, findings: &mut Findings) -> Result<WebConnection> {
    let uri = target_uri(check)?;
    let secure_site = uri.scheme_str() == Some("https");
    let host = uri.host().context("the request failed")?.to_string();
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = uri.port_u16().unwrap_or(if secure_site { 443 } else { 80 });

    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    if !secure_site {
        return WebConnection::start(socket, false).await;
    }
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let secured = secure(&host, socket, &alpn, findings).await?;
    // Before the request, which can hold a password, reaches whoever this is.
    certificate_verdict(check, secured.problem)?;
    let (_, connection) = secured.stream.get_ref();
    let use_http2 = connection.alpn_protocol() == Some(b"h2");
    WebConnection::start(secured.stream, use_http2).await
}

/// Makes a web request on a connection of its own, timing each stage. Redirects
/// aren't followed, as a second request would muddle every timing.
async fn request(check: &Check, findings: &mut Findings, login: Option<&Login>) -> Result<Answer> {
    let mut connection = open_web(check, findings).await?;
    connection.send(check, findings, login).await
}

/// A redirect is an answer from a working site, so anything below 400 is up.
async fn check_http(check: &Check, findings: &mut Findings) -> Result<()> {
    let Answer {
        status,
        compressed,
        body,
        ..
    } = request(check, findings, None).await?;

    // Unpacking and searching a big page takes real time, so it can't run on a
    // task, where it would hold up everything else on the thread.
    let pattern = check.regex.clone();
    let (length, matched) = tokio::task::spawn_blocking(move || examine(body, compressed, pattern))
        .await
        .map_err(|_| anyhow!("the request failed"))??;
    findings.content_length = Some(length);
    findings.regex_matched = matched;

    ensure!(status < 400, "the server returned status {status}");
    ensure!(
        findings.regex_matched != Some(false),
        "the page didn't match"
    );
    Ok(())
}

/// Without a server, this asks the system, as anything on the host would.
async fn check_dns(check: &Check, findings: &mut Findings) -> Result<()> {
    let Some(server) = &check.server else {
        let addresses = resolve(&check.target, 0, findings).await?;
        findings.records = Some(addresses.len());
        return Ok(());
    };
    let answers = query_server(check, server, findings).await?;
    findings.records = Some(answers);
    ensure!(answers > 0, "no records were returned");
    Ok(())
}

fn dns_query(check: &Check, id: u16) -> Result<Vec<u8>> {
    let record = check.record.as_deref().unwrap_or("A");
    let record = RecordType::from_str(record).map_err(|_| anyhow!("unknown record type"))?;
    let name = Name::from_utf8(format!("{}.", check.target.trim_end_matches('.')))
        .map_err(|_| anyhow!("invalid name"))?;

    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record));
    message.to_vec().map_err(|_| anyhow!("invalid query"))
}

fn dns_answers(bytes: &[u8], id: u16) -> Result<usize> {
    let message = Message::from_vec(bytes).map_err(|_| anyhow!("unreadable DNS answer"))?;
    ensure!(
        message.metadata.id == id,
        "the DNS answer didn't match the question"
    );
    match message.metadata.response_code {
        ResponseCode::NoError => Ok(message.answers.len()),
        ResponseCode::NXDomain => bail!("the name wasn't found"),
        _ => bail!("the DNS server refused"),
    }
}

/// A DNS server is a name or address, with a port only when written as `host:port`
/// or `[v6]:port`. A bare IPv6 address has colons of its own and no port.
fn dns_server(server: &str) -> Result<(String, u16)> {
    let bare_address = server.parse::<IpAddr>().is_ok();
    let with_port = server.starts_with('[') || (!bare_address && server.contains(':'));
    if with_port {
        host_and_port(server)
    } else {
        Ok((server.to_string(), DNS_PORT))
    }
}

async fn query_server(check: &Check, server: &str, findings: &mut Findings) -> Result<usize> {
    let (host, port) = dns_server(server)?;
    let addresses = lookup_host((host.as_str(), port))
        .await
        .map_err(|_| anyhow!("the DNS server wasn't found"))?
        .collect::<Vec<_>>();
    let address = *addresses.first().context("the DNS server wasn't found")?;

    let local: SocketAddr = if address.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0_u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(local)
        .await
        .map_err(|_| anyhow!("couldn't connect"))?;
    socket
        .connect(address)
        .await
        .map_err(|_| anyhow!("couldn't connect"))?;

    // Not for secrecy: this only has to tell one answer from another.
    let id = (Utc::now().timestamp_subsec_nanos() & 0xffff) as u16;
    let started = Instant::now();
    socket
        .send(&dns_query(check, id)?)
        .await
        .map_err(|_| anyhow!("couldn't connect"))?;
    let mut buffer = vec![0; DNS_BUFFER_BYTES];
    let size = socket
        .recv(&mut buffer)
        .await
        .map_err(|_| anyhow!("couldn't connect"))?;
    findings.dns_secs = Some(elapsed_secs(started));
    dns_answers(&buffer[..size], id)
}

/// Linux, macOS and FreeBSD only let programs with the rights send pings, which
/// their own `ping` has. It's given an address rather than the name, IPv4 first,
/// as macOS's only does IPv4 and IPv6 is `ping6` there and on FreeBSD. Their
/// options differ: macOS and FreeBSD take a deadline for the whole run, and Linux
/// a per-reply wait and a separate deadline. `ping6` takes no deadline, so the
/// check's own limit stops it.
#[cfg(unix)]
fn ping_command(
    os: &str,
    address: IpAddr,
    count: u32,
    limit: Duration,
) -> (&'static str, Vec<String>) {
    let count = count.to_string();
    let seconds = limit.as_secs().max(1).to_string();
    let (program, options): (&str, Vec<&str>) = match (os, address) {
        ("linux", _) => ("ping", vec!["-c", &count, "-W", &seconds, "-w", &seconds]),
        (_, IpAddr::V4(_)) => ("ping", vec!["-c", &count, "-t", &seconds]),
        (_, IpAddr::V6(_)) => ("ping6", vec!["-c", &count]),
    };
    let arguments = options
        .into_iter()
        .map(String::from)
        .chain([address.to_string()])
        .collect();
    (program, arguments)
}

/// Reads the summary Unix pings end with.
#[cfg(unix)]
fn read_ping_summary(output: &str, findings: &mut Findings) {
    for line in output.lines() {
        if let Some(before) = line
            .split("% packet loss")
            .next()
            .filter(|_| line.contains('%'))
        {
            let number = before.rsplit([' ', ',']).next().unwrap_or_default();
            if let Ok(loss) = number.parse() {
                findings.packet_loss_percent = Some(loss);
            }
        }
        if let Some((names, values)) = line.split_once(" = ")
            && names.contains("min/avg/max")
        {
            let numbers: Vec<f64> = values
                .trim_end_matches(" ms")
                .split('/')
                .filter_map(|value| value.trim().parse().ok())
                .collect();
            // Pings give milliseconds.
            let seconds: Vec<f64> = numbers.iter().map(|ms| ms / 1000.0).collect();
            if let [min, _, max, stddev] = seconds[..] {
                findings.rtt_min_secs = Some(min);
                findings.rtt_max_secs = Some(max);
                findings.rtt_stddev_secs = Some(stddev);
            }
        }
    }
}

/// The check as a whole stops at its limit, so pinging stops a little before, to
/// report what came back rather than running out of time.
fn ping_deadline(check: &Check) -> tokio::time::Instant {
    let limit = limit(check);
    tokio::time::Instant::now() + limit - (limit / 10).min(Duration::from_millis(500))
}

#[cfg(windows)]
async fn check_ping(check: &Check, findings: &mut Findings) -> Result<()> {
    let deadline = ping_deadline(check);
    let host = check.target.trim_start_matches('[').trim_end_matches(']');
    let addresses = resolve(host, 0, findings).await?;
    let replies = ping::ping(&addresses, check.count.unwrap_or(1), deadline).await?;
    findings.packet_loss_percent = Some(replies.loss_percent());
    if let Some((min, max, stddev)) = replies.times_secs() {
        findings.rtt_min_secs = Some(min);
        findings.rtt_max_secs = Some(max);
        findings.rtt_stddev_secs = Some(stddev);
    }
    ensure!(replies.received() > 0, "no reply");
    Ok(())
}

#[cfg(unix)]
async fn check_ping(check: &Check, findings: &mut Findings) -> Result<()> {
    let deadline = ping_deadline(check);
    let host = check.target.trim_start_matches('[').trim_end_matches(']');
    let addresses = resolve(host, 0, findings).await?;
    let address = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .unwrap_or(&addresses[0])
        .ip();
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    let (program, arguments) = ping_command(
        std::env::consts::OS,
        address,
        check.count.unwrap_or(1),
        left,
    );
    let output = Command::new(program)
        .args(arguments)
        // Newer Linux pings print in the system's language otherwise.
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|_| anyhow!("couldn't run {program}"))?;
    read_ping_summary(&String::from_utf8_lossy(&output.stdout), findings);
    // Any reply means it's up, as on Windows. Linux's ping fails when fewer
    // replies come than were sent, and the others only when none do.
    ensure!(
        findings
            .packet_loss_percent
            .is_some_and(|loss| loss < 100.0),
        "no reply"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{TcpListener, UdpSocket as StdUdpSocket};
    use std::thread;

    use super::*;

    fn check(kind: CheckKind, target: &str) -> Check {
        Check::new("a", kind, target)
    }

    #[test]
    fn jitter_varies_and_stays_within_its_limit() {
        let limit = Duration::from_secs(10);
        let times: Vec<Duration> = (0..100).map(|_| jitter(limit)).collect();

        assert!(times.iter().all(|time| *time < limit));
        assert!(times.iter().any(|time| *time != times[0]));
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn a_check_is_named_after_the_host_it_reaches() {
        for (kind, target, host) in [
            (
                CheckKind::Http,
                "https://www.example.com/health",
                "www.example.com",
            ),
            (
                CheckKind::Http,
                "http://Shop.Example.com:8080/?a=1",
                "shop.example.com",
            ),
            (
                CheckKind::Http,
                "https://user:secret@example.com/",
                "example.com",
            ),
            (
                CheckKind::Http,
                "https://[2001:db8::1]:8443/",
                "2001:db8::1",
            ),
            (CheckKind::Http, "http://192.0.2.10/", "192.0.2.10"),
            (CheckKind::Tcp, "db1.internal:5432", "db1.internal"),
            (CheckKind::Postgres, "10.0.0.5:5432", "10.0.0.5"),
            (CheckKind::Ssh, "[2001:db8::2]:22", "2001:db8::2"),
            (CheckKind::Tls, "mail.example.com:993", "mail.example.com"),
            (CheckKind::Smtp, "SMTP.example.com:587", "smtp.example.com"),
            (CheckKind::Dns, "example.com", "example.com"),
            (CheckKind::Ping, "2001:db8::3", "2001:db8::3"),
            (CheckKind::Ping, "192.0.2.1", "192.0.2.1"),
        ] {
            assert_eq!(host_reached(&check(kind, target)), host, "{target}");
        }
    }

    /// Runs a check the way a collector does.
    fn run(check: &Check) -> Value {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(super::run(check))
    }

    /// The whole of a request, its body too. Closing a connection with some of it
    /// unread makes Windows reset the connection, and the answer is lost with it.
    /// Something that isn't HTTP, like a TLS handshake, never ends the way a request
    /// does, so it's taken to be over once nothing more comes for a moment.
    fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut request: Vec<u8> = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            // A request starts with its method in capitals.
            if request
                .first()
                .is_some_and(|byte| !byte.is_ascii_uppercase())
            {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
            }
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    return request;
                }
            }
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => return request,
                Ok(size) => request.extend_from_slice(&buffer[..size]),
            }
        }
    }

    /// Answers one request with `response`, and hands back what was asked.
    fn serve_once(response: &'static [u8]) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let _ = stream.write_all(response);
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    /// An address nothing can listen on, so connecting fails at once on every system.
    /// A port that was free a moment ago can be given to another test meanwhile, and
    /// one held without listening is refused on Linux but ignored on macOS until the
    /// connection times out.
    const CLOSED_ADDRESS: &str = "127.0.0.1:0";

    fn http_check(address: &str) -> Check {
        check(CheckKind::Http, &format!("http://{address}/health"))
    }

    #[test]
    fn an_open_port_is_up_and_says_how_fast() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();

        let output = run(&check(CheckKind::Tcp, &target));
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["name"], "a");
        assert_eq!(output["kind"], "tcp");
        assert!(output["response_secs"].as_f64().unwrap() >= 0.0);
        assert!(output["connect_secs"].as_f64().unwrap() >= 0.0);
        assert!(output["dns_secs"].as_f64().unwrap() >= 0.0);
    }

    #[test]
    fn a_closed_port_is_down_and_says_why() {
        let output = run(&check(CheckKind::Tcp, CLOSED_ADDRESS));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "couldn't connect");
        assert!(output.get("response_secs").is_none());
    }

    #[test]
    fn a_failure_keeps_what_was_learned_before_it() {
        let output = run(&check(CheckKind::Tcp, CLOSED_ADDRESS));
        assert!(output["dns_secs"].is_f64(), "{output}");
    }

    #[test]
    fn an_unknown_name_is_down() {
        let output = run(&check(CheckKind::Tcp, "no-such-host.invalid:80"));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "the name wasn't found");
    }

    #[test]
    fn a_good_web_response_is_up_with_each_stage_timed() {
        let (address, _) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        let output = run(&http_check(&address));

        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["status"], 200);
        assert_eq!(output["protocol"], "HTTP/1.1");
        assert_eq!(output["content_length"], 5);
        assert_eq!(output["compressed"], false);
        for stage in [
            "dns_secs",
            "connect_secs",
            "first_byte_secs",
            "download_secs",
            "response_secs",
        ] {
            assert!(output[stage].is_f64(), "{stage}: {output}");
        }
        assert!(output.get("tls_secs").is_none());
    }

    #[test]
    fn the_request_says_who_is_asking_and_what_it_accepts() {
        let (address, request) = serve_once(b"HTTP/1.1 204 No Content\r\n\r\n");
        run(&http_check(&address));

        let request = request.join().unwrap().to_lowercase();
        assert!(request.starts_with("get /health http/1.1\r\n"), "{request}");
        assert!(request.contains("user-agent: maxnines-agent/"), "{request}");
        assert!(request.contains("accept-encoding: gzip"), "{request}");
        assert!(
            request.contains(&format!("host: {}", address.to_lowercase())),
            "{request}"
        );
    }

    #[test]
    fn a_check_can_choose_its_method_and_body() {
        let (address, request) = serve_once(b"HTTP/1.1 204 No Content\r\n\r\n");
        let output = run(&Check {
            method: Some("POST".to_string()),
            body: Some("hello=world".to_string()),
            ..http_check(&address)
        });

        assert_eq!(output["up"], 1, "{output}");
        let request = request.join().unwrap();
        assert!(request.starts_with("POST /health"), "{request}");
        assert!(request.ends_with("hello=world"), "{request}");
    }

    #[test]
    fn a_web_error_is_down_and_gives_the_status() {
        let (address, _) = serve_once(b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n");
        let output = run(&http_check(&address));
        assert_eq!(output["up"], 0);
        assert_eq!(output["status"], 503);
        assert_eq!(output["error"], "the server returned status 503");
    }

    #[test]
    fn redirects_are_reported_rather_than_followed() {
        let (address, _) =
            serve_once(b"HTTP/1.1 301 Moved\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n");
        let output = run(&http_check(&address));
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["status"], 301);
    }

    #[test]
    fn a_page_has_to_match_its_regex() {
        let page: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nWelcome, user!";

        let (address, _) = serve_once(page);
        let output = run(&Check {
            regex: Some("^Welcome".to_string()),
            ..http_check(&address)
        });
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["regex_matched"], true);

        let (address, _) = serve_once(page);
        let output = run(&Check {
            regex: Some("Goodbye".to_string()),
            ..http_check(&address)
        });
        assert_eq!(output["up"], 0);
        assert_eq!(output["regex_matched"], false);
        assert_eq!(output["error"], "the page didn't match");
    }

    fn gzipped(text: &str) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn a_compressed_page_is_measured_and_searched_unpacked() {
        let packed = gzipped("Welcome, user!");
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            packed.len()
        )
        .into_bytes();
        response.extend(packed);

        let (address, _) = serve_once(Box::leak(response.into_boxed_slice()));
        let output = run(&Check {
            regex: Some("Welcome".to_string()),
            ..http_check(&address)
        });
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["compressed"], true);
        assert_eq!(output["content_length"], 14);
        assert_eq!(output["regex_matched"], true);
    }

    #[test]
    fn a_huge_unpacked_page_stops_at_the_limit() {
        let packed = gzipped(&"x".repeat(MAX_BODY_BYTES + 1000));
        let (unpacked, cut) = decompress(&packed).unwrap();
        assert_eq!((unpacked.len(), cut), (MAX_BODY_BYTES, true));
        let packed = gzipped(&"x".repeat(MAX_BODY_BYTES));
        assert!(!decompress(&packed).unwrap().1);
    }

    #[test]
    fn a_page_too_big_to_read_whole_is_refused_rather_than_cut_short() {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        )
        .into_bytes();
        response.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES + 1));
        let (address, _server) = serve_once(Box::leak(response.into_boxed_slice()));
        let failure = fetch(&format!("http://{address}/metrics")).unwrap_err();
        assert_eq!(failure.to_string(), TOO_BIG);

        let packed = gzipped(&"x".repeat(MAX_BODY_BYTES + 1));
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            packed.len()
        )
        .into_bytes();
        response.extend(packed);
        let (address, _server) = serve_once(Box::leak(response.into_boxed_slice()));
        let failure = fetch(&format!("http://{address}/metrics")).unwrap_err();
        assert_eq!(failure.to_string(), TOO_BIG);
    }

    #[test]
    fn a_failed_web_check_does_not_repeat_its_url() {
        let target = format!("http://user:secret@{CLOSED_ADDRESS}/token");
        let output = run(&check(CheckKind::Http, &target));
        assert_eq!(output["up"], 0);
        assert!(!output.to_string().contains("secret"), "{output}");
        assert!(!output.to_string().contains("token"), "{output}");
    }

    fn fetch(url: &str) -> Result<String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fetch_page(url, Duration::from_secs(5), None))
    }

    #[test]
    fn a_page_is_fetched_as_text() {
        let (address, server) =
            serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nBusyWorkers: 3\n");
        let text = fetch(&format!("http://{address}/server-status?auto")).unwrap();
        assert_eq!(text, "BusyWorkers: 3\n");
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("GET /server-status?auto ")
        );
    }

    #[test]
    fn a_compressed_page_is_unpacked() {
        let body = gzipped("Active connections: 1\n");
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        let (address, _server) = serve_once(Box::leak(response.into_boxed_slice()));
        assert_eq!(
            fetch(&format!("http://{address}/")).unwrap(),
            "Active connections: 1\n"
        );
    }

    #[test]
    fn only_a_successful_page_counts() {
        for (response, error) in [
            (
                &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"[..],
                "the page returned status 403",
            ),
            (
                &b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n"[..],
                "the page returned status 302",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xff\xfe"[..],
                "the page isn't text",
            ),
        ] {
            let (address, _server) = serve_once(response);
            let failure = fetch(&format!("http://{address}/")).unwrap_err();
            assert_eq!(failure.to_string(), error);
        }
        let failure = fetch(&format!("http://user:secret@{CLOSED_ADDRESS}/token")).unwrap_err();
        assert!(!format!("{failure:#}").contains("secret"));
    }

    #[test]
    fn any_other_web_failure_does_not_repeat_its_url_either() {
        let output = run(&check(CheckKind::Http, "http://[secret-token"));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "the request failed");
    }

    #[test]
    fn a_server_that_goes_silent_runs_out_of_time() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let started = Instant::now();
        let output = run(&Check {
            timeout: Some(Duration::from_secs(2)),
            ..http_check(&address)
        });

        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "timed out");
        assert!(output["connect_secs"].is_f64(), "{output}");
        // Well short of the 10 seconds a check gets when it doesn't say.
        assert!(started.elapsed() < Duration::from_secs(8));
        drop(listener);
    }

    #[test]
    fn a_server_that_will_not_speak_tls_is_down() {
        let (address, _) = serve_once(b"this isn't TLS\r\n");
        let output = run(&check(CheckKind::Tls, &address));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "the TLS handshake failed");
    }

    /// A TLS server for one connection, with a certificate nothing trusts.
    fn serve_tls(names: &[&str]) -> String {
        serve_tls_sending(names, Vec::new())
    }

    /// As [`serve_tls`], sending `extra` certificates after its own.
    fn serve_tls_sending(names: &[&str], extra: Vec<CertificateDer<'static>>) -> String {
        let certified = rcgen::generate_simple_self_signed(
            names.iter().map(ToString::to_string).collect::<Vec<_>>(),
        )
        .unwrap();
        let mut chain = vec![certified.cert.der().clone()];
        chain.extend(extra);
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();

        // On the address localhost means first, which is the one checks try first, so
        // none of them waits on another being refused, which takes Windows seconds.
        let listener = TcpListener::bind("localhost:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
            let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::Stream::new(&mut connection, &mut socket);
            // The whole request, then the answer, then whatever the check sends until
            // it closes, so nothing is left unread to make Windows reset the connection.
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(size) => request.extend_from_slice(&buffer[..size]),
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
            while matches!(stream.read(&mut buffer), Ok(size) if size > 0) {}
        });
        format!("localhost:{}", address.port())
    }

    #[test]
    fn an_untrusted_certificate_is_down_but_still_measured() {
        let output = run(&check(CheckKind::Tls, &serve_tls(&["localhost"])));

        assert_eq!(output["up"], 0, "{output}");
        assert_eq!(output["error"], "the certificate isn't trusted");
        assert_eq!(output["cert_valid"], false);
        assert_eq!(output["hostname_valid"], true);
        assert!(output["tls_secs"].is_f64(), "{output}");
        assert!(
            output["tls_version"]
                .as_str()
                .unwrap()
                .starts_with("TLS 1.")
        );
        assert!(output["cert_days_left"].as_i64().unwrap() > 300);
    }

    /// A server can send certificates beyond the ones its own rests on, such as an
    /// old cross-signed one long expired, which say nothing about the site.
    #[test]
    fn dates_come_only_from_the_certificates_the_site_rests_on() {
        let expired = certificate(2000, 2001);
        let address = serve_tls_sending(&["localhost"], vec![expired]);
        let output = run(&check(CheckKind::Tls, &address));
        assert!(output["cert_days_left"].as_i64().unwrap() > 300, "{output}");
    }

    #[test]
    fn a_certificate_for_another_name_is_noticed() {
        let output = run(&check(CheckKind::Tls, &serve_tls(&["example.org"])));
        assert_eq!(output["hostname_valid"], false, "{output}");
    }

    #[test]
    fn insecure_measures_a_site_without_failing_it() {
        let output = run(&Check {
            insecure: Some(true),
            ..check(CheckKind::Tls, &serve_tls(&["localhost"]))
        });
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["cert_valid"], false);
    }

    /// The request could carry a password in its URL, so it's never sent to a
    /// server that failed the certificate check, though the certificate itself is
    /// still measured.
    #[test]
    fn a_secure_page_with_a_bad_certificate_is_not_sent_the_request() {
        let target = format!("https://{}/secret?token=abc", serve_tls(&["localhost"]));
        let output = run(&check(CheckKind::Http, &target));

        assert_eq!(output["up"], 0, "{output}");
        assert_eq!(output["error"], "the certificate isn't trusted");
        assert_eq!(output["cert_valid"], false);
        assert!(output["tls_secs"].is_f64(), "{output}");
        assert!(output["status"].is_null(), "{output}");
        assert!(output["first_byte_secs"].is_null(), "{output}");
    }

    #[test]
    fn insecure_lets_a_secure_page_pass() {
        let target = format!("https://{}/", serve_tls(&["localhost"]));
        let output = run(&Check {
            insecure: Some(true),
            ..check(CheckKind::Http, &target)
        });
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["status"], 200);
    }

    #[test]
    fn dns_servers_can_be_written_every_way() {
        let server = |text: &str| dns_server(text).unwrap();
        assert_eq!(server("8.8.8.8"), ("8.8.8.8".to_string(), 53));
        assert_eq!(server("8.8.8.8:5353"), ("8.8.8.8".to_string(), 5353));
        assert_eq!(
            server("dns.example.com"),
            ("dns.example.com".to_string(), 53)
        );
        assert_eq!(
            server("dns.example.com:5353"),
            ("dns.example.com".to_string(), 5353)
        );
        assert_eq!(server("2001:db8::1"), ("2001:db8::1".to_string(), 53));
        assert_eq!(
            server("[2001:db8::1]:5353"),
            ("2001:db8::1".to_string(), 5353)
        );
        assert!(dns_server("[2001:db8::1]:port").is_err());
    }

    #[test]
    fn certificate_problems_are_named() {
        let error = |kind| TlsError::InvalidCertificate(kind);
        assert_eq!(
            describe_certificate_problem(&error(CertificateError::Expired)),
            "the certificate has expired"
        );
        assert_eq!(
            describe_certificate_problem(&error(CertificateError::NotValidForName)),
            "the certificate is for a different name"
        );
        assert_eq!(
            describe_certificate_problem(&error(CertificateError::UnknownIssuer)),
            "the certificate isn't trusted"
        );
    }

    fn certificate(start_year: i32, end_year: i32) -> CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::new(vec!["a.example".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(start_year, 1, 1);
        params.not_after = rcgen::date_time_ymd(end_year, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn dates_come_from_the_tightest_certificates_in_the_chain() {
        let (leaf, issuer) = (certificate(2024, 2040), certificate(2022, 2030));

        for chain in [
            [leaf.clone(), issuer.clone()],
            [issuer.clone(), leaf.clone()],
        ] {
            let mut findings = Findings::default();
            let now = DateTime::UNIX_EPOCH;
            read_dates(&chain, now, &mut findings);
            let at = |year| {
                DateTime::from_timestamp(rcgen::date_time_ymd(year, 1, 1).unix_timestamp(), 0)
            };
            assert_eq!(findings.cert_valid_from, at(2024));
            assert_eq!(findings.cert_valid_until, at(2030));
            assert_eq!(
                findings.cert_days_left,
                Some(days_left(at(2030).unwrap(), now))
            );
        }
    }

    #[test]
    fn days_left_rounds_down_and_goes_negative_once_expired() {
        let now = DateTime::UNIX_EPOCH;
        let day = TimeDelta::days(1);
        assert_eq!(days_left(now + day * 10, now), 10);
        assert_eq!(days_left(now + day * 10 - TimeDelta::seconds(1), now), 9);
        assert_eq!(days_left(now - TimeDelta::seconds(1), now), -1);
        assert_eq!(days_left(now - day, now), -1);
        assert_eq!(days_left(now - day - TimeDelta::seconds(1), now), -2);
    }

    #[test]
    fn dns_checks_can_use_the_system_resolver() {
        let output = run(&check(CheckKind::Dns, "localhost"));
        assert_eq!(output["up"], 1, "{output}");
        assert!(output["records"].as_u64().unwrap() >= 1);
        assert_eq!(run(&check(CheckKind::Dns, "no-such-host.invalid"))["up"], 0);
    }

    /// A DNS server for one question, answering with an A record or `code`.
    fn serve_dns(code: ResponseCode, answers: usize) -> String {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap().to_string();
        thread::spawn(move || {
            let mut buffer = [0; 512];
            let (size, from) = socket.recv_from(&mut buffer).unwrap();
            let question = Message::from_vec(&buffer[..size]).unwrap();
            let mut answer =
                Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
            answer.metadata.response_code = code;
            for query in &question.queries {
                answer.add_query(query.clone());
                for index in 0..answers {
                    answer.add_answer(hickory_proto::rr::Record::from_rdata(
                        query.name.clone(),
                        60,
                        hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(
                            10,
                            0,
                            0,
                            index as u8,
                        )),
                    ));
                }
            }
            socket.send_to(&answer.to_vec().unwrap(), from).unwrap();
        });
        address
    }

    fn dns_check(server: String) -> Check {
        Check {
            server: Some(server),
            ..check(CheckKind::Dns, "example.com")
        }
    }

    #[test]
    fn a_dns_server_can_be_asked_directly() {
        let output = run(&dns_check(serve_dns(ResponseCode::NoError, 2)));
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["records"], 2);
        assert!(output["dns_secs"].is_f64());
    }

    #[test]
    fn a_dns_server_with_no_answer_is_down() {
        let output = run(&dns_check(serve_dns(ResponseCode::NoError, 0)));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "no records were returned");
    }

    #[test]
    fn an_unknown_name_from_a_dns_server_is_down() {
        let output = run(&dns_check(serve_dns(ResponseCode::NXDomain, 0)));
        assert_eq!(output["error"], "the name wasn't found");
    }

    #[test]
    fn a_dns_answer_to_another_question_is_refused() {
        let bytes = dns_query(&check(CheckKind::Dns, "example.com"), 1).unwrap();
        assert!(dns_answers(&bytes, 2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ping_commands_suit_each_system() {
        let limit = Duration::from_secs(10);
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            ping_command("linux", v4, 5, limit),
            (
                "ping",
                vec!["-c", "5", "-W", "10", "-w", "10", "10.0.0.1"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
        assert_eq!(
            ping_command("linux", v6, 1, limit)
                .1
                .last()
                .map(String::as_str),
            Some("::1"),
            "Linux's ping does IPv6 itself"
        );
        assert_eq!(
            ping_command("macos", v4, 5, limit),
            (
                "ping",
                vec!["-c", "5", "-t", "10", "10.0.0.1"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
        assert_eq!(
            ping_command("freebsd", v6, 1, limit),
            (
                "ping6",
                vec!["-c", "1", "::1"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
        assert_eq!(
            ping_command("macos", v4, 1, Duration::from_millis(300)).1[3],
            "1",
            "never less than a second"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ping_summaries_are_read_on_each_system() {
        let linux = "5 packets transmitted, 4 received, 20% packet loss, time 4005ms\n\
                     rtt min/avg/max/mdev = 1.100/2.200/3.300/0.400 ms\n";
        let mut findings = Findings::default();
        read_ping_summary(linux, &mut findings);
        assert_eq!(findings.packet_loss_percent, Some(20.0));
        let close = |found: Option<f64>, secs: f64| (found.unwrap() - secs).abs() < 1e-12;
        assert!(close(findings.rtt_min_secs, 0.0011), "{findings:?}");
        assert!(close(findings.rtt_max_secs, 0.0033), "{findings:?}");
        assert!(close(findings.rtt_stddev_secs, 0.0004), "{findings:?}");

        let bsd = "5 packets transmitted, 5 packets received, 0.0% packet loss\n\
                   round-trip min/avg/max/stddev = 0.1/0.2/0.3/0.05 ms\n";
        let mut findings = Findings::default();
        read_ping_summary(bsd, &mut findings);
        assert_eq!(findings.packet_loss_percent, Some(0.0));
        assert!((findings.rtt_min_secs.unwrap() - 0.0001).abs() < 1e-12);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_ping_summary_is_left_out() {
        let mut findings = Findings::default();
        read_ping_summary(
            "Antwort von 10.0.0.1: Zeit<1ms\n100% something",
            &mut findings,
        );
        assert_eq!(findings.packet_loss_percent, None);
        assert_eq!(findings.rtt_min_secs, None);
    }

    #[test]
    fn ping_reaches_this_host_and_reports_loss() {
        let output = run(&Check {
            count: Some(2),
            ..check(CheckKind::Ping, "127.0.0.1")
        });
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["packet_loss_percent"], 0.0);
        assert!(output["rtt_max_secs"].is_f64(), "{output}");
        assert!(output["dns_secs"].is_f64(), "{output}");
    }
}
