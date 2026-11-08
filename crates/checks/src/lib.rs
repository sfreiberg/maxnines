//! Tries reaching things, to see if they're up and how quickly. Agents run these
//! from where they are, and the server runs them against remote sites directly.
//! Each stage of a web request is timed separately, so a slow site can be told apart from slow
//! DNS, and whatever was learned before a failure is still reported.
//!
//! Errors only ever say what kind of failure it was, as a URL can hold a password.

use std::io::Read;
use std::net::SocketAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use flate2::read::GzDecoder;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HOST, USER_AGENT};
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use maxnines_protocol::{Check, CheckKind};
use regex_lite::Regex;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
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
use tokio::process::Command;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::parse_x509_certificate;

/// How long a check gets unless it says otherwise. A slower answer counts as down.
const DEFAULT_TIMEOUT: Duration =
    Duration::from_secs(maxnines_protocol::DEFAULT_CHECK_TIMEOUT_SECS);

/// A name can have several addresses, and one that's gone shouldn't use up the
/// whole time limit before the others are tried.
const CONNECT_ATTEMPT: Duration = Duration::from_secs(5);

/// How much of a page is read. It's only measured and searched, never kept.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// What's put in the logs of sites being checked.
const AGENT_NAME: &str = concat!("MaxNines-Agent/", env!("CARGO_PKG_VERSION"));

const SECS_PER_DAY: i64 = 86_400;

const DNS_PORT: u16 = 53;

/// The largest answer a plain UDP lookup returns.
const DNS_BUFFER_BYTES: usize = 4096;

/// How long a check gets.
pub fn limit(check: &Check) -> Duration {
    check
        .timeout_secs
        .map_or(DEFAULT_TIMEOUT, Duration::from_secs)
}

fn timed_out() -> anyhow::Error {
    anyhow!("timed out")
}

/// What a check found out. Stage times are how long each stage took on its own,
/// so together they add up to about `response_ms`.
#[derive(Debug, Default, Serialize)]
struct Findings {
    response_ms: Option<f64>,
    dns_ms: Option<f64>,
    connect_ms: Option<f64>,
    tls_ms: Option<f64>,
    first_byte_ms: Option<f64>,
    download_ms: Option<f64>,
    status: Option<u16>,
    protocol: Option<String>,
    content_length: Option<usize>,
    compressed: Option<bool>,
    regex_matched: Option<bool>,
    tls_version: Option<String>,
    cert_valid: Option<bool>,
    hostname_valid: Option<bool>,
    cert_not_before: Option<i64>,
    cert_not_after: Option<i64>,
    cert_days_left: Option<i64>,
    records: Option<usize>,
    packet_loss_percent: Option<f64>,
    rtt_min_ms: Option<f64>,
    rtt_max_ms: Option<f64>,
    rtt_stddev_ms: Option<f64>,
}

fn elapsed_ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
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

/// Runs a check, until it's done or out of time. Always gives a result, and
/// whatever was learned before running out of time is kept.
pub async fn run(check: &Check) -> Value {
    let started = Instant::now();
    let mut findings = Findings::default();
    let work = async {
        match check.kind {
            CheckKind::Tcp => check_tcp(check, &mut findings).await,
            CheckKind::Http => check_http(check, &mut findings).await,
            CheckKind::Tls => check_tls(check, &mut findings).await,
            CheckKind::Dns => check_dns(check, &mut findings).await,
            CheckKind::Ping => check_ping(check, &mut findings).await,
        }
    };
    let result = timeout(limit(check), work)
        .await
        .unwrap_or_else(|_| Err(timed_out()));
    if result.is_ok() {
        findings.response_ms = Some(elapsed_ms(started));
    }
    report(check, findings, result)
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
    findings.dns_ms = Some(elapsed_ms(started));
    ensure!(!addresses.is_empty(), "the name wasn't found");
    Ok(addresses)
}

/// Tries each address, as only some of a name's may answer.
async fn connect(addresses: &[SocketAddr], findings: &mut Findings) -> Result<TcpStream> {
    let started = Instant::now();
    for address in addresses {
        if let Ok(Ok(stream)) = timeout(CONNECT_ATTEMPT, TcpStream::connect(address)).await {
            findings.connect_ms = Some(elapsed_ms(started));
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

/// Lets a handshake finish whatever the certificate's like, so that a site with a
/// bad one can still have its certificate's dates and name read, and remembers what
/// the real check said. Nothing is sent over the connection afterwards unless the
/// check was told not to mind, as a request can carry a secret.
#[derive(Debug)]
struct RecordingVerifier {
    real: Arc<WebPkiServerVerifier>,
    outcome: Arc<Mutex<Option<TlsError>>>,
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
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner) = result.err();
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

/// Reads the dates across the whole chain, as any certificate in it expiring
/// breaks the site. So the start is the latest and the end is the earliest.
fn read_dates(chain: &[CertificateDer<'_>], now_secs: i64, findings: &mut Findings) {
    for certificate in chain {
        if let Ok((_, parsed)) = parse_x509_certificate(certificate) {
            let (start, end) = (
                parsed.validity().not_before.timestamp(),
                parsed.validity().not_after.timestamp(),
            );
            findings.cert_not_before = findings.cert_not_before.max(Some(start));
            findings.cert_not_after = Some(findings.cert_not_after.map_or(end, |e| e.min(end)));
        }
    }
    findings.cert_days_left = findings.cert_not_after.map(|end| days_left(end, now_secs));
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64)
}

fn days_left(expires_secs: i64, now_secs: i64) -> i64 {
    (expires_secs - now_secs).div_euclid(SECS_PER_DAY)
}

fn tls_config(verifier: Arc<RecordingVerifier>) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

fn trusted_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let real = WebPkiServerVerifier::builder_with_provider(Arc::new(trusted_roots()), provider)
        .build()
        .context("setting up TLS")?;
    let outcome = Arc::new(Mutex::new(None));
    let verifier = Arc::new(RecordingVerifier {
        real,
        outcome: outcome.clone(),
    });
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
    findings.tls_ms = Some(elapsed_ms(started));

    let (_, connection) = stream.get_ref();
    findings.tls_version = version_name(connection.protocol_version());
    let chain = connection.peer_certificates().unwrap_or_default();
    read_dates(chain, now_secs(), findings);
    findings.hostname_valid = chain.first().and_then(|certificate| {
        let parsed = ParsedCertificate::try_from(certificate).ok()?;
        Some(rustls::client::verify_server_name(&parsed, &name).is_ok())
    });

    let error = outcome
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
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

/// Sends the request and waits for the response to start.
async fn exchange<S>(
    stream: S,
    use_http2: bool,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let failed = |_| anyhow!("the request failed");
    if use_http2 {
        let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(failed)?;
        tokio::spawn(connection);
        sender.send_request(request).await.map_err(failed)
    } else {
        let (mut sender, connection) = http1::handshake(io).await.map_err(failed)?;
        tokio::spawn(connection);
        sender.send_request(request).await.map_err(failed)
    }
}

fn build_request(check: &Check, uri: &Uri, use_http2: bool) -> Result<Request<Full<Bytes>>> {
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
    Request::builder()
        .method(method)
        .uri(target)
        .header(HOST, host_header)
        .header(USER_AGENT, AGENT_NAME)
        .header(ACCEPT_ENCODING, "gzip")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| anyhow!("invalid request"))
}

async fn read_body(response: &mut Response<Incoming>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < MAX_BODY_BYTES {
        let Some(frame) = response.body_mut().frame().await else {
            break;
        };
        let frame = frame.map_err(|_| anyhow!("the response was cut off"))?;
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

/// A small file can unpack to something enormous, so this stops at the limit.
fn decompress(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut unpacked = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_BODY_BYTES as u64)
        .read_to_end(&mut unpacked)
        .ok()?;
    Some(unpacked)
}

/// Gives a page's size and, if asked, whether it matches.
fn examine(
    body: Vec<u8>,
    compressed: bool,
    pattern: Option<String>,
) -> Result<(usize, Option<bool>)> {
    let body = if compressed {
        decompress(&body).context("the page couldn't be unpacked")?
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

/// Redirects aren't followed, as a second request would muddle every timing. A
/// redirect is an answer from a working site, so anything below 400 is up.
async fn check_http(check: &Check, findings: &mut Findings) -> Result<()> {
    let uri: Uri = check
        .target
        .parse()
        .map_err(|_| anyhow!("the request failed"))?;
    let secure_site = uri.scheme_str() == Some("https");
    let host = uri.host().context("the request failed")?.to_string();
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = uri.port_u16().unwrap_or(if secure_site { 443 } else { 80 });

    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;

    let (sent, mut response) = if secure_site {
        let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let secured = secure(&host, socket, &alpn, findings).await?;
        // Before the request, which can hold a password, reaches whoever this is.
        certificate_verdict(check, secured.problem)?;
        let (_, connection) = secured.stream.get_ref();
        let use_http2 = connection.alpn_protocol() == Some(b"h2");
        let request = build_request(check, &uri, use_http2)?;
        let sent = Instant::now();
        (sent, exchange(secured.stream, use_http2, request).await?)
    } else {
        let request = build_request(check, &uri, false)?;
        let sent = Instant::now();
        (sent, exchange(socket, false, request).await?)
    };
    findings.first_byte_ms = Some(elapsed_ms(sent));

    let downloading = Instant::now();
    findings.protocol = Some(format!("{:?}", response.version()));
    let status = response.status().as_u16();
    findings.status = Some(status);
    let compressed = response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|encoding| encoding.as_bytes().eq_ignore_ascii_case(b"gzip"));
    findings.compressed = Some(compressed);

    let body = read_body(&mut response).await?;
    findings.download_ms = Some(elapsed_ms(downloading));

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

/// Without a server, this asks the system, as anything on the machine would.
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

async fn query_server(check: &Check, server: &str, findings: &mut Findings) -> Result<usize> {
    let (host, port) = if server.contains('.') && server.contains(':') {
        host_and_port(server)?
    } else {
        (server.to_string(), DNS_PORT)
    };
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
    let id = (now_nanos() & 0xffff) as u16;
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
    findings.dns_ms = Some(elapsed_ms(started));
    dns_answers(&buffer[..size], id)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos())
}

/// Sending ICMP directly needs special rights, so this uses the system's own
/// `ping`, which every platform ships with those rights. Their options differ:
/// macOS and FreeBSD take a deadline for the whole run, Linux takes a per-reply
/// wait and a separate deadline, and Windows only takes a per-reply wait, so the
/// limit is shared out between the replies there.
fn ping_arguments(os: &str, host: &str, count: u32, limit: Duration) -> Vec<String> {
    let per_reply_ms = (limit.as_millis() / u128::from(count.max(1))).to_string();
    let count = count.to_string();
    let seconds = limit.as_secs().to_string();
    let options: Vec<&str> = match os {
        "windows" => vec!["-n", &count, "-w", &per_reply_ms],
        "linux" => vec!["-c", &count, "-W", &seconds, "-w", &seconds],
        _ => vec!["-c", &count, "-t", &seconds],
    };
    options
        .into_iter()
        .map(String::from)
        .chain([host.to_string()])
        .collect()
}

/// Reads the summary Unix pings end with. Windows words its own by language, so
/// there only the exit code is used.
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
            if let [min, _, max, stddev] = numbers[..] {
                findings.rtt_min_ms = Some(min);
                findings.rtt_max_ms = Some(max);
                findings.rtt_stddev_ms = Some(stddev);
            }
        }
    }
}

async fn check_ping(check: &Check, findings: &mut Findings) -> Result<()> {
    let count = check.count.unwrap_or(1);
    let arguments = ping_arguments(std::env::consts::OS, &check.target, count, limit(check));
    let output = Command::new("ping")
        .args(arguments)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|_| anyhow!("couldn't run ping"))?;
    read_ping_summary(&String::from_utf8_lossy(&output.stdout), findings);
    ensure!(output.status.success(), "no reply");
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

    /// Runs a check the way a collector does.
    fn run(check: &Check) -> Value {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(super::run(check))
    }

    /// Answers one request with `response`, and hands back what was asked.
    fn serve_once(response: &'static [u8]) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let size = stream.read(&mut request).unwrap_or(0);
            let _ = stream.write_all(response);
            String::from_utf8_lossy(&request[..size]).to_string()
        });
        (address, handle)
    }

    fn closed_port() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

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
        assert!(output["response_ms"].as_f64().unwrap() >= 0.0);
        assert!(output["connect_ms"].as_f64().unwrap() >= 0.0);
        assert!(output["dns_ms"].as_f64().unwrap() >= 0.0);
    }

    #[test]
    fn a_closed_port_is_down_and_says_why() {
        let output = run(&check(CheckKind::Tcp, &closed_port()));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "couldn't connect");
        assert!(output.get("response_ms").is_none());
    }

    #[test]
    fn a_failure_keeps_what_was_learned_before_it() {
        let output = run(&check(CheckKind::Tcp, &closed_port()));
        assert!(output["dns_ms"].is_f64(), "{output}");
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
            "dns_ms",
            "connect_ms",
            "first_byte_ms",
            "download_ms",
            "response_ms",
        ] {
            assert!(output[stage].is_f64(), "{stage}: {output}");
        }
        assert!(output.get("tls_ms").is_none());
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
        assert_eq!(decompress(&packed).unwrap().len(), MAX_BODY_BYTES);
    }

    #[test]
    fn a_failed_web_check_does_not_repeat_its_url() {
        let target = format!("http://user:secret@{}/token", closed_port());
        let output = run(&check(CheckKind::Http, &target));
        assert_eq!(output["up"], 0);
        assert!(!output.to_string().contains("secret"), "{output}");
        assert!(!output.to_string().contains("token"), "{output}");
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
            timeout_secs: Some(1),
            ..http_check(&address)
        });

        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "timed out");
        assert!(output["connect_ms"].is_f64(), "{output}");
        assert!(started.elapsed() < Duration::from_secs(3));
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
        let certified = rcgen::generate_simple_self_signed(
            names.iter().map(ToString::to_string).collect::<Vec<_>>(),
        )
        .unwrap();
        let chain = vec![certified.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::Stream::new(&mut connection, &mut socket);
            let mut request = [0; 1024];
            if stream.read(&mut request).is_ok() {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(200));
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
        assert!(output["tls_ms"].is_f64(), "{output}");
        assert!(
            output["tls_version"]
                .as_str()
                .unwrap()
                .starts_with("TLS 1.")
        );
        assert!(output["cert_days_left"].as_i64().unwrap() > 300);
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
        assert!(output["tls_ms"].is_f64(), "{output}");
        assert!(output["status"].is_null(), "{output}");
        assert!(output["first_byte_ms"].is_null(), "{output}");
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
            read_dates(&chain, 0, &mut findings);
            let start = rcgen::date_time_ymd(2024, 1, 1).unix_timestamp();
            let end = rcgen::date_time_ymd(2030, 1, 1).unix_timestamp();
            assert_eq!(findings.cert_not_before, Some(start));
            assert_eq!(findings.cert_not_after, Some(end));
            assert_eq!(findings.cert_days_left, Some(days_left(end, 0)));
        }
    }

    #[test]
    fn days_left_rounds_down_and_goes_negative_once_expired() {
        assert_eq!(days_left(10 * SECS_PER_DAY, 0), 10);
        assert_eq!(days_left(10 * SECS_PER_DAY - 1, 0), 9);
        assert_eq!(days_left(0, 1), -1);
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
        assert!(output["dns_ms"].is_f64());
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

    #[test]
    fn ping_options_suit_each_system() {
        let limit = Duration::from_secs(10);
        assert_eq!(
            ping_arguments("linux", "a", 5, limit),
            ["-c", "5", "-W", "10", "-w", "10", "a"]
        );
        assert_eq!(
            ping_arguments("macos", "a", 5, limit),
            ["-c", "5", "-t", "10", "a"]
        );
        assert_eq!(
            ping_arguments("freebsd", "a", 1, limit),
            ["-c", "1", "-t", "10", "a"]
        );
        assert_eq!(
            ping_arguments("windows", "a", 5, limit),
            ["-n", "5", "-w", "2000", "a"],
            "Windows only waits per reply, so the limit is shared out"
        );
    }

    #[test]
    fn ping_summaries_are_read_on_each_system() {
        let linux = "5 packets transmitted, 4 received, 20% packet loss, time 4005ms\n\
                     rtt min/avg/max/mdev = 1.100/2.200/3.300/0.400 ms\n";
        let mut findings = Findings::default();
        read_ping_summary(linux, &mut findings);
        assert_eq!(findings.packet_loss_percent, Some(20.0));
        assert_eq!(findings.rtt_min_ms, Some(1.1));
        assert_eq!(findings.rtt_max_ms, Some(3.3));
        assert_eq!(findings.rtt_stddev_ms, Some(0.4));

        let bsd = "5 packets transmitted, 5 packets received, 0.0% packet loss\n\
                   round-trip min/avg/max/stddev = 0.1/0.2/0.3/0.05 ms\n";
        let mut findings = Findings::default();
        read_ping_summary(bsd, &mut findings);
        assert_eq!(findings.packet_loss_percent, Some(0.0));
        assert_eq!(findings.rtt_min_ms, Some(0.1));
    }

    #[test]
    fn an_unreadable_ping_summary_is_left_out() {
        let mut findings = Findings::default();
        read_ping_summary(
            "Antwort von 10.0.0.1: Zeit<1ms\n100% something",
            &mut findings,
        );
        assert_eq!(findings.packet_loss_percent, None);
        assert_eq!(findings.rtt_min_ms, None);
    }

    #[test]
    fn ping_reaches_this_machine_and_reports_loss() {
        let output = run(&Check {
            count: Some(2),
            ..check(CheckKind::Ping, "127.0.0.1")
        });
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["packet_loss_percent"], 0.0);
        assert!(output["rtt_max_ms"].is_f64(), "{output}");
    }
}
