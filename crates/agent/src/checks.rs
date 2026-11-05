//! Tries reaching things, to see if they're up. Errors only ever say what kind
//! of failure it was, as a URL can hold a password.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use maxnines_protocol::{Check, CheckKind};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};
use serde_json::{Value, json};
use x509_parser::parse_x509_certificate;

use crate::background::{Background, Prober};
use crate::collector::Collector;

/// How long one check gets. A slower answer counts as down.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Who to say is asking.
const USER_AGENT: &str = concat!("MaxNines-Agent/", env!("CARGO_PKG_VERSION"));

const REDIRECTS_TO_FOLLOW: u32 = 5;

const SECS_PER_DAY: i64 = 86_400;

pub struct CheckCollector {
    background: Background,
}

impl CheckCollector {
    pub fn new(checks: Vec<Check>, interval: Duration) -> Self {
        let prober = Prober::new(checks, TIMEOUT + Duration::from_secs(1));
        let background = Background::start(interval, move || {
            let results = prober.round(run, |check| report(check, None, Err(timed_out())));
            Value::Array(results)
        });
        Self { background }
    }
}

impl Collector for CheckCollector {
    fn name(&self) -> &'static str {
        "checks"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

fn timed_out() -> anyhow::Error {
    anyhow!("timed out")
}

/// What a successful check found out, beyond being up.
#[derive(Default)]
struct Findings {
    status: Option<u16>,
    cert_days_left: Option<i64>,
}

fn report(check: &Check, elapsed: Option<Duration>, result: Result<Findings>) -> Value {
    let mut output = json!({
        "name": check.name,
        "kind": check.kind.as_str(),
        "up": u8::from(result.is_ok()),
    });
    match result {
        Ok(findings) => {
            if let Some(elapsed) = elapsed {
                output["response_ms"] = json!(elapsed.as_secs_f64() * 1000.0);
            }
            if let Some(status) = findings.status {
                output["status"] = json!(status);
            }
            if let Some(days) = findings.cert_days_left {
                output["cert_days_left"] = json!(days);
            }
        }
        Err(error) => output["error"] = json!(format!("{error:#}")),
    }
    output
}

fn run(check: &Check) -> Value {
    let started = Instant::now();
    let result = match check.kind {
        CheckKind::Tcp => check_tcp(&check.target),
        CheckKind::Http => check_http(&check.target),
        CheckKind::Tls => check_tls(&check.target),
        CheckKind::Dns => check_dns(&check.target),
        CheckKind::Ping => check_ping(&check.target),
    };
    report(check, Some(started.elapsed()), result)
}

fn resolve(target: &str) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|_| anyhow!("the name wasn't found"))?
        .collect();
    ensure!(!addresses.is_empty(), "the name wasn't found");
    Ok(addresses)
}

/// Tries each address, as a name can have several and only some may answer.
fn connect(target: &str) -> Result<TcpStream> {
    for address in resolve(target)? {
        if let Ok(stream) = TcpStream::connect_timeout(&address, TIMEOUT) {
            return Ok(stream);
        }
    }
    bail!("couldn't connect")
}

fn check_tcp(target: &str) -> Result<Findings> {
    connect(target)?;
    Ok(Findings::default())
}

fn check_dns(target: &str) -> Result<Findings> {
    resolve(&format!("{target}:0"))?;
    Ok(Findings::default())
}

/// Anything below 400 is up. Redirects are followed, as sites commonly send
/// plain HTTP on to HTTPS.
fn check_http(url: &str) -> Result<Findings> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .max_redirects(REDIRECTS_TO_FOLLOW)
        .http_status_as_error(false)
        .user_agent(USER_AGENT)
        .build()
        .new_agent();

    match agent.get(url).call() {
        Ok(response) => {
            let status = response.status().as_u16();
            ensure!(status < 400, "the server returned status {status}");
            Ok(Findings {
                status: Some(status),
                ..Findings::default()
            })
        }
        Err(ureq::Error::Timeout(_)) => Err(timed_out()),
        Err(ureq::Error::HostNotFound) => bail!("the name wasn't found"),
        Err(ureq::Error::ConnectionFailed | ureq::Error::Io(_)) => bail!("couldn't connect"),
        Err(ureq::Error::Tls(_) | ureq::Error::Rustls(_)) => {
            bail!("the certificate wasn't accepted")
        }
        Err(_) => bail!("the request failed"),
    }
}

fn tls_config() -> Result<Arc<ClientConfig>> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Connects and reads how long the certificate has left. One that's expired or
/// untrusted fails the handshake, so it counts as down.
fn check_tls(target: &str) -> Result<Findings> {
    let (host, _) = target.rsplit_once(':').context("no port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let name = ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid host name"))?;

    let mut socket = connect(target)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let mut connection = ClientConnection::new(tls_config()?, name)?;
    let mut stream = Stream::new(&mut connection, &mut socket);
    stream
        .flush()
        .map_err(|_| anyhow!("the certificate wasn't accepted"))?;

    let certificate = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .context("the server sent no certificate")?;
    let (_, parsed) =
        parse_x509_certificate(certificate).map_err(|_| anyhow!("unreadable certificate"))?;
    let expires = parsed.validity().not_after.timestamp();
    Ok(Findings {
        cert_days_left: Some(days_left(expires, now_secs())),
        ..Findings::default()
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64)
}

fn days_left(expires_secs: i64, now_secs: i64) -> i64 {
    (expires_secs - now_secs).div_euclid(SECS_PER_DAY)
}

/// Sending ICMP directly needs special rights, so this uses the system's own
/// `ping`, which every platform ships with those rights. Their options differ.
fn ping_arguments(os: &str, host: &str) -> Vec<String> {
    let seconds = TIMEOUT.as_secs().to_string();
    let millis = TIMEOUT.as_millis().to_string();
    let options: Vec<&str> = match os {
        "windows" => vec!["-n", "1", "-w", &millis],
        "linux" => vec!["-c", "1", "-W", &seconds],
        _ => vec!["-c", "1", "-t", &seconds],
    };
    options
        .into_iter()
        .map(String::from)
        .chain([host.to_string()])
        .collect()
}

fn check_ping(host: &str) -> Result<Findings> {
    let status = Command::new("ping")
        .args(ping_arguments(std::env::consts::OS, host))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| anyhow!("couldn't run ping"))?;
    ensure!(status.success(), "no reply");
    Ok(Findings::default())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn check(kind: CheckKind, target: &str) -> Check {
        Check {
            name: "a".to_string(),
            kind,
            target: target.to_string(),
        }
    }

    /// Answers one request with `response`, then closes.
    fn serve_once(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request);
            stream.write_all(response.as_bytes()).unwrap();
        });
        address
    }

    fn closed_port() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
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
    }

    #[test]
    fn a_closed_port_is_down_and_says_why() {
        let output = run(&check(CheckKind::Tcp, &closed_port()));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "couldn't connect");
        assert!(output.get("response_ms").is_none());
    }

    #[test]
    fn an_unknown_name_is_down() {
        let output = run(&check(CheckKind::Tcp, "no-such-host.invalid:80"));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "the name wasn't found");
    }

    #[test]
    fn dns_checks_resolve_a_name() {
        assert_eq!(run(&check(CheckKind::Dns, "localhost"))["up"], 1);
        assert_eq!(run(&check(CheckKind::Dns, "no-such-host.invalid"))["up"], 0);
    }

    #[test]
    fn a_good_web_response_is_up() {
        let address = serve_once("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        let output = run(&check(CheckKind::Http, &format!("http://{address}/health")));
        assert_eq!(output["up"], 1, "{output}");
        assert_eq!(output["status"], 204);
    }

    #[test]
    fn a_web_error_is_down_and_gives_the_status() {
        let address = serve_once("HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n");
        let output = run(&check(CheckKind::Http, &format!("http://{address}/")));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "the server returned status 503");
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
    fn a_server_that_will_not_speak_tls_is_down() {
        let address = serve_once("this isn't TLS\r\n");
        let output = run(&check(CheckKind::Tls, &address));
        assert_eq!(output["up"], 0);
        assert_eq!(output["error"], "the certificate wasn't accepted");
    }

    #[test]
    fn days_left_rounds_down_and_goes_negative_once_expired() {
        assert_eq!(days_left(10 * SECS_PER_DAY, 0), 10);
        assert_eq!(days_left(10 * SECS_PER_DAY - 1, 0), 9);
        assert_eq!(days_left(0, 1), -1);
    }

    #[test]
    fn ping_options_suit_each_system() {
        assert_eq!(ping_arguments("linux", "a"), ["-c", "1", "-W", "10", "a"]);
        assert_eq!(ping_arguments("macos", "a"), ["-c", "1", "-t", "10", "a"]);
        assert_eq!(ping_arguments("freebsd", "a"), ["-c", "1", "-t", "10", "a"]);
        assert_eq!(
            ping_arguments("windows", "a"),
            ["-n", "1", "-w", "10000", "a"]
        );
    }

    #[test]
    fn ping_reaches_this_machine() {
        let output = run(&check(CheckKind::Ping, "127.0.0.1"));
        assert_eq!(output["up"], 1, "{output}");
    }

    #[test]
    fn the_collector_reports_what_its_checks_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let mut collector = CheckCollector::new(
            vec![check(CheckKind::Tcp, &target)],
            Duration::from_secs(60),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let output = collector.collect().unwrap();
            if output[0]["up"] == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "{output}");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
