//! maxnines run for real against a fake server, as a person or a script would.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

/// A request the fake server saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    body: String,
}

type Answerer = dyn Fn(&Seen) -> (u16, String) + Send + Sync;

/// Answers each request with what `answer` says, and keeps them.
struct FakeServer {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeServer {
    fn start(answer: impl Fn(&Seen) -> (u16, String) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&seen);
        let answer: Arc<Answerer> = Arc::new(answer);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (kept, answer) = (Arc::clone(&kept), Arc::clone(&answer));
                std::thread::spawn(move || serve(stream, &kept, &*answer));
            }
        });
        Self { url, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn requests_to(&self, prefix: &str) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.target.starts_with(prefix))
            .collect()
    }
}

/// Reads the whole request, headers and body, before answering, so the client is
/// never cut off mid-send.
fn serve(mut stream: TcpStream, kept: &Mutex<Vec<Seen>>, answer: &Answerer) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };
    let length: usize = header("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    while buffer.len() < head_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let seen = Seen {
        method: first.next().unwrap_or_default().to_string(),
        target: first.next().unwrap_or_default().to_string(),
        authorization: header("authorization"),
        body: String::from_utf8_lossy(&buffer[head_end..]).to_string(),
    };
    kept.lock().unwrap().push(seen.clone());
    let (status, body) = answer(&seen);
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Runs maxnines with its own folder, so nothing of yours is touched.
fn maxnines(folder: &Path, environment: &[(&str, &str)], arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maxnines"));
    command
        .args(arguments)
        .env("MAXNINES_CONFIG_DIR", folder)
        .env_remove("MAXNINES_URL")
        .env_remove("MAXNINES_API_KEY")
        .env_remove("MAXNINES_CONTEXT");
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn with_key(url: &str) -> [(&str, &str); 2] {
    [("MAXNINES_URL", url), ("MAXNINES_API_KEY", "mxn_test")]
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn hosts_json() -> Value {
    json!([
        {"id": "3f2a1c9d4e6b0000", "kind": "agent", "hostname": "web-1", "state": "approved", "online": true, "health": "online", "last_seen_at": null},
        {"id": "8be04471aaaa0000", "kind": "agent", "hostname": "web-1", "state": "approved", "online": false, "health": "offline", "last_seen_at": null},
        {"id": "22ad9264b6eb0000", "kind": "agentless", "hostname": "db-1", "state": "pending", "online": false, "health": null, "last_seen_at": null}
    ])
}

fn alerts_json() -> Value {
    json!({
        "open": [{
            "id": 41, "rule_id": 2, "rule_name": "Container down", "severity": "critical",
            "host_id": "22ad9264b6eb0000", "hostname": "db-1", "series": "web",
            "summary": "Container web on db-1 is exited", "started_at": "1970-01-01T00:00:00.001Z",
            "resolved_at": null, "acknowledged_by": null, "silence_id": null, "maintenance_window_id": null
        }],
        "resolved": []
    })
}

/// A server with hosts and one alert, taking silences.
fn monitoring() -> FakeServer {
    FakeServer::start(|seen| {
        match (seen.method.as_str(), seen.target.as_str()) {
        // The one filter these tests use, as the server would apply it.
        ("GET", target) if target.starts_with("/api/v1/hosts?filter=hostname%3Dweb") => {
            let web: Vec<Value> = hosts_json().as_array().unwrap().iter().filter(|host| host["hostname"] == "web-1").cloned().collect();
            (200, Value::Array(web).to_string())
        }
        ("GET", target) if target.starts_with("/api/v1/hosts") => (200, hosts_json().to_string()),
        ("GET", "/api/v1/alerts") => (200, alerts_json().to_string()),
        ("GET", "/api/v1/alert-rules") => (200, "[]".to_string()),
        ("GET", "/api/v1/silences") => (
            200,
            json!({"active": [], "ended": [{"id": 9, "rule_id": null, "filter": "hostname=db*", "series": null, "all_alerts": false, "reason": "Done", "created_by": "you@example.com", "starts_at": "1970-01-01T00:00:00.001Z", "ends_at": "1970-01-01T00:00:00.002Z"}]}).to_string(),
        ),
        ("POST", "/api/v1/silences") => (201, json!({"id": 57}).to_string()),
        ("POST", "/api/v1/alerts/41/acknowledge") => (204, String::new()),
        ("POST", "/api/v1/hosts/22ad9264b6eb0000/approve") => (
            200,
            json!({"id": "22ad9264b6eb0000", "kind": "agentless", "hostname": "db-1", "state": "approved"}).to_string(),
        ),
        ("GET", "/api/v1/remote-checks") => (
            200,
            json!([{"id": 7, "host_id": "3f2a1c9d4e6b0000", "enabled": true, "check": {"name": "Home page", "kind": "http", "target": "http://web-1"}, "latest": {"up": true}}]).to_string(),
        ),
        ("GET", "/api/v1/me") => (200, json!({"email": "you@example.com", "role": "responder", "via": {"kind": "api_key", "id": 3, "name": "ci"}}).to_string()),
        _ => (404, json!({"error": "There's nothing at this address"}).to_string()),
    }
    })
}

#[test]
fn hosts_are_listed_for_people_and_for_scripts() {
    let folder = tempfile::tempdir().unwrap();
    let server = monitoring();

    let table = maxnines(folder.path(), &with_key(&server.url), &["get", "hosts"]);
    assert!(table.status.success(), "{}", stderr(&table));
    let text = stdout(&table);
    assert!(
        text.starts_with("HOSTNAME  ID        STATUS   LAST SEEN"),
        "{text}"
    );
    assert!(text.contains("db-1      22ad9264  pending  -"), "{text}");
    assert_eq!(
        server.seen()[0].authorization.as_deref(),
        Some("Bearer mxn_test")
    );

    // By ID, as hostnames needn't be unique, in a form every command takes back.
    let names = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "hosts", "-o", "name", "db-1"],
    );
    assert_eq!(stdout(&names), "host/22ad9264b6eb0000");
    let back = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "hosts", "-o", "name", &stdout(&names)],
    );
    assert_eq!(stdout(&back), "host/22ad9264b6eb0000", "{}", stderr(&back));

    // Approving gives the API's answer as JSON: the host, approved.
    let approved = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["approve", "host", "host/22ad9264b6eb0000", "-o", "json"],
    );
    assert!(approved.status.success(), "{}", stderr(&approved));
    let host: Value = serde_json::from_str(&stdout(&approved)).unwrap();
    assert_eq!(host["state"], "approved");

    let json = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "h", "3f2a", "-o", "json"],
    );
    let listed: Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(listed[0]["id"], "3f2a1c9d4e6b0000");

    let filtered = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "hosts", "--filter", "os=linux"],
    );
    assert!(filtered.status.success());
    assert!(server.requests_to("/api/v1/hosts?filter=os%3Dlinux").len() == 1);
}

#[test]
fn each_kind_of_failure_has_its_own_exit_code() {
    let folder = tempfile::tempdir().unwrap();
    let server = monitoring();

    // Two hosts by the same name.
    let twice = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "hosts", "web-1"],
    );
    assert_eq!(twice.status.code(), Some(3));
    assert!(
        stderr(&twice).contains("2 hosts are called web-1: 3f2a1c9d…, 8be04471…"),
        "{}",
        stderr(&twice)
    );

    let refusing = FakeServer::start(|seen| match seen.target.as_str() {
        "/api/v1/hosts" => (401, String::new()),
        "/api/v1/alerts" => (500, String::new()),
        "/api/v1/alerts/1/acknowledge" => (
            403,
            json!({"error": "This needs the responder role"}).to_string(),
        ),
        _ => (
            422,
            json!({"error": "A silence needs a reason"}).to_string(),
        ),
    });
    let unknown_key = maxnines(folder.path(), &with_key(&refusing.url), &["get", "hosts"]);
    assert_eq!(unknown_key.status.code(), Some(4));
    assert!(stderr(&unknown_key).contains("didn't accept the API key"));
    let role = maxnines(folder.path(), &with_key(&refusing.url), &["ack", "1"]);
    assert_eq!(role.status.code(), Some(4));
    assert!(stderr(&role).contains("This needs the responder role"));
    let refused = maxnines(
        folder.path(),
        &with_key(&refusing.url),
        &["silence", "--filter", "x", "--for", "1h", "--reason", " "],
    );
    assert_eq!(refused.status.code(), Some(5));
    assert!(stderr(&refused).contains("A silence needs a reason"));

    // The server failing is its own code, so it's never taken for --exit-code finding something.
    let broken = maxnines(
        folder.path(),
        &with_key(&refusing.url),
        &["get", "alerts", "--exit-code"],
    );
    assert_eq!(broken.status.code(), Some(7), "{}", stderr(&broken));

    // Nothing listens on port 0, so this fails at once everywhere.
    let gone = maxnines(
        folder.path(),
        &with_key("http://127.0.0.1:0"),
        &["get", "hosts"],
    );
    assert_eq!(gone.status.code(), Some(6), "{}", stderr(&gone));

    // Plain http beyond the local network is refused before anything is sent.
    let far = maxnines(
        folder.path(),
        &with_key("http://monitor.example.com"),
        &["get", "hosts"],
    );
    assert_eq!(far.status.code(), Some(2));
    assert!(stderr(&far).contains("needs https://"), "{}", stderr(&far));

    // Not signed in anywhere yet.
    let nowhere = maxnines(folder.path(), &[], &["get", "hosts"]);
    assert_eq!(nowhere.status.code(), Some(4));
    assert!(stderr(&nowhere).contains("maxnines login"));
}

#[test]
fn silencing_an_alert_names_only_that_alert() {
    let folder = tempfile::tempdir().unwrap();
    let server = monitoring();
    let silenced = maxnines(
        folder.path(),
        &with_key(&server.url),
        &[
            "silence", "alert", "41", "--for", "1h", "--reason", "Known", "-o", "name",
        ],
    );
    assert!(silenced.status.success(), "{}", stderr(&silenced));
    assert_eq!(stdout(&silenced), "silence/57");
    let sent: Value =
        serde_json::from_str(&server.requests_to("/api/v1/silences")[0].body).unwrap();
    assert_eq!(
        sent,
        json!({"rule_id": 2, "filter": "id=22ad9264b6eb0000", "series": "web", "reason": "Known", "duration_secs": 3600})
    );

    // The length said back is the one asked for, not rounded down.
    let host = maxnines(
        folder.path(),
        &with_key(&server.url),
        &[
            "silence",
            "host",
            "db-1",
            "--for",
            "2h30m",
            "--reason",
            "Rebooting",
        ],
    );
    assert_eq!(
        stdout(&host),
        "silence/57 started, for 2h 30m",
        "{}",
        stderr(&host)
    );

    // Saying nothing about what to silence isn't silencing everything.
    let unsaid = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["silence", "--for", "1h", "--reason", "x"],
    );
    assert_eq!(unsaid.status.code(), Some(2));
    assert_eq!(server.requests_to("/api/v1/silences").len(), 2);
}

#[test]
fn a_script_can_ask_whether_anything_is_firing() {
    let folder = tempfile::tempdir().unwrap();
    let server = monitoring();
    let firing = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "alerts", "--exit-code"],
    );
    assert_eq!(firing.status.code(), Some(1));
    assert!(
        stdout(&firing).contains("Container down"),
        "{}",
        stdout(&firing)
    );
    let elsewhere = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "alerts", "--exit-code", "--filter", "hostname=web*"],
    );
    assert_eq!(elsewhere.status.code(), Some(0), "{}", stderr(&elsewhere));

    let acknowledged = maxnines(folder.path(), &with_key(&server.url), &["ack", "41"]);
    assert_eq!(
        stdout(&acknowledged),
        "alert/41 acknowledged",
        "{}",
        stderr(&acknowledged)
    );
    let posted = &server.requests_to("/api/v1/alerts/41/acknowledge")[0];
    assert_eq!(posted.method, "POST");
    assert_eq!(posted.body, "");
    // As -o name gives it, and with JSON the API's own answer, which is nothing.
    let quiet = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["ack", "alert/41", "-o", "json"],
    );
    assert!(quiet.status.success(), "{}", stderr(&quiet));
    assert_eq!(stdout(&quiet), "");

    // Something that's ended is still found by describe, as text or as JSON.
    let ended = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["describe", "silence", "9", "-o", "json"],
    );
    assert!(ended.status.success(), "{}", stderr(&ended));
    let described: Value = serde_json::from_str(&stdout(&ended)).unwrap();
    assert_eq!(described["reason"], "Done");
    // Found in the one answer, without asking again.
    assert_eq!(server.requests_to("/api/v1/silences").len(), 1);

    let me = maxnines(folder.path(), &with_key(&server.url), &["whoami"]);
    assert_eq!(
        stdout(&me),
        "you@example.com (responder) on MAXNINES_URL, with the API key ci"
    );
}

fn issued(access: &str, refresh: &str) -> String {
    json!({
        "access_token": access, "token_type": "Bearer", "expires_in": 3600,
        "refresh_token": refresh, "refresh_token_expires_in": 7_776_000,
        "role": "responder", "user": "you@example.com", "sign_in_id": 4
    })
    .to_string()
}

#[test]
fn signing_in_with_a_code_keeps_the_tokens_refreshes_them_and_signs_out() {
    let folder = tempfile::tempdir().unwrap();
    let polls = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&polls);
    let server = FakeServer::start(move |seen| {
        match (seen.method.as_str(), seen.target.as_str()) {
        ("POST", "/oauth/device") => (
            200,
            json!({
                "device_code": "mxd_1", "user_code": "BCDF-GHJK",
                "verification_uri": "http://x/device", "verification_uri_complete": "http://x/device?code=BCDF-GHJK",
                "expires_in": 600, "interval": 1
            })
            .to_string(),
        ),
        ("POST", "/oauth/token") if seen.body.contains("device_code") => {
            let mut polls = counted.lock().unwrap();
            *polls += 1;
            if *polls == 1 {
                (400, json!({"error": "authorization_pending"}).to_string())
            } else {
                (200, issued("mxa_1", "mxr_1"))
            }
        }
        ("POST", "/oauth/token") if seen.body.contains("refresh_token=mxr_1") => (200, issued("mxa_2", "mxr_2")),
        ("POST", "/oauth/revoke") => (200, String::new()),
        ("GET", "/api/v1/hosts") => (200, hosts_json().to_string()),
        _ => (404, String::new()),
    }
    });

    let signed_in = maxnines(
        folder.path(),
        &[],
        &[
            "login",
            "lan",
            &server.url,
            "--device",
            "--role",
            "responder",
        ],
    );
    assert!(signed_in.status.success(), "{}", stderr(&signed_in));
    assert!(
        stderr(&signed_in).contains("enter BCDF-GHJK"),
        "{}",
        stderr(&signed_in)
    );
    assert!(
        stdout(&signed_in).contains("as you@example.com (responder)"),
        "{}",
        stdout(&signed_in)
    );
    let started = &server.requests_to("/oauth/device")[0].body;
    assert!(
        started.contains("client_id=maxnines-cli") && started.contains("role=responder"),
        "{started}"
    );

    let config = std::fs::read_to_string(folder.path().join("config.hcl")).unwrap();
    assert!(config.contains("current = \"lan\""), "{config}");
    let listed = maxnines(folder.path(), &[], &["config", "list"]);
    assert!(
        stdout(&listed).contains("you@example.com (responder)"),
        "{}",
        stdout(&listed)
    );

    let hosts = maxnines(folder.path(), &[], &["get", "hosts", "-o", "name"]);
    assert!(hosts.status.success(), "{}", stderr(&hosts));
    assert_eq!(
        server.requests_to("/api/v1/hosts")[0]
            .authorization
            .as_deref(),
        Some("Bearer mxa_1")
    );

    // Once the access token is about to run out, the next command refreshes it first.
    let tokens_file = folder.path().join("tokens.json");
    let mut saved: Value =
        serde_json::from_str(&std::fs::read_to_string(&tokens_file).unwrap()).unwrap();
    saved["lan"]["access_expires_at"] = json!("1970-01-01T00:00:00Z");
    std::fs::write(&tokens_file, saved.to_string()).unwrap();
    let refreshed = maxnines(folder.path(), &[], &["get", "hosts", "-o", "name"]);
    assert!(refreshed.status.success(), "{}", stderr(&refreshed));
    assert_eq!(
        server.requests_to("/api/v1/hosts")[1]
            .authorization
            .as_deref(),
        Some("Bearer mxa_2")
    );
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(&tokens_file).unwrap()).unwrap();
    assert_eq!(saved["lan"]["refresh_token"], "mxr_2");

    let signed_out = maxnines(folder.path(), &[], &["logout"]);
    assert!(signed_out.status.success(), "{}", stderr(&signed_out));
    assert!(
        server.requests_to("/oauth/revoke")[0]
            .body
            .contains("token=mxr_2")
    );
    let after = maxnines(folder.path(), &[], &["get", "hosts"]);
    assert_eq!(after.status.code(), Some(4));
    assert!(
        stderr(&after).contains("run maxnines login lan"),
        "{}",
        stderr(&after)
    );

    // Which works: a context's name signs in to it again.
    let again = maxnines(folder.path(), &[], &["login", "lan", "--device"]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert_eq!(server.requests_to("/oauth/device").len(), 2);
}

#[test]
fn silences_and_checks_ask_only_for_what_they_show() {
    let folder = tempfile::tempdir().unwrap();
    let server = monitoring();

    // A silence that names no rule or host by ID needs neither looked up.
    let ended = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "silences", "--ended"],
    );
    assert!(ended.status.success(), "{}", stderr(&ended));
    assert!(
        stdout(&ended).contains("hostname=db*"),
        "{}",
        stdout(&ended)
    );
    assert!(server.requests_to("/api/v1/alert-rules").is_empty());
    assert!(server.requests_to("/api/v1/hosts").is_empty());

    // A silence's own filter says which hosts it covers, so --filter can't pick them.
    let filtered = maxnines(
        folder.path(),
        &with_key(&server.url),
        &[
            "get",
            "silences",
            "--filter",
            "hostname=web-1",
            "--exit-code",
        ],
    );
    assert_eq!(filtered.status.code(), Some(2), "{}", stderr(&filtered));
    assert_eq!(server.requests_to("/api/v1/silences").len(), 1);

    // The hosts a filter matched name the checks shown.
    let checks = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["get", "checks", "--filter", "hostname=web-1"],
    );
    assert!(checks.status.success(), "{}", stderr(&checks));
    assert!(
        stdout(&checks).contains("Home page  web-1"),
        "{}",
        stdout(&checks)
    );
    assert_eq!(server.requests_to("/api/v1/hosts").len(), 1);
}

#[test]
fn the_api_command_sends_what_it_was_given_and_reads_any_answer() {
    let folder = tempfile::tempdir().unwrap();
    let big = format!("\"{}\"", "x".repeat(11 << 20));
    let server = FakeServer::start(move |seen| match seen.target.as_str() {
        "/api/v1/big" => (200, big.clone()),
        _ => (200, "{}".to_string()),
    });

    // Fields join a query the path already has.
    let joined = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["api", "GET", "/hosts?filter=os%3Dlinux", "text=x"],
    );
    assert!(joined.status.success(), "{}", stderr(&joined));
    assert_eq!(
        server.seen()[0].target,
        "/api/v1/hosts?filter=os%3Dlinux&text=x"
    );

    // A body is fields or --data, never both with one dropped.
    let both = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["api", "POST", "/annotations", "--data", "{}", "kind=deploy"],
    );
    assert_eq!(both.status.code(), Some(2), "{}", stderr(&both));

    // A path that can't be asked for is the command's fault, not the network's.
    let spaced = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["api", "GET", "/hosts/filter options"],
    );
    assert_eq!(spaced.status.code(), Some(2), "{}", stderr(&spaced));
    assert_eq!(server.seen().len(), 1);

    // An answer bigger than ureq reads by default is still read whole.
    let read = maxnines(
        folder.path(),
        &with_key(&server.url),
        &["api", "GET", "/big"],
    );
    assert!(read.status.success(), "{}", stderr(&read));
    assert_eq!(stdout(&read).len(), (11 << 20) + 2);
}

#[test]
fn signing_in_again_or_replacing_a_context_revokes_the_sign_in_it_replaces() {
    let folder = tempfile::tempdir().unwrap();
    let issues = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&issues);
    let server = FakeServer::start(move |seen| {
        match (seen.method.as_str(), seen.target.as_str()) {
        ("POST", "/oauth/device") => (
            200,
            json!({
                "device_code": "mxd_1", "user_code": "BCDF-GHJK",
                "verification_uri": "http://x/device", "verification_uri_complete": "http://x/device?code=BCDF-GHJK",
                "expires_in": 600, "interval": 1
            })
            .to_string(),
        ),
        ("POST", "/oauth/token") => {
            let mut issues = counted.lock().unwrap();
            *issues += 1;
            (200, issued(&format!("mxa_{issues}"), &format!("mxr_{issues}")))
        }
        ("POST", "/oauth/revoke") => (200, String::new()),
        _ => (404, String::new()),
    }
    });
    let revoked = || -> Vec<String> {
        server
            .requests_to("/oauth/revoke")
            .iter()
            .map(|seen| seen.body.clone())
            .collect()
    };

    for name in ["lan", "prod"] {
        let signed_in = maxnines(
            folder.path(),
            &[],
            &["login", name, &server.url, "--device"],
        );
        assert!(signed_in.status.success(), "{}", stderr(&signed_in));
    }
    assert!(revoked().is_empty());
    let config = std::fs::read_to_string(folder.path().join("config.hcl")).unwrap();
    assert!(config.contains("current = \"prod\""), "{config}");
    assert!(config.contains("tokens.json beside this file"), "{config}");

    // --context says which to sign in to again, and the sign-in it replaces ends.
    let again = maxnines(
        folder.path(),
        &[],
        &["--context", "lan", "login", "--device"],
    );
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stdout(&again).contains("Context \"lan\""),
        "{}",
        stdout(&again)
    );
    let revoked_now = revoked();
    assert_eq!(revoked_now.len(), 1);
    assert!(revoked_now[0].contains("token=mxr_1"), "{}", revoked_now[0]);

    // A context replaced by one with a key is signed out first.
    let added = maxnines(
        folder.path(),
        &[],
        &[
            "config",
            "add",
            "prod",
            "--server",
            &server.url,
            "--key-env",
            "CI_KEY",
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let revoked_now = revoked();
    assert_eq!(revoked_now.len(), 2);
    assert!(revoked_now[1].contains("token=mxr_2"), "{}", revoked_now[1]);
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(folder.path().join("tokens.json")).unwrap())
            .unwrap();
    assert!(saved.get("prod").is_none(), "{saved}");
    assert_eq!(saved["lan"]["refresh_token"], "mxr_3");
}
