//! Tests that run the real router over real sockets.

mod alerting;
mod audit;
mod dashboards;
mod docs;
mod roles;
mod two_factor;
mod users;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum_csrf::CsrfConfig;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::{AgentConfig, AgentMessage, RegistrationStatus, Sample, ServerMessage};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{Instant, sleep};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::app_state::{AppState, Heartbeat};
use crate::config::Config;
use crate::controllers::app;
use crate::controllers::host_list::PAGE_SIZE;
use crate::facts::FlatFacts;
use crate::metrics::{Metrics, TimeRange, now_ms};
use crate::models::{Database, FactVersion, RuleInput};
use crate::presence::Presence;
use crate::registration::{AgentState, Registry, Rules};
use crate::server_stats::ServerStatus;
use crate::store::testing::{MemoryStore, Saved};
use crate::store::{self, MetricsReader, Store, WRITE_QUEUE_SIZE, spawn_writer};
use crate::views::Views;
use crate::{AgentsCommand, Cli, Command};

const AUDIENCE: &str = "wss://monitor.example.com/ws";

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct TestServer {
    address: SocketAddr,
    /// A signed in user's session, which browsers use unless they're anonymous.
    session: String,
    /// A key for the API, as scripts use.
    api_key: String,
    state: AppState,
    saved: Saved,
    /// Holds the metrics database, for tests that use a real one.
    _folder: Option<tempfile::TempDir>,
}

fn identity() -> Identity {
    Identity::from_pkcs8(&Identity::generate().unwrap()).unwrap()
}

/// What the pages call the database these tests are running against.
pub fn main_database_engine() -> &'static str {
    match std::env::var("MAXNINES_TEST_DATABASE_URL") {
        Ok(url) if url.starts_with("postgres") => "PostgreSQL",
        Ok(_) => "MySQL",
        Err(_) => "SQLite",
    }
}

async fn start() -> TestServer {
    start_with("").await
}

async fn start_with(config: &str) -> TestServer {
    let saved = Saved::default();
    let store = Box::new(MemoryStore(saved.clone()));
    let reader = store.reader().unwrap();
    start_on(config, store, reader, saved, None).await
}

/// Pings often, so tests about pings needn't wait, and gives up on a quiet client only
/// after a long time. Most tests hold clients they don't read, and a busy machine
/// running every test at once can leave a test unable to read for seconds.
const TEST_HEARTBEAT: Heartbeat = Heartbeat {
    interval: Duration::from_millis(50),
    timeout: Duration::from_secs(120),
};

/// For the tests about giving up on a quiet client, which wait for it to happen.
async fn start_quick_to_drop() -> TestServer {
    let saved = Saved::default();
    let store = Box::new(MemoryStore(saved.clone()));
    let reader = store.reader().unwrap();
    let heartbeat = Heartbeat {
        timeout: Duration::from_secs(1),
        ..TEST_HEARTBEAT
    };
    start_with_heartbeat("", store, reader, saved, None, heartbeat).await
}

/// Starts with a real metrics database, for tests of what's stored.
async fn start_with_metrics() -> TestServer {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("metrics.duckdb");
    let text = format!("metrics \"duckdb\" {{\n  path = {path:?}\n}}\n");
    let store = store::open(&Config::parse(&text).unwrap().metrics).unwrap();
    let reader = store.reader().unwrap();
    start_on("", store, reader, Saved::default(), Some(folder)).await
}

async fn start_on(
    config: &str,
    store: Box<dyn Store>,
    reader: Arc<dyn MetricsReader>,
    saved: Saved,
    folder: Option<tempfile::TempDir>,
) -> TestServer {
    start_with_heartbeat(config, store, reader, saved, folder, TEST_HEARTBEAT).await
}

async fn start_with_heartbeat(
    config: &str,
    store: Box<dyn Store>,
    reader: Arc<dyn MetricsReader>,
    saved: Saved,
    folder: Option<tempfile::TempDir>,
    heartbeat: Heartbeat,
) -> TestServer {
    let text = format!("{config}\nmetrics \"duckdb\" {{\n  path = \"x\"\n}}\n");
    let config = Config::parse(&text).unwrap();

    let database = Database::for_test().await;
    // Tests start with no alert rules, so each says what it relies on. The built-in
    // rule has tests of its own.
    for rule in database.list_alert_rules().await.unwrap() {
        database.delete_alert_rule(rule.id, now_ms()).await.unwrap();
    }
    let (user, _) = database
        .create_user(
            "test@example.com",
            "Tester",
            crate::roles::Role::Admin,
            now_ms(),
        )
        .await
        .unwrap()
        .unwrap();
    let session = database.start_session(user.id, now_ms()).await.unwrap();
    let (_, api_key) = database
        .create_api_key("tests", user.id, crate::roles::Role::Admin, None, now_ms())
        .await
        .unwrap();
    let status = Arc::new(ServerStatus::new(None).unwrap());
    let (writer, _thread) = spawn_writer(store, status.writes.clone());
    let state = AppState {
        presence: Arc::new(Presence::refilling_slowly()),
        registry: Arc::new(Registry::new(
            Vec::new(),
            Rules::compile(&config.registration).unwrap(),
            config.registration.max_pending,
            database.clone(),
        )),
        database,
        config_changes: Arc::new(watch::Sender::new(0)),
        writer,
        metrics: Metrics::new(reader),
        senders: Default::default(),
        check_results: Arc::default(),
        status,
        heartbeat,
        audience: AUDIENCE.into(),
        trusted_proxies: config.trusted_networks().unwrap().into(),
        views: Arc::new(Views::load().unwrap()),
        csrf: CsrfConfig::default(),
        web_url: "http://site.test".into(),
        sign_ins: Arc::default(),
        require_two_factor: Arc::default(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });

    TestServer {
        address,
        session,
        api_key,
        state,
        saved,
        _folder: folder,
    }
}

impl TestServer {
    /// The signed in user's ID.
    async fn user_id(&self) -> i64 {
        let database = &self.state.database;
        let user = database.active_user_by_email("test@example.com").await;
        user.unwrap().unwrap().id
    }

    async fn connect(&self) -> Client {
        connect_async(format!("ws://{}/ws", self.address))
            .await
            .unwrap()
            .0
    }

    async fn connect_from(&self, forwarded_for: &str) -> Client {
        let mut request = format!("ws://{}/ws", self.address)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("x-forwarded-for", forwarded_for.parse().unwrap());
        connect_async(request).await.unwrap().0
    }

    /// Connects an already approved agent.
    async fn connect_approved(&self, agent: &Identity, host: &str) -> Client {
        let mut client = self.connect().await;
        assert_eq!(
            handshake(&mut client, agent, host, None).await,
            RegistrationStatus::Pending
        );
        self.approve(agent).await;

        let mut client = self.connect().await;
        assert_eq!(
            handshake(&mut client, agent, host, None).await,
            RegistrationStatus::Approved
        );
        self.wait_for_online(&agent.id(), true).await;
        client
    }

    async fn approve(&self, agent: &Identity) {
        let id = agent.id();
        let registry = &self.state.registry;
        registry.decide(&id, AgentState::Approved).await.unwrap();
    }

    /// Returns as soon as it's so, so a long deadline costs nothing.
    async fn wait_for_online(&self, id: &str, online: bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self
                .state
                .presence
                .get(id)
                .is_some_and(|p| p.online == online)
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("{id} never reached online={online}");
    }

    async fn wait_for_sample(&self) -> (String, String, u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(sample) = self.saved.samples.lock().unwrap().first() {
                return sample.clone();
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("no sample arrived");
    }

    async fn http(&self, method: &str, path: &str, token: Option<&str>) -> String {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }
}

async fn read_server_message(client: &mut Client) -> ServerMessage {
    loop {
        match client.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected message {other:?}"),
        }
    }
}

async fn read_nonce(client: &mut Client) -> String {
    match read_server_message(client).await {
        ServerMessage::Challenge { nonce } => nonce,
        other => panic!("expected a challenge, got {other:?}"),
    }
}

async fn read_status(client: &mut Client) -> RegistrationStatus {
    match read_server_message(client).await {
        ServerMessage::Registration { status } => status,
        other => panic!("expected a status, got {other:?}"),
    }
}

async fn send(client: &mut Client, message: &AgentMessage) {
    let text = serde_json::to_string(message).unwrap();
    client.send(Message::text(text)).await.unwrap();
}

fn hello(agent: &Identity, host: &str, signature: String, token: Option<&str>) -> AgentMessage {
    AgentMessage::Hello {
        host: host.to_string(),
        public_key: agent.public_key(),
        signature,
        token: token.map(String::from),
    }
}

async fn handshake(
    client: &mut Client,
    agent: &Identity,
    host: &str,
    token: Option<&str>,
) -> RegistrationStatus {
    let nonce = read_nonce(client).await;
    let signature = agent.sign(AUDIENCE, &nonce);
    send(client, &hello(agent, host, signature, token)).await;
    read_status(client).await
}

fn sample(timestamp_ms: u64) -> AgentMessage {
    AgentMessage::Sample(Sample {
        timestamp_ms,
        metrics: BTreeMap::new(),
    })
}

/// True once the server has closed the connection.
async fn is_closed(client: &mut Client) -> bool {
    let reading = async {
        loop {
            match client.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), reading)
        .await
        .is_ok()
}

// ---- registration

#[tokio::test]
async fn a_new_agent_is_pending_and_disconnected() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;

    let status = handshake(&mut client, &agent, "web-1", None).await;

    assert_eq!(status, RegistrationStatus::Pending);
    assert!(is_closed(&mut client).await);
    assert!(server.state.presence.get(&agent.id()).is_none());
}

#[tokio::test]
async fn a_pending_agent_can_not_send_samples() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "web-1", None).await;

    let _ = client
        .send(Message::text(serde_json::to_string(&sample(1)).unwrap()))
        .await;
    sleep(Duration::from_millis(100)).await;

    assert!(server.saved.samples.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_approved_agent_is_accepted_and_its_samples_are_attributed() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    send(&mut client, &sample(42)).await;

    assert_eq!(
        server.wait_for_sample().await,
        (agent.id(), "web-1".to_string(), 42)
    );
}

#[tokio::test]
async fn revoking_a_connected_agent_drops_it_and_keeps_it_out() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let id = agent.id();
    let registry = &server.state.registry;
    registry.decide(&id, AgentState::Revoked).await.unwrap();

    assert!(is_closed(&mut client).await);
    server.wait_for_online(&agent.id(), false).await;

    let mut client = server.connect().await;
    assert_eq!(
        handshake(&mut client, &agent, "web-1", None).await,
        RegistrationStatus::Rejected
    );
}

#[tokio::test]
async fn approving_one_agent_does_not_disturb_another() {
    let server = start().await;
    let first = identity();
    let mut client = server.connect_approved(&first, "web-1").await;

    server.connect_approved(&identity(), "web-2").await;

    send(&mut client, &sample(42)).await;
    assert_eq!(server.wait_for_sample().await.2, 42);
}

// ---- authentication

#[tokio::test]
async fn a_signature_for_another_server_is_rejected() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;

    let nonce = read_nonce(&mut client).await;
    let signature = agent.sign("wss://evil.example.com/ws", &nonce);
    send(&mut client, &hello(&agent, "web-1", signature, None)).await;

    assert_eq!(read_status(&mut client).await, RegistrationStatus::Rejected);
    assert!(server.state.registry.list().await.is_empty());
}

#[tokio::test]
async fn a_replayed_signature_is_rejected() {
    let server = start().await;
    let agent = identity();

    let mut first = server.connect().await;
    let nonce = read_nonce(&mut first).await;
    let captured = agent.sign(AUDIENCE, &nonce);
    send(&mut first, &hello(&agent, "web-1", captured.clone(), None)).await;
    read_status(&mut first).await;
    server.approve(&agent).await;

    let mut second = server.connect().await;
    read_nonce(&mut second).await;
    send(&mut second, &hello(&agent, "web-1", captured, None)).await;

    assert_eq!(read_status(&mut second).await, RegistrationStatus::Rejected);
}

#[tokio::test]
async fn an_approved_agents_public_key_is_useless_without_its_private_key() {
    let server = start().await;
    let agent = identity();
    server.connect_approved(&agent, "web-1").await;

    let attacker = identity();
    let mut client = server.connect().await;
    let nonce = read_nonce(&mut client).await;
    let forged = attacker.sign(AUDIENCE, &nonce);
    send(&mut client, &hello(&agent, "web-1", forged, None)).await;

    assert_eq!(read_status(&mut client).await, RegistrationStatus::Rejected);
}

#[tokio::test]
async fn a_sample_before_the_handshake_ends_the_connection() {
    let server = start().await;
    let mut client = server.connect().await;

    read_nonce(&mut client).await;
    send(&mut client, &sample(1)).await;

    assert!(is_closed(&mut client).await);
    assert!(server.saved.samples.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_oversized_hostname_ends_the_connection() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;

    let nonce = read_nonce(&mut client).await;
    let signature = agent.sign(AUDIENCE, &nonce);
    send(
        &mut client,
        &hello(&agent, &"x".repeat(256), signature, None),
    )
    .await;

    assert!(is_closed(&mut client).await);
    assert!(server.state.registry.list().await.is_empty());
}

/// Anyone can open a connection, so what one can make the server hold in memory
/// is limited before the handshake as well as after it.
#[tokio::test]
async fn a_huge_message_ends_the_connection_before_and_after_the_handshake() {
    let server = start().await;
    let huge = "x".repeat(2 * 1024 * 1024);

    let mut client = server.connect().await;
    read_nonce(&mut client).await;
    let _ = client.send(Message::text(huge.clone())).await;
    assert!(is_closed(&mut client).await);

    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let _ = client.send(Message::text(huge)).await;
    assert!(is_closed(&mut client).await);
    assert!(server.saved.samples.lock().unwrap().is_empty());
}

/// One key, one connection: a second machine with the same key would otherwise
/// share the agent's identity quietly.
#[tokio::test]
async fn a_newer_connection_replaces_the_older_one() {
    let server = start().await;
    let agent = identity();
    let mut first = server.connect_approved(&agent, "web-1").await;

    let mut second = server.connect().await;
    assert_eq!(
        handshake(&mut second, &agent, "web-1", None).await,
        RegistrationStatus::Approved
    );

    assert!(is_closed(&mut first).await);
    assert!(server.state.presence.get(&agent.id()).unwrap().online);
}

#[tokio::test]
async fn an_agent_connecting_too_often_is_told_to_wait() {
    let server = start().await;
    let agent = identity();
    let _first = server.connect_approved(&agent, "web-1").await;

    let mut clients = Vec::new();
    for _ in 1..10 {
        let mut client = server.connect().await;
        assert_eq!(
            handshake(&mut client, &agent, "web-1", None).await,
            RegistrationStatus::Approved
        );
        clients.push(client);
    }

    let mut client = server.connect().await;
    assert_eq!(
        handshake(&mut client, &agent, "web-1", None).await,
        RegistrationStatus::Pending
    );
    assert!(is_closed(&mut client).await);
}

#[tokio::test]
async fn facts_reported_too_often_are_dropped() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    for version in 0..8 {
        send(&mut client, &facts(&format!("24.{version}"))).await;
    }
    // Messages are judged in the order they come, so once a sample after them is
    // confirmed, every one of the facts has been kept or dropped.
    send(&mut client, &sample(1)).await;
    let confirmed = async {
        while let Some(Ok(message)) = client.next().await {
            if let Message::Text(text) = message
                && let Ok(ServerMessage::Ack { .. }) = serde_json::from_str(&text)
            {
                return;
            }
        }
        panic!("the connection ended");
    };
    tokio::time::timeout(Duration::from_secs(30), confirmed)
        .await
        .unwrap();

    // The family once, and each version kept.
    let history = server.wait_for_facts(&agent.id(), 6).await;
    let versions: Vec<&str> = history
        .iter()
        .filter(|fact| fact.name == "os.version")
        .filter_map(|fact| fact.value.as_str())
        .collect();
    assert_eq!(versions.len(), 5, "{versions:?}");
}

#[tokio::test]
async fn the_agents_page_says_when_a_waiting_agent_last_asked() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "new-box", None).await;

    let page = Browser::default().get(&server, "/agents").await;

    assert!(page.body.contains("Waiting for approval"), "{}", page.body);
    assert!(page.body.contains("asked "), "{}", page.body);
}

#[tokio::test]
async fn the_online_count_is_out_of_approved_agents_only() {
    let server = start().await;
    let (kept, revoked) = (identity(), identity());
    let _client = server.connect_approved(&kept, "web-1").await;
    let _gone = server.connect_approved(&revoked, "web-2").await;
    server
        .state
        .registry
        .decide(&revoked.id(), AgentState::Revoked)
        .await
        .unwrap();

    let page = Browser::default().get(&server, "/agents").await;

    assert!(page.body.contains("1 of 1 online"), "{}", page.body);
}

#[tokio::test]
async fn a_connection_that_never_answers_the_challenge_is_closed() {
    let server = start_quick_to_drop().await;
    let mut client = server.connect().await;

    assert!(is_closed(&mut client).await);
    assert!(server.state.registry.list().await.is_empty());
}

// ---- automatic rules through real connections

#[tokio::test]
async fn a_token_rule_approves_over_a_real_connection() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("token");
    std::fs::write(&path, "enroll-me").unwrap();
    let config = format!(
        "registration {{\nrule \"token\" {{\n  action = \"approve\"\n  token_file = {:?}\n}}\n}}",
        path.display().to_string()
    );
    let server = start_with(&config).await;

    let mut client = server.connect().await;
    let status = handshake(&mut client, &identity(), "web-1", Some("enroll-me")).await;

    assert_eq!(status, RegistrationStatus::Approved);
}

const SUBNET_CONFIG: &str = r#"
trusted_proxies = ["127.0.0.1"]
registration {
  rule "subnet" {
    action       = "approve"
    source_cidrs = ["10.20.0.0/16"]
  }
}
"#;

#[tokio::test]
async fn a_source_rule_uses_the_address_from_a_trusted_proxy() {
    let server = start_with(SUBNET_CONFIG).await;

    let mut client = server.connect_from("10.20.1.2").await;
    let status = handshake(&mut client, &identity(), "web-1", None).await;

    assert_eq!(status, RegistrationStatus::Approved);
}

#[tokio::test]
async fn a_forged_forwarded_header_does_not_match_a_source_rule() {
    // Without trusted_proxies, the same header must count for nothing.
    let server = start_with(&SUBNET_CONFIG.replace(r#"["127.0.0.1"]"#, "[]")).await;

    let mut client = server.connect_from("10.20.1.2").await;
    let status = handshake(&mut client, &identity(), "web-1", None).await;

    assert_eq!(status, RegistrationStatus::Pending);
}

// ---- presence and heartbeats

#[tokio::test]
async fn a_clean_close_marks_the_agent_offline() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    client.close(None).await.unwrap();

    server.wait_for_online(&agent.id(), false).await;
}

/// Reads in the background as an agent would, counting the server's pings.
fn count_pings(receiver: futures_util::stream::SplitStream<Client>) -> Arc<AtomicU64> {
    let pings = Arc::new(AtomicU64::new(0));
    let counted = pings.clone();
    tokio::spawn(async move {
        let mut receiver = receiver;
        while let Some(Ok(message)) = receiver.next().await {
            if matches!(message, Message::Ping(_)) {
                counted.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    pings
}

/// An address nothing can listen on, so connecting fails at once on every system. A
/// port that was free a moment ago can be given to another test meanwhile, and one
/// held without listening is refused on Linux but ignored on macOS until it times out.
const CLOSED_ADDRESS: &str = "127.0.0.1:0";

/// Waits for another ping to arrive, however long the machine takes.
async fn more_pings(pings: &AtomicU64) {
    let before = pings.load(Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(30);
    while pings.load(Ordering::Relaxed) == before {
        assert!(Instant::now() < deadline, "pings stopped");
        sleep(Duration::from_millis(10)).await;
    }
}

mod health {
    use std::sync::atomic::Ordering;

    use super::*;

    async fn health(server: &TestServer) -> (u16, Value) {
        let page = Browser::anonymous().get(server, "/health").await;
        (page.status, serde_json::from_str(&page.body).unwrap())
    }

    #[tokio::test]
    async fn a_working_server_says_so_to_anyone() {
        let server = start().await;

        let (status, body) = health(&server).await;

        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body,
            json!({
                "status": "ok",
                "checks": {
                    "database": "ok",
                    "metrics": "ok",
                    "writer": "ok",
                    "alerts": "ok",
                },
            })
        );
    }

    /// Some uptime monitors can only send `HEAD`, so the status has to tell them.
    #[tokio::test]
    async fn a_head_request_gets_the_status_with_no_body() {
        let server = start().await;

        let response = server.http("HEAD", "/health", None).await;

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty(), "{body}");
    }

    #[tokio::test]
    async fn a_head_request_hears_about_a_failure_too() {
        let server = start().await;
        server.state.database.break_for_test().await;

        let response = server.http("HEAD", "/health", None).await;

        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty(), "{body}");
    }

    #[tokio::test]
    async fn a_database_that_is_down_fails_the_check_without_saying_why() {
        let server = start().await;
        server.state.database.break_for_test().await;

        let (status, body) = health(&server).await;

        assert_eq!(status, 503);
        assert_eq!(body["status"], "failing");
        assert_eq!(body["checks"]["database"], "failing");
        assert_eq!(body["checks"]["metrics"], "ok");
    }

    #[tokio::test]
    async fn a_stalled_database_counts_as_failing_rather_than_hanging() {
        let server = start().await;
        let _stalled = server.state.database.stall_for_test().await;

        let (status, body) = health(&server).await;

        assert_eq!(status, 503);
        assert_eq!(body["checks"]["database"], "failing");
    }

    #[tokio::test]
    async fn alert_rules_that_have_stopped_fail_the_check() {
        let server = start().await;
        let long_ago = now_ms() - 120_000;
        let mut stale = ServerStatus::new(None).unwrap();
        stale.started_ms = long_ago;
        let mut state = server.state.clone();
        state.status = Arc::new(stale);
        state
            .status
            .last_alert_pass_ms
            .store(long_ago, Ordering::Relaxed);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = app(state).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, service).await });

        let response = get_health(address).await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains(r#""alerts":"failing""#), "{response}");
    }

    async fn get_health(address: SocketAddr) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }
}

#[tokio::test]
async fn a_sample_with_an_impossible_time_is_answered_but_never_stored() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    send(&mut client, &sample(u64::MAX)).await;
    loop {
        if let ServerMessage::Ack { timestamp_ms } = read_server_message(&mut client).await {
            assert_eq!(timestamp_ms, u64::MAX);
            break;
        }
    }

    send(&mut client, &sample(5)).await;
    assert_eq!(
        server.wait_for_sample().await.2,
        5,
        "and it blocked nothing"
    );
}

#[tokio::test]
async fn a_stalled_database_does_not_hold_up_samples_or_heartbeats() {
    let server = start().await;
    let agent = identity();
    let client = server.connect_approved(&agent, "web-1").await;
    let (mut sender, receiver) = client.split();
    let pings = count_pings(receiver);
    let stalled = server.state.database.stall_for_test().await;

    let facts = AgentMessage::Facts {
        facts: json!({ "os": "linux" }),
    };
    for message in [&facts, &sample(1)] {
        let text = serde_json::to_string(message).unwrap();
        sender.send(Message::text(text)).await.unwrap();
    }

    assert_eq!(server.wait_for_sample().await.2, 1);
    more_pings(&pings).await;

    drop(stalled);
    let facts = server.wait_for_facts(&agent.id(), 1).await;
    assert_eq!(facts[0].name, "os");
}

#[tokio::test]
async fn a_full_write_queue_stops_reading_but_not_the_heartbeat() {
    let server = start_quick_to_drop().await;
    let agent = identity();
    let client = server.connect_approved(&agent, "web-1").await;
    let (mut sender, receiver) = client.split();
    let pings = count_pings(receiver);
    server.saved.paused.store(true, Ordering::Relaxed);

    // One lot being written, a full queue, and more waiting behind them.
    let count = 2 * WRITE_QUEUE_SIZE as u64 + 100;
    for time in 0..count {
        let text = serde_json::to_string(&sample(time)).unwrap();
        sender.send(Message::text(text)).await.unwrap();
    }

    // Long enough to be taken for dead, had the wait counted as silence.
    sleep(server.state.heartbeat.timeout + Duration::from_millis(500)).await;
    more_pings(&pings).await;
    assert!(server.state.presence.get(&agent.id()).unwrap().online);

    server.saved.paused.store(false, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(30);
    while (server.saved.samples.lock().unwrap().len() as u64) < count {
        assert!(Instant::now() < deadline, "samples went missing");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_dropped_connection_marks_the_agent_offline() {
    let server = start().await;
    let agent = identity();
    let client = server.connect_approved(&agent, "web-1").await;

    drop(client);

    server.wait_for_online(&agent.id(), false).await;
}

#[tokio::test]
async fn an_agent_that_stops_responding_goes_offline() {
    let server = start_quick_to_drop().await;
    let agent = identity();
    // Held open but never read, like a hung agent or a dead network.
    let _client = server.connect_approved(&agent, "web-1").await;

    server.wait_for_online(&agent.id(), false).await;
}

#[tokio::test]
async fn an_agent_answering_pings_stays_online() {
    let server = start_quick_to_drop().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    // Past the point where a quiet agent counts as gone. Reading is what answers
    // the pings.
    let deadline = Instant::now() + server.state.heartbeat.timeout + Duration::from_millis(500);
    // Stops at the deadline, or when the server closes the connection.
    while let Ok(Some(Ok(_))) = tokio::time::timeout_at(deadline, client.next()).await {}

    assert!(server.state.presence.get(&agent.id()).unwrap().online);
}

#[tokio::test]
async fn invalid_messages_do_not_end_the_connection() {
    let server = start().await;
    let mut client = server.connect_approved(&identity(), "web-1").await;

    client.send(Message::text("not json")).await.unwrap();
    send(&mut client, &sample(42)).await;

    assert_eq!(server.wait_for_sample().await.2, 42);
}

// ---- facts

impl TestServer {
    async fn wait_for_facts(&self, id: &str, count: usize) -> Vec<FactVersion> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let history = self.state.database.facts_history(id).await.unwrap();
            if history.len() >= count {
                return history;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("{id} never reached {count} facts");
    }
}

fn facts(version: &str) -> AgentMessage {
    AgentMessage::Facts {
        facts: json!({ "os": { "family": "linux", "version": version } }),
    }
}

#[tokio::test]
async fn facts_are_stored_with_their_history() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    send(&mut client, &facts("24.04")).await;
    send(&mut client, &facts("24.04")).await;
    send(&mut client, &facts("24.10")).await;

    let history = server.wait_for_facts(&agent.id(), 3).await;

    // os.family stayed the same, so only os.version has a second row.
    let versions: Vec<_> = history.iter().filter(|f| f.name == "os.version").collect();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].value, "24.04");
    assert_eq!(versions[1].value, "24.10");
    assert_eq!(history.iter().filter(|f| f.name == "os.family").count(), 1);
}

#[tokio::test]
async fn custom_fact_names_with_dots_are_shown_nested() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let dotted = AgentMessage::Facts {
        facts: json!({ "os": { "family": "linux" }, "custom": { "one.thing": "x" } }),
    };
    send(&mut client, &dotted).await;
    server.wait_for_facts(&id, 2).await;

    let response = server
        .http(
            "GET",
            &format!("/api/v1/agents/{id}/facts"),
            Some(&server.api_key),
        )
        .await;
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let view: serde_json::Value = serde_json::from_str(body).unwrap();

    assert_eq!(view["reported"]["custom"]["one"]["thing"], "x");
    assert_eq!(view["reported"]["os"]["family"], "linux");
}

#[tokio::test]
async fn list_items_are_stored_under_indexed_names() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let tagged = AgentMessage::Facts {
        facts: json!({ "custom": { "tags": ["web", "prod", "eu"] } }),
    };
    send(&mut client, &tagged).await;
    server.wait_for_facts(&id, 3).await;

    let response = server
        .http(
            "GET",
            &format!("/api/v1/agents/{id}/facts"),
            Some(&server.api_key),
        )
        .await;
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let view: serde_json::Value = serde_json::from_str(body).unwrap();

    assert_eq!(
        view["reported"]["custom"]["tags"],
        json!(["web", "prod", "eu"])
    );

    let rows = server.state.database.current_facts(&id).await.unwrap();
    let names: Vec<&str> = rows.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        ["custom.tags[0]", "custom.tags[1]", "custom.tags[2]"]
    );
}

#[tokio::test]
async fn values_come_back_with_the_type_they_went_in_with() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let typed = AgentMessage::Facts {
        facts: json!({
            "web": {
                "id": 1,
                "text_id": "1",
                "ratio": 1.5,
                "enabled": true,
                "big": 18_446_744_073_709_551_615_u64,
            },
        }),
    };
    send(&mut client, &typed).await;
    server.wait_for_facts(&id, 5).await;

    let response = server
        .http(
            "GET",
            &format!("/api/v1/agents/{id}/facts"),
            Some(&server.api_key),
        )
        .await;
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let view: serde_json::Value = serde_json::from_str(body).unwrap();
    let web = &view["reported"]["web"];

    assert_eq!(web["id"], json!(1));
    assert_eq!(web["text_id"], json!("1"));
    assert_eq!(web["ratio"], json!(1.5));
    assert_eq!(web["enabled"], json!(true));
    assert_eq!(web["big"], json!(18_446_744_073_709_551_615_u64));
}

#[tokio::test]
async fn invalid_facts_are_skipped_without_ending_the_connection() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let not_an_object = AgentMessage::Facts { facts: json!([1]) };
    send(&mut client, &not_an_object).await;
    let too_long = AgentMessage::Facts {
        facts: json!({ "custom": { "note": "x".repeat(256) } }),
    };
    send(&mut client, &too_long).await;
    let oversized = AgentMessage::Facts {
        facts: json!({ "custom": { "note": "x".repeat(70_000) } }),
    };
    send(&mut client, &oversized).await;
    send(&mut client, &facts("24.04")).await;

    let history = server.wait_for_facts(&agent.id(), 2).await;
    assert_eq!(history.len(), 2);
    assert!(history.iter().any(|f| f.value == "24.04"));
}

#[tokio::test]
async fn a_pending_agent_can_not_report_facts() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "web-1", None).await;

    let text = serde_json::to_string(&facts("24.04")).unwrap();
    let _ = client.send(Message::text(text)).await;
    sleep(Duration::from_millis(100)).await;

    let history = server.state.database.facts_history(&agent.id()).await;
    assert!(history.unwrap().is_empty());
}

#[tokio::test]
async fn the_admin_api_separates_trusted_and_reported_facts() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, "web-1").await;

    // An agent claiming to be approved or to have another ID changes nothing.
    let lying = AgentMessage::Facts {
        facts: json!({ "trusted": { "state": "revoked" }, "agent_id": "someone-else" }),
    };
    send(&mut client, &lying).await;
    server.wait_for_facts(&id, 2).await;

    let response = server
        .http(
            "GET",
            &format!("/api/v1/agents/{id}/facts"),
            Some(&server.api_key),
        )
        .await;
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let view: serde_json::Value = serde_json::from_str(body).unwrap();

    assert_eq!(view["trusted"]["agent_id"], json!(id));
    assert_eq!(view["trusted"]["state"], "approved");
    assert_eq!(view["trusted"]["decided_by"], "admin");
    assert_eq!(view["trusted"]["online"], true);
    assert_eq!(view["trusted"]["source_address"], "127.0.0.1");
    assert_eq!(view["reported"]["agent_id"], "someone-else");
    assert_eq!(view["reported"]["trusted"]["state"], "revoked");
}

#[tokio::test]
async fn the_facts_api_needs_the_token_and_a_known_agent() {
    let server = start().await;
    let agent = identity();
    server.connect_approved(&agent, "web-1").await;
    let id = agent.id();

    for path in [
        format!("/api/v1/agents/{id}/facts"),
        format!("/api/v1/agents/{id}/facts/history"),
    ] {
        let response = server.http("GET", &path, None).await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }
    for path in [
        "/api/v1/agents/nope/facts",
        "/api/v1/agents/nope/facts/history",
    ] {
        let response = server.http("GET", path, Some(&server.api_key)).await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }
}

#[tokio::test]
async fn the_history_api_returns_every_change_in_order() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, "web-1").await;
    send(&mut client, &facts("24.04")).await;
    send(&mut client, &facts("24.10")).await;
    server.wait_for_facts(&id, 3).await;

    let path = format!("/api/v1/agents/{id}/facts/history");
    let response = server.http("GET", &path, Some(&server.api_key)).await;
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let history: Vec<FactVersion> = serde_json::from_str(body).unwrap();

    assert_eq!(history.len(), 3);
    assert_eq!(history.last().unwrap().value, "24.10");
}

// ---- agent config

impl TestServer {
    /// Reads what a connected agent is sent until the config arrives.
    async fn next_config(client: &mut Client) -> (String, AgentConfig) {
        let reading = async {
            loop {
                if let ServerMessage::Config { version, config } = read_server_message(client).await
                {
                    return (version, config);
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .expect("no config arrived")
    }

    async fn create_rule(&self, name: &str, priority: i32, condition: &str, settings: Value) {
        let input = RuleInput {
            name: name.to_string(),
            priority,
            condition: Some(condition.to_string()),
            enabled: true,
            settings,
        };
        self.state.database.create_rule(&input).await.unwrap();
        self.state.config_changed();
    }

    async fn request(&self, method: &str, path: &str, body: &str) -> String {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.api_key,
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }
}

#[tokio::test]
async fn an_approved_agent_is_sent_the_default_config() {
    let server = start().await;
    let mut client = server.connect_approved(&identity(), "web-1").await;

    let (version, config) = TestServer::next_config(&mut client).await;

    assert_eq!(version, config.version().unwrap());
    assert_eq!(config.interval_secs, 15);
    assert_eq!(config.collectors.len(), 5);
}

#[tokio::test]
async fn a_rule_change_reaches_connected_agents() {
    let server = start().await;
    let mut client = server.connect_approved(&identity(), "web-1").await;
    TestServer::next_config(&mut client).await;

    server
        .create_rule("faster", 100, "true", json!({ "interval_secs": 5 }))
        .await;

    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.interval_secs, 5);
}

#[tokio::test]
async fn an_agent_gets_a_new_config_when_its_facts_start_matching_a_rule() {
    let server = start().await;
    server
        .create_rule(
            "linux",
            100,
            r#"facts.os.family == "linux""#,
            json!({ "interval_secs": 7 }),
        )
        .await;
    let mut client = server.connect_approved(&identity(), "web-1").await;

    let (_, first) = TestServer::next_config(&mut client).await;
    assert_eq!(first.interval_secs, 15);

    send(&mut client, &facts("24.04")).await;

    let (_, second) = TestServer::next_config(&mut client).await;
    assert_eq!(second.interval_secs, 7);
}

#[tokio::test]
async fn an_unchanged_config_is_not_sent_again() {
    let server = start().await;
    let mut client = server.connect_approved(&identity(), "web-1").await;
    TestServer::next_config(&mut client).await;

    // Matches nothing, so the config stays the same.
    server
        .create_rule("nothing", 100, "false", json!({ "interval_secs": 5 }))
        .await;

    let next = tokio::time::timeout(
        Duration::from_millis(150),
        TestServer::next_config(&mut client),
    );
    assert!(next.await.is_err());
}

#[tokio::test]
async fn an_agent_is_only_sent_collectors_it_supports() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    TestServer::next_config(&mut client).await;

    let older = AgentMessage::Facts {
        facts: json!({ "agent": { "collectors": ["cpu", "memory"] } }),
    };
    send(&mut client, &older).await;

    let (_, config) = TestServer::next_config(&mut client).await;
    let names: Vec<&str> = config.collectors.keys().map(String::as_str).collect();
    assert_eq!(names, ["cpu", "memory"]);
}

#[tokio::test]
async fn an_agents_config_result_is_recorded_and_shown() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let (version, _) = TestServer::next_config(&mut client).await;

    let result = AgentMessage::ConfigResult {
        version: version.clone(),
        error: Some("x".repeat(5000)),
    };
    send(&mut client, &result).await;

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = server.state.database.config_status(&id).await.unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "no status arrived");
        sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(status.version, version);
    assert_eq!(status.error.unwrap().len(), 1000);

    let path = format!("/api/v1/agents/{id}/config");
    let response = server.request("GET", &path, "").await;
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let view: Value = serde_json::from_str(body).unwrap();

    assert_eq!(view["desired"]["version"], json!(version));
    assert_eq!(view["desired"]["config"]["interval_secs"], 15);
    assert_eq!(view["desired"]["matched_rules"], json!(["Default"]));
    assert_eq!(view["reported"]["version"], json!(version));
}

#[tokio::test]
async fn rules_can_be_managed_through_the_api() {
    let server = start().await;

    let body = r#"{"name":"web","priority":100,"condition":"facts.custom.role == \"web\"","settings":{"interval_secs":5}}"#;
    let created = server.request("POST", "/api/v1/rules", body).await;
    assert!(created.starts_with("HTTP/1.1 201"), "{created}");
    let id: Value = serde_json::from_str(created.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let path = format!("/api/v1/rules/{}", id["id"]);

    let shown = server.request("GET", &path, "").await;
    assert!(shown.contains(r#""interval_secs":5"#), "{shown}");

    let changed = r#"{"name":"web","priority":100,"condition":null,"enabled":false,"settings":{}}"#;
    let updated = server.request("PUT", &path, changed).await;
    assert!(updated.starts_with("HTTP/1.1 204"), "{updated}");

    let listed = server.request("GET", "/api/v1/rules", "").await;
    assert!(listed.contains(r#""enabled":false"#), "{listed}");

    let deleted = server.request("DELETE", &path, "").await;
    assert!(deleted.starts_with("HTTP/1.1 204"), "{deleted}");
    let gone = server.request("GET", &path, "").await;
    assert!(gone.starts_with("HTTP/1.1 404"), "{gone}");
}

#[tokio::test]
async fn invalid_rules_are_refused_with_a_reason() {
    let server = start().await;

    let cases = [
        (
            r#"{"name":"","priority":1,"condition":null,"settings":{}}"#,
            "name",
        ),
        (
            r#"{"name":"a","priority":1,"condition":"1 +","settings":{}}"#,
            "condition",
        ),
        (
            r#"{"name":"a","priority":1,"condition":null,"settings":{"intervl":5}}"#,
            "settings",
        ),
        (
            r#"{"name":"a","priority":1,"condition":null,"settings":{"interval_secs":0}}"#,
            "at least 1",
        ),
        (
            r#"{"name":"a","priority":1,"condition":null,"settings":{"collectors":{"gpu":{}}}}"#,
            "unknown collector",
        ),
        (
            r#"{"name":"Default","priority":1,"condition":null,"settings":{}}"#,
            "already exists",
        ),
    ];

    for (body, reason) in cases {
        let response = server.request("POST", "/api/v1/rules", body).await;
        assert!(response.starts_with("HTTP/1.1 422"), "{body}: {response}");
        assert!(response.contains(reason), "{body}: {response}");
    }
    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_rules_api_needs_the_token() {
    let server = start().await;
    let response = server.http("GET", "/api/v1/rules", None).await;
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
}

// ---- web pages

/// A browser: keeps the CSRF cookie and reads tokens out of forms.
#[derive(Default)]
struct Browser {
    cookies: BTreeMap<String, String>,
    /// Stays signed out until it signs in, unlike other browsers in these tests.
    anonymous: bool,
}

struct Page {
    status: u16,
    headers: String,
    body: String,
}

impl Page {
    /// Whether the only scripts here are the ones embedded in the binary, so nothing
    /// an agent or a person typed has become a script.
    fn has_only_our_scripts(&self) -> bool {
        self.body
            .match_indices("<script")
            .all(|(at, _)| self.body[at..].starts_with(r#"<script src="/assets/js/"#))
    }

    fn token(&self) -> String {
        let marker = r#"name="authenticity_token" value=""#;
        let start = self.body.find(marker).expect("no form on this page") + marker.len();
        let end = self.body[start..].find('"').unwrap();
        self.body[start..start + end].to_string()
    }

    fn header(&self, name: &str) -> Option<&str> {
        let prefix = format!("{}: ", name.to_lowercase());
        self.headers.lines().find_map(|line| {
            line.to_lowercase()
                .starts_with(&prefix)
                .then(|| &line[prefix.len()..])
        })
    }
}

impl Browser {
    fn anonymous() -> Self {
        Self {
            anonymous: true,
            ..Self::default()
        }
    }

    fn cookie_header(&self, server: &TestServer) -> String {
        let mut cookies = self.cookies.clone();
        if !self.anonymous {
            cookies
                .entry("maxnines_session".to_string())
                .or_insert_with(|| server.session.clone());
        }
        let pairs = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"));
        pairs.collect::<Vec<_>>().join("; ")
    }

    async fn send(&mut self, server: &TestServer, request: String) -> Page {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let response = String::from_utf8_lossy(&bytes);

        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        for line in headers.lines() {
            if line.to_lowercase().starts_with("set-cookie: ") {
                let cookie = line["set-cookie: ".len()..].split(';').next().unwrap();
                let (name, value) = cookie.split_once('=').unwrap();
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
        Page {
            status: headers.split_whitespace().nth(1).unwrap().parse().unwrap(),
            headers: headers.to_string(),
            body: body.to_string(),
        }
    }

    async fn get(&mut self, server: &TestServer, path: &str) -> Page {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nCookie: {}\r\nConnection: close\r\n\r\n",
            self.cookie_header(server)
        );
        self.send(server, request).await
    }

    async fn post(&mut self, server: &TestServer, path: &str, fields: &[(&str, &str)]) -> Page {
        let body: Vec<String> = fields
            .iter()
            .map(|(name, value)| format!("{name}={}", encode(value)))
            .collect();
        let body = body.join("&");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nCookie: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.cookie_header(server),
            body.len()
        );
        self.send(server, request).await
    }

    async fn get_gzipped(&mut self, server: &TestServer, path: &str) -> Page {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nCookie: {}\r\nAccept-Encoding: gzip\r\n\
             Connection: close\r\n\r\n",
            self.cookie_header(server)
        );
        self.send(server, request).await
    }

    /// Opens a page and submits its form, as a person would.
    async fn submit(
        &mut self,
        server: &TestServer,
        form_page: &str,
        path: &str,
        fields: &[(&str, &str)],
    ) -> Page {
        let token = self.get(server, form_page).await.token();
        let mut all = vec![("authenticity_token", token.as_str())];
        all.extend_from_slice(fields);
        self.post(server, path, &all).await
    }
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

const RULE_FIELDS: [(&str, &str); 7] = [
    ("name", "Web servers"),
    ("priority", "100"),
    ("clause_fact_0", "custom.role"),
    ("clause_operator_0", "equals"),
    ("clause_value_0", "web"),
    ("enabled", "on"),
    ("interval_secs", "30"),
];

#[tokio::test]
async fn every_page_renders() {
    let server = start().await;
    let agent = identity();
    server.connect_approved(&agent, "web-1").await;
    let rule = server.state.database.list_rules().await.unwrap()[0].id;
    let mut browser = Browser::default();

    for path in [
        "/".to_string(),
        "/settings".to_string(),
        "/settings/audit-log".to_string(),
        "/agents".to_string(),
        format!("/agents/{}", agent.id()),
        "/rules".to_string(),
        "/rules/new".to_string(),
        format!("/rules/{rule}/edit"),
        "/map".to_string(),
        "/map/rules".to_string(),
        "/map/rules/new".to_string(),
        format!("/map/rules/new?agent={}", agent.id()),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
        assert!(page.body.contains("MaxNines"), "{path}");
    }
}

#[tokio::test]
async fn the_home_page_is_the_overview() {
    let server = start().await;
    let page = Browser::default().get(&server, "/").await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("All clear"), "{}", page.body);
}

#[tokio::test]
async fn unknown_pages_are_a_friendly_not_found() {
    let server = start().await;
    let mut browser = Browser::default();

    for path in ["/nope", "/agents/nope", "/rules/9999/edit"] {
        let page = browser.get(&server, path).await;
        assert_eq!(page.status, 404, "{path}");
        assert!(page.body.contains("Page not found"), "{path}");
    }
}

#[tokio::test]
async fn embedded_assets_are_served_and_nothing_else_is() {
    let server = start().await;
    let mut browser = Browser::default();

    let css = browser.get(&server, "/assets/css/application.css").await;
    assert_eq!(css.status, 200);
    assert_eq!(css.header("content-type"), Some("text/css"));

    for path in [
        "/assets/js/htmx.min.js",
        "/assets/js/idiomorph-ext.min.js",
        "/assets/js/application.js",
        "/assets/js/charts.js",
        "/assets/js/map.js",
    ] {
        let script = browser.get(&server, path).await;
        assert_eq!(script.status, 200, "{path}");
        assert_eq!(
            script.header("content-type"),
            Some("text/javascript"),
            "{path}"
        );
    }

    // Every logo the stylesheet asks for.
    for system in ["macos", "linux", "windows", "freebsd", "openbsd"] {
        let path = format!("/assets/os/{system}.svg");
        assert!(css.body.contains(&path), "{path}");
        let logo = browser.get(&server, &path).await;
        assert_eq!(logo.status, 200, "{path}");
        assert_eq!(logo.header("content-type"), Some("image/svg+xml"), "{path}");
    }

    for path in [
        "/assets/nope.css",
        "/assets/../Cargo.toml",
        "/assets/%2e%2e/Cargo.toml",
        "/assets/..%2f..%2fCargo.toml",
    ] {
        let page = browser.get(&server, path).await;
        assert_eq!(page.status, 404, "{path}");
        assert!(!page.body.contains("[package]"), "{path}");
    }
}

const THEMES_CSS: &str = include_str!("../assets/static/css/themes.css");

/// Each theme's name with its colours, as they're written in themes.css.
fn themes() -> Vec<(&'static str, HashMap<&'static str, &'static str>)> {
    THEMES_CSS
        .split(r#"[data-theme=""#)
        .skip(1)
        .map(|block| {
            let (name, rest) = block.split_once('"').unwrap();
            let colours = rest
                .split_once('{')
                .unwrap()
                .1
                .split_once('}')
                .unwrap()
                .0
                .lines()
                .filter_map(|line| line.trim().strip_prefix("--")?.strip_suffix(';'))
                .filter_map(|line| line.split_once(": "))
                .collect();
            (name, colours)
        })
        .collect()
}

/// How bright a colour like #0f1114 looks, as WCAG defines it.
fn luminance(colour: &str) -> f64 {
    let channel = |at: usize| {
        let value = f64::from(u8::from_str_radix(&colour[at..at + 2], 16).unwrap()) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5)
}

fn contrast(first: &str, second: &str) -> f64 {
    let (first, second) = (luminance(first), luminance(second));
    (first.max(second) + 0.05) / (first.min(second) + 0.05)
}

#[test]
fn every_theme_is_readable() {
    const TEXT: f64 = 4.5;
    const GRAPHIC: f64 = 3.0;
    let pairs = [
        ("text", "background", TEXT),
        ("text", "surface", TEXT),
        ("text", "sunken", TEXT),
        ("text", "raised", TEXT),
        ("muted", "background", TEXT),
        ("muted", "surface", TEXT),
        ("muted", "sunken", TEXT),
        ("muted", "raised", TEXT),
        ("muted", "neutral-surface", TEXT),
        ("accent-text", "accent", TEXT),
        ("accent-text", "accent-hover", TEXT),
        ("accent-ink", "background", TEXT),
        ("accent-ink", "surface", TEXT),
        ("accent-ink", "accent-surface", TEXT),
        ("good", "good-surface", TEXT),
        ("good", "surface", TEXT),
        ("bad", "bad-surface", TEXT),
        ("bad", "surface", TEXT),
        ("bad-text", "bad", TEXT),
        ("warn", "warn-surface", TEXT),
        ("warn", "surface", TEXT),
        ("code-comment", "sunken", TEXT),
        ("code-keyword", "sunken", TEXT),
        ("code-string", "sunken", TEXT),
        ("code-number", "sunken", TEXT),
        ("code-name", "sunken", TEXT),
        ("meter", "surface", GRAPHIC),
        ("meter-hot", "surface", GRAPHIC),
    ];

    let themes = themes();
    assert!(themes.len() >= 5);
    for (theme, colours) in &themes {
        for (foreground, background, least) in pairs {
            let ratio = contrast(colours[foreground], colours[background]);
            assert!(
                ratio >= least,
                "{theme}: {foreground} on {background} is only {ratio:.2}:1"
            );
        }
    }
}

#[test]
fn every_theme_sets_the_same_colours() {
    let themes = themes();
    let (_, first) = &themes[0];
    for (theme, colours) in &themes {
        let mut names: Vec<_> = colours.keys().collect();
        let mut expected: Vec<_> = first.keys().collect();
        names.sort();
        expected.sort();
        assert_eq!(names, expected, "{theme}");
    }
}

#[test]
fn everyone_can_choose_every_theme() {
    for (theme, _) in themes() {
        assert!(crate::models::is_theme(theme), "{theme}");
    }
}

#[tokio::test]
async fn pages_load_the_theme_before_they_draw() {
    let server = start().await;
    let page = Browser::default().get(&server, "/agents").await;

    let theme = page.body.find(r#"<script src="/assets/js/theme.js">"#);
    assert!(theme.unwrap() < page.body.find("<body").unwrap());
    let mut browser = Browser::default();
    for path in [
        "/assets/js/theme.js",
        "/assets/css/themes.css",
        "/assets/fonts/inter.woff2",
        "/assets/fonts/jetbrains-mono.woff2",
    ] {
        assert_eq!(browser.get(&server, path).await.status, 200, "{path}");
    }
}

#[tokio::test]
async fn the_site_can_be_installed_as_an_app() {
    let server = start().await;
    let mut browser = Browser::default();
    let page = browser.get(&server, "/").await;
    for tag in [
        r#"<link rel="manifest" href="/assets/manifest.webmanifest">"#,
        r#"<link rel="apple-touch-icon" href="/assets/icons/apple-touch-icon.png">"#,
        r#"<meta name="apple-mobile-web-app-capable" content="yes">"#,
    ] {
        assert!(page.body.contains(tag), "{tag}");
    }
    // theme.js fills this in, so it has to come first.
    let colour = page.body.find(r#"<meta name="theme-color""#).unwrap();
    assert!(colour < page.body.find("/assets/js/theme.js").unwrap());

    let response = browser.get(&server, "/assets/manifest.webmanifest").await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/manifest+json")
    );
    let manifest: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(manifest["display"], "standalone");
    assert_eq!(manifest["start_url"], "/");

    let mut icons: Vec<(String, u32)> = manifest["icons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|icon| {
            let size = icon["sizes"].as_str().unwrap().split('x').next().unwrap();
            let path = icon["src"].as_str().unwrap().to_string();
            (path, size.parse().unwrap())
        })
        .collect();
    assert!(icons.iter().any(|(_, size)| *size == 192));
    assert!(icons.iter().any(|(_, size)| *size == 512));
    icons.push(("/assets/icons/apple-touch-icon.png".to_string(), 180));
    for (path, size) in icons {
        let file = crate::views::StaticFiles::get(path.strip_prefix("/assets/").unwrap());
        let data = file.unwrap_or_else(|| panic!("{path} is missing")).data;
        let width = u32::from_be_bytes(data[16..20].try_into().unwrap());
        assert!(data.starts_with(b"\x89PNG"), "{path}");
        assert_eq!(width, size, "{path}");
    }
}

#[tokio::test]
async fn only_pages_that_update_themselves_say_they_are_live() {
    let server = start().await;
    let mut browser = Browser::default();

    for path in ["/", "/agents", "/alerts", "/server"] {
        let page = browser.get(&server, path).await;
        assert!(page.body.contains(r#"id="live-status""#), "{path}");
    }
    for path in ["/settings", "/rules/new", "/settings/api-keys"] {
        let page = browser.get(&server, path).await;
        assert!(!page.body.contains(r#"id="live-status""#), "{path}");
    }
}

#[tokio::test]
async fn pages_carry_security_headers() {
    let server = start().await;
    let page = Browser::default().get(&server, "/agents").await;

    let policy = page.header("content-security-policy").unwrap();
    assert!(policy.contains("default-src 'none'"), "{policy}");
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    assert_eq!(page.header("x-frame-options"), Some("DENY"));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
}

#[tokio::test]
async fn a_rule_created_in_the_browser_is_stored_and_reaches_agents() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    TestServer::next_config(&mut client).await;
    let role = AgentMessage::Facts {
        facts: json!({ "custom": { "role": "web" } }),
    };
    send(&mut client, &role).await;
    server.wait_for_facts(&agent.id(), 1).await;

    let mut browser = Browser::default();
    let page = browser
        .submit(&server, "/rules/new", "/rules", &RULE_FIELDS)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let rules = server.state.database.list_rules().await.unwrap();
    let rule = &rules.last().unwrap().rule;
    assert_eq!(rule.name, "Web servers");
    assert_eq!(rule.priority, 100);
    assert_eq!(rule.settings, json!({ "interval_secs": 30 }));

    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.interval_secs, 30);

    let list = browser.get(&server, "/rules").await;
    assert!(list.body.contains("Web servers"));
    assert!(list.body.contains("every 30s"));
}

/// An agent that hasn't reported facts counts for the same rules on the Rules
/// page as it gets a config for, including ones about facts it doesn't have.
#[tokio::test]
async fn the_rules_page_counts_agents_without_facts_the_same_as_their_config() {
    let server = start().await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    server
        .create_rule(
            "Needs setup",
            10,
            "!has(facts.os)",
            json!({ "interval_secs": 5 }),
        )
        .await;
    let config = server.state.config_for(&agent.id()).await.unwrap();
    assert!(
        config.matched_rules.contains(&"Needs setup".to_string()),
        "{:?}",
        config.matched_rules
    );

    let page = Browser::default().get(&server, "/rules").await;

    let row = &page.body[page.body.find("Needs setup").unwrap()..];
    let row = &row[..row.find("</tr>").unwrap()];
    assert!(row.contains(r#"<td class="number">1</td>"#), "{row}");
}

#[tokio::test]
async fn a_rule_can_be_edited_and_deleted_in_the_browser() {
    let server = start().await;
    let mut browser = Browser::default();
    browser
        .submit(&server, "/rules/new", "/rules", &RULE_FIELDS)
        .await;
    let id = server.state.database.list_rules().await.unwrap()[1].id;
    let edit = format!("/rules/{id}/edit");

    let form = browser.get(&server, &edit).await;
    assert!(
        form.body.contains(r#"value="Web servers""#),
        "{}",
        form.body
    );

    let page = browser
        .submit(
            &server,
            &edit,
            &format!("/rules/{id}"),
            &[
                ("name", "Renamed"),
                ("priority", "5"),
                ("collector_cpu", "off"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let rule = server
        .state
        .database
        .get_rule(id)
        .await
        .unwrap()
        .unwrap()
        .rule;
    assert_eq!(rule.name, "Renamed");
    assert!(!rule.enabled);
    assert_eq!(rule.condition, None);
    assert_eq!(
        rule.settings,
        json!({ "collectors": { "cpu": { "enabled": false } } })
    );

    let page = browser
        .submit(&server, &edit, &format!("/rules/{id}/delete"), &[])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(server.state.database.get_rule(id).await.unwrap(), None);
}

#[tokio::test]
async fn an_invalid_rule_shows_why_and_keeps_what_was_typed() {
    let server = start().await;
    let mut browser = Browser::default();

    let cases: [(&[(&str, &str)], &str); 5] = [
        (&[("name", ""), ("priority", "1")], "needs a name"),
        (&[("name", "a"), ("priority", "high")], "priority"),
        (
            &[
                ("name", "a"),
                ("priority", "1"),
                ("condition_mode", "expression"),
                ("condition", "1 +"),
            ],
            "invalid condition",
        ),
        (
            &[("name", "a"), ("priority", "1"), ("interval_secs", "0")],
            "at least 1",
        ),
        (&[("name", "Default"), ("priority", "1")], "already exists"),
    ];

    for (fields, reason) in cases {
        let page = browser
            .submit(&server, "/rules/new", "/rules", fields)
            .await;
        assert_eq!(page.status, 422, "{fields:?}: {}", page.body);
        assert!(page.body.contains(reason), "{fields:?}: {}", page.body);
    }

    let typed = [
        ("name", "Keep me"),
        ("priority", "1"),
        ("condition_mode", "expression"),
        ("condition", "1 +"),
    ];
    let page = browser
        .submit(&server, "/rules/new", "/rules", &typed)
        .await;
    assert!(page.body.contains(r#"value="Keep me""#), "{}", page.body);
    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
}

#[tokio::test]
async fn agents_can_be_approved_and_revoked_in_the_browser() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "web-1", None).await;

    let path = format!("/agents/{id}");
    let mut browser = Browser::default();

    let page = browser
        .submit(&server, &path, &format!("{path}/approve"), &[])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(server.state.registry.is_approved(&id).await);

    let page = browser
        .submit(&server, &path, &format!("{path}/revoke"), &[])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(!server.state.registry.is_approved(&id).await);
}

#[tokio::test]
async fn every_form_refuses_a_missing_or_wrong_csrf_token() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "web-1", None).await;
    let rule = server.state.database.list_rules().await.unwrap()[0].id;

    let paths = [
        "/rules".to_string(),
        format!("/rules/{rule}"),
        format!("/rules/{rule}/delete"),
        format!("/agents/{id}/approve"),
        format!("/agents/{id}/revoke"),
    ];
    let mut browser = Browser::default();
    browser.get(&server, "/rules/new").await;

    for path in &paths {
        let missing = browser
            .post(&server, path, &[("name", "x"), ("priority", "1")])
            .await;
        assert_eq!(missing.status, 403, "{path}");

        let wrong = [
            ("authenticity_token", "wrong"),
            ("name", "x"),
            ("priority", "1"),
        ];
        let page = browser.post(&server, path, &wrong).await;
        assert_eq!(page.status, 403, "{path}");
    }

    // Nothing happened.
    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
    assert!(!server.state.registry.is_approved(&id).await);
}

#[tokio::test]
async fn a_token_from_another_browser_is_refused() {
    let server = start().await;
    let mut victim = Browser::default();
    let mut attacker = Browser::default();

    let stolen = attacker.get(&server, "/rules/new").await.token();
    victim.get(&server, "/rules/new").await;

    let fields = [
        ("authenticity_token", stolen.as_str()),
        ("name", "x"),
        ("priority", "1"),
    ];
    let page = victim.post(&server, "/rules", &fields).await;

    assert_eq!(page.status, 403, "{}", page.body);
}

#[tokio::test]
async fn agent_reported_text_can_not_inject_html() {
    let server = start().await;
    let attack = "<script>alert(1)</script>";
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect_approved(&agent, attack).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "custom": { "note": attack } }),
    };
    send(&mut client, &facts).await;
    server.wait_for_facts(&id, 1).await;

    let rejected = AgentMessage::ConfigResult {
        version: "v1".to_string(),
        error: Some(attack.to_string()),
    };
    send(&mut client, &rejected).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while server
        .state
        .database
        .config_status(&id)
        .await
        .unwrap()
        .is_none()
    {
        assert!(Instant::now() < deadline, "no status arrived");
        sleep(Duration::from_millis(10)).await;
    }

    let mut browser = Browser::default();
    for path in ["/agents".to_string(), format!("/agents/{id}")] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(page.has_only_our_scripts(), "{path}: {}", page.body);
        assert!(page.body.contains("&lt;script"), "{path}: {}", page.body);
    }
}

#[tokio::test]
async fn text_in_a_rule_can_not_inject_html() {
    let server = start().await;
    let attack = r#""><script>alert(1)</script>"#;
    let mut browser = Browser::default();
    let fields = [
        ("name", attack),
        ("priority", "1"),
        ("condition_mode", "expression"),
        ("condition", "true"),
    ];
    browser
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;
    let id = server.state.database.list_rules().await.unwrap()[1].id;

    for path in ["/rules".to_string(), format!("/rules/{id}/edit")] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(page.has_only_our_scripts(), "{path}: {}", page.body);
    }
}

// ---- condition builder

async fn only_custom_rule(server: &TestServer) -> RuleInput {
    let rules = server.state.database.list_rules().await.unwrap();
    assert_eq!(rules.len(), 2, "{rules:?}");
    rules[1].rule.clone()
}

#[tokio::test]
async fn a_rule_built_with_form_fields_stores_a_real_expression() {
    let server = start().await;
    let mut browser = Browser::default();

    let fields = [
        ("name", "Linux web"),
        ("priority", "100"),
        ("match", "all"),
        ("clause_fact_0", "os.family"),
        ("clause_operator_0", "equals"),
        ("clause_value_0", "linux"),
        ("clause_fact_1", "host.name"),
        ("clause_operator_1", "starts_with"),
        ("clause_value_1", "web-"),
        ("enabled", "on"),
    ];
    let page = browser
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    assert_eq!(
        only_custom_rule(&server).await.condition.as_deref(),
        Some(r#"facts.os.family == "linux" && facts.host.name.startsWith("web-")"#)
    );

    let list = browser.get(&server, "/rules").await;
    assert!(
        list.body
            .contains("os.family is linux and host.name starts with web-"),
        "{}",
        list.body
    );
}

#[tokio::test]
async fn the_builder_buttons_work_without_saving_or_losing_what_was_typed() {
    let server = start().await;
    let mut browser = Browser::default();

    let fields = [
        ("name", "Half done"),
        ("priority", "100"),
        ("clause_fact_0", "os.family"),
        ("clause_operator_0", "equals"),
        ("clause_value_0", "linux"),
        ("form_action", "add_clause"),
    ];
    let page = browser
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains(r#"name="clause_fact_1""#),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"value="linux""#), "{}", page.body);
    assert!(page.body.contains(r#"value="Half done""#), "{}", page.body);
    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_builder_buttons_need_a_csrf_token_too() {
    let server = start().await;
    let mut browser = Browser::default();
    browser.get(&server, "/rules/new").await;

    let page = browser
        .post(&server, "/rules", &[("form_action", "add_clause")])
        .await;

    assert_eq!(page.status, 403);
}

#[tokio::test]
async fn enter_saves_the_rule_instead_of_pressing_a_builder_button() {
    let server = start().await;
    let page = Browser::default().get(&server, "/rules/new").await;

    let form = page.body.find("<form").unwrap();
    let first_button = form + page.body[form..].find("<button").unwrap();
    assert!(
        page.body[first_button..].starts_with(r#"<button type="submit" class="default-submit""#),
        "{}",
        &page.body[first_button..first_button + 80]
    );
}

#[tokio::test]
async fn a_rule_opens_in_the_builder_when_it_fits() {
    let server = start().await;
    server
        .create_rule("r", 100, r#"facts.os.family == "linux""#, json!({}))
        .await;
    let id = server.state.database.list_rules().await.unwrap()[1].id;

    let page = Browser::default()
        .get(&server, &format!("/rules/{id}/edit"))
        .await;

    assert!(
        page.body
            .contains(r#"name="clause_fact_0" value="os.family""#),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"value="linux""#), "{}", page.body);
    assert!(!page.body.contains("too complex"), "{}", page.body);
}

#[tokio::test]
async fn saving_a_complex_rule_from_its_form_leaves_the_expression_unchanged() {
    let server = start().await;
    let condition = r#"(facts.a == "x" || facts.b == "y") && facts.c != "z""#;
    server.create_rule("r", 100, condition, json!({})).await;
    let id = server.state.database.list_rules().await.unwrap()[1].id;
    let edit = format!("/rules/{id}/edit");
    let mut browser = Browser::default();

    let form = browser.get(&server, &edit).await;
    assert!(form.body.contains("too complex"), "{}", form.body);

    let fields = [
        ("name", "r"),
        ("priority", "100"),
        ("enabled", "on"),
        ("condition_mode", "expression"),
        ("condition", condition),
    ];
    let page = browser
        .submit(&server, &edit, &format!("/rules/{id}"), &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    assert_eq!(
        only_custom_rule(&server).await.condition.as_deref(),
        Some(condition)
    );
}

#[tokio::test]
async fn the_builder_suggests_facts_agents_have_reported() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let reported = AgentMessage::Facts {
        facts: json!({ "custom": { "tags": ["a", "b"] }, "os": { "family": "linux" } }),
    };
    send(&mut client, &reported).await;
    server.wait_for_facts(&agent.id(), 3).await;

    let page = Browser::default().get(&server, "/rules/new").await;

    assert!(
        page.body.contains(r#"<option value="os.family">"#),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(r#"<option value="custom.tags">"#),
        "{}",
        page.body
    );
    assert!(!page.body.contains("custom.tags[0]"), "{}", page.body);
}

#[tokio::test]
async fn a_number_fact_is_compared_as_a_number() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    TestServer::next_config(&mut client).await;
    let reported = AgentMessage::Facts {
        facts: json!({ "custom": { "rack": 12 } }),
    };
    send(&mut client, &reported).await;
    server.wait_for_facts(&agent.id(), 1).await;

    let fields = [
        ("name", "Rack 12"),
        ("priority", "100"),
        ("enabled", "on"),
        ("clause_fact_0", "custom.rack"),
        ("clause_operator_0", "equals"),
        ("clause_value_0", "12"),
        ("interval_secs", "3"),
    ];
    let page = Browser::default()
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.interval_secs, 3);
}

#[tokio::test]
async fn a_quote_in_a_value_stays_a_value_all_the_way_through() {
    let server = start().await;
    let mut browser = Browser::default();
    let attack = r#"x" || true || "y"#;

    let fields = [
        ("name", "Quoted"),
        ("priority", "100"),
        ("enabled", "on"),
        ("clause_fact_0", "custom.role"),
        ("clause_operator_0", "equals"),
        ("clause_value_0", attack),
        ("interval_secs", "3"),
    ];
    let page = browser
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    // It matches nothing, instead of everything.
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.interval_secs, 15);

    // Editing shows the same text, safely.
    let id = server.state.database.list_rules().await.unwrap()[1].id;
    let form = browser.get(&server, &format!("/rules/{id}/edit")).await;
    assert!(form.body.contains("x&quot; || true"), "{}", form.body);
}

#[tokio::test]
async fn bad_conditions_are_explained_on_the_form() {
    let server = start().await;
    let mut browser = Browser::default();

    let cases = [
        ("os family", "equals", "x", "a fact name"),
        ("os.family", "equals", "", "needs a value"),
        (
            "memory.total_bytes",
            "greater_than",
            "lots",
            "needs a number",
        ),
        ("os.family", "nonsense", "x", "unknown comparison"),
    ];
    for (fact, operator, value, reason) in cases {
        let fields = [
            ("name", "Bad"),
            ("priority", "100"),
            ("clause_fact_0", fact),
            ("clause_operator_0", operator),
            ("clause_value_0", value),
        ];
        let page = browser
            .submit(&server, "/rules/new", "/rules", &fields)
            .await;
        assert_eq!(page.status, 422, "{fact}: {}", page.body);
        assert!(page.body.contains(reason), "{fact}: {}", page.body);
    }
    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
}

// ---- admin API

#[tokio::test]
async fn the_admin_api_needs_the_token() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "web-1", None).await;
    let approve = format!("/api/v1/agents/{}/approve", agent.id());

    for token in [None, Some("wrong")] {
        let list = server.http("GET", "/api/v1/agents", token).await;
        assert!(list.starts_with("HTTP/1.1 401"), "{list}");

        let change = server.http("POST", &approve, token).await;
        assert!(change.starts_with("HTTP/1.1 401"), "{change}");
    }

    assert_eq!(
        server.state.registry.list().await[0].state,
        AgentState::Pending
    );
}

#[tokio::test]
async fn the_admin_api_lists_approves_and_revokes() {
    let server = start().await;
    let agent = identity();
    let id = agent.id();
    let mut client = server.connect().await;
    handshake(&mut client, &agent, "web-1", None).await;

    let list = server
        .http("GET", "/api/v1/agents", Some(&server.api_key))
        .await;
    assert!(list.starts_with("HTTP/1.1 200"), "{list}");
    assert!(list.contains(&id), "{list}");
    assert!(list.contains(r#""state":"pending""#), "{list}");
    assert!(list.contains(r#""online":false"#), "{list}");

    let path = format!("/api/v1/agents/{id}/approve");
    let response = server.http("POST", &path, Some(&server.api_key)).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(server.state.registry.is_approved(&id).await);

    let path = format!("/api/v1/agents/{id}/revoke");
    let response = server.http("POST", &path, Some(&server.api_key)).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!server.state.registry.is_approved(&id).await);
}

#[tokio::test]
async fn approving_an_unknown_agent_is_not_found() {
    let server = start().await;
    let response = server
        .http("POST", "/api/v1/agents/nope/approve", Some(&server.api_key))
        .await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}

// ---- command line

fn parse(text: &str) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("maxnines-server").chain(text.split_whitespace()))
}

#[test]
fn the_cli_definition_is_valid() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}

#[test]
fn parses_commands() {
    let cli = parse("").unwrap();
    assert_eq!(cli.command, None);
    assert_eq!(cli.config.to_str(), Some("server.hcl"));

    let cli = parse("agents approve abc --config my.hcl").unwrap();
    assert_eq!(
        cli.command,
        Some(Command::Agents(AgentsCommand::Approve {
            id: "abc".to_string()
        }))
    );
    assert_eq!(cli.config.to_str(), Some("my.hcl"));

    assert_eq!(parse("version").unwrap().command, Some(Command::Version));

    assert_eq!(
        parse("agents delete abc").unwrap().command,
        Some(Command::Agents(AgentsCommand::Delete {
            id: "abc".to_string()
        }))
    );
    assert!(parse("agents approve").is_err());
    assert!(parse("agents delete").is_err());

    // A key always has an owner.
    assert!(parse("api-keys create ci").is_err());
    assert_eq!(
        parse("api-keys create ci --user ci@example.com")
            .unwrap()
            .command,
        Some(Command::ApiKeys(crate::ApiKeysCommand::Create {
            name: "ci".to_string(),
            user: "ci@example.com".to_string(),
            role: None,
            expires_in: None,
        }))
    );
}

// ---- agent versions

async fn report_version(server: &TestServer, client: &mut Client, id: &str, version: &str) {
    TestServer::next_config(client).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "agent": { "version": version } }),
    };
    send(client, &facts).await;
    server.wait_for_facts(id, 1).await;
}

#[tokio::test]
async fn the_agents_page_shows_which_agents_have_an_update() {
    let server = start().await;
    let newest = crate::agent_versions::NEWEST_AGENT_VERSION;
    let (old, current, newer) = (identity(), identity(), identity());
    let mut clients = Vec::new();
    for (agent, host, version) in [
        (&old, "old-1", "0.0.1"),
        (&current, "current-1", newest),
        (&newer, "newer-1", "999.0.0"),
    ] {
        let mut client = server.connect_approved(agent, host).await;
        report_version(&server, &mut client, &agent.id(), version).await;
        clients.push(client);
    }
    let mut browser = Browser::default();

    let page = browser.get(&server, "/agents?view=table").await;
    assert!(page.body.contains("<th>Version</th>"), "{}", page.body);
    assert_eq!(page.body.matches(">Update available</span>").count(), 1);
    assert!(page.body.contains(&format!(
        "This agent runs 0.0.1, and the newest is {newest}."
    )));
    assert_eq!(page.body.matches(">Newer than server</span>").count(), 1);
    assert!(
        page.body
            .contains(&format!(r#"<td class="nowrap">{newest} "#))
    );

    let page = browser.get(&server, "/agents").await;
    assert_eq!(page.body.matches(">Update available</span>").count(), 1);

    let page = browser.get(&server, &format!("/agents/{}", old.id())).await;
    assert!(page.body.contains(">Update available</span>"));
    assert!(page.body.contains(&format!("The newest is {newest}.")));
    let page = browser
        .get(&server, &format!("/agents/{}", current.id()))
        .await;
    assert!(!page.body.contains(">Update available</span>"));
    assert!(!page.body.contains(">Newer than server</span>"));
}

// ---- rule preview

async fn report_role(server: &TestServer, client: &mut Client, id: &str, role: &str) {
    TestServer::next_config(client).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "custom": { "role": role } }),
    };
    send(client, &facts).await;
    server.wait_for_facts(id, 1).await;
}

fn with_preview<'a>(fields: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut all = fields.to_vec();
    all.push(("form_action", "preview"));
    all
}

#[tokio::test]
async fn a_preview_shows_the_effect_and_saves_nothing() {
    let server = start().await;
    let (web, db) = (identity(), identity());
    let mut web_client = server.connect_approved(&web, "web-1").await;
    let mut db_client = server.connect_approved(&db, "db-1").await;
    report_role(&server, &mut web_client, &web.id(), "web").await;
    report_role(&server, &mut db_client, &db.id(), "db").await;
    let revision = *server.state.config_changes.borrow();

    let mut browser = Browser::default();
    let page = browser
        .submit(&server, "/rules/new", "/rules", &with_preview(&RULE_FIELDS))
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains(r#"id="preview""#), "{}", page.body);
    assert!(page.body.contains("web-1"), "{}", page.body);
    assert!(page.body.contains("db-1"), "{}", page.body);
    assert!(page.body.contains("Sample interval: 15s → 30s"));
    assert_eq!(page.body.matches("Sample interval: 15s").count(), 1);
    // What was typed is still there to carry on with.
    assert!(page.body.contains(r#"value="Web servers""#));
    assert!(page.body.contains(r#"value="custom.role""#));

    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
    assert_eq!(*server.state.config_changes.borrow(), revision);

    // Saving then does what the preview said.
    let saved = browser
        .submit(&server, "/rules/new", "/rules", &RULE_FIELDS)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let (_, config) = TestServer::next_config(&mut web_client).await;
    assert_eq!(config.interval_secs, 30);
}

#[tokio::test]
async fn a_preview_of_an_edit_uses_the_form_and_leaves_the_saved_rule_alone() {
    let server = start().await;
    let web = identity();
    let mut client = server.connect_approved(&web, "web-1").await;
    report_role(&server, &mut client, &web.id(), "web").await;

    let mut browser = Browser::default();
    browser
        .submit(&server, "/rules/new", "/rules", &RULE_FIELDS)
        .await;
    TestServer::next_config(&mut client).await;
    let saved = only_custom_rule(&server).await;
    let id = server.state.database.list_rules().await.unwrap()[1].id;

    let mut fields = RULE_FIELDS.to_vec();
    fields.retain(|(name, _)| *name != "interval_secs");
    fields.push(("interval_secs", "60"));
    let page = browser
        .submit(
            &server,
            &format!("/rules/{id}/edit"),
            &format!("/rules/{id}"),
            &with_preview(&fields),
        )
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("Sample interval: 30s → 60s"),
        "{}",
        page.body
    );
    assert_eq!(only_custom_rule(&server).await, saved);
}

#[tokio::test]
async fn a_preview_only_covers_approved_agents_but_includes_offline_ones() {
    let server = start().await;
    let (offline, pending, revoked) = (identity(), identity(), identity());

    let mut client = server.connect_approved(&offline, "offline-1").await;
    report_role(&server, &mut client, &offline.id(), "web").await;
    drop(client);
    server.wait_for_online(&offline.id(), false).await;

    let mut client = server.connect().await;
    handshake(&mut client, &pending, "pending-1", None).await;
    let mut client = server.connect().await;
    handshake(&mut client, &revoked, "revoked-1", None).await;
    server
        .state
        .registry
        .decide(&revoked.id(), AgentState::Revoked)
        .await
        .unwrap();

    let mut browser = Browser::default();
    let page = browser
        .submit(&server, "/rules/new", "/rules", &with_preview(&RULE_FIELDS))
        .await;

    assert!(page.body.contains("offline-1"), "{}", page.body);
    assert!(page.body.contains("Offline"), "{}", page.body);
    assert!(!page.body.contains("pending-1"), "{}", page.body);
    assert!(!page.body.contains("revoked-1"), "{}", page.body);
}

#[tokio::test]
async fn a_rule_can_be_previewed_before_it_has_a_name() {
    let server = start().await;
    let fields = [("priority", "100"), ("form_action", "preview")];

    let mut browser = Browser::default();
    let page = browser
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("no approved agents"), "{}", page.body);
}

#[tokio::test]
async fn a_preview_of_a_broken_rule_explains_what_is_wrong() {
    let server = start().await;
    for (name, value) in [("condition", "facts.os =="), ("interval_secs", "soon")] {
        let fields = [
            ("name", "Broken"),
            ("priority", "100"),
            ("condition_mode", "expression"),
            (name, value),
            ("form_action", "preview"),
        ];

        let mut browser = Browser::default();
        let page = browser
            .submit(&server, "/rules/new", "/rules", &fields)
            .await;

        assert_eq!(page.status, 422, "{}", page.body);
        assert!(page.body.contains(r#"class="error""#), "{}", page.body);
        assert!(!page.body.contains(r#"id="preview""#), "{}", page.body);
    }
}

#[tokio::test]
async fn the_preview_button_brings_the_results_into_view() {
    let server = start().await;
    let id = server.state.database.list_rules().await.unwrap()[0].id;

    let mut browser = Browser::default();
    for (form, action) in [
        ("/rules/new".to_string(), "/rules#preview".to_string()),
        (format!("/rules/{id}/edit"), format!("/rules/{id}#preview")),
    ] {
        let page = browser.get(&server, &form).await;
        let wanted = format!(r#"formaction="{action}""#);
        assert!(page.body.contains(&wanted), "{form}: {}", page.body);
    }
}

#[tokio::test]
async fn a_preview_needs_a_csrf_token() {
    let server = start().await;
    let mut browser = Browser::default();
    browser.get(&server, "/rules/new").await;

    let page = browser
        .post(&server, "/rules", &with_preview(&RULE_FIELDS))
        .await;

    assert_eq!(page.status, 403, "{}", page.body);
}

#[tokio::test]
async fn text_from_an_agent_can_not_inject_html_into_a_preview() {
    let server = start().await;
    let attack = identity();
    let host = "<script>alert(1)</script>";
    let mut client = server.connect_approved(&attack, host).await;
    TestServer::next_config(&mut client).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "custom": { "role": "<script>alert(2)</script>" } }),
    };
    send(&mut client, &facts).await;
    server.wait_for_facts(&attack.id(), 1).await;

    let mut browser = Browser::default();
    let page = browser
        .submit(&server, "/rules/new", "/rules", &with_preview(&RULE_FIELDS))
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("&lt;script&gt;alert(1)"),
        "{}",
        page.body
    );
    assert!(page.has_only_our_scripts(), "{}", page.body);
}

// ---- build details

#[tokio::test]
async fn every_page_shows_which_build_of_the_server_is_running() {
    let server = start().await;
    let build = maxnines_protocol::build_info!();

    let mut browser = Browser::default();
    for path in ["/agents", "/rules", "/rules/new", "/nope"] {
        let page = browser.get(&server, path).await;
        assert!(page.body.contains(&build.version), "{path}: {}", page.body);
        assert!(page.body.contains(&build.commit), "{path}: {}", page.body);
        assert!(page.body.contains(&build.built_at), "{path}: {}", page.body);
    }
}

// ---- metrics

/// What a real agent sends, for the keys the server reads.
fn full_sample(timestamp_ms: u64, mount_point: &str) -> AgentMessage {
    AgentMessage::Sample(Sample {
        timestamp_ms,
        metrics: BTreeMap::from([
            (
                "cpu".to_string(),
                json!({
                    "usage_percent": 42.5,
                    "load_average": { "one": 1.5, "five": 1.0, "fifteen": 0.5 },
                }),
            ),
            (
                "memory".to_string(),
                json!({
                    "total_bytes": 1000,
                    "used_bytes": 250,
                    "swap_total_bytes": 100,
                    "swap_used_bytes": 10,
                }),
            ),
            (
                "disk".to_string(),
                json!([{ "mount_point": mount_point, "total_bytes": 100, "used_bytes": 60 }]),
            ),
            (
                "network".to_string(),
                json!({ "en0": { "received_bytes": 3000, "transmitted_bytes": 1500 } }),
            ),
        ]),
    })
}

/// What a Windows agent sends: everything but a load average.
fn windows_sample(timestamp_ms: u64, mount_point: &str) -> AgentMessage {
    let mut message = full_sample(timestamp_ms, mount_point);
    if let AgentMessage::Sample(sample) = &mut message {
        sample.metrics.get_mut("cpu").unwrap()["load_average"] = Value::Null;
    }
    message
}

/// Connects an agent and waits until what it sent can be read back.
async fn report_samples(server: &TestServer, mount_point: &str) -> (Identity, Client) {
    report(server, |time_ms| full_sample(time_ms, mount_point)).await
}

/// Connects an agent, sends four samples made by `sample` and waits until they
/// can be read back.
async fn report(server: &TestServer, sample: impl Fn(u64) -> AgentMessage) -> (Identity, Client) {
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let now = now_ms() as u64;
    for seconds_ago in [60, 45, 30, 15] {
        send(&mut client, &sample(now - seconds_ago * 1000)).await;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let current = server.state.metrics.current(now_ms()).await.unwrap();
        if current
            .get(&agent.id())
            .is_some_and(|v| v.time_ms >= (now - 15_000) as i64)
        {
            return (agent, client);
        }
        // Reading answers heartbeats, or the server would drop a client this quiet.
        tokio::time::timeout(Duration::from_millis(10), client.next())
            .await
            .ok();
    }
    panic!("the samples never arrived");
}

#[tokio::test]
async fn samples_from_an_agent_reach_the_fleet_page() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/data").await;

    let page = Browser::default().get(&server, "/metrics").await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body
            .contains(&format!("/agents/{}/metrics", agent.id()))
    );
    assert!(page.body.contains("web-1"));
    for value in ["42.5%", "25%", "60%", "/data"] {
        assert!(page.body.contains(value), "{value}: {}", page.body);
    }
}

#[tokio::test]
async fn samples_from_an_agent_reach_its_charts() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/data").await;

    let page = Browser::default()
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    for title in [
        "CPU usage",
        "Load average",
        "Memory usage",
        "Disk usage",
        "Network received",
        "Network sent",
    ] {
        assert!(page.body.contains(title), "{title}");
    }
    assert!(page.body.contains("<polyline"), "{}", page.body);
    assert!(
        !page.body.contains("No data in this range"),
        "{}",
        page.body
    );
    // Every metric got a chart with something in it.
    assert_eq!(
        page.body.matches("<table class=\"chart-summary\">").count(),
        6
    );
    assert!(
        page.body.contains("200 B/s"),
        "3000 bytes in 15s: {}",
        page.body
    );
}

#[tokio::test]
async fn a_machine_without_a_load_average_gets_no_load_average_chart() {
    let server = start_with_metrics().await;
    let (agent, _client) = report(&server, |time_ms| windows_sample(time_ms, "C:\\")).await;

    let page = Browser::default()
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("CPU usage"), "{}", page.body);
    assert!(!page.body.contains("Load average"), "{}", page.body);
    assert_eq!(
        page.body.matches("<table class=\"chart-summary\">").count(),
        5
    );
}

#[tokio::test]
async fn the_range_links_change_what_is_shown() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/data").await;
    let path = format!("/agents/{}/metrics", agent.id());
    let mut browser = Browser::default();

    let page = browser.get(&server, &format!("{path}?range=7d")).await;
    assert_eq!(page.body.matches("class=\"selected\"").count(), 1);
    assert!(
        page.body.contains("metrics?range=7d\" class=\"selected\""),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("/metrics/cpu.usage?range=7d"),
        "{}",
        page.body
    );

    let page = browser
        .get(&server, &format!("{path}?range=nonsense"))
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("metrics?range=1h\" class=\"selected\""),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn pages_of_data_update_in_place() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/").await;
    let mut browser = Browser::default();

    for (path, every) in [
        ("/".to_string(), "15s"),
        ("/agents".to_string(), "15s"),
        (format!("/agents/{}", agent.id()), "15s"),
        ("/alerts".to_string(), "15s"),
        ("/checks".to_string(), "15s"),
        ("/metrics".to_string(), "15s"),
        ("/server".to_string(), "15s"),
        (format!("/agents/{}/metrics", agent.id()), "60s"),
        (format!("/agents/{}/metrics/cpu.usage", agent.id()), "60s"),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(page.body.contains(r#"<main id="page""#), "{path}");
        assert!(page.body.contains(r##"hx-select="#page""##), "{path}");
        let (_, rest) = page.body.split_once("<main").unwrap();
        let (main, _) = rest.split_once('>').unwrap();
        assert!(
            main.contains(&format!(r#"hx-trigger="every {every}""#)),
            "{path}: {main}"
        );
        assert!(
            page.body
                .contains(r#"<noscript><meta http-equiv="refresh" content="60"></noscript>"#),
            "pages still update without scripts: {path}"
        );
        assert_eq!(page.body.matches("http-equiv").count(), 1, "{path}");
    }
}

#[tokio::test]
async fn metric_pages_and_assets_are_gzipped_for_browsers_that_accept_it() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/").await;
    let mut browser = Browser::default();

    for path in [
        format!("/agents/{}/metrics", agent.id()),
        "/metrics".to_string(),
        "/assets/js/htmx.min.js".to_string(),
        "/assets/css/application.css".to_string(),
    ] {
        let gzipped = browser.get_gzipped(&server, &path).await;
        assert_eq!(gzipped.status, 200, "{path}");
        assert_eq!(gzipped.header("content-encoding"), Some("gzip"), "{path}");

        let plain = browser.get(&server, &path).await;
        assert_eq!(plain.header("content-encoding"), None, "{path}");
        assert!(gzipped.body.len() < plain.body.len(), "{path}");
    }
}

#[tokio::test]
async fn pages_with_a_csrf_token_and_fonts_are_never_gzipped() {
    let server = start().await;
    let mut browser = Browser::default();

    for path in [
        "/agents",
        "/rules/new",
        "/checks/new",
        "/settings",
        "/assets/fonts/inter.woff2",
    ] {
        let page = browser.get_gzipped(&server, path).await;
        assert_eq!(page.status, 200, "{path}");
        assert_eq!(page.header("content-encoding"), None, "{path}");
    }
}

#[tokio::test]
async fn pages_being_filled_in_never_update_themselves() {
    let server = start().await;
    let mut browser = Browser::default();

    for path in ["/rules/new", "/checks/new", "/settings"] {
        let page = browser.get(&server, path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(!page.body.contains(r##"hx-select="#page""##), "{path}");
        assert!(!page.body.contains("http-equiv"), "{path}");
    }
}

/// What a page says about the build it came from.
fn build_of(page: &Page) -> String {
    let (_, rest) = page.body.split_once("/update-notice?build=").unwrap();
    rest.split('"').next().unwrap().to_string()
}

#[tokio::test]
async fn every_page_asks_whether_the_server_has_been_updated() {
    let server = start().await;
    let mut browser = Browser::default();

    for path in ["/", "/rules/new", "/settings", "/no-such-page"] {
        let page = browser.get(&server, path).await;
        let build = build_of(&page);
        assert!(!build.is_empty(), "{path}");
        assert!(page.body.contains(r#"hx-trigger="every 60s,"#), "{path}");
    }
}

#[tokio::test]
async fn a_page_from_this_build_is_told_nothing() {
    let server = start().await;
    let mut browser = Browser::default();
    let page = browser.get(&server, "/").await;

    let path = format!("/update-notice?build={}", build_of(&page));
    let answer = browser.get(&server, &path).await;

    assert_eq!(answer.status, 204);
    assert_eq!(answer.body, "");
}

#[tokio::test]
async fn a_page_from_another_build_is_told_to_refresh() {
    let server = start().await;
    let mut browser = Browser::default();

    let answer = browser.get(&server, "/update-notice?build=older").await;

    assert_eq!(answer.status, 200);
    assert!(answer.body.contains("MaxNines has been updated."));
    assert!(answer.body.contains(r#"<a href="">Refresh this page</a>"#));
}

#[tokio::test]
async fn a_form_still_works_after_the_page_has_updated_around_it() {
    let server = start().await;
    let mut browser = Browser::default();
    let opened = browser.get(&server, "/rules/new").await;
    let token = opened.token();

    for _ in 0..3 {
        browser.get(&server, "/agents").await;
    }

    let mut fields = vec![("authenticity_token", token.as_str())];
    fields.extend(RULE_FIELDS);
    let saved = browser.post(&server, "/rules", &fields).await;
    assert_eq!(saved.status, 303, "{}", saved.body);
}

/// How many samples of `metric` are stored in a range around now.
async fn stored_points(server: &TestServer, agent: &Identity) -> usize {
    let now = now_ms();
    let range = TimeRange::new(now - 3_600_000, now + 3_600_000).unwrap();
    let metric = crate::metrics::find("cpu.usage").unwrap();
    let id = agent.id();
    let result = server.state.metrics.series(&id, metric, range, 8);
    let result = result.await.unwrap();
    result
        .series
        .first()
        .map_or(0, |series| series.points.len())
}

async fn wait_for_points(server: &TestServer, agent: &Identity, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while stored_points(server, agent).await < count {
        assert!(Instant::now() < deadline, "the samples never arrived");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn only_recent_samples_count_as_current() {
    let server = start_with_metrics().await;
    let agent = identity();
    let client = server.connect_approved(&agent, "web-1").await;
    // Reading in the background answers heartbeats, as an agent would, however long
    // the checks below take. The server would drop a client that went quiet.
    let (mut sender, mut receiver) = client.split();
    tokio::spawn(async move { while receiver.next().await.is_some() {} });
    let now = now_ms() as u64;
    let mut report = async |time_ms| {
        let text = serde_json::to_string(&full_sample(time_ms, "/")).unwrap();
        sender.send(Message::text(text)).await.unwrap();
    };

    report(now - 600_000).await;
    wait_for_points(&server, &agent, 1).await;
    let current = server.state.metrics.current(now_ms()).await.unwrap();
    assert!(!current.contains_key(&agent.id()), "ten minutes old");

    report(now + 1_800_000).await;
    wait_for_points(&server, &agent, 2).await;
    let current = server.state.metrics.current(now_ms()).await.unwrap();
    assert!(!current.contains_key(&agent.id()), "from the future");

    report(now - 240_000).await;
    wait_for_points(&server, &agent, 3).await;
    let current = server.state.metrics.current(now_ms()).await.unwrap();
    assert!(current.contains_key(&agent.id()), "four minutes old");
}

#[tokio::test]
async fn a_charts_numbers_can_be_read_as_a_table() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/data").await;

    let path = format!("/agents/{}/metrics/memory.usage?range=6h", agent.id());
    let page = Browser::default().get(&server, &path).await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("<th class=\"number\">Swap</th>"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("<td class=\"number\">25%</td>"),
        "{}",
        page.body
    );
    assert!(page.body.contains("The last 6 hours"), "{}", page.body);
}

#[tokio::test]
async fn names_from_agents_are_escaped_on_metric_pages() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "<script>alert(1)</script>").await;
    let mut browser = Browser::default();

    for path in [
        "/metrics".to_string(),
        format!("/agents/{}/metrics", agent.id()),
        format!("/agents/{}/metrics/disk.usage", agent.id()),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(
            page.body.contains("&lt;script&gt;"),
            "{path}: {}",
            page.body
        );
        assert!(page.has_only_our_scripts(), "{path}: {}", page.body);
    }
}

#[tokio::test]
async fn host_names_from_agents_are_escaped_on_metric_pages() {
    let server = start().await;
    let agent = identity();
    let host = "<script>alert(2)</script>";
    let _client = server.connect_approved(&agent, host).await;
    let id = agent.id();
    let mut browser = Browser::default();

    for path in [
        "/metrics".to_string(),
        format!("/agents/{id}/metrics"),
        format!("/agents/{id}/metrics/cpu.usage"),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(
            page.body.contains("&lt;script&gt;"),
            "{path}: {}",
            page.body
        );
        assert!(page.has_only_our_scripts(), "{path}: {}", page.body);
    }
}

#[tokio::test]
async fn fixed_series_are_listed_in_their_natural_order() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/").await;

    let path = format!("/agents/{}/metrics", agent.id());
    let page = Browser::default().get(&server, &path).await;

    // Sorted by name, 15 minutes would come before 5 minutes.
    let position = |name: &str| {
        let row = format!("</span>{name}</td>");
        page.body.find(&row).unwrap_or_else(|| panic!("{name}"))
    };
    assert!(position("1 minute") < position("5 minutes"));
    assert!(position("5 minutes") < position("15 minutes"));
}

#[tokio::test]
async fn metric_pages_need_nothing_the_security_policy_blocks() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/").await;

    let path = format!("/agents/{}/metrics", agent.id());
    let page = Browser::default().get(&server, &path).await;

    assert_eq!(
        page.header("content-security-policy").unwrap(),
        "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; \
         font-src 'self'; img-src 'self'; manifest-src 'self'; form-action 'self'; \
         base-uri 'none'; frame-ancestors 'none'"
    );
    assert!(!page.body.contains(" style="), "inline styles are blocked");
    assert!(
        !page.body.contains("<script>"),
        "inline scripts are blocked"
    );
    assert!(
        page.body.contains(r#""allowEval":false"#),
        "eval is blocked, and agent data must never be able to reach it"
    );
}

#[tokio::test]
async fn an_agent_with_no_metrics_gets_empty_charts() {
    let server = start_with_metrics().await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "quiet").await;
    let mut browser = Browser::default();

    let page = browser
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    // Load average waits for data, since Windows machines never send one.
    assert_eq!(page.body.matches("No data in this range").count(), 5);

    let page = browser.get(&server, "/metrics").await;
    assert!(
        page.body.contains("None in the last 5 minutes"),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn only_approved_agents_are_on_the_fleet_page() {
    let server = start().await;
    let approved = identity();
    let _client = server.connect_approved(&approved, "approved-host").await;
    let mut pending = server.connect().await;
    handshake(&mut pending, &identity(), "pending-host", None).await;

    let page = Browser::default().get(&server, "/metrics").await;

    assert!(page.body.contains("approved-host"));
    assert!(!page.body.contains("pending-host"));
}

#[tokio::test]
async fn unknown_agents_and_metrics_are_not_found() {
    let server = start().await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let id = agent.id();
    let mut browser = Browser::default();

    for path in [
        "/agents/nope/metrics".to_string(),
        "/agents/nope/metrics/cpu.usage".to_string(),
        format!("/agents/{id}/metrics/nonsense"),
    ] {
        assert_eq!(browser.get(&server, &path).await.status, 404, "{path}");
    }
}

#[tokio::test]
async fn the_agent_and_metric_pages_link_to_each_other() {
    let server = start().await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let id = agent.id();
    let mut browser = Browser::default();

    let page = browser.get(&server, &format!("/agents/{id}")).await;
    assert!(
        page.body
            .contains(&format!("href=\"/agents/{id}/metrics\""))
    );

    let page = browser.get(&server, &format!("/agents/{id}/metrics")).await;
    assert!(page.body.contains(&format!("href=\"/agents/{id}\"")));
    assert!(page.body.contains("href=\"/metrics\""));
}

#[tokio::test]
async fn the_metrics_api_needs_an_api_key() {
    let server = start().await;
    for path in [
        "/api/v1/metrics",
        "/api/v1/metrics/current",
        "/api/v1/agents/x/metrics/cpu.usage",
    ] {
        let response = server.http("GET", path, None).await;
        assert!(response.starts_with("HTTP/1.1 401"), "{path}: {response}");
    }
}

fn json_body(response: &str) -> Value {
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap_or_else(|_| panic!("not JSON: {response}"))
}

#[tokio::test]
async fn the_metrics_api_lists_what_can_be_asked_for() {
    let server = start().await;

    let response = server
        .http("GET", "/api/v1/metrics", Some(&server.api_key))
        .await;

    let catalog = json_body(&response);
    assert_eq!(
        catalog.as_array().unwrap().len(),
        crate::metrics::METRICS.len()
    );
    assert_eq!(
        catalog[0],
        json!({ "name": "cpu.usage", "title": "CPU usage", "unit": "percent", "collector": "cpu" })
    );
}

#[tokio::test]
async fn the_metrics_api_returns_series_and_current_values() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/data").await;
    let id = agent.id();

    let path = format!("/api/v1/agents/{id}/metrics/cpu.usage");
    let body = json_body(&server.http("GET", &path, Some(&server.api_key)).await);

    assert_eq!(body["metric"], "cpu.usage");
    assert_eq!(body["unit"], "percent");
    assert_eq!(body["step_ms"], 15_000);
    assert_eq!(body["hidden"], 0);
    assert_eq!(body["series"][0]["name"], "CPU");
    let point = &body["series"][0]["points"][0];
    assert_eq!(point["avg"], 42.5);
    assert_eq!(point["min"], 42.5);
    assert_eq!(point["max"], 42.5);

    let body = json_body(
        &server
            .http("GET", "/api/v1/metrics/current", Some(&server.api_key))
            .await,
    );
    assert_eq!(body[&id]["cpu_percent"], 42.5);
    assert_eq!(body[&id]["disk_mount_point"], "/data");
}

#[tokio::test]
async fn the_metrics_api_can_be_given_a_time_range() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/").await;
    let now = now_ms();
    let base = format!("/api/v1/agents/{}/metrics/cpu.usage", agent.id());

    let path = format!(
        "{base}?from_ms={}&to_ms={}",
        now - 7_200_000,
        now - 3_600_000
    );
    let body = json_body(&server.http("GET", &path, Some(&server.api_key)).await);
    assert_eq!(body["series"], json!([]));

    let path = format!("{base}?from_ms={}&to_ms={now}", now - 86_400_000);
    let body = json_body(&server.http("GET", &path, Some(&server.api_key)).await);
    assert_eq!(body["step_ms"], 600_000);
    assert_eq!(body["series"][0]["name"], "CPU");
}

#[tokio::test]
async fn the_metrics_api_refuses_what_it_can_not_answer() {
    let server = start().await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let id = agent.id();
    let token = Some(server.api_key.as_str());

    let metric = format!("/api/v1/agents/{id}/metrics/cpu.usage");
    for query in [
        "from_ms=5&to_ms=1",
        "from_ms=-1&to_ms=5",
        "to_ms=not-a-number",
    ] {
        let response = server
            .http("GET", &format!("{metric}?{query}"), token)
            .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{query}: {response}");
    }
    let far_future = format!("{metric}?to_ms={}", i64::MAX);
    assert!(
        server
            .http("GET", &far_future, token)
            .await
            .starts_with("HTTP/1.1 400")
    );

    for path in [
        format!("/api/v1/agents/{id}/metrics/nonsense"),
        "/api/v1/agents/nope/metrics/cpu.usage".to_string(),
    ] {
        let response = server.http("GET", &path, token).await;
        assert!(response.starts_with("HTTP/1.1 404"), "{path}: {response}");
    }
}

/// Fails the way a real database might.
struct BrokenReader;

impl MetricsReader for BrokenReader {
    fn series(
        &self,
        _query: &crate::metrics::SeriesQuery,
    ) -> anyhow::Result<crate::metrics::SeriesResult> {
        panic!("deliberate test panic");
    }

    fn last_samples(
        &self,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::LastSample>> {
        anyhow::bail!("deliberate test failure with a secret in it");
    }

    fn latest_output(
        &self,
        _agent_id: &str,
        _collector: &str,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Option<Value>> {
        anyhow::bail!("deliberate test failure with a secret in it");
    }

    fn newest(
        &self,
        _metric: &crate::metrics::Metric,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::NewestReading>> {
        anyhow::bail!("deliberate test failure with a secret in it");
    }

    fn trends(
        &self,
        _metric: &crate::metrics::Metric,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::Trend>> {
        anyhow::bail!("deliberate test failure with a secret in it");
    }

    fn stats(&self, _hour_ago_ms: i64) -> anyhow::Result<crate::store::StoreStats> {
        anyhow::bail!("deliberate test failure with a secret in it");
    }

    fn series_count(&self) -> anyhow::Result<u64> {
        Ok(0)
    }

    fn calculate(
        &self,
        _query: &crate::calculations::CalculationQuery,
    ) -> anyhow::Result<crate::metrics::SeriesResult> {
        anyhow::bail!("deliberate test failure");
    }
}

#[tokio::test]
async fn a_failing_metrics_query_only_fails_that_request() {
    let saved = Saved::default();
    let store = Box::new(MemoryStore(saved.clone()));
    let server = start_on("", store, Arc::new(BrokenReader), saved, None).await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let mut browser = Browser::default();

    let path = format!("/agents/{}/metrics", agent.id());
    assert_eq!(browser.get(&server, &path).await.status, 500, "a panic");

    let page = browser.get(&server, "/metrics").await;
    assert_eq!(page.status, 500, "an error");
    assert!(!page.body.contains("secret"), "{}", page.body);

    assert_eq!(browser.get(&server, "/agents").await.status, 200);
}

#[tokio::test]
async fn containers_become_charts_of_each_one() {
    let server = start_with_metrics().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let id = agent.id();

    // As the agent sends them: a failing container has no figures to give.
    let now = now_ms() as u64;
    for (step, seconds_ago) in [45_u64, 30, 15].into_iter().enumerate() {
        let containers = json!([
            {
                "name": "web", "image": "nginx", "state": "running", "health": "healthy",
                "up": 1, "restarts": 0, "cpu_percent": 12.5, "memory_bytes": 200,
                "memory_limit_bytes": 1000, "received_bytes": 1500 * step,
                "sent_bytes": 3000 * step, "read_bytes": 0, "written_bytes": 0,
            },
            { "name": "worker", "image": "app", "state": "exited", "exit_code": 1,
              "up": 0, "restarts": 4 },
        ]);
        let message = AgentMessage::Sample(Sample {
            timestamp_ms: now - seconds_ago * 1000,
            metrics: BTreeMap::from([("containers".to_string(), containers)]),
        });
        send(&mut client, &message).await;
    }

    let series = |metric: &str| format!("/api/v1/agents/{id}/metrics/{metric}?range=1h");
    let read = async |metric: &str| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let body = json_body(
                &server
                    .http("GET", &series(metric), Some(&server.api_key))
                    .await,
            );
            if body["series"]
                .as_array()
                .is_some_and(|lines| !lines.is_empty())
            {
                return body;
            }
            assert!(Instant::now() < deadline, "{metric}: {body}");
            sleep(Duration::from_millis(20)).await;
        }
    };
    let up = read("container.up").await;
    let names: Vec<&str> = up["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["web", "worker"]);
    let memory = read("container.memory_limit").await;
    assert_eq!(memory["series"][0]["points"][0]["avg"], 20.0);
    let received = read("container.received").await;
    assert_eq!(received["series"][0]["name"], "web");

    let page = Browser::default()
        .get(&server, &format!("/agents/{id}/metrics"))
        .await;
    assert!(page.body.contains("Containers up"), "{}", page.body);
    assert!(page.body.contains("Container CPU usage"));
}

#[tokio::test]
async fn web_server_status_pages_become_charts() {
    let server = start_with_metrics().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let id = agent.id();
    let apache_page = "http://localhost/server-status";
    let pool = "http://localhost/status-www";

    // As the agent sends them: totals as the change since the sample before.
    let now = now_ms() as u64;
    for seconds_ago in [45, 30, 15] {
        let metrics = BTreeMap::from([
            (
                "apache".to_string(),
                json!([{
                    "name": apache_page, "up": 1, "busy_workers": 3.0,
                    "idle_workers": 12.0, "worker_slots": 15.0, "requests": 30, "bytes": 15360
                }]),
            ),
            (
                "php_fpm".to_string(),
                json!([
                    { "name": pool, "up": 1, "listen_queue": 2.0, "active_processes": 1.0 },
                    { "name": "http://localhost/status-api", "up": 0, "error": "timed out" }
                ]),
            ),
        ]);
        let message = AgentMessage::Sample(Sample {
            timestamp_ms: now - seconds_ago * 1000,
            metrics,
        });
        send(&mut client, &message).await;
    }

    let series = |metric: &str| format!("/api/v1/agents/{id}/metrics/{metric}?range=1h");
    let deadline = Instant::now() + Duration::from_secs(5);
    let requests = loop {
        let body = json_body(
            &server
                .http("GET", &series("apache.requests"), Some(&server.api_key))
                .await,
        );
        if body["series"]
            .as_array()
            .is_some_and(|lines| !lines.is_empty())
        {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "the samples never arrived: {body}"
        );
        tokio::time::timeout(Duration::from_millis(10), client.next())
            .await
            .ok();
    };
    assert_eq!(requests["unit"], "per_second");
    assert_eq!(requests["series"][0]["name"], apache_page);
    assert_eq!(requests["series"][0]["points"][0]["avg"], 2.0);

    let get = |metric: &str| {
        let path = series(metric);
        let server = &server;
        async move { json_body(&server.http("GET", &path, Some(&server.api_key)).await) }
    };
    let usage = get("apache.worker_usage").await;
    assert_eq!(usage["series"][0]["points"][0]["avg"], 20.0);
    let traffic = get("apache.traffic").await;
    assert_eq!(traffic["series"][0]["points"][0]["avg"], 1024.0);

    let queue = get("php_fpm.listen_queue").await;
    assert_eq!(queue["series"][0]["name"], pool);
    assert_eq!(queue["series"][0]["points"][0]["avg"], 2.0);
    let up = get("php_fpm.up").await;
    let names: Vec<&str> = up["series"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|line| line["name"].as_str())
        .collect();
    assert_eq!(names.len(), 2, "{up}");
}

// ---- finding hosts

async fn report_facts(server: &TestServer, host: &str, facts: Value) -> (Identity, Client) {
    let agent = identity();
    let mut client = server.connect_approved(&agent, host).await;
    let count = crate::facts::flatten(&facts).unwrap().len();
    send(&mut client, &AgentMessage::Facts { facts }).await;
    server.wait_for_facts(&agent.id(), count).await;
    (agent, client)
}

/// One Linux web server and one macOS database server.
async fn two_hosts(server: &TestServer) -> [(Identity, Client); 2] {
    let web = json!({ "os": { "family": "linux", "name": "Ubuntu Linux" }, "custom": { "tags": ["web", "eu"] } });
    let db = json!({ "os": { "family": "macos", "name": "Darwin" }, "custom": { "tags": ["db"] } });
    [
        report_facts(server, "web-1", web).await,
        report_facts(server, "db-1", db).await,
    ]
}

async fn hosts_on(server: &TestServer, path: &str) -> (bool, bool) {
    let page = Browser::default().get(server, path).await;
    assert_eq!(page.status, 200, "{path}: {}", page.body);
    (page.body.contains(">web-1"), page.body.contains(">db-1"))
}

#[tokio::test]
async fn each_host_shows_an_icon_for_its_system() {
    let server = start().await;
    let [(web, _web), (db, _db)] = two_hosts(&server).await;
    let odd = json!({ "os": { "family": "<b>plan9</b>" } });
    let _odd = report_facts(&server, "odd-1", odd).await;
    let mut browser = Browser::default();

    for path in ["/", "/agents", "/agents?view=table", "/metrics"] {
        let page = browser.get(&server, path).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
        assert!(
            page.body.contains("aria-label=\"Linux\""),
            "{path}: {}",
            page.body
        );
        assert!(
            page.body.contains("aria-label=\"macOS\""),
            "{path}: {}",
            page.body
        );
        assert_eq!(page.body.matches("class=\"os-icon ").count(), 2, "{path}");
        assert!(!page.body.contains("plan9</b>"), "{path}");
    }
    let page = browser.get(&server, &format!("/agents/{}", web.id())).await;
    assert!(page.body.contains("aria-label=\"Linux\""), "{}", page.body);
    let page = browser.get(&server, &format!("/agents/{}", db.id())).await;
    assert!(page.body.contains("aria-label=\"macOS\""), "{}", page.body);
}

#[tokio::test]
async fn hosts_can_be_filtered_by_their_facts() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    for (query, web, db) in [
        ("", true, true),
        ("?q=os%3Dlinux", true, false),
        ("?q=os.family%3Dmacos", false, true),
        ("?q=os%21%3Dlinux", false, true),
        ("?q=hostname%3Dweb%2A", true, false),
        ("?q=db", false, true),
        ("?q=custom.tags%3Deu", true, false),
        ("?q=os.name%3D%22Ubuntu+Linux%22", true, false),
        ("?q=os%3Dlinux+hostname%3Ddb%2A", false, false),
        ("?q=custom.rack%3Da1", false, false),
    ] {
        let found = hosts_on(&server, &format!("/agents{query}")).await;
        assert_eq!(found, (web, db), "{query}");
    }
}

#[tokio::test]
async fn the_fleet_metrics_page_filters_the_same_way() {
    let server = start_with_metrics().await;
    let _hosts = two_hosts(&server).await;

    assert_eq!(
        hosts_on(&server, "/metrics?q=os%3Dlinux").await,
        (true, false)
    );
    let page = Browser::default().get(&server, "/metrics?q=nothing").await;
    assert!(page.body.contains("No agents match this filter."));
}

#[tokio::test]
async fn a_filter_that_cannot_be_read_says_why_and_shows_nothing() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    let page = Browser::default().get(&server, "/agents?q=os%3D").await;

    assert!(page.body.contains("os needs a value"), "{}", page.body);
    assert!(!page.body.contains(">web-1"));
}

#[tokio::test]
async fn links_on_the_agents_page_keep_the_filter() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    let page = Browser::default()
        .get(&server, "/agents?filter=online&view=table&q=os%3Dlinux")
        .await;

    assert!(page.body.contains(r#"value="os=linux""#), "{}", page.body);
    assert!(page.body.contains(r#"name="filter" value="online""#));
    assert!(page.body.contains(r#"name="view" value="table""#));
    for tab in ["Online 1", "All 1", "Offline 0"] {
        assert!(page.body.contains(tab), "{tab}: {}", page.body);
    }
    // Encoded for the address, then again for the page.
    assert!(page.body.contains("q=os%3Dlinux"), "{}", page.body);
}

#[tokio::test]
async fn a_table_shows_each_hosts_config_state() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    let page = Browser::default().get(&server, "/agents?view=table").await;

    assert!(page.body.contains("Not reported"), "{}", page.body);
}

#[tokio::test]
async fn what_is_typed_into_a_filter_is_never_markup() {
    let server = start().await;
    let hostile = "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E";

    for path in ["/agents", "/metrics"] {
        let page = Browser::default()
            .get(&server, &format!("{path}?q={hostile}"))
            .await;
        assert!(page.has_only_our_scripts(), "{}", page.body);
    }
}

#[tokio::test]
async fn long_lists_are_split_into_pages() {
    let server = start().await;
    for number in 0..PAGE_SIZE + 1 {
        let agent = identity();
        server
            .connect_approved(&agent, &format!("host-{number:03}"))
            .await;
    }

    let first = Browser::default().get(&server, "/agents").await;
    let second = Browser::default().get(&server, "/agents?page=2").await;

    assert!(first.body.contains("host-000"));
    assert!(!first.body.contains(&format!("host-{PAGE_SIZE:03}")));
    assert!(
        first
            .body
            .contains(&format!("1 to {PAGE_SIZE} of {}", PAGE_SIZE + 1))
    );
    assert!(first.body.contains("page=2"), "{}", first.body);
    assert!(second.body.contains(&format!("host-{PAGE_SIZE:03}")));
    assert!(!second.body.contains("host-000"));
    assert!(second.body.contains(r#"rel="prev""#));
}

async fn options(server: &TestServer, term: &str) -> Vec<Value> {
    let path = format!("/agents/filter-options?term={term}");
    let page = Browser::default().get(server, &path).await;
    assert_eq!(page.status, 200, "{}", page.body);
    serde_json::from_str(&page.body).unwrap()
}

fn option_texts(options: &[Value]) -> Vec<&str> {
    options.iter().filter_map(|o| o["text"].as_str()).collect()
}

#[tokio::test]
async fn the_filter_suggests_fact_names() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    let found = options(&server, "os").await;
    assert_eq!(
        option_texts(&found),
        ["os=", "os.family=", "os.name=", "hostname="]
    );

    let found = options(&server, "cust").await;
    assert_eq!(option_texts(&found), ["custom.tags="]);
}

#[tokio::test]
async fn the_filter_suggests_values() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    assert_eq!(
        option_texts(&options(&server, "os%3D").await),
        ["os=linux", "os=macos"]
    );
    assert_eq!(
        option_texts(&options(&server, "os%3Dmac").await),
        ["os=macos"]
    );
    assert_eq!(
        option_texts(&options(&server, "custom.tags%3D").await),
        ["custom.tags=db", "custom.tags=eu", "custom.tags=web"]
    );
    assert_eq!(
        option_texts(&options(&server, "hostname%3Dweb").await),
        ["hostname=web-1"]
    );
    assert_eq!(
        option_texts(&options(&server, "os.name%3DUbu").await),
        [r#"os.name="Ubuntu Linux""#]
    );
}

// ---- the versioned API

fn status_of(response: &str) -> &str {
    response.split_whitespace().nth(1).unwrap_or_default()
}

fn body_of(response: &str) -> Value {
    let body = response.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn hosts_in(response: &str) -> Vec<String> {
    let mut hosts: Vec<String> = body_of(response)
        .as_array()
        .unwrap()
        .iter()
        .map(|agent| agent["host"].as_str().unwrap().to_string())
        .collect();
    hosts.sort();
    hosts
}

/// The addresses in the API's routes, read from its source so a new one can't be
/// missed.
/// Every method and path the API router sets up, read from its source.
fn api_routes() -> Vec<(String, String)> {
    let source = include_str!("controllers/api.rs");
    let start = source.find("pub fn routes").unwrap();
    let end = source.find(".route_layer(").unwrap();
    let mut routes = Vec::new();
    for piece in source[start..end].split(".route(").skip(1) {
        let path = piece.split('"').nth(1).unwrap().to_string();
        let handlers = piece.split('"').nth(2).unwrap();
        for method in ["get", "post", "put", "delete"] {
            if handlers.contains(&format!("{method}(")) {
                routes.push((method.to_uppercase(), path.clone()));
            }
        }
    }
    routes
}

#[test]
fn every_api_route_is_documented() {
    let docs = include_str!("../../../docs/api.md");
    let routes = api_routes();

    assert!(routes.len() > 40, "{routes:?}");
    for (method, path) in routes {
        let heading = format!("`{method} /api/v1{path}`");
        assert!(
            docs.contains(&heading),
            "{method} {path} isn't in docs/api.md"
        );
    }
}

#[tokio::test]
async fn the_api_lives_under_its_version() {
    let server = start().await;

    let versioned = server.request("GET", "/api/v1/agents", "").await;
    let old = server.request("GET", "/admin/agents", "").await;

    assert_eq!(status_of(&versioned), "200", "{versioned}");
    assert_eq!(status_of(&old), "404", "{old}");
}

#[tokio::test]
async fn an_unknown_api_address_answers_in_json() {
    let server = start().await;

    let response = server.request("GET", "/api/v1/nope", "").await;

    assert_eq!(status_of(&response), "404", "{response}");
    assert!(body_of(&response)["error"].is_string(), "{response}");
}

#[tokio::test]
async fn the_api_still_needs_the_token() {
    let server = start().await;

    let page = Browser::default().get(&server, "/api/v1/agents").await;

    assert_eq!(page.status, 401, "{}", page.body);
}

/// Names needn't be unique, so the ID is the one way to mean a single machine.
#[tokio::test]
async fn the_filter_can_pick_an_agent_by_id() {
    let server = start().await;
    let hosts = two_hosts(&server).await;
    let web = hosts[0].0.id();

    let by_id = server
        .request("GET", &format!("/api/v1/agents?q=id%3D{web}"), "")
        .await;
    assert_eq!(hosts_in(&by_id), ["web-1"]);

    let prefix = &web[..8];
    assert_eq!(
        hosts_on(&server, &format!("/agents?q=id%3D{prefix}*")).await,
        (true, false)
    );
    assert_eq!(
        hosts_on(&server, &format!("/agents?q=id!%3D{prefix}*")).await,
        (false, true)
    );
}

#[tokio::test]
async fn the_filter_suggests_agents_by_name_for_an_id() {
    let server = start().await;
    let hosts = two_hosts(&server).await;
    let web = hosts[0].0.id();

    let found = options(&server, "id%3Dweb").await;

    assert_eq!(option_texts(&found), [format!("id={web}")]);
    assert_eq!(found[0]["label"], format!("web-1 ({})", &web[..8]));
    let by_prefix = options(&server, &format!("id%3D{}", &web[..4])).await;
    assert_eq!(option_texts(&by_prefix), [format!("id={web}")]);
}

#[tokio::test]
async fn pages_show_the_start_of_each_agents_id_beside_its_name() {
    let server = start().await;
    let hosts = two_hosts(&server).await;
    let marker = format!(r#"<span class="agent-id">{}</span>"#, &hosts[0].0.id()[..8]);

    for path in ["/agents", "/agents?view=table", "/", "/metrics"] {
        let page = Browser::default().get(&server, path).await;
        assert!(page.body.contains(&marker), "{path}: {}", page.body);
    }
}

#[tokio::test]
async fn the_api_filters_hosts_the_same_way_as_the_pages() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    let all = server.request("GET", "/api/v1/agents", "").await;
    let linux = server
        .request("GET", "/api/v1/agents?q=os%3Dlinux", "")
        .await;

    assert_eq!(hosts_in(&all), ["db-1", "web-1"]);
    assert_eq!(hosts_in(&linux), ["web-1"]);
    assert_eq!(body_of(&linux)[0]["health"], "online");
}

#[tokio::test]
async fn the_api_shows_one_agent() {
    let server = start().await;
    let hosts = two_hosts(&server).await;
    let id = hosts[0].0.id();

    let found = server
        .request("GET", &format!("/api/v1/agents/{id}"), "")
        .await;
    let missing = server.request("GET", "/api/v1/agents/nope", "").await;

    assert_eq!(body_of(&found)["host"], "web-1", "{found}");
    assert_eq!(body_of(&found)["health"], "online");
    assert_eq!(status_of(&missing), "404", "{missing}");
}

#[tokio::test]
async fn the_api_explains_a_filter_it_cannot_read() {
    let server = start().await;

    let response = server.request("GET", "/api/v1/agents?q=os%3D", "").await;

    assert_eq!(status_of(&response), "400", "{response}");
    assert!(
        body_of(&response)["error"]
            .as_str()
            .unwrap()
            .contains("needs a value")
    );
}

#[tokio::test]
async fn the_api_suggests_what_the_filter_box_does() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;

    let response = server
        .request("GET", "/api/v1/agents/filter-options?term=os%3D", "")
        .await;

    assert_eq!(body_of(&response)[0]["text"], "os=linux", "{response}");
}

#[tokio::test]
async fn the_api_can_preview_a_rule_without_saving_it() {
    let server = start().await;
    let _hosts = two_hosts(&server).await;
    let rule = json!({
        "name": "Linux only",
        "priority": 100,
        "condition": "facts.os.family == \"linux\"",
        "settings": { "interval_secs": 60 },
    });

    let response = server
        .request("POST", "/api/v1/rules/preview", &rule.to_string())
        .await;

    assert_eq!(status_of(&response), "200", "{response}");
    let preview = body_of(&response);
    assert_eq!(preview["total"], 2);
    assert_eq!(preview["matching"], 1);

    let rules = server.request("GET", "/api/v1/rules", "").await;
    assert!(!rules.contains("Linux only"), "{rules}");
}

#[tokio::test]
async fn the_api_refuses_to_preview_a_bad_rule() {
    let server = start().await;
    let rule = json!({
        "name": "Broken",
        "priority": 100,
        "condition": "facts.os.family ==",
        "settings": {},
    });

    let response = server
        .request("POST", "/api/v1/rules/preview", &rule.to_string())
        .await;

    assert!(status_of(&response).starts_with('4'), "{response}");
}

#[tokio::test]
async fn testing_a_channel_that_does_not_exist_is_not_found() {
    let server = start().await;

    let response = server
        .request("POST", "/api/v1/notification-channels/999/test", "")
        .await;

    assert_eq!(status_of(&response), "404", "{response}");
}

// ---- API keys

async fn request_with_key(server: &TestServer, key: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

async fn new_key(server: &TestServer, details: Value) -> Value {
    let response = server
        .request("POST", "/api/v1/api-keys", &details.to_string())
        .await;
    assert_eq!(status_of(&response), "201", "{response}");
    body_of(&response)
}

#[tokio::test]
async fn a_key_from_the_api_opens_the_api_until_it_is_revoked() {
    let server = start().await;
    let created = new_key(&server, json!({ "name": "backup" })).await;
    // A key made with a key belongs to the same person.
    assert_eq!(created["owner"], "test@example.com", "{created}");
    let key = created["key"].as_str().unwrap();
    assert!(key.starts_with("mxn_"));

    let using = request_with_key(&server, key, "/api/v1/agents").await;
    assert_eq!(status_of(&using), "200", "{using}");

    let path = format!("/api/v1/api-keys/{}", created["id"]);
    let revoked = server.request("DELETE", &path, "").await;
    assert_eq!(status_of(&revoked), "204", "{revoked}");

    let refused = request_with_key(&server, key, "/api/v1/agents").await;
    assert_eq!(status_of(&refused), "401", "{refused}");
}

#[tokio::test]
async fn a_made_up_key_is_refused() {
    let server = start().await;

    let response = request_with_key(&server, "mxn_nope", "/api/v1/agents").await;

    assert_eq!(status_of(&response), "401", "{response}");
}

#[tokio::test]
async fn listing_keys_never_shows_them() {
    let server = start().await;
    let created = new_key(&server, json!({ "name": "backup" })).await;
    let key = created["key"].as_str().unwrap();

    let list = server.request("GET", "/api/v1/api-keys", "").await;

    assert!(!list.contains(key), "{list}");
    assert!(!list.contains("token_hash"), "{list}");
    assert_eq!(body_of(&list)[0]["name"], "backup");
}

#[tokio::test]
async fn a_key_can_be_short_lived() {
    let server = start().await;
    let created = new_key(
        &server,
        json!({ "name": "deploy", "expires_in_secs": 3600 }),
    )
    .await;

    let expires = created["expires_ms"].as_i64().unwrap();
    let hour = 3_600_000;
    assert!((expires - now_ms() - hour).abs() < 5000, "{created}");

    let forever = new_key(&server, json!({ "name": "ci" })).await;
    assert!(forever["expires_ms"].is_null(), "{forever}");
}

#[tokio::test]
async fn a_key_that_has_run_out_is_refused() {
    let server = start().await;
    let (_, key) = server
        .state
        .database
        .create_api_key(
            "old",
            server.user_id().await,
            crate::roles::Role::Admin,
            Some(now_ms() - 1000),
            now_ms() - 5000,
        )
        .await
        .unwrap();

    let response = request_with_key(&server, &key, "/api/v1/agents").await;

    assert_eq!(status_of(&response), "401", "{response}");
}

#[tokio::test]
async fn impossible_key_lifetimes_are_refused() {
    let server = start().await;
    for details in [
        json!({ "name": "a", "expires_in_secs": 0 }),
        json!({ "name": "a", "expires_in_secs": u64::MAX }),
        json!({ "name": "  " }),
    ] {
        let response = server
            .request("POST", "/api/v1/api-keys", &details.to_string())
            .await;
        assert_eq!(status_of(&response), "422", "{response}");
    }
}

#[tokio::test]
async fn the_keys_page_shows_a_new_key_once() {
    let server = start().await;
    let mut browser = Browser::default();
    let page = browser.get(&server, "/settings/api-keys").await;
    let token = page.token();

    let created = browser
        .post(
            &server,
            "/settings/api-keys",
            &[
                ("authenticity_token", token.as_str()),
                ("name", "Backup script"),
                ("role", "admin"),
                ("lifetime", "3600"),
            ],
        )
        .await;

    assert_eq!(created.status, 200, "{}", created.body);
    assert!(created.body.contains("Your new key"));
    assert!(created.headers.to_lowercase().contains("no-store"));
    let start = created.body.find("mxn_").unwrap();
    let key: String = created.body[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    assert_eq!(key.len(), 68, "{key}");

    let again = browser.get(&server, "/settings/api-keys").await;
    assert!(again.body.contains("Backup script"));
    assert!(!again.body.contains(&key), "{}", again.body);
    assert!(!again.body.contains("Your new key"));
}

#[tokio::test]
async fn the_keys_page_needs_a_valid_form() {
    let server = start().await;
    let mut browser = Browser::default();

    let page = browser
        .post(
            &server,
            "/settings/api-keys",
            &[("authenticity_token", "wrong"), ("name", "x")],
        )
        .await;

    assert_eq!(page.status, 403, "{}", page.body);
}

#[tokio::test]
async fn the_keys_page_offers_only_set_lifetimes() {
    let server = start().await;
    let mut browser = Browser::default();
    let token = browser.get(&server, "/settings/api-keys").await.token();

    let page = browser
        .post(
            &server,
            "/settings/api-keys",
            &[
                ("authenticity_token", token.as_str()),
                ("name", "a"),
                ("role", "admin"),
                ("lifetime", "5"),
            ],
        )
        .await;

    assert_eq!(page.status, 422, "{}", page.body);
    assert!(!page.body.contains("Your new key"), "{}", page.body);
    assert!(!page.body.contains(r#"class="secret""#), "{}", page.body);
}

#[tokio::test]
async fn a_key_can_be_revoked_from_its_page() {
    let server = start().await;
    let created = new_key(&server, json!({ "name": "old" })).await;
    let key = created["key"].as_str().unwrap();
    let mut browser = Browser::default();
    let token = browser.get(&server, "/settings/api-keys").await.token();

    browser
        .post(
            &server,
            &format!("/settings/api-keys/{}/revoke", created["id"]),
            &[("authenticity_token", token.as_str())],
        )
        .await;

    let response = request_with_key(&server, key, "/api/v1/agents").await;
    assert_eq!(status_of(&response), "401", "{response}");
    let page = browser.get(&server, "/settings/api-keys").await;
    assert!(page.body.contains("Revoked"), "{}", page.body);
}

// ---- the map

const LEEDS: [(&str, &str); 6] = [
    ("name", "Leeds office"),
    ("filter", "hostname=web*"),
    ("place", "Leeds, England, United Kingdom"),
    ("latitude", "53.79648"),
    ("longitude", "-1.54785"),
    ("priority", "0"),
];

#[tokio::test]
async fn the_map_puts_machines_where_their_rules_say() {
    let server = start().await;
    let web = identity();
    let db = identity();
    let _web = server.connect_approved(&web, "web-1").await;
    let _db = server.connect_approved(&db, "db-1").await;
    let mut browser = Browser::default();

    let saved = browser
        .submit(&server, "/map/rules/new", "/map/rules", &LEEDS)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);

    let page = browser.get(&server, "/map").await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Leeds office"), "{}", page.body);
    assert!(page.body.contains("1 site · 2 machines"), "{}", page.body);
    // The machine no rule covers is listed to be placed.
    let place_db = format!("/map/rules/new?agent={}", db.id());
    assert!(page.body.contains(&place_db), "{}", page.body);
    assert!(
        !page.body.contains(&format!("agent={}", web.id())),
        "{}",
        page.body
    );

    let map = body_of(&server.request("GET", "/api/v1/map", "").await);
    assert_eq!(map["sites"][0]["name"], "Leeds office");
    assert_eq!(map["sites"][0]["counts"]["online"], 1);
    assert_eq!(map["sites"][0]["machines"][0]["host"], "web-1");
    assert_eq!(map["sites"][0]["machines"][0]["short_id"], &web.id()[..8]);
    assert_eq!(map["unplaced"][0]["host"], "db-1");

    let rules = browser.get(&server, "/map/rules").await;
    assert!(rules.body.contains("hostname=web*"), "{}", rules.body);
}

#[tokio::test]
async fn a_machine_placed_from_its_page_outranks_a_broader_rule() {
    let server = start().await;
    let web = identity();
    server.connect_approved(&web, "web-1").await;
    let mut browser = Browser::default();
    browser
        .submit(&server, "/map/rules/new", "/map/rules", &LEEDS)
        .await;

    let agent_page = format!("/agents/{}", web.id());
    let page = browser.get(&server, &agent_page).await;
    assert!(page.body.contains("Leeds office"), "{}", page.body);
    assert!(page.body.contains("Place it by itself"), "{}", page.body);

    let form = format!("/map/rules/new?agent={}", web.id());
    let page = browser.get(&server, &form).await;
    let filter = format!("id={}", web.id());
    assert!(page.body.contains(&filter), "{}", page.body);
    assert!(
        page.body.contains(r#"name="priority" value="100""#),
        "{}",
        page.body
    );

    let saved = browser
        .submit(
            &server,
            &form,
            "/map/rules",
            &[
                ("name", "Rack 4"),
                ("filter", &filter),
                ("place", "Wetherby, England, United Kingdom"),
                ("latitude", "53.92"),
                ("longitude", "-1.38"),
                ("priority", "100"),
            ],
        )
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);

    let page = browser.get(&server, &agent_page).await;
    assert!(page.body.contains("Rack 4"), "{}", page.body);
    assert!(!page.body.contains("Place it by itself"), "{}", page.body);
    let map = body_of(&server.request("GET", "/api/v1/map", "").await);
    assert_eq!(map["sites"].as_array().unwrap().len(), 1);
    assert_eq!(map["sites"][0]["name"], "Rack 4");
}

#[tokio::test]
async fn a_location_with_a_mistake_is_shown_again_with_the_reason() {
    let server = start().await;
    let mut browser = Browser::default();

    let mut fields = LEEDS.to_vec();
    fields[3] = ("latitude", "91");
    let page = browser
        .submit(&server, "/map/rules/new", "/map/rules", &fields)
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(page.body.contains("between -90 and 90"), "{}", page.body);
    assert!(page.body.contains("Leeds office"), "{}", page.body);

    fields[3] = ("latitude", "");
    let page = browser
        .submit(&server, "/map/rules/new", "/map/rules", &fields)
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(page.body.contains("Choose a place"), "{}", page.body);
    assert!(
        server
            .state
            .database
            .list_location_rules()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_location_can_be_changed_and_deleted_from_its_page() {
    let server = start().await;
    let mut browser = Browser::default();
    browser
        .submit(&server, "/map/rules/new", "/map/rules", &LEEDS)
        .await;
    let id = server.state.database.list_location_rules().await.unwrap()[0].id;
    let edit = format!("/map/rules/{id}/edit");

    let mut fields = LEEDS.to_vec();
    fields[0] = ("name", "Leeds data centre");
    let saved = browser
        .submit(&server, &edit, &format!("/map/rules/{id}"), &fields)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let rule = server
        .state
        .database
        .get_location_rule(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rule.rule.name, "Leeds data centre");

    let deleted = browser
        .submit(&server, &edit, &format!("/map/rules/{id}/delete"), &[])
        .await;
    assert_eq!(deleted.status, 303, "{}", deleted.body);
    assert_eq!(browser.get(&server, &edit).await.status, 404);
}

#[tokio::test]
async fn location_rules_can_be_managed_through_the_api() {
    let server = start().await;

    let body = json!({
        "name": "Leeds office",
        "filter": "networking.addresses=10.1.*",
        "latitude": 53.8,
        "longitude": -1.55
    });
    let created = server
        .request("POST", "/api/v1/location-rules", &body.to_string())
        .await;
    assert_eq!(status_of(&created), "201", "{created}");
    let path = format!("/api/v1/location-rules/{}", body_of(&created)["id"]);

    let shown = body_of(&server.request("GET", &path, "").await);
    assert_eq!(shown["priority"], 0);
    assert_eq!(shown["place"], "");

    let changed = json!({ "name": "Leeds", "latitude": 53.8, "longitude": -1.55, "priority": 5 });
    let updated = server.request("PUT", &path, &changed.to_string()).await;
    assert_eq!(status_of(&updated), "204", "{updated}");
    let listed = body_of(&server.request("GET", "/api/v1/location-rules", "").await);
    assert_eq!(listed[0]["name"], "Leeds");
    assert_eq!(listed[0]["filter"], "");

    for (bad, reason) in [
        (
            json!({ "name": "", "latitude": 1, "longitude": 1 }),
            "needs a name",
        ),
        (
            json!({ "name": "a", "latitude": 1, "longitude": 200 }),
            "longitude",
        ),
        (
            json!({ "name": "a", "filter": "\"open", "latitude": 1, "longitude": 1 }),
            "quote",
        ),
    ] {
        let response = server
            .request("POST", "/api/v1/location-rules", &bad.to_string())
            .await;
        assert_eq!(status_of(&response), "422", "{bad}: {response}");
        assert!(response.contains(reason), "{bad}: {response}");
    }

    let deleted = server.request("DELETE", &path, "").await;
    assert_eq!(status_of(&deleted), "204", "{deleted}");
    assert_eq!(status_of(&server.request("GET", &path, "").await), "404");
    assert_eq!(status_of(&server.request("DELETE", &path, "").await), "404");
}

#[tokio::test]
async fn places_can_be_looked_up_from_the_form_and_the_api() {
    let server = start().await;
    let mut browser = Browser::default();

    let page = browser.get(&server, "/map/places?q=leeds").await;
    assert_eq!(page.status, 200, "{}", page.body);
    let found: Value = serde_json::from_str(&page.body).unwrap();
    assert_eq!(found[0]["label"], "Leeds, England, United Kingdom");

    let found = body_of(
        &server
            .request("GET", "/api/v1/places?q=portland,%20maine", "")
            .await,
    );
    assert_eq!(found[0]["label"], "Portland, Maine, United States");
    assert_eq!(found.as_array().unwrap().len(), 1);

    let near = body_of(
        &server
            .request("GET", "/api/v1/places/nearest?lat=53.93&lon=-1.39", "")
            .await,
    );
    assert_eq!(near["label"], "Wetherby, England, United Kingdom");

    let page = browser.get(&server, "/map/nearest?lat=x&lon=1").await;
    assert_eq!(page.status, 400);
    let anonymous = Browser::anonymous()
        .get(&server, "/map/places?q=leeds")
        .await;
    assert_ne!(anonymous.status, 200);
}

#[tokio::test]
async fn names_on_the_map_stay_text() {
    let server = start().await;
    let agent = identity();
    server.connect_approved(&agent, "<i>web</i>").await;
    let mut browser = Browser::default();
    let mut fields = LEEDS.to_vec();
    fields[0] = ("name", "<b>Leeds</b>");
    fields[1] = ("filter", "");
    browser
        .submit(&server, "/map/rules/new", "/map/rules", &fields)
        .await;

    let page = browser.get(&server, "/map").await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(!page.body.contains("<b>Leeds"), "{}", page.body);
    assert!(!page.body.contains("<i>web"), "{}", page.body);
    assert!(page.has_only_our_scripts(), "{}", page.body);
    let page = browser
        .get(&server, &format!("/agents/{}", agent.id()))
        .await;
    assert!(!page.body.contains("<b>Leeds"), "{}", page.body);
}
