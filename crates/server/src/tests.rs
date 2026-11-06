//! Tests that run the real router over real sockets.

mod alerting;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
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
use crate::registration::{AgentState, Registry, Rules, hash_token};
use crate::server_stats::ServerStatus;
use crate::store::testing::{MemoryStore, Saved};
use crate::store::{self, MetricsReader, Store, spawn_writer};
use crate::views::Views;
use crate::{AgentsCommand, Cli, Command};

const AUDIENCE: &str = "wss://monitor.example.com/ws";
const ADMIN_TOKEN: &str = "test-admin-token";

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct TestServer {
    address: SocketAddr,
    state: AppState,
    saved: Saved,
    /// Holds the metrics database, for tests that use a real one.
    _folder: Option<tempfile::TempDir>,
}

fn identity() -> Identity {
    Identity::from_pkcs8(&Identity::generate().unwrap()).unwrap()
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
    let text = format!("{config}\nmetrics \"duckdb\" {{\n  path = \"x\"\n}}\n");
    let config = Config::parse(&text).unwrap();

    let database = Database::in_memory().await;
    let status = Arc::new(ServerStatus::new(None).unwrap());
    let (writer, _thread) = spawn_writer(store, status.writes.clone());
    let state = AppState {
        presence: Arc::new(Presence::default()),
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
        heartbeat: Heartbeat {
            interval: Duration::from_millis(50),
            timeout: Duration::from_millis(200),
        },
        audience: AUDIENCE.into(),
        trusted_proxies: config.trusted_networks().unwrap().into(),
        admin_token_hash: hash_token(ADMIN_TOKEN).into(),
        views: Arc::new(Views::load().unwrap()),
        csrf: CsrfConfig::default(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });

    TestServer {
        address,
        state,
        saved,
        _folder: folder,
    }
}

impl TestServer {
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

    async fn wait_for_online(&self, id: &str, online: bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
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
    tokio::time::timeout(Duration::from_secs(5), reading)
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

#[tokio::test]
async fn a_connection_that_never_answers_the_challenge_is_closed() {
    let server = start().await;
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
    let server = start().await;
    let agent = identity();
    // Held open but never read, like a hung agent or a dead network.
    let _client = server.connect_approved(&agent, "web-1").await;

    server.wait_for_online(&agent.id(), false).await;
}

#[tokio::test]
async fn an_agent_answering_pings_stays_online() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    // Three times the timeout. Reading is what answers the pings.
    let deadline = Instant::now() + Duration::from_millis(600);
    while tokio::time::timeout_at(deadline, client.next())
        .await
        .is_ok()
    {}

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
        let deadline = Instant::now() + Duration::from_secs(5);
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
            &format!("/admin/agents/{id}/facts"),
            Some(ADMIN_TOKEN),
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
            &format!("/admin/agents/{id}/facts"),
            Some(ADMIN_TOKEN),
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
            &format!("/admin/agents/{id}/facts"),
            Some(ADMIN_TOKEN),
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
            &format!("/admin/agents/{id}/facts"),
            Some(ADMIN_TOKEN),
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
        format!("/admin/agents/{id}/facts"),
        format!("/admin/agents/{id}/facts/history"),
    ] {
        let response = server.http("GET", &path, None).await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }
    for path in [
        "/admin/agents/nope/facts",
        "/admin/agents/nope/facts/history",
    ] {
        let response = server.http("GET", path, Some(ADMIN_TOKEN)).await;
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

    let path = format!("/admin/agents/{id}/facts/history");
    let response = server.http("GET", &path, Some(ADMIN_TOKEN)).await;
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
            "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {ADMIN_TOKEN}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

    let path = format!("/admin/agents/{id}/config");
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
    let created = server.request("POST", "/admin/rules", body).await;
    assert!(created.starts_with("HTTP/1.1 201"), "{created}");
    let id: Value = serde_json::from_str(created.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let path = format!("/admin/rules/{}", id["id"]);

    let shown = server.request("GET", &path, "").await;
    assert!(shown.contains(r#""interval_secs":5"#), "{shown}");

    let changed = r#"{"name":"web","priority":100,"condition":null,"enabled":false,"settings":{}}"#;
    let updated = server.request("PUT", &path, changed).await;
    assert!(updated.starts_with("HTTP/1.1 204"), "{updated}");

    let listed = server.request("GET", "/admin/rules", "").await;
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
        let response = server.request("POST", "/admin/rules", body).await;
        assert!(response.starts_with("HTTP/1.1 422"), "{body}: {response}");
        assert!(response.contains(reason), "{body}: {response}");
    }
    assert_eq!(server.state.database.list_rules().await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_rules_api_needs_the_token() {
    let server = start().await;
    let response = server.http("GET", "/admin/rules", None).await;
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
}

// ---- web pages

/// A browser: keeps the CSRF cookie and reads tokens out of forms.
#[derive(Default)]
struct Browser {
    cookie: String,
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
    async fn send(&mut self, server: &TestServer, request: String) -> Page {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let response = String::from_utf8_lossy(&bytes);

        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        for line in headers.lines() {
            if line.to_lowercase().starts_with("set-cookie: ") {
                let cookie = &line["set-cookie: ".len()..];
                self.cookie = cookie.split(';').next().unwrap().to_string();
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
            self.cookie
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
            self.cookie,
            body.len()
        );
        self.send(server, request).await
    }

    async fn get_gzipped(&mut self, server: &TestServer, path: &str) -> Page {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nCookie: {}\r\nAccept-Encoding: gzip\r\n\
             Connection: close\r\n\r\n",
            self.cookie
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
        "/agents".to_string(),
        format!("/agents/{}", agent.id()),
        "/rules".to_string(),
        "/rules/new".to_string(),
        format!("/rules/{rule}/edit"),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
        assert!(page.body.contains("MaxNines"), "{path}");
    }
}

#[test]
fn the_admin_token_has_a_command() {
    let cli = Cli::parse_from(["maxnines-server", "admin-token"]);
    assert_eq!(cli.command, Some(Command::AdminToken));
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
    ] {
        let script = browser.get(&server, path).await;
        assert_eq!(script.status, 200, "{path}");
        assert_eq!(
            script.header("content-type"),
            Some("text/javascript"),
            "{path}"
        );
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

    let first_button = page.body.find("<button").unwrap();
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
    let approve = format!("/admin/agents/{}/approve", agent.id());

    for token in [None, Some("wrong")] {
        let list = server.http("GET", "/admin/agents", token).await;
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

    let list = server.http("GET", "/admin/agents", Some(ADMIN_TOKEN)).await;
    assert!(list.starts_with("HTTP/1.1 200"), "{list}");
    assert!(list.contains(&id), "{list}");
    assert!(list.contains(r#""state":"pending""#), "{list}");
    assert!(list.contains(r#""online":false"#), "{list}");

    let path = format!("/admin/agents/{id}/approve");
    let response = server.http("POST", &path, Some(ADMIN_TOKEN)).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(server.state.registry.is_approved(&id).await);

    let path = format!("/admin/agents/{id}/revoke");
    let response = server.http("POST", &path, Some(ADMIN_TOKEN)).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!server.state.registry.is_approved(&id).await);
}

#[tokio::test]
async fn approving_an_unknown_agent_is_not_found() {
    let server = start().await;
    let response = server
        .http("POST", "/admin/agents/nope/approve", Some(ADMIN_TOKEN))
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

    assert!(parse("agents approve").is_err());
    assert!(parse("agents delete abc").is_err());
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

/// Connects an agent and waits until what it sent can be read back.
async fn report_samples(server: &TestServer, mount_point: &str) -> (Identity, Client) {
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;

    let now = now_ms() as u64;
    for seconds_ago in [60, 45, 30, 15] {
        send(
            &mut client,
            &full_sample(now - seconds_ago * 1000, mount_point),
        )
        .await;
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
        sleep(Duration::from_millis(10)).await;
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
        ("/settings/server".to_string(), "15s"),
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
        "/assets/fonts/figtree.woff2",
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
        assert!(page.body.contains(r#"hx-trigger="every 60s""#), "{path}");
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
    let mut client = server.connect_approved(&agent, "web-1").await;
    let now = now_ms() as u64;

    send(&mut client, &full_sample(now - 600_000, "/")).await;
    wait_for_points(&server, &agent, 1).await;
    let current = server.state.metrics.current(now_ms()).await.unwrap();
    assert!(!current.contains_key(&agent.id()), "ten minutes old");

    send(&mut client, &full_sample(now + 1_800_000, "/")).await;
    wait_for_points(&server, &agent, 2).await;
    let current = server.state.metrics.current(now_ms()).await.unwrap();
    assert!(!current.contains_key(&agent.id()), "from the future");

    send(&mut client, &full_sample(now - 240_000, "/")).await;
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
         font-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; \
         frame-ancestors 'none'"
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
    assert_eq!(page.body.matches("No data in this range").count(), 6);

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
async fn the_metrics_api_needs_the_admin_token() {
    let server = start().await;
    for path in [
        "/admin/metrics",
        "/admin/metrics/current",
        "/admin/agents/x/metrics/cpu.usage",
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
        .http("GET", "/admin/metrics", Some(ADMIN_TOKEN))
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

    let path = format!("/admin/agents/{id}/metrics/cpu.usage");
    let body = json_body(&server.http("GET", &path, Some(ADMIN_TOKEN)).await);

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
            .http("GET", "/admin/metrics/current", Some(ADMIN_TOKEN))
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
    let base = format!("/admin/agents/{}/metrics/cpu.usage", agent.id());

    let path = format!(
        "{base}?from_ms={}&to_ms={}",
        now - 7_200_000,
        now - 3_600_000
    );
    let body = json_body(&server.http("GET", &path, Some(ADMIN_TOKEN)).await);
    assert_eq!(body["series"], json!([]));

    let path = format!("{base}?from_ms={}&to_ms={now}", now - 86_400_000);
    let body = json_body(&server.http("GET", &path, Some(ADMIN_TOKEN)).await);
    assert_eq!(body["step_ms"], 600_000);
    assert_eq!(body["series"][0]["name"], "CPU");
}

#[tokio::test]
async fn the_metrics_api_refuses_what_it_can_not_answer() {
    let server = start().await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let id = agent.id();
    let token = Some(ADMIN_TOKEN);

    let metric = format!("/admin/agents/{id}/metrics/cpu.usage");
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
        format!("/admin/agents/{id}/metrics/nonsense"),
        "/admin/agents/nope/metrics/cpu.usage".to_string(),
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

    fn latest(
        &self,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::LatestSample>> {
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

    fn stats(&self, _hour_ago_ms: i64) -> anyhow::Result<crate::store::StoreStats> {
        anyhow::bail!("deliberate test failure with a secret in it");
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
