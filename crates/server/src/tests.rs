//! Tests that run the real router over real sockets.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::{AgentMessage, RegistrationStatus, Sample, ServerMessage};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::config::Config;
use crate::connection::{AppState, Heartbeat};
use crate::database::{Database, FactVersion};
use crate::presence::Presence;
use crate::registration::{AgentState, Registry, Rules, hash_token};
use crate::store::spawn_writer;
use crate::store::testing::{MemoryStore, Saved};
use crate::{AgentsCommand, Cli, Command, app};

const AUDIENCE: &str = "wss://monitor.example.com/ws";
const ADMIN_TOKEN: &str = "test-admin-token";

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct TestServer {
    address: SocketAddr,
    state: AppState,
    saved: Saved,
}

fn identity() -> Identity {
    Identity::from_pkcs8(&Identity::generate().unwrap()).unwrap()
}

async fn start() -> TestServer {
    start_with("").await
}

async fn start_with(config: &str) -> TestServer {
    let text = format!("{config}\nmetrics \"duckdb\" {{\n  path = \"x\"\n}}\n");
    let config = Config::parse(&text).unwrap();

    let database = Database::in_memory().await;
    let saved = Saved::default();
    let (writer, _thread) = spawn_writer(Box::new(MemoryStore(saved.clone())));
    let state = AppState {
        presence: Arc::new(Presence::default()),
        registry: Arc::new(Registry::new(
            Vec::new(),
            Rules::compile(&config.registration).unwrap(),
            config.registration.max_pending,
            database.clone(),
        )),
        database,
        writer,
        heartbeat: Heartbeat {
            interval: Duration::from_millis(50),
            timeout: Duration::from_millis(200),
        },
        audience: AUDIENCE.into(),
        trusted_proxies: config.trusted_networks().unwrap().into(),
        admin_token_hash: hash_token(ADMIN_TOKEN).into(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });

    TestServer {
        address,
        state,
        saved,
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
