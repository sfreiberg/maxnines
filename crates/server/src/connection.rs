use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ipnet::IpNet;
use maxnines_protocol::{AgentMessage, RegistrationStatus, ServerMessage, auth};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval, timeout};
use tracing::{info, warn};

use crate::database::Database;
use crate::facts::flatten;
use crate::presence::Presence;
use crate::registration::{Admission, Registry};
use crate::store::WriterCommand;

/// The longest hostname DNS allows, and what the database column holds.
const MAX_HOST_LEN: usize = 255;
/// Far more than real facts need, so one agent can't fill the database.
const MAX_FACTS_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Clone)]
pub struct AppState {
    pub presence: Arc<Presence>,
    pub registry: Arc<Registry>,
    pub database: Database,
    pub writer: mpsc::Sender<WriterCommand>,
    pub heartbeat: Heartbeat,
    /// The URL agents must have signed.
    pub audience: Arc<str>,
    pub trusted_proxies: Arc<[IpNet]>,
    pub admin_token_hash: Arc<[u8]>,
}

pub async fn upgrade(
    socket: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let forwarded: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let source = client_ip(peer.ip(), &forwarded.join(","), &state.trusted_proxies);
    socket.on_upgrade(move |socket| handle(socket, source, state))
}

/// Finds the real client address. `X-Forwarded-For` can be forged by anyone, so
/// it only counts from a trusted proxy, and only as far back as trusted proxies
/// go: each proxy appends the address it saw, so the entries are read from the
/// right and the first untrusted one is the client.
pub fn client_ip(peer: IpAddr, forwarded: &str, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(&ip));

    let mut client = peer.to_canonical();
    if !is_trusted(client) {
        return client;
    }

    for entry in forwarded.rsplit(',') {
        let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            break;
        };
        client = ip.to_canonical();
        if !is_trusted(client) {
            break;
        }
    }
    client
}

struct Agent {
    id: String,
    host: String,
}

/// Marks the agent offline however the connection ends. Running on drop means
/// a panic, which ends only this connection's task, is covered too.
struct OnlineGuard<'a> {
    presence: &'a Presence,
    id: &'a str,
    connection: u64,
}

impl Drop for OnlineGuard<'_> {
    fn drop(&mut self) {
        self.presence.disconnected(self.id, self.connection);
    }
}

async fn handle(mut socket: WebSocket, source: IpAddr, state: AppState) {
    let handshake = timeout(
        state.heartbeat.timeout,
        authenticate(&mut socket, source, &state),
    );
    let agent = match handshake.await {
        Ok(Ok(Some(agent))) => agent,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            warn!(%source, error = format!("{error:#}"), "handshake failed");
            return;
        }
        Err(_) => {
            warn!(%source, "handshake timed out");
            return;
        }
    };

    let connected = state.presence.connected(&agent.id, source);
    if connected.already_online {
        warn!(
            id = agent.id,
            host = agent.host,
            "agent is already online, two machines may be sharing a key"
        );
    }
    let _online = OnlineGuard {
        presence: &state.presence,
        id: &agent.id,
        connection: connected.connection,
    };
    info!(id = agent.id, host = agent.host, %source, "agent online");

    let reason = serve(&mut socket, &agent, &state).await;
    info!(id = agent.id, host = agent.host, reason, "agent offline");
}

/// Challenges the agent and returns it if it is approved. Anything else ends
/// the connection, including for pending agents, which try again later.
async fn authenticate(
    socket: &mut WebSocket,
    source: IpAddr,
    state: &AppState,
) -> Result<Option<Agent>> {
    let nonce = auth::new_nonce()?;
    let challenge = ServerMessage::Challenge {
        nonce: nonce.clone(),
    };
    send(socket, &challenge).await?;

    let message = socket
        .recv()
        .await
        .context("connection closed before hello")?
        .context("reading hello")?;
    let Message::Text(text) = message else {
        bail!("expected a text message");
    };
    let AgentMessage::Hello {
        host,
        public_key,
        signature,
        token,
    } = serde_json::from_str(&text).context("invalid hello")?
    else {
        bail!("expected hello");
    };

    ensure!(host.len() <= MAX_HOST_LEN, "hostname is too long");

    let id = match auth::verify(&public_key, &state.audience, &nonce, &signature) {
        Ok(id) => id,
        Err(error) => {
            send_status(socket, RegistrationStatus::Rejected).await.ok();
            return Err(error.context("agent failed authentication"));
        }
    };

    let status = state
        .registry
        .admit(&Admission {
            id: &id,
            public_key: &public_key,
            host: &host,
            source,
            token: token.as_deref(),
        })
        .await?;
    send_status(socket, status).await?;

    Ok((status == RegistrationStatus::Approved).then_some(Agent { id, host }))
}

async fn send_status(socket: &mut WebSocket, status: RegistrationStatus) -> Result<()> {
    send(socket, &ServerMessage::Registration { status }).await
}

async fn send(socket: &mut WebSocket, message: &ServerMessage) -> Result<()> {
    let text = serde_json::to_string(message)?;
    socket
        .send(Message::text(text))
        .await
        .map_err(|error| anyhow!("sending to agent: {error}"))
}

/// Reads from the agent and pings it until the connection ends, returning why.
/// Any message counts as a sign of life, not just pongs.
async fn serve(socket: &mut WebSocket, agent: &Agent, state: &AppState) -> &'static str {
    let mut ping = interval(state.heartbeat.interval);
    let mut changes = state.registry.subscribe();
    let mut last_heard = Instant::now();

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_heard.elapsed() >= state.heartbeat.timeout {
                    return "heartbeat timeout";
                }
                if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    return "send failed";
                }
            }
            Ok(()) = changes.changed() => {
                if !state.registry.is_approved(&agent.id).await {
                    return "revoked";
                }
            }
            message = socket.recv() => {
                last_heard = Instant::now();
                state.presence.seen(&agent.id);

                match message {
                    Some(Ok(Message::Text(text))) => receive(&text, agent, state).await,
                    Some(Ok(Message::Close(_))) | None => return "connection closed",
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return "connection lost",
                }
            }
        }
    }
}

/// A bad message is logged and skipped rather than ending the connection.
async fn receive(text: &str, agent: &Agent, state: &AppState) {
    match serde_json::from_str(text) {
        Ok(AgentMessage::Sample(sample)) => {
            let command = WriterCommand::Save {
                agent_id: agent.id.clone(),
                host: agent.host.clone(),
                sample,
            };
            if state.writer.send(command).await.is_err() {
                warn!(id = agent.id, "writer stopped, sample dropped");
            }
        }
        Ok(AgentMessage::Facts { facts }) => save_facts(text.len(), facts, agent, state).await,
        Ok(AgentMessage::Hello { .. }) => warn!(id = agent.id, "ignoring repeated hello"),
        Err(error) => warn!(id = agent.id, %error, "skipping invalid message"),
    }
}

/// Failing to save loses nothing, because the agent reports again later.
async fn save_facts(size: usize, facts: Value, agent: &Agent, state: &AppState) {
    if size > MAX_FACTS_LEN {
        warn!(id = agent.id, size, "skipping oversized facts");
        return;
    }
    let facts = match flatten(&facts) {
        Ok(facts) => facts,
        Err(error) => {
            warn!(
                id = agent.id,
                error = format!("{error:#}"),
                "skipping invalid facts"
            );
            return;
        }
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    match state.database.record_facts(&agent.id, &facts, now_ms).await {
        Ok(true) => info!(id = agent.id, host = agent.host, "facts changed"),
        Ok(false) => {}
        Err(error) => warn!(
            id = agent.id,
            error = format!("{error:#}"),
            "saving facts failed"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn proxies() -> Vec<IpNet> {
        vec!["10.0.0.0/24".parse().unwrap()]
    }

    #[test]
    fn an_untrusted_peer_can_not_fake_its_address() {
        let source = client_ip(ip("1.2.3.4"), "10.20.0.1", &proxies());
        assert_eq!(source, ip("1.2.3.4"));
    }

    #[test]
    fn a_trusted_proxy_supplies_the_client_address() {
        let source = client_ip(ip("10.0.0.5"), "1.2.3.4", &proxies());
        assert_eq!(source, ip("1.2.3.4"));
    }

    #[test]
    fn a_forged_entry_before_the_real_client_is_ignored() {
        // The client sent "10.20.0.1", and the proxy appended what it really saw.
        let source = client_ip(ip("10.0.0.5"), "10.20.0.1, 1.2.3.4", &proxies());
        assert_eq!(source, ip("1.2.3.4"));
    }

    #[test]
    fn a_chain_of_trusted_proxies_is_skipped() {
        let source = client_ip(ip("10.0.0.5"), "1.2.3.4, 10.0.0.6", &proxies());
        assert_eq!(source, ip("1.2.3.4"));
    }

    #[test]
    fn a_trusted_proxy_without_the_header_is_the_source() {
        assert_eq!(client_ip(ip("10.0.0.5"), "", &proxies()), ip("10.0.0.5"));
    }

    #[test]
    fn garbage_in_the_header_is_not_believed() {
        let source = client_ip(ip("10.0.0.5"), "1.2.3.4, nonsense", &proxies());
        assert_eq!(source, ip("10.0.0.5"));
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_rules() {
        let source = client_ip(ip("::ffff:10.0.0.5"), "1.2.3.4", &proxies());
        assert_eq!(source, ip("1.2.3.4"));
    }
}
