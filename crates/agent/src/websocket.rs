use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{FutureExt, SinkExt, StreamExt};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::{AgentConfig, AgentMessage, RegistrationStatus, Sample, ServerMessage};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::watch;
use tokio::time::{Instant, interval_at, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::facts;

/// Samples kept while the server is unreachable. Newer ones are dropped once
/// this is full. At the default 15 second interval this covers 16 minutes.
const OUTBOX_SIZE: usize = 64;
const MIN_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
/// The server pings regularly, so this much silence means the connection died.
const SERVER_SILENCE_LIMIT: Duration = Duration::from_secs(30);
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(15);
/// Configs arrive rarely, and only the newest one matters.
const CONFIG_QUEUE_SIZE: usize = 8;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How often to report facts until the server says otherwise.
const DEFAULT_FACTS_INTERVAL: Duration = Duration::from_secs(3600);

/// A config from the server, waiting to be applied.
#[derive(Debug)]
pub struct ConfigUpdate {
    pub version: String,
    pub config: AgentConfig,
}

/// Talks to a background task that owns the connection, so a slow or missing
/// server never holds up collection.
pub struct ServerLink {
    outbox: mpsc::Sender<String>,
    configs: mpsc::Receiver<ConfigUpdate>,
    facts_every: watch::Sender<Duration>,
}

struct Connection {
    url: String,
    host: String,
    identity: Identity,
    token: Option<String>,
    connector: Connector,
    custom_facts: BTreeMap<String, Value>,
    facts_every: watch::Receiver<Duration>,
    configs: mpsc::Sender<ConfigUpdate>,
}

impl ServerLink {
    pub fn start(config: &Config, host: &str, identity: Identity) -> Result<Self> {
        let url = config.server.url.clone();
        if url.starts_with("ws://") {
            warn!(
                url,
                "connection is not encrypted, use wss:// beyond this machine"
            );
        }
        info!(agent_id = identity.id(), "agent identity loaded");

        let (facts_every, facts_every_receiver) = watch::channel(DEFAULT_FACTS_INTERVAL);
        let (config_sender, configs) = mpsc::channel(CONFIG_QUEUE_SIZE);
        let connection = Connection {
            url,
            host: host.to_string(),
            identity,
            token: config
                .server
                .token_file
                .as_deref()
                .map(read_token)
                .transpose()?,
            connector: tls_connector(config.server.ca_file.as_deref())?,
            custom_facts: config.facts.clone(),
            facts_every: facts_every_receiver,
            configs: config_sender,
        };

        let (outbox, pending) = mpsc::channel(OUTBOX_SIZE);
        tokio::spawn(stay_connected(connection, pending));
        Ok(Self {
            outbox,
            configs,
            facts_every,
        })
    }

    pub fn send_sample(&self, sample: &Sample) -> Result<()> {
        self.send(&AgentMessage::Sample(sample.clone()), "sample")
    }

    pub fn report_config(&self, version: &str, error: Option<String>) -> Result<()> {
        let message = AgentMessage::ConfigResult {
            version: version.to_string(),
            error,
        };
        self.send(&message, "config result")
    }

    pub fn set_facts_interval(&self, every: Duration) {
        self.facts_every.send_replace(every);
    }

    /// Waits for the next config from the server.
    pub async fn next_config(&mut self) -> Option<ConfigUpdate> {
        self.configs.recv().await
    }

    fn send(&self, message: &AgentMessage, what: &str) -> Result<()> {
        let text = serde_json::to_string(message)?;
        match self.outbox.try_send(text) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => warn!(what, "outbox full, message dropped"),
            Err(TrySendError::Closed(_)) => error!(what, "connection task gone, message dropped"),
        }
        Ok(())
    }
}

fn read_token(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading token file {}", path.display()))?;
    Ok(text.trim().to_string())
}

/// Verifies the server against the public roots, or only `ca_file` if set.
fn tls_connector(ca_file: Option<&Path>) -> Result<Connector> {
    let mut roots = RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let certificates = CertificateDer::pem_file_iter(path)
                .with_context(|| format!("reading CA file {}", path.display()))?;
            for certificate in certificates {
                roots.add(certificate.context("parsing CA file")?)?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

/// Reconnects forever, backing off while the server stays unreachable. This is
/// also how a pending agent checks for approval. A panic in a session is
/// treated like any other lost connection.
async fn stay_connected(connection: Connection, mut pending: mpsc::Receiver<String>) {
    let mut delay = MIN_RETRY_DELAY;

    loop {
        let started = Instant::now();
        let outcome = AssertUnwindSafe(session(&connection, &mut pending))
            .catch_unwind()
            .await;

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(error = format!("{error:#}"), "not connected to server"),
            Err(_) => error!("websocket session panicked"),
        }

        if started.elapsed() > MAX_RETRY_DELAY {
            delay = MIN_RETRY_DELAY;
        }
        sleep(delay).await;
        delay = (delay * 2).min(MAX_RETRY_DELAY);
    }
}

/// Runs one connection until it fails. Reading also answers the server's pings.
async fn session(connection: &Connection, pending: &mut mpsc::Receiver<String>) -> Result<()> {
    let url = connection.url.as_str();
    let connector = Some(connection.connector.clone());
    let (mut socket, _) = connect_async_tls_with_config(url, None, false, connector)
        .await
        .with_context(|| format!("connecting to {url}"))?;

    timeout(HANDSHAKE_LIMIT, authenticate(&mut socket, connection))
        .await
        .context("server did not finish the handshake")??;
    info!(url, "connected to server");

    send_facts(&mut socket, connection).await?;
    let mut facts_every = connection.facts_every.clone();
    let every = *facts_every.borrow_and_update();
    let mut facts_timer = interval_at(Instant::now() + every, every);

    let silence = sleep(SERVER_SILENCE_LIMIT);
    tokio::pin!(silence);

    loop {
        tokio::select! {
            Some(text) = pending.recv() => socket.send(Message::text(text)).await?,
            _ = facts_timer.tick() => send_facts(&mut socket, connection).await?,
            Ok(()) = facts_every.changed() => {
                let every = *facts_every.borrow_and_update();
                facts_timer = interval_at(Instant::now() + every, every);
            }
            message = socket.next() => {
                silence.as_mut().reset(Instant::now() + SERVER_SILENCE_LIMIT);
                match message {
                    Some(Ok(Message::Text(text))) => receive(&text, connection).await,
                    Some(Ok(Message::Close(_))) | None => bail!("server closed the connection"),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error.into()),
                }
            }
            () = &mut silence => bail!("no heartbeat from server"),
        }
    }
}

/// Anything unexpected is logged and ignored, so a newer server can't take down
/// an older agent.
async fn receive(text: &str, connection: &Connection) {
    match serde_json::from_str(text) {
        Ok(ServerMessage::Config { version, config }) => {
            let update = ConfigUpdate { version, config };
            if connection.configs.send(update).await.is_err() {
                error!("config dropped, the agent has stopped");
            }
        }
        Ok(_) => warn!("ignoring an unexpected message from the server"),
        Err(error) => warn!(%error, "ignoring an invalid message from the server"),
    }
}

/// Sends everything each time and lets the server work out what changed, so a
/// change can't be lost if the server couldn't save it the first time.
async fn send_facts(socket: &mut Socket, connection: &Connection) -> Result<()> {
    let facts = match facts::gather(&connection.custom_facts) {
        Ok(facts) => facts,
        Err(error) => {
            warn!(error = format!("{error:#}"), "gathering facts failed");
            return Ok(());
        }
    };
    let text = serde_json::to_string(&AgentMessage::Facts { facts })?;
    socket.send(Message::text(text)).await?;
    Ok(())
}

/// Answers the server's challenge and returns once the agent is approved.
async fn authenticate(socket: &mut Socket, connection: &Connection) -> Result<()> {
    let ServerMessage::Challenge { nonce } = read_server_message(socket).await? else {
        bail!("expected a challenge from the server");
    };

    let hello = AgentMessage::Hello {
        host: connection.host.clone(),
        public_key: connection.identity.public_key(),
        signature: connection.identity.sign(&connection.url, &nonce),
        token: connection.token.clone(),
    };
    socket
        .send(Message::text(serde_json::to_string(&hello)?))
        .await?;

    let ServerMessage::Registration { status } = read_server_message(socket).await? else {
        bail!("expected a registration result from the server");
    };

    let id = connection.identity.id();
    match status {
        RegistrationStatus::Approved => Ok(()),
        RegistrationStatus::Pending => bail!("agent {id} is waiting for approval"),
        RegistrationStatus::Rejected => bail!("agent {id} was rejected by the server"),
    }
}

async fn read_server_message(socket: &mut Socket) -> Result<ServerMessage> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).context("invalid message from server");
            }
            Some(Ok(Message::Close(_))) | None => bail!("server closed the connection"),
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use maxnines_protocol::auth;
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    use super::*;
    use crate::config::ServerConfig;

    fn identity() -> Identity {
        Identity::from_pkcs8(&Identity::generate().unwrap()).unwrap()
    }

    fn config(url: &str) -> Config {
        Config {
            server: ServerConfig {
                url: url.to_string(),
                token_file: None,
                ca_file: None,
            },
            state_dir: "state".into(),
            facts: BTreeMap::from([("role".to_string(), json!("web"))]),
        }
    }

    fn sample() -> Sample {
        Sample {
            timestamp_ms: 7,
            metrics: BTreeMap::new(),
        }
    }

    async fn free_address() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    async fn next_message<S>(socket: &mut WebSocketStream<S>) -> AgentMessage
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let message = socket.next().await.unwrap().unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    async fn send_to_agent<S>(socket: &mut WebSocketStream<S>, message: &ServerMessage)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let text = serde_json::to_string(message).unwrap();
        socket.send(Message::text(text)).await.unwrap();
    }

    /// Plays the server's side of the handshake, returning the verified ID.
    async fn accept_agent<S>(socket: &mut WebSocketStream<S>, url: &str) -> String
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let challenge = ServerMessage::Challenge {
            nonce: "test-nonce".to_string(),
        };
        send_to_agent(socket, &challenge).await;

        let AgentMessage::Hello {
            public_key,
            signature,
            ..
        } = next_message(socket).await
        else {
            panic!("expected hello");
        };
        let id = auth::verify(&public_key, url, "test-nonce", &signature).unwrap();

        let approved = ServerMessage::Registration {
            status: RegistrationStatus::Approved,
        };
        send_to_agent(socket, &approved).await;
        id
    }

    /// Connects an agent to a throwaway server and gets past its first facts.
    async fn connected() -> (ServerLink, WebSocketStream<TcpStream>) {
        let address = free_address().await;
        let url = format!("ws://{address}/ws");
        let listener = TcpListener::bind(address).await.unwrap();

        let link = ServerLink::start(&config(&url), "web-1", identity()).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, &url).await;
        next_message(&mut socket).await;
        (link, socket)
    }

    #[tokio::test]
    async fn delivers_samples_queued_before_the_server_came_up() {
        // Find a free port, then leave it closed so the first attempt fails.
        let address = free_address().await;
        let url = format!("ws://{address}/ws");

        let agent = identity();
        let agent_id = agent.id();
        let link = ServerLink::start(&config(&url), "web-1", agent).unwrap();
        link.send_sample(&sample()).unwrap();

        // Let the first connection attempt run and fail.
        sleep(Duration::from_millis(100)).await;

        let listener = TcpListener::bind(address).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();

        assert_eq!(accept_agent(&mut socket, &url).await, agent_id);

        assert!(matches!(
            next_message(&mut socket).await,
            AgentMessage::Facts { .. }
        ));
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::Sample(sample())
        );
    }

    #[tokio::test]
    async fn reports_facts_on_connecting_and_then_regularly() {
        let (link, mut socket) = connected().await;
        link.set_facts_interval(Duration::from_millis(50));

        for _ in 0..3 {
            let AgentMessage::Facts { facts } = next_message(&mut socket).await else {
                panic!("expected facts");
            };
            assert_eq!(facts["custom"]["role"], "web");
        }
    }

    #[tokio::test]
    async fn passes_configs_on_and_reports_the_result() {
        let (mut link, mut socket) = connected().await;

        let sent: AgentConfig = serde_json::from_value(json!({ "interval_secs": 9 })).unwrap();
        let message = ServerMessage::Config {
            version: "v1".to_string(),
            config: sent.clone(),
        };
        send_to_agent(&mut socket, &message).await;

        let update = link.next_config().await.unwrap();
        assert_eq!(update.version, "v1");
        assert_eq!(update.config, sent);

        link.report_config("v1", Some("broken".to_string()))
            .unwrap();
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::ConfigResult {
                version: "v1".to_string(),
                error: Some("broken".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn an_invalid_message_from_the_server_does_not_end_the_connection() {
        let (mut link, mut socket) = connected().await;

        socket.send(Message::text("not json")).await.unwrap();
        let message = ServerMessage::Config {
            version: "v1".to_string(),
            config: serde_json::from_value(json!({})).unwrap(),
        };
        send_to_agent(&mut socket, &message).await;

        assert_eq!(link.next_config().await.unwrap().version, "v1");
    }

    #[tokio::test]
    async fn holds_samples_back_until_approved() {
        let address = free_address().await;
        let url = format!("ws://{address}/ws");
        let listener = TcpListener::bind(address).await.unwrap();

        let link = ServerLink::start(&config(&url), "web-1", identity()).unwrap();
        link.send_sample(&sample()).unwrap();

        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let challenge = ServerMessage::Challenge {
            nonce: "n".to_string(),
        };
        send_to_agent(&mut socket, &challenge).await;
        socket.next().await.unwrap().unwrap();

        let pending = ServerMessage::Registration {
            status: RegistrationStatus::Pending,
        };
        send_to_agent(&mut socket, &pending).await;

        // Pending ends the session, so the sample must not arrive on this one.
        let next = socket.next().await;
        assert!(!matches!(next, Some(Ok(Message::Text(_)))), "{next:?}");
    }

    #[tokio::test]
    async fn drops_samples_instead_of_blocking_when_the_outbox_is_full() {
        let (outbox, _pending) = mpsc::channel(1);
        let (_config_sender, configs) = mpsc::channel(1);
        let (facts_every, _) = watch::channel(DEFAULT_FACTS_INTERVAL);
        let link = ServerLink {
            outbox,
            configs,
            facts_every,
        };

        link.send_sample(&sample()).unwrap();
        link.send_sample(&sample()).unwrap();
    }

    #[test]
    fn a_missing_ca_file_is_an_error() {
        assert!(tls_connector(Some(Path::new("/nonexistent.pem"))).is_err());
    }

    #[test]
    fn the_public_roots_load() {
        assert!(tls_connector(None).is_ok());
    }
}
