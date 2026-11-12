use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{FutureExt, Sink, SinkExt, StreamExt};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::{
    AgentConfig, AgentMessage, Backoff, RegistrationStatus, Sample, ServerMessage,
};
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

use crate::actions::{Actions, Runner};
use crate::config::Config;
use crate::custom::Definitions;
use crate::facts;
use crate::spool::Spool;

/// The server pings regularly, so this much silence means the connection died.
const SERVER_SILENCE_LIMIT: Duration =
    Duration::from_secs(maxnines_protocol::AGENT_SILENCE_LIMIT_SECS);
/// How long connecting, and then the handshake, each get. A server, firewall or load
/// balancer that accepts the connection and then says nothing would otherwise hold
/// the agent offline for good.
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
    spool: Arc<Spool>,
    config_results: mpsc::Sender<String>,
    configs: mpsc::Receiver<ConfigUpdate>,
    facts_every: watch::Sender<Duration>,
}

struct Connection {
    url: String,
    hostname: String,
    identity: Identity,
    token: Option<String>,
    connector: Connector,
    spool: Arc<Spool>,
    custom_facts: BTreeMap<String, Value>,
    custom_metrics: Definitions,
    actions: Actions,
    built_in_actions: bool,
    /// Runs what the server asks for, apart from the connection, so a slow action
    /// never holds up samples or the server's pings.
    runner: Arc<Runner>,
    /// For anything to send besides samples, whichever connection is open by then.
    outgoing: mpsc::Sender<String>,
    facts_every: watch::Receiver<Duration>,
    configs: mpsc::Sender<ConfigUpdate>,
}

impl ServerLink {
    pub fn start(config: &Config, hostname: &str, identity: Identity) -> Result<Self> {
        let url = config.server.url.clone();
        if url.starts_with("ws://") {
            warn!(
                url,
                "connection is not encrypted, use wss:// beyond this host"
            );
        }
        info!(host_id = identity.id(), "agent identity loaded");

        let (facts_every, facts_every_receiver) = watch::channel(DEFAULT_FACTS_INTERVAL);
        let (config_sender, configs) = mpsc::channel(CONFIG_QUEUE_SIZE);
        let (config_results, pending) = mpsc::channel(CONFIG_QUEUE_SIZE);
        let spool = Arc::new(Spool::open(&config.sample_queue_folder()));
        let connection = Connection {
            url,
            hostname: hostname.to_string(),
            identity,
            token: config
                .server
                .token_file
                .as_deref()
                .map(read_token)
                .transpose()?,
            connector: tls_connector(config.server.ca_file.as_deref())?,
            spool: spool.clone(),
            custom_facts: config.facts.clone(),
            custom_metrics: config.custom_metrics.clone(),
            actions: config.actions.clone(),
            built_in_actions: config.built_in_actions,
            runner: Runner::new(
                config.actions.clone(),
                config.built_in_actions,
                &config.state_dir,
            ),
            outgoing: config_results.clone(),
            facts_every: facts_every_receiver,
            configs: config_sender,
        };

        tokio::spawn(stay_connected(connection, pending));
        Ok(Self {
            spool,
            config_results,
            configs,
            facts_every,
        })
    }

    pub fn send_sample(&self, sample: &Sample) -> Result<()> {
        let text = serde_json::to_string(&AgentMessage::Sample(sample.clone()))?;
        self.spool.push(text);
        Ok(())
    }

    pub fn report_config(&self, version: &str, error: Option<String>) -> Result<()> {
        let message = AgentMessage::ConfigResult {
            version: version.to_string(),
            error,
        };
        let text = serde_json::to_string(&message)?;
        match self.config_results.try_send(text) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => warn!("too many config results, one was dropped"),
            Err(TrySendError::Closed(_)) => error!("connection task gone, config result dropped"),
        }
        Ok(())
    }

    pub fn set_facts_interval(&self, every: Duration) {
        self.facts_every.send_replace(every);
    }

    /// Saves what the server hasn't confirmed, for when the agent stops.
    pub fn save_unconfirmed(&self) {
        self.spool.set_online(false);
    }

    /// Waits for the next config from the server.
    pub async fn next_config(&mut self) -> Option<ConfigUpdate> {
        self.configs.recv().await
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
    let mut backoff = Backoff::new();

    loop {
        let started = Instant::now();
        let outcome = AssertUnwindSafe(session(&connection, &mut pending))
            .catch_unwind()
            .await;
        connection.spool.set_online(false);

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(error = format!("{error:#}"), "not connected to server"),
            Err(_) => error!("websocket session panicked"),
        }

        if started.elapsed() > Backoff::MAX {
            backoff.reset();
        }
        sleep(backoff.next_wait(rand::random())).await;
    }
}

/// Opens the connection, giving up after `limit` if the other end doesn't finish
/// its side, as a stuck one would never fail on its own.
async fn connect(url: &str, connector: &Connector, limit: Duration) -> Result<Socket> {
    let connecting = connect_async_tls_with_config(url, None, false, Some(connector.clone()));
    let (socket, _) = timeout(limit, connecting)
        .await
        .with_context(|| format!("connecting to {url} timed out"))?
        .with_context(|| format!("connecting to {url}"))?;
    Ok(socket)
}

/// Runs one connection until it fails. Reading also answers the server's pings.
async fn session(connection: &Connection, pending: &mut mpsc::Receiver<String>) -> Result<()> {
    let url = connection.url.as_str();
    let mut socket = connect(url, &connection.connector, HANDSHAKE_LIMIT).await?;

    timeout(HANDSHAKE_LIMIT, authenticate(&mut socket, connection))
        .await
        .context("server did not finish the handshake")??;
    info!(url, "connected to server");
    connection.spool.set_online(true);

    send_facts(&mut socket, connection).await?;
    let mut facts_every = connection.facts_every.clone();
    let every = *facts_every.borrow_and_update();
    let mut facts_timer = interval_at(Instant::now() + every, every);

    let silence = sleep(SERVER_SILENCE_LIMIT);
    tokio::pin!(silence);

    loop {
        tokio::select! {
            Some(text) = pending.recv() => socket.send(Message::text(text)).await?,
            () = connection.spool.wait() => send_next(&mut socket, &connection.spool).await?,
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

/// A failed send ends the connection, which puts the sample back in line.
async fn send_next<S>(socket: &mut S, spool: &Spool) -> Result<(), S::Error>
where
    S: Sink<Message> + Unpin,
{
    if let Some(text) = spool.next() {
        socket.send(Message::text(text)).await?;
    }
    Ok(())
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
        Ok(ServerMessage::Ack { timestamp_ms }) => connection.spool.acked(timestamp_ms),
        Ok(ServerMessage::RunAction {
            id,
            action,
            variables,
            timeout_secs,
        }) => {
            let (runner, outgoing) = (connection.runner.clone(), connection.outgoing.clone());
            tokio::spawn(async move {
                let result = runner.run(id, &action, &variables, timeout_secs).await;
                match serde_json::to_string(&AgentMessage::ActionResult(result)) {
                    // Waits its turn if the connection is down, and goes when it's back.
                    Ok(text) => {
                        if outgoing.send(text).await.is_err() {
                            error!("an action's result was dropped, the agent has stopped");
                        }
                    }
                    Err(error) => error!(%error, "an action's result couldn't be sent"),
                }
            });
        }
        Ok(_) => warn!("ignoring an unexpected message from the server"),
        Err(error) => warn!(%error, "ignoring an invalid message from the server"),
    }
}

/// Sends everything each time and lets the server work out what changed, so a
/// change can't be lost if the server couldn't save it the first time.
async fn send_facts(socket: &mut Socket, connection: &Connection) -> Result<()> {
    let facts = match facts::gather(
        &connection.custom_facts,
        &connection.custom_metrics,
        &connection.actions,
        connection.built_in_actions,
    ) {
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
        hostname: connection.hostname.clone(),
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
    use maxnines_protocol::actions::{ActionOutcome, ActionResult};
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
            state_dir: tempfile::tempdir().unwrap().keep(),
            facts: BTreeMap::from([("role".to_string(), json!("web"))]),
            custom_metrics: Definitions::new(),
            actions: Actions::from([(
                "greet".to_string(),
                crate::actions::Action {
                    command: ["/bin/echo", "hello", "{hostname}"]
                        .map(str::to_string)
                        .to_vec(),
                },
            )]),
            built_in_actions: false,
            run_as: None,
            privileged_helper: true,
            no_new_privileges: false,
        }
    }

    fn sample() -> Sample {
        Sample {
            timestamp_ms: 7,
            metrics: BTreeMap::new(),
        }
    }

    /// Waits for something the agent does in its own time, however slow the host.
    async fn until(done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "it never happened");
            sleep(Duration::from_millis(5)).await;
        }
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");

        let link = ServerLink::start(&config(&url), "web-1", identity()).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, &url).await;
        next_message(&mut socket).await;
        (link, socket)
    }

    #[tokio::test]
    async fn delivers_samples_queued_before_the_server_came_up() {
        // A port held without listening, so the first attempt is refused and no
        // other test can be given it before the server comes up.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = reserved.local_addr().unwrap();
        let url = format!("ws://{address}/ws");

        let agent = identity();
        let host_id = agent.id();
        let link = ServerLink::start(&config(&url), "web-1", agent).unwrap();
        link.send_sample(&sample()).unwrap();

        // Let the first connection attempt run and fail.
        sleep(Duration::from_millis(100)).await;

        let listener = reserved.listen(16).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();

        assert_eq!(accept_agent(&mut socket, &url).await, host_id);

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
    async fn a_server_that_accepts_but_never_answers_is_given_up_on() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let connector = tls_connector(None).unwrap();

        let error = connect(&url, &connector, Duration::from_millis(100))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
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

    /// Facts arrive whenever they're due, so they're skipped over.
    async fn next_action_result<S>(socket: &mut WebSocketStream<S>) -> ActionResult
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        loop {
            if let AgentMessage::ActionResult(result) = next_message(socket).await {
                return result;
            }
        }
    }

    #[tokio::test]
    async fn reports_its_actions_as_facts() {
        let (link, mut socket) = connected().await;
        link.set_facts_interval(Duration::from_millis(50));
        let AgentMessage::Facts { facts } = next_message(&mut socket).await else {
            panic!("expected facts");
        };
        assert_eq!(facts["agent"]["actions"], json!(["greet"]));
        assert_eq!(
            facts["agent"]["action_variables"],
            json!({ "greet": ["hostname"] })
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runs_an_action_the_server_asks_for_and_sends_what_it_printed() {
        let (_link, mut socket) = connected().await;
        let ask = ServerMessage::RunAction {
            id: "run-1".to_string(),
            action: "greet".to_string(),
            variables: BTreeMap::from([("hostname".to_string(), "web-1".to_string())]),
            timeout_secs: 5,
        };
        send_to_agent(&mut socket, &ask).await;

        let result = next_action_result(&mut socket).await;
        assert_eq!(result.id, "run-1");
        assert_eq!(result.outcome, ActionOutcome::Succeeded);
        assert_eq!(result.output, "hello web-1\n");
    }

    #[tokio::test]
    async fn an_action_it_does_not_have_is_answered_without_running_anything() {
        let (_link, mut socket) = connected().await;
        let ask = ServerMessage::RunAction {
            id: "run-2".to_string(),
            action: "reboot".to_string(),
            variables: BTreeMap::new(),
            timeout_secs: 5,
        };
        send_to_agent(&mut socket, &ask).await;

        let result = next_action_result(&mut socket).await;
        assert_eq!(result.id, "run-2");
        assert_eq!(result.outcome, ActionOutcome::NotDefined);
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");

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
    async fn sends_again_a_sample_the_connection_lost() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");
        let link = ServerLink::start(&config(&url), "web-1", identity()).unwrap();

        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, &url).await;
        next_message(&mut socket).await;
        drop(socket);
        until(|| !link.spool.is_online()).await;

        link.send_sample(&sample()).unwrap();
        assert!(link.spool.saved_bytes() > 0, "offline samples go to disk");

        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, &url).await;
        next_message(&mut socket).await;
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::Sample(sample())
        );
    }

    #[tokio::test]
    async fn a_connected_agent_sends_samples_without_saving_them() {
        let (link, mut socket) = connected().await;

        link.send_sample(&sample()).unwrap();

        assert_eq!(link.spool.saved_bytes(), 0);
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::Sample(sample())
        );
    }

    #[tokio::test]
    async fn a_sample_that_fails_to_send_stays_queued() {
        let folder = tempfile::tempdir().unwrap();
        let spool = Spool::open(&folder.path().join("samples"));
        spool.push(r#"{"timestamp_ms":1}"#.to_string());
        let broken = futures_util::sink::unfold((), |(), _: Message| async {
            Err::<(), &str>("connection lost")
        });
        let mut broken = std::pin::pin!(broken);

        assert!(send_next(&mut broken, &spool).await.is_err());
        spool.set_online(false);

        assert_eq!(spool.next().unwrap(), r#"{"timestamp_ms":1}"#);
    }

    /// Waits for a new connection from the agent, and gets past its first facts.
    async fn reconnected(listener: &TcpListener, url: &str) -> WebSocketStream<TcpStream> {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, url).await;
        next_message(&mut socket).await;
        socket
    }

    #[tokio::test]
    async fn a_sample_the_server_never_confirmed_is_sent_again() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");
        let link = ServerLink::start(&config(&url), "web-1", identity()).unwrap();
        let mut socket = reconnected(&listener, &url).await;

        link.send_sample(&sample()).unwrap();
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::Sample(sample())
        );
        drop(socket);

        let mut socket = reconnected(&listener, &url).await;
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::Sample(sample())
        );
    }

    #[tokio::test]
    async fn a_confirmed_sample_is_not_sent_again() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");
        let link = ServerLink::start(&config(&url), "web-1", identity()).unwrap();
        let mut socket = reconnected(&listener, &url).await;

        link.send_sample(&sample()).unwrap();
        next_message(&mut socket).await;
        let ack = ServerMessage::Ack { timestamp_ms: 7 };
        send_to_agent(&mut socket, &ack).await;
        until(|| link.spool.unconfirmed() == 0).await;
        drop(socket);

        let mut socket = reconnected(&listener, &url).await;
        let nothing = timeout(Duration::from_millis(300), next_message(&mut socket)).await;
        assert!(nothing.is_err(), "{nothing:?}");
    }

    #[tokio::test]
    async fn delivers_samples_saved_before_a_restart() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");
        let settings = config(&url);
        let saved = serde_json::to_string(&AgentMessage::Sample(sample())).unwrap();
        Spool::open(&settings.sample_queue_folder()).push(saved);

        let _link = ServerLink::start(&settings, "web-1", identity()).unwrap();

        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, &url).await;
        next_message(&mut socket).await;
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::Sample(sample())
        );
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
