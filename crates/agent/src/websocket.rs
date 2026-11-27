use std::collections::{BTreeMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{FutureExt, Sink, SinkExt, StreamExt};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::{
    AgentConfig, AgentMessage, Backoff, PROTOCOL_VERSION, RegistrationStatus, Sample, ServerMessage,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Interval, interval_at, sleep, timeout};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use tracing::{debug, error, info, warn};

use crate::actions::{Actions, Runner};
use crate::config::Config;
use crate::facts;
use crate::facts::Allowed;
use crate::spool::Spool;

/// The server pings regularly, so this much silence means the connection died.
const SERVER_SILENCE_LIMIT: Duration = maxnines_protocol::AGENT_SILENCE_LIMIT;
/// How long anything sent gets to go. Nothing is read while it's going, so a
/// connection the server stopped reading is given up on in the time it takes to
/// notice the server has gone quiet, rather than whenever TCP gives up.
const SEND_LIMIT: Duration = SERVER_SILENCE_LIMIT;
/// How long connecting, and then the handshake, each get. A server, firewall or load
/// balancer that accepts the connection and then says nothing would otherwise hold
/// the agent offline for good.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(15);
/// The longest an agent the server refused waits before trying again. Trying sooner
/// wouldn't help, as something has to be upgraded first, and that restarts whichever
/// side it was. The wait is anywhere from half of this to all of it, so that agents
/// refused together don't all come back together.
const REFUSED_WAIT: Duration = Duration::from_secs(600);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How often to report facts until the server says otherwise.
const DEFAULT_FACTS_INTERVAL: Duration = Duration::from_secs(3600);

/// A config from the server, waiting to be applied.
#[derive(Debug, Clone)]
pub struct ConfigUpdate {
    pub version: String,
    pub config: AgentConfig,
    /// The config just as the server sent it, which is what's saved. What this build
    /// reads from it leaves out what it doesn't know, which a newer server can send,
    /// and an upgraded agent reads the whole of it again.
    pub sent: Value,
}

impl ConfigUpdate {
    /// Reads a config as the server sent it.
    pub fn read(version: String, sent: Value) -> Result<Self> {
        let config = serde_json::from_value(sent.clone()).context("reading the config")?;
        Ok(Self {
            version,
            config,
            sent,
        })
    }
}

/// Just the config from a [`ServerMessage::Config`], as it was sent.
#[derive(Deserialize)]
struct SentConfig {
    config: Value,
}

/// Talks to a background task that owns the connection, so a slow or missing
/// server never holds up collection.
pub struct ServerLink {
    spool: Arc<Spool>,
    outbox: Arc<Outbox>,
    /// Only the newest config matters, so one that arrives replaces any still
    /// waiting, and receiving one never waits on applying the one before.
    configs: watch::Receiver<Option<ConfigUpdate>>,
    facts_every: watch::Sender<Duration>,
}

/// What the agent was asked to report about itself, gathered apart from the
/// connection, as asking the resolver and the system can be slow.
struct FactsAsked {
    custom: BTreeMap<String, Value>,
    allowed: Allowed,
    actions: Actions,
    built_in_actions: bool,
}

impl FactsAsked {
    fn gather(&self) -> Result<Value> {
        facts::gather(
            &self.custom,
            &self.allowed,
            &self.actions,
            self.built_in_actions,
        )
    }
}

/// Results the server is waiting for, such as an action's, kept until they've gone,
/// so one isn't lost when the connection is.
#[derive(Default)]
struct Outbox {
    waiting: Mutex<VecDeque<Utf8Bytes>>,
    arrived: Notify,
}

impl Outbox {
    fn waiting(&self) -> std::sync::MutexGuard<'_, VecDeque<Utf8Bytes>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, text: String) {
        self.waiting().push_back(text.into());
        self.arrived.notify_one();
    }

    /// Waits for the oldest result, which stays until [`Outbox::sent`].
    async fn next(&self) -> Utf8Bytes {
        loop {
            if let Some(text) = self.waiting().front() {
                return text.clone();
            }
            self.arrived.notified().await;
        }
    }

    /// The oldest result has gone.
    fn sent(&self) {
        self.waiting().pop_front();
    }
}

struct Connection {
    url: String,
    hostname: String,
    identity: Identity,
    token: Option<String>,
    connector: Connector,
    spool: Arc<Spool>,
    facts: Arc<FactsAsked>,
    /// Runs what the server asks for, apart from the connection, so a slow action
    /// never holds up samples or the server's pings.
    runner: Arc<Runner>,
    outbox: Arc<Outbox>,
    facts_every: watch::Receiver<Duration>,
    configs: watch::Sender<Option<ConfigUpdate>>,
}

/// What the agent trusts the server with and by: its enrollment token and the
/// authority its certificate is checked against. Both are read before an agent
/// started as root gives that up, so either can be a file only root can read.
pub struct ServerTrust {
    token: Option<String>,
    connector: Connector,
}

impl ServerTrust {
    pub fn read(config: &Config) -> Result<Self> {
        let server = &config.server;
        Ok(Self {
            token: server.token_file.as_deref().map(read_token).transpose()?,
            connector: tls_connector(server.ca_file.as_deref())?,
        })
    }
}

impl ServerLink {
    pub fn start(
        config: &Config,
        trust: ServerTrust,
        hostname: &str,
        identity: Identity,
    ) -> Result<Self> {
        let (link, connection) = Self::new(config, trust, hostname, identity)?;
        tokio::spawn(stay_connected(connection));
        Ok(link)
    }

    /// The link, and the connection for a task of its own to keep up.
    fn new(
        config: &Config,
        trust: ServerTrust,
        hostname: &str,
        identity: Identity,
    ) -> Result<(Self, Connection)> {
        let url = config.server.url.clone();
        if url.starts_with("ws://") {
            warn!(
                url,
                "connection is not encrypted, use wss:// beyond this host"
            );
        }
        info!(host_id = identity.id(), "agent identity loaded");

        let (facts_every, facts_every_receiver) = watch::channel(DEFAULT_FACTS_INTERVAL);
        let (config_sender, configs) = watch::channel(None);
        let spool = Arc::new(Spool::open(&config.sample_queue_folder()));
        let outbox = Arc::new(Outbox::default());
        let connection = Connection {
            url,
            hostname: hostname.to_string(),
            identity,
            token: trust.token,
            connector: trust.connector,
            spool: spool.clone(),
            facts: Arc::new(FactsAsked {
                custom: config.facts.clone(),
                allowed: config.allowed(),
                actions: config.actions.clone(),
                built_in_actions: config.built_in_actions,
            }),
            runner: Runner::new(
                config.actions.clone(),
                config.built_in_actions,
                &config.state_dir,
            ),
            outbox: outbox.clone(),
            facts_every: facts_every_receiver,
            configs: config_sender,
        };

        let link = Self {
            spool,
            outbox,
            configs,
            facts_every,
        };
        Ok((link, connection))
    }

    pub fn send_sample(&self, sample: Sample) -> Result<()> {
        let taken_at = sample.time;
        let text = serde_json::to_string(&AgentMessage::Sample(sample))?;
        self.spool.push(text, taken_at);
        Ok(())
    }

    /// Goes once the connection is up, however long that takes.
    pub fn report_config(
        &self,
        version: &str,
        error: Option<String>,
        skipped_collectors: Vec<String>,
    ) -> Result<()> {
        let message = AgentMessage::ConfigResult {
            version: version.to_string(),
            error,
            skipped_collectors,
        };
        self.outbox.push(serde_json::to_string(&message)?);
        Ok(())
    }

    /// Only a change restarts the wait for the next report.
    pub fn set_facts_interval(&self, every: Duration) {
        self.facts_every.send_if_modified(|current| {
            let changed = *current != every;
            *current = every;
            changed
        });
    }

    /// Saves what the server hasn't confirmed, for when the agent stops.
    pub async fn save_unconfirmed(&self) {
        self.spool.set_online(false);
        self.spool.flush().await;
    }

    /// Waits for the next config from the server, the newest if several came while
    /// one was being applied.
    pub async fn next_config(&mut self) -> Option<ConfigUpdate> {
        loop {
            self.configs.changed().await.ok()?;
            if let Some(update) = self.configs.borrow_and_update().clone() {
                return Some(update);
            }
        }
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

/// Why the server refused this agent, in its own words, which waiting a little won't
/// change.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the server refused this agent: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// What the agent says about being refused: the server's whole reason the first time,
/// and a short line on later tries while nothing changes.
#[derive(Default)]
struct Refusals {
    last: Option<String>,
}

impl Refusals {
    /// Logs a refusal, and gives how long to wait before trying again, given a random
    /// number from 0 to 1.
    fn refused(&mut self, refused: &Refused, random: f64) -> Duration {
        let wait = REFUSED_WAIT.mul_f64(0.5 + random.clamp(0.0, 1.0) / 2.0);
        error!("{}", self.line(refused, wait));
        wait
    }

    fn line(&mut self, refused: &Refused, wait: Duration) -> String {
        let minutes = wait.as_secs().div_ceil(60);
        if self.last.as_ref() == Some(&refused.0) {
            return format!(
                "the server still refuses this agent, as above. Trying again in {minutes} \
                 minutes."
            );
        }
        self.last = Some(refused.0.clone());
        format!("{refused} Trying again in {minutes} minutes.")
    }

    /// Anything else happening is a change, after which a refusal is told in full.
    fn clear(&mut self) {
        self.last = None;
    }
}

/// Reconnects forever, backing off while the server stays unreachable. This is
/// also how a pending agent checks for approval. A panic in a session is
/// treated like any other lost connection. An agent the server refuses waits far
/// longer, as only an upgrade changes that.
async fn stay_connected(connection: Connection) {
    let mut backoff = Backoff::new();
    let mut refusals = Refusals::default();

    loop {
        let started = Instant::now();
        let outcome = AssertUnwindSafe(session(&connection)).catch_unwind().await;
        connection.spool.set_online(false);

        let refused = match &outcome {
            Ok(Err(error)) => error.downcast_ref::<Refused>(),
            _ => None,
        };
        if let Some(refused) = refused {
            sleep(refusals.refused(refused, rand::random())).await;
            backoff.reset();
            continue;
        }
        refusals.clear();
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

/// Sends one message, giving up if it doesn't go in [`SEND_LIMIT`].
async fn send<S>(socket: &mut S, text: impl Into<Utf8Bytes>) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    timeout(SEND_LIMIT, socket.send(Message::Text(text.into())))
        .await
        .context("the server stopped taking what was sent")??;
    Ok(())
}

/// Gathers facts on a thread of its own, as asking the resolver and the system can
/// be slow, and the connection has to keep answering the server meanwhile.
fn gather_facts(facts: &Arc<FactsAsked>) -> JoinHandle<Result<Value>> {
    let facts = facts.clone();
    tokio::task::spawn_blocking(move || facts.gather())
}

/// Waits for facts being gathered, if they are.
async fn gathered(gathering: &mut Option<JoinHandle<Result<Value>>>) -> Result<Value> {
    let Some(task) = gathering else {
        return std::future::pending().await;
    };
    let found = task.await;
    *gathering = None;
    found.context("gathering facts panicked")?
}

/// Every `every`, starting `every` from now.
fn from_now(every: Duration) -> Interval {
    interval_at(Instant::now() + every, every)
}

/// Runs one connection until it fails. Reading also answers the server's pings.
/// Facts go first, and nothing else is sent until they have.
async fn session(connection: &Connection) -> Result<()> {
    let url = connection.url.as_str();
    let mut socket = connect(url, &connection.connector, HANDSHAKE_LIMIT).await?;

    timeout(HANDSHAKE_LIMIT, authenticate(&mut socket, connection))
        .await
        .context("server did not finish the handshake")??;
    info!(url, "connected to server");
    connection.spool.set_online(true);

    let mut gathering = Some(gather_facts(&connection.facts));
    let mut facts_sent = false;
    let mut facts_every = connection.facts_every.clone();
    let mut facts_timer = from_now(*facts_every.borrow_and_update());

    let silence = sleep(SERVER_SILENCE_LIMIT);
    tokio::pin!(silence);

    loop {
        tokio::select! {
            found = gathered(&mut gathering) => {
                match found {
                    Ok(facts) => {
                        let text = serde_json::to_string(&AgentMessage::Facts { facts })?;
                        send(&mut socket, text).await?;
                    }
                    Err(error) => warn!(error = format!("{error:#}"), "gathering facts failed"),
                }
                facts_sent = true;
            }
            text = connection.outbox.next(), if facts_sent => {
                send(&mut socket, text).await?;
                connection.outbox.sent();
            }
            () = connection.spool.wait(), if facts_sent => {
                send_next(&mut socket, &connection.spool).await?;
            }
            _ = facts_timer.tick() => {
                if gathering.is_none() {
                    gathering = Some(gather_facts(&connection.facts));
                }
            }
            Ok(()) = facts_every.changed() => {
                facts_timer = from_now(*facts_every.borrow_and_update());
            }
            message = socket.next() => {
                silence.as_mut().reset(Instant::now() + SERVER_SILENCE_LIMIT);
                match message {
                    Some(Ok(Message::Text(text))) => {
                        // Sent ahead of anything else that's waiting, as the server
                        // is timing it.
                        if let Some(answer) = receive(&text, connection).await {
                            send(&mut socket, answer).await?;
                        }
                    }
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
async fn send_next<S>(socket: &mut S, spool: &Spool) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if let Some(text) = spool.next() {
        send(socket, text).await?;
    }
    Ok(())
}

/// Anything unexpected is logged and ignored, so a newer server can't take down
/// an older agent. Returns an answer the server is waiting for now.
async fn receive(text: &str, connection: &Connection) -> Option<String> {
    match serde_json::from_str(text) {
        Ok(ServerMessage::AskTime { nonce }) => {
            let answered_at = maxnines_protocol::time::now();
            return serde_json::to_string(&AgentMessage::Time { nonce, answered_at })
                .inspect_err(|error| error!(%error, "the time couldn't be sent"))
                .ok();
        }
        Ok(ServerMessage::Config { version, config }) => {
            let sent = match serde_json::from_str::<SentConfig>(text) {
                Ok(sent) => sent.config,
                Err(error) => {
                    warn!(%error, "ignoring a config that can't be kept as it was sent");
                    return None;
                }
            };
            let update = ConfigUpdate {
                version,
                config,
                sent,
            };
            connection.configs.send_replace(Some(update));
        }
        Ok(ServerMessage::Ack { time }) => connection.spool.acked(time),
        Ok(ServerMessage::Unknown) => debug!("ignoring a message from a newer server"),
        Ok(ServerMessage::RunAction {
            id,
            action,
            variables,
            timeout,
        }) => {
            let (runner, outbox) = (connection.runner.clone(), connection.outbox.clone());
            tokio::spawn(async move {
                let result = runner.run(id, &action, &variables, timeout).await;
                match serde_json::to_string(&AgentMessage::ActionResult(result)) {
                    // Waits its turn if the connection is down, and goes when it's back.
                    Ok(text) => outbox.push(text),
                    Err(error) => error!(%error, "an action's result couldn't be sent"),
                }
            });
        }
        Ok(_) => warn!("ignoring an unexpected message from the server"),
        Err(error) => warn!(%error, "ignoring an invalid message from the server"),
    }
    None
}

/// Answers the server's challenge and returns once the agent is approved.
async fn authenticate(socket: &mut Socket, connection: &Connection) -> Result<()> {
    let ServerMessage::Challenge { nonce, protocols } = read_server_message(socket).await? else {
        bail!("expected a challenge from the server");
    };
    // The server says whether it takes this agent's, after the hello.
    debug!(
        oldest = protocols.oldest,
        newest = protocols.newest,
        "the server takes these protocol versions"
    );

    let hello = AgentMessage::Hello {
        hostname: connection.hostname.clone(),
        public_key: connection.identity.public_key(),
        signature: connection.identity.sign(&connection.url, &nonce),
        token: connection.token.clone(),
        protocol: PROTOCOL_VERSION,
        agent_version: maxnines_protocol::build_info!().version,
    };
    socket
        .send(Message::text(serde_json::to_string(&hello)?))
        .await?;

    registration(socket, connection).await
}

/// Reads how the server took the hello, returning once the agent is approved.
async fn registration(socket: &mut Socket, connection: &Connection) -> Result<()> {
    let status = match read_server_message(socket).await? {
        ServerMessage::Registration { status } => status,
        ServerMessage::Refused { reason } => return Err(Refused(reason).into()),
        _ => bail!("expected a registration result from the server"),
    };

    let id = connection.identity.id();
    match status {
        RegistrationStatus::Approved => Ok(()),
        RegistrationStatus::Pending => bail!("waiting for the server to approve host ID {id}"),
        RegistrationStatus::Rejected => bail!("the server rejected host ID {id}"),
        // Whatever it is, it isn't approval, so the agent tries again as it does
        // while it's waiting.
        RegistrationStatus::Unknown => bail!(
            "the server answered host ID {id} with a status this agent doesn't know, so the \
             agent may need upgrading"
        ),
    }
}

/// The next message the agent knows, skipping any from a newer server.
async fn read_server_message(socket: &mut Socket) -> Result<ServerMessage> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                match serde_json::from_str(&text).context("invalid message from server")? {
                    ServerMessage::Unknown => debug!("ignoring a message from a newer server"),
                    message => return Ok(message),
                }
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

    fn start(config: &Config, hostname: &str, identity: Identity) -> ServerLink {
        let trust = ServerTrust::read(config).unwrap();
        ServerLink::start(config, trust, hostname, identity).unwrap()
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
            custom_metrics: crate::custom::Definitions::new(),
            check_commands: BTreeMap::new(),
            checks: BTreeMap::new(),
            metrics_pages: BTreeMap::new(),
            databases: BTreeMap::new(),
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
        }
    }

    /// When [`sample`] was taken.
    fn taken_at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(1_789_000_000_007).unwrap()
    }

    fn sample() -> Sample {
        Sample {
            time: taken_at(),
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
            protocols: maxnines_protocol::Protocols::SUPPORTED,
        };
        send_to_agent(socket, &challenge).await;

        let AgentMessage::Hello {
            public_key,
            signature,
            protocol,
            agent_version,
            ..
        } = next_message(socket).await
        else {
            panic!("expected hello");
        };
        assert_eq!(protocol, PROTOCOL_VERSION);
        assert_eq!(agent_version, env!("CARGO_PKG_VERSION"));
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

        let link = start(&config(&url), "web-1", identity());
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
        let link = start(&config(&url), "web-1", agent);
        link.send_sample(sample()).unwrap();

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
            timeout: Duration::from_secs(5),
        };
        send_to_agent(&mut socket, &ask).await;

        let result = next_action_result(&mut socket).await;
        assert_eq!(result.id, "run-1");
        assert_eq!(result.outcome, ActionOutcome::Succeeded);
        assert_eq!(result.output, "hello web-1\n");
    }

    #[tokio::test]
    async fn says_what_its_clock_reads_as_soon_as_it_is_asked() {
        let (_link, mut socket) = connected().await;
        let before = maxnines_protocol::time::now();
        let ask = ServerMessage::AskTime {
            nonce: "question-1".to_string(),
        };
        send_to_agent(&mut socket, &ask).await;

        // Facts arrive whenever they're due, so they're skipped over.
        let (nonce, answered_at) = loop {
            if let AgentMessage::Time { nonce, answered_at } = next_message(&mut socket).await {
                break (nonce, answered_at);
            }
        };
        assert_eq!(nonce, "question-1");
        let after = maxnines_protocol::time::now();
        assert!((before..=after).contains(&answered_at), "{answered_at}");
    }

    #[tokio::test]
    async fn an_action_it_does_not_have_is_answered_without_running_anything() {
        let (_link, mut socket) = connected().await;
        let ask = ServerMessage::RunAction {
            id: "run-2".to_string(),
            action: "reboot".to_string(),
            variables: BTreeMap::new(),
            timeout: Duration::from_secs(5),
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

        link.report_config("v1", Some("broken".to_string()), Vec::new())
            .unwrap();
        assert_eq!(
            next_message(&mut socket).await,
            AgentMessage::ConfigResult {
                version: "v1".to_string(),
                error: Some("broken".to_string()),
                skipped_collectors: Vec::new(),
            }
        );
    }

    /// Only the newest of configs that come faster than they're applied is applied,
    /// and nothing the server sends meanwhile waits on them.
    #[tokio::test]
    async fn configs_that_come_quickly_leave_only_the_newest_waiting() {
        let (mut link, mut socket) = connected().await;
        for version in 1..=20 {
            let message = ServerMessage::Config {
                version: format!("v{version}"),
                config: serde_json::from_value(json!({})).unwrap(),
            };
            send_to_agent(&mut socket, &message).await;
        }
        // Still read, while none of them is applied.
        let ask = ServerMessage::AskTime {
            nonce: "after".to_string(),
        };
        send_to_agent(&mut socket, &ask).await;
        let answered = async {
            loop {
                if let AgentMessage::Time { nonce, .. } = next_message(&mut socket).await {
                    return nonce;
                }
            }
        };
        let answered = tokio::time::timeout(Duration::from_secs(10), answered).await;
        assert_eq!(answered.expect("the agent stopped reading"), "after");

        assert_eq!(link.next_config().await.unwrap().version, "v20");
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
    async fn a_config_is_passed_on_with_what_this_agent_does_not_know() {
        let (mut link, mut socket) = connected().await;

        let config = json!({
            "interval_secs": 9,
            "collectors": { "checks": { "checks": [
                { "name": "burrow", "kind": "gopher", "target": "gopher.example.com:70" },
            ] } },
            "from_a_newer_server": true,
        });
        let message = json!({ "type": "config", "version": "v1", "config": config });
        socket
            .send(Message::text(message.to_string()))
            .await
            .unwrap();

        let update = link.next_config().await.unwrap();
        assert_eq!(update.sent, config);
        let checks = update.config.collectors["checks"].checks.clone().unwrap();
        assert_eq!(checks[0].kind, maxnines_protocol::CheckKind::Unknown);
    }

    #[tokio::test]
    async fn a_message_from_a_newer_server_is_ignored() {
        let (mut link, mut socket) = connected().await;

        socket
            .send(Message::text(
                json!({ "type": "reboot_soon", "at": "later" }).to_string(),
            ))
            .await
            .unwrap();
        let message = ServerMessage::Config {
            version: "v1".to_string(),
            config: serde_json::from_value(json!({})).unwrap(),
        };
        send_to_agent(&mut socket, &message).await;

        assert_eq!(link.next_config().await.unwrap().version, "v1");
    }

    /// Plays a server that answers the hello with `replies`, and returns how one
    /// session of the agent's ended.
    async fn session_answered_with(replies: Vec<Value>) -> anyhow::Error {
        let challenge = json!({
            "type": "challenge",
            "nonce": "n",
            "protocols": maxnines_protocol::Protocols::SUPPORTED,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let (_link, connection) = {
            let config = config(&url);
            let trust = ServerTrust::read(&config).unwrap();
            ServerLink::new(&config, trust, "web-1", identity()).unwrap()
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            socket
                .send(Message::text(challenge.to_string()))
                .await
                .unwrap();
            socket.next().await.unwrap().unwrap();
            for reply in replies {
                socket.send(Message::text(reply.to_string())).await.unwrap();
            }
            // Held until the agent is done with it.
            socket.next().await;
        });
        let error = session(&connection).await.unwrap_err();
        server.await.unwrap();
        error
    }

    /// It isn't approval, so the agent tries again as it does while it waits, not as
    /// it does when it's refused.
    #[tokio::test]
    async fn a_status_from_a_newer_server_is_tried_again_soon() {
        let error = session_answered_with(vec![
            json!({ "type": "something_new" }),
            json!({ "type": "registration", "status": "quarantined" }),
        ])
        .await;

        assert!(error.downcast_ref::<Refused>().is_none(), "{error:#}");
        let error = format!("{error:#}");
        assert!(error.contains("status this agent doesn't know"), "{error}");
        assert!(error.contains("may need upgrading"), "{error}");
    }

    #[tokio::test]
    async fn a_refusal_ends_the_session_with_the_servers_reason() {
        let reason = "This agent (version 0.1.0, protocol 1) is too old. Upgrade the agent.";
        let error =
            session_answered_with(vec![json!({ "type": "refused", "reason": reason })]).await;

        let refused = error.downcast_ref::<Refused>().expect("a refusal");
        assert_eq!(refused.0, reason);
        assert_eq!(
            format!("{error:#}"),
            format!("the server refused this agent: {reason}")
        );
    }

    #[test]
    fn a_refusal_is_told_in_full_once_until_something_changes() {
        let mut refusals = Refusals::default();
        let too_old = Refused("This agent is too old. Upgrade it.".to_string());
        let other = Refused("Something else.".to_string());
        let wait = Duration::from_secs(400);

        let first = refusals.line(&too_old, wait);
        assert_eq!(
            first,
            "the server refused this agent: This agent is too old. Upgrade it. Trying again \
             in 7 minutes."
        );
        assert!(!refusals.line(&too_old, wait).contains("too old"));
        assert!(refusals.line(&other, wait).contains("Something else."));
        assert!(!refusals.line(&other, wait).contains("Something else."));
        refusals.clear();
        assert!(refusals.line(&other, wait).contains("Something else."));
    }

    /// Long, as only an upgrade helps, and spread out, so a fleet refused together
    /// doesn't come back together.
    #[test]
    fn a_refusal_waits_long_and_spread_out() {
        let mut refusals = Refusals::default();
        let refused = Refused("No.".to_string());
        assert_eq!(refusals.refused(&refused, 1.0), Duration::from_secs(600));
        assert_eq!(refusals.refused(&refused, 0.0), Duration::from_secs(300));
        assert_eq!(refusals.refused(&refused, 0.5), Duration::from_secs(450));
        assert!(REFUSED_WAIT / 2 > Backoff::MAX * 5);
    }

    #[tokio::test]
    async fn holds_samples_back_until_approved() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("ws://{address}/ws");

        let link = start(&config(&url), "web-1", identity());
        link.send_sample(sample()).unwrap();

        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let challenge = ServerMessage::Challenge {
            nonce: "n".to_string(),
            protocols: maxnines_protocol::Protocols::SUPPORTED,
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
        let link = start(&config(&url), "web-1", identity());

        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        accept_agent(&mut socket, &url).await;
        next_message(&mut socket).await;
        drop(socket);
        until(|| !link.spool.is_online()).await;

        link.send_sample(sample()).unwrap();
        link.spool.flush().await;
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

        link.send_sample(sample()).unwrap();

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
        spool.set_online(true);
        let text = serde_json::to_string(&sample()).unwrap();
        spool.push(text.clone(), taken_at());
        let broken = futures_util::sink::unfold((), |(), _: Message| async {
            Err::<(), _>(std::io::Error::other("connection lost"))
        });
        let mut broken = std::pin::pin!(broken);

        assert!(send_next(&mut broken, &spool).await.is_err());
        spool.set_online(false);
        spool.flush().await;

        assert_eq!(spool.next().unwrap(), text.as_str());
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
        let link = start(&config(&url), "web-1", identity());
        let mut socket = reconnected(&listener, &url).await;

        link.send_sample(sample()).unwrap();
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
        let link = start(&config(&url), "web-1", identity());
        let mut socket = reconnected(&listener, &url).await;

        link.send_sample(sample()).unwrap();
        next_message(&mut socket).await;
        let ack = ServerMessage::Ack { time: taken_at() };
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
        Spool::open(&settings.sample_queue_folder()).push(saved, taken_at());

        let _link = start(&settings, "web-1", identity());

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
    async fn a_result_waiting_when_the_connection_went_goes_on_the_next() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let link = start(&config(&url), "web-1", identity());
        let socket = reconnected(&listener, &url).await;
        drop(socket);
        until(|| !link.spool.is_online()).await;

        // Many at once, more than were ever kept before.
        for version in 0..20 {
            link.report_config(&format!("v{version}"), None, Vec::new())
                .unwrap();
        }

        let mut socket = reconnected(&listener, &url).await;
        for version in 0..20 {
            assert_eq!(
                next_message(&mut socket).await,
                AgentMessage::ConfigResult {
                    version: format!("v{version}"),
                    error: None,
                    skipped_collectors: Vec::new(),
                }
            );
        }
    }

    #[test]
    fn a_result_stays_until_it_has_gone() {
        let outbox = Outbox::default();
        outbox.push("first".to_string());
        outbox.push("second".to_string());
        let next = || futures_util::FutureExt::now_or_never(outbox.next()).unwrap();

        // Taken but never sent, as when the connection drops while sending.
        assert_eq!(next(), "first");
        assert_eq!(next(), "first");
        outbox.sent();
        assert_eq!(next(), "second");
    }

    /// On a paused clock, so the limit passes as soon as nothing else can happen.
    #[tokio::test(start_paused = true)]
    async fn a_send_the_server_never_takes_is_given_up_on() {
        let stalled = futures_util::sink::unfold((), |(), _: Message| async {
            std::future::pending::<Result<(), std::io::Error>>().await
        });
        let mut stalled = std::pin::pin!(stalled);
        let started = Instant::now();

        let error = send(&mut stalled, "sample").await.unwrap_err();

        assert_eq!(started.elapsed(), SEND_LIMIT);
        assert!(format!("{error:#}").contains("stopped taking"), "{error:#}");
    }

    #[tokio::test]
    async fn the_same_facts_interval_again_changes_nothing() {
        let (link, _socket) = connected().await;
        let watching = link.facts_every.subscribe();
        link.set_facts_interval(DEFAULT_FACTS_INTERVAL);
        assert!(!watching.has_changed().unwrap());
        link.set_facts_interval(Duration::from_secs(60));
        assert!(watching.has_changed().unwrap());
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
