use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ipnet::IpNet;
use maxnines_protocol::actions::ActionResult;
use maxnines_protocol::{
    AgentMessage, ProtocolFit, Protocols, RegistrationStatus, ServerMessage, auth,
};
use serde_json::Value;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::{Instant, MissedTickBehavior, interval, interval_at, timeout};
use tracing::{debug, info, warn};

use crate::actions::Actions;
use crate::agent_versions::NEWEST_AGENT_VERSION;
use crate::app_state::AppState;
use crate::clock::Asked;
use crate::events::{BOOT_TIME_SLACK, EventKind, restarted};
use crate::facts::flatten;
use crate::models::ConfigStatus;
use crate::presence::Presence;
use crate::registration::Admission;
use crate::store::{NewSample, WriterCommand, can_store};
use crate::times::{self, Timestamp};

/// Far more than real facts need, so one agent can't fill the database.
const MAX_FACTS_LEN: usize = 64 * 1024;

/// The most a single message from an agent can be. Facts are limited well below
/// this, and a sample from even a large host is a few hundred KiB, so anything
/// bigger is a mistake or an attack, and a connection sending one is closed before
/// the server holds the whole of it in memory.
const MAX_MESSAGE_LEN: usize = 1024 * 1024;
/// What the database column holds.
const MAX_VERSION_LEN: usize = 32;
/// Longer than any real version, which is a version number and perhaps a little after it.
const MAX_AGENT_VERSION_LEN: usize = 64;
/// Plenty to explain a problem, without letting an agent store anything it likes.
const MAX_ERROR_LEN: usize = 1000;
/// Bigger than most messages, and they can still be larger than this. A busy server
/// holds thousands of these, and the default of 128 KB each way adds up to gigabytes.
const SOCKET_BUFFER_SIZE: usize = 8 * 1024;
/// Facts and config results waiting on the database, for one agent. It sends few of
/// them, so this only fills up if the database has stalled or an agent misbehaves.
const JOB_QUEUE_SIZE: usize = 8;
/// More than an agent has waiting at once. A missed one only means a sample is sent
/// twice.
const ACK_QUEUE_SIZE: usize = 128;

pub async fn upgrade(
    socket: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let source = super::request_source(&state, peer, &headers);
    socket
        .read_buffer_size(SOCKET_BUFFER_SIZE)
        .write_buffer_size(SOCKET_BUFFER_SIZE)
        .max_message_size(MAX_MESSAGE_LEN)
        .max_frame_size(MAX_MESSAGE_LEN)
        .on_upgrade(move |socket| handle(socket, source, state))
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
    hostname: String,
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

/// Stops actions being asked of a connection that has ended, however it ends.
struct ActionsGuard<'a> {
    actions: &'a Actions,
    id: &'a str,
    connection: u64,
}

impl Drop for ActionsGuard<'_> {
    fn drop(&mut self) {
        self.actions.disconnected(self.id, self.connection);
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
            hostname = agent.hostname,
            "agent is already online, two hosts may be sharing a key"
        );
    }
    let _online = OnlineGuard {
        presence: &state.presence,
        id: &agent.id,
        connection: connected.connection,
    };
    info!(id = agent.id, hostname = agent.hostname, %source, "agent online");

    let reason = serve(&mut socket, agent.clone(), &state, &connected.replaced).await;
    info!(
        id = agent.id,
        hostname = agent.hostname,
        reason,
        "agent offline"
    );
}

/// Challenges the agent and returns it if it is approved. Anything else ends
/// the connection, including for pending agents, which try again later.
async fn authenticate(
    socket: &mut WebSocket,
    source: IpAddr,
    state: &AppState,
) -> Result<Option<Arc<Agent>>> {
    let nonce = auth::new_nonce()?;
    let challenge = ServerMessage::Challenge {
        nonce: nonce.clone(),
        protocols: Protocols::SUPPORTED,
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
        hostname,
        public_key,
        signature,
        token,
        protocol,
        agent_version,
    } = serde_json::from_str(&text).context("invalid hello")?
    else {
        bail!("expected hello");
    };

    let hostname = crate::registration::checked_hostname(&hostname)
        .context("the agent's hostname won't do")?;
    ensure!(
        agent_version.len() <= MAX_AGENT_VERSION_LEN
            && !agent_version.chars().any(char::is_control),
        "the agent's version won't do"
    );

    let id = match auth::verify(&public_key, &state.audience, &nonce, &signature) {
        Ok(id) => id,
        Err(error) => {
            send_status(socket, RegistrationStatus::Rejected).await.ok();
            return Err(error.context("agent failed authentication"));
        }
    };

    let mut status = state
        .registry
        .admit(&Admission {
            id: &id,
            public_key: &public_key,
            hostname: &hostname,
            source,
            token: token.as_deref(),
        })
        .await?;
    // A revoked agent is told no more than that.
    if status != RegistrationStatus::Rejected
        && let Some(reason) = refusal(protocol, &agent_version)
    {
        let supported = Protocols::SUPPORTED;
        warn!(
            id,
            hostname,
            agent_protocol = protocol,
            agent_version,
            oldest_protocol = supported.oldest,
            newest_protocol = supported.newest,
            "turned away an agent that speaks a protocol this server doesn't take"
        );
        send(socket, &ServerMessage::Refused { reason }).await?;
        return Ok(None);
    }
    // Told to wait, as an agent is after any other refusal, rather than let one
    // key open connections as fast as it likes.
    if status == RegistrationStatus::Approved && !state.presence.allow_connection(&id) {
        warn!(id, hostname, %source, "agent is connecting too often, telling it to wait");
        status = RegistrationStatus::Pending;
    }
    send_status(socket, status).await?;

    Ok((status == RegistrationStatus::Approved).then(|| Arc::new(Agent { id, hostname })))
}

/// Why an agent that speaks `protocol` is turned away, if it is, in words for whoever
/// runs it.
pub fn refusal(protocol: u32, agent_version: &str) -> Option<String> {
    let supported = Protocols::SUPPORTED;
    let agent = match agent_version {
        "" => "from before protocol versions".to_string(),
        version => format!("version {version}, protocol {protocol}"),
    };
    let server = env!("CARGO_PKG_VERSION");
    let takes = supported.describe();
    match supported.fit(protocol) {
        ProtocolFit::Supported => None,
        ProtocolFit::TooOld => Some(format!(
            "This agent ({agent}) is too old for this server (version {server}), which takes \
             agent {takes}. Upgrade the agent to {NEWEST_AGENT_VERSION}."
        )),
        ProtocolFit::TooNew => Some(format!(
            "This agent ({agent}) is newer than this server (version {server}), which takes \
             agent {takes}. Upgrade the server first."
        )),
    }
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

/// Work for the main database, which has to wait its turn without holding up samples.
enum Job {
    Facts(Value),
    /// How an action the server asked for went.
    ActionResult(ActionResult),
    ConfigResult {
        version: String,
        error: Option<String>,
        skipped_collectors: Vec<String>,
    },
    /// When the host started, as a sample said.
    Boot(Timestamp),
}

/// Reads from the agent and pings it until the connection ends, returning why.
/// Any message counts as a sign of life, not just pongs.
///
/// This loop never waits on a database. Samples go straight to the writer, and
/// everything else goes to [`do_jobs`], which is its own task so that a query is never
/// abandoned half way when the connection ends. When the writer's queue is full
/// reading stops, so that agents slow down, but heartbeats carry on.
async fn serve(
    socket: &mut WebSocket,
    agent: Arc<Agent>,
    state: &AppState,
    replaced: &Notify,
) -> &'static str {
    let mut ping = interval(state.heartbeat.interval);
    // After a stall, one ping goes at once, not one for each that was missed.
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_heard = Instant::now();
    let mut waiting_sample = None;
    let mut last_boot = None;
    let mut ask_time = interval_at(
        Instant::now() + state.heartbeat.clock_every,
        state.heartbeat.clock_every,
    );
    ask_time.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut asked = None;

    let (jobs, job_queue) = mpsc::channel(JOB_QUEUE_SIZE);
    let (config_sender, mut configs) = mpsc::channel(1);
    let (ack_sender, mut acks) = mpsc::channel(ACK_QUEUE_SIZE);
    let (action_link, mut action_requests) = state.actions.connected(&agent.id);
    let _actions = ActionsGuard {
        actions: &state.actions,
        id: &agent.id,
        connection: action_link,
    };
    let mut work = tokio::spawn(do_jobs(
        job_queue,
        config_sender,
        agent.clone(),
        state.clone(),
    ));

    loop {
        tokio::select! {
            reason = &mut work => return reason.unwrap_or("database work failed"),
            () = replaced.notified() => return "replaced by a newer connection",
            due = ping.tick() => {
                // A ping this late means this server was too busy to run, not that
                // the agent went quiet, and what it sent is still waiting to be read.
                // The agent gets its whole time again.
                if due.elapsed() > state.heartbeat.interval {
                    last_heard = Instant::now();
                }
                // Nothing is being read while a sample waits, so silence means nothing.
                if waiting_sample.is_none() && last_heard.elapsed() >= state.heartbeat.timeout {
                    return "heartbeat timeout";
                }
                if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    return "send failed";
                }
            }
            _ = ask_time.tick() => {
                let Ok(nonce) = auth::new_nonce() else {
                    continue;
                };
                // Timed from before it's sent, so a slow send counts against it.
                let question = Asked::new(nonce.clone(), times::now());
                if send(socket, &ServerMessage::AskTime { nonce }).await.is_err() {
                    return "send failed";
                }
                asked = Some(question);
            }
            Some(text) = configs.recv() => {
                if socket.send(Message::text(text)).await.is_err() {
                    return "send failed";
                }
            }
            Some(text) = action_requests.recv() => {
                if socket.send(Message::text(text)).await.is_err() {
                    return "send failed";
                }
            }
            Some(time) = acks.recv() => {
                if send(socket, &ServerMessage::Ack { time }).await.is_err() {
                    return "send failed";
                }
            }
            reserved = state.writer.reserve(), if waiting_sample.is_some() => {
                last_heard = Instant::now();
                match (reserved, waiting_sample.take()) {
                    (Ok(permit), Some(command)) => permit.send(command),
                    _ => warn!(id = agent.id, "writer stopped, sample dropped"),
                }
            }
            message = socket.recv(), if waiting_sample.is_none() => {
                last_heard = Instant::now();
                state.presence.seen(&agent.id);

                match message {
                    Some(Ok(Message::Text(text))) => {
                        let mut connection = Connection {
                            jobs: &jobs,
                            acks: &ack_sender,
                            last_boot: &mut last_boot,
                            asked: &mut asked,
                            time_came_late: false,
                        };
                        waiting_sample = receive(&text, &agent, state, &mut connection);
                        // Asked for again soon, not a whole turn later.
                        if connection.time_came_late {
                            let soon = state.heartbeat.interval.min(state.heartbeat.clock_every);
                            ask_time.reset_after(soon);
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return "connection closed",
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return "connection lost",
                }
            }
        }
    }
}

/// Everything about a connection that waits on the main database, one job at a time,
/// which keeps a config from being worked out before the facts it depends on are in.
/// Returns why the connection should end.
async fn do_jobs(
    mut jobs: mpsc::Receiver<Job>,
    configs: mpsc::Sender<String>,
    agent: Arc<Agent>,
    state: AppState,
) -> &'static str {
    let (agent, state) = (agent.as_ref(), &state);
    let mut changes = state.registry.subscribe();
    let mut config_changes = state.configs.subscribe();
    let mut sent_version = None;
    let mut known_boot = None;

    send_config(&configs, agent, state, &mut sent_version).await;
    loop {
        tokio::select! {
            Ok(()) = changes.changed() => {
                if !state.registry.is_approved(&agent.id).await {
                    return "revoked";
                }
            }
            Ok(()) = config_changes.changed() => {
                send_config(&configs, agent, state, &mut sent_version).await;
            }
            job = jobs.recv() => match job {
                Some(Job::Facts(facts)) => {
                    if save_facts(facts, agent, state).await {
                        send_config(&configs, agent, state, &mut sent_version).await;
                    }
                }
                Some(Job::ConfigResult { version, error, skipped_collectors }) => {
                    if !skipped_collectors.is_empty() {
                        warn!(
                            id = agent.id,
                            version,
                            skipped = skipped_collectors.join(", "),
                            "agent doesn't know these collectors, and runs the rest of its config"
                        );
                    }
                    save_config_result(version, error, agent, state).await;
                }
                Some(Job::Boot(booted_at)) => {
                    save_boot(booted_at, agent, state, &mut known_boot).await;
                }
                Some(Job::ActionResult(result)) => {
                    let saved = state.actions.finished(&agent.id, result, times::now());
                    if let Err(error) = saved.await {
                        warn!(id = agent.id, error = format!("{error:#}"), "saving an action's result failed");
                    }
                }
                None => return "connection closed",
            }
        }
    }
}

/// Sends the agent its config if it's different from what it was last sent. If it
/// can't be worked out, the agent keeps what it has, and it's tried again on the next
/// change.
async fn send_config(
    configs: &mpsc::Sender<String>,
    agent: &Agent,
    state: &AppState,
    sent_version: &mut Option<String>,
) {
    let resolved = match state.config_for(&agent.id).await {
        Ok(resolved) => resolved,
        Err(error) => {
            warn!(
                id = agent.id,
                error = format!("{error:#}"),
                "working out config failed"
            );
            return;
        }
    };

    if sent_version.as_ref() == Some(&resolved.version) {
        return;
    }
    if !resolved.skipped_collectors.is_empty() {
        warn!(
            id = agent.id,
            skipped = resolved.skipped_collectors.join(", "),
            "agent doesn't support these collectors"
        );
    }

    let message = ServerMessage::Config {
        version: resolved.version.clone(),
        config: resolved.config,
    };
    match serde_json::to_string(&message) {
        Ok(text) => {
            if configs.send(text).await.is_ok() {
                *sent_version = Some(resolved.version);
            }
        }
        Err(error) => warn!(id = agent.id, %error, "encoding config failed"),
    }
}

/// What one connection keeps between messages.
struct Connection<'a> {
    jobs: &'a mpsc::Sender<Job>,
    acks: &'a mpsc::Sender<Timestamp>,
    last_boot: &'a mut Option<Timestamp>,
    /// The question about its clock that the agent hasn't answered yet.
    asked: &'a mut Option<Asked>,
    /// Set when its answer took too long to use.
    time_came_late: bool,
}

/// A bad message is logged and skipped rather than ending the connection. Returns a
/// sample the writer has no room for yet.
fn receive(
    text: &str,
    agent: &Agent,
    state: &AppState,
    connection: &mut Connection,
) -> Option<WriterCommand> {
    let Connection {
        jobs,
        acks,
        last_boot,
        asked,
        time_came_late,
    } = connection;
    let job = match serde_json::from_str(text) {
        Ok(AgentMessage::Time { nonce, answered_at }) => {
            *time_came_late = !save_time(&nonce, answered_at, agent, state, asked);
            return None;
        }
        Ok(AgentMessage::Sample(sample)) if !can_store(sample.time) => {
            // Answered, so the agent lets go of something that can never be stored.
            warn!(id = agent.id, "skipping a sample with an impossible time");
            acks.try_send(sample.time).ok();
            return None;
        }
        Ok(AgentMessage::Sample(sample)) => {
            note_boot(&sample, agent, jobs, last_boot);
            let command = WriterCommand::SaveAndAck {
                sample: NewSample {
                    host_id: agent.id.clone(),
                    hostname: agent.hostname.clone(),
                    sample,
                },
                acks: acks.clone(),
            };
            return match state.writer.try_send(command) {
                Ok(()) => None,
                Err(TrySendError::Full(command)) => Some(command),
                Err(TrySendError::Closed(_)) => {
                    warn!(id = agent.id, "writer stopped, sample dropped");
                    None
                }
            };
        }
        Ok(AgentMessage::Facts { .. }) if text.len() > MAX_FACTS_LEN => {
            warn!(id = agent.id, size = text.len(), "skipping oversized facts");
            return None;
        }
        Ok(AgentMessage::Facts { .. }) if !state.presence.allow_facts(&agent.id) => {
            warn!(id = agent.id, "facts reported too often, skipping");
            return None;
        }
        Ok(AgentMessage::Facts { facts }) => Job::Facts(facts),
        Ok(AgentMessage::ConfigResult {
            version,
            error,
            skipped_collectors,
        }) => Job::ConfigResult {
            version,
            error,
            skipped_collectors,
        },
        Ok(AgentMessage::Hello { .. }) => {
            warn!(id = agent.id, "ignoring repeated hello");
            return None;
        }
        Ok(AgentMessage::ActionResult(result)) => Job::ActionResult(result),
        Ok(AgentMessage::Unknown) => {
            debug!(id = agent.id, "ignoring a message from a newer agent");
            return None;
        }
        Err(error) => {
            warn!(id = agent.id, %error, "skipping invalid message");
            return None;
        }
    };
    // Agents report facts again later, and a config result again with the next config.
    if jobs.try_send(job).is_err() {
        warn!(
            id = agent.id,
            "too much waiting on the database, skipping a report"
        );
    }
    None
}

/// Saves how the host's clock compares with the server's, if this answers the
/// question that's waiting. Any other answer is ignored. Returns false only for
/// the right answer taking too long to use.
fn save_time(
    nonce: &str,
    answered_at: Timestamp,
    agent: &Agent,
    state: &AppState,
    asked: &mut Option<Asked>,
) -> bool {
    let Some(question) = asked.take_if(|question| question.nonce == nonce) else {
        return true;
    };
    let Some(reading) = question.answered(nonce, answered_at) else {
        return false;
    };
    let sample = reading.sample(&agent.id, &agent.hostname, times::now());
    // The next one is a minute away, so one the writer has no room for is let go.
    if state.writer.try_send(WriterCommand::Save(sample)).is_err() {
        warn!(
            id = agent.id,
            "no room to save a clock reading, skipping it"
        );
    }
    true
}

/// Passes on when the host started, only when it's a later start than this
/// connection has already passed on. An agent sends samples it kept from before a
/// restart after its live ones, and those mustn't look like another restart.
fn note_boot(
    sample: &maxnines_protocol::Sample,
    agent: &Agent,
    jobs: &mpsc::Sender<Job>,
    last_boot: &mut Option<Timestamp>,
) {
    let Some(booted_at) = sample
        .metrics
        .get("host")
        .and_then(|output| output.get("booted_at"))
        .and_then(Value::as_str)
        .and_then(times::parse_moment)
    else {
        return;
    };
    let later = last_boot.is_none_or(|known| booted_at > known + BOOT_TIME_SLACK);
    if later && jobs.try_send(Job::Boot(booted_at)).is_ok() {
        *last_boot = Some(booted_at);
    } else if later {
        warn!(
            id = agent.id,
            "too much waiting on the database, skipping a boot time"
        );
    }
}

/// Notes when the host started, and marks a restart when it's later than the start
/// the server last knew of. `known` is loaded the first time.
async fn save_boot(
    booted_at: Timestamp,
    agent: &Agent,
    state: &AppState,
    known: &mut Option<Option<Timestamp>>,
) {
    let previous = match known {
        Some(previous) => *previous,
        None => match state.database.boot_time(&agent.id).await {
            Ok(previous) => previous,
            Err(error) => {
                warn!(
                    id = agent.id,
                    error = format!("{error:#}"),
                    "loading boot time failed"
                );
                return;
            }
        },
    };
    let restarted =
        restarted(previous, booted_at) && previous.is_some_and(|known| booted_at > known);
    if previous.is_some() && !restarted {
        *known = Some(previous);
        return;
    }
    match state
        .database
        .save_boot_time(&agent.id, booted_at, restarted, times::now())
        .await
    {
        Ok(()) => *known = Some(Some(booted_at)),
        Err(error) => warn!(
            id = agent.id,
            error = format!("{error:#}"),
            "saving boot time failed"
        ),
    }
}

async fn save_config_result(
    version: String,
    error: Option<String>,
    agent: &Agent,
    state: &AppState,
) {
    if let Some(error) = &error {
        warn!(id = agent.id, version, error, "agent rejected its config");
    }
    if version.len() > MAX_VERSION_LEN {
        warn!(id = agent.id, "skipping an oversized config version");
        return;
    }

    // A config that took over from a different one is a change worth marking. The first
    // an agent ever applies isn't, and nor is one it turned down.
    let changed = match state.database.config_status(&agent.id).await {
        Ok(previous) => {
            error.is_none() && previous.is_some_and(|previous| previous.version != version)
        }
        Err(error) => {
            warn!(
                id = agent.id,
                error = format!("{error:#}"),
                "loading config status failed"
            );
            false
        }
    };
    let status = ConfigStatus {
        version,
        error: error.map(|error| error.chars().take(MAX_ERROR_LEN).collect()),
        reported_at: crate::times::now(),
    };
    if let Err(error) = state.database.save_config_status(&agent.id, &status).await {
        warn!(
            id = agent.id,
            error = format!("{error:#}"),
            "saving config status failed"
        );
        return;
    }
    if changed {
        record_config_change(agent, state, status.reported_at).await;
    }
}

/// Marks a new config on the host's charts, saying which rules it came from.
async fn record_config_change(agent: &Agent, state: &AppState, now: Timestamp) {
    let rules = match state.config_for(&agent.id).await {
        Ok(resolved) => Some(format!(
            "From rules: {}.",
            resolved.matched_rules.join(", ")
        )),
        Err(_) => None,
    };
    let saved = state
        .database
        .record_server_event(
            EventKind::Config,
            &agent.id,
            now,
            "Config changed",
            rules.as_deref(),
            now,
        )
        .await;
    if let Err(error) = saved {
        warn!(
            id = agent.id,
            error = format!("{error:#}"),
            "recording a config change failed"
        );
    }
}

/// Failing to save loses nothing, because the agent reports again later.
/// Returns whether anything changed.
async fn save_facts(facts: Value, agent: &Agent, state: &AppState) -> bool {
    let facts = match flatten(&facts) {
        Ok(facts) => facts,
        Err(error) => {
            warn!(
                id = agent.id,
                error = format!("{error:#}"),
                "skipping invalid facts"
            );
            return false;
        }
    };

    match state
        .database
        .record_facts(&agent.id, &facts, times::now())
        .await
    {
        Ok(true) => {
            info!(id = agent.id, hostname = agent.hostname, "facts changed");
            true
        }
        Ok(false) => false,
        Err(error) => {
            warn!(
                id = agent.id,
                error = format!("{error:#}"),
                "saving facts failed"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use maxnines_protocol::PROTOCOL_VERSION;

    use super::*;

    #[test]
    fn an_agent_is_told_which_side_to_upgrade() {
        assert_eq!(refusal(PROTOCOL_VERSION, "1.0.0"), None);

        let server = env!("CARGO_PKG_VERSION");
        let old = refusal(0, "").unwrap();
        assert_eq!(
            old,
            format!(
                "This agent (from before protocol versions) is too old for this server \
                 (version {server}), which takes agent {}. Upgrade the agent to {server}.",
                Protocols::SUPPORTED.describe()
            )
        );
        let newer = PROTOCOL_VERSION + 1;
        let new = refusal(newer, "9.0.0").unwrap();
        assert_eq!(
            new,
            format!(
                "This agent (version 9.0.0, protocol {newer}) is newer than this server \
                 (version {server}), which takes agent {}. Upgrade the server first.",
                Protocols::SUPPORTED.describe()
            )
        );
    }

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
