//! The simulated agents. Each holds a connection and behaves as a real one does: the
//! same handshake, a sample on a timer that starts at a random point, live samples
//! ahead of saved ones, and the same retry timing after losing the connection.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::{AgentMessage, Backoff, RegistrationStatus, Sample, ServerMessage};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{
    Instant, Interval, MissedTickBehavior, interval_at, sleep, sleep_until, timeout,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::sample::{Readings, Shape, facts};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);

/// What every agent adds to.
#[derive(Default)]
pub struct Counters {
    pub online: AtomicU64,
    pub attempts: AtomicU64,
    pub connected: AtomicU64,
    pub lost: AtomicU64,
    pub live_samples: AtomicU64,
    pub saved_samples: AtomicU64,
    pub bytes: AtomicU64,
    pub configs: AtomicU64,
    /// How long connecting took, from opening the socket to having a config.
    pub connect_times: Mutex<Vec<Duration>>,
    pub errors: Mutex<BTreeMap<String, u64>>,
}

impl Counters {
    pub fn samples(&self) -> u64 {
        self.live_samples.load(Relaxed) + self.saved_samples.load(Relaxed)
    }

    fn failed(&self, error: String) {
        let mut errors = self.errors.lock().unwrap_or_else(PoisonError::into_inner);
        *errors.entry(error).or_default() += 1;
    }
}

/// What all agents share.
pub struct Plan {
    pub url: String,
    pub interval: Duration,
    pub shape: Shape,
    pub backlog: usize,
    pub backlog_gap: Duration,
    pub churn_percent: f64,
    pub facts_every: Duration,
    pub fact_change_percent: f64,
    pub hot_percent: f64,
    pub counters: Counters,
}

/// Ways for a session to end.
enum End {
    Stopped,
    Outage,
    Churn,
    Failed(String),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn chance(percent: f64) -> bool {
    rand::random::<f64>() * 100.0 < percent
}

/// When an agent next reconnects. Each is independent, at the average rate asked for.
fn next_churn(percent_per_minute: f64) -> Option<Instant> {
    (percent_per_minute > 0.0).then(|| {
        let average_secs = 60.0 / (percent_per_minute / 100.0);
        let wait = -rand::random::<f64>().max(f64::MIN_POSITIVE).ln() * average_secs;
        Instant::now() + Duration::from_secs_f64(wait)
    })
}

async fn read(socket: &mut Socket) -> Option<ServerMessage> {
    loop {
        match socket.next().await? {
            Ok(Message::Text(text)) => return serde_json::from_str(&text).ok(),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

/// Answers the server's challenge, as far as the registration status.
async fn introduce(
    socket: &mut Socket,
    identity: &Identity,
    host: &str,
    url: &str,
) -> Result<RegistrationStatus> {
    let Some(ServerMessage::Challenge { nonce }) = read(socket).await else {
        bail!("no challenge from the server");
    };
    let hello = AgentMessage::Hello {
        host: host.to_string(),
        public_key: identity.public_key(),
        signature: identity.sign(url, &nonce),
        token: None,
    };
    socket
        .send(Message::text(serde_json::to_string(&hello)?))
        .await?;
    match read(socket).await {
        Some(ServerMessage::Registration { status }) => Ok(status),
        _ => bail!("no registration status from the server"),
    }
}

/// Connects once, so the server knows about an agent and it can be approved.
pub async fn register(url: &str, identity: &Identity, host: &str) -> Result<RegistrationStatus> {
    let (mut socket, _) = connect_async(url)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    timeout(HANDSHAKE_LIMIT, introduce(&mut socket, identity, host, url))
        .await
        .context("the server didn't finish the handshake")?
}

/// A sample that's yet to reach the server.
#[derive(Clone, Copy)]
struct Waiting {
    taken_at: u64,
    /// Going again because the connection ended before it was confirmed, so it's
    /// already been counted.
    resend: bool,
}

impl Waiting {
    fn new(taken_at: u64) -> Self {
        Self {
            taken_at,
            resend: false,
        }
    }
}

pub struct SimulatedAgent {
    index: usize,
    identity: Identity,
    host: String,
    readings: Readings,
    ticker: Interval,
    last_sample: Instant,
    /// Samples to send from before, oldest first.
    saved: VecDeque<Waiting>,
    next_saved: Instant,
    /// When samples the server hasn't confirmed yet were taken.
    unconfirmed: Vec<u64>,
    /// The saved one on its way, as they go one at a time.
    saved_unconfirmed: Option<u64>,
    next_churn: Option<Instant>,
    build: u64,
}

impl SimulatedAgent {
    pub fn new(index: usize, identity: Identity, host: String, plan: &Plan) -> Self {
        let first = Instant::now() + plan.interval.mul_f64(rand::random());
        let mut ticker = interval_at(first, plan.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let shape: Shape = plan.shape;
        let interval_ms = plan.interval.as_millis() as u64;
        let started = now_ms();
        Self {
            index,
            identity,
            host,
            readings: Readings::new(shape, chance(plan.hot_percent)),
            ticker,
            last_sample: Instant::now(),
            saved: (0..plan.backlog as u64)
                .rev()
                .map(|age| Waiting::new(started.saturating_sub((age + 1) * interval_ms)))
                .collect(),
            next_saved: Instant::now(),
            unconfirmed: Vec::new(),
            saved_unconfirmed: None,
            next_churn: next_churn(plan.churn_percent),
            build: 0,
        }
    }

    fn sample_text(&mut self, timestamp_ms: u64) -> Result<String> {
        let elapsed = self.last_sample.elapsed().as_secs();
        self.last_sample = Instant::now();
        let metrics = self.readings.metrics(elapsed);
        let sample = AgentMessage::Sample(Sample {
            timestamp_ms,
            metrics,
        });
        Ok(serde_json::to_string(&sample)?)
    }

    fn facts_text(&self) -> Result<String> {
        let facts = facts(self.index, &self.host, self.build);
        Ok(serde_json::to_string(&AgentMessage::Facts { facts })?)
    }

    /// What a real agent does on losing a connection.
    fn requeue_unconfirmed(&mut self) {
        let saved = self.saved_unconfirmed.take();
        let live = self.unconfirmed.drain(..);
        for taken_at in saved.into_iter().chain(live) {
            self.saved.push_back(Waiting {
                taken_at,
                resend: true,
            });
        }
    }

    async fn serve(
        &mut self,
        socket: &mut Socket,
        plan: &Plan,
        began: Instant,
        stop: &mut watch::Receiver<bool>,
        outage: &mut watch::Receiver<bool>,
    ) -> Result<End> {
        let counters = &plan.counters;
        let mut timed = false;
        socket.send(Message::text(self.facts_text()?)).await?;
        let mut facts_timer = interval_at(Instant::now() + plan.facts_every, plan.facts_every);

        loop {
            let saved_due = !self.saved.is_empty() && self.saved_unconfirmed.is_none();
            let churn = self.next_churn;
            tokio::select! {
                _ = stop.changed() => return Ok(End::Stopped),
                _ = outage.changed() => {
                    if *outage.borrow() {
                        return Ok(End::Outage);
                    }
                }
                () = sleep_until(churn.unwrap_or_else(Instant::now)), if churn.is_some() => {
                    self.next_churn = next_churn(plan.churn_percent);
                    return Ok(End::Churn);
                }
                _ = self.ticker.tick() => {
                    let taken_at = now_ms();
                    let text = self.sample_text(taken_at)?;
                    counters.bytes.fetch_add(text.len() as u64, Relaxed);
                    self.unconfirmed.push(taken_at);
                    counters.live_samples.fetch_add(1, Relaxed);
                    socket.send(Message::text(text)).await?;
                }
                () = sleep_until(self.next_saved), if saved_due => {
                    if let Some(waiting) = self.saved.pop_front() {
                        let text = self.sample_text(waiting.taken_at)?;
                        counters.bytes.fetch_add(text.len() as u64, Relaxed);
                        self.saved_unconfirmed = Some(waiting.taken_at);
                        if !waiting.resend {
                            counters.saved_samples.fetch_add(1, Relaxed);
                        }
                        socket.send(Message::text(text)).await?;
                    }
                }
                _ = facts_timer.tick() => {
                    if chance(plan.fact_change_percent) {
                        self.build += 1;
                    }
                    socket.send(Message::text(self.facts_text()?)).await?;
                }
                message = socket.next() => match message {
                    Some(Ok(Message::Text(text))) => match serde_json::from_str(&text) {
                        Ok(ServerMessage::Ack { timestamp_ms }) => {
                            if self.saved_unconfirmed == Some(timestamp_ms) {
                                self.saved_unconfirmed = None;
                                self.next_saved = Instant::now() + plan.backlog_gap;
                            } else {
                                self.unconfirmed.retain(|time| *time != timestamp_ms);
                            }
                        }
                        Ok(ServerMessage::Config { version, .. }) => {
                            if !timed {
                                timed = true;
                                counters
                                    .connect_times
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .push(began.elapsed());
                            }
                            counters.configs.fetch_add(1, Relaxed);
                            let result = AgentMessage::ConfigResult { version, error: None };
                            socket
                                .send(Message::text(serde_json::to_string(&result)?))
                                .await?;
                        }
                        _ => {}
                    }
                    Some(Ok(Message::Close(_))) | None => bail!("the server closed the connection"),
                    Some(Err(error)) => bail!("the connection failed: {error}"),
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    async fn session(
        &mut self,
        plan: &Plan,
        stop: &mut watch::Receiver<bool>,
        outage: &mut watch::Receiver<bool>,
    ) -> End {
        let counters = &plan.counters;
        let began = Instant::now();
        counters.attempts.fetch_add(1, Relaxed);

        let connected = timeout(HANDSHAKE_LIMIT, async {
            let (mut socket, _) = connect_async(&plan.url).await?;
            let status = introduce(&mut socket, &self.identity, &self.host, &plan.url).await?;
            anyhow::Ok((socket, status))
        })
        .await;
        let mut socket = match connected {
            Ok(Ok((socket, RegistrationStatus::Approved))) => socket,
            Ok(Ok((_, status))) => return End::Failed(format!("the server said {status:?}")),
            Ok(Err(error)) => return End::Failed(format!("{error:#}")),
            Err(_) => return End::Failed("the handshake timed out".to_string()),
        };

        counters.connected.fetch_add(1, Relaxed);
        counters.online.fetch_add(1, Relaxed);
        let end = self.serve(&mut socket, plan, began, stop, outage).await;
        counters.online.fetch_sub(1, Relaxed);
        self.requeue_unconfirmed();
        match end {
            Ok(end) => end,
            Err(error) => {
                counters.lost.fetch_add(1, Relaxed);
                End::Failed(format!("{error:#}"))
            }
        }
    }

    /// Runs until stopped. Samples due while disconnected are saved for later.
    pub async fn run(
        mut self,
        plan: Arc<Plan>,
        start_after: Duration,
        mut stop: watch::Receiver<bool>,
        mut outage: watch::Receiver<bool>,
    ) {
        tokio::select! {
            () = sleep(start_after) => {}
            _ = stop.changed() => return,
        }

        let mut backoff = Backoff::new();
        loop {
            let tried = Instant::now();
            if !*outage.borrow() {
                match self.session(&plan, &mut stop, &mut outage).await {
                    End::Stopped => return,
                    End::Outage => {}
                    End::Churn => backoff.reset(),
                    End::Failed(error) => plan.counters.failed(error),
                }
            }
            if tried.elapsed() > Backoff::MAX {
                backoff.reset();
            }

            let retry = Instant::now() + backoff.next_wait(rand::random());
            loop {
                tokio::select! {
                    () = sleep_until(retry) => break,
                    _ = self.ticker.tick() => self.saved.push_back(Waiting::new(now_ms())),
                    _ = stop.changed() => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn churn_averages_out_to_the_rate_asked_for() {
        let now = Instant::now();
        let count = 5000;
        let total: f64 = (0..count)
            .map(|_| (next_churn(10.0).unwrap() - now).as_secs_f64())
            .sum();

        let average = total / f64::from(count);

        assert!((500.0..700.0).contains(&average), "{average}");
    }

    #[test]
    fn no_churn_means_no_reconnecting() {
        assert!(next_churn(0.0).is_none());
    }

    #[test]
    fn chance_follows_the_percentage() {
        assert!(!chance(0.0));
        assert!(chance(100.0));
    }

    #[tokio::test]
    async fn a_starting_backlog_goes_back_in_time_oldest_first() {
        let plan = Plan {
            url: String::new(),
            interval: Duration::from_secs(15),
            shape: Shape {
                cores: 1,
                disks: 1,
                interfaces: 1,
            },
            backlog: 3,
            backlog_gap: Duration::from_secs(1),
            churn_percent: 0.0,
            facts_every: Duration::from_secs(3600),
            fact_change_percent: 0.0,
            hot_percent: 0.0,
            counters: Counters::default(),
        };
        let identity = Identity::from_pkcs8(&Identity::generate().unwrap()).unwrap();

        let agent = SimulatedAgent::new(0, identity, "h".to_string(), &plan);

        let saved: Vec<u64> = agent.saved.iter().map(|sample| sample.taken_at).collect();
        assert_eq!(saved.len(), 3);
        assert_eq!(saved[1] - saved[0], 15_000);
        assert!(saved[2] < now_ms());
    }

    #[test]
    fn errors_are_counted_by_what_went_wrong() {
        let counters = Counters::default();
        counters.failed("a".to_string());
        counters.failed("a".to_string());
        counters.failed("b".to_string());

        let errors = counters.errors.lock().unwrap();
        assert_eq!(errors["a"], 2);
        assert_eq!(errors["b"], 1);
    }
}
