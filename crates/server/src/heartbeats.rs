//! Heartbeat checks, for scheduled work no outward check can see, such as a cron job
//! or a backup. The work pings an address of its own on the server when it finishes,
//! and the check is down if it hasn't by the time it should have: its period, plus a
//! grace time for runs that start or finish late.
//!
//! The address holds a token only the check has, and only says the work ran. It's on
//! the server's one port, needs no sign in, and reaches nothing else. A ping to
//! `…/start` first times the run, and one to `…/fail` says the work failed.
//!
//! Results are a check's like any other, saved as samples from its host, so `check.up`,
//! the Checks page and alert rules treat them the same. Nothing here runs on agents.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};
use tracing::warn;

use crate::app_state::AppState;
use crate::remote_checks::{self, RemoteCheck};
use crate::times::{self, Timestamp};

/// Where heartbeats are pinged, followed by their token.
pub const PING_PATH: &str = "/ping";

/// A heartbeat's result is saved at least this often, so its charts and its host's
/// presence carry on between pings, however far apart they are.
pub const REPORT_EVERY: chrono::TimeDelta = chrono::TimeDelta::minutes(1);

/// How many hex digits a token is: 32 random bytes, as other secrets the server
/// makes are.
const TOKEN_LENGTH: usize = 64;

/// Pings closer together than this, to one heartbeat, aren't counted.
const MIN_GAP: Duration = Duration::from_secs(1);

/// How many pings to addresses that aren't any heartbeat's one source may make a
/// minute before it's turned away, so nobody can try tokens quickly.
const MAX_MISSES: u32 = 20;
const MISS_WINDOW: Duration = Duration::from_secs(60);

/// How many sources and heartbeats are remembered before the oldest are let go.
const MAX_REMEMBERED: usize = 10_000;

pub fn routes() -> Router<AppState> {
    // HEAD is answered as GET is.
    Router::new()
        .route("/ping/{token}", get(finished).post(finished))
        .route("/ping/{token}/start", get(started).post(started))
        .route("/ping/{token}/fail", get(failed).post(failed))
}

/// A new token, for a heartbeat's address: random, and only hex digits.
pub fn new_token() -> anyhow::Result<String> {
    maxnines_protocol::auth::new_nonce()
}

/// Whether `text` could be a token, which is checked before anything is looked up.
fn is_token(text: &str) -> bool {
    text.len() == TOKEN_LENGTH && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The address a heartbeat is pinged at, from the address the server's pages are at.
pub fn ping_url(web_url: &str, token: &str) -> String {
    format!("{}{PING_PATH}/{token}", web_url.trim_end_matches('/'))
}

/// What a ping says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ping {
    /// A run has started.
    Started,
    /// A run has finished, and worked.
    Finished,
    /// A run has finished, and failed.
    Failed,
}

/// What a heartbeat has been pinged with.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Pings {
    /// When a run last finished, or failed.
    pub pinged_at: Option<Timestamp>,
    /// Whether that run failed.
    pub failed: bool,
    /// When the run under way started, if one's said it has.
    pub started_at: Option<Timestamp>,
    /// How long the last run took, when it said when it started.
    pub run_secs: Option<f64>,
}

impl Pings {
    /// What it's been pinged with once `ping` comes, at `at`.
    pub fn after(&self, ping: Ping, at: Timestamp) -> Self {
        match ping {
            Ping::Started => Self {
                started_at: Some(at),
                ..self.clone()
            },
            Ping::Finished | Ping::Failed => Self {
                pinged_at: Some(at),
                failed: ping == Ping::Failed,
                started_at: None,
                // A run that never said it started isn't timed, rather than being
                // given the last one's time.
                run_secs: self
                    .started_at
                    .map(|started| (at - started).as_seconds_f64().max(0.0)),
            },
        }
    }
}

/// "1 h 5 min", for how long a heartbeat is given.
pub fn length_text(length: Duration) -> String {
    let secs = length.as_secs();
    let (days, hours, minutes, seconds) = (
        secs / 86_400,
        secs % 86_400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    let parts: Vec<String> = [(days, "d"), (hours, "h"), (minutes, "min"), (seconds, "s")]
        .into_iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, unit)| format!("{count} {unit}"))
        .collect();
    if parts.is_empty() {
        "0 s".to_string()
    } else {
        parts.join(" ")
    }
}

/// How a heartbeat is at `now`, as a check's result. `since` is when it began being
/// watched as it is now, which a run that's due counts from if it's never been
/// pinged, or was last pinged before that.
pub fn status(check: &RemoteCheck, pings: &Pings, since: Timestamp, now: Timestamp) -> Value {
    let input = &check.input;
    let allowed = input.interval + input.grace.unwrap_or_default();
    let mut result = json!({
        "name": input.check.name,
        "kind": input.check.kind.as_str(),
    });
    let fields = result.as_object_mut().expect("made as an object");
    if let Some(pinged) = pings.pinged_at {
        fields.insert("pinged_at".to_string(), json!(pinged));
    }
    if let Some(started) = pings.started_at {
        fields.insert("started_at".to_string(), json!(started));
    }
    let from = pings.pinged_at.map_or(since, |pinged| pinged.max(since));
    let due = from + chrono::TimeDelta::from_std(allowed).unwrap_or(chrono::TimeDelta::MAX);
    let error = if pings.failed {
        Some("its last run said it failed".to_string())
    } else if now > due {
        Some(match pings.pinged_at {
            Some(_) => format!("it wasn't pinged within {}", length_text(allowed)),
            None => format!(
                "it hasn't been pinged, in the {} it was given",
                length_text(allowed)
            ),
        })
    } else {
        None
    };
    fields.insert("up".to_string(), json!(u8::from(error.is_none())));
    match error {
        Some(error) => {
            fields.insert("error".to_string(), json!(error));
        }
        // How long the last run took, as a check's response time is how long it took.
        None => {
            if let Some(secs) = pings.run_secs {
                fields.insert("response_secs".to_string(), json!(secs));
            }
        }
    }
    result
}

/// Turns away pings that come too fast: to one heartbeat, closer together than a
/// second, and to addresses that aren't any heartbeat's, too many from one source.
#[derive(Default)]
pub struct PingLimiter {
    last: Mutex<HashMap<i64, Instant>>,
    misses: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl PingLimiter {
    /// Whether a ping to heartbeat `id` now counts.
    fn allow(&self, id: i64, now: Instant) -> bool {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last
            .get(&id)
            .is_some_and(|then| now.duration_since(*then) < MIN_GAP)
        {
            return false;
        }
        if last.len() >= MAX_REMEMBERED {
            last.retain(|_, then| now.duration_since(*then) < MIN_GAP);
        }
        last.insert(id, now);
        true
    }

    /// Notes a ping to an address that isn't a heartbeat's, and says whether its
    /// source may still be told so, rather than being turned away.
    fn miss(&self, source: Option<IpAddr>, now: Instant) -> bool {
        let Some(source) = source else {
            return true;
        };
        let mut misses = self.misses.lock().unwrap_or_else(PoisonError::into_inner);
        if misses.len() >= MAX_REMEMBERED {
            misses.retain(|_, (since, _)| now.duration_since(*since) < MISS_WINDOW);
        }
        let entry = misses.entry(source).or_insert((now, 0));
        if now.duration_since(entry.0) >= MISS_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= MAX_MISSES
    }
}

async fn finished(state: State<AppState>, token: Path<String>) -> Response {
    ping(state, token, Ping::Finished).await
}

async fn started(state: State<AppState>, token: Path<String>) -> Response {
    ping(state, token, Ping::Started).await
}

async fn failed(state: State<AppState>, token: Path<String>) -> Response {
    ping(state, token, Ping::Failed).await
}

fn answer(status: StatusCode, text: &'static str) -> Response {
    (status, text).into_response()
}

/// Notes a ping, and for one that ends a run, saves the heartbeat's result at once.
/// What's sent with it is never read, and the answer is plain text for a script.
async fn ping(State(state): State<AppState>, Path(token): Path<String>, ping: Ping) -> Response {
    const UNKNOWN: &str = "No heartbeat has this address.\n";
    let now = Instant::now();
    let found = if is_token(&token) {
        match state.database.heartbeat_by_token(&token).await {
            Ok(found) => found,
            Err(error) => {
                warn!(
                    error = format!("{error:#}"),
                    "looking up a heartbeat failed"
                );
                return answer(StatusCode::SERVICE_UNAVAILABLE, "Try again later.\n");
            }
        }
    } else {
        None
    };
    let Some(check) = found else {
        if state.pings.miss(crate::audit::source(), now) {
            return answer(StatusCode::NOT_FOUND, UNKNOWN);
        }
        return answer(StatusCode::TOO_MANY_REQUESTS, "Too many tries.\n");
    };
    if !state.pings.allow(check.id, now) {
        return answer(
            StatusCode::TOO_MANY_REQUESTS,
            "Pinged too often: at most once a second.\n",
        );
    }
    let at = times::now();
    let pings = match state.database.record_ping(check.id, ping, at).await {
        Ok(pings) => pings,
        Err(error) => {
            warn!(error = format!("{error:#}"), "saving a ping failed");
            return answer(StatusCode::SERVICE_UNAVAILABLE, "Try again later.\n");
        }
    };
    // A paused heartbeat keeps its pings, so it's up to date once resumed, but says
    // nothing about its host while it's paused.
    if ping != Ping::Started
        && check.input.enabled
        && let Some(host) = state.agentless_host(&check.input.host_id).await
    {
        let result = status(&check, &pings, at, at);
        remote_checks::keep(
            &check,
            host.hostname,
            result,
            &state.writer,
            &state.check_results,
            &state.presence,
        )
        .await;
    }
    answer(StatusCode::OK, "OK\n")
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use maxnines_protocol::{Check, CheckKind};

    use super::*;
    use crate::remote_checks::RemoteCheckInput;

    fn heartbeat(period: u64, grace: u64) -> RemoteCheck {
        RemoteCheck {
            id: 1,
            input: RemoteCheckInput {
                host_id: "h".to_string(),
                check: Check::new("backup", CheckKind::Heartbeat, ""),
                interval: Duration::from_secs(period),
                enabled: true,
                read_stats: false,
                sign_in: Default::default(),
                grace: Some(Duration::from_secs(grace)),
            },
            ping_token: Some(new_token().unwrap()),
        }
    }

    fn at(secs: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH + TimeDelta::seconds(1_800_000_000 + secs)
    }

    #[test]
    fn it_is_up_until_its_period_and_grace_pass_without_a_ping() {
        let check = heartbeat(3600, 300);
        let pinged = Pings::default().after(Ping::Finished, at(0));
        assert_eq!(status(&check, &pinged, at(0), at(3900))["up"], 1);
        let late = status(&check, &pinged, at(0), at(3901));
        assert_eq!(late["up"], 0, "{late}");
        assert_eq!(late["error"], "it wasn't pinged within 1 h 5 min", "{late}");
        // Pinged again, it's up again.
        let again = pinged.after(Ping::Finished, at(4000));
        assert_eq!(status(&check, &again, at(0), at(4001))["up"], 1);
    }

    #[test]
    fn one_never_pinged_is_given_its_time_from_when_it_was_watched() {
        let check = heartbeat(60, 0);
        let never = Pings::default();
        assert_eq!(status(&check, &never, at(100), at(160))["up"], 1);
        let late = status(&check, &never, at(100), at(161));
        assert_eq!(
            late["error"],
            "it hasn't been pinged, in the 1 min it was given"
        );
        // Resumed or changed after its last ping, it's given its time again.
        let old = never.after(Ping::Finished, at(0));
        assert_eq!(status(&check, &old, at(100), at(150))["up"], 1);
    }

    #[test]
    fn a_failed_run_is_down_until_one_works() {
        let check = heartbeat(3600, 0);
        let failed = Pings::default().after(Ping::Failed, at(0));
        let result = status(&check, &failed, at(0), at(1));
        assert_eq!(result["up"], 0);
        assert_eq!(result["error"], "its last run said it failed");
        let worked = failed.after(Ping::Finished, at(10));
        assert_eq!(status(&check, &worked, at(0), at(11))["up"], 1);
    }

    #[test]
    fn a_run_that_said_it_started_is_timed() {
        let check = heartbeat(3600, 0);
        let started = Pings::default().after(Ping::Started, at(0));
        assert_eq!(started.pinged_at, None);
        let done = started.after(Ping::Finished, at(90));
        assert_eq!(done.run_secs, Some(90.0));
        assert_eq!(done.started_at, None);
        assert_eq!(status(&check, &done, at(0), at(91))["response_secs"], 90.0);
        // The next run didn't say it started, so it isn't timed.
        let untimed = done.after(Ping::Finished, at(4000));
        assert_eq!(untimed.run_secs, None);
    }

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_ne!(a, b);
        assert!(is_token(&a), "{a}");
        assert!(!is_token("../../etc/passwd"));
        assert!(!is_token(&a[1..]));
        assert_eq!(
            ping_url("https://monitor.example.com/", &a),
            format!("https://monitor.example.com/ping/{a}")
        );
    }

    #[test]
    fn pings_that_come_too_fast_are_turned_away() {
        let limiter = PingLimiter::default();
        let start = Instant::now();
        assert!(limiter.allow(1, start));
        assert!(!limiter.allow(1, start + Duration::from_millis(500)));
        assert!(limiter.allow(2, start + Duration::from_millis(500)));
        assert!(limiter.allow(1, start + Duration::from_secs(1)));

        let source: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..MAX_MISSES {
            assert!(limiter.miss(Some(source), start));
        }
        assert!(!limiter.miss(Some(source), start));
        assert!(limiter.miss(Some("192.0.2.2".parse().unwrap()), start));
        assert!(limiter.miss(Some(source), start + MISS_WINDOW));
    }

    #[test]
    fn lengths_read_naturally() {
        assert_eq!(length_text(Duration::from_secs(3900)), "1 h 5 min");
        assert_eq!(length_text(Duration::from_secs(86_400 * 7)), "7 d");
        assert_eq!(length_text(Duration::from_secs(90)), "1 min 30 s");
    }
}
