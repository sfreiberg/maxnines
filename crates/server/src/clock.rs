//! How far each host's clock is from the server's.
//!
//! A reading can't come as a sample, because an agent keeps samples and sends
//! them late, and what its clock said a minute ago says nothing about now. So the
//! server asks over the agent's connection, the agent answers at once, and the
//! server times the round trip. The agent's clock was read somewhere inside it,
//! so comparing with the middle is out by no more than half of it, and an answer
//! that took too long is thrown away.
//!
//! The result is saved as a sample dated by the server, as the agent's clock is
//! what's in question. It says how far apart the clocks are, whichever is ahead.

use std::collections::BTreeMap;
use std::time::Duration;

use maxnines_protocol::Sample;
use serde_json::json;
use tokio::time::Instant;

use crate::store::NewSample;

/// How often each connected agent is asked. Clocks drift slowly.
pub const ASK_EVERY: Duration = Duration::from_secs(60);

/// The longest an answer can take and still be used, which keeps a reading to
/// within half a second. A slower one is asked for again.
const MAX_ROUND_TRIP: Duration = Duration::from_secs(1);

/// A question that's waiting for its answer.
pub struct Asked {
    /// Sent back with the answer, so an answer to an older question, or one
    /// nobody asked, matches nothing.
    pub nonce: String,
    sent: Instant,
    /// What the server's clock said when it was sent.
    sent_ms: i64,
}

impl Asked {
    pub fn new(nonce: String, now_ms: i64) -> Self {
        Self {
            nonce,
            sent: Instant::now(),
            sent_ms: now_ms,
        }
    }

    /// What an answer saying `host_ms` means, if it's the answer to this.
    pub fn answered(&self, nonce: &str, host_ms: u64) -> Option<Reading> {
        (nonce == self.nonce)
            .then(|| reading(self.sent_ms, self.sent.elapsed(), host_ms))
            .flatten()
    }
}

/// How a host's clock compares with the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// How far ahead of the server's the host's clock is, in milliseconds. Behind
    /// is negative.
    pub offset_ms: i64,
    pub round_trip_ms: u64,
}

/// Compares what the host said with the middle of the round trip, or nothing if
/// that took too long to say where in it the host's clock was read.
fn reading(sent_ms: i64, round_trip: Duration, host_ms: u64) -> Option<Reading> {
    if round_trip > MAX_ROUND_TRIP {
        return None;
    }
    let round_trip_ms = round_trip.as_millis() as u64;
    let middle_ms = sent_ms.saturating_add((round_trip_ms / 2) as i64);
    let host_ms = i64::try_from(host_ms).unwrap_or(i64::MAX);
    Some(Reading {
        offset_ms: host_ms.saturating_sub(middle_ms),
        round_trip_ms,
    })
}

impl Reading {
    /// As a sample from the host, dated by the server. Only how far apart the
    /// clocks are is kept, not which is ahead: either way the host's is wrong,
    /// and one number is one thing to alert on.
    pub fn sample(self, host_id: &str, hostname: &str, now_ms: i64) -> NewSample {
        let clock = json!({
            "difference_secs": self.offset_ms.unsigned_abs() as f64 / 1000.0,
            "round_trip_ms": self.round_trip_ms,
        });
        NewSample {
            host_id: host_id.to_string(),
            hostname: hostname.to_string(),
            sample: Sample {
                timestamp_ms: u64::try_from(now_ms).unwrap_or(0),
                metrics: BTreeMap::from([("clock".to_string(), clock)]),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOON_MS: i64 = 1_800_000_000_000;

    #[test]
    fn a_clock_is_compared_with_the_middle_of_the_round_trip() {
        // Asked at noon and answered 40 ms later, so it was read about 20 ms in.
        let took = Duration::from_millis(40);
        let right = reading(NOON_MS, took, NOON_MS as u64 + 20).unwrap();
        assert_eq!((right.offset_ms, right.round_trip_ms), (0, 40));

        let ahead = reading(NOON_MS, took, NOON_MS as u64 + 7020).unwrap();
        assert_eq!(ahead.offset_ms, 7000);
        let behind = reading(NOON_MS, took, NOON_MS as u64 - 2980).unwrap();
        assert_eq!(behind.offset_ms, -3000);
    }

    #[test]
    fn an_answer_that_took_too_long_is_not_used() {
        assert!(reading(NOON_MS, MAX_ROUND_TRIP, NOON_MS as u64).is_some());
        let late = MAX_ROUND_TRIP + Duration::from_millis(1);
        assert_eq!(reading(NOON_MS, late, NOON_MS as u64), None);
    }

    #[test]
    fn a_time_that_cannot_be_true_does_not_overflow() {
        let reading = reading(NOON_MS, Duration::ZERO, u64::MAX).unwrap();
        assert!(reading.offset_ms > 0);
    }

    #[tokio::test]
    async fn only_the_answer_to_the_question_asked_counts() {
        let asked = Asked::new("this one".to_string(), NOON_MS);
        assert_eq!(asked.answered("another", NOON_MS as u64), None);
        assert!(asked.answered("this one", NOON_MS as u64).is_some());
    }

    #[test]
    fn a_reading_is_saved_as_how_far_apart_and_dated_by_the_server() {
        let ahead = Reading {
            offset_ms: 7500,
            round_trip_ms: 12,
        };
        let saved = ahead.sample("abc", "web-1", NOON_MS);
        assert_eq!(
            (saved.host_id.as_str(), saved.hostname.as_str()),
            ("abc", "web-1")
        );
        assert_eq!(saved.sample.timestamp_ms, NOON_MS as u64);
        let clock = &saved.sample.metrics["clock"];
        assert_eq!(clock["difference_secs"], 7.5);
        assert_eq!(clock["round_trip_ms"], 12);

        let behind = Reading {
            offset_ms: -250,
            round_trip_ms: 12,
        };
        let clock = &behind.sample("abc", "web-1", NOON_MS).sample.metrics["clock"];
        assert_eq!(clock["difference_secs"], 0.25);
    }
}
