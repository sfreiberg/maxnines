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

use chrono::TimeDelta;
use maxnines_protocol::Sample;
use serde_json::json;
use tokio::time::Instant;

use crate::store::NewSample;
use crate::times::Timestamp;

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
    /// When it was sent, by a clock that only goes forward, for timing the answer.
    sent: Instant,
    /// What the server's clock said when it was sent.
    sent_at: Timestamp,
}

impl Asked {
    pub fn new(nonce: String, now: Timestamp) -> Self {
        Self {
            nonce,
            sent: Instant::now(),
            sent_at: now,
        }
    }

    /// What an answer saying the host's clock read `host_time` means, if it's the
    /// answer to this.
    pub fn answered(&self, nonce: &str, host_time: Timestamp) -> Option<Reading> {
        (nonce == self.nonce)
            .then(|| reading(self.sent_at, self.sent.elapsed(), host_time))
            .flatten()
    }
}

/// How a host's clock compares with the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// How far ahead of the server's the host's clock is. Behind is negative.
    pub offset: TimeDelta,
    pub round_trip: Duration,
}

/// Compares what the host said with the middle of the round trip, or nothing if
/// that took too long to say where in it the host's clock was read.
fn reading(sent_at: Timestamp, round_trip: Duration, host_time: Timestamp) -> Option<Reading> {
    if round_trip > MAX_ROUND_TRIP {
        return None;
    }
    let middle = sent_at + TimeDelta::from_std(round_trip / 2).ok()?;
    Some(Reading {
        offset: host_time - middle,
        round_trip,
    })
}

impl Reading {
    /// As a sample from the host, dated by the server. Only how far apart the
    /// clocks are is kept, not which is ahead: either way the host's is wrong,
    /// and one number is one thing to alert on.
    pub fn sample(self, host_id: &str, hostname: &str, now: Timestamp) -> NewSample {
        let apart = self.offset.abs();
        let clock = json!({
            "difference_secs": apart.num_milliseconds() as f64 / 1000.0,
            "round_trip_ms": u64::try_from(self.round_trip.as_millis()).unwrap_or(u64::MAX),
        });
        NewSample {
            host_id: host_id.to_string(),
            hostname: hostname.to_string(),
            sample: Sample {
                time: now,
                metrics: BTreeMap::from([("clock".to_string(), clock)]),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::times::from_ms;

    fn noon() -> Timestamp {
        from_ms(1_800_000_000_000)
    }

    fn ms(milliseconds: i64) -> TimeDelta {
        TimeDelta::milliseconds(milliseconds)
    }

    #[test]
    fn a_clock_is_compared_with_the_middle_of_the_round_trip() {
        // Asked at noon and answered 40 ms later, so it was read about 20 ms in.
        let took = Duration::from_millis(40);
        let right = reading(noon(), took, noon() + ms(20)).unwrap();
        assert_eq!((right.offset, right.round_trip), (ms(0), took));

        let ahead = reading(noon(), took, noon() + ms(7020)).unwrap();
        assert_eq!(ahead.offset, ms(7000));
        let behind = reading(noon(), took, noon() - ms(2980)).unwrap();
        assert_eq!(behind.offset, ms(-3000));
    }

    #[test]
    fn an_answer_that_took_too_long_is_not_used() {
        assert!(reading(noon(), MAX_ROUND_TRIP, noon()).is_some());
        let late = MAX_ROUND_TRIP + Duration::from_millis(1);
        assert_eq!(reading(noon(), late, noon()), None);
    }

    #[test]
    fn a_time_that_cannot_be_true_does_not_overflow() {
        let reading = reading(noon(), Duration::ZERO, Timestamp::MAX_UTC).unwrap();
        assert!(reading.offset > TimeDelta::zero());
    }

    #[tokio::test]
    async fn only_the_answer_to_the_question_asked_counts() {
        let asked = Asked::new("this one".to_string(), noon());
        assert_eq!(asked.answered("another", noon()), None);
        assert!(asked.answered("this one", noon()).is_some());
    }

    #[test]
    fn a_reading_is_saved_as_how_far_apart_and_dated_by_the_server() {
        let round_trip = Duration::from_millis(12);
        let ahead = Reading {
            offset: ms(7500),
            round_trip,
        };
        let saved = ahead.sample("abc", "web-1", noon());
        assert_eq!(
            (saved.host_id.as_str(), saved.hostname.as_str()),
            ("abc", "web-1")
        );
        assert_eq!(saved.sample.time, noon());
        let clock = &saved.sample.metrics["clock"];
        assert_eq!(clock["difference_secs"], 7.5);
        assert_eq!(clock["round_trip_ms"], 12);

        let behind = Reading {
            offset: ms(-250),
            round_trip,
        };
        let clock = &behind.sample("abc", "web-1", noon()).sample.metrics["clock"];
        assert_eq!(clock["difference_secs"], 0.25);
    }
}
