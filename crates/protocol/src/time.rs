//! Moments and lengths of time as agents and the server send them. A moment is an
//! ISO 8601 time in UTC to the millisecond, such as `2026-11-19T01:57:17.828Z`, as
//! the API gives them. A length of time is a whole number, with its unit at the end
//! of its name, such as `timeout_secs`, as settings are written by hand.

use chrono::{DateTime, DurationRound, TimeDelta, Utc};

/// Now, to the millisecond, as every moment sent or kept is. Anything finer would
/// only be dropped along the way, and two copies of the same sample have to match.
pub fn now() -> DateTime<Utc> {
    let now = Utc::now();
    to_the_millisecond(now)
}

/// A moment without anything finer than a millisecond.
pub fn to_the_millisecond(time: DateTime<Utc>) -> DateTime<Utc> {
    time.duration_trunc(TimeDelta::milliseconds(1))
        .unwrap_or(time)
}

/// For serde, a length of time in whole seconds.
pub mod seconds {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(length: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(length.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_secs)
    }
}

/// For serde, a length of time in whole seconds that can be left out.
pub mod optional_seconds {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        length: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match length {
            Some(length) => serializer.serialize_some(&length.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Option::<u64>::deserialize(deserializer).map(|seconds| seconds.map(Duration::from_secs))
    }
}

/// For serde, a length of time in whole milliseconds, for what's measured rather
/// than chosen.
pub mod milliseconds {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(length: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::try_from(length.as_millis()).unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_to_the_millisecond() {
        let now = now();
        assert_eq!(now.timestamp_subsec_nanos() % 1_000_000, 0);
    }

    #[test]
    fn a_moment_is_written_in_iso_8601_to_the_millisecond() {
        let time = DateTime::from_timestamp_millis(1_795_053_437_828).unwrap();
        let text = serde_json::to_string(&time).unwrap();
        assert_eq!(text, r#""2026-11-19T01:57:17.828Z""#);
        assert_eq!(serde_json::from_str::<DateTime<Utc>>(&text).unwrap(), time);
    }
}
