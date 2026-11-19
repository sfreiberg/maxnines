//! Times as people read them. The pages show them in the time zone each person
//! chooses on their profile. The command line and alert messages have no one person
//! reading them, so they use UTC.

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use chrono_tz::Tz;

/// A moment, as the database keeps them, always in UTC and to the millisecond: the
/// database's timestamp types, and the API's ISO 8601 times.
pub type Timestamp = DateTime<Utc>;

/// Now, to the millisecond, as everything kept is. Finer than that, SQLite, which keeps
/// times as text, would write some with more digits than others, and they'd no longer
/// sort or compare as text the way they do as times. This is the server's only clock:
/// everything else is handed the time, so tests can choose it.
pub fn now() -> Timestamp {
    maxnines_protocol::time::now()
}

/// The moment `ms` milliseconds after 1970, or the nearest one there can be. For
/// tests, which count in round numbers.
#[cfg(test)]
pub fn from_ms(ms: i64) -> Timestamp {
    DateTime::from_timestamp_millis(ms).unwrap_or(if ms < 0 {
        DateTime::<Utc>::MIN_UTC
    } else {
        DateTime::<Utc>::MAX_UTC
    })
}

/// The start of the hour a moment is in.
pub fn hour_of(time: Timestamp) -> Timestamp {
    time.duration_trunc(TimeDelta::hours(1)).unwrap_or(time)
}

/// A moment written in ISO 8601, as the API takes them, such as
/// `2026-11-19T01:57:17.828Z`, to the millisecond, as everything kept is.
pub fn parse_moment(text: &str) -> Option<Timestamp> {
    let time = DateTime::parse_from_rfc3339(text.trim()).ok()?.to_utc();
    time.duration_trunc(TimeDelta::milliseconds(1)).ok()
}

/// For serde, a moment the API or a page may leave out, written in ISO 8601. An
/// empty one, as a form sends for a field left blank, is left out too.
pub mod optional_moment {
    use serde::{Deserialize, Deserializer, de::Error};

    use super::{Timestamp, parse_moment};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(None),
            Some(text) if text.trim().is_empty() => Ok(None),
            Some(text) => parse_moment(&text).map(Some).ok_or_else(|| {
                D::Error::custom(format!(
                    "{text:?} isn't a time in ISO 8601, such as 2026-11-19T01:57:17Z"
                ))
            }),
        }
    }
}

/// For serde, a length of time in whole seconds, as rules and forms write them, such
/// as `for_secs`. A negative number or one too big to be a length isn't one.
pub mod whole_seconds {
    use chrono::TimeDelta;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(length: &TimeDelta, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(length.num_seconds())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<TimeDelta, D::Error> {
        let seconds = u64::deserialize(deserializer)?;
        i64::try_from(seconds)
            .ok()
            .and_then(TimeDelta::try_seconds)
            .ok_or_else(|| D::Error::custom(format!("{seconds} seconds is too long")))
    }
}

/// For serde, a length of time in whole seconds that can be left out.
pub mod optional_whole_seconds {
    use chrono::TimeDelta;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        length: &Option<TimeDelta>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match length {
            Some(length) => serializer.serialize_some(&length.num_seconds()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<TimeDelta>, D::Error> {
        #[derive(Deserialize)]
        struct Seconds(#[serde(with = "super::whole_seconds")] TimeDelta);
        Ok(Option::<Seconds>::deserialize(deserializer)?.map(|Seconds(length)| length))
    }
}

/// How long `ms` milliseconds is. For tests, which count in round numbers.
#[cfg(test)]
pub fn millis(ms: i64) -> TimeDelta {
    TimeDelta::milliseconds(ms)
}

/// A moment to the second in `zone`, ending with the zone's abbreviation, such as
/// `PST`.
pub fn format_moment(time: Timestamp, zone: Tz) -> String {
    time.with_timezone(&zone)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

/// Where everyone starts, until they choose their own.
pub const DEFAULT_TIME_ZONE: Tz = Tz::UTC;

/// Just the day, for where the time of day is more than anyone needs.
pub fn format_date(time: Timestamp, zone: Tz) -> String {
    time.with_timezone(&zone).format("%Y-%m-%d").to_string()
}

/// How long something has lasted, in its two largest units, such as "1 day and 13
/// hours", which says enough at a glance without counting seconds.
pub fn lasting(length: TimeDelta) -> String {
    let plural = |count: i64, unit: &str| match count {
        1 => format!("1 {unit}"),
        _ => format!("{count} {unit}s"),
    };
    let minutes = length.num_minutes().max(0);
    let (days, hours, minutes) = (minutes / 1440, minutes / 60 % 24, minutes % 60);
    let (larger, smaller) = match (days, hours) {
        (0, 0) if minutes == 0 => return "less than a minute".to_string(),
        (0, 0) => return plural(minutes, "minute"),
        (0, _) => (plural(hours, "hour"), plural(minutes, "minute")),
        _ => (plural(days, "day"), plural(hours, "hour")),
    };
    if smaller.starts_with("0 ") {
        larger
    } else {
        format!("{larger} and {smaller}")
    }
}

/// In the largest unit that makes sense, as "3 minutes ago" reads better than a
/// timestamp when you're only asking how recent something is.
pub fn ago(then: Timestamp, now: Timestamp) -> String {
    let secs = u64::try_from((now - then).num_seconds()).unwrap_or(0);
    let plural = |count: u64, unit: &str| match count {
        1 => format!("1 {unit} ago"),
        _ => format!("{count} {unit}s ago"),
    };
    match secs {
        0..60 => "just now".to_string(),
        60..3600 => plural(secs / 60, "minute"),
        3600..86_400 => plural(secs / 3600, "hour"),
        _ => plural(secs / 86_400, "day"),
    }
}

/// The zone with this name in the time zone database, like `Europe/London`.
pub fn zone_named(name: &str) -> Option<Tz> {
    name.parse().ok()
}

/// Every zone's name, for choosing one.
pub fn zone_names() -> Vec<&'static str> {
    chrono_tz::TZ_VARIANTS
        .iter()
        .map(|zone| zone.name())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nov_14_2023() -> Timestamp {
        from_ms(1_700_000_000_000)
    }

    #[test]
    fn formats_times_in_utc() {
        assert_eq!(
            format_moment(nov_14_2023(), Tz::UTC),
            "2023-11-14 22:13:20 UTC"
        );
    }

    #[test]
    fn formats_times_in_a_zone_with_its_abbreviation() {
        assert_eq!(
            format_moment(nov_14_2023(), Tz::America__Los_Angeles),
            "2023-11-14 14:13:20 PST"
        );
        assert_eq!(
            format_moment(nov_14_2023(), Tz::Asia__Kolkata),
            "2023-11-15 03:43:20 IST"
        );
    }

    #[test]
    fn an_hour_starts_on_the_hour() {
        let time = parse_moment("2026-11-19T01:57:17.828Z").unwrap();
        assert_eq!(hour_of(time), parse_moment("2026-11-19T01:00:00Z").unwrap());
        assert_eq!(hour_of(hour_of(time)), hour_of(time));
    }

    #[test]
    fn moments_are_read_in_iso_8601_to_the_millisecond() {
        let time = parse_moment("2026-11-19T01:57:17.828Z").unwrap();
        assert_eq!(time, from_ms(1_795_053_437_828));
        // Any offset, as long as it says which, and anything finer is dropped.
        assert_eq!(parse_moment("2026-11-18T17:57:17.8289-08:00"), Some(time));
        assert_eq!(
            parse_moment(" 2026-11-19T01:57:17Z "),
            Some(time - millis(828))
        );
        for vague in [
            "2026-11-19",
            "2026-11-19T01:57:17",
            "1795053437828",
            "soon",
            "",
        ] {
            assert_eq!(parse_moment(vague), None, "{vague}");
        }
    }

    #[test]
    fn a_date_is_the_day_in_the_zone() {
        let time = nov_14_2023();
        assert_eq!(format_date(time, Tz::UTC), "2023-11-14");
        // Already the next day there.
        assert_eq!(format_date(time, Tz::Asia__Kolkata), "2023-11-15");
    }

    #[test]
    fn how_long_is_said_in_two_units_at_most() {
        let minutes = TimeDelta::minutes;
        assert_eq!(lasting(millis(59_999)), "less than a minute");
        assert_eq!(lasting(minutes(1)), "1 minute");
        assert_eq!(lasting(minutes(59) + millis(59_999)), "59 minutes");
        assert_eq!(lasting(minutes(60)), "1 hour");
        assert_eq!(lasting(minutes(125)), "2 hours and 5 minutes");
        assert_eq!(lasting(minutes(1440)), "1 day");
        assert_eq!(lasting(minutes(1440 + 13 * 60 + 59)), "1 day and 13 hours");
        assert_eq!(lasting(minutes(3 * 1440 + 1)), "3 days");
        assert_eq!(lasting(-minutes(5)), "less than a minute");
    }

    #[test]
    fn times_ago_use_the_largest_unit() {
        let now = from_ms(100 * 86_400_000);
        assert_eq!(ago(now - millis(5_000), now), "just now");
        assert_eq!(ago(now - millis(60_000), now), "1 minute ago");
        assert_eq!(ago(now - millis(7_200_000), now), "2 hours ago");
        assert_eq!(ago(now - millis(3 * 86_400_000), now), "3 days ago");
        assert_eq!(ago(now + millis(5_000), now), "just now");
    }

    #[test]
    fn only_zones_in_the_database_are_found() {
        assert_eq!(zone_named("Europe/London"), Some(Tz::Europe__London));
        assert_eq!(zone_named("UTC"), Some(Tz::UTC));
        assert_eq!(zone_named("Mars/Olympus"), None);
        assert_eq!(zone_named(""), None);
        assert!(zone_names().contains(&"America/New_York"));
    }
}
