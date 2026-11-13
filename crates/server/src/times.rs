//! Times as people read them. The pages show them in the time zone each person
//! chooses on their profile. The command line and alert messages have no one person
//! reading them, so they use UTC.

use chrono::DateTime;
use chrono_tz::Tz;

/// Where everyone starts, until they choose their own.
pub const DEFAULT_TIME_ZONE: Tz = Tz::UTC;

/// A time to the second, ending with the zone's abbreviation, such as `PST`.
pub fn format_time(ms: u64, zone: Tz) -> String {
    let time = i64::try_from(ms)
        .ok()
        .and_then(DateTime::from_timestamp_millis);
    match time {
        Some(time) => time
            .with_timezone(&zone)
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string(),
        None => format!("{ms} ms"),
    }
}

/// Just the day, for where the time of day is more than anyone needs.
pub fn format_date(ms: u64, zone: Tz) -> String {
    let time = i64::try_from(ms)
        .ok()
        .and_then(DateTime::from_timestamp_millis);
    match time {
        Some(time) => time.with_timezone(&zone).format("%Y-%m-%d").to_string(),
        None => format!("{ms} ms"),
    }
}

/// In the largest unit that makes sense, as "3 minutes ago" reads better than a
/// timestamp when you're only asking how recent something is.
pub fn ago(ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(ms) / 1000;
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

    const NOV_14_2023: u64 = 1_700_000_000_000;

    #[test]
    fn formats_times_in_utc() {
        assert_eq!(format_time(NOV_14_2023, Tz::UTC), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn formats_times_in_a_zone_with_its_abbreviation() {
        assert_eq!(
            format_time(NOV_14_2023, Tz::America__Los_Angeles),
            "2023-11-14 14:13:20 PST"
        );
        assert_eq!(
            format_time(NOV_14_2023, Tz::Asia__Kolkata),
            "2023-11-15 03:43:20 IST"
        );
    }

    #[test]
    fn a_date_is_the_day_in_the_zone() {
        assert_eq!(format_date(NOV_14_2023, Tz::UTC), "2023-11-14");
        // Already the next day there.
        assert_eq!(format_date(NOV_14_2023, Tz::Asia__Kolkata), "2023-11-15");
    }

    #[test]
    fn times_ago_use_the_largest_unit() {
        let now = 100 * 86_400_000;
        assert_eq!(ago(now - 5_000, now), "just now");
        assert_eq!(ago(now - 60_000, now), "1 minute ago");
        assert_eq!(ago(now - 7_200_000, now), "2 hours ago");
        assert_eq!(ago(now - 3 * 86_400_000, now), "3 days ago");
        assert_eq!(ago(now + 5_000, now), "just now");
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
