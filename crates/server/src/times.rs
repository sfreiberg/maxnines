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
    fn only_zones_in_the_database_are_found() {
        assert_eq!(zone_named("Europe/London"), Some(Tz::Europe__London));
        assert_eq!(zone_named("UTC"), Some(Tz::UTC));
        assert_eq!(zone_named("Mars/Olympus"), None);
        assert_eq!(zone_named(""), None);
        assert!(zone_names().contains(&"America/New_York"));
    }
}
