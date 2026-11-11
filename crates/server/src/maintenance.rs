//! Maintenance windows: silences that come round on a schedule, such as every Sunday
//! morning. Times are wall clock times in a named zone, so one keeps its place in the
//! day when the clocks change.

use anyhow::{Result, bail};
use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, TimeDelta, TimeZone};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::alerting::format_duration;
use crate::silences::check_filter;

/// The days a window can run on, in the order they're shown.
pub const DAYS: [(&str, &str); 7] = [
    ("mon", "Monday"),
    ("tue", "Tuesday"),
    ("wed", "Wednesday"),
    ("thu", "Thursday"),
    ("fri", "Friday"),
    ("sat", "Saturday"),
    ("sun", "Sunday"),
];

const MAX_NAME_CHARS: usize = 255;
const MAX_DURATION_MINUTES: u32 = 7 * 24 * 60;
const MINUTES_IN_A_DAY: u32 = 24 * 60;
const TIME_FORMAT: &str = "%H:%M";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceWindowInput {
    pub name: String,
    /// Every rule, if empty.
    #[serde(default)]
    pub rule_id: Option<i64>,
    /// Which hosts, in the same form as the host list. Every host, if empty.
    #[serde(default)]
    pub filter: String,
    /// The days it starts on, like `sun`.
    pub days: Vec<String>,
    /// When it starts, like `02:00`.
    pub start_time: String,
    pub duration_minutes: u32,
    /// A name from the time zone database, like `Europe/London`.
    pub time_zone: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaintenanceWindow {
    pub id: i64,
    #[serde(flatten)]
    pub window: MaintenanceWindowInput,
}

/// Whether a window makes sense, apart from whether its rule exists.
pub fn check_window(input: &MaintenanceWindowInput) -> Result<()> {
    if input.name.trim().is_empty() {
        bail!("A maintenance window needs a name.");
    }
    if input.name.chars().count() > MAX_NAME_CHARS {
        bail!("The name is too long. It can be up to {MAX_NAME_CHARS} characters.");
    }
    check_filter(&input.filter)?;
    if input.days.is_empty() {
        bail!("Choose at least one day.");
    }
    if let Some(day) = input.days.iter().find(|day| !is_day(day)) {
        bail!("{day:?} isn't a day. Use mon, tue, wed, thu, fri, sat or sun.");
    }
    if NaiveTime::parse_from_str(&input.start_time, TIME_FORMAT).is_err() {
        bail!("The start time should look like 02:00.");
    }
    if input.duration_minutes == 0 || input.duration_minutes > MAX_DURATION_MINUTES {
        bail!("A maintenance window can last up to 7 days.");
    }
    if input.time_zone.parse::<Tz>().is_err() {
        bail!(
            "{:?} isn't a time zone. Try one like Europe/London.",
            input.time_zone
        );
    }
    Ok(())
}

fn is_day(text: &str) -> bool {
    DAYS.iter().any(|(day, _)| *day == text)
}

/// A wall clock time as a real moment. When the clocks go back it happens twice, and
/// this is the first. When they go forward it may not happen at all, so it's an hour on.
pub fn moment(zone: Tz, date: NaiveDate, time: NaiveTime) -> Option<i64> {
    let local = date.and_time(time);
    let found = zone.from_local_datetime(&local).earliest().or_else(|| {
        let later = local.checked_add_signed(TimeDelta::hours(1))?;
        zone.from_local_datetime(&later).earliest()
    })?;
    Some(found.timestamp_millis())
}

impl MaintenanceWindow {
    /// When it ends, if it's running at this moment.
    pub fn ends_at(&self, now_ms: i64) -> Option<i64> {
        let window = &self.window;
        let zone: Tz = window.time_zone.parse().ok()?;
        let time = NaiveTime::parse_from_str(&window.start_time, TIME_FORMAT).ok()?;
        let today = DateTime::from_timestamp_millis(now_ms)?
            .with_timezone(&zone)
            .date_naive();
        let lasts_ms = i64::from(window.duration_minutes) * 60_000;

        // One that started on an earlier day may not have finished.
        let days_back = i64::from(window.duration_minutes.div_ceil(MINUTES_IN_A_DAY)) + 1;
        (0..=days_back)
            .filter_map(|back| today.checked_sub_signed(TimeDelta::days(back)))
            .filter(|date| {
                let day = date.weekday().to_string().to_lowercase();
                window.days.contains(&day)
            })
            .filter_map(|date| moment(zone, date, time))
            .filter(|start| *start <= now_ms && now_ms < start + lasts_ms)
            .map(|start| start + lasts_ms)
            .max()
    }

    /// In words, for the pages.
    pub fn schedule(&self) -> String {
        let window = &self.window;
        let days: Vec<&str> = DAYS
            .iter()
            .filter(|(day, _)| window.days.iter().any(|chosen| chosen == day))
            .map(|(_, name)| *name)
            .collect();
        format!(
            "{} at {} for {}, {}",
            days.join(", "),
            window.start_time,
            format_duration(u64::from(window.duration_minutes) * 60),
            window.time_zone
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> MaintenanceWindowInput {
        MaintenanceWindowInput {
            name: "Patching".to_string(),
            rule_id: None,
            filter: String::new(),
            days: vec!["sun".to_string()],
            start_time: "02:00".to_string(),
            duration_minutes: 120,
            time_zone: "UTC".to_string(),
        }
    }

    fn window(input: MaintenanceWindowInput) -> MaintenanceWindow {
        MaintenanceWindow {
            id: 1,
            window: input,
        }
    }

    /// A moment in UTC, like `2026-11-08T03:00:00Z`.
    fn at(text: &str) -> i64 {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .timestamp_millis()
    }

    #[test]
    fn it_runs_from_its_start_until_its_end_on_its_day() {
        let sunday = window(input());

        assert_eq!(sunday.ends_at(at("2026-11-08T01:59:59Z")), None);
        let end = Some(at("2026-11-08T04:00:00Z"));
        assert_eq!(sunday.ends_at(at("2026-11-08T02:00:00Z")), end);
        assert_eq!(sunday.ends_at(at("2026-11-08T03:59:59Z")), end);
        assert_eq!(sunday.ends_at(at("2026-11-08T04:00:00Z")), None);
    }

    #[test]
    fn it_does_not_run_on_other_days() {
        assert_eq!(window(input()).ends_at(at("2026-11-07T03:00:00Z")), None);
    }

    #[test]
    fn it_can_run_past_midnight_into_a_day_it_was_not_set_for() {
        let late = window(MaintenanceWindowInput {
            start_time: "23:00".to_string(),
            ..input()
        });

        let monday = at("2026-11-09T00:30:00Z");

        assert_eq!(late.ends_at(monday), Some(at("2026-11-09T01:00:00Z")));
    }

    #[test]
    fn it_can_last_for_days() {
        let long = window(MaintenanceWindowInput {
            duration_minutes: 3 * MINUTES_IN_A_DAY,
            ..input()
        });

        let tuesday = at("2026-11-10T12:00:00Z");

        assert_eq!(long.ends_at(tuesday), Some(at("2026-11-11T02:00:00Z")));
    }

    #[test]
    fn it_keeps_its_place_in_the_day_when_the_clocks_change() {
        let new_york = window(MaintenanceWindowInput {
            start_time: "03:00".to_string(),
            time_zone: "America/New_York".to_string(),
            ..input()
        });

        // Five hours behind UTC in winter, and four in summer.
        let winter = at("2026-01-04T08:30:00Z");
        let summer = at("2026-07-05T07:30:00Z");

        assert_eq!(new_york.ends_at(winter), Some(at("2026-01-04T10:00:00Z")));
        assert_eq!(new_york.ends_at(summer), Some(at("2026-07-05T09:00:00Z")));
    }

    #[test]
    fn a_start_the_clocks_skip_moves_an_hour_on() {
        let skipped = window(MaintenanceWindowInput {
            start_time: "02:30".to_string(),
            duration_minutes: 30,
            time_zone: "America/New_York".to_string(),
            ..input()
        });

        // 02:30 doesn't exist that morning, and 03:30 is 07:30 in UTC.
        let during = at("2026-03-08T07:45:00Z");

        assert_eq!(skipped.ends_at(during), Some(at("2026-03-08T08:00:00Z")));
    }

    #[test]
    fn a_start_the_clocks_repeat_is_the_first_one() {
        let repeated = window(MaintenanceWindowInput {
            start_time: "01:30".to_string(),
            duration_minutes: 30,
            time_zone: "America/New_York".to_string(),
            ..input()
        });

        // The first 01:30 that morning is 05:30 in UTC, and the second is 06:30.
        let first = at("2026-11-01T05:45:00Z");
        let second = at("2026-11-01T06:45:00Z");

        assert_eq!(repeated.ends_at(first), Some(at("2026-11-01T06:00:00Z")));
        assert_eq!(repeated.ends_at(second), None);
    }

    #[test]
    fn it_says_its_schedule_in_words() {
        let days = vec!["sun".to_string(), "mon".to_string()];
        let window = window(MaintenanceWindowInput { days, ..input() });

        assert_eq!(
            window.schedule(),
            "Monday, Sunday at 02:00 for 2 hours, UTC"
        );
    }

    #[test]
    fn a_good_window_passes() {
        check_window(&input()).unwrap();
    }

    #[test]
    fn bad_windows_are_refused_with_a_reason() {
        for (bad, expected) in [
            (
                MaintenanceWindowInput {
                    name: " ".to_string(),
                    ..input()
                },
                "needs a name",
            ),
            (
                MaintenanceWindowInput {
                    days: Vec::new(),
                    ..input()
                },
                "at least one day",
            ),
            (
                MaintenanceWindowInput {
                    days: vec!["someday".to_string()],
                    ..input()
                },
                "isn't a day",
            ),
            (
                MaintenanceWindowInput {
                    start_time: "25:00".to_string(),
                    ..input()
                },
                "look like 02:00",
            ),
            (
                MaintenanceWindowInput {
                    duration_minutes: 0,
                    ..input()
                },
                "up to 7 days",
            ),
            (
                MaintenanceWindowInput {
                    duration_minutes: MAX_DURATION_MINUTES + 1,
                    ..input()
                },
                "up to 7 days",
            ),
            (
                MaintenanceWindowInput {
                    time_zone: "Mars/Olympus".to_string(),
                    ..input()
                },
                "isn't a time zone",
            ),
            (
                MaintenanceWindowInput {
                    filter: "hostname=\"web".to_string(),
                    ..input()
                },
                "quote",
            ),
        ] {
            let error = check_window(&bad).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }
}
