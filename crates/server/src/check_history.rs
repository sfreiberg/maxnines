//! What a check's saved results say about how it's been: how much of the time it
//! passed, how often it failed and for how long, and how long it's been the way
//! it is now. All of it is worked out from the points of its "passing" series,
//! each of which covers one step of time, so it's only as fine as those steps:
//! a failure is known to within a step, not to the second.

use chrono::TimeDelta;
use serde::Serialize;

use crate::metrics::Point;
use crate::times::Timestamp;

/// How a stretch of time went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    /// Every run in it passed.
    Passed,
    /// At least one run in it failed.
    Failed,
    /// Nothing ran in it.
    NotRun,
}

fn failed(point: &Point) -> bool {
    point.min < 1.0
}

/// The time from `from` to `to` cut into `count` equal slots, oldest first, each
/// saying how the runs in it went.
pub fn slots(points: &[Point], from: Timestamp, to: Timestamp, count: usize) -> Vec<Slot> {
    let mut slots = vec![Slot::NotRun; count];
    if count == 0 || to <= from {
        return slots;
    }
    let length = (to - from).num_milliseconds();
    for point in points {
        if point.time < from || point.time >= to {
            continue;
        }
        let offset = (point.time - from).num_milliseconds();
        let index = (i128::from(offset) * count as i128 / i128::from(length)) as usize;
        let slot = &mut slots[index.min(count - 1)];
        if failed(point) {
            *slot = Slot::Failed;
        } else if *slot == Slot::NotRun {
            *slot = Slot::Passed;
        }
    }
    slots
}

/// How much of a stretch of time a check passed for.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Availability {
    /// Nothing, if it didn't run at all.
    pub percent: Option<f64>,
    /// How many separate times it failed, counting runs of failures as one.
    pub failures: usize,
    /// About how long it was failing, going by the share of runs that failed.
    pub down: TimeDelta,
}

/// `points` are in time order and each covers `step`. `ran_for` is how long the
/// check is known to have run in the stretch, where that's less than its points
/// cover: a check newer than a step only filled part of its first one, which would
/// otherwise count whole.
pub fn availability(points: &[Point], step: TimeDelta, ran_for: Option<TimeDelta>) -> Availability {
    if points.is_empty() {
        return Availability {
            percent: None,
            failures: 0,
            down: TimeDelta::zero(),
        };
    }
    let passed: f64 = points.iter().map(|point| point.avg.clamp(0.0, 1.0)).sum();
    let share = passed / points.len() as f64;
    let mut failures = 0;
    let mut failing = false;
    let mut last: Option<Timestamp> = None;
    for point in points {
        // A gap with nothing run ends a failure, as far as anyone can tell.
        let follows = last.is_some_and(|last| point.time - last <= step);
        if failed(point) && !(failing && follows) {
            failures += 1;
        }
        failing = failed(point);
        last = Some(point.time);
    }
    let covered = step * i32::try_from(points.len()).unwrap_or(i32::MAX);
    let ran_for = ran_for.map_or(covered, |ran_for| ran_for.clamp(TimeDelta::zero(), covered));
    let down = (1.0 - share) * ran_for.num_milliseconds() as f64;
    Availability {
        percent: Some(share * 100.0),
        failures,
        down: TimeDelta::milliseconds(down.round() as i64),
    }
}

/// How long a check has been the way it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Streak {
    pub passing: bool,
    /// When it became so, as near as the points say.
    pub since: Timestamp,
    /// Whether that's only where the points start, so it may be longer.
    pub or_longer: bool,
}

/// `points` are in time order and each covers `step`. Nothing, with no points.
pub fn streak(points: &[Point], step: TimeDelta) -> Option<Streak> {
    let last = points.last()?;
    let passing = !failed(last);
    let changed = points.iter().rposition(|point| failed(point) == passing);
    Some(match changed {
        // It changed at the end of the last point that was the other way.
        Some(index) => Streak {
            passing,
            since: points[index].time + step,
            or_longer: false,
        },
        None => Streak {
            passing,
            since: points[0].time,
            or_longer: true,
        },
    })
}

/// A share of time as a percentage, with enough decimals to tell 99.9 from 100.
pub fn percent_text(percent: f64) -> String {
    if percent >= 100.0 {
        "100%".to_string()
    } else if percent >= 99.9 {
        // Never rounded up to 100, which would hide a failure.
        format!("{:.2}%", (percent * 100.0).floor() / 100.0)
    } else {
        format!("{:.1}%", (percent * 10.0).floor() / 10.0)
    }
}

/// A length of time in its two largest units, such as "5 days 14 hours".
pub fn span_text(length: TimeDelta) -> String {
    let part = |count: i64, unit: &str| match count {
        1 => format!("1 {unit}"),
        _ => format!("{count} {unit}s"),
    };
    let secs = length.num_seconds().max(0);
    let (days, hours, minutes) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    match (days, hours, minutes) {
        (0, 0, 0) => "under a minute".to_string(),
        (0, 0, minutes) => part(minutes, "minute"),
        (0, hours, 0) => part(hours, "hour"),
        (0, hours, minutes) => format!("{} {}", part(hours, "hour"), part(minutes, "minute")),
        (days, 0, _) => part(days, "day"),
        (days, hours, _) => format!("{} {}", part(days, "day"), part(hours, "hour")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::times::from_ms;

    const MINUTE: TimeDelta = TimeDelta::minutes(1);

    /// The start of the points.
    fn start() -> Timestamp {
        from_ms(1_795_000_000_000)
    }

    /// One point a minute from the start, each the share of its runs that passed.
    fn points(passed: &[f64]) -> Vec<Point> {
        passed
            .iter()
            .enumerate()
            .map(|(index, avg)| Point {
                time: start() + MINUTE * index as i32,
                avg: *avg,
                min: avg.floor(),
                max: avg.ceil(),
            })
            .collect()
    }

    #[test]
    fn slots_say_whether_anything_in_them_failed() {
        let points = points(&[1.0, 1.0, 0.5, 1.0, 1.0, 1.0]);
        // Three slots of two minutes, then one nothing ran in.
        let slots = slots(&points, start(), start() + MINUTE * 8, 4);
        assert_eq!(
            slots,
            [Slot::Passed, Slot::Failed, Slot::Passed, Slot::NotRun]
        );
        // Points outside the stretch aren't in any slot.
        assert_eq!(
            super::slots(&points, start() + MINUTE * 10, start() + MINUTE * 12, 1),
            [Slot::NotRun]
        );
        assert!(
            super::slots(&points, start(), start(), 3)
                .iter()
                .all(|slot| *slot == Slot::NotRun)
        );
    }

    #[test]
    fn availability_counts_each_run_of_failures_once() {
        let always = availability(&points(&[1.0; 10]), MINUTE, None);
        assert_eq!(always.percent, Some(100.0));
        assert_eq!((always.failures, always.down), (0, TimeDelta::zero()));

        // Down for two minutes, up, then half of one minute's runs failed.
        let some = availability(
            &points(&[1.0, 0.0, 0.0, 1.0, 0.5, 1.0, 1.0, 1.0, 1.0, 1.0]),
            MINUTE,
            None,
        );
        assert_eq!(some.percent, Some(75.0));
        assert_eq!(some.failures, 2);
        assert_eq!(some.down, TimeDelta::seconds(150));

        let never_ran = availability(&[], MINUTE, None);
        assert_eq!(never_ran.percent, None);
    }

    #[test]
    fn a_new_check_is_never_down_for_longer_than_it_has_run() {
        // One coarse step of an hour, though it has only run for ten minutes.
        let one = points(&[0.0]);
        let hour = MINUTE * 60;
        assert_eq!(availability(&one, hour, None).down, hour);
        assert_eq!(
            availability(&one, hour, Some(MINUTE * 10)).down,
            MINUTE * 10
        );
        // Never more than the points cover, whatever it's told.
        assert_eq!(availability(&one, hour, Some(hour * 3)).down, hour);
    }

    #[test]
    fn a_gap_between_failures_makes_them_two() {
        let mut points = points(&[0.0, 0.0]);
        points[1].time = start() + MINUTE * 30;
        assert_eq!(availability(&points, MINUTE, None).failures, 2);
    }

    #[test]
    fn a_streak_starts_where_the_other_state_ended() {
        let up = streak(&points(&[1.0, 0.0, 1.0, 1.0]), MINUTE).unwrap();
        assert_eq!(
            (up.passing, up.since, up.or_longer),
            (true, start() + MINUTE * 2, false)
        );
        let down = streak(&points(&[1.0, 1.0, 0.0, 0.0]), MINUTE).unwrap();
        assert_eq!(
            (down.passing, down.since, down.or_longer),
            (false, start() + MINUTE * 2, false)
        );
        // With nothing the other way, it's been so for at least as long as is known.
        let whole = streak(&points(&[1.0, 1.0]), MINUTE).unwrap();
        assert_eq!(
            (whole.passing, whole.since, whole.or_longer),
            (true, start(), true)
        );
        assert_eq!(streak(&[], MINUTE), None);
    }

    #[test]
    fn percentages_never_round_a_failure_away() {
        assert_eq!(percent_text(100.0), "100%");
        assert_eq!(percent_text(99.999), "99.99%");
        assert_eq!(percent_text(99.95), "99.95%");
        assert_eq!(percent_text(97.26), "97.2%");
        assert_eq!(percent_text(0.0), "0.0%");
    }

    #[test]
    fn spans_read_in_their_two_largest_units() {
        assert_eq!(span_text(TimeDelta::seconds(20)), "under a minute");
        assert_eq!(span_text(MINUTE * 40), "40 minutes");
        assert_eq!(span_text(MINUTE * 60), "1 hour");
        assert_eq!(span_text(MINUTE * 61), "1 hour 1 minute");
        assert_eq!(span_text(MINUTE * 134 * 60), "5 days 14 hours");
        assert_eq!(span_text(MINUTE * (48 * 60 + 5)), "2 days");
    }
}
