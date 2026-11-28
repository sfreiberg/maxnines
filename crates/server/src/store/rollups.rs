//! What both stores share about keeping metrics: how long each resolution lasts,
//! which one a chart reads, and when an hour is ready to roll up.
//!
//! Rollups are made from what charts show, a metric from the catalog at a time, the
//! built-in ones and each template's alike, with
//! percentages and rates already worked out. So 5 minutes or an hour keeps the lowest,
//! highest and total of the values a chart would have drawn, and a spike in a rate
//! survives as well as one in a percentage. An hour is rolled up once it's over: its
//! 5 minute spans from the samples, and the hour itself from those.

use std::collections::BTreeSet;

use chrono::TimeDelta;

use crate::config::RetentionConfig;
use crate::times::{Timestamp, hour_of};

/// The finer of the two rollups. A chart has at most 240 points, so this is as fine
/// as one of 20 hours or more can show, and a year of it takes a fifth of the space of
/// minutes.
pub const FIVE_MINUTES: TimeDelta = TimeDelta::minutes(5);
pub const HOUR: TimeDelta = TimeDelta::hours(1);

/// How long after an hour ends before it's rolled up, so samples a few minutes late,
/// such as from agents reconnecting after a restart, are in it. Anything later has its
/// hour rolled up again.
pub const SETTLE: TimeDelta = TimeDelta::minutes(5);

/// How far before a span the samples are read when working out rates, as each rate
/// needs the sample before it. Agents report every 15 seconds unless told otherwise.
pub const RATE_LEAD: TimeDelta = TimeDelta::minutes(10);

/// How often old data is looked for to delete.
pub const EXPIRE_EVERY: TimeDelta = HOUR;

/// The resolutions a metric is kept at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Full,
    FiveMinutes,
    Hour,
}

impl Tier {
    /// The table a rolled-up tier is kept in.
    pub fn table(self) -> Option<&'static str> {
        match self {
            Self::Full => None,
            Self::FiveMinutes => Some("rollups_five_minute"),
            Self::Hour => Some("rollups_hour"),
        }
    }
}

/// How long each resolution is kept. Hours can be kept for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub full: TimeDelta,
    pub five_minute: TimeDelta,
    pub hour: Option<TimeDelta>,
}

impl From<RetentionConfig> for Retention {
    fn from(config: RetentionConfig) -> Self {
        let days = |days: u32| TimeDelta::days(i64::from(days));
        Self {
            full: days(config.full_resolution_days),
            five_minute: days(config.five_minute_days),
            hour: config.hour_days.map(days),
        }
    }
}

impl Retention {
    /// For tests, whose samples can be from any time at all.
    #[cfg(test)]
    pub const KEEP_EVERYTHING: Self = Self {
        full: TimeDelta::MAX,
        five_minute: TimeDelta::MAX,
        hour: None,
    };
}

impl Default for Retention {
    fn default() -> Self {
        RetentionConfig::default().into()
    }
}

/// The moment `kept` before `now`, before which something kept that long goes. Nothing
/// does if that's further back than a moment can be.
pub fn kept_since(now: Timestamp, kept: TimeDelta) -> Option<Timestamp> {
    now.checked_sub_signed(kept)
}

/// Which resolution a chart reads. The coarsest that fits evenly into its step is just
/// as exact and much quicker, and a range reaching back past what's kept at a finer
/// resolution reads a coarser one. Whatever isn't rolled up yet comes from the samples.
pub fn tier_for(step: TimeDelta, from: Timestamp, now: Timestamp, retention: &Retention) -> Tier {
    let fits = |span: TimeDelta| step.num_milliseconds() % span.num_milliseconds() == 0;
    let mut tier = if fits(HOUR) {
        Tier::Hour
    } else if fits(FIVE_MINUTES) {
        Tier::FiveMinutes
    } else {
        Tier::Full
    };
    let older_than = |kept| kept_since(now, kept).is_some_and(|since| from < since);
    if tier == Tier::Full && older_than(retention.full) {
        tier = Tier::FiveMinutes;
    }
    if tier == Tier::FiveMinutes && older_than(retention.five_minute) {
        tier = Tier::Hour;
    }
    tier
}

/// Whether an hour is over and settled, and so ready to roll up.
pub fn is_due(hour: Timestamp, now: Timestamp) -> bool {
    hour + HOUR + SETTLE <= now
}

/// The hours that samples at these times change, of those already rolled up and still
/// kept at full resolution. A rate's first sample in an hour reaches back to the one
/// before, so a sample also changes the hour after its own.
pub fn hours_to_redo(
    times: impl IntoIterator<Item = Timestamp>,
    rolled_up_until: Timestamp,
    full_since: Option<Timestamp>,
) -> BTreeSet<Timestamp> {
    let mut hours = BTreeSet::new();
    for time in times {
        let hour = hour_of(time);
        for hour in [hour, hour + HOUR] {
            let still_full = full_since.is_none_or(|since| hour >= hour_of(since));
            if hour < rolled_up_until && still_full {
                hours.insert(hour);
            }
        }
    }
    hours
}

/// Before this, samples can be deleted: they're older than full resolution is kept,
/// and every metric has rolled them up, with none waiting to be rolled up again. So a
/// rollup that falls behind keeps the samples instead of losing them.
pub fn full_resolution_cutoff(
    now: Timestamp,
    retention: &Retention,
    rolled_up_until: Option<Timestamp>,
    first_redo: Option<Timestamp>,
) -> Option<Timestamp> {
    let cutoff = [kept_since(now, retention.full)?, rolled_up_until?]
        .into_iter()
        .chain(first_redo)
        .min()?;
    Some(hour_of(cutoff))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::times::from_ms;

    const DAY: TimeDelta = TimeDelta::days(1);

    fn now() -> Timestamp {
        from_ms(1_000 * DAY.num_milliseconds())
    }

    /// The start of the `n`th hour after 1970.
    fn hour(n: i32) -> Timestamp {
        from_ms(0) + HOUR * n
    }

    fn retention() -> Retention {
        Retention {
            full: DAY * 30,
            five_minute: DAY * 365,
            hour: None,
        }
    }

    #[test]
    fn a_chart_reads_the_coarsest_resolution_that_fits_its_step() {
        let recent = now() - HOUR;
        let tier = |step| tier_for(step, recent, now(), &retention());
        assert_eq!(tier(TimeDelta::seconds(15)), Tier::Full);
        assert_eq!(tier(TimeDelta::seconds(30)), Tier::Full);
        assert_eq!(tier(TimeDelta::minutes(2)), Tier::Full);
        assert_eq!(tier(TimeDelta::minutes(5)), Tier::FiveMinutes);
        assert_eq!(tier(TimeDelta::minutes(15)), Tier::FiveMinutes);
        assert_eq!(tier(HOUR * 3), Tier::Hour);
    }

    #[test]
    fn a_range_older_than_a_resolution_is_kept_reads_a_coarser_one() {
        let two_months_ago = now() - DAY * 60;
        assert_eq!(
            tier_for(TimeDelta::seconds(15), two_months_ago, now(), &retention()),
            Tier::FiveMinutes
        );
        let two_years_ago = now() - DAY * 730;
        assert_eq!(
            tier_for(TimeDelta::seconds(15), two_years_ago, now(), &retention()),
            Tier::Hour
        );
        assert_eq!(
            tier_for(TimeDelta::minutes(2), two_years_ago, now(), &retention()),
            Tier::Hour
        );
        // Kept for good, however far back.
        assert_eq!(
            tier_for(
                TimeDelta::seconds(15),
                two_years_ago,
                now(),
                &Retention::KEEP_EVERYTHING
            ),
            Tier::Full
        );
    }

    #[test]
    fn an_hour_is_rolled_up_once_it_has_settled() {
        let hour = hour(10);
        let millisecond = TimeDelta::milliseconds(1);
        assert!(!is_due(hour, hour + HOUR));
        assert!(!is_due(hour, hour + HOUR + SETTLE - millisecond));
        assert!(is_due(hour, hour + HOUR + SETTLE));
    }

    #[test]
    fn a_late_sample_redoes_its_hour_and_the_next() {
        let late = hour(5) + TimeDelta::milliseconds(10);
        let hours = hours_to_redo([late], hour(20), Some(hour(0)));
        assert_eq!(hours.into_iter().collect::<Vec<_>>(), [hour(5), hour(6)]);
    }

    #[test]
    fn only_rolled_up_hours_still_at_full_resolution_are_redone() {
        // Not rolled up yet, so it'll be included when it is.
        assert!(hours_to_redo([hour(30)], hour(20), Some(hour(0))).is_empty());
        // Its samples are already going, so rolling it up again would lose the rest.
        assert!(hours_to_redo([hour(5)], hour(20), Some(hour(10))).is_empty());
        // The hour after the last one rolled up isn't rolled up either.
        let late = hour(19) + TimeDelta::milliseconds(5);
        let hours = hours_to_redo([late], hour(20), Some(hour(0)));
        assert_eq!(hours.into_iter().collect::<Vec<_>>(), [hour(19)]);
    }

    #[test]
    fn samples_go_only_once_rolled_up_and_older_than_they_are_kept() {
        let retention = retention();
        let now = now();
        let old = now - retention.full;
        assert_eq!(
            full_resolution_cutoff(now, &retention, Some(now), None),
            Some(hour_of(old))
        );
        // Behind on rolling up: what's not rolled up stays.
        let behind = old - HOUR * 50;
        assert_eq!(
            full_resolution_cutoff(now, &retention, Some(behind), None),
            Some(behind)
        );
        // An hour waiting to be redone keeps its samples.
        let redo = old - HOUR * 3;
        assert_eq!(
            full_resolution_cutoff(now, &retention, Some(now), Some(redo)),
            Some(redo)
        );
        // Nothing rolled up yet: nothing goes.
        assert_eq!(full_resolution_cutoff(now, &retention, None, None), None);
        // Kept for good: nothing goes either.
        let everything = Retention::KEEP_EVERYTHING;
        assert_eq!(
            full_resolution_cutoff(now, &everything, Some(now), None),
            None
        );
    }

    #[test]
    fn retention_comes_from_days() {
        let retention = Retention::from(RetentionConfig {
            full_resolution_days: 2,
            five_minute_days: 3,
            hour_days: Some(4),
        });
        assert_eq!(retention.full, DAY * 2);
        assert_eq!(retention.five_minute, DAY * 3);
        assert_eq!(retention.hour, Some(DAY * 4));
    }
}
