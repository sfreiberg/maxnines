//! What both stores share about keeping metrics: how long each resolution lasts,
//! which one a chart reads, and when an hour is ready to roll up.
//!
//! Rollups are made from what charts show, a metric from the catalog at a time, with
//! percentages and rates already worked out. So 5 minutes or an hour keeps the lowest,
//! highest and total of the values a chart would have drawn, and a spike in a rate
//! survives as well as one in a percentage. An hour is rolled up once it's over: its
//! 5 minute spans from the samples, and the hour itself from those.

use std::collections::BTreeSet;

use crate::config::RetentionConfig;
use crate::metrics::METRICS;

pub const MINUTE_MS: i64 = 60_000;
/// The finer of the two rollups. A chart has at most 240 points, so this is as fine
/// as one of 20 hours or more can show, and a year of it takes a fifth of the space of
/// minutes.
pub const FIVE_MINUTES_MS: i64 = 5 * MINUTE_MS;
pub const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// How long after an hour ends before it's rolled up, so samples a few minutes late,
/// such as from agents reconnecting after a restart, are in it. Anything later has its
/// hour rolled up again.
pub const SETTLE_MS: i64 = 5 * MINUTE_MS;

/// How far before a span the samples are read when working out rates, as each rate
/// needs the sample before it. Agents report every 15 seconds unless told otherwise.
pub const RATE_LEAD_MS: i64 = 10 * MINUTE_MS;

/// How often old data is looked for to delete.
pub const EXPIRE_EVERY_MS: i64 = HOUR_MS;

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

/// How long each resolution is kept, in milliseconds. Hours can be kept for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub full_ms: i64,
    pub five_minute_ms: i64,
    pub hour_ms: Option<i64>,
}

impl From<RetentionConfig> for Retention {
    fn from(config: RetentionConfig) -> Self {
        let days = |days: u32| i64::from(days) * DAY_MS;
        Self {
            full_ms: days(config.full_resolution_days),
            five_minute_ms: days(config.five_minute_days),
            hour_ms: config.hour_days.map(days),
        }
    }
}

impl Retention {
    /// For tests, whose samples can be from any time at all.
    #[cfg(test)]
    pub const KEEP_EVERYTHING: Self = Self {
        full_ms: i64::MAX / 4,
        five_minute_ms: i64::MAX / 4,
        hour_ms: None,
    };
}

impl Default for Retention {
    fn default() -> Self {
        RetentionConfig::default().into()
    }
}

/// Which resolution a chart reads. The coarsest that fits evenly into its step is just
/// as exact and much quicker, and a range reaching back past what's kept at a finer
/// resolution reads a coarser one. Whatever isn't rolled up yet comes from the samples.
pub fn tier_for(step_ms: i64, from_ms: i64, now_ms: i64, retention: &Retention) -> Tier {
    let mut tier = if step_ms % HOUR_MS == 0 {
        Tier::Hour
    } else if step_ms % FIVE_MINUTES_MS == 0 {
        Tier::FiveMinutes
    } else {
        Tier::Full
    };
    if tier == Tier::Full && from_ms < now_ms.saturating_sub(retention.full_ms) {
        tier = Tier::FiveMinutes;
    }
    if tier == Tier::FiveMinutes && from_ms < now_ms.saturating_sub(retention.five_minute_ms) {
        tier = Tier::Hour;
    }
    tier
}

pub fn hour_of(time_ms: i64) -> i64 {
    time_ms.div_euclid(HOUR_MS) * HOUR_MS
}

/// Whether an hour is over and settled, and so ready to roll up.
pub fn is_due(hour_ms: i64, now_ms: i64) -> bool {
    hour_ms.saturating_add(HOUR_MS + SETTLE_MS) <= now_ms
}

/// The hours that samples at these times change, of those already rolled up and still
/// kept at full resolution. A rate's first sample in an hour reaches back to the one
/// before, so a sample also changes the hour after its own.
pub fn hours_to_redo(
    times_ms: impl IntoIterator<Item = i64>,
    rolled_up_until: i64,
    full_since: i64,
) -> BTreeSet<i64> {
    let mut hours = BTreeSet::new();
    for time in times_ms {
        let hour = hour_of(time);
        for hour in [hour, hour + HOUR_MS] {
            if hour < rolled_up_until && hour >= hour_of(full_since) {
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
    now_ms: i64,
    retention: &Retention,
    rolled_up_until: Option<i64>,
    first_redo: Option<i64>,
) -> Option<i64> {
    let rolled_up_until = rolled_up_until?;
    let cutoff = [now_ms - retention.full_ms, rolled_up_until]
        .into_iter()
        .chain(first_redo)
        .min()?;
    Some(hour_of(cutoff))
}

/// Every metric the catalog has, which is what gets rolled up.
pub fn metric_names() -> impl Iterator<Item = &'static str> {
    METRICS.iter().map(|metric| metric.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000 * DAY_MS;

    fn retention() -> Retention {
        Retention {
            full_ms: 30 * DAY_MS,
            five_minute_ms: 365 * DAY_MS,
            hour_ms: None,
        }
    }

    #[test]
    fn a_chart_reads_the_coarsest_resolution_that_fits_its_step() {
        let recent = NOW - HOUR_MS;
        assert_eq!(tier_for(15_000, recent, NOW, &retention()), Tier::Full);
        assert_eq!(tier_for(30_000, recent, NOW, &retention()), Tier::Full);
        assert_eq!(tier_for(120_000, recent, NOW, &retention()), Tier::Full);
        assert_eq!(
            tier_for(300_000, recent, NOW, &retention()),
            Tier::FiveMinutes
        );
        assert_eq!(
            tier_for(900_000, recent, NOW, &retention()),
            Tier::FiveMinutes
        );
        assert_eq!(tier_for(3 * HOUR_MS, recent, NOW, &retention()), Tier::Hour);
    }

    #[test]
    fn a_range_older_than_a_resolution_is_kept_reads_a_coarser_one() {
        let two_months_ago = NOW - 60 * DAY_MS;
        assert_eq!(
            tier_for(15_000, two_months_ago, NOW, &retention()),
            Tier::FiveMinutes
        );
        let two_years_ago = NOW - 730 * DAY_MS;
        assert_eq!(
            tier_for(15_000, two_years_ago, NOW, &retention()),
            Tier::Hour
        );
        assert_eq!(
            tier_for(120_000, two_years_ago, NOW, &retention()),
            Tier::Hour
        );
    }

    #[test]
    fn an_hour_is_rolled_up_once_it_has_settled() {
        let hour = 10 * HOUR_MS;
        assert!(!is_due(hour, hour + HOUR_MS));
        assert!(!is_due(hour, hour + HOUR_MS + SETTLE_MS - 1));
        assert!(is_due(hour, hour + HOUR_MS + SETTLE_MS));
    }

    #[test]
    fn a_late_sample_redoes_its_hour_and_the_next() {
        let hours = hours_to_redo([5 * HOUR_MS + 10], 20 * HOUR_MS, 0);
        assert_eq!(
            hours.into_iter().collect::<Vec<_>>(),
            [5 * HOUR_MS, 6 * HOUR_MS]
        );
    }

    #[test]
    fn only_rolled_up_hours_still_at_full_resolution_are_redone() {
        // Not rolled up yet, so it'll be included when it is.
        assert!(hours_to_redo([30 * HOUR_MS], 20 * HOUR_MS, 0).is_empty());
        // Its samples are already going, so rolling it up again would lose the rest.
        assert!(hours_to_redo([5 * HOUR_MS], 20 * HOUR_MS, 10 * HOUR_MS).is_empty());
        // The hour after the last one rolled up isn't rolled up either.
        let hours = hours_to_redo([19 * HOUR_MS + 5], 20 * HOUR_MS, 0);
        assert_eq!(hours.into_iter().collect::<Vec<_>>(), [19 * HOUR_MS]);
    }

    #[test]
    fn samples_go_only_once_rolled_up_and_older_than_they_are_kept() {
        let retention = retention();
        let old = NOW - retention.full_ms;
        assert_eq!(
            full_resolution_cutoff(NOW, &retention, Some(NOW), None),
            Some(hour_of(old))
        );
        // Behind on rolling up: what's not rolled up stays.
        let behind = old - 50 * HOUR_MS;
        assert_eq!(
            full_resolution_cutoff(NOW, &retention, Some(behind), None),
            Some(behind)
        );
        // An hour waiting to be redone keeps its samples.
        let redo = old - 3 * HOUR_MS;
        assert_eq!(
            full_resolution_cutoff(NOW, &retention, Some(NOW), Some(redo)),
            Some(redo)
        );
        // Nothing rolled up yet: nothing goes.
        assert_eq!(full_resolution_cutoff(NOW, &retention, None, None), None);
    }

    #[test]
    fn retention_comes_from_days() {
        let retention = Retention::from(RetentionConfig {
            full_resolution_days: 2,
            five_minute_days: 3,
            hour_days: Some(4),
        });
        assert_eq!(retention.full_ms, 2 * DAY_MS);
        assert_eq!(retention.five_minute_ms, 3 * DAY_MS);
        assert_eq!(retention.hour_ms, Some(4 * DAY_MS));
    }
}
