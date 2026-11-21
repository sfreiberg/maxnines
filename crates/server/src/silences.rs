//! Silences: being told nothing about some alerts for a while, as during planned work.
//! An alert that's silenced still fires and still shows, and only its notifications
//! wait. If it's still firing when the silence ends, they're sent then. Maintenance
//! windows work the same way, on a schedule.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::alerting::Alert;
use crate::facts::FlatFacts;
use crate::host_filter::HostFilter;
use crate::maintenance::MaintenanceWindow;
use crate::models::Database;
use crate::remote_checks::FLEET_HOST_ID;
use crate::times::Timestamp;

const MAX_REASON_CHARS: usize = 255;
const MAX_FILTER_CHARS: usize = 500;
const MAX_SERIES_CHARS: usize = 255;
const MAX_DURATION: TimeDelta = TimeDelta::days(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Silence {
    pub id: i64,
    /// Every rule, if empty.
    pub rule_id: Option<i64>,
    /// Which hosts, in the same form as the Hosts list. Every host, if none.
    pub filter: Option<String>,
    /// The one series it's for, such as a check's name. Every series, if none.
    pub series: Option<String>,
    /// Whether it covers every alert there is, having no rule, filter or series.
    pub all_alerts: bool,
    pub reason: String,
    pub created_by: String,
    pub starts_at: Timestamp,
    pub ends_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SilenceInput {
    #[serde(default)]
    pub rule_id: Option<i64>,
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub filter: Option<String>,
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub series: Option<String>,
    /// Has to be said to cover every alert, with no rule, filter or series, so that
    /// leaving them out never does by accident.
    #[serde(default)]
    pub all_alerts: bool,
    pub reason: String,
    #[serde(rename = "duration_secs", with = "crate::times::whole_seconds")]
    pub duration: TimeDelta,
}

/// A silence covering just this alert: its rule, on its host, by ID, as names
/// needn't be unique, for its series. An alert about the fleet has no host, and a
/// filter would leave it out, so it has none.
pub fn silence_for(alert: &Alert, reason: &str, duration: TimeDelta) -> SilenceInput {
    let filter = (alert.host_id != FLEET_HOST_ID).then(|| crate::host_filter::only(&alert.host_id));
    SilenceInput {
        rule_id: Some(alert.rule_id),
        filter,
        series: alert.series.clone(),
        all_alerts: false,
        reason: reason.to_string(),
        duration,
    }
}

/// Whether what a silence or maintenance window covers is said plainly: every alert
/// only when asked for by name, and never by leaving everything out. A maintenance
/// window has no series to name.
pub fn check_covers(
    what: &str,
    rule_id: Option<i64>,
    filter: Option<&str>,
    series: Covered,
    all_alerts: bool,
) -> Result<()> {
    let names_nothing = rule_id.is_none() && filter.is_none() && !matches!(series, Covered::One);
    let choices = match series {
        Covered::NoSeries => "a rule or hosts",
        Covered::Every | Covered::One => "a rule, hosts or a series",
    };
    if names_nothing && !all_alerts {
        bail!(
            "Choose what the {what} covers: {choices}. To cover every alert on every host, \
             choose every alert."
        );
    }
    if all_alerts && !names_nothing {
        bail!("A {what} for every alert can't also name {choices}.");
    }
    Ok(())
}

/// Which series something covers, for [`check_covers`].
#[derive(Debug, Clone, Copy)]
pub enum Covered {
    /// It has no series to name, as a maintenance window hasn't.
    NoSeries,
    Every,
    One,
}

/// Whether a silence makes sense, apart from whether its rule exists.
pub fn check_silence(input: &SilenceInput) -> Result<()> {
    if input.reason.trim().is_empty() {
        bail!("A silence needs a reason, so others know why they aren't being told.");
    }
    if input.reason.chars().count() > MAX_REASON_CHARS {
        bail!("The reason is too long. It can be up to {MAX_REASON_CHARS} characters.");
    }
    check_filter(input.filter.as_deref())?;
    if input
        .series
        .as_ref()
        .is_some_and(|series| series.chars().count() > MAX_SERIES_CHARS)
    {
        bail!("The series is too long. It can be up to {MAX_SERIES_CHARS} characters.");
    }
    if input.duration <= TimeDelta::zero() || input.duration > MAX_DURATION {
        bail!("A silence can last up to 30 days.");
    }
    check_covers(
        "silence",
        input.rule_id,
        input.filter.as_deref(),
        if input.series.is_some() {
            Covered::One
        } else {
            Covered::Every
        },
        input.all_alerts,
    )
}

/// Whether a filter can be saved for a silence or a maintenance window.
pub fn check_filter(filter: Option<&str>) -> Result<()> {
    let Some(filter) = filter else {
        return Ok(());
    };
    if filter.chars().count() > MAX_FILTER_CHARS {
        bail!("The filter is too long. It can be up to {MAX_FILTER_CHARS} characters.");
    }
    if let Err(error) = HostFilter::parse(filter) {
        bail!("{error}");
    }
    Ok(())
}

/// What's keeping an alert's notifications back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    Silence { id: i64, ends_at: Timestamp },
    Window { id: i64, ends_at: Timestamp },
}

impl Cover {
    pub fn ends_at(self) -> Timestamp {
        match self {
            Self::Silence { ends_at, .. } | Self::Window { ends_at, .. } => ends_at,
        }
    }
}

struct Quiet {
    cover: Cover,
    rule_id: Option<i64>,
    /// None if it covers every host.
    filter: Option<HostFilter>,
    /// None if it covers every series.
    series: Option<String>,
}

impl Quiet {
    fn new(
        cover: Cover,
        rule_id: Option<i64>,
        filter: Option<&str>,
        series: Option<&str>,
    ) -> Option<Self> {
        let filter = match filter.map(HostFilter::parse).transpose() {
            Ok(parsed) => parsed,
            // Filters are checked when saved, so only a change to filters gets here.
            Err(error) => {
                warn!(?cover, error, "ignoring something with a bad filter");
                return None;
            }
        };
        Some(Self {
            cover,
            rule_id,
            filter,
            series: series.map(str::to_string),
        })
    }
}

/// The silences and maintenance windows running at one moment, ready to compare with
/// alerts.
pub struct ActiveSilences {
    quiet: Vec<Quiet>,
    facts: BTreeMap<String, FlatFacts>,
}

impl ActiveSilences {
    pub async fn load(database: &Database, now: Timestamp) -> Result<Self> {
        let silences = database.active_silences(now).await?;
        let windows = database.list_maintenance_windows().await?;
        Self::load_from(database, silences, windows, now).await
    }

    async fn load_from(
        database: &Database,
        silences: Vec<Silence>,
        windows: Vec<MaintenanceWindow>,
        now: Timestamp,
    ) -> Result<Self> {
        let silences = silences.into_iter().filter_map(|silence| {
            let cover = Cover::Silence {
                id: silence.id,
                ends_at: silence.ends_at,
            };
            Quiet::new(
                cover,
                silence.rule_id,
                silence.filter.as_deref(),
                silence.series.as_deref(),
            )
        });
        let windows = windows.into_iter().filter_map(|window| {
            let cover = Cover::Window {
                id: window.id,
                ends_at: window.ends_at(now)?,
            };
            Quiet::new(
                cover,
                window.window.rule_id,
                window.window.filter.as_deref(),
                None,
            )
        });
        let mut quiet: Vec<Quiet> = silences.chain(windows).collect();
        quiet.sort_by_key(|entry| std::cmp::Reverse(entry.cover.ends_at()));

        let names: BTreeSet<&str> = quiet
            .iter()
            .filter_map(|entry| entry.filter.as_ref())
            .flat_map(HostFilter::fact_names)
            .collect();
        let facts = if names.is_empty() {
            BTreeMap::new()
        } else {
            let names: Vec<&str> = names.into_iter().collect();
            database.facts_named(&names).await?
        };
        Ok(Self { quiet, facts })
    }

    /// Whatever holds back every alert about a host for longest, whichever rule
    /// it's from.
    pub fn covering_host(&self, host_id: &str, hostname: &str) -> Option<Cover> {
        let covers = |entry: &&Quiet| {
            entry.rule_id.is_none()
                && entry.series.is_none()
                && self.on_host(entry, host_id, hostname)
        };
        self.quiet.iter().find(covers).map(|entry| entry.cover)
    }

    /// Whatever holds back every alert about one series of a host for longest,
    /// such as one of its checks, whichever rule it's from. What covers the whole
    /// host covers it too.
    pub fn covering_series(&self, host_id: &str, hostname: &str, series: &str) -> Option<Cover> {
        let covers = |entry: &&Quiet| {
            entry.rule_id.is_none()
                && entry.series.as_deref().is_none_or(|only| only == series)
                && self.on_host(entry, host_id, hostname)
        };
        self.quiet.iter().find(covers).map(|entry| entry.cover)
    }

    fn on_host(&self, entry: &Quiet, host_id: &str, hostname: &str) -> bool {
        let facts = self.facts.get(host_id);
        entry
            .filter
            .as_ref()
            .is_none_or(|filter| filter.matches(host_id, hostname, facts))
    }

    /// Whatever covers an alert for longest. A group's alert has no host to compare, so
    /// a filter never covers one.
    pub fn covering(&self, alert: &Alert) -> Option<Cover> {
        let covers = |entry: &&Quiet| {
            let rule = entry.rule_id.is_none_or(|id| alert.rule_id == id);
            let hostname = entry.filter.as_ref().is_none_or(|filter| {
                alert.host_id != FLEET_HOST_ID
                    && filter.matches(
                        &alert.host_id,
                        &alert.hostname,
                        self.facts.get(&alert.host_id),
                    )
            });
            let series = entry
                .series
                .as_deref()
                .is_none_or(|only| alert.series.as_deref() == Some(only));
            rule && hostname && series
        };
        self.quiet.iter().find(covers).map(|entry| entry.cover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> SilenceInput {
        SilenceInput {
            rule_id: None,
            filter: Some("os=linux".to_string()),
            series: None,
            all_alerts: false,
            reason: "Upgrading Postgres".to_string(),
            duration: TimeDelta::hours(1),
        }
    }

    #[test]
    fn a_good_silence_passes() {
        check_silence(&input()).unwrap();
    }

    #[test]
    fn every_alert_is_only_silenced_when_asked_for() {
        let everything = SilenceInput {
            filter: None,
            all_alerts: true,
            ..input()
        };
        check_silence(&everything).unwrap();
        // Leaving out what it covers isn't asking for everything.
        let error = check_silence(&SilenceInput {
            all_alerts: false,
            ..everything.clone()
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("a rule, hosts or a series"), "{error}");
        // Naming any of them means it isn't everything.
        for named in [
            SilenceInput {
                rule_id: Some(1),
                ..everything.clone()
            },
            SilenceInput {
                series: Some("/var".to_string()),
                ..everything.clone()
            },
            SilenceInput {
                filter: Some("os=linux".to_string()),
                ..everything.clone()
            },
        ] {
            let error = check_silence(&named).unwrap_err().to_string();
            assert!(error.contains("can't also name"), "{error}");
        }
    }

    #[test]
    fn bad_silences_are_refused_with_a_reason() {
        for (bad, expected) in [
            (
                SilenceInput {
                    reason: "  ".to_string(),
                    ..input()
                },
                "needs a reason",
            ),
            (
                SilenceInput {
                    reason: "x".repeat(256),
                    ..input()
                },
                "too long",
            ),
            (
                SilenceInput {
                    filter: Some("x".repeat(501)),
                    ..input()
                },
                "too long",
            ),
            (
                SilenceInput {
                    filter: Some("hostname=\"web".to_string()),
                    ..input()
                },
                "quote",
            ),
            (
                SilenceInput {
                    duration: TimeDelta::zero(),
                    ..input()
                },
                "up to 30 days",
            ),
            (
                SilenceInput {
                    duration: MAX_DURATION + TimeDelta::seconds(1),
                    ..input()
                },
                "up to 30 days",
            ),
        ] {
            let error = check_silence(&bad).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }
}
