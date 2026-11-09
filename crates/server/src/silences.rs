//! Silences: being told nothing about some alerts for a while, as during planned work.
//! An alert that's silenced still fires and still shows, and only its notifications
//! wait. If it's still firing when the silence ends, they're sent then. Maintenance
//! windows work the same way, on a schedule.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::alerting::Alert;
use crate::facts::FlatFacts;
use crate::host_filter::HostFilter;
use crate::maintenance::MaintenanceWindow;
use crate::models::Database;
use crate::remote_checks::FLEET_AGENT_ID;

const MAX_REASON_CHARS: usize = 255;
const MAX_FILTER_CHARS: usize = 500;
const MAX_DURATION_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Silence {
    pub id: i64,
    /// Every rule, if empty.
    pub rule_id: Option<i64>,
    /// Which hosts, in the same form as the host list. Every host, if empty.
    pub filter: String,
    pub reason: String,
    pub created_by: String,
    pub starts_ms: i64,
    pub ends_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SilenceInput {
    #[serde(default)]
    pub rule_id: Option<i64>,
    #[serde(default)]
    pub filter: String,
    pub reason: String,
    pub duration_secs: u64,
}

/// A silence covering just this alert: its rule, on its machine, by ID, as names
/// needn't be unique. An alert about the fleet has no machine, so its rule alone.
pub fn silence_for(alert: &Alert, reason: &str, duration_secs: u64) -> SilenceInput {
    let filter = if alert.agent_id == FLEET_AGENT_ID {
        String::new()
    } else {
        crate::host_filter::only(&alert.agent_id)
    };
    SilenceInput {
        rule_id: alert.rule_id,
        filter,
        reason: reason.to_string(),
        duration_secs,
    }
}

/// Whether a silence makes sense, apart from whether its rule exists.
pub fn check_silence(input: &SilenceInput) -> Result<()> {
    if input.reason.trim().is_empty() {
        bail!("A silence needs a reason, so others know why they aren't being told.");
    }
    if input.reason.chars().count() > MAX_REASON_CHARS {
        bail!("The reason is too long. It can be up to {MAX_REASON_CHARS} characters.");
    }
    check_filter(&input.filter)?;
    if input.duration_secs == 0 || input.duration_secs > MAX_DURATION_SECS {
        bail!("A silence can last up to 30 days.");
    }
    Ok(())
}

/// Whether a filter can be saved for a silence or a maintenance window.
pub fn check_filter(filter: &str) -> Result<()> {
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
    Silence { id: i64, ends_ms: i64 },
    Window { id: i64, ends_ms: i64 },
}

impl Cover {
    pub fn ends_ms(self) -> i64 {
        match self {
            Self::Silence { ends_ms, .. } | Self::Window { ends_ms, .. } => ends_ms,
        }
    }
}

struct Quiet {
    cover: Cover,
    rule_id: Option<i64>,
    /// Empty if it covers every host.
    filter: Option<HostFilter>,
}

impl Quiet {
    fn new(cover: Cover, rule_id: Option<i64>, filter: &str) -> Option<Self> {
        let parsed = match HostFilter::parse(filter) {
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
            filter: (!filter.is_empty()).then_some(parsed),
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
    pub async fn load(database: &Database, now_ms: i64) -> Result<Self> {
        let silences = database.active_silences(now_ms).await?;
        let windows = database.list_maintenance_windows().await?;
        Self::load_from(database, silences, windows, now_ms).await
    }

    async fn load_from(
        database: &Database,
        silences: Vec<Silence>,
        windows: Vec<MaintenanceWindow>,
        now_ms: i64,
    ) -> Result<Self> {
        let silences = silences.into_iter().filter_map(|silence| {
            let cover = Cover::Silence {
                id: silence.id,
                ends_ms: silence.ends_ms,
            };
            Quiet::new(cover, silence.rule_id, &silence.filter)
        });
        let windows = windows.into_iter().filter_map(|window| {
            let cover = Cover::Window {
                id: window.id,
                ends_ms: window.ends_at(now_ms)?,
            };
            Quiet::new(cover, window.window.rule_id, &window.window.filter)
        });
        let mut quiet: Vec<Quiet> = silences.chain(windows).collect();
        quiet.sort_by_key(|entry| std::cmp::Reverse(entry.cover.ends_ms()));

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

    /// Whatever covers an alert for longest. A group's alert has no host to compare, so
    /// a filter never covers one.
    pub fn covering(&self, alert: &Alert) -> Option<Cover> {
        let covers = |entry: &&Quiet| {
            let rule = entry.rule_id.is_none_or(|id| alert.rule_id == Some(id));
            let host = entry.filter.as_ref().is_none_or(|filter| {
                alert.agent_id != FLEET_AGENT_ID
                    && filter.matches(
                        &alert.agent_id,
                        &alert.host,
                        self.facts.get(&alert.agent_id),
                    )
            });
            rule && host
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
            filter: "os=linux".to_string(),
            reason: "Upgrading Postgres".to_string(),
            duration_secs: 3600,
        }
    }

    #[test]
    fn a_good_silence_passes() {
        check_silence(&input()).unwrap();
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
                    filter: "x".repeat(501),
                    ..input()
                },
                "too long",
            ),
            (
                SilenceInput {
                    filter: "hostname=\"web".to_string(),
                    ..input()
                },
                "quote",
            ),
            (
                SilenceInput {
                    duration_secs: 0,
                    ..input()
                },
                "up to 30 days",
            ),
            (
                SilenceInput {
                    duration_secs: MAX_DURATION_SECS + 1,
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
