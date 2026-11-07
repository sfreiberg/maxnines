//! Silences: being told nothing about some alerts for a while, as during planned work.
//! An alert that's silenced still fires and still shows, and only its notifications
//! wait. If it's still firing when the silence ends, they're sent then.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::alerting::Alert;
use crate::facts::FlatFacts;
use crate::host_filter::HostFilter;
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

/// Whether a silence makes sense, apart from whether its rule exists.
pub fn check_silence(input: &SilenceInput) -> Result<()> {
    if input.reason.trim().is_empty() {
        bail!("A silence needs a reason, so others know why they aren't being told.");
    }
    if input.reason.chars().count() > MAX_REASON_CHARS {
        bail!("The reason is too long. It can be up to {MAX_REASON_CHARS} characters.");
    }
    if input.filter.chars().count() > MAX_FILTER_CHARS {
        bail!("The filter is too long. It can be up to {MAX_FILTER_CHARS} characters.");
    }
    if let Err(error) = HostFilter::parse(&input.filter) {
        bail!("{error}");
    }
    if input.duration_secs == 0 || input.duration_secs > MAX_DURATION_SECS {
        bail!("A silence can last up to 30 days.");
    }
    Ok(())
}

/// The silences running at one moment, ready to compare with alerts.
pub struct ActiveSilences {
    silences: Vec<(Silence, HostFilter)>,
    facts: BTreeMap<String, FlatFacts>,
}

impl ActiveSilences {
    pub async fn load(database: &Database, now_ms: i64) -> Result<Self> {
        let mut silences = Vec::new();
        for silence in database.active_silences(now_ms).await? {
            match HostFilter::parse(&silence.filter) {
                Ok(filter) => silences.push((silence, filter)),
                // Filters are checked when saved, so only a change to filters gets here.
                Err(error) => warn!(id = silence.id, error, "ignoring a silence's filter"),
            }
        }

        let names: BTreeSet<&str> = silences
            .iter()
            .flat_map(|(_, filter)| filter.fact_names())
            .collect();
        let facts = if names.is_empty() {
            BTreeMap::new()
        } else {
            let names: Vec<&str> = names.into_iter().collect();
            database.facts_named(&names).await?
        };
        Ok(Self { silences, facts })
    }

    /// The longest lasting silence that covers an alert. A group's alert has no host to
    /// compare, so a filter never covers one.
    pub fn covering(&self, alert: &Alert) -> Option<&Silence> {
        let covers = |silence: &Silence, filter: &HostFilter| {
            let rule = silence.rule_id.is_none_or(|id| alert.rule_id == Some(id));
            let host = silence.filter.is_empty()
                || (alert.agent_id != FLEET_AGENT_ID
                    && filter.matches(&alert.host, self.facts.get(&alert.agent_id)));
            rule && host
        };
        self.silences
            .iter()
            .find(|(silence, filter)| covers(silence, filter))
            .map(|(silence, _)| silence)
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
