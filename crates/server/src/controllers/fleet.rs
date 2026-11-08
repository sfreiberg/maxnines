//! How each agent is doing, which several pages show in their own way.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::alerting::{Alert, Severity};
use crate::app_state::AppState;
use crate::fact_history::format_time;
use crate::facts::FlatFacts;
use crate::metric_charts::format_value;
use crate::metrics::{CurrentValues, Unit, now_ms};
use crate::registration::{AgentRecord, AgentState, short_id};

/// A disk this full is drawn in the warning color.
const FULL_DISK_PERCENT: f64 = 90.0;

#[derive(Serialize)]
pub struct Meter {
    pub text: String,
    /// The value as a width for the drawing, kept from going off the end.
    pub width: f64,
}

impl Meter {
    fn new(value: Option<f64>) -> Option<Self> {
        value.map(|value| Self {
            text: format_value(Unit::Percent, value),
            width: value.clamp(0.0, 100.0),
        })
    }
}

/// How an agent is, as a word and a class. Problems outrank being online.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Critical,
    Warning,
    Offline,
    Online,
}

impl Health {
    pub fn of(online: bool, alerts: &[&Alert]) -> Self {
        if alerts.iter().any(|a| a.severity == Severity::Critical) {
            Self::Critical
        } else if !alerts.is_empty() {
            Self::Warning
        } else if online {
            Self::Online
        } else {
            Self::Offline
        }
    }
}

/// Which system an agent runs, for drawing its icon. Only these names reach a
/// page, never the fact an agent sent, and anything else gets no icon.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Macos,
    Linux,
    Windows,
    Freebsd,
    Openbsd,
}

impl OsFamily {
    pub fn of(facts: &FlatFacts) -> Option<Self> {
        match facts.get("os.family")?.as_str()? {
            "macos" => Some(Self::Macos),
            "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            "freebsd" => Some(Self::Freebsd),
            "openbsd" => Some(Self::Openbsd),
            _ => None,
        }
    }
}

#[derive(Serialize)]
pub struct FleetRow {
    pub id: String,
    pub short_id: String,
    pub host: String,
    pub os_family: Option<OsFamily>,
    pub online: bool,
    pub health: Health,
    pub cpu: Option<Meter>,
    pub memory: Option<Meter>,
    pub disk: Option<Meter>,
    pub disk_is_full: bool,
    pub disk_mount_point: Option<String>,
    pub updated: Option<String>,
}

fn row(
    state: &AppState,
    agent: AgentRecord,
    values: CurrentValues,
    facts: Option<&FlatFacts>,
    alerts: &[&Alert],
) -> FleetRow {
    let online = state.presence.get(&agent.id).is_some_and(|p| p.online);
    FleetRow {
        os_family: facts.and_then(OsFamily::of),
        online,
        health: Health::of(online, alerts),
        cpu: Meter::new(values.cpu_percent),
        memory: Meter::new(values.memory_percent),
        disk_is_full: values.disk_percent.is_some_and(|d| d >= FULL_DISK_PERCENT),
        disk: Meter::new(values.disk_percent),
        disk_mount_point: values.disk_mount_point,
        updated: u64::try_from(values.time_ms)
            .ok()
            .filter(|time| *time > 0)
            .map(format_time),
        short_id: short_id(&agent.id).to_string(),
        id: agent.id,
        host: agent.host,
    }
}

/// Every approved agent, most in need of attention first.
pub async fn rows(state: &AppState) -> Result<Vec<FleetRow>> {
    let mut current = state.metrics.current(now_ms()).await?;
    let open = state.database.open_alerts().await?;
    let mut alerts: BTreeMap<&str, Vec<&Alert>> = BTreeMap::new();
    for alert in &open {
        alerts.entry(&alert.agent_id).or_default().push(alert);
    }

    let agents: Vec<AgentRecord> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|agent| agent.state == AgentState::Approved && !agent.is_local())
        .collect();
    let ids: Vec<&str> = agents.iter().map(|agent| agent.id.as_str()).collect();
    let facts = state.database.facts_of(&ids).await?;

    let mut rows: Vec<FleetRow> = agents
        .into_iter()
        .map(|agent| {
            let values = current.remove(&agent.id).unwrap_or_default();
            let mine = alerts.get(agent.id.as_str()).map_or(&[][..], Vec::as_slice);
            let known = facts.get(&agent.id);
            row(state, agent, values, known, mine)
        })
        .collect();
    rows.sort_by(|a, b| a.health.cmp(&b.health).then_with(|| a.host.cmp(&b.host)));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn a_meter_cannot_be_drawn_past_its_ends() {
        assert_eq!(Meter::new(Some(250.0)).unwrap().width, 100.0);
        assert_eq!(Meter::new(Some(-5.0)).unwrap().width, 0.0);
        assert_eq!(Meter::new(Some(250.0)).unwrap().text, "250%");
        assert!(Meter::new(None).is_none());
    }

    #[test]
    fn only_known_systems_get_an_icon() {
        let family = |value: Value| {
            let facts: FlatFacts = [("os.family".to_string(), value)].into_iter().collect();
            OsFamily::of(&facts)
        };
        assert_eq!(family(json!("macos")), Some(OsFamily::Macos));
        assert_eq!(family(json!("linux")), Some(OsFamily::Linux));
        assert_eq!(family(json!("windows")), Some(OsFamily::Windows));
        assert_eq!(family(json!("freebsd")), Some(OsFamily::Freebsd));
        assert_eq!(family(json!("openbsd")), Some(OsFamily::Openbsd));
        // NetBSD's logo can't be used as an icon, so it has none.
        assert_eq!(family(json!("netbsd")), None);
        assert_eq!(family(json!("<svg onload=x>")), None);
        assert_eq!(family(json!(7)), None);
        assert_eq!(OsFamily::of(&FlatFacts::new()), None);
    }

    #[test]
    fn being_online_doesnt_hide_a_problem() {
        assert!(Health::Critical < Health::Warning);
        assert!(Health::Warning < Health::Offline);
        assert!(Health::Offline < Health::Online);
        assert!(Health::of(true, &[]) == Health::Online);
        assert!(Health::of(false, &[]) == Health::Offline);
    }
}
