//! How each agent is doing, which several pages show in their own way.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::alerting::{Alert, Severity};
use crate::app_state::AppState;
use crate::fact_history::format_time;
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

#[derive(Serialize)]
pub struct FleetRow {
    pub id: String,
    pub short_id: String,
    pub host: String,
    pub online: bool,
    pub health: Health,
    pub cpu: Option<Meter>,
    pub memory: Option<Meter>,
    pub disk: Option<Meter>,
    pub disk_is_full: bool,
    pub disk_mount_point: Option<String>,
    pub updated: Option<String>,
}

fn row(state: &AppState, agent: AgentRecord, values: CurrentValues, alerts: &[&Alert]) -> FleetRow {
    let online = state.presence.get(&agent.id).is_some_and(|p| p.online);
    FleetRow {
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

    let mut rows: Vec<FleetRow> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|agent| agent.state == AgentState::Approved && !agent.is_local())
        .map(|agent| {
            let values = current.remove(&agent.id).unwrap_or_default();
            let mine = alerts.get(agent.id.as_str()).map_or(&[][..], Vec::as_slice);
            row(state, agent, values, mine)
        })
        .collect();
    rows.sort_by(|a, b| a.health.cmp(&b.health).then_with(|| a.host.cmp(&b.host)));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_meter_cannot_be_drawn_past_its_ends() {
        assert_eq!(Meter::new(Some(250.0)).unwrap().width, 100.0);
        assert_eq!(Meter::new(Some(-5.0)).unwrap().width, 0.0);
        assert_eq!(Meter::new(Some(250.0)).unwrap().text, "250%");
        assert!(Meter::new(None).is_none());
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
