//! How each agent is doing, which several pages show in their own way.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::local_time;
use crate::alerting::{Alert, Severity};
use crate::app_state::AppState;
use crate::facts::FlatFacts;
use crate::metric_charts::format_value;
use crate::metrics::{CurrentValues, Unit};
use crate::presence::Reach;
use crate::registration::{HostRecord, HostState, short_id};

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
    /// A host with no agent and nothing being read for it.
    NotRead,
}

impl Health {
    pub fn of(reach: Reach, alerts: &[&Alert]) -> Self {
        if alerts.iter().any(|a| a.severity == Severity::Critical) {
            Self::Critical
        } else if !alerts.is_empty() {
            Self::Warning
        } else {
            match reach {
                Reach::Online => Self::Online,
                Reach::Offline => Self::Offline,
                Reach::NotRead => Self::NotRead,
            }
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
    pub hostname: String,
    pub os_family: Option<OsFamily>,
    pub online: bool,
    /// Neither online nor offline, so left out of counts of either.
    pub not_read: bool,
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
    host: HostRecord,
    values: Option<CurrentValues>,
    facts: Option<&FlatFacts>,
    alerts: &[&Alert],
) -> FleetRow {
    let reach = state.presence.reach(&host);
    let updated = values
        .as_ref()
        .map(|values| local_time(values.last_sample_at));
    let values = values.as_ref();
    let disk = values.and_then(|values| values.disk_percent);
    FleetRow {
        os_family: facts.and_then(OsFamily::of),
        online: reach == Reach::Online,
        not_read: reach == Reach::NotRead,
        health: Health::of(reach, alerts),
        cpu: Meter::new(values.and_then(|values| values.cpu_percent)),
        memory: Meter::new(values.and_then(|values| values.memory_percent)),
        disk_is_full: disk.is_some_and(|d| d >= FULL_DISK_PERCENT),
        disk: Meter::new(disk),
        disk_mount_point: values.and_then(|values| values.disk_mount_point.clone()),
        updated,
        short_id: short_id(&host.id).to_string(),
        id: host.id,
        hostname: host.hostname,
    }
}

/// Every approved agent, most in need of attention first.
pub async fn rows(state: &AppState) -> Result<Vec<FleetRow>> {
    let mut current = state.metrics.current(crate::times::now()).await?;
    let open = state.database.open_alerts().await?;
    let mut alerts: BTreeMap<&str, Vec<&Alert>> = BTreeMap::new();
    for alert in &open {
        alerts.entry(&alert.host_id).or_default().push(alert);
    }

    let hosts: Vec<HostRecord> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|host| host.state == HostState::Approved && !host.is_local())
        .collect();
    let ids: Vec<&str> = hosts.iter().map(|host| host.id.as_str()).collect();
    let facts = state.database.facts_of(&ids).await?;

    let mut rows: Vec<FleetRow> = hosts
        .into_iter()
        .map(|host| {
            let values = current.remove(&host.id);
            let mine = alerts.get(host.id.as_str()).map_or(&[][..], Vec::as_slice);
            let known = facts.get(&host.id);
            row(state, host, values, known, mine)
        })
        .collect();
    rows.sort_by(|a, b| {
        a.health
            .cmp(&b.health)
            .then_with(|| a.hostname.cmp(&b.hostname))
    });
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
        assert!(Health::Online < Health::NotRead);
        assert!(Health::of(Reach::Online, &[]) == Health::Online);
        assert!(Health::of(Reach::Offline, &[]) == Health::Offline);
        assert!(Health::of(Reach::NotRead, &[]) == Health::NotRead);
    }
}
