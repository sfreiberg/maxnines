//! What a host's newest readings say about it beyond its numbers: its drives, its
//! updates and its services, from what its collectors last sent. The host's pages
//! and the API both read them from here, so they can't come to say different things.
//! Agents send these, so nothing is trusted to be the right shape: anything unusable
//! is left out or blank.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::metrics::Metrics;
use crate::times::Timestamp;

/// One drive, from the smart collector's newest reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Drive {
    /// Its model and serial number, which its series are called. Nothing for one
    /// smartctl couldn't read, which only has its device.
    pub name: Option<String>,
    pub device: String,
    /// Whether it passes its own assessment, if it says.
    pub healthy: Option<bool>,
    pub temperature_celsius: Option<f64>,
    /// Whether it was asleep, so wasn't asked, and this is what it last said.
    pub asleep: bool,
    /// What the agent noticed about it, such as a USB bridge it doesn't know.
    pub note: Option<String>,
}

/// Each drive the smart collector last read, and why it couldn't read any.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Drives {
    pub drives: Vec<Drive>,
    /// Why it couldn't read them, with what to do about it, such as installing
    /// smartctl.
    pub problem: Option<String>,
}

impl Drives {
    pub fn of(output: Option<&Value>) -> Self {
        let mut drives = Self::default();
        for item in output.and_then(Value::as_array).into_iter().flatten() {
            if let Some(said) = item["problem"].as_str() {
                drives.problem = Some(said.to_string());
                continue;
            }
            // A drive smartctl couldn't read is named by its device alone.
            let named = item["model"].is_string() || item["serial"].is_string();
            drives.drives.push(Drive {
                name: item["name"].as_str().filter(|_| named).map(str::to_string),
                device: item["device"].as_str().unwrap_or_default().to_string(),
                healthy: item["healthy"].as_f64().map(|healthy| healthy >= 1.0),
                temperature_celsius: item["temperature_celsius"].as_f64(),
                asleep: item["asleep"].as_f64().is_some_and(|asleep| asleep >= 1.0),
                note: text(item, "note"),
            });
        }
        drives
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Self> {
        let output = metrics.latest_output(host_id, "smart", now).await?;
        Ok(Self::of(output.as_ref()))
    }
}

/// Whether a host is up to date, from the updates collector's newest reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Updates {
    /// What was asked, such as apt.
    pub manager: Option<String>,
    /// How many updates are waiting.
    pub pending: Option<u64>,
    /// How many of them are for security, if the system says.
    pub security: Option<u64>,
    /// How many installed packages have known vulnerabilities, if the system says.
    pub vulnerable: Option<u64>,
    pub reboot_required: Option<bool>,
    /// How long since the package lists were refreshed.
    pub lists_age_secs: Option<u64>,
    /// Why nothing could be asked, with what to do about it. The numbers are all
    /// empty then.
    pub problem: Option<String>,
    /// What went wrong with part of it.
    pub note: Option<String>,
}

impl Updates {
    pub fn of(output: &Value) -> Option<Self> {
        if !output.is_object() {
            return None;
        }
        // The store keeps each number's newest value, so after a problem the
        // numbers it last read are still there, and aren't what's true now.
        let problem = text(output, "problem");
        let fresh = problem.is_none();
        let count = |name: &str| {
            output[name]
                .as_f64()
                .filter(|_| fresh)
                .map(|count| count as u64)
        };
        Some(Self {
            manager: text(output, "manager"),
            pending: count("pending"),
            security: count("security"),
            vulnerable: count("vulnerable"),
            reboot_required: output["reboot_required"]
                .as_f64()
                .filter(|_| fresh)
                .map(|reboot| reboot >= 1.0),
            lists_age_secs: count("lists_age_secs"),
            problem,
            note: text(output, "note"),
        })
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Option<Self>> {
        let output = metrics.latest_output(host_id, "updates", now).await?;
        Ok(output.as_ref().and_then(Self::of))
    }
}

/// A watched service as its host's service manager last described it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchedService {
    pub name: String,
    pub running: bool,
    /// The service manager's word for it, when it isn't running.
    pub state: Option<String>,
}

impl WatchedService {
    fn of(service: &Value) -> Option<Self> {
        let running = service["running"].as_u64() == Some(1);
        Some(Self {
            name: service["name"].as_str()?.to_string(),
            running,
            state: service["state"]
                .as_str()
                .filter(|_| !running)
                .map(String::from),
        })
    }

    /// Each service the services collector last read, in its order.
    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Vec<Self>> {
        Ok(
            match metrics.latest_output(host_id, "services", now).await? {
                Some(Value::Array(items)) => items.iter().filter_map(Self::of).collect(),
                _ => Vec::new(),
            },
        )
    }
}

/// The services a host last said had stopped with an error, by name, so a count of
/// them always comes with which they are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedServices {
    pub count: u64,
    pub names: Vec<String>,
    /// How many failed past the names the agent sends, which it caps.
    pub unnamed: u64,
}

impl FailedServices {
    /// From the system collector's newest reading, which only counts them on systems
    /// that have such a state, so on others there's nothing to say.
    pub fn of(output: &Value) -> Option<Self> {
        let count = output["failed_services"].as_f64()? as u64;
        // The agent joins them as `a, b and 3 more`.
        let listed = output["failed_service_names"].as_str().unwrap_or_default();
        let listed = match listed.rsplit_once(" and ") {
            Some((named, more))
                if more
                    .strip_suffix(" more")
                    .is_some_and(|more| more.parse::<u64>().is_ok()) =>
            {
                named
            }
            _ => listed,
        };
        let names: Vec<String> = listed
            .split(", ")
            .filter(|name| !name.is_empty())
            .map(String::from)
            .collect();
        Some(Self {
            count,
            unnamed: count.saturating_sub(names.len() as u64),
            names,
        })
    }

    pub async fn load(metrics: &Metrics, host_id: &str, now: Timestamp) -> Result<Option<Self>> {
        let output = metrics.latest_output(host_id, "system", now).await?;
        Ok(output.as_ref().and_then(Self::of))
    }
}

/// A field that says something, which an empty one doesn't.
fn text(item: &Value, name: &str) -> Option<String> {
    item[name]
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn failed_services_are_named_with_how_many_went_unnamed() {
        let failed = |count: u64, names: &str| {
            let output = json!({ "failed_services": count, "failed_service_names": names });
            FailedServices::of(&output).unwrap()
        };
        let named = failed(2, "backup.timer, nginx.service");
        assert_eq!(named.names, ["backup.timer", "nginx.service"]);
        assert_eq!(named.unnamed, 0);

        let capped = failed(5, "a.service, b.service and 3 more");
        assert_eq!(capped.names, ["a.service", "b.service"]);
        assert_eq!(capped.unnamed, 3);

        // A name that only looks like the end of the list is still a name.
        let odd = failed(1, "Backup and more");
        assert_eq!(odd.names, ["Backup and more"]);

        let none = failed(0, "");
        assert!(none.names.is_empty());
        assert_eq!(none.count, 0);

        // Systems with no such state don't count them.
        assert_eq!(FailedServices::of(&json!({ "processes": 3 })), None);
    }

    #[test]
    fn a_problem_reading_updates_leaves_none_of_the_numbers_it_last_read() {
        let output = json!({
            "manager": "pacman", "pending": 12, "security": 3, "reboot_required": 1,
            "lists_age_secs": 7200, "problem": "checkupdates isn't installed", "note": "",
        });
        let updates = Updates::of(&output).unwrap();
        assert_eq!(updates.pending, None);
        assert_eq!(updates.reboot_required, None);
        assert_eq!(updates.lists_age_secs, None);
        assert_eq!(updates.manager.as_deref(), Some("pacman"));
        assert_eq!(updates.note, None);
    }

    #[test]
    fn a_drive_smartctl_could_not_read_goes_by_its_device() {
        let output = json!([
            { "name": "/dev/sdc", "device": "/dev/sdc", "asleep": 1, "note": "" },
            { "name": "WDC WD40EFRX WD-1", "device": "/dev/sda", "model": "WDC WD40EFRX",
              "healthy": 1, "temperature_celsius": 38.0, "asleep": 0, "note": "" },
        ]);
        let drives = Drives::of(Some(&output));
        assert_eq!(drives.problem, None);
        assert_eq!(drives.drives[0].name, None);
        assert!(drives.drives[0].asleep);
        assert_eq!(drives.drives[1].name.as_deref(), Some("WDC WD40EFRX WD-1"));
        assert_eq!(drives.drives[1].healthy, Some(true));
        assert_eq!(drives.drives[1].temperature_celsius, Some(38.0));
    }
}
