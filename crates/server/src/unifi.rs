//! UniFi checks: the server reads a UniFi console's devices and keeps each as a
//! host without an agent of its own, named after the device, so a switch that goes
//! offline is a host going offline, as for anything else.
//!
//! A device is known by the console's ID for it, never its name, so renaming it on
//! the console, or two devices with the same name, never muddles its history. A
//! device's host is made the first time the check finds it, already approved, as
//! adding the check was the decision to watch what the console has. Hosts are never
//! deleted for you: a device the console stops listing is offline until its host is
//! deleted.
//!
//! When the console can't be read, the check is down and its devices are left as
//! they were, as nothing new is known of them.

use std::collections::BTreeSet;

use anyhow::Result;
use maxnines_checks::unifi::{self, Device};
use serde_json::{Value, json};
use tracing::warn;

use crate::facts::flatten;
use crate::presence::Reached;
use crate::registration::HostRecord;
use crate::remote_checks::{RemoteCheck, Running};
use crate::times;

/// What a device's samples are kept under.
pub const COLLECTOR: &str = "unifi";

/// Reads a UniFi check's console, keeps what it found of each device, and gives the
/// check's own result.
pub async fn run(check: &RemoteCheck, to: &Running<'_>) -> Value {
    // An API key named as an environment variable is read each time, so a changed
    // one is used without restarting.
    let console = match check.input.sign_in.api_key() {
        Ok(key) => unifi::read(&check.input.check, key.as_deref()).await,
        Err(why) => unifi::Console {
            report: maxnines_checks::failed_report(&check.input.check, &why),
            devices: None,
        },
    };
    if let Some(devices) = &console.devices
        && let Err(error) = keep_devices(check, devices, to).await
    {
        warn!(
            check = check.id,
            error = format!("{error:#}"),
            "keeping what a UniFi check found failed"
        );
    }
    console.report
}

/// Keeps each device as a host: made for it if it has none, with its facts, a
/// sample of its numbers, and whether it's online. One the console has stopped
/// listing is offline.
async fn keep_devices(check: &RemoteCheck, devices: &[Device], to: &Running<'_>) -> Result<()> {
    let known = to.database.unifi_device_hosts(check.id).await?;
    let mut listed = BTreeSet::new();
    for device in devices {
        listed.insert(device.id.as_str());
        let host = known
            .get(&device.id)
            .and_then(|id| to.registry.read(|hosts| hosts.get(id).cloned()));
        let host = match host {
            Some(host) => host,
            None => add_host(check, device, to).await?,
        };
        let facts = flatten(&facts(device))?;
        to.database
            .record_facts(&host.id, &facts, times::now())
            .await?;
        save(to, &host, sample(device)).await;
        to.presence
            .reached(&host.id, Reached::Device(check.id), device.is_online());
    }
    for (device, host_id) in &known {
        if listed.contains(device.as_str()) {
            continue;
        }
        let Some(host) = to.registry.read(|hosts| hosts.get(host_id).cloned()) else {
            continue;
        };
        save(to, &host, json!({ "up": 0 })).await;
        to.presence
            .reached(&host.id, Reached::Device(check.id), false);
    }
    Ok(())
}

/// Makes a host for a device, named after it, approved by the check that found it.
async fn add_host(check: &RemoteCheck, device: &Device, to: &Running<'_>) -> Result<HostRecord> {
    let by = format!("check:{}", check.input.check.name);
    let database = to.database.clone();
    let (check_id, device_id) = (check.id, device.id.clone());
    let saving = async move |host: &HostRecord| {
        database
            .save_unifi_device_host(host, check_id, &device_id)
            .await
    };
    let (host, ()) = to
        .registry
        .add_agentless_with(&hostname(device), &by, saving)
        .await?;
    Ok(host)
}

/// What a device's host is called: its name on the console, or its model and
/// address for one with no name.
fn hostname(device: &Device) -> String {
    let name = device.name.trim();
    if !name.is_empty() && !name.chars().any(char::is_control) {
        return name.chars().take(255).collect();
    }
    let model = device.model.trim();
    match (model.is_empty(), device.mac.is_empty()) {
        (false, false) => format!("{model} {}", device.mac),
        (false, true) => model.to_string(),
        _ => format!("UniFi {}", device.id),
    }
}

/// What's known of a device, kept as its host's facts under `unifi`, which the
/// built-in UniFi template's alerts look for.
fn facts(device: &Device) -> Value {
    let mut unifi = json!({
        "id": device.id,
        "model": device.model,
        "mac": device.mac,
        "ip": device.ip,
        "site": device.site,
        "features": device.features.join(", "),
    });
    if let Some(firmware) = &device.firmware {
        unifi["firmware"] = json!(firmware);
    }
    json!({ "unifi": unifi })
}

/// A device's numbers as a sample's `unifi` collector holds them. The console
/// gives its uplink's rates in bits a second, which are kept in bytes, as every
/// other rate is.
fn sample(device: &Device) -> Value {
    let mut sample = json!({
        "up": u8::from(device.is_online()),
        "state": device.state,
        "firmware_update": u8::from(device.firmware_updatable),
        "clients": device.clients,
    });
    let Some(statistics) = &device.statistics else {
        return sample;
    };
    let mut set = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            sample[name] = value;
        }
    };
    set("uptime_secs", statistics.uptime_sec.map(Value::from));
    set(
        "cpu_percent",
        statistics.cpu_utilization_pct.map(Value::from),
    );
    set(
        "memory_percent",
        statistics.memory_utilization_pct.map(Value::from),
    );
    let bytes = |bits: Option<u64>| bits.map(|bits| Value::from(bits as f64 / 8.0));
    set(
        "uplink_received_bytes",
        bytes(statistics.uplink.rx_rate_bps),
    );
    set("uplink_sent_bytes", bytes(statistics.uplink.tx_rate_bps));
    let load = [
        ("one", statistics.load_average_1_min),
        ("five", statistics.load_average_5_min),
        ("fifteen", statistics.load_average_15_min),
    ];
    if load.iter().any(|(_, value)| value.is_some()) {
        let mut average = json!({});
        for (name, value) in load {
            if let Some(value) = value {
                average[name] = json!(value);
            }
        }
        sample["load_average"] = average;
    }
    sample
}

async fn save(to: &Running<'_>, host: &HostRecord, output: Value) {
    crate::remote_checks::save(
        to.writer,
        host.id.clone(),
        host.hostname.clone(),
        COLLECTOR,
        output,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> Device {
        Device {
            id: "4d8c3a1e-0000-4000-8000-000000000001".to_string(),
            mac: "74:ac:b9:00:00:01".to_string(),
            name: "Dream Machine".to_string(),
            model: "UDM Pro".to_string(),
            ip: "192.168.1.1".to_string(),
            firmware: Some("4.1.13".to_string()),
            state: "ONLINE".to_string(),
            firmware_updatable: true,
            features: vec!["gateway".to_string()],
            site: "Default".to_string(),
            clients: 4,
            statistics: Some(unifi::Statistics {
                uptime_sec: Some(60),
                cpu_utilization_pct: Some(12.5),
                memory_utilization_pct: None,
                load_average_1_min: Some(0.5),
                load_average_5_min: None,
                load_average_15_min: None,
                uplink: unifi::Uplink {
                    rx_rate_bps: Some(16_000),
                    tx_rate_bps: None,
                },
            }),
        }
    }

    #[test]
    fn a_sample_has_what_the_console_gave_and_rates_in_bytes() {
        let sample = sample(&device());
        assert_eq!(sample["up"], 1);
        assert_eq!(sample["firmware_update"], 1);
        assert_eq!(sample["clients"], 4);
        assert_eq!(sample["uptime_secs"], 60);
        assert_eq!(sample["cpu_percent"], 12.5);
        assert!(sample.get("memory_percent").is_none(), "nothing's made up");
        assert_eq!(sample["uplink_received_bytes"], 2000.0);
        assert!(sample.get("uplink_sent_bytes").is_none());
        assert_eq!(sample["load_average"], json!({ "one": 0.5 }));

        let mut offline = device();
        offline.state = "OFFLINE".to_string();
        offline.statistics = None;
        let sample = super::sample(&offline);
        assert_eq!(sample["up"], 0);
        assert!(sample.get("cpu_percent").is_none());
    }

    #[test]
    fn a_device_with_no_name_is_called_by_its_model_and_address() {
        let mut device = device();
        assert_eq!(hostname(&device), "Dream Machine");
        device.name = "  ".to_string();
        assert_eq!(hostname(&device), "UDM Pro 74:ac:b9:00:00:01");
        device.model.clear();
        device.mac.clear();
        assert_eq!(
            hostname(&device),
            "UniFi 4d8c3a1e-0000-4000-8000-000000000001"
        );
    }
}
