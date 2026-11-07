use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use maxnines_protocol::build_info;
use serde_json::{Value, json};
use sysinfo::{CpuRefreshKind, IpNetwork, MacAddr, Motherboard, Networks, Product, System};

use crate::collector;
use crate::custom::Definitions;

/// Every address this machine has, and where each one is. `addresses` is a plain list so
/// that a host filter can match any of them. The loopback address is the same everywhere,
/// so it's left out, along with any interface that has nothing else.
fn network_facts<'a>(
    interfaces: impl Iterator<Item = (String, MacAddr, &'a [IpNetwork])>,
) -> Value {
    let mut addresses = BTreeSet::new();
    let mut described = BTreeMap::new();
    for (name, mac, networks) in interfaces {
        let networks: BTreeSet<String> = networks
            .iter()
            .filter(|network| !network.addr.is_loopback())
            .inspect(|network| {
                addresses.insert(network.addr.to_string());
            })
            .map(ToString::to_string)
            .collect();
        if !networks.is_empty() {
            let mac = (!mac.is_unspecified()).then(|| mac.to_string());
            let interface = json!({ "name": name, "mac": mac, "addresses": networks });
            described.insert(name, interface);
        }
    }
    json!({
        "addresses": addresses,
        "interfaces": described.into_values().collect::<Vec<_>>(),
    })
}

/// Gathers what this machine is, as opposed to what it's doing. Everything here
/// should rarely change, because each change is kept as history. That's why
/// swap size, which some systems resize on demand, isn't included.
pub fn gather(custom: &BTreeMap<String, Value>, metrics: &Definitions) -> Result<Value> {
    let build = build_info!();
    let mut system = System::new()?;
    system.refresh_memory();
    system.refresh_cpu_list(CpuRefreshKind::nothing());
    let board = Motherboard::new().ok();
    let networks = Networks::new_with_refreshed_list()?;
    let interfaces = networks.iter().map(|(name, data)| {
        let name = name.to_string_lossy().into_owned();
        (name, data.mac_address(), data.ip_networks())
    });

    Ok(json!({
        "os": {
            "family": std::env::consts::OS,
            "name": System::name().ok(),
            "version": System::os_version().ok(),
            "long_version": System::long_os_version().ok(),
            "kernel": System::kernel_version().ok(),
        },
        "host": {
            "name": System::host_name().ok(),
            "arch": System::cpu_arch(),
        },
        "cpu": {
            "model": system.cpus().first().map(|cpu| cpu.brand().trim().to_string()),
            "physical_cores": System::physical_core_count().ok(),
            "logical_cores": system.cpus().len(),
        },
        "memory": {
            "total_bytes": system.total_memory(),
        },
        "network": network_facts(interfaces),
        // Virtual machines and missing rights leave some of these out.
        "hardware": {
            "vendor": Product::vendor_name().ok(),
            "product": Product::name().ok(),
            "serial_number": Product::serial_number().ok(),
            "uuid": Product::uuid().ok(),
            "board_vendor": board.as_ref().and_then(Motherboard::vendor_name),
            "board_name": board.as_ref().and_then(Motherboard::name),
        },
        "agent": {
            "version": build.version,
            "commit": build.commit,
            "built_at": build.built_at,
            "collectors": collector::SUPPORTED,
            // Only the names. What they run stays on this machine.
            "custom_metrics": metrics.keys().collect::<Vec<_>>(),
        },
        "custom": custom,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom::CustomMetric;

    #[test]
    fn reports_the_built_in_facts() {
        let facts = gather(&BTreeMap::new(), &Definitions::new()).unwrap();

        assert_eq!(facts["os"]["family"], std::env::consts::OS);
        assert!(facts["host"]["arch"].is_string());
        assert!(facts["cpu"]["logical_cores"].as_u64().unwrap() > 0);
        assert!(facts["memory"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(facts["network"]["addresses"].is_array());
        assert_eq!(facts["agent"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(facts["agent"]["collectors"], json!(collector::SUPPORTED));
    }

    fn network(text: &str) -> IpNetwork {
        let (addr, prefix) = text.split_once('/').unwrap();
        IpNetwork {
            addr: addr.parse().unwrap(),
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn lists_every_address_and_where_it_is() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let wired = [network("192.168.0.5/24"), network("fd00::5/64")];
        let wifi = [network("10.0.0.9/16")];
        let interfaces: [(String, MacAddr, &[IpNetwork]); 2] = [
            ("wifi0".to_string(), MacAddr::UNSPECIFIED, &wifi),
            ("eth0".to_string(), mac, &wired),
        ];

        let facts = network_facts(interfaces.into_iter());

        assert_eq!(
            facts,
            json!({
                "addresses": ["10.0.0.9", "192.168.0.5", "fd00::5"],
                "interfaces": [
                    {
                        "name": "eth0",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "addresses": ["192.168.0.5/24", "fd00::5/64"],
                    },
                    { "name": "wifi0", "mac": null, "addresses": ["10.0.0.9/16"] },
                ],
            })
        );
    }

    #[test]
    fn loopback_and_interfaces_with_no_address_are_left_out() {
        let loopback = [network("127.0.0.1/8"), network("::1/128")];
        let interfaces: [(String, MacAddr, &[IpNetwork]); 2] = [
            ("lo".to_string(), MacAddr::UNSPECIFIED, &loopback),
            ("eth1".to_string(), MacAddr::UNSPECIFIED, &[]),
        ];

        let facts = network_facts(interfaces.into_iter());

        assert_eq!(facts, json!({ "addresses": [], "interfaces": [] }));
    }

    #[test]
    fn an_address_on_two_interfaces_is_listed_once() {
        let shared = [network("10.0.0.1/24")];
        let interfaces: [(String, MacAddr, &[IpNetwork]); 2] = [
            ("eth0".to_string(), MacAddr::UNSPECIFIED, &shared),
            ("eth1".to_string(), MacAddr::UNSPECIFIED, &shared),
        ];

        let facts = network_facts(interfaces.into_iter());

        assert_eq!(facts["addresses"], json!(["10.0.0.1"]));
    }

    #[test]
    fn reports_which_build_this_is() {
        let facts = gather(&BTreeMap::new(), &Definitions::new()).unwrap();
        let agent = &facts["agent"];

        let commit = agent["commit"].as_str().unwrap();
        assert!(!commit.is_empty() && !commit.contains("VERGEN"), "{commit}");
        let built_at = agent["built_at"].as_str().unwrap();
        assert!(
            built_at.starts_with("20") && built_at.ends_with('Z'),
            "{built_at}"
        );
    }

    #[test]
    fn reports_custom_facts() {
        let custom = BTreeMap::from([("role".to_string(), json!("web"))]);

        assert_eq!(
            gather(&custom, &Definitions::new()).unwrap()["custom"]["role"],
            "web"
        );
    }

    #[test]
    fn gathering_twice_gives_the_same_facts() {
        // A difference here would fill the history with false changes.
        let custom = BTreeMap::new();
        let none = Definitions::new();
        assert_eq!(
            gather(&custom, &none).unwrap(),
            gather(&custom, &none).unwrap()
        );
    }

    #[test]
    fn custom_metrics_are_listed_by_name_without_their_commands() {
        let metrics = Definitions::from([(
            "queue".to_string(),
            CustomMetric {
                command: vec!["/usr/local/bin/secret-tool".to_string()],
                timeout_secs: None,
            },
        )]);
        let facts = gather(&BTreeMap::new(), &metrics).unwrap();

        assert_eq!(facts["agent"]["custom_metrics"], json!(["queue"]));
        assert!(!facts.to_string().contains("secret-tool"));
    }
}
