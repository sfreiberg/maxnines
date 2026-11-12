use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Result;
use dns_lookup::{AddrInfoHints, getaddrinfo};
use maxnines_protocol::build_info;
use serde_json::{Value, json};
use sysinfo::{CpuRefreshKind, IpNetwork, MacAddr, Motherboard, Networks, Product, System};

use crate::actions::{self, Actions};
use crate::collector;
use crate::custom::Definitions;

/// Asks for the canonical name. The value is the same on every platform we build for.
const AI_CANONNAME: i32 = 2;

/// How long the resolver gets before the host is left with its short name.
const FQDN_LOOKUP_LIMIT: Duration = Duration::from_secs(2);

/// The part of a hostname before the first dot, which is what hosts are called.
pub fn short_name(hostname: &str) -> &str {
    hostname.split('.').next().unwrap_or(hostname)
}

/// What the resolver calls this host, as `hostname -f` finds out. It can hang on a
/// broken resolver, so it gets its own thread and a time limit.
fn canonical_name(hostname: &str) -> Option<String> {
    let (sender, receiver) = mpsc::channel();
    let hostname = hostname.to_string();
    std::thread::spawn(move || {
        let hints = AddrInfoHints {
            flags: AI_CANONNAME,
            address: 0,
            socktype: 0,
            protocol: 0,
        };
        let found = getaddrinfo(Some(&hostname), None, Some(hints))
            .ok()
            .and_then(|mut found| found.find_map(|info| info.ok()?.canonname));
        sender.send(found).ok();
    });
    receiver.recv_timeout(FQDN_LOOKUP_LIMIT).ok().flatten()
}

/// The host's names, as facter calls them: `hostname` is the short name, `fqdn` the
/// name with its domain, and `domain` the rest. Without a resolver answer, a hostname
/// that already has dots in it is its own fully qualified name.
fn name_facts(hostname: Option<&str>, canonical: Option<&str>) -> Value {
    let short = hostname.map(short_name);
    let qualified = |name: &str| name.contains('.');
    let fqdn = canonical
        .filter(|name| qualified(name))
        .or_else(|| hostname.filter(|name| qualified(name)))
        .or(short)
        .map(|name| name.trim_end_matches('.').to_lowercase());
    let domain = match (&fqdn, short) {
        (Some(fqdn), Some(short)) => fqdn
            .strip_prefix(&short.to_lowercase())
            .and_then(|rest| rest.strip_prefix('.'))
            .map(str::to_string),
        _ => None,
    };
    json!({ "hostname": short, "fqdn": fqdn, "domain": domain })
}

/// Loopback is the same everywhere. Link-local addresses are plentiful, can change with
/// each reboot or VPN connection, and every change would be kept as history.
fn reachable(address: IpAddr) -> bool {
    let link_local = match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    };
    !address.is_loopback() && !link_local
}

/// Every address this host has, and where each one is. `addresses` is a plain list so
/// that a host filter can match any of them. Addresses that only mean something on the
/// host or its own link are left out, along with any interface that has nothing else.
fn network_facts<'a>(
    interfaces: impl Iterator<Item = (String, MacAddr, &'a [IpNetwork])>,
) -> Value {
    let mut addresses = BTreeSet::new();
    let mut described = BTreeMap::new();
    for (name, mac, networks) in interfaces {
        let networks: BTreeSet<String> = networks
            .iter()
            .filter(|network| reachable(network.addr))
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

/// Gathers what this host is, as opposed to what it's doing. Everything here
/// should rarely change, because each change is kept as history. That's why
/// swap size, which some systems resize on demand, isn't included.
pub fn gather(
    custom: &BTreeMap<String, Value>,
    metrics: &Definitions,
    actions: &Actions,
    built_in_actions: bool,
) -> Result<Value> {
    let hostname = System::host_name().ok();
    let canonical = hostname.as_deref().and_then(canonical_name);
    gather_named(
        custom,
        metrics,
        actions,
        built_in_actions,
        hostname.as_deref(),
        canonical.as_deref(),
    )
}

/// Everything but asking the resolver what the host is called.
fn gather_named(
    custom: &BTreeMap<String, Value>,
    metrics: &Definitions,
    actions: &Actions,
    built_in_actions: bool,
    hostname: Option<&str>,
    canonical: Option<&str>,
) -> Result<Value> {
    let build = build_info!();
    let (action_names, action_variables) = actions::facts(actions, built_in_actions);
    let mut system = System::new()?;
    system.refresh_memory();
    system.refresh_cpu_list(CpuRefreshKind::nothing());
    let board = Motherboard::new().ok();
    let networks = Networks::new_with_refreshed_list()?;
    let interfaces = networks.iter().map(|(name, data)| {
        let name = name.to_string_lossy().into_owned();
        (name, data.mac_address(), data.ip_networks())
    });
    let mut networking = network_facts(interfaces);
    if let (Some(networking), Some(names)) = (
        networking.as_object_mut(),
        name_facts(hostname, canonical).as_object(),
    ) {
        networking.extend(names.clone());
    }

    Ok(json!({
        "os": {
            "family": std::env::consts::OS,
            "name": System::name().ok(),
            "version": System::os_version().ok(),
            "long_version": System::long_os_version().ok(),
            "kernel": System::kernel_version().ok(),
        },
        "host": {
            "name": hostname.map(short_name),
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
        "networking": networking,
        // Virtual hosts and missing rights leave some of these out.
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
            "collectors": collector::supported(),
            // Only the names. What they run stays on this host.
            "custom_metrics": metrics.keys().collect::<Vec<_>>(),
            // What the server can ask this host to run, and what each needs to
            // be told, so it can check before asking.
            "actions": action_names,
            // Whether it was started as root and kept a helper with those rights.
            "privileged_helper": crate::privileges::helper().is_some(),
            "action_variables": action_variables,
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
        let facts = gather(&BTreeMap::new(), &Definitions::new(), &Actions::new(), true).unwrap();

        assert_eq!(facts["os"]["family"], std::env::consts::OS);
        assert!(facts["host"]["arch"].is_string());
        assert!(facts["cpu"]["logical_cores"].as_u64().unwrap() > 0);
        assert!(facts["memory"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(facts["networking"]["addresses"].is_array());
        let short = facts["host"]["name"].as_str().unwrap();
        assert!(!short.contains('.'), "{short}");
        assert_eq!(facts["networking"]["hostname"], short);
        assert!(facts["networking"]["fqdn"].is_string());
        assert_eq!(facts["agent"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(facts["agent"]["collectors"], json!(collector::supported()));
    }

    #[test]
    fn names_follow_facter() {
        let names = name_facts(Some("web-1"), Some("web-1.example.com"));
        assert_eq!(
            names,
            json!({ "hostname": "web-1", "fqdn": "web-1.example.com", "domain": "example.com" })
        );

        // A hostname that was set fully qualified is its own answer.
        let names = name_facts(Some("Web-1.Example.com"), None);
        assert_eq!(
            names,
            json!({ "hostname": "Web-1", "fqdn": "web-1.example.com", "domain": "example.com" })
        );

        // Nothing from the resolver, and nothing to add.
        let names = name_facts(Some("web-1"), Some("web-1"));
        assert_eq!(
            names,
            json!({ "hostname": "web-1", "fqdn": "web-1", "domain": null })
        );
        assert_eq!(
            name_facts(Some("web-1"), None),
            json!({ "hostname": "web-1", "fqdn": "web-1", "domain": null })
        );

        // The resolver knows the host by another name, which isn't its domain.
        let names = name_facts(Some("web-1"), Some("alias.example.net."));
        assert_eq!(
            names,
            json!({ "hostname": "web-1", "fqdn": "alias.example.net", "domain": null })
        );

        assert_eq!(
            name_facts(None, None),
            json!({ "hostname": null, "fqdn": null, "domain": null })
        );
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
    fn link_local_addresses_are_left_out() {
        let tunnel = [network("fe80::1/64"), network("169.254.3.4/16")];
        let wired = [network("fe80::2/64"), network("192.168.0.5/24")];
        let interfaces: [(String, MacAddr, &[IpNetwork]); 2] = [
            ("utun0".to_string(), MacAddr::UNSPECIFIED, &tunnel),
            ("eth0".to_string(), MacAddr::UNSPECIFIED, &wired),
        ];

        let facts = network_facts(interfaces.into_iter());

        assert_eq!(facts["addresses"], json!(["192.168.0.5"]));
        assert_eq!(facts["interfaces"].as_array().unwrap().len(), 1);
        assert_eq!(
            facts["interfaces"][0]["addresses"],
            json!(["192.168.0.5/24"])
        );
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
        let facts = gather(&BTreeMap::new(), &Definitions::new(), &Actions::new(), true).unwrap();
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
            gather(&custom, &Definitions::new(), &Actions::new(), true).unwrap()["custom"]["role"],
            "web"
        );
    }

    #[test]
    fn gathering_twice_gives_the_same_facts() {
        // A difference here would fill the history with false changes. The resolver
        // is asked once, as it can answer one time and be too slow the next.
        let custom = BTreeMap::new();
        let none = Definitions::new();
        let actions = Actions::new();
        let named = |custom, none| {
            let canonical = Some("web-1.example.com");
            gather_named(custom, none, &actions, true, Some("web-1"), canonical).unwrap()
        };
        assert_eq!(named(&custom, &none), named(&custom, &none));
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
        let facts = gather(&BTreeMap::new(), &metrics, &Actions::new(), true).unwrap();

        assert_eq!(facts["agent"]["custom_metrics"], json!(["queue"]));
        assert!(!facts.to_string().contains("secret-tool"));
    }

    #[test]
    fn actions_are_listed_by_name_without_their_commands() {
        let command = |parts: &[&str]| actions::Action {
            command: parts.iter().map(|part| (*part).to_string()).collect(),
            user: None,
        };
        let actions = Actions::from([
            (
                "disk_hogs".to_string(),
                command(&["/opt/secret-tool", "{disk}"]),
            ),
            ("restart_nginx".to_string(), command(&["/opt/secret-tool"])),
        ]);
        let facts = gather(&BTreeMap::new(), &Definitions::new(), &actions, false).unwrap();

        let agent = &facts["agent"];
        assert_eq!(agent["actions"], json!(["disk_hogs", "restart_nginx"]));
        assert_eq!(agent["action_variables"], json!({ "disk_hogs": ["disk"] }));
        assert!(!facts.to_string().contains("secret-tool"));
    }
}
