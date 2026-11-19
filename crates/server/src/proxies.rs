//! Proxies in front of the server. A request's `X-Forwarded-For` header is only
//! believed from a proxy the server trusts, as anyone can send one. Proxies are trusted
//! from `trusted_proxies` in the server's config, which is loopback when it isn't set,
//! and from what admins decide in the pages.
//!
//! Admins are told about proxies the server isn't trusting yet: a signed-in request
//! that comes with a forwarded address from an untrusted one is noted, and admins see
//! a notice until they say whether it's theirs. The server never decides that itself,
//! since an address sending the header could be anyone's.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Result, ensure};
use axum::http::HeaderMap;
use ipnet::IpNet;
use serde::Serialize;

use crate::config::parse_network;
use crate::controllers::agent_socket::client_ip;
use crate::times::{Timestamp, from_ms};

/// The most proxies waiting for a decision that are kept, so a busy network can't
/// grow the list for ever.
const MAX_SEEN: usize = 20;

/// The widest range that can be trusted: anyone in a wider one could claim any address.
const WIDEST_V4_PREFIX: u8 = 8;
const WIDEST_V6_PREFIX: u8 = 32;

/// The most people kept for each proxy waiting for a decision.
const MAX_PEOPLE: usize = 5;

/// A provider whose proxies connect from ranges it publishes, trusted by its name so
/// a new release can bring the list up to date.
pub struct Provider {
    /// What's saved, such as `cloudflare`.
    pub key: &'static str,
    pub name: &'static str,
    ranges: &'static [&'static str],
    /// Whether it adds its own address after the client's in `X-Forwarded-For`, so the
    /// last entry is the provider's and the client's is the one before.
    adds_its_own: bool,
}

impl Provider {
    pub fn networks(&self) -> Vec<IpNet> {
        self.ranges
            .iter()
            .filter_map(|range| range.parse().ok())
            .collect()
    }

    fn contains(&self, address: &IpAddr) -> bool {
        self.networks()
            .iter()
            .any(|network| network.contains(address))
    }
}

/// Providers whose published ranges are built in.
pub const PROVIDERS: [Provider; 2] = [
    // From https://www.cloudflare.com/ips-v4 and /ips-v6.
    Provider {
        key: "cloudflare",
        name: "Cloudflare",
        ranges: &[
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2405:b500::/32",
            "2405:8100::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32",
        ],
        adds_its_own: false,
    },
    // Google Cloud's external Application Load Balancers, from
    // https://cloud.google.com/load-balancing/docs/https. They add the client's
    // address and then the load balancer's own.
    Provider {
        key: "google-cloud",
        name: "Google Cloud",
        ranges: &["35.191.0.0/16", "130.211.0.0/22", "2600:2d00:1:1::/64"],
        adds_its_own: true,
    },
];

/// The provider an address belongs to, if it's one built in.
pub fn provider_of(address: &IpAddr) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.contains(address))
}

fn provider_named(key: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.key == key)
}

/// What kind of address something is, to help decide whether it's a proxy of yours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    /// This machine.
    Loopback,
    /// A private network, as cloud load balancers inside your own network use.
    Private,
    /// A provider's published range.
    Provider,
    /// Anywhere else on the internet.
    Public,
}

pub fn kind_of(address: &IpAddr) -> AddressKind {
    let address = address.to_canonical();
    if address.is_loopback() {
        return AddressKind::Loopback;
    }
    if provider_of(&address).is_some() {
        return AddressKind::Provider;
    }
    let private = match address {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)
        }
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    if private {
        AddressKind::Private
    } else {
        AddressKind::Public
    }
}

/// What trusting a proxy at `address` should cover: a provider's ranges, the private
/// network around it, or just it.
pub fn suggested_range(address: &IpAddr) -> String {
    let address = address.to_canonical();
    if let Some(provider) = provider_of(&address) {
        return provider.key.to_string();
    }
    let prefix = match (kind_of(&address), address) {
        (AddressKind::Private, IpAddr::V4(_)) => 24,
        (AddressKind::Private, IpAddr::V6(_)) => 64,
        _ => return address.to_string(),
    };
    IpNet::new(address, prefix).map_or_else(
        |_| address.to_string(),
        |network| network.trunc().to_string(),
    )
}

/// What a decision's address covers: a range, or a provider's ranges.
fn networks_of(address: &str) -> Vec<IpNet> {
    match provider_named(address) {
        Some(provider) => provider.networks(),
        None => parse_network(address).into_iter().collect(),
    }
}

/// What's trusted when the config doesn't say: a proxy on the same machine.
pub fn loopback() -> Vec<IpNet> {
    ["127.0.0.0/8", "::1/128"]
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect()
}

/// A decision an admin made about an address or range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub id: i64,
    /// An address, or a range such as `10.0.0.0/16`.
    pub address: String,
    /// Whether it's a proxy to believe, or something that isn't a proxy at all.
    pub trusted: bool,
    pub created_at: Timestamp,
}

/// An address that's passed on forwarded addresses without being trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Seen {
    pub address: IpAddr,
    /// The last address it said it was passing on.
    pub forwarded_for: IpAddr,
    pub first_seen_at: Timestamp,
    pub last_seen_at: Timestamp,
    /// How many signed-in requests came through it.
    pub requests: u64,
    /// Who came through it, by email address: the first few.
    pub people: BTreeSet<String>,
    pub kind: AddressKind,
    /// The provider it belongs to, if it's one built in.
    pub provider: Option<&'static str>,
    /// What trusting it would cover.
    pub suggested: String,
}

pub struct Proxies {
    configured: Vec<IpNet>,
    /// Whether `configured` came from the config, rather than being loopback.
    from_config: bool,
    decided: RwLock<Vec<(IpNet, bool)>>,
    /// Trusted proxies that add their own address after the client's.
    adding_their_own: RwLock<Vec<IpNet>>,
    trusted: RwLock<Arc<[IpNet]>>,
    seen: Mutex<BTreeMap<IpAddr, Seen>>,
}

impl Proxies {
    /// `configured` is `trusted_proxies` from the config, if it's there.
    pub fn new(configured: Option<Vec<IpNet>>) -> Self {
        let from_config = configured.is_some();
        let configured = configured.unwrap_or_else(loopback);
        Self {
            trusted: RwLock::new(configured.clone().into()),
            configured,
            from_config,
            decided: RwLock::default(),
            adding_their_own: RwLock::default(),
            seen: Mutex::default(),
        }
    }

    /// Everything trusted now: the config's and what admins trusted.
    pub fn trusted(&self) -> Arc<[IpNet]> {
        Arc::clone(
            &self
                .trusted
                .read()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }

    /// What the config trusts, and whether that's the config's or loopback.
    pub fn configured(&self) -> (&[IpNet], bool) {
        (&self.configured, self.from_config)
    }

    /// Takes on what admins decided, as the database has it now.
    pub fn set_decisions(&self, decisions: &[Decision]) {
        let decided: Vec<(IpNet, bool)> = decisions
            .iter()
            .flat_map(|decision| {
                let trusted = decision.trusted;
                networks_of(&decision.address)
                    .into_iter()
                    .map(move |network| (network, trusted))
            })
            .collect();
        let adding: Vec<IpNet> = decisions
            .iter()
            .filter(|decision| decision.trusted)
            .filter_map(|decision| provider_named(&decision.address))
            .filter(|provider| provider.adds_its_own)
            .flat_map(Provider::networks)
            .collect();
        *self
            .adding_their_own
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = adding;
        let mut trusted = self.configured.clone();
        trusted.extend(
            decided
                .iter()
                .filter(|(_, trusted)| *trusted)
                .map(|(network, _)| *network),
        );
        *self
            .trusted
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = trusted.into();
        self.seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retain(|address, _| !decided.iter().any(|(network, _)| network.contains(address)));
        *self
            .decided
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = decided;
    }

    /// Notes a signed-in request by `person` that came from `peer`, which said it was
    /// passing on `forwarded_for`, unless that's been decided either way.
    pub fn note(&self, peer: IpAddr, forwarded_for: IpAddr, person: &str, now_ms: i64) {
        let decided = self
            .decided
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        if decided.iter().any(|(network, _)| network.contains(&peer))
            || self.trusted().iter().any(|network| network.contains(&peer))
        {
            return;
        }
        drop(decided);
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !seen.contains_key(&peer) && seen.len() >= MAX_SEEN {
            let oldest = seen
                .values()
                .min_by_key(|seen| seen.last_seen_at)
                .map(|seen| seen.address);
            if let Some(oldest) = oldest {
                seen.remove(&oldest);
            }
        }
        let entry = seen.entry(peer).or_insert_with(|| Seen {
            address: peer,
            forwarded_for,
            first_seen_at: from_ms(now_ms),
            last_seen_at: from_ms(now_ms),
            requests: 0,
            people: BTreeSet::new(),
            kind: kind_of(&peer),
            provider: provider_of(&peer).map(|provider| provider.name),
            suggested: suggested_range(&peer),
        });
        entry.forwarded_for = forwarded_for;
        entry.last_seen_at = from_ms(now_ms);
        entry.requests += 1;
        if entry.people.len() < MAX_PEOPLE {
            entry.people.insert(person.to_string());
        }
    }

    /// Proxies waiting for an admin to say whether they're theirs, most recent first.
    pub fn undecided(&self) -> Vec<Seen> {
        let seen = self
            .seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut all: Vec<Seen> = seen.values().cloned().collect();
        all.sort_by_key(|seen| std::cmp::Reverse(seen.last_seen_at));
        all
    }
}

/// Checks an address, range or provider an admin wants to decide about, giving it
/// back as it's kept. A range too wide to be one network's proxies is refused.
pub fn check_address(text: &str) -> Result<String> {
    if let Some(provider) = provider_named(text.trim()) {
        return Ok(provider.key.to_string());
    }
    let network = parse_network(text.trim())
        .map_err(|_| anyhow::anyhow!("That's not an address or a range such as 10.0.0.0/16."))?;
    let widest = match network {
        IpNet::V4(_) => WIDEST_V4_PREFIX,
        IpNet::V6(_) => WIDEST_V6_PREFIX,
    };
    ensure!(
        network.prefix_len() >= widest,
        "That range is too wide: anyone in it could claim to be anyone. Use /{widest} or narrower."
    );
    let network = network.trunc();
    Ok(if network.prefix_len() == network.max_prefix_len() {
        network.addr().to_string()
    } else {
        network.to_string()
    })
}

impl Proxies {
    /// Where a request came from, believing `X-Forwarded-For` only as far back as
    /// trusted proxies go. A provider that adds its own address after the client's has
    /// that skipped.
    pub fn source(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let trusted = self.trusted();
        let forwarded = forwarded_header(headers).unwrap_or_default();
        let peer = peer.to_canonical();
        let adding = self
            .adding_their_own
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        if adding.iter().any(|network| network.contains(&peer))
            && let Some((rest, _its_own)) = forwarded.rsplit_once(',')
        {
            return client_ip(peer, rest, &trusted);
        }
        client_ip(peer, &forwarded, &trusted)
    }

    /// The address an untrusted `peer` says it's passing on, if it says so. Nothing
    /// for a trusted one, as its header is already believed.
    pub fn forwarded_for(&self, peer: IpAddr, headers: &HeaderMap) -> Option<IpAddr> {
        let trusted = self.trusted();
        let peer = peer.to_canonical();
        if trusted.iter().any(|network| network.contains(&peer)) {
            return None;
        }
        let mut forwarded = forwarded_header(headers)?;
        // A provider adding its own address after the client's: the client's is the
        // one before.
        if provider_of(&peer).is_some_and(|provider| provider.adds_its_own)
            && let Some((rest, _its_own)) = forwarded.rsplit_once(',')
        {
            forwarded = rest.to_string();
        }
        let mut with_peer = trusted.to_vec();
        with_peer.push(IpNet::from(peer));
        let claimed = client_ip(peer, &forwarded, &with_peer);
        (claimed != peer).then_some(claimed)
    }
}

/// Every `X-Forwarded-For` header, joined as one, if there's any.
pub fn forwarded_header(headers: &HeaderMap) -> Option<String> {
    let all: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    (!all.is_empty()).then(|| all.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(forwarded: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(forwarded).unwrap());
        headers
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn decision(id: i64, address: &str, trusted: bool) -> Decision {
        Decision {
            id,
            address: address.to_string(),
            trusted,
            created_at: crate::times::from_ms(0),
        }
    }

    #[test]
    fn an_untrusted_proxy_is_heard_but_not_believed() {
        let proxies = Proxies::new(None);
        let proxy = ip("10.0.0.5");
        let claim = |forwarded: &str| proxies.forwarded_for(proxy, &headers(forwarded));
        assert_eq!(claim("203.0.113.7"), Some(ip("203.0.113.7")));
        // What a client sent first is passed over, as the proxy adds its own last.
        assert_eq!(claim("1.2.3.4, 203.0.113.7"), Some(ip("203.0.113.7")));
        assert_eq!(proxies.forwarded_for(proxy, &HeaderMap::new()), None);
        assert_eq!(claim("nonsense"), None);
        assert_eq!(proxies.source(proxy, &headers("203.0.113.7")), proxy);
        // A trusted proxy's header is believed already, so there's nothing to add.
        let local = ip("127.0.0.1");
        assert_eq!(proxies.forwarded_for(local, &headers("203.0.113.7")), None);
        assert_eq!(
            proxies.source(local, &headers("203.0.113.7")),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn google_adds_its_own_address_after_the_clients() {
        let proxies = Proxies::new(None);
        let google = ip("35.191.10.20");
        let forwarded = headers("1.2.3.4, 203.0.113.7, 34.120.0.9");
        assert_eq!(
            proxies.forwarded_for(google, &forwarded),
            Some(ip("203.0.113.7"))
        );
        proxies.set_decisions(&[decision(1, "google-cloud", true)]);
        assert_eq!(proxies.source(google, &forwarded), ip("203.0.113.7"));
        // Cloudflare doesn't.
        proxies.set_decisions(&[decision(1, "cloudflare", true)]);
        let cloudflare = ip("162.158.1.1");
        assert_eq!(
            proxies.source(cloudflare, &headers("1.2.3.4, 203.0.113.7")),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn addresses_are_told_apart_and_ranges_suggested() {
        assert_eq!(kind_of(&ip("127.0.0.1")), AddressKind::Loopback);
        assert_eq!(kind_of(&ip("10.0.1.17")), AddressKind::Private);
        assert_eq!(kind_of(&ip("100.64.3.2")), AddressKind::Private);
        assert_eq!(kind_of(&ip("fd12::1")), AddressKind::Private);
        assert_eq!(kind_of(&ip("162.158.1.1")), AddressKind::Provider);
        assert_eq!(kind_of(&ip("2606:4700::6810:84e5")), AddressKind::Provider);
        assert_eq!(kind_of(&ip("203.0.113.7")), AddressKind::Public);
        assert_eq!(suggested_range(&ip("10.0.1.17")), "10.0.1.0/24");
        assert_eq!(suggested_range(&ip("fd12::1")), "fd12::/64");
        assert_eq!(suggested_range(&ip("162.158.1.1")), "cloudflare");
        assert_eq!(suggested_range(&ip("130.211.0.9")), "google-cloud");
        assert_eq!(suggested_range(&ip("203.0.113.7")), "203.0.113.7");
    }

    #[test]
    fn loopback_is_trusted_unless_the_config_says_otherwise() {
        let proxies = Proxies::new(None);
        assert!(
            proxies
                .trusted()
                .iter()
                .any(|network| network.contains(&ip("127.0.0.1")))
        );
        assert!(
            proxies
                .trusted()
                .iter()
                .any(|network| network.contains(&ip("::1")))
        );
        let proxies = Proxies::new(Some(vec![]));
        assert!(proxies.trusted().is_empty());
    }

    #[test]
    fn proxies_are_noted_until_decided() {
        let proxies = Proxies::new(None);
        proxies.note(ip("10.0.0.5"), ip("203.0.113.7"), "a@example.com", 1);
        proxies.note(ip("10.0.0.5"), ip("203.0.113.8"), "b@example.com", 2);
        proxies.note(ip("127.0.0.1"), ip("203.0.113.7"), "a@example.com", 3);
        let undecided = proxies.undecided();
        assert_eq!(undecided.len(), 1);
        assert_eq!(undecided[0].requests, 2);
        assert_eq!(undecided[0].forwarded_for, ip("203.0.113.8"));
        assert_eq!(undecided[0].people.len(), 2);
        assert_eq!(undecided[0].suggested, "10.0.0.0/24");

        proxies.set_decisions(&[decision(1, "10.0.0.0/16", true)]);
        assert!(proxies.undecided().is_empty());
        assert!(
            proxies
                .trusted()
                .iter()
                .any(|network| network.contains(&ip("10.0.9.9")))
        );
        // Not a proxy: no more notices, and still not believed.
        proxies.note(ip("192.168.0.9"), ip("203.0.113.7"), "a@example.com", 4);
        proxies.set_decisions(&[decision(2, "192.168.0.9", false)]);
        proxies.note(ip("192.168.0.9"), ip("203.0.113.7"), "a@example.com", 5);
        assert!(proxies.undecided().is_empty());
        assert!(
            !proxies
                .trusted()
                .iter()
                .any(|network| network.contains(&ip("192.168.0.9")))
        );
    }

    #[test]
    fn only_so_many_are_kept_waiting() {
        let proxies = Proxies::new(None);
        for n in 0..30u8 {
            let peer = IpAddr::from([10, 0, 0, n]);
            proxies.note(peer, ip("203.0.113.7"), "a@example.com", i64::from(n));
        }
        let undecided = proxies.undecided();
        assert_eq!(undecided.len(), MAX_SEEN);
        assert_eq!(undecided[0].address, IpAddr::from([10, 0, 0, 29]));
    }

    #[test]
    fn addresses_are_checked_and_tidied() {
        assert_eq!(check_address(" 10.0.0.5 ").unwrap(), "10.0.0.5");
        assert_eq!(check_address("10.0.0.5/32").unwrap(), "10.0.0.5");
        assert_eq!(check_address("10.1.2.3/16").unwrap(), "10.1.0.0/16");
        assert_eq!(check_address("35.191.0.0/16").unwrap(), "35.191.0.0/16");
        assert_eq!(check_address("2001:db8::/48").unwrap(), "2001:db8::/48");
        assert!(check_address("0.0.0.0/0").is_err());
        assert!(check_address("10.0.0.0/7").is_err());
        assert!(check_address("::/0").is_err());
        assert!(check_address("proxy.example.com").is_err());
        assert_eq!(check_address("cloudflare").unwrap(), "cloudflare");
    }
}
