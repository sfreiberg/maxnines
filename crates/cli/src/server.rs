//! A server's address, and whether it's safe to send a sign in to.

use std::net::IpAddr;

use crate::failure::Failure;

/// Where a MaxNines server is: its scheme, host and port, whatever page of it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Such as `https://monitor.example.com` or `http://192.168.0.155:9000`.
    pub root: String,
    pub host: String,
}

impl Server {
    /// The server at `address`, refusing plain http beyond the local network, so a
    /// token or key never crosses the internet unencrypted.
    pub fn parse(address: &str) -> Result<Self, Failure> {
        let address = address.trim();
        let (scheme, rest) = address.split_once("://").ok_or_else(|| {
            Failure::usage(format!(
                "{address:?} isn't a web address. Give it with https://, like https://monitor.example.com"
            ))
        })?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(Failure::usage(format!(
                "{address:?} isn't a web address: it has to start with https:// or http://"
            )));
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(Failure::usage(format!("{address:?} doesn't name a server")));
        }
        let host = host_of(authority);
        if scheme == "http" && !is_local_network(&host) {
            return Err(Failure::usage(format!(
                "{host} isn't on your local network, so it needs https://, to keep your sign in \
                 from crossing the internet unencrypted"
            )));
        }
        Ok(Self {
            root: format!("{scheme}://{}", authority.to_ascii_lowercase()),
            host,
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.root)
    }

    /// A name for a context signed in to it: its host's first part, such as `monitor`
    /// for monitor.example.com, or the whole address for an IP address.
    pub fn short_name(&self) -> String {
        if self.host.parse::<IpAddr>().is_ok() || self.host.starts_with('[') {
            return self.host.clone();
        }
        self.host
            .split('.')
            .next()
            .unwrap_or(&self.host)
            .to_string()
    }
}

/// The host in `host:port`, or in `[v6]:port`, lowercased.
fn host_of(authority: &str) -> String {
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map_or(authority, |(host, _)| host)
            .trim_start_matches('[')
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    };
    host.to_ascii_lowercase()
}

/// This computer, a private or link-local address, or a name that only means
/// something nearby: one with no dots, or ending in `.local`.
pub fn is_local_network(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    let Ok(address) = host.parse::<IpAddr>() else {
        return host == "localhost"
            || (!host.contains('.') && !is_number(host))
            || host.ends_with(".local");
    };
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_network(&v4.to_string());
            }
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Whether a host with no dots is a number, which a resolver takes for an IPv4
/// address, such as `134744072` or `0x08080808` for 8.8.8.8, rather than a name.
fn is_number(host: &str) -> bool {
    let hex = host
        .strip_prefix("0x")
        .or_else(|| host.strip_prefix("0X"))
        .is_some_and(|digits| digits.chars().all(|c| c.is_ascii_hexdigit()));
    hex || host.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_page_of_a_server_gives_its_root() {
        let server = Server::parse(" https://Monitor.Example.com/alerts?x=1 ").unwrap();
        assert_eq!(server.root, "https://monitor.example.com");
        assert_eq!(
            server.url("/api/v1/hosts"),
            "https://monitor.example.com/api/v1/hosts"
        );
        assert_eq!(server.short_name(), "monitor");

        let lan = Server::parse("http://192.168.0.155:9000").unwrap();
        assert_eq!(lan.root, "http://192.168.0.155:9000");
        assert_eq!(lan.short_name(), "192.168.0.155");
    }

    #[test]
    fn plain_http_is_only_for_the_local_network() {
        for local in [
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://10.1.2.3",
            "http://172.16.0.1",
            "http://192.168.0.155:9000",
            "http://169.254.1.1",
            "http://[::1]:9000",
            "http://[fd00::1]",
            "http://monitor:9000",
            "http://monitor.local",
        ] {
            assert!(Server::parse(local).is_ok(), "{local}");
        }
        for far in [
            "http://monitor.example.com",
            "http://8.8.8.8",
            "http://172.32.0.1",
            "http://[2001:db8::1]",
            // Numbers a resolver reads as an address, which could be anywhere.
            "http://134744072",
            "http://0x08080808",
        ] {
            let refused = Server::parse(far).unwrap_err();
            assert_eq!(refused.code, Failure::USAGE, "{far}");
            assert!(
                Server::parse(&far.replace("http:", "https:")).is_ok(),
                "{far}"
            );
        }
        for number in ["134744072", "0x08080808", "0X8080808", "010"] {
            assert!(!is_local_network(number), "{number}");
        }
        assert!(is_local_network("nas2"));
    }

    #[test]
    fn what_isnt_a_server_is_said() {
        for bad in [
            "monitor.example.com",
            "ftp://x",
            "https://",
            "https://user@x",
        ] {
            assert_eq!(
                Server::parse(bad).unwrap_err().code,
                Failure::USAGE,
                "{bad}"
            );
        }
    }
}
