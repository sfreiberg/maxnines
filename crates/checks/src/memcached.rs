//! The Memcached check: it connects, asks for `stats` in Memcached's plain-text
//! protocol, and leaves. From what that says, it reports the version, how many
//! connections are open, memory used against the limit, and since Memcached
//! started, the share of reads it had the key for and how many keys it evicted to
//! make room.
//!
//! Memcached only signs in with SASL over its binary protocol, which the check
//! doesn't speak, so it never signs in. It can connect over TLS, which Memcached
//! offers when started with it.

use std::collections::HashMap;

use anyhow::{Result, bail, ensure};
use maxnines_protocol::Check;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{Findings, certificate_verdict, connect, host_and_port, resolve, secure};

/// A line longer than this isn't Memcached, and nor are this many lines of
/// stats, which is a little over a hundred.
const MAX_LINE: u64 = 1024;
const MAX_LINES: usize = 500;

const NOT_MEMCACHED: &str = "it didn't answer as Memcached does";

pub(crate) async fn check_memcached(check: &Check, findings: &mut Findings) -> Result<()> {
    let (host, port) = host_and_port(&check.target)?;
    let addresses = resolve(&host, port, findings).await?;
    let socket = connect(&addresses, findings).await?;
    let stats = if check.tls == Some(true) {
        let secured = secure(&host, socket, &[], findings).await?;
        certificate_verdict(check, secured.problem)?;
        stats(secured.stream).await?
    } else {
        stats(socket).await?
    };
    read(&stats, findings);
    Ok(())
}

/// Asks for the stats, then leaves.
async fn stats<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Result<HashMap<String, String>> {
    let mut reader = BufReader::new(stream);
    reader.get_mut().write_all(b"stats\r\n").await?;
    let mut stats = HashMap::new();
    loop {
        let mut line = String::new();
        let read = (&mut reader).take(MAX_LINE).read_line(&mut line).await?;
        ensure!(read > 0, "it closed the connection");
        let line = line.trim_end();
        if line == "END" {
            break;
        }
        if line.starts_with("SERVER_ERROR") || line.starts_with("CLIENT_ERROR") || line == "ERROR" {
            bail!(NOT_MEMCACHED);
        }
        let Some((name, value)) = line
            .strip_prefix("STAT ")
            .and_then(|stat| stat.split_once(' '))
        else {
            bail!(NOT_MEMCACHED);
        };
        stats.insert(name.to_string(), value.to_string());
        ensure!(stats.len() < MAX_LINES, NOT_MEMCACHED);
    }
    // Its version is in every Memcached's stats, so without it this is something else.
    ensure!(stats.contains_key("version"), NOT_MEMCACHED);
    let _ = reader.get_mut().write_all(b"quit\r\n").await;
    Ok(stats)
}

fn read(stats: &HashMap<String, String>, findings: &mut Findings) {
    let number = |name: &str| stats.get(name).and_then(|value| value.parse::<u64>().ok());
    findings.server_version = stats.get("version").cloned();
    findings.connections = number("curr_connections");
    findings.memory_used_bytes = number("bytes");
    findings.memory_limit_bytes = number("limit_maxbytes");
    findings.evictions = number("evictions");
    if let (Some(hits), Some(misses)) = (number("get_hits"), number("get_misses")) {
        let reads = hits.saturating_add(misses);
        if reads > 0 {
            #[allow(clippy::cast_precision_loss)]
            let percent = hits as f64 / reads as f64 * 100.0;
            findings.hit_rate_percent = Some(percent);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use maxnines_protocol::CheckKind;
    use serde_json::Value;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::run;
    use crate::test_tls::acceptor;

    const STATS: &str = "STAT pid 1\r\nSTAT version 1.6.29\r\nSTAT curr_connections 7\r\n\
        STAT get_hits 75\r\nSTAT get_misses 25\r\nSTAT bytes 1048576\r\n\
        STAT limit_maxbytes 67108864\r\nSTAT evictions 3\r\nEND\r\n";

    /// Answers `stats` with `answer`, over TLS from the start when `tls`.
    async fn fake(answer: &'static str, tls: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = acceptor();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if tls {
                        if let Ok(stream) = acceptor.accept(socket).await {
                            serve(stream, answer).await;
                        }
                    } else {
                        serve(socket, answer).await;
                    }
                });
            }
        });
        address
    }

    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(stream: S, answer: &str) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        while matches!(reader.read_line(&mut line).await, Ok(n) if n > 0) {
            let reply = match line.trim_end() {
                "stats" => answer,
                "quit" => return,
                _ => "ERROR\r\n",
            };
            if reader.get_mut().write_all(reply.as_bytes()).await.is_err() {
                return;
            }
            line.clear();
        }
    }

    fn check(address: SocketAddr, tls: bool) -> Check {
        let mut check = Check::new("cache", CheckKind::Memcached, &address.to_string());
        if tls {
            check.tls = Some(true);
            check.insecure = Some(true);
        }
        check
    }

    #[tokio::test]
    async fn it_reports_what_memcached_says_of_itself() {
        for tls in [false, true] {
            let result = run(&check(fake(STATS, tls).await, tls)).await;
            assert_eq!(result["up"], 1, "{result}");
            assert_eq!(result["server_version"], "1.6.29", "{result}");
            assert_eq!(result["connections"], 7, "{result}");
            assert_eq!(result["hit_rate_percent"], 75.0, "{result}");
            assert_eq!(result["memory_used_bytes"], 1_048_576, "{result}");
            assert_eq!(result["memory_limit_bytes"], 67_108_864, "{result}");
            assert_eq!(result["evictions"], 3, "{result}");
            for stage in ["dns_secs", "connect_secs", "response_secs"] {
                assert!(result[stage].is_f64(), "{stage}: {result}");
            }
            assert_eq!(result["tls_secs"].is_f64(), tls, "{result}");
            if tls {
                // A self-signed certificate, which the check was told not to mind.
                assert_eq!(result["cert_valid"], false, "{result}");
            }
        }
    }

    #[tokio::test]
    async fn a_bad_certificate_is_down_unless_it_is_not_minded() {
        let address = fake(STATS, true).await;
        let mut strict = check(address, true);
        strict.insecure = None;
        let result = run(&strict).await;
        assert_eq!(result["up"], 0, "{result}");
        assert!(result["cert_days_left"].is_i64(), "{result}");
    }

    #[tokio::test]
    async fn a_new_memcached_has_no_hit_rate_yet() {
        let fresh = "STAT version 1.6.29\r\nSTAT get_hits 0\r\nSTAT get_misses 0\r\nEND\r\n";
        let result = run(&check(fake(fresh, false).await, false)).await;
        assert_eq!(result["up"], 1, "{result}");
        assert!(result.get("hit_rate_percent").is_none(), "{result}");
    }

    #[tokio::test]
    async fn something_else_is_not_taken_for_memcached() {
        for answer in ["ERROR\r\n", "+PONG\r\n", "STAT pid 1\r\nEND\r\n"] {
            let result: Value = run(&check(fake(answer, false).await, false)).await;
            assert_eq!(result["up"], 0, "{answer:?}: {result}");
            assert_eq!(result["error"], NOT_MEMCACHED, "{answer:?}: {result}");
        }
    }

    #[tokio::test]
    async fn a_server_that_says_nothing_is_down() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                drop::<TcpStream>(socket);
            }
        });
        let result = run(&check(address, false)).await;
        assert_eq!(result["up"], 0, "{result}");
    }
}
