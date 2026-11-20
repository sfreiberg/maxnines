//! Pinging on Windows with its own ICMP functions, which any account may use.
//! Its `ping` prints its results in the system's language, and counts a router
//! saying "destination unreachable" as a reply, so a host that couldn't be
//! reached showed as up. Linux, macOS and FreeBSD use their own `ping`, which
//! has neither problem and has the rights every account lacks there.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::time::{Instant, sleep_until};

/// What came back from the echo requests sent.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Replies {
    pub sent: u32,
    /// How long each reply took, in the order they came.
    pub times: Vec<Duration>,
}

impl Replies {
    pub fn received(&self) -> usize {
        self.times.len()
    }

    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 100.0;
        }
        let lost = f64::from(self.sent) - self.times.len() as f64;
        lost / f64::from(self.sent) * 100.0
    }

    /// The smallest, largest and standard deviation of the times, in seconds, if
    /// anything came back.
    pub fn times_secs(&self) -> Option<(f64, f64, f64)> {
        let times: Vec<f64> = self.times.iter().map(Duration::as_secs_f64).collect();
        let min = times.iter().copied().reduce(f64::min)?;
        let max = times.iter().copied().reduce(f64::max)?;
        let count = times.len() as f64;
        let mean = times.iter().sum::<f64>() / count;
        let variance = times.iter().map(|time| (time - mean).powi(2)).sum::<f64>() / count;
        Some((min, max, variance.sqrt()))
    }
}

/// Pings the first of `addresses` there's a way to, IPv4 first as `ping` does on
/// most systems: `count` echo requests, a second apart, each waiting for its reply
/// for an equal share of the time left before `deadline`. Anything that goes wrong
/// once it's started is a lost ping, not a failure, as is a router saying the
/// target can't be reached.
pub(crate) async fn ping(
    addresses: &[SocketAddr],
    count: u32,
    deadline: Instant,
) -> Result<Replies> {
    let mut problem = None;
    for &address in &in_order(addresses) {
        match system::Pinger::open(address) {
            Ok(pinger) => return Ok(echoes(pinger, count, deadline).await),
            // Such as no route to this address, when another may have one.
            Err(error) => problem = Some(error),
        }
    }
    match problem {
        Some(error) => Err(error).context("couldn't ping it"),
        None => bail!("the name wasn't found"),
    }
}

/// IPv4 addresses before IPv6, each kept in the order the system gave them.
fn in_order(addresses: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut ordered = addresses.to_vec();
    ordered.sort_by_key(SocketAddr::is_ipv6);
    ordered
}

async fn echoes(pinger: system::Pinger, count: u32, deadline: Instant) -> Replies {
    let count = count.max(1);
    let wait = deadline.saturating_duration_since(Instant::now()) / count;
    let token = token();
    let mut replies = Replies::default();
    for sequence in 0..count {
        let started = Instant::now();
        if started >= deadline {
            break;
        }
        replies.sent += 1;
        let left = deadline - started;
        if let Some(took) = pinger.echo(&token, wait.min(left)).await {
            replies.times.push(took);
        }
        if sequence + 1 < count {
            let next = (started + Duration::from_secs(1).min(wait)).min(deadline);
            sleep_until(next).await;
        }
    }
    replies
}

/// Sent in every request and expected back, so replies to another check's pings,
/// or another program's, aren't counted. Unique within this process, and the
/// process ID sets it apart from others.
fn token() -> [u8; 8] {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let mut token = [0; 8];
    token[..4].copy_from_slice(&std::process::id().to_be_bytes());
    token[4..].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    token
}

mod system {
    use std::io;
    use std::net::SocketAddr;
    use std::ptr::{null, null_mut};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::time::Instant;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_SUCCESS, Icmp6CreateFile, Icmp6SendEcho2,
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

    /// Room for the reply and what's echoed back, aligned as the reply needs.
    const REPLY_WORDS: usize = 64;

    /// Closed once nothing is using it, which may be a wait still going after
    /// the check that started it was given up on.
    struct Handle(HANDLE);

    // SAFETY: an ICMP handle can be used from any thread.
    unsafe impl Send for Handle {}
    // SAFETY: Windows lets several threads send through one handle at once.
    unsafe impl Sync for Handle {}

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: it came from IcmpCreateFile or Icmp6CreateFile, and nothing
            // can use it after this.
            unsafe { IcmpCloseHandle(self.0) };
        }
    }

    pub struct Pinger {
        handle: Arc<Handle>,
        target: SocketAddr,
    }

    impl Pinger {
        pub fn open(target: SocketAddr) -> io::Result<Self> {
            // SAFETY: neither takes anything, and the handle is checked.
            let handle = unsafe {
                if target.is_ipv6() {
                    Icmp6CreateFile()
                } else {
                    IcmpCreateFile()
                }
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                handle: Arc::new(Handle(handle)),
                target,
            })
        }

        /// How long the reply took, or nothing if none came in time, a router
        /// said the target can't be reached, it didn't echo the token, or Windows
        /// couldn't send it. Windows only waits by blocking, so each wait has a
        /// thread of its own.
        pub async fn echo(&self, token: &[u8; 8], wait: Duration) -> Option<Duration> {
            let handle = Arc::clone(&self.handle);
            let target = self.target;
            let token = *token;
            let started = Instant::now();
            let replied = tokio::task::spawn_blocking(move || send(&handle, target, &token, wait))
                .await
                .unwrap_or(false);
            replied.then(|| started.elapsed())
        }
    }

    /// Where the echoed data starts in an IPv6 reply: after the reply itself and
    /// the ICMP header of the echo.
    const ICMPV6_DATA_OFFSET: usize = std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + 8;

    /// Whether the target itself replied, echoing the token.
    fn send(handle: &Handle, target: SocketAddr, token: &[u8; 8], wait: Duration) -> bool {
        let mut reply = [0u64; REPLY_WORDS];
        let reply_size = std::mem::size_of_val(&reply) as u32;
        let timeout_ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX).max(1);
        let buffer = reply.as_ptr().cast::<u8>();
        let buffer_size = std::mem::size_of_val(&reply);
        // SAFETY: the request and reply buffers outlive the calls, the sizes given
        // are theirs, and the reply is only read where Windows said it wrote one,
        // at the start of the buffer, which is aligned for it. The echoed data is
        // only read inside the buffer.
        let (status, echoed) = unsafe {
            match target {
                SocketAddr::V4(target) => {
                    let replies = IcmpSendEcho(
                        handle.0,
                        u32::from_ne_bytes(target.ip().octets()),
                        token.as_ptr().cast(),
                        token.len() as u16,
                        null(),
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    );
                    if replies == 0 {
                        return false;
                    }
                    let answer = &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>();
                    let data = answer.Data.cast::<u8>().cast_const();
                    let size = usize::from(answer.DataSize);
                    let inside = data >= buffer
                        && data.wrapping_add(size) <= buffer.wrapping_add(buffer_size);
                    let echoed = inside && std::slice::from_raw_parts(data, size) == token;
                    (answer.Status, echoed)
                }
                SocketAddr::V6(target) => {
                    let mut source: SOCKADDR_IN6 = std::mem::zeroed();
                    source.sin6_family = AF_INET6;
                    let mut destination: SOCKADDR_IN6 = std::mem::zeroed();
                    destination.sin6_family = AF_INET6;
                    destination.sin6_addr.u.Byte = target.ip().octets();
                    destination.Anonymous.sin6_scope_id = target.scope_id();
                    let replies = Icmp6SendEcho2(
                        handle.0,
                        null_mut(),
                        None,
                        null(),
                        &source,
                        &destination,
                        token.as_ptr().cast(),
                        token.len() as u16,
                        null(),
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    );
                    if replies == 0 {
                        return false;
                    }
                    let answer = &*reply.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>();
                    let data =
                        std::slice::from_raw_parts(buffer.add(ICMPV6_DATA_OFFSET), token.len());
                    (answer.Status, data == token)
                }
            }
        };
        // Anything but success, such as a router saying the target can't be
        // reached, isn't a reply from it, and nor is one to another's ping.
        status == IP_SUCCESS && echoed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_give_loss_and_times() {
        let replies = Replies {
            sent: 4,
            times: vec![
                Duration::from_millis(2),
                Duration::from_millis(4),
                Duration::from_millis(6),
            ],
        };
        assert_eq!(replies.loss_percent(), 25.0);
        let (min, max, stddev) = replies.times_secs().unwrap();
        assert!((min - 0.002).abs() < 1e-12 && (max - 0.006).abs() < 1e-12);
        assert!((stddev - (8.0f64 / 3.0).sqrt() / 1000.0).abs() < 1e-12);

        let nothing = Replies {
            sent: 2,
            times: vec![],
        };
        assert_eq!(nothing.loss_percent(), 100.0);
        assert_eq!(nothing.times_secs(), None);
    }

    fn ping_now(addresses: &[&str], count: u32, limit: Duration) -> Result<Replies> {
        let addresses: Vec<SocketAddr> = addresses.iter().map(|a| a.parse().unwrap()).collect();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { ping(&addresses, count, Instant::now() + limit).await })
    }

    #[test]
    fn this_host_answers() {
        let replies = ping_now(&["127.0.0.1:0"], 2, Duration::from_secs(5)).unwrap();
        assert_eq!((replies.sent, replies.received()), (2, 2));
    }

    #[test]
    fn this_host_answers_over_ipv6() {
        let replies = ping_now(&["[::1]:0"], 2, Duration::from_secs(5)).unwrap();
        assert_eq!((replies.sent, replies.received()), (2, 2));
    }

    #[test]
    fn nothing_answers_for_an_address_kept_for_documentation() {
        // Without a route there, it can't be pinged at all, which is fine too.
        if let Ok(replies) = ping_now(&["192.0.2.1:0"], 1, Duration::from_secs(1)) {
            assert_eq!((replies.sent, replies.received()), (1, 0));
        }
    }

    #[test]
    fn ipv4_comes_first() {
        let addresses: Vec<SocketAddr> = ["[::1]:0", "10.0.0.1:0", "[::2]:0", "10.0.0.2:0"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let ordered: Vec<String> = in_order(&addresses)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(ordered, ["10.0.0.1:0", "10.0.0.2:0", "[::1]:0", "[::2]:0"]);
    }

    #[test]
    fn every_ping_has_its_own_token() {
        assert_ne!(token(), token());
    }
}
