//! Pinging without running the system's `ping`. Its output changes with the
//! system's language, and Windows' counts "destination unreachable" from a router
//! as a reply. Windows lets any account send pings with its own ICMP functions,
//! and Linux and macOS let ordinary users send them through ICMP datagram
//! sockets, where the system allows it. Where it doesn't, as on FreeBSD or a
//! Linux with `net.ipv4.ping_group_range` closed, this says so and the caller
//! falls back to the system's `ping`, which has the rights.

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

    /// The smallest, largest and standard deviation of the times, in
    /// milliseconds, as `ping` reports them, if anything came back.
    pub fn times_ms(&self) -> Option<(f64, f64, f64)> {
        let times: Vec<f64> = self
            .times
            .iter()
            .map(|time| time.as_secs_f64() * 1000.0)
            .collect();
        let min = times.iter().copied().reduce(f64::min)?;
        let max = times.iter().copied().reduce(f64::max)?;
        let count = times.len() as f64;
        let mean = times.iter().sum::<f64>() / count;
        let variance = times.iter().map(|time| (time - mean).powi(2)).sum::<f64>() / count;
        Some((min, max, variance.sqrt()))
    }
}

pub(crate) enum Pinged {
    Replies(Replies),
    /// This system doesn't let this account send pings itself.
    NotAllowed,
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
) -> Result<Pinged> {
    let mut problem = None;
    for &address in &in_order(addresses) {
        match system::Pinger::open(address) {
            Ok(pinger) => return Ok(Pinged::Replies(echoes(pinger, count, deadline).await)),
            Err(error) if system::not_allowed(&error) => return Ok(Pinged::NotAllowed),
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
        // The sequence number only tells requests apart, so it wraps.
        let left = deadline - started;
        if let Some(took) = pinger.echo(sequence as u16, &token, wait.min(left)).await {
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

/// An ICMP echo request: type, code, checksum, identifier, sequence number, and
/// the token. IPv6 fills in its own checksum.
#[cfg_attr(windows, allow(dead_code))]
fn request(v6: bool, identifier: u16, sequence: u16, token: &[u8; 8]) -> [u8; 16] {
    let mut packet = [0; 16];
    packet[0] = if v6 { 128 } else { 8 };
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..16].copy_from_slice(token);
    if !v6 {
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// The Internet checksum: the ones' complement of the ones' complement sum of
/// the 16-bit words.
#[cfg_attr(windows, allow(dead_code))]
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Whether a packet is the reply to this request. macOS gives IPv4 replies with
/// their IP header still on, and Linux without. The identifier isn't checked, as
/// Linux replaces it with its own.
#[cfg_attr(windows, allow(dead_code))]
fn is_reply(packet: &[u8], v6: bool, sequence: u16, token: &[u8; 8]) -> bool {
    let packet = match packet.first() {
        Some(first) if !v6 && first >> 4 == 4 => {
            let header = usize::from(first & 0x0f) * 4;
            packet.get(header..).unwrap_or_default()
        }
        _ => packet,
    };
    let reply = if v6 { 129 } else { 0 };
    packet.len() >= 16
        && packet[0] == reply
        && packet[6..8] == sequence.to_be_bytes()
        && packet[8..16] == token[..]
}

#[cfg(unix)]
mod system {
    use std::io::{self, ErrorKind};
    use std::net::SocketAddr;
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::net::UdpSocket;
    use tokio::time::{Instant, sleep, timeout_at};

    pub struct Pinger {
        /// Sending and receiving only, which works the same for ICMP.
        socket: UdpSocket,
        v6: bool,
        identifier: u16,
    }

    impl Pinger {
        pub fn open(target: SocketAddr) -> io::Result<Self> {
            let v6 = target.is_ipv6();
            let protocol = if v6 {
                Protocol::ICMPV6
            } else {
                Protocol::ICMPV4
            };
            let socket = Socket::new(Domain::for_address(target), Type::DGRAM, Some(protocol))?;
            // So only replies from the target arrive.
            socket.connect(&target.into())?;
            socket.set_nonblocking(true)?;
            Ok(Self {
                socket: UdpSocket::from_std(socket.into())?,
                v6,
                identifier: std::process::id() as u16,
            })
        }

        /// How long the reply took, or nothing if none came in time.
        pub async fn echo(
            &self,
            sequence: u16,
            token: &[u8; 8],
            wait: Duration,
        ) -> Option<Duration> {
            let request = super::request(self.v6, self.identifier, sequence, token);
            let started = Instant::now();
            self.socket.send(&request).await.ok()?;
            let mut buffer = [0; 1500];
            loop {
                match timeout_at(started + wait, self.socket.recv(&mut buffer)).await {
                    Err(_) => return None,
                    Ok(Ok(size)) if super::is_reply(&buffer[..size], self.v6, sequence, token) => {
                        return Some(started.elapsed());
                    }
                    // Someone else's reply, or an older one of ours.
                    Ok(Ok(_)) => {}
                    // The system passing on an ICMP error, such as a router saying
                    // the target can't be reached. It doesn't say which request it
                    // was for, so this one keeps waiting for its own reply. The
                    // pause is in case the error doesn't clear.
                    Ok(Err(_)) => sleep(Duration::from_millis(10)).await,
                }
            }
        }
    }

    /// The system refused this account an ICMP socket, rather than failing.
    pub fn not_allowed(error: &io::Error) -> bool {
        error.kind() == ErrorKind::PermissionDenied
            || matches!(
                error.raw_os_error(),
                Some(libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT | libc::ESOCKTNOSUPPORT)
            )
    }
}

#[cfg(windows)]
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
        /// said the target can't be reached, or Windows couldn't send it. Windows
        /// only waits by blocking, so each wait has a thread of its own.
        pub async fn echo(
            &self,
            _sequence: u16,
            token: &[u8; 8],
            wait: Duration,
        ) -> Option<Duration> {
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

    /// Whether the target itself replied.
    fn send(handle: &Handle, target: SocketAddr, token: &[u8; 8], wait: Duration) -> bool {
        let mut reply = [0u64; REPLY_WORDS];
        let reply_size = std::mem::size_of_val(&reply) as u32;
        let timeout_ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX).max(1);
        // SAFETY: the request and reply buffers outlive the calls, the sizes given
        // are theirs, and the reply is only read where Windows said it wrote one,
        // at the start of the buffer, which is aligned for it.
        let status = unsafe {
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
                    (*reply.as_ptr().cast::<ICMP_ECHO_REPLY>()).Status
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
                    (*reply.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()).Status
                }
            }
        };
        // Anything but success, such as a router saying the target can't be
        // reached, isn't a reply from it.
        status == IP_SUCCESS
    }

    /// Windows lets any account ping.
    pub fn not_allowed(_error: &io::Error) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_has_a_valid_checksum() {
        let token = [1, 2, 3, 4, 5, 6, 7, 8];
        let packet = request(false, 0x1234, 7, &token);
        assert_eq!(packet[0], 8);
        // A packet with its checksum in sums to zero.
        assert_eq!(checksum(&packet), 0);
        assert_eq!(&packet[6..8], &[0, 7]);

        let packet = request(true, 0x1234, 7, &token);
        assert_eq!(packet[0], 128);
        assert_eq!(&packet[2..4], &[0, 0], "IPv6 fills in its own checksum");
    }

    #[test]
    fn replies_are_matched_to_the_request() {
        let token = [9; 8];
        let mut reply = request(false, 1, 3, &token);
        reply[0] = 0;
        assert!(is_reply(&reply, false, 3, &token));
        assert!(!is_reply(&reply, false, 4, &token), "another sequence");
        assert!(!is_reply(&reply, false, 3, &[8; 8]), "someone else's");
        assert!(!is_reply(&reply[..12], false, 3, &token), "cut short");

        // macOS keeps the IPv4 header on.
        let mut with_header = vec![0x45; 20];
        with_header.extend_from_slice(&reply);
        assert!(is_reply(&with_header, false, 3, &token));

        let mut request_back = request(false, 1, 3, &token);
        request_back[0] = 8;
        assert!(
            !is_reply(&request_back, false, 3, &token),
            "a request isn't a reply"
        );

        let mut v6 = request(true, 1, 3, &token);
        v6[0] = 129;
        assert!(is_reply(&v6, true, 3, &token));
    }

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
        let (min, max, stddev) = replies.times_ms().unwrap();
        assert!((min - 2.0).abs() < 1e-9 && (max - 6.0).abs() < 1e-9);
        assert!((stddev - (8.0f64 / 3.0).sqrt()).abs() < 1e-9);

        let nothing = Replies {
            sent: 2,
            times: vec![],
        };
        assert_eq!(nothing.loss_percent(), 100.0);
        assert_eq!(nothing.times_ms(), None);
    }

    fn ping_now(addresses: &[&str], count: u32, limit: Duration) -> Result<Pinged> {
        let addresses: Vec<SocketAddr> = addresses.iter().map(|a| a.parse().unwrap()).collect();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { ping(&addresses, count, Instant::now() + limit).await })
    }

    #[test]
    fn this_host_answers() {
        match ping_now(&["127.0.0.1:0"], 2, Duration::from_secs(5)).unwrap() {
            Pinged::Replies(replies) => {
                assert_eq!((replies.sent, replies.received()), (2, 2));
            }
            // Only where the system keeps ICMP sockets from ordinary users, which
            // Windows and macOS don't.
            Pinged::NotAllowed => {
                #[cfg(any(windows, target_os = "macos"))]
                panic!("this system lets anyone ping");
            }
        }
    }

    #[test]
    fn nothing_answers_for_an_address_kept_for_documentation() {
        // Without a route there, it can't be pinged at all, which is fine too.
        if let Ok(Pinged::Replies(replies)) = ping_now(&["192.0.2.1:0"], 1, Duration::from_secs(1))
        {
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
