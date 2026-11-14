//! The `connections` built-in action: which processes hold the host's network
//! connections, what state those are in, and who they're mostly with.
//!
//! Linux, macOS and Windows are read through netstat2. FreeBSD, which that
//! doesn't cover, is asked for each process's open files, which say everything
//! but what state a connection is in.

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
#[cfg(not(target_os = "freebsd"))]
use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, iterate_sockets_info,
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::builtin_actions::{name, owner, sees_everything, table};

/// How many processes are listed.
const ROWS: usize = 20;

/// How many remote addresses are listed.
const ADDRESSES: usize = 10;

/// What one socket is, as far as the tables go.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// Waiting for connections.
    Listening,
    /// A TCP connection, made or on its way in or out.
    Connection {
        remote: IpAddr,
        /// Where the system says.
        state: Option<&'static str>,
    },
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Socket {
    /// The process holding it, where the system says.
    pid: Option<u32>,
    kind: Kind,
}

/// A process as the table names it.
struct Holder {
    user: String,
    name: String,
}

/// What one process holds.
#[derive(Default)]
struct Held {
    connections: usize,
    listening: usize,
    udp: usize,
}

#[cfg(not(target_os = "freebsd"))]
fn state(state: TcpState) -> &'static str {
    match state {
        TcpState::Established => "established",
        TcpState::SynSent => "connecting",
        TcpState::SynReceived => "being accepted",
        TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::LastAck => {
            "closing"
        }
        TcpState::CloseWait => "closed by the other end",
        TcpState::TimeWait => "waiting after close",
        TcpState::Closed | TcpState::DeleteTcb => "closed",
        TcpState::Listen | TcpState::Unknown => "in another state",
    }
}

/// Every TCP and UDP socket on the host. One the system can't describe is left
/// out rather than ending the list.
#[cfg(not(target_os = "freebsd"))]
fn sockets(_holders: &BTreeMap<u32, Holder>) -> Result<Vec<Socket>> {
    let families = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let protocols = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let found = iterate_sockets_info(families, protocols).context("listing sockets")?;
    Ok(found
        .filter_map(Result::ok)
        .map(|socket| {
            let kind = match socket.protocol_socket_info {
                ProtocolSocketInfo::Udp(_) => Kind::Udp,
                ProtocolSocketInfo::Tcp(tcp) if tcp.state == TcpState::Listen => Kind::Listening,
                ProtocolSocketInfo::Tcp(tcp) => Kind::Connection {
                    remote: tcp.remote_addr,
                    state: Some(state(tcp.state)),
                },
            };
            // Shared between a process and those it started, so it's counted
            // once, for the first of them.
            let pid = socket.associated_pids.iter().min().copied();
            Socket { pid, kind }
        })
        .collect())
}

/// FreeBSD's list of a process's open files, as `kern.proc.filedesc` gives it:
/// records one after another, each saying how long it is. The libc crate keeps
/// the part of a record that describes a socket private, so it's read here from
/// where `struct kinfo_file` in FreeBSD's `sys/user.h` puts it, which has been
/// the same since FreeBSD 12.
#[cfg(any(target_os = "freebsd", test))]
mod open_files {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{Kind, Socket};

    /// Where each field starts in a record.
    const TYPE: usize = 4;
    const DOMAIN: usize = 36;
    const PROTOCOL: usize = 44;
    const PEER: usize = 176;
    const PCB: usize = 304;
    const END: usize = 312;

    const SOCKET: i32 = 2;
    const INET: i32 = 2;
    const INET6: i32 = 28;
    const TCP: i32 = 6;
    const UDP: i32 = 17;

    fn int(record: &[u8], at: usize) -> Option<i32> {
        let bytes = record.get(at..at + 4)?;
        Some(i32::from_ne_bytes(bytes.try_into().ok()?))
    }

    /// The address and port in a `sockaddr`, if it holds an internet one.
    fn address(sockaddr: &[u8]) -> Option<(IpAddr, u16)> {
        let port = u16::from_be_bytes([*sockaddr.get(2)?, *sockaddr.get(3)?]);
        let address = match i32::from(*sockaddr.get(1)?) {
            INET => {
                let bytes: [u8; 4] = sockaddr.get(4..8)?.try_into().ok()?;
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            INET6 => {
                let bytes: [u8; 16] = sockaddr.get(8..24)?.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return None,
        };
        Some((address, port))
    }

    /// The TCP and UDP sockets among a process's open files, each with what the
    /// kernel calls it, which is the same in every process that shares it.
    pub fn sockets(mut records: &[u8], pid: u32) -> Vec<(u64, Socket)> {
        let mut found = Vec::new();
        while let Some(length) = int(records, 0) {
            let Some(length) = usize::try_from(length).ok().filter(|length| *length >= 4) else {
                break;
            };
            let Some(record) = records.get(..length) else {
                break;
            };
            records = &records[length..];
            if record.len() < END || int(record, TYPE) != Some(SOCKET) {
                continue;
            }
            if !matches!(int(record, DOMAIN), Some(INET | INET6)) {
                continue;
            }
            let kind = match int(record, PROTOCOL) {
                Some(UDP) => Kind::Udp,
                // One that isn't connected to anyone is taken to be listening.
                Some(TCP) => match address(&record[PEER..PCB]) {
                    Some((remote, port)) if port != 0 => Kind::Connection {
                        remote,
                        state: None,
                    },
                    _ => Kind::Listening,
                },
                _ => continue,
            };
            let pcb = record[PCB..END].try_into().map_or(0, u64::from_ne_bytes);
            let pid = Some(pid);
            found.push((pcb, Socket { pid, kind }));
        }
        found
    }
}

/// A process's open files, as the kernel lists them, if it lets this process see.
#[cfg(target_os = "freebsd")]
fn open_files_of(pid: u32) -> Option<Vec<u8>> {
    let name = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_FILEDESC,
        libc::c_int::try_from(pid).ok()?,
    ];
    let ask = |into: *mut libc::c_void, size: &mut usize| {
        // SAFETY: `into` is null, to ask how much there is, or points at `size`
        // bytes that the kernel fills no more than.
        unsafe {
            libc::sysctl(
                name.as_ptr(),
                name.len() as libc::c_uint,
                into,
                size,
                std::ptr::null(),
                0,
            ) == 0
        }
    };
    let mut size = 0;
    if !ask(std::ptr::null_mut(), &mut size) {
        return None;
    }
    // It may open more in between, so there's room to spare.
    let mut records = vec![0u8; size + size / 3 + 4096];
    let mut size = records.len();
    if !ask(records.as_mut_ptr().cast(), &mut size) {
        return None;
    }
    records.truncate(size);
    Some(records)
}

/// Every TCP and UDP socket of every process this one is allowed to look at. One
/// shared between a process and those it started is counted once, for the first
/// of them.
#[cfg(target_os = "freebsd")]
fn sockets(holders: &BTreeMap<u32, Holder>) -> Result<Vec<Socket>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut sockets = Vec::new();
    for pid in holders.keys() {
        let Some(records) = open_files_of(*pid) else {
            continue;
        };
        for (pcb, socket) in open_files::sockets(&records, *pid) {
            if pcb == 0 || seen.insert(pcb) {
                sockets.push(socket);
            }
        }
    }
    Ok(sockets)
}

fn holders() -> Result<BTreeMap<u32, Holder>> {
    let mut system = System::new().context("reading the process list")?;
    let kind = ProcessRefreshKind::nothing().with_user(UpdateKind::OnlyIfNotSet);
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind.without_tasks());
    let users = Users::new_with_refreshed_list().context("reading the list of users")?;
    Ok(system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let holder = Holder {
                user: owner(process, &users),
                name: name(process),
            };
            (pid.as_u32(), holder)
        })
        .collect())
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The tables, from what was found. `everything` is whether every socket's
/// process could be seen.
fn describe(sockets: &[Socket], holders: &BTreeMap<u32, Holder>, everything: bool) -> String {
    let mut held: BTreeMap<Option<u32>, Held> = BTreeMap::new();
    let mut connections = 0;
    let mut states: BTreeMap<&str, usize> = BTreeMap::new();
    // For each remote address: how many connections, and how many each process has.
    let mut remotes: BTreeMap<IpAddr, (usize, BTreeMap<Option<u32>, usize>)> = BTreeMap::new();
    for socket in sockets {
        let entry = held.entry(socket.pid).or_default();
        match &socket.kind {
            Kind::Listening => entry.listening += 1,
            Kind::Udp => entry.udp += 1,
            Kind::Connection { remote, state } => {
                entry.connections += 1;
                connections += 1;
                if let Some(state) = state {
                    *states.entry(state).or_default() += 1;
                }
                let (count, by) = remotes.entry(*remote).or_default();
                *count += 1;
                *by.entry(socket.pid).or_default() += 1;
            }
        }
    }
    let unseen = held.remove(&None).unwrap_or_default();
    let name_of = |pid: Option<u32>| {
        pid.and_then(|pid| holders.get(&pid))
            .map_or("?", |holder| holder.name.as_str())
    };

    let mut busiest: Vec<(u32, &Held)> = held
        .iter()
        .filter_map(|(pid, held)| Some(((*pid)?, held)))
        .collect();
    busiest.sort_by_key(|(pid, held)| {
        let all = held.connections + held.listening + held.udp;
        (std::cmp::Reverse((held.connections, all)), *pid)
    });
    let rows: Vec<Vec<String>> = busiest
        .iter()
        .take(ROWS)
        .map(|(pid, held)| {
            vec![
                pid.to_string(),
                holders
                    .get(pid)
                    .map_or("?", |h| h.user.as_str())
                    .to_string(),
                held.connections.to_string(),
                held.listening.to_string(),
                held.udp.to_string(),
                name_of(Some(*pid)).to_string(),
            ]
        })
        .collect();

    let mut text = if rows.is_empty() {
        "No process the agent can see holds a network socket.\n".to_string()
    } else {
        let headings = [" PID", "USER", " CONNECTIONS", " LISTENING", " UDP", "NAME"];
        table(&headings, &rows)
    };

    text.push_str(&format!(
        "\n{}",
        plural(connections, "TCP connection", "TCP connections")
    ));
    let stateless = connections > 0 && states.is_empty();
    if !states.is_empty() {
        let mut by_state: Vec<(&str, usize)> = states.into_iter().collect();
        by_state.sort_by_key(|(state, count)| (std::cmp::Reverse(*count), *state));
        let parts: Vec<String> = by_state
            .iter()
            .map(|(state, count)| format!("{count} {state}"))
            .collect();
        text.push_str(&format!(": {}", parts.join(", ")));
    }
    text.push_str(&format!(
        ". {} hold sockets.\n",
        plural(busiest.len(), "process", "processes")
    ));
    if stateless {
        text.push_str("This system doesn't say what state each connection is in.\n");
    }

    if !remotes.is_empty() {
        let mut busiest: Vec<_> = remotes.into_iter().collect();
        busiest.sort_by_key(|(address, (count, _))| (std::cmp::Reverse(*count), *address));
        let rows: Vec<Vec<String>> = busiest
            .iter()
            .take(ADDRESSES)
            .map(|(address, (count, by))| {
                // Whichever process has the most of them, and the first of equals.
                let most = by
                    .iter()
                    .max_by_key(|(pid, count)| (**count, std::cmp::Reverse(**pid)));
                let pid = most.and_then(|(pid, _)| *pid);
                vec![
                    count.to_string(),
                    address.to_string(),
                    name_of(pid).to_string(),
                ]
            })
            .collect();
        text.push_str("\nThe addresses with the most connections, and who holds most of each:\n");
        text.push_str(&table(&[" CONNECTIONS", "ADDRESS", "NAME"], &rows));
    }

    let unseen = unseen.connections + unseen.listening + unseen.udp;
    if unseen > 0 {
        text.push_str(&format!(
            "\n{} to processes the agent can't see.\n",
            plural(unseen, "socket belongs", "sockets belong")
        ));
    }
    if !everything {
        text.push_str(
            "The agent isn't running as root, so it can only see which of its own user's \
             processes hold sockets.\n",
        );
    }
    text
}

pub fn report() -> Result<String> {
    let holders = holders()?;
    let sockets = sockets(&holders)?;
    Ok(describe(&sockets, &holders, sees_everything()))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};

    use super::*;

    fn connection(pid: Option<u32>, remote: [u8; 4], state: &'static str) -> Socket {
        Socket {
            pid,
            kind: Kind::Connection {
                remote: IpAddr::V4(Ipv4Addr::from(remote)),
                state: Some(state),
            },
        }
    }

    fn holders() -> BTreeMap<u32, Holder> {
        let holder = |user: &str, name: &str| Holder {
            user: user.to_string(),
            name: name.to_string(),
        };
        BTreeMap::from([
            (7, holder("root", "sshd")),
            (40, holder("postgres", "postgres")),
        ])
    }

    #[test]
    fn processes_are_listed_by_how_many_connections_they_hold() {
        let listening = |pid| Socket {
            pid: Some(pid),
            kind: Kind::Listening,
        };
        let sockets = [
            listening(7),
            connection(Some(7), [10, 0, 0, 9], "established"),
            listening(40),
            connection(Some(40), [10, 0, 0, 5], "established"),
            connection(Some(40), [10, 0, 0, 5], "established"),
            connection(Some(40), [10, 0, 0, 9], "waiting after close"),
            Socket {
                pid: Some(40),
                kind: Kind::Udp,
            },
        ];
        let text = describe(&sockets, &holders(), true);
        let expected = "\
PID  USER      CONNECTIONS  LISTENING  UDP  NAME
 40  postgres            3          1    1  postgres
  7  root                1          1    0  sshd

4 TCP connections: 3 established, 1 waiting after close. 2 processes hold sockets.

The addresses with the most connections, and who holds most of each:
CONNECTIONS  ADDRESS   NAME
          2  10.0.0.5  postgres
          2  10.0.0.9  sshd
";
        assert_eq!(text, expected);
    }

    #[test]
    fn sockets_the_agent_cannot_place_are_counted_and_explained() {
        let sockets = [
            connection(None, [10, 0, 0, 5], "established"),
            connection(Some(999), [10, 0, 0, 5], "established"),
        ];
        let text = describe(&sockets, &holders(), false);
        // A process that ended in between has no name, and is still counted.
        assert!(text.contains("999  ?"), "{text}");
        assert!(
            text.contains("1 socket belongs to processes the agent can't see."),
            "{text}"
        );
        assert!(text.contains("isn't running as root"), "{text}");
        assert!(text.contains("2 TCP connections: 2 established. 1 process hold"));

        let nothing = describe(&[], &holders(), true);
        assert!(
            nothing.starts_with("No process the agent can see"),
            "{nothing}"
        );
        assert!(
            nothing.contains("0 TCP connections. 0 processes"),
            "{nothing}"
        );
    }

    /// One record of FreeBSD's, as long as `length` says, for a socket or not.
    fn open_file(length: usize, kind: i32, protocol: i32, peer: &[u8], pcb: u64) -> Vec<u8> {
        let mut record = vec![0u8; length];
        let mut put = |at: usize, bytes: &[u8]| {
            // A record too short to hold a socket holds only what fits.
            if let Some(into) = record.get_mut(at..at + bytes.len()) {
                into.copy_from_slice(bytes);
            }
        };
        put(0, &i32::try_from(length).unwrap().to_ne_bytes());
        put(4, &kind.to_ne_bytes());
        // IPv4, or IPv6 when the other end's address says so.
        let domain: i32 = if peer.get(1) == Some(&28) { 28 } else { 2 };
        put(36, &domain.to_ne_bytes());
        put(44, &protocol.to_ne_bytes());
        put(176, peer);
        put(304, &pcb.to_ne_bytes());
        record
    }

    #[test]
    fn freebsds_open_files_are_read_for_their_sockets() {
        // Length, family, port 5432, then the address.
        let v4 = [16, 2, 0x15, 0x38, 10, 0, 0, 5];
        let mut v6 = vec![28, 28, 0x01, 0xbb, 0, 0, 0, 0];
        v6.extend(Ipv6Addr::LOCALHOST.octets());
        let records = [
            // A file, which isn't a socket, and is shorter than one.
            open_file(64, 1, 0, &[], 0),
            open_file(400, 2, 6, &v4, 0xa1),
            open_file(312, 2, 6, &v6, 0xa2),
            // Not connected to anyone, so listening.
            open_file(320, 2, 6, &[], 0xa3),
            open_file(312, 2, 17, &[], 0xa4),
            // A Unix socket's protocol is nothing these tables count.
            open_file(312, 2, 0, &[], 0xa5),
        ]
        .concat();
        let connection = |remote: IpAddr| Kind::Connection {
            remote,
            state: None,
        };
        let found = open_files::sockets(&records, 40);
        let kinds: Vec<(u64, Kind)> = found
            .iter()
            .map(|(pcb, socket)| (*pcb, socket.kind.clone()))
            .collect();
        assert_eq!(
            kinds,
            [
                (0xa1, connection(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))),
                (0xa2, connection(IpAddr::V6(Ipv6Addr::LOCALHOST))),
                (0xa3, Kind::Listening),
                (0xa4, Kind::Udp),
            ]
        );
        assert!(found.iter().all(|(_, socket)| socket.pid == Some(40)));

        // What was cut short, or says it's longer than it is, ends the list
        // without reading past the end.
        let cut = &records[..records.len() - 312 - 1];
        assert_eq!(open_files::sockets(cut, 40).len(), 3);
        assert!(open_files::sockets(&[200, 0, 0, 0, 2, 0, 0, 0], 40).is_empty());
        assert!(open_files::sockets(&[0; 16], 40).is_empty());
        assert!(open_files::sockets(&[], 40).is_empty());

        // Without states, the line that would list them says why it doesn't.
        let sockets: Vec<Socket> = found.into_iter().map(|(_, socket)| socket).collect();
        let text = describe(&sockets, &holders(), true);
        assert!(
            text.contains(
                "2 TCP connections. 1 process hold sockets.\n\
                 This system doesn't say what state each connection is in.\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn this_process_and_a_connection_it_made_are_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _made = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _taken = listener.accept().unwrap();

        let me = std::process::id();
        let mine: Vec<Socket> = sockets(&super::holders().unwrap())
            .unwrap()
            .into_iter()
            .filter(|socket| socket.pid == Some(me))
            .collect();
        let listening = mine.iter().filter(|s| s.kind == Kind::Listening).count();
        assert!(listening >= 1, "{mine:?}");
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // FreeBSD doesn't say what state a connection is in.
        let state = (!cfg!(target_os = "freebsd")).then_some("established");
        let to_itself = |socket: &&Socket| {
            matches!(&socket.kind, Kind::Connection { remote, state: found }
                if *remote == local && *found == state)
        };
        assert!(mine.iter().filter(to_itself).count() >= 2, "{mine:?}");

        let text = report().unwrap();
        assert!(text.contains(&format!("{me}  ")), "{text}");
        assert!(text.contains("127.0.0.1"), "{text}");
    }
}
