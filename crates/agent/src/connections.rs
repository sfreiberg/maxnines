//! The `connections` built-in action: which processes hold the host's network
//! connections, what state those are in, and who they're mostly with.

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
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
        state: &'static str,
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
fn sockets() -> Result<Vec<Socket>> {
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
                    state: state(tcp.state),
                },
            };
            // Shared between a process and those it started, so it's counted
            // once, for the first of them.
            let pid = socket.associated_pids.iter().min().copied();
            Socket { pid, kind }
        })
        .collect())
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
                *states.entry(state).or_default() += 1;
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

    let connections: usize = states.values().sum();
    text.push_str(&format!(
        "\n{}",
        plural(connections, "TCP connection", "TCP connections")
    ));
    if connections > 0 {
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
    let sockets = sockets()?;
    let holders = holders()?;
    Ok(describe(&sockets, &holders, sees_everything()))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    use super::*;

    fn connection(pid: Option<u32>, remote: [u8; 4], state: &'static str) -> Socket {
        Socket {
            pid,
            kind: Kind::Connection {
                remote: IpAddr::V4(Ipv4Addr::from(remote)),
                state,
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

    #[test]
    fn this_process_and_a_connection_it_made_are_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _made = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _taken = listener.accept().unwrap();

        let me = std::process::id();
        let mine: Vec<Socket> = sockets()
            .unwrap()
            .into_iter()
            .filter(|socket| socket.pid == Some(me))
            .collect();
        let listening = mine.iter().filter(|s| s.kind == Kind::Listening).count();
        assert!(listening >= 1, "{mine:?}");
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let to_itself = |socket: &&Socket| {
            matches!(&socket.kind, Kind::Connection { remote, state }
                if *remote == local && *state == "established")
        };
        assert!(mine.iter().filter(to_itself).count() >= 2, "{mine:?}");

        let text = report().unwrap();
        assert!(text.contains(&format!("{me}  ")), "{text}");
        assert!(text.contains("127.0.0.1"), "{text}");
    }
}
