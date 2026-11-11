//! How many TCP connections a host has, in the states that matter: established,
//! listening, and the two that pile up when something goes wrong. Thousands in
//! `TIME_WAIT` can use up the ports for new connections, and connections in
//! `CLOSE_WAIT` are ones a program never closed, which is usually a leak.

use serde_json::{Value, json};

/// Connections by state, IPv4 and IPv6 together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpStates {
    pub established: u64,
    pub listening: u64,
    pub time_wait: u64,
    pub close_wait: u64,
    pub total: u64,
}

/// The states, as each system names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Established,
    Listening,
    TimeWait,
    CloseWait,
    Other,
}

impl TcpStates {
    fn add(&mut self, state: State) {
        self.total += 1;
        match state {
            State::Established => self.established += 1,
            State::Listening => self.listening += 1,
            State::TimeWait => self.time_wait += 1,
            State::CloseWait => self.close_wait += 1,
            State::Other => {}
        }
    }

    pub fn report(states: Option<Self>) -> [(&'static str, Value); 5] {
        let field = |pick: fn(&Self) -> u64| json!(states.as_ref().map(pick));
        [
            ("tcp_established", field(|s| s.established)),
            ("tcp_listening", field(|s| s.listening)),
            ("tcp_time_wait", field(|s| s.time_wait)),
            ("tcp_close_wait", field(|s| s.close_wait)),
            ("tcp_connections", field(|s| s.total)),
        ]
    }
}

/// Linux's tables have a header, then a connection a line, with its state in hex in
/// the fourth column: 01 established, 06 time wait, 08 close wait, 0A listening.
#[cfg(any(target_os = "linux", test))]
fn count_proc_net_tcp(text: &str, states: &mut TcpStates) {
    for line in text.lines().skip(1) {
        let Some(code) = line.split_whitespace().nth(3) else {
            continue;
        };
        states.add(match code {
            "01" => State::Established,
            "0A" => State::Listening,
            "06" => State::TimeWait,
            "08" => State::CloseWait,
            _ => State::Other,
        });
    }
}

/// `netstat -an -p tcp` on macOS and FreeBSD: a line for each connection starting
/// `tcp4` or `tcp6`, with the state last.
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
fn count_netstat(text: &str) -> TcpStates {
    let mut states = TcpStates::default();
    for line in text.lines().filter(|line| line.starts_with("tcp")) {
        states.add(match line.split_whitespace().last() {
            Some("ESTABLISHED") => State::Established,
            Some("LISTEN") => State::Listening,
            Some("TIME_WAIT") => State::TimeWait,
            Some("CLOSE_WAIT") => State::CloseWait,
            _ => State::Other,
        });
    }
    states
}

#[cfg(target_os = "linux")]
pub async fn tcp_states() -> Option<TcpStates> {
    let mut states = TcpStates::default();
    let mut read_any = false;
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table) {
            count_proc_net_tcp(&text, &mut states);
            read_any = true;
        }
    }
    read_any.then_some(states)
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn tcp_states() -> Option<TcpStates> {
    let output = crate::system::run_quietly("netstat", &["-an", "-p", "tcp"]).await?;
    output
        .status
        .success()
        .then(|| count_netstat(&String::from_utf8_lossy(&output.stdout)))
}

/// Windows names the states by number: 2 listening, 5 established, 8 close wait and
/// 11 time wait.
#[cfg(windows)]
pub async fn tcp_states() -> Option<TcpStates> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// Each table's rows, as their states. Asked for twice, as connections come and go
    /// between asking how much room the table needs and reading it.
    fn table(family: u16) -> Option<Vec<u32>> {
        for _ in 0..3 {
            let mut size = 0u32;
            // SAFETY: asking how much room the table needs, with nowhere to put it.
            unsafe {
                GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            // In eights, for the rows' alignment, with room for a few more.
            let mut buffer = vec![0u64; (size as usize).div_ceil(8) + 64];
            let mut size = u32::try_from(buffer.len() * 8).ok()?;
            // SAFETY: the buffer holds `size` bytes, and is aligned for the table.
            let status = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if status != 0 {
                continue;
            }
            let states = if family == AF_INET {
                // SAFETY: Windows filled the buffer with a table of this kind.
                let table = unsafe { &*buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>() };
                // SAFETY: the table has `dwNumEntries` rows, one after another.
                let rows = unsafe {
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
                };
                rows.iter().map(|row| row.dwState).collect()
            } else {
                // SAFETY: as above, for IPv6.
                let table = unsafe { &*buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>() };
                // SAFETY: as above.
                let rows = unsafe {
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
                };
                rows.iter().map(|row| row.dwState).collect()
            };
            return Some(states);
        }
        None
    }

    let mut states = TcpStates::default();
    for family in [AF_INET, AF_INET6] {
        for state in table(family)? {
            states.add(match state {
                5 => State::Established,
                2 => State::Listening,
                11 => State::TimeWait,
                8 => State::CloseWait,
                _ => State::Other,
            });
        }
    }
    Some(states)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
pub async fn tcp_states() -> Option<TcpStates> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_tables_give_each_connections_state() {
        let table =
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   1: 0100007F:0CEA 0100007F:A2B4 01 00000000:00000000 00:00000000 00000000  1000
   2: 0100007F:A2B4 0100007F:0CEA 06 00000000:00000000 03:00001234 00000000     0
   3: 0100007F:A2B6 0100007F:0CEA 08 00000000:00000000 00:00000000 00000000  1000
   4: 0100007F:A2B8 0100007F:0CEA 02 00000000:00000000 01:00000064 00000002  1000
";
        let mut states = TcpStates::default();
        count_proc_net_tcp(table, &mut states);
        assert_eq!(
            states,
            TcpStates {
                established: 1,
                listening: 1,
                time_wait: 1,
                close_wait: 1,
                total: 5,
            }
        );
    }

    #[test]
    fn netstat_gives_each_connections_state_last() {
        let output = "Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.0.155.9000     192.168.0.29.58712     ESTABLISHED
tcp6       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.5432         127.0.0.1.60002        TIME_WAIT
tcp4       0      0  127.0.0.1.60003        127.0.0.1.5432         CLOSE_WAIT
tcp4       0      0  127.0.0.1.60004        127.0.0.1.5432         SYN_SENT
";
        assert_eq!(
            count_netstat(output),
            TcpStates {
                established: 1,
                listening: 2,
                time_wait: 1,
                close_wait: 1,
                total: 6,
            }
        );
    }

    #[test]
    fn a_host_that_can_not_say_reports_nothing_rather_than_zero() {
        let report = TcpStates::report(None);
        assert!(report.iter().all(|(_, value)| value.is_null()));
        let report = TcpStates::report(Some(TcpStates {
            established: 3,
            ..TcpStates::default()
        }));
        assert_eq!(report[0], ("tcp_established", json!(3)));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[tokio::test]
    async fn this_host_counts_its_connections() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let states = tcp_states().await.unwrap();
        assert!(states.listening >= 1, "{states:?}");
        assert!(states.total >= states.listening + states.established);
        drop(listener);
    }
}
