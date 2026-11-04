use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Whether an agent is connected right now.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct AgentPresence {
    pub online: bool,
    /// When `online` last changed.
    pub since_ms: u64,
    /// When the server last heard anything from this agent.
    pub last_seen_ms: u64,
    /// Where the latest connection came from, as seen by the server.
    pub source: IpAddr,
}

struct Entry {
    presence: AgentPresence,
    /// Only the newest connection may mark the agent offline.
    connection: u64,
}

/// Tracks live connections by agent ID. Held in memory, because a connection
/// doesn't outlive the server.
#[derive(Default)]
pub struct Presence {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    agents: BTreeMap<String, Entry>,
    next_connection: u64,
}

pub struct Connected {
    pub connection: u64,
    /// The agent was already online, which can mean two machines share a key.
    pub already_online: bool,
}

impl Presence {
    pub fn connected(&self, id: &str, source: IpAddr) -> Connected {
        let mut state = self.state.lock().unwrap();
        state.next_connection += 1;
        let connection = state.next_connection;
        let now = now_ms();

        let entry = state.agents.entry(id.to_string()).or_insert(Entry {
            presence: AgentPresence {
                online: false,
                since_ms: now,
                last_seen_ms: now,
                source,
            },
            connection,
        });
        let already_online = entry.presence.online;

        entry.connection = connection;
        entry.presence.last_seen_ms = now;
        entry.presence.source = source;
        if !already_online {
            entry.presence.online = true;
            entry.presence.since_ms = now;
        }

        Connected {
            connection,
            already_online,
        }
    }

    pub fn seen(&self, id: &str) {
        if let Some(entry) = self.state.lock().unwrap().agents.get_mut(id) {
            entry.presence.last_seen_ms = now_ms();
        }
    }

    /// Ignored if the agent has already reconnected on a newer connection.
    pub fn disconnected(&self, id: &str, connection: u64) {
        if let Some(entry) = self.state.lock().unwrap().agents.get_mut(id)
            && entry.connection == connection
        {
            entry.presence.online = false;
            entry.presence.since_ms = now_ms();
        }
    }

    pub fn get(&self, id: &str) -> Option<AgentPresence> {
        let state = self.state.lock().unwrap();
        state.agents.get(id).map(|entry| entry.presence)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn is_online(presence: &Presence, id: &str) -> bool {
        presence.get(id).is_some_and(|p| p.online)
    }

    #[test]
    fn tracks_an_agent_going_online_and_offline() {
        let presence = Presence::default();

        let connected = presence.connected("a", SOURCE);
        assert!(is_online(&presence, "a"));
        assert!(!connected.already_online);

        presence.disconnected("a", connected.connection);
        assert!(!is_online(&presence, "a"));
    }

    #[test]
    fn an_old_connection_closing_does_not_hide_a_new_one() {
        let presence = Presence::default();

        let old = presence.connected("a", SOURCE);
        let new = presence.connected("a", SOURCE);
        assert!(new.already_online);

        presence.disconnected("a", old.connection);
        assert!(is_online(&presence, "a"));

        presence.disconnected("a", new.connection);
        assert!(!is_online(&presence, "a"));
    }
}
