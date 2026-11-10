use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use serde::Serialize;
use tokio::sync::Notify;

/// How often one agent may connect. A real agent reconnects a few times after a
/// network blip; two machines sharing a key knock each other off far faster.
const CONNECTIONS_PER_MINUTE: NonZeroU32 = NonZeroU32::new(10).unwrap();

/// Facts arrive once per connection and then every `facts_interval_secs`, which is
/// at least a minute. A few more are allowed for a reconnect or two, and the rest
/// are dropped, so a misbehaving agent can't fill the facts history.
const FACTS_PER_MINUTE: NonZeroU32 = NonZeroU32::MIN;
const FACTS_BURST: NonZeroU32 = NonZeroU32::new(5).unwrap();

/// Keys are forgotten once there are this many, as they're only agent IDs.
const MAX_REMEMBERED_KEYS: usize = 100_000;

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
    /// Told when a newer connection takes over, so the older one can end.
    replaced: Arc<Notify>,
}

/// Tracks live connections by agent ID. Held in memory, because a connection
/// doesn't outlive the server.
pub struct Presence {
    state: Mutex<State>,
    connections: DefaultKeyedRateLimiter<String>,
    facts: DefaultKeyedRateLimiter<String>,
}

impl Default for Presence {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            connections: RateLimiter::keyed(Quota::per_minute(CONNECTIONS_PER_MINUTE)),
            facts: RateLimiter::keyed(Quota::per_minute(FACTS_PER_MINUTE).allow_burst(FACTS_BURST)),
        }
    }
}

#[cfg(test)]
impl Presence {
    /// The same allowances, given back by the hour, so a test that uses them up isn't
    /// handed another by a slow machine taking longer than expected.
    pub fn refilling_slowly() -> Self {
        Self {
            state: Mutex::default(),
            connections: RateLimiter::keyed(Quota::per_hour(CONNECTIONS_PER_MINUTE)),
            facts: RateLimiter::keyed(Quota::per_hour(FACTS_PER_MINUTE).allow_burst(FACTS_BURST)),
        }
    }
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
    /// Fires when a newer connection for the same agent takes over.
    pub replaced: Arc<Notify>,
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
            replaced: Arc::new(Notify::new()),
        });
        let already_online = entry.presence.online;

        // One agent, one connection: the older one is told to go.
        if already_online {
            entry.replaced.notify_one();
        }
        let replaced = Arc::new(Notify::new());
        entry.replaced = replaced.clone();
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
            replaced,
        }
    }

    /// Whether this agent may connect again yet.
    pub fn allow_connection(&self, id: &str) -> bool {
        if self.connections.len() > MAX_REMEMBERED_KEYS {
            self.connections.retain_recent();
        }
        self.connections.check_key(&id.to_string()).is_ok()
    }

    /// Whether another facts report from this agent is worth recording.
    pub fn allow_facts(&self, id: &str) -> bool {
        if self.facts.len() > MAX_REMEMBERED_KEYS {
            self.facts.retain_recent();
        }
        self.facts.check_key(&id.to_string()).is_ok()
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

    /// For an agent that's been deleted.
    pub fn forget(&self, id: &str) {
        self.state.lock().unwrap().agents.remove(id);
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
    use std::time::Duration;

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

    #[tokio::test]
    async fn a_newer_connection_tells_the_older_one_to_go() {
        let presence = Presence::default();
        let old = presence.connected("a", SOURCE);
        let other = presence.connected("b", SOURCE);

        let new = presence.connected("a", SOURCE);

        old.replaced.notified().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), new.replaced.notified())
                .await
                .is_err(),
            "the newest connection stays"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), other.replaced.notified())
                .await
                .is_err(),
            "other agents aren't touched"
        );
    }

    #[test]
    fn an_agent_can_only_connect_so_often() {
        let presence = Presence::default();
        for _ in 0..CONNECTIONS_PER_MINUTE.get() {
            assert!(presence.allow_connection("a"));
        }
        assert!(!presence.allow_connection("a"));
        assert!(presence.allow_connection("b"), "each agent has its own");
    }

    #[test]
    fn an_agent_can_only_report_facts_so_often() {
        let presence = Presence::default();
        for _ in 0..FACTS_BURST.get() {
            assert!(presence.allow_facts("a"));
        }
        assert!(!presence.allow_facts("a"));
        assert!(presence.allow_facts("b"));
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
