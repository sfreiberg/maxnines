//! Types shared by the agent and the server.

pub mod auth;

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every collector the project knows about. An agent reports the ones it can
/// run in its facts, because older agents may not have them all.
pub const COLLECTORS: [&str; 5] = ["cpu", "disk", "host", "memory", "network"];

/// What git and the build tool report when they have no answer.
const NO_BUILD_VALUE: &str = "VERGEN_IDEMPOTENT_OUTPUT";

/// Exactly which build of a program is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildInfo {
    pub version: String,
    /// The git commit, ending in `-dirty` if it had uncommitted changes.
    pub commit: String,
    /// When it was compiled, in UTC.
    pub built_at: String,
}

impl BuildInfo {
    /// Takes the values `build.rs` records. Use [`build_info`] to get them.
    pub fn new(version: &str, commit: &str, dirty: &str, built_at: &str) -> Self {
        let known = |value: &str| match value {
            NO_BUILD_VALUE => "unknown".to_string(),
            value => value.to_string(),
        };
        let suffix = if dirty == "true" { "-dirty" } else { "" };
        Self {
            version: version.to_string(),
            commit: format!("{}{suffix}", known(commit)),
            built_at: known(built_at),
        }
    }
}

/// The calling program's own build. It's a macro so that the values come from
/// the program being compiled and not from this library.
#[macro_export]
macro_rules! build_info {
    () => {
        $crate::BuildInfo::new(
            env!("CARGO_PKG_VERSION"),
            env!("VERGEN_GIT_SHA"),
            env!("VERGEN_GIT_DIRTY"),
            env!("VERGEN_BUILD_TIMESTAMP"),
        )
    };
}

/// What the server tells an agent to do. Everything about monitoring comes from
/// here, and the agent's own config only says how to reach the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Seconds between samples.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Seconds between fact reports, on top of one on every connection.
    #[serde(default = "default_facts_interval_secs")]
    pub facts_interval_secs: u64,
    #[serde(default)]
    pub collectors: BTreeMap<String, CollectorSettings>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorSettings {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Disk collector only: limit output to these mount points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_points: Option<Vec<String>>,
}

fn default_interval_secs() -> u64 {
    15
}

fn default_facts_interval_secs() -> u64 {
    3600
}

fn default_enabled() -> bool {
    true
}

impl AgentConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.interval_secs > 0, "interval_secs must be at least 1");
        ensure!(
            self.facts_interval_secs > 0,
            "facts_interval_secs must be at least 1"
        );
        for name in self.collectors.keys() {
            ensure!(
                COLLECTORS.contains(&name.as_str()),
                "unknown collector {name:?}"
            );
        }
        Ok(())
    }

    /// Identifies this exact config, so an agent can report which one it runs.
    pub fn version(&self) -> Result<String> {
        let text = serde_json::to_string(self)?;
        let mut version = hex::encode(digest(&SHA256, text.as_bytes()));
        version.truncate(16);
        Ok(version)
    }
}

/// Everything gathered in one collection pass. It doesn't say which agent it
/// came from, because the server takes that from the authenticated connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub timestamp_ms: u64,
    /// Collector output, keyed by collector name.
    pub metrics: BTreeMap<String, Value>,
}

/// What an agent sends to the server, one message per WebSocket text frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// The answer to [`ServerMessage::Challenge`].
    Hello {
        host: String,
        /// Hex-encoded Ed25519 public key.
        public_key: String,
        /// Hex-encoded signature, see [`auth`].
        signature: String,
        /// Enrollment token, for automatic approval rules.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    Sample(Sample),
    /// What the agent reports about its machine, as a JSON object. The server
    /// doesn't interpret it, so new facts need no server change. Sent on every
    /// connection and then regularly, and the server keeps what changed.
    Facts {
        facts: Value,
    },
    /// Whether the agent applied a config. It keeps the last good one if not.
    ConfigResult {
        version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

/// What the server sends to an agent during the handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The first message on every connection.
    Challenge { nonce: String },
    /// The handshake result. The server closes the connection unless approved.
    Registration { status: RegistrationStatus },
    /// Sent after the handshake, and again whenever the agent's config changes.
    Config {
        version: String,
        config: AgentConfig,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Approved,
    /// Waiting for an admin. The agent should try again later.
    Pending,
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> AgentConfig {
        serde_json::from_value(json!({
            "interval_secs": 30,
            "collectors": { "cpu": {}, "disk": { "mount_points": ["/"] } },
        }))
        .unwrap()
    }

    #[test]
    fn a_config_fills_in_defaults() {
        let config = config();

        assert_eq!(config.facts_interval_secs, 3600);
        assert!(config.collectors["cpu"].enabled);
        assert_eq!(config.collectors["cpu"].mount_points, None);
    }

    #[test]
    fn a_config_rejects_settings_it_does_not_know() {
        let typo = json!({ "intervl_secs": 5 });
        assert!(serde_json::from_value::<AgentConfig>(typo).is_err());
    }

    #[test]
    fn a_config_rejects_unusable_values() {
        let mut bad = config();
        bad.interval_secs = 0;
        assert!(bad.validate().is_err());

        let mut bad = config();
        bad.facts_interval_secs = 0;
        assert!(bad.validate().is_err());

        let mut bad = config();
        let cpu = bad.collectors["cpu"].clone();
        bad.collectors.insert("gpu".to_string(), cpu);
        assert!(bad.validate().is_err());

        assert!(config().validate().is_ok());
    }

    #[test]
    fn the_version_changes_with_the_config() {
        let mut changed = config();
        changed.interval_secs = 31;

        assert_eq!(config().version().unwrap(), config().version().unwrap());
        assert_ne!(config().version().unwrap(), changed.version().unwrap());
    }

    #[test]
    fn agent_messages_survive_a_json_round_trip() {
        let messages = [
            AgentMessage::Hello {
                host: "web-1".to_string(),
                public_key: "ab".to_string(),
                signature: "cd".to_string(),
                token: Some("secret".to_string()),
            },
            AgentMessage::Sample(Sample {
                timestamp_ms: 1_789_000_000_000,
                metrics: BTreeMap::from([("memory".to_string(), json!({ "total": 1 }))]),
            }),
            AgentMessage::Facts {
                facts: json!({ "os": { "family": "linux" } }),
            },
            AgentMessage::ConfigResult {
                version: "abc".to_string(),
                error: Some("nope".to_string()),
            },
        ];

        for message in messages {
            let text = serde_json::to_string(&message).unwrap();
            assert_eq!(
                serde_json::from_str::<AgentMessage>(&text).unwrap(),
                message
            );
        }
    }

    #[test]
    fn a_build_with_uncommitted_changes_says_so() {
        let build = BuildInfo::new("1.2.3", "abc123", "true", "2026-11-04");

        assert_eq!(build.commit, "abc123-dirty");
    }

    #[test]
    fn a_clean_build_is_just_its_commit() {
        let build = BuildInfo::new("1.2.3", "abc123", "false", "2026-11-04");

        assert_eq!(build.commit, "abc123");
    }

    #[test]
    fn a_build_without_git_history_is_unknown_and_not_a_placeholder() {
        let build = BuildInfo::new("1.2.3", NO_BUILD_VALUE, NO_BUILD_VALUE, "2026-11-04");

        assert_eq!(build.commit, "unknown");
        assert_eq!(build.built_at, "2026-11-04");
        assert_eq!(
            BuildInfo::new("1.2.3", "abc", "false", NO_BUILD_VALUE).built_at,
            "unknown"
        );
    }

    #[test]
    fn server_messages_survive_a_json_round_trip() {
        let messages = [
            ServerMessage::Challenge {
                nonce: "ab".to_string(),
            },
            ServerMessage::Registration {
                status: RegistrationStatus::Pending,
            },
            ServerMessage::Config {
                version: "abc".to_string(),
                config: config(),
            },
        ];

        for message in messages {
            let text = serde_json::to_string(&message).unwrap();
            assert_eq!(
                serde_json::from_str::<ServerMessage>(&text).unwrap(),
                message
            );
        }
    }
}
