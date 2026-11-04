//! Types shared by the agent and the server.

pub mod auth;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
}

/// What the server sends to an agent during the handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The first message on every connection.
    Challenge { nonce: String },
    /// The handshake result. The server closes the connection unless approved.
    Registration { status: RegistrationStatus },
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
    fn server_messages_survive_a_json_round_trip() {
        let messages = [
            ServerMessage::Challenge {
                nonce: "ab".to_string(),
            },
            ServerMessage::Registration {
                status: RegistrationStatus::Pending,
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
