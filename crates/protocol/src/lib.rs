//! Types shared by the agent and the server.

pub mod auth;

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every collector the project knows about. An agent reports the ones it can
/// run in its facts, because older agents may not have them all.
pub const COLLECTORS: [&str; 10] = [
    "checks",
    "cpu",
    "disk",
    "files",
    "host",
    "memory",
    "network",
    "processes",
    "sensors",
    "services",
];

/// How many things one collector can be told to watch.
const MAX_WATCHED: usize = 64;

/// What the server can store for one setting.
const MAX_SETTING_LEN: usize = 255;

/// Checks each use a thread and reach out over the network, so fewer of them.
const MAX_CHECKS: usize = 32;

/// A check's name is a series name, which has to fit in chart labels.
const MAX_CHECK_NAME_LEN: usize = 64;

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
    /// Processes and services collectors only: the names to watch. Nothing else
    /// about what's running on a machine is reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// Files collector only: the files and folders to watch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Checks collector only: what to try reaching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<Check>>,
}

/// Something an agent tries reaching, to see if it's up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    /// What it's called on charts and in alerts.
    pub name: String,
    pub kind: CheckKind,
    /// `host:port` for tcp and tls, a URL for http, and a host for dns and ping.
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    Tcp,
    Http,
    Tls,
    Dns,
    Ping,
}

impl CheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Dns => "dns",
            Self::Ping => "ping",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "tcp" => Some(Self::Tcp),
            "http" => Some(Self::Http),
            "tls" => Some(Self::Tls),
            "dns" => Some(Self::Dns),
            "ping" => Some(Self::Ping),
            _ => None,
        }
    }
}

/// Goes on a command line, so it can't be anything an option could look like.
fn is_plain_name(name: &str, extra: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c) || extra.contains(c))
}

fn has_port(target: &str) -> bool {
    target
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0))
}

impl Check {
    fn validate(&self) -> Result<()> {
        let name = &self.name;
        ensure!(!name.trim().is_empty(), "a check needs a name");
        ensure!(
            name.len() <= MAX_CHECK_NAME_LEN,
            "the check name {name:?} is too long"
        );
        let target = &self.target;
        ensure!(
            !target.is_empty() && target.len() <= MAX_SETTING_LEN,
            "check {name:?} needs a target of at most {MAX_SETTING_LEN} characters"
        );
        ensure!(
            !target.chars().any(|c| c.is_whitespace() || c.is_control()),
            "check {name:?} has spaces in its target"
        );
        match self.kind {
            CheckKind::Tcp | CheckKind::Tls => ensure!(
                has_port(target),
                "check {name:?} needs a target like host:port"
            ),
            CheckKind::Http => ensure!(
                target.starts_with("http://") || target.starts_with("https://"),
                "check {name:?} needs a target starting with http:// or https://"
            ),
            CheckKind::Dns | CheckKind::Ping => ensure!(
                is_plain_name(target, ":"),
                "check {name:?} needs a host name as its target"
            ),
        }
        Ok(())
    }
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
        for (name, settings) in &self.collectors {
            ensure!(
                COLLECTORS.contains(&name.as_str()),
                "unknown collector {name:?}"
            );
            settings.validate(name)?;
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

impl CollectorSettings {
    fn validate(&self, collector: &str) -> Result<()> {
        let names = self.names.as_deref().unwrap_or_default();
        ensure!(
            names.len() <= MAX_WATCHED,
            "a collector can watch at most {MAX_WATCHED} names"
        );
        for name in names {
            ensure!(!name.trim().is_empty(), "names can't be empty");
            ensure!(
                name.len() <= MAX_SETTING_LEN,
                "the name {name:?} is too long"
            );
            // Service names reach a command line. `@` and `:` appear in real ones.
            ensure!(
                collector != "services" || is_plain_name(name, "@:"),
                "{name:?} isn't a valid service name"
            );
        }

        let paths = self.paths.as_deref().unwrap_or_default();
        ensure!(
            paths.len() <= MAX_WATCHED,
            "a collector can watch at most {MAX_WATCHED} paths"
        );
        for path in paths {
            ensure!(!path.trim().is_empty(), "paths can't be empty");
            ensure!(
                path.len() <= MAX_SETTING_LEN,
                "the path {path:?} is too long"
            );
        }

        let checks = self.checks.as_deref().unwrap_or_default();
        ensure!(
            checks.len() <= MAX_CHECKS,
            "a collector can run at most {MAX_CHECKS} checks"
        );
        for (index, check) in checks.iter().enumerate() {
            check.validate()?;
            ensure!(
                !checks[..index].iter().any(|other| other.name == check.name),
                "two checks are named {:?}",
                check.name
            );
        }
        Ok(())
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

    fn watching(names: Value) -> AgentConfig {
        serde_json::from_value(json!({ "collectors": { "processes": { "names": names } } }))
            .unwrap()
    }

    #[test]
    fn process_names_are_checked() {
        watching(json!(["nginx", "postgres"])).validate().unwrap();

        let too_many: Vec<String> = (0..=MAX_WATCHED).map(|i| i.to_string()).collect();
        for names in [
            json!([""]),
            json!(["  "]),
            json!(["x".repeat(256)]),
            json!(too_many),
        ] {
            assert!(watching(names.clone()).validate().is_err(), "{names}");
        }
    }

    fn with(collector: &str, settings: Value) -> AgentConfig {
        serde_json::from_value(json!({ "collectors": { collector: settings } })).unwrap()
    }

    #[test]
    fn service_names_cannot_look_like_options() {
        let services = |name: &str| with("services", json!({ "names": [name] }));
        for good in [
            "nginx",
            "nginx.service",
            "getty@tty1",
            "com.apple.Finder",
            "MSSQL$SQL",
        ] {
            let result = services(good).validate();
            assert_eq!(result.is_ok(), good != "MSSQL$SQL", "{good}");
        }
        for bad in ["-H", "--root=/", "a b", "../x", "a;b", ""] {
            assert!(services(bad).validate().is_err(), "{bad}");
        }
        // The same characters are fine as process names, which never reach a command.
        with("processes", json!({ "names": ["a b"] }))
            .validate()
            .unwrap();
    }

    #[test]
    fn paths_are_limited() {
        let files = |paths: Value| with("files", json!({ "paths": paths }));
        files(json!(["/var/log/x", "C:\\backup"]))
            .validate()
            .unwrap();
        assert!(files(json!([""])).validate().is_err());
        assert!(files(json!(["x".repeat(256)])).validate().is_err());
        let too_many: Vec<String> = (0..=MAX_WATCHED).map(|i| i.to_string()).collect();
        assert!(files(json!(too_many)).validate().is_err());
    }

    fn check(kind: &str, target: &str) -> AgentConfig {
        let checks = json!([{ "name": "a", "kind": kind, "target": target }]);
        with("checks", json!({ "checks": checks }))
    }

    #[test]
    fn check_targets_have_to_suit_their_kind() {
        for (kind, target) in [
            ("tcp", "db.internal:5432"),
            ("tcp", "[::1]:5432"),
            ("tls", "example.com:443"),
            ("http", "https://example.com/health?x=1"),
            ("http", "http://10.0.0.1:8080/"),
            ("dns", "example.com"),
            ("ping", "10.0.0.1"),
            ("ping", "::1"),
        ] {
            check(kind, target).validate().unwrap();
        }
        for (kind, target) in [
            ("tcp", "db.internal"),
            ("tcp", ":5432"),
            ("tcp", "db:0"),
            ("tcp", "db:99999"),
            ("tls", "example.com"),
            ("http", "example.com"),
            ("http", "ftp://example.com"),
            ("http", "https://exa mple.com"),
            ("dns", "-x"),
            ("ping", "-f"),
            ("ping", "a;b"),
            ("ping", ""),
        ] {
            assert!(check(kind, target).validate().is_err(), "{kind} {target}");
        }
    }

    #[test]
    fn checks_need_their_own_short_names() {
        let target = "example.com:80";
        let one = |name: &str| json!({ "name": name, "kind": "tcp", "target": target });
        let checks = |list: Value| with("checks", json!({ "checks": list }));

        assert!(checks(json!([one(""),])).validate().is_err());
        assert!(checks(json!([one(&"x".repeat(65))])).validate().is_err());
        assert!(checks(json!([one("a"), one("a")])).validate().is_err());
        checks(json!([one("a"), one("b")])).validate().unwrap();

        let many: Vec<Value> = (0..=MAX_CHECKS).map(|i| one(&i.to_string())).collect();
        assert!(checks(json!(many)).validate().is_err());
    }

    #[test]
    fn check_kinds_read_back_as_written() {
        for kind in [
            CheckKind::Tcp,
            CheckKind::Http,
            CheckKind::Tls,
            CheckKind::Dns,
            CheckKind::Ping,
        ] {
            assert_eq!(CheckKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(CheckKind::parse("carrier-pigeon"), None);
    }

    #[test]
    fn a_config_without_process_names_keeps_its_version() {
        let config: AgentConfig =
            serde_json::from_value(json!({ "collectors": { "cpu": {} } })).unwrap();
        assert!(!serde_json::to_string(&config).unwrap().contains("names"));
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
