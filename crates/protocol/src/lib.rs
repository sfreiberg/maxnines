//! Types shared by the agent and the server.

pub mod auth;
pub mod hcl_env;
pub mod logging;
#[cfg(windows)]
pub mod service;
pub mod stopping;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, ensure};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every collector the project knows about. An agent reports the ones it can
/// run in its facts, because older agents may not have them all.
pub const COLLECTORS: [&str; 12] = [
    "checks",
    "cpu",
    "custom",
    "disk",
    "files",
    "host",
    "memory",
    "network",
    "processes",
    "sensors",
    "services",
    "system",
];

/// How many things one collector can be told to watch.
const MAX_WATCHED: usize = 64;

/// What the server can store for one setting.
const MAX_SETTING_LEN: usize = 255;

/// Checks each use a thread and reach out over the network, so fewer of them.
const MAX_CHECKS: usize = 32;

/// A check runs inside a sampling round, so it can't take forever.
const MAX_CHECK_TIMEOUT_SECS: u64 = 60;

const MAX_PING_COUNT: u32 = 20;

/// A check's name is a series name, which has to fit in chart labels.
const MAX_CHECK_NAME_LEN: usize = 64;

/// What git and the build tool report when they have no answer.
const NO_BUILD_VALUE: &str = "VERGEN_IDEMPOTENT_OUTPUT";

/// How long an agent waits before trying the server again. The limit on the wait
/// doubles with each try, and the wait itself is anywhere up to the limit, so that
/// agents cut off together don't all come back together.
#[derive(Debug, Clone)]
pub struct Backoff {
    limit: Duration,
}

impl Backoff {
    /// The longest an agent ever waits, and how long a connection has to last for it
    /// to count as having worked.
    pub const MAX: Duration = Duration::from_secs(30);
    const MIN: Duration = Duration::from_secs(1);

    pub fn new() -> Self {
        Self { limit: Self::MIN }
    }

    /// The next wait, given a random number from 0 to 1.
    pub fn next_wait(&mut self, random: f64) -> Duration {
        let wait = self.limit.mul_f64(random.clamp(0.0, 1.0));
        self.limit = (self.limit * 2).min(Self::MAX);
        wait
    }

    pub fn reset(&mut self) {
        self.limit = Self::MIN;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

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
///
/// Settings this build doesn't know are ignored rather than refused, so a newer
/// server's config still reaches an older agent. The server refuses them when a
/// rule is saved, which is where a typo can be put right.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
pub struct CollectorSettings {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Disk collector only: limit output to these mount points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_points: Option<Vec<String>>,
    /// Processes, services and custom collectors only: the names to watch. Nothing
    /// else about what's running on a machine is reported. For custom metrics these
    /// pick from what the agent's own config defines.
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
pub struct Check {
    /// What it's called on charts and in alerts.
    pub name: String,
    pub kind: CheckKind,
    /// `host:port` for tcp and tls, a URL for http, and a host for dns and ping.
    pub target: String,
    /// How long it gets, up to a minute. A slower answer counts as down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// http: the method to use. Defaults to GET.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// http: what to send, for methods like POST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// http: a regular expression the page has to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// http and tls: measure a site whose certificate can't be verified, such as
    /// one from a private authority, without counting that as down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// dns: ask this server directly, instead of the system's resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// dns: the record type to ask for, with `server`. Defaults to A.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// ping: how many packets to send. Defaults to 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
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
/// A custom metric's name is a series name, so it has to fit in chart labels.
pub fn is_custom_metric_name(name: &str) -> bool {
    name.len() <= MAX_CHECK_NAME_LEN && is_plain_name(name, "")
}

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
    pub fn new(name: &str, kind: CheckKind, target: &str) -> Self {
        Self {
            name: name.to_string(),
            kind,
            target: target.to_string(),
            timeout_secs: None,
            method: None,
            body: None,
            regex: None,
            insecure: None,
            server: None,
            record: None,
            count: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
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
        self.validate_options()
    }

    fn validate_options(&self) -> Result<()> {
        let name = &self.name;
        let only_for = |set: bool, option: &str, kinds: &[CheckKind]| {
            ensure!(
                !set || kinds.contains(&self.kind),
                "check {name:?} can't use {option}"
            );
            Ok(())
        };
        only_for(self.method.is_some(), "method", &[CheckKind::Http])?;
        only_for(self.body.is_some(), "body", &[CheckKind::Http])?;
        only_for(self.regex.is_some(), "regex", &[CheckKind::Http])?;
        only_for(
            self.insecure.is_some(),
            "insecure",
            &[CheckKind::Http, CheckKind::Tls],
        )?;
        only_for(self.server.is_some(), "server", &[CheckKind::Dns])?;
        only_for(self.record.is_some(), "record", &[CheckKind::Dns])?;
        only_for(self.count.is_some(), "count", &[CheckKind::Ping])?;

        if let Some(seconds) = self.timeout_secs {
            ensure!(
                (1..=MAX_CHECK_TIMEOUT_SECS).contains(&seconds),
                "check {name:?} needs a timeout from 1 to {MAX_CHECK_TIMEOUT_SECS} seconds"
            );
        }
        if let Some(method) = &self.method {
            ensure!(
                !method.is_empty()
                    && method.len() <= 16
                    && method.chars().all(|c| c.is_ascii_uppercase()),
                "check {name:?} has an invalid method"
            );
        }
        for (option, text) in [("body", &self.body), ("regex", &self.regex)] {
            if let Some(text) = text {
                ensure!(
                    text.len() <= MAX_SETTING_LEN,
                    "check {name:?} has too long a {option}"
                );
            }
        }
        if let Some(pattern) = &self.regex {
            regex_lite::Regex::new(pattern)
                .map_err(|_| anyhow::anyhow!("check {name:?} has an invalid regex"))?;
        }
        if let Some(server) = &self.server {
            ensure!(
                has_port(server) || is_plain_name(server, ":"),
                "check {name:?} has an invalid server"
            );
        }
        if let Some(record) = &self.record {
            ensure!(
                self.server.is_some(),
                "check {name:?} needs a server to ask for a record type"
            );
            ensure!(
                !record.is_empty()
                    && record.len() <= 10
                    && record.chars().all(|c| c.is_ascii_alphanumeric()),
                "check {name:?} has an invalid record type"
            );
        }
        if let Some(count) = self.count {
            ensure!(
                (1..=MAX_PING_COUNT).contains(&count),
                "check {name:?} needs a count from 1 to {MAX_PING_COUNT}"
            );
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

/// Longer than anyone wants between samples, and far below what a timer can hold.
pub const MAX_INTERVAL_SECS: u64 = 86_400;
/// A week between fact reports, on top of one on every connection.
pub const MAX_FACTS_INTERVAL_SECS: u64 = 7 * 86_400;

impl AgentConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.interval_secs > 0, "interval_secs must be at least 1");
        ensure!(
            self.interval_secs <= MAX_INTERVAL_SECS,
            "interval_secs can be at most {MAX_INTERVAL_SECS}, a day"
        );
        ensure!(
            self.facts_interval_secs > 0,
            "facts_interval_secs must be at least 1"
        );
        ensure!(
            self.facts_interval_secs <= MAX_FACTS_INTERVAL_SECS,
            "facts_interval_secs can be at most {MAX_FACTS_INTERVAL_SECS}, a week"
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
            ensure!(
                collector != "custom" || is_custom_metric_name(name),
                "{name:?} isn't a valid custom metric name"
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

/// What the server sends to an agent.
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
    /// The sample taken at this time is safely stored, so the agent can forget it.
    /// Until then it keeps the sample and sends it again if the connection ends, so
    /// the server ignores one it's already stored.
    Ack { timestamp_ms: u64 },
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
    fn the_longest_wait_doubles_until_it_reaches_the_limit() {
        let mut backoff = Backoff::new();
        let waits: Vec<u64> = (0..7).map(|_| backoff.next_wait(1.0).as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30]);
    }

    #[test]
    fn a_wait_is_spread_over_the_whole_of_the_limit() {
        let mut backoff = Backoff::new();
        assert_eq!(backoff.next_wait(0.0), Duration::ZERO);
        assert_eq!(backoff.next_wait(0.5), Duration::from_secs(1));
    }

    #[test]
    fn a_reset_goes_back_to_short_waits() {
        let mut backoff = Backoff::new();
        for _ in 0..4 {
            backoff.next_wait(1.0);
        }
        backoff.reset();
        assert_eq!(backoff.next_wait(1.0), Duration::from_secs(1));
    }

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

    /// A timer can't hold a span anywhere near `u64::MAX` seconds, and the agent
    /// would otherwise fall over on the arithmetic, every time it restarted.
    #[test]
    fn intervals_have_limits() {
        let with = |interval: u64, facts: u64| AgentConfig {
            interval_secs: interval,
            facts_interval_secs: facts,
            ..config()
        };
        with(MAX_INTERVAL_SECS, MAX_FACTS_INTERVAL_SECS)
            .validate()
            .unwrap();
        for bad in [
            with(0, 60),
            with(MAX_INTERVAL_SECS + 1, 60),
            with(u64::MAX, 60),
            with(60, 0),
            with(60, MAX_FACTS_INTERVAL_SECS + 1),
            with(60, u64::MAX),
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    /// A newer server can add settings without older agents refusing every config
    /// it sends from then on.
    #[test]
    fn settings_from_a_newer_server_are_ignored() {
        let config: AgentConfig = serde_json::from_value(json!({
            "interval_secs": 30,
            "brand_new_setting": true,
            "collectors": {
                "cpu": { "enabled": true, "per_core_detail": "all" },
                "checks": {
                    "checks": [{
                        "name": "site", "kind": "http", "target": "https://example.com/",
                        "follow_redirects": true,
                    }],
                },
            },
        }))
        .unwrap();
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.collectors.len(), 2);
        config.validate().unwrap();
    }

    #[test]
    fn custom_metric_names_are_checked() {
        let custom = |name: &str| -> AgentConfig {
            serde_json::from_value(json!({ "collectors": { "custom": { "names": [name] } } }))
                .unwrap()
        };
        custom("queue.depth-1_a").validate().unwrap();
        for bad in ["/bin/sh", "a b", "-x", "a;b", &"x".repeat(65)] {
            assert!(custom(bad).validate().is_err(), "{bad}");
        }
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

    fn option(kind: &str, target: &str, options: Value) -> AgentConfig {
        let mut check = json!({ "name": "a", "kind": kind, "target": target });
        check
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        with("checks", json!({ "checks": [check] }))
    }

    #[test]
    fn check_options_are_checked() {
        let url = "https://example.com/";
        for (kind, target, good) in [
            (
                "http",
                url,
                json!({ "method": "POST", "body": "{}", "timeout_secs": 30 }),
            ),
            (
                "http",
                url,
                json!({ "regex": "^Welcome", "insecure": true }),
            ),
            ("tls", "example.com:443", json!({ "insecure": true })),
            (
                "dns",
                "example.com",
                json!({ "server": "8.8.8.8", "record": "MX" }),
            ),
            ("dns", "example.com", json!({ "server": "10.0.0.1:5353" })),
            ("ping", "example.com", json!({ "count": 5 })),
        ] {
            option(kind, target, good).validate().unwrap();
        }
        for (kind, target, bad) in [
            ("http", url, json!({ "method": "post" })),
            ("http", url, json!({ "method": "GET /" })),
            ("http", url, json!({ "regex": "(" })),
            ("http", url, json!({ "regex": "x".repeat(256) })),
            ("http", url, json!({ "body": "x".repeat(256) })),
            ("http", url, json!({ "timeout_secs": 0 })),
            ("http", url, json!({ "timeout_secs": 61 })),
            ("http", url, json!({ "count": 2 })),
            ("tcp", "a:1", json!({ "regex": "x" })),
            ("tcp", "a:1", json!({ "insecure": true })),
            ("dns", "example.com", json!({ "record": "A" })),
            ("dns", "example.com", json!({ "server": "-x" })),
            (
                "dns",
                "example.com",
                json!({ "server": "8.8.8.8", "record": "A;B" }),
            ),
            ("ping", "example.com", json!({ "count": 0 })),
            ("ping", "example.com", json!({ "count": 21 })),
        ] {
            assert!(
                option(kind, target, bad.clone()).validate().is_err(),
                "{bad}"
            );
        }
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
