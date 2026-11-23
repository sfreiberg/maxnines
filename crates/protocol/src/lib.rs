//! Types shared by the agent and the server.

pub mod actions;
pub mod auth;
pub mod config_file;
pub mod hcl_env;
pub mod logging;
#[cfg(windows)]
pub mod service;
pub mod stopping;
pub mod templates;
pub mod time;
pub mod totals;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The version of the protocol agents and their server speak to each other, which
/// an agent says in its hello and a server checks before anything else.
///
/// It goes up only for a change that breaks something: removing or renaming a
/// message, field, status, check kind or collector, changing what one means, or
/// adding a [`RegistrationStatus`] that lets an agent in. Adding anything else
/// doesn't, whether a message, an optional field, a check kind, a collector or a
/// status that keeps an agent out, as each side passes over what it doesn't know: an
/// unknown message is ignored, an unknown check reports that the agent needs
/// upgrading, an unknown collector is skipped and reported, and an unknown status
/// keeps the agent out, trying again as it does while it's pending.
///
/// After it goes up, a server keeps taking the version before for one release, so
/// that the usual order of upgrading, the server and then its agents, never cuts an
/// agent off, and [`OLDEST_SUPPORTED_PROTOCOL`] moves up by one each release.
/// An agent older than that is refused with a message saying to upgrade it, and
/// one newer than the server with a message saying to upgrade the server first.
pub const PROTOCOL_VERSION: u32 = 1;

/// The oldest version of the protocol a server takes from its agents. See
/// [`PROTOCOL_VERSION`].
pub const OLDEST_SUPPORTED_PROTOCOL: u32 = 1;

const _: () = assert!(OLDEST_SUPPORTED_PROTOCOL <= PROTOCOL_VERSION);

/// The versions of the protocol a server takes from agents, from `oldest` to
/// `newest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocols {
    pub oldest: u32,
    pub newest: u32,
}

/// How an agent's protocol compares with what a server takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFit {
    Supported,
    /// The agent needs upgrading.
    TooOld,
    /// The server needs upgrading.
    TooNew,
}

impl Protocols {
    /// What this build takes.
    pub const SUPPORTED: Self = Self {
        oldest: OLDEST_SUPPORTED_PROTOCOL,
        newest: PROTOCOL_VERSION,
    };

    pub fn fit(self, protocol: u32) -> ProtocolFit {
        if protocol < self.oldest {
            ProtocolFit::TooOld
        } else if protocol > self.newest {
            ProtocolFit::TooNew
        } else {
            ProtocolFit::Supported
        }
    }

    /// The versions in words, such as `protocol 1` or `protocols 1 to 2`.
    pub fn describe(self) -> String {
        if self.oldest == self.newest {
            format!("protocol {}", self.oldest)
        } else {
            format!("protocols {} to {}", self.oldest, self.newest)
        }
    }
}

/// Every collector the project knows about. An agent reports the ones it can
/// run in its facts, because older agents may not have them all.
pub const COLLECTORS: [&str; 22] = [
    "apache",
    "checks",
    "commands",
    "containers",
    "counters",
    "cpu",
    "custom",
    "databases",
    "disk",
    "files",
    "gpu",
    "host",
    "memory",
    "network",
    "nginx",
    "openmetrics",
    "php_fpm",
    "processes",
    "sensors",
    "services",
    "system",
    "top_processes",
];

/// How many things one collector can be told to watch.
const MAX_WATCHED: usize = 64;

/// A host rarely runs more than a few web servers or PHP pools, and each page
/// is a request every round.
const MAX_STATUS_PAGES: usize = 16;

/// What the server can store for one setting.
const MAX_SETTING_LEN: usize = 255;

/// Checks each run as a task and reach out over the network, so fewer of them.
const MAX_CHECKS: usize = 32;

/// A check runs inside a sampling round, so it can't take forever.
const MAX_CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a check gets when it doesn't say.
pub const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an agent waits to hear anything from the server before it reconnects.
/// The server's heartbeat has to come well inside this.
pub const AGENT_SILENCE_LIMIT: Duration = Duration::from_secs(30);

const MAX_PING_COUNT: u32 = 20;

/// A check's name is a series name, which has to fit in chart labels.
pub const MAX_CHECK_NAME_LEN: usize = 64;

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
    /// When it was compiled, if the build said.
    pub built_at: Option<DateTime<Utc>>,
    /// The Rust compiler it was built with, such as `1.100.0`.
    pub rust_version: String,
}

impl BuildInfo {
    /// Takes the values `build.rs` records. Use [`build_info`] to get them.
    pub fn new(
        version: &str,
        commit: &str,
        dirty: &str,
        built_at: &str,
        rust_version: &str,
    ) -> Self {
        let known = |value: &str| match value {
            NO_BUILD_VALUE => "unknown".to_string(),
            value => value.to_string(),
        };
        let suffix = if dirty == "true" { "-dirty" } else { "" };
        Self {
            version: version.to_string(),
            commit: format!("{}{suffix}", known(commit)),
            // The build tool writes RFC 3339.
            built_at: built_at.parse().ok(),
            rust_version: known(rust_version),
        }
    }

    /// What a program's `version` command prints: its name and version, then exactly
    /// which build it is and what it runs on.
    pub fn describe(&self, program: &str) -> String {
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let built = self.built_at.map_or_else(
            || "unknown".to_string(),
            |built| built.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        format!(
            "{program} {}\ncommit:   {}\nbuilt:    {built}\nrust:     {}\nplatform: {platform}",
            self.version, self.commit, self.rust_version
        )
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
            env!("VERGEN_RUSTC_SEMVER"),
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
    /// How long between samples.
    #[serde(
        rename = "interval_secs",
        with = "time::seconds",
        default = "default_interval"
    )]
    pub interval: Duration,
    /// How long between fact reports, on top of one on every connection.
    #[serde(
        rename = "facts_interval_secs",
        with = "time::seconds",
        default = "default_facts_interval"
    )]
    pub facts_interval: Duration,
    #[serde(default)]
    pub collectors: BTreeMap<String, CollectorSettings>,
    /// What templates have the agent read, worked out by the server for this host.
    /// Config rules can't set it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<templates::work::TemplateWork>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectorSettings {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Disk collector only: limit output to these mount points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_points: Option<Vec<String>>,
    /// Processes, services, custom and counters collectors only: the names to watch.
    /// Nothing else about what's running on a host is reported. For custom metrics
    /// these pick from what the agent's own config defines, and for counters they're
    /// Windows performance counter paths. For the OpenMetrics collector they're the
    /// metrics to keep from its pages, with `*` and `?` as wildcards, and without any
    /// it keeps them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// Files collector only: the files and folders to watch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Checks collector only: what to try reaching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<Check>>,
    /// Checks collector only: checks the agent's own config defines, with what
    /// they sign in with, to run. The server picks from those and says how often.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_checks: Option<Vec<LocalCheck>>,
    /// OpenMetrics collector only: pages the agent's own config defines, with
    /// how they sign in, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_pages: Option<Vec<String>>,
    /// Databases collector only: databases the agent's own config defines, by
    /// name, with what to read from each beyond the usual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub databases: Option<Vec<DatabaseChoice>>,
    /// Apache, nginx and PHP-FPM collectors only: the status pages to read. Without
    /// any, the collector reads [`default_status_page`]. For the OpenMetrics collector
    /// they're the metrics pages to read, and it has no usual one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
}

/// A check the agent's own config defines, which a rule asks it to run. The
/// config says what it reaches and how it signs in; this says when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCheck {
    pub name: String,
    /// How long it gets. Defaults to [`DEFAULT_CHECK_TIMEOUT`].
    #[serde(
        rename = "timeout_secs",
        with = "time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout: Option<Duration>,
    /// How often it runs, if less often than every sample.
    #[serde(
        rename = "interval_secs",
        with = "time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub interval: Option<Duration>,
}

impl LocalCheck {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            timeout: None,
            interval: None,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_check_name(&self.name)?;
        validate_check_timing(&self.name, self.timeout, self.interval)
    }
}

/// Refuses a name that can't be a check's, whoever defines the check.
fn validate_check_name(name: &str) -> Result<()> {
    ensure!(
        is_check_name(name),
        "{name:?} isn't a check's name, which is at most {MAX_CHECK_NAME_LEN} \
         characters with no line breaks"
    );
    Ok(())
}

/// Refuses a time limit or interval out of range, whoever defines the check.
fn validate_check_timing(
    name: &str,
    timeout: Option<Duration>,
    interval: Option<Duration>,
) -> Result<()> {
    if let Some(timeout) = timeout {
        ensure!(
            (Duration::from_secs(1)..=MAX_CHECK_TIMEOUT).contains(&timeout),
            "check {name:?} needs a timeout from 1 to {} seconds",
            MAX_CHECK_TIMEOUT.as_secs()
        );
    }
    if let Some(interval) = interval {
        ensure!(
            (Duration::from_secs(1)..=MAX_INTERVAL).contains(&interval),
            "check {name:?} needs an interval from 1 to {} seconds, a day",
            MAX_INTERVAL.as_secs()
        );
    }
    Ok(())
}

/// What can be read from a database beyond what always is, each costing more:
/// sizes on disk. Kinds read by templates have queries of their own to turn on
/// instead.
pub const DATABASE_EXTRAS: [&str; 1] = ["sizes"];

/// How many databases one agent can be asked to read.
const MAX_DATABASES: usize = 16;

/// A database the agent's own config defines, which a rule asks it to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseChoice {
    pub name: String,
    /// From [`DATABASE_EXTRAS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extras: Vec<String>,
}

/// Whether an OpenMetrics page the agent's config defines could be called this.
/// Its series are named by it, then a space, then the metric.
pub fn is_page_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SETTING_LEN
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Whether a check could be called this. It names a series, so it has to fit
/// in a chart's labels.
pub fn is_check_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= MAX_CHECK_NAME_LEN
        && !name.chars().any(char::is_control)
}

/// Where a collector looks for a status page when it isn't told. These are the
/// addresses the software's own documentation suggests.
pub fn default_status_page(collector: &str) -> Option<&'static str> {
    match collector {
        "apache" => Some("http://localhost/server-status?auto"),
        "nginx" => Some("http://localhost/nginx_status"),
        "php_fpm" => Some("http://localhost/status"),
        _ => None,
    }
}

/// What an OpenMetrics page is called, in front of each of its series: its address
/// without the scheme, anything after a `?`, or a path that's only `/metrics`, like
/// `localhost:9100`.
pub fn metrics_page_name(url: &str) -> &str {
    let address = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let address = address.split(['?', '#']).next().unwrap_or(address);
    address
        .strip_suffix("/metrics")
        .unwrap_or(address)
        .trim_end_matches('/')
}

/// A metric's name as OpenMetrics pages write them, where `*` and `?` stand for
/// anything.
fn is_metric_pattern(pattern: &str) -> bool {
    // A leading ! leaves out what the rest matches.
    let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
    !pattern.is_empty()
        && pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_:*?".contains(c))
}

/// Whether an OpenMetrics collector could be given these pages and these metrics to
/// keep. The server asks this of pages it reads itself, so both read the same ones.
pub fn check_metrics_pages(urls: &[String], names: &[String]) -> Result<()> {
    let settings = CollectorSettings {
        enabled: true,
        mount_points: None,
        names: Some(names.to_vec()),
        paths: None,
        checks: None,
        local_checks: None,
        local_pages: None,
        databases: None,
        urls: Some(urls.to_vec()),
    };
    settings.validate("openmetrics", Checking::Saved)
}

/// A status page has to be a plain web address. A username or password in it
/// would show up on every page that lists the setting, so those are refused, and
/// status pages are normally limited to the host itself anyway.
fn check_status_page(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else {
        anyhow::bail!("the status page {url:?} has to start with http:// or https://");
    };
    ensure!(
        url.len() <= MAX_SETTING_LEN,
        "the status page {url:?} is too long"
    );
    ensure!(
        !url.chars().any(|c| c.is_whitespace() || c.is_control()),
        "the status page {url:?} can't contain spaces"
    );
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    ensure!(
        !authority.is_empty(),
        "the status page {url:?} needs a hostname"
    );
    ensure!(
        !authority.contains('@'),
        "status pages can't hold a username or password"
    );
    Ok(())
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
    #[serde(
        rename = "timeout_secs",
        with = "time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout: Option<Duration>,
    /// On an agent, how often it runs, up to a day. Without one it runs with every
    /// sample, and it can't run more often than that. The server's own checks have
    /// their interval beside the check instead.
    #[serde(
        rename = "interval_secs",
        with = "time::optional_seconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub interval: Option<Duration>,
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
    /// postgres: the database to sign in to. Defaults to `postgres`. mongodb: the
    /// database the account belongs to. Defaults to `admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// mysql, redis, memcached, mongodb and clickhouse: connect over TLS, which
    /// they don't offer on their own. For ClickHouse, that's HTTPS. Mail and ftp:
    /// from the start, rather than upgrading to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    /// ssh: the host key's SHA-256 fingerprint, as `ssh-keygen -l` prints it, such
    /// as `SHA256:Dfij…`. Any other key counts as down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// http: whether to look up when the site's domain registration runs out.
    /// Defaults to yes; `false` turns it off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_expiry: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    Tcp,
    Http,
    Tls,
    Dns,
    Ping,
    Postgres,
    Mysql,
    Redis,
    Memcached,
    Mongodb,
    Clickhouse,
    Ssh,
    Smtp,
    Imap,
    Pop3,
    Ftp,
    /// Scheduled work pings the server when it finishes, and it's down when it
    /// hasn't in time. Only the server watches these: an agent never runs one.
    Heartbeat,
    /// A kind this build doesn't know, from a newer server. The server never saves
    /// one, and an agent reports that it can't run it rather than turning down the
    /// whole of its config.
    #[serde(other)]
    Unknown,
}

impl CheckKind {
    /// What a check of [`CheckKind::Unknown`] reports instead of running.
    pub const UNKNOWN_MESSAGE: &str =
        "this agent doesn't know this kind of check, which is newer, so it needs upgrading";

    /// Every kind this build can run.
    /// In the order people are offered them. `Unknown` stays the last variant, which
    /// a test relies on to check that nothing's missing here.
    pub const KNOWN: [Self; 17] = [
        Self::Http,
        Self::Tcp,
        Self::Tls,
        Self::Dns,
        Self::Ping,
        Self::Postgres,
        Self::Mysql,
        Self::Redis,
        Self::Memcached,
        Self::Mongodb,
        Self::Clickhouse,
        Self::Ssh,
        Self::Smtp,
        Self::Imap,
        Self::Pop3,
        Self::Ftp,
        Self::Heartbeat,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Dns => "dns",
            Self::Ping => "ping",
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Redis => "redis",
            Self::Memcached => "memcached",
            Self::Mongodb => "mongodb",
            Self::Clickhouse => "clickhouse",
            Self::Ssh => "ssh",
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
            Self::Ftp => "ftp",
            Self::Heartbeat => "heartbeat",
            Self::Unknown => "unknown",
        }
    }

    /// Whether it can sign in, with a username and password, or a key for ssh.
    pub fn signs_in(self) -> bool {
        matches!(
            self,
            Self::Postgres
                | Self::Mysql
                | Self::Redis
                | Self::Mongodb
                | Self::Clickhouse
                | Self::Ssh
                | Self::Smtp
                | Self::Imap
                | Self::Pop3
                | Self::Ftp
        )
    }

    /// One of the kinds this build knows, by its name.
    pub fn parse(text: &str) -> Option<Self> {
        Self::KNOWN.into_iter().find(|kind| kind.as_str() == text)
    }
}

/// A Windows performance counter, by its English path, like
/// `\Processor(_Total)\% Processor Time` or `\PhysicalDisk(*)\Disk Reads/sec`. It's
/// only ever read, and only on the host itself, so a path naming another computer,
/// starting `\\computer`, isn't one.
pub fn is_counter_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('\\') else {
        return false;
    };
    let mut parts = rest.split('\\');
    let (Some(object), Some(counter), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    path.len() <= MAX_SETTING_LEN
        && !object.is_empty()
        && !object.starts_with('(')
        && !counter.trim().is_empty()
        && !path.chars().any(char::is_control)
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
    target.rsplit_once(':').is_some_and(|(hostname, port)| {
        !hostname.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0)
    })
}

impl Check {
    pub fn new(name: &str, kind: CheckKind, target: &str) -> Self {
        Self {
            name: name.to_string(),
            kind,
            target: target.to_string(),
            timeout: None,
            interval: None,
            method: None,
            body: None,
            regex: None,
            insecure: None,
            server: None,
            record: None,
            count: None,
            database: None,
            tls: None,
            host_key: None,
            domain_expiry: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let name = &self.name;
        validate_check_name(name)?;
        let target = &self.target;
        if self.kind == CheckKind::Heartbeat {
            ensure!(
                target.is_empty(),
                "check {name:?} is a heartbeat, which is pinged rather than reaching anything, \
                 so it has no target"
            );
            ensure!(
                self.timeout.is_none(),
                "check {name:?} is a heartbeat, which is pinged rather than run, so it has no \
                 timeout"
            );
            return self.validate_options();
        }
        ensure!(
            !target.is_empty() && target.len() <= MAX_SETTING_LEN,
            "check {name:?} needs a target of at most {MAX_SETTING_LEN} characters"
        );
        ensure!(
            !target.chars().any(|c| c.is_whitespace() || c.is_control()),
            "check {name:?} has spaces in its target"
        );
        match self.kind {
            CheckKind::Unknown => anyhow::bail!(
                "check {name:?} needs a kind this version knows: {}",
                CheckKind::KNOWN.map(CheckKind::as_str).join(", ")
            ),
            CheckKind::Tcp
            | CheckKind::Tls
            | CheckKind::Postgres
            | CheckKind::Mysql
            | CheckKind::Redis
            | CheckKind::Memcached
            | CheckKind::Mongodb
            | CheckKind::Clickhouse
            | CheckKind::Ssh
            | CheckKind::Smtp
            | CheckKind::Imap
            | CheckKind::Pop3
            | CheckKind::Ftp => ensure!(
                has_port(target),
                "check {name:?} needs a target like host:port"
            ),
            CheckKind::Http => ensure!(
                target.starts_with("http://") || target.starts_with("https://"),
                "check {name:?} needs a target starting with http:// or https://"
            ),
            CheckKind::Dns | CheckKind::Ping => ensure!(
                is_plain_name(target, ":"),
                "check {name:?} needs a hostname as its target"
            ),
            CheckKind::Heartbeat => {}
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
            &[
                CheckKind::Http,
                CheckKind::Tls,
                CheckKind::Postgres,
                CheckKind::Mysql,
                CheckKind::Redis,
                CheckKind::Memcached,
                CheckKind::Mongodb,
                CheckKind::Clickhouse,
                CheckKind::Smtp,
                CheckKind::Imap,
                CheckKind::Pop3,
                CheckKind::Ftp,
            ],
        )?;
        only_for(
            self.database.is_some(),
            "database",
            &[CheckKind::Postgres, CheckKind::Mongodb],
        )?;
        only_for(
            self.tls.is_some(),
            "tls",
            &[
                CheckKind::Postgres,
                CheckKind::Mysql,
                CheckKind::Redis,
                CheckKind::Memcached,
                CheckKind::Mongodb,
                CheckKind::Clickhouse,
                CheckKind::Smtp,
                CheckKind::Imap,
                CheckKind::Pop3,
                CheckKind::Ftp,
            ],
        )?;
        only_for(self.host_key.is_some(), "host_key", &[CheckKind::Ssh])?;
        only_for(
            self.domain_expiry.is_some(),
            "domain_expiry",
            &[CheckKind::Http],
        )?;
        if let Some(database) = &self.database {
            ensure!(
                !database.is_empty()
                    && database.len() <= 63
                    && !database
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace()),
                "check {name:?} needs a database name of at most 63 characters, without spaces"
            );
        }
        if let Some(key) = &self.host_key {
            let encoded = key.strip_prefix("SHA256:").unwrap_or_default();
            ensure!(
                !encoded.is_empty()
                    && encoded.len() <= 64
                    && encoded
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)),
                "check {name:?} needs a host key fingerprint like SHA256:Dfij…, as \
                 ssh-keygen -l prints it"
            );
        }
        only_for(self.server.is_some(), "server", &[CheckKind::Dns])?;
        only_for(self.record.is_some(), "record", &[CheckKind::Dns])?;
        only_for(self.count.is_some(), "count", &[CheckKind::Ping])?;

        validate_check_timing(name, self.timeout, self.interval)?;
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
            // Every platform's ping sends one a second, whatever it's told.
            let limit = self.timeout.unwrap_or(DEFAULT_CHECK_TIMEOUT);
            ensure!(
                Duration::from_secs(u64::from(count)) < limit,
                "check {name:?} sends one ping a second, so a count of {count} needs \
                 timeout_secs above {count}"
            );
        }
        Ok(())
    }
}
fn default_interval() -> Duration {
    Duration::from_secs(15)
}

fn default_facts_interval() -> Duration {
    Duration::from_secs(3600)
}

fn default_enabled() -> bool {
    true
}

/// Longer than anyone wants between samples, and far below what a timer can hold.
pub const MAX_INTERVAL: Duration = Duration::from_secs(86_400);
/// Facts rarely change, and the server drops reports that come faster than this.
pub const MIN_FACTS_INTERVAL: Duration = Duration::from_secs(60);
/// A week between fact reports, on top of one on every connection.
pub const MAX_FACTS_INTERVAL: Duration = Duration::from_secs(7 * 86_400);

/// Whose config is being checked: one a server is saving, which has to be all
/// known, or one an agent was sent, which can be from a newer server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checking {
    Saved,
    Sent,
}

impl AgentConfig {
    /// Checks a config as a server saves it, where everything in it has to be known.
    pub fn validate(&self) -> Result<()> {
        self.check(Checking::Saved)
    }

    /// Takes out the collectors this build doesn't know, returning their names. A
    /// newer server can name collectors an older agent doesn't have, and the agent
    /// runs the rest.
    pub fn remove_unknown_collectors(&mut self) -> Vec<String> {
        let unknown: Vec<String> = self
            .collectors
            .keys()
            .filter(|name| !COLLECTORS.contains(&name.as_str()))
            .cloned()
            .collect();
        for name in &unknown {
            self.collectors.remove(name);
        }
        unknown
    }

    /// Checks a config an agent was sent, once
    /// [`AgentConfig::remove_unknown_collectors`] has taken out what it can't run.
    /// It's as [`AgentConfig::validate`], except that a check of a kind this build
    /// doesn't know is let through, for the agent to report that it can't run it.
    pub fn validate_sent(&self) -> Result<()> {
        self.check(Checking::Sent)
    }

    fn check(&self, checking: Checking) -> Result<()> {
        ensure!(
            self.interval >= Duration::from_secs(1),
            "interval_secs must be at least 1"
        );
        ensure!(
            self.interval <= MAX_INTERVAL,
            "interval_secs can be at most {}, a day",
            MAX_INTERVAL.as_secs()
        );
        ensure!(
            self.facts_interval >= MIN_FACTS_INTERVAL,
            "facts_interval_secs must be at least {}",
            MIN_FACTS_INTERVAL.as_secs()
        );
        ensure!(
            self.facts_interval <= MAX_FACTS_INTERVAL,
            "facts_interval_secs can be at most {}, a week",
            MAX_FACTS_INTERVAL.as_secs()
        );
        for (name, settings) in &self.collectors {
            ensure!(
                COLLECTORS.contains(&name.as_str()),
                "unknown collector {name:?}"
            );
            settings.validate(name, checking)?;
        }
        templates::work::check_work(&self.templates)
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
    fn validate(&self, collector: &str, checking: Checking) -> Result<()> {
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
                !matches!(collector, "custom" | "commands") || is_custom_metric_name(name),
                "{name:?} can only use letters, digits, ., - and _"
            );
            ensure!(
                collector != "openmetrics" || is_metric_pattern(name),
                "{name:?} isn't a metric's name, which has only letters, digits, _ and :, \
                 with * and ? for anything, and ! in front to leave it out"
            );
            ensure!(
                collector != "counters" || is_counter_path(name),
                "{name:?} isn't a performance counter path, which looks like \
                 \\Processor(_Total)\\% Processor Time"
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

        let urls = self.urls.as_deref().unwrap_or_default();
        let local_pages = self.local_pages.as_deref().unwrap_or_default();
        ensure!(
            urls.len() + local_pages.len() <= MAX_STATUS_PAGES,
            "a collector can read at most {MAX_STATUS_PAGES} status pages"
        );
        for (index, name) in local_pages.iter().enumerate() {
            ensure!(
                is_page_name(name),
                "{name:?} isn't the name of a page in the agent's config, which has no \
                 spaces"
            );
            ensure!(
                !local_pages[..index].contains(name),
                "{name:?} is listed twice"
            );
            // Series are told apart by their page's name, wherever it's defined.
            if let Some(url) = urls.iter().find(|url| metrics_page_name(url) == name) {
                anyhow::bail!(
                    "{url:?} and the agent's page {name:?} would both be called {name:?}"
                );
            }
        }
        for (index, url) in urls.iter().enumerate() {
            check_status_page(url)?;
            ensure!(!urls[..index].contains(url), "{url:?} is listed twice");
            // Series are told apart by their page's name.
            let name = metrics_page_name(url);
            let same = urls[..index]
                .iter()
                .find(|other| collector == "openmetrics" && metrics_page_name(other) == name);
            if let Some(other) = same {
                anyhow::bail!("{other:?} and {url:?} would both be called {name:?}");
            }
        }

        let databases = self.databases.as_deref().unwrap_or_default();
        ensure!(
            databases.len() <= MAX_DATABASES,
            "a collector can read at most {MAX_DATABASES} databases"
        );
        for (index, database) in databases.iter().enumerate() {
            let name = &database.name;
            ensure!(
                is_page_name(name),
                "{name:?} isn't the name of a database in the agent's config, which has \
                 no spaces"
            );
            ensure!(
                !databases[..index].iter().any(|other| &other.name == name),
                "the database {name:?} is listed twice"
            );
            for extra in &database.extras {
                ensure!(
                    DATABASE_EXTRAS.contains(&extra.as_str()),
                    "{extra:?} isn't something that can be read from a database, which are: {}",
                    DATABASE_EXTRAS.join(", ")
                );
            }
        }

        let checks = self.checks.as_deref().unwrap_or_default();
        let local = self.local_checks.as_deref().unwrap_or_default();
        ensure!(
            checks.len() + local.len() <= MAX_CHECKS,
            "a collector can run at most {MAX_CHECKS} checks"
        );
        for check in checks {
            ensure!(
                check.kind != CheckKind::Heartbeat,
                "check {:?} is a heartbeat, which the server watches for pings, so an agent \
                 can't run it",
                check.name
            );
        }
        for check in checks {
            // Its name is still a series, so it has to be one.
            if check.kind == CheckKind::Unknown && checking == Checking::Sent {
                validate_check_name(&check.name)?;
            } else {
                check.validate()?;
            }
        }
        for check in local {
            check.validate()?;
        }
        // Each is a series, by its name, wherever it's defined.
        let names: Vec<&str> = checks
            .iter()
            .map(|check| check.name.as_str())
            .chain(local.iter().map(|check| check.name.as_str()))
            .collect();
        for (index, name) in names.iter().enumerate() {
            ensure!(
                !names[..index].contains(name),
                "two checks are named {name:?}"
            );
        }
        Ok(())
    }
}

/// Everything gathered in one collection pass. It doesn't say which agent it
/// came from, because the server takes that from the authenticated connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// When it was taken, which also tells it apart from the agent's other samples.
    pub time: DateTime<Utc>,
    /// Collector output, keyed by collector name.
    pub metrics: BTreeMap<String, Value>,
}

/// What an agent sends to the server, one message per WebSocket text frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// The answer to [`ServerMessage::Challenge`].
    Hello {
        hostname: String,
        /// Hex-encoded Ed25519 public key.
        public_key: String,
        /// Hex-encoded signature, see [`auth`].
        signature: String,
        /// Enrollment token, for automatic approval rules.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        /// The [`PROTOCOL_VERSION`] the agent speaks.
        protocol: u32,
        /// The agent's own version, as [`BuildInfo::version`].
        agent_version: String,
    },
    Sample(Sample),
    /// What the agent reports about its host, as a JSON object. The server
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
        /// Collectors in an applied config that this agent doesn't know, and
        /// left out, as a newer server can name them.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        skipped_collectors: Vec<String>,
    },
    /// How an action the server asked for went.
    ActionResult(actions::ActionResult),
    /// The answer to [`ServerMessage::AskTime`]: what the agent's clock says, sent
    /// the moment it's asked and never kept to send later, as it's only true then.
    Time {
        nonce: String,
        answered_at: DateTime<Utc>,
    },
    /// A message this build doesn't know, from a newer agent, which the server
    /// ignores.
    #[serde(other)]
    Unknown,
}

/// What the server sends to an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The first message on every connection, with the versions of the protocol the
    /// server takes.
    Challenge { nonce: String, protocols: Protocols },
    /// The handshake result. The server closes the connection unless approved.
    Registration { status: RegistrationStatus },
    /// The other handshake result: the server won't take this agent until one of the
    /// two is upgraded, as it doesn't speak a version of the protocol the server
    /// takes. `reason` says which, in words for whoever runs the agent. The server
    /// closes the connection, and the agent waits a long while before trying again.
    Refused { reason: String },
    /// Sent after the handshake, and again whenever the agent's config changes.
    Config {
        version: String,
        config: AgentConfig,
    },
    /// Asks the agent to run one of its actions, by name. It answers with an
    /// [`AgentMessage::ActionResult`] carrying the same `id`.
    RunAction {
        id: String,
        action: String,
        /// Values from the alert it runs for, by variable name.
        #[serde(default)]
        variables: BTreeMap<String, String>,
        /// How long it gets before it's stopped.
        #[serde(rename = "timeout_secs", with = "time::seconds")]
        timeout: Duration,
    },
    /// The sample taken at this time is safely stored, so the agent can forget it.
    /// Until then it keeps the sample and sends it again if the connection ends, so
    /// the server ignores one it's already stored.
    Ack { time: DateTime<Utc> },
    /// Asks what the agent's clock says, to compare with the server's. The agent
    /// answers at once with an [`AgentMessage::Time`] carrying the same `nonce`,
    /// and the server times how long that took, which is how far out the
    /// comparison can be.
    AskTime { nonce: String },
    /// A message this build doesn't know, from a newer server, which the agent
    /// ignores.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Approved,
    /// Waiting for an admin. The agent should try again later.
    Pending,
    Rejected,
    /// A status this build doesn't know, from a newer server. It isn't approval, so
    /// the agent tries again as it does while it's pending, saying it may need
    /// upgrading. A newer server can add a status that keeps agents out without
    /// changing [`PROTOCOL_VERSION`], but not one that lets them in.
    #[serde(other)]
    Unknown,
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
            interval: Duration::from_secs(interval),
            facts_interval: Duration::from_secs(facts),
            ..config()
        };
        let (max, min_facts, max_facts) = (
            MAX_INTERVAL.as_secs(),
            MIN_FACTS_INTERVAL.as_secs(),
            MAX_FACTS_INTERVAL.as_secs(),
        );
        with(max, max_facts).validate().unwrap();
        for bad in [
            with(0, 60),
            with(max + 1, 60),
            with(u64::MAX, 60),
            with(60, 0),
            with(60, min_facts - 1),
            with(60, max_facts + 1),
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
        assert_eq!(config.interval, Duration::from_secs(30));
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

    #[test]
    fn counter_paths_are_checked() {
        for path in [
            r"\Processor(_Total)\% Processor Time",
            r"\PhysicalDisk(*)\Avg. Disk sec/Read",
            r"\Memory\Available MBytes",
            r"\Network Interface(Intel[R] Ethernet)\Bytes Total/sec",
        ] {
            assert!(is_counter_path(path), "{path}");
            with("counters", json!({ "names": [path] }))
                .validate()
                .unwrap();
        }
        for path in [
            "Memory\\Available MBytes",
            r"\Memory",
            r"\\server\Memory\Available MBytes",
            r"\(x)\Count",
            r"\Memory\ ",
            "\\Memory\\Avail\nable",
        ] {
            assert!(!is_counter_path(path), "{path}");
            let config = with("counters", json!({ "names": [path] }));
            assert!(config.validate().is_err(), "{path}");
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

    #[test]
    fn status_pages_are_plain_web_addresses() {
        let pages = |urls: Value| with("apache", json!({ "urls": urls })).validate();
        pages(json!([
            "http://localhost/server-status?auto",
            "https://[::1]:8443/status"
        ]))
        .unwrap();
        for bad in [
            json!(["localhost/server-status"]),
            json!(["ftp://localhost/"]),
            json!(["http://"]),
            json!(["http:///status"]),
            json!(["http://local host/"]),
            json!(["http://admin:secret@localhost/status"]),
            json!(["http://localhost/a", "http://localhost/a"]),
            json!([format!("http://localhost/{}", "x".repeat(255))]),
        ] {
            assert!(pages(bad.clone()).is_err(), "{bad}");
        }
        // An @ further along is part of the path or query, not a password.
        pages(json!(["http://localhost/status?who=@me"])).unwrap();
        let too_many: Vec<String> = (0..=MAX_STATUS_PAGES)
            .map(|i| format!("http://localhost/{i}"))
            .collect();
        assert!(pages(json!(too_many)).is_err());
    }

    #[test]
    fn metrics_pages_are_named_by_where_they_are() {
        for (url, name) in [
            ("http://localhost:9100/metrics", "localhost:9100"),
            (
                "https://app.example.com/metrics?format=text",
                "app.example.com",
            ),
            ("http://localhost:8080/app/metrics", "localhost:8080/app"),
            (
                "http://localhost:9115/probe?target=a",
                "localhost:9115/probe",
            ),
            ("http://[::1]:9100/", "[::1]:9100"),
        ] {
            assert_eq!(metrics_page_name(url), name);
        }
    }

    #[test]
    fn openmetrics_pages_have_different_names_and_plain_metric_names() {
        let settings = |settings: Value| with("openmetrics", settings).validate();
        settings(json!({
            "urls": ["http://localhost:9100/metrics", "http://localhost:9187/metrics"],
            "names": ["http_*", "process_cpu_seconds_total", "app:latency:p9?", "!go_*"]
        }))
        .unwrap();
        // The same page twice over, as far as its series' names go.
        let same = json!([
            "http://localhost:9100/metrics",
            "https://localhost:9100/metrics?x=1"
        ]);
        let error = settings(json!({ "urls": same.clone() })).unwrap_err();
        assert!(error.to_string().contains("both be called"), "{error}");
        // Only this collector names its pages.
        with("nginx", json!({ "urls": same })).validate().unwrap();
        for bad in [
            "http_requests{code=\"200\"}",
            "a b",
            "",
            "näme",
            "!",
            "!!go_*",
            "go_!",
        ] {
            assert!(settings(json!({ "names": [bad] })).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_status_page_collector_has_a_default_page() {
        for collector in ["apache", "nginx", "php_fpm"] {
            let page = default_status_page(collector).unwrap();
            check_status_page(page).unwrap();
        }
        assert_eq!(default_status_page("cpu"), None);
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
        // A series name with a line break in it would break charts and alerts.
        assert!(checks(json!([one("web\nprod")])).validate().is_err());
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
            ("tcp", "a:1", json!({ "interval_secs": 300 })),
            ("ping", "example.com", json!({ "interval_secs": 86_400 })),
            (
                "dns",
                "example.com",
                json!({ "server": "8.8.8.8", "record": "MX" }),
            ),
            ("dns", "example.com", json!({ "server": "10.0.0.1:5353" })),
            ("ping", "example.com", json!({ "count": 5 })),
            (
                "ping",
                "example.com",
                json!({ "count": 20, "timeout_secs": 21 }),
            ),
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
            ("http", url, json!({ "interval_secs": 0 })),
            ("http", url, json!({ "interval_secs": 86_401 })),
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
            // One ping a second never fits ten of them in the default ten seconds.
            ("ping", "example.com", json!({ "count": 10 })),
            (
                "ping",
                "example.com",
                json!({ "count": 5, "timeout_secs": 5 }),
            ),
        ] {
            assert!(
                option(kind, target, bad.clone()).validate().is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_heartbeat_has_no_target_and_is_never_an_agent_s() {
        let heartbeat = Check::new("backup", CheckKind::Heartbeat, "");
        heartbeat.validate().unwrap();
        let aimed = Check::new("backup", CheckKind::Heartbeat, "example.com:22");
        assert!(aimed.validate().is_err());
        let mut timed = heartbeat.clone();
        timed.timeout = Some(Duration::from_secs(5));
        assert!(timed.validate().is_err());

        let config: AgentConfig = serde_json::from_value(json!({
            "collectors": { "checks": { "checks": [
                { "name": "backup", "kind": "heartbeat", "target": "" },
            ] } },
        }))
        .unwrap();
        let refused = config.validate_sent().unwrap_err().to_string();
        assert!(refused.contains("heartbeat"), "{refused}");
    }

    #[test]
    fn check_kinds_read_back_as_written() {
        for kind in CheckKind::KNOWN {
            assert_eq!(CheckKind::parse(kind.as_str()), Some(kind));
            let text = serde_json::to_string(&kind).unwrap();
            assert_eq!(serde_json::from_str::<CheckKind>(&text).unwrap(), kind);
        }
        assert_eq!(CheckKind::parse("carrier-pigeon"), None);
        assert_eq!(CheckKind::parse("unknown"), None);
    }

    /// `parse` only finds what's in `KNOWN`, so a kind left out of it could never be
    /// saved or run.
    #[test]
    fn known_has_every_kind_but_unknown() {
        // Exhaustive, so a new kind doesn't compile until it's thought about here.
        let runs = |kind: CheckKind| match kind {
            CheckKind::Tcp
            | CheckKind::Http
            | CheckKind::Tls
            | CheckKind::Dns
            | CheckKind::Ping
            | CheckKind::Postgres
            | CheckKind::Mysql
            | CheckKind::Redis
            | CheckKind::Memcached
            | CheckKind::Mongodb
            | CheckKind::Clickhouse
            | CheckKind::Ssh
            | CheckKind::Smtp
            | CheckKind::Imap
            | CheckKind::Pop3
            | CheckKind::Ftp
            | CheckKind::Heartbeat => true,
            CheckKind::Unknown => false,
        };
        assert!(CheckKind::KNOWN.into_iter().all(runs));
        assert!(!runs(CheckKind::Unknown));
        let names: std::collections::BTreeSet<&str> =
            CheckKind::KNOWN.map(CheckKind::as_str).into();
        assert_eq!(names.len(), CheckKind::KNOWN.len(), "listed twice");
        // Unknown is the last variant, so every kind before it has to be listed.
        assert_eq!(CheckKind::Unknown as usize, CheckKind::KNOWN.len());
    }

    fn with_unknown_kind() -> AgentConfig {
        serde_json::from_value(json!({
            "collectors": {
                "checks": {
                    "checks": [
                        { "name": "directory", "kind": "ldap", "target": "ldap.example.com:389" },
                        { "name": "site", "kind": "http", "target": "https://example.com/" },
                    ],
                },
            },
        }))
        .unwrap()
    }

    /// A newer server can add a kind of check without older agents turning down
    /// every config it sends from then on.
    #[test]
    fn a_check_of_a_kind_from_a_newer_server_is_read_and_let_through_by_an_agent() {
        let config = with_unknown_kind();
        let checks = config.collectors["checks"].checks.as_ref().unwrap();
        assert_eq!(checks[0].kind, CheckKind::Unknown);
        assert_eq!(checks[1].kind, CheckKind::Http);
        config.validate_sent().unwrap();
    }

    #[test]
    fn a_server_never_saves_a_check_of_a_kind_it_does_not_know() {
        let error = with_unknown_kind().validate().unwrap_err().to_string();
        assert!(error.contains("\"directory\" needs a kind"), "{error}");
        assert!(error.contains("http, tcp"), "{error}");
    }

    #[test]
    fn a_check_of_an_unknown_kind_still_needs_a_name_that_can_be_a_series() {
        let config = check("ldap", "x");
        config.validate_sent().unwrap();
        let bad = serde_json::from_value::<AgentConfig>(json!({
            "collectors": { "checks": { "checks": [
                { "name": "a\nb", "kind": "ldap", "target": "x" },
            ] } },
        }))
        .unwrap();
        assert!(bad.validate_sent().is_err());
    }

    #[test]
    fn an_agent_leaves_out_collectors_it_does_not_know_and_says_which() {
        let mut config: AgentConfig = serde_json::from_value(json!({
            "collectors": { "cpu": {}, "zfs": { "pools": ["tank"] }, "ebpf": {} },
        }))
        .unwrap();
        // A server saving it would turn it down.
        assert!(config.validate().is_err());

        assert_eq!(config.remove_unknown_collectors(), ["ebpf", "zfs"]);
        assert_eq!(config.collectors.keys().collect::<Vec<_>>(), ["cpu"]);
        config.validate_sent().unwrap();
        assert!(config.remove_unknown_collectors().is_empty());
    }

    /// Both are sent inside a config, so a field a newer server adds to either
    /// mustn't turn the whole of it down.
    #[test]
    fn local_checks_and_databases_take_fields_from_a_newer_server() {
        let config: AgentConfig = serde_json::from_value(json!({
            "collectors": {
                "checks": { "local_checks": [{ "name": "db", "retries": 3 }] },
                "databases": { "databases": [{ "name": "orders", "sample_rate": 0.5 }] },
            },
        }))
        .unwrap();
        config.validate_sent().unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn a_hello_and_challenge_carry_the_protocol() {
        let hello = AgentMessage::Hello {
            hostname: "web-1".to_string(),
            public_key: "ab".to_string(),
            signature: "cd".to_string(),
            token: None,
            protocol: 1,
            agent_version: "0.1.0".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&hello).unwrap(),
            json!({
                "type": "hello", "hostname": "web-1", "public_key": "ab", "signature": "cd",
                "protocol": 1, "agent_version": "0.1.0",
            })
        );
        let challenge = ServerMessage::Challenge {
            nonce: "n".to_string(),
            protocols: Protocols {
                oldest: 1,
                newest: 2,
            },
        };
        assert_eq!(
            serde_json::to_value(&challenge).unwrap(),
            json!({ "type": "challenge", "nonce": "n", "protocols": { "oldest": 1, "newest": 2 } })
        );
    }

    #[test]
    fn a_server_takes_the_protocols_from_its_oldest_to_its_newest() {
        let protocols = Protocols {
            oldest: 2,
            newest: 3,
        };
        assert_eq!(protocols.fit(1), ProtocolFit::TooOld);
        assert_eq!(protocols.fit(2), ProtocolFit::Supported);
        assert_eq!(protocols.fit(3), ProtocolFit::Supported);
        assert_eq!(protocols.fit(4), ProtocolFit::TooNew);
        assert_eq!(protocols.describe(), "protocols 2 to 3");
        assert_eq!(Protocols::SUPPORTED.describe(), "protocol 1");
        assert_eq!(
            Protocols::SUPPORTED.fit(PROTOCOL_VERSION),
            ProtocolFit::Supported
        );
    }

    #[test]
    fn messages_from_a_newer_side_are_read_as_unknown() {
        let server: ServerMessage =
            serde_json::from_value(json!({ "type": "reboot_soon", "at": "later" })).unwrap();
        assert_eq!(server, ServerMessage::Unknown);
        let agent: AgentMessage =
            serde_json::from_value(json!({ "type": "logs", "lines": ["a"] })).unwrap();
        assert_eq!(agent, AgentMessage::Unknown);
        let status: ServerMessage =
            serde_json::from_value(json!({ "type": "registration", "status": "quarantined" }))
                .unwrap();
        assert_eq!(
            status,
            ServerMessage::Registration {
                status: RegistrationStatus::Unknown
            }
        );
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

        assert_eq!(config.facts_interval, Duration::from_secs(3600));
        assert!(config.collectors["cpu"].enabled);
        assert_eq!(config.collectors["cpu"].mount_points, None);
    }

    #[test]
    fn a_config_rejects_unusable_values() {
        let mut bad = config();
        bad.interval = Duration::ZERO;
        assert!(bad.validate().is_err());

        let mut bad = config();
        bad.facts_interval = Duration::ZERO;
        assert!(bad.validate().is_err());

        let mut bad = config();
        let cpu = bad.collectors["cpu"].clone();
        bad.collectors.insert("nope".to_string(), cpu);
        assert!(bad.validate().is_err());

        assert!(config().validate().is_ok());
    }

    #[test]
    fn the_version_changes_with_the_config() {
        let mut changed = config();
        changed.interval = Duration::from_secs(31);

        assert_eq!(config().version().unwrap(), config().version().unwrap());
        assert_ne!(config().version().unwrap(), changed.version().unwrap());
    }

    #[test]
    fn agent_messages_survive_a_json_round_trip() {
        let messages = [
            AgentMessage::Hello {
                hostname: "web-1".to_string(),
                public_key: "ab".to_string(),
                signature: "cd".to_string(),
                token: Some("secret".to_string()),
                protocol: PROTOCOL_VERSION,
                agent_version: "1.2.3".to_string(),
            },
            AgentMessage::Sample(Sample {
                time: DateTime::from_timestamp_millis(1_789_000_000_123).unwrap(),
                metrics: BTreeMap::from([("memory".to_string(), json!({ "total": 1 }))]),
            }),
            AgentMessage::Facts {
                facts: json!({ "os": { "family": "linux" } }),
            },
            AgentMessage::ConfigResult {
                version: "abc".to_string(),
                error: Some("nope".to_string()),
                skipped_collectors: vec!["zfs".to_string()],
            },
            AgentMessage::Time {
                nonce: "ab".to_string(),
                answered_at: DateTime::from_timestamp_millis(1_789_000_000_000).unwrap(),
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
    fn a_build_describes_itself_for_the_version_command() {
        let build = BuildInfo::new(
            "1.2.3",
            "abc123",
            "false",
            "2026-11-04T10:00:00Z",
            "1.100.0",
        );

        let text = build.describe("maxnines-agent");

        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        assert_eq!(
            text,
            format!(
                "maxnines-agent 1.2.3\ncommit:   abc123\nbuilt:    2026-11-04T10:00:00Z\nrust:     1.100.0\nplatform: {platform}"
            )
        );
    }

    #[test]
    fn a_build_with_uncommitted_changes_says_so() {
        let build = BuildInfo::new("1.2.3", "abc123", "true", "2026-11-04", "1.100.0");

        assert_eq!(build.commit, "abc123-dirty");
    }

    #[test]
    fn a_clean_build_is_just_its_commit() {
        let build = BuildInfo::new("1.2.3", "abc123", "false", "2026-11-04", "1.100.0");

        assert_eq!(build.commit, "abc123");
    }

    #[test]
    fn a_build_without_git_history_is_unknown_and_not_a_placeholder() {
        let build = BuildInfo::new(
            "1.2.3",
            NO_BUILD_VALUE,
            NO_BUILD_VALUE,
            "2026-11-04",
            NO_BUILD_VALUE,
        );

        assert_eq!(build.commit, "unknown");
        assert_eq!(build.built_at, None);
        assert_eq!(build.rust_version, "unknown");
        let built = BuildInfo::new("1.2.3", "abc", "false", "2026-11-04T10:00:00.5Z", "1.0.0");
        assert_eq!(
            built.built_at,
            Some("2026-11-04T10:00:00.5Z".parse().unwrap())
        );
    }

    #[test]
    fn server_messages_survive_a_json_round_trip() {
        let messages = [
            ServerMessage::Challenge {
                nonce: "ab".to_string(),
                protocols: Protocols::SUPPORTED,
            },
            ServerMessage::Registration {
                status: RegistrationStatus::Pending,
            },
            ServerMessage::Refused {
                reason: "Upgrade the agent.".to_string(),
            },
            ServerMessage::Config {
                version: "abc".to_string(),
                config: config(),
            },
            ServerMessage::RunAction {
                id: "1".to_string(),
                action: "restart".to_string(),
                variables: BTreeMap::new(),
                timeout: Duration::from_secs(30),
            },
            ServerMessage::Ack {
                time: DateTime::from_timestamp_millis(1_789_000_000_123).unwrap(),
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
