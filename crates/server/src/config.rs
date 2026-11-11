use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use indexmap::IndexMap;
use ipnet::IpNet;
use maxnines_protocol::{AGENT_SILENCE_LIMIT_SECS, hcl_env::config_context};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to accept connections on.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The address agents connect to. Defaults to this server's own address.
    pub public_url: Option<String>,
    /// Proxies whose `X-Forwarded-For` header can be believed.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// How often to ping each agent.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// How long an agent can stay silent before it counts as offline.
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    /// Where samples are saved.
    pub metrics: MetricsConfig,
    /// How long samples are kept, at full resolution and rolled up.
    #[serde(default)]
    pub retention: RetentionConfig,
    /// Where everything else is saved, such as registered agents.
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
    /// Serves HTTPS. Leave it out behind a proxy, or on a trusted network.
    pub tls: Option<TlsConfig>,
}

/// Where a certificate comes from: files, or an ACME service.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// Who signed a private certificate, for this server's own command line tools.
    /// A certificate from a public authority doesn't need it.
    pub ca_file: Option<PathBuf>,
    pub acme: Option<AcmeSettings>,
}

/// Getting certificates automatically, from Let's Encrypt unless told otherwise.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSettings {
    pub domains: Vec<String>,
    /// Who the service can contact about the certificates.
    pub email: Option<String>,
    /// Keeps the certificate and account key. It has to survive restarts, because
    /// services limit how many certificates can be issued.
    pub cache_dir: PathBuf,
    #[serde(default = "default_acme_directory")]
    pub directory: String,
    /// Who to trust for a private ACME service.
    pub ca_file: Option<PathBuf>,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

impl TlsConfig {
    fn validate(&self) -> Result<()> {
        let files = self.certificate_file.is_some() || self.key_file.is_some();
        ensure!(
            self.certificate_file.is_some() == self.key_file.is_some(),
            "set both certificate_file and key_file"
        );
        match &self.acme {
            Some(acme) => {
                ensure!(!files, "use certificate files or acme, not both");
                ensure!(!acme.domains.is_empty(), "acme needs at least one domain");
            }
            None => ensure!(files, "set certificate_file and key_file, or an acme block"),
        }
        Ok(())
    }
}

/// One variant per database, selected by the `metrics "<name>"` block label.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum MetricsConfig {
    Duckdb {
        path: PathBuf,
        /// How much memory DuckDB may use, such as "1GiB" or "512MB".
        #[serde(default = "default_duckdb_memory_limit")]
        memory_limit: String,
    },
    /// For bigger fleets. Takes a server of its own.
    Clickhouse {
        /// Such as "http://127.0.0.1:8123".
        url: String,
        #[serde(default = "default_clickhouse_database")]
        database: String,
        #[serde(default)]
        user: Option<String>,
        /// A file holding the password, so it stays out of the config.
        #[serde(default)]
        password_file: Option<PathBuf>,
    },
}

fn default_clickhouse_database() -> String {
    "maxnines".to_string()
}

impl MetricsConfig {
    /// Where the metrics are kept, if it's on this machine.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Duckdb { path, .. } => Some(path),
            Self::Clickhouse { .. } => None,
        }
    }
}

/// How long metrics are kept, in days. Every sample is kept at full resolution for a
/// while, and each 5 minutes and each hour for longer, as the lowest, highest and average
/// value. That's what long charts read, so a spike still shows once the samples are
/// gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default = "default_full_resolution_days")]
    pub full_resolution_days: u32,
    #[serde(default = "default_five_minute_days")]
    pub five_minute_days: u32,
    /// Left out, hours are kept for good.
    #[serde(default)]
    pub hour_days: Option<u32>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            full_resolution_days: default_full_resolution_days(),
            five_minute_days: default_five_minute_days(),
            hour_days: None,
        }
    }
}

/// Alerts look back up to a day at full resolution, and an hour is only rolled up
/// once it's over, so less than this would leave them short.
pub const MIN_FULL_RESOLUTION_DAYS: u32 = 2;

fn default_full_resolution_days() -> u32 {
    30
}

fn default_five_minute_days() -> u32 {
    365
}

/// A century, which is far more than anything needs and keeps times in range.
const MAX_RETENTION_DAYS: u32 = 36_500;

impl RetentionConfig {
    fn validate(&self) -> Result<()> {
        let longest = [self.full_resolution_days, self.five_minute_days]
            .into_iter()
            .chain(self.hour_days)
            .max()
            .unwrap_or(0);
        ensure!(
            longest <= MAX_RETENTION_DAYS,
            "retention can be at most {MAX_RETENTION_DAYS} days; leave hour_days out to keep \
             hours for good"
        );
        ensure!(
            self.full_resolution_days >= MIN_FULL_RESOLUTION_DAYS,
            "full_resolution_days must be at least {MIN_FULL_RESOLUTION_DAYS}, as alerts look \
             back up to a day"
        );
        ensure!(
            self.five_minute_days >= self.full_resolution_days,
            "five_minute_days can't be shorter than full_resolution_days"
        );
        if let Some(hours) = self.hour_days {
            ensure!(
                hours >= self.five_minute_days,
                "hour_days can't be shorter than five_minute_days"
            );
        }
        Ok(())
    }
}

/// SQLite, Postgres or MySQL, chosen by the URL. A URL can hold a password, so
/// it can come from a file instead of the config.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: Option<String>,
    pub url_file: Option<PathBuf>,
}

impl DatabaseConfig {
    pub fn resolve_url(&self) -> Result<String> {
        match (&self.url, &self.url_file) {
            (Some(url), None) => Ok(url.clone()),
            (None, Some(path)) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading database url {}", path.display()))?;
                let url = text.trim();
                ensure!(!url.is_empty(), "database url {} is empty", path.display());
                Ok(url.to_string())
            }
            (None, None) => Ok("sqlite://maxnines.sqlite?mode=rwc".to_string()),
            (Some(_), Some(_)) => bail!("set either url or url_file in the database block"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationConfig {
    /// How many agents can wait for approval at once. This stops anyone who
    /// can reach the server from filling the database with requests.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    /// `rule "<name>" { ... }` blocks, in the order they are checked.
    #[serde(default)]
    pub rule: IndexMap<String, RuleConfig>,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            max_pending: default_max_pending(),
            rule: IndexMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub action: RuleAction,
    /// Matches agents connecting from these addresses or CIDRs.
    #[serde(default)]
    pub source_cidrs: Vec<String>,
    /// Matches the reported hostname, with `*` and `?` wildcards.
    pub hostname: Option<String>,
    /// Matches agents presenting the token in this file.
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Approve,
    Reject,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9000))
}

fn default_heartbeat_interval_secs() -> u64 {
    5
}

fn default_heartbeat_timeout_secs() -> u64 {
    15
}

fn default_duckdb_memory_limit() -> String {
    "1GiB".to_string()
}

fn default_max_pending() -> usize {
    1000
}

/// Accepts a CIDR or a single address.
pub fn parse_network(text: &str) -> Result<IpNet> {
    text.parse::<IpNet>()
        .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
        .with_context(|| format!("invalid address or CIDR {text:?}"))
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Config = hcl::eval::from_str(text, &config_context())?;
        ensure!(
            config.heartbeat_interval_secs > 0,
            "heartbeat_interval_secs must be at least 1"
        );
        ensure!(
            config.heartbeat_timeout_secs > config.heartbeat_interval_secs,
            "heartbeat_timeout_secs must be longer than heartbeat_interval_secs"
        );
        // Agents reconnect after this long without a word, so one heartbeat
        // arriving late mustn't be enough to cause that.
        let longest_interval = AGENT_SILENCE_LIMIT_SECS / 2;
        ensure!(
            config.heartbeat_interval_secs <= longest_interval,
            "heartbeat_interval_secs can be at most {longest_interval}, as agents give up \
             after {AGENT_SILENCE_LIMIT_SECS} seconds without hearing from the server"
        );
        config.trusted_networks()?;
        config.retention.validate().context("retention block")?;
        if let Some(tls) = &config.tls {
            tls.validate().context("tls block")?;
            ensure!(
                config.audience().starts_with("wss://"),
                "with a tls block, public_url has to start with wss://"
            );
        }
        for (name, rule) in &config.registration.rule {
            rule.validate().with_context(|| format!("rule {name:?}"))?;
        }
        Ok(config)
    }

    pub fn trusted_networks(&self) -> Result<Vec<IpNet>> {
        self.trusted_proxies
            .iter()
            .map(|text| parse_network(text))
            .collect()
    }

    pub fn audience(&self) -> String {
        self.public_url
            .clone()
            .unwrap_or_else(|| format!("ws://{}/ws", self.listen))
    }
}

impl RuleConfig {
    fn validate(&self) -> Result<()> {
        for text in &self.source_cidrs {
            parse_network(text)?;
        }
        // The hostname is whatever the agent says it is, so it proves nothing.
        if self.action == RuleAction::Approve
            && self.source_cidrs.is_empty()
            && self.token_file.is_none()
        {
            bail!("an approve rule needs source_cidrs or token_file");
        }
        Ok(())
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    const METRICS: &str = "metrics \"duckdb\" {\n  path = \"x\"\n}\n";

    fn parse_with(line: &str) -> Result<Config> {
        Config::parse(&format!("{line}\n{METRICS}"))
    }

    fn set_variable() -> (&'static str, String) {
        ("PATH", std::env::var("PATH").unwrap())
    }

    #[test]
    fn a_setting_can_come_from_the_environment() {
        let (name, value) = set_variable();
        let config = parse_with(&format!("public_url = env(\"{name}\")")).unwrap();
        assert_eq!(config.public_url, Some(value));
    }

    #[test]
    fn a_variable_can_be_part_of_a_longer_value() {
        let (name, value) = set_variable();
        let line = format!("database {{\n  url = \"x://${{env(\"{name}\")}}/y\"\n}}");
        let config = parse_with(&line).unwrap();
        assert_eq!(config.database.url, Some(format!("x://{value}/y")));
    }

    #[test]
    fn a_default_covers_an_unset_variable() {
        let line = "public_url = env(\"MAXNINES_TEST_UNSET\", \"ws://fallback/ws\")";
        let config = parse_with(line).unwrap();
        assert_eq!(config.public_url.as_deref(), Some("ws://fallback/ws"));
    }

    #[test]
    fn a_set_variable_beats_its_default() {
        let (name, value) = set_variable();
        let config = parse_with(&format!("public_url = env(\"{name}\", \"unused\")")).unwrap();
        assert_eq!(config.public_url, Some(value));
    }

    #[test]
    fn an_unset_variable_stops_the_server_and_says_which() {
        let error = parse_with("public_url = env(\"MAXNINES_TEST_UNSET\")").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("MAXNINES_TEST_UNSET"), "{message}");
    }

    #[test]
    fn labelled_blocks_still_work_when_values_are_evaluated() {
        let line = "registration {\n  rule \"a\" {\n    action = \"reject\"\n    \
                    source_cidrs = [env(\"MAXNINES_TEST_UNSET\", \"10.0.0.0/8\")]\n  }\n}";
        let config = parse_with(line).unwrap();
        assert_eq!(config.registration.rule["a"].source_cidrs, ["10.0.0.0/8"]);
    }
}

#[cfg(test)]
mod tls_config {
    use super::*;

    fn parsed(tls: &str, public_url: &str) -> Result<Config> {
        Config::parse(&format!(
            "public_url = \"{public_url}\"\n{tls}\nmetrics \"duckdb\" {{\n  path = \"x\"\n}}\n"
        ))
    }

    const FILES: &str = r#"tls {
      certificate_file = "a.crt"
      key_file = "a.key"
    }"#;

    const ACME: &str = r#"tls {
      acme {
        domains = ["maxnines.example.com"]
        email = "you@example.com"
        cache_dir = "acme"
      }
    }"#;

    #[test]
    fn https_is_off_unless_asked_for() {
        assert!(parsed("", "ws://x/ws").unwrap().tls.is_none());
    }

    #[test]
    fn certificate_files_can_be_used() {
        let config = parsed(FILES, "wss://x/ws").unwrap();
        assert!(config.tls.unwrap().certificate_file.is_some());
    }

    #[test]
    fn acme_uses_lets_encrypt_unless_told_otherwise() {
        let config = parsed(ACME, "wss://x/ws").unwrap();
        let acme = config.tls.unwrap().acme.unwrap();
        assert!(acme.directory.contains("letsencrypt.org"));
    }

    #[test]
    fn half_a_certificate_is_refused() {
        let tls = r#"tls {
          certificate_file = "a.crt"
        }"#;
        assert!(parsed(tls, "wss://x/ws").is_err());
    }

    #[test]
    fn a_tls_block_has_to_say_something() {
        assert!(parsed("tls {}", "wss://x/ws").is_err());
    }

    #[test]
    fn files_and_acme_can_not_both_be_used() {
        let tls = r#"tls {
          certificate_file = "a.crt"
          key_file = "a.key"
          acme {
            domains = ["x"]
            cache_dir = "acme"
          }
        }"#;
        assert!(parsed(tls, "wss://x/ws").is_err());
    }

    #[test]
    fn acme_needs_a_domain() {
        let tls = r#"tls {
          acme {
            domains = []
            cache_dir = "acme"
          }
        }"#;
        assert!(parsed(tls, "wss://x/ws").is_err());
    }

    #[test]
    fn a_private_authority_can_be_named() {
        let tls = r#"tls {
          certificate_file = "a.crt"
          key_file = "a.key"
          ca_file = "ca.pem"
        }"#;
        let config = parsed(tls, "wss://x/ws").unwrap();
        assert!(config.tls.unwrap().ca_file.is_some());
    }

    #[test]
    fn agents_have_to_be_told_to_use_it() {
        let error = parsed(FILES, "ws://x/ws").unwrap_err();
        assert!(format!("{error:#}").contains("wss://"), "{error:#}");
    }
}

#[cfg(test)]
mod clickhouse_config {
    use super::*;

    #[test]
    fn clickhouse_can_be_chosen_with_only_a_url() {
        let text = r#"
            metrics "clickhouse" {
              url = "http://127.0.0.1:8123"
            }
        "#;
        let config = Config::parse(text).unwrap();
        assert_eq!(config.metrics.path(), None);
        assert_eq!(
            config.metrics,
            MetricsConfig::Clickhouse {
                url: "http://127.0.0.1:8123".to_string(),
                database: "maxnines".to_string(),
                user: None,
                password_file: None,
            }
        );
    }

    #[test]
    fn clickhouse_can_have_its_own_database_and_login() {
        let text = r#"
            metrics "clickhouse" {
              url           = "https://clickhouse.internal:8443"
              database      = "metrics"
              user          = "maxnines"
              password_file = "/etc/maxnines/clickhouse.password"
            }
        "#;
        let config = Config::parse(text).unwrap();
        assert!(matches!(
            config.metrics,
            MetricsConfig::Clickhouse { ref database, .. } if database == "metrics"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORAGE: &str = "metrics \"duckdb\" {\n  path = \"x\"\n}\n";

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text)
    }

    fn with_registration(body: &str) -> Result<Config> {
        parse(&format!("{STORAGE}registration {{\n{body}\n}}\n"))
    }

    fn with_retention(body: &str) -> Result<RetentionConfig> {
        parse(&format!("{STORAGE}retention {{\n{body}\n}}\n")).map(|config| config.retention)
    }

    #[test]
    fn retention_defaults_to_a_month_a_year_and_for_good() {
        let config = parse(STORAGE).unwrap();
        assert_eq!(
            config.retention,
            RetentionConfig {
                full_resolution_days: 30,
                five_minute_days: 365,
                hour_days: None,
            }
        );
    }

    #[test]
    fn each_resolution_can_be_kept_longer() {
        let retention =
            with_retention("full_resolution_days = 90\nfive_minute_days = 400\nhour_days = 3650")
                .unwrap();
        assert_eq!(retention.full_resolution_days, 90);
        assert_eq!(retention.five_minute_days, 400);
        assert_eq!(retention.hour_days, Some(3650));
    }

    #[test]
    fn full_resolution_has_to_cover_what_alerts_look_back_on() {
        let error = with_retention("full_resolution_days = 1").unwrap_err();
        assert!(format!("{error:#}").contains("at least 2"), "{error:#}");
        assert!(with_retention("full_resolution_days = 2").is_ok());
    }

    #[test]
    fn a_coarser_resolution_is_never_kept_for_less_time() {
        assert!(with_retention("full_resolution_days = 400").is_err());
        assert!(with_retention("five_minute_days = 30\nhour_days = 20").is_err());
        assert!(with_retention("full_resolution_days = 365").is_ok());
    }

    #[test]
    fn retention_beyond_a_century_is_refused() {
        assert!(with_retention("hour_days = 40000").is_err());
        assert!(with_retention("hour_days = 36500").is_ok());
    }

    #[test]
    fn an_unknown_retention_setting_is_refused() {
        assert!(with_retention("raw_days = 5").is_err());
    }

    #[test]
    fn shipped_config_parses() {
        let config = parse(include_str!("../config/server.hcl")).unwrap();
        assert_eq!(
            config.metrics,
            MetricsConfig::Duckdb {
                path: "data.nosync/maxnines.duckdb".into(),
                memory_limit: "1GiB".to_string(),
            }
        );
        assert_eq!(config.audience(), "ws://127.0.0.1:9000/ws");
        assert_eq!(config.registration.max_pending, 1000);
        assert!(config.registration.rule.is_empty());
    }

    /// What the Linux packages install, which keeps everything in the service's
    /// own folder.
    #[test]
    fn packaged_config_parses() {
        let config = parse(include_str!("../../../packaging/linux/server.hcl")).unwrap();
        assert_eq!(
            config.metrics,
            MetricsConfig::Duckdb {
                path: "/var/lib/maxnines-server/metrics.duckdb".into(),
                memory_limit: "1GiB".to_string(),
            }
        );
        assert_eq!(
            config.database.url.as_deref(),
            Some("sqlite:///var/lib/maxnines-server/maxnines.sqlite?mode=rwc")
        );
        assert_eq!(config.audience(), "ws://127.0.0.1:9000/ws");
    }

    /// What the Docker image runs, which listens on every address in the container
    /// unless told otherwise.
    #[test]
    fn container_config_parses() {
        let config = parse(include_str!("../../../packaging/docker/server.hcl")).unwrap();
        assert_eq!(config.listen.to_string(), "0.0.0.0:9000");
        assert_eq!(config.audience(), "ws://localhost:9000/ws");
        assert_eq!(
            config.metrics,
            MetricsConfig::Duckdb {
                path: "/var/lib/maxnines-server/metrics.duckdb".into(),
                memory_limit: "1GiB".to_string(),
            }
        );
    }

    #[test]
    fn server_settings_have_defaults() {
        let config = parse(STORAGE).unwrap();
        assert_eq!(config.listen.to_string(), "127.0.0.1:9000");
        assert_eq!(config.audience(), "ws://127.0.0.1:9000/ws");
        assert_eq!(config.heartbeat_interval_secs, 5);
        assert_eq!(config.heartbeat_timeout_secs, 15);
    }

    #[test]
    fn server_settings_can_be_set() {
        let text = format!(
            "listen = \"0.0.0.0:8000\"\npublic_url = \"wss://m.example.com/ws\"\n\
             trusted_proxies = [\"10.0.0.5\", \"10.1.0.0/16\"]\n\
             heartbeat_interval_secs = 2\nheartbeat_timeout_secs = 6\n{STORAGE}"
        );
        let config = parse(&text).unwrap();
        assert_eq!(config.listen.to_string(), "0.0.0.0:8000");
        assert_eq!(config.audience(), "wss://m.example.com/ws");
        assert_eq!(config.trusted_networks().unwrap().len(), 2);
        assert_eq!(config.heartbeat_interval_secs, 2);
        assert_eq!(config.heartbeat_timeout_secs, 6);
    }

    #[test]
    fn rejects_unusable_heartbeat_settings() {
        assert!(parse(&format!("heartbeat_interval_secs = 0\n{STORAGE}")).is_err());
        assert!(parse(&format!("heartbeat_timeout_secs = 5\n{STORAGE}")).is_err());
        let slow = "heartbeat_interval_secs = 16\nheartbeat_timeout_secs = 40\n";
        let error = parse(&format!("{slow}{STORAGE}")).unwrap_err().to_string();
        assert!(error.contains("at most 15"), "{error}");
        let slowest = "heartbeat_interval_secs = 15\nheartbeat_timeout_secs = 40\n";
        parse(&format!("{slowest}{STORAGE}")).unwrap();
    }

    #[test]
    fn rejects_an_invalid_listen_address() {
        assert!(parse(&format!("listen = \"not an address\"\n{STORAGE}")).is_err());
    }

    #[test]
    fn rejects_an_invalid_trusted_proxy() {
        assert!(parse(&format!("trusted_proxies = [\"nope\"]\n{STORAGE}")).is_err());
    }

    #[test]
    fn memory_limit_defaults_to_1gib() {
        assert_eq!(
            parse(STORAGE).unwrap().metrics,
            MetricsConfig::Duckdb {
                path: "x".into(),
                memory_limit: "1GiB".to_string(),
            }
        );
    }

    #[test]
    fn memory_limit_can_be_set() {
        let text = "metrics \"duckdb\" {\n  path = \"x\"\n  memory_limit = \"256MiB\"\n}\n";
        assert_eq!(
            parse(text).unwrap().metrics,
            MetricsConfig::Duckdb {
                path: "x".into(),
                memory_limit: "256MiB".to_string(),
            }
        );
    }

    #[test]
    fn requires_a_metrics_block() {
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_unknown_databases() {
        assert!(parse("metrics \"oracle\" {\n  path = \"x\"\n}\n").is_err());
    }

    #[test]
    fn rejects_unknown_settings() {
        assert!(parse("metrics \"duckdb\" {\n  path = \"x\"\n  pth = \"y\"\n}\n").is_err());
        assert!(parse(&format!("admin_listen = \"x\"\n{STORAGE}")).is_err());
    }

    #[test]
    fn rejects_more_than_one_metrics_block() {
        let text =
            "metrics \"duckdb\" {\n  path = \"a\"\n}\nmetrics \"duckdb\" {\n  path = \"b\"\n}\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn the_database_defaults_to_a_local_sqlite_file() {
        let url = parse(STORAGE).unwrap().database.resolve_url().unwrap();
        assert_eq!(url, "sqlite://maxnines.sqlite?mode=rwc");
    }

    #[test]
    fn the_database_url_can_be_set() {
        let text = format!("{STORAGE}database {{\n  url = \"postgres://h/db\"\n}}\n");
        let url = parse(&text).unwrap().database.resolve_url().unwrap();
        assert_eq!(url, "postgres://h/db");
    }

    #[test]
    fn the_database_url_can_come_from_a_file() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("url");
        std::fs::write(&path, "mysql://user:secret@h/db\n").unwrap();

        let config = DatabaseConfig {
            url: None,
            url_file: Some(path),
        };

        assert_eq!(config.resolve_url().unwrap(), "mysql://user:secret@h/db");
    }

    #[test]
    fn the_database_url_can_not_be_set_twice() {
        let config = DatabaseConfig {
            url: Some("sqlite::memory:".to_string()),
            url_file: Some("x".into()),
        };
        assert!(config.resolve_url().is_err());
    }

    #[test]
    fn rules_keep_the_order_they_are_written_in() {
        let config = with_registration(
            r#"
            rule "zebra" {
              action = "reject"
            }
            rule "apple" {
              action       = "approve"
              source_cidrs = ["10.0.0.0/8"]
            }
            rule "mango" {
              action = "reject"
            }
            "#,
        )
        .unwrap();

        let names: Vec<&str> = config
            .registration
            .rule
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names, ["zebra", "apple", "mango"]);
    }

    #[test]
    fn an_approve_rule_needs_more_than_a_hostname() {
        let error = with_registration(
            r#"
            rule "unsafe" {
              action   = "approve"
              hostname = "web-*"
            }
            "#,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("needs source_cidrs or token_file"));
    }

    #[test]
    fn a_reject_rule_can_use_just_a_hostname() {
        let text = "rule \"r\" {\n  action = \"reject\"\n  hostname = \"bad-*\"\n}\n";
        assert!(with_registration(text).is_ok());
    }

    #[test]
    fn rejects_an_invalid_cidr_in_a_rule() {
        let text = "rule \"r\" {\n  action = \"reject\"\n  source_cidrs = [\"nope\"]\n}\n";
        assert!(with_registration(text).is_err());
    }

    #[test]
    fn rejects_an_unknown_rule_action() {
        let text = "rule \"r\" {\n  action = \"maybe\"\n}\n";
        assert!(with_registration(text).is_err());
    }
}
