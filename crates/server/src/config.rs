use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use ipnet::IpNet;
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
    /// Holds the token that protects the admin endpoints.
    #[serde(default = "default_admin_token_file")]
    pub admin_token_file: PathBuf,
    /// How often to ping each agent.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// How long an agent can stay silent before it counts as offline.
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    /// Where samples are saved.
    pub metrics: MetricsConfig,
    /// Where everything else is saved, such as registered agents.
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
}

/// One variant per database, selected by the `metrics "<name>"` block label.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum MetricsConfig {
    Duckdb {
        path: PathBuf,
        /// How much memory DuckDB may use, such as "1GB" or "512MB".
        #[serde(default = "default_duckdb_memory_limit")]
        memory_limit: String,
    },
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

fn default_admin_token_file() -> PathBuf {
    PathBuf::from("admin.token")
}

fn default_heartbeat_interval_secs() -> u64 {
    5
}

fn default_heartbeat_timeout_secs() -> u64 {
    15
}

fn default_duckdb_memory_limit() -> String {
    "1GB".to_string()
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
        let config: Config = hcl::from_str(text)?;
        ensure!(
            config.heartbeat_interval_secs > 0,
            "heartbeat_interval_secs must be at least 1"
        );
        ensure!(
            config.heartbeat_timeout_secs > config.heartbeat_interval_secs,
            "heartbeat_timeout_secs must be longer than heartbeat_interval_secs"
        );
        config.trusted_networks()?;
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
mod tests {
    use super::*;

    const STORAGE: &str = "metrics \"duckdb\" {\n  path = \"x\"\n}\n";

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text)
    }

    fn with_registration(body: &str) -> Result<Config> {
        parse(&format!("{STORAGE}registration {{\n{body}\n}}\n"))
    }

    #[test]
    fn shipped_config_parses() {
        let config = parse(include_str!("../config/server.hcl")).unwrap();
        assert_eq!(
            config.metrics,
            MetricsConfig::Duckdb {
                path: "data.nosync/maxnines.duckdb".into(),
                memory_limit: "1GB".to_string(),
            }
        );
        assert_eq!(config.audience(), "ws://127.0.0.1:9000/ws");
        assert_eq!(config.registration.max_pending, 1000);
        assert!(config.registration.rule.is_empty());
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
    fn memory_limit_defaults_to_1gb() {
        assert_eq!(
            parse(STORAGE).unwrap().metrics,
            MetricsConfig::Duckdb {
                path: "x".into(),
                memory_limit: "1GB".to_string(),
            }
        );
    }

    #[test]
    fn memory_limit_can_be_set() {
        let text = "metrics \"duckdb\" {\n  path = \"x\"\n  memory_limit = \"256MB\"\n}\n";
        assert_eq!(
            parse(text).unwrap().metrics,
            MetricsConfig::Duckdb {
                path: "x".into(),
                memory_limit: "256MB".to_string(),
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
