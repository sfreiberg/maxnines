//! What can be adjusted about a test.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::Parser;
use humantime::{format_duration, parse_duration};
use serde::Serialize;

/// Simulates a fleet of agents against a MaxNines server and reports how it held up.
///
/// Run it against a test server: simulated agents are approved and their samples are
/// saved like any others. Make a key with `maxnines-server api-keys create`.
#[derive(Parser)]
#[command(version)]
pub struct Options {
    /// The server's agent address, as in an agent's config
    #[arg(long, value_name = "URL", help_heading = "Server")]
    pub url: String,

    /// Where to reach the API and pages [default: worked out from --url]
    #[arg(long, value_name = "URL", help_heading = "Server")]
    pub admin_url: Option<String>,

    /// A key for the server's API
    #[arg(
        long,
        env = "MAXNINES_API_KEY",
        hide_env_values = true,
        value_name = "KEY",
        help_heading = "Server"
    )]
    pub api_key: String,

    /// Allow a server that isn't on this host
    #[arg(long, help_heading = "Server")]
    pub yes: bool,

    /// How many agents to simulate
    #[arg(long, default_value_t = 1000, help_heading = "Load")]
    pub agents: usize,

    /// How long to run, after the agents start connecting
    #[arg(long, default_value = "5m", value_parser = parse_duration, help_heading = "Load")]
    pub duration: Duration,

    /// How often each agent sends a sample
    #[arg(long, default_value = "15s", value_parser = parse_duration, help_heading = "Load")]
    pub interval: Duration,

    /// How long to spread agents connecting over. 0s connects them all at once
    #[arg(long, default_value = "30s", value_parser = parse_duration, help_heading = "Load")]
    pub ramp: Duration,

    /// Percent of agents that drop and reconnect each minute
    #[arg(
        long,
        default_value_t = 0.0,
        value_name = "PERCENT",
        help_heading = "Load"
    )]
    pub churn: f64,

    /// Saved samples each agent starts with, as if after an outage
    #[arg(
        long,
        default_value_t = 0,
        value_name = "SAMPLES",
        help_heading = "Load"
    )]
    pub backlog: usize,

    /// The time between an agent's saved samples
    #[arg(long, default_value = "1s", value_parser = parse_duration, help_heading = "Load")]
    pub backlog_gap: Duration,

    /// CPU cores per agent, which adds to the size of each sample
    #[arg(long, default_value_t = 8, help_heading = "Sample size")]
    pub cores: usize,

    /// Disks per agent
    #[arg(long, default_value_t = 2, help_heading = "Sample size")]
    pub disks: usize,

    /// Network interfaces per agent
    #[arg(long, default_value_t = 3, help_heading = "Sample size")]
    pub interfaces: usize,

    /// How often each agent reports its facts
    #[arg(long, default_value = "1h", value_parser = parse_duration, help_heading = "Facts and alerts")]
    pub facts_every: Duration,

    /// Percent of agents whose facts have changed at each report
    #[arg(
        long,
        default_value_t = 0.0,
        value_name = "PERCENT",
        help_heading = "Facts and alerts"
    )]
    pub fact_changes: f64,

    /// Percent of agents reporting 99% CPU, to set off any alert rules you've made
    #[arg(
        long,
        default_value_t = 0.0,
        value_name = "PERCENT",
        help_heading = "Facts and alerts"
    )]
    pub hot_agents: f64,

    /// Drop every agent's connection this long into the test
    #[arg(long, value_name = "TIME", value_parser = parse_duration, help_heading = "Events")]
    pub outage_at: Option<Duration>,

    /// How long an outage lasts. Agents save samples and send them afterwards
    #[arg(long, default_value = "30s", value_parser = parse_duration, help_heading = "Events")]
    pub outage_for: Duration,

    /// Change the first config rule this long into the test, sending every agent a
    /// new config. It's put back at the end
    #[arg(long, value_name = "TIME", value_parser = parse_duration, help_heading = "Events")]
    pub rule_change_at: Option<Duration>,

    /// How many people to simulate looking at pages
    #[arg(long, default_value_t = 1, help_heading = "Pages")]
    pub viewers: usize,

    /// How often each viewer loads the pages
    #[arg(long, default_value = "15s", value_parser = parse_duration, help_heading = "Pages")]
    pub page_every: Duration,

    /// Where to write the report
    #[arg(
        long,
        default_value = "loadtest-report.html",
        value_name = "FILE",
        help_heading = "Results"
    )]
    pub report: PathBuf,

    /// Also write the results as JSON
    #[arg(long, value_name = "FILE", help_heading = "Results")]
    pub json: Option<PathBuf>,

    /// Fail on warnings as well as failures
    #[arg(long, help_heading = "Results")]
    pub strict: bool,

    /// Where to keep the agents' keys, so running again reuses the same agents
    #[arg(
        long,
        default_value = "loadtest-keys.json",
        value_name = "FILE",
        help_heading = "Simulated agents"
    )]
    pub keys_file: PathBuf,

    /// What to start host names with
    #[arg(
        long,
        default_value = "loadtest",
        value_name = "TEXT",
        help_heading = "Simulated agents"
    )]
    pub host_prefix: String,

    /// Revoke the simulated agents at the end
    #[arg(long, help_heading = "Simulated agents")]
    pub revoke: bool,
}

/// A setting as the report shows it.
#[derive(Serialize)]
pub struct Setting {
    pub name: &'static str,
    pub value: String,
}

fn time(duration: Duration) -> String {
    format_duration(duration).to_string()
}

impl Options {
    pub fn check(&self) -> Result<()> {
        if self.agents == 0 {
            bail!("--agents has to be at least 1");
        }
        if self.interval.is_zero() {
            bail!("--interval has to be longer than nothing");
        }
        if self.backlog_gap.is_zero() {
            bail!("--backlog-gap has to be longer than nothing");
        }
        for (name, percent) in [
            ("--churn", self.churn),
            ("--fact-changes", self.fact_changes),
            ("--hot-agents", self.hot_agents),
        ] {
            if !(0.0..=100.0).contains(&percent) {
                bail!("{name} is a percentage, from 0 to 100");
            }
        }
        if !self.yes && !is_this_host(&self.url) {
            bail!(
                "{} isn't on this host. Simulated agents are approved and saved like real \
                 ones, so use a test server, and add --yes to go ahead",
                self.url
            );
        }
        Ok(())
    }

    pub fn admin_address(&self) -> String {
        let address = self.admin_url.clone().unwrap_or_else(|| {
            let address = self.url.replacen("ws", "http", 1);
            address.strip_suffix("/ws").unwrap_or(&address).to_string()
        });
        address.trim_end_matches('/').to_string()
    }

    /// Everything that shaped the load. The API key is deliberately not here.
    pub fn settings(&self) -> Vec<Setting> {
        let mut settings = vec![
            ("Server", self.url.clone()),
            ("Agents", self.agents.to_string()),
            ("Duration", time(self.duration)),
            ("Sample interval", time(self.interval)),
            ("Connecting over", time(self.ramp)),
            ("Disks", self.disks.to_string()),
            ("Network interfaces", self.interfaces.to_string()),
            ("CPU cores", self.cores.to_string()),
            ("Facts reported every", time(self.facts_every)),
            ("Viewers", self.viewers.to_string()),
        ];
        if self.churn > 0.0 {
            settings.push(("Reconnecting each minute", format!("{}%", self.churn)));
        }
        if self.backlog > 0 {
            let text = format!("{} samples, {} apart", self.backlog, time(self.backlog_gap));
            settings.push(("Starting backlog", text));
        }
        if self.fact_changes > 0.0 {
            settings.push(("Facts changing", format!("{}%", self.fact_changes)));
        }
        if self.hot_agents > 0.0 {
            settings.push(("Agents at 99% CPU", format!("{}%", self.hot_agents)));
        }
        if let Some(at) = self.outage_at {
            let text = format!("At {} for {}", time(at), time(self.outage_for));
            settings.push(("Outage", text));
        }
        if let Some(at) = self.rule_change_at {
            settings.push(("Rule change", format!("At {}", time(at))));
        }
        settings
            .into_iter()
            .map(|(name, value)| Setting { name, value })
            .collect()
    }
}

fn is_this_host(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let hostname = rest.split(['/', '?']).next().unwrap_or_default();
    let hostname = match hostname.strip_prefix('[') {
        Some(ipv6) => ipv6.split(']').next().unwrap_or_default(),
        None => hostname.split(':').next().unwrap_or_default(),
    };
    matches!(hostname, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn options(arguments: &str) -> Options {
        let line = format!("loadtest --api-key t {arguments}");
        Options::try_parse_from(line.split_whitespace()).unwrap()
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Options::command().debug_assert();
    }

    #[test]
    fn durations_read_naturally() {
        let options = options("--url ws://localhost/ws --duration 2m --interval 500ms");
        assert_eq!(options.duration, Duration::from_secs(120));
        assert_eq!(options.interval, Duration::from_millis(500));
    }

    #[test]
    fn the_admin_address_comes_from_the_agent_address() {
        for (url, expected) in [
            ("ws://localhost:9000/ws", "http://localhost:9000"),
            (
                "wss://monitor.example.com/ws",
                "https://monitor.example.com",
            ),
        ] {
            let options = options(&format!("--url {url}"));
            assert_eq!(options.admin_address(), expected);
        }
    }

    #[test]
    fn the_admin_address_can_be_given() {
        let options = options("--url ws://a/ws --admin-url http://b:1/ --yes");
        assert_eq!(options.admin_address(), "http://b:1");
    }

    #[test]
    fn another_host_has_to_be_confirmed() {
        assert!(options("--url ws://127.0.0.1:9000/ws").check().is_ok());
        assert!(options("--url ws://localhost/ws").check().is_ok());
        assert!(options("--url ws://[::1]:9000/ws").check().is_ok());
        let error = options("--url ws://10.0.0.5:9000/ws").check().unwrap_err();
        assert!(error.to_string().contains("--yes"));
        assert!(options("--url ws://10.0.0.5:9000/ws --yes").check().is_ok());
    }

    #[test]
    fn looking_like_this_host_is_not_enough() {
        let error = options("--url ws://localhost.example.com/ws").check();
        assert!(error.is_err());
    }

    #[test]
    fn impossible_settings_are_refused() {
        for bad in [
            "--agents 0",
            "--interval 0s",
            "--churn 101",
            "--hot-agents -1",
        ] {
            let line = format!("loadtest --api-key t --url ws://localhost/ws {bad}");
            let parsed = Options::try_parse_from(line.split_whitespace());
            assert!(parsed.is_err() || parsed.unwrap().check().is_err(), "{bad}");
        }
    }

    #[test]
    fn the_settings_never_include_the_api_key() {
        let line = "loadtest --api-key secret-key --url ws://localhost/ws";
        let options = Options::try_parse_from(line.split_whitespace()).unwrap();
        let text = serde_json::to_string(&options.settings()).unwrap();
        assert!(!text.contains("secret-key"), "{text}");
    }

    #[test]
    fn optional_load_only_shows_when_used() {
        let names = |options: &Options| -> Vec<&str> {
            options.settings().iter().map(|s| s.name).collect()
        };
        assert!(!names(&options("--url ws://l/ws")).contains(&"Outage"));
        let with = options("--url ws://l/ws --outage-at 1m");
        assert!(names(&with).contains(&"Outage"));
    }
}
