mod background;
mod checks;
mod collector;
mod config;
mod custom;
mod facts;
mod files;
mod identity;
mod saved_config;
mod services;
mod system;
mod websocket;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use maxnines_protocol::Sample;
use maxnines_protocol::auth::Identity;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use collector::Collector;
use config::Config;
use custom::Definitions;
use websocket::{ConfigUpdate, ServerLink};

#[derive(Debug, Parser)]
#[command(version, about = "Reports system metrics to a MaxNines server")]
struct Cli {
    /// Path to the config file
    #[arg(short, long, global = true, default_value = "agent.hcl")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, PartialEq, Subcommand)]
enum Command {
    /// Run the agent (the default)
    Run,
    /// Manage this agent's key and ID
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Print the facts this agent reports
    Facts,
}

#[derive(Debug, PartialEq, Subcommand)]
enum IdentityCommand {
    /// Create this agent's key
    Generate {
        /// Replace an existing key, creating a new identity to approve
        #[arg(long)]
        force: bool,
    },
    /// Show this agent's ID and public key
    Show,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(cli.config),
        Command::Facts => {
            let config = Config::load(&cli.config)?;
            let facts = facts::gather(&config.facts, &config.custom_metrics)?;
            println!("{}", serde_json::to_string_pretty(&facts)?);
            Ok(())
        }
        Command::Identity(command) => {
            let config = Config::load(&cli.config)?;
            let identity = match command {
                IdentityCommand::Generate { force } => {
                    identity::generate(&config.key_file(), force)?
                }
                IdentityCommand::Show => identity::load(&config.key_file())?,
            };
            print_identity(&identity);
            Ok(())
        }
    }
}

fn print_identity(identity: &Identity) {
    println!("agent id:   {}", identity.id());
    println!("public key: {}", identity.public_key());
}

/// The monitoring the agent is currently doing.
struct Monitoring {
    version: String,
    collectors: Vec<Box<dyn Collector>>,
    ticker: Interval,
}

impl Monitoring {
    /// Fails without side effects, so a bad config leaves the old one running.
    fn start(update: &ConfigUpdate, definitions: &Definitions) -> Result<Self> {
        let collectors = catch_unwind(AssertUnwindSafe(|| {
            update.config.validate()?;
            collector::build_all(&update.config, definitions)
        }))
        .map_err(|_| anyhow!("building collectors panicked"))??;

        // CPU usage is measured between refreshes, so the first sample waits.
        let period = Duration::from_secs(update.config.interval_secs);
        let mut ticker = interval_at(Instant::now() + collector::WARMUP, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        Ok(Self {
            version: update.version.clone(),
            collectors,
            ticker,
        })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run(path: PathBuf) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::load(&path)?;
    let identity = identity::load_or_create(&config.key_file())?;
    let mut link = ServerLink::start(&config, &collector::host_name(), identity)?;
    info!(config = %path.display(), "agent started");

    // The last good config means monitoring carries on through a server outage.
    let saved_file = config.saved_config_file();
    let mut monitoring = None;
    if let Some(update) = saved_config::load(&saved_file) {
        match Monitoring::start(&update, &config.custom_metrics) {
            Ok(started) => {
                info!(version = update.version, "using the saved config");
                link.set_facts_interval(Duration::from_secs(update.config.facts_interval_secs));
                monitoring = Some(started);
            }
            Err(error) => warn!(error = format!("{error:#}"), "saved config is unusable"),
        }
    }

    loop {
        tokio::select! {
            () = next_tick(&mut monitoring) => {
                if let Some(active) = &mut monitoring {
                    link.send_sample(&collect(&mut active.collectors))?;
                }
            }
            Some(update) = link.next_config() => {
                apply(update, &config.custom_metrics, &mut monitoring, &link, &saved_file)?;
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("shutting down");
                return Ok(());
            }
        }
    }
}

/// Waits forever until there's a config, because only the server says what to do.
async fn next_tick(monitoring: &mut Option<Monitoring>) {
    match monitoring {
        Some(active) => {
            active.ticker.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// Swaps in a new config, or keeps the current one and tells the server why not.
fn apply(
    update: ConfigUpdate,
    definitions: &Definitions,
    monitoring: &mut Option<Monitoring>,
    link: &ServerLink,
    saved_file: &Path,
) -> Result<()> {
    let already_running = monitoring
        .as_ref()
        .is_some_and(|active| active.version == update.version);
    if already_running {
        return link.report_config(&update.version, None);
    }

    match Monitoring::start(&update, definitions) {
        Ok(started) => {
            info!(
                version = update.version,
                collectors = started.collectors.len(),
                interval_secs = update.config.interval_secs,
                "config applied"
            );
            *monitoring = Some(started);
            link.set_facts_interval(Duration::from_secs(update.config.facts_interval_secs));
            if let Err(error) = saved_config::save(saved_file, &update) {
                warn!(error = format!("{error:#}"), "saving the config failed");
            }
            link.report_config(&update.version, None)
        }
        Err(error) => {
            let error = format!("{error:#}");
            warn!(version = update.version, error, "config rejected");
            link.report_config(&update.version, Some(error))
        }
    }
}

/// A collector that fails or panics is logged and skipped so the others still
/// report, and it gets another chance on the next tick. Rust's panic hook has
/// already written the panic message and location to stderr.
fn collect(collectors: &mut [Box<dyn Collector>]) -> Sample {
    let mut metrics = BTreeMap::new();
    for collector in collectors {
        match catch_unwind(AssertUnwindSafe(|| collector.collect())) {
            Ok(Ok(value)) => {
                metrics.insert(collector.name().to_string(), value);
            }
            Ok(Err(error)) => warn!(collector = collector.name(), %error, "collection failed"),
            Err(_) => error!(collector = collector.name(), "collector panicked"),
        }
    }

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Sample {
        timestamp_ms,
        metrics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    struct Working;

    impl Collector for Working {
        fn name(&self) -> &'static str {
            "working"
        }

        fn collect(&mut self) -> Result<Value> {
            Ok(json!(1))
        }
    }

    struct Panicking;

    impl Collector for Panicking {
        fn name(&self) -> &'static str {
            "panicking"
        }

        fn collect(&mut self) -> Result<Value> {
            panic!("deliberate test panic");
        }
    }

    fn update(version: &str, config: Value) -> ConfigUpdate {
        ConfigUpdate {
            version: version.to_string(),
            config: serde_json::from_value(config).unwrap(),
        }
    }

    fn parse(text: &str) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("maxnines-agent").chain(text.split_whitespace()))
    }

    #[test]
    fn the_cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn running_is_the_default() {
        let cli = parse("").unwrap();
        assert_eq!(cli.command, None);
        assert_eq!(cli.config, PathBuf::from("agent.hcl"));
    }

    #[test]
    fn parses_identity_commands() {
        let cli = parse("identity generate --force --config my.hcl").unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Identity(IdentityCommand::Generate { force: true }))
        );
        assert_eq!(cli.config, PathBuf::from("my.hcl"));

        let cli = parse("facts").unwrap();
        assert_eq!(cli.command, Some(Command::Facts));

        let cli = parse("-c my.hcl identity show").unwrap();
        assert_eq!(cli.command, Some(Command::Identity(IdentityCommand::Show)));
        assert_eq!(cli.config, PathBuf::from("my.hcl"));
    }

    #[test]
    fn rejects_bad_commands() {
        for text in ["identity", "identity delete", "identity generate --forse"] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn panicking_collector_does_not_stop_the_others() {
        let mut collectors: Vec<Box<dyn Collector>> = vec![Box::new(Panicking), Box::new(Working)];

        // Twice, because the panicking collector must not break later ticks.
        for _ in 0..2 {
            let sample = collect(&mut collectors);
            assert_eq!(sample.metrics.get("working"), Some(&json!(1)));
            assert!(!sample.metrics.contains_key("panicking"));
        }
    }

    #[tokio::test]
    async fn a_good_config_starts_its_collectors() {
        let config = json!({ "collectors": { "cpu": {} } });
        let started = Monitoring::start(&update("v1", config), &Definitions::new()).unwrap();

        assert_eq!(started.version, "v1");
        assert_eq!(started.collectors.len(), 1);
    }

    #[tokio::test]
    async fn a_bad_config_is_refused() {
        for config in [
            json!({ "interval_secs": 0 }),
            json!({ "collectors": { "gpu": {} } }),
        ] {
            assert!(Monitoring::start(&update("v1", config), &Definitions::new()).is_err());
        }
    }
}
