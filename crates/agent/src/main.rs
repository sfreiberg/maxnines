mod collector;
mod config;
mod exporter;
mod facts;
mod identity;
mod websocket;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use maxnines_protocol::Sample;
use maxnines_protocol::auth::Identity;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use collector::Collector;
use config::Config;
use exporter::Exporter;

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
            let facts = facts::gather(&config.facts)?;
            println!("{}", serde_json::to_string_pretty(&facts)?);
            Ok(())
        }
        Command::Identity(command) => {
            let config = Config::load(&cli.config)?;
            let identity = match command {
                IdentityCommand::Generate { force } => identity::generate(&config.key_file, force)?,
                IdentityCommand::Show => identity::load(&config.key_file)?,
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

#[tokio::main(flavor = "current_thread")]
async fn run(path: PathBuf) -> Result<()> {
    // Logs go to stderr so stdout carries nothing but samples.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::load(&path)?;
    let host = collector::host_name();

    let mut collectors = config
        .collector
        .iter()
        .filter(|(_, c)| c.enabled)
        .map(|(name, c)| collector::build(name, c))
        .collect::<Result<Vec<_>>>()?;
    let mut exporters = config
        .exporter
        .iter()
        .map(|(name, e)| exporter::build(name, e, &config, &host))
        .collect::<Result<Vec<_>>>()?;

    ensure!(!collectors.is_empty(), "no collectors are enabled");
    ensure!(!exporters.is_empty(), "no exporters are configured");

    info!(
        config = %path.display(),
        interval_secs = config.interval_secs,
        collectors = collectors.len(),
        "agent started"
    );

    sleep(collector::WARMUP).await;

    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let sample = collect(&mut collectors);
                export(&mut exporters, &sample)?;
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("shutting down");
                return Ok(());
            }
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

/// An export error stops the agent: for stdout it means the reader has gone.
/// A panic only loses this sample for that exporter.
fn export(exporters: &mut [Box<dyn Exporter>], sample: &Sample) -> Result<()> {
    for exporter in exporters {
        match catch_unwind(AssertUnwindSafe(|| exporter.export(sample))) {
            Ok(result) => result?,
            Err(_) => error!("exporter panicked, sample dropped"),
        }
    }
    Ok(())
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

    struct PanickingExporter;

    impl Exporter for PanickingExporter {
        fn export(&mut self, _: &Sample) -> Result<()> {
            panic!("deliberate test panic");
        }
    }

    struct CountingExporter(usize);

    impl Exporter for CountingExporter {
        fn export(&mut self, _: &Sample) -> Result<()> {
            self.0 += 1;
            Ok(())
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

    #[test]
    fn panicking_exporter_does_not_stop_the_agent() {
        let sample = Sample {
            timestamp_ms: 0,
            metrics: BTreeMap::new(),
        };
        let mut exporters: Vec<Box<dyn Exporter>> =
            vec![Box::new(PanickingExporter), Box::new(CountingExporter(0))];

        assert!(export(&mut exporters, &sample).is_ok());
    }
}
