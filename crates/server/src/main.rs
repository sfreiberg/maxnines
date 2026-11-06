mod alert_evaluator;
mod alerting;
mod app_state;
mod cli;
mod condition_builder;
mod config;
mod controllers;
mod fact_history;
mod facts;
mod host_filter;
mod metric_charts;
mod metrics;
mod migrations;
mod models;
mod notifier;
mod presence;
mod registration;
mod remote_checks;
mod rule_engine;
mod rule_preview;
mod server_stats;
mod store;
mod views;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum_csrf::CsrfConfig;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::EnvFilter;

use alert_evaluator::Evaluator;
use app_state::{AppState, Heartbeat};
use config::Config;
use metrics::{Metrics, now_ms};
use models::Database;
use notifier::{Mailer, Notifier, Senders, web_url};
use presence::Presence;
use registration::{Registry, Rules, hash_token};
use remote_checks::{LOCAL_AGENT_ID, LatestResults, Scheduler};
use server_stats::ServerStatus;
use store::WriterCommand;
use views::Views;

#[derive(Debug, Parser)]
#[command(version, about = "Receives and stores metrics from MaxNines agents")]
struct Cli {
    /// Path to the config file
    #[arg(short, long, global = true, default_value = "server.hcl")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, PartialEq, Subcommand)]
enum Command {
    /// Run the server (the default)
    Run,
    /// Manage registered agents on a running server
    #[command(subcommand)]
    Agents(AgentsCommand),
    /// Manage keys for the API on a running server
    #[command(subcommand)]
    ApiKeys(ApiKeysCommand),
    /// Print the server's own token, which works like an API key and can't be revoked
    AdminToken,
}

#[derive(Debug, PartialEq, Subcommand)]
enum ApiKeysCommand {
    /// List keys, without the keys themselves
    List,
    /// Make a key and print it, which is the only time it can be seen
    Create {
        name: String,
        /// How long it lasts, like 1h or 30d. Without this it never expires
        #[arg(long, value_name = "TIME", value_parser = humantime::parse_duration)]
        expires_in: Option<std::time::Duration>,
    },
    /// Stop a key working
    Revoke { id: i64 },
}

#[derive(Debug, PartialEq, Subcommand)]
enum AgentsCommand {
    /// List agents and their status
    List,
    /// Show what is known about an agent
    Facts {
        id: String,
        /// Show every change instead of the current facts
        #[arg(long)]
        history: bool,
    },
    /// Let an agent connect
    Approve { id: String },
    /// Stop an agent from connecting, and drop it if it's connected
    Revoke { id: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => serve(&cli.config),
        Command::AdminToken => cli::print_admin_token(&Config::load(&cli.config)?),
        Command::ApiKeys(command) => {
            let config = Config::load(&cli.config)?;
            match command {
                ApiKeysCommand::List => cli::print_api_keys(&config),
                ApiKeysCommand::Create { name, expires_in } => {
                    cli::create_api_key(&config, &name, expires_in)
                }
                ApiKeysCommand::Revoke { id } => cli::revoke_api_key(&config, id),
            }
        }
        Command::Agents(command) => {
            let config = Config::load(&cli.config)?;
            match command {
                AgentsCommand::List => cli::print_agents(&config),
                AgentsCommand::Facts { id, history: false } => cli::print_facts(&config, &id),
                AgentsCommand::Facts { id, history: true } => {
                    cli::print_facts_history(&config, &id)
                }
                AgentsCommand::Approve { id } => cli::change_agent(&config, &id, "approve"),
                AgentsCommand::Revoke { id } => cli::change_agent(&config, &id, "revoke"),
            }
        }
    }
}

#[tokio::main]
async fn serve(path: &Path) -> Result<()> {
    // Logs go to stderr, matching the agent.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::load(path)?;
    let rules = Rules::compile(&config.registration)?;

    let database = Database::connect(&config.database.resolve_url()?).await?;
    let admin_token = database.admin_token().await?;
    let agents = database.load_agents().await.context("loading agents")?;
    let store = store::open(&config.metrics)?;
    let metrics = Metrics::new(store.reader()?);
    let status = Arc::new(ServerStatus::new(Some(
        config.metrics.path().to_path_buf(),
    ))?);
    let (writer, writer_thread) = store::spawn_writer(store, status.writes.clone());
    let mailer = config
        .email
        .as_ref()
        .map(Mailer::new)
        .transpose()
        .context("setting up email")?
        .map(Arc::new);

    let state = AppState {
        presence: Arc::new(Presence::default()),
        registry: Arc::new(Registry::new(
            agents,
            rules,
            config.registration.max_pending,
            database.clone(),
        )),
        database,
        config_changes: Arc::new(watch::Sender::new(0)),
        writer: writer.clone(),
        metrics,
        senders: Senders::new(mailer, web_url(config.audience())),
        check_results: Arc::new(LatestResults::default()),
        status,
        heartbeat: Heartbeat {
            interval: Duration::from_secs(config.heartbeat_interval_secs),
            timeout: Duration::from_secs(config.heartbeat_timeout_secs),
        },
        audience: config.audience().into(),
        trusted_proxies: config.trusted_networks()?.into(),
        admin_token_hash: hash_token(&admin_token).into(),
        views: Arc::new(Views::load()?),
        csrf: CsrfConfig::default().with_secure(config.audience().starts_with("wss://")),
    };

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("listening on {}", config.listen))?;
    info!(
        config = %path.display(),
        listen = %config.listen,
        public_url = %state.audience,
        "server started"
    );

    Evaluator::new(
        state.database.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.metrics.clone(),
        state.status.clone(),
        now_ms(),
    )
    .spawn();
    Notifier::new(state.database.clone(), state.senders.clone()).spawn();
    Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.check_results.clone(),
    )
    .spawn();
    // The server is always online to itself, so nothing reads it as missing.
    state
        .presence
        .connected(LOCAL_AGENT_ID, IpAddr::from([127, 0, 0, 1]));

    let service = controllers::app(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::select! {
        result = axum::serve(listener, service).into_future() => result?,
        result = tokio::signal::ctrl_c() => result?,
    }

    info!("shutting down");
    writer.send(WriterCommand::Stop).await?;
    tokio::task::spawn_blocking(move || writer_thread.join())
        .await?
        .ok();
    Ok(())
}
