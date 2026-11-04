mod app_state;
mod cli;
mod condition_builder;
mod config;
mod controllers;
mod fact_history;
mod facts;
mod migrations;
mod models;
mod presence;
mod registration;
mod rule_engine;
mod rule_preview;
mod store;
mod views;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
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

use app_state::{AppState, Heartbeat};
use config::Config;
use models::Database;
use presence::Presence;
use registration::{Registry, Rules, hash_token};
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
    let admin_token = controllers::admin::load_or_create_token(&config.admin_token_file)?;

    let database = Database::connect(&config.database.resolve_url()?).await?;
    let agents = database.load_agents().await.context("loading agents")?;
    let (writer, writer_thread) = store::spawn_writer(store::open(&config.metrics)?);

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
