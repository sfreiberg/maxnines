mod admin;
mod config;
mod connection;
mod database;
mod facts;
mod presence;
mod registration;
mod store;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::get;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use config::Config;
use connection::{AppState, Heartbeat};
use database::Database;
use presence::Presence;
use registration::{Registry, Rules, hash_token};
use store::WriterCommand;

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
                AgentsCommand::List => admin::print_agents(&config),
                AgentsCommand::Facts { id, history: false } => admin::print_facts(&config, &id),
                AgentsCommand::Facts { id, history: true } => {
                    admin::print_facts_history(&config, &id)
                }
                AgentsCommand::Approve { id } => admin::change_agent(&config, &id, "approve"),
                AgentsCommand::Revoke { id } => admin::change_agent(&config, &id, "revoke"),
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
    let admin_token = admin::load_or_create_token(&config.admin_token_file)?;

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
        writer: writer.clone(),
        heartbeat: Heartbeat {
            interval: Duration::from_secs(config.heartbeat_interval_secs),
            timeout: Duration::from_secs(config.heartbeat_timeout_secs),
        },
        audience: config.audience().into(),
        trusted_proxies: config.trusted_networks()?.into(),
        admin_token_hash: hash_token(&admin_token).into(),
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

    let service = app(state).into_make_service_with_connect_info::<SocketAddr>();
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

fn app(state: AppState) -> Router {
    Router::new()
        .route("/ws", get(connection::upgrade))
        .merge(admin::routes(state.clone()))
        .with_state(state)
}
