mod alert_evaluator;
mod alerting;
mod app_state;
mod calculations;
mod cli;
mod condition_builder;
mod config;
mod controllers;
mod csrf;
mod dashboards;
mod docs;
mod fact_history;
mod facts;
mod host_filter;
mod locations;
mod maintenance;
mod metric_charts;
mod metrics;
mod migrations;
mod models;
mod notifier;
mod passwords;
mod places;
mod presence;
mod registration;
mod remote_checks;
mod rule_engine;
mod rule_preview;
mod server_stats;
mod silences;
mod slack_actions;
mod store;
mod tls;
mod views;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

use alert_evaluator::Evaluator;
use app_state::{AppState, Heartbeat};
use config::Config;
use maxnines_protocol::logging;
#[cfg(windows)]
use maxnines_protocol::service::{self, Service, ServiceCommand};
use maxnines_protocol::stopping::StopSignal;
use metrics::{Metrics, now_ms};
use models::Database;
use notifier::{Mailer, Notifier, Senders, web_url};
use presence::Presence;
use registration::{Registry, Rules};
use remote_checks::{LOCAL_AGENT_ID, LatestResults, Scheduler};
use server_stats::ServerStatus;
use store::WriterCommand;
use views::Views;

#[cfg(windows)]
static SERVICE: Service = Service {
    name: "MaxNinesServer",
    display_name: "MaxNines Server",
    description: "Receives and stores metrics from MaxNines agents.",
    log_name: "server",
};

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
    /// Manage registered agents on the running server, with MAXNINES_API_KEY set
    #[command(subcommand)]
    Agents(AgentsCommand),
    /// Manage keys for the API, in the main database
    #[command(subcommand)]
    ApiKeys(ApiKeysCommand),
    /// Manage who can sign in, in the main database
    #[command(subcommand)]
    Users(UsersCommand),
    /// Run the server as a Windows service
    #[cfg(windows)]
    #[command(subcommand)]
    Service(ServiceCommand),
}

#[derive(Debug, PartialEq, Subcommand)]
enum UsersCommand {
    /// List everyone who can sign in
    List,
    /// Add someone and print the link for them to set a password
    Create { email: String, name: String },
    /// Print a new link for someone to set a password, as when they've forgotten it
    SetupLink { id: i64 },
    /// Stop someone signing in, and sign them out
    Disable { id: i64 },
    /// Let someone sign in again
    Enable { id: i64 },
    /// Remove someone who's been disabled
    Delete { id: i64 },
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
        Command::Run => {
            logging::to_stderr();
            serve(&cli.config)
        }
        #[cfg(windows)]
        Command::Service(ServiceCommand::Install) => {
            Config::load(&cli.config)?;
            service::install(&SERVICE, &cli.config)
        }
        #[cfg(windows)]
        Command::Service(ServiceCommand::Uninstall) => service::uninstall(&SERVICE),
        #[cfg(windows)]
        Command::Service(ServiceCommand::Run) => {
            service::run(&SERVICE, &cli.config, |path| serve(&path))
        }
        Command::Users(command) => {
            let config = Config::load(&cli.config)?;
            match command {
                UsersCommand::List => cli::print_users(&config),
                UsersCommand::Create { email, name } => cli::create_user(&config, &email, &name),
                UsersCommand::SetupLink { id } => cli::print_setup_link(&config, id),
                UsersCommand::Disable { id } => cli::change_user(&config, id, "disable"),
                UsersCommand::Enable { id } => cli::change_user(&config, id, "enable"),
                UsersCommand::Delete { id } => cli::delete_user(&config, id),
            }
        }
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
    let config = Config::load(path)?;
    let rules = Rules::compile(&config.registration)?;

    let database = Database::connect(&config.database.resolve_url()?).await?;
    let secure_site = config.audience().starts_with("wss://");
    let csrf = csrf::config(&database, secure_site).await?;
    let agents = database.load_agents().await.context("loading agents")?;
    let store = store::open(&config.metrics)?;
    let metrics = Metrics::new(store.reader()?);
    let status = Arc::new(ServerStatus::new(
        config.metrics.path().map(Path::to_path_buf),
    )?);
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
        views: Arc::new(Views::load()?),
        csrf,
        web_url: web_url(config.audience()).unwrap_or_default().into(),
        sign_ins: Arc::default(),
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
    slack_actions::spawn(state.database.clone(), state.senders.web_url.clone());
    Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.check_results.clone(),
    )
    .spawn();
    server_stats::spawn_recorder(state.clone());
    // The server is always online to itself, so nothing reads it as missing.
    state
        .presence
        .connected(LOCAL_AGENT_ID, IpAddr::from([127, 0, 0, 1]));

    let mut stop = StopSignal::listen().context("listening for being asked to stop")?;
    let service = controllers::app(state).into_make_service_with_connect_info::<SocketAddr>();
    let serving = async {
        match &config.tls {
            Some(tls) => tls::serve(listener, tls, service).await,
            None => Ok(axum::serve(listener, service).await?),
        }
    };
    tokio::select! {
        result = serving => result?,
        result = stop.wait() => result?,
    }

    info!("shutting down");
    writer.send(WriterCommand::Stop).await?;
    tokio::task::spawn_blocking(move || writer_thread.join())
        .await?
        .ok();
    Ok(())
}
