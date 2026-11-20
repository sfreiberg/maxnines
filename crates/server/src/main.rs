mod actions;
mod agent_configs;
mod agent_versions;
mod alert_charts;
mod alert_evaluator;
mod alerting;
mod app_sign_ins;
mod app_state;
mod audit;
mod built_in_rules;
mod calculations;
mod channels;
mod check_history;
mod cli;
mod clock;
mod condition_builder;
mod config;
#[cfg(any(windows, test))]
mod configure;
mod controllers;
mod csrf;
mod dashboard_variables;
mod dashboards;
mod docs;
mod events;
mod fact_history;
mod facts;
mod host_filter;
mod locations;
mod maintenance;
mod metric_charts;
mod metrics;
mod metrics_pages;
mod migrations;
mod models;
mod notifier;
mod passwords;
mod places;
mod presence;
mod proxies;
mod registration;
mod remote_checks;
mod roles;
mod rule_engine;
mod rule_preview;
mod server_stats;
mod silences;
mod slack_actions;
mod store;
mod text;
mod times;
mod tls;
mod two_factor;
mod views;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::info;

use alert_evaluator::Evaluator;
use app_state::{AppState, Heartbeat};
use config::Config;
use maxnines_protocol::logging;
#[cfg(windows)]
use maxnines_protocol::service::{self, Service, ServiceCommand};
use maxnines_protocol::stopping::StopSignal;
use metrics::Metrics;
use models::Database;
use notifier::{Notifier, Senders, web_url};
use presence::Presence;
use registration::{Registry, Rules};
use remote_checks::{LOCAL_HOST_ID, LatestResults, Scheduler};
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
    /// Manage registered hosts on the running server, with MAXNINES_API_KEY set
    #[command(subcommand)]
    Hosts(HostsCommand),
    /// Manage keys for the API, in the main database
    #[command(subcommand)]
    ApiKeys(ApiKeysCommand),
    /// Manage who can sign in, in the main database
    #[command(subcommand)]
    Users(UsersCommand),
    /// Print this server's version, and exactly which build it is
    Version,
    /// What Windows starts the server's service with
    #[cfg(windows)]
    #[command(subcommand, hide = true)]
    Service(ServiceCommand),
    /// Set the address, port and HTTPS, creating the config file if there isn't
    /// one, add the first administrator, and restart the service if it's running
    #[cfg(windows)]
    Configure(ConfigureArgs),
}

/// What the Windows installer asks. It passes an empty value for anything not
/// given, which counts as leaving it out.
#[cfg(windows)]
#[derive(Debug, PartialEq, clap::Args)]
struct ConfigureArgs {
    /// The address people open in a browser and agents connect to, such as
    /// https://monitor.example.com
    #[arg(long)]
    address: String,
    /// The port to listen on
    #[arg(long)]
    port: u16,
    #[arg(long, value_enum, default_value = "none")]
    https: configure::Https,
    /// Who Let's Encrypt can contact about the certificate
    #[arg(long)]
    acme_email: Option<String>,
    /// The certificate in PEM format, for --https files
    #[arg(long)]
    certificate_file: Option<String>,
    /// Its private key in PEM format, for --https files
    #[arg(long)]
    key_file: Option<String>,
    /// Add this administrator, if nobody's been added yet
    #[arg(long)]
    admin_email: Option<String>,
    #[arg(long)]
    admin_name: Option<String>,
    /// Save the administrator's link for setting a password here, as a shortcut,
    /// instead of printing it. Empty says how to get the link instead. Text
    /// rather than a path, as a path can't be empty, and the installer passes an
    /// empty one when there's nowhere to put it
    #[arg(long)]
    setup_link_file: Option<String>,
}

#[cfg(windows)]
fn configure_for_installer(path: &Path, arguments: ConfigureArgs) -> Result<()> {
    use maxnines_protocol::config_file;

    let given = |value: Option<String>| value.filter(|value| !value.trim().is_empty());
    let installer = vec![
        ("SERVER_ADDRESS", arguments.address.clone()),
        ("PORT", arguments.port.to_string()),
        ("HTTPS", arguments.https.as_str().to_string()),
        (
            "ACME_EMAIL",
            arguments.acme_email.clone().unwrap_or_default(),
        ),
        (
            "CERTIFICATE_FILE",
            arguments.certificate_file.clone().unwrap_or_default(),
        ),
        ("KEY_FILE", arguments.key_file.clone().unwrap_or_default()),
    ];
    let remembered =
        config_file::remembered_for_installer("Server", &configure::INSTALLER_SETTINGS);
    let current = Config::load(path)
        .map(|config| configure::installer_settings(&config))
        .unwrap_or_default();
    let settings = configure::Settings::from_installer(&configure::keep_hand_edits(
        &installer,
        &remembered,
        &current,
    ))?;

    // The service runs as its own account, which can't otherwise read files only
    // administrators can. Before the config names them, so a failure leaves the
    // old config as it was.
    if settings.https == Some(configure::Https::Files) {
        for file in [&settings.certificate_file, &settings.key_file]
            .into_iter()
            .flatten()
        {
            configure::let_service_read(file)
                .with_context(|| format!("letting the service read {}", file.display()))?;
        }
    }
    let config = configure::write(path, &settings, configure::protect_config)?;
    remember_for_installer(&config)?;

    if let Some(email) = given(arguments.admin_email) {
        let name = arguments.admin_name.unwrap_or_default();
        match cli::first_admin(&config, &email, &name)? {
            Some((id, link)) => {
                println!("Added {email} as an administrator.");
                match arguments.setup_link_file.as_deref() {
                    None => println!("Open this to set a password: {link}"),
                    // A silent install has nowhere to show it, and its log isn't
                    // the place for it.
                    Some("") => println!(
                        "Get the link to set a password with: maxnines-server users setup-link {id}"
                    ),
                    Some(file) => {
                        config_file::replace(Path::new(file), &configure::shortcut(&link))?;
                    }
                }
            }
            None => println!("Someone's already been added, so {email} wasn't."),
        }
    }
    service::restart_if_running(&SERVICE)
}

/// Saves the settings for the installer to show in Modify. Only this, run by the
/// installer as Windows itself, saves them: the service can't, so a server that's
/// been taken over can't choose what the installer does next.
#[cfg(windows)]
fn remember_for_installer(config: &Config) -> Result<()> {
    let settings = configure::installer_settings(config);
    let settings: Vec<(&str, &str)> = settings
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    maxnines_protocol::config_file::remember_for_installer("Server", &settings)
}

#[derive(Debug, PartialEq, Subcommand)]
enum UsersCommand {
    /// List everyone who can sign in
    List,
    /// Add someone and print the link for them to set a password
    Create {
        email: String,
        name: String,
        /// What they may do: viewer, responder, editor or admin
        #[arg(long, default_value = "admin", value_parser = roles::Role::parse)]
        role: roles::Role,
    },
    /// Change what someone may do: viewer, responder, editor or admin
    Role {
        id: i64,
        #[arg(value_parser = roles::Role::parse)]
        role: roles::Role,
    },
    /// Turn off someone's two-factor sign-in, as when they've lost their phone
    ResetTwoFactor { id: i64 },
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
        /// The email address of the user the key acts as
        #[arg(long, value_name = "EMAIL")]
        user: String,
        /// The most the key can do: viewer, responder, editor or admin. Without this
        /// it's the user's own role. Give it the least that does the job, like editor
        /// for a tool that manages rules, as an admin key can add users
        #[arg(long, value_parser = roles::Role::parse)]
        role: Option<roles::Role>,
        /// How long it lasts, like 1h or 30d. Without this it never expires
        #[arg(long, value_name = "TIME", value_parser = humantime::parse_duration)]
        expires_in: Option<std::time::Duration>,
    },
    /// Stop a key working
    Revoke { id: i64 },
}

#[derive(Debug, PartialEq, Subcommand)]
enum HostsCommand {
    /// List hosts and their status
    List,
    /// Show what is known about a host
    Facts {
        id: String,
        /// Show every change instead of the current facts
        #[arg(long)]
        history: bool,
    },
    /// Approve a host, so its agent can connect
    Approve { id: String },
    /// Revoke a host, so its agent can no longer connect, and drop it if it is
    Revoke { id: String },
    /// Delete a revoked host with its metrics, facts and alerts, for good
    Delete { id: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            logging::to_stderr();
            serve(&cli.config)
        }
        #[cfg(windows)]
        Command::Service(ServiceCommand::Run) => {
            service::run(&SERVICE, &cli.config, |path| serve(&path))
        }
        #[cfg(windows)]
        Command::Configure(arguments) => configure_for_installer(&cli.config, arguments),
        Command::Version => {
            let build = maxnines_protocol::build_info!();
            println!("{}", build.describe(env!("CARGO_PKG_NAME")));
            Ok(())
        }
        Command::Users(command) => {
            let config = Config::load(&cli.config)?;
            match command {
                UsersCommand::List => cli::print_users(&config),
                UsersCommand::Create { email, name, role } => {
                    cli::create_user(&config, &email, &name, role)
                }
                UsersCommand::Role { id, role } => cli::set_role(&config, id, role),
                UsersCommand::ResetTwoFactor { id } => cli::reset_two_factor(&config, id),
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
                ApiKeysCommand::Create {
                    name,
                    user,
                    role,
                    expires_in,
                } => cli::create_api_key(&config, &name, &user, role, expires_in),
                ApiKeysCommand::Revoke { id } => cli::revoke_api_key(&config, id),
            }
        }
        Command::Hosts(command) => {
            let config = Config::load(&cli.config)?;
            match command {
                HostsCommand::List => cli::print_hosts(&config),
                HostsCommand::Facts { id, history: false } => cli::print_facts(&config, &id),
                HostsCommand::Facts { id, history: true } => cli::print_facts_history(&config, &id),
                HostsCommand::Approve { id } => cli::change_host(&config, &id, "approve"),
                HostsCommand::Revoke { id } => cli::change_host(&config, &id, "revoke"),
                HostsCommand::Delete { id } => cli::delete_host(&config, &id),
            }
        }
    }
}

#[tokio::main]
async fn serve(path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    let rules = Rules::compile(&config.registration)?;

    let database = Database::connect(&config.database.resolve_url()?).await?;
    // The config rules that come with this version, which an upgrade may change.
    let changed = database
        .sync_built_in_rules(&built_in_rules::all(), crate::times::now())
        .await
        .context("updating the built-in config rules")?;
    if !changed.is_empty() {
        info!(rules = changed.join(", "), "built-in config rules updated");
    }
    let secure_site = config.audience().starts_with("wss://");
    let csrf = csrf::config(&database, secure_site).await?;
    let hosts = database.load_hosts().await.context("loading hosts")?;
    let store = store::open(&config.metrics, config.retention)?;
    let metrics = Metrics::new(store.reader()?);
    let status = Arc::new(ServerStatus::new(
        config.metrics.path().map(Path::to_path_buf),
    )?);
    let (writer, writer_thread) = store::spawn_writer(store, status.writes.clone());

    let require_two_factor = database.two_factor_required().await?;
    let proxies = proxies::Proxies::new(config.trusted_networks()?);
    proxies.set_decisions(&database.list_proxies().await?);
    let state = AppState {
        presence: Arc::new(Presence::default()),
        registry: Arc::new(Registry::new(
            hosts,
            rules,
            config.registration.max_pending,
            database.clone(),
        )),
        actions: actions::Actions::new(database.clone()),
        configs: Arc::new(agent_configs::AgentConfigs::new(database.clone())),
        database,
        writer: writer.clone(),
        metrics,
        senders: Senders::new(web_url(config.audience())),
        check_results: Arc::new(LatestResults::default()),
        page_reads: Arc::default(),
        status,
        heartbeat: Heartbeat {
            interval: config.heartbeat_interval,
            timeout: config.heartbeat_timeout,
            clock_every: clock::ASK_EVERY,
        },
        audience: config.audience().into(),
        proxies: Arc::new(proxies),
        views: Arc::new(Views::load()?),
        csrf,
        web_url: web_url(config.audience()).unwrap_or_default().into(),
        sign_ins: Arc::default(),
        require_two_factor: Arc::new(require_two_factor.into()),
        pending_sign_ins: Arc::default(),
        health_limit: controllers::health::CHECK_LIMIT,
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
        state.actions.clone(),
        crate::times::now(),
    )
    .spawn();
    Notifier::new(state.database.clone(), state.senders.clone())
        .with_charts(alert_charts::ChartSources {
            database: state.database.clone(),
            registry: state.registry.clone(),
            metrics: state.metrics.clone(),
        })
        .spawn();
    slack_actions::spawn(state.database.clone(), state.senders.web_url.clone());
    Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.check_results.clone(),
    )
    .spawn();
    metrics_pages::Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.page_reads.clone(),
    )
    .spawn();
    server_stats::spawn_recorder(state.clone());
    // The server is always online to itself, so nothing reads it as missing.
    state
        .presence
        .connected(LOCAL_HOST_ID, IpAddr::from([127, 0, 0, 1]));

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
