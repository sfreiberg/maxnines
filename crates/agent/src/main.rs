mod actions;
mod background;
mod builtin_actions;
mod checks;
mod collector;
mod commands;
mod config;
#[cfg(any(windows, test))]
mod configure;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
))]
mod connections;
#[cfg(target_os = "linux")]
mod containers;
mod custom;
mod databases;
mod disk_space;
mod facts;
mod files;
mod identity;
mod openmetrics;
mod own_usage;
mod privileges;
mod saved_config;
mod services;
mod smart;
mod spool;
mod status_pages;
mod system_collector;
mod templates;
mod websocket;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use maxnines_protocol::auth::Identity;
use maxnines_protocol::logging;
#[cfg(windows)]
use maxnines_protocol::service::{self, Service, ServiceCommand};
use maxnines_protocol::{AgentConfig, Sample};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at, timeout};
use tracing::{error, info, warn};

use background::jitter;
use collector::{Collector, Local, Made};
use config::Config;
use maxnines_protocol::stopping::StopSignal;
use own_usage::OwnUsageCollector;
use templates::TemplateCollector;
use websocket::{ConfigUpdate, ServerLink};

#[cfg(windows)]
static SERVICE: Service = Service {
    name: "MaxNinesAgent",
    display_name: "MaxNines Agent",
    description: "Reports system metrics to a MaxNines server.",
    log_name: "agent",
};

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
    /// Run one of this agent's actions as the server would, and print the result
    Action {
        /// The action's name, built in or from the config file
        name: String,
        /// Values for its variables, like disk=/var
        #[arg(value_name = "NAME=VALUE", value_parser = parse_variable)]
        variables: Vec<(String, String)>,
        /// How long it gets, in seconds. Without it, as long as the server gives
        #[arg(long = "timeout-secs", value_name = "SECONDS", value_parser = parse_seconds)]
        timeout: Option<Duration>,
    },
    /// Print this agent's version, and exactly which build it is
    Version,
    /// What Windows starts the agent's service with
    #[cfg(windows)]
    #[command(subcommand, hide = true)]
    Service(ServiceCommand),
    /// Set the server to report to, creating the config file if there isn't one,
    /// and restart the service if it's running
    #[cfg(windows)]
    Configure {
        /// The server's address as opened in a browser, such as
        /// https://monitor.example.com, or its public_url
        #[arg(long)]
        server_url: String,
        /// Enrollment token, for servers with automatic approval rules. Leave it
        /// out to keep the one there is
        #[arg(long)]
        token: Option<String>,
    },
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

fn parse_variable(text: &str) -> Result<(String, String), String> {
    let (name, value) = text
        .split_once('=')
        .ok_or("a variable is written as name=value, like disk=/var")?;
    Ok((name.to_string(), value.to_string()))
}

fn parse_seconds(text: &str) -> Result<Duration, String> {
    text.parse()
        .map(Duration::from_secs)
        .map_err(|_| "a time limit is a whole number of seconds, like 30".to_string())
}

/// Runs an action exactly as it would for the server, so it can be tried out on
/// the host, as the user the agent runs as.
fn try_action(
    config: &Config,
    name: &str,
    variables: Vec<(String, String)>,
    timeout: Duration,
) -> Result<()> {
    #[cfg(unix)]
    privileges::split(config)?;
    let runner = actions::Runner::new(
        config.actions.clone(),
        config.built_in_actions,
        &config.state_dir,
    );
    let variables = variables.into_iter().collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(runner.run("try".to_string(), name, &variables, timeout));

    print!("{}", result.output);
    if result.truncated {
        eprintln!("(the rest was cut off)");
    }
    let took = result.duration.as_secs_f64();
    let outcome = result.outcome.as_str().replace('_', " ");
    match (result.error, result.exit_code) {
        (Some(error), _) => eprintln!("{outcome} after {took:.1}s: {error}"),
        (None, Some(code)) => eprintln!("{outcome} after {took:.1}s, exit status {code}"),
        (None, None) => eprintln!("{outcome} after {took:.1}s"),
    }
    anyhow::ensure!(
        result.outcome == maxnines_protocol::actions::ActionOutcome::Succeeded,
        "the action didn't succeed"
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        // A service logs to files, which it sets up once it knows where it is.
        #[cfg(windows)]
        Command::Service(ServiceCommand::Run) => service::run(&SERVICE, &cli.config, |path| {
            remember_for_installer(&path);
            run(path)
        }),
        // Anything else says what went wrong where it was typed.
        command => {
            logging::to_stderr();
            run_command(command, cli.config)
        }
    }
}

/// Runs what was typed, rather than what Windows starts.
fn run_command(command: Command, path: PathBuf) -> Result<()> {
    match command {
        Command::Run => run(path),
        #[cfg(windows)]
        Command::Service(ServiceCommand::Run) => {
            anyhow::bail!("only Windows starts the service this way")
        }
        #[cfg(windows)]
        Command::Configure { server_url, token } => {
            configure::write(&path, &server_url, token.as_deref())?;
            remember_for_installer(&path);
            service::restart_if_running(&SERVICE)
        }
        Command::Version => {
            let build = maxnines_protocol::build_info!();
            println!("{}", build.describe(env!("CARGO_PKG_NAME")));
            Ok(())
        }
        Command::Facts => {
            let config = Config::load(&path)?;
            let facts = facts::gather(
                &config.facts,
                &config.allowed(),
                &config.actions,
                config.built_in_actions,
            )?;
            println!("{}", serde_json::to_string_pretty(&facts)?);
            Ok(())
        }
        Command::Action {
            name,
            variables,
            timeout,
        } => {
            let config = Config::load(&path)?;
            let timeout = timeout.unwrap_or(maxnines_protocol::actions::DEFAULT_ACTION_TIMEOUT);
            try_action(&config, &name, variables, timeout)
        }
        Command::Identity(command) => {
            let config = Config::load(&path)?;
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

/// Saves the server for the installer to show in Modify, from the config, so it
/// stays right after the file's edited by hand.
#[cfg(windows)]
fn remember_for_installer(path: &Path) {
    use maxnines_protocol::config_file;

    let saved = Config::load(path).and_then(|config| {
        let address = config_file::browser_address(&config.server.url);
        config_file::remember_for_installer("Agent", &[("SERVER_URL", &address)])
    });
    if let Err(error) = saved {
        warn!(
            error = format!("{error:#}"),
            "couldn't save the settings for the installer"
        );
    }
}

fn print_identity(identity: &Identity) {
    println!("host id:    {}", identity.id());
    println!("public key: {}", identity.public_key());
}

/// What a config turns on, ready to collect.
type Collectors = Vec<Box<dyn Collector + Send>>;

/// What a config built: what each of its collectors is made from, each built
/// unless one made the same is running already, and the collectors it named that
/// this agent doesn't know, which a newer server can send.
struct Built {
    plan: collector::Plan,
    skipped_collectors: Vec<String>,
}

/// Builds what a config turns on that isn't running already, `keeping` being what
/// the collectors running now were made from. It fails without side effects, so a
/// bad config leaves the old one running. Everything that could go wrong with a
/// config happens in here, so a bad one is refused rather than taking the agent
/// down. What this agent doesn't know is left out, and the rest runs.
fn build(config: &AgentConfig, local: Local<'_>, keeping: &[Made]) -> Result<Built> {
    catch_unwind(AssertUnwindSafe(|| {
        let mut config = config.clone();
        let skipped_collectors = config.remove_unknown_collectors();
        if !skipped_collectors.is_empty() {
            warn!(
                skipped = skipped_collectors.join(", "),
                "the server asked for collectors this agent doesn't know, upgrade it to run them"
            );
        }
        config.validate_sent()?;
        let mut plan = collector::build_all(&config, local, keeping)?;
        let own: Option<Box<dyn Collector + Send>> = match keeping.contains(&Made::OwnUsage) {
            true => None,
            false => Some(Box::new(OwnUsageCollector::new()?)),
        };
        plan.push((Made::OwnUsage, own));
        anyhow::Ok(Built {
            plan,
            skipped_collectors,
        })
    }))
    .map_err(|_| anyhow!("building collectors panicked"))?
}

/// Builds what a config turns on, apart from the connection, as reading the system
/// can block, and the agent's one thread also keeps the connection alive.
async fn build_apart(
    update: ConfigUpdate,
    config: &Arc<Config>,
    keeping: Vec<Made>,
) -> Result<(ConfigUpdate, Built)> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let built = build(&update.config, config.local(), &keeping)?;
        Ok((update, built))
    })
    .await
    .context("building collectors stopped")?
}

/// Saves a config that's running, so monitoring carries on with it through a
/// server outage.
async fn save_apart(update: ConfigUpdate, config: &Arc<Config>) {
    let path = config.saved_config_file();
    let saved = tokio::task::spawn_blocking(move || saved_config::save(&path, &update)).await;
    if let Err(error) = saved.map_err(anyhow::Error::from).and_then(|saved| saved) {
        warn!(error = format!("{error:#}"), "saving the config failed");
    }
}

/// The collectors running now, each with what it was made from.
type Running = Vec<(Made, Box<dyn Collector + Send>)>;

/// Puts a plan's collectors together: those it built, and for the rest, the one
/// running now made the same, which is taken from `running`. What templates read is
/// changed in place, once everything else is there. None if one the plan keeps
/// isn't running, or can't be changed, and then `running` is as it was.
fn assemble(
    plan: collector::Plan,
    running: &mut Running,
    config: &AgentConfig,
    local: Local<'_>,
) -> Option<(Collectors, Vec<Made>)> {
    // Each collector, and whether it was taken from `running`.
    let mut parts: Vec<(Made, Box<dyn Collector + Send>, bool)> = Vec::with_capacity(plan.len());
    let give_back = |parts: Vec<(Made, Box<dyn Collector + Send>, bool)>, running: &mut Running| {
        running.extend(
            parts
                .into_iter()
                .filter(|(_, _, taken)| *taken)
                .map(|(made, collector, _)| (made, collector)),
        );
    };
    for (what, built) in plan {
        match built {
            Some(built) => parts.push((what, built, false)),
            None => match running.iter().position(|(kept, _)| *kept == what) {
                Some(at) => {
                    let (made, kept) = running.remove(at);
                    parts.push((made, kept, true));
                }
                None => {
                    give_back(parts, running);
                    return None;
                }
            },
        }
    }
    let kept_templates = parts
        .iter_mut()
        .find(|(made, _, taken)| *taken && *made == Made::Templates);
    if let Some((_, kept, _)) = kept_templates {
        let changed = match kept
            .as_any_mut()
            .and_then(|any| any.downcast_mut::<TemplateCollector>())
        {
            Some(templates) => templates
                .update(&config.templates, local.databases, config.interval)
                .map_err(|error| format!("{error:#}")),
            None => Err("it isn't what templates are read with".to_string()),
        };
        if let Err(error) = changed {
            warn!(error, "changing what templates read failed");
            give_back(parts, running);
            return None;
        }
    }
    Some(
        parts
            .into_iter()
            .map(|(made, collector, _)| (collector, made))
            .unzip(),
    )
}

/// [`assemble`] apart from the connection, as changing what templates read can
/// block on Windows' performance counters. `running` comes back as `assemble`
/// leaves it.
async fn assemble_apart(
    plan: collector::Plan,
    running: Running,
    update: &ConfigUpdate,
    config: &Arc<Config>,
) -> (Option<(Collectors, Vec<Made>)>, Running) {
    let (agent, config) = (update.config.clone(), config.clone());
    let assembling = tokio::task::spawn_blocking(move || {
        let mut running = running;
        let assembled = catch_unwind(AssertUnwindSafe(|| {
            assemble(plan, &mut running, &agent, config.local())
        }))
        .unwrap_or_else(|_| {
            error!("putting collectors together panicked");
            None
        });
        (assembled, running)
    });
    match assembling.await {
        Ok(done) => done,
        // It catches panics, so only a runtime shutting down gets here.
        Err(error) => {
            error!(%error, "putting collectors together stopped");
            (None, Vec::new())
        }
    }
}

/// Where the collectors are.
enum Collecting {
    Ready(Collectors),
    /// Collecting a sample on a thread of their own, as reading the system can
    /// block, on a hung network drive say, and the agent's one thread also keeps the
    /// connection to the server alive. Since when.
    Away(JoinHandle<Collected>, Instant),
}

/// What a sample's collection gives back: the collectors, the sample, and which
/// collectors panicked, by where they are among them.
type Collected = (Collectors, Sample, Vec<usize>);

/// How long a new config waits, in all, for the collectors to finish a sample, to
/// keep what's the same, before building them all again. Counted from when the
/// sample began, so collectors that are stuck hold up only the first config.
const TAKE_BACK_LIMIT: Duration = Duration::from_secs(5);

/// The monitoring the agent is currently doing.
struct Monitoring {
    version: String,
    collecting: Collecting,
    /// What each collector was made from, in the same order.
    made: Vec<Made>,
    /// Collectors that panicked, which a new config builds again rather than keeps,
    /// as a panic may have left them broken.
    broken: Vec<Made>,
    period: Duration,
    ticker: Interval,
}

impl Monitoring {
    fn new(version: String, collectors: Collectors, made: Vec<Made>, period: Duration) -> Self {
        // CPU usage is measured between refreshes, so the first sample waits. The
        // random part is because a config can reach every agent at the same moment,
        // and they would then all collect together from then on.
        let first = Instant::now() + collector::WARMUP + jitter(period);
        let mut ticker = interval_at(first, period);
        // A sample that took longer than the interval is followed at once by the
        // next, and the ones after keep to the schedule.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self {
            version,
            collecting: Collecting::Ready(collectors),
            made,
            broken: Vec::new(),
            period,
            ticker,
        }
    }

    fn collector_count(&self) -> usize {
        match &self.collecting {
            Collecting::Ready(collectors) => collectors.len(),
            Collecting::Away(..) => 0,
        }
    }

    /// What the collectors running now were made from, but for those that panicked.
    fn keeping(&self) -> Vec<Made> {
        self.made
            .iter()
            .filter(|made| !self.broken.contains(made))
            .cloned()
            .collect()
    }

    /// Notes which collectors panicked in a sample.
    fn note_panicked(&mut self, panicked: &[usize]) {
        for at in panicked {
            if let Some(made) = self.made.get(*at)
                && !self.broken.contains(made)
            {
                self.broken.push(made.clone());
            }
        }
    }

    /// The collectors, with what each was made from, once they're back from any
    /// sample they're taking, and that sample. None if they don't come back soon,
    /// and then they carry on with it.
    async fn take_back(&mut self) -> Option<(Running, Option<Sample>)> {
        let mut finished = None;
        if let Collecting::Away(task, since) = &mut self.collecting {
            let left = TAKE_BACK_LIMIT.saturating_sub(since.elapsed());
            let Ok(Ok((collectors, sample, panicked))) = timeout(left, &mut *task).await else {
                return None;
            };
            finished = Some(sample);
            self.note_panicked(&panicked);
            self.collecting = Collecting::Ready(collectors);
        }
        let Collecting::Ready(collectors) =
            std::mem::replace(&mut self.collecting, Collecting::Ready(Vec::new()))
        else {
            return None;
        };
        let running = std::mem::take(&mut self.made)
            .into_iter()
            .zip(collectors)
            .collect();
        Some((running, finished))
    }

    /// Puts back collectors [`Self::take_back`] took, when a new config couldn't
    /// use them, so the config that was running carries on.
    fn put_back(&mut self, running: Running) {
        let (made, collectors): (Vec<Made>, Collectors) = running.into_iter().unzip();
        self.made = made;
        self.collecting = Collecting::Ready(collectors);
    }
}

/// Reads the config and, if started as root, gives that up before anything else
/// happens. The config is read first, while it's still certain to be readable.
fn run(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    #[cfg(unix)]
    privileges::split(&config)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run_agent(path, Arc::new(config)));
    // A sample stuck on a hung drive mustn't keep the agent from stopping.
    runtime.shutdown_background();
    result
}

async fn run_agent(path: PathBuf, config: Arc<Config>) -> Result<()> {
    let identity = identity::load_or_create(&config.key_file())?;
    let mut link = ServerLink::start(&config, &collector::host_name(), identity)?;
    info!(config = %path.display(), "agent started");

    // The last good config means monitoring carries on through a server outage.
    let mut monitoring = None;
    if let Some(update) = saved_config::load(&config.saved_config_file()) {
        match build_apart(update, &config, Vec::new()).await {
            Ok((update, built)) => {
                info!(version = update.version, "using the saved config");
                link.set_facts_interval(update.config.facts_interval);
                let period = update.config.interval;
                if let (Some((collectors, made)), _) =
                    assemble_apart(built.plan, Vec::new(), &update, &config).await
                {
                    monitoring = Some(Monitoring::new(update.version, collectors, made, period));
                }
            }
            Err(error) => warn!(error = format!("{error:#}"), "saved config is unusable"),
        }
    }

    let mut stop = StopSignal::listen().context("listening for being asked to stop")?;
    loop {
        tokio::select! {
            Some(sample) = next_sample(&mut monitoring) => link.send_sample(sample)?,
            Some(update) = link.next_config() => {
                apply(update, &config, &mut monitoring, &link).await?;
            }
            result = stop.wait() => {
                result?;
                info!("shutting down");
                link.save_unconfirmed().await;
                return Ok(());
            }
        }
    }
}

/// Collects a sample when one is due, apart from the connection. Waits forever
/// until there's a config, because only the server says what to do. It can be
/// stopped at any await and carry on where it was.
async fn next_sample(monitoring: &mut Option<Monitoring>) -> Option<Sample> {
    let Some(active) = monitoring else {
        return std::future::pending().await;
    };
    loop {
        match &mut active.collecting {
            Collecting::Ready(_) => {
                active.ticker.tick().await;
                let ready =
                    std::mem::replace(&mut active.collecting, Collecting::Ready(Vec::new()));
                let Collecting::Ready(mut collectors) = ready else {
                    continue;
                };
                let task = tokio::task::spawn_blocking(move || {
                    let (sample, panicked) = collect(&mut collectors);
                    (collectors, sample, panicked)
                });
                active.collecting = Collecting::Away(task, Instant::now());
            }
            Collecting::Away(task, _) => {
                let collected = task.await;
                match collected {
                    Ok((collectors, sample, panicked)) => {
                        active.note_panicked(&panicked);
                        active.collecting = Collecting::Ready(collectors);
                        return Some(sample);
                    }
                    Err(error) => {
                        // Collecting catches what a collector does wrong, so this
                        // leaves nothing to collect with until the next config.
                        error!(%error, "collecting stopped, waiting for a new config");
                        *monitoring = None;
                        return None;
                    }
                }
            }
        }
    }
}

/// Swaps in a new config, or keeps the current one and tells the server why not.
/// Collectors whose settings are the same carry on, with whatever they hold, such
/// as connections and running totals, and templates take their new work in place.
/// A config that can't be put together that way has everything built again, and
/// one that can't be built at all leaves the one running as it was. Only a config
/// that runs is saved.
async fn apply(
    update: ConfigUpdate,
    config: &Arc<Config>,
    monitoring: &mut Option<Monitoring>,
    link: &ServerLink,
) -> Result<()> {
    let already_running = monitoring
        .as_ref()
        .is_some_and(|active| active.version == update.version);
    if already_running {
        let mut config = update.config;
        let skipped_collectors = config.remove_unknown_collectors();
        return link.report_config(&update.version, None, skipped_collectors);
    }

    let version = update.version.clone();
    let rejected = |error: anyhow::Error| {
        let error = format!("{error:#}");
        warn!(version, error, "config rejected");
        link.report_config(&version, Some(error), Vec::new())
    };
    let keeping = monitoring
        .as_ref()
        .map(Monitoring::keeping)
        .unwrap_or_default();
    let (update, built) = match build_apart(update, config, keeping).await {
        Ok(built) => built,
        Err(error) => return rejected(error),
    };
    let period = update.config.interval;
    let fresh = built
        .plan
        .iter()
        .any(|(made, built)| built.is_some() && matches!(made, Made::Settings { .. }));
    let skipped_collectors = built.skipped_collectors.clone();
    let running = match monitoring.as_mut() {
        Some(active) => active.take_back().await.map(|(running, finished)| {
            if let Some(sample) = finished
                && let Err(error) = link.send_sample(sample)
            {
                warn!(error = format!("{error:#}"), "keeping a sample failed");
            }
            running
        }),
        None => Some(Vec::new()),
    };
    let mut assembled = None;
    if let Some(running) = running {
        let (done, running) = assemble_apart(built.plan, running, &update, config).await;
        match done {
            Some(done) => assembled = Some(done),
            // What wasn't used goes back, so the old config carries on if the new
            // one can't be built afresh either.
            None => {
                if let Some(active) = monitoring.as_mut() {
                    active.put_back(running);
                }
            }
        }
    }
    let started = match assembled {
        Some((collectors, made)) => {
            // Unchanged, the samples keep to their schedule, unless something new
            // has to warm up first.
            let same_schedule = !fresh
                && monitoring
                    .as_ref()
                    .is_some_and(|active| active.period == period);
            match (monitoring.take(), same_schedule) {
                (Some(mut active), true) => {
                    active.version = update.version.clone();
                    active.collecting = Collecting::Ready(collectors);
                    active.made = made;
                    active.broken.clear();
                    active
                }
                _ => Monitoring::new(update.version.clone(), collectors, made, period),
            }
        }
        // What was to be kept isn't there, or is still collecting, so everything's
        // built again.
        None => {
            let (_, built) = match build_apart(update.clone(), config, Vec::new()).await {
                Ok(built) => built,
                Err(error) => return rejected(error),
            };
            match assemble_apart(built.plan, Vec::new(), &update, config).await {
                (Some((collectors, made)), _) => {
                    Monitoring::new(update.version.clone(), collectors, made, period)
                }
                (None, _) => return rejected(anyhow!("putting its collectors together failed")),
            }
        }
    };
    info!(
        version = update.version,
        collectors = started.collector_count(),
        interval_secs = period.as_secs(),
        "config applied"
    );
    *monitoring = Some(started);
    link.set_facts_interval(update.config.facts_interval);
    save_apart(update.clone(), config).await;
    link.report_config(&update.version, None, skipped_collectors)
}

/// Collects a sample. A collector that fails or panics is logged and skipped so
/// the others still report, and it gets another chance on the next tick; which
/// ones panicked comes back too, by where they are. Rust's panic hook has already
/// written the panic message and location to stderr.
fn collect(collectors: &mut [Box<dyn Collector + Send>]) -> (Sample, Vec<usize>) {
    let mut metrics = BTreeMap::new();
    let mut panicked = Vec::new();
    for (at, collector) in collectors.iter_mut().enumerate() {
        match catch_unwind(AssertUnwindSafe(|| collector.collect())) {
            // Nothing yet, which isn't the same as finding nothing.
            Ok(Ok(Value::Null)) => {}
            Ok(Ok(Value::Object(entries))) if collector.spreads() => metrics.extend(entries),
            Ok(Ok(value)) => {
                metrics.insert(collector.name().to_string(), value);
            }
            Ok(Err(error)) => warn!(collector = collector.name(), %error, "collection failed"),
            Err(_) => {
                error!(collector = collector.name(), "collector panicked");
                panicked.push(at);
            }
        }
    }

    let sample = Sample {
        time: maxnines_protocol::time::now(),
        metrics,
    };
    (sample, panicked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::time::timeout;

    struct Working;

    impl Collector for Working {
        fn name(&self) -> &'static str {
            "working"
        }

        fn collect(&mut self) -> Result<Value> {
            Ok(json!(1))
        }
    }

    struct NothingYet;

    impl Collector for NothingYet {
        fn name(&self) -> &'static str {
            "nothing-yet"
        }

        fn collect(&mut self) -> Result<Value> {
            Ok(Value::Null)
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
        ConfigUpdate::read(version.to_string(), config).unwrap()
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

        let cli = parse("version").unwrap();
        assert_eq!(cli.command, Some(Command::Version));

        let cli = parse("-c my.hcl identity show").unwrap();
        assert_eq!(cli.command, Some(Command::Identity(IdentityCommand::Show)));
        assert_eq!(cli.config, PathBuf::from("my.hcl"));
    }

    #[cfg(windows)]
    #[test]
    fn parses_what_windows_starts_a_service_with() {
        let cli = parse(r"--config C:\agent.hcl service run").unwrap();
        assert_eq!(cli.command, Some(Command::Service(ServiceCommand::Run)));
        assert_eq!(cli.config, PathBuf::from(r"C:\agent.hcl"));
    }

    #[cfg(windows)]
    #[test]
    fn parses_what_the_installer_configures_with() {
        let cli = parse(
            r"--config C:\agent.hcl configure --server-url https://m.example.com --token abc",
        )
        .unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Configure {
                server_url: "https://m.example.com".to_string(),
                token: Some("abc".to_string()),
            })
        );
    }

    #[test]
    fn rejects_bad_commands() {
        for text in ["identity", "identity delete", "identity generate --forse"] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn panicking_collector_does_not_stop_the_others() {
        let mut collectors: Collectors = vec![Box::new(Panicking), Box::new(Working)];

        // Twice, because the panicking collector must not break later ticks.
        for _ in 0..2 {
            let (sample, panicked) = collect(&mut collectors);
            assert_eq!(sample.metrics.get("working"), Some(&json!(1)));
            assert!(!sample.metrics.contains_key("panicking"));
            assert_eq!(panicked, [0]);
        }
    }

    #[test]
    fn a_collector_with_no_result_yet_is_left_out() {
        let mut collectors: Collectors = vec![Box::new(NothingYet), Box::new(Working)];

        let (sample, panicked) = collect(&mut collectors);

        assert_eq!(sample.metrics.get("working"), Some(&json!(1)));
        assert!(!sample.metrics.contains_key("nothing-yet"));
        assert!(panicked.is_empty());
    }

    #[tokio::test]
    async fn the_first_sample_waits_for_a_random_part_of_the_interval() {
        let mut started = Monitoring::new(
            "v1".to_string(),
            vec![Box::new(Working)],
            vec![Made::OwnUsage],
            Duration::from_secs(36_000),
        );

        let first = timeout(Duration::from_secs(1), started.ticker.tick()).await;

        assert!(first.is_err());
    }

    #[test]
    fn a_good_config_builds_its_collectors() {
        let config = update("v1", json!({ "collectors": { "cpu": {} } })).config;
        let built = build(&config, Local::none(), &[]).unwrap();

        // What was asked for, and the agent reporting on itself.
        assert_eq!(built.plan.len(), 2);
        assert!(built.skipped_collectors.is_empty());
    }

    #[test]
    fn a_bad_config_is_refused() {
        for config in [
            json!({ "interval_secs": 0 }),
            json!({ "collectors": { "processes": { "names": [""] } } }),
        ] {
            assert!(build(&update("v1", config).config, Local::none(), &[]).is_err());
        }
    }

    /// A newer server can add a collector without older agents turning down every
    /// config it sends from then on.
    #[test]
    fn a_collector_this_agent_does_not_know_is_skipped_and_the_rest_run() {
        let config = json!({ "collectors": { "cpu": {}, "zfs": { "pools": ["tank"] } } });
        let built = build(&update("v1", config).config, Local::none(), &[]).unwrap();

        assert_eq!(built.plan.len(), 2);
        assert_eq!(built.skipped_collectors, ["zfs"]);
    }

    /// Counts its samples, which only one that carries on remembers.
    struct Counting(u64);

    impl Collector for Counting {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn collect(&mut self) -> Result<Value> {
            self.0 += 1;
            Ok(json!(self.0))
        }
    }

    #[test]
    fn a_new_config_keeps_the_collectors_it_says_the_same_of() {
        let before = update("v1", json!({ "collectors": { "cpu": {}, "memory": {} } })).config;
        let keeping: Vec<Made> = build(&before, Local::none(), &[])
            .unwrap()
            .plan
            .into_iter()
            .map(|(made, _)| made)
            .collect();
        // What's running now: the same, with something it remembers.
        let mut running: Vec<(Made, Box<dyn Collector + Send>)> = keeping
            .iter()
            .map(|made| {
                (
                    made.clone(),
                    Box::new(Counting(0)) as Box<dyn Collector + Send>,
                )
            })
            .collect();
        for (_, collector) in &mut running {
            collector.collect().unwrap();
        }

        // Memory goes, cpu and the agent's report on itself carry on.
        let after = update("v2", json!({ "collectors": { "cpu": {} } })).config;
        let built = build(&after, Local::none(), &keeping).unwrap();
        assert!(built.plan.iter().all(|(_, built)| built.is_none()));
        let (mut collectors, made) =
            assemble(built.plan, &mut running, &after, Local::none()).unwrap();
        assert_eq!(made.len(), 2);
        for collector in &mut collectors {
            assert_eq!(
                collector.collect().unwrap(),
                json!(2),
                "{}",
                collector.name()
            );
        }

        // One that isn't running any more can't be kept.
        let built = build(&after, Local::none(), &keeping).unwrap();
        assert!(assemble(built.plan, &mut Vec::new(), &after, Local::none()).is_none());
    }

    /// A config that can't be put together leaves what was running as it was, so the
    /// config before carries on.
    #[test]
    fn a_config_that_cannot_be_put_together_gives_back_what_it_took() {
        let before = update("v1", json!({ "collectors": { "cpu": {}, "memory": {} } })).config;
        let keeping: Vec<Made> = build(&before, Local::none(), &[])
            .unwrap()
            .plan
            .into_iter()
            .map(|(made, _)| made)
            .collect();
        let cpu = keeping
            .iter()
            .find(|made| matches!(made, Made::Settings { name, .. } if name == "cpu"))
            .unwrap()
            .clone();
        // Only cpu is running, so memory, which the plan keeps, isn't there.
        let mut running: Running = vec![(cpu.clone(), Box::new(Counting(7)))];
        let built = build(&before, Local::none(), &keeping).unwrap();

        assert!(assemble(built.plan, &mut running, &before, Local::none()).is_none());
        assert_eq!(running.len(), 1);
        assert!(running[0].0 == cpu);
        assert_eq!(running[0].1.collect().unwrap(), json!(8));
    }

    /// A collector that panicked is built again by the next config, rather than
    /// kept, as the panic may have left it broken.
    #[tokio::test]
    async fn a_collector_that_panicked_is_not_kept() {
        let mut monitoring = Monitoring::new(
            "v1".to_string(),
            vec![Box::new(Panicking), Box::new(Working)],
            vec![Made::Templates, Made::OwnUsage],
            Duration::from_secs(60),
        );
        let Collecting::Ready(mut collectors) =
            std::mem::replace(&mut monitoring.collecting, Collecting::Ready(Vec::new()))
        else {
            unreachable!()
        };
        let (_, panicked) = collect(&mut collectors);
        monitoring.note_panicked(&panicked);
        monitoring.collecting = Collecting::Ready(collectors);

        assert!(monitoring.keeping() == [Made::OwnUsage]);
    }

    /// Collectors stuck in a sample hold up a new config only so long, counted from
    /// when the sample began, and carry on with it when they're not taken back.
    #[tokio::test]
    async fn collectors_stuck_in_a_sample_are_left_to_it() {
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let mut monitoring = Monitoring::new(
            "v1".to_string(),
            Vec::new(),
            Vec::new(),
            Duration::from_secs(60),
        );
        let task = tokio::task::spawn_blocking(move || {
            stuck.recv().ok();
            (
                Collectors::new(),
                Sample {
                    time: maxnines_protocol::time::now(),
                    metrics: BTreeMap::new(),
                },
                Vec::new(),
            )
        });
        // Away for longer than a new config waits, so it doesn't wait at all.
        let since = Instant::now() - TAKE_BACK_LIMIT;
        monitoring.collecting = Collecting::Away(task, since);

        let waited = Instant::now();
        assert!(monitoring.take_back().await.is_none());
        assert!(waited.elapsed() < TAKE_BACK_LIMIT);
        assert!(matches!(monitoring.collecting, Collecting::Away(..)));

        release.send(()).unwrap();
        while let Collecting::Away(task, _) = &monitoring.collecting
            && !task.is_finished()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (running, finished) = monitoring.take_back().await.unwrap();
        assert!(running.is_empty());
        assert!(finished.is_some());
    }

    /// Blocks until it's let go, as reading a hung network drive does.
    struct Stuck(std::sync::Mutex<std::sync::mpsc::Receiver<()>>);

    impl Collector for Stuck {
        fn name(&self) -> &'static str {
            "stuck"
        }

        fn collect(&mut self) -> Result<Value> {
            self.0.lock().unwrap().recv().ok();
            Ok(json!(1))
        }
    }

    #[tokio::test]
    async fn a_collector_that_blocks_does_not_hold_up_the_agent() {
        let (release, stuck) = std::sync::mpsc::channel();
        let collectors: Collectors = vec![Box::new(Stuck(std::sync::Mutex::new(stuck)))];
        let mut monitoring = Some(Monitoring::new(
            "v1".to_string(),
            collectors,
            vec![Made::OwnUsage],
            Duration::from_millis(1),
        ));
        // Lets it go in the end, so a test that fails doesn't hang.
        let watchdog_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog = {
            let (release, fired) = (release.clone(), watchdog_fired.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(60));
                fired.store(true, std::sync::atomic::Ordering::Relaxed);
                release.send(()).ok();
            })
        };
        let collecting = tokio::spawn(async move { next_sample(&mut monitoring).await });

        // This test's runtime has one thread, the same as the agent's, so this
        // only wakes up if collecting left it free.
        tokio::time::sleep(collector::WARMUP + Duration::from_millis(100)).await;
        assert!(!watchdog_fired.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!collecting.is_finished());

        release.send(()).unwrap();
        let sample = collecting.await.unwrap().unwrap();
        assert_eq!(sample.metrics["stuck"], json!(1));
        drop(watchdog);
    }
}
