//! maxnines, the command line for a MaxNines server. It only talks to the server's
//! API, signed in through the browser or with an API key, so it can do what the pages
//! can and nothing more: it never talks to agents, and can't make a host run anything.

mod api;
mod config;
mod failure;
mod http;
mod kinds;
mod output;
mod server;
mod signin;
mod tokens;

use std::cell::RefCell;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

use crate::api::{Api, Auth, expires_after};
use crate::config::{Config, Context};
use crate::failure::Failure;
use crate::kinds::{Kind, Options};
use crate::output::{Format, text};
use crate::server::Server;
use crate::tokens::Tokens;

/// The environment variables the API docs use, which win over the config file, as in CI.
const URL_VARIABLE: &str = "MAXNINES_URL";
const KEY_VARIABLE: &str = "MAXNINES_API_KEY";

#[derive(Parser)]
#[command(
    name = "maxnines",
    version,
    about = "The command line for a MaxNines server"
)]
struct Cli {
    /// Which server, by the name it was signed in as. The current one if left out.
    #[arg(long, global = true, env = "MAXNINES_CONTEXT")]
    context: Option<String>,

    /// How to show what comes back.
    #[arg(short, long, global = true, value_enum, default_value_t = Format::Table)]
    output: Format,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in to a server through the browser, saving it by name
    Login(LoginArgs),
    /// Sign out of a server, here and on the server
    Logout {
        /// The context to sign out of. The current one if left out.
        name: Option<String>,
    },
    /// Who you're signed in as, and with what role
    Whoami,
    /// The servers maxnines knows
    #[command(subcommand)]
    Config(ConfigCommand),
    /// List hosts, alerts, silences or checks
    Get(GetArgs),
    /// Everything about one host, alert, silence or check
    Describe {
        #[arg(value_enum)]
        kind: Kind,
        name: String,
    },
    /// Acknowledge alerts, by ID
    Ack {
        #[arg(required = true)]
        ids: Vec<i64>,
    },
    /// Undo acknowledging alerts, by ID
    Unack {
        #[arg(required = true)]
        ids: Vec<i64>,
    },
    /// Keep notifications back for a while
    Silence(SilenceArgs),
    /// End silences, as `silence 12` or `silence/12`
    End {
        #[arg(required = true)]
        what: Vec<String>,
    },
    /// Approve a host waiting to be let in
    Approve {
        #[arg(value_enum)]
        kind: ApproveKind,
        name: String,
    },
    /// Open something's page in the browser
    Open {
        #[arg(value_enum)]
        kind: Kind,
        name: Option<String>,
    },
    /// Call any of the API, under /api/v1, and show its JSON
    Api {
        /// GET, POST, PUT or DELETE.
        method: String,
        /// Such as /hosts/filter-options.
        path: String,
        /// name=value pairs: the query for GET and DELETE, a JSON object otherwise.
        fields: Vec<String>,
        /// A JSON body to send as it is.
        #[arg(long)]
        data: Option<String>,
    },
    /// Shell completions, to save where your shell looks for them
    Completion {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Args)]
struct LoginArgs {
    /// The server's address, or a name for it and then its address.
    #[arg(num_args = 0..=2, value_names = ["NAME", "SERVER"])]
    target: Vec<String>,
    /// Show a code to type on another device, for a machine with no browser.
    #[arg(long)]
    device: bool,
    /// The most to ask for. The approval page offers this, or less.
    #[arg(long, value_enum)]
    role: Option<Role>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Role {
    Viewer,
    Responder,
    Editor,
    Admin,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Responder => "responder",
            Self::Editor => "editor",
            Self::Admin => "admin",
        }
    }
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// The servers maxnines knows, and who each is signed in as
    List,
    /// Use this one when --context doesn't say
    Use { name: String },
    /// Add a server that uses an API key from an environment variable, as in CI
    Add {
        name: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        key_env: String,
    },
    /// Forget a server, signing out of it first
    Remove { name: String },
}

#[derive(Args)]
struct GetArgs {
    #[arg(value_enum)]
    kind: Kind,
    /// Only these, by hostname, name or ID.
    names: Vec<String>,
    /// Only what's about hosts matching this filter, as on the Hosts page.
    #[arg(long)]
    filter: Option<String>,
    /// Alerts that have resolved, or silences that have ended, instead.
    #[arg(long)]
    ended: bool,
    /// Exit 1 if anything was found, for scripts.
    #[arg(long)]
    exit_code: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SilenceKind {
    /// Just that alert: its rule, on its host, for its series.
    Alert,
    /// Everything about one host.
    Host,
    /// One check and nothing else on its host.
    Check,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ApproveKind {
    #[value(alias = "hosts")]
    Host,
}

#[derive(Args)]
struct SilenceArgs {
    /// What to silence. Leave out to say with --rule, --filter and --series.
    #[arg(value_enum)]
    kind: Option<SilenceKind>,
    /// Which alert, host or check.
    name: Option<String>,
    /// How long, such as 30m, 2h or 1d.
    #[arg(long = "for", value_parser = parse_duration)]
    duration: Duration,
    /// Why, which everyone sees.
    #[arg(long)]
    reason: String,
    /// One alert rule, by name or ID.
    #[arg(long)]
    rule: Option<String>,
    /// Hosts matching this filter.
    #[arg(long)]
    filter: Option<String>,
    /// One series alone, such as a check's name or a disk's mount point.
    #[arg(long)]
    series: Option<String>,
    /// Every alert on every host, which has to be said.
    #[arg(long)]
    all_alerts: bool,
}

/// A length such as `90s`, `30m`, `2h30m` or `1d`, read as the server reads its own.
fn parse_duration(text: &str) -> Result<Duration, String> {
    match humantime::parse_duration(text) {
        Ok(length) if length.as_secs() > 0 => Ok(length),
        Ok(_) => Err(format!(
            "{text:?} is too short: a silence lasts a second or more"
        )),
        Err(error) => Err(format!("{text:?} isn't a length, like 30m or 2h: {error}")),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let message = format!("{error:#}");
            if !message.is_empty() {
                eprintln!("Error: {message}");
            }
            ExitCode::from(failure::exit_code(&error))
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let folder = config::folder()?;
    let format = cli.output;
    match cli.command {
        Command::Login(args) => login(&folder, args, cli.context.as_deref()),
        Command::Logout { name } => logout(&folder, name.as_deref().or(cli.context.as_deref())),
        Command::Config(command) => configure(&folder, command),
        Command::Completion { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "maxnines",
                &mut std::io::stdout(),
            );
            Ok(0)
        }
        command => {
            let api = connect(&folder, cli.context.as_deref())?;
            act(&api, command, format)
        }
    }
}

/// The API for the context `--context` names, the current one, or the server the
/// environment names, as in CI.
fn connect(folder: &Path, name: Option<&str>) -> Result<Api> {
    if let Ok(url) = std::env::var(URL_VARIABLE)
        && !url.is_empty()
        && name.is_none()
    {
        let key = std::env::var(KEY_VARIABLE)
            .ok()
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(|| {
                Failure::not_allowed(format!(
                    "{URL_VARIABLE} is set, so {KEY_VARIABLE} needs to be too"
                ))
            })?;
        return Ok(Api::new(
            Server::parse(&url)?,
            URL_VARIABLE.to_string(),
            Auth::Key(key.trim().to_string()),
        ));
    }
    let config = Config::load(folder)?;
    let (name, context) = config.pick(name)?;
    let server = Server::parse(&context.server)?;
    if let Some(variable) = &context.key_env {
        let key = std::env::var(variable)
            .ok()
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(|| {
                Failure::not_allowed(format!(
                    "The {name} context takes its API key from {variable}, which isn't set"
                ))
            })?;
        return Ok(Api::new(server, name, Auth::Key(key.trim().to_string())));
    }
    let store = tokens::system(folder);
    let held = store.load(&name)?.ok_or_else(|| {
        Failure::not_allowed(format!(
            "Not signed in to {name}: run maxnines login {name}"
        ))
    })?;
    let auth = Auth::SignedIn {
        context: name.clone(),
        folder: folder.to_path_buf(),
        store,
        tokens: RefCell::new(held),
    };
    Ok(Api::new(server, name, auth))
}

/// What to tell someone when the server couldn't be told a sign-in has ended.
const REVOKE_BY_HAND: &str = "Revoke it in MaxNines under Settings, then Signed-in apps.";

/// Signs in, to the server `args` names, or else the context `--context` names or
/// the current one, again.
fn login(folder: &Path, args: LoginArgs, context: Option<&str>) -> Result<u8> {
    let mut config = Config::load(folder)?;
    let (name, address) = match args.target.as_slice() {
        [name, address] => (Some(name.clone()), address.clone()),
        // A context's name signs in to it again, as the messages about signing in say.
        [name] if !name.contains("://") && config.contexts.contains_key(name) => {
            (Some(name.clone()), config.contexts[name].server.clone())
        }
        [address] => (None, address.clone()),
        [] => {
            let (name, context) = config.pick(context)?;
            (Some(name), context.server)
        }
        _ => unreachable!("clap allows at most two"),
    };
    let server = Server::parse(&address)?;
    let name = name.unwrap_or_else(|| server.short_name());
    let device = gethostname::gethostname().to_string_lossy().into_owned();
    let role = args.role.map(Role::as_str);
    let http = http::Http::new();
    let issued = if args.device {
        let show = |start: &signin::DeviceStart| {
            eprintln!(
                "On any device, open {} and enter {}",
                start.verification_uri, start.user_code
            );
            eprintln!("Or open {}", start.verification_uri_complete);
            eprintln!("Waiting…");
        };
        let wait = |delay: Duration| std::thread::sleep(delay);
        signin::with_device(&http, &server, &device, role, &show, &wait)?
    } else {
        let open = |url: &str| {
            eprintln!("Opening the browser to sign in. If it doesn't open, go to:\n  {url}");
            let _ = webbrowser::open(url);
        };
        signin::with_browser(&http, &server, &device, role, &open)?
    };
    let held = Tokens {
        access_token: issued.access_token,
        access_expires_at: expires_after(issued.expires_in),
        refresh_token: issued.refresh_token,
        user: issued.user.clone(),
        role: issued.role.clone(),
    };
    let replaced = {
        // Others may be refreshing other contexts' tokens in the same store, and held
        // throughout, so the sign-in replaced is its newest.
        let _lock = tokens::lock(folder)?;
        let store = tokens::system(folder);
        let replaced = store.load(&name)?;
        store.save(&name, &held)?;
        replaced
    };
    // Revoked once the new one is kept, so failing to never loses it. The earlier one
    // is on the server the context was for, which the new one may not be.
    if let Some(replaced) = replaced {
        let earlier = match config.contexts.get(&name) {
            Some(context) => Server::parse(&context.server)?,
            None => server.clone(),
        };
        if let Err(failure) = signin::revoke(&http, &earlier, &replaced.refresh_token) {
            eprintln!(
                "The earlier sign-in to {name} couldn't be revoked on the server ({failure})."
            );
            eprintln!("{REVOKE_BY_HAND}");
        }
    }
    config.contexts.insert(
        name.clone(),
        Context {
            server: server.root.clone(),
            key_env: None,
        },
    );
    config.current = Some(name.clone());
    config.save(folder)?;
    println!(
        "Signed in to {} as {} ({}). Context {name:?} saved, and in use.",
        server.host, issued.user, issued.role
    );
    Ok(0)
}

fn logout(folder: &Path, name: Option<&str>) -> Result<u8> {
    let config = Config::load(folder)?;
    let (name, context) = config.pick(name)?;
    if !sign_out(folder, &name, &context)? {
        println!("Not signed in to {name}.");
    }
    Ok(0)
}

/// Signs a context out here and on the server, saying how it went. False if it
/// wasn't signed in.
fn sign_out(folder: &Path, name: &str, context: &Context) -> Result<bool> {
    let store = tokens::system(folder);
    // Held throughout, so a refresh can't swap the token between reading it and
    // revoking it, as the server only revokes the newest.
    let lock = tokens::lock(folder)?;
    let Some(held) = store.load(name)? else {
        return Ok(false);
    };
    let server = Server::parse(&context.server)?;
    let revoked = signin::revoke(&http::Http::new(), &server, &held.refresh_token);
    store.forget(name)?;
    drop(lock);
    match revoked {
        Ok(()) => println!("Signed out of {name}."),
        Err(failure) => {
            println!("Signed out of {name} here, but the server couldn't be told ({failure}).");
            println!("{REVOKE_BY_HAND}");
        }
    }
    Ok(true)
}

fn configure(folder: &Path, command: ConfigCommand) -> Result<u8> {
    let mut config = Config::load(folder)?;
    match command {
        ConfigCommand::List => {
            if config.contexts.is_empty() {
                println!("No servers yet: run maxnines login https://your-server");
                return Ok(0);
            }
            let store = tokens::system(folder);
            let mut rows = Vec::new();
            for (name, context) in &config.contexts {
                let signed_in = match &context.key_env {
                    Some(variable) => format!("API key in ${variable}"),
                    None => match store.load(name)? {
                        Some(held) => format!("{} ({})", held.user, held.role),
                        None => "not signed in".to_string(),
                    },
                };
                let current = if config.current.as_deref() == Some(name.as_str()) {
                    "*"
                } else {
                    ""
                };
                rows.push(vec![
                    current.to_string(),
                    name.clone(),
                    context.server.clone(),
                    signed_in,
                ]);
            }
            println!(
                "{}",
                output::table(&["", "name", "server", "signed in as"], &rows)
            );
        }
        ConfigCommand::Use { name } => {
            config.pick(Some(&name))?;
            config.current = Some(name.clone());
            config.save(folder)?;
            println!("Using {name}.");
        }
        ConfigCommand::Add {
            name,
            server,
            key_env,
        } => {
            let server = Server::parse(&server)?;
            // A context replaced by one with a key no longer uses its sign-in, so
            // nothing would ever sign it out.
            if let Some(replaced) = config.contexts.get(&name) {
                sign_out(folder, &name, replaced)?;
            }
            config.contexts.insert(
                name.clone(),
                Context {
                    server: server.root,
                    key_env: Some(key_env),
                },
            );
            if config.current.is_none() {
                config.current = Some(name.clone());
            }
            config.save(folder)?;
            println!("Added {name}.");
        }
        ConfigCommand::Remove { name } => {
            config.pick(Some(&name))?;
            logout(folder, Some(&name))?;
            config.contexts.remove(&name);
            if config.current.as_deref() == Some(name.as_str()) {
                config.current = None;
            }
            config.save(folder)?;
            println!("Removed {name}.");
        }
    }
    Ok(0)
}

/// Commands that need a server.
fn act(api: &Api, command: Command, format: Format) -> Result<u8> {
    match command {
        Command::Whoami => {
            let me = api.get("/me")?;
            if format == Format::Json {
                println!("{}", output::json(&me));
                return Ok(0);
            }
            let via = match text(&me["via"], "kind").as_str() {
                "app" => format!(", as {}", text(&me["via"], "name")),
                "api_key" => format!(", with the API key {}", text(&me["via"], "name")),
                _ => String::new(),
            };
            println!(
                "{} ({}) on {}{via}",
                text(&me, "email"),
                text(&me, "role"),
                api.context
            );
        }
        Command::Get(args) => {
            let options = Options {
                filter: args.filter,
                ended: args.ended,
            };
            let items = kinds::fetch(api, args.kind, &args.names, &options)?;
            let shown = kinds::show(api, args.kind, &items, format, &options)?;
            if !shown.is_empty() {
                println!("{shown}");
            }
            if args.exit_code && !items.is_empty() {
                return Ok(Failure::FOUND);
            }
        }
        Command::Describe { kind, name } => {
            if format == Format::Json {
                println!("{}", output::json(&kinds::find_one(api, kind, &name)?));
            } else {
                println!("{}", kinds::describe(api, kind, &name)?);
            }
        }
        Command::Ack { ids } => acknowledge(api, &ids, "acknowledge", "acknowledged", format)?,
        Command::Unack { ids } => {
            acknowledge(api, &ids, "unacknowledge", "no longer acknowledged", format)?
        }
        Command::Silence(args) => silence(api, args, format)?,
        Command::End { what } => {
            for id in silence_ids(&what)? {
                api.call("POST", &format!("/silences/{id}/end"), None)?;
                print_done(format, &format!("silence/{id}"), "ended");
            }
        }
        Command::Approve {
            kind: ApproveKind::Host,
            name,
        } => {
            let all = kinds::hosts(api, None)?;
            let host = kinds::find_host(&all, &name)?;
            api.call(
                "POST",
                &format!("/hosts/{}/approve", text(host, "id")),
                None,
            )?;
            print_done(
                format,
                &format!("host/{}", text(host, "hostname")),
                "approved",
            );
        }
        Command::Open { kind, name } => {
            let path = page(api, kind, name.as_deref())?;
            let url = api.server.url(&path);
            eprintln!("Opening {url}");
            webbrowser::open(&url).with_context(|| format!("opening {url}"))?;
        }
        Command::Api {
            method,
            path,
            fields,
            data,
        } => {
            let method = method.to_ascii_uppercase();
            let path = path.strip_prefix("/api/v1").unwrap_or(&path).to_string();
            let path = if path.starts_with('/') {
                path
            } else {
                format!("/{path}")
            };
            let pairs: Vec<(String, String)> = fields
                .iter()
                .map(|field| {
                    field
                        .split_once('=')
                        .map(|(name, value)| (name.to_string(), value.to_string()))
                        .ok_or_else(|| Failure::usage(format!("{field:?} isn't name=value")))
                })
                .collect::<Result<_, _>>()?;
            let reads = method == "GET" || method == "DELETE";
            let data = data
                .map(|data| {
                    serde_json::from_str::<Value>(&data)
                        .map_err(|error| Failure::usage(format!("--data isn't JSON: {error}")))
                })
                .transpose()?;
            let (path, body) = match (reads, data) {
                (true, data) if !pairs.is_empty() => {
                    // Added to any query the path already has.
                    let query = serde_urlencoded::to_string(&pairs).unwrap_or_default();
                    let joint = if path.contains('?') { '&' } else { '?' };
                    (format!("{path}{joint}{query}"), data)
                }
                (false, Some(_)) if !pairs.is_empty() => {
                    return Err(Failure::usage(
                        "Give the body as name=value pairs or as --data, not both",
                    )
                    .into());
                }
                (false, None) if !pairs.is_empty() => {
                    let object: serde_json::Map<String, Value> = pairs
                        .into_iter()
                        .map(|(name, value)| (name, Value::String(value)))
                        .collect();
                    (path, Some(Value::Object(object)))
                }
                (_, data) => (path, data),
            };
            let answer = api.call(&method, &path, body.as_ref())?;
            if !answer.is_null() {
                println!("{}", output::json(&answer));
            }
        }
        Command::Login(_)
        | Command::Logout { .. }
        | Command::Config(_)
        | Command::Completion { .. } => {
            unreachable!("handled without a server")
        }
    }
    Ok(0)
}

fn print_done(format: Format, name: &str, done: &str) {
    match format {
        Format::Name => println!("{name}"),
        Format::Json => println!("{}", json!({ "name": name, "done": done })),
        Format::Table | Format::Wide => println!("{name} {done}"),
    }
}

fn acknowledge(api: &Api, ids: &[i64], action: &str, done: &str, format: Format) -> Result<()> {
    for id in ids {
        api.call("POST", &format!("/alerts/{id}/{action}"), None)?;
        print_done(format, &format!("alert/{id}"), done);
    }
    Ok(())
}

/// Silences from `silence 12 13` or `silence/12 silence/13`.
fn silence_ids(what: &[String]) -> Result<Vec<i64>, Failure> {
    let words: Vec<&str> = match what.first().map(String::as_str) {
        Some("silence" | "silences" | "sil") => what[1..].iter().map(String::as_str).collect(),
        _ => what.iter().map(String::as_str).collect(),
    };
    if words.is_empty() {
        return Err(Failure::usage(
            "Say which silence, as maxnines end silence 12",
        ));
    }
    words
        .iter()
        .map(|word| {
            word.strip_prefix("silence/")
                .unwrap_or(word)
                .parse()
                .map_err(|_| {
                    Failure::usage(format!(
                        "{word:?} isn't a silence: use its number, or silence/12"
                    ))
                })
        })
        .collect()
}

fn silence(api: &Api, args: SilenceArgs, format: Format) -> Result<()> {
    let mut body = json!({ "reason": args.reason, "duration_secs": args.duration.as_secs() });
    let named_any =
        args.rule.is_some() || args.filter.is_some() || args.series.is_some() || args.all_alerts;
    match (args.kind, args.name.as_deref()) {
        (Some(_), _) if named_any => {
            return Err(Failure::usage(
                "Silence an alert, host or check, or say --rule, --filter and --series, not both",
            )
            .into());
        }
        (Some(_), None) => {
            return Err(Failure::usage("Say which, as maxnines silence host web-1").into());
        }
        (Some(SilenceKind::Alert), Some(id)) => {
            let found = kinds::fetch(api, Kind::Alerts, &[id.to_string()], &Options::default())?;
            let alert = &found[0];
            // Every alert has a rule, even once it's deleted. Without one this would be
            // a silence for every rule on the host.
            let Some(rule) = alert["rule_id"].as_i64() else {
                return Err(Failure::refused(
                    "The server didn't say which rule that alert is from",
                )
                .into());
            };
            body["rule_id"] = json!(rule);
            let host = text(alert, "host_id");
            if host != "fleet" {
                body["filter"] = json!(format!("id={host}"));
            }
            let series = text(alert, "series");
            if !series.is_empty() {
                body["series"] = json!(series);
            }
        }
        (Some(SilenceKind::Host), Some(name)) => {
            let all = kinds::hosts(api, None)?;
            let host = kinds::find_host(&all, name)?;
            body["filter"] = json!(format!("id={}", text(host, "id")));
        }
        (Some(SilenceKind::Check), Some(name)) => {
            let found = kinds::fetch(api, Kind::Checks, &[name.to_string()], &Options::default())?;
            let check = &found[0];
            body["filter"] = json!(format!("id={}", text(check, "host_id")));
            body["series"] = json!(text(&check["check"], "name"));
        }
        (None, Some(_)) => {
            return Err(Failure::usage("Say what that is: alert, host or check").into());
        }
        (None, None) => {
            if !named_any {
                return Err(Failure::usage(
                    "Say what to silence: an alert, host or check, or --rule, --filter and --series, or --all-alerts",
                )
                .into());
            }
            if let Some(rule) = &args.rule {
                body["rule_id"] = json!(rule_id(api, rule)?);
            }
            if let Some(filter) = args.filter {
                body["filter"] = json!(filter);
            }
            if let Some(series) = args.series {
                body["series"] = json!(series);
            }
            if args.all_alerts {
                body["all_alerts"] = json!(true);
            }
        }
    }
    let created = api.call("POST", "/silences", Some(&body))?;
    let name = format!("silence/{}", text(&created, "id"));
    match format {
        Format::Name => println!("{name}"),
        Format::Json => println!("{}", output::json(&created)),
        Format::Table | Format::Wide => println!(
            "{name} started, for {}",
            humantime::format_duration(args.duration)
        ),
    }
    Ok(())
}

/// An alert rule's ID, from its name or its ID.
fn rule_id(api: &Api, rule: &str) -> Result<i64> {
    let rules = api.get("/alert-rules")?;
    let matches: Vec<i64> = rules
        .as_array()
        .into_iter()
        .flatten()
        .filter(|candidate| text(candidate, "name") == rule || text(candidate, "id") == rule)
        .filter_map(|candidate| candidate["id"].as_i64())
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(Failure::not_found(format!("There's no alert rule called {rule:?}")).into()),
        _ => Err(Failure::not_found(format!(
            "More than one alert rule is called {rule:?}: use its ID"
        ))
        .into()),
    }
}

/// The page of the web interface something is on.
fn page(api: &Api, kind: Kind, name: Option<&str>) -> Result<String> {
    let Some(name) = name else {
        return Ok(match kind {
            Kind::Hosts => "/hosts",
            Kind::Alerts => "/alerts",
            Kind::Silences => "/alerts/silences",
            Kind::Checks => "/checks",
        }
        .to_string());
    };
    let item = &kinds::fetch(api, kind, &[name.to_string()], &Options::default())?[0];
    Ok(match kind {
        Kind::Hosts => format!("/hosts/{}", text(item, "id")),
        Kind::Alerts => format!("/hosts/{}", text(item, "host_id")),
        Kind::Silences => "/alerts/silences".to_string(),
        Kind::Checks => format!("/checks/{}", text(item, "id")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_read_in_their_units() {
        let secs = |text: &str| parse_duration(text).map(|length| length.as_secs());
        assert_eq!(secs("90s"), Ok(90));
        assert_eq!(secs("30m"), Ok(1800));
        assert_eq!(secs("2h30m"), Ok(9000));
        assert_eq!(secs("1d"), Ok(86_400));
        // Too long to count is refused, never wrapped round to something shorter.
        for bad in [
            "",
            "30",
            "m",
            "0m",
            "213503982334602d",
            "99999999999999999999s",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        assert_eq!(
            humantime::format_duration(parse_duration("2h30m").unwrap()).to_string(),
            "2h 30m"
        );
    }

    #[test]
    fn silences_to_end_are_read_either_way() {
        let words = |text: &str| text.split(' ').map(str::to_string).collect::<Vec<_>>();
        assert_eq!(silence_ids(&words("silence 12 13")).unwrap(), [12, 13]);
        assert_eq!(silence_ids(&words("silence/12")).unwrap(), [12]);
        assert_eq!(silence_ids(&words("12")).unwrap(), [12]);
        assert!(silence_ids(&words("silence")).is_err());
        assert!(silence_ids(&words("silence/x")).is_err());
    }

    #[test]
    fn the_commands_hang_together() {
        Cli::command().debug_assert();
    }
}
