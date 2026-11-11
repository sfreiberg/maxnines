//! The command-line tools. Users and API keys are managed in the main database
//! itself, which is how the first user gets in before anyone can sign in. Agents
//! live in the running server's memory, so those commands go through its API with
//! an API key, as any script would.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono_tz::Tz;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde_json::Value;

use crate::audit::{self, Acting, Actor};
use crate::config::Config;
use crate::controllers::api::{BASE_PATH, HostView};
use crate::fact_history::describe_history;
use crate::metrics::now_ms;
use crate::models::{
    Database, FactVersion, UserChange, check_api_key_name, check_new_user, expiry_after,
};
use crate::notifier::web_url;
use crate::roles::Role;
use crate::times::format_time;

/// Where scripts and these commands find a key for the running server's API.
const API_KEY_VARIABLE: &str = "MAXNINES_API_KEY";

/// Runs database work to completion, as these commands aren't async themselves.
fn with_database<T, Work, Done>(config: &Config, work: Work) -> Result<T>
where
    Work: FnOnce(Database) -> Done,
    Done: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting")?;
    // Whoever ran it, as the system says, for the audit log.
    let account = ["USER", "USERNAME"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
    let acting = Acting {
        actor: Actor::CommandLine { account },
        via: None,
        source: None,
    };
    runtime.block_on(audit::acting(acting, async {
        let database = Database::connect(&config.database.resolve_url()?).await?;
        work(database).await
    }))
}

fn api_key() -> Result<String> {
    std::env::var(API_KEY_VARIABLE)
        .ok()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .with_context(|| {
            format!(
                "set {API_KEY_VARIABLE} to a key for the running server, which \
                 `maxnines-server api-keys create` makes"
            )
        })
}

/// Where this host reaches the server, even if it listens on all addresses. With
/// HTTPS that's its public name, as that's what its certificate says.
fn server_url(config: &Config) -> String {
    if config.tls.is_some() {
        let audience = config.audience();
        let hostname = audience.strip_prefix("wss://").unwrap_or(&audience);
        let hostname = hostname.split('/').next().unwrap_or(hostname);
        return format!("https://{hostname}");
    }
    let listen = config.listen;
    let mut address = listen;
    if address.ip().is_unspecified() {
        address.set_ip(if listen.is_ipv4() {
            [127, 0, 0, 1].into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    format!("http://{address}")
}

/// Checks the server's certificate as anything else would: against the public
/// authorities, or the one named in the config for a private certificate.
fn client(config: &Config) -> Result<ureq::Agent> {
    let ca_file = config.tls.as_ref().and_then(|tls| tls.ca_file.as_deref());
    let mut tls = ureq::tls::TlsConfig::builder();
    if let Some(path) = ca_file {
        let roots = CertificateDer::pem_file_iter(path)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .with_context(|| format!("reading CA file {}", path.display()))?;
        let roots = roots
            .iter()
            .map(|root| ureq::tls::Certificate::from_der(root.as_ref()).to_owned())
            .collect();
        tls = tls.root_certs(ureq::tls::RootCerts::Specific(Arc::new(roots)));
    }
    let config = ureq::Agent::config_builder()
        .tls_config(tls.build())
        .build();
    Ok(ureq::Agent::new_with_config(config))
}

fn explain(error: ureq::Error, url: &str) -> anyhow::Error {
    match error {
        ureq::Error::StatusCode(401) => {
            anyhow::anyhow!("the server refused the API key in {API_KEY_VARIABLE}")
        }
        ureq::Error::StatusCode(404) => anyhow::anyhow!("no host with that ID"),
        ureq::Error::StatusCode(code) => anyhow::anyhow!("the server returned status {code}"),
        other => anyhow::Error::new(other).context(format!("is the server running at {url}?")),
    }
}

fn get_json(config: &Config, path: &str) -> Result<String> {
    let base = server_url(config);
    let key = api_key()?;

    let mut response = client(config)?
        .get(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {key}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    Ok(response.body_mut().read_to_string()?)
}

pub fn print_hosts(config: &Config) -> Result<()> {
    let body = get_json(config, &format!("{BASE_PATH}/hosts"))?;
    let hosts: Vec<HostView> = serde_json::from_str(&body).context("invalid server response")?;

    if hosts.is_empty() {
        println!("no hosts yet");
        return Ok(());
    }

    println!(
        "{:<32}  {:<9} {:<8} {:<24} HOST",
        "ID", "STATE", "ONLINE", "DECIDED BY"
    );
    for view in hosts {
        let host = view.host;
        println!(
            "{:<32}  {:<9} {:<8} {:<24} {}",
            host.id,
            host.state.as_str(),
            if view.online { "yes" } else { "no" },
            host.decided_by.as_deref().unwrap_or("-"),
            host.hostname,
        );
    }
    Ok(())
}

pub fn print_facts(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("{BASE_PATH}/hosts/{id}/facts"))?;
    let view: Value = serde_json::from_str(&body).context("invalid server response")?;
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

pub fn print_facts_history(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("{BASE_PATH}/hosts/{id}/facts/history"))?;
    let history: Vec<FactVersion> =
        serde_json::from_str(&body).context("invalid server response")?;

    if history.is_empty() {
        println!("no facts reported yet");
    }
    for (time, changes) in describe_history(&history) {
        println!("{}", format_time(time, Tz::UTC));
        for change in changes {
            println!("  {change}");
        }
    }
    Ok(())
}

pub fn change_host(config: &Config, id: &str, action: &str) -> Result<()> {
    let base = server_url(config);
    let key = api_key()?;

    let result = client(config)?
        .post(format!("{base}{BASE_PATH}/hosts/{id}/{action}"))
        .header("Authorization", format!("Bearer {key}"))
        .send_empty();
    match result {
        Ok(_) => {
            println!("{action}: {id}");
            Ok(())
        }
        Err(error) => bail!(explain(error, &base)),
    }
}

pub fn delete_host(config: &Config, id: &str) -> Result<()> {
    let base = server_url(config);
    let key = api_key()?;

    let result = client(config)?
        .delete(format!("{base}{BASE_PATH}/hosts/{id}"))
        .header("Authorization", format!("Bearer {key}"))
        .call();
    match result {
        Ok(_) => {
            println!("deleted: {id}");
            Ok(())
        }
        Err(ureq::Error::StatusCode(409)) => {
            bail!("revoke the host before deleting it: maxnines-server hosts revoke {id}")
        }
        Err(error) => bail!(explain(error, &base)),
    }
}

pub fn print_api_keys(config: &Config) -> Result<()> {
    let keys = with_database(
        config,
        |database| async move { database.list_api_keys().await },
    )?;
    if keys.is_empty() {
        println!("no API keys yet");
        return Ok(());
    }

    let now = now_ms();
    println!(
        "{:<6} {:<16} {:<8} {:<20} {:<30} {:<9} NAME",
        "ID", "KEY", "STATE", "EXPIRES", "OWNER", "ROLE"
    );
    for key in keys {
        let state = if key.revoked_ms.is_some() {
            "revoked"
        } else if key.has_expired(now) {
            "expired"
        } else {
            "active"
        };
        println!(
            "{:<6} {:<16} {:<8} {:<20} {:<30} {:<9} {}",
            key.id,
            format!("{}...", key.hint),
            state,
            key.expires_ms
                .and_then(|time| u64::try_from(time).ok())
                .map_or_else(|| "never".to_string(), |time| format_time(time, Tz::UTC)),
            key.owner,
            key.role.as_str(),
            key.name,
        );
    }
    Ok(())
}

/// Makes a key that acts as the user with this email address.
pub fn create_api_key(
    config: &Config,
    name: &str,
    owner: &str,
    role: Option<Role>,
    expires_in: Option<Duration>,
) -> Result<()> {
    let name = name.trim();
    check_api_key_name(name)?;
    let now = now_ms();
    let expires_ms = expires_in
        .map(|time| expiry_after(time.as_secs(), now))
        .transpose()?;
    let (_, key) = with_database(config, |database| async move {
        let owner = database
            .active_user_by_email(owner)
            .await?
            .with_context(|| format!("no user who can sign in has the address {owner}"))?;
        let role = role.unwrap_or(owner.role);
        database
            .create_api_key(name, owner.id, role, expires_ms, now)
            .await
    })?;

    println!("{key}");
    eprintln!("Save this now. It can't be shown again.");
    Ok(())
}

pub fn revoke_api_key(config: &Config, id: i64) -> Result<()> {
    let revoked = with_database(config, |database| async move {
        database.revoke_api_key(id, now_ms()).await
    })?;
    if !revoked {
        bail!("no API key with that ID");
    }
    println!("revoked: {id}");
    Ok(())
}

pub fn print_users(config: &Config) -> Result<()> {
    let users = with_database(
        config,
        |database| async move { database.list_users().await },
    )?;
    for user in users {
        let status = if user.disabled_ms.is_some() {
            "disabled"
        } else if user.has_password {
            "active"
        } else {
            "invited"
        };
        println!(
            "{}  {status:<8}  {:<9}  {}  {}",
            user.id,
            user.role.as_str(),
            user.email,
            user.name
        );
    }
    Ok(())
}

/// Prints the link, the only time it can be seen.
fn print_link(config: &Config, token: &str) {
    let site = web_url(config.audience()).unwrap_or_default();
    println!("{site}/setup/{token}");
    eprintln!("Open this to set a password. It works once and lasts 7 days.");
}

pub fn create_user(config: &Config, email: &str, name: &str, role: Role) -> Result<()> {
    let (email, name) = check_new_user(email, name)?;
    let created = with_database(config, |database| async move {
        database.create_user(&email, &name, role, now_ms()).await
    })?;
    let Some((_, token)) = created else {
        bail!("there's already a user with that address");
    };
    print_link(config, &token);
    Ok(())
}

pub fn print_setup_link(config: &Config, id: i64) -> Result<()> {
    let token = with_database(config, |database| async move {
        database.new_setup_link(id, now_ms()).await
    })?;
    let Some(token) = token else {
        bail!("no user with that ID");
    };
    print_link(config, &token);
    Ok(())
}

/// Says what stood in the way of a change, in the words the page uses.
fn changed(change: UserChange, done: &str) -> Result<()> {
    match change {
        UserChange::Done => {
            println!("{done}");
            Ok(())
        }
        UserChange::NoSuchUser => bail!("no user with that ID"),
        UserChange::LastAdmin => bail!("refused: this would leave no admin able to sign in"),
        UserChange::StillEnabled => bail!("refused: only a disabled user can be deleted"),
    }
}

pub fn reset_two_factor(config: &Config, id: i64) -> Result<()> {
    let found = with_database(config, |database| async move {
        database.turn_off_two_factor(id).await
    })?;
    if !found {
        bail!("no user with that ID");
    }
    println!("two-factor is off for {id}, until they set it up again");
    Ok(())
}

pub fn set_role(config: &Config, id: i64, role: Role) -> Result<()> {
    let change = with_database(config, |database| async move {
        database.set_role(id, role).await
    })?;
    changed(change, &format!("{id} is now {}", role.as_str()))
}

/// `action` is `disable` or `enable`.
pub fn change_user(config: &Config, id: i64, action: &str) -> Result<()> {
    let change = with_database(config, |database| async move {
        match action {
            "disable" => database.disable_user(id, now_ms()).await,
            _ => database.enable_user(id).await,
        }
    })?;
    changed(change, &format!("{action}d: {id}"))
}

pub fn delete_user(config: &Config, id: i64) -> Result<()> {
    let change = with_database(
        config,
        |database| async move { database.delete_user(id).await },
    )?;
    changed(change, &format!("deleted: {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_for(settings: &str) -> String {
        let text = format!("{settings}\nmetrics \"duckdb\" {{\n  path = \"x\"\n}}\n");
        server_url(&Config::parse(&text).unwrap())
    }

    #[test]
    fn a_server_on_every_address_is_reached_on_this_host() {
        assert_eq!(
            url_for(r#"listen = "0.0.0.0:9000""#),
            "http://127.0.0.1:9000"
        );
        assert_eq!(url_for(r#"listen = "[::]:9000""#), "http://[::1]:9000");
        assert_eq!(
            url_for(r#"listen = "10.0.0.1:9000""#),
            "http://10.0.0.1:9000"
        );
    }

    #[test]
    fn a_server_with_https_is_reached_by_the_name_on_its_certificate() {
        let settings = r#"
            listen = "0.0.0.0:443"
            public_url = "wss://maxnines.example.com/ws"
            tls {
              certificate_file = "a.crt"
              key_file = "a.key"
            }
        "#;
        assert_eq!(url_for(settings), "https://maxnines.example.com");
    }

    #[test]
    fn a_port_in_the_public_address_is_kept() {
        let settings = r#"
            public_url = "wss://maxnines.example.com:8443/ws"
            tls {
              certificate_file = "a.crt"
              key_file = "a.key"
            }
        "#;
        assert_eq!(url_for(settings), "https://maxnines.example.com:8443");
    }
}
