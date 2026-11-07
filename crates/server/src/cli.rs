//! The admin commands. They go through the running server, which holds the agent
//! list and the metrics database, using the token kept in the main database.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde_json::Value;

use crate::config::Config;
use crate::controllers::api::{AgentView, BASE_PATH};
use crate::fact_history::{describe_history, format_time};
use crate::models::{Database, FactVersion};

/// Reads the admin token from the main database.
fn admin_token(config: &Config) -> Result<String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("reading the admin token")?;
    runtime.block_on(async {
        let database = Database::connect(&config.database.resolve_url()?).await?;
        database.admin_token().await
    })
}

/// Prints the admin token, for scripts that use the admin API.
pub fn print_admin_token(config: &Config) -> Result<()> {
    println!("{}", admin_token(config)?);
    Ok(())
}

/// Where this machine reaches the server, even if it listens on all addresses. With
/// HTTPS that's its public name, as that's what its certificate says.
fn server_url(config: &Config) -> String {
    if config.tls.is_some() {
        let audience = config.audience();
        let host = audience.strip_prefix("wss://").unwrap_or(&audience);
        let host = host.split('/').next().unwrap_or(host);
        return format!("https://{host}");
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
            anyhow::anyhow!("the server refused the admin token")
        }
        ureq::Error::StatusCode(404) => anyhow::anyhow!("no agent with that ID"),
        ureq::Error::StatusCode(code) => anyhow::anyhow!("the server returned status {code}"),
        other => anyhow::Error::new(other).context(format!("is the server running at {url}?")),
    }
}

pub fn print_agents(config: &Config) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let mut response = client(config)?
        .get(format!("{base}{BASE_PATH}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    let body = response.body_mut().read_to_string()?;
    let agents: Vec<AgentView> = serde_json::from_str(&body).context("invalid server response")?;

    if agents.is_empty() {
        println!("no agents yet");
        return Ok(());
    }

    println!(
        "{:<32}  {:<9} {:<8} {:<24} HOST",
        "ID", "STATE", "ONLINE", "DECIDED BY"
    );
    for view in agents {
        let agent = view.agent;
        println!(
            "{:<32}  {:<9} {:<8} {:<24} {}",
            agent.id,
            agent.state.as_str(),
            if view.online { "yes" } else { "no" },
            agent.decided_by.as_deref().unwrap_or("-"),
            agent.host,
        );
    }
    Ok(())
}

fn get_json(config: &Config, path: &str) -> Result<String> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let mut response = client(config)?
        .get(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    Ok(response.body_mut().read_to_string()?)
}

pub fn print_facts(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("{BASE_PATH}/agents/{id}/facts"))?;
    let view: Value = serde_json::from_str(&body).context("invalid server response")?;
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

pub fn print_facts_history(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("{BASE_PATH}/agents/{id}/facts/history"))?;
    let history: Vec<FactVersion> =
        serde_json::from_str(&body).context("invalid server response")?;

    if history.is_empty() {
        println!("no facts reported yet");
    }
    for (time, changes) in describe_history(&history) {
        println!("{}", format_time(time));
        for change in changes {
            println!("  {change}");
        }
    }
    Ok(())
}

pub fn change_agent(config: &Config, id: &str, action: &str) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let result = client(config)?
        .post(format!("{base}{BASE_PATH}/agents/{id}/{action}"))
        .header("Authorization", format!("Bearer {token}"))
        .send_empty();
    match result {
        Ok(_) => {
            println!("{action}: {id}");
            Ok(())
        }
        Err(error) => bail!(explain(error, &base)),
    }
}

pub fn print_api_keys(config: &Config) -> Result<()> {
    let body = get_json(config, &format!("{BASE_PATH}/api-keys"))?;
    let keys: Vec<Value> = serde_json::from_str(&body).context("invalid server response")?;
    if keys.is_empty() {
        println!("no API keys yet");
        return Ok(());
    }

    let now = crate::metrics::now_ms();
    println!(
        "{:<6} {:<16} {:<8} {:<20} NAME",
        "ID", "KEY", "STATE", "EXPIRES"
    );
    for key in keys {
        let expires = key["expires_ms"].as_i64();
        let state = if !key["revoked_ms"].is_null() {
            "revoked"
        } else if expires.is_some_and(|time| now >= time) {
            "expired"
        } else {
            "active"
        };
        println!(
            "{:<6} {:<16} {:<8} {:<20} {}",
            key["id"],
            format!("{}...", key["hint"].as_str().unwrap_or_default()),
            state,
            expires
                .and_then(|time| u64::try_from(time).ok())
                .map_or_else(|| "never".to_string(), format_time),
            key["name"].as_str().unwrap_or_default(),
        );
    }
    Ok(())
}

pub fn create_api_key(config: &Config, name: &str, expires_in: Option<Duration>) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let mut response = client(config)?
        .post(format!("{base}{BASE_PATH}/api-keys"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(
            serde_json::json!({
                "name": name,
                "expires_in_secs": expires_in.map(|time| time.as_secs()),
            })
            .to_string(),
        )
        .map_err(|error| explain(error, &base))?;
    let body = response.body_mut().read_to_string()?;
    let created: Value = serde_json::from_str(&body).context("invalid server response")?;
    let key = created["key"].as_str().context("invalid server response")?;

    println!("{key}");
    eprintln!("Save this now. It can't be shown again.");
    Ok(())
}

pub fn revoke_api_key(config: &Config, id: i64) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let result = client(config)?
        .delete(format!("{base}{BASE_PATH}/api-keys/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .call();
    match result {
        Ok(_) => {
            println!("revoked: {id}");
            Ok(())
        }
        Err(ureq::Error::StatusCode(404)) => bail!("no API key with that ID"),
        Err(error) => bail!(explain(error, &base)),
    }
}

/// What the server said was wrong, or a plain explanation if it didn't say.
fn users_error(error: ureq::Error, url: &str) -> anyhow::Error {
    match error {
        ureq::Error::StatusCode(404) => anyhow::anyhow!("no user with that ID"),
        ureq::Error::StatusCode(409) => {
            anyhow::anyhow!(
                "refused: this would leave nobody able to sign in, or they aren't disabled"
            )
        }
        ureq::Error::StatusCode(422) => anyhow::anyhow!("that isn't a valid address and name"),
        other => explain(other, url),
    }
}

pub fn print_users(config: &Config) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let mut response = client(config)?
        .get(format!("{base}{BASE_PATH}/users"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    let body = response.body_mut().read_to_string()?;
    let users: Vec<Value> = serde_json::from_str(&body).context("invalid server response")?;

    for user in users {
        let status = if !user["disabled_ms"].is_null() {
            "disabled"
        } else if user["has_password"] == true {
            "active"
        } else {
            "invited"
        };
        println!(
            "{}  {status:<8}  {}  {}",
            user["id"],
            user["email"].as_str().unwrap_or_default(),
            user["name"].as_str().unwrap_or_default(),
        );
    }
    Ok(())
}

/// Prints the link, the only time it can be seen.
fn print_link(body: &str) -> Result<()> {
    let answer: Value = serde_json::from_str(body).context("invalid server response")?;
    let url = answer["setup_url"]
        .as_str()
        .context("invalid server response")?;
    println!("{url}");
    eprintln!("Open this to set a password. It works once and lasts 7 days.");
    Ok(())
}

pub fn create_user(config: &Config, email: &str, name: &str) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let result = client(config)?
        .post(format!("{base}{BASE_PATH}/users"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(serde_json::json!({ "email": email, "name": name }).to_string());
    let mut response = match result {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(409)) => bail!("there's already a user with that address"),
        Err(error) => bail!(users_error(error, &base)),
    };
    print_link(&response.body_mut().read_to_string()?)
}

pub fn print_setup_link(config: &Config, id: i64) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    let mut response = client(config)?
        .post(format!("{base}{BASE_PATH}/users/{id}/setup-link"))
        .header("Authorization", format!("Bearer {token}"))
        .send_empty()
        .map_err(|error| users_error(error, &base))?;
    print_link(&response.body_mut().read_to_string()?)
}

/// `action` is the last part of the API's address for it.
pub fn change_user(config: &Config, id: i64, action: &str) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    client(config)?
        .post(format!("{base}{BASE_PATH}/users/{id}/{action}"))
        .header("Authorization", format!("Bearer {token}"))
        .send_empty()
        .map_err(|error| users_error(error, &base))?;
    println!("{action}d: {id}");
    Ok(())
}

pub fn delete_user(config: &Config, id: i64) -> Result<()> {
    let base = server_url(config);
    let token = admin_token(config)?;

    client(config)?
        .delete(format!("{base}{BASE_PATH}/users/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| users_error(error, &base))?;
    println!("deleted: {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_for(settings: &str) -> String {
        let text = format!("{settings}\nmetrics \"duckdb\" {{\n  path = \"x\"\n}}\n");
        server_url(&Config::parse(&text).unwrap())
    }

    #[test]
    fn a_server_on_every_address_is_reached_on_this_machine() {
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
