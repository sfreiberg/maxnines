//! The admin commands. They go through the running server, which holds the agent
//! list and the metrics database, using the token kept in the main database.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
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

/// Where this machine reaches the server, even if it listens on all addresses.
fn local_url(listen: SocketAddr) -> String {
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
    let base = local_url(config.listen);
    let token = admin_token(config)?;

    let mut response = ureq::get(format!("{base}{BASE_PATH}/agents"))
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
    let base = local_url(config.listen);
    let token = admin_token(config)?;

    let mut response = ureq::get(format!("{base}{path}"))
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
    let base = local_url(config.listen);
    let token = admin_token(config)?;

    let result = ureq::post(format!("{base}{BASE_PATH}/agents/{id}/{action}"))
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
    let base = local_url(config.listen);
    let token = admin_token(config)?;

    let mut response = ureq::post(format!("{base}{BASE_PATH}/api-keys"))
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
    let base = local_url(config.listen);
    let token = admin_token(config)?;

    let result = ureq::delete(format!("{base}{BASE_PATH}/api-keys/{id}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_commands_reach_a_server_listening_on_all_addresses() {
        assert_eq!(
            local_url("0.0.0.0:9000".parse().unwrap()),
            "http://127.0.0.1:9000"
        );
        assert_eq!(local_url("[::]:9000".parse().unwrap()), "http://[::1]:9000");
        assert_eq!(
            local_url("10.0.0.1:9000".parse().unwrap()),
            "http://10.0.0.1:9000"
        );
    }
}
