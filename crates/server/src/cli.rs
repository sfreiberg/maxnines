//! The admin commands, which go through the running server because it holds the
//! only database connection.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::config::Config;
use crate::controllers::admin::{AgentView, read_token};
use crate::fact_history::{describe_history, format_time};
use crate::models::FactVersion;

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
    let token = read_token(&config.admin_token_file)?;

    let mut response = ureq::get(format!("{base}/admin/agents"))
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
    let token = read_token(&config.admin_token_file)?;

    let mut response = ureq::get(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| explain(error, &base))?;
    Ok(response.body_mut().read_to_string()?)
}

pub fn print_facts(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("/admin/agents/{id}/facts"))?;
    let view: Value = serde_json::from_str(&body).context("invalid server response")?;
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

pub fn print_facts_history(config: &Config, id: &str) -> Result<()> {
    let body = get_json(config, &format!("/admin/agents/{id}/facts/history"))?;
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
    let token = read_token(&config.admin_token_file)?;

    let result = ureq::post(format!("{base}/admin/agents/{id}/{action}"))
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
