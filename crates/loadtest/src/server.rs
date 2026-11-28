//! Talking to the server's API and pages.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use ureq::Agent;

use crate::trust::PrivateCa;

const REQUEST_LIMIT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct Server {
    client: Agent,
    base: String,
    token: String,
}

/// How one page load went.
pub struct PageLoad {
    pub took: Duration,
    pub bytes: usize,
    pub ok: bool,
}

impl Server {
    /// The server at `base`, its certificate checked against `ca` where given.
    pub fn new(base: String, token: String, ca: Option<&PrivateCa>) -> Self {
        let mut config = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_LIMIT));
        if let Some(ca) = ca {
            let tls = ureq::tls::TlsConfig::builder()
                .root_certs(ca.roots())
                .build();
            config = config.tls_config(tls);
        }
        let client = config.build().into();
        Self {
            client,
            base,
            token,
        }
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn get_json(&self, path: &str) -> Result<Value> {
        let mut response = self
            .client
            .get(format!("{}{path}", self.base))
            .header("Authorization", self.bearer())
            .call()
            .with_context(|| format!("asking the server for {path}"))?;
        let status = response.status();
        if status == 401 {
            bail!("the server didn't accept the API key");
        }
        if !status.is_success() {
            bail!("{path} gave {status}");
        }
        let text = response.body_mut().read_to_string()?;
        serde_json::from_str(&text).with_context(|| format!("reading {path}"))
    }

    fn post(&self, path: &str) -> Result<()> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .header("Authorization", self.bearer())
            .send_empty()
            .with_context(|| format!("posting to {path}"))?;
        if !response.status().is_success() {
            bail!("{path} gave {}", response.status());
        }
        Ok(())
    }

    pub fn stats(&self) -> Result<Value> {
        self.get_json("/api/v1/server")
    }

    pub fn approve(&self, id: &str) -> Result<()> {
        self.post(&format!("/api/v1/hosts/{id}/approve"))
    }

    pub fn revoke(&self, id: &str) -> Result<()> {
        self.post(&format!("/api/v1/hosts/{id}/revoke"))
    }

    /// Adds a config rule that applies over every other, as built-in rules can't be
    /// changed and someone's own shouldn't be, giving its ID to delete it by.
    /// One left by a run that was stopped before it could delete it goes first.
    pub fn add_rule_over_all(&self, name: &str, settings: Value) -> Result<i64> {
        let rules = self.get_json("/api/v1/rules")?;
        let rules = rules.as_array().cloned().unwrap_or_default();
        for left in rules.iter().filter(|rule| rule["name"] == name) {
            let id = left["id"].as_i64().context("a rule without an ID")?;
            self.delete_rule(id)?;
        }
        let highest = rules
            .iter()
            .filter(|rule| rule["name"] != name)
            .filter_map(|rule| rule["priority"].as_i64())
            .max()
            .unwrap_or(0);
        let rule = json!({ "name": name, "priority": highest + 1, "settings": settings });
        let path = "/api/v1/rules";
        let mut response = self
            .client
            .post(format!("{}{path}", self.base))
            .header("Authorization", self.bearer())
            .header("Content-Type", "application/json")
            .send(rule.to_string())
            .with_context(|| format!("posting to {path}"))?;
        if !response.status().is_success() {
            bail!("{path} gave {}", response.status());
        }
        let made: Value = serde_json::from_str(&response.body_mut().read_to_string()?)?;
        made["id"]
            .as_i64()
            .context("the server didn't say what the rule is")
    }

    pub fn delete_rule(&self, id: i64) -> Result<()> {
        let path = format!("/api/v1/rules/{id}");
        let response = self
            .client
            .delete(format!("{}{path}", self.base))
            .header("Authorization", self.bearer())
            .call()
            .with_context(|| format!("deleting {path}"))?;
        if !response.status().is_success() {
            bail!("{path} gave {}", response.status());
        }
        Ok(())
    }

    /// Loads a page the way a browser would, with compression.
    pub fn load_page(&self, path: &str) -> PageLoad {
        let began = Instant::now();
        let response = self
            .client
            .get(format!("{}{path}", self.base))
            .header("Authorization", self.bearer())
            .header("Accept-Encoding", "gzip")
            // Being sent to sign in is a failure, not a very fast page.
            .config()
            .max_redirects(0)
            .build()
            .call();
        let (bytes, ok) = match response {
            Ok(mut response) => {
                let status = response.status();
                let text = response.body_mut().read_to_vec();
                (
                    text.as_ref().map_or(0, Vec::len),
                    status.is_success() && text.is_ok(),
                )
            }
            Err(_) => (0, false),
        };
        PageLoad {
            took: began.elapsed(),
            bytes,
            ok,
        }
    }
}
