//! Talking to the server's API and pages.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use ureq::Agent;

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
    pub fn new(base: String, token: String) -> Self {
        let client = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_LIMIT))
            .build()
            .into();
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
            bail!("the server didn't accept the admin token");
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
        self.post(&format!("/api/v1/agents/{id}/approve"))
    }

    pub fn revoke(&self, id: &str) -> Result<()> {
        self.post(&format!("/api/v1/agents/{id}/revoke"))
    }

    /// The first config rule, for changing and putting back.
    pub fn first_rule(&self) -> Result<(i64, Value)> {
        let rules = self.get_json("/api/v1/rules")?;
        let id = rules[0]["id"]
            .as_i64()
            .context("the server has no config rules")?;
        let mut rule = self.get_json(&format!("/api/v1/rules/{id}"))?;
        if let Some(fields) = rule.as_object_mut() {
            fields.remove("id");
        }
        Ok((id, rule))
    }

    pub fn save_rule(&self, id: i64, rule: &Value) -> Result<()> {
        let path = format!("/api/v1/rules/{id}");
        let response = self
            .client
            .put(format!("{}{path}", self.base))
            .header("Authorization", self.bearer())
            .header("Content-Type", "application/json")
            .send(rule.to_string())
            .with_context(|| format!("saving {path}"))?;
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
            .header("Accept-Encoding", "gzip")
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
