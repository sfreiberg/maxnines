//! Asking a server something over HTTP. Only a server that can't be reached is an
//! error here: what it answers, whatever the status, is for the caller to read.

use std::time::Duration;

use serde_json::Value;

use crate::failure::Failure;

/// What a request carries.
pub enum Body<'a> {
    None,
    Json(&'a Value),
    Form(&'a [(&'a str, &'a str)]),
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub text: String,
}

impl Answer {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The server's own words for what's wrong, as its API and OAuth both give them.
    pub fn error(&self) -> Option<String> {
        let json = self.json();
        json.get("error_description")
            .or_else(|| json.get("error"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// One that waits `timeout` at most for each answer.
    pub fn with_timeout(timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .user_agent(format!("maxnines/{}", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }

    pub fn send(
        &self,
        method: &str,
        url: &str,
        bearer: Option<&str>,
        body: Body<'_>,
    ) -> Result<Answer, Failure> {
        let mut request = ureq::http::Request::builder().method(method).uri(url);
        if let Some(token) = bearer {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let (content_type, text) = match body {
            Body::None if matches!(method, "GET" | "HEAD" | "DELETE") => (None, None),
            // A POST or PUT says it's empty, rather than sending an empty chunked body,
            // which some servers refuse or leave unread.
            Body::None => (None, Some(String::new())),
            Body::Json(value) => (Some("application/json"), Some(value.to_string())),
            Body::Form(fields) => (
                Some("application/x-www-form-urlencoded"),
                Some(serde_urlencoded::to_string(fields).unwrap_or_default()),
            ),
        };
        if let Some(content_type) = content_type {
            request = request.header("Content-Type", content_type);
        }
        let unreachable = |error: &dyn std::fmt::Display| {
            Failure::unreachable(format!("Couldn't reach {}: {error}", origin(url)))
        };
        let response = match text {
            Some(text) => {
                let request = request.body(text).map_err(|error| unreachable(&error))?;
                self.agent.run(request)
            }
            None => {
                let request = request.body(()).map_err(|error| unreachable(&error))?;
                self.agent.run(request)
            }
        };
        let mut response = response.map_err(|error| unreachable(&error))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|error| unreachable(&error))?;
        Ok(Answer { status, text })
    }
}

/// The scheme, host and port of a URL, for saying where couldn't be reached.
fn origin(url: &str) -> &str {
    let start = url.find("://").map_or(0, |at| at + 3);
    let end = url[start..].find('/').map_or(url.len(), |at| start + at);
    &url[..end]
}
