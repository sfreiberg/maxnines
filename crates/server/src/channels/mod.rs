//! Where notifications go. Each kind of channel is a [`ChannelType`], with its own
//! checks, message and way of sending in a file of its own. [`ChannelKind`] is what's
//! stored and what the API takes, and [`of`] finds what does the work for each.

pub mod alertops;
pub mod custom_webhook;
mod discord;
pub mod email;
mod on_call;
pub mod pagerduty;
pub mod resend;
mod signl4;
pub mod slack;
mod teams;
pub mod telegram;
mod webhook;

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::http::Uri;
use serde_json::Value;
use ureq::unversioned::multipart::Part;

use crate::alerting::{Channel, ChannelInput, ChannelKind};
use crate::notifier::{Notice, Senders};

/// How long one request to a service can take.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// What a chart is called when it's sent as a file.
const CHART_FILE: &str = "chart.png";

/// What one kind of channel does differently from the rest.
#[async_trait::async_trait]
pub trait ChannelType: Send + Sync {
    /// What the pages call it.
    fn name(&self) -> &'static str;

    /// Checks a channel's own settings before they're saved. What every channel
    /// needs, such as a name, is checked before this. Errors end up on the page, so
    /// they never repeat a secret.
    fn check(&self, channel: &ChannelInput) -> Result<()>;

    /// Enough of the destination to recognize it by.
    fn preview(&self, target: &str) -> String {
        target.to_string()
    }

    /// Whether the destination works like a password, so it's never shown again.
    fn hides_target(&self) -> bool {
        false
    }

    /// Whether it needs a token beside its destination.
    fn has_credential(&self) -> bool {
        false
    }

    /// Whether it takes an app-level token too, for buttons.
    fn takes_app_token(&self) -> bool {
        false
    }

    /// Whether the service keeps after people itself until someone responds, so it's
    /// never sent reminders.
    fn is_on_call(&self) -> bool {
        false
    }

    /// Whether it sends email, so it has a from address and maybe a mail server.
    fn sends_mail(&self) -> bool {
        false
    }

    /// Whether an alert starting or getting worse goes with a chart.
    fn shows_charts(&self) -> bool {
        false
    }

    /// Sends one notification, and gives what the service called it if that matters
    /// later, such as a message to reply to when the alert ends.
    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        reply_to: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>>;
}

/// Every kind, in the order the pages offer them. A kind has to be here to be
/// read back from what's stored.
pub const ALL: [ChannelKind; 11] = [
    ChannelKind::Webhook,
    ChannelKind::CustomWebhook,
    ChannelKind::Email,
    ChannelKind::Resend,
    ChannelKind::Discord,
    ChannelKind::Slack,
    ChannelKind::Teams,
    ChannelKind::PagerDuty,
    ChannelKind::AlertOps,
    ChannelKind::Signl4,
    ChannelKind::Telegram,
];

/// What does the work for a kind of channel.
pub fn of(kind: ChannelKind) -> &'static dyn ChannelType {
    match kind {
        ChannelKind::Webhook => &webhook::Webhook,
        ChannelKind::CustomWebhook => &custom_webhook::CustomWebhook,
        ChannelKind::Email => &email::Email,
        ChannelKind::Resend => &resend::Resend,
        ChannelKind::Discord => &discord::Discord,
        ChannelKind::Slack => &slack::Slack,
        ChannelKind::Teams => &teams::Teams,
        ChannelKind::PagerDuty => &pagerduty::PagerDuty,
        ChannelKind::AlertOps => &alertops::AlertOps,
        ChannelKind::Signl4 => &signl4::Signl4,
        ChannelKind::Telegram => &telegram::Telegram,
    }
}

/// Runs a send that blocks, off the threads that run everything else.
async fn blocking<F>(send: F) -> Result<Option<String>>
where
    F: FnOnce() -> Result<Option<String>> + Send + 'static,
{
    tokio::task::spawn_blocking(send)
        .await
        .map_err(|_| anyhow!("sending failed unexpectedly"))?
}

/// The link to the alerts page, from the address people reach the server at.
pub(crate) fn alerts_link(web_url: &str) -> String {
    format!("{web_url}/alerts")
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(SEND_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("MaxNines/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

type Response = Result<ureq::http::Response<ureq::Body>, ureq::Error>;

/// Posts JSON, and gives the response whatever its status.
fn post(url: &str, body: &Value) -> Response {
    agent()
        .post(url.trim())
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
}

/// Posts a form with files in it, and gives the response whatever its status.
fn post_form(url: &str, form: ureq::unversioned::multipart::Form) -> Response {
    agent().post(url.trim()).send(form)
}

/// Errors are saved and shown, and a URL often holds a password, so they only
/// ever say what kind of failure it was. `who` is what to call the receiver.
fn explain_http(who: &str, error: &ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Timeout(_) => anyhow!("{who} timed out"),
        ureq::Error::HostNotFound => anyhow!("{who}'s host wasn't found"),
        ureq::Error::ConnectionFailed | ureq::Error::Io(_) => anyhow!("couldn't connect to {who}"),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => {
            anyhow!("{who}'s certificate wasn't accepted")
        }
        _ => anyhow!("the request to {who} failed"),
    }
}

/// Fails unless the receiver says it took it.
fn accepted(who: &str, response: Response) -> Result<()> {
    let response = response.map_err(|error| explain_http(who, &error))?;
    let status = response.status();
    if !status.is_success() {
        bail!("{who} returned status {}", status.as_u16());
    }
    Ok(())
}

fn post_json(who: &str, url: &str, body: &Value) -> Result<()> {
    accepted(who, post(url, body))
}

/// The chart as a part of a form.
fn chart_part(chart: &[u8]) -> Result<Part<'_>> {
    Part::bytes(chart)
        .file_name(CHART_FILE)
        .mime_str("image/png")
        .context("naming the chart's type")
}

/// The part of a URL that's safe to show. Errors don't repeat the URL.
fn url_host(url: &str) -> Result<String> {
    let uri: Uri = url
        .trim()
        .parse()
        .map_err(|_| anyhow!("the webhook URL isn't valid"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    ensure!(
        matches!(scheme, "http" | "https"),
        "the webhook URL must start with http:// or https://"
    );
    let host = uri.host().context("the webhook URL needs a host")?;
    Ok(format!("{scheme}://{host}"))
}

/// A URL that works like a password, shown as no more than where it goes.
fn url_preview(url: &str) -> String {
    url_host(url).map_or_else(|_| "Unknown".to_string(), |host| format!("{host}/…"))
}

#[cfg(test)]
pub(crate) mod testing {
    use crate::alerting::{Alert, Event, Severity};
    use crate::notifier::Notice;

    pub fn alert() -> Alert {
        Alert {
            id: 7,
            rule_id: Some(1),
            rule_name: "High CPU".to_string(),
            severity: Severity::Critical,
            agent_id: "abc".to_string(),
            host: "web-1".to_string(),
            series: "CPU".to_string(),
            value: Some(97.0),
            summary: "CPU usage on web-1 is 97%, above 90%".to_string(),
            started_ms: 1_000,
            resolved_ms: None,
            resolve_reason: None,
            acknowledged_by: None,
            acknowledged_ms: None,
        }
    }

    pub fn notice(event: Event, alert: Alert) -> Notice {
        let text = alert.summary.clone();
        Notice {
            id: 3,
            event,
            alert: Some(alert),
            text,
            chart: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_is_offered_once_and_named() {
        let mut names: Vec<&str> = ALL.iter().map(|kind| kind.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL.len());
        for kind in ALL {
            assert_eq!(ChannelKind::parse(kind.as_str()).unwrap(), kind);
            assert!(!of(kind).name().is_empty());
        }
    }

    #[test]
    fn only_secret_destinations_are_hidden() {
        for kind in ALL {
            let shown = of(kind).preview("https://hooks.example.com/secret-path");
            assert_eq!(
                of(kind).hides_target(),
                !shown.contains("secret"),
                "{}",
                kind.as_str()
            );
        }
    }
}
