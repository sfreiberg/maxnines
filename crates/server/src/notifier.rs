//! Delivers notifications from the queue. Deliveries are at least once: a crash
//! between sending and saving sends it again, so webhooks carry an ID to spot that.

use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::FutureExt;
use hyper_rustls::HttpsConnectorBuilder;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::Serialize;
use serde_json::{Value, json};
use slack_morphism::api::{
    SlackApiChatPostMessageRequest, SlackApiChatUpdateRequest, SlackApiFilesComplete,
    SlackApiFilesCompleteUploadExternalRequest, SlackApiFilesGetUploadUrlExternalRequest,
    SlackApiFilesUploadViaUrlRequest,
};
use slack_morphism::errors::SlackClientError;
use slack_morphism::prelude::{
    SlackActionBlockElement, SlackActionsBlock, SlackBlock, SlackBlockButtonElement,
    SlackBlockButtonStyle, SlackBlockMarkDownText, SlackBlockPlainText, SlackClientHyperConnector,
    SlackClientHyperHttpsConnector, SlackContextBlock, SlackContextBlockElement, SlackFileIdOrUrl,
    SlackImageBlock, SlackImageUrlOrFile, SlackSectionBlock,
};
use slack_morphism::{
    SlackActionId, SlackApiToken, SlackApiTokenValue, SlackChannelId, SlackClient,
    SlackClientHttpConnector, SlackClientSession, SlackFileId, SlackMessageAttachment,
    SlackMessageContent, SlackTs,
};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, timeout};
use tracing::{error, info, warn};
use ureq::unversioned::multipart::{Form, Part};

use crate::alert_charts::ChartSources;
use crate::alerting::{Alert, Channel, ChannelKind, Delivery, Event, Severity, recipients};
use crate::config::{EmailConfig, EmailSecurity};
use crate::metrics::now_ms;
use crate::models::Database;
use crate::registration::short_id;
use crate::remote_checks::FLEET_AGENT_ID;
use crate::silences::ActiveSilences;

/// How often the queue is checked.
const INTERVAL: Duration = Duration::from_secs(5);

/// How many deliveries run at once, which also limits how many a pass can take.
const BATCH_SIZE: usize = 16;

/// How long one delivery can take.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// What a chart is called when it's sent as a file.
const CHART_FILE: &str = "chart.png";

/// Keeps a message well inside what Teams takes, which counts the card's markup too.
const TEAMS_MAX_CHARS: usize = 3000;

/// The longest message Discord accepts.
const DISCORD_MAX_CHARS: usize = 2000;

/// Where PagerDuty takes events.
const PAGERDUTY_EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";
/// The longest summary PagerDuty accepts.
const PAGERDUTY_MAX_SUMMARY_CHARS: usize = 1024;
/// Where Telegram's bot API lives.
const TELEGRAM_API_URL: &str = "https://api.telegram.org";

/// Ties a test's two steps together.
const TEST_INCIDENT_ID: &str = "maxnines-test";

const FIRST_RETRY_MS: i64 = 30_000;
const LONGEST_RETRY_MS: i64 = 30 * 60_000;

/// After this, a notification is too old to be useful and shows as failed.
const GIVE_UP_AFTER_MS: i64 = 24 * 3_600_000;

/// Doubles each time, up to a limit.
fn retry_delay_ms(attempts: i32) -> i64 {
    let doublings = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or(0)
        .min(16);
    (FIRST_RETRY_MS << doublings).min(LONGEST_RETRY_MS)
}

/// What a notification does to an incident in an on-call service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Incident {
    Open,
    Close,
}

/// What a notification says, in the form every channel starts from.
#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    /// The same for every attempt, so a receiver can spot a repeat.
    pub id: i64,
    pub event: Event,
    pub alert: Option<Alert>,
    /// One line in plain words.
    pub text: String,
    /// A PNG of the last hour, for channels that show pictures.
    #[serde(skip)]
    pub chart: Option<Arc<Vec<u8>>>,
}

impl Notice {
    pub fn for_delivery(delivery: &Delivery) -> Self {
        Self {
            id: delivery.id,
            ..Self::for_alert(delivery.alert.clone(), delivery.event)
        }
    }

    /// What a message about this alert says, outside the queue.
    pub fn for_alert(alert: Alert, event: Event) -> Self {
        let text = match event {
            Event::Escalated => format!("Now critical: {}", alert.summary),
            Event::Eased => format!("Down to a warning: {}", alert.summary),
            Event::Reminder => format!("Still firing: {}", alert.summary),
            Event::Resolved => format!("Resolved: {}", alert.summary),
            _ => alert.summary.clone(),
        };
        Self {
            id: 0,
            event,
            alert: Some(alert),
            text,
            chart: None,
        }
    }

    pub fn test() -> Self {
        Self {
            id: 0,
            event: Event::Test,
            alert: None,
            text: "This is a test notification from MaxNines.".to_string(),
            chart: None,
        }
    }

    /// Words for whoever can't see the chart.
    fn chart_description(&self) -> String {
        let summary = self
            .alert
            .as_ref()
            .map_or(self.text.as_str(), |a| &a.summary);
        format!("The last hour: {summary}")
    }

    /// The plain text, with the chart under it.
    fn email_html(&self) -> String {
        format!(
            "<!doctype html><html><body>\
             <pre style=\"font-family: sans-serif; white-space: pre-wrap\">{}</pre>\
             <img src=\"cid:chart\" alt=\"{}\" width=\"720\" style=\"max-width: 100%\">\
             </body></html>",
            escape_html(&self.email_body()),
            escape_html(&self.chart_description())
        )
    }

    /// `text` is what Slack and tools like it show, so a plain webhook works
    /// with them. `version` is for changes to this format.
    fn webhook_body(&self) -> Value {
        json!({
            "version": 1,
            "id": self.id,
            "event": self.event,
            "text": self.text,
            "alert": self.alert,
        })
    }

    fn label(&self) -> String {
        match (self.event, &self.alert) {
            (Event::Firing, Some(alert)) => alert.severity.as_str().to_uppercase(),
            (Event::Escalated, _) => "NOW CRITICAL".to_string(),
            (Event::Eased, _) => "NOW WARNING".to_string(),
            (Event::Reminder, _) => "STILL FIRING".to_string(),
            (Event::Resolved, _) => "RESOLVED".to_string(),
            _ => "TEST".to_string(),
        }
    }

    /// Mentions are turned off, as agents choose their own names and one called
    /// `@everyone` would otherwise ping a whole server.
    fn discord_body(&self) -> Value {
        let summary = self
            .alert
            .as_ref()
            .map_or(self.text.as_str(), |a| &a.summary);
        let content: String = format!("**{}** {summary}", self.label())
            .chars()
            .take(DISCORD_MAX_CHARS)
            .collect();
        json!({ "content": content, "allowed_mentions": { "parse": [] } })
    }

    /// An Adaptive Card, as a Teams workflow posts. Teams turns `[text](url)` into a
    /// link, and agents choose their own names, so that's broken up in what they
    /// chose. Mentions need a list of who's meant, which this never sends.
    fn teams_body(&self, web_url: Option<&str>) -> Value {
        let unlinked = |text: &str| -> String {
            text.chars()
                .take(TEAMS_MAX_CHARS)
                .collect::<String>()
                .replace("](", "]\u{200b}(")
        };
        let colour = match (self.event, &self.alert) {
            (Event::Resolved, _) => "Good",
            (Event::Test, _) | (_, None) => "Default",
            (Event::Escalated, _) => "Attention",
            (Event::Eased, _) => "Warning",
            (_, Some(alert)) if alert.severity == Severity::Critical => "Attention",
            (_, Some(_)) => "Warning",
        };
        let summary = self
            .alert
            .as_ref()
            .map_or(self.text.as_str(), |a| &a.summary);
        let mut body = vec![
            json!({ "type": "TextBlock", "text": self.label(), "weight": "Bolder",
                    "color": colour, "wrap": true }),
            json!({ "type": "TextBlock", "text": unlinked(summary), "wrap": true }),
        ];
        if let Some(alert) = &self.alert {
            let mut facts = vec![
                json!({ "title": "Rule", "value": unlinked(&alert.rule_name) }),
                if alert.agent_id == FLEET_AGENT_ID {
                    json!({ "title": "Machines", "value": unlinked(&alert.host) })
                } else {
                    let agent = format!("{} ({})", alert.host, short_id(&alert.agent_id));
                    json!({ "title": "Agent", "value": unlinked(&agent) })
                },
                json!({ "title": "Started", "value": format_ms(alert.started_ms) }),
            ];
            if let (Event::Resolved, Some(reason)) = (self.event, &alert.resolve_reason) {
                facts.push(json!({ "title": "Reason", "value": unlinked(reason) }));
            }
            body.push(json!({ "type": "FactSet", "facts": facts }));
        }
        let mut card = json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "msteams": { "width": "Full" },
            "body": body,
        });
        if let Some(url) = web_url {
            card["actions"] = json!([
                { "type": "Action.OpenUrl", "title": "View alerts", "url": alerts_link(url) }
            ]);
        }
        json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": card,
            }],
        })
    }

    /// What this means for an on-call service. A test has to open an incident to prove
    /// anything, so it closes it again rather than leave someone paged.
    fn incident_steps(&self) -> &'static [Incident] {
        match self.event {
            // Sent again with the same ID, which updates the incident's severity.
            Event::Firing | Event::Escalated | Event::Eased => &[Incident::Open],
            Event::Resolved => &[Incident::Close],
            Event::Test => &[Incident::Open, Incident::Close],
            // They repeat for themselves, so they're never sent these.
            Event::Reminder => &[],
        }
    }

    /// Ties closing an incident to the one that was opened, and makes a repeat delivery
    /// land on that incident too.
    fn incident_id(&self) -> String {
        self.alert.as_ref().map_or_else(
            || TEST_INCIDENT_ID.to_string(),
            |alert| format!("maxnines-alert-{}", alert.id),
        )
    }

    fn incident_title(&self) -> &str {
        self.alert.as_ref().map_or("Test", |a| &a.rule_name)
    }

    fn incident_severity(&self) -> &'static str {
        self.alert.as_ref().map_or("info", |a| a.severity.as_str())
    }

    fn incident_host(&self) -> &str {
        self.alert.as_ref().map_or("MaxNines", |a| &a.host)
    }

    fn pagerduty_event(&self, step: Incident, key: &str, web_url: Option<&str>) -> Value {
        let dedup_key = self.incident_id();
        if step == Incident::Close {
            return json!({
                "routing_key": key,
                "event_action": "resolve",
                "dedup_key": dedup_key,
            });
        }

        let summary: String = self
            .text
            .chars()
            .take(PAGERDUTY_MAX_SUMMARY_CHARS)
            .collect();
        let details = self.alert.as_ref().map_or_else(
            || json!({}),
            |alert| {
                json!({
                    "rule": alert.rule_name,
                    "series": alert.series,
                    "value": alert.value,
                })
            },
        );
        let mut event = json!({
            "routing_key": key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "client": "MaxNines",
            "payload": {
                "summary": summary,
                "source": self.incident_host(),
                "severity": self.incident_severity(),
                "custom_details": details,
            },
        });
        if let Some(url) = web_url {
            event["client_url"] = json!(alerts_link(url));
        }
        event
    }

    /// Fixed names only, as AlertOps leaves it to whoever sets up the integration to
    /// say which of them means what. The form shows this as the sample to map from.
    fn alertops_event(&self, step: Incident, web_url: Option<&str>) -> Value {
        let mut event = json!({
            "alert_id": self.incident_id(),
            "status": if step == Incident::Open { "open" } else { "closed" },
            "subject": self.incident_title(),
            "message": self.text,
            "severity": self.incident_severity(),
            "host": self.incident_host(),
        });
        if let Some(url) = web_url {
            event["link"] = json!(alerts_link(url));
        }
        event
    }

    /// Names starting `X-S4-` mean something to SIGNL4. It shows the others in the alert.
    fn signl4_event(&self, step: Incident, web_url: Option<&str>) -> Value {
        let id = self.incident_id();
        if step == Incident::Close {
            return json!({ "X-S4-ExternalID": id, "X-S4-Status": "resolved" });
        }

        let mut event = json!({
            "Title": self.incident_title(),
            "Message": self.text,
            "Severity": self.incident_severity(),
            "Host": self.incident_host(),
            "X-S4-ExternalID": id,
            "X-S4-Status": "new",
            "X-S4-SourceSystem": "MaxNines",
        });
        if let Some(url) = web_url {
            event["Link"] = json!(alerts_link(url));
        }
        event
    }

    fn subject(&self) -> String {
        let label = self.label();
        let summary = self
            .alert
            .as_ref()
            .map_or(self.text.as_str(), |a| &a.summary);
        format!("[MaxNines {label}] {summary}")
    }

    fn email_body(&self) -> String {
        let Some(alert) = &self.alert else {
            return format!("{}\n", self.text);
        };
        let mut lines = vec![
            self.text.clone(),
            String::new(),
            format!("Rule: {}", alert.rule_name),
            format!("Severity: {}", alert.severity.as_str()),
            if alert.agent_id == FLEET_AGENT_ID {
                format!("Machines: {}", alert.host)
            } else {
                format!("Agent: {} ({})", alert.host, alert.agent_id)
            },
            format!("Started: {}", format_ms(alert.started_ms)),
        ];
        if let Some(resolved) = alert.resolved_ms {
            lines.push(format!("Resolved: {}", format_ms(resolved)));
        }
        if let Some(reason) = &alert.resolve_reason {
            lines.push(format!("Reason: {reason}"));
        }
        lines.push(String::new());
        lines.join("\n")
    }
}

pub fn format_ms(ms: i64) -> String {
    u64::try_from(ms).map_or_else(
        |_| ms.to_string(),
        |ms| crate::times::format_time(ms, chrono_tz::Tz::UTC),
    )
}

/// Sends email through the server in the config.
pub struct Mailer {
    transport: SmtpTransport,
    from: Mailbox,
}

impl Mailer {
    pub fn new(config: &EmailConfig) -> Result<Self> {
        let from: Mailbox = config
            .from
            .parse()
            .with_context(|| format!("invalid from address {:?}", config.from))?;

        let mut builder = match config.security {
            EmailSecurity::Tls => SmtpTransport::relay(&config.host)?,
            EmailSecurity::Starttls => SmtpTransport::starttls_relay(&config.host)?,
            EmailSecurity::None => SmtpTransport::builder_dangerous(&config.host),
        };
        if let Some(port) = config.port {
            builder = builder.port(port);
        }
        if let Some(username) = &config.username {
            builder = builder.credentials(Credentials::new(
                username.clone(),
                config.password()?.unwrap_or_default(),
            ));
        }

        Ok(Self {
            transport: builder.timeout(Some(SEND_TIMEOUT)).build(),
            from,
        })
    }

    fn send(&self, to: &str, notice: &Notice) -> Result<()> {
        let message = email_message(&self.from, to, notice)?;
        self.transport
            .send(&message)
            .map_err(|error| match error.status() {
                Some(code) => anyhow!("the mail server refused it with code {code}"),
                None if error.is_timeout() => anyhow!("the mail server timed out"),
                None => anyhow!("couldn't reach the mail server"),
            })?;
        Ok(())
    }
}

/// Plain text, or with a chart, plain text beside HTML that shows it.
fn email_message(from: &Mailbox, to: &str, notice: &Notice) -> Result<Message> {
    let mut message = Message::builder()
        .from(from.clone())
        .subject(notice.subject());
    for address in recipients(to)? {
        message = message.to(Mailbox::new(None, address));
    }
    let message = match &notice.chart {
        None => message
            .header(ContentType::TEXT_PLAIN)
            .body(notice.email_body()),
        Some(chart) => {
            let png = ContentType::parse("image/png").context("naming the chart's type")?;
            let shown = MultiPart::related()
                .singlepart(SinglePart::html(notice.email_html()))
                .singlepart(Attachment::new_inline("chart".to_string()).body(chart.to_vec(), png));
            message.multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(notice.email_body()))
                    .multipart(shown),
            )
        }
    }
    .context("building the email")?;
    Ok(message)
}

fn alerts_link(web_url: &str) -> String {
    format!("{web_url}/alerts")
}

/// What a Slack app for MaxNines needs: a bot that can post anywhere, can look up
/// who pressed a button, and hears buttons through Socket Mode.
fn slack_manifest_value() -> Value {
    json!({
        "display_information": { "name": "MaxNines" },
        "features": { "bot_user": { "display_name": "maxnines", "always_online": false } },
        "oauth_config": {
            "scopes": {
                "bot": [
                    "chat:write",
                    "chat:write.public",
                    "files:write",
                    "users:read",
                    "users:read.email",
                ],
            },
        },
        "settings": {
            "interactivity": { "is_enabled": true },
            "socket_mode_enabled": true,
        },
    })
}

/// The manifest to paste into Slack by hand.
pub fn slack_manifest() -> String {
    serde_json::to_string_pretty(&slack_manifest_value()).unwrap_or_default()
}

/// Opens Slack's new app page with the manifest already filled in.
pub fn slack_manifest_link() -> String {
    let manifest = slack_manifest_value().to_string();
    let query = serde_urlencoded::to_string([("new_app", "1"), ("manifest_json", &manifest)])
        .unwrap_or_default();
    format!("https://api.slack.com/apps?{query}")
}

/// What AlertOps' sample data box needs, to map its fields from.
pub fn alertops_sample() -> String {
    let event = Notice::test().alertops_event(Incident::Open, Some("https://maxnines.example.com"));
    serde_json::to_string_pretty(&event).unwrap_or_default()
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

/// Posts JSON, and gives the response whatever its status.
fn post(url: &str, body: &Value) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    agent()
        .post(url.trim())
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
}

/// Posts a form with files in it, and gives the response whatever its status.
fn post_form(url: &str, form: Form) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    agent().post(url.trim()).send(form)
}

/// The chart as a part of a form.
fn chart_part(chart: &[u8]) -> Result<Part<'_>> {
    Part::bytes(chart)
        .file_name(CHART_FILE)
        .mime_str("image/png")
        .context("naming the chart's type")
}

/// A Discord message, with the chart attached when there is one, which Discord
/// shows under the text.
fn post_to_discord(url: &str, notice: &Notice) -> Result<()> {
    let body = notice.discord_body();
    let Some(chart) = &notice.chart else {
        return post_json("the webhook", url, &body);
    };
    let payload = body.to_string();
    let json = Part::text(&payload)
        .mime_str("application/json")
        .context("naming the message's type")?;
    let form = Form::new()
        .part("payload_json", json)
        .part("files[0]", chart_part(chart)?);
    let response = post_form(url, form).map_err(|error| explain_http("the webhook", &error))?;
    let status = response.status();
    if !status.is_success() {
        bail!("the webhook returned status {}", status.as_u16());
    }
    Ok(())
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

fn post_json(who: &str, url: &str, body: &Value) -> Result<()> {
    let response = post(url, body).map_err(|error| explain_http(who, &error))?;
    let status = response.status();
    if !status.is_success() {
        bail!("{who} returned status {}", status.as_u16());
    }
    Ok(())
}

/// For the HTML part of an email.
fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Telegram's HTML needs only these escaped, and agents choose their own names.
fn escape_telegram(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Shortens text to what Telegram counts as `max` characters, which it measures
/// in UTF-16.
fn clip_utf16(text: &str, max: usize) -> &str {
    let mut used = 0;
    for (index, c) in text.char_indices() {
        used += c.len_utf16();
        if used > max {
            return &text[..index];
        }
    }
    text
}

/// The parts of a message, before escaping, are kept under these so that the
/// whole fits Telegram's limit of 4096.
const TELEGRAM_MAX_SUMMARY: usize = 3000;
const TELEGRAM_MAX_DETAIL: usize = 300;

fn telegram_text(notice: &Notice, web_url: Option<&str>) -> String {
    let Some(alert) = &notice.alert else {
        return escape_telegram(&notice.text);
    };
    let clip = |text: &str| escape_telegram(clip_utf16(text, TELEGRAM_MAX_DETAIL));
    let mut lines = vec![format!(
        "<b>{}</b> {}",
        notice.label(),
        escape_telegram(clip_utf16(&alert.summary, TELEGRAM_MAX_SUMMARY))
    )];
    let place = if alert.agent_id == FLEET_AGENT_ID {
        format!("Machines: {}", clip(&alert.host))
    } else {
        format!(
            "Agent: {} ({})",
            clip(&alert.host),
            short_id(&alert.agent_id)
        )
    };
    lines.push(format!(
        "Rule: {} · {place} · Started: {}",
        clip(&alert.rule_name),
        format_ms(alert.started_ms)
    ));
    if let (Event::Resolved, Some(reason)) = (notice.event, &alert.resolve_reason) {
        lines.push(format!("Reason: {}", clip(reason)));
    }
    if let Some(url) = web_url {
        lines.push(format!(
            "<a href=\"{}\">View alerts</a>",
            escape_telegram(&alerts_link(url))
        ));
    }
    lines.join("\n")
}

/// Telegram would otherwise fetch links in a message, and agents choose what's in
/// these. A reply to a message someone deleted is sent on its own.
fn telegram_message(
    notice: &Notice,
    chat: &str,
    reply_to: Option<&str>,
    web_url: Option<&str>,
) -> Value {
    let mut message = json!({
        "chat_id": chat.trim(),
        "text": telegram_text(notice, web_url),
        "parse_mode": "HTML",
        "link_preview_options": { "is_disabled": true },
    });
    if let Some(id) = reply_to.and_then(|id| id.parse::<i64>().ok()) {
        message["reply_parameters"] = json!({
            "message_id": id,
            "allow_sending_without_reply": true,
        });
    }
    message
}

/// The problems people can fix themselves, in words that say how. Telegram's
/// description is kept, as it never holds the token.
fn explain_telegram(status: u16, answer: &Value) -> anyhow::Error {
    let said: String = answer["description"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    if let Some(chat) = answer["parameters"]["migrate_to_chat_id"].as_i64() {
        return anyhow!("the group became a supergroup, so change the chat ID to {chat}");
    }
    let advice = match status {
        401 | 404 => "Telegram didn't accept the bot token",
        400 if said.contains("chat not found") => {
            "Telegram can't find that chat. Add the bot to the group, or send the bot a \
             message first"
        }
        403 => {
            "the bot can't post in that chat. Check it's still in it, and for a channel, that it's an admin"
        }
        429 => "Telegram asked us to slow down",
        _ if said.is_empty() => return anyhow!("Telegram returned status {status}"),
        _ => return anyhow!("Telegram said: {said}"),
    };
    if said.is_empty() {
        anyhow!("{advice}")
    } else {
        anyhow!("{advice} ({said})")
    }
}

/// The longest caption Telegram puts under a photo.
const TELEGRAM_MAX_CAPTION: usize = 1024;

/// Sends a message, as a reply to the alert's first one when there is one, and
/// gives what Telegram called it. With a chart, the message is the photo's caption,
/// or when it's too long for one, the photo is a reply to it.
fn send_to_telegram(
    channel: &Channel,
    notice: &Notice,
    reply_to: Option<&str>,
    senders: &Senders,
) -> Result<Option<String>> {
    let token = channel
        .channel
        .credential
        .as_deref()
        .context("this channel has no bot token")?;
    let method = |name: &str| format!("{}/bot{}/{name}", senders.telegram_api_url(), token.trim());
    let chat = channel.channel.target.trim();
    let web_url = senders.web_url.as_deref();
    let send_photo = |chart: &[u8], caption: Option<&str>, reply_to: Option<&str>| {
        let reply = reply_to
            .and_then(|id| id.parse::<i64>().ok())
            .map(|id| json!({ "message_id": id, "allow_sending_without_reply": true }).to_string());
        let mut form = Form::new()
            .text("chat_id", chat)
            .part("photo", chart_part(chart)?);
        if let Some(caption) = caption {
            form = form.text("caption", caption).text("parse_mode", "HTML");
        }
        if let Some(reply) = &reply {
            form = form.text("reply_parameters", reply);
        }
        telegram_answer(post_form(&method("sendPhoto"), form))
    };

    let text = telegram_text(notice, web_url);
    match &notice.chart {
        Some(chart) if text.encode_utf16().count() <= TELEGRAM_MAX_CAPTION => {
            send_photo(chart, Some(&text), reply_to)
        }
        Some(chart) => {
            let message = telegram_message(notice, chat, reply_to, web_url);
            let sent = telegram_answer(post(&method("sendMessage"), &message))?;
            send_photo(chart, None, sent.as_deref())?;
            Ok(sent)
        }
        None => {
            let message = telegram_message(notice, chat, reply_to, web_url);
            telegram_answer(post(&method("sendMessage"), &message))
        }
    }
}

/// What Telegram called what was sent, or why it refused it.
fn telegram_answer(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<Option<String>> {
    let mut response = response.map_err(|error| explain_http("Telegram", &error))?;
    let status = response.status();
    let answer: Value = response
        .body_mut()
        .read_to_string()
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    if !status.is_success() || answer["ok"] != true {
        return Err(explain_telegram(status.as_u16(), &answer));
    }
    Ok(answer["result"]["message_id"]
        .as_i64()
        .map(|id| id.to_string()))
}

/// What sending needs beyond the channel itself.
#[derive(Clone, Default)]
pub struct Senders {
    pub mailer: Option<Arc<Mailer>>,
    /// Where people reach this server's pages, for links in messages.
    pub web_url: Option<String>,
    /// Where to find a stand-in for Slack.
    #[cfg(test)]
    pub slack_api_url: Option<String>,
    /// Where to find a stand-in for PagerDuty.
    #[cfg(test)]
    pub pagerduty_url: Option<String>,
    /// Where to find a stand-in for Telegram.
    #[cfg(test)]
    pub telegram_api_url: Option<String>,
}

impl Senders {
    pub fn new(mailer: Option<Arc<Mailer>>, web_url: Option<String>) -> Self {
        Self {
            mailer,
            web_url,
            #[cfg(test)]
            slack_api_url: None,
            #[cfg(test)]
            pagerduty_url: None,
            #[cfg(test)]
            telegram_api_url: None,
        }
    }

    #[cfg(not(test))]
    fn telegram_api_url(&self) -> &str {
        TELEGRAM_API_URL
    }

    #[cfg(test)]
    fn telegram_api_url(&self) -> &str {
        self.telegram_api_url.as_deref().unwrap_or(TELEGRAM_API_URL)
    }

    #[cfg(not(test))]
    fn pagerduty_url(&self) -> &str {
        PAGERDUTY_EVENTS_URL
    }

    #[cfg(test)]
    fn pagerduty_url(&self) -> &str {
        self.pagerduty_url
            .as_deref()
            .unwrap_or(PAGERDUTY_EVENTS_URL)
    }
}

/// The address behind the one agents connect to, for links to the web pages.
pub fn web_url(agent_url: impl AsRef<str>) -> Option<String> {
    let agent_url = agent_url.as_ref();
    let (scheme, rest) = agent_url.split_once("://")?;
    let scheme = match scheme {
        "wss" => "https",
        "ws" => "http",
        _ => return None,
    };
    let host = rest.split('/').next().filter(|host| !host.is_empty())?;
    Some(format!("{scheme}://{host}"))
}

/// Slack reads `<...>` as commands, such as `<!everyone>`, and agents choose their
/// own names. Slack asks for exactly these three to be escaped.
fn escape_slack(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn slack_color(notice: &Notice) -> &'static str {
    match (notice.event, &notice.alert) {
        (Event::Escalated, _) => "#b3261e",
        (Event::Eased, _) => "#b87a00",
        (Event::Firing | Event::Reminder, Some(alert)) if alert.severity == Severity::Critical => {
            "#b3261e"
        }
        (Event::Firing | Event::Reminder, Some(_)) => "#b87a00",
        (Event::Resolved, _) => "#0b6b4b",
        _ => "#6b7280",
    }
}

fn slack_text(notice: &Notice, web_url: Option<&str>) -> String {
    let Some(alert) = &notice.alert else {
        return escape_slack(&notice.text);
    };
    let mut lines = vec![format!(
        "*{}* {}",
        notice.label(),
        escape_slack(&alert.summary)
    )];
    let mut details = vec![
        format!("Rule: {}", escape_slack(&alert.rule_name)),
        if alert.agent_id == FLEET_AGENT_ID {
            format!("Machines: {}", escape_slack(&alert.host))
        } else {
            format!(
                "Agent: {} ({})",
                escape_slack(&alert.host),
                short_id(&alert.agent_id)
            )
        },
        format!("Started: {}", format_ms(alert.started_ms)),
    ];
    if let Some(url) = web_url {
        details.push(format!("<{url}/alerts|View alerts>"));
    }
    lines.push(details.join(" · "));
    lines.join("\n")
}

/// Says which button was pressed, when Slack tells us. The button's value is the alert.
pub const ACKNOWLEDGE_ACTION: &str = "maxnines_acknowledge";
pub const SILENCE_HOUR_ACTION: &str = "maxnines_silence_hour";

/// Buttons under an alert, for a Slack app the server hears through Socket Mode.
#[derive(Debug, Clone, Default)]
pub struct SlackControls {
    /// Who silenced it and until when, shown in place of its button.
    pub silenced: Option<String>,
}

/// The longest description Slack takes for an image.
const SLACK_ALT_TEXT_MAX_CHARS: usize = 2000;

/// The most text Slack shows in one section of a message.
const SLACK_SECTION_MAX_CHARS: usize = 3000;

/// Shortens escaped text without cutting an `&amp;` in two.
fn clip_escaped(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let mut clipped: String = text.chars().take(max).collect();
    if let Some(start) = clipped.rfind('&')
        && !clipped[start..].contains(';')
    {
        clipped.truncate(start);
    }
    clipped
}

/// What's been done about it so far.
fn slack_status(notice: &Notice, controls: Option<&SlackControls>) -> Vec<String> {
    let mut lines = Vec::new();
    let acknowledged = notice
        .alert
        .as_ref()
        .and_then(|a| a.acknowledged_by.as_deref());
    if let Some(by) = acknowledged {
        lines.push(format!("Acknowledged by {}", escape_slack(by)));
    }
    if let Some(silenced) = controls.and_then(|c| c.silenced.as_deref()) {
        lines.push(escape_slack(silenced));
    }
    lines
}

/// Only while it's firing, and only what hasn't been done yet.
fn slack_buttons(
    notice: &Notice,
    controls: Option<&SlackControls>,
) -> Vec<SlackActionBlockElement> {
    let (Some(controls), Some(alert)) = (controls, &notice.alert) else {
        return Vec::new();
    };
    let firing = matches!(
        notice.event,
        Event::Firing | Event::Escalated | Event::Eased | Event::Reminder
    );
    if !firing || alert.resolved_ms.is_some() {
        return Vec::new();
    }
    let button = |action: &str, label: &str| {
        SlackBlockButtonElement::new(SlackBlockPlainText::new(label.to_string()).into())
            .with_action_id(SlackActionId(action.to_string()))
            .with_value(alert.id.to_string())
    };
    let mut buttons = Vec::new();
    if alert.acknowledged_by.is_none() {
        let acknowledge =
            button(ACKNOWLEDGE_ACTION, "Acknowledge").with_style(SlackBlockButtonStyle::Primary);
        buttons.push(SlackActionBlockElement::Button(acknowledge));
    }
    if controls.silenced.is_none() {
        buttons.push(SlackActionBlockElement::Button(button(
            SILENCE_HOUR_ACTION,
            "Silence 1 hour",
        )));
    }
    buttons
}

/// One colored attachment holding the message, its chart, what's been done about
/// it, and any buttons. `text` is what notifications and older clients show.
pub fn slack_content(
    notice: &Notice,
    web_url: Option<&str>,
    controls: Option<&SlackControls>,
    chart: Option<&SlackFileId>,
) -> SlackMessageContent {
    let text = clip_escaped(slack_text(notice, web_url), SLACK_SECTION_MAX_CHARS);
    let mut blocks: Vec<SlackBlock> = vec![
        SlackSectionBlock::new()
            .with_text(SlackBlockMarkDownText::new(text).into())
            .into(),
    ];
    if let Some(file) = chart {
        let image = SlackImageUrlOrFile::SlackFile {
            slack_file: SlackFileIdOrUrl::Id { id: file.clone() },
        };
        let description = clip_escaped(notice.chart_description(), SLACK_ALT_TEXT_MAX_CHARS);
        blocks.push(SlackImageBlock::new(image, description).into());
    }
    let status = slack_status(notice, controls);
    if !status.is_empty() {
        let line = SlackBlockMarkDownText::new(status.join(" · "));
        blocks.push(SlackContextBlock::new(vec![SlackContextBlockElement::MarkDown(line)]).into());
    }
    let buttons = slack_buttons(notice, controls);
    if !buttons.is_empty() {
        blocks.push(SlackActionsBlock::new(buttons).into());
    }
    let attachment = SlackMessageAttachment::new()
        .with_color(slack_color(notice).to_string())
        .with_fallback(escape_slack(&notice.text))
        .with_blocks(blocks);
    SlackMessageContent::new()
        .with_text(escape_slack(&notice.text))
        .with_attachments(vec![attachment])
}

/// Slack would otherwise fetch any link in a message, and agents choose what's in
/// these.
fn slack_post(
    channel: SlackChannelId,
    content: SlackMessageContent,
) -> SlackApiChatPostMessageRequest {
    SlackApiChatPostMessageRequest::new(channel, content)
        .with_unfurl_links(false)
        .with_unfurl_media(false)
}

/// Uses the certificates built into this binary, as the rest of the server does,
/// so that Slack works on machines without their own.
pub fn slack_connector() -> Result<SlackClientHyperHttpsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider)
        .map_err(|_| anyhow!("couldn't set up TLS for Slack"))?
        .https_only()
        .enable_http2()
        .build();
    Ok(SlackClientHyperConnector::with_connector(https))
}

/// The channel and timestamp that together name a Slack message, and its chart if it
/// has one, kept together as `channel:ts:file` so a changed message keeps its chart.
fn slack_message_id(external_id: &str) -> Option<(SlackChannelId, SlackTs, Option<SlackFileId>)> {
    let mut parts = external_id.splitn(3, ':');
    let channel = parts.next().filter(|part| !part.is_empty())?;
    let ts = parts.next().filter(|part| !part.is_empty())?;
    let chart = parts.next().map(|file| SlackFileId(file.to_string()));
    Some((
        SlackChannelId(channel.to_string()),
        SlackTs(ts.to_string()),
        chart,
    ))
}

fn slack_external_id(
    channel: &SlackChannelId,
    ts: &SlackTs,
    chart: Option<&SlackFileId>,
) -> String {
    match chart {
        Some(file) => format!("{channel}:{ts}:{file}"),
        None => format!("{channel}:{ts}"),
    }
}

/// The chart in a message Slack sent back, such as one whose button was pressed.
pub fn slack_chart(content: &SlackMessageContent) -> Option<SlackFileId> {
    let attached = content
        .attachments
        .iter()
        .flatten()
        .flat_map(|attachment| attachment.blocks.iter().flatten());
    content
        .blocks
        .iter()
        .flatten()
        .chain(attached)
        .find_map(|block| match block {
            SlackBlock::Image(SlackImageBlock {
                image_url_or_file:
                    SlackImageUrlOrFile::SlackFile {
                        slack_file: SlackFileIdOrUrl::Id { id },
                    },
                ..
            }) => Some(id.clone()),
            _ => None,
        })
}

/// Uploads a chart for a message to show. It's shared with nobody until a message
/// shows it.
async fn upload_to_slack<C>(
    session: &SlackClientSession<'_, C>,
    chart: &[u8],
    description: &str,
) -> Result<SlackFileId>
where
    C: SlackClientHttpConnector + Send + Sync,
{
    let request =
        SlackApiFilesGetUploadUrlExternalRequest::new(CHART_FILE.to_string(), chart.len())
            .with_alt_txt(description.chars().take(SLACK_ALT_TEXT_MAX_CHARS).collect());
    let upload = session
        .get_upload_url_external(&request)
        .await
        .map_err(|error| explain_slack(&error))?;
    let content = SlackApiFilesUploadViaUrlRequest::new(
        upload.upload_url,
        chart.to_vec(),
        "image/png".to_string(),
    );
    session
        .files_upload_via_url(&content)
        .await
        .map_err(|error| explain_slack(&error))?;
    let done = SlackApiFilesCompleteUploadExternalRequest::new(vec![SlackApiFilesComplete::new(
        upload.file_id.clone(),
    )]);
    session
        .files_complete_upload_external(&done)
        .await
        .map_err(|error| explain_slack(&error))?;
    Ok(upload.file_id)
}

/// Slack's error codes are safe to keep and say what's wrong, but anything else
/// could quote the request, which holds the token.
pub fn explain_slack(error: &SlackClientError) -> anyhow::Error {
    match error {
        SlackClientError::ApiError(error) => explain_slack_code(&error.code),
        SlackClientError::RateLimitError(_) => anyhow!("Slack asked us to slow down"),
        _ => anyhow!("couldn't reach Slack"),
    }
}

/// The problems people can fix themselves, in words that say how.
fn explain_slack_code(code: &str) -> anyhow::Error {
    let advice = match code {
        "invalid_auth" | "not_authed" | "token_revoked" | "token_expired" | "account_inactive" => {
            "Slack didn't accept the bot token"
        }
        "channel_not_found" => {
            "Slack can't find that channel. For a private channel, invite the app first"
        }
        "not_in_channel" => "the app isn't in that channel, so invite it",
        "is_archived" => "that Slack channel is archived",
        "missing_scope" => "the Slack app is missing the permissions in the setup steps",
        _ => return anyhow!("Slack said {code}"),
    };
    anyhow!("{advice} ({code})")
}

fn is_invalid_blocks(error: &SlackClientError) -> bool {
    matches!(error, SlackClientError::ApiError(error) if error.code == "invalid_blocks")
}

fn is_gone(error: &SlackClientError) -> bool {
    matches!(error, SlackClientError::ApiError(error) if error.code == "message_not_found")
}

/// Posts a message, or when an alert resolves, turns the original green and adds
/// a reply, so that a channel shows one message per alert. Gives what Slack called
/// a new message.
async fn post_to_slack<C>(
    client: &SlackClient<C>,
    channel: &Channel,
    notice: &Notice,
    reply_to: Option<&str>,
    web_url: Option<&str>,
) -> Result<Option<String>>
where
    C: SlackClientHttpConnector + Send + Sync,
{
    let token = channel
        .channel
        .credential
        .clone()
        .context("this channel has no bot token")?;
    let token = SlackApiToken::new(SlackApiTokenValue(token));
    let session = client.open_session(&token);
    // A resolved alert has nothing left to press.
    let controls = channel
        .channel
        .app_token
        .is_some()
        .then(SlackControls::default);

    if let Some((message_channel, ts, chart)) = reply_to
        .filter(|_| notice.event == Event::Resolved)
        .and_then(slack_message_id)
    {
        let content = slack_content(notice, web_url, controls.as_ref(), chart.as_ref());
        let update =
            SlackApiChatUpdateRequest::new(message_channel.clone(), content.clone(), ts.clone());
        match session.chat_update(&update).await {
            Ok(_) => {
                let reason = notice
                    .alert
                    .as_ref()
                    .and_then(|a| a.resolve_reason.as_deref());
                let reply = SlackMessageContent::new()
                    .with_text(escape_slack(reason.unwrap_or("Resolved")));
                let request = slack_post(message_channel, reply).with_thread_ts(ts);
                session
                    .chat_post_message(&request)
                    .await
                    .map_err(|error| explain_slack(&error))?;
                return Ok(None);
            }
            // Someone deleted it, so this has to stand on its own.
            Err(error) if is_gone(&error) => {}
            Err(error) => return Err(explain_slack(&error)),
        }
    }

    // The message matters more than its chart, so it goes without one that fails.
    let mut chart = None;
    if let Some(png) = notice.chart.as_deref() {
        match upload_to_slack(&session, png, &notice.chart_description()).await {
            Ok(file) => chart = Some(file),
            Err(error) => warn!(
                error = format!("{error:#}"),
                "couldn't send a chart to Slack"
            ),
        }
    }
    let target = SlackChannelId(channel.channel.target.trim().to_string());
    let content = slack_content(notice, web_url, controls.as_ref(), chart.as_ref());
    let response = match session
        .chat_post_message(&slack_post(target.clone(), content))
        .await
    {
        Ok(response) => response,
        // Slack can refuse a chart it hasn't finished taking in yet.
        Err(error) if chart.is_some() && is_invalid_blocks(&error) => {
            warn!("Slack wouldn't show the chart, so the alert went without it");
            chart = None;
            let content = slack_content(notice, web_url, controls.as_ref(), None);
            session
                .chat_post_message(&slack_post(target, content))
                .await
                .map_err(|error| explain_slack(&error))?
        }
        Err(error) => return Err(explain_slack(&error)),
    };

    // Otherwise a wrong token would only show in the server's log.
    if let (Event::Test, Some(app_token)) = (notice.event, &channel.channel.app_token) {
        crate::slack_actions::check_app_token(client, app_token)
            .await
            .context("the test message was sent, but the buttons won't work")?;
    }
    Ok(Some(slack_external_id(
        &response.channel,
        &response.ts,
        chart.as_ref(),
    )))
}

async fn send_to_slack(
    channel: &Channel,
    notice: &Notice,
    reply_to: Option<&str>,
    senders: &Senders,
) -> Result<Option<String>> {
    let web_url = senders.web_url.as_deref();

    #[cfg(test)]
    if let Some(url) = &senders.slack_api_url {
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let connector =
            SlackClientHyperConnector::with_connector(connector).with_slack_api_url(url);
        let client = SlackClient::new(connector);
        return post_to_slack(&client, channel, notice, reply_to, web_url).await;
    }

    let client = SlackClient::new(slack_connector()?);
    post_to_slack(&client, channel, notice, reply_to, web_url).await
}

/// Sends one notification, and gives what the service called it if that matters
/// later. Blocks, so it can't run on an async thread.
fn send_blocking(
    channel: &Channel,
    notice: &Notice,
    reply_to: Option<&str>,
    senders: &Senders,
) -> Result<Option<String>> {
    let target = &channel.channel.target;
    let web_url = senders.web_url.as_deref();
    let sent = match channel.channel.kind {
        ChannelKind::Webhook => post_json("the webhook", target, &notice.webhook_body()),
        ChannelKind::Discord => post_to_discord(target, notice),
        ChannelKind::Teams => post_json("the Teams workflow", target, &notice.teams_body(web_url)),
        ChannelKind::Email => senders
            .mailer
            .as_deref()
            .context("email isn't set up in the server config")?
            .send(target, notice),
        ChannelKind::PagerDuty => notice.incident_steps().iter().try_for_each(|step| {
            let event = notice.pagerduty_event(*step, target, web_url);
            post_json("PagerDuty", senders.pagerduty_url(), &event)
        }),
        ChannelKind::AlertOps => notice.incident_steps().iter().try_for_each(|step| {
            post_json("AlertOps", target, &notice.alertops_event(*step, web_url))
        }),
        ChannelKind::Signl4 => notice
            .incident_steps()
            .iter()
            .try_for_each(|step| post_json("SIGNL4", target, &notice.signl4_event(*step, web_url))),
        ChannelKind::Telegram => return send_to_telegram(channel, notice, reply_to, senders),
        ChannelKind::Slack => bail!("Slack doesn't send this way"),
    };
    sent.map(|()| None)
}

/// Sends one notification, and gives what the service called it if that matters
/// later. A panic counts as a failed delivery, whichever way it's sent, so one
/// delivery can't stop the rest of a pass or be retried straight away.
pub async fn send(
    channel: Channel,
    notice: Notice,
    reply_to: Option<String>,
    senders: Senders,
) -> Result<Option<String>> {
    if channel.channel.kind == ChannelKind::Slack {
        let sending = send_to_slack(&channel, &notice, reply_to.as_deref(), &senders);
        return guarded("Slack", SEND_TIMEOUT, sending).await;
    }

    tokio::task::spawn_blocking(move || {
        send_blocking(&channel, &notice, reply_to.as_deref(), &senders)
    })
    .await
    .map_err(|_| anyhow!("sending failed unexpectedly"))?
}

/// Whether a notification goes with a chart: an alert starting or getting worse,
/// on a channel that shows pictures.
fn shows_chart(delivery: &Delivery) -> bool {
    matches!(delivery.event, Event::Firing | Event::Escalated)
        && matches!(
            delivery.channel.channel.kind,
            ChannelKind::Discord | ChannelKind::Telegram | ChannelKind::Slack | ChannelKind::Email
        )
}

/// Runs a send with a time limit, turning a panic into an ordinary failure.
async fn guarded<T>(
    who: &str,
    limit: Duration,
    sending: impl Future<Output = Result<T>>,
) -> Result<T> {
    match timeout(limit, AssertUnwindSafe(sending).catch_unwind()).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(anyhow!("sending to {who} failed unexpectedly")),
        Err(_) => Err(anyhow!("{who} timed out")),
    }
}

#[derive(Clone)]
pub struct Notifier {
    database: Database,
    senders: Senders,
    /// Where charts come from, for channels that show them.
    charts: Option<Arc<ChartSources>>,
}

impl Notifier {
    pub fn new(database: Database, senders: Senders) -> Self {
        Self {
            database,
            senders,
            charts: None,
        }
    }

    /// Sends charts with alerts to the channels that show them.
    pub fn with_charts(mut self, charts: ChartSources) -> Self {
        self.charts = Some(Arc::new(charts));
        self
    }

    /// The chart for a delivery, if it gets one. Drawing one is never a reason not
    /// to send the notification.
    async fn chart_for(&self, delivery: &Delivery, now_ms: i64) -> Option<Arc<Vec<u8>>> {
        let charts = self.charts.as_ref()?;
        if !shows_chart(delivery) {
            return None;
        }
        match charts.draw(&delivery.alert, now_ms).await {
            Ok(chart) => chart.map(Arc::new),
            Err(error) => {
                warn!(
                    alert = delivery.alert.id,
                    error = format!("{error:#}"),
                    "couldn't draw a chart for an alert"
                );
                None
            }
        }
    }

    /// Runs until the server stops. Each pass is its own task, so a panic costs
    /// that pass and the next one starts as usual.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(INTERVAL);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                let notifier = self.clone();
                let pass = tokio::spawn(async move { notifier.deliver_due(now_ms()).await });
                match pass.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        error!(
                            error = format!("{error:#}"),
                            "delivering notifications failed"
                        );
                    }
                    Err(error) => error!(%error, "delivering notifications panicked"),
                }
            }
        })
    }

    /// Lets go of what no silence covers any more. Something held for an alert
    /// that has since ended is dropped instead: the alert ended in the moment
    /// between the queue being read and the hold, and nobody needs to hear of it.
    async fn release_held(&self, silences: &ActiveSilences, now_ms: i64) -> Result<()> {
        let mut ids = Vec::new();
        for (alert, held) in self.database.held_deliveries().await? {
            if alert.resolved_ms.is_some() {
                self.database.drop_held_for(alert.id).await?;
            } else if silences.covering(&alert).is_none() {
                ids.extend(held);
            }
        }
        if !ids.is_empty() {
            self.database.release_deliveries(&ids, now_ms).await?;
        }
        Ok(())
    }

    /// Whether a reminder queued a moment ago still has a point.
    fn reminder_is_stale(delivery: &Delivery, silences: &ActiveSilences) -> bool {
        let alert = &delivery.alert;
        alert.resolved_ms.is_some()
            || alert.acknowledged_ms.is_some()
            || silences.covering(alert).is_some()
    }

    async fn queue_reminders(&self, silences: &ActiveSilences, now_ms: i64) -> Result<()> {
        let alerts: Vec<(i64, i64)> = self
            .database
            .alerts_to_remind()
            .await?
            .into_iter()
            .filter(|(alert, _)| silences.covering(alert).is_none())
            .map(|(alert, every_secs)| (alert.id, every_secs))
            .collect();
        self.database.queue_reminders(&alerts, now_ms).await
    }

    /// Sends what's due, and saves how each one went. Someone who was told an alert
    /// started always hears that it ended, or an on-call incident would stay open.
    pub async fn deliver_due(&self, now_ms: i64) -> Result<()> {
        let silences = ActiveSilences::load(&self.database, now_ms).await?;
        self.release_held(&silences, now_ms).await?;
        self.queue_reminders(&silences, now_ms).await?;
        let due = self.database.due_deliveries(now_ms, BATCH_SIZE).await?;

        let mut sends = JoinSet::new();
        // Each chart is drawn once a pass, however many channels it goes to.
        let mut charts: HashMap<(i64, Event), Option<Arc<Vec<u8>>>> = HashMap::new();
        for delivery in due {
            let tells_of_a_problem = matches!(
                delivery.event,
                Event::Firing | Event::Escalated | Event::Eased
            );
            if tells_of_a_problem && silences.covering(&delivery.alert).is_some() {
                self.database.hold_delivery(&delivery).await?;
                continue;
            }
            if delivery.event == Event::Reminder && Self::reminder_is_stale(&delivery, &silences) {
                self.database.drop_delivery(delivery.id).await?;
                continue;
            }
            let chart = if shows_chart(&delivery) {
                let key = (delivery.alert.id, delivery.event);
                match charts.get(&key) {
                    Some(drawn) => drawn.clone(),
                    None => {
                        let drawn = self.chart_for(&delivery, now_ms).await;
                        charts.insert(key, drawn.clone());
                        drawn
                    }
                }
            } else {
                None
            };
            let senders = self.senders.clone();
            sends.spawn(async move {
                let notice = Notice {
                    chart,
                    ..Notice::for_delivery(&delivery)
                };
                let reply_to = delivery.reply_to.clone();
                let result = send(delivery.channel.clone(), notice, reply_to, senders).await;
                (delivery, result)
            });
        }

        while let Some(finished) = sends.join_next().await {
            match finished {
                Ok((delivery, result)) => self.record(&delivery, result, now_ms).await?,
                // The rest of the batch still gets recorded.
                Err(error) => error!(%error, "a delivery stopped unexpectedly"),
            }
        }
        Ok(())
    }

    async fn record(
        &self,
        delivery: &Delivery,
        result: Result<Option<String>>,
        now_ms: i64,
    ) -> Result<()> {
        let attempts = delivery.attempts.saturating_add(1);
        let channel = &delivery.channel.channel.name;
        match result {
            Ok(external_id) => {
                info!(
                    channel,
                    event = delivery.event.as_str(),
                    "notification sent"
                );
                self.database
                    .delivery_sent(delivery.id, attempts, now_ms, external_id.as_deref())
                    .await
            }
            Err(error) => {
                let message = format!("{error:#}");
                let next = (now_ms - delivery.created_ms < GIVE_UP_AFTER_MS)
                    .then(|| now_ms + retry_delay_ms(attempts));
                warn!(
                    channel,
                    attempts,
                    error = message,
                    gave_up = next.is_none(),
                    "notification failed"
                );
                self.database
                    .delivery_failed(delivery.id, attempts, &message, next)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> Alert {
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

    fn notice(event: Event, alert: Alert) -> Notice {
        let text = alert.summary.clone();
        Notice {
            id: 3,
            event,
            alert: Some(alert),
            text,
            chart: None,
        }
    }

    #[tokio::test]
    async fn a_send_that_panics_or_hangs_is_an_ordinary_failure() {
        let panicking = async { panic!("deliberate test panic") };
        let error = guarded::<()>("Slack", Duration::from_secs(1), panicking)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "sending to Slack failed unexpectedly");

        let hanging = std::future::pending::<Result<()>>();
        let error = guarded("Slack", Duration::from_millis(10), hanging)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Slack timed out");

        let fine = async { Ok(Some("id".to_string())) };
        let sent = guarded("Slack", Duration::from_secs(1), fine)
            .await
            .unwrap();
        assert_eq!(sent.as_deref(), Some("id"));
    }

    #[test]
    fn retries_slow_down_up_to_a_limit() {
        assert_eq!(retry_delay_ms(1), 30_000);
        assert_eq!(retry_delay_ms(2), 60_000);
        assert_eq!(retry_delay_ms(3), 120_000);
        assert_eq!(retry_delay_ms(7), LONGEST_RETRY_MS);
        assert_eq!(retry_delay_ms(i32::MAX), LONGEST_RETRY_MS);
        assert_eq!(retry_delay_ms(0), 30_000);
    }

    #[test]
    fn links_use_the_address_agents_connect_to() {
        assert_eq!(
            web_url("wss://monitor.example.com/ws").as_deref(),
            Some("https://monitor.example.com")
        );
        assert_eq!(
            web_url("ws://127.0.0.1:9000/ws").as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert_eq!(web_url("nonsense"), None);
        assert_eq!(web_url("ftp://x/y"), None);
    }

    #[test]
    fn a_host_cannot_ping_a_slack_channel() {
        let alert = Alert {
            summary: "<!everyone> & <@U123> are <http://evil|offline>".to_string(),
            host: "<!here>".to_string(),
            rule_name: "<!channel>".to_string(),
            ..alert()
        };
        let notice = notice(Event::Firing, alert);
        let text = slack_text(&notice, None);
        assert!(!text.contains('<'), "{text}");
        assert!(
            text.contains("&lt;!everyone&gt; &amp; &lt;@U123&gt;"),
            "{text}"
        );

        let content = slack_content(&notice, None, None, None);
        assert!(!content.text.unwrap().contains('<'));
    }

    #[test]
    fn slack_messages_say_what_happened_and_where_to_look() {
        let text = slack_text(
            &notice(Event::Firing, alert()),
            Some("https://m.example.com"),
        );
        assert!(text.starts_with("*CRITICAL* CPU usage on web-1"), "{text}");
        assert!(text.contains("Rule: High CPU"), "{text}");
        assert!(text.contains("Agent: web-1"), "{text}");
        assert!(
            text.contains("<https://m.example.com/alerts|View alerts>"),
            "{text}"
        );
    }

    #[test]
    fn slack_colors_follow_severity_and_state() {
        let warning = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        assert_eq!(slack_color(&notice(Event::Firing, alert())), "#b3261e");
        assert_eq!(slack_color(&notice(Event::Firing, warning)), "#b87a00");
        assert_eq!(slack_color(&notice(Event::Resolved, alert())), "#0b6b4b");
        assert_eq!(slack_color(&Notice::test()), "#6b7280");
    }

    #[test]
    fn common_slack_problems_say_what_to_do_and_keep_the_code() {
        assert_eq!(
            explain_slack_code("token_revoked").to_string(),
            "Slack didn't accept the bot token (token_revoked)"
        );
        assert_eq!(
            explain_slack_code("not_in_channel").to_string(),
            "the app isn't in that channel, so invite it (not_in_channel)"
        );
        assert_eq!(
            explain_slack_code("fatal_error").to_string(),
            "Slack said fatal_error"
        );
    }

    #[test]
    fn slack_needs_no_certificates_or_tls_setup_from_the_machine() {
        slack_connector().unwrap();
    }

    fn block_types(content: &SlackMessageContent) -> Vec<String> {
        let value = serde_json::to_value(content).unwrap();
        value["attachments"][0]["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|block| block["type"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn slack_buttons_only_show_while_firing_and_for_what_is_left_to_do() {
        let controls = SlackControls::default();
        let firing = notice(Event::Firing, alert());
        assert_eq!(
            block_types(&slack_content(&firing, None, None, None)),
            ["section"]
        );
        assert_eq!(
            block_types(&slack_content(&firing, None, Some(&controls), None)),
            ["section", "actions"]
        );

        let resolved = Alert {
            resolved_ms: Some(2_000),
            ..alert()
        };
        let content = slack_content(
            &notice(Event::Resolved, resolved),
            None,
            Some(&controls),
            None,
        );
        assert_eq!(block_types(&content), ["section"]);

        let handled = Alert {
            acknowledged_by: Some("sam@example.com".to_string()),
            ..alert()
        };
        let silenced = SlackControls {
            silenced: Some("Silenced by sam@example.com until later".to_string()),
        };
        let content = slack_content(
            &notice(Event::Reminder, handled),
            None,
            Some(&silenced),
            None,
        );
        assert_eq!(block_types(&content), ["section", "context"]);
        let value = serde_json::to_value(&content).unwrap();
        assert_eq!(
            value["attachments"][0]["blocks"][1]["elements"][0]["text"],
            "Acknowledged by sam@example.com · Silenced by sam@example.com until later"
        );
    }

    #[test]
    fn a_long_slack_message_is_cut_without_breaking_an_escape() {
        assert_eq!(clip_escaped("a&amp;b".to_string(), 4), "a");
        assert_eq!(clip_escaped("a&amp;b".to_string(), 6), "a&amp;");
        assert_eq!(clip_escaped("short".to_string(), 10), "short");

        let alert = Alert {
            summary: "<".repeat(5000),
            ..alert()
        };
        let content = slack_content(&notice(Event::Firing, alert), None, None, None);
        let value = serde_json::to_value(&content).unwrap();
        let text = value["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap();
        assert!(text.chars().count() <= SLACK_SECTION_MAX_CHARS);
        assert!(text.ends_with("&lt;"), "{}", &text[text.len() - 10..]);
    }

    #[test]
    fn the_slack_link_and_the_manifest_to_paste_say_the_same_thing() {
        let link = slack_manifest_link();
        let query = link.strip_prefix("https://api.slack.com/apps?").unwrap();
        let fields: Vec<(String, String)> = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(fields[0], ("new_app".to_string(), "1".to_string()));
        assert_eq!(fields[1].0, "manifest_json");
        let linked: Value = serde_json::from_str(&fields[1].1).unwrap();
        let pasted: Value = serde_json::from_str(&slack_manifest()).unwrap();
        assert_eq!(linked, pasted);
        assert_eq!(linked["settings"]["socket_mode_enabled"], true);
        assert_eq!(
            linked["oauth_config"]["scopes"]["bot"],
            json!([
                "chat:write",
                "chat:write.public",
                "files:write",
                "users:read",
                "users:read.email"
            ])
        );
    }

    #[test]
    fn slack_is_told_not_to_fetch_links() {
        let request = slack_post(SlackChannelId("C1".to_string()), SlackMessageContent::new());
        assert_eq!(request.unfurl_links, Some(false));
        assert_eq!(request.unfurl_media, Some(false));
    }

    fn with_chart(event: Event) -> Notice {
        Notice {
            chart: Some(Arc::new(b"\x89PNG chart".to_vec())),
            ..notice(event, alert())
        }
    }

    #[test]
    fn an_email_with_a_chart_shows_it_beside_the_plain_text() {
        let from: Mailbox = "maxnines@example.com".parse().unwrap();
        let odd_host = Alert {
            host: "web-<1>".to_string(),
            ..alert()
        };
        let charted = Notice {
            chart: Some(Arc::new(b"\x89PNG chart".to_vec())),
            ..notice(Event::Firing, odd_host)
        };
        let message = email_message(&from, "ops@example.com", &charted).unwrap();
        let text = String::from_utf8_lossy(&message.formatted()).to_string();

        assert!(text.contains("multipart/alternative"), "{text}");
        assert!(text.contains("multipart/related"));
        assert!(text.contains("Content-ID: <chart>"));
        assert!(text.contains("Content-Type: image/png"));
        assert!(text.contains("src=3D\"cid:chart\"") || text.contains("src=\"cid:chart\""));
        assert!(text.contains("web-&lt;1&gt;"), "{text}");

        let plain =
            email_message(&from, "ops@example.com", &notice(Event::Firing, alert())).unwrap();
        let text = String::from_utf8_lossy(&plain.formatted()).to_string();
        assert!(!text.contains("multipart"));
    }

    #[test]
    fn a_slack_message_shows_its_chart_and_gives_it_back() {
        let file = SlackFileId("F123".to_string());
        let content = slack_content(&with_chart(Event::Firing), None, None, Some(&file));
        let sent = serde_json::to_value(&content).unwrap();
        let blocks = &sent["attachments"][0]["blocks"];
        assert_eq!(blocks[1]["type"], "image");
        assert_eq!(blocks[1]["slack_file"]["id"], "F123");
        assert!(
            blocks[1]["alt_text"]
                .as_str()
                .unwrap()
                .starts_with("The last hour: CPU usage on web-1")
        );

        let back: SlackMessageContent = serde_json::from_value(sent).unwrap();
        assert_eq!(slack_chart(&back), Some(file));
        let plain = slack_content(&notice(Event::Firing, alert()), None, None, None);
        assert_eq!(slack_chart(&plain), None);
    }

    #[test]
    fn the_slack_app_can_upload_charts() {
        let manifest = slack_manifest_value();
        let scopes = manifest["oauth_config"]["scopes"]["bot"]
            .as_array()
            .unwrap();
        assert!(scopes.contains(&json!("files:write")));
    }

    #[test]
    fn a_message_id_needs_both_parts_and_may_name_a_chart() {
        let (channel, ts, chart) = slack_message_id("C1:12.34").unwrap();
        assert_eq!(
            (channel.0.as_str(), ts.0.as_str(), chart),
            ("C1", "12.34", None)
        );
        let (_, _, chart) = slack_message_id("C1:12.34:F9").unwrap();
        assert_eq!(chart, Some(SlackFileId("F9".to_string())));
        assert!(slack_message_id("nonsense").is_none());
        assert!(slack_message_id(":12.34").is_none());
        assert_eq!(
            slack_external_id(
                &SlackChannelId("C1".to_string()),
                &SlackTs("12.34".to_string()),
                Some(&SlackFileId("F9".to_string()))
            ),
            "C1:12.34:F9"
        );
    }

    #[test]
    fn discord_messages_lead_with_what_happened() {
        let body = notice(Event::Firing, alert()).discord_body();
        assert_eq!(
            body["content"],
            "**CRITICAL** CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            notice(Event::Resolved, alert()).discord_body()["content"],
            "**RESOLVED** CPU usage on web-1 is 97%, above 90%"
        );
    }

    #[test]
    fn a_change_of_severity_says_which_way_it_went_and_updates_the_incident() {
        let warning = Alert {
            severity: Severity::Warning,
            summary: "CPU usage on web-1 is 85%, above 80%".to_string(),
            ..alert()
        };
        let escalated = notice(Event::Escalated, alert());
        let eased = notice(Event::Eased, warning);

        assert_eq!(
            Notice::for_alert(alert(), Event::Escalated).text,
            "Now critical: CPU usage on web-1 is 97%, above 90%"
        );
        let warning = eased.alert.clone().unwrap();
        assert_eq!(
            Notice::for_alert(warning, Event::Eased).text,
            "Down to a warning: CPU usage on web-1 is 85%, above 80%"
        );
        assert_eq!(
            escalated.discord_body()["content"],
            "**NOW CRITICAL** CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            eased.subject(),
            "[MaxNines NOW WARNING] CPU usage on web-1 is 85%, above 80%"
        );
        assert_eq!(slack_color(&escalated), "#b3261e");
        assert_eq!(slack_color(&eased), "#b87a00");
        for notice in [&escalated, &eased] {
            assert_eq!(notice.incident_steps(), [Incident::Open]);
            assert_eq!(notice.incident_id(), "maxnines-alert-7");
        }
        let event = eased.pagerduty_event(Incident::Open, "key", None);
        assert_eq!(event["event_action"], "trigger");
        assert_eq!(event["payload"]["severity"], "warning");
        assert_eq!(escalated.webhook_body()["event"], "escalated");
    }

    #[test]
    fn teams_gets_a_card_coloured_by_severity_with_a_link_back() {
        let body = notice(Event::Firing, alert()).teams_body(Some("https://m.example.com"));
        assert_eq!(body["type"], "message");
        let attachment = &body["attachments"][0];
        assert_eq!(
            attachment["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        let card = &attachment["content"];
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["body"][0]["text"], "CRITICAL");
        assert_eq!(card["body"][0]["color"], "Attention");
        assert_eq!(
            card["body"][1]["text"],
            "CPU usage on web-1 is 97%, above 90%"
        );
        let facts = card["body"][2]["facts"].as_array().unwrap();
        assert_eq!(facts[0], json!({ "title": "Rule", "value": "High CPU" }));
        assert_eq!(facts[1]["title"], "Agent");
        assert_eq!(card["actions"][0]["url"], "https://m.example.com/alerts");

        let warning = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        let card = |event, alert| {
            notice(event, alert).teams_body(None)["attachments"][0]["content"].clone()
        };
        assert_eq!(card(Event::Firing, warning)["body"][0]["color"], "Warning");
        let resolved = card(Event::Resolved, alert());
        assert_eq!(resolved["body"][0]["color"], "Good");
        assert!(resolved.get("actions").is_none());
    }

    #[test]
    fn a_host_cannot_add_a_link_to_a_teams_card() {
        let alert = Alert {
            host: "[click](https://evil.example)".to_string(),
            summary: "Disk on [click](https://evil.example) is full".to_string(),
            ..alert()
        };
        let text = notice(Event::Firing, alert).teams_body(None).to_string();
        assert!(!text.contains("](https"), "{text}");
    }

    #[test]
    fn a_host_cannot_ping_a_discord_server() {
        let alert = Alert {
            summary: "@everyone is offline".to_string(),
            ..alert()
        };
        let body = notice(Event::Firing, alert).discord_body();
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
    }

    #[test]
    fn a_long_discord_message_fits_the_limit() {
        let alert = Alert {
            summary: "é".repeat(3000),
            ..alert()
        };
        let body = notice(Event::Firing, alert).discord_body();
        let content = body["content"].as_str().unwrap();
        assert_eq!(content.chars().count(), DISCORD_MAX_CHARS);
    }

    #[test]
    fn telegram_messages_say_what_happened_and_where_to_look() {
        let text = telegram_text(
            &notice(Event::Firing, alert()),
            Some("https://m.example.com"),
        );
        assert_eq!(
            text,
            "<b>CRITICAL</b> CPU usage on web-1 is 97%, above 90%\n\
             Rule: High CPU · Agent: web-1 (abc) · Started: 1970-01-01 00:00:01 UTC\n\
             <a href=\"https://m.example.com/alerts\">View alerts</a>"
        );
        assert_eq!(
            telegram_text(&Notice::test(), None),
            "This is a test notification from MaxNines."
        );
    }

    #[test]
    fn a_resolved_telegram_message_says_why() {
        let alert = Alert {
            resolved_ms: Some(61_000),
            resolve_reason: Some("The problem cleared".to_string()),
            ..alert()
        };
        let text = telegram_text(&notice(Event::Resolved, alert), None);
        assert!(text.starts_with("<b>RESOLVED</b>"), "{text}");
        assert!(text.ends_with("\nReason: The problem cleared"), "{text}");
    }

    #[test]
    fn a_host_cannot_add_markup_to_a_telegram_message() {
        let alert = Alert {
            summary: "<a href=\"http://evil\">click</a> & <b>".to_string(),
            host: "<i>web</i>".to_string(),
            ..alert()
        };
        let text = telegram_text(&notice(Event::Firing, alert), None);
        assert!(
            text.contains("&lt;a href=&quot;http://evil&quot;&gt;click&lt;/a&gt; &amp; &lt;b&gt;"),
            "{text}"
        );
        assert!(text.contains("Agent: &lt;i&gt;web&lt;/i&gt;"), "{text}");
    }

    #[test]
    fn a_long_telegram_message_fits_the_limit() {
        let alert = Alert {
            summary: "😀".repeat(5000),
            host: "&".repeat(5000),
            rule_name: "r".repeat(255),
            ..alert()
        };
        let text = telegram_text(&notice(Event::Firing, alert), Some("https://m.example.com"));
        let shown = text
            .replace("&amp;", "&")
            .replace(['<', '>'], "")
            .encode_utf16()
            .count();
        assert!(shown <= 4096, "{shown}");
        assert_eq!(clip_utf16("a😀b", 2), "a");
        assert_eq!(clip_utf16("a😀b", 3), "a😀");
        assert_eq!(clip_utf16("ab", 10), "ab");
    }

    #[test]
    fn telegram_is_told_not_to_fetch_links_and_replies_to_the_first_message() {
        let message = telegram_message(
            &notice(Event::Resolved, alert()),
            " -100123 ",
            Some("42"),
            None,
        );
        assert_eq!(message["chat_id"], "-100123");
        assert_eq!(message["parse_mode"], "HTML");
        assert_eq!(message["link_preview_options"]["is_disabled"], true);
        assert_eq!(message["reply_parameters"]["message_id"], 42);
        assert_eq!(
            message["reply_parameters"]["allow_sending_without_reply"],
            true
        );

        let message = telegram_message(&notice(Event::Firing, alert()), "-100123", None, None);
        assert!(message.get("reply_parameters").is_none());
    }

    #[test]
    fn common_telegram_problems_say_what_to_do() {
        let said = |text: &str| json!({ "ok": false, "description": text });
        assert_eq!(
            explain_telegram(401, &said("Unauthorized")).to_string(),
            "Telegram didn't accept the bot token (Unauthorized)"
        );
        assert_eq!(
            explain_telegram(400, &said("Bad Request: chat not found")).to_string(),
            "Telegram can't find that chat. Add the bot to the group, or send the bot a \
             message first (Bad Request: chat not found)"
        );
        let upgraded = json!({
            "ok": false,
            "description": "Bad Request: group chat was upgraded to a supergroup chat",
            "parameters": { "migrate_to_chat_id": -1_001_234_567_890_i64 },
        });
        assert_eq!(
            explain_telegram(400, &upgraded).to_string(),
            "the group became a supergroup, so change the chat ID to -1001234567890"
        );
        assert_eq!(
            explain_telegram(400, &said("Bad Request: message is too long")).to_string(),
            "Telegram said: Bad Request: message is too long"
        );
        assert_eq!(
            explain_telegram(502, &Value::Null).to_string(),
            "Telegram returned status 502"
        );
    }

    #[test]
    fn subjects_lead_with_what_happened() {
        assert_eq!(
            notice(Event::Firing, alert()).subject(),
            "[MaxNines CRITICAL] CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            notice(Event::Resolved, alert()).subject(),
            "[MaxNines RESOLVED] CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            Notice::test().subject(),
            "[MaxNines TEST] This is a test notification from MaxNines."
        );
    }

    #[test]
    fn a_resolved_email_says_when_and_why() {
        let alert = Alert {
            resolved_ms: Some(61_000),
            resolve_reason: Some("The problem cleared".to_string()),
            ..alert()
        };
        let body = notice(Event::Resolved, alert).email_body();
        assert!(body.contains("Rule: High CPU"), "{body}");
        assert!(body.contains("Agent: web-1 (abc)"), "{body}");
        assert!(body.contains("Resolved: 1970-01-01 00:01:01 UTC"), "{body}");
        assert!(body.contains("Reason: The problem cleared"), "{body}");
    }

    #[test]
    fn a_firing_email_has_no_end_yet() {
        let body = notice(Event::Firing, alert()).email_body();
        assert!(!body.contains("Resolved:"), "{body}");
        assert!(!body.contains("Reason:"), "{body}");
    }

    #[test]
    fn webhooks_get_a_versioned_body_with_plain_text() {
        let body = notice(Event::Firing, alert()).webhook_body();
        assert_eq!(body["version"], 1);
        assert_eq!(body["id"], 3);
        assert_eq!(body["event"], "firing");
        assert_eq!(body["text"], "CPU usage on web-1 is 97%, above 90%");
        assert_eq!(body["alert"]["severity"], "critical");
        assert_eq!(body["alert"]["agent_id"], "abc");
    }
}
