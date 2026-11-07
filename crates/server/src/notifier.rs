//! Delivers notifications from the queue. Deliveries are at least once: a crash
//! between sending and saving sends it again, so webhooks carry an ID to spot that.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use hyper_rustls::HttpsConnectorBuilder;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::Serialize;
use serde_json::{Value, json};
use slack_morphism::api::{SlackApiChatPostMessageRequest, SlackApiChatUpdateRequest};
use slack_morphism::errors::SlackClientError;
use slack_morphism::prelude::{SlackClientHyperConnector, SlackClientHyperHttpsConnector};
use slack_morphism::{
    SlackApiToken, SlackApiTokenValue, SlackChannelId, SlackClient, SlackClientHttpConnector,
    SlackMessageAttachment, SlackMessageContent, SlackTs,
};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, timeout};
use tracing::{error, info, warn};

use crate::alerting::{Alert, Channel, ChannelKind, Delivery, Event, Severity, recipients};
use crate::config::{EmailConfig, EmailSecurity};
use crate::metrics::now_ms;
use crate::models::Database;
use crate::remote_checks::FLEET_AGENT_ID;
use crate::silences::ActiveSilences;

/// How often the queue is checked.
const INTERVAL: Duration = Duration::from_secs(5);

/// How many deliveries run at once, which also limits how many a pass can take.
const BATCH_SIZE: usize = 16;

/// How long one delivery can take.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest message Discord accepts.
const DISCORD_MAX_CHARS: usize = 2000;

/// Where PagerDuty takes events.
const PAGERDUTY_EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";
/// The longest summary PagerDuty accepts.
const PAGERDUTY_MAX_SUMMARY_CHARS: usize = 1024;
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
}

impl Notice {
    pub fn for_delivery(delivery: &Delivery) -> Self {
        let alert = &delivery.alert;
        let text = match delivery.event {
            Event::Resolved => format!("Resolved: {}", alert.summary),
            _ => alert.summary.clone(),
        };
        Self {
            id: delivery.id,
            event: delivery.event,
            alert: Some(alert.clone()),
            text,
        }
    }

    pub fn test() -> Self {
        Self {
            id: 0,
            event: Event::Test,
            alert: None,
            text: "This is a test notification from MaxNines.".to_string(),
        }
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

    /// What this means for an on-call service. A test has to open an incident to prove
    /// anything, so it closes it again rather than leave someone paged.
    fn incident_steps(&self) -> &'static [Incident] {
        match self.event {
            Event::Firing => &[Incident::Open],
            Event::Resolved => &[Incident::Close],
            Event::Test => &[Incident::Open, Incident::Close],
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

fn format_ms(ms: i64) -> String {
    u64::try_from(ms).map_or_else(|_| ms.to_string(), crate::fact_history::format_time)
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
        let mut message = Message::builder()
            .from(self.from.clone())
            .subject(notice.subject());
        for address in recipients(to)? {
            message = message.to(Mailbox::new(None, address));
        }
        let message = message
            .header(ContentType::TEXT_PLAIN)
            .body(notice.email_body())
            .context("building the email")?;

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

fn alerts_link(web_url: &str) -> String {
    format!("{web_url}/alerts")
}

/// What AlertOps' sample data box needs, to map its fields from.
pub fn alertops_sample() -> String {
    let event = Notice::test().alertops_event(Incident::Open, Some("https://maxnines.example.com"));
    serde_json::to_string_pretty(&event).unwrap_or_default()
}

/// Errors are saved and shown, and a webhook's URL is often its password, so
/// they only ever say what kind of failure it was. `who` is what to call the receiver.
fn post_json(who: &str, url: &str, body: &Value) -> Result<()> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(SEND_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("MaxNines/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent();

    let body = body.to_string();
    let result = agent
        .post(url.trim())
        .header("content-type", "application/json")
        .send(body.as_bytes());
    match result {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => bail!("{who} returned status {}", response.status().as_u16()),
        Err(ureq::Error::Timeout(_)) => bail!("{who} timed out"),
        Err(ureq::Error::HostNotFound) => bail!("{who}'s host wasn't found"),
        Err(ureq::Error::ConnectionFailed | ureq::Error::Io(_)) => {
            bail!("couldn't connect to {who}")
        }
        Err(ureq::Error::Tls(_) | ureq::Error::Rustls(_)) => {
            bail!("{who}'s certificate wasn't accepted")
        }
        Err(_) => bail!("the request to {who} failed"),
    }
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
        }
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
        (Event::Firing, Some(alert)) if alert.severity == Severity::Critical => "#b3261e",
        (Event::Firing, Some(_)) => "#b87a00",
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
        format!(
            "{}: {}",
            if alert.agent_id == FLEET_AGENT_ID {
                "Machines"
            } else {
                "Agent"
            },
            escape_slack(&alert.host)
        ),
        format!("Started: {}", format_ms(alert.started_ms)),
    ];
    if let Some(url) = web_url {
        details.push(format!("<{url}/alerts|View alerts>"));
    }
    lines.push(details.join(" · "));
    lines.join("\n")
}

fn slack_content(notice: &Notice, web_url: Option<&str>) -> SlackMessageContent {
    let attachment = SlackMessageAttachment::new()
        .with_color(slack_color(notice).to_string())
        .with_text(slack_text(notice, web_url))
        .with_mrkdwn_in(vec!["text".to_string()]);
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
fn slack_connector() -> Result<SlackClientHyperHttpsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider)
        .map_err(|_| anyhow!("couldn't set up TLS for Slack"))?
        .https_only()
        .enable_http2()
        .build();
    Ok(SlackClientHyperConnector::with_connector(https))
}

/// The channel and timestamp that together name a Slack message.
fn slack_message_id(external_id: &str) -> Option<(SlackChannelId, SlackTs)> {
    let (channel, ts) = external_id.split_once(':')?;
    Some((SlackChannelId(channel.to_string()), SlackTs(ts.to_string())))
}

/// Slack's error codes are safe to keep and say what's wrong, but anything else
/// could quote the request, which holds the token.
fn explain_slack(error: &SlackClientError) -> anyhow::Error {
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
    let content = slack_content(notice, web_url);

    if let Some((message_channel, ts)) = reply_to
        .filter(|_| notice.event == Event::Resolved)
        .and_then(slack_message_id)
    {
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

    let target = SlackChannelId(channel.channel.target.trim().to_string());
    let request = slack_post(target, content);
    let response = session
        .chat_post_message(&request)
        .await
        .map_err(|error| explain_slack(&error))?;
    Ok(Some(format!("{}:{}", response.channel, response.ts)))
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

/// Sends one notification. Blocks, so it can't run on an async thread.
fn send_blocking(channel: &Channel, notice: &Notice, senders: &Senders) -> Result<()> {
    let target = &channel.channel.target;
    let web_url = senders.web_url.as_deref();
    match channel.channel.kind {
        ChannelKind::Webhook => post_json("the webhook", target, &notice.webhook_body()),
        ChannelKind::Discord => post_json("the webhook", target, &notice.discord_body()),
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
        ChannelKind::Slack => bail!("Slack doesn't send this way"),
    }
}

/// Sends one notification, and gives what the service called it if that matters
/// later. A panic counts as a failed delivery.
pub async fn send(
    channel: Channel,
    notice: Notice,
    reply_to: Option<String>,
    senders: Senders,
) -> Result<Option<String>> {
    if channel.channel.kind == ChannelKind::Slack {
        return timeout(
            SEND_TIMEOUT,
            send_to_slack(&channel, &notice, reply_to.as_deref(), &senders),
        )
        .await
        .map_err(|_| anyhow!("Slack timed out"))?;
    }

    tokio::task::spawn_blocking(move || send_blocking(&channel, &notice, &senders))
        .await
        .map_err(|_| anyhow!("sending failed unexpectedly"))??;
    Ok(None)
}

#[derive(Clone)]
pub struct Notifier {
    database: Database,
    senders: Senders,
}

impl Notifier {
    pub fn new(database: Database, senders: Senders) -> Self {
        Self { database, senders }
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

    /// Lets go of what no silence covers any more.
    async fn release_held(&self, silences: &ActiveSilences, now_ms: i64) -> Result<()> {
        let ids: Vec<i64> = self
            .database
            .held_deliveries()
            .await?
            .into_iter()
            .filter(|(alert, _)| silences.covering(alert).is_none())
            .flat_map(|(_, ids)| ids)
            .collect();
        if !ids.is_empty() {
            self.database.release_deliveries(&ids, now_ms).await?;
        }
        Ok(())
    }

    /// Sends what's due, and saves how each one went. Someone who was told an alert
    /// started always hears that it ended, or an on-call incident would stay open.
    pub async fn deliver_due(&self, now_ms: i64) -> Result<()> {
        let silences = ActiveSilences::load(&self.database, now_ms).await?;
        self.release_held(&silences, now_ms).await?;
        let due = self.database.due_deliveries(now_ms, BATCH_SIZE).await?;

        let mut sends = JoinSet::new();
        for delivery in due {
            if delivery.event == Event::Firing && silences.covering(&delivery.alert).is_some() {
                self.database.hold_delivery(&delivery).await?;
                continue;
            }
            let senders = self.senders.clone();
            sends.spawn(async move {
                let notice = Notice::for_delivery(&delivery);
                let reply_to = delivery.reply_to.clone();
                let result = send(delivery.channel.clone(), notice, reply_to, senders).await;
                (delivery, result)
            });
        }

        while let Some(finished) = sends.join_next().await {
            let (delivery, result) = finished.context("a delivery stopped unexpectedly")?;
            self.record(&delivery, result, now_ms).await?;
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
        }
    }

    fn notice(event: Event, alert: Alert) -> Notice {
        let text = alert.summary.clone();
        Notice {
            id: 3,
            event,
            alert: Some(alert),
            text,
        }
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

        let content = slack_content(&notice, None);
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

    #[test]
    fn slack_is_told_not_to_fetch_links() {
        let request = slack_post(SlackChannelId("C1".to_string()), SlackMessageContent::new());
        assert_eq!(request.unfurl_links, Some(false));
        assert_eq!(request.unfurl_media, Some(false));
    }

    #[test]
    fn a_message_id_needs_both_parts() {
        let (channel, ts) = slack_message_id("C1:12.34").unwrap();
        assert_eq!(channel.0, "C1");
        assert_eq!(ts.0, "12.34");
        assert!(slack_message_id("nonsense").is_none());
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
