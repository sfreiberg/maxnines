//! Delivers notifications from the queue. Deliveries are at least once: a crash
//! between sending and saving sends it again, so webhooks carry an ID to spot that.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::alerting::{Alert, Channel, ChannelKind, Delivery, Event, recipients};
use crate::config::{EmailConfig, EmailSecurity};
use crate::metrics::now_ms;
use crate::models::Database;

/// How often the queue is checked.
const INTERVAL: Duration = Duration::from_secs(5);

/// How many deliveries run at once, which also limits how many a pass can take.
const BATCH_SIZE: usize = 16;

/// How long one delivery can take.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

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

    fn subject(&self) -> String {
        let label = match (self.event, &self.alert) {
            (Event::Firing, Some(alert)) => alert.severity.as_str().to_uppercase(),
            (Event::Resolved, _) => "RESOLVED".to_string(),
            _ => "TEST".to_string(),
        };
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
            format!("Agent: {} ({})", alert.host, alert.agent_id),
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

/// Errors are saved and shown, and a webhook's URL is often its password, so
/// they only ever say what kind of failure it was.
fn post_webhook(url: &str, notice: &Notice) -> Result<()> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(SEND_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("MaxNines/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent();

    let body = notice.webhook_body().to_string();
    let result = agent
        .post(url.trim())
        .header("content-type", "application/json")
        .send(body.as_bytes());
    match result {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => bail!("the webhook returned status {}", response.status().as_u16()),
        Err(ureq::Error::Timeout(_)) => bail!("the webhook timed out"),
        Err(ureq::Error::HostNotFound) => bail!("the webhook's host wasn't found"),
        Err(ureq::Error::ConnectionFailed | ureq::Error::Io(_)) => {
            bail!("couldn't connect to the webhook")
        }
        Err(ureq::Error::Tls(_) | ureq::Error::Rustls(_)) => {
            bail!("the webhook's certificate wasn't accepted")
        }
        Err(_) => bail!("the webhook request failed"),
    }
}

/// Sends one notification. Blocks, so it can't run on an async thread.
fn send_blocking(channel: &Channel, notice: &Notice, mailer: Option<&Mailer>) -> Result<()> {
    match channel.channel.kind {
        ChannelKind::Webhook => post_webhook(&channel.channel.target, notice),
        ChannelKind::Email => mailer
            .context("email isn't set up in the server config")?
            .send(&channel.channel.target, notice),
    }
}

/// Sends one notification. A panic counts as a failed delivery.
pub async fn send(channel: Channel, notice: Notice, mailer: Option<Arc<Mailer>>) -> Result<()> {
    tokio::task::spawn_blocking(move || send_blocking(&channel, &notice, mailer.as_deref()))
        .await
        .map_err(|_| anyhow!("sending failed unexpectedly"))?
}

#[derive(Clone)]
pub struct Notifier {
    database: Database,
    mailer: Option<Arc<Mailer>>,
}

impl Notifier {
    pub fn new(database: Database, mailer: Option<Arc<Mailer>>) -> Self {
        Self { database, mailer }
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

    /// Sends what's due, and saves how each one went.
    pub async fn deliver_due(&self, now_ms: i64) -> Result<()> {
        let due = self.database.due_deliveries(now_ms, BATCH_SIZE).await?;

        let mut sends = JoinSet::new();
        for delivery in due {
            let mailer = self.mailer.clone();
            sends.spawn(async move {
                let notice = Notice::for_delivery(&delivery);
                let result = send(delivery.channel.clone(), notice, mailer).await;
                (delivery, result)
            });
        }

        while let Some(finished) = sends.join_next().await {
            let (delivery, result) = finished.context("a delivery stopped unexpectedly")?;
            self.record(&delivery, result, now_ms).await?;
        }
        Ok(())
    }

    async fn record(&self, delivery: &Delivery, result: Result<()>, now_ms: i64) -> Result<()> {
        let attempts = delivery.attempts.saturating_add(1);
        let channel = &delivery.channel.channel.name;
        match result {
            Ok(()) => {
                info!(
                    channel,
                    event = delivery.event.as_str(),
                    "notification sent"
                );
                self.database
                    .delivery_sent(delivery.id, attempts, now_ms)
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
    use crate::alerting::Severity;

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
