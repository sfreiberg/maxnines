//! Email, through the mail server in the server's config.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, Message, SmtpTransport, Transport};

use super::{ChannelType, SEND_TIMEOUT, blocking};
use crate::alerting::{Channel, ChannelInput};
use crate::config::{EmailConfig, EmailSecurity};
use crate::notifier::{Notice, Senders, format_ms};
use crate::remote_checks::FLEET_AGENT_ID;

pub(crate) const MAX_RECIPIENTS: usize = 20;

pub struct Email;

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
        let message = message(&self.from, to, notice)?;
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

/// Email addresses separated by commas.
pub fn recipients(target: &str) -> Result<Vec<Address>> {
    target
        .split(',')
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(|address| {
            address
                .parse()
                .map_err(|_| anyhow!("{address:?} isn't a valid email address"))
        })
        .collect()
}

fn subject(notice: &Notice) -> String {
    let label = notice.label();
    let summary = notice
        .alert
        .as_ref()
        .map_or(notice.text.as_str(), |a| &a.summary);
    format!("[MaxNines {label}] {summary}")
}

fn text(notice: &Notice) -> String {
    let Some(alert) = &notice.alert else {
        return format!("{}\n", notice.text);
    };
    let mut lines = vec![
        notice.text.clone(),
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

/// For the HTML part of an email.
fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The plain text, with the chart under it.
fn html(notice: &Notice) -> String {
    format!(
        "<!doctype html><html><body>\
         <pre style=\"font-family: sans-serif; white-space: pre-wrap\">{}</pre>\
         <img src=\"cid:chart\" alt=\"{}\" width=\"720\" style=\"max-width: 100%\">\
         </body></html>",
        escape_html(&text(notice)),
        escape_html(&notice.chart_description())
    )
}

/// Plain text, or with a chart, plain text beside HTML that shows it.
fn message(from: &Mailbox, to: &str, notice: &Notice) -> Result<Message> {
    let mut message = Message::builder()
        .from(from.clone())
        .subject(subject(notice));
    for address in recipients(to)? {
        message = message.to(Mailbox::new(None, address));
    }
    let message = match &notice.chart {
        None => message.header(ContentType::TEXT_PLAIN).body(text(notice)),
        Some(chart) => {
            let png = ContentType::parse("image/png").context("naming the chart's type")?;
            let shown = MultiPart::related()
                .singlepart(SinglePart::html(html(notice)))
                .singlepart(Attachment::new_inline("chart".to_string()).body(chart.to_vec(), png));
            message.multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text(notice)))
                    .multipart(shown),
            )
        }
    }
    .context("building the email")?;
    Ok(message)
}

#[async_trait::async_trait]
impl ChannelType for Email {
    fn name(&self) -> &'static str {
        "Email"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        let recipients = recipients(&channel.target)?;
        ensure!(!recipients.is_empty(), "add at least one email address");
        ensure!(
            recipients.len() <= MAX_RECIPIENTS,
            "a channel can have at most {MAX_RECIPIENTS} email addresses"
        );
        Ok(())
    }

    fn shows_charts(&self) -> bool {
        true
    }

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>> {
        let mailer: Arc<Mailer> = senders
            .mailer
            .clone()
            .context("email isn't set up in the server config")?;
        let to = channel.channel.target.clone();
        let notice = notice.clone();
        blocking(move || mailer.send(&to, &notice).map(|()| None)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{Alert, Event};
    use crate::channels::testing::{alert, notice};

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
        let email = message(&from, "ops@example.com", &charted).unwrap();
        let text = String::from_utf8_lossy(&email.formatted()).to_string();

        assert!(text.contains("multipart/alternative"), "{text}");
        assert!(text.contains("multipart/related"));
        assert!(text.contains("Content-ID: <chart>"));
        assert!(text.contains("Content-Type: image/png"));
        assert!(text.contains("src=3D\"cid:chart\"") || text.contains("src=\"cid:chart\""));
        assert!(text.contains("web-&lt;1&gt;"), "{text}");

        let plain = message(&from, "ops@example.com", &notice(Event::Firing, alert())).unwrap();
        let text = String::from_utf8_lossy(&plain.formatted()).to_string();
        assert!(!text.contains("multipart"));
    }

    #[test]
    fn subjects_lead_with_what_happened() {
        assert_eq!(
            subject(&notice(Event::Firing, alert())),
            "[MaxNines CRITICAL] CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            subject(&notice(Event::Resolved, alert())),
            "[MaxNines RESOLVED] CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            subject(&Notice::test()),
            "[MaxNines TEST] This is a test notification from MaxNines."
        );
        let eased = Alert {
            severity: crate::alerting::Severity::Warning,
            summary: "CPU usage on web-1 is 85%, above 80%".to_string(),
            ..alert()
        };
        assert_eq!(
            subject(&notice(Event::Eased, eased)),
            "[MaxNines NOW WARNING] CPU usage on web-1 is 85%, above 80%"
        );
    }

    #[test]
    fn a_resolved_email_says_when_and_why() {
        let alert = Alert {
            resolved_ms: Some(61_000),
            resolve_reason: Some("The problem cleared".to_string()),
            ..alert()
        };
        let body = text(&notice(Event::Resolved, alert));
        assert!(body.contains("Rule: High CPU"), "{body}");
        assert!(body.contains("Agent: web-1 (abc)"), "{body}");
        assert!(body.contains("Resolved: 1970-01-01 00:01:01 UTC"), "{body}");
        assert!(body.contains("Reason: The problem cleared"), "{body}");
    }

    #[test]
    fn a_firing_email_has_no_end_yet() {
        let body = text(&notice(Event::Firing, alert()));
        assert!(!body.contains("Resolved:"), "{body}");
        assert!(!body.contains("Reason:"), "{body}");
    }
}
