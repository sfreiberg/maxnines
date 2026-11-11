//! Email, through the mail server set on the channel.

use anyhow::{Context, Result, anyhow, bail, ensure};
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, Message, SmtpTransport, Transport};

use super::{ChannelType, SEND_TIMEOUT, blocking};
use crate::alerting::{Channel, ChannelInput, Mail, MailSecurity, MailServer};
use crate::notifier::{Notice, Senders, format_ms};
use crate::remote_checks::FLEET_HOST_ID;

pub(crate) const MAX_RECIPIENTS: usize = 20;
/// The longest hostname DNS allows.
const MAX_HOST_LEN: usize = 253;
const MAX_USERNAME_LEN: usize = 255;

pub struct Email;

/// The channel's mail server, ready to send.
fn transport(server: &MailServer, password: Option<&str>) -> Result<SmtpTransport> {
    let hostname = server.hostname.trim();
    let mut builder = match server.security {
        MailSecurity::Tls => SmtpTransport::relay(hostname)?,
        MailSecurity::Starttls => SmtpTransport::starttls_relay(hostname)?,
        MailSecurity::None => SmtpTransport::builder_dangerous(hostname),
    };
    if let Some(port) = server.port {
        builder = builder.port(port);
    }
    if let Some(username) = &server.username {
        let password = password.unwrap_or_default().to_string();
        builder = builder.credentials(Credentials::new(username.clone(), password));
    }
    Ok(builder.timeout(Some(SEND_TIMEOUT)).build())
}

/// Sends through the channel's own mail server. Errors only say how it failed, as
/// a mail server's reply can repeat what it was sent.
fn send_through(channel: &ChannelInput, notice: &Notice) -> Result<()> {
    let (from, server) = settings(channel)?;
    let message = message(&from, &channel.target, notice)?;
    transport(server, channel.credential.as_deref())?
        .send(&message)
        .map_err(|error| match error.status() {
            Some(code) => anyhow!("the mail server refused it with code {code}"),
            None if error.is_timeout() => anyhow!("the mail server timed out"),
            None => anyhow!("couldn't reach the mail server"),
        })?;
    Ok(())
}

/// Who it's from and the server it goes through, which every email channel needs.
fn settings(channel: &ChannelInput) -> Result<(Mailbox, &MailServer)> {
    let mail = channel
        .mail
        .as_ref()
        .context("this channel needs a from address and a mail server")?;
    let server = mail
        .server
        .as_ref()
        .context("this channel needs a mail server")?;
    Ok((sender(mail)?, server))
}

/// Who email comes from, as written on the channel.
pub(super) fn sender(mail: &Mail) -> Result<Mailbox> {
    mail.from
        .trim()
        .parse()
        .map_err(|_| anyhow!("{:?} isn't a valid from address", mail.from.trim()))
}

/// The addresses a channel sends to, which every email channel checks the same way.
pub(super) fn check_recipients(target: &str) -> Result<()> {
    let recipients = recipients(target)?;
    ensure!(!recipients.is_empty(), "add at least one email address");
    ensure!(
        recipients.len() <= MAX_RECIPIENTS,
        "a channel can have at most {MAX_RECIPIENTS} email addresses"
    );
    Ok(())
}

fn check_server(server: &MailServer, has_password: bool) -> Result<()> {
    let hostname = server.hostname.trim();
    ensure!(!hostname.is_empty(), "add the mail server's hostname");
    ensure!(
        hostname.len() <= MAX_HOST_LEN && !hostname.chars().any(|c| c.is_whitespace() || c == '/'),
        "the mail server's hostname should be a name like smtp.example.com, without anything else"
    );
    ensure!(server.port != Some(0), "the mail server's port can't be 0");
    match &server.username {
        Some(username) => {
            ensure!(
                !username.trim().is_empty() && username.len() <= MAX_USERNAME_LEN,
                "the mail server's username isn't valid"
            );
            ensure!(
                has_password,
                "add the password for the mail server's username"
            );
            ensure!(
                server.security != MailSecurity::None,
                "choose TLS or STARTTLS to sign in to the mail server, as without \
                 encryption the password would cross the network for anyone to read"
            );
        }
        None if has_password => bail!("add the username that goes with the password"),
        None => {}
    }
    Ok(())
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

pub(super) fn subject(notice: &Notice) -> String {
    let label = notice.label();
    let summary = notice
        .alert
        .as_ref()
        .map_or(notice.text.as_str(), |a| &a.summary);
    format!("[MaxNines {label}] {summary}")
}

pub(super) fn text(notice: &Notice) -> String {
    let Some(alert) = &notice.alert else {
        return format!("{}\n", notice.text);
    };
    let mut lines = vec![
        notice.text.clone(),
        String::new(),
        format!("Rule: {}", alert.rule_name),
        format!("Severity: {}", alert.severity.as_str()),
        if alert.host_id == FLEET_HOST_ID {
            format!("Hosts: {}", alert.hostname)
        } else {
            format!("Host: {} ({})", alert.hostname, alert.host_id)
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
pub(super) fn html(notice: &Notice) -> String {
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
        check_recipients(&channel.target)?;
        let mail = channel
            .mail
            .as_ref()
            .context("add who the email comes from and the mail server it goes through")?;
        sender(mail)?;
        let server = mail
            .server
            .as_ref()
            .context("add the mail server the email goes through")?;
        check_server(server, channel.credential.is_some())
    }

    /// The mail server's password.
    fn has_credential(&self) -> bool {
        true
    }

    fn sends_mail(&self) -> bool {
        true
    }

    fn shows_charts(&self) -> bool {
        true
    }

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        _senders: &Senders,
    ) -> Result<Option<String>> {
        let channel = channel.channel.clone();
        let notice = notice.clone();
        blocking(move || send_through(&channel, &notice).map(|()| None)).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::alerting::{Alert, Event};
    use crate::channels::testing::{alert, notice};

    #[test]
    fn an_email_with_a_chart_shows_it_beside_the_plain_text() {
        let from: Mailbox = "maxnines@example.com".parse().unwrap();
        let odd_host = Alert {
            hostname: "web-<1>".to_string(),
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
        assert!(body.contains("Host: web-1 (abc)"), "{body}");
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
