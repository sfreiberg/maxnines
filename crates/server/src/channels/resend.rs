//! Email through Resend's API, for a server that can't reach a mail server or
//! would rather not run one. The from address has to be on a domain verified in
//! Resend.

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::email::{check_recipients, html, recipients, sender, subject, text};
use super::{ChannelType, agent, blocking, explain_http};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders};

/// Where emails are sent.
pub const EMAILS_URL: &str = "https://api.resend.com/emails";
/// What the chart is called in the HTML, which Resend matches to its attachment.
const CHART_ID: &str = "chart";

pub struct Resend;

/// What Resend is asked to send. With a chart, there's HTML showing it beside the
/// plain text.
fn body(channel: &ChannelInput, notice: &Notice) -> Result<Value> {
    let mail = channel
        .mail
        .as_ref()
        .context("this channel needs a from address")?;
    let to: Vec<String> = recipients(&channel.target)?
        .into_iter()
        .map(|address| address.to_string())
        .collect();
    let mut body = json!({
        "from": sender(mail)?.to_string(),
        "to": to,
        "subject": subject(notice),
        "text": text(notice),
    });
    if let Some(chart) = &notice.chart {
        body["html"] = json!(html(notice));
        body["attachments"] = json!([{
            "filename": "chart.png",
            "content": STANDARD.encode(chart.as_slice()),
            "content_type": "image/png",
            "content_id": CHART_ID,
        }]);
    }
    Ok(body)
}

/// Resend keeps a key for a day, so a retry after a timeout isn't sent twice. The
/// alert's start time tells apart deliveries with the same number on two servers
/// sharing an account. A test isn't queued, so it has none.
fn idempotency_key(channel: &Channel, notice: &Notice) -> Option<String> {
    let alert = notice.alert.as_ref().filter(|_| notice.id > 0)?;
    Some(format!(
        "maxnines-{}-{}-{}",
        alert.started_ms, channel.id, notice.id
    ))
}

/// What went wrong, in Resend's words where they help, without repeating the key.
fn explain(status: u16, reply: &str) -> anyhow::Error {
    let name = serde_json::from_str::<Value>(reply)
        .ok()
        .and_then(|reply| reply["name"].as_str().map(str::to_string));
    match (status, name.as_deref()) {
        (401 | 403, Some("restricted_api_key")) => {
            anyhow!("Resend says the API key can't send, or isn't active")
        }
        (401, _) => anyhow!("Resend didn't accept the API key"),
        (403, _) => {
            anyhow!("Resend refused it: check the from address is on a domain verified in Resend")
        }
        (429, Some("daily_quota_exceeded" | "monthly_quota_exceeded")) => {
            anyhow!("the Resend account has used up its quota")
        }
        (429, _) => anyhow!("Resend is limiting how fast emails are sent"),
        (400 | 422, _) => anyhow!("Resend refused the email as invalid"),
        (status, _) => anyhow!("Resend returned status {status}"),
    }
}

fn post(url: &str, key: &str, idempotency: Option<&str>, body: &Value) -> Result<Option<String>> {
    let mut request = agent()
        .post(url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json");
    if let Some(idempotency) = idempotency {
        request = request.header("idempotency-key", idempotency);
    }
    let mut response = request
        .send(body.to_string().as_bytes())
        .map_err(|error| explain_http("Resend", &error))?;
    let status = response.status().as_u16();
    let reply = response.body_mut().read_to_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(explain(status, &reply));
    }
    let id = serde_json::from_str::<Value>(&reply)
        .ok()
        .and_then(|reply| reply["id"].as_str().map(str::to_string));
    Ok(id)
}

#[async_trait::async_trait]
impl ChannelType for Resend {
    fn name(&self) -> &'static str {
        "Resend"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        check_recipients(&channel.target)?;
        let mail = channel
            .mail
            .as_ref()
            .context("add who the email comes from, on a domain verified in Resend")?;
        sender(mail)?;
        ensure!(
            mail.server.is_none(),
            "Resend sends the email itself, so it doesn't take a mail server"
        );
        match channel.credential.as_deref() {
            None => bail!("add the Resend API key"),
            Some(key) if key.chars().any(char::is_whitespace) => {
                bail!("the API key has spaces in it, so it wasn't copied whole")
            }
            Some(_) => Ok(()),
        }
    }

    /// The API key.
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
        senders: &Senders,
    ) -> Result<Option<String>> {
        let body = body(&channel.channel, notice)?;
        let key = channel
            .channel
            .credential
            .clone()
            .context("this channel needs a Resend API key")?;
        let idempotency = idempotency_key(channel, notice);
        let url = senders.resend_url().to_string();
        // The email's ID only matters to Resend.
        blocking(move || post(&url, &key, idempotency.as_deref(), &body).map(|_| None)).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::alerting::{ChannelKind, Event, Mail, every_severity};
    use crate::channels::testing::{alert, notice};

    fn channel() -> ChannelInput {
        ChannelInput {
            name: "Ops".into(),
            kind: ChannelKind::Resend,
            target: "a@example.com, b@example.com".into(),
            credential: Some("re_123".into()),
            app_token: None,
            severities: every_severity(),
            mail: Some(Mail {
                from: "MaxNines <alerts@example.com>".into(),
                server: None,
            }),
        }
    }

    #[test]
    fn a_chart_goes_inline_beside_the_plain_text() {
        let charted = Notice {
            chart: Some(Arc::new(b"\x89PNG".to_vec())),
            ..notice(Event::Firing, alert())
        };

        let body = body(&channel(), &charted).unwrap();

        assert_eq!(body["from"], "MaxNines <alerts@example.com>");
        assert_eq!(body["to"], json!(["a@example.com", "b@example.com"]));
        assert_eq!(
            body["subject"],
            "[MaxNines CRITICAL] CPU usage on web-1 is 97%, above 90%"
        );
        assert!(body["html"].as_str().unwrap().contains("cid:chart"));
        assert_eq!(body["attachments"][0]["content_id"], CHART_ID);
        assert_eq!(
            body["attachments"][0]["content"],
            STANDARD.encode(b"\x89PNG")
        );
        let plain = super::body(&channel(), &notice(Event::Firing, alert())).unwrap();
        assert!(plain.get("html").is_none() && plain.get("attachments").is_none());
    }

    #[test]
    fn only_queued_deliveries_have_an_idempotency_key() {
        let saved = Channel {
            id: 4,
            channel: channel(),
        };
        let queued = notice(Event::Firing, alert());
        assert_eq!(
            idempotency_key(&saved, &queued).as_deref(),
            Some("maxnines-1000-4-3")
        );
        assert_eq!(idempotency_key(&saved, &Notice::test()), None);
    }

    #[test]
    fn a_channel_needs_a_key_and_a_from_address_but_no_mail_server() {
        assert!(Resend.check(&channel()).is_ok());
        let keyless = ChannelInput {
            credential: None,
            ..channel()
        };
        assert!(format!("{:#}", Resend.check(&keyless).unwrap_err()).contains("API key"));
        let fromless = ChannelInput {
            mail: None,
            ..channel()
        };
        assert!(Resend.check(&fromless).is_err());
    }

    #[test]
    fn errors_say_what_to_fix_without_the_key() {
        let unverified = r#"{"statusCode":403,"name":"validation_error","message":"The x.com domain is not verified"}"#;
        assert!(explain(403, unverified).to_string().contains("verified"));
        assert!(explain(401, "").to_string().contains("API key"));
        let quota = r#"{"name":"daily_quota_exceeded"}"#;
        assert!(explain(429, quota).to_string().contains("quota"));
    }
}
