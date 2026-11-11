//! A Discord channel's webhook, with the chart attached when there is one.

use anyhow::{Context, Result, anyhow, ensure};
use axum::http::Uri;
use serde_json::{Value, json};
use ureq::unversioned::multipart::{Form, Part};

use super::{ChannelType, accepted, blocking, chart_part, post_form, post_json, url_preview};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders, Tone};

/// The longest message Discord accepts.
const MAX_CHARS: usize = 2000;

/// Where Discord's webhooks live, including its test builds and older domain.
const HOSTS: [&str; 4] = [
    "discord.com",
    "discordapp.com",
    "ptb.discord.com",
    "canary.discord.com",
];

pub struct Discord;

/// A circle in the colour Slack's messages use, so how bad it is shows at a glance.
fn circle(tone: Tone) -> &'static str {
    match tone {
        Tone::Critical => "🔴 ",
        Tone::Warning => "🟡 ",
        Tone::Clear => "🟢 ",
        Tone::Neutral => "",
    }
}

/// Mentions are turned off, as agents choose their own names and one called
/// `@everyone` would otherwise ping a whole server.
fn body(notice: &Notice) -> Value {
    let summary = notice
        .alert
        .as_ref()
        .map_or(notice.text.as_str(), |a| &a.summary);
    let circle = circle(notice.tone());
    let content: String = format!("{circle}**{}** {summary}", notice.label())
        .chars()
        .take(MAX_CHARS)
        .collect();
    json!({ "content": content, "allowed_mentions": { "parse": [] } })
}

/// The message, with the chart attached when there is one, which Discord shows
/// under the text.
fn post(url: &str, body: &Value, chart: Option<&[u8]>) -> Result<()> {
    let Some(chart) = chart else {
        return post_json("the webhook", url, body);
    };
    let payload = body.to_string();
    let json = Part::text(&payload)
        .mime_str("application/json")
        .context("naming the message's type")?;
    let form = Form::new()
        .part("payload_json", json)
        .part("files[0]", chart_part(chart)?);
    accepted("the webhook", post_form(url, form))
}

#[async_trait::async_trait]
impl ChannelType for Discord {
    fn name(&self) -> &'static str {
        "Discord"
    }

    /// Catches pasting the wrong thing here, which would otherwise only show up when
    /// the first alert failed to arrive. Errors don't repeat the URL.
    fn check(&self, channel: &ChannelInput) -> Result<()> {
        let uri: Uri = channel
            .target
            .trim()
            .parse()
            .map_err(|_| anyhow!("the Discord webhook URL isn't valid"))?;
        let hostname = uri.host().unwrap_or_default();
        ensure!(
            uri.scheme_str() == Some("https")
                && HOSTS.contains(&hostname)
                && uri.path().starts_with("/api/webhooks/"),
            "that doesn't look like a Discord webhook URL, which starts with \
             https://discord.com/api/webhooks/"
        );
        Ok(())
    }

    fn preview(&self, target: &str) -> String {
        url_preview(target)
    }

    fn hides_target(&self) -> bool {
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
        let target = channel.channel.target.clone();
        let body = body(notice);
        let chart = notice.chart.clone();
        blocking(move || post(&target, &body, chart.as_deref().map(Vec::as_slice)).map(|()| None))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{Alert, Event};
    use crate::channels::testing::{alert, notice};

    #[test]
    fn discord_messages_lead_with_what_happened() {
        assert_eq!(
            body(&notice(Event::Firing, alert()))["content"],
            "🔴 **CRITICAL** CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            body(&notice(Event::Resolved, alert()))["content"],
            "🟢 **RESOLVED** CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            body(&notice(Event::Escalated, alert()))["content"],
            "🔴 **NOW CRITICAL** CPU usage on web-1 is 97%, above 90%"
        );
    }

    #[test]
    fn discord_messages_show_how_bad_it_is_as_a_circle() {
        let warning = Alert {
            severity: crate::alerting::Severity::Warning,
            ..alert()
        };
        let starts = |notice: Notice| {
            body(&notice)["content"]
                .as_str()
                .unwrap()
                .chars()
                .next()
                .unwrap()
        };
        assert_eq!(starts(notice(Event::Firing, warning.clone())), '🟡');
        assert_eq!(starts(notice(Event::Reminder, warning.clone())), '🟡');
        assert_eq!(starts(notice(Event::Eased, warning)), '🟡');
        assert_eq!(starts(notice(Event::Reminder, alert())), '🔴');
        assert_eq!(starts(Notice::test()), '*');
    }

    #[test]
    fn a_host_cannot_ping_a_discord_server() {
        let alert = Alert {
            summary: "@everyone is offline".to_string(),
            ..alert()
        };
        let body = body(&notice(Event::Firing, alert));
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
    }

    #[test]
    fn a_long_discord_message_fits_the_limit() {
        let alert = Alert {
            summary: "é".repeat(3000),
            ..alert()
        };
        let body = body(&notice(Event::Firing, alert));
        let content = body["content"].as_str().unwrap();
        assert_eq!(content.chars().count(), MAX_CHARS);
    }
}
