//! A Microsoft Teams channel, through the workflow Teams makes to post what's sent
//! to it. A workflow can only post, so there's no chart and no buttons.

use anyhow::{Result, anyhow, ensure};
use axum::http::Uri;
use serde_json::{Value, json};

use super::{ChannelType, alerts_link, blocking, post_json, url_preview};
use crate::alerting::{Channel, ChannelInput, Event, Severity};
use crate::notifier::{Notice, Senders, format_ms};
use crate::registration::short_id;
use crate::remote_checks::FLEET_AGENT_ID;

/// Keeps a message well inside what Teams takes, which counts the card's markup too.
const MAX_CHARS: usize = 3000;

/// Where Teams workflows take requests: Power Automate's older and newer addresses.
const HOSTS: [&str; 2] = [".logic.azure.com", ".powerplatform.com"];

pub struct Teams;

/// An Adaptive Card, as a Teams workflow posts. Teams turns `[text](url)` into a
/// link, and agents choose their own names, so that's broken up in what they chose.
/// Mentions need a list of who's meant, which this never sends.
fn body(notice: &Notice, web_url: Option<&str>) -> Value {
    let unlinked = |text: &str| -> String {
        text.chars()
            .take(MAX_CHARS)
            .collect::<String>()
            .replace("](", "]\u{200b}(")
    };
    let colour = match (notice.event, &notice.alert) {
        (Event::Resolved, _) => "Good",
        (Event::Test, _) | (_, None) => "Default",
        (Event::Escalated, _) => "Attention",
        (Event::Eased, _) => "Warning",
        (_, Some(alert)) if alert.severity == Severity::Critical => "Attention",
        (_, Some(_)) => "Warning",
    };
    let summary = notice
        .alert
        .as_ref()
        .map_or(notice.text.as_str(), |a| &a.summary);
    let mut body = vec![
        json!({ "type": "TextBlock", "text": notice.label(), "weight": "Bolder",
                "color": colour, "wrap": true }),
        json!({ "type": "TextBlock", "text": unlinked(summary), "wrap": true }),
    ];
    if let Some(alert) = &notice.alert {
        let mut facts = vec![
            json!({ "title": "Rule", "value": unlinked(&alert.rule_name) }),
            if alert.agent_id == FLEET_AGENT_ID {
                json!({ "title": "Machines", "value": unlinked(&alert.host) })
            } else {
                let agent = format!("{} ({})", alert.host, short_id(&alert.agent_id));
                json!({ "title": "Machine", "value": unlinked(&agent) })
            },
            json!({ "title": "Started", "value": format_ms(alert.started_ms) }),
        ];
        if let (Event::Resolved, Some(reason)) = (notice.event, &alert.resolve_reason) {
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

#[async_trait::async_trait]
impl ChannelType for Teams {
    fn name(&self) -> &'static str {
        "Microsoft Teams"
    }

    /// Catches pasting the wrong thing, such as a retired Office 365 connector's URL.
    /// Errors don't repeat the URL, which holds a signature that works like a password.
    fn check(&self, channel: &ChannelInput) -> Result<()> {
        let complaint = "that doesn't look like the URL of a Teams workflow, which comes from \
                         its \"When a Teams webhook request is received\" step";
        let uri: Uri = channel
            .target
            .trim()
            .parse()
            .map_err(|_| anyhow!("{complaint}"))?;
        let host = uri.host().unwrap_or_default();
        ensure!(
            uri.scheme_str() == Some("https")
                && HOSTS.iter().any(|end| host.ends_with(end))
                && uri.path().contains("/workflows/"),
            "{complaint}"
        );
        Ok(())
    }

    fn preview(&self, target: &str) -> String {
        url_preview(target)
    }

    fn hides_target(&self) -> bool {
        true
    }

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>> {
        let target = channel.channel.target.clone();
        let body = body(notice, senders.web_url.as_deref());
        blocking(move || post_json("the Teams workflow", &target, &body).map(|()| None)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::Alert;
    use crate::channels::testing::{alert, notice};

    #[test]
    fn teams_gets_a_card_coloured_by_severity_with_a_link_back() {
        let body = body(
            &notice(Event::Firing, alert()),
            Some("https://m.example.com"),
        );
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
        assert_eq!(facts[1]["title"], "Machine");
        assert_eq!(card["actions"][0]["url"], "https://m.example.com/alerts");

        let warning = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        let card = |event, alert| {
            super::body(&notice(event, alert), None)["attachments"][0]["content"].clone()
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
        let text = body(&notice(Event::Firing, alert), None).to_string();
        assert!(!text.contains("](https"), "{text}");
    }
}
