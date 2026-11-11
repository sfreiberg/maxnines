//! Slack, through a Slack app's bot, with the chart in the message and, when the
//! server hears the app through Socket Mode, Acknowledge and Silence buttons. A
//! channel shows one message per alert, which turns green when it resolves.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use hyper_rustls::HttpsConnectorBuilder;
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
use tracing::warn;

use super::{CHART_FILE, ChannelType};
use crate::alerting::{Channel, ChannelInput, Event, Severity};
use crate::notifier::{Notice, Senders, format_ms};
use crate::registration::short_id;
use crate::remote_checks::FLEET_AGENT_ID;

/// Says which button was pressed, when Slack tells us. The button's value is the alert.
pub const ACKNOWLEDGE_ACTION: &str = "maxnines_acknowledge";
pub const SILENCE_HOUR_ACTION: &str = "maxnines_silence_hour";

/// The longest description Slack takes for an image.
const ALT_TEXT_MAX_CHARS: usize = 2000;

/// The most text Slack shows in one section of a message.
const SECTION_MAX_CHARS: usize = 3000;

/// Slack's own limit on a channel name, plus its leading `#`.
const MAX_CHANNEL_LEN: usize = 81;

pub struct Slack;

/// Buttons under an alert, for a Slack app the server hears through Socket Mode.
#[derive(Debug, Clone, Default)]
pub struct SlackControls {
    /// Who silenced it and until when, shown in place of its button.
    pub silenced: Option<String>,
}

/// What a Slack app for MaxNines needs: a bot that can post anywhere, can upload
/// charts, can look up who pressed a button, and hears buttons through Socket Mode.
fn manifest_value() -> Value {
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
pub fn manifest() -> String {
    serde_json::to_string_pretty(&manifest_value()).unwrap_or_default()
}

/// Opens Slack's new app page with the manifest already filled in.
pub fn manifest_link() -> String {
    let manifest = manifest_value().to_string();
    let query = serde_urlencoded::to_string([("new_app", "1"), ("manifest_json", &manifest)])
        .unwrap_or_default();
    format!("https://api.slack.com/apps?{query}")
}

/// Slack reads `<...>` as commands, such as `<!everyone>`, and agents choose their
/// own names. Slack asks for exactly these three to be escaped.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn color(notice: &Notice) -> &'static str {
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

fn text(notice: &Notice, web_url: Option<&str>) -> String {
    let Some(alert) = &notice.alert else {
        return escape(&notice.text);
    };
    let mut lines = vec![format!("*{}* {}", notice.label(), escape(&alert.summary))];
    let mut details = vec![
        format!("Rule: {}", escape(&alert.rule_name)),
        if alert.agent_id == FLEET_AGENT_ID {
            format!("Machines: {}", escape(&alert.host))
        } else {
            format!(
                "Machine: {} ({})",
                escape(&alert.host),
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
fn status(notice: &Notice, controls: Option<&SlackControls>) -> Vec<String> {
    let mut lines = Vec::new();
    let acknowledged = notice
        .alert
        .as_ref()
        .and_then(|a| a.acknowledged_by.as_deref());
    if let Some(by) = acknowledged {
        lines.push(format!("Acknowledged by {}", escape(by)));
    }
    if let Some(silenced) = controls.and_then(|c| c.silenced.as_deref()) {
        lines.push(escape(silenced));
    }
    lines
}

/// Only while it's firing, and only what hasn't been done yet.
fn buttons(notice: &Notice, controls: Option<&SlackControls>) -> Vec<SlackActionBlockElement> {
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
pub fn content(
    notice: &Notice,
    web_url: Option<&str>,
    controls: Option<&SlackControls>,
    chart: Option<&SlackFileId>,
) -> SlackMessageContent {
    let text = clip_escaped(text(notice, web_url), SECTION_MAX_CHARS);
    let mut blocks: Vec<SlackBlock> = vec![
        SlackSectionBlock::new()
            .with_text(SlackBlockMarkDownText::new(text).into())
            .into(),
    ];
    if let Some(file) = chart {
        let image = SlackImageUrlOrFile::SlackFile {
            slack_file: SlackFileIdOrUrl::Id { id: file.clone() },
        };
        let description = clip_escaped(notice.chart_description(), ALT_TEXT_MAX_CHARS);
        blocks.push(SlackImageBlock::new(image, description).into());
    }
    let status = status(notice, controls);
    if !status.is_empty() {
        let line = SlackBlockMarkDownText::new(status.join(" · "));
        blocks.push(SlackContextBlock::new(vec![SlackContextBlockElement::MarkDown(line)]).into());
    }
    let buttons = buttons(notice, controls);
    if !buttons.is_empty() {
        blocks.push(SlackActionsBlock::new(buttons).into());
    }
    let attachment = SlackMessageAttachment::new()
        .with_color(color(notice).to_string())
        .with_fallback(escape(&notice.text))
        .with_blocks(blocks);
    SlackMessageContent::new()
        .with_text(escape(&notice.text))
        .with_attachments(vec![attachment])
}

/// Slack would otherwise fetch any link in a message, and agents choose what's in
/// these.
fn post_request(
    channel: SlackChannelId,
    content: SlackMessageContent,
) -> SlackApiChatPostMessageRequest {
    SlackApiChatPostMessageRequest::new(channel, content)
        .with_unfurl_links(false)
        .with_unfurl_media(false)
}

/// Uses the certificates built into this binary, as the rest of the server does,
/// so that Slack works on machines without their own.
pub fn connector() -> Result<SlackClientHyperHttpsConnector> {
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
fn message_id(external_id: &str) -> Option<(SlackChannelId, SlackTs, Option<SlackFileId>)> {
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

fn external_id(channel: &SlackChannelId, ts: &SlackTs, chart: Option<&SlackFileId>) -> String {
    match chart {
        Some(file) => format!("{channel}:{ts}:{file}"),
        None => format!("{channel}:{ts}"),
    }
}

/// The chart in a message Slack sent back, such as one whose button was pressed.
pub fn chart_in(content: &SlackMessageContent) -> Option<SlackFileId> {
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
async fn upload<C>(
    session: &SlackClientSession<'_, C>,
    chart: &[u8],
    description: &str,
) -> Result<SlackFileId>
where
    C: SlackClientHttpConnector + Send + Sync,
{
    let request =
        SlackApiFilesGetUploadUrlExternalRequest::new(CHART_FILE.to_string(), chart.len())
            .with_alt_txt(description.chars().take(ALT_TEXT_MAX_CHARS).collect());
    let upload = session
        .get_upload_url_external(&request)
        .await
        .map_err(|error| explain(&error))?;
    let content = SlackApiFilesUploadViaUrlRequest::new(
        upload.upload_url,
        chart.to_vec(),
        "image/png".to_string(),
    );
    session
        .files_upload_via_url(&content)
        .await
        .map_err(|error| explain(&error))?;
    let done = SlackApiFilesCompleteUploadExternalRequest::new(vec![SlackApiFilesComplete::new(
        upload.file_id.clone(),
    )]);
    session
        .files_complete_upload_external(&done)
        .await
        .map_err(|error| explain(&error))?;
    Ok(upload.file_id)
}

/// Slack's error codes are safe to keep and say what's wrong, but anything else
/// could quote the request, which holds the token.
pub fn explain(error: &SlackClientError) -> anyhow::Error {
    match error {
        SlackClientError::ApiError(error) => explain_code(&error.code),
        SlackClientError::RateLimitError(_) => anyhow!("Slack asked us to slow down"),
        _ => anyhow!("couldn't reach Slack"),
    }
}

/// The problems people can fix themselves, in words that say how.
fn explain_code(code: &str) -> anyhow::Error {
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
async fn post<C>(
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
        .and_then(message_id)
    {
        let content = content(notice, web_url, controls.as_ref(), chart.as_ref());
        let update =
            SlackApiChatUpdateRequest::new(message_channel.clone(), content.clone(), ts.clone());
        match session.chat_update(&update).await {
            Ok(_) => {
                let reason = notice
                    .alert
                    .as_ref()
                    .and_then(|a| a.resolve_reason.as_deref());
                let reply =
                    SlackMessageContent::new().with_text(escape(reason.unwrap_or("Resolved")));
                let request = post_request(message_channel, reply).with_thread_ts(ts);
                session
                    .chat_post_message(&request)
                    .await
                    .map_err(|error| explain(&error))?;
                return Ok(None);
            }
            // Someone deleted it, so this has to stand on its own.
            Err(error) if is_gone(&error) => {}
            Err(error) => return Err(explain(&error)),
        }
    }

    // The message matters more than its chart, so it goes without one that fails.
    let mut chart = None;
    if let Some(png) = notice.chart.as_deref() {
        match upload(&session, png, &notice.chart_description()).await {
            Ok(file) => chart = Some(file),
            Err(error) => warn!(
                error = format!("{error:#}"),
                "couldn't send a chart to Slack"
            ),
        }
    }
    let target = SlackChannelId(channel.channel.target.trim().to_string());
    let shown = content(notice, web_url, controls.as_ref(), chart.as_ref());
    let response = match session
        .chat_post_message(&post_request(target.clone(), shown))
        .await
    {
        Ok(response) => response,
        // Slack can refuse a chart it hasn't finished taking in yet.
        Err(error) if chart.is_some() && is_invalid_blocks(&error) => {
            warn!("Slack wouldn't show the chart, so the alert went without it");
            chart = None;
            let shown = content(notice, web_url, controls.as_ref(), None);
            session
                .chat_post_message(&post_request(target, shown))
                .await
                .map_err(|error| explain(&error))?
        }
        Err(error) => return Err(explain(&error)),
    };

    // Otherwise a wrong token would only show in the server's log.
    if let (Event::Test, Some(app_token)) = (notice.event, &channel.channel.app_token) {
        crate::slack_actions::check_app_token(client, app_token)
            .await
            .context("the test message was sent, but the buttons won't work")?;
    }
    Ok(Some(external_id(
        &response.channel,
        &response.ts,
        chart.as_ref(),
    )))
}

#[async_trait::async_trait]
impl ChannelType for Slack {
    fn name(&self) -> &'static str {
        "Slack"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        let target = channel.target.trim();
        ensure!(
            !target.is_empty()
                && target.len() <= MAX_CHANNEL_LEN
                && !target.contains(char::is_whitespace),
            "enter a Slack channel, such as #alerts or C0123456789"
        );
        let token = channel.credential.as_deref().unwrap_or_default();
        ensure!(
            token.starts_with("xoxb-"),
            "enter the app's bot token, which starts with xoxb-"
        );
        if let Some(token) = &channel.app_token {
            ensure!(
                token.trim().starts_with("xapp-"),
                "the app-level token starts with xapp-. Leave it empty for messages without buttons"
            );
        }
        Ok(())
    }

    fn has_credential(&self) -> bool {
        true
    }

    fn takes_app_token(&self) -> bool {
        true
    }

    fn shows_charts(&self) -> bool {
        true
    }

    async fn send(
        &self,
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
            return post(&client, channel, notice, reply_to, web_url).await;
        }

        let client = SlackClient::new(connector()?);
        post(&client, channel, notice, reply_to, web_url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::Alert;
    use crate::channels::testing::{alert, notice};

    #[test]
    fn a_host_cannot_ping_a_slack_channel() {
        let alert = Alert {
            summary: "<!everyone> & <@U123> are <http://evil|offline>".to_string(),
            host: "<!here>".to_string(),
            rule_name: "<!channel>".to_string(),
            ..alert()
        };
        let notice = notice(Event::Firing, alert);
        let text = text(&notice, None);
        assert!(!text.contains('<'), "{text}");
        assert!(
            text.contains("&lt;!everyone&gt; &amp; &lt;@U123&gt;"),
            "{text}"
        );

        let content = content(&notice, None, None, None);
        assert!(!content.text.unwrap().contains('<'));
    }

    #[test]
    fn slack_messages_say_what_happened_and_where_to_look() {
        let text = text(
            &notice(Event::Firing, alert()),
            Some("https://m.example.com"),
        );
        assert!(text.starts_with("*CRITICAL* CPU usage on web-1"), "{text}");
        assert!(text.contains("Rule: High CPU"), "{text}");
        assert!(text.contains("Machine: web-1"), "{text}");
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
        assert_eq!(color(&notice(Event::Firing, alert())), "#b3261e");
        assert_eq!(color(&notice(Event::Firing, warning.clone())), "#b87a00");
        assert_eq!(color(&notice(Event::Resolved, alert())), "#0b6b4b");
        assert_eq!(color(&notice(Event::Escalated, alert())), "#b3261e");
        assert_eq!(color(&notice(Event::Eased, warning)), "#b87a00");
        assert_eq!(color(&Notice::test()), "#6b7280");
    }

    #[test]
    fn common_slack_problems_say_what_to_do_and_keep_the_code() {
        assert_eq!(
            explain_code("token_revoked").to_string(),
            "Slack didn't accept the bot token (token_revoked)"
        );
        assert_eq!(
            explain_code("not_in_channel").to_string(),
            "the app isn't in that channel, so invite it (not_in_channel)"
        );
        assert_eq!(
            explain_code("fatal_error").to_string(),
            "Slack said fatal_error"
        );
    }

    #[test]
    fn slack_needs_no_certificates_or_tls_setup_from_the_machine() {
        connector().unwrap();
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
            block_types(&content(&firing, None, None, None)),
            ["section"]
        );
        assert_eq!(
            block_types(&content(&firing, None, Some(&controls), None)),
            ["section", "actions"]
        );

        let resolved = Alert {
            resolved_ms: Some(2_000),
            ..alert()
        };
        let shown = content(
            &notice(Event::Resolved, resolved),
            None,
            Some(&controls),
            None,
        );
        assert_eq!(block_types(&shown), ["section"]);

        let handled = Alert {
            acknowledged_by: Some("sam@example.com".to_string()),
            ..alert()
        };
        let silenced = SlackControls {
            silenced: Some("Silenced by sam@example.com until later".to_string()),
        };
        let shown = content(
            &notice(Event::Reminder, handled),
            None,
            Some(&silenced),
            None,
        );
        assert_eq!(block_types(&shown), ["section", "context"]);
        let value = serde_json::to_value(&shown).unwrap();
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
        let shown = content(&notice(Event::Firing, alert), None, None, None);
        let value = serde_json::to_value(&shown).unwrap();
        let text = value["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap();
        assert!(text.chars().count() <= SECTION_MAX_CHARS);
        assert!(text.ends_with("&lt;"), "{}", &text[text.len() - 10..]);
    }

    #[test]
    fn the_slack_link_and_the_manifest_to_paste_say_the_same_thing() {
        let link = manifest_link();
        let query = link.strip_prefix("https://api.slack.com/apps?").unwrap();
        let fields: Vec<(String, String)> = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(fields[0], ("new_app".to_string(), "1".to_string()));
        assert_eq!(fields[1].0, "manifest_json");
        let linked: Value = serde_json::from_str(&fields[1].1).unwrap();
        let pasted: Value = serde_json::from_str(&manifest()).unwrap();
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
        let request = post_request(SlackChannelId("C1".to_string()), SlackMessageContent::new());
        assert_eq!(request.unfurl_links, Some(false));
        assert_eq!(request.unfurl_media, Some(false));
    }

    #[test]
    fn a_slack_message_shows_its_chart_and_gives_it_back() {
        let file = SlackFileId("F123".to_string());
        let charted = Notice {
            chart: Some(Arc::new(b"\x89PNG chart".to_vec())),
            ..notice(Event::Firing, alert())
        };
        let shown = content(&charted, None, None, Some(&file));
        let sent = serde_json::to_value(&shown).unwrap();
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
        assert_eq!(chart_in(&back), Some(file));
        let plain = content(&notice(Event::Firing, alert()), None, None, None);
        assert_eq!(chart_in(&plain), None);
    }

    #[test]
    fn a_message_id_needs_both_parts_and_may_name_a_chart() {
        let (channel, ts, chart) = message_id("C1:12.34").unwrap();
        assert_eq!(
            (channel.0.as_str(), ts.0.as_str(), chart),
            ("C1", "12.34", None)
        );
        let (_, _, chart) = message_id("C1:12.34:F9").unwrap();
        assert_eq!(chart, Some(SlackFileId("F9".to_string())));
        assert!(message_id("nonsense").is_none());
        assert!(message_id(":12.34").is_none());
        assert_eq!(
            external_id(
                &SlackChannelId("C1".to_string()),
                &SlackTs("12.34".to_string()),
                Some(&SlackFileId("F9".to_string()))
            ),
            "C1:12.34:F9"
        );
    }
}
