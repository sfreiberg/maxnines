//! Telegram, through a bot of your own, with the chart as a photo.

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use ureq::unversioned::multipart::Form;

use super::{
    ChannelType, Response, alerts_link, blocking, chart_part, explain_http, post, post_form,
};
use crate::alerting::{Channel, ChannelInput, Event};
use crate::notifier::{Notice, Senders, format_ms};
use crate::registration::short_id;
use crate::remote_checks::FLEET_AGENT_ID;

/// Where Telegram's bot API lives.
pub const API_URL: &str = "https://api.telegram.org";

/// The parts of a message, before escaping, are kept under these so that the
/// whole fits Telegram's limit of 4096.
const MAX_SUMMARY: usize = 3000;
const MAX_DETAIL: usize = 300;

/// The longest caption Telegram puts under a photo.
const MAX_CAPTION: usize = 1024;

/// Telegram's limits on a public channel's or group's username.
const USERNAME_LEN: std::ops::RangeInclusive<usize> = 5..=32;

pub struct Telegram;

/// Telegram's HTML needs only these escaped, and agents choose their own names.
fn escape(text: &str) -> String {
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

fn text(notice: &Notice, web_url: Option<&str>) -> String {
    let Some(alert) = &notice.alert else {
        return escape(&notice.text);
    };
    let clip = |text: &str| escape(clip_utf16(text, MAX_DETAIL));
    let mut lines = vec![format!(
        "<b>{}</b> {}",
        notice.label(),
        escape(clip_utf16(&alert.summary, MAX_SUMMARY))
    )];
    let place = if alert.agent_id == FLEET_AGENT_ID {
        format!("Machines: {}", clip(&alert.host))
    } else {
        format!(
            "Machine: {} ({})",
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
            escape(&alerts_link(url))
        ));
    }
    lines.join("\n")
}

/// Telegram would otherwise fetch links in a message, and agents choose what's in
/// these. A reply to a message someone deleted is sent on its own.
fn message(notice: &Notice, chat: &str, reply_to: Option<&str>, web_url: Option<&str>) -> Value {
    let mut message = json!({
        "chat_id": chat.trim(),
        "text": text(notice, web_url),
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
fn explain(status: u16, answer: &Value) -> anyhow::Error {
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

/// What Telegram called what was sent, or why it refused it.
fn answer(response: Response) -> Result<Option<String>> {
    let mut response = response.map_err(|error| explain_http("Telegram", &error))?;
    let status = response.status();
    let answer: Value = response
        .body_mut()
        .read_to_string()
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    if !status.is_success() || answer["ok"] != true {
        return Err(explain(status.as_u16(), &answer));
    }
    Ok(answer["result"]["message_id"]
        .as_i64()
        .map(|id| id.to_string()))
}

/// A chat's number, which is negative for groups and channels, or the `@username`
/// of a public one.
fn is_chat(target: &str) -> bool {
    match target.strip_prefix('@') {
        Some(name) => {
            USERNAME_LEN.contains(&name.len())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => target.parse::<i64>().is_ok_and(|id| id != 0),
    }
}

/// The bot's number, a colon, and its secret. Errors don't repeat the token.
fn is_token(token: &str) -> bool {
    let Some((bot, secret)) = token.split_once(':') else {
        return false;
    };
    !bot.is_empty()
        && bot.chars().all(|c| c.is_ascii_digit())
        && secret.len() >= 30
        && secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Sends a message, as a reply to the alert's first one when there is one, and
/// gives what Telegram called it. With a chart, the message is the photo's caption,
/// or when it's too long for one, the photo is a reply to it.
fn send(
    api: &str,
    chat: &str,
    notice: &Notice,
    reply_to: Option<&str>,
    web_url: Option<&str>,
) -> Result<Option<String>> {
    let method = |name: &str| format!("{api}/{name}");
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
        answer(post_form(&method("sendPhoto"), form))
    };

    let text = text(notice, web_url);
    match &notice.chart {
        Some(chart) if text.encode_utf16().count() <= MAX_CAPTION => {
            send_photo(chart, Some(&text), reply_to)
        }
        Some(chart) => {
            let message = message(notice, chat, reply_to, web_url);
            let sent = answer(post(&method("sendMessage"), &message))?;
            send_photo(chart, None, sent.as_deref())?;
            Ok(sent)
        }
        None => {
            let message = message(notice, chat, reply_to, web_url);
            answer(post(&method("sendMessage"), &message))
        }
    }
}

#[async_trait::async_trait]
impl ChannelType for Telegram {
    fn name(&self) -> &'static str {
        "Telegram"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        ensure!(
            is_chat(channel.target.trim()),
            "enter a Telegram chat ID, such as -1001234567890, or a public channel such as \
             @alerts"
        );
        ensure!(
            is_token(channel.credential.as_deref().unwrap_or_default().trim()),
            "enter the bot token from BotFather, which is a number, a colon, then a long code"
        );
        Ok(())
    }

    fn has_credential(&self) -> bool {
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
        let token = channel
            .channel
            .credential
            .as_deref()
            .context("this channel has no bot token")?;
        let api = format!("{}/bot{}", senders.telegram_api_url(), token.trim());
        let chat = channel.channel.target.trim().to_string();
        let notice = notice.clone();
        let reply_to = reply_to.map(str::to_string);
        let web_url = senders.web_url.clone();
        blocking(move || {
            send(
                &api,
                &chat,
                &notice,
                reply_to.as_deref(),
                web_url.as_deref(),
            )
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::Alert;
    use crate::channels::testing::{alert, notice};

    #[test]
    fn telegram_messages_say_what_happened_and_where_to_look() {
        let text = text(
            &notice(Event::Firing, alert()),
            Some("https://m.example.com"),
        );
        assert_eq!(
            text,
            "<b>CRITICAL</b> CPU usage on web-1 is 97%, above 90%\n\
             Rule: High CPU · Machine: web-1 (abc) · Started: 1970-01-01 00:00:01 UTC\n\
             <a href=\"https://m.example.com/alerts\">View alerts</a>"
        );
        assert_eq!(
            super::text(&Notice::test(), None),
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
        let text = text(&notice(Event::Resolved, alert), None);
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
        let text = text(&notice(Event::Firing, alert), None);
        assert!(
            text.contains("&lt;a href=&quot;http://evil&quot;&gt;click&lt;/a&gt; &amp; &lt;b&gt;"),
            "{text}"
        );
        assert!(text.contains("Machine: &lt;i&gt;web&lt;/i&gt;"), "{text}");
    }

    #[test]
    fn a_long_telegram_message_fits_the_limit() {
        let alert = Alert {
            summary: "😀".repeat(5000),
            host: "&".repeat(5000),
            rule_name: "r".repeat(255),
            ..alert()
        };
        let text = text(&notice(Event::Firing, alert), Some("https://m.example.com"));
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
        let sent = message(
            &notice(Event::Resolved, alert()),
            " -100123 ",
            Some("42"),
            None,
        );
        assert_eq!(sent["chat_id"], "-100123");
        assert_eq!(sent["parse_mode"], "HTML");
        assert_eq!(sent["link_preview_options"]["is_disabled"], true);
        assert_eq!(sent["reply_parameters"]["message_id"], 42);
        assert_eq!(
            sent["reply_parameters"]["allow_sending_without_reply"],
            true
        );

        let sent = message(&notice(Event::Firing, alert()), "-100123", None, None);
        assert!(sent.get("reply_parameters").is_none());
    }

    #[test]
    fn common_telegram_problems_say_what_to_do() {
        let said = |text: &str| json!({ "ok": false, "description": text });
        assert_eq!(
            explain(401, &said("Unauthorized")).to_string(),
            "Telegram didn't accept the bot token (Unauthorized)"
        );
        assert_eq!(
            explain(400, &said("Bad Request: chat not found")).to_string(),
            "Telegram can't find that chat. Add the bot to the group, or send the bot a \
             message first (Bad Request: chat not found)"
        );
        let upgraded = json!({
            "ok": false,
            "description": "Bad Request: group chat was upgraded to a supergroup chat",
            "parameters": { "migrate_to_chat_id": -1_001_234_567_890_i64 },
        });
        assert_eq!(
            explain(400, &upgraded).to_string(),
            "the group became a supergroup, so change the chat ID to -1001234567890"
        );
        assert_eq!(
            explain(400, &said("Bad Request: message is too long")).to_string(),
            "Telegram said: Bad Request: message is too long"
        );
        assert_eq!(
            explain(502, &Value::Null).to_string(),
            "Telegram returned status 502"
        );
    }
}
