//! A Discord channel's webhook, with the chart attached when there is one. What
//! an action printed goes in the message, and as a file too when it's too long.

use anyhow::{Context, Result, anyhow, ensure};
use axum::http::Uri;
use serde_json::{Value, json};
use ureq::unversioned::multipart::{Form, Part};

use super::{ChannelType, accepted, blocking, chart_part, post_form, post_json, url_preview};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Printed, Senders, Tone};

/// The longest message Discord accepts.
const MAX_CHARS: usize = 2000;

/// How much of a message about an action its first line can take, which leaves
/// the rest for what the action printed.
const MAX_HEADLINE_CHARS: usize = 400;

/// What goes around what an action printed, so it lines up.
const FENCE_START: &str = "\n```\n";
const FENCE_END: &str = "\n```";
const CUT_NOTE: &str = "\nCut short. All of it is in the file.";

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

/// A link to the alert's own page, with its chart, as a line of its own. The
/// address is in angle brackets so Discord doesn't add a preview of the page.
fn link_line(notice: &Notice, web_url: Option<&str>) -> String {
    web_url.map_or_else(String::new, |url| {
        format!("\n[{}](<{}>)", notice.link_label(), notice.link(url))
    })
}

/// The first line, short enough to leave room for the link after it.
fn headline(notice: &Notice, link: &str) -> String {
    let circle = circle(notice.tone());
    let max = if notice.action.is_some() {
        MAX_HEADLINE_CHARS
    } else {
        MAX_CHARS.saturating_sub(link.chars().count())
    };
    // The summary has hostnames and series in it, which agents choose.
    let summary = super::unlinked(notice.summary());
    format!("{circle}**{}** {summary}", notice.label())
        .chars()
        .take(max)
        .collect()
}

/// What an action printed, as much as fits between the headline and the link.
fn printed(notice: &Notice, headline: &str, link: &str) -> Option<Printed> {
    let around = FENCE_START.len() + FENCE_END.len() + CUT_NOTE.len();
    let used = headline.chars().count() + link.chars().count() + around;
    notice.printed(MAX_CHARS.saturating_sub(used))
}

/// Mentions are turned off, as agents choose their own names and one called
/// `@everyone` would otherwise ping a whole server.
fn body(notice: &Notice, web_url: Option<&str>) -> Value {
    let link = link_line(notice, web_url);
    let mut content = headline(notice, &link);
    if let Some(printed) = printed(notice, &content, &link) {
        // Three backticks would end the block early.
        let text = printed.text.replace("```", "'''");
        content.push_str(&format!("{FENCE_START}{text}{FENCE_END}"));
        if printed.cut {
            content.push_str(CUT_NOTE);
        }
    }
    content.push_str(&link);
    json!({ "content": content, "allowed_mentions": { "parse": [] } })
}

/// All of what an action printed, as a file, when the message had to cut it.
fn whole_output(notice: &Notice, web_url: Option<&str>) -> Option<(String, String)> {
    let run = notice.action.as_ref()?;
    let link = link_line(notice, web_url);
    let cut = printed(notice, &headline(notice, &link), &link)?.cut;
    cut.then(|| (format!("{}.txt", run.action), run.output.clone()))
}

/// The message, with the chart attached when there is one, which Discord shows
/// under the text, and what an action printed when that didn't fit.
fn post(
    url: &str,
    body: &Value,
    chart: Option<&[u8]>,
    output: Option<&(String, String)>,
) -> Result<()> {
    if chart.is_none() && output.is_none() {
        return post_json("the webhook", url, body);
    }
    let payload = body.to_string();
    let json = Part::text(&payload)
        .mime_str("application/json")
        .context("naming the message's type")?;
    let mut form = Form::new().part("payload_json", json);
    if let Some(chart) = chart {
        form = form.part("files[0]", chart_part(chart)?);
    }
    if let Some((name, output)) = output {
        let file = Part::bytes(output.as_bytes())
            .file_name(name)
            .mime_str("text/plain; charset=utf-8")
            .context("naming the output's type")?;
        form = form.part("files[1]", file);
    }
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
        senders: &Senders,
    ) -> Result<Option<String>> {
        let target = channel.channel.target.clone();
        let web_url = senders.web_url.as_deref();
        let body = body(notice, web_url);
        let chart = notice.chart.clone();
        let output = whole_output(notice, web_url);
        blocking(move || {
            let chart = chart.as_deref().map(Vec::as_slice);
            post(&target, &body, chart, output.as_ref()).map(|()| None)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{Alert, Event};
    use crate::channels::testing::{action_notice, alert, notice};

    #[test]
    fn what_an_action_printed_is_shown_so_it_lines_up() {
        let notice = action_notice("FOLDER  SIZE\n/var/log  9 GiB\n```@everyone\n");
        let body = body(&notice, None);
        assert_eq!(
            body["content"],
            "**ACTION** disk_space ran on web-1\n```\nFOLDER  SIZE\n/var/log  9 GiB\n'''@everyone\n```"
        );
        assert_eq!(whole_output(&notice, None), None);
        // One that printed nothing still says how it went.
        assert_eq!(
            super::body(&action_notice(""), None)["content"],
            "**ACTION** disk_space ran on web-1"
        );
    }

    #[test]
    fn output_too_long_for_a_message_is_cut_at_a_line_and_sent_whole_as_a_file() {
        let line = "/var/lib/something  1 GiB\n";
        let notice = action_notice(&line.repeat(200));
        let body = body(&notice, None);
        let content = body["content"].as_str().unwrap();
        assert!(content.chars().count() <= MAX_CHARS, "{content}");
        assert!(
            content.ends_with("1 GiB\n```\nCut short. All of it is in the file."),
            "{content}"
        );
        let (name, whole) = whole_output(&notice, None).unwrap();
        assert_eq!(name, "disk_space.txt");
        assert_eq!(whole, line.repeat(200));
    }

    #[test]
    fn discord_messages_lead_with_what_happened() {
        assert_eq!(
            body(&notice(Event::Firing, alert()), None)["content"],
            "🔴 **CRITICAL** CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            body(&notice(Event::Resolved, alert()), None)["content"],
            "🟢 **RESOLVED** CPU usage on web-1 is 97%, above 90%"
        );
        assert_eq!(
            body(&notice(Event::Escalated, alert()), None)["content"],
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
            body(&notice, None)["content"]
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
        let body = body(&notice(Event::Firing, alert), None);
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
    }

    #[test]
    fn a_long_discord_message_fits_the_limit() {
        let alert = Alert {
            summary: "é".repeat(3000),
            ..alert()
        };
        let plain = body(&notice(Event::Firing, alert.clone()), None);
        let content = plain["content"].as_str().unwrap();
        assert_eq!(content.chars().count(), MAX_CHARS);

        // The link to the alert is never what's cut.
        let linked = body(&notice(Event::Firing, alert), Some(URL));
        let content = linked["content"].as_str().unwrap();
        assert_eq!(content.chars().count(), MAX_CHARS);
        assert!(
            content.ends_with("\n[View alert](<https://m.example.com/alerts/7>)"),
            "{content}"
        );
    }

    const URL: &str = "https://m.example.com";

    #[test]
    fn a_discord_message_links_to_its_alert_and_its_chart() {
        assert_eq!(
            body(&notice(Event::Firing, alert()), Some(URL))["content"],
            "🔴 **CRITICAL** CPU usage on web-1 is 97%, above 90%\n\
             [View alert](<https://m.example.com/alerts/7>)"
        );
        // One about no alert links to them all.
        assert!(
            body(&Notice::test(), Some(URL))["content"]
                .as_str()
                .unwrap()
                .ends_with("\n[View alerts](<https://m.example.com/alerts>)")
        );
    }

    #[test]
    fn what_an_action_printed_leaves_room_for_the_link() {
        let line = "/var/lib/something  1 GiB\n";
        let notice = action_notice(&line.repeat(200));
        let sent = body(&notice, Some(URL));
        let content = sent["content"].as_str().unwrap();
        assert!(content.chars().count() <= MAX_CHARS, "{content}");
        assert!(
            content.ends_with(
                "Cut short. All of it is in the file.\n[View alert](<https://m.example.com/alerts/7>)"
            ),
            "{content}"
        );
        assert!(whole_output(&notice, Some(URL)).is_some());
    }

    #[test]
    fn a_host_cannot_add_a_link_to_a_discord_message() {
        let alert = Alert {
            hostname: "[click](https://evil.example)".to_string(),
            summary: "Disk on [click](<https://evil.example>) is full".to_string(),
            ..alert()
        };
        let content = body(&notice(Event::Firing, alert), None)["content"].to_string();
        assert!(!content.contains("](https"), "{content}");
        assert!(!content.contains("](<https://evil"), "{content}");
    }
}
