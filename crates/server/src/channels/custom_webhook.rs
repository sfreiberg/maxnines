//! A webhook whose request is written by whoever sets it up, so MaxNines can talk
//! to a service it has no channel for. The body is a Tera template filled in with
//! the notification, and the headers are kept like a password, as they usually
//! hold a token.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use axum::http::{HeaderName, HeaderValue};
use maxnines_protocol::actions::ActionOutcome;
use serde_json::{Map, Value, json};
use tera::{Context, Kwargs, State, Tera};

use super::{ChannelType, agent, blocking, explain_http, url_host, url_preview};
use crate::actions::ActionRun;
use crate::alerting::{
    Alert, Channel, ChannelInput, Event, Severity, WebhookMethod, WebhookRequest,
};
use crate::notifier::{Notice, Senders};

pub struct CustomWebhook;

/// How long a body template can be.
pub const MAX_TEMPLATE_LEN: usize = 16 * 1024;
/// How big a filled-in body can get.
const MAX_BODY_LEN: usize = 256 * 1024;
/// How long the headers can be altogether.
const MAX_HEADERS_LEN: usize = 8 * 1024;
const MAX_HEADERS: usize = 20;

/// Headers the request sets itself, which a template can't change.
const OWN_HEADERS: [&str; 5] = [
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
];

/// What a new custom webhook starts with, to show what can go in one.
pub const EXAMPLE_BODY: &str = r#"{
  "title": "{{ alert.rule_name }} on {{ alert.hostname }}",
  "message": "{{ text }}",
  "severity": "{{ alert.severity }}",
  "status": "{{ event }}",
  "value": {{ alert.value | json }},
  "link": {{ link | json }}
}"#;

/// Whether a content type is JSON, so what's filled in is escaped for it.
fn is_json(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

/// Escapes text to go inside a JSON string.
fn escape_json(input: &str, output: &mut dyn Write) -> io::Result<()> {
    let quoted = serde_json::to_string(input).map_err(io::Error::other)?;
    output.write_all(&quoted.as_bytes()[1..quoted.len() - 1])
}

/// Turns any value into JSON, quotes and all, such as `null` for something
/// missing.
fn json_filter(value: tera::Value, _: Kwargs, _: &State) -> tera::TeraResult<tera::Value> {
    serde_json::to_string(&value)
        .map(|text| tera::Value::safe_string(&text))
        .map_err(|error| tera::Error::message(error.to_string()))
}

/// Writes into memory, up to a limit, so a template can't fill it.
struct Limited(Vec<u8>);

impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len() + bytes.len() > MAX_BODY_LEN {
            return Err(io::Error::other("the body is too big"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An alert to fill a template in with when there's no real one, for a test or
/// to check the template when it's saved.
fn example_alert() -> Alert {
    Alert {
        id: 0,
        rule_id: None,
        rule_name: "Test notification".to_string(),
        severity: Severity::Warning,
        host_id: String::new(),
        hostname: "maxnines-test".to_string(),
        series: String::new(),
        value: None,
        summary: Notice::test().text,
        started_ms: chrono::Utc::now().timestamp_millis(),
        resolved_ms: None,
        resolve_reason: None,
        acknowledged_by: None,
        acknowledged_ms: None,
    }
}

/// A run to check a template with, for one that sends what actions print.
fn example_run() -> ActionRun {
    ActionRun {
        id: 0,
        host_id: String::new(),
        alert_id: Some(0),
        action: "top_cpu".to_string(),
        run_on: "first".to_string(),
        variables: BTreeMap::new(),
        requested_by: None,
        requested_ms: 0,
        timeout_secs: 30,
        outcome: Some(ActionOutcome::Succeeded),
        exit_code: Some(0),
        error: None,
        output: "PID  NAME\n  1  init\n".to_string(),
        truncated: false,
        duration_ms: Some(1000),
        finished_ms: Some(1000),
    }
}

/// What a template can use. A test has no alert, so it gets an example one, as
/// the template is written for alerts.
fn context(notice: &Notice, web_url: Option<&str>) -> Result<Context> {
    let alert = notice.alert.clone().unwrap_or_else(example_alert);
    let mut fields = match serde_json::to_value(&alert).context("reading the alert")? {
        Value::Object(fields) => fields,
        _ => Map::new(),
    };
    fields.insert("started".into(), crate::audit::time(alert.started_ms));
    fields.insert(
        "resolved".into(),
        alert.resolved_ms.map_or(Value::Null, crate::audit::time),
    );
    fields.insert(
        "acknowledged".into(),
        alert
            .acknowledged_ms
            .map_or(Value::Null, crate::audit::time),
    );
    let values = json!({
        "id": notice.id,
        "event": notice.event,
        "text": notice.text,
        "link": web_url.map(super::alerts_link),
        "alert": fields,
        "action": notice.action_fields(),
    });
    Context::from_serialize(&values).context("filling in the template")
}

/// The body for a notification.
pub fn render(request: &WebhookRequest, notice: &Notice, web_url: Option<&str>) -> Result<String> {
    let body = fill(request, notice, web_url)?;
    if let Some(problem) = json_problem(request, &body) {
        bail!("{problem}");
    }
    Ok(body)
}

/// The template filled in, before checking it's JSON.
fn fill(request: &WebhookRequest, notice: &Notice, web_url: Option<&str>) -> Result<String> {
    let mut tera = Tera::default();
    tera.register_filter("json", json_filter);
    let json = is_json(&request.content_type);
    if json {
        tera.set_escape_fn(escape_json);
    }
    let mut output = Limited(Vec::new());
    tera.render_str_to(&request.body, &context(notice, web_url)?, json, &mut output)
        .map_err(|error| anyhow!("the body template didn't work: {}", explain_tera(&error)))?;
    String::from_utf8(output.0).context("the body isn't text")
}

/// Why a body that should be JSON isn't.
fn json_problem(request: &WebhookRequest, body: &str) -> Option<String> {
    if !is_json(&request.content_type) {
        return None;
    }
    serde_json::from_str::<Value>(body)
        .err()
        .map(|error| format!("the body isn't valid JSON: {error}"))
}

/// A body filled in for the form, with what's wrong with it, if anything.
pub struct Preview {
    /// Empty if the template itself didn't work.
    pub body: Option<String>,
    pub problem: Option<String>,
}

/// The body for an example alert starting, to show on the form before saving.
/// A body that isn't valid JSON is still shown, as the error says where in it the
/// problem is.
pub fn preview(request: &WebhookRequest, web_url: Option<&str>) -> Preview {
    let alert = Alert {
        id: 42,
        rule_id: Some(1),
        rule_name: "High CPU".to_string(),
        severity: Severity::Critical,
        host_id: "example-host-id".to_string(),
        hostname: "web-1".to_string(),
        series: String::new(),
        value: Some(97.0),
        summary: "CPU usage on web-1 is 97%, above 90%".to_string(),
        ..example_alert()
    };
    let notice = Notice {
        id: 1,
        ..Notice::for_alert(alert, Event::Firing)
    };
    match fill(request, &notice, web_url) {
        Ok(body) => Preview {
            problem: json_problem(request, &body),
            body: Some(body),
        },
        Err(error) => Preview {
            body: None,
            problem: Some(format!("{error:#}")),
        },
    }
}

/// Tera's error and what caused it, on one line.
fn explain_tera(error: &tera::Error) -> String {
    let mut words = vec![error.to_string()];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        words.push(cause.to_string());
        source = cause.source();
    }
    words
        .join(": ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The headers, one `Name: value` to a line. Errors never repeat a value, as it's
/// usually a token.
pub fn headers(text: &str) -> Result<Vec<(String, String)>> {
    ensure!(text.len() <= MAX_HEADERS_LEN, "the headers are too long");
    let mut found = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .context("each header goes on its own line, as Name: value")?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| anyhow!("{:?} isn't a header name", name.trim()))?;
        if OWN_HEADERS.contains(&name.as_str()) {
            bail!("the {name} header is set by MaxNines");
        }
        HeaderValue::from_str(value.trim())
            .map_err(|_| anyhow!("the {name} header's value has characters headers can't"))?;
        found.push((name.as_str().to_string(), value.trim().to_string()));
    }
    ensure!(
        found.len() <= MAX_HEADERS,
        "there can be up to {MAX_HEADERS} headers"
    );
    Ok(found)
}

/// The header names saved for a channel, which aren't secret, for its form.
pub fn header_names(text: &str) -> Vec<String> {
    headers(text)
        .map(|headers| headers.into_iter().map(|(name, _)| name).collect())
        .unwrap_or_default()
}

#[async_trait::async_trait]
impl ChannelType for CustomWebhook {
    fn name(&self) -> &'static str {
        "Custom webhook"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        url_host(&channel.target)?;
        let request = channel
            .request
            .as_ref()
            .context("a custom webhook needs a body to send")?;
        ensure!(
            !request.body.trim().is_empty(),
            "a custom webhook needs a body to send"
        );
        ensure!(
            request.body.len() <= MAX_TEMPLATE_LEN,
            "the body can be up to {} KB",
            MAX_TEMPLATE_LEN / 1024
        );
        let content_type = request.content_type.trim();
        ensure!(
            !content_type.is_empty(),
            "a custom webhook needs a content type, like application/json"
        );
        ensure!(
            content_type.len() <= 255 && HeaderValue::from_str(content_type).is_ok(),
            "the content type isn't valid"
        );
        if let Some(text) = &channel.credential {
            headers(text)?;
        }
        // Filled in for each kind of message, so a mistake shows now rather than
        // when an alert fires.
        let mut resolved = example_alert();
        resolved.resolved_ms = Some(resolved.started_ms);
        let examples = [
            Notice::for_alert(example_alert(), Event::Firing),
            Notice::for_alert(resolved, Event::Resolved),
            Notice::for_action(example_alert(), example_run()),
            Notice::test(),
        ];
        for notice in &examples {
            render(request, notice, Some("https://maxnines.example.com"))?;
            render(request, notice, None)?;
        }
        Ok(())
    }

    fn preview(&self, target: &str) -> String {
        url_preview(target)
    }

    /// Only when its body was written with actions in mind. One written for
    /// alerts alone would send what looks like another alert.
    fn takes_action_output(&self, channel: &ChannelInput) -> bool {
        channel
            .request
            .as_ref()
            .is_some_and(|request| request.body.contains("action."))
    }

    fn hides_target(&self) -> bool {
        true
    }

    fn has_credential(&self) -> bool {
        true
    }

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>> {
        let request = channel
            .channel
            .request
            .clone()
            .context("the custom webhook has no body to send")?;
        let body = render(&request, notice, senders.web_url.as_deref())?;
        let headers = headers(channel.channel.credential.as_deref().unwrap_or_default())?;
        let target = channel.channel.target.clone();
        blocking(move || {
            let url = target.trim();
            let agent = agent();
            let mut builder = match request.method {
                WebhookMethod::Post => agent.post(url),
                WebhookMethod::Put => agent.put(url),
                WebhookMethod::Patch => agent.patch(url),
            };
            builder = builder.header("content-type", request.content_type.trim());
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let response = builder
                .send(body.as_bytes())
                .map_err(|error| explain_http("the webhook", &error))?;
            let status = response.status();
            if !status.is_success() {
                bail!(
                    "the webhook returned status {}{}",
                    status.as_u16(),
                    reply(response)
                );
            }
            Ok(None)
        })
        .await
    }
}

/// How much of a refusal to show.
const MAX_REPLY_LEN: usize = 300;

/// The start of what a receiver said when it refused a request, which usually
/// says what was wrong with the body. It's the receiver's own words, so it holds
/// nothing of the channel's secrets.
fn reply(response: ureq::http::Response<ureq::Body>) -> String {
    let mut body = response.into_body();
    let text = body
        .with_config()
        .limit(16 * 1024)
        .read_to_string()
        .unwrap_or_default();
    let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return String::new();
    }
    let mut cut: String = text.chars().take(MAX_REPLY_LEN).collect();
    if cut.len() < text.len() {
        cut.push('…');
    }
    format!(": {cut}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::testing::{alert, notice};

    fn request(content_type: &str, body: &str) -> WebhookRequest {
        WebhookRequest {
            method: WebhookMethod::Post,
            content_type: content_type.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn the_example_fills_in_as_json() {
        let body = render(
            &request("application/json", EXAMPLE_BODY),
            &notice(Event::Firing, alert()),
            Some("https://maxnines.example.com"),
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["title"], "High CPU on web-1");
        assert_eq!(body["message"], "CPU usage on web-1 is 97%, above 90%");
        assert_eq!(body["severity"], "critical");
        assert_eq!(body["status"], "firing");
        assert_eq!(body["value"], 97.0);
        assert_eq!(body["link"], "https://maxnines.example.com/alerts");
    }

    #[test]
    fn what_is_filled_in_cannot_break_out_of_a_json_string() {
        let mut sneaky = alert();
        sneaky.hostname = "web\", \"admin\": true, \"x\": \"\n".to_string();
        let body = render(
            &request(
                "application/json; charset=utf-8",
                r#"{"host": "{{ alert.hostname }}"}"#,
            ),
            &notice(Event::Firing, sneaky.clone()),
            None,
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["host"], sneaky.hostname.as_str());
        assert_eq!(body.as_object().unwrap().len(), 1);
    }

    #[test]
    fn other_bodies_are_left_as_they_are() {
        let body = render(
            &request(
                "text/plain",
                "{{ alert.hostname }} & {{ event }}: {{ text }}",
            ),
            &notice(Event::Resolved, alert()),
            None,
        )
        .unwrap();
        assert_eq!(
            body,
            "web-1 & resolved: CPU usage on web-1 is 97%, above 90%"
        );
    }

    #[test]
    fn missing_values_can_be_written_as_null() {
        let body = render(
            &request(
                "application/vnd.api+json",
                r#"{"link": {{ link | json }}, "resolved": {{ alert.resolved | json }}}"#,
            ),
            &notice(Event::Firing, alert()),
            None,
        )
        .unwrap();
        assert_eq!(body, r#"{"link": null, "resolved": null}"#);
    }

    #[test]
    fn times_are_given_as_text_too() {
        let body = render(
            &request("text/plain", "{{ alert.started }} {{ alert.started_ms }}"),
            &notice(Event::Firing, alert()),
            None,
        )
        .unwrap();
        assert_eq!(body, "1970-01-01T00:00:01Z 1000");
    }

    #[test]
    fn a_test_fills_in_an_example_alert() {
        let body = render(
            &request(
                "text/plain",
                "{{ event }} {{ alert.hostname }} {{ alert.summary }}",
            ),
            &Notice::test(),
            None,
        )
        .unwrap();
        assert_eq!(
            body,
            "test maxnines-test This is a test notification from MaxNines."
        );
    }

    #[test]
    fn broken_templates_say_so() {
        for body in ["{{ alert.host", "{{ nothing.here }}", "{% for x in %}"] {
            let error = render(
                &request("text/plain", body),
                &notice(Event::Firing, alert()),
                None,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .starts_with("the body template didn't work"),
                "{body}: {error}"
            );
        }
        let error = render(
            &request("application/json", "{\"value\": {{ alert.value }}"),
            &notice(Event::Firing, alert()),
            None,
        )
        .unwrap_err();
        assert!(
            error.to_string().starts_with("the body isn't valid JSON"),
            "{error}"
        );
    }

    #[test]
    fn a_body_cannot_grow_without_end() {
        let error = render(
            &request(
                "text/plain",
                "{% for i in range(end=100000) %}{{ text }}{% endfor %}",
            ),
            &notice(Event::Firing, alert()),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("too big"), "{error}");
    }

    #[test]
    fn headers_are_one_to_a_line() {
        let found = headers("Authorization: Bearer abc:def\r\n\n  X-Team : ops  \n").unwrap();
        assert_eq!(
            found,
            [
                ("authorization".to_string(), "Bearer abc:def".to_string()),
                ("x-team".to_string(), "ops".to_string()),
            ]
        );
        assert_eq!(headers("").unwrap(), []);
        assert_eq!(header_names("Authorization: secret"), ["authorization"]);
    }

    #[test]
    fn bad_headers_are_refused_without_repeating_their_values() {
        for (text, problem) in [
            ("Authorization secret", "Name: value"),
            ("Bad Name: secret", "isn't a header name"),
            ("Content-Type: secret", "set by MaxNines"),
            ("Host: secret", "set by MaxNines"),
            ("X-Token: secret\u{7}", "characters"),
        ] {
            let error = headers(text).unwrap_err().to_string();
            assert!(error.contains(problem), "{text}: {error}");
            assert!(!error.contains("secret"), "{text}: {error}");
        }
        let many = (0..=MAX_HEADERS)
            .map(|i| format!("X-{i}: 1\n"))
            .collect::<String>();
        assert!(headers(&many).is_err());
    }

    fn channel(body: &str) -> ChannelInput {
        ChannelInput {
            name: "Ops".to_string(),
            kind: crate::alerting::ChannelKind::CustomWebhook,
            target: "https://hooks.example.com/secret".to_string(),
            credential: Some("Authorization: Bearer abc".to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
            mail: None,
            request: Some(request("application/json", body)),
        }
    }

    #[test]
    fn a_body_that_uses_what_actions_print_is_sent_it() {
        let body = r#"{"text": "{% if action %}{{ action.name }} {{ action.outcome }}: {{ action.output }}{% else %}{{ text }}{% endif %}"}"#;
        let written_for_actions = channel(body);
        CustomWebhook.check(&written_for_actions).unwrap();
        assert!(CustomWebhook.takes_action_output(&written_for_actions));
        assert!(!CustomWebhook.takes_action_output(&channel(EXAMPLE_BODY)));

        let request = request("application/json", body);
        let ran = crate::channels::testing::action_notice("A \"quoted\"\nline\n");
        let sent: Value = serde_json::from_str(&render(&request, &ran, None).unwrap()).unwrap();
        assert_eq!(sent["text"], "disk_space succeeded: A \"quoted\"\nline\n");
        let firing = render(&request, &notice(Event::Firing, alert()), None).unwrap();
        let sent: Value = serde_json::from_str(&firing).unwrap();
        assert_eq!(sent["text"], "CPU usage on web-1 is 97%, above 90%");
    }

    #[test]
    fn templates_are_checked_when_saved() {
        assert!(CustomWebhook.check(&channel(EXAMPLE_BODY)).is_ok());
        // Fine for an alert, but a test has no rule, so it'd be broken JSON then.
        let error = CustomWebhook
            .check(&channel(r#"{"rule": {{ alert.rule_id }}}"#))
            .unwrap_err();
        assert!(error.to_string().contains("valid JSON"), "{error}");
        assert!(CustomWebhook.check(&channel(" ")).is_err());
        assert!(
            CustomWebhook
                .check(&channel(&"x".repeat(MAX_TEMPLATE_LEN + 1)))
                .is_err()
        );

        let mut no_request = channel(EXAMPLE_BODY);
        no_request.request = None;
        assert!(CustomWebhook.check(&no_request).is_err());

        let mut bad_type = channel(EXAMPLE_BODY);
        bad_type.request.as_mut().unwrap().content_type = "text/\nplain".to_string();
        assert!(CustomWebhook.check(&bad_type).is_err());

        let mut bad_headers = channel(EXAMPLE_BODY);
        bad_headers.credential = Some("Content-Length: 1".to_string());
        assert!(CustomWebhook.check(&bad_headers).is_err());
    }
}
