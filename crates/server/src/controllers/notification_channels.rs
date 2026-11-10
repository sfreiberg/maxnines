use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{CsrfForm, Page, server_error};
use crate::alerting::{
    Channel, ChannelInput, ChannelKind, Mail, MailSecurity, MailServer, Severity, WebhookMethod,
    WebhookRequest,
};
use crate::app_state::AppState;
use crate::channels;
use crate::channels::custom_webhook;
use crate::notifier::{self, Notice};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts/channels", get(index).post(create))
        .route("/alerts/channels/new", get(new))
        .route("/alerts/channels/{id}", post(update))
        .route("/alerts/channels/{id}/edit", get(edit))
        .route("/alerts/channels/{id}/delete", post(delete))
        .route("/alerts/channels/{id}/test", post(test))
}

/// A channel as its form shows it. A saved webhook's URL often is its password,
/// so it's never put back in the page: leaving the box empty keeps it.
#[derive(Serialize)]
struct ChannelForm {
    name: String,
    kind: String,
    target: String,
    /// What's saved, for a webhook that isn't being shown.
    preview: Option<String>,
    /// Slack's or Telegram's bot token, which is only ever typed in and never
    /// shown again.
    credential: String,
    has_credential: bool,
    /// A Slack app-level token, which works the same way.
    app_token: String,
    has_app_token: bool,
    /// Ticked to turn a Slack channel's buttons off again.
    remove_app_token: bool,
    sends_warnings: bool,
    sends_critical: bool,
    /// Who email comes from, for email and Resend.
    mail_from: String,
    /// An email channel's mail server. Its password is the credential.
    mail_host: String,
    mail_port: String,
    mail_security: String,
    mail_username: String,
    /// A custom webhook's headers, one to a line. They usually hold a token, so
    /// they're only ever typed in. Only their names are shown once saved.
    headers: String,
    header_names: Vec<String>,
    /// Ticked to send no headers any more.
    remove_headers: bool,
    request_method: String,
    request_content_type: String,
    request_body: String,
}

impl ChannelForm {
    fn blank() -> Self {
        Self {
            name: String::new(),
            kind: ChannelKind::Webhook.as_str().to_string(),
            target: String::new(),
            preview: None,
            credential: String::new(),
            has_credential: false,
            app_token: String::new(),
            has_app_token: false,
            remove_app_token: false,
            sends_warnings: true,
            sends_critical: true,
            mail_from: String::new(),
            mail_host: String::new(),
            mail_port: String::new(),
            mail_security: MailSecurity::default().as_str().to_string(),
            mail_username: String::new(),
            headers: String::new(),
            header_names: Vec::new(),
            remove_headers: false,
            request_method: WebhookMethod::default().as_str().to_string(),
            request_content_type: "application/json".to_string(),
            request_body: custom_webhook::EXAMPLE_BODY.to_string(),
        }
    }

    fn from_channel(channel: &ChannelInput) -> Self {
        let hidden = channels::of(channel.kind).hides_target();
        let mail = channel.mail.as_ref();
        let server = mail.and_then(|mail| mail.server.as_ref());
        let blank = Self::blank();
        let request = channel.request.as_ref();
        let custom = channel.kind == ChannelKind::CustomWebhook;
        Self {
            name: channel.name.clone(),
            kind: channel.kind.as_str().to_string(),
            target: if hidden {
                String::new()
            } else {
                channel.target.clone()
            },
            preview: hidden.then(|| channel.target_preview()),
            credential: String::new(),
            has_credential: channel.credential.is_some(),
            app_token: String::new(),
            has_app_token: channel.app_token.is_some(),
            remove_app_token: false,
            sends_warnings: channel.severities.contains(&Severity::Warning),
            sends_critical: channel.severities.contains(&Severity::Critical),
            mail_from: mail.map(|mail| mail.from.clone()).unwrap_or_default(),
            mail_host: server.map(|server| server.host.clone()).unwrap_or_default(),
            mail_port: server
                .and_then(|server| server.port)
                .map(|port| port.to_string())
                .unwrap_or_default(),
            mail_security: server
                .map(|server| server.security)
                .unwrap_or_default()
                .as_str()
                .to_string(),
            mail_username: server
                .and_then(|server| server.username.clone())
                .unwrap_or_default(),
            headers: String::new(),
            header_names: match &channel.credential {
                Some(headers) if custom => custom_webhook::header_names(headers),
                _ => Vec::new(),
            },
            remove_headers: false,
            request_method: request.map_or(blank.request_method, |request| {
                request.method.as_str().to_string()
            }),
            request_content_type: request.map_or(blank.request_content_type, |request| {
                request.content_type.clone()
            }),
            request_body: request.map_or(blank.request_body, |request| request.body.clone()),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            name: text("name"),
            kind: text("kind"),
            target: text("target"),
            preview: None,
            credential: text("credential"),
            has_credential: false,
            app_token: text("app_token"),
            has_app_token: false,
            remove_app_token: fields.contains_key("remove_app_token"),
            sends_warnings: fields.contains_key("sends_warnings"),
            sends_critical: fields.contains_key("sends_critical"),
            mail_from: text("mail_from"),
            mail_host: text("mail_host"),
            mail_port: text("mail_port"),
            mail_security: text("mail_security"),
            mail_username: text("mail_username"),
            headers: text("headers"),
            header_names: Vec::new(),
            remove_headers: fields.contains_key("remove_headers"),
            request_method: text("request_method"),
            request_content_type: text("request_content_type"),
            request_body: text("request_body"),
        }
    }

    /// What a custom webhook sends, if it is one. Browsers send a text box's lines
    /// ending in CRLF, which would end up in the body.
    fn to_request(&self, kind: ChannelKind) -> Result<Option<WebhookRequest>> {
        if kind != ChannelKind::CustomWebhook {
            return Ok(None);
        }
        Ok(Some(WebhookRequest {
            method: WebhookMethod::parse(self.request_method.trim())?,
            content_type: self.request_content_type.trim().to_string(),
            body: self.request_body.replace("\r\n", "\n"),
        }))
    }

    /// What's been typed for the credential, which for a custom webhook is its
    /// headers, tidied to one to a line.
    fn typed_credential(&self, kind: ChannelKind) -> String {
        if kind != ChannelKind::CustomWebhook {
            return self.credential.trim().to_string();
        }
        self.headers
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// How the channel sends email, if it's a kind that does. Empty boxes are left
    /// out, so the checks can say what's missing.
    fn to_mail(&self, kind: ChannelKind) -> Result<Option<Mail>> {
        if !kind.sends_mail() {
            return Ok(None);
        }
        let from = self.mail_from.trim();
        if from.is_empty() {
            return Ok(None);
        }
        let host = self.mail_host.trim();
        let server = if kind == ChannelKind::Email && !host.is_empty() {
            let port = self.mail_port.trim();
            let port = if port.is_empty() {
                None
            } else {
                Some(port.parse::<u16>().map_err(|_| {
                    anyhow!("the mail server's port should be a number from 1 to 65535")
                })?)
            };
            let username = self.mail_username.trim();
            Some(MailServer {
                host: host.to_string(),
                port,
                security: MailSecurity::parse(self.mail_security.trim())?,
                username: (!username.is_empty()).then(|| username.to_string()),
            })
        } else {
            None
        };
        Ok(Some(Mail {
            from: from.to_string(),
            server,
        }))
    }

    /// `saved` is the channel being edited. Its destination is kept if the box
    /// is empty, unless the kind changed and it can't mean the same thing.
    fn to_channel(&self, saved: Option<&ChannelInput>) -> Result<ChannelInput> {
        let kind = ChannelKind::parse(&self.kind)?;
        let typed = self.target.trim();
        let target = match saved {
            Some(saved) if typed.is_empty() && saved.kind == kind => saved.target.clone(),
            _ => typed.to_string(),
        };
        let mail = self.to_mail(kind)?;
        // A mail server's password only goes with a username, so clearing the
        // username clears the password too.
        let signs_in = mail
            .as_ref()
            .and_then(|mail| mail.server.as_ref())
            .is_some_and(|server| server.username.is_some());
        let typed = self.typed_credential(kind);
        let credential = match saved {
            _ if !kind.has_credential() => None,
            _ if kind == ChannelKind::Email && !signs_in => None,
            _ if kind == ChannelKind::CustomWebhook && self.remove_headers => None,
            _ if !typed.is_empty() => Some(typed),
            Some(saved) if saved.kind == kind => saved.credential.clone(),
            _ => None,
        };
        let typed = self.app_token.trim();
        let app_token = match saved {
            _ if !channels::of(kind).takes_app_token() || self.remove_app_token => None,
            _ if !typed.is_empty() => Some(typed.to_string()),
            Some(saved) if saved.kind == kind => saved.app_token.clone(),
            _ => None,
        };
        Ok(ChannelInput {
            name: self.name.trim().to_string(),
            kind,
            target,
            credential,
            app_token,
            severities: [
                (Severity::Warning, self.sends_warnings),
                (Severity::Critical, self.sends_critical),
            ]
            .into_iter()
            .filter_map(|(severity, ticked)| ticked.then_some(severity))
            .collect(),
            mail,
            request: self.to_request(kind)?,
        })
    }
}

/// A custom webhook's body filled in with an example alert, or why it can't be.
#[derive(Serialize)]
struct BodyPreview {
    method: String,
    content_type: String,
    body: Option<String>,
    error: Option<String>,
}

fn body_preview(state: &AppState, form: &ChannelForm) -> BodyPreview {
    let (body, error) = match form.to_request(ChannelKind::CustomWebhook) {
        Ok(Some(request)) => {
            let preview = custom_webhook::preview(&request, state.senders.web_url.as_deref());
            (preview.body, preview.problem)
        }
        Ok(None) => (None, None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    BodyPreview {
        method: form.request_method.trim().to_string(),
        content_type: form.request_content_type.trim().to_string(),
        body,
        error,
    }
}

#[derive(Serialize)]
struct ChannelRow {
    id: i64,
    name: String,
    kind: &'static str,
    /// What the kind is called.
    kind_name: &'static str,
    target: String,
    /// A plain webhook into Slack, which Slack is moving away from.
    legacy_slack: bool,
    /// Which alerts it takes, when it isn't all of them.
    only: Option<&'static str>,
}

impl From<Channel> for ChannelRow {
    fn from(channel: Channel) -> Self {
        Self {
            id: channel.id,
            kind: channel.channel.kind.as_str(),
            kind_name: channels::of(channel.channel.kind).name(),
            target: channel.channel.target_preview(),
            legacy_slack: channel.channel.kind == ChannelKind::Webhook
                && channel.channel.target.contains("hooks.slack.com"),
            only: match channel.channel.severities.iter().collect::<Vec<_>>()[..] {
                [Severity::Warning] => Some("Warnings only"),
                [Severity::Critical] => Some("Critical alerts only"),
                _ => None,
            },
            name: channel.channel.name,
        }
    }
}

async fn index_page(
    state: &AppState,
    token: &CsrfToken,
    notice: Option<&str>,
    error: Option<&str>,
) -> Response {
    let channels = match state.database.list_channels().await {
        Ok(channels) => channels,
        Err(error) => return server_error(&error),
    };
    let rows: Vec<ChannelRow> = channels.into_iter().map(ChannelRow::from).collect();
    Page::new(state, token, "notification_channels/index.html")
        .with("channels", &rows)
        .with("notice", &notice)
        .with("error", &error)
        .render()
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    index_page(&state, &token, None, None).await
}

/// A kind of channel to choose from on the form.
#[derive(Serialize)]
struct KindChoice {
    value: &'static str,
    name: &'static str,
}

fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &ChannelForm,
    error: Option<&str>,
) -> Response {
    form_page_with(state, token, id, form, error, None)
}

fn form_page_with(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &ChannelForm,
    error: Option<&str>,
    preview: Option<&BodyPreview>,
) -> Response {
    let kinds: Vec<KindChoice> = channels::ALL
        .into_iter()
        .map(|kind| KindChoice {
            value: kind.as_str(),
            name: channels::of(kind).name(),
        })
        .collect();
    let page = Page::new(state, token, "notification_channels/form.html")
        .with("id", &id)
        .with("channel", form)
        .with("kinds", &kinds)
        .with("alertops_sample", &channels::alertops::sample())
        .with("slack_manifest", &channels::slack::manifest())
        .with("slack_manifest_link", &channels::slack::manifest_link())
        .with("securities", &MailSecurity::ALL.map(MailSecurity::as_str))
        .with("methods", &WebhookMethod::ALL.map(WebhookMethod::as_str))
        .with("preview", &preview)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

async fn new(State(state): State<AppState>, token: CsrfToken) -> Response {
    form_page(&state, &token, None, &ChannelForm::blank(), None)
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_channel(id).await {
        Ok(Some(channel)) => {
            let form = ChannelForm::from_channel(&channel.channel);
            form_page(&state, &token, Some(id), &form, None)
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

/// Shows a custom webhook's body filled in, without saving anything.
fn preview_page(
    state: &AppState,
    form: &CsrfForm,
    id: Option<i64>,
    fields: &ChannelForm,
) -> Response {
    let preview = body_preview(state, fields);
    form_page_with(state, &form.token, id, fields, None, Some(&preview))
}

fn wants_preview(form: &CsrfForm) -> bool {
    form.fields
        .get("form_action")
        .is_some_and(|action| action == "preview")
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let fields = ChannelForm::from_fields(&form.fields);
    if wants_preview(&form) {
        return preview_page(&state, &form, None, &fields);
    }
    let checked = async {
        let input = fields.to_channel(None)?;
        state.check_channel(&input, None).await?;
        anyhow::Ok(input)
    };
    let input = match checked.await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, None, &fields, Some(&message));
        }
    };

    match state.database.create_channel(&input).await {
        Ok(_) => (form.token, Redirect::to("/alerts/channels")).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let saved = match state.database.get_channel(id).await {
        Ok(Some(saved)) => saved,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };

    let mut fields = ChannelForm::from_fields(&form.fields);
    if saved.channel.kind == ChannelKind::CustomWebhook {
        fields.header_names = ChannelForm::from_channel(&saved.channel).header_names;
    }
    if wants_preview(&form) {
        if saved.channel.kind.as_str() == fields.kind
            && channels::of(saved.channel.kind).hides_target()
        {
            fields.preview = Some(saved.channel.target_preview());
        }
        return preview_page(&state, &form, Some(id), &fields);
    }
    let checked = async {
        let input = fields.to_channel(Some(&saved.channel))?;
        state.check_channel(&input, Some(id)).await?;
        anyhow::Ok(input)
    };
    let input = match checked.await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            if saved.channel.kind.as_str() == fields.kind
                && channels::of(saved.channel.kind).hides_target()
            {
                fields.preview = Some(saved.channel.target_preview());
            }
            return form_page(&state, &form.token, Some(id), &fields, Some(&message));
        }
    };

    match state.database.update_channel(id, &input).await {
        Ok(true) => (form.token, Redirect::to("/alerts/channels")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.delete_channel(id).await {
        Ok(true) => (form.token, Redirect::to("/alerts/channels")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

/// Sends a test straight away, without using the queue, and says how it went.
async fn test(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let channel = match state.database.get_channel(id).await {
        Ok(Some(channel)) => channel,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };

    let name = channel.channel.name.clone();
    match notifier::send(channel, Notice::test(), None, state.senders.clone()).await {
        Ok(_) => {
            let notice = format!("A test notification was sent to {name}.");
            index_page(&state, &form.token, Some(&notice), None).await
        }
        Err(error) => {
            let message = format!("The test to {name} failed: {error:#}");
            index_page(&state, &form.token, None, Some(&message)).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webhook() -> ChannelInput {
        ChannelInput {
            name: "Ops".to_string(),
            kind: ChannelKind::Webhook,
            target: "https://hooks.example.com/secret".to_string(),
            credential: None,
            app_token: None,
            severities: crate::alerting::every_severity(),
            mail: None,
            request: None,
        }
    }

    fn email() -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Email,
            target: "ops@example.com".to_string(),
            credential: Some("mail-secret".to_string()),
            mail: Some(Mail {
                from: "MaxNines <alerts@example.com>".to_string(),
                server: Some(MailServer {
                    host: "smtp.example.com".to_string(),
                    port: Some(2525),
                    security: MailSecurity::Tls,
                    username: Some("alerts".to_string()),
                }),
            }),
            ..webhook()
        }
    }

    #[test]
    fn an_email_channel_comes_back_from_its_form_as_it_was_without_the_password() {
        let saved = email();
        let form = ChannelForm::from_channel(&saved);
        assert_eq!(form.credential, "");
        assert!(form.has_credential);
        assert_eq!(form.mail_host, "smtp.example.com");
        assert_eq!(form.mail_port, "2525");
        assert_eq!(form.mail_security, "tls");
        assert_eq!(form.to_channel(Some(&saved)).unwrap(), saved);
    }

    #[test]
    fn clearing_the_username_drops_the_password() {
        let saved = email();
        let mut form = ChannelForm::from_channel(&saved);
        form.mail_username = String::new();
        let channel = form.to_channel(Some(&saved)).unwrap();
        assert_eq!(channel.credential, None);
        assert_eq!(channel.mail.unwrap().server.unwrap().username, None);
    }

    #[test]
    fn a_port_has_to_be_a_port() {
        let mut form = ChannelForm::from_channel(&email());
        for port in ["0x19", "70000", "-1"] {
            form.mail_port = port.to_string();
            assert!(form.to_channel(None).is_err(), "{port}");
        }
        form.mail_port = String::new();
        let channel = form.to_channel(None).unwrap();
        assert_eq!(channel.mail.unwrap().server.unwrap().port, None);
    }

    #[test]
    fn resend_keeps_a_from_address_but_no_mail_server() {
        let mut form = ChannelForm::from_channel(&email());
        form.kind = "resend".to_string();
        form.credential = "re_key".to_string();
        let channel = form.to_channel(None).unwrap();
        let mail = channel.mail.unwrap();
        assert_eq!(mail.from, "MaxNines <alerts@example.com>");
        assert_eq!(mail.server, None);
        assert_eq!(channel.credential.as_deref(), Some("re_key"));
    }

    #[test]
    fn other_kinds_drop_mail_settings() {
        let mut form = ChannelForm::from_channel(&email());
        form.kind = "webhook".to_string();
        form.target = "https://example.com/x".to_string();
        assert_eq!(form.to_channel(None).unwrap().mail, None);
    }

    #[test]
    fn a_discord_url_never_reaches_the_form() {
        let channel = ChannelInput {
            kind: ChannelKind::Discord,
            target: "https://discord.com/api/webhooks/1/secret".to_string(),
            ..webhook()
        };
        let form = ChannelForm::from_channel(&channel);
        assert_eq!(form.target, "");
        assert_eq!(form.preview.as_deref(), Some("https://discord.com/…"));
    }

    fn slack() -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Slack,
            target: "#alerts".to_string(),
            credential: Some("xoxb-secret".to_string()),
            ..webhook()
        }
    }

    #[test]
    fn a_slack_token_never_reaches_the_form_but_its_channel_does() {
        let form = ChannelForm::from_channel(&slack());
        assert_eq!(form.credential, "");
        assert!(form.has_credential);
        assert_eq!(form.target, "#alerts");
    }

    #[test]
    fn leaving_the_token_empty_keeps_it() {
        let saved = slack();
        let form = ChannelForm::from_channel(&saved);
        assert_eq!(form.to_channel(Some(&saved)).unwrap(), saved);
    }

    #[test]
    fn a_new_token_replaces_the_saved_one() {
        let saved = slack();
        let mut form = ChannelForm::from_channel(&saved);
        form.credential = " xoxb-new ".to_string();
        let channel = form.to_channel(Some(&saved)).unwrap();
        assert_eq!(channel.credential.as_deref(), Some("xoxb-new"));
    }

    #[test]
    fn leaving_slack_drops_its_token() {
        let saved = slack();
        let mut form = ChannelForm::from_channel(&saved);
        form.kind = "webhook".to_string();
        form.target = "https://example.com/x".to_string();
        assert_eq!(form.to_channel(Some(&saved)).unwrap().credential, None);
    }

    #[test]
    fn an_app_token_is_kept_until_removed_and_never_shown() {
        let saved = ChannelInput {
            app_token: Some("xapp-secret".to_string()),
            ..slack()
        };
        let form = ChannelForm::from_channel(&saved);
        assert_eq!(form.app_token, "");
        assert!(form.has_app_token);
        assert_eq!(form.to_channel(Some(&saved)).unwrap(), saved);

        let mut form = ChannelForm::from_channel(&saved);
        form.app_token = " xapp-new ".to_string();
        let channel = form.to_channel(Some(&saved)).unwrap();
        assert_eq!(channel.app_token.as_deref(), Some("xapp-new"));

        let mut form = ChannelForm::from_channel(&saved);
        form.remove_app_token = true;
        assert_eq!(form.to_channel(Some(&saved)).unwrap().app_token, None);
    }

    #[test]
    fn an_app_token_is_only_for_slack() {
        let mut form = ChannelForm::from_channel(&webhook());
        form.app_token = "xapp-1".to_string();
        form.target = "https://example.com/x".to_string();
        assert_eq!(form.to_channel(None).unwrap().app_token, None);
    }

    #[test]
    fn a_slack_token_does_not_carry_over_to_telegram() {
        let saved = slack();
        let mut form = ChannelForm::from_channel(&saved);
        form.kind = "telegram".to_string();
        form.target = "-100123".to_string();
        assert_eq!(form.to_channel(Some(&saved)).unwrap().credential, None);
    }

    #[test]
    fn a_telegram_token_is_kept_when_left_empty() {
        let saved = ChannelInput {
            kind: ChannelKind::Telegram,
            target: "-100123".to_string(),
            credential: Some("123:secret".to_string()),
            ..webhook()
        };
        let form = ChannelForm::from_channel(&saved);
        assert_eq!(form.credential, "");
        assert_eq!(form.target, "-100123");
        assert_eq!(form.to_channel(Some(&saved)).unwrap(), saved);
    }

    #[test]
    fn a_webhooks_url_never_reaches_the_form() {
        let form = ChannelForm::from_channel(&webhook());
        assert_eq!(form.target, "");
        assert_eq!(form.preview.as_deref(), Some("https://hooks.example.com/…"));
    }

    #[test]
    fn email_addresses_stay_editable() {
        let channel = ChannelInput {
            kind: ChannelKind::Email,
            target: "a@example.com".to_string(),
            ..webhook()
        };
        let form = ChannelForm::from_channel(&channel);
        assert_eq!(form.target, "a@example.com");
        assert_eq!(form.preview, None);
    }

    #[test]
    fn leaving_the_url_empty_keeps_it() {
        let saved = webhook();
        let form = ChannelForm::from_channel(&saved);
        assert_eq!(form.to_channel(Some(&saved)).unwrap(), saved);
    }

    #[test]
    fn a_new_url_replaces_the_saved_one() {
        let saved = webhook();
        let mut form = ChannelForm::from_channel(&saved);
        form.target = " https://hooks.example.com/new ".to_string();
        let channel = form.to_channel(Some(&saved)).unwrap();
        assert_eq!(channel.target, "https://hooks.example.com/new");
    }

    #[test]
    fn changing_the_kind_does_not_carry_the_old_destination_over() {
        let saved = webhook();
        let mut form = ChannelForm::from_channel(&saved);
        form.kind = "email".to_string();
        assert_eq!(form.to_channel(Some(&saved)).unwrap().target, "");
    }

    fn custom() -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::CustomWebhook,
            credential: Some("Authorization: Bearer secret\nX-Team: ops".to_string()),
            request: Some(WebhookRequest {
                method: WebhookMethod::Put,
                content_type: "application/json".to_string(),
                body: custom_webhook::EXAMPLE_BODY.to_string(),
            }),
            ..webhook()
        }
    }

    #[test]
    fn a_custom_webhooks_headers_never_reach_the_form_but_their_names_do() {
        let saved = custom();
        let form = ChannelForm::from_channel(&saved);
        assert_eq!(form.headers, "");
        assert_eq!(form.header_names, ["authorization", "x-team"]);
        assert_eq!(form.request_method, "PUT");
        assert_eq!(form.to_channel(Some(&saved)).unwrap(), saved);
    }

    #[test]
    fn typed_headers_replace_the_saved_ones_and_can_be_removed() {
        let saved = custom();
        let mut form = ChannelForm::from_channel(&saved);
        form.headers = "  X-Key: new \r\n\r\nX-Other: 2\r\n".to_string();
        let channel = form.to_channel(Some(&saved)).unwrap();
        assert_eq!(
            channel.credential.as_deref(),
            Some("X-Key: new\nX-Other: 2")
        );

        let mut form = ChannelForm::from_channel(&saved);
        form.remove_headers = true;
        assert_eq!(form.to_channel(Some(&saved)).unwrap().credential, None);
    }

    #[test]
    fn a_new_custom_webhook_starts_with_an_example_and_others_send_no_request() {
        let mut form = ChannelForm::blank();
        assert_eq!(form.request_body, custom_webhook::EXAMPLE_BODY);
        assert_eq!(form.request_content_type, "application/json");
        assert_eq!(form.to_channel(None).unwrap().request, None);
        form.kind = "custom_webhook".to_string();
        let request = form.to_channel(None).unwrap().request.unwrap();
        assert_eq!(request.method, WebhookMethod::Post);

        // A plain webhook made from a custom one keeps neither its headers nor its body.
        let saved = custom();
        let mut form = ChannelForm::from_channel(&saved);
        form.kind = "webhook".to_string();
        let channel = form.to_channel(Some(&saved)).unwrap();
        assert_eq!(channel.credential, None);
        assert_eq!(channel.request, None);
    }

    #[test]
    fn a_new_channel_has_nothing_to_keep() {
        assert_eq!(ChannelForm::blank().to_channel(None).unwrap().target, "");
    }
}
