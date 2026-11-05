use std::collections::BTreeMap;

use anyhow::Result;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{CsrfForm, Page, server_error};
use crate::alerting::{Channel, ChannelInput, ChannelKind};
use crate::app_state::AppState;
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
    /// Slack's bot token, which is only ever typed in and never shown again.
    credential: String,
    has_credential: bool,
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
        }
    }

    fn from_channel(channel: &ChannelInput) -> Self {
        let hidden = matches!(channel.kind, ChannelKind::Webhook | ChannelKind::Discord);
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
        }
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
        let typed = self.credential.trim();
        let credential = match saved {
            _ if kind != ChannelKind::Slack => None,
            _ if !typed.is_empty() => Some(typed.to_string()),
            Some(saved) if saved.kind == kind => saved.credential.clone(),
            _ => None,
        };
        Ok(ChannelInput {
            name: self.name.trim().to_string(),
            kind,
            target,
            credential,
        })
    }
}

#[derive(Serialize)]
struct ChannelRow {
    id: i64,
    name: String,
    kind: &'static str,
    target: String,
    /// A plain webhook into Slack, which Slack is moving away from.
    legacy_slack: bool,
}

impl From<Channel> for ChannelRow {
    fn from(channel: Channel) -> Self {
        Self {
            id: channel.id,
            kind: channel.channel.kind.as_str(),
            target: channel.channel.target_preview(),
            legacy_slack: channel.channel.kind == ChannelKind::Webhook
                && channel.channel.target.contains("hooks.slack.com"),
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
        .with("email_ready", &state.senders.mailer.is_some())
        .with("notice", &notice)
        .with("error", &error)
        .render()
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    index_page(&state, &token, None, None).await
}

fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &ChannelForm,
    error: Option<&str>,
) -> Response {
    let page = Page::new(state, token, "notification_channels/form.html")
        .with("id", &id)
        .with("channel", form)
        .with("email_ready", &state.senders.mailer.is_some())
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

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let fields = ChannelForm::from_fields(&form.fields);
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
                && saved.channel.kind != ChannelKind::Email
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
        }
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

    #[test]
    fn a_new_channel_has_nothing_to_keep() {
        assert_eq!(ChannelForm::blank().to_channel(None).unwrap().target, "");
    }
}
