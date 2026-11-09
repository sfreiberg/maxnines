//! Buttons on Slack messages. A Slack channel with an app-level token gets a Socket
//! Mode connection: the server connects out to Slack, and Slack sends button presses
//! back over it, so the server needs no address the internet can reach.
//!
//! Whoever presses a button acts as the MaxNines user with the same email address.
//! Slack guests and people from other organizations can't act at all.

use std::collections::{BTreeSet, HashMap};
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::FutureExt;
use slack_morphism::prelude::{
    SlackApiAppsConnectionOpenRequest, SlackApiPostWebhookMessageRequest, SlackApiUsersInfoRequest,
    SlackClientEventsListenerEnvironment, SlackClientEventsUserState,
    SlackClientHyperHttpsConnector, SlackInteractionBlockActionsEvent, SlackInteractionEvent,
    SlackInteractionResponse,
};
use slack_morphism::{
    SlackApiToken, SlackApiTokenValue, SlackClient, SlackClientHttpConnector,
    SlackClientSocketModeConfig, SlackClientSocketModeListener, SlackFileId, SlackMessageContent,
    SlackSocketModeListenerCallbacks, SlackUser, SlackUserId, UserCallbackResult,
};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use anyhow::anyhow;
use slack_morphism::errors::SlackClientError;

use crate::alerting::{Alert, ChannelKind, Event};
use crate::metrics::now_ms;
use crate::models::Database;
use crate::notifier::{
    self, ACKNOWLEDGE_ACTION, Notice, SILENCE_HOUR_ACTION, SlackControls, explain_slack, format_ms,
};
use crate::silences::{self, ActiveSilences, Cover};

const SILENCE_SECS: u64 = 3600;
const SILENCE_REASON: &str = "Silenced from Slack";

/// How long what Slack said about someone's email is trusted before asking again.
/// A MaxNines account is checked on every press, so disabling one works at once.
const REMEMBER_EMAILS: Duration = Duration::from_secs(300);

/// How often the server checks which Slack apps it should be listening to.
const CHECK_EVERY: Duration = Duration::from_secs(15);

/// How long to wait after Slack refuses an app-level token before trying again.
const RETRY_REFUSED: Duration = Duration::from_secs(300);

/// Why someone in Slack can't act.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Outsider,
    NoEmail,
    NoAccount(String),
}

impl Refusal {
    fn message(&self) -> String {
        match self {
            Self::Outsider => {
                "Only full members of this Slack workspace can act on MaxNines alerts.".to_string()
            }
            Self::NoEmail => "Slack didn't share your email address, so MaxNines can't tell who \
                              you are. The Slack app needs the users:read.email permission."
                .to_string(),
            Self::NoAccount(email) => format!(
                "There's no MaxNines account for {email}. Ask someone to add you, using the \
                 email address you use in Slack."
            ),
        }
    }
}

/// How to answer a press.
#[derive(Debug)]
enum Reply {
    /// Shows the message again with what's changed.
    Replace(SlackMessageContent),
    /// Tells only the person who pressed it.
    Tell(String),
}

/// What one Slack app's buttons do.
pub struct SlackActions {
    database: Database,
    web_url: Option<String>,
    bot_token: SlackApiToken,
    /// Slack user IDs, and the email address and when Slack gave it.
    emails: Mutex<HashMap<String, (Instant, String)>>,
}

impl SlackActions {
    pub fn new(database: Database, web_url: Option<String>, bot_token: &str) -> Self {
        Self {
            database,
            web_url,
            bot_token: SlackApiToken::new(SlackApiTokenValue(bot_token.trim().to_string())),
            emails: Mutex::default(),
        }
    }

    /// Does what was pressed, and answers through the message's response URL, which
    /// is the only place Slack can show anything.
    pub async fn handle<C>(&self, client: &SlackClient<C>, event: SlackInteractionBlockActionsEvent)
    where
        C: SlackClientHttpConnector + Send + Sync,
    {
        let Some(response_url) = event.response_url.clone() else {
            return;
        };
        let reply = match self.act(client, &event).await {
            Ok(None) => return,
            Ok(Some(Reply::Replace(content))) => {
                SlackApiPostWebhookMessageRequest::new(content).with_replace_original(true)
            }
            Ok(Some(Reply::Tell(text))) => tell(text),
            Err(error) => {
                warn!(error = format!("{error:#}"), "a Slack button failed");
                tell("That didn't work, so nothing changed. The MaxNines server's log says why.")
            }
        };
        if let Err(error) = client.respond_to_event(&response_url, &reply).await {
            warn!(error = %explain_slack(&error), "couldn't answer a Slack button");
        }
    }

    async fn act<C>(
        &self,
        client: &SlackClient<C>,
        event: &SlackInteractionBlockActionsEvent,
    ) -> Result<Option<Reply>>
    where
        C: SlackClientHttpConnector + Send + Sync,
    {
        let ours = [ACKNOWLEDGE_ACTION, SILENCE_HOUR_ACTION];
        let Some(action) = event
            .actions
            .iter()
            .flatten()
            .find(|action| ours.contains(&action.action_id.0.as_str()))
        else {
            return Ok(None);
        };
        let alert_id: i64 = action
            .value
            .as_deref()
            .and_then(|value| value.parse().ok())
            .context("the button doesn't name an alert")?;
        let user = event
            .user
            .as_ref()
            .context("Slack didn't say who pressed it")?;

        let email = match self.email_of(client, &user.id).await? {
            Ok(email) => email,
            Err(refusal) => return Ok(Some(Reply::Tell(refusal.message()))),
        };
        let Some(account) = self.database.active_user_by_email(&email).await? else {
            return Ok(Some(Reply::Tell(Refusal::NoAccount(email).message())));
        };

        let now = now_ms();
        if action.action_id.0 == ACKNOWLEDGE_ACTION {
            self.database
                .acknowledge_alert(alert_id, &account.email, now)
                .await?;
        } else {
            self.silence(alert_id, &account.email, now).await?;
        }
        info!(
            alert = alert_id,
            by = account.email,
            action = action.action_id.0,
            "acted on an alert from Slack"
        );

        let Some(alert) = self.database.get_alert(alert_id).await? else {
            return Ok(Some(Reply::Tell(
                "That alert no longer exists.".to_string(),
            )));
        };
        // The message keeps the chart it was sent with.
        let chart = event
            .message
            .as_ref()
            .and_then(|message| notifier::slack_chart(&message.content));
        Ok(Some(Reply::Replace(
            self.content(&alert, now, chart.as_ref()).await?,
        )))
    }

    /// Silences just this alert, unless something already covers it or it's over.
    async fn silence(&self, alert_id: i64, by: &str, now: i64) -> Result<()> {
        let Some(alert) = self.database.get_alert(alert_id).await? else {
            return Ok(());
        };
        if alert.resolved_ms.is_some() || alert.rule_id.is_none() {
            return Ok(());
        }
        let quiet = ActiveSilences::load(&self.database, now).await?;
        if quiet.covering(&alert).is_some() {
            return Ok(());
        }
        let input = silences::silence_for(&alert, SILENCE_REASON, SILENCE_SECS);
        silences::check_silence(&input)?;
        self.database.create_silence(&input, by, now).await?;
        Ok(())
    }

    /// The message as it should look now, with only the buttons still worth pressing.
    async fn content(
        &self,
        alert: &Alert,
        now: i64,
        chart: Option<&SlackFileId>,
    ) -> Result<SlackMessageContent> {
        let event = if alert.resolved_ms.is_some() {
            Event::Resolved
        } else {
            Event::Firing
        };
        let quiet = ActiveSilences::load(&self.database, now).await?;
        let silenced = match quiet.covering(alert) {
            Some(Cover::Silence { id, ends_ms }) => {
                let by = self.database.get_silence(id).await?.map(|s| s.created_by);
                Some(match by {
                    Some(by) => format!("Silenced by {by} until {}", format_ms(ends_ms)),
                    None => format!("Silenced until {}", format_ms(ends_ms)),
                })
            }
            Some(Cover::Window { ends_ms, .. }) => Some(format!(
                "In a maintenance window until {}",
                format_ms(ends_ms)
            )),
            None => None,
        };
        let notice = Notice::for_alert(alert.clone(), event);
        let controls = SlackControls { silenced };
        Ok(notifier::slack_content(
            &notice,
            self.web_url.as_deref(),
            Some(&controls),
            chart,
        ))
    }

    /// The email address on someone's Slack profile, unless they're a guest, from
    /// another organization, or not a person.
    async fn email_of<C>(
        &self,
        client: &SlackClient<C>,
        user: &SlackUserId,
    ) -> Result<Result<String, Refusal>>
    where
        C: SlackClientHttpConnector + Send + Sync,
    {
        if let Some(email) = self.remembered(&user.0) {
            return Ok(Ok(email));
        }
        let session = client.open_session(&self.bot_token);
        let found = session
            .users_info(&SlackApiUsersInfoRequest::new(user.clone()))
            .await
            .map_err(|error| explain_slack(&error))?
            .user;
        let email = match email_for(found) {
            Ok(email) => email,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut emails = self.emails.lock().unwrap_or_else(PoisonError::into_inner);
        emails.retain(|_, (at, _)| at.elapsed() < REMEMBER_EMAILS);
        emails.insert(user.0.clone(), (Instant::now(), email.clone()));
        Ok(Ok(email))
    }

    fn remembered(&self, user: &str) -> Option<String> {
        let emails = self.emails.lock().unwrap_or_else(PoisonError::into_inner);
        emails
            .get(user)
            .filter(|(at, _)| at.elapsed() < REMEMBER_EMAILS)
            .map(|(_, email)| email.clone())
    }
}

/// Guests are invited to a few channels, strangers come from another organization
/// through Slack Connect, and neither is someone MaxNines should take orders from.
fn email_for(user: SlackUser) -> Result<String, Refusal> {
    let flags = &user.flags;
    let outsider = [
        flags.is_restricted,
        flags.is_ultra_restricted,
        flags.is_stranger,
        flags.is_bot,
        user.deleted,
    ]
    .contains(&Some(true));
    if outsider {
        return Err(Refusal::Outsider);
    }
    user.profile
        .and_then(|profile| profile.email)
        .map(|email| email.0.trim().to_lowercase())
        .filter(|email| !email.is_empty())
        .ok_or(Refusal::NoEmail)
}

/// Slack shows a reply only to whoever pressed the button, unless told otherwise.
fn tell(text: impl Into<String>) -> SlackApiPostWebhookMessageRequest {
    SlackApiPostWebhookMessageRequest::new(SlackMessageContent::new().with_text(text.into()))
        .with_replace_original(false)
}

/// Checks Slack will take an app-level token, without connecting.
pub async fn check_app_token<C>(client: &SlackClient<C>, app_token: &str) -> Result<()>
where
    C: SlackClientHttpConnector + Send + Sync,
{
    let token = SlackApiToken::new(SlackApiTokenValue(app_token.trim().to_string()));
    client
        .open_session(&token)
        .apps_connections_open(&SlackApiAppsConnectionOpenRequest::new())
        .await
        .map_err(|error| explain_app_token(&error))?;
    Ok(())
}

/// The bot token's problems are worded differently, so these get their own.
fn explain_app_token(error: &SlackClientError) -> anyhow::Error {
    let SlackClientError::ApiError(error) = error else {
        return explain_slack(error);
    };
    let code = error.code.as_str();
    match code {
        "invalid_auth" | "not_authed" | "token_revoked" | "token_expired" | "account_inactive" => {
            anyhow!("Slack didn't accept the app-level token ({code})")
        }
        "not_allowed_token_type" => {
            anyhow!("that isn't an app-level token, which starts with xapp- ({code})")
        }
        "missing_scope" => {
            anyhow!("the app-level token needs the connections:write scope ({code})")
        }
        _ => anyhow!("Slack said {code}"),
    }
}

type Listener = SlackClientSocketModeListener<SlackClientHyperHttpsConnector>;

/// The app-level and bot tokens of each Slack app with buttons.
type AppTokens = (String, String);

/// Keeps a Socket Mode connection open for each Slack app that has an app-level
/// token, following channels as they're added, changed and removed.
pub fn spawn(database: Database, web_url: Option<String>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut running: HashMap<AppTokens, Listener> = HashMap::new();
        let mut refused: HashMap<AppTokens, Instant> = HashMap::new();
        let mut timer = tokio::time::interval(CHECK_EVERY);
        loop {
            timer.tick().await;
            let pass = follow_channels(&database, web_url.as_ref(), &mut running, &mut refused);
            match AssertUnwindSafe(pass).catch_unwind().await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!(error = format!("{error:#}"), "checking Slack apps failed");
                }
                Err(_) => error!("checking Slack apps panicked"),
            }
        }
    })
}

async fn follow_channels(
    database: &Database,
    web_url: Option<&String>,
    running: &mut HashMap<AppTokens, Listener>,
    refused: &mut HashMap<AppTokens, Instant>,
) -> Result<()> {
    let wanted: BTreeSet<AppTokens> = database
        .list_channels()
        .await?
        .into_iter()
        .filter(|channel| channel.channel.kind == ChannelKind::Slack)
        .filter_map(|channel| {
            let app = channel.channel.app_token?.trim().to_string();
            let bot = channel.channel.credential?.trim().to_string();
            Some((app, bot))
        })
        .collect();

    let gone: Vec<AppTokens> = running
        .keys()
        .filter(|tokens| !wanted.contains(*tokens))
        .cloned()
        .collect();
    for tokens in gone {
        if let Some(listener) = running.remove(&tokens) {
            listener.shutdown().await;
            info!("stopped listening for a Slack app's buttons");
        }
    }
    refused.retain(|tokens, at| wanted.contains(tokens) && at.elapsed() < RETRY_REFUSED);

    for tokens in wanted {
        if running.contains_key(&tokens) || refused.contains_key(&tokens) {
            continue;
        }
        match listen(database, web_url, &tokens).await {
            Ok(listener) => {
                info!("listening for a Slack app's buttons");
                running.insert(tokens, listener);
            }
            Err(error) => {
                warn!(
                    error = format!("{error:#}"),
                    "couldn't listen for a Slack app's buttons, so trying again in 5 minutes"
                );
                refused.insert(tokens, Instant::now());
            }
        }
    }
    Ok(())
}

/// Each press is handled in a task of its own, as Slack expects to hear back over
/// the connection within three seconds, and the reply goes by the response URL.
async fn listen(
    database: &Database,
    web_url: Option<&String>,
    (app_token, bot_token): &AppTokens,
) -> Result<Listener> {
    let client = Arc::new(SlackClient::new(notifier::slack_connector()?));
    check_app_token(&client, app_token).await?;

    let actions = Arc::new(SlackActions::new(
        database.clone(),
        web_url.cloned(),
        bot_token,
    ));
    let mut callbacks = SlackSocketModeListenerCallbacks::new();
    callbacks.interaction_callback = Box::new(
        move |event: SlackInteractionEvent,
              client: Arc<SlackClient<SlackClientHyperHttpsConnector>>,
              _state: SlackClientEventsUserState| {
            let actions = actions.clone();
            async move {
                if let SlackInteractionEvent::BlockActions(event) = event {
                    tokio::spawn(async move { actions.handle(&client, event).await });
                }
                UserCallbackResult::Ok(SlackInteractionResponse::Empty)
            }
        },
    );

    let environment = Arc::new(SlackClientEventsListenerEnvironment::new(client));
    let listener = SlackClientSocketModeListener::new(
        &SlackClientSocketModeConfig::new(),
        environment,
        callbacks,
    );
    let token = SlackApiToken::new(SlackApiTokenValue(app_token.clone()));
    listener
        .listen_for(&token)
        .await
        .map_err(|error| explain_slack(&error))?;
    listener.start().await;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(extra: serde_json::Value) -> SlackUser {
        let mut value = json!({
            "id": "U1",
            "profile": { "email": " Sam@Example.com " },
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_member_is_known_by_their_email_in_lower_case() {
        assert_eq!(
            email_for(user(json!({}))),
            Ok("sam@example.com".to_string())
        );
    }

    #[test]
    fn guests_strangers_bots_and_deleted_users_are_refused() {
        for flag in [
            "is_restricted",
            "is_ultra_restricted",
            "is_stranger",
            "is_bot",
            "deleted",
        ] {
            assert_eq!(
                email_for(user(json!({ flag: true }))),
                Err(Refusal::Outsider),
                "{flag}"
            );
        }
    }

    /// Socket Mode connects with tokio-tungstenite, which only speaks TLS when this
    /// crate turns it on. Without it, every connection would fail with a URL error.
    #[tokio::test]
    async fn socket_mode_connections_can_use_tls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        });

        let error = tokio_tungstenite::connect_async(format!("wss://{address}/link"))
            .await
            .unwrap_err();

        assert!(
            !matches!(error, tokio_tungstenite::tungstenite::Error::Url(_)),
            "{error:?}"
        );
    }

    #[test]
    fn app_level_token_problems_say_which_token() {
        let refused = |code: &str| {
            let error = slack_morphism::errors::SlackClientApiError::new(code.to_string());
            explain_app_token(&SlackClientError::ApiError(error)).to_string()
        };
        assert_eq!(
            refused("invalid_auth"),
            "Slack didn't accept the app-level token (invalid_auth)"
        );
        assert_eq!(
            refused("not_allowed_token_type"),
            "that isn't an app-level token, which starts with xapp- (not_allowed_token_type)"
        );
        assert_eq!(refused("ratelimited"), "Slack said ratelimited");
    }

    #[test]
    fn someone_without_a_shared_email_is_refused() {
        assert_eq!(
            email_for(user(json!({ "profile": {} }))),
            Err(Refusal::NoEmail)
        );
    }
}
