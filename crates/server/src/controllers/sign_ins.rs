//! Who's signed in, from where and with what role: browsers, apps signed in through
//! the browser, and API keys in use. Admins see everyone's under Settings, Users,
//! Sign-ins, and each person sees their own on their profile. Any can be ended.

use std::collections::BTreeMap;

use anyhow::Result;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};

use super::sessions::this_session;
use super::{CsrfForm, Page, local_date, local_time, server_error, signed_in_user};
use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::models::User;
use crate::roles::Role;

pub const SIGN_INS_PAGE: &str = "/settings/users/sign-ins";
const PROFILE_PAGE: &str = "/profile";

/// An API key used within this long counts as signed in.
const KEY_IN_USE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(SIGN_INS_PAGE, get(index))
        .route("/profile/sign-ins/{kind}/{id}/end", post(end))
}

/// How someone's signed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Browser,
    App,
    ApiKey,
}

impl Kind {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "browser" => Some(Self::Browser),
            "app" => Some(Self::App),
            "api_key" => Some(Self::ApiKey),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::App => "app",
            Self::ApiKey => "api_key",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Browser => "Browser",
            Self::App => "App",
            Self::ApiKey => "API key",
        }
    }
}

/// One way someone's signed in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignIn {
    pub kind: Kind,
    pub id: i64,
    pub user_id: i64,
    /// Their email address.
    pub user: String,
    /// What it may do now: the person's role, or the app's or key's if that's lower.
    pub role: Role,
    /// The browser, such as "Chrome on macOS", the app and its device, or the key's name.
    pub name: String,
    /// Where it was last used from. Behind a proxy, it's the address the proxy passed
    /// on, if the proxy is one the server trusts.
    pub address: Option<String>,
    /// What an untrusted proxy at `address` said it was passing on, so unconfirmed.
    pub forwarded_for: Option<String>,
    pub signed_in_ms: i64,
    pub last_used_ms: Option<i64>,
    /// When it stops working unless it's used, or for a key that never expires, nothing.
    pub expires_ms: Option<i64>,
    /// Whether it's the browser asking.
    pub current: bool,
}

/// Whose sign-ins whoever's signed in may see and end: their own, or for an admin,
/// everyone's, which is `None`. Nobody's, if nobody's signed in.
pub fn whose() -> Option<Option<i64>> {
    let viewer = signed_in_user()?;
    Some((viewer.role < Role::Admin).then_some(viewer.id))
}

/// Every way people are signed in now, most recently used first: everyone's, or only
/// `user_id`'s. Disabled people are left out, as none of theirs works.
pub async fn sign_ins(state: &AppState, user_id: Option<i64>, now: i64) -> Result<Vec<SignIn>> {
    let people: BTreeMap<i64, User> = state
        .database
        .list_users()
        .await?
        .into_iter()
        .filter(|user| user.disabled_ms.is_none())
        .map(|user| (user.id, user))
        .collect();
    let current = this_session();
    let mut all = Vec::new();
    for session in state.database.list_sessions(user_id, now).await? {
        let Some(person) = people.get(&session.user_id) else {
            continue;
        };
        all.push(SignIn {
            kind: Kind::Browser,
            id: session.id,
            user_id: person.id,
            user: person.email.clone(),
            role: person.role,
            name: browser_name(session.user_agent.as_deref()),
            address: session.last_address,
            forwarded_for: session.last_forwarded_for,
            signed_in_ms: session.created_ms,
            last_used_ms: session.last_used_ms,
            expires_ms: Some(session.expires_ms),
            current: current == Some(session.id),
        });
    }
    for app in state.database.list_app_sign_ins(user_id).await? {
        let Some(person) = people.get(&app.user_id).filter(|_| app.is_active(now)) else {
            continue;
        };
        all.push(SignIn {
            kind: Kind::App,
            id: app.id,
            user_id: person.id,
            user: person.email.clone(),
            role: app.role.min(person.role),
            name: app.title(),
            address: app.last_address,
            forwarded_for: app.last_forwarded_for,
            signed_in_ms: app.created_ms,
            last_used_ms: app.last_used_ms,
            expires_ms: Some(app.expires_ms),
            current: false,
        });
    }
    for key in state.database.list_api_keys().await? {
        let in_use = key.revoked_ms.is_none()
            && !key.has_expired(now)
            && key
                .last_used_ms
                .is_some_and(|used| now - used < KEY_IN_USE_MS)
            && user_id.is_none_or(|user_id| key.user_id == user_id);
        let Some(person) = people.get(&key.user_id).filter(|_| in_use) else {
            continue;
        };
        all.push(SignIn {
            kind: Kind::ApiKey,
            id: key.id,
            user_id: person.id,
            user: person.email.clone(),
            role: key.role.min(person.role),
            name: key.name,
            address: key.last_address,
            forwarded_for: key.last_forwarded_for,
            signed_in_ms: key.created_ms,
            last_used_ms: key.last_used_ms,
            expires_ms: key.expires_ms,
            current: false,
        });
    }
    all.sort_by_key(|sign_in| {
        std::cmp::Reverse(sign_in.last_used_ms.unwrap_or(sign_in.signed_in_ms))
    });
    Ok(all)
}

/// Ends a sign-in if it's one whoever's signed in may end. Returns false for any other,
/// as if it weren't there.
pub async fn end_if_allowed(state: &AppState, kind: Kind, id: i64) -> Result<bool> {
    let Some(whose) = whose() else {
        return Ok(false);
    };
    match kind {
        Kind::Browser => {
            let theirs = state
                .database
                .list_sessions(whose, now_ms())
                .await?
                .iter()
                .any(|session| session.id == id);
            if !theirs {
                return Ok(false);
            }
            Ok(state.database.end_session_by_id(id).await?.is_some())
        }
        Kind::App => super::app_sign_ins::revoke_if_allowed(state, id).await,
        Kind::ApiKey => super::api_keys::revoke_if_allowed(state, id).await,
    }
}

/// What a browser said it was, in a few words, such as "Chrome on macOS".
pub fn browser_name(user_agent: Option<&str>) -> String {
    let Some(agent) = user_agent.filter(|agent| !agent.is_empty()) else {
        return "A browser".to_string();
    };
    let browser = if agent.contains("Edg/") {
        "Edge"
    } else if agent.contains("OPR/") {
        "Opera"
    } else if agent.contains("Firefox/") || agent.contains("FxiOS/") {
        "Firefox"
    } else if agent.contains("Chrome/") || agent.contains("CriOS/") {
        "Chrome"
    } else if agent.contains("Safari/") {
        "Safari"
    } else {
        "A browser"
    };
    let system = if agent.contains("iPhone") {
        Some("iPhone")
    } else if agent.contains("iPad") {
        Some("iPad")
    } else if agent.contains("Android") {
        Some("Android")
    } else if agent.contains("CrOS") {
        Some("ChromeOS")
    } else if agent.contains("Windows") {
        Some("Windows")
    } else if agent.contains("Mac OS X") || agent.contains("Macintosh") {
        Some("macOS")
    } else if agent.contains("Linux") {
        Some("Linux")
    } else if agent.contains("FreeBSD") {
        Some("FreeBSD")
    } else {
        None
    };
    match system {
        Some(system) => format!("{browser} on {system}"),
        None => browser.to_string(),
    }
}

/// A sign-in as a table shows it.
#[derive(Serialize)]
pub struct Row {
    kind: &'static str,
    kind_label: &'static str,
    id: i64,
    user: String,
    role: &'static str,
    name: String,
    address: String,
    forwarded_for: Option<String>,
    since: String,
    since_at: String,
    last_used: Option<String>,
    last_used_at: Option<String>,
    expires: String,
    current: bool,
}

pub fn rows(sign_ins: Vec<SignIn>, now: i64) -> Vec<Row> {
    let ago = |ms: i64| {
        let (then, now) = (u64::try_from(ms).ok()?, u64::try_from(now).ok()?);
        Some(crate::times::ago(then, now))
    };
    sign_ins
        .into_iter()
        .map(|sign_in| Row {
            kind: sign_in.kind.as_str(),
            kind_label: sign_in.kind.label(),
            id: sign_in.id,
            role: sign_in.role.label(),
            address: sign_in.address.unwrap_or_else(|| "–".to_string()),
            forwarded_for: sign_in.forwarded_for,
            since: local_date(sign_in.signed_in_ms),
            since_at: local_time(sign_in.signed_in_ms),
            last_used: sign_in.last_used_ms.and_then(ago),
            last_used_at: sign_in.last_used_ms.map(local_time),
            expires: sign_in
                .expires_ms
                .map_or_else(|| "Never".to_string(), local_date),
            current: sign_in.current,
            user: sign_in.user,
            name: sign_in.name,
        })
        .collect()
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let now = now_ms();
    match sign_ins(&state, None, now).await {
        Ok(found) => Page::new(&state, &token, "settings/sign_ins.html")
            .with("sign_ins", &rows(found, now))
            .render(),
        Err(error) => server_error(&error),
    }
}

async fn end(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, i64)>,
    form: CsrfForm,
) -> Response {
    let Some(kind) = Kind::parse(&kind) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let own_browser = kind == Kind::Browser && this_session() == Some(id);
    match end_if_allowed(&state, kind, id).await {
        // Ending this browser's own sign-in signs it out.
        Ok(true) if own_browser => (form.token, Redirect::to("/login")).into_response(),
        Ok(true) => {
            let back = match form.fields.get("back").map(String::as_str) {
                Some(SIGN_INS_PAGE) => SIGN_INS_PAGE,
                _ => PROFILE_PAGE,
            };
            (form.token, Redirect::to(back)).into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_are_named_in_a_few_words() {
        let names = [
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Chrome on macOS",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
                "Edge on Windows",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
                "Firefox on Linux",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
                "Safari on iPhone",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
                "Safari on macOS",
            ),
            ("curl/8.7.1", "A browser"),
        ];
        for (agent, name) in names {
            assert_eq!(browser_name(Some(agent)), name, "{agent}");
        }
        assert_eq!(browser_name(None), "A browser");
    }
}
