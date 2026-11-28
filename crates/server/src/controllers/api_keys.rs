//! The page for creating and revoking API keys.

use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use chrono::TimeDelta;
use serde::Serialize;

use super::users::role_choices;
use super::{CsrfForm, Page, local_date, local_time, server_error, signed_in_user};
use crate::app_state::AppState;
use crate::models::{ApiKey, check_api_key_name, expiry_after};
use crate::roles::Role;
use crate::times::{self, Timestamp};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings/api-keys", get(index).post(create))
        .route("/settings/api-keys/{id}/revoke", post(revoke))
}

/// What the form offers, in seconds. Anything else can be asked for through the API.
const LIFETIMES: [(&str, Option<u64>); 7] = [
    ("Never expires", None),
    ("1 hour", Some(3600)),
    ("1 day", Some(86_400)),
    ("7 days", Some(604_800)),
    ("30 days", Some(2_592_000)),
    ("90 days", Some(7_776_000)),
    ("1 year", Some(31_536_000)),
];

#[derive(Serialize)]
struct KeyRow {
    id: i64,
    name: String,
    /// Who it acts as.
    owner: String,
    role: &'static str,
    hint: String,
    /// The day it was made, and the whole time for anyone who wants it.
    created: String,
    created_at: String,
    /// What it says about expiring, such as `Expires 2026-11-19`.
    expiry: String,
    expires_at: Option<String>,
    /// Still working, but not for much longer.
    expires_soon: bool,
    /// How long ago it was last used, and exactly when.
    last_used: Option<String>,
    last_used_at: Option<String>,
    status: &'static str,
    usable: bool,
}

/// How close to expiring a key is worth pointing out.
const EXPIRES_SOON: TimeDelta = TimeDelta::days(7);

#[derive(Serialize)]
struct Lifetime {
    label: &'static str,
    value: String,
}

fn lifetimes() -> Vec<Lifetime> {
    LIFETIMES
        .iter()
        .map(|(label, secs)| Lifetime {
            label,
            value: secs.map_or_else(String::new, |secs| secs.to_string()),
        })
        .collect()
}

/// A lifetime from the form, which only ever offers those above.
fn chosen_lifetime(value: &str) -> Option<Option<u64>> {
    if value.is_empty() {
        return Some(None);
    }
    let secs: u64 = value.parse().ok()?;
    LIFETIMES
        .iter()
        .any(|(_, offered)| *offered == Some(secs))
        .then_some(Some(secs))
}

fn row(key: ApiKey, now: Timestamp) -> KeyRow {
    let status = if key.revoked_at.is_some() {
        "Revoked"
    } else if key.has_expired(now) {
        "Expired"
    } else {
        "Active"
    };
    let usable = status == "Active";
    let expiry = match key.expires_at {
        None => "Never expires".to_string(),
        Some(expires) if expires <= now => format!("Expired {}", local_date(expires)),
        Some(expires) => format!("Expires {}", local_date(expires)),
    };
    KeyRow {
        created: local_date(key.created_at),
        created_at: local_time(key.created_at),
        expiry,
        expires_at: key.expires_at.map(local_time),
        expires_soon: usable
            && key
                .expires_at
                .is_some_and(|expires| expires - now <= EXPIRES_SOON),
        last_used: key.last_used_at.map(|used| times::ago(used, now)),
        last_used_at: key.last_used_at.map(local_time),
        status,
        usable,
        id: key.id,
        name: key.name,
        owner: key.owner,
        role: key.role.label(),
        hint: key.hint,
    }
}

/// The keys whoever's signed in may see and revoke: their own, or for an admin,
/// everyone's.
pub async fn visible_keys(state: &AppState) -> anyhow::Result<Vec<ApiKey>> {
    let Some(viewer) = signed_in_user() else {
        return Ok(Vec::new());
    };
    let mut keys = state.database.list_api_keys().await?;
    if viewer.role < Role::Admin {
        keys.retain(|key| key.user_id == viewer.id);
    }
    Ok(keys)
}

/// Revokes a key if it's one they may. Returns false for any other, as if it
/// weren't there.
pub async fn revoke_if_allowed(state: &AppState, id: i64) -> anyhow::Result<bool> {
    if !visible_keys(state).await?.iter().any(|key| key.id == id) {
        return Ok(false);
    }
    state.database.revoke_api_key(id, crate::times::now()).await
}

/// `new_key` is only ever on the page right after creating it.
async fn page(
    state: &AppState,
    token: &CsrfToken,
    new_key: Option<&str>,
    error: Option<&str>,
) -> Response {
    let keys = match visible_keys(state).await {
        Ok(keys) => keys,
        Err(error) => return server_error(&error),
    };
    let yours = signed_in_user().map_or(Role::Viewer, |user| user.role);
    let now = crate::times::now();
    let rows: Vec<KeyRow> = keys.into_iter().map(|key| row(key, now)).collect();
    let page = Page::new(state, token, "settings/api_keys.html")
        .with("keys", &rows)
        .with("lifetimes", &lifetimes())
        .with("roles", &role_choices(yours))
        .with("your_role", yours.as_str())
        .with("sees_all", &(yours >= Role::Admin))
        .with("new_key", &new_key)
        .with("error", &error);
    if error.is_some() {
        page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render()
    } else {
        page.render()
    }
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    page(&state, &token, None, None).await
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let name = form.fields.get("name").map_or("", |name| name.trim());
    if let Err(error) = check_api_key_name(name) {
        return page(&state, &form.token, None, Some(&format!("{error:#}"))).await;
    }
    let lifetime = form.fields.get("lifetime").map_or("", String::as_str);
    let Some(lifetime) = chosen_lifetime(lifetime) else {
        let error = "Choose how long the key should last.";
        return page(&state, &form.token, None, Some(error)).await;
    };
    let now = crate::times::now();
    let expires_at = match lifetime
        .map(|secs| expiry_after(Duration::from_secs(secs), now))
        .transpose()
    {
        Ok(expires) => expires,
        Err(error) => return server_error(&error),
    };
    // Everyone here is signed in, as a person or with a key that acts as one.
    let Some(owner) = signed_in_user() else {
        return server_error(&anyhow::anyhow!("nobody signed in to own a key"));
    };
    let role = form.fields.get("role").map_or("", String::as_str);
    let role = match Role::parse(role) {
        Ok(role) if role <= owner.role => role,
        Ok(_) => {
            let error = "A key can't do more than you can.";
            return page(&state, &form.token, None, Some(error)).await;
        }
        Err(error) => return page(&state, &form.token, None, Some(&format!("{error:#}"))).await,
    };
    match state
        .database
        .create_api_key(name, owner.id, role, expires_at, now)
        .await
    {
        Ok((_, key)) => {
            let mut response = page(&state, &form.token, Some(&key), None).await;
            // The key is on this page, and nowhere else from now on.
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => server_error(&error),
    }
}

async fn revoke(State(state): State<AppState>, Path(id): Path<i64>, _form: CsrfForm) -> Response {
    match revoke_if_allowed(&state, id).await {
        Ok(_) => Redirect::to("/settings/api-keys").into_response(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_can_only_choose_what_it_offers() {
        assert_eq!(chosen_lifetime(""), Some(None));
        assert_eq!(chosen_lifetime("3600"), Some(Some(3600)));
        assert_eq!(chosen_lifetime("12345"), None);
        assert_eq!(chosen_lifetime("soon"), None);
    }

    /// A key, with when it expires and was revoked.
    fn key(expires_at: Option<Timestamp>, revoked_at: Option<Timestamp>) -> ApiKey {
        ApiKey {
            id: 1,
            name: "a".to_string(),
            user_id: 1,
            owner: "a@example.com".to_string(),
            role: Role::Admin,
            hint: "mxn_".to_string(),
            created_at: times::from_ms(0),
            expires_at,
            last_used_at: None,
            last_address: None,
            last_forwarded_for: None,
            revoked_at,
        }
    }

    #[test]
    fn keys_say_whether_they_still_work() {
        let at = times::from_ms;
        assert_eq!(row(key(None, None), at(100)).status, "Active");
        assert_eq!(row(key(Some(at(200)), None), at(100)).status, "Active");
        assert_eq!(row(key(Some(at(50)), None), at(100)).status, "Expired");
        assert_eq!(
            row(key(Some(at(50)), Some(at(10))), at(100)).status,
            "Revoked"
        );
        assert!(!row(key(Some(at(50)), None), at(100)).usable);
    }

    #[test]
    fn keys_say_when_they_expire_and_how_long_ago_they_were_used() {
        const DAY: TimeDelta = TimeDelta::days(1);
        let now = times::from_ms(0) + DAY * 400;

        let forever = row(key(None, None), now);
        assert_eq!(forever.created, "1970-01-01");
        assert_eq!(forever.created_at, "1970-01-01 00:00:00 UTC");
        assert_eq!(forever.expiry, "Never expires");
        assert!(!forever.expires_soon);
        assert_eq!((forever.last_used, forever.last_used_at), (None, None));

        // A week or less to go is worth pointing out, while it still works.
        let soon = row(key(Some(now + DAY * 7), None), now);
        assert_eq!(soon.expiry, "Expires 1971-02-12");
        assert!(soon.expires_soon);
        assert!(!row(key(Some(now + DAY * 8), None), now).expires_soon);
        assert!(!row(key(Some(now + DAY), Some(times::from_ms(5))), now).expires_soon);

        let expired = row(key(Some(now - DAY), None), now);
        assert_eq!(expired.expiry, "Expired 1971-02-04");
        assert!(!expired.expires_soon);

        let mut used = key(None, None);
        used.last_used_at = Some(now - TimeDelta::minutes(5));
        let used = row(used, now);
        assert_eq!(used.last_used.as_deref(), Some("5 minutes ago"));
        assert_eq!(
            used.last_used_at.as_deref(),
            Some("1971-02-04 23:55:00 UTC")
        );
    }
}
