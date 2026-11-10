//! The page for creating and revoking API keys.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::users::role_choices;
use super::{CsrfForm, Page, local_time, server_error, signed_in_user};
use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::models::{ApiKey, check_api_key_name, expiry_after};
use crate::roles::Role;

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
    created: String,
    expires: Option<String>,
    last_used: Option<String>,
    status: &'static str,
    usable: bool,
}

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

fn row(key: ApiKey, now_ms: i64) -> KeyRow {
    let status = if key.revoked_ms.is_some() {
        "Revoked"
    } else if key.has_expired(now_ms) {
        "Expired"
    } else {
        "Active"
    };
    KeyRow {
        created: local_time(key.created_ms),
        expires: key.expires_ms.map(local_time),
        last_used: key.last_used_ms.map(local_time),
        status,
        usable: status == "Active",
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
    state.database.revoke_api_key(id, now_ms()).await
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
    let now = now_ms();
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
    let now = now_ms();
    let expires_ms = match lifetime.map(|secs| expiry_after(secs, now)).transpose() {
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
        .create_api_key(name, owner.id, role, expires_ms, now)
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

    fn key(expires_ms: Option<i64>, revoked_ms: Option<i64>) -> ApiKey {
        ApiKey {
            id: 1,
            name: "a".to_string(),
            user_id: 1,
            owner: "a@example.com".to_string(),
            role: Role::Admin,
            hint: "mxn_".to_string(),
            created_ms: 0,
            expires_ms,
            last_used_ms: None,
            revoked_ms,
        }
    }

    #[test]
    fn keys_say_whether_they_still_work() {
        assert_eq!(row(key(None, None), 100).status, "Active");
        assert_eq!(row(key(Some(200), None), 100).status, "Active");
        assert_eq!(row(key(Some(50), None), 100).status, "Expired");
        assert_eq!(row(key(Some(50), Some(10)), 100).status, "Revoked");
        assert!(!row(key(Some(50), None), 100).usable);
    }
}
