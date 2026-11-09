//! The pages for managing users, and each person's own profile.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::sessions::session_token;
use super::{CsrfForm, Page, local_time, server_error, signed_in_user};
use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::models::{THEMES, User, UserChange, check_new_password, check_new_user, is_theme};
use crate::passwords::{hash_password, password_matches};
use crate::times::{zone_named, zone_names};

const USERS_PAGE: &str = "/settings/users";
const PROFILE_PAGE: &str = "/profile";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(USERS_PAGE, get(index).post(create))
        .route("/settings/users/{id}/disable", post(disable))
        .route("/settings/users/{id}/enable", post(enable))
        .route("/settings/users/{id}/delete", post(delete))
        .route("/settings/users/{id}/setup-link", post(new_link))
        .route(PROFILE_PAGE, get(profile))
        .route("/profile/theme", post(choose_theme))
        .route("/profile/time-zone", post(choose_time_zone))
        .route("/profile/password", post(change_password))
}

/// Where someone goes to set their password, which only works while the link does.
pub fn setup_url(state: &AppState, token: &str) -> String {
    format!("{}/setup/{token}", state.web_url)
}

#[derive(Serialize)]
struct UserRow {
    id: i64,
    email: String,
    name: String,
    last_sign_in: Option<String>,
    status: &'static str,
    disabled: bool,
    is_you: bool,
}

fn row(user: User, you: Option<i64>) -> UserRow {
    let status = if user.disabled_ms.is_some() {
        "Disabled"
    } else if user.has_password {
        "Active"
    } else {
        "Invited"
    };
    UserRow {
        last_sign_in: user.last_sign_in_ms.map(local_time),
        disabled: user.disabled_ms.is_some(),
        is_you: you == Some(user.id),
        status,
        id: user.id,
        email: user.email,
        name: user.name,
    }
}

/// The link for someone to use, shown once, with who it's for.
#[derive(Serialize)]
struct NewLink<'a> {
    name: &'a str,
    url: String,
}

async fn page(
    state: &AppState,
    token: &CsrfToken,
    new_link: Option<&NewLink<'_>>,
    error: Option<&str>,
) -> Response {
    let users = match state.database.list_users().await {
        Ok(users) => users,
        Err(error) => return server_error(&error),
    };
    let you = signed_in_user().map(|user| user.id);
    let rows: Vec<UserRow> = users.into_iter().map(|user| row(user, you)).collect();
    let page = Page::new(state, token, "settings/users.html")
        .with("users", &rows)
        .with("new_link", &new_link)
        .with("error", &error);
    let mut response = if error.is_some() {
        page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render()
    } else {
        page.render()
    };
    if new_link.is_some() {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    page(&state, &token, None, None).await
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let email = form.fields.get("email").map_or("", String::as_str);
    let name = form.fields.get("name").map_or("", String::as_str);
    let (email, name) = match check_new_user(email, name) {
        Ok(checked) => checked,
        Err(error) => return page(&state, &form.token, None, Some(&format!("{error:#}"))).await,
    };
    match state.database.create_user(&email, &name, now_ms()).await {
        Ok(Some((_, link))) => {
            let url = setup_url(&state, &link);
            let new_link = NewLink { name: &name, url };
            page(&state, &form.token, Some(&new_link), None).await
        }
        Ok(None) => {
            let error = "There's already a user with that address.";
            page(&state, &form.token, None, Some(error)).await
        }
        Err(error) => server_error(&error),
    }
}

/// What to tell someone about a change that wasn't made.
pub fn refusal(change: UserChange) -> Option<&'static str> {
    match change {
        UserChange::Done | UserChange::NoSuchUser => None,
        UserChange::LastUser => Some("That would leave nobody able to sign in."),
        UserChange::StillEnabled => Some("Disable this user before deleting them."),
    }
}

async fn after_change(
    state: &AppState,
    token: &CsrfToken,
    change: anyhow::Result<UserChange>,
) -> Response {
    match change.map(refusal) {
        Ok(None) => Redirect::to(USERS_PAGE).into_response(),
        Ok(Some(refused)) => page(state, token, None, Some(refused)).await,
        Err(error) => server_error(&error),
    }
}

fn is_you(id: i64) -> bool {
    signed_in_user().is_some_and(|user| user.id == id)
}

async fn disable(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    if is_you(id) {
        let error = "You can't disable yourself.";
        return page(&state, &form.token, None, Some(error)).await;
    }
    let change = state.database.disable_user(id, now_ms()).await;
    after_change(&state, &form.token, change).await
}

async fn enable(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let change = state.database.enable_user(id).await;
    after_change(&state, &form.token, change).await
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let change = state.database.delete_user(id).await;
    after_change(&state, &form.token, change).await
}

async fn new_link(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let user = match state.database.user(id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Redirect::to(USERS_PAGE).into_response(),
        Err(error) => return server_error(&error),
    };
    match state.database.new_setup_link(id, now_ms()).await {
        Ok(Some(link)) => {
            let url = setup_url(&state, &link);
            let new_link = NewLink {
                name: &user.name,
                url,
            };
            page(&state, &form.token, Some(&new_link), None).await
        }
        Ok(None) => Redirect::to(USERS_PAGE).into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Serialize)]
struct ThemeChoice {
    value: &'static str,
    label: &'static str,
    chosen: bool,
}

fn profile_page(
    state: &AppState,
    token: &CsrfToken,
    user: &User,
    saved: bool,
    error: Option<&str>,
) -> Response {
    let themes: Vec<ThemeChoice> = THEMES
        .iter()
        .map(|(value, label)| ThemeChoice {
            value,
            label,
            chosen: *value == user.theme,
        })
        .collect();
    let page = Page::new(state, token, "profile/show.html")
        .with("person", user)
        .with("themes", &themes)
        .with("zones", &zone_names())
        .with("saved", &saved)
        .with("error", &error);
    if error.is_some() {
        page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render()
    } else {
        page.render()
    }
}

/// Only a person has a profile, and scripts with API keys aren't one.
async fn profile(State(state): State<AppState>, token: CsrfToken) -> Response {
    match signed_in_user() {
        Some(user) => profile_page(&state, &token, &user, false, None),
        None => Redirect::to("/login").into_response(),
    }
}

async fn choose_theme(State(state): State<AppState>, form: CsrfForm) -> Response {
    let Some(user) = signed_in_user() else {
        return Redirect::to("/login").into_response();
    };
    let theme = form.fields.get("theme").map_or("", String::as_str);
    if !is_theme(theme) {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    match state.database.set_theme(user.id, theme).await {
        Ok(_) => Redirect::to(PROFILE_PAGE).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn choose_time_zone(State(state): State<AppState>, form: CsrfForm) -> Response {
    let Some(user) = signed_in_user() else {
        return Redirect::to("/login").into_response();
    };
    let name = form.fields.get("time_zone").map_or("", |name| name.trim());
    let Some(zone) = zone_named(name) else {
        let problem = format!("{name:?} isn't a time zone. Try one like Europe/London.");
        return profile_page(&state, &form.token, &user, false, Some(&problem));
    };
    match state.database.set_time_zone(user.id, zone).await {
        Ok(_) => Redirect::to(PROFILE_PAGE).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: CsrfForm,
) -> Response {
    let Some(user) = signed_in_user() else {
        return Redirect::to("/login").into_response();
    };
    let current = form.fields.get("current").cloned().unwrap_or_default();
    let new = form.fields.get("password").map_or("", String::as_str);
    let confirm = form.fields.get("confirm").map_or("", String::as_str);

    let details = match state.database.sign_in_details(&user.email).await {
        Ok(details) => details,
        Err(error) => return server_error(&error),
    };
    let hash = details.and_then(|(_, hash)| hash);
    let matches = match password_matches(current, hash).await {
        Ok(matches) => matches,
        Err(error) => return server_error(&error),
    };
    let problem = if !matches {
        Some("Your current password isn't right.".to_string())
    } else if new != confirm {
        Some("Those passwords don't match.".to_string())
    } else {
        check_new_password(new)
            .err()
            .map(|error| format!("{error:#}"))
    };
    if let Some(problem) = problem {
        return profile_page(&state, &form.token, &user, false, Some(&problem));
    }

    let hash = match hash_password(new.to_string()).await {
        Ok(hash) => hash,
        Err(error) => return server_error(&error),
    };
    let session = session_token(&headers).unwrap_or_default();
    match state
        .database
        .change_password(user.id, &hash, session)
        .await
    {
        Ok(()) => profile_page(&state, &form.token, &user, true, None),
        Err(error) => server_error(&error),
    }
}
