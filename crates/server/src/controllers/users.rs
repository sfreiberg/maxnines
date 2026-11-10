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
use std::sync::atomic::Ordering;

use crate::app_state::AppState;
use crate::audit;
use crate::metrics::now_ms;
use crate::models::{THEMES, User, UserChange, check_new_password, check_new_user, is_theme};
use crate::passwords::{hash_password, password_matches};
use crate::roles::Role;
use crate::times::{zone_named, zone_names};
use crate::two_factor;

const USERS_PAGE: &str = "/settings/users";
const PROFILE_PAGE: &str = "/profile";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(USERS_PAGE, get(index).post(create))
        .route("/settings/users/{id}/disable", post(disable))
        .route("/settings/users/{id}/enable", post(enable))
        .route("/settings/users/{id}/delete", post(delete))
        .route("/settings/users/{id}/role", post(choose_role))
        .route("/settings/users/{id}/setup-link", post(new_link))
        .route(PROFILE_PAGE, get(profile))
        .route("/profile/theme", post(choose_theme))
        .route("/profile/time-zone", post(choose_time_zone))
        .route("/profile/password", post(change_password))
        .route("/profile/two-factor/start", post(start_two_factor))
        .route("/profile/two-factor/qr.png", get(two_factor_qr))
        .route("/profile/two-factor/confirm", post(confirm_two_factor))
        .route("/profile/two-factor/{change}", post(change_two_factor))
        .route("/settings/users/two-factor", post(require_two_factor))
        .route(
            "/settings/users/{id}/two-factor/reset",
            post(reset_two_factor),
        )
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
    role: &'static str,
    two_factor: bool,
}

/// A role to choose, with what it adds.
#[derive(Serialize)]
pub struct RoleChoice {
    value: &'static str,
    label: &'static str,
    adds: &'static str,
}

pub fn role_choices(up_to: Role) -> Vec<RoleChoice> {
    Role::ALL
        .into_iter()
        .filter(|role| *role <= up_to)
        .map(|role| RoleChoice {
            value: role.as_str(),
            label: role.label(),
            adds: role.describe(),
        })
        .collect()
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
        role: user.role.as_str(),
        two_factor: user.two_factor,
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
        .with("roles", &role_choices(Role::Admin))
        .with(
            "two_factor_required",
            &state.require_two_factor.load(Ordering::Relaxed),
        )
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
    let role = form.fields.get("role").map_or("", String::as_str);
    let role = match Role::parse(role) {
        Ok(role) => role,
        Err(error) => return page(&state, &form.token, None, Some(&format!("{error:#}"))).await,
    };
    match state
        .database
        .create_user(&email, &name, role, now_ms())
        .await
    {
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

async fn choose_role(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    let role = form.fields.get("role").map_or("", String::as_str);
    let change = match Role::parse(role) {
        Ok(role) => state.database.set_role(id, role).await,
        Err(error) => return page(&state, &form.token, None, Some(&format!("{error:#}"))).await,
    };
    after_change(&state, &form.token, change).await
}

/// What to tell someone about a change that wasn't made.
pub fn refusal(change: UserChange) -> Option<&'static str> {
    match change {
        UserChange::Done | UserChange::NoSuchUser => None,
        UserChange::LastAdmin => Some("That would leave no admin able to sign in."),
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

/// Where someone is with two-factor, for their profile.
#[derive(Serialize)]
struct TwoFactorView {
    on: bool,
    /// The secret being set up, as typed into an app that can't scan the QR code.
    pending_secret: Option<String>,
    codes_left: u64,
    /// Whether an admin has said everyone must use it.
    required: bool,
}

/// What to show above the profile after a change.
#[derive(Default)]
struct ProfileNotes<'a> {
    password_changed: bool,
    error: Option<&'a str>,
    /// Recovery codes, the one time they're shown.
    new_codes: Option<&'a [String]>,
}

async fn profile_page(
    state: &AppState,
    token: &CsrfToken,
    user: &User,
    notes: ProfileNotes<'_>,
) -> Response {
    // As they are now, as this request may have just changed them.
    let loaded = async {
        let user = state.database.user(user.id).await?;
        let secret = state
            .database
            .pending_two_factor_secret(user_id(&user))
            .await?;
        let left = state.database.recovery_codes_left(user_id(&user)).await?;
        anyhow::Ok((user, secret, left))
    };
    let (user, secret, codes_left) = match loaded.await {
        Ok((Some(user), secret, left)) => (user, secret, left),
        Ok((None, ..)) => return Redirect::to("/login").into_response(),
        Err(error) => return server_error(&error),
    };
    let two_factor = TwoFactorView {
        on: user.two_factor,
        pending_secret: secret.as_deref().map(two_factor::grouped),
        codes_left,
        required: state.require_two_factor.load(Ordering::Relaxed),
    };
    let themes: Vec<ThemeChoice> = THEMES
        .iter()
        .map(|(value, label)| ThemeChoice {
            value,
            label,
            chosen: *value == user.theme,
        })
        .collect();
    let page = Page::new(state, token, "profile/show.html")
        .with("person", &user)
        .with("themes", &themes)
        .with("zones", &zone_names())
        .with("saved", &notes.password_changed)
        .with("two_factor", &two_factor)
        .with("new_codes", &notes.new_codes)
        .with("error", &notes.error);
    let mut response = if notes.error.is_some() {
        page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render()
    } else {
        page.render()
    };
    // A secret or recovery codes may be on it.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn user_id(user: &Option<User>) -> i64 {
    user.as_ref().map_or(0, |user| user.id)
}

fn with_error(problem: &str) -> ProfileNotes<'_> {
    ProfileNotes {
        error: Some(problem),
        ..ProfileNotes::default()
    }
}

/// Whether this is their current password.
async fn password_is(state: &AppState, user: &User, typed: String) -> anyhow::Result<bool> {
    let details = state.database.sign_in_details(&user.email).await?;
    password_matches(typed, details.and_then(|(_, hash)| hash)).await
}

async fn start_two_factor(State(state): State<AppState>, form: CsrfForm) -> Response {
    let Some(user) = signed_in_user() else {
        return Redirect::to("/login").into_response();
    };
    match state.database.start_two_factor(user.id).await {
        Ok(_) => profile_page(&state, &form.token, &user, ProfileNotes::default()).await,
        Err(error) => server_error(&error),
    }
}

/// The QR code for the secret being set up. Only for the person in their own
/// browser: a key acting as them never sees it.
async fn two_factor_qr(State(state): State<AppState>) -> Response {
    let user = signed_in_user().filter(|_| audit::current().via.is_none());
    let Some(user) = user else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let secret = match state.database.pending_two_factor_secret(user.id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    match two_factor::qr_png(&secret, &user.email) {
        Ok(png) => {
            let headers = [
                (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ];
            (headers, png).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn confirm_two_factor(State(state): State<AppState>, form: CsrfForm) -> Response {
    let Some(user) = signed_in_user() else {
        return Redirect::to("/login").into_response();
    };
    let code = form.fields.get("code").map_or("", String::as_str);
    match state
        .database
        .confirm_two_factor(user.id, code, now_ms())
        .await
    {
        Ok(Some(codes)) => {
            let notes = ProfileNotes {
                new_codes: Some(&codes),
                ..ProfileNotes::default()
            };
            profile_page(&state, &form.token, &user, notes).await
        }
        Ok(None) => {
            let problem = "That code isn't right. Check the app shows a code for MaxNines, and \
                           that this machine's clock and your phone's are right.";
            profile_page(&state, &form.token, &user, with_error(problem)).await
        }
        Err(error) => server_error(&error),
    }
}

/// Turning it off, or replacing the recovery codes, takes their password again, so
/// a browser left open isn't enough.
async fn change_two_factor(
    State(state): State<AppState>,
    Path(change): Path<String>,
    form: CsrfForm,
) -> Response {
    let Some(user) = signed_in_user() else {
        return Redirect::to("/login").into_response();
    };
    if change != "codes" && change != "off" {
        return StatusCode::NOT_FOUND.into_response();
    }
    if change == "off" && state.require_two_factor.load(Ordering::Relaxed) {
        let problem = "An admin has made two-factor required for everyone.";
        return profile_page(&state, &form.token, &user, with_error(problem)).await;
    }
    let typed = form.fields.get("current").cloned().unwrap_or_default();
    match password_is(&state, &user, typed).await {
        Ok(true) => {}
        Ok(false) => {
            let problem = "Your current password isn't right.";
            return profile_page(&state, &form.token, &user, with_error(problem)).await;
        }
        Err(error) => return server_error(&error),
    }
    if change == "codes" {
        return match state.database.new_recovery_codes(user.id).await {
            Ok(codes) => {
                let notes = ProfileNotes {
                    new_codes: codes.as_deref(),
                    ..ProfileNotes::default()
                };
                profile_page(&state, &form.token, &user, notes).await
            }
            Err(error) => server_error(&error),
        };
    }
    match state.database.turn_off_two_factor(user.id).await {
        Ok(_) => Redirect::to(PROFILE_PAGE).into_response(),
        Err(error) => server_error(&error),
    }
}

/// For someone who's lost their phone and their recovery codes.
async fn reset_two_factor(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    _form: CsrfForm,
) -> Response {
    match state.database.turn_off_two_factor(id).await {
        Ok(_) => Redirect::to(USERS_PAGE).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Makes everyone set up two-factor, or stops asking. Whoever turns it on has to
/// have it themselves, so they aren't the first one it keeps out.
pub async fn require_for_everyone(
    state: &AppState,
    required: bool,
) -> anyhow::Result<Result<(), &'static str>> {
    if required && !signed_in_user().is_some_and(|user| user.two_factor) {
        return Ok(Err("Set up two-factor on your own profile first."));
    }
    state.database.require_two_factor(required).await?;
    state.require_two_factor.store(required, Ordering::Relaxed);
    Ok(Ok(()))
}

async fn require_two_factor(State(state): State<AppState>, form: CsrfForm) -> Response {
    let required = form
        .fields
        .get("required")
        .is_some_and(|value| value == "true");
    match require_for_everyone(&state, required).await {
        Ok(Ok(())) => Redirect::to(USERS_PAGE).into_response(),
        Ok(Err(problem)) => page(&state, &form.token, None, Some(problem)).await,
        Err(error) => server_error(&error),
    }
}

/// Only a person has a profile, and scripts with API keys aren't one.
async fn profile(State(state): State<AppState>, token: CsrfToken) -> Response {
    match signed_in_user() {
        Some(user) => profile_page(&state, &token, &user, ProfileNotes::default()).await,
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
        return profile_page(&state, &form.token, &user, with_error(&problem)).await;
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
        return profile_page(&state, &form.token, &user, with_error(&problem)).await;
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
        Ok(()) => {
            let notes = ProfileNotes {
                password_changed: true,
                ..ProfileNotes::default()
            };
            profile_page(&state, &form.token, &user, notes).await
        }
        Err(error) => server_error(&error),
    }
}
