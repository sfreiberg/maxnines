//! Signing in apps through the browser: the page where someone approves an app, the
//! endpoints apps swap approvals and refresh tokens at, and the page listing what's
//! signed in. See [`crate::app_sign_ins`] for how it fits together.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_csrf::CsrfToken;
use serde::Serialize;
use serde_json::{Value, json};

use super::users::role_choices;
use super::{CsrfForm, Page, local_date, local_time, server_error, signed_in_user};
use crate::app_sign_ins::{
    ACCESS_LIFETIME_MS, AppClient, Approval, DEVICE_INTERVAL_SECS, DevicePoll, PENDING_LIFETIME_MS,
    REFRESH_LIFETIME_MS, check_challenge, check_device, check_redirect, client,
};
use crate::app_state::AppState;
use crate::audit::{self, Actor};
use crate::metrics::now_ms;
use crate::models::{AppSignIn, AppTokens, Refreshed};
use crate::roles::Role;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The pages, which need someone signed in.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oauth/authorize", get(authorize_page).post(authorize))
        .route("/device", get(device_page).post(device_lookup))
        .route("/device/decide", post(device_decide))
        .route("/settings/apps", get(index))
        .route("/settings/apps/{id}/revoke", post(revoke))
}

/// What apps call, with no one signed in: they prove themselves with what they hold.
pub fn app_routes() -> Router<AppState> {
    Router::new()
        .route("/oauth/token", post(token))
        .route("/oauth/device", post(start_device))
        .route("/oauth/revoke", post(revoke_token))
}

// The approval page.

type Fields = BTreeMap<String, String>;

fn field<'a>(fields: &'a Fields, name: &str) -> &'a str {
    fields.get(name).map_or("", String::as_str)
}

/// The role an app is asked for, if it named one it could have.
fn asked_role(fields: &Fields) -> Result<Option<Role>, ()> {
    match field(fields, "role") {
        "" => Ok(None),
        text => Role::parse(text).map(Some).map_err(|_| ()),
    }
}

/// What the approval page offers: the role the app asked for, or theirs, and never
/// more than theirs.
fn role_offer(page: Page<'_>, asked: Option<Role>) -> Page<'_> {
    let yours = signed_in_user().map_or(Role::Viewer, |user| user.role);
    let chosen = asked.map_or(yours, |asked| asked.min(yours));
    page.with("roles", &role_choices(yours))
        .with("chosen_role", chosen.as_str())
}

/// Where the browser is sent back to with an answer.
fn back_to(redirect_uri: &str, answer: &[(&str, &str)]) -> Response {
    let query = serde_urlencoded::to_string(answer).unwrap_or_default();
    let joiner = if redirect_uri.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{redirect_uri}{joiner}{query}")).into_response()
}

fn refusal_page(state: &AppState, token: &CsrfToken, message: &str) -> Response {
    Page::new(state, token, "app_sign_ins/refused.html")
        .with("message", message)
        .with_status(StatusCode::BAD_REQUEST)
        .render()
}

/// The request checked: the app, and where it can be sent back to. Anything wrong
/// before that's known can only be said on the page, never sent to an address that
/// might not be the app's.
struct Asked {
    client: AppClient,
    redirect_uri: String,
    origin: String,
    state: String,
    challenge: String,
    device: String,
    role: Option<Role>,
}

enum Checked {
    Asked(Asked),
    /// Said on the page.
    Refused(&'static str),
    /// Sent back to the app as an OAuth error.
    SendBack(String, String, &'static str),
}

fn check_ask(fields: &Fields) -> Checked {
    let Some(client) = client(field(fields, "client_id")) else {
        return Checked::Refused("That isn't an app MaxNines knows, so it can't be signed in.");
    };
    let redirect_uri = field(fields, "redirect_uri").to_string();
    let Ok(origin) = check_redirect(&redirect_uri) else {
        return Checked::Refused(
            "The app asked to be answered somewhere other than this computer, so it can't be \
             signed in this way.",
        );
    };
    let state = field(fields, "state").to_string();
    if field(fields, "response_type") != "code" {
        return Checked::SendBack(redirect_uri, state, "unsupported_response_type");
    }
    let challenge = field(fields, "code_challenge");
    let method = field(fields, "code_challenge_method");
    let (Ok(()), Ok(device), Ok(role)) = (
        check_challenge(challenge, method),
        check_device(field(fields, "device")),
        asked_role(fields),
    ) else {
        return Checked::SendBack(redirect_uri, state, "invalid_request");
    };
    Checked::Asked(Asked {
        client,
        redirect_uri,
        origin,
        state,
        challenge: challenge.to_string(),
        device,
        role,
    })
}

async fn authorize_page(
    State(state): State<AppState>,
    token: CsrfToken,
    Query(fields): Query<Fields>,
) -> Response {
    let asked = match check_ask(&fields) {
        Checked::Asked(asked) => asked,
        Checked::Refused(message) => return refusal_page(&state, &token, message),
        Checked::SendBack(uri, app_state, error) => {
            return back_to(&uri, &[("error", error), ("state", &app_state)]);
        }
    };
    let page = Page::new(&state, &token, "app_sign_ins/approve.html")
        .with("action", "/oauth/authorize")
        .with("app", asked.client.name)
        .with("device", &asked.device)
        .with("email", &signed_in_user().map(|user| user.email.clone()))
        .with(
            "hidden",
            &hidden(&[
                ("response_type", "code"),
                ("client_id", asked.client.id),
                ("redirect_uri", &asked.redirect_uri),
                ("state", &asked.state),
                ("code_challenge", &asked.challenge),
                ("code_challenge_method", "S256"),
                ("device", &asked.device),
            ]),
        );
    let mut response = role_offer(page, asked.role).render();
    // The answer goes back to the app on this computer, which the page's policy has to
    // let the form lead to.
    let policy = super::CONTENT_SECURITY_POLICY.replace(
        "form-action 'self'",
        &format!("form-action 'self' {}", asked.origin),
    );
    if let Ok(policy) = HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    response
}

/// A field the approval form carries through unchanged.
#[derive(Serialize)]
struct Hidden {
    name: &'static str,
    value: String,
}

fn hidden(fields: &[(&'static str, &str)]) -> Vec<Hidden> {
    fields
        .iter()
        .map(|(name, value)| Hidden {
            name,
            value: (*value).to_string(),
        })
        .collect()
}

/// The role chosen on the page, if it's one they may give.
fn chosen_role(fields: &Fields) -> Option<Role> {
    let yours = signed_in_user()?.role;
    Role::parse(field(fields, "chosen_role"))
        .ok()
        .filter(|role| *role <= yours)
}

async fn authorize(State(state): State<AppState>, form: CsrfForm) -> Response {
    let asked = match check_ask(&form.fields) {
        Checked::Asked(asked) => asked,
        Checked::Refused(message) => return refusal_page(&state, &form.token, message),
        Checked::SendBack(uri, app_state, error) => {
            return back_to(&uri, &[("error", error), ("state", &app_state)]);
        }
    };
    let deny = || {
        back_to(
            &asked.redirect_uri,
            &[("error", "access_denied"), ("state", &asked.state)],
        )
    };
    if field(&form.fields, "decision") != "allow" {
        return deny();
    }
    let (Some(user), Some(role)) = (signed_in_user(), chosen_role(&form.fields)) else {
        return deny();
    };
    let approval = Approval {
        user_id: user.id,
        client: asked.client,
        device: asked.device.clone(),
        role,
    };
    match state.pending_sign_ins.approve_code(
        approval,
        &asked.redirect_uri,
        &asked.challenge,
        now_ms(),
    ) {
        Ok(code) => back_to(
            &asked.redirect_uri,
            &[("code", &code), ("state", &asked.state)],
        ),
        Err(error) => server_error(&error),
    }
}

// The device pages: someone types the code a device shows them.

#[derive(serde::Deserialize)]
struct CodeQuery {
    #[serde(default)]
    code: String,
}

async fn device_page(
    State(state): State<AppState>,
    token: CsrfToken,
    Query(query): Query<CodeQuery>,
) -> Response {
    if query.code.is_empty() {
        return Page::new(&state, &token, "app_sign_ins/device.html").render();
    }
    device_approval(&state, &token, &query.code)
}

async fn device_lookup(State(state): State<AppState>, form: CsrfForm) -> Response {
    device_approval(&state, &form.token, field(&form.fields, "user_code"))
}

fn device_approval(state: &AppState, token: &CsrfToken, typed: &str) -> Response {
    let Some(asking) = state.pending_sign_ins.device_asking(typed, now_ms()) else {
        return Page::new(state, token, "app_sign_ins/device.html")
            .with("code", typed)
            .with(
                "error",
                "No app is waiting with that code. Codes last 10 minutes, so it may have \
                 run out: start signing in again.",
            )
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .render();
    };
    let page = Page::new(state, token, "app_sign_ins/approve.html")
        .with("action", "/device/decide")
        .with("app", asking.client.name)
        .with("device", &asking.device)
        .with("user_code", &asking.user_code)
        .with("email", &signed_in_user().map(|user| user.email.clone()))
        .with("hidden", &hidden(&[("user_code", &asking.user_code)]));
    role_offer(page, asking.role).render()
}

async fn device_decide(State(state): State<AppState>, form: CsrfForm) -> Response {
    let user_code = field(&form.fields, "user_code");
    let Some(asking) = state.pending_sign_ins.device_asking(user_code, now_ms()) else {
        return device_approval(&state, &form.token, user_code);
    };
    let allowed = field(&form.fields, "decision") == "allow";
    let approver = match (signed_in_user(), chosen_role(&form.fields)) {
        (Some(user), Some(role)) if allowed => Some((user.id, role)),
        _ => None,
    };
    let approved = approver.is_some();
    if !state
        .pending_sign_ins
        .decide_device(user_code, approver, now_ms())
    {
        return device_approval(&state, &form.token, user_code);
    }
    Page::new(&state, &form.token, "app_sign_ins/done.html")
        .with("app", asking.client.name)
        .with("device", &asking.device)
        .with("approved", &approved)
        .render()
}

// What apps call.

/// An OAuth error, as RFC 6749 words them.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = Json(json!({ "error": error, "error_description": description }));
    no_store((status, body).into_response())
}

/// Tokens must never be kept by anything in between.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn issued(sign_in: &AppSignIn, tokens: &AppTokens) -> Response {
    let body = Json(json!({
        "access_token": tokens.access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_LIFETIME_MS / 1000,
        "refresh_token": tokens.refresh_token,
        "refresh_token_expires_in": REFRESH_LIFETIME_MS / 1000,
        "role": sign_in.role,
        "user": sign_in.owner,
        "sign_in_id": sign_in.id,
    }));
    no_store(body.into_response())
}

/// Signs in the app someone approved, recorded as theirs.
async fn sign_in_approved(state: &AppState, approval: Approval) -> Response {
    let Ok(Some(user)) = state.database.user(approval.user_id).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "That person can't sign in",
        );
    };
    let actor = Actor::Person {
        id: user.id,
        email: user.email.clone(),
    };
    let created = audit::acting_as(
        actor,
        None,
        state.database.create_app_sign_in(
            approval.user_id,
            approval.client.id,
            &approval.device,
            approval.role.min(user.role),
            now_ms(),
        ),
    )
    .await;
    match created {
        Ok((sign_in, tokens)) => issued(&sign_in, &tokens),
        Err(error) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            &format!("{error:#}"),
        ),
    }
}

async fn token(State(state): State<AppState>, Form(fields): Form<Fields>) -> Response {
    let client_id = field(&fields, "client_id");
    if client(client_id).is_none() {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "That isn't an app MaxNines knows",
        );
    }
    match field(&fields, "grant_type") {
        "authorization_code" => {
            let approval = state.pending_sign_ins.take_code(
                field(&fields, "code"),
                client_id,
                field(&fields, "redirect_uri"),
                field(&fields, "code_verifier"),
                now_ms(),
            );
            match approval {
                Some(approval) => sign_in_approved(&state, approval).await,
                None => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "That code is wrong, used, or out of date, or the verifier doesn't match",
                ),
            }
        }
        DEVICE_CODE_GRANT => {
            let poll = state.pending_sign_ins.poll_device(
                field(&fields, "device_code"),
                client_id,
                now_ms(),
            );
            let waiting = |error: &str, description: &str| {
                oauth_error(StatusCode::BAD_REQUEST, error, description)
            };
            match poll {
                DevicePoll::Allowed(approval) => sign_in_approved(&state, approval).await,
                DevicePoll::Pending => waiting("authorization_pending", "Not approved yet"),
                DevicePoll::SlowDown => waiting("slow_down", "Asking too often"),
                DevicePoll::Denied => waiting("access_denied", "It was turned down"),
                DevicePoll::Expired => waiting("expired_token", "Start signing in again"),
            }
        }
        "refresh_token" => {
            let refreshed = audit::acting_as(
                Actor::MaxNines,
                None,
                state.database.refresh_app_sign_in(
                    field(&fields, "refresh_token"),
                    client_id,
                    now_ms(),
                ),
            )
            .await;
            match refreshed {
                Ok(Refreshed::Issued(sign_in, tokens)) => issued(&sign_in, &tokens),
                Ok(Refreshed::Refused) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "That refresh token doesn't work any more: sign in again",
                ),
                Ok(Refreshed::Reused) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "That refresh token was already used, so the sign in has been revoked: sign in again",
                ),
                Err(error) => server_error(&error),
            }
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Use authorization_code, refresh_token or the device code grant",
        ),
    }
}

async fn start_device(State(state): State<AppState>, Form(fields): Form<Fields>) -> Response {
    let Some(client) = client(field(&fields, "client_id")) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "That isn't an app MaxNines knows",
        );
    };
    let (Ok(device), Ok(role)) = (check_device(field(&fields, "device")), asked_role(&fields))
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The device name or role isn't one that works",
        );
    };
    let started = match state
        .pending_sign_ins
        .start_device(client, &device, role, now_ms())
    {
        Ok(started) => started,
        Err(error) => return server_error(&error),
    };
    let page = format!("{}/device", state.web_url.trim_end_matches('/'));
    let body: Value = json!({
        "device_code": started.device_code,
        "user_code": started.user_code,
        "verification_uri": page,
        "verification_uri_complete": format!("{page}?code={}", started.user_code),
        "expires_in": PENDING_LIFETIME_MS / 1000,
        "interval": DEVICE_INTERVAL_SECS,
    });
    no_store(Json(body).into_response())
}

/// RFC 7009: signs out whichever app holds the token. It always says it worked, so
/// it can't be used to find out which tokens are real.
async fn revoke_token(State(state): State<AppState>, Form(fields): Form<Fields>) -> Response {
    let client_id = field(&fields, "client_id");
    if client(client_id).is_none() {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "That isn't an app MaxNines knows",
        );
    }
    let revoked = audit::acting_as(
        Actor::MaxNines,
        None,
        state
            .database
            .revoke_app_token(field(&fields, "token"), client_id, now_ms()),
    )
    .await;
    match revoked {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => server_error(&error),
    }
}

// The page listing what's signed in.

/// The apps whoever's signed in may see and revoke: their own, or for an admin,
/// everyone's.
pub async fn visible_sign_ins(state: &AppState) -> anyhow::Result<Vec<AppSignIn>> {
    let Some(viewer) = signed_in_user() else {
        return Ok(Vec::new());
    };
    let mut sign_ins = state.database.list_app_sign_ins().await?;
    if viewer.role < Role::Admin {
        sign_ins.retain(|sign_in| sign_in.user_id == viewer.id);
    }
    Ok(sign_ins)
}

/// Revokes a sign in if it's one they may. Returns false for any other, as if it
/// weren't there.
pub async fn revoke_if_allowed(state: &AppState, id: i64) -> anyhow::Result<bool> {
    if !visible_sign_ins(state)
        .await?
        .iter()
        .any(|sign_in| sign_in.id == id)
    {
        return Ok(false);
    }
    state.database.revoke_app_sign_in(id, now_ms()).await
}

#[derive(Serialize)]
struct SignInRow {
    id: i64,
    title: String,
    owner: String,
    role: &'static str,
    created: String,
    created_at: String,
    last_used: Option<String>,
    last_used_at: Option<String>,
    expires: String,
    status: &'static str,
    active: bool,
}

fn row(sign_in: AppSignIn, now_ms: i64) -> SignInRow {
    let active = sign_in.is_active(now_ms);
    let status = if sign_in.revoked_ms.is_some() {
        "Revoked"
    } else if active {
        "Signed in"
    } else {
        "Expired"
    };
    let ago = |ms: i64| {
        let (then, now) = (u64::try_from(ms).ok()?, u64::try_from(now_ms).ok()?);
        Some(crate::times::ago(then, now))
    };
    SignInRow {
        id: sign_in.id,
        title: sign_in.title(),
        role: sign_in.role.label(),
        created: local_date(sign_in.created_ms),
        created_at: local_time(sign_in.created_ms),
        last_used: sign_in.last_used_ms.and_then(ago),
        last_used_at: sign_in.last_used_ms.map(local_time),
        expires: local_date(sign_in.expires_ms),
        status,
        active,
        owner: sign_in.owner,
    }
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let sign_ins = match visible_sign_ins(&state).await {
        Ok(sign_ins) => sign_ins,
        Err(error) => return server_error(&error),
    };
    let now = now_ms();
    let rows: Vec<SignInRow> = sign_ins
        .into_iter()
        .map(|sign_in| row(sign_in, now))
        .collect();
    let sees_all = signed_in_user().is_some_and(|user| user.role >= Role::Admin);
    Page::new(&state, &token, "settings/apps.html")
        .with("sign_ins", &rows)
        .with("sees_all", &sees_all)
        .render()
}

async fn revoke(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match revoke_if_allowed(&state, id).await {
        Ok(true) => (form.token, Redirect::to("/settings/apps")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
