//! Signing in and out, setting a password from a link, and keeping pages behind
//! a login. Agents and the API prove who they are in their own ways.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use serde::Deserialize;
use tracing::warn;

use super::{CsrfForm, Page, api, request_source, run_as, server_error};
use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::models::{CHALLENGE_LIFETIME_MS, SESSION_LIFETIME_MS, User, check_new_password};
use crate::passwords::{hash_password, password_matches};

const SESSION_COOKIE: &str = "maxnines_session";
const SIGNED_IN_HOME: &str = "/";
/// What a browser holds between a right password and a right code.
const CHALLENGE_COOKIE: &str = "maxnines_challenge";
const CODE_PAGE: &str = "/login/code";
/// Where someone sets up two-factor.
const PROFILE_PAGE: &str = "/profile";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(sign_in_page).post(sign_in))
        .route(CODE_PAGE, get(code_page).post(check_code))
        .route("/logout", post(sign_out))
        .route("/setup/{token}", get(setup_page).post(setup))
}

/// The session token this browser sent, if any.
pub fn session_token(headers: &HeaderMap) -> Option<&str> {
    cookie_named(headers, SESSION_COOKIE)
}

fn cookie_named<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|cookie| cookie.trim().strip_prefix(name)?.strip_prefix('='))
}

async fn session_user(state: &AppState, headers: &HeaderMap) -> anyhow::Result<Option<User>> {
    match session_token(headers) {
        Some(token) => state.database.session_user(token, now_ms()).await,
        None => Ok(None),
    }
}

/// Lets through someone signed in, or a script with an API key, and sends anyone
/// else to sign in. Forms still need a CSRF token, so a key can't submit those.
pub async fn require_login(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    match session_user(&state, request.headers()).await {
        Ok(Some(user)) => {
            // When everyone has to use two-factor, someone without it can only
            // reach their profile, to set it up, and sign out.
            let path = request.uri().path();
            let required = state.require_two_factor.load(Ordering::Relaxed);
            let allowed = path.starts_with(PROFILE_PAGE) || path == "/logout";
            if required && !user.two_factor && !allowed {
                return redirect(&request, PROFILE_PAGE);
            }
            run_as(&state, user, None, request, next).await
        }
        Ok(None) => match api::key_holder(&state, request.headers()).await {
            Ok(Some((owner, via))) => run_as(&state, owner, Some(via), request, next).await,
            Ok(None) => to_sign_in(&request),
            Err(error) => server_error(&error),
        },
        Err(error) => server_error(&error),
    }
}

fn to_sign_in(request: &Request) -> Response {
    let path = request
        .uri()
        .path_and_query()
        .map_or(SIGNED_IN_HOME, |path| path.as_str());
    let query = serde_urlencoded::to_string([("next", path)]).unwrap_or_default();
    redirect(request, &format!("/login?{query}"))
}

/// Sends a browser elsewhere. A page updating itself would swap the other page
/// into the one it's showing, so this asks htmx to leave for it instead.
fn redirect(request: &Request, address: &str) -> Response {
    if request.headers().contains_key("hx-request") {
        let redirect = HeaderValue::from_str(address).ok();
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        if let Some(redirect) = redirect {
            response.headers_mut().insert("hx-redirect", redirect);
        }
        return response;
    }
    Redirect::to(address).into_response()
}

/// Only ever a page on this site, so a link can't send someone elsewhere after
/// signing in. Browsers read `//` and `/\` as the start of another site.
fn safe_next(next: Option<&str>) -> &str {
    next.filter(|next| {
        next.starts_with('/')
            && !next.starts_with("//")
            && !next.starts_with("/\\")
            && !next.chars().any(char::is_control)
    })
    .unwrap_or(SIGNED_IN_HOME)
}

fn session_cookie(state: &AppState, value: String, lifetime_ms: i64) -> Option<HeaderValue> {
    let cookie = Cookie::build((SESSION_COOKIE, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.audience.starts_with("wss://"))
        .max_age(Duration::milliseconds(lifetime_ms));
    HeaderValue::from_str(&cookie.to_string()).ok()
}

/// Signs someone in on this browser and sends them on.
async fn signed_in_response(state: &AppState, user_id: i64, next: &str) -> Response {
    let token = match state.database.start_session(user_id, now_ms()).await {
        Ok(token) => token,
        Err(error) => return server_error(&error),
    };
    let mut response = Redirect::to(next).into_response();
    if let Some(cookie) = session_cookie(state, token, SESSION_LIFETIME_MS) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn challenge_cookie(state: &AppState, value: String, lifetime_ms: i64) -> Option<HeaderValue> {
    let cookie = Cookie::build((CHALLENGE_COOKIE, value))
        .path("/login")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(state.audience.starts_with("wss://"))
        .max_age(Duration::milliseconds(lifetime_ms));
    HeaderValue::from_str(&cookie.to_string()).ok()
}

/// What follows a right password, or a password set from a link: signed in, or for
/// someone with two-factor on, asked for a code first.
async fn after_password(state: &AppState, user: &User, next: &str) -> Response {
    if !user.two_factor {
        return signed_in_response(state, user.id, next).await;
    }
    let token = match state
        .database
        .start_sign_in_challenge(user.id, now_ms())
        .await
    {
        Ok(token) => token,
        Err(error) => return server_error(&error),
    };
    let query = serde_urlencoded::to_string([("next", next)]).unwrap_or_default();
    let mut response = Redirect::to(&format!("{CODE_PAGE}?{query}")).into_response();
    if let Some(cookie) = challenge_cookie(state, token, CHALLENGE_LIFETIME_MS) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// Who gave the right password and still owes a code, with their token.
async fn challenged<'a>(
    state: &AppState,
    headers: &'a HeaderMap,
) -> anyhow::Result<Option<(User, &'a str)>> {
    let Some(token) = cookie_named(headers, CHALLENGE_COOKIE) else {
        return Ok(None);
    };
    let user = state
        .database
        .sign_in_challenge_user(token, now_ms())
        .await?;
    Ok(user.map(|user| (user, token)))
}

fn code_form(
    state: &AppState,
    token: &CsrfToken,
    next: &str,
    problem: Option<(StatusCode, &str)>,
) -> Response {
    let page = Page::new(state, token, "sessions/code.html")
        .with("next", next)
        .with("error", &problem.map(|(_, error)| error))
        .with_status(problem.map_or(StatusCode::OK, |(status, _)| status));
    not_stored(page.render())
}

async fn code_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    token: CsrfToken,
    Query(query): Query<SignInQuery>,
) -> Response {
    match challenged(&state, &headers).await {
        Ok(Some(_)) => code_form(&state, &token, safe_next(query.next.as_deref()), None),
        // It ran out, or they never gave a password.
        Ok(None) => Redirect::to("/login").into_response(),
        Err(error) => server_error(&error),
    }
}

async fn check_code(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    form: CsrfForm,
) -> Response {
    let next = safe_next(form.fields.get("next").map(String::as_str)).to_string();
    let (user, challenge) = match challenged(&state, &headers).await {
        Ok(Some(found)) => found,
        Ok(None) => return Redirect::to("/login").into_response(),
        Err(error) => return server_error(&error),
    };
    // Guesses at a code are limited as guesses at a password are.
    let source = request_source(peer, &headers, &state.trusted_proxies);
    if !state.sign_ins.allow(source, &user.email) {
        warn!(%source, "too many sign in attempts");
        let problem = (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a minute and try again.",
        );
        return code_form(&state, &form.token, &next, Some(problem));
    }
    let code = form.fields.get("code").map_or("", String::as_str);
    let accepted = state
        .database
        .accept_two_factor_code(user.id, code, now_ms());
    match accepted.await {
        Ok(true) => {}
        Ok(false) => {
            let failed = state
                .database
                .record_failed_sign_in(&user.email, Some(&user));
            if let Err(error) = failed.await {
                return server_error(&error);
            }
            let problem = (StatusCode::UNAUTHORIZED, "That code isn't right.");
            return code_form(&state, &form.token, &next, Some(problem));
        }
        Err(error) => return server_error(&error),
    }
    if let Err(error) = state.database.end_sign_in_challenge(challenge).await {
        return server_error(&error);
    }
    let mut response = signed_in_response(&state, user.id, &next).await;
    if let Some(cookie) = challenge_cookie(&state, String::new(), 0) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

#[derive(Deserialize)]
struct SignInQuery {
    next: Option<String>,
}

async fn sign_in_form(
    state: &AppState,
    token: &CsrfToken,
    email: &str,
    next: &str,
    problem: Option<(StatusCode, &str)>,
) -> Response {
    // Saying so gives nothing away, as a server with no users has nothing to protect.
    let no_users = matches!(state.database.user_count().await, Ok(0));
    Page::new(state, token, "sessions/sign_in.html")
        .with("email", email)
        .with("next", next)
        .with("no_users", &no_users)
        .with("error", &problem.map(|(_, error)| error))
        .with_status(problem.map_or(StatusCode::OK, |(status, _)| status))
        .render()
}

async fn sign_in_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    token: CsrfToken,
    Query(query): Query<SignInQuery>,
) -> Response {
    let next = safe_next(query.next.as_deref());
    if matches!(session_user(&state, &headers).await, Ok(Some(_))) {
        return Redirect::to(next).into_response();
    }
    sign_in_form(&state, &token, "", next, None).await
}

async fn sign_in(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    form: CsrfForm,
) -> Response {
    let email = form.fields.get("email").map_or("", |email| email.trim());
    let password = form.fields.get("password").cloned().unwrap_or_default();
    let next = safe_next(form.fields.get("next").map(String::as_str)).to_string();

    let source = request_source(peer, &headers, &state.trusted_proxies);
    if !state.sign_ins.allow(source, &email.to_lowercase()) {
        warn!(%source, "too many sign in attempts");
        let problem = (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a minute and try again.",
        );
        return sign_in_form(&state, &form.token, email, &next, Some(problem)).await;
    }

    let details = match state.database.sign_in_details(email).await {
        Ok(details) => details,
        Err(error) => return server_error(&error),
    };
    let (user, hash) = details.map_or((None, None), |(user, hash)| (Some(user), hash));
    let matches = match password_matches(password, hash).await {
        Ok(matches) => matches,
        Err(error) => return server_error(&error),
    };
    if matches && let Some(user) = &user {
        return after_password(&state, user, &next).await;
    }
    if let Err(error) = state
        .database
        .record_failed_sign_in(email, user.as_ref())
        .await
    {
        return server_error(&error);
    }
    // The same answer either way, so it doesn't show which addresses exist.
    let problem = (
        StatusCode::UNAUTHORIZED,
        "That email or password isn't right.",
    );
    sign_in_form(&state, &form.token, email, &next, Some(problem)).await
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap, _form: CsrfForm) -> Response {
    if let Some(token) = session_token(&headers)
        && let Err(error) = state.database.end_session(token).await
    {
        return server_error(&error);
    }
    let mut response = Redirect::to("/login").into_response();
    if let Some(cookie) = session_cookie(&state, String::new(), 0) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// The link is the secret here, so this page is never stored.
fn not_stored(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn setup_form(
    state: &AppState,
    token: &CsrfToken,
    link: &str,
    user: Option<&User>,
    error: Option<&str>,
) -> Response {
    let page = Page::new(state, token, "sessions/setup.html")
        .with("link", link)
        .with("person", &user)
        .with("error", &error);
    let status = match (user, error) {
        (None, _) => StatusCode::NOT_FOUND,
        (Some(_), Some(_)) => StatusCode::UNPROCESSABLE_ENTITY,
        (Some(_), None) => StatusCode::OK,
    };
    not_stored(page.with_status(status).render())
}

async fn setup_page(
    State(state): State<AppState>,
    Path(link): Path<String>,
    token: CsrfToken,
) -> Response {
    match state.database.setup_link_user(&link, now_ms()).await {
        Ok(user) => setup_form(&state, &token, &link, user.as_ref(), None),
        Err(error) => server_error(&error),
    }
}

async fn setup(
    State(state): State<AppState>,
    Path(link): Path<String>,
    form: CsrfForm,
) -> Response {
    let user = match state.database.setup_link_user(&link, now_ms()).await {
        Ok(Some(user)) => user,
        Ok(None) => return setup_form(&state, &form.token, &link, None, None),
        Err(error) => return server_error(&error),
    };
    let password = form.fields.get("password").map_or("", String::as_str);
    let confirm = form.fields.get("confirm").map_or("", String::as_str);
    let problem = if password == confirm {
        check_new_password(password).err().map(|e| format!("{e:#}"))
    } else {
        Some("Those passwords don't match.".to_string())
    };
    if let Some(problem) = problem {
        return setup_form(&state, &form.token, &link, Some(&user), Some(&problem));
    }

    let hash = match hash_password(password.to_string()).await {
        Ok(hash) => hash,
        Err(error) => return server_error(&error),
    };
    let saved = state
        .database
        .use_setup_link(user.id, &link, &hash, now_ms())
        .await;
    match saved {
        Ok(true) => after_password(&state, &user, SIGNED_IN_HOME).await,
        Ok(false) => setup_form(&state, &form.token, &link, None, None),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_in_only_ever_leads_to_this_site() {
        assert_eq!(safe_next(Some("/hosts?view=table")), "/hosts?view=table");
        for outside in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "evil.example",
            "/\nSet-Cookie: x",
            "",
        ] {
            assert_eq!(safe_next(Some(outside)), "/", "{outside:?}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn only_the_session_cookie_counts() {
        let mut headers = HeaderMap::new();
        let value = "a=1; maxnines_session_old=2; maxnines_session=abc; z=3";
        headers.insert(header::COOKIE, HeaderValue::from_static(value));

        assert_eq!(session_token(&headers), Some("abc"));
        assert_eq!(session_token(&HeaderMap::new()), None);
    }
}
