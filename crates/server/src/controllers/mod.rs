//! Routes and request handling. Pages live in `overview`, `agents`, `alerts`,
//! `alert_rules`, `metrics`, `notification_channels`, `remote_checks`, `rules`,
//! `settings`, `audit_log` and `docs`, the token protected API in `api`, agent connections in
//! `agent_socket`, signing in in `sessions`, people in `users`, and how an open page
//! learns of a new build in `update_notice`.

pub mod agent_socket;
mod agents;
mod alert_rules;
mod alerts;
mod annotations;
pub mod api;
mod api_keys;
mod assets;
mod audit_log;
mod condition_form;
mod dashboards;
mod docs;
mod fleet;
mod health;
pub mod host_list;
mod maintenance_windows;
pub mod map;
mod metrics;
mod notification_channels;
mod overview;
mod remote_checks;
mod rules;
mod server;
mod sessions;
mod settings;
mod silences;
mod update_notice;
mod users;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Error;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Router};
use axum_csrf::CsrfToken;
use chrono_tz::Tz;
use ipnet::IpNet;
use serde_json::json;
use tera::Context;
use tower_http::compression::CompressionLayer;
use tower_http::compression::predicate::{DefaultPredicate, NotForContentType, Predicate};
use tracing::{error, warn};

use crate::app_state::AppState;
use crate::audit::{self, Acting, Actor, Via};
use crate::models::{DEFAULT_THEME, User};
use crate::roles::{self, Role};
use crate::times::{DEFAULT_TIME_ZONE, format_time};

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; \
     style-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; form-action 'self'; \
     base-uri 'none'; frame-ancestors 'none'";

tokio::task_local! {
    /// Who this request is from, for the page's frame and anything they do.
    static SIGNED_IN: Arc<User>;
}

/// Who's signed in, which is nobody on the sign in pages or for an API key.
fn signed_in_user() -> Option<Arc<User>> {
    SIGNED_IN.try_with(Arc::clone).ok()
}

/// Runs a request as `user`, for the page's frame and the audit log, `via` an API
/// key or the like if that's how they came.
/// Nothing runs for someone whose role doesn't allow it: see [`roles::required`].
async fn run_as(
    state: &AppState,
    user: User,
    via: Option<Via>,
    request: Request,
    next: Next,
) -> Response {
    let actor = Actor::Person {
        id: user.id,
        email: user.email.clone(),
    };
    // The route as it's written, so an ID in the address can't change what's needed.
    // What isn't found has no route, and only ever says so.
    let matched = request.extensions().get::<MatchedPath>().cloned();
    let route = matched
        .as_ref()
        .map_or_else(|| request.uri().path(), MatchedPath::as_str);
    let (is_api, route) = match route.strip_prefix(api::BASE_PATH) {
        Some(rest) => (true, rest),
        None => (false, route),
    };
    let needed = roles::required(request.method(), route);
    let yours = user.role;
    let answer = async {
        if yours >= needed {
            return next.run(request).await;
        }
        if is_api {
            let error = format!(
                "This needs the {} role, and this key acts as {} {}",
                needed.as_str(),
                article(yours),
                yours.as_str()
            );
            return (StatusCode::FORBIDDEN, axum::Json(json!({ "error": error }))).into_response();
        }
        let (mut parts, _) = request.into_parts();
        match CsrfToken::from_request_parts(&mut parts, state).await {
            Ok(token) => Page::new(state, &token, "errors/forbidden.html")
                .with("needed", needed.label())
                .with("yours", yours.label())
                .with_status(StatusCode::FORBIDDEN)
                .render(),
            Err(_) => StatusCode::FORBIDDEN.into_response(),
        }
    };
    let signed_in = SIGNED_IN.scope(Arc::new(user), answer);
    audit::acting_as(actor, via, signed_in).await
}

fn article(role: Role) -> &'static str {
    match role {
        Role::Editor | Role::Admin => "an",
        Role::Viewer | Role::Responder => "a",
    }
}

/// The zone whoever's signed in reads times in. Request handlers only, as a task
/// they spawn doesn't know who's signed in: pass the zone to those instead.
fn viewer_zone() -> Tz {
    signed_in_user().map_or(DEFAULT_TIME_ZONE, |user| user.zone())
}

/// A time as whoever's signed in reads it, or nothing for one before 1970.
fn local_time(ms: i64) -> String {
    u64::try_from(ms).map_or_else(|_| String::new(), |ms| format_time(ms, viewer_zone()))
}

/// Where a request came from: the address connecting, or for a trusted proxy, the
/// one it says it's passing on.
fn request_source(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let forwarded: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    agent_socket::client_ip(peer.ip(), &forwarded.join(","), trusted)
}

/// Notes where each request came from, for the audit log, with nobody acting until
/// a sign in check says who it is.
async fn note_source(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| request_source(*peer, request.headers(), &state.trusted_proxies));
    let acting = Acting {
        actor: Actor::Nobody,
        via: None,
        source,
    };
    audit::acting(acting, next.run(request)).await
}

pub fn app(state: AppState) -> Router {
    // Everything here needs someone signed in, including what isn't found, so a
    // stranger can't tell which addresses exist.
    let pages = Router::new()
        .merge(overview::routes())
        .merge(settings::routes())
        .merge(compressed(server::routes()))
        .merge(dashboards::routes())
        .merge(docs::routes())
        .merge(api_keys::routes())
        .merge(audit_log::routes())
        .merge(users::routes())
        .merge(agents::routes())
        .merge(alerts::routes())
        .merge(silences::routes())
        .merge(annotations::routes())
        .merge(maintenance_windows::routes())
        .merge(alert_rules::routes())
        .merge(notification_channels::routes())
        .merge(remote_checks::routes())
        .merge(map::routes())
        .merge(compressed(metrics::routes()))
        .merge(rules::routes())
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            sessions::require_login,
        ));

    Router::new()
        .route("/ws", get(agent_socket::upgrade))
        .merge(pages)
        .merge(sessions::routes())
        .merge(compressed(assets::routes()))
        // Open to all, so a form being filled in isn't lost to a login that ran out.
        .merge(update_notice::routes())
        .merge(health::routes())
        .nest(api::BASE_PATH, api::routes(state.clone()))
        .layer(middleware::from_fn_with_state(state.clone(), note_source))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Gzips responses for routes with no forms on them. A page holding a CSRF token
/// stays uncompressed, because its compressed size could give the token away to
/// someone watching encrypted traffic. Fonts are compressed already.
fn compressed(routes: Router<AppState>) -> Router<AppState> {
    let worthwhile = DefaultPredicate::new().and(NotForContentType::const_new("font/"));
    routes.layer(CompressionLayer::new().compress_when(worthwhile))
}

async fn not_found(state: axum::extract::State<AppState>, token: CsrfToken) -> Response {
    let page = Page::new(&state, &token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // Setup links are secrets, and a referrer would hand them to anything linked to.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Which item in the navigation a template belongs to.
fn section_of(template: &str) -> &'static str {
    match template.split('/').next().unwrap_or_default() {
        "overview" => "overview",
        "agents" => "agents",
        "metrics" => "metrics",
        "remote_checks" => "checks",
        "alerts" | "silences" | "maintenance_windows" => "alerts",
        "server" => "server",
        "map" => "map",
        "dashboards" => "dashboards",
        "settings" | "rules" | "alert_rules" | "notification_channels" => "settings",
        "profile" => "profile",
        "docs" => "docs",
        _ => "",
    }
}

/// Identifies this exact build, so an open page can tell the server has changed.
fn build_id() -> String {
    let build = maxnines_protocol::build_info!();
    format!("{}-{}", build.commit, build.built_at)
}

/// What the frame around a page shows of whoever's signed in.
#[derive(serde::Serialize)]
struct Badge {
    name: String,
    initial: String,
}

fn badge(user: &User) -> Badge {
    let initial = user.name.chars().next().map(char::to_uppercase);
    Badge {
        name: user.name.clone(),
        initial: initial.map(|letters| letters.collect()).unwrap_or_default(),
    }
}

/// A page to render, carrying the CSRF token every form on it needs.
struct Page<'a> {
    state: &'a AppState,
    token: CsrfToken,
    template: &'a str,
    context: Context,
    status: StatusCode,
}

impl<'a> Page<'a> {
    fn new(state: &'a AppState, token: &CsrfToken, template: &'a str) -> Self {
        let mut context = Context::new();
        match token.authenticity_token() {
            Ok(value) => context.insert("csrf_token", &value),
            Err(error) => warn!(%error, "creating a CSRF token failed"),
        }
        context.insert("build", &maxnines_protocol::build_info!());
        context.insert("build_id", &build_id());
        context.insert("section", section_of(template));
        context.insert("firing", &state.status.firing.load(Ordering::Relaxed));
        let user = signed_in_user();
        context.insert("user", &user.as_deref().map(badge));
        // What the pages offer. The server checks each request whatever they show.
        let role = user.as_deref().map(|user| user.role);
        context.insert("can_respond", &(role >= Some(Role::Responder)));
        context.insert("can_edit", &(role >= Some(Role::Editor)));
        context.insert("is_admin", &(role >= Some(Role::Admin)));
        let theme = user.as_deref().map_or(DEFAULT_THEME, |user| &user.theme);
        context.insert("theme", theme);
        context.insert("time_zone", viewer_zone().name());
        Self {
            state,
            token: token.clone(),
            template,
            context,
            status: StatusCode::OK,
        }
    }

    fn with<T: serde::Serialize + ?Sized>(mut self, name: &'static str, value: &T) -> Self {
        self.context.insert(name, value);
        self
    }

    fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    fn render(self) -> Response {
        match self.state.views.render(self.template, &self.context) {
            Ok(html) => (self.status, self.token, Html(html)).into_response(),
            Err(error) => server_error(&error),
        }
    }
}

fn server_error(error: &Error) -> Response {
    error!(error = format!("{error:#}"), "request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
}

/// A submitted form that has passed its CSRF check. This is the only way pages
/// read a form, so a handler can't forget the check.
struct CsrfForm {
    token: CsrfToken,
    fields: BTreeMap<String, String>,
}

const TOKEN_FIELD: &str = "authenticity_token";

impl FromRequest<AppState> for CsrfForm {
    type Rejection = Response;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Response> {
        let (mut parts, body) = request.into_parts();
        let token = CsrfToken::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        let request = Request::from_parts(parts, body);
        let Form(mut fields) = Form::<BTreeMap<String, String>>::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;

        let submitted = fields.remove(TOKEN_FIELD).unwrap_or_default();
        if token.verify(&submitted).is_err() {
            warn!("refused a form with a bad CSRF token");
            let message = "This form has expired. Go back, refresh the page and try again.";
            return Err((StatusCode::FORBIDDEN, message).into_response());
        }
        Ok(Self { token, fields })
    }
}
