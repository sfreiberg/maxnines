//! Routes and request handling. Pages live in `overview`, `agents`, `alerts`,
//! `alert_rules`, `metrics`, `notification_channels`, `remote_checks`, `rules`,
//! `settings` and `docs`, the token protected API in `api`, agent connections in
//! `agent_socket`, signing in in `sessions`, people in `users`, and how an open page
//! learns of a new build in `update_notice`.

pub mod agent_socket;
mod agents;
mod alert_rules;
mod alerts;
pub mod api;
mod api_keys;
mod assets;
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
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Error;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Router};
use axum_csrf::CsrfToken;
use tera::Context;
use tower_http::compression::CompressionLayer;
use tower_http::compression::predicate::{DefaultPredicate, NotForContentType, Predicate};
use tracing::{error, warn};

use crate::app_state::AppState;
use crate::models::{DEFAULT_THEME, User};

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
        .merge(users::routes())
        .merge(agents::routes())
        .merge(alerts::routes())
        .merge(silences::routes())
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
        let theme = user.as_deref().map_or(DEFAULT_THEME, |user| &user.theme);
        context.insert("theme", theme);
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
