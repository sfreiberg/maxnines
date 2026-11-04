//! Routes and request handling. Pages live in `agents` and `rules`, the token
//! protected API in `admin`, and agent connections in `agent_socket`.

pub mod admin;
pub mod agent_socket;
mod agents;
mod assets;
mod rules;

use std::collections::BTreeMap;

use anyhow::Error;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use axum_csrf::CsrfToken;
use tera::Context;
use tracing::{error, warn};

use crate::app_state::AppState;

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; \
     form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/ws", get(agent_socket::upgrade))
        .merge(agents::routes())
        .merge(rules::routes())
        .merge(assets::routes())
        .merge(admin::routes(state.clone()))
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn home() -> Redirect {
    Redirect::to("/agents")
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
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
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
