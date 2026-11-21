use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use tera::Context;

use super::{build_id, server_error};
use crate::app_state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/update-notice", get(show))
}

#[derive(Deserialize)]
struct OpenPage {
    build: String,
}

/// Open pages ask this now and then, saying which build they came from. The answer
/// is empty until the server is running a different one.
async fn show(State(state): State<AppState>, Query(page): Query<OpenPage>) -> Response {
    if page.build == build_id() {
        return StatusCode::NO_CONTENT.into_response();
    }
    match state
        .views
        .render("layouts/_update_notice.html", &Context::new())
    {
        Ok(html) => Html(html).into_response(),
        Err(error) => server_error(&error),
    }
}
