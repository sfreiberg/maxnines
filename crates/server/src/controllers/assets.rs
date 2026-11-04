use axum::Router;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::app_state::AppState;
use crate::views::StaticFiles;

pub fn routes() -> Router<AppState> {
    Router::new().route("/assets/{*path}", get(show))
}

/// Only files embedded in the binary exist here, so a path can't reach anything
/// else on the machine.
async fn show(Path(path): Path<String>) -> Response {
    match StaticFiles::get(&path) {
        Some(file) => {
            let content_type = file.metadata.mimetype().to_string();
            ([(header::CONTENT_TYPE, content_type)], file.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
