//! The documentation pages, for anyone signed in.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use serde::Deserialize;

use super::{Page, server_error};
use crate::app_state::AppState;
use crate::docs::{BASE_PATH, Chapter, Docs};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(BASE_PATH, get(first))
        .route(&format!("{BASE_PATH}/search"), get(search))
        .route(&format!("{BASE_PATH}/examples/{{name}}"), get(example))
        .route(&format!("{BASE_PATH}/{{name}}"), get(show))
}

/// An example file the pages link to, as text to read or save.
async fn example(
    State(state): State<AppState>,
    token: CsrfToken,
    Path(name): Path<String>,
) -> Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    match crate::docs::example(&name) {
        Some(text) => (
            [
                (
                    header::CONTENT_TYPE,
                    "text/plain; charset=utf-8".to_string(),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    format!("inline; filename=\"{name}\""),
                ),
            ],
            text,
        )
            .into_response(),
        None => Page::new(&state, &token, "errors/not_found.html")
            .with_status(StatusCode::NOT_FOUND)
            .render(),
    }
}

async fn first(State(state): State<AppState>, token: CsrfToken) -> Response {
    match Docs::get() {
        Ok(docs) => chapter_page(&state, &token, &docs, docs.first()).render(),
        Err(error) => server_error(&error),
    }
}

async fn show(
    State(state): State<AppState>,
    token: CsrfToken,
    Path(name): Path<String>,
) -> Response {
    let docs = match Docs::get() {
        Ok(docs) => docs,
        Err(error) => return server_error(&error),
    };
    match docs.chapter(&name) {
        Some(chapter) => chapter_page(&state, &token, &docs, chapter).render(),
        None => Page::new(&state, &token, "errors/not_found.html")
            .with_status(StatusCode::NOT_FOUND)
            .render(),
    }
}

fn chapter_page<'a>(
    state: &'a AppState,
    token: &CsrfToken,
    docs: &Docs,
    chapter: &Chapter,
) -> Page<'a> {
    Page::new(state, token, "docs/show.html")
        .with("contents", &docs.contents(&chapter.name))
        .with("query", "")
        .with("title", &docs.full_title(chapter))
        .with("html", &chapter.html)
}

#[derive(Deserialize)]
struct SearchParams {
    #[serde(default)]
    q: String,
}

async fn search(
    State(state): State<AppState>,
    token: CsrfToken,
    Query(params): Query<SearchParams>,
) -> Response {
    let docs = match Docs::get() {
        Ok(docs) => docs,
        Err(error) => return server_error(&error),
    };
    let query = params.q.trim();
    Page::new(&state, &token, "docs/search.html")
        .with("contents", &docs.contents(""))
        .with("query", query)
        .with("hits", &docs.search(query))
        .render()
}
