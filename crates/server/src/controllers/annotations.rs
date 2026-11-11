//! Annotations on the pages: the Annotations tab under Metrics, which lists them and
//! records one for any filter, and the quick form on a host's charts, for that
//! host alone.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use chrono::{NaiveDateTime, TimeDelta};
use serde::{Deserialize, Serialize};

use super::metrics::{RangeParams, selected_range};
use super::{CsrfForm, Page, local_time, recorded_by, server_error, viewer_zone};
use crate::app_state::{AppState, EventRefusal};
use crate::events::EventInput;
use crate::host_filter;
use crate::maintenance::moment;
use crate::metrics::now_ms;

/// How far back the list goes.
const LIST_DAYS: i64 = 30;
/// The most the list shows.
const LIST_LIMIT: u64 = 200;
/// How a time is written in the form, as the browser's date and time picker sends it.
const FORM_TIME: &str = "%Y-%m-%dT%H:%M";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics/annotations", get(index).post(create))
        .route("/metrics/annotations/{id}/delete", post(delete))
        .route("/hosts/{id}/annotations", post(create_for_host))
}

/// What the form holds, given back as it was when it's refused.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AnnotationForm {
    kind: String,
    title: String,
    detail: String,
    filter: String,
    /// In the viewer's time zone. Empty for now.
    when: String,
}

#[derive(Serialize)]
struct AnnotationRow {
    id: i64,
    time: String,
    kind: &'static str,
    kind_label: &'static str,
    title: String,
    detail: Option<String>,
    filter: String,
    created_by: String,
}

#[derive(Deserialize, Default)]
struct IndexParams {
    /// A filter to start the form with, as from a host's page.
    filter: Option<String>,
}

async fn page(
    state: &AppState,
    token: &CsrfToken,
    form: &AnnotationForm,
    error: Option<&str>,
) -> Response {
    let now = now_ms();
    let since = now - LIST_DAYS * TimeDelta::days(1).num_milliseconds();
    let annotations = match state
        .database
        .list_events(since, now + 3_600_000, LIST_LIMIT)
        .await
    {
        Ok(annotations) => annotations,
        Err(error) => return server_error(&error),
    };
    let rows: Vec<AnnotationRow> = annotations
        .into_iter()
        .map(|annotation| AnnotationRow {
            id: annotation.id,
            time: local_time(annotation.time_ms),
            kind: annotation.kind.as_str(),
            kind_label: annotation.kind.label(),
            title: annotation.title,
            detail: annotation.detail,
            filter: annotation.filter,
            created_by: annotation.created_by,
        })
        .collect();
    let page = Page::new(state, token, "metrics/annotations.html")
        .with("annotation", form)
        .with("annotations", &rows)
        .with("list_days", &LIST_DAYS);
    match error {
        Some(error) => page
            .with("error", error)
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .render(),
        None => page.render(),
    }
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<IndexParams>,
    token: CsrfToken,
) -> Response {
    let form = AnnotationForm {
        filter: params.filter.unwrap_or_default(),
        ..AnnotationForm::default()
    };
    page(&state, &token, &form, None).await
}

/// A time from the form, in the viewer's time zone.
fn when(text: &str) -> Result<Option<i64>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let local = NaiveDateTime::parse_from_str(text, FORM_TIME)
        .map_err(|_| "Give the time as a date and time, or leave it empty for now.".to_string())?;
    moment(viewer_zone(), local.date(), local.time())
        .map(Some)
        .ok_or_else(|| "That time doesn't exist in your time zone.".to_string())
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let text = |name: &str| form.fields.get(name).cloned().unwrap_or_default();
    let filled = AnnotationForm {
        kind: text("kind"),
        title: text("title"),
        detail: text("detail"),
        filter: text("filter"),
        when: text("when"),
    };
    let time_ms = match when(&filled.when) {
        Ok(time) => time,
        Err(error) => return page(&state, &form.token, &filled, Some(&error)).await,
    };
    let input = EventInput {
        kind: Some(filled.kind.clone()),
        title: filled.title.clone(),
        detail: Some(filled.detail.clone()),
        time_ms,
        filter: Some(filled.filter.clone()),
    };
    match state.record_event(input, &recorded_by(), now_ms()).await {
        Ok(_) => (form.token, Redirect::to("/metrics/annotations")).into_response(),
        Err(EventRefusal::Invalid(message)) => {
            page(&state, &form.token, &filled, Some(&message)).await
        }
        Err(EventRefusal::Failed(error)) => server_error(&error),
    }
}

/// Back to a host's charts, at the range they were on. A refusal goes along to be
/// shown above the form.
fn back_to(host_id: &str, form: &CsrfForm, refusal: Option<&str>) -> String {
    let params = RangeParams {
        range: form.fields.get("range").cloned(),
    };
    let (range, _, _) = selected_range(&params);
    let mut query = vec![("range", range)];
    if let Some(refusal) = refusal {
        query.push(("event_error", refusal));
    }
    let query = serde_urlencoded::to_string(query).unwrap_or_default();
    format!("/hosts/{host_id}/metrics?{query}#events")
}

/// A note or a deploy for one host, happening now, from its charts.
async fn create_for_host(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    let Some(host) = state
        .registry
        .get(&id)
        .await
        .filter(|host| !host.is_local())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let text = |name: &str| form.fields.get(name).cloned();
    let input = EventInput {
        kind: text("kind"),
        title: text("title").unwrap_or_default(),
        detail: text("detail"),
        time_ms: None,
        filter: Some(host_filter::only(&host.id)),
    };
    match state.record_event(input, &recorded_by(), now_ms()).await {
        Ok(_) => {
            let target = back_to(&host.id, &form, None);
            (form.token, Redirect::to(&target)).into_response()
        }
        Err(EventRefusal::Invalid(message)) => {
            let target = back_to(&host.id, &form, Some(&message));
            (form.token, Redirect::to(&target)).into_response()
        }
        Err(EventRefusal::Failed(error)) => server_error(&error),
    }
}

/// Deletes an annotation, then goes back to the host it was deleted from, or to the
/// Annotations tab.
async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let page_host = match form.fields.get("host_id") {
        Some(host) => match state.registry.get(host).await {
            Some(host) => Some(host),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
        None => None,
    };
    match state.database.delete_event(id).await {
        Ok(true) => {
            let target = page_host.map_or_else(
                || "/metrics/annotations".to_string(),
                |host| back_to(&host.id, &form, None),
            );
            (form.token, Redirect::to(&target)).into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_time_is_now_and_anything_else_has_to_be_one() {
        assert_eq!(when(" "), Ok(None));
        assert!(when("2026-11-10T14:30").unwrap().is_some());
        assert!(when("yesterday").is_err());
    }
}
