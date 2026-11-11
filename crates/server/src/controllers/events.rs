//! Recording a note or a deploy from a machine's page, and deleting one.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;

use super::metrics::{RangeParams, selected_range};
use super::{CsrfForm, server_error, signed_in_user};
use crate::app_state::{AppState, EventRefusal};
use crate::events::EventInput;
use crate::host_filter;
use crate::metrics::now_ms;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/agents/{id}/events", post(create))
        .route("/events/{id}/delete", post(delete))
}

/// Who recorded something from a page.
pub(super) fn recorded_by() -> String {
    signed_in_user().map_or_else(|| "admin".to_string(), |user| user.email.clone())
}

/// Back to the machine's charts, at the range they were on. A refusal goes along to be
/// shown above the form.
fn back_to(agent_id: &str, form: &CsrfForm, refusal: Option<&str>) -> String {
    let params = RangeParams {
        range: form.fields.get("range").cloned(),
    };
    let (range, _, _) = selected_range(&params);
    let mut query = vec![("range", range)];
    if let Some(refusal) = refusal {
        query.push(("event_error", refusal));
    }
    let query = serde_urlencoded::to_string(query).unwrap_or_default();
    format!("/agents/{agent_id}/metrics?{query}#events")
}

/// A note or a deploy for this machine alone, happening now.
async fn create(State(state): State<AppState>, Path(id): Path<String>, form: CsrfForm) -> Response {
    let Some(agent) = state
        .registry
        .get(&id)
        .await
        .filter(|agent| !agent.is_local())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let text = |name: &str| form.fields.get(name).cloned();
    let input = EventInput {
        kind: text("kind"),
        title: text("title").unwrap_or_default(),
        detail: text("detail"),
        time_ms: None,
        filter: Some(host_filter::only(&agent.id)),
    };
    match state.record_event(input, &recorded_by(), now_ms()).await {
        Ok(_) => {
            let target = back_to(&agent.id, &form, None);
            (form.token, Redirect::to(&target)).into_response()
        }
        Err(EventRefusal::Invalid(message)) => {
            let target = back_to(&agent.id, &form, Some(&message));
            (form.token, Redirect::to(&target)).into_response()
        }
        Err(EventRefusal::Failed(error)) => server_error(&error),
    }
}

/// Deletes an event wherever it was recorded for, then goes back to the machine it was
/// deleted from.
async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let agent = form.fields.get("agent_id").cloned().unwrap_or_default();
    let Some(agent) = state.registry.get(&agent).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match state.database.delete_event(id).await {
        Ok(true) => {
            let target = back_to(&agent.id, &form, None);
            (form.token, Redirect::to(&target)).into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
