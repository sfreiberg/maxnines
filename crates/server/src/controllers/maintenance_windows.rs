use std::collections::BTreeMap;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{CsrfForm, Page, server_error};
use crate::app_state::AppState;
use crate::maintenance::{DAYS, MaintenanceWindowInput};
use crate::times::zone_names;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts/maintenance", post(create))
        .route("/alerts/maintenance/new", get(new))
        .route("/alerts/maintenance/{id}", post(update))
        .route("/alerts/maintenance/{id}/edit", get(edit))
        .route("/alerts/maintenance/{id}/delete", post(delete))
}

/// A window as its form shows it, including whatever was just typed.
#[derive(Serialize)]
struct WindowForm {
    name: String,
    rule_id: String,
    filter: String,
    start_time: String,
    duration_minutes: String,
    time_zone: String,
    days: Vec<String>,
}

impl WindowForm {
    fn blank() -> Self {
        Self {
            name: String::new(),
            rule_id: String::new(),
            filter: String::new(),
            start_time: "02:00".to_string(),
            duration_minutes: "120".to_string(),
            time_zone: "UTC".to_string(),
            days: vec!["sun".to_string()],
        }
    }

    fn from_window(window: MaintenanceWindowInput) -> Self {
        Self {
            rule_id: window.rule_id.map(|id| id.to_string()).unwrap_or_default(),
            duration_minutes: window.duration_minutes.to_string(),
            name: window.name,
            filter: window.filter,
            start_time: window.start_time,
            time_zone: window.time_zone,
            days: window.days,
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            name: text("name"),
            rule_id: text("rule_id"),
            filter: text("filter"),
            start_time: text("start_time"),
            duration_minutes: text("duration_minutes"),
            time_zone: text("time_zone").trim().to_string(),
            days: DAYS
                .iter()
                .filter(|(day, _)| fields.contains_key(&format!("day_{day}")))
                .map(|(day, _)| (*day).to_string())
                .collect(),
        }
    }

    fn to_input(&self) -> Result<MaintenanceWindowInput, String> {
        let rule_id = match self.rule_id.as_str() {
            "" => None,
            text => Some(text.parse().map_err(|_| "Choose a rule.".to_string())?),
        };
        let duration_minutes = self
            .duration_minutes
            .trim()
            .parse()
            .map_err(|_| "The length must be a whole number of minutes.".to_string())?;
        Ok(MaintenanceWindowInput {
            name: self.name.clone(),
            rule_id,
            filter: self.filter.clone(),
            days: self.days.clone(),
            start_time: self.start_time.clone(),
            duration_minutes,
            time_zone: self.time_zone.clone(),
        })
    }
}

#[derive(Serialize)]
struct RuleChoice {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct DayChoice {
    value: &'static str,
    label: &'static str,
    chosen: bool,
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    window: &WindowForm,
    error: Option<&str>,
) -> Response {
    let rules = match state.database.list_alert_rules().await {
        Ok(rules) => rules,
        Err(error) => return server_error(&error),
    };
    let rules: Vec<RuleChoice> = rules
        .into_iter()
        .map(|rule| RuleChoice {
            id: rule.id.to_string(),
            name: rule.rule.name,
        })
        .collect();
    let days: Vec<DayChoice> = DAYS
        .iter()
        .map(|(value, label)| DayChoice {
            value,
            label,
            chosen: window.days.iter().any(|day| day == value),
        })
        .collect();
    let zones = zone_names();

    let mut page = Page::new(state, token, "maintenance_windows/form.html")
        .with("window", window)
        .with("rules", &rules)
        .with("days", &days)
        .with("zones", &zones);
    if let Some(id) = id {
        page = page.with("id", &id);
    }
    match error {
        Some(error) => page
            .with("error", error)
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .render(),
        None => page.render(),
    }
}

async fn new(State(state): State<AppState>, token: CsrfToken) -> Response {
    form_page(&state, &token, None, &WindowForm::blank(), None).await
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_maintenance_window(id).await {
        Ok(Some(found)) => {
            let window = WindowForm::from_window(found.window);
            form_page(&state, &token, Some(id), &window, None).await
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// What the form means, or why it can't be saved.
async fn checked(state: &AppState, window: &WindowForm) -> Result<MaintenanceWindowInput, String> {
    let input = window.to_input()?;
    match state.check_maintenance_window(&input).await {
        Ok(()) => Ok(input),
        Err(error) => Err(format!("{error:#}")),
    }
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let window = WindowForm::from_fields(&form.fields);
    let input = match checked(&state, &window).await {
        Ok(input) => input,
        Err(error) => return form_page(&state, &form.token, None, &window, Some(&error)).await,
    };
    match state.database.create_maintenance_window(&input).await {
        Ok(_) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let window = WindowForm::from_fields(&form.fields);
    let input = match checked(&state, &window).await {
        Ok(input) => input,
        Err(error) => return form_page(&state, &form.token, Some(id), &window, Some(&error)).await,
    };
    match state.database.update_maintenance_window(id, &input).await {
        Ok(true) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.delete_maintenance_window(id).await {
        Ok(true) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
