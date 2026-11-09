use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};

use super::{CsrfForm, Page, local_time, server_error, signed_in_user};
use crate::app_state::AppState;
use crate::maintenance::MaintenanceWindow;
use crate::metrics::now_ms;
use crate::silences::{Silence, SilenceInput};

/// How many ended silences the page shows.
const HISTORY: u64 = 20;

const ONE_HOUR: u64 = 3600;

/// What the form offers, in seconds.
const DURATIONS: [(u64, &str); 8] = [
    (1800, "30 minutes"),
    (ONE_HOUR, "1 hour"),
    (2 * ONE_HOUR, "2 hours"),
    (4 * ONE_HOUR, "4 hours"),
    (8 * ONE_HOUR, "8 hours"),
    (24 * ONE_HOUR, "1 day"),
    (3 * 24 * ONE_HOUR, "3 days"),
    (7 * 24 * ONE_HOUR, "7 days"),
];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts/silences", get(index).post(create))
        .route("/alerts/silences/new", get(new))
        .route("/alerts/silences/{id}/end", post(end))
}

#[derive(Serialize)]
struct SilenceRow {
    id: i64,
    rule: String,
    hosts: String,
    reason: String,
    created_by: String,
    starts: String,
    ends: String,
}

async fn rows(state: &AppState, silences: Vec<Silence>) -> anyhow::Result<Vec<SilenceRow>> {
    let rules = state.database.list_alert_rules().await?;
    let rule_name = |id: i64| {
        rules
            .iter()
            .find(|rule| rule.id == id)
            .map(|rule| rule.rule.name.clone())
    };
    Ok(silences
        .into_iter()
        .map(|silence| SilenceRow {
            id: silence.id,
            rule: silence.rule_id.map_or("Every rule".to_string(), |id| {
                rule_name(id).unwrap_or_default()
            }),
            hosts: if silence.filter.is_empty() {
                "Every host".to_string()
            } else {
                silence.filter
            },
            reason: silence.reason,
            created_by: silence.created_by,
            starts: local_time(silence.starts_ms),
            ends: local_time(silence.ends_ms),
        })
        .collect())
}

#[derive(Serialize)]
struct WindowRow {
    id: i64,
    name: String,
    schedule: String,
    hosts: String,
    rule: String,
    running: bool,
}

async fn window_rows(
    state: &AppState,
    windows: Vec<MaintenanceWindow>,
    now: i64,
) -> anyhow::Result<Vec<WindowRow>> {
    let rules = state.database.list_alert_rules().await?;
    let rule_name = |id: i64| {
        let rule = rules.iter().find(|rule| rule.id == id);
        rule.map(|rule| rule.rule.name.clone()).unwrap_or_default()
    };
    Ok(windows
        .into_iter()
        .map(|window| WindowRow {
            schedule: window.schedule(),
            running: window.ends_at(now).is_some(),
            id: window.id,
            rule: window
                .window
                .rule_id
                .map_or("Every rule".to_string(), rule_name),
            hosts: if window.window.filter.is_empty() {
                "Every host".to_string()
            } else {
                window.window.filter
            },
            name: window.window.name,
        })
        .collect())
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let now = now_ms();
    let lists = async {
        let active = state.database.active_silences(now).await?;
        let ended = state.database.ended_silences(now, HISTORY).await?;
        let windows = state.database.list_maintenance_windows().await?;
        anyhow::Ok((
            rows(&state, active).await?,
            rows(&state, ended).await?,
            window_rows(&state, windows, now).await?,
        ))
    };
    match lists.await {
        Ok((active, ended, windows)) => Page::new(&state, &token, "silences/index.html")
            .with("active", &active)
            .with("ended", &ended)
            .with("windows", &windows)
            .render(),
        Err(error) => server_error(&error),
    }
}

/// A silence as its form shows it, including whatever was just typed.
#[derive(Default, Deserialize, Serialize)]
struct SilenceForm {
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    filter: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    duration_secs: String,
}

#[derive(Serialize)]
struct RuleChoice {
    id: i64,
    name: String,
}

#[derive(Serialize)]
struct DurationChoice {
    secs: String,
    label: &'static str,
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    silence: &SilenceForm,
    error: Option<&str>,
) -> Response {
    let rules = match state.database.list_alert_rules().await {
        Ok(rules) => rules,
        Err(error) => return server_error(&error),
    };
    let rules: Vec<RuleChoice> = rules
        .into_iter()
        .map(|rule| RuleChoice {
            id: rule.id,
            name: rule.rule.name,
        })
        .collect();
    let durations: Vec<DurationChoice> = DURATIONS
        .iter()
        .map(|(secs, label)| DurationChoice {
            secs: secs.to_string(),
            label,
        })
        .collect();

    let page = Page::new(state, token, "silences/form.html")
        .with("silence", silence)
        .with("rules", &rules)
        .with("durations", &durations);
    match error {
        Some(error) => page
            .with("error", error)
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .render(),
        None => page.render(),
    }
}

/// Starts from what's in the address, so an alert can link to a silence for itself.
async fn new(
    State(state): State<AppState>,
    token: CsrfToken,
    Query(mut silence): Query<SilenceForm>,
) -> Response {
    silence.duration_secs = ONE_HOUR.to_string();
    form_page(&state, &token, &silence, None).await
}

fn input_from(silence: &SilenceForm) -> Result<SilenceInput, String> {
    let rule_id = match silence.rule_id.as_str() {
        "" => None,
        text => Some(text.parse().map_err(|_| "Choose a rule.".to_string())?),
    };
    let duration_secs = silence
        .duration_secs
        .parse()
        .map_err(|_| "Choose how long it lasts.".to_string())?;
    Ok(SilenceInput {
        rule_id,
        filter: silence.filter.clone(),
        reason: silence.reason.clone(),
        duration_secs,
    })
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let text = |name: &str| form.fields.get(name).cloned().unwrap_or_default();
    let silence = SilenceForm {
        rule_id: text("rule_id"),
        filter: text("filter"),
        reason: text("reason"),
        duration_secs: text("duration_secs"),
    };

    let input = match input_from(&silence) {
        Ok(input) => input,
        Err(error) => return form_page(&state, &form.token, &silence, Some(&error)).await,
    };
    if let Err(error) = state.check_silence(&input).await {
        let message = format!("{error:#}");
        return form_page(&state, &form.token, &silence, Some(&message)).await;
    }

    let by = signed_in_user().map_or_else(|| "admin".to_string(), |user| user.email.clone());
    match state.database.create_silence(&input, &by, now_ms()).await {
        Ok(_) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn end(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.end_silence(id, now_ms()).await {
        Ok(true) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
