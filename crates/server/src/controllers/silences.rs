use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use super::{CsrfForm, Page, local_time, recorded_by, server_error};
use crate::app_state::AppState;
use crate::maintenance::MaintenanceWindow;
use crate::silences::{Silence, SilenceInput};
use crate::times::Timestamp;

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
    /// The one series it's for, if it isn't for all of them.
    series: Option<String>,
    reason: String,
    created_by: String,
    starts: String,
    ends: String,
}

async fn rows(state: &AppState, silences: Vec<Silence>) -> anyhow::Result<Vec<SilenceRow>> {
    // Silences that have ended can be for a rule deleted since.
    let names = state.database.alert_rule_names().await?;
    let rule_name = |id: i64| names.get(&id).cloned();
    Ok(silences
        .into_iter()
        .map(|silence| SilenceRow {
            id: silence.id,
            rule: silence.rule_id.map_or("Every rule".to_string(), |id| {
                rule_name(id).unwrap_or_default()
            }),
            hosts: silence.filter.unwrap_or_else(|| "Every host".to_string()),
            series: silence.series,
            reason: silence.reason,
            created_by: silence.created_by,
            starts: local_time(silence.starts_at),
            ends: local_time(silence.ends_at),
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
    now: Timestamp,
) -> anyhow::Result<Vec<WindowRow>> {
    let names = state.database.alert_rule_names().await?;
    let rule_name = |id: i64| names.get(&id).cloned().unwrap_or_default();
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
            hosts: window
                .window
                .filter
                .unwrap_or_else(|| "Every host".to_string()),
            name: window.window.name,
        })
        .collect())
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let now = crate::times::now();
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
    series: String,
    #[serde(default)]
    all_alerts: bool,
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
    let duration = silence
        .duration_secs
        .parse()
        .ok()
        .and_then(TimeDelta::try_seconds)
        .ok_or_else(|| "Choose how long it lasts.".to_string())?;
    Ok(SilenceInput {
        rule_id,
        filter: crate::text::non_blank(&silence.filter),
        series: crate::text::non_blank(&silence.series),
        all_alerts: silence.all_alerts,
        reason: silence.reason.clone(),
        duration,
    })
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let text = |name: &str| form.fields.get(name).cloned().unwrap_or_default();
    let silence = SilenceForm {
        rule_id: text("rule_id"),
        filter: text("filter"),
        series: text("series"),
        all_alerts: form.fields.contains_key("all_alerts"),
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

    let by = recorded_by();
    match state
        .database
        .create_silence(&input, &by, crate::times::now())
        .await
    {
        Ok(_) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn end(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.end_silence(id, crate::times::now()).await {
        Ok(true) => (form.token, Redirect::to("/alerts/silences")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
