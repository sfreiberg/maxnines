//! Pages for hosts with no agent: adding one, renaming it, and the OpenMetrics
//! pages the server reads for it.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::{CsrfForm, Page, recorded_by, server_error};
use crate::app_state::AppState;
use crate::metrics_pages::{ENV_PREFIX, MetricsPage, MetricsPageInput};
use crate::registration::HostRecord;

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

fn host_form(state: &AppState, token: &CsrfToken, hostname: &str, error: Option<&str>) -> Response {
    let page = Page::new(state, token, "hosts/new.html")
        .with("hostname", hostname)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

pub async fn new(State(state): State<AppState>, token: CsrfToken) -> Response {
    host_form(&state, &token, "", None)
}

pub async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let hostname = form.fields.get("hostname").cloned().unwrap_or_default();
    // Only a name that won't do can stop this, short of the database failing.
    if let Err(error) = crate::registration::agentless_hostname(&hostname) {
        let message = format!("{error:#}");
        return host_form(&state, &form.token, &hostname, Some(&message));
    }
    match state
        .registry
        .add_agentless(&hostname, &recorded_by())
        .await
    {
        Ok(host) => (form.token, Redirect::to(&format!("/hosts/{}", host.id))).into_response(),
        Err(error) => server_error(&error),
    }
}

pub async fn rename(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: CsrfForm,
) -> Response {
    let hostname = form.fields.get("hostname").cloned().unwrap_or_default();
    if crate::registration::agentless_hostname(&hostname).is_err() {
        let message = "A host's name can't be empty or over 255 characters.";
        return (StatusCode::UNPROCESSABLE_ENTITY, message).into_response();
    }
    match state.registry.rename_agentless(&id, &hostname).await {
        Ok(Some(_)) => (form.token, Redirect::to(&format!("/hosts/{id}"))).into_response(),
        Ok(None) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

/// A page as its form shows it, including whatever was just typed. A saved
/// password is never put back in the form.
#[derive(Serialize, Default)]
struct PageForm {
    url: String,
    names: String,
    interval_secs: String,
    enabled: bool,
    username: String,
    password: String,
    password_env: String,
    /// Whether a password is saved, which leaving the box empty keeps.
    has_password: bool,
}

impl PageForm {
    fn blank() -> Self {
        Self {
            interval_secs: "60".to_string(),
            enabled: true,
            ..Self::default()
        }
    }

    fn from_input(input: &MetricsPageInput) -> Self {
        Self {
            url: input.url.clone(),
            names: input.names.join("\n"),
            interval_secs: input.interval_secs.to_string(),
            enabled: input.enabled,
            username: input.username.clone().unwrap_or_default(),
            password: String::new(),
            password_env: input.password_env.clone().unwrap_or_default(),
            has_password: input.password.is_some(),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>, saved: Option<&MetricsPageInput>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            url: text("url"),
            names: text("names"),
            interval_secs: text("interval_secs"),
            enabled: fields.contains_key("enabled"),
            username: text("username"),
            password: text("password"),
            password_env: text("password_env"),
            has_password: saved.is_some_and(|saved| saved.password.is_some()),
        }
    }

    fn to_input(&self) -> Result<MetricsPageInput> {
        let filled = |text: &str| Some(text.trim().to_string()).filter(|text| !text.is_empty());
        let interval_secs = self
            .interval_secs
            .trim()
            .parse()
            .context("the interval has to be a number of seconds")?;
        Ok(MetricsPageInput {
            url: self.url.trim().to_string(),
            names: self.names.lines().filter_map(filled).collect(),
            interval_secs,
            enabled: self.enabled,
            username: filled(&self.username),
            // A password is whatever was typed, spaces and all.
            password: Some(self.password.clone()).filter(|password| !password.is_empty()),
            password_env: filled(&self.password_env),
        })
    }
}

fn page_form(
    state: &AppState,
    token: &CsrfToken,
    host: &HostRecord,
    id: Option<i64>,
    form: &PageForm,
    error: Option<&str>,
) -> Response {
    let page = Page::new(state, token, "hosts/page_form.html")
        .with("host_id", &host.id)
        .with("hostname", &host.hostname)
        .with("id", &id)
        .with("page", form)
        .with("env_prefix", ENV_PREFIX)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

/// A host's page, if both exist and belong together.
async fn find(
    state: &AppState,
    host_id: &str,
    id: i64,
) -> Result<Option<(HostRecord, MetricsPage)>> {
    let Some(host) = state.agentless_host(host_id).await else {
        return Ok(None);
    };
    let page = state.database.get_metrics_page(id).await?;
    Ok(page
        .filter(|page| page.host_id == host.id)
        .map(|page| (host, page)))
}

pub async fn new_page(
    State(state): State<AppState>,
    Path(host_id): Path<String>,
    token: CsrfToken,
) -> Response {
    match state.agentless_host(&host_id).await {
        Some(host) => page_form(&state, &token, &host, None, &PageForm::blank(), None),
        None => not_found(&state, &token),
    }
}

pub async fn edit_page(
    State(state): State<AppState>,
    Path((host_id, id)): Path<(String, i64)>,
    token: CsrfToken,
) -> Response {
    match find(&state, &host_id, id).await {
        Ok(Some((host, page))) => {
            let form = PageForm::from_input(&page.input);
            page_form(&state, &token, &host, Some(id), &form, None)
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

pub async fn create_page(
    State(state): State<AppState>,
    Path(host_id): Path<String>,
    form: CsrfForm,
) -> Response {
    let Some(host) = state.agentless_host(&host_id).await else {
        return not_found(&state, &form.token);
    };
    let fields = PageForm::from_fields(&form.fields, None);
    let checked = match fields.to_input() {
        Ok(input) => state.checked_metrics_page(&host.id, None, input).await,
        Err(error) => Err(error),
    };
    let input = match checked {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return page_form(&state, &form.token, &host, None, &fields, Some(&message));
        }
    };
    match state.database.create_metrics_page(&host.id, &input).await {
        Ok(_) => (form.token, Redirect::to(&format!("/hosts/{host_id}"))).into_response(),
        Err(error) => server_error(&error),
    }
}

pub async fn update_page(
    State(state): State<AppState>,
    Path((host_id, id)): Path<(String, i64)>,
    form: CsrfForm,
) -> Response {
    let (host, saved) = match find(&state, &host_id, id).await {
        Ok(Some(found)) => found,
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let fields = PageForm::from_fields(&form.fields, Some(&saved.input));
    let checked = match fields.to_input() {
        Ok(input) => state.checked_metrics_page(&host.id, Some(id), input).await,
        Err(error) => Err(error),
    };
    let input = match checked {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return page_form(
                &state,
                &form.token,
                &host,
                Some(id),
                &fields,
                Some(&message),
            );
        }
    };
    match state.database.update_metrics_page(id, input).await {
        Ok(true) => (form.token, Redirect::to(&format!("/hosts/{host_id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

pub async fn delete_page(
    State(state): State<AppState>,
    Path((host_id, id)): Path<(String, i64)>,
    form: CsrfForm,
) -> Response {
    match find(&state, &host_id, id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    }
    match state.database.delete_metrics_page(id).await {
        Ok(_) => (form.token, Redirect::to(&format!("/hosts/{host_id}"))).into_response(),
        Err(error) => server_error(&error),
    }
}

/// A host's page as its host's page lists it.
#[derive(Serialize)]
pub struct PageRow {
    id: i64,
    name: String,
    url: String,
    interval_secs: u64,
    enabled: bool,
    /// How many metric names it's limited to, or none for everything.
    keeps: usize,
    /// Who it signs in as, and where the password comes from.
    username: Option<String>,
    password_env: Option<String>,
    /// Whether it's been read since the server started, and how that went.
    read: bool,
    answered: bool,
    error: Option<String>,
    dropped: u64,
}

pub async fn page_rows(state: &AppState, host_id: &str) -> Result<Vec<PageRow>> {
    let pages = state.database.metrics_pages_of(host_id).await?;
    Ok(pages
        .into_iter()
        .map(|page| {
            let result = state.page_reads.result(page.id);
            let result = result.as_ref();
            PageRow {
                id: page.id,
                name: page.input.name().to_string(),
                keeps: page.input.names.len(),
                read: result.is_some(),
                answered: result.is_some_and(|result| result["up"] == 1),
                error: result
                    .and_then(|result| result["error"].as_str())
                    .map(String::from),
                dropped: result
                    .and_then(|result| result["dropped"].as_u64())
                    .unwrap_or_default(),
                url: page.input.url,
                interval_secs: page.input.interval_secs,
                enabled: page.input.enabled,
                username: page.input.username,
                password_env: page.input.password_env,
            }
        })
        .collect())
}

/// A check about a host, as its host's page lists it.
#[derive(Serialize)]
pub struct CheckRow {
    id: i64,
    name: String,
    kind: &'static str,
    target: String,
    interval_secs: u64,
    enabled: bool,
    /// Whether it's run since the server started, and how that went.
    run: bool,
    up: bool,
    error: Option<String>,
}

pub async fn check_rows(state: &AppState, host_id: &str) -> Result<Vec<CheckRow>> {
    let checks = state.database.list_remote_checks().await?;
    let latest = state.check_results.all();
    Ok(checks
        .into_iter()
        .filter(|check| check.input.host_id == host_id)
        .map(|check| {
            let input = check.input;
            let result = latest.get(&input.check.name);
            CheckRow {
                id: check.id,
                kind: input.check.kind.as_str(),
                run: result.is_some(),
                up: result.is_some_and(|result| result["up"] == 1),
                error: result
                    .and_then(|result| result["error"].as_str())
                    .map(String::from),
                name: input.check.name,
                target: input.check.target,
                interval_secs: input.interval_secs,
                enabled: input.enabled,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> MetricsPageInput {
        MetricsPageInput {
            url: "https://db.example.com:9187/metrics".to_string(),
            names: vec!["pg_*".to_string(), "process_cpu_seconds_total".to_string()],
            interval_secs: 120,
            enabled: false,
            username: Some("metrics".to_string()),
            password: None,
            password_env: Some("MAXNINES_SECRET_DB".to_string()),
        }
    }

    #[test]
    fn a_page_survives_the_trip_through_its_form() {
        let original = input();
        assert_eq!(
            PageForm::from_input(&original).to_input().unwrap(),
            original
        );
    }

    #[test]
    fn a_saved_password_is_never_put_in_the_form() {
        let mut saved = input();
        saved.password = Some("s3cret".to_string());
        saved.password_env = None;

        let form = PageForm::from_input(&saved);
        assert!(form.has_password);
        assert_eq!(form.password, "");
        // Sent back untouched, it gives no password, which keeps the saved one.
        let again = form.to_input().unwrap().keeping_password_of(&saved);
        assert_eq!(again, saved);
    }

    #[test]
    fn typing_mistakes_are_explained() {
        let mut form = PageForm::blank();
        form.interval_secs = "often".to_string();
        let error = format!("{:#}", form.to_input().unwrap_err());
        assert!(error.contains("number of seconds"), "{error}");
    }
}
