use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use maxnines_protocol::{Check, CheckKind};
use serde::{Deserialize, Serialize};

use super::metrics::{CheckRow, check_row};
use super::{CsrfForm, Page, server_error};
use crate::app_state::AppState;
use crate::registration::HostState;
use crate::remote_checks::{LOCAL_HOST_ID, LOCAL_HOSTNAME, RemoteCheckInput};

const KINDS: [CheckKind; 5] = [
    CheckKind::Http,
    CheckKind::Tcp,
    CheckKind::Tls,
    CheckKind::Dns,
    CheckKind::Ping,
];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/checks", get(index).post(create))
        .route("/checks/new", get(new))
        .route("/checks/{id}", post(update))
        .route("/checks/{id}/edit", get(edit))
        .route("/checks/{id}/delete", post(delete))
}

/// A check as its form shows it, including whatever was just typed.
#[derive(Serialize, Default)]
struct CheckForm {
    /// The host it's about: one with no agent, or the server itself.
    host_id: String,
    name: String,
    kind: String,
    target: String,
    interval_secs: String,
    timeout_secs: String,
    method: String,
    body: String,
    regex: String,
    insecure: bool,
    server: String,
    record: String,
    count: String,
    enabled: bool,
}

/// What's left empty on a form isn't set at all.
fn optional(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> Result<Option<T>> {
    optional(text)
        .map(|text| {
            text.parse()
                .ok()
                .with_context(|| format!("{what} has to be a number"))
        })
        .transpose()
}

impl CheckForm {
    fn blank() -> Self {
        Self {
            host_id: LOCAL_HOST_ID.to_string(),
            kind: CheckKind::Http.as_str().to_string(),
            interval_secs: "60".to_string(),
            enabled: true,
            ..Self::default()
        }
    }

    fn from_input(input: &RemoteCheckInput) -> Self {
        let check = &input.check;
        let text = |value: &Option<String>| value.clone().unwrap_or_default();
        Self {
            host_id: input.host_id.clone(),
            name: check.name.clone(),
            kind: check.kind.as_str().to_string(),
            target: check.target.clone(),
            interval_secs: input.interval_secs.to_string(),
            timeout_secs: check
                .timeout_secs
                .map(|t| t.to_string())
                .unwrap_or_default(),
            method: text(&check.method),
            body: text(&check.body),
            regex: text(&check.regex),
            insecure: check.insecure == Some(true),
            server: text(&check.server),
            record: text(&check.record),
            count: check.count.map(|c| c.to_string()).unwrap_or_default(),
            enabled: input.enabled,
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            // A form without one is from before checks had hosts.
            host_id: optional(&text("host_id")).unwrap_or_else(|| LOCAL_HOST_ID.to_string()),
            name: text("name"),
            kind: text("kind"),
            target: text("target"),
            interval_secs: text("interval_secs"),
            timeout_secs: text("timeout_secs"),
            method: text("method"),
            body: text("body"),
            regex: text("regex"),
            insecure: fields.contains_key("insecure"),
            server: text("server"),
            record: text("record"),
            count: text("count"),
            enabled: fields.contains_key("enabled"),
        }
    }

    fn to_input(&self) -> Result<RemoteCheckInput> {
        let Some(kind) = CheckKind::parse(&self.kind) else {
            bail!("choose a kind of check");
        };
        let mut check = Check::new(self.name.trim(), kind, self.target.trim());
        check.timeout_secs = number(&self.timeout_secs, "the timeout")?;
        check.method = optional(&self.method);
        check.body = optional(&self.body);
        check.regex = optional(&self.regex);
        check.insecure = self.insecure.then_some(true);
        check.server = optional(&self.server);
        check.record = optional(&self.record);
        check.count = number(&self.count, "the count")?;
        let interval_secs =
            number(&self.interval_secs, "the interval")?.context("a check needs an interval")?;
        Ok(RemoteCheckInput {
            host_id: self.host_id.clone(),
            check,
            interval_secs,
            enabled: self.enabled,
        })
    }
}

#[derive(Serialize)]
struct ListRow {
    id: i64,
    /// The host it's about, unless that's the server itself.
    host: Option<HostChoice>,
    name: String,
    kind: &'static str,
    target: String,
    interval_secs: u64,
    enabled: bool,
    latest: Option<CheckRow>,
}

#[derive(Deserialize)]
struct ListParams {
    /// Which tab: down or disabled.
    status: Option<String>,
}

#[derive(Serialize)]
struct FilterTab {
    key: &'static str,
    label: &'static str,
    count: usize,
    selected: bool,
}

fn matches(filter: &str, row: &ListRow) -> bool {
    match filter {
        "down" => row.latest.as_ref().is_some_and(|latest| !latest.up),
        "disabled" => !row.enabled,
        _ => true,
    }
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
    token: CsrfToken,
) -> Response {
    let checks = match state.database.list_remote_checks().await {
        Ok(checks) => checks,
        Err(error) => return server_error(&error),
    };
    let latest = state.check_results.all();
    let hosts = host_choices(&state).await;
    let mut rows: Vec<ListRow> = checks
        .into_iter()
        .map(|check| {
            let input = check.input;
            let about_server = input.host_id == LOCAL_HOST_ID;
            let host = hosts.iter().find(|host| host.id == input.host_id);
            ListRow {
                id: check.id,
                host: host.filter(|_| !about_server).cloned(),
                kind: input.check.kind.as_str(),
                latest: latest.get(&input.check.name).and_then(check_row),
                name: input.check.name,
                target: input.check.target,
                interval_secs: input.interval_secs,
                enabled: input.enabled,
            }
        })
        .collect();

    let selected = params.status.as_deref().unwrap_or("all");
    let filters: Vec<FilterTab> = [("all", "All"), ("down", "Down"), ("disabled", "Disabled")]
        .into_iter()
        .map(|(key, label)| FilterTab {
            key,
            label,
            count: rows.iter().filter(|row| matches(key, row)).count(),
            selected: key == selected,
        })
        .collect();
    rows.retain(|row| matches(selected, row));

    Page::new(&state, &token, "remote_checks/index.html")
        .with("checks", &rows)
        .with("filters", &filters)
        .with("host_id", LOCAL_HOST_ID)
        .render()
}

/// A host a check can be about.
#[derive(Serialize, Clone)]
struct HostChoice {
    id: String,
    hostname: String,
}

/// The server itself, then every host with no agent, by name.
async fn host_choices(state: &AppState) -> Vec<HostChoice> {
    let mut agentless: Vec<HostChoice> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|host| host.is_agentless() && host.state == HostState::Approved)
        .map(|host| HostChoice {
            id: host.id,
            hostname: host.hostname,
        })
        .collect();
    agentless.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    let server = HostChoice {
        id: LOCAL_HOST_ID.to_string(),
        hostname: LOCAL_HOSTNAME.to_string(),
    };
    std::iter::once(server).chain(agentless).collect()
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &CheckForm,
    error: Option<&str>,
) -> Response {
    let kinds: Vec<&str> = KINDS.iter().map(|kind| kind.as_str()).collect();
    let page = Page::new(state, token, "remote_checks/form.html")
        .with("id", &id)
        .with("check", form)
        .with("hosts", &host_choices(state).await)
        .with("back", &back_to(&form.host_id))
        .with("kinds", &kinds)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

/// Where a check's form goes when it's done: its host's page, or the list of
/// checks for the server's own.
fn back_to(host_id: &str) -> String {
    if host_id == LOCAL_HOST_ID {
        "/checks".to_string()
    } else {
        format!("/hosts/{host_id}")
    }
}

#[derive(Deserialize)]
struct NewParams {
    /// The host to start with, as its page's link to here gives.
    host: Option<String>,
}

async fn new(
    State(state): State<AppState>,
    Query(params): Query<NewParams>,
    token: CsrfToken,
) -> Response {
    let mut form = CheckForm::blank();
    if let Some(host) = params.host
        && state.agentless_host(&host).await.is_some()
    {
        form.host_id = host;
    }
    form_page(&state, &token, None, &form, None).await
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_remote_check(id).await {
        Ok(Some(check)) => {
            let form = CheckForm::from_input(&check.input);
            form_page(&state, &token, Some(id), &form, None).await
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

async fn validate(state: &AppState, form: &CheckForm, id: Option<i64>) -> Result<RemoteCheckInput> {
    let input = form.to_input()?;
    state.check_remote_check(&input, id).await?;
    Ok(input)
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let fields = CheckForm::from_fields(&form.fields);
    let input = match validate(&state, &fields, None).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, None, &fields, Some(&message)).await;
        }
    };
    match state.database.create_remote_check(&input).await {
        Ok(_) => (form.token, Redirect::to(&back_to(&input.host_id))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let fields = CheckForm::from_fields(&form.fields);
    let input = match validate(&state, &fields, Some(id)).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, Some(id), &fields, Some(&message)).await;
        }
    };
    match state.database.update_remote_check(id, &input).await {
        Ok(true) => (form.token, Redirect::to(&back_to(&input.host_id))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let back = match state.database.get_remote_check(id).await {
        Ok(Some(check)) => back_to(&check.input.host_id),
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    match state.database.delete_remote_check(id).await {
        Ok(true) => (form.token, Redirect::to(&back)).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> RemoteCheckInput {
        let mut check = Check::new("site", CheckKind::Http, "https://example.com/");
        check.timeout_secs = Some(5);
        check.method = Some("POST".to_string());
        check.body = Some("hello".to_string());
        check.regex = Some("Welcome back".to_string());
        check.insecure = Some(true);
        RemoteCheckInput {
            host_id: "5f0c1d6f2a8e4b7790d3c1a2b4e6f809".to_string(),
            check,
            interval_secs: 120,
            enabled: false,
        }
    }

    #[test]
    fn a_check_survives_the_trip_through_its_form() {
        let original = input();
        assert_eq!(
            CheckForm::from_input(&original).to_input().unwrap(),
            original
        );

        let mut dns = Check::new("ns", CheckKind::Dns, "example.com");
        dns.server = Some("8.8.8.8".to_string());
        dns.record = Some("MX".to_string());
        let original = RemoteCheckInput {
            host_id: crate::remote_checks::LOCAL_HOST_ID.to_string(),
            check: dns,
            interval_secs: 60,
            enabled: true,
        };
        assert_eq!(
            CheckForm::from_input(&original).to_input().unwrap(),
            original
        );
    }

    #[test]
    fn empty_options_are_not_set() {
        let mut form = CheckForm::blank();
        form.name = "a".to_string();
        form.target = "https://example.com/".to_string();
        let input = form.to_input().unwrap();
        assert_eq!(input.check.method, None);
        assert_eq!(input.check.insecure, None);
        assert_eq!(input.check.timeout_secs, None);
        input.check.validate().unwrap();
    }

    #[test]
    fn typing_mistakes_are_explained() {
        let mut form = CheckForm::blank();
        form.timeout_secs = "soon".to_string();
        let error = format!("{:#}", form.to_input().unwrap_err());
        assert!(error.contains("the timeout has to be a number"), "{error}");

        let mut form = CheckForm::blank();
        form.interval_secs = String::new();
        let error = format!("{:#}", form.to_input().unwrap_err());
        assert!(error.contains("needs an interval"), "{error}");

        let mut form = CheckForm::blank();
        form.kind = "gopher".to_string();
        assert!(form.to_input().is_err());
    }
}
