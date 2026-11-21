//! The Templates pages, under Settings: the built-in templates and people's own, each
//! with its alerts, metrics and HCL, and the form for adding and changing one's own.
//! The API's `/templates` routes are here too, as they do what the pages do.

use std::collections::BTreeMap;

use anyhow::Result;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::json;

use maxnines_protocol::templates::{Problem, Problems, Template, parse, to_hcl};

use super::template_form::{TemplateForm, field_errors};
use super::{CsrfForm, Page, local_date, server_error};
use crate::alert_conditions::LocalKind;
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::app_state::AppState;
use crate::models::StoredTemplate;
use crate::templates::{Refused, alert_rule as template_values, local_metrics};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/templates", get(index).post(create))
        .route("/templates/new", get(new))
        .route("/templates/new/hcl", get(new_hcl))
        .route("/templates/hcl", post(create_hcl))
        .route("/templates/upgrades/dismiss", post(dismiss_upgrades))
        .route("/templates/{id}", get(show).post(update))
        .route("/templates/{id}/edit", get(edit))
        .route("/templates/{id}/edit/hcl", get(edit_hcl))
        .route("/templates/{id}/hcl", post(update_hcl))
        .route("/templates/{id}/delete", post(delete))
        .route("/templates/{id}/enable", post(enable))
        .route("/templates/{id}/disable", post(disable))
        .route("/templates/{id}/alerts/{rule}/enable", post(enable_alert))
        .route("/templates/{id}/alerts/{rule}/disable", post(disable_alert))
        .route("/templates/{id}/alerts/{rule}/reset", post(reset_alert))
}

/// What the API has of templates.
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/templates", get(api_list).post(api_create))
        .route("/templates/upgrades", get(api_upgrades))
        .route("/templates/upgrades/dismiss", post(api_dismiss_upgrades))
        .route(
            "/templates/{id}",
            get(api_show).put(api_update).delete(api_delete),
        )
        .route("/templates/{id}/enable", post(api_enable))
        .route("/templates/{id}/disable", post(api_disable))
        .route("/templates/{id}/alerts/{key}", put(api_override_alert))
        .route("/templates/{id}/alerts/{key}/reset", post(api_reset_alert))
}

/// What a template runs for, in words.
fn target_words(template: &Template) -> String {
    use maxnines_protocol::templates::Target;
    match &template.target {
        None => "Every host".to_string(),
        Some(Target::Database(kind)) => format!("Each {kind} database"),
        Some(Target::Service(service)) => format!("Hosts with the {service} service"),
        Some(Target::Os(systems)) => {
            let names: Vec<&str> = systems
                .iter()
                .map(|system| {
                    crate::rule_engine::OPERATING_SYSTEMS
                        .iter()
                        .find(|(key, _)| key == system)
                        .map_or(system.as_str(), |(_, name)| name)
                })
                .collect();
            names.join(", ")
        }
    }
}

fn kind_words(kind: LocalKind) -> &'static str {
    match kind {
        LocalKind::Number => "Number",
        LocalKind::Seconds => "Length of time",
        LocalKind::Flag => "Yes or no",
        LocalKind::Unknown => "As the database gives it",
    }
}

#[derive(Serialize)]
struct TemplateRow {
    id: i64,
    name: String,
    key: String,
    description: String,
    target: String,
    built_in: bool,
    enabled: bool,
    alerts: usize,
    upgraded: Option<String>,
    /// Whether people changed any of its alerts.
    changed: bool,
}

async fn rows(state: &AppState) -> Result<Vec<TemplateRow>> {
    let templates = state.database.list_templates().await?;
    let rules = state.database.list_alert_rules().await?;
    Ok(templates
        .into_iter()
        .map(|stored| {
            let mine: Vec<&AlertRule> = rules
                .iter()
                .filter(|rule| rule.template.as_ref().is_some_and(|t| t.id == stored.id))
                .collect();
            TemplateRow {
                id: stored.id,
                name: stored.template.name.clone(),
                key: stored.template.key.clone(),
                description: stored.template.description.clone().unwrap_or_default(),
                target: target_words(&stored.template),
                built_in: stored.built_in,
                enabled: stored.enabled,
                alerts: mine.len(),
                upgraded: stored.upgraded_at.map(local_date),
                changed: mine.iter().any(|rule| {
                    rule.template
                        .as_ref()
                        .is_some_and(|t| !t.overridden.is_empty())
                }),
            }
        })
        .collect())
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    match rows(&state).await {
        Ok(rows) => Page::new(&state, &token, "templates/index.html")
            .with("templates", &rows)
            .render(),
        Err(error) => server_error(&error),
    }
}

/// One of a template's alerts as its page shows it: what's in effect, with what
/// people changed marked and the template's value beside it.
#[derive(Serialize)]
struct AlertRow {
    rule_id: i64,
    key: String,
    name: String,
    warning: String,
    critical: String,
    hold: String,
    summary: String,
    enabled: bool,
    waits_for_agents: bool,
    /// The fields people changed, as the form names them.
    changed: Vec<String>,
    /// The template's own value of each field that was changed.
    template_values: BTreeMap<String, String>,
    /// What else was changed, by label, with the template's value.
    other_changes: Vec<(&'static str, String)>,
}

#[derive(Serialize)]
struct MetricRow {
    name: String,
    short: String,
    kind: &'static str,
    labels: String,
    unit: String,
    description: String,
    from: String,
}

/// What the alert rule form calls a field the API names, for saying what was changed.
pub fn field_label(field: &str) -> &'static str {
    match field {
        "name" => "Name",
        "warning" => "Warning when",
        "critical" => "Critical when",
        "summary" => "Summary",
        "resolved_summary" => "Summary when it clears",
        "for_secs" => "For at least",
        "applies_to" => "Applies to",
        "enabled" => "Enabled",
        "channels" | "all_channels" => "Notify",
        "window_secs" => "Looking back",
        "remind_every_secs" => "Remind every",
        "actions" => "Actions",
        _ => "Other",
    }
}

/// The labels of the fields changed, each once.
pub fn changed_labels(fields: &[String]) -> Vec<&'static str> {
    let mut labels: Vec<&'static str> = Vec::new();
    for field in fields {
        let label = field_label(field);
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

fn field_words(rule: &AlertRuleInput, field: &str) -> String {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    match field {
        "name" => rule.name.clone(),
        "warning" => text(&rule.warning),
        "critical" => text(&rule.critical),
        "summary" => text(&rule.summary),
        "resolved_summary" => text(&rule.resolved_summary),
        "for_secs" => crate::alerting::format_duration(rule.hold),
        "enabled" => if rule.enabled { "on" } else { "off" }.to_string(),
        "window_secs" => rule
            .window
            .map(crate::alerting::format_duration)
            .unwrap_or_default(),
        "all_channels" | "channels" => match rule.all_channels {
            true => "every channel".to_string(),
            false => "the channels chosen".to_string(),
        },
        "applies_to" => text(&rule.applies_to),
        _ => String::new(),
    }
}

fn alert_rows(stored: &StoredTemplate, rules: &[AlertRule]) -> Vec<AlertRow> {
    rules
        .iter()
        .filter_map(|rule| {
            let link = rule.template.as_ref()?;
            let alert = stored
                .template
                .alerts
                .iter()
                .find(|a| a.key == link.alert)?;
            let theirs = template_values(&stored.template, alert).ok()?;
            let own_enabled = !link.overridden.contains(&"enabled".to_string()) && alert.enabled
                || link.overridden.contains(&"enabled".to_string()) && !alert.enabled;
            Some(AlertRow {
                rule_id: rule.id,
                key: link.alert.clone(),
                name: rule.rule.name.clone(),
                warning: rule.rule.warning.clone().unwrap_or_default(),
                critical: rule.rule.critical.clone().unwrap_or_default(),
                hold: crate::alerting::format_duration(rule.rule.hold),
                summary: rule.rule.summary.clone().unwrap_or_default(),
                enabled: own_enabled,
                waits_for_agents: link.waits_for_agents,
                changed: link.overridden.clone(),
                template_values: link
                    .overridden
                    .iter()
                    .map(|field| (field.clone(), field_words(&theirs, field)))
                    .collect(),
                other_changes: {
                    let shown = ["warning", "critical", "name", "for_secs", "enabled"];
                    let others: Vec<String> = link
                        .overridden
                        .iter()
                        .filter(|field| !shown.contains(&field.as_str()))
                        .cloned()
                        .collect();
                    changed_labels(&others)
                        .into_iter()
                        .map(|label| {
                            let field = others
                                .iter()
                                .find(|field| field_label(field) == label)
                                .map_or("", String::as_str);
                            (label, field_words(&theirs, field))
                        })
                        .collect()
                },
            })
        })
        .collect()
}

fn metric_rows(template: &Template) -> Vec<MetricRow> {
    let local = local_metrics(template);
    let detail = |short: &str| {
        template
            .queries
            .iter()
            .flat_map(|query| {
                query
                    .metrics
                    .iter()
                    .map(move |m| (format!("query {}", query.key), m))
            })
            .chain(template.counters.iter().flat_map(|counters| {
                counters
                    .metrics
                    .iter()
                    .map(move |m| (format!("counters {}", counters.key), m))
            }))
            .find(|(_, metric)| metric.key == short)
    };
    let from_query = |short: &str| {
        template.queries.iter().find_map(|query| {
            crate::templates::query_columns_of(template, query)
                .contains(&short.to_string())
                .then(|| format!("query {}", query.key))
        })
    };
    local
        .metrics
        .iter()
        .map(|(short, metric)| {
            let found = detail(short);
            let from = match (short.as_str(), &found) {
                (crate::templates::UP, None) => "the agent".to_string(),
                (_, Some((from, _))) => from_query(short).unwrap_or_else(|| from.clone()),
                (_, None) => from_query(short).unwrap_or_default(),
            };
            let metric_detail = found.map(|(_, m)| m);
            MetricRow {
                name: format!("{}.{short}", local.prefix),
                short: short.clone(),
                kind: kind_words(metric.kind),
                labels: metric.labels.join(", "),
                unit: metric_detail
                    .and_then(|m| m.unit.clone())
                    .unwrap_or_default(),
                description: metric_detail
                    .and_then(|m| m.description.clone())
                    .unwrap_or_default(),
                from,
            }
        })
        .collect()
}

async fn show(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    let loaded = async {
        let Some(stored) = state.database.get_template(id).await? else {
            return Ok(None);
        };
        let rules = state.database.template_rules(&stored).await?;
        anyhow::Ok(Some((stored, rules)))
    };
    let (stored, rules) = match loaded.await {
        Ok(Some(found)) => found,
        Ok(None) => return not_found(&state, &token),
        Err(error) => return server_error(&error),
    };
    Page::new(&state, &token, "templates/show.html")
        .with("id", &stored.id)
        .with("template", &stored.template)
        .with("built_in", &stored.built_in)
        .with("enabled", &stored.enabled)
        .with("target", &target_words(&stored.template))
        .with("upgraded", &stored.upgraded_at.map(local_date))
        .with("source", &stored.source)
        .with("alerts", &alert_rows(&stored, &rules))
        .with("metrics", &metric_rows(&stored.template))
        .render()
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

/// What the CEL fields of the form can suggest of the template's own metrics.
#[derive(Serialize)]
struct LocalSuggestion {
    name: String,
    kind: &'static str,
    labels: Vec<String>,
}

pub(super) fn local_suggestions(template: &Template) -> String {
    let local = local_metrics(template);
    let metrics: Vec<LocalSuggestion> = local
        .metrics
        .iter()
        .map(|(short, metric)| LocalSuggestion {
            name: short.clone(),
            kind: kind_words(metric.kind),
            labels: metric.labels.clone(),
        })
        .collect();
    json!({
        "prefix": local.prefix,
        "metrics": metrics,
        "discovered": crate::templates::discovered_names(template),
    })
    .to_string()
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &TemplateForm,
    problems: &[Problem],
) -> Response {
    let (template, _) = form.to_template();
    let errors = field_errors(problems);
    let page = Page::new(state, token, "templates/form.html")
        .with("id", &id)
        .with("form", form)
        .with("errors", &errors)
        .with("problem_count", &problems.len())
        .with("operating_systems", &crate::rule_engine::OPERATING_SYSTEMS)
        .with("units", &maxnines_protocol::templates::UNITS)
        .with("local_metrics", &local_suggestions(&template));
    match problems.is_empty() {
        true => page.render(),
        false => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
    }
}

async fn hcl_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    hcl: &str,
    error: Option<&str>,
) -> Response {
    let page = Page::new(state, token, "templates/hcl.html")
        .with("id", &id)
        .with("hcl", hcl)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

async fn new(State(state): State<AppState>, token: CsrfToken) -> Response {
    form_page(&state, &token, None, &TemplateForm::blank(), &[]).await
}

async fn new_hcl(State(state): State<AppState>, token: CsrfToken) -> Response {
    let starter = to_hcl(&TemplateForm::blank().to_template().0);
    hcl_page(&state, &token, None, &starter, None).await
}

/// Someone's own template, as they can change it: never a built-in one.
async fn own_template(state: &AppState, id: i64) -> Result<Option<StoredTemplate>> {
    Ok(state
        .database
        .get_template(id)
        .await?
        .filter(|stored| !stored.built_in))
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match own_template(&state, id).await {
        Ok(Some(stored)) => {
            let form = TemplateForm::from_template(&stored.template);
            form_page(&state, &token, Some(id), &form, &[]).await
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

async fn edit_hcl(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    token: CsrfToken,
) -> Response {
    match own_template(&state, id).await {
        Ok(Some(stored)) => hcl_page(&state, &token, Some(id), &stored.source, None).await,
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

/// Where a problem saving goes on the form: a name or key in use is the field's.
fn saving_problem(error: &anyhow::Error) -> Option<Problem> {
    use maxnines_protocol::templates::Place;
    let message = format!("{error:#}");
    match error.downcast_ref::<NameTaken>()? {
        NameTaken::Template(_) => Some(Problem::new(Place::Template, "name", message)),
        NameTaken::TemplateKey(_) => Some(Problem::new(Place::Template, "key", message)),
        NameTaken::AlertRule(name) => Some(Problem::new(
            Place::Template,
            "",
            format!("an alert rule is already called {name:?}: give the alert another name"),
        )),
        _ => None,
    }
}

/// Saves a template that's been checked, as new or over `id`.
async fn save(
    state: &AppState,
    id: Option<i64>,
    template: &Template,
    source: &str,
) -> Result<Option<i64>> {
    let now = crate::times::now();
    match id {
        None => state
            .database
            .create_template(template, source, now)
            .await
            .map(Some),
        Some(id) => Ok(state
            .database
            .update_template(id, template, source, now)
            .await?
            .then_some(id)),
    }
}

async fn save_form(state: AppState, id: Option<i64>, form: CsrfForm) -> Response {
    let mut fields = TemplateForm::from_fields(&form.fields);
    let action = form.fields.get("form_action").cloned().unwrap_or_default();
    if fields.apply_action(&action) {
        return form_page(&state, &form.token, id, &fields, &[]).await;
    }
    let (template, mut problems) = fields.to_template();
    match state.check_template(&template).await {
        Ok(found) => problems.extend(found),
        Err(error) => return server_error(&error),
    }
    if !problems.is_empty() {
        return form_page(&state, &form.token, id, &fields, &problems).await;
    }
    let source = to_hcl(&template);
    match save(&state, id, &template, &source).await {
        Ok(Some(id)) => (form.token, Redirect::to(&format!("/templates/{id}"))).into_response(),
        Ok(None) => not_found(&state, &form.token),
        Err(error) => match saving_problem(&error) {
            Some(problem) => form_page(&state, &form.token, id, &fields, &[problem]).await,
            None => server_error(&error),
        },
    }
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    save_form(state, None, form).await
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match own_template(&state, id).await {
        Ok(Some(_)) => save_form(state, Some(id), form).await,
        Ok(None) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

/// Reads and checks a template's HCL, saying everything wrong with it.
async fn checked(state: &AppState, hcl: &str) -> Result<Result<Template, String>> {
    let template = match parse(hcl) {
        Ok(template) => template,
        Err(error) => return Ok(Err(format!("{error:#}"))),
    };
    let problems = state.check_template(&template).await?;
    Ok(match problems.is_empty() {
        true => Ok(template),
        false => Err(Problems::new(&template, problems).described.join("\n")),
    })
}

async fn save_hcl(state: AppState, id: Option<i64>, form: CsrfForm) -> Response {
    let hcl = form
        .fields
        .get("hcl")
        .cloned()
        .unwrap_or_default()
        .replace("\r\n", "\n");
    let template = match checked(&state, &hcl).await {
        Ok(Ok(template)) => template,
        Ok(Err(message)) => return hcl_page(&state, &form.token, id, &hcl, Some(&message)).await,
        Err(error) => return server_error(&error),
    };
    match save(&state, id, &template, &hcl).await {
        Ok(Some(id)) => (form.token, Redirect::to(&format!("/templates/{id}"))).into_response(),
        Ok(None) => not_found(&state, &form.token),
        Err(error) => match saving_problem(&error) {
            Some(problem) => {
                let message = problem.describe(&template);
                hcl_page(&state, &form.token, id, &hcl, Some(&message)).await
            }
            None => server_error(&error),
        },
    }
}

async fn create_hcl(State(state): State<AppState>, form: CsrfForm) -> Response {
    save_hcl(state, None, form).await
}

async fn update_hcl(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    match own_template(&state, id).await {
        Ok(Some(_)) => save_hcl(state, Some(id), form).await,
        Ok(None) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state
        .database
        .delete_template(id, crate::times::now())
        .await
    {
        Ok(true) => (form.token, Redirect::to("/templates")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) if error.is::<Refused>() => {
            (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response()
        }
        Err(error) => server_error(&error),
    }
}

/// Back to where the button was: the list, or the template's page.
fn back(form: &CsrfForm, id: i64) -> String {
    match form.fields.get("back").map(String::as_str) {
        Some("list") => "/templates".to_string(),
        _ => format!("/templates/{id}"),
    }
}

async fn turn(state: &AppState, id: i64, enabled: bool, form: CsrfForm) -> Response {
    match state
        .database
        .set_template_enabled(id, enabled, crate::times::now())
        .await
    {
        Ok(true) => (form.token.clone(), Redirect::to(&back(&form, id))).into_response(),
        Ok(false) => not_found(state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn enable(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    turn(&state, id, true, form).await
}

async fn disable(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    turn(&state, id, false, form).await
}

/// Turns one of a template's alerts on or off, as something changed of it.
async fn turn_alert(state: &AppState, id: i64, rule_id: i64, enabled: bool) -> Result<bool> {
    let Some((stored, _, _, own)) = state.database.template_rule(rule_id).await? else {
        return Ok(false);
    };
    if stored.id != id {
        return Ok(false);
    }
    let wanted = AlertRuleInput { enabled, ..own };
    state
        .database
        .override_template_rule(rule_id, &wanted, crate::times::now())
        .await
}

async fn enable_alert(
    State(state): State<AppState>,
    Path((id, rule)): Path<(i64, i64)>,
    form: CsrfForm,
) -> Response {
    match turn_alert(&state, id, rule, true).await {
        Ok(true) => (form.token, Redirect::to(&format!("/templates/{id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn disable_alert(
    State(state): State<AppState>,
    Path((id, rule)): Path<(i64, i64)>,
    form: CsrfForm,
) -> Response {
    match turn_alert(&state, id, rule, false).await {
        Ok(true) => (form.token, Redirect::to(&format!("/templates/{id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn reset_alert(
    State(state): State<AppState>,
    Path((id, rule)): Path<(i64, i64)>,
    form: CsrfForm,
) -> Response {
    let reset = async {
        match state.database.template_rule(rule).await? {
            Some((stored, ..)) if stored.id == id => {
                state
                    .database
                    .reset_template_rule(rule, crate::times::now())
                    .await
            }
            _ => Ok(false),
        }
    };
    let to = match form.fields.get("back").map(String::as_str) {
        Some("rule") => format!("/alerts/rules/{rule}/edit"),
        _ => format!("/templates/{id}"),
    };
    match reset.await {
        Ok(true) => (form.token, Redirect::to(&to)).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn dismiss_upgrades(State(state): State<AppState>, form: CsrfForm) -> Response {
    match state.dismiss_template_upgrades().await {
        Ok(()) => {
            let to = form
                .fields
                .get("back")
                .cloned()
                .unwrap_or_else(|| "/templates".to_string());
            // Only somewhere on this site.
            let to = if to.starts_with('/') && !to.starts_with("//") {
                to
            } else {
                "/templates".to_string()
            };
            (form.token, Redirect::to(&to)).into_response()
        }
        Err(error) => server_error(&error),
    }
}

// The API.

fn refused(error: &anyhow::Error) -> Response {
    let body = Json(json!({ "error": format!("{error:#}") }));
    (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
}

/// A template as the API lists it.
#[derive(Serialize)]
struct TemplateSummary {
    id: i64,
    key: String,
    name: String,
    description: Option<String>,
    built_in: bool,
    enabled: bool,
    target: Option<maxnines_protocol::templates::Target>,
    created_at: crate::times::Timestamp,
    updated_at: crate::times::Timestamp,
    upgraded_at: Option<crate::times::Timestamp>,
    /// Whether people changed any of its alerts.
    changed: bool,
}

fn summary(stored: &StoredTemplate, rules: &[AlertRule]) -> TemplateSummary {
    TemplateSummary {
        id: stored.id,
        key: stored.template.key.clone(),
        name: stored.template.name.clone(),
        description: stored.template.description.clone(),
        built_in: stored.built_in,
        enabled: stored.enabled,
        target: stored.template.target.clone(),
        created_at: stored.created_at,
        updated_at: stored.updated_at,
        upgraded_at: stored.upgraded_at,
        changed: rules.iter().any(|rule| {
            rule.template
                .as_ref()
                .is_some_and(|t| t.id == stored.id && !t.overridden.is_empty())
        }),
    }
}

async fn api_list(State(state): State<AppState>) -> Response {
    let loaded = async {
        let templates = state.database.list_templates().await?;
        let rules = state.database.list_alert_rules().await?;
        anyhow::Ok(
            templates
                .iter()
                .map(|stored| summary(stored, &rules))
                .collect::<Vec<_>>(),
        )
    };
    match loaded.await {
        Ok(list) => Json(list).into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

/// One of a template's alerts as the API shows it: the rule in effect, with the
/// template's values beside it.
#[derive(Serialize)]
struct AlertView {
    key: String,
    rule: AlertRule,
    template_values: AlertRuleInput,
}

#[derive(Serialize)]
struct MetricView {
    name: String,
    kind: &'static str,
    labels: Vec<String>,
}

async fn api_show(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let loaded = async {
        let Some(stored) = state.database.get_template(id).await? else {
            return Ok(None);
        };
        let rules = state.database.template_rules(&stored).await?;
        let alerts: Vec<AlertView> = rules
            .iter()
            .filter_map(|rule| {
                let key = rule.template.as_ref()?.alert.clone();
                let alert = stored.template.alerts.iter().find(|a| a.key == key)?;
                Some(AlertView {
                    template_values: template_values(&stored.template, alert).ok()?,
                    key,
                    rule: rule.clone(),
                })
            })
            .collect();
        let local = local_metrics(&stored.template);
        let metrics: Vec<MetricView> = local
            .metrics
            .iter()
            .map(|(short, metric)| MetricView {
                name: format!("{}.{short}", local.prefix),
                kind: match metric.kind {
                    LocalKind::Number => "number",
                    LocalKind::Seconds => "seconds",
                    LocalKind::Flag => "flag",
                    LocalKind::Unknown => "unknown",
                },
                labels: metric.labels.clone(),
            })
            .collect();
        let mut view = serde_json::to_value(summary(&stored, &rules))?;
        view["hcl"] = json!(stored.source);
        view["template"] = serde_json::to_value(&stored.template)?;
        view["metrics"] = serde_json::to_value(metrics)?;
        view["alerts"] = serde_json::to_value(alerts)?;
        anyhow::Ok(Some(view))
    };
    match loaded.await {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

#[derive(Deserialize)]
struct HclInput {
    hcl: String,
}

async fn api_save(state: &AppState, id: Option<i64>, hcl: &str) -> Response {
    let template = match checked(state, hcl).await {
        Ok(Ok(template)) => template,
        Ok(Err(message)) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": message })),
            )
                .into_response();
        }
        Err(error) => return super::api::server_error(&error),
    };
    if let Some(id) = id {
        match state.database.get_template(id).await {
            Ok(Some(stored)) if stored.built_in => {
                return refused(&anyhow::anyhow!(Refused(
                    "a built-in template can't be changed, as upgrades replace it: disable it, or change its alerts".to_string()
                )));
            }
            Ok(Some(_)) => {}
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(error) => return super::api::server_error(&error),
        }
    }
    match save(state, id, &template, hcl).await {
        Ok(Some(saved)) if id.is_none() => {
            (StatusCode::CREATED, Json(json!({ "id": saved }))).into_response()
        }
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() || error.is::<Refused>() => refused(&error),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_create(State(state): State<AppState>, Json(input): Json<HclInput>) -> Response {
    api_save(&state, None, &input.hcl).await
}

async fn api_update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(input): Json<HclInput>,
) -> Response {
    api_save(&state, Some(id), &input.hcl).await
}

async fn api_delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state
        .database
        .delete_template(id, crate::times::now())
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<Refused>() => refused(&error),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_turn(state: &AppState, id: i64, enabled: bool) -> Response {
    match state
        .database
        .set_template_enabled(id, enabled, crate::times::now())
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_enable(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    api_turn(&state, id, true).await
}

async fn api_disable(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    api_turn(&state, id, false).await
}

/// The rule one of a template's alerts is, by the alert's key.
async fn rule_of(state: &AppState, id: i64, key: &str) -> Result<Option<i64>> {
    let Some(stored) = state.database.get_template(id).await? else {
        return Ok(None);
    };
    let rules = state.database.template_rules(&stored).await?;
    Ok(rules
        .iter()
        .find(|rule| rule.template.as_ref().is_some_and(|t| t.alert == key))
        .map(|rule| rule.id))
}

async fn api_override_alert(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    let rule = match rule_of(&state, id, &key).await {
        Ok(Some(rule)) => rule,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return super::api::server_error(&error),
    };
    if let Err(error) = state.check_saved_alert_rule(rule, &input).await {
        return refused(&error);
    }
    match state
        .database
        .override_template_rule(rule, &input, crate::times::now())
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() || error.is::<Refused>() => refused(&error),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_reset_alert(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
) -> Response {
    let reset = async {
        let Some(rule) = rule_of(&state, id, &key).await? else {
            return Ok(false);
        };
        state
            .database
            .reset_template_rule(rule, crate::times::now())
            .await
    };
    match reset.await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_upgrades(State(state): State<AppState>) -> Response {
    match state.database.template_upgrades().await {
        Ok(names) => Json(json!({ "templates": names })).into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_dismiss_upgrades(State(state): State<AppState>) -> Response {
    match state.dismiss_template_upgrades().await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}
