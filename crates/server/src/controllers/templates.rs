//! The Templates pages, under Settings: the built-in templates and people's own, each
//! with its alerts, metrics and HCL, and the form for adding and changing one's own.
//! The API's `/templates` routes are here too, as they do what the pages do.

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
use super::{CsrfForm, Page, local_date, local_time, server_error};
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::app_state::AppState;
use crate::metrics::{INSTANCE_LABEL, Kind};
use crate::models::{Imported, Origin, Part, PartKind, StoredTemplate, TemplateAlert};
use crate::templates::{Refused, metrics_of};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/templates", get(index).post(create))
        .route("/templates/new", get(new))
        .route("/templates/new/hcl", get(new_hcl))
        .route("/templates/hcl", post(create_hcl))
        .route("/templates/import", get(import_page).post(import))
        .route("/templates/{id}/export", get(export))
        .route("/templates/upgrades/dismiss", post(dismiss_upgrades))
        .route("/templates/{id}", get(show).post(update))
        .route("/templates/{id}/edit", get(edit))
        .route("/templates/{id}/edit/hcl", get(edit_hcl))
        .route("/templates/{id}/hcl", post(update_hcl))
        .route("/templates/{id}/delete", post(delete))
        .route("/templates/{id}/enable", post(enable))
        .route("/templates/{id}/disable", post(disable))
        .route("/templates/{id}/follow", post(follow))
        .route("/templates/{id}/hosts", post(set_hosts))
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
        .route("/templates/import", post(api_import))
        .route("/templates/{id}/export", get(api_export))
        .route(
            "/templates/{id}",
            get(api_show).put(api_update).delete(api_delete),
        )
        .route("/templates/{id}/enable", post(api_enable))
        .route("/templates/{id}/disable", post(api_disable))
        .route("/templates/{id}/follow", post(api_follow))
        .route("/templates/{id}/hosts", put(api_set_hosts))
        .route(
            "/templates/{id}/alerts/{key}",
            put(api_override_alert).delete(api_reset_alert),
        )
        .route("/templates/{id}/alerts/{key}/reset", post(api_reset_alert))
        .route("/templates/{id}/runs", get(api_runs))
        .route("/hosts/{id}/templates", get(api_host_runs))
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

fn kind_words(kind: Kind) -> &'static str {
    match kind {
        Kind::Number => "Number",
        Kind::Seconds => "Length of time",
        Kind::Flag => "Yes or no",
        Kind::Unknown => "As the database gives it",
    }
}

/// One of a template's metrics, as the pages and the API show it.
struct OwnMetric {
    /// Its name within the template: `lag` for `postgres.lag`.
    short: String,
    name: String,
    kind: Kind,
    /// The labels its series have besides what the template runs for, which are
    /// what `labels.` gives a summary.
    labels: Vec<String>,
}

/// A template's metrics, in order of name.
fn own_metrics(template: &Template) -> Vec<OwnMetric> {
    let mut metrics: Vec<OwnMetric> = metrics_of(template)
        .into_iter()
        .map(|(metric, _)| OwnMetric {
            short: crate::alerting::short_name(&metric, &template.key).to_string(),
            kind: metric.kind,
            labels: metric
                .labels()
                .iter()
                .filter(|label| *label != INSTANCE_LABEL)
                .cloned()
                .collect(),
            name: metric.name,
        })
        .collect();
    metrics.sort_by(|a, b| a.short.cmp(&b.short));
    metrics
}

#[derive(Serialize)]
struct TemplateRow {
    id: i64,
    name: String,
    key: String,
    description: String,
    target: String,
    origin: &'static str,
    /// Whether it's a built-in or imported one, which isn't edited.
    original: bool,
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
                origin: stored.origin.as_str(),
                original: stored.origin.is_original(),
                enabled: stored.enabled,
                alerts: mine.len(),
                upgraded: stored.upgraded_at.map(local_date),
                changed: mine.iter().any(|rule| {
                    rule.template
                        .as_ref()
                        .is_some_and(|t| t.replaces_id.is_some())
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

/// One of a template's alerts as its page shows it: the rule in use, and where
/// that's someone's own copy, the built-in template's rule beside it.
#[derive(Serialize)]
struct AlertRow {
    /// The rule in use.
    rule_id: i64,
    key: String,
    name: String,
    warning: String,
    critical: String,
    hold: String,
    enabled: bool,
    /// Whether someone chose that, rather than the template shipping it so.
    enabled_chosen: bool,
    /// Whether it's only for the databases where discovery found what its `when`
    /// or `since` says.
    picks_by_discovery: bool,
    /// The built-in template's own rule, when the one in use is someone's copy.
    built_in: Option<BuiltInValues>,
    /// When an upgrade last changed the built-in rule under someone's copy.
    built_in_changed: Option<String>,
}

/// What a built-in template's own rule says, for comparing with someone's copy.
#[derive(Serialize)]
pub(super) struct BuiltInValues {
    name: String,
    warning: String,
    critical: String,
    hold: String,
    summary: String,
    resolved_summary: String,
}

impl BuiltInValues {
    pub(super) fn of(rule: &AlertRuleInput) -> Self {
        let text = |value: &Option<String>| value.clone().unwrap_or_default();
        Self {
            name: rule.name.clone(),
            warning: text(&rule.warning),
            critical: text(&rule.critical),
            hold: crate::alerting::format_duration(rule.hold),
            summary: text(&rule.summary),
            resolved_summary: text(&rule.resolved_summary),
        }
    }
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

fn alert_rows(alerts: &[TemplateAlert]) -> Vec<AlertRow> {
    alerts
        .iter()
        .map(|alert| {
            let rule = alert.in_use();
            AlertRow {
                rule_id: rule.id,
                key: alert.key.clone(),
                name: rule.rule.name.clone(),
                warning: rule.rule.warning.clone().unwrap_or_default(),
                critical: rule.rule.critical.clone().unwrap_or_default(),
                hold: crate::alerting::format_duration(rule.rule.hold),
                enabled: rule.rule.enabled,
                enabled_chosen: alert
                    .rule
                    .template
                    .as_ref()
                    .is_some_and(|link| link.enabled_choice.is_some()),
                picks_by_discovery: rule.picks_by_discovery(),
                built_in: alert
                    .copy
                    .as_ref()
                    .map(|_| BuiltInValues::of(&alert.rule.rule)),
                built_in_changed: alert
                    .copy
                    .as_ref()
                    .and_then(|copy| copy.template.as_ref()?.original_changed_at)
                    .map(local_date),
            }
        })
        .collect()
}

/// One of a template's discover blocks, queries or counters blocks, as its page
/// lists it: as it runs, with what someone made of it.
#[derive(Serialize)]
struct PartRow {
    /// `discover`, `query` or `counters`.
    kind: &'static str,
    /// What its address calls its kind: `discover`, `queries` or `counters`.
    segment: &'static str,
    key: String,
    /// The SQL it runs, the counter set it reads, or what it looks for.
    reads: String,
    every: String,
    when: String,
    since: String,
    /// The metrics it says more about, by their short names.
    metrics: Vec<String>,
    enabled: bool,
    turns_off: bool,
    /// Whether someone has their own copy of it, used in its place.
    copied: bool,
    /// Whether someone chose it on or off, rather than the template.
    enabled_chosen: bool,
    /// When a newer version changed the template's own, under someone's copy.
    changed: Option<String>,
    /// What the template's own says it reads, when someone has a copy.
    comes_as: String,
}

/// What a part reads, in short.
fn reads(part: &Part) -> String {
    match part {
        Part::Discover(discover) => {
            let mut said = Vec::new();
            said.extend(discover.sql.clone());
            said.extend(discover.registry.iter().map(|read| {
                let names: Vec<&str> = read.values.values().map(String::as_str).collect();
                format!("{}: {}", read.key, names.join(", "))
            }));
            said.extend(
                discover
                    .counter_sets
                    .values()
                    .map(|set| format!("whether there's a {set} counter set")),
            );
            said.join("\n")
        }
        Part::Query(query) => query.sql.clone(),
        Part::Counters(counters) => counters.object.clone(),
    }
}

/// Where a template runs, as a page lists it.
#[derive(Serialize)]
pub(super) struct RunRow {
    host_id: String,
    hostname: String,
    template_id: i64,
    template_name: String,
    /// The database, or empty for the host itself.
    database: String,
    /// What discovery found, `name = value`.
    found: Vec<String>,
    /// What's read there now, as `query sessions`.
    reads: Vec<String>,
    errors: Vec<RunErrorRow>,
}

#[derive(Serialize)]
pub(super) struct RunErrorRow {
    part: String,
    message: String,
    since: String,
}

/// The most places a page lists that a template runs.
pub(super) const MOST_RUNS: usize = 100;

/// Where templates run, as a page lists it, those going wrong first, and how many
/// more there are than it lists.
pub(super) async fn run_rows(
    state: &AppState,
    host_id: Option<&str>,
    template_id: Option<i64>,
) -> Result<(Vec<RunRow>, usize)> {
    let runs = crate::templates::runs::runs(state, host_id, template_id).await?;
    let more = runs.len().saturating_sub(MOST_RUNS);
    let rows = runs
        .into_iter()
        .take(MOST_RUNS)
        .map(|run| {
            let mut reads: Vec<String> = Vec::new();
            reads.extend(run.discover.iter().map(|key| format!("discover {key}")));
            reads.extend(run.queries.iter().map(|key| format!("query {key}")));
            reads.extend(run.counters.iter().map(|key| format!("counters {key}")));
            RunRow {
                host_id: run.host_id,
                hostname: run.hostname,
                template_id: run.template_id,
                template_name: run.template_name,
                database: run.database.unwrap_or_default(),
                found: run
                    .found
                    .iter()
                    .map(|(name, value)| match value {
                        serde_json::Value::String(text) => format!("{name} = {text}"),
                        value => format!("{name} = {value}"),
                    })
                    .collect(),
                reads,
                errors: run
                    .errors
                    .into_iter()
                    .map(|error| RunErrorRow {
                        part: error.part,
                        message: error.message,
                        since: local_time(error.since),
                    })
                    .collect(),
            }
        })
        .collect();
    Ok((rows, more))
}

async fn api_runs(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state.database.get_template(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return super::api::server_error(&error),
    }
    match crate::templates::runs::runs(&state, None, Some(id)).await {
        Ok(runs) => Json(runs).into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_host_runs(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match crate::templates::runs::runs(&state, Some(&id), None).await {
        Ok(runs) => Json(runs).into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

/// A card of a template's page listing one kind of its parts.
#[derive(Serialize)]
struct PartSection {
    title: &'static str,
    hint: &'static str,
    rows: Vec<PartRow>,
}

fn part_sections(stored: &StoredTemplate, as_run: &Template) -> Vec<PartSection> {
    let mut rows = part_rows(stored, as_run);
    let mut take = |kind: PartKind| {
        let (these, rest) = rows.drain(..).partition(|row| row.kind == kind.as_str());
        rows = rest;
        these
    };
    vec![
        PartSection {
            title: "Discovery",
            hint: "Each discover block runs first, then every interval. What they find is what \
                queries' and alerts' conditions look at. A discover block can be changed but \
                not turned off, as what it finds is waited on.",
            rows: take(PartKind::Discover),
        },
        PartSection {
            title: "Queries",
            hint: "Each column becomes a metric.",
            rows: take(PartKind::Query),
        },
        PartSection {
            title: "Performance counters",
            hint: "Read on Windows hosts.",
            rows: take(PartKind::Counters),
        },
    ]
}

fn part_rows(stored: &StoredTemplate, as_run: &Template) -> Vec<PartRow> {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let mut parts: Vec<Part> = Vec::new();
    parts.extend(as_run.discover.iter().cloned().map(Part::Discover));
    parts.extend(as_run.queries.iter().cloned().map(Part::Query));
    parts.extend(as_run.counters.iter().cloned().map(Part::Counters));
    parts
        .into_iter()
        .map(|part| {
            let kind = part.kind();
            let choice = stored
                .choices
                .iter()
                .find(|choice| choice.kind == kind && choice.key == part.key());
            let copied = choice.is_some_and(|choice| choice.copied);
            let comes_as = match copied {
                true => Part::of(&stored.template, kind, part.key())
                    .map(|(_, own)| reads(&own))
                    .unwrap_or_default(),
                false => String::new(),
            };
            let (every, when, since, metrics, enabled) = match &part {
                Part::Discover(discover) => (
                    discover
                        .interval
                        .clone()
                        .unwrap_or_else(|| "1h".to_string()),
                    String::new(),
                    String::new(),
                    Vec::new(),
                    true,
                ),
                Part::Query(query) => (
                    text(&query.interval),
                    text(&query.when),
                    text(&query.since),
                    query.metrics.iter().map(|m| m.key.clone()).collect(),
                    query.enabled,
                ),
                Part::Counters(counters) => (
                    text(&counters.interval),
                    text(&counters.when),
                    text(&counters.since),
                    counters.metrics.iter().map(|m| m.key.clone()).collect(),
                    counters.enabled,
                ),
            };
            PartRow {
                kind: kind.as_str(),
                segment: match kind {
                    PartKind::Discover => "discover",
                    PartKind::Query => "queries",
                    PartKind::Counters => "counters",
                },
                key: part.key().to_string(),
                reads: reads(&part),
                every,
                when,
                since,
                metrics,
                enabled,
                turns_off: kind.turns_off(),
                copied,
                enabled_chosen: choice.is_some_and(|choice| choice.enabled_choice.is_some()),
                changed: choice
                    .and_then(|choice| choice.original_changed_at)
                    .map(local_date),
                comes_as,
            }
        })
        .collect()
}

fn metric_rows(template: &Template) -> Vec<MetricRow> {
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
    own_metrics(template)
        .into_iter()
        .map(|metric| {
            let short = &metric.short;
            let found = detail(short);
            let from = match (short.as_str(), &found) {
                (crate::templates::UP, None) => "the agent".to_string(),
                (_, Some((from, _))) => from_query(short).unwrap_or_else(|| from.clone()),
                (_, None) => from_query(short).unwrap_or_default(),
            };
            let metric_detail = found.map(|(_, m)| m);
            MetricRow {
                name: metric.name.clone(),
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
    show_page(&state, &token, id, None).await
}

/// What was typed into the Hosts form, shown again with what's wrong with it.
struct HostsTyped {
    applies_to: String,
    host_ids: Vec<String>,
    error: String,
}

async fn show_page(
    state: &AppState,
    token: &CsrfToken,
    id: i64,
    typed: Option<HostsTyped>,
) -> Response {
    let loaded = async {
        let Some(stored) = state.database.get_template(id).await? else {
            return Ok(None);
        };
        let alerts = state.database.template_alerts(stored.id).await?;
        let runs = run_rows(state, None, Some(stored.id)).await?;
        let as_run = state
            .database
            .template_as_run(stored.id)
            .await?
            .unwrap_or_else(|| stored.template.clone());
        anyhow::Ok(Some((stored, alerts, as_run, runs)))
    };
    let (stored, alerts, as_run, (runs, more_runs)) = match loaded.await {
        Ok(Some(found)) => found,
        Ok(None) => return not_found(state, token),
        Err(error) => return server_error(&error),
    };
    let given = typed
        .as_ref()
        .map_or(&stored.host_ids, |typed| &typed.host_ids);
    let hosts = host_choices(state, given).await;
    let applies_to = typed.as_ref().map_or(stored.applies_to.clone(), |typed| {
        Some(typed.applies_to.clone())
    });
    let page = Page::new(state, token, "templates/show.html")
        .with("id", &stored.id)
        .with("template", &stored.template)
        .with("origin", stored.origin.as_str())
        .with("original", &stored.origin.is_original())
        .with("enabled", &stored.enabled)
        .with("enabled_choice", &stored.enabled_choice.is_some())
        .with("target", &target_words(&stored.template))
        .with("applies_to", &applies_to)
        .with(
            "hosts_error",
            &typed.as_ref().map(|typed| typed.error.as_str()),
        )
        .with("applies_to_chosen", &stored.applies_to_chosen)
        .with("ships_applies_to", &stored.template.applies_to)
        .with("hosts", &hosts)
        .with(
            "given_hosts",
            &hosts
                .iter()
                .filter(|host| host.given)
                .map(|host| host.hostname.as_str())
                .collect::<Vec<_>>(),
        )
        .with("upgraded", &stored.upgraded_at.map(local_date))
        .with("source", &stored.hcl())
        .with("alerts", &alert_rows(&alerts))
        .with("part_sections", &part_sections(&stored, &as_run))
        .with("runs", &runs)
        .with("more_runs", &more_runs)
        .with("metrics", &metric_rows(&as_run));
    match typed {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

/// A host the template's page can give it by hand.
#[derive(Serialize)]
struct HostChoice {
    id: String,
    hostname: String,
    given: bool,
}

async fn host_choices(state: &AppState, given: &[String]) -> Vec<HostChoice> {
    let mut hosts: Vec<HostChoice> = state
        .registry
        .list()
        .await
        .into_iter()
        .map(|host| HostChoice {
            given: given.contains(&host.id),
            id: host.id,
            hostname: host.hostname,
        })
        .collect();
    hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.id.cmp(&b.id)));
    hosts
}

/// Which hosts a template is for, as a page or the API asks: the condition, which
/// has to be CEL, and hosts that have to be there. Says what's wrong otherwise.
async fn save_hosts(
    state: &AppState,
    id: i64,
    applies_to: Option<String>,
    host_ids: Vec<String>,
) -> Result<Result<bool, String>> {
    let applies_to = applies_to
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());
    if let Some(text) = &applies_to
        && let Err(error) = crate::rule_engine::Condition::compile(text)
    {
        return Ok(Err(format!("applies_to isn't CEL: {error}")));
    }
    let known = state.registry.list().await;
    let mut given = std::collections::BTreeSet::new();
    for host_id in host_ids {
        if !known.iter().any(|host| host.id == host_id) {
            return Ok(Err(format!("there's no host {host_id:?}")));
        }
        given.insert(host_id);
    }
    Ok(Ok(state
        .database
        .set_template_hosts(id, applies_to, &given, crate::times::now())
        .await?))
}

async fn set_hosts(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let applies_to = form.fields.get("applies_to").cloned();
    let host_ids: Vec<String> = form
        .fields
        .iter()
        .filter_map(|(name, value)| {
            (value == "on").then(|| name.strip_prefix("host.").map(str::to_string))?
        })
        .collect();
    match save_hosts(&state, id, applies_to.clone(), host_ids.clone()).await {
        Ok(Ok(true)) => (
            form.token.clone(),
            Redirect::to(&format!("/templates/{id}")),
        )
            .into_response(),
        Ok(Ok(false)) => not_found(&state, &form.token),
        Ok(Err(error)) => {
            let typed = HostsTyped {
                applies_to: applies_to.unwrap_or_default(),
                host_ids,
                error,
            };
            show_page(&state, &form.token, id, Some(typed)).await
        }
        Err(error) => server_error(&error),
    }
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
    let metrics: Vec<LocalSuggestion> = own_metrics(template)
        .into_iter()
        .map(|metric| LocalSuggestion {
            name: metric.short,
            kind: kind_words(metric.kind),
            labels: metric.labels,
        })
        .collect();
    json!({
        "prefix": template.key,
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
        .with("part_only", &false)
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
        .filter(|stored| stored.origin == Origin::Own))
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
        Ok(Some(stored)) => hcl_page(&state, &token, Some(id), &stored.hcl(), None).await,
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
async fn save(state: &AppState, id: Option<i64>, template: &Template) -> Result<Option<i64>> {
    let now = crate::times::now();
    match id {
        None => state
            .database
            .create_template(template, now)
            .await
            .map(Some),
        Some(id) => Ok(state
            .database
            .update_template(id, template, now)
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
    match save(&state, id, &template).await {
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
    match save(&state, id, &template).await {
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

async fn follow(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state
        .database
        .follow_template_enabled(id, crate::times::now())
        .await
    {
        Ok(true) => (form.token.clone(), Redirect::to(&back(&form, id))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn enable(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    turn(&state, id, true, form).await
}

async fn disable(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    turn(&state, id, false, form).await
}

/// Turns one of a template's alerts on or off: the rule in use, which for a
/// built-in template's own rule is only its flag.
async fn turn_alert(state: &AppState, id: i64, rule_id: i64, enabled: bool) -> Result<bool> {
    let Some(found) = state.database.template_rule(rule_id).await? else {
        return Ok(false);
    };
    if found.template.id != id {
        return Ok(false);
    }
    let in_use = found.copy.unwrap_or(found.original);
    let Some(rule) = state.database.get_alert_rule(in_use).await? else {
        return Ok(false);
    };
    let wanted = AlertRuleInput {
        enabled,
        ..rule.rule
    };
    state.database.update_template_rule(in_use, &wanted).await
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
            Some(found) if found.template.id == id => {
                state
                    .database
                    .reset_template_rule(rule, crate::times::now())
                    .await
            }
            _ => Ok(false),
        }
    };
    let to = format!("/templates/{id}");
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
    /// `built_in`, `imported` or `own`.
    origin: Origin,
    enabled: bool,
    /// What someone chose for a built-in or imported one, or nothing while it
    /// follows what the template ships.
    enabled_choice: Option<bool>,
    target: Option<maxnines_protocol::templates::Target>,
    /// CEL over a host's facts saying which hosts it's for: someone's choice for a
    /// built-in or imported one, or what the template says.
    applies_to: Option<String>,
    /// Whether that's someone's choice.
    applies_to_chosen: bool,
    /// The hosts given it by hand, on top of those `applies_to` picks.
    host_ids: Vec<String>,
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
        origin: stored.origin,
        enabled: stored.enabled,
        enabled_choice: stored.enabled_choice,
        target: stored.template.target.clone(),
        applies_to: stored.applies_to.clone(),
        applies_to_chosen: stored.applies_to_chosen,
        host_ids: stored.host_ids.clone(),
        created_at: stored.created_at,
        updated_at: stored.updated_at,
        upgraded_at: stored.upgraded_at,
        changed: rules.iter().any(|rule| {
            rule.template
                .as_ref()
                .is_some_and(|t| t.id == stored.id && t.replaces_id.is_some())
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

/// One of a template's alerts as the API shows it: the rule in use, and where
/// that's someone's own copy, the built-in template's rule beside it.
#[derive(Serialize)]
struct AlertView {
    key: String,
    rule: AlertRule,
    built_in_rule: Option<AlertRule>,
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
        let rules = state.database.list_alert_rules().await?;
        let alerts: Vec<AlertView> = state
            .database
            .template_alerts(stored.id)
            .await?
            .into_iter()
            .map(|alert| AlertView {
                rule: alert.in_use().clone(),
                built_in_rule: alert.copy.is_some().then_some(alert.rule),
                key: alert.key,
            })
            .collect();
        let metrics = metric_views(&stored.template);
        let mut view = serde_json::to_value(summary(&stored, &rules))?;
        view["hcl"] = json!(stored.hcl());
        view["template"] = serde_json::to_value(&stored.template)?;
        view["metrics"] = serde_json::to_value(metrics)?;
        view["alerts"] = serde_json::to_value(alerts)?;
        view["choices"] = serde_json::to_value(&stored.choices)?;
        view["copies"] = serde_json::to_value(&stored.copies)?;
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
            Ok(Some(stored)) if stored.origin.is_original() => {
                return refused(&anyhow::anyhow!(Refused(
                    "a built-in or imported template can't be changed, as a newer version replaces it: disable it, or change its alerts".to_string()
                )));
            }
            Ok(Some(_)) => {}
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(error) => return super::api::server_error(&error),
        }
    }
    match save(state, id, &template).await {
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

async fn api_follow(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state
        .database
        .follow_template_enabled(id, crate::times::now())
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

#[derive(Deserialize)]
struct HostsInput {
    applies_to: Option<String>,
    #[serde(default)]
    host_ids: Vec<String>,
}

async fn api_set_hosts(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(input): Json<HostsInput>,
) -> Response {
    match save_hosts(&state, id, input.applies_to, input.host_ids).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(message)) => refused(&anyhow::anyhow!(message)),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_enable(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    api_turn(&state, id, true).await
}

async fn api_disable(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    api_turn(&state, id, false).await
}

/// The template's own rule for one of its alerts, by the alert's key.
async fn rule_of(state: &AppState, id: i64, key: &str) -> Result<Option<i64>> {
    let alerts = state.database.template_alerts(id).await?;
    Ok(alerts
        .iter()
        .find(|alert| alert.key == key)
        .map(|alert| alert.rule.id))
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
    match state.database.update_template_rule(rule, &input).await {
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

// Importing and exporting.

/// What importing a template would do, shown before it's done: what it is, what
/// it would run, anything wrong with it, and what would change of one imported
/// before.
#[derive(Serialize)]
struct ImportPreview {
    /// `added`, `updated` or `unchanged`, when it can be imported.
    outcome: Option<Imported>,
    /// Why it can't be imported, each on its own.
    problems: Vec<String>,
    key: String,
    name: String,
    description: Option<String>,
    /// What it runs for, in words.
    target: String,
    metrics: Vec<MetricView>,
    alerts: Vec<PreviewAlert>,
    /// Every SQL statement it would run, with each version's fills filled in.
    sql: Vec<PreviewSql>,
    /// Every performance counter it would read.
    counters: Vec<PreviewCounters>,
    /// For one imported before, what's different, part by part.
    changes: Vec<String>,
}

#[derive(Serialize)]
struct PreviewAlert {
    key: String,
    name: String,
    warning: Option<String>,
    critical: Option<String>,
    enabled: bool,
}

#[derive(Serialize)]
struct PreviewSql {
    /// `discover`, or the query's key.
    from: String,
    statements: Vec<String>,
}

#[derive(Serialize)]
struct PreviewCounters {
    key: String,
    object: String,
    counters: Vec<String>,
}

fn metric_views(template: &Template) -> Vec<MetricView> {
    own_metrics(template)
        .into_iter()
        .map(|metric| MetricView {
            name: metric.name,
            kind: match metric.kind {
                Kind::Number => "number",
                Kind::Seconds => "seconds",
                Kind::Flag => "flag",
                Kind::Unknown => "unknown",
            },
            labels: metric.labels,
        })
        .collect()
}

/// What's different between two versions of a template, a part to a line.
fn differences(old: &Template, new: &Template) -> Vec<String> {
    fn parts<T: PartialEq>(
        kind: &str,
        old: &[T],
        new: &[T],
        key: impl Fn(&T) -> &str,
        changes: &mut Vec<String>,
    ) {
        for part in new {
            match old.iter().find(|other| key(other) == key(part)) {
                None => changes.push(format!("Adds the {kind} {}", key(part))),
                Some(other) if other != part => {
                    changes.push(format!("Changes the {kind} {}", key(part)));
                }
                Some(_) => {}
            }
        }
        for part in old {
            if !new.iter().any(|other| key(other) == key(part)) {
                changes.push(format!("Removes the {kind} {}", key(part)));
            }
        }
    }
    let mut changes = Vec::new();
    let top = |template: &Template| {
        (
            template.name.clone(),
            template.description.clone(),
            template.target.clone(),
            template.min_version.clone(),
            template.services.clone(),
        )
    };
    if top(old) != top(new) {
        changes.push("Changes its name, description or what it runs for".to_string());
    }
    if old.discover != new.discover {
        changes.push("Changes its discovery".to_string());
    }
    parts(
        "notice",
        &old.notices,
        &new.notices,
        |n| &n.key,
        &mut changes,
    );
    parts(
        "query",
        &old.queries,
        &new.queries,
        |q| &q.key,
        &mut changes,
    );
    parts(
        "counters",
        &old.counters,
        &new.counters,
        |c| &c.key,
        &mut changes,
    );
    // Whether an alert is on is the server's own to keep, not the import's.
    let alerts = |template: &Template| -> Vec<maxnines_protocol::templates::Alert> {
        template
            .alerts
            .iter()
            .cloned()
            .map(|mut alert| {
                alert.enabled = true;
                alert
            })
            .collect()
    };
    parts(
        "alert",
        &alerts(old),
        &alerts(new),
        |a| &a.key,
        &mut changes,
    );
    changes
}

async fn preview_of(
    state: &AppState,
    hcl: &str,
) -> Result<Result<(Template, ImportPreview), String>> {
    let template = match parse(hcl) {
        Ok(template) => template,
        Err(error) => return Ok(Err(format!("{error:#}"))),
    };
    let found = state.check_template(&template).await?;
    let mut problems = Problems::new(&template, found).described;
    let outcome = match state.database.import_outcome(&template).await {
        Ok(outcome) => Some(outcome),
        Err(error) if error.is::<Refused>() || error.is::<NameTaken>() => {
            problems.push(format!("{error:#}"));
            None
        }
        Err(error) => return Err(error),
    };
    let mut changes = Vec::new();
    if outcome == Some(Imported::Updated) {
        let before = state.database.list_templates().await?;
        if let Some(stored) = before
            .iter()
            .find(|stored| stored.template.key == template.key)
        {
            changes = differences(&stored.template, &template);
        }
    }
    let mut sql = Vec::new();
    for discover in &template.discover {
        if let Some(statement) = &discover.sql {
            sql.push(PreviewSql {
                from: format!("discover {}", discover.key),
                statements: vec![statement.clone()],
            });
        }
    }
    for query in &template.queries {
        sql.push(PreviewSql {
            from: query.key.clone(),
            statements: maxnines_protocol::templates::filled_sql(query),
        });
    }
    let preview = ImportPreview {
        outcome: outcome.filter(|_| problems.is_empty()),
        problems,
        key: template.key.clone(),
        name: template.name.clone(),
        description: template.description.clone(),
        target: target_words(&template),
        metrics: metric_views(&template),
        alerts: template
            .alerts
            .iter()
            .map(|alert| PreviewAlert {
                key: alert.key.clone(),
                name: alert.name.clone(),
                warning: alert.warning.clone(),
                critical: alert.critical.clone(),
                enabled: alert.enabled,
            })
            .collect(),
        sql,
        counters: template
            .counters
            .iter()
            .map(|counters| PreviewCounters {
                key: counters.key.clone(),
                object: counters.object.clone(),
                counters: counters
                    .metrics
                    .iter()
                    .filter_map(|metric| metric.counter.clone())
                    .collect(),
            })
            .collect(),
        changes,
    };
    Ok(Ok((template, preview)))
}

fn import_view(
    state: &AppState,
    token: &CsrfToken,
    hcl: &str,
    preview: Option<&ImportPreview>,
    error: Option<&str>,
) -> Response {
    let page = Page::new(state, token, "templates/import.html")
        .with("hcl", hcl)
        .with("preview", &preview)
        .with("error", &error);
    match error.is_some() || preview.is_some_and(|preview| !preview.problems.is_empty()) {
        true => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        false => page.render(),
    }
}

async fn import_page(State(state): State<AppState>, token: CsrfToken) -> Response {
    import_view(&state, &token, "", None, None)
}

/// Shows what importing would do, and once that's been seen and confirmed, does it.
async fn import(State(state): State<AppState>, form: CsrfForm) -> Response {
    let hcl = form
        .fields
        .get("hcl")
        .cloned()
        .unwrap_or_default()
        .replace("\r\n", "\n");
    let (template, preview) = match preview_of(&state, &hcl).await {
        Ok(Ok(found)) => found,
        Ok(Err(message)) => return import_view(&state, &form.token, &hcl, None, Some(&message)),
        Err(error) => return server_error(&error),
    };
    if !form.fields.contains_key("confirm") || preview.outcome.is_none() {
        return import_view(&state, &form.token, &hcl, Some(&preview), None);
    }
    match state
        .database
        .import_template(&template, crate::times::now())
        .await
    {
        Ok((id, _)) => {
            refresh_upgrades(&state).await;
            (form.token, Redirect::to(&format!("/templates/{id}"))).into_response()
        }
        Err(error) if error.is::<Refused>() || error.is::<NameTaken>() => {
            let message = format!("{error:#}");
            import_view(&state, &form.token, &hcl, Some(&preview), Some(&message))
        }
        Err(error) => server_error(&error),
    }
}

/// The notice admins see is kept in memory, so importing a newer version says so
/// at once.
async fn refresh_upgrades(state: &AppState) {
    if let Ok(upgrades) = state.database.template_upgrades().await {
        *state
            .template_upgrades
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = upgrades;
    }
}

fn hcl_file(stored: &StoredTemplate) -> Response {
    use axum::http::header;
    let name = format!("attachment; filename=\"{}.hcl\"", stored.template.key);
    (
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (header::CONTENT_DISPOSITION, name),
        ],
        stored.hcl(),
    )
        .into_response()
}

async fn export(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_template(id).await {
        Ok(Some(stored)) => hcl_file(&stored),
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

async fn api_export(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state.database.get_template(id).await {
        Ok(Some(stored)) => hcl_file(&stored),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

#[derive(Deserialize)]
struct ImportInput {
    hcl: String,
    /// Only say what importing would do.
    #[serde(default)]
    dry_run: bool,
}

async fn api_import(State(state): State<AppState>, Json(input): Json<ImportInput>) -> Response {
    let (template, preview) = match preview_of(&state, &input.hcl).await {
        Ok(Ok(found)) => found,
        Ok(Err(message)) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": message })),
            )
                .into_response();
        }
        Err(error) => return super::api::server_error(&error),
    };
    if input.dry_run {
        return Json(preview).into_response();
    }
    if preview.outcome.is_none() {
        let body = Json(json!({ "error": preview.problems.join("; ") }));
        return (StatusCode::UNPROCESSABLE_ENTITY, body).into_response();
    }
    match state
        .database
        .import_template(&template, crate::times::now())
        .await
    {
        Ok((id, outcome)) => {
            refresh_upgrades(&state).await;
            let status = match outcome {
                Imported::Added => StatusCode::CREATED,
                _ => StatusCode::OK,
            };
            (status, Json(json!({ "id": id, "outcome": outcome }))).into_response()
        }
        Err(error) if error.is::<Refused>() || error.is::<NameTaken>() => refused(&error),
        Err(error) => super::api::server_error(&error),
    }
}
