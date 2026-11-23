//! Changing one of a template's discover blocks, queries or counters blocks on its
//! own, and turning a query or counters block on or off. For someone's own template
//! the part is changed in place. A built-in or imported one isn't theirs to change,
//! so changing a part makes a copy of their own, used in its place, which upgrades
//! leave alone, and resetting it goes back to the template's. The API's routes for
//! the same are here too.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde_json::json;

use maxnines_protocol::templates::{Counters, Discover, Place, Problem, Query, Template};

use super::template_form::{TemplateForm, field_errors};
use super::templates::local_suggestions;
use super::{CsrfForm, Page, server_error};
use crate::alerting::NameTaken;
use crate::app_state::AppState;
use crate::models::{Part, PartKind, StoredTemplate};
use crate::templates::Refused;

/// What each kind of part is called in addresses, and what it is.
const KINDS: [(&str, PartKind); 3] = [
    ("discover", PartKind::Discover),
    ("queries", PartKind::Query),
    ("counters", PartKind::Counters),
];

pub fn routes() -> Router<AppState> {
    let mut router = Router::new();
    for (segment, kind) in KINDS {
        let base = format!("/templates/{{id}}/{segment}/{{key}}");
        router = router
            .route(
                &format!("{base}/edit"),
                get(move |state, path, token| edit(state, path, token, kind)),
            )
            .route(
                &base,
                post(move |state, path, form| save(state, path, form, kind)),
            )
            .route(
                &format!("{base}/reset"),
                post(move |state, path, form| reset(state, path, form, kind)),
            );
        if kind.turns_off() {
            router = router
                .route(
                    &format!("{base}/enable"),
                    post(move |state, path, form| turn(state, path, form, kind, true)),
                )
                .route(
                    &format!("{base}/disable"),
                    post(move |state, path, form| turn(state, path, form, kind, false)),
                );
        }
    }
    router
}

pub fn api_routes() -> Router<AppState> {
    let mut router = Router::new();
    for (segment, kind) in KINDS {
        let base = format!("/templates/{{id}}/{segment}/{{key}}");
        router = router
            .route(
                &base,
                get(move |state, path| api_show(state, path, kind))
                    .put(move |state, path, body| api_save(state, path, body, kind))
                    .delete(move |state, path| api_reset(state, path, kind)),
            )
            .route(
                &format!("{base}/reset"),
                post(move |state, path| api_reset(state, path, kind)),
            );
        if kind.turns_off() {
            router = router
                .route(
                    &format!("{base}/enable"),
                    post(move |state, path| api_turn(state, path, kind, true)),
                )
                .route(
                    &format!("{base}/disable"),
                    post(move |state, path| api_turn(state, path, kind, false)),
                );
        }
    }
    router
}

/// What a kind of part is called on the pages.
fn kind_words(kind: PartKind) -> &'static str {
    match kind {
        PartKind::Discover => "discover block",
        PartKind::Query => "query",
        PartKind::Counters => "counters block",
    }
}

/// What a part's fields are called in the form: `query.0.`.
fn form_prefix(kind: PartKind) -> &'static str {
    match kind {
        PartKind::Discover => "discover.0.",
        PartKind::Query => "query.0.",
        PartKind::Counters => "counters.0.",
    }
}

/// A template holding only `part`, as the form shows one part.
fn holding(template: &Template, part: Part) -> Template {
    let mut shell = template.clone();
    shell.discover.clear();
    shell.notices.clear();
    shell.queries.clear();
    shell.counters.clear();
    shell.alerts.clear();
    match part {
        Part::Discover(part) => shell.discover.push(part),
        Part::Query(part) => shell.queries.push(part),
        Part::Counters(part) => shell.counters.push(part),
    }
    shell
}

/// The one part of `kind` a form's template holds, given `key`, as the address says
/// it, whatever was typed.
fn part_in(template: Template, kind: PartKind, key: &str) -> Option<Part> {
    let mut part = match kind {
        PartKind::Discover => Part::Discover(template.discover.into_iter().next()?),
        PartKind::Query => Part::Query(template.queries.into_iter().next()?),
        PartKind::Counters => Part::Counters(template.counters.into_iter().next()?),
    };
    match &mut part {
        Part::Discover(Discover { key: typed, .. })
        | Part::Query(Query { key: typed, .. })
        | Part::Counters(Counters { key: typed, .. }) => *typed = key.to_string(),
    }
    Some(part)
}

/// Where a problem with the whole template goes on the form for one of its parts:
/// on the part's own fields if it's about the part at `at`, and said in full at
/// the top if it's about anything else, such as an alert using a metric the part
/// no longer makes.
fn on_the_form(problem: Problem, kind: PartKind, at: usize, template: &Template) -> Problem {
    let place = match (kind, problem.place) {
        (PartKind::Discover, Place::Discover(i)) if i == at => Some(Place::Discover(0)),
        (PartKind::Query, Place::Query(i)) if i == at => Some(Place::Query(0)),
        (PartKind::Query, Place::Fill(i, fill)) if i == at => Some(Place::Fill(0, fill)),
        (PartKind::Query, Place::QueryMetric(i, metric)) if i == at => {
            Some(Place::QueryMetric(0, metric))
        }
        (PartKind::Counters, Place::Counters(i)) if i == at => Some(Place::Counters(0)),
        (PartKind::Counters, Place::Join(i)) if i == at => Some(Place::Join(0)),
        (PartKind::Counters, Place::CountersMetric(i, metric)) if i == at => {
            Some(Place::CountersMetric(0, metric))
        }
        _ => None,
    };
    match place {
        Some(place) => Problem { place, ..problem },
        None => Problem::new(Place::Template, "", problem.describe(template)),
    }
}

/// The template, as it is and as it runs, and its part of `kind` with `key` as it
/// runs. None if there's no such template or part.
async fn load(
    state: &AppState,
    id: i64,
    kind: PartKind,
    key: &str,
) -> anyhow::Result<Option<(StoredTemplate, Template, usize, Part)>> {
    let Some(stored) = state.database.get_template(id).await? else {
        return Ok(None);
    };
    let Some(as_run) = state.database.template_as_run(id).await? else {
        return Ok(None);
    };
    let Some((at, part)) = Part::of(&as_run, kind, key) else {
        return Ok(None);
    };
    Ok(Some((stored, as_run, at, part)))
}

#[allow(clippy::too_many_arguments)]
fn form_page(
    state: &AppState,
    token: &CsrfToken,
    stored: &StoredTemplate,
    as_run: &Template,
    kind: PartKind,
    key: &str,
    form: &TemplateForm,
    problems: &[Problem],
) -> Response {
    let segment = KINDS
        .iter()
        .find(|(_, k)| *k == kind)
        .map_or("", |(segment, _)| *segment);
    let choice = stored
        .choices
        .iter()
        .find(|choice| choice.kind == kind && choice.key == key);
    let page = Page::new(state, token, "templates/part.html")
        .with("id", &stored.id)
        .with("template", &stored.template)
        .with("original", &stored.origin.is_original())
        .with("copied", &choice.is_some_and(|choice| choice.copied))
        .with("kind", kind.as_str())
        .with("kind_words", kind_words(kind))
        .with("key", key)
        .with(
            "action",
            &format!("/templates/{}/{segment}/{key}", stored.id),
        )
        .with("form", form)
        .with("part_only", &true)
        .with("errors", &field_errors(problems))
        .with("problem_count", &problems.len())
        .with("units", &maxnines_protocol::templates::UNITS)
        .with("local_metrics", &local_suggestions(as_run));
    match problems.is_empty() {
        true => page.render(),
        false => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
    }
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn edit(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    token: CsrfToken,
    kind: PartKind,
) -> Response {
    match load(&state, id, kind, &key).await {
        Ok(Some((stored, as_run, _, part))) => {
            let form = TemplateForm::from_template(&holding(&as_run, part));
            form_page(&state, &token, &stored, &as_run, kind, &key, &form, &[])
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

/// Checks `part` in the template as it runs, in place of the part it changes, and
/// saves it. Gives what's wrong with it, if anything, on the form's fields.
async fn check_and_save(
    state: &AppState,
    id: i64,
    as_run: &Template,
    at: usize,
    part: Part,
) -> anyhow::Result<Result<bool, Vec<Problem>>> {
    let kind = part.kind();
    let mut changed = as_run.clone();
    part.clone().put_in(&mut changed);
    let problems: Vec<Problem> = state
        .check_template(&changed)
        .await?
        .into_iter()
        .map(|problem| on_the_form(problem, kind, at, &changed))
        .collect();
    if !problems.is_empty() {
        return Ok(Err(problems));
    }
    match state
        .database
        .save_template_part(id, part, crate::times::now())
        .await
    {
        Ok(saved) => Ok(Ok(saved)),
        Err(error) if error.is::<NameTaken>() || error.is::<Refused>() => {
            Ok(Err(vec![Problem::new(
                Place::Template,
                "",
                format!("{error:#}"),
            )]))
        }
        Err(error) => Err(error),
    }
}

async fn save(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    form: CsrfForm,
    kind: PartKind,
) -> Response {
    let (stored, as_run, at) = match load(&state, id, kind, &key).await {
        Ok(Some((stored, as_run, at, _))) => (stored, as_run, at),
        Ok(None) => return not_found(&state, &form.token),
        Err(error) => return server_error(&error),
    };
    let mut fields = TemplateForm::from_fields(&form.fields);
    let action = form.fields.get("form_action").cloned().unwrap_or_default();
    // Only rows within the part are added or taken away here.
    if action.contains(form_prefix(kind).trim_end_matches('.')) && fields.apply_action(&action) {
        return form_page(
            &state,
            &form.token,
            &stored,
            &as_run,
            kind,
            &key,
            &fields,
            &[],
        );
    }
    let (typed, problems) = fields.to_template();
    let Some(part) = part_in(typed, kind, &key) else {
        return not_found(&state, &form.token);
    };
    let show = |problems: &[Problem]| {
        form_page(
            &state,
            &form.token,
            &stored,
            &as_run,
            kind,
            &key,
            &fields,
            problems,
        )
    };
    if !problems.is_empty() {
        return show(&problems);
    }
    match check_and_save(&state, id, &as_run, at, part).await {
        Ok(Ok(true)) => (
            form.token.clone(),
            Redirect::to(&format!("/templates/{id}")),
        )
            .into_response(),
        Ok(Ok(false)) => not_found(&state, &form.token),
        Ok(Err(problems)) => show(&problems),
        Err(error) => server_error(&error),
    }
}

async fn turn(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    form: CsrfForm,
    kind: PartKind,
    enabled: bool,
) -> Response {
    let now = crate::times::now();
    match state
        .database
        .set_template_part_enabled(id, kind, &key, enabled, now)
        .await
    {
        Ok(true) => (form.token, Redirect::to(&format!("/templates/{id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn reset(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    form: CsrfForm,
    kind: PartKind,
) -> Response {
    let now = crate::times::now();
    match state
        .database
        .reset_template_part(id, kind, &key, now)
        .await
    {
        Ok(true) => (form.token, Redirect::to(&format!("/templates/{id}"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

// The API.

fn refused(message: impl Into<String>) -> Response {
    let body = Json(json!({ "error": message.into() }));
    (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
}

async fn api_show(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    kind: PartKind,
) -> Response {
    let loaded = async {
        let Some((stored, _, _, part)) = load(&state, id, kind, &key).await? else {
            return Ok(None);
        };
        let choice = stored
            .choices
            .iter()
            .find(|choice| choice.kind == kind && choice.key == key);
        let built_in = Part::of(&stored.template, kind, &key).map(|(_, part)| part);
        let mut view = serde_json::to_value(&part)?;
        view["copied"] = json!(choice.is_some_and(|choice| choice.copied));
        view["enabled_choice"] = json!(choice.and_then(|choice| choice.enabled_choice));
        view["original_changed_at"] = json!(choice.and_then(|choice| choice.original_changed_at));
        if choice.is_some_and(|choice| choice.copied) {
            view["template_part"] = serde_json::to_value(built_in)?;
        }
        anyhow::Ok(Some(view))
    };
    match loaded.await {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_save(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    Json(body): Json<serde_json::Value>,
    kind: PartKind,
) -> Response {
    let mut body = body;
    // The key is the address's, whatever the body says.
    if let Some(fields) = body.as_object_mut() {
        fields.insert("key".to_string(), json!(key));
    }
    let part = match kind {
        PartKind::Discover => serde_json::from_value(body).map(Part::Discover),
        PartKind::Query => serde_json::from_value(body).map(Part::Query),
        PartKind::Counters => serde_json::from_value(body).map(Part::Counters),
    };
    let part = match part {
        Ok(part) => part,
        Err(error) => return refused(format!("{error}")),
    };
    let (as_run, at) = match load(&state, id, kind, &key).await {
        Ok(Some((_, as_run, at, _))) => (as_run, at),
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return super::api::server_error(&error),
    };
    let mut changed = as_run.clone();
    part.clone().put_in(&mut changed);
    match check_and_save(&state, id, &as_run, at, part).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(problems)) => {
            let said: Vec<String> = problems
                .iter()
                .map(|problem| match problem.place {
                    Place::Template => problem.message.clone(),
                    _ => problem.describe(&changed),
                })
                .collect();
            refused(said.join("; "))
        }
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_turn(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    kind: PartKind,
    enabled: bool,
) -> Response {
    let now = crate::times::now();
    match state
        .database
        .set_template_part_enabled(id, kind, &key, enabled, now)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<Refused>() => refused(format!("{error:#}")),
        Err(error) => super::api::server_error(&error),
    }
}

async fn api_reset(
    State(state): State<AppState>,
    Path((id, key)): Path<(i64, String)>,
    kind: PartKind,
) -> Response {
    let now = crate::times::now();
    match state
        .database
        .reset_template_part(id, kind, &key, now)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => super::api::server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_with_the_part_goes_on_its_fields_and_any_other_is_said_in_full() {
        let template = maxnines_protocol::templates::parse(
            r#"template "pg" {
                 name     = "PG"
                 database = "postgres"
                 query "a" { sql = "SELECT 1 AS one" }
                 query "b" { sql = "SELECT 2 AS two" }
               }"#,
        )
        .unwrap();
        let own = on_the_form(
            Problem::new(Place::QueryMetric(1, 2), "unit", "no such unit"),
            PartKind::Query,
            1,
            &template,
        );
        assert_eq!(own.place, Place::QueryMetric(0, 2));
        assert_eq!(own.form_field(), "query.0.metric.2.unit");

        let other = on_the_form(
            Problem::new(Place::Query(0), "sql", "isn't SQL"),
            PartKind::Query,
            1,
            &template,
        );
        assert_eq!(other.place, Place::Template);
        assert_eq!(other.form_field(), "");
        assert!(other.message.contains("query \"a\""), "{}", other.message);
    }
}
