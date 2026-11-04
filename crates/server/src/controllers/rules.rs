use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use maxnines_protocol::COLLECTORS;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::{CsrfForm, Page, server_error};
use crate::app_state::AppState;
use crate::condition_builder::{
    Builder, Clause, MAX_CLAUSES, MatchMode, OPERATORS, Operator, ValueKind,
};
use crate::models::RuleInput;
use crate::rule_engine;
use crate::rule_preview::Preview;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/rules", get(index).post(create))
        .route("/rules/new", get(new))
        .route("/rules/{id}", post(update))
        .route("/rules/{id}/edit", get(edit))
        .route("/rules/{id}/delete", post(delete))
}

/// A rule as its form shows it, including whatever was just typed.
#[derive(Serialize, Default)]
struct RuleForm {
    name: String,
    priority: String,
    /// The expression, when it's being written by hand.
    condition: String,
    /// Whether the expression box is showing instead of the builder.
    use_expression: bool,
    /// Why the builder can't show this condition.
    note: Option<String>,
    match_any: bool,
    clauses: Vec<ClauseRow>,
    enabled: bool,
    interval_secs: String,
    facts_interval_secs: String,
    mount_points: String,
    collectors: Vec<CollectorChoice>,
}

/// One row of the builder.
#[derive(Serialize, Clone)]
struct ClauseRow {
    fact: String,
    operator: String,
    value: String,
    kind: String,
}

impl ClauseRow {
    fn blank() -> Self {
        Self {
            fact: String::new(),
            operator: Operator::Equals.form_name().to_string(),
            value: String::new(),
            kind: ValueKind::Text.form_name().to_string(),
        }
    }

    fn from_clause(clause: Clause) -> Self {
        Self {
            fact: clause.fact,
            operator: clause.operator.form_name().to_string(),
            value: clause.value,
            kind: clause.kind.form_name().to_string(),
        }
    }

    fn is_blank(&self) -> bool {
        self.fact.trim().is_empty() && self.value.trim().is_empty()
    }

    fn to_clause(&self) -> Result<Clause> {
        Ok(Clause {
            fact: self.fact.trim().to_string(),
            operator: Operator::parse(&self.operator).context("unknown comparison")?,
            value: self.value.clone(),
            kind: ValueKind::parse(&self.kind),
        })
    }
}

/// A collector's setting. `inherit` leaves it to other rules.
#[derive(Serialize)]
struct CollectorChoice {
    name: &'static str,
    choice: String,
}

impl RuleForm {
    fn blank() -> Self {
        Self {
            priority: "100".to_string(),
            enabled: true,
            clauses: vec![ClauseRow::blank()],
            collectors: choices(|_| "inherit".to_string()),
            ..Self::default()
        }
    }

    /// Shows a condition in the builder if it fits there, or as text if not.
    fn set_condition(&mut self, condition: Option<&str>) {
        self.condition = condition.unwrap_or_default().to_string();
        match condition.map(Builder::from_expression) {
            None => self.clauses = vec![ClauseRow::blank()],
            Some(Some(builder)) => {
                self.match_any = builder.mode == MatchMode::Any;
                self.clauses = builder
                    .clauses
                    .into_iter()
                    .map(ClauseRow::from_clause)
                    .collect();
                self.use_expression = false;
                self.note = None;
            }
            Some(None) => {
                self.use_expression = true;
                self.note = Some(TOO_COMPLEX.to_string());
            }
        }
    }

    fn builder(&self) -> Result<Builder> {
        let clauses = self
            .clauses
            .iter()
            .filter(|row| !row.is_blank())
            .map(ClauseRow::to_clause)
            .collect::<Result<Vec<_>>>()?;
        let mode = if self.match_any {
            MatchMode::Any
        } else {
            MatchMode::All
        };
        Ok(Builder { mode, clauses })
    }

    fn expression(&self, known: &BTreeMap<String, String>) -> Result<Option<String>> {
        if self.use_expression {
            let condition = self.condition.trim();
            return Ok((!condition.is_empty()).then(|| condition.to_string()));
        }
        self.builder()?.to_expression(known)
    }

    fn from_rule(rule: &RuleInput) -> Self {
        let number = |name: &str| match &rule.settings[name] {
            Value::Null => String::new(),
            value => value.to_string(),
        };
        let mounts = rule.settings["collectors"]["disk"]["mount_points"]
            .as_array()
            .map(|mounts| {
                let lines: Vec<&str> = mounts.iter().filter_map(Value::as_str).collect();
                lines.join("\n")
            })
            .unwrap_or_default();

        let mut form = Self {
            name: rule.name.clone(),
            priority: rule.priority.to_string(),
            enabled: rule.enabled,
            interval_secs: number("interval_secs"),
            facts_interval_secs: number("facts_interval_secs"),
            mount_points: mounts,
            collectors: choices(|name| {
                match rule.settings["collectors"][name]["enabled"].as_bool() {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => "inherit",
                }
                .to_string()
            }),
            ..Self::default()
        };
        form.set_condition(rule.condition.as_deref());
        form
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            name: text("name"),
            priority: text("priority"),
            condition: text("condition"),
            use_expression: text("condition_mode") == "expression",
            note: None,
            match_any: text("match") == "any",
            clauses: (0..MAX_CLAUSES)
                .map_while(|index| {
                    fields.get(&format!("clause_fact_{index}"))?;
                    Some(ClauseRow {
                        fact: text(&format!("clause_fact_{index}")),
                        operator: text(&format!("clause_operator_{index}")),
                        value: text(&format!("clause_value_{index}")),
                        kind: text(&format!("clause_kind_{index}")),
                    })
                })
                .collect(),
            enabled: fields.contains_key("enabled"),
            interval_secs: text("interval_secs"),
            facts_interval_secs: text("facts_interval_secs"),
            mount_points: text("mount_points"),
            collectors: choices(|name| text(&format!("collector_{name}"))),
        }
    }

    fn to_rule(&self, known: &BTreeMap<String, String>) -> Result<RuleInput> {
        let mut settings = Map::new();
        for (name, text) in [
            ("interval_secs", &self.interval_secs),
            ("facts_interval_secs", &self.facts_interval_secs),
        ] {
            let text = text.trim();
            if !text.is_empty() {
                let seconds: u64 = text
                    .parse()
                    .with_context(|| format!("{name} must be a whole number of seconds"))?;
                settings.insert(name.to_string(), json!(seconds));
            }
        }

        let mut collectors = Map::new();
        for collector in &self.collectors {
            let enabled = match collector.choice.as_str() {
                "on" => Some(true),
                "off" => Some(false),
                "inherit" | "" => None,
                other => bail!("unknown choice {other:?} for {}", collector.name),
            };
            let mut fields = Map::new();
            if let Some(enabled) = enabled {
                fields.insert("enabled".to_string(), json!(enabled));
            }
            if collector.name == "disk" {
                let mounts: Vec<&str> = self
                    .mount_points
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .collect();
                if !mounts.is_empty() {
                    fields.insert("mount_points".to_string(), json!(mounts));
                }
            }
            if !fields.is_empty() {
                collectors.insert(collector.name.to_string(), Value::Object(fields));
            }
        }
        if !collectors.is_empty() {
            settings.insert("collectors".to_string(), Value::Object(collectors));
        }

        Ok(RuleInput {
            name: self.name.trim().to_string(),
            priority: self
                .priority
                .trim()
                .parse()
                .context("priority must be a whole number")?,
            condition: self.expression(known)?,
            enabled: self.enabled,
            settings: Value::Object(settings),
        })
    }
}

const TOO_COMPLEX: &str = "This condition is too complex for the builder, so it's shown as an \
                          expression.";

fn choices(mut choice: impl FnMut(&str) -> String) -> Vec<CollectorChoice> {
    COLLECTORS
        .iter()
        .map(|name| CollectorChoice {
            name,
            choice: choice(name),
        })
        .collect()
}

#[derive(Serialize)]
struct RuleRow {
    id: i64,
    name: String,
    priority: i32,
    condition: Option<String>,
    /// The condition in plain words, if it's simple enough.
    description: Option<String>,
    enabled: bool,
    summary: String,
}

/// Describes what a rule sets in a few words.
fn summarize(settings: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(seconds) = settings["interval_secs"].as_u64() {
        parts.push(format!("every {seconds}s"));
    }
    if let Some(seconds) = settings["facts_interval_secs"].as_u64() {
        parts.push(format!("facts every {seconds}s"));
    }
    if let Some(collectors) = settings["collectors"].as_object() {
        let named = |wanted: bool| {
            let names: Vec<&str> = collectors
                .iter()
                .filter(|(_, fields)| fields["enabled"].as_bool() == Some(wanted))
                .map(|(name, _)| name.as_str())
                .collect();
            names.join(", ")
        };
        for (label, wanted) in [("on", true), ("off", false)] {
            let names = named(wanted);
            if !names.is_empty() {
                parts.push(format!("{label}: {names}"));
            }
        }
    }
    parts.join(" · ")
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let rules = match state.database.list_rules().await {
        Ok(rules) => rules,
        Err(error) => return server_error(&error),
    };
    let rows: Vec<RuleRow> = rules
        .into_iter()
        .map(|rule| RuleRow {
            id: rule.id,
            summary: summarize(&rule.rule.settings),
            description: rule
                .rule
                .condition
                .as_deref()
                .and_then(Builder::from_expression)
                .map(|builder| builder.describe()),
            name: rule.rule.name,
            priority: rule.rule.priority,
            condition: rule.rule.condition,
            enabled: rule.rule.enabled,
        })
        .collect();

    Page::new(&state, &token, "rules/index.html")
        .with("rules", &rows)
        .render()
}

#[derive(Serialize)]
struct OperatorOption {
    name: &'static str,
    label: &'static str,
}

/// The rule form, ready to render.
async fn form_view<'a>(
    state: &'a AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &RuleForm,
) -> Page<'a> {
    let operators: Vec<OperatorOption> = OPERATORS
        .iter()
        .map(|(_, name, label)| OperatorOption { name, label })
        .collect();
    let known: Vec<String> = known_facts(state).await.into_keys().collect();

    Page::new(state, token, "rules/form.html")
        .with("id", &id)
        .with("rule", form)
        .with("operators", &operators)
        .with("known_facts", &known)
        .with("preview", &None::<Preview>)
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &RuleForm,
    error: Option<&str>,
) -> Response {
    let page = form_view(state, token, id, form)
        .await
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

/// Names to suggest. The form still works without them, and agents may not have
/// reported yet, so a failure here isn't worth stopping for.
async fn known_facts(state: &AppState) -> BTreeMap<String, String> {
    state.database.known_facts().await.unwrap_or_default()
}

/// The builder's buttons change the form without saving it, so it works without
/// any JavaScript. Returns true if one of them was pressed.
fn apply_form_action(form: &mut RuleForm, action: &str, known: &BTreeMap<String, String>) -> bool {
    if action == "add_clause" {
        if form.clauses.len() < MAX_CLAUSES {
            form.clauses.push(ClauseRow::blank());
        }
        return true;
    }

    if let Some(index) = action.strip_prefix("remove_clause_") {
        if let Some(index) = index
            .parse::<usize>()
            .ok()
            .filter(|i| *i < form.clauses.len())
        {
            form.clauses.remove(index);
        }
        if form.clauses.is_empty() {
            form.clauses.push(ClauseRow::blank());
        }
        return true;
    }

    match action {
        "use_expression" => {
            // Keep what's been built, if it's complete enough to write out.
            if let Ok(expression) = form.builder().and_then(|b| b.to_expression(known)) {
                form.condition = expression.unwrap_or_default();
            }
            form.use_expression = true;
            form.note = None;
            true
        }
        "use_builder" => {
            let condition = form.condition.trim().to_string();
            form.use_expression = false;
            form.set_condition((!condition.is_empty()).then_some(condition.as_str()));
            true
        }
        _ => false,
    }
}

/// Handles the buttons that show the form again without saving it, so a
/// response means there's nothing left to do.
async fn without_saving(
    state: &AppState,
    id: Option<i64>,
    fields: &mut RuleForm,
    form: &CsrfForm,
) -> Option<Response> {
    let action = form.fields.get("form_action").cloned().unwrap_or_default();
    if action == "preview" {
        return Some(preview_page(state, &form.token, id, fields).await);
    }
    if apply_form_action(fields, &action, &known_facts(state).await) {
        return Some(form_page(state, &form.token, id, fields, None).await);
    }
    None
}

async fn preview_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &RuleForm,
) -> Response {
    match preview(state, form, id).await {
        Ok(preview) => form_view(state, token, id, form)
            .await
            .with("error", &None::<String>)
            .with("preview", &preview)
            .render(),
        Err(error) => form_page(state, token, id, form, Some(&format!("{error:#}"))).await,
    }
}

/// Holds the form to the same checks as saving, except that a rule doesn't need
/// a name yet to be tried out.
async fn preview(state: &AppState, form: &RuleForm, id: Option<i64>) -> Result<Preview> {
    let mut input = form.to_rule(&known_facts(state).await)?;
    if input.name.is_empty() {
        input.name = "Unnamed rule".to_string();
    }
    rule_engine::check_rule(&input)?;
    state.preview_rule(id, input).await
}

async fn new(State(state): State<AppState>, token: CsrfToken) -> Response {
    form_page(&state, &token, None, &RuleForm::blank(), None).await
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_rule(id).await {
        Ok(Some(rule)) => {
            form_page(
                &state,
                &token,
                Some(id),
                &RuleForm::from_rule(&rule.rule),
                None,
            )
            .await
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

/// Turns the form into a valid rule, or explains what's wrong with it.
async fn validate(state: &AppState, form: &RuleForm, id: Option<i64>) -> Result<RuleInput> {
    let input = form.to_rule(&known_facts(state).await)?;
    rule_engine::check_rule(&input)?;

    let rules = state.database.list_rules().await?;
    let taken = rules
        .iter()
        .any(|rule| rule.rule.name == input.name && Some(rule.id) != id);
    if taken {
        bail!("a rule named {:?} already exists", input.name);
    }
    Ok(input)
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let mut fields = RuleForm::from_fields(&form.fields);
    if let Some(response) = without_saving(&state, None, &mut fields, &form).await {
        return response;
    }

    let input = match validate(&state, &fields, None).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, None, &fields, Some(&message)).await;
        }
    };

    match state.database.create_rule(&input).await {
        Ok(_) => {
            state.config_changed();
            (form.token, Redirect::to("/rules")).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let mut fields = RuleForm::from_fields(&form.fields);
    if let Some(response) = without_saving(&state, Some(id), &mut fields, &form).await {
        return response;
    }

    let input = match validate(&state, &fields, Some(id)).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, Some(id), &fields, Some(&message)).await;
        }
    };

    match state.database.update_rule(id, &input).await {
        Ok(true) => {
            state.config_changed();
            (form.token, Redirect::to("/rules")).into_response()
        }
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.delete_rule(id).await {
        Ok(true) => {
            state.config_changed();
            (form.token, Redirect::to("/rules")).into_response()
        }
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(settings: Value) -> RuleInput {
        RuleInput {
            name: "web".to_string(),
            priority: 100,
            condition: Some("true".to_string()),
            enabled: false,
            settings,
        }
    }

    #[test]
    fn a_rule_survives_the_trip_through_its_form() {
        let original = rule(json!({
            "interval_secs": 5,
            "facts_interval_secs": 60,
            "collectors": {
                "cpu": { "enabled": true },
                "memory": { "enabled": false },
                "disk": { "enabled": true, "mount_points": ["/", "/data"] },
            },
        }));

        assert_eq!(
            RuleForm::from_rule(&original)
                .to_rule(&BTreeMap::new())
                .unwrap(),
            original
        );
    }

    #[test]
    fn blank_settings_are_left_out_so_other_rules_decide() {
        let mut form = RuleForm::blank();
        form.name = "web".to_string();

        assert_eq!(form.to_rule(&BTreeMap::new()).unwrap().settings, json!({}));
    }

    #[test]
    fn mount_points_can_be_set_without_turning_the_collector_on() {
        let mut form = RuleForm::blank();
        form.mount_points = "/\n\n  /data  \n".to_string();

        assert_eq!(
            form.to_rule(&BTreeMap::new()).unwrap().settings,
            json!({ "collectors": { "disk": { "mount_points": ["/", "/data"] } } })
        );
    }

    #[test]
    fn an_empty_condition_means_every_agent() {
        let mut form = RuleForm::blank();
        form.use_expression = true;
        form.condition = "   ".to_string();

        assert_eq!(form.to_rule(&BTreeMap::new()).unwrap().condition, None);
    }

    #[test]
    fn numbers_are_checked() {
        let mut form = RuleForm::blank();
        form.interval_secs = "soon".to_string();
        assert!(form.to_rule(&BTreeMap::new()).is_err());

        let mut form = RuleForm::blank();
        form.priority = "high".to_string();
        assert!(form.to_rule(&BTreeMap::new()).is_err());
    }

    #[test]
    fn an_unknown_collector_choice_is_refused() {
        let mut form = RuleForm::blank();
        form.collectors[0].choice = "maybe".to_string();

        assert!(form.to_rule(&BTreeMap::new()).is_err());
    }

    fn fact(name: &str, operator: &str, value: &str) -> ClauseRow {
        ClauseRow {
            fact: name.to_string(),
            operator: operator.to_string(),
            value: value.to_string(),
            kind: "string".to_string(),
        }
    }

    fn built(rows: Vec<ClauseRow>) -> RuleForm {
        let mut form = RuleForm::blank();
        form.clauses = rows;
        form
    }

    fn known() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn the_builder_writes_the_condition() {
        let form = built(vec![
            fact("os.family", "equals", "linux"),
            fact("host.name", "starts_with", "web-"),
        ]);

        assert_eq!(
            form.to_rule(&known()).unwrap().condition.as_deref(),
            Some(r#"facts.os.family == "linux" && facts.host.name.startsWith("web-")"#)
        );
    }

    #[test]
    fn blank_rows_are_ignored() {
        let form = built(vec![
            ClauseRow::blank(),
            fact("os.family", "equals", "linux"),
        ]);

        assert_eq!(
            form.to_rule(&known()).unwrap().condition.as_deref(),
            Some(r#"facts.os.family == "linux""#)
        );
        assert_eq!(
            built(vec![ClauseRow::blank()])
                .to_rule(&known())
                .unwrap()
                .condition,
            None
        );
    }

    #[test]
    fn a_simple_condition_opens_in_the_builder() {
        let mut input = rule(json!({}));
        input.condition = Some(r#"facts.os.family == "linux""#.to_string());

        let form = RuleForm::from_rule(&input);

        assert!(!form.use_expression);
        assert_eq!(form.clauses[0].fact, "os.family");
        assert_eq!(form.clauses[0].value, "linux");
        assert_eq!(form.to_rule(&known()).unwrap(), input);
    }

    #[test]
    fn a_complex_condition_stays_as_written() {
        let mut input = rule(json!({}));
        input.condition = Some(r#"(facts.a == "x" || facts.b == "y") && true"#.to_string());

        let form = RuleForm::from_rule(&input);

        assert!(form.use_expression);
        assert!(form.note.is_some());
        assert_eq!(form.to_rule(&known()).unwrap(), input);
    }

    #[test]
    fn rows_can_be_added_and_removed() {
        let mut form = built(vec![fact("a", "equals", "1"), fact("b", "equals", "2")]);

        assert!(apply_form_action(&mut form, "add_clause", &known()));
        assert_eq!(form.clauses.len(), 3);

        assert!(apply_form_action(&mut form, "remove_clause_0", &known()));
        assert_eq!(form.clauses[0].fact, "b");

        // An index past the end changes nothing.
        assert!(apply_form_action(&mut form, "remove_clause_9", &known()));
        assert_eq!(form.clauses.len(), 2);
    }

    #[test]
    fn removing_the_last_row_leaves_an_empty_one() {
        let mut form = built(vec![fact("a", "equals", "1")]);

        apply_form_action(&mut form, "remove_clause_0", &known());

        assert_eq!(form.clauses.len(), 1);
        assert!(form.clauses[0].is_blank());
    }

    #[test]
    fn switching_to_the_expression_keeps_the_conditions() {
        let mut form = built(vec![fact("os.family", "equals", "linux")]);

        apply_form_action(&mut form, "use_expression", &known());

        assert!(form.use_expression);
        assert_eq!(form.condition, r#"facts.os.family == "linux""#);
    }

    #[test]
    fn switching_back_reads_the_expression_or_explains_why_not() {
        let mut form = RuleForm::blank();
        form.use_expression = true;
        form.condition = r#"facts.os.family == "linux""#.to_string();
        apply_form_action(&mut form, "use_builder", &known());
        assert!(!form.use_expression);
        assert_eq!(form.clauses[0].value, "linux");

        let mut form = RuleForm::blank();
        form.use_expression = true;
        form.condition = "1 + 1 == 2".to_string();
        apply_form_action(&mut form, "use_builder", &known());
        assert!(form.use_expression);
        assert!(form.note.is_some());
        assert_eq!(form.condition, "1 + 1 == 2");
    }

    #[test]
    fn saving_is_not_a_form_action() {
        assert!(!apply_form_action(&mut RuleForm::blank(), "", &known()));
    }

    #[test]
    fn a_rule_is_summarized_in_a_few_words() {
        let settings = json!({
            "interval_secs": 5,
            "collectors": { "cpu": { "enabled": true }, "disk": { "enabled": false } },
        });

        assert_eq!(summarize(&settings), "every 5s · on: cpu · off: disk");
    }
}
