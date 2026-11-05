use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use maxnines_protocol::{COLLECTORS, Check, CheckKind};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::condition_form::{ConditionForm, operators};
use super::{CsrfForm, Page, server_error};
use crate::app_state::AppState;
use crate::condition_builder::Builder;
use crate::facts::unflatten;
use crate::models::RuleInput;
use crate::registration::AgentState;
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
    #[serde(flatten)]
    applies_to: ConditionForm,
    enabled: bool,
    interval_secs: String,
    facts_interval_secs: String,
    mount_points: String,
    process_names: String,
    custom_names: String,
    service_names: String,
    file_paths: String,
    checks: String,
    collectors: Vec<CollectorChoice>,
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
            applies_to: ConditionForm::blank(),
            collectors: choices(|_| "inherit".to_string()),
            ..Self::default()
        }
    }

    fn from_rule(rule: &RuleInput) -> Self {
        let number = |name: &str| match &rule.settings[name] {
            Value::Null => String::new(),
            value => value.to_string(),
        };
        let lines = |value: &Value| {
            value
                .as_array()
                .map(|items| {
                    let lines: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                    lines.join("\n")
                })
                .unwrap_or_default()
        };

        Self {
            name: rule.name.clone(),
            priority: rule.priority.to_string(),
            enabled: rule.enabled,
            interval_secs: number("interval_secs"),
            facts_interval_secs: number("facts_interval_secs"),
            mount_points: lines(&rule.settings["collectors"]["disk"]["mount_points"]),
            process_names: lines(&rule.settings["collectors"]["processes"]["names"]),
            custom_names: lines(&rule.settings["collectors"]["custom"]["names"]),
            service_names: lines(&rule.settings["collectors"]["services"]["names"]),
            file_paths: lines(&rule.settings["collectors"]["files"]["paths"]),
            checks: check_lines(&rule.settings["collectors"]["checks"]["checks"]),
            collectors: choices(|name| {
                match rule.settings["collectors"][name]["enabled"].as_bool() {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => "inherit",
                }
                .to_string()
            }),
            applies_to: ConditionForm::from_condition(rule.condition.as_deref()),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            name: text("name"),
            priority: text("priority"),
            applies_to: ConditionForm::from_fields(fields),
            enabled: fields.contains_key("enabled"),
            interval_secs: text("interval_secs"),
            facts_interval_secs: text("facts_interval_secs"),
            mount_points: text("mount_points"),
            process_names: text("process_names"),
            custom_names: text("custom_names"),
            service_names: text("service_names"),
            file_paths: text("file_paths"),
            checks: text("checks"),
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
            let list = match collector.name {
                "disk" => Some(("mount_points", &self.mount_points)),
                "processes" => Some(("names", &self.process_names)),
                "custom" => Some(("names", &self.custom_names)),
                "services" => Some(("names", &self.service_names)),
                "files" => Some(("paths", &self.file_paths)),
                _ => None,
            };
            if let Some((name, text)) = list {
                let lines: Vec<&str> = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .collect();
                if !lines.is_empty() {
                    fields.insert(name.to_string(), json!(lines));
                }
            }
            if collector.name == "checks" {
                let checks = parse_checks(&self.checks)?;
                if !checks.is_empty() {
                    fields.insert("checks".to_string(), json!(checks));
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
            condition: self.applies_to.expression(known)?,
            enabled: self.enabled,
            settings: Value::Object(settings),
        })
    }
}

/// Splits a line on spaces, except inside double quotes, where `\"` and `\\`
/// stand for themselves.
fn split_words(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let (mut in_word, mut quoted) = (false, false);
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        match character {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            '\\' if quoted => word.extend(characters.next()),
            ' ' | '\t' if !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            other => {
                word.push(other);
                in_word = true;
            }
        }
    }
    if quoted {
        bail!("{line:?} has an opening quote with no closing quote");
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

fn quote(text: &str) -> String {
    if text.is_empty() || text.contains([' ', '\t', '"', '\\']) {
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        text.to_string()
    }
}

fn set_option(check: &mut Check, option: &str, line: &str) -> Result<()> {
    if option == "insecure" {
        check.insecure = Some(true);
        return Ok(());
    }
    let Some((name, value)) = option.split_once('=') else {
        bail!("{option:?} isn't an option, in {line:?}");
    };
    let number = || {
        value
            .parse()
            .with_context(|| format!("{name} has to be a number, in {line:?}"))
    };
    match name {
        "timeout" => check.timeout_secs = Some(number()?),
        "count" => check.count = Some(u32::try_from(number()?)?),
        "method" => check.method = Some(value.to_string()),
        "body" => check.body = Some(value.to_string()),
        "regex" => check.regex = Some(value.to_string()),
        "server" => check.server = Some(value.to_string()),
        "record" => check.record = Some(value.to_string()),
        other => bail!("{other:?} isn't an option, in {line:?}"),
    }
    Ok(())
}

/// Checks are typed one per line, as `kind name target` and then any options,
/// such as `timeout=5` or `regex="Welcome back"`.
fn parse_checks(text: &str) -> Result<Vec<Check>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let words = split_words(line)?;
            let [kind, name, target, options @ ..] = &words[..] else {
                bail!("{line:?} should be a kind, a name and a target, such as: tcp db db1:5432");
            };
            let kind = CheckKind::parse(kind)
                .with_context(|| format!("{kind:?} isn't a kind of check, in {line:?}"))?;
            let mut check = Check::new(name, kind, target);
            for option in options {
                set_option(&mut check, option, line)?;
            }
            Ok(check)
        })
        .collect()
}

fn check_line(check: &Check) -> String {
    let mut words = vec![
        check.kind.as_str().to_string(),
        quote(&check.name),
        quote(&check.target),
    ];
    let options = [
        ("timeout", check.timeout_secs.map(|value| value.to_string())),
        ("method", check.method.clone()),
        ("body", check.body.clone()),
        ("regex", check.regex.clone()),
        ("server", check.server.clone()),
        ("record", check.record.clone()),
        ("count", check.count.map(|value| value.to_string())),
    ];
    for (name, value) in options {
        if let Some(value) = value {
            words.push(format!("{name}={}", quote(&value)));
        }
    }
    if check.insecure == Some(true) {
        words.push("insecure".to_string());
    }
    words.join(" ")
}

fn check_lines(value: &Value) -> String {
    let checks: Vec<Check> = serde_json::from_value(value.clone()).unwrap_or_default();
    let lines: Vec<String> = checks.iter().map(check_line).collect();
    lines.join("\n")
}

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
    /// How many approved agents it applies to.
    agents: usize,
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
    let facts = match state.database.all_current_facts().await {
        Ok(facts) => facts,
        Err(error) => return server_error(&error),
    };
    let agents: Vec<(String, Value)> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|agent| agent.state == AgentState::Approved && !agent.is_local())
        .map(|agent| {
            let shape = facts.get(&agent.id).map(unflatten).unwrap_or(Value::Null);
            (agent.id, shape)
        })
        .collect();

    let rows: Vec<RuleRow> = rules
        .into_iter()
        .map(|rule| RuleRow {
            id: rule.id,
            agents: agents
                .iter()
                .filter(|(id, facts)| rule_engine::matches(&rule.rule, facts, id))
                .count(),
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

/// The rule form, ready to render.
async fn form_view<'a>(
    state: &'a AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &RuleForm,
) -> Page<'a> {
    let known: Vec<String> = known_facts(state).await.into_keys().collect();

    Page::new(state, token, "rules/form.html")
        .with("id", &id)
        .with("rule", form)
        .with("operators", &operators())
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
    if fields
        .applies_to
        .apply_action(&action, &known_facts(state).await)
    {
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
    use super::super::condition_form::ClauseRow;
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
    fn checks_are_typed_one_per_line() {
        let checks = parse_checks("tcp db db1:5432\n\n  ping gw 10.0.0.1  \n").unwrap();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].kind, CheckKind::Tcp);
        assert_eq!(checks[0].name, "db");
        assert_eq!(checks[1].target, "10.0.0.1");
    }

    #[test]
    fn check_options_can_follow_the_target() {
        let line = r#"http site https://example.com/ timeout=5 regex="Welcome \"back\"" insecure"#;
        let checks = parse_checks(line).unwrap();
        assert_eq!(checks[0].timeout_secs, Some(5));
        assert_eq!(checks[0].regex.as_deref(), Some(r#"Welcome "back""#));
        assert_eq!(checks[0].insecure, Some(true));
    }

    #[test]
    fn a_badly_typed_option_is_explained() {
        for (line, expected) in [
            ("tcp a b:1 nonsense", "isn't an option"),
            ("tcp a b:1 color=red", "isn't an option"),
            ("tcp a b:1 timeout=soon", "has to be a number"),
            (r#"http a http://b regex="open"#, "no closing quote"),
        ] {
            let error = format!("{:#}", parse_checks(line).unwrap_err());
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_badly_typed_check_is_explained() {
        for (line, expected) in [
            ("tcp db", "should be a kind"),
            ("gopher db a:1", "isn't a kind of check"),
        ] {
            let error = format!("{:#}", parse_checks(line).unwrap_err());
            assert!(error.contains(expected), "{error}");
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
                "processes": { "enabled": true, "names": ["nginx", "postgres"] },
                "services": { "enabled": true, "names": ["nginx.service"] },
                "custom": { "enabled": true, "names": ["queue", "disk.temp"] },
                "files": { "enabled": true, "paths": ["/var/backup/latest.tar"] },
                "checks": { "enabled": true, "checks": [
                    { "name": "db", "kind": "tcp", "target": "db1:5432" },
                    { "name": "site", "kind": "http", "target": "https://example.com/",
                      "timeout_secs": 5, "method": "POST", "body": "a b",
                      "regex": "Hello \\\"you\\\"\\d", "insecure": true },
                    { "name": "ns", "kind": "dns", "target": "example.com",
                      "server": "8.8.8.8", "record": "MX" },
                    { "name": "gw", "kind": "ping", "target": "10.0.0.1", "count": 3 },
                ] },
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
        form.applies_to.use_expression = true;
        form.applies_to.condition = "   ".to_string();

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
        form.applies_to.clauses = rows;
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

        assert!(!form.applies_to.use_expression);
        assert_eq!(form.applies_to.clauses[0].fact, "os.family");
        assert_eq!(form.applies_to.clauses[0].value, "linux");
        assert_eq!(form.to_rule(&known()).unwrap(), input);
    }

    #[test]
    fn a_complex_condition_stays_as_written() {
        let mut input = rule(json!({}));
        input.condition = Some(r#"(facts.a == "x" || facts.b == "y") && true"#.to_string());

        let form = RuleForm::from_rule(&input);

        assert!(form.applies_to.use_expression);
        assert!(form.applies_to.note.is_some());
        assert_eq!(form.to_rule(&known()).unwrap(), input);
    }

    #[test]
    fn rows_can_be_added_and_removed() {
        let mut form = built(vec![fact("a", "equals", "1"), fact("b", "equals", "2")]);

        assert!(form.applies_to.apply_action("add_clause", &known()));
        assert_eq!(form.applies_to.clauses.len(), 3);

        assert!(form.applies_to.apply_action("remove_clause_0", &known()));
        assert_eq!(form.applies_to.clauses[0].fact, "b");

        // An index past the end changes nothing.
        assert!(form.applies_to.apply_action("remove_clause_9", &known()));
        assert_eq!(form.applies_to.clauses.len(), 2);
    }

    #[test]
    fn removing_the_last_row_leaves_an_empty_one() {
        let mut form = built(vec![fact("a", "equals", "1")]);

        form.applies_to.apply_action("remove_clause_0", &known());

        assert_eq!(form.applies_to.clauses.len(), 1);
        assert!(form.applies_to.clauses[0].is_blank());
    }

    #[test]
    fn switching_to_the_expression_keeps_the_conditions() {
        let mut form = built(vec![fact("os.family", "equals", "linux")]);

        form.applies_to.apply_action("use_expression", &known());

        assert!(form.applies_to.use_expression);
        assert_eq!(form.applies_to.condition, r#"facts.os.family == "linux""#);
    }

    #[test]
    fn switching_back_reads_the_expression_or_explains_why_not() {
        let mut form = RuleForm::blank();
        form.applies_to.use_expression = true;
        form.applies_to.condition = r#"facts.os.family == "linux""#.to_string();
        form.applies_to.apply_action("use_builder", &known());
        assert!(!form.applies_to.use_expression);
        assert_eq!(form.applies_to.clauses[0].value, "linux");

        let mut form = RuleForm::blank();
        form.applies_to.use_expression = true;
        form.applies_to.condition = "1 + 1 == 2".to_string();
        form.applies_to.apply_action("use_builder", &known());
        assert!(form.applies_to.use_expression);
        assert!(form.applies_to.note.is_some());
        assert_eq!(form.applies_to.condition, "1 + 1 == 2");
    }

    #[test]
    fn saving_is_not_a_form_action() {
        assert!(!RuleForm::blank().applies_to.apply_action("", &known()));
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
