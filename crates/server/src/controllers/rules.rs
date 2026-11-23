use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use maxnines_protocol::{
    COLLECTORS, Check, CheckKind, DATABASE_EXTRAS, DatabaseChoice, LocalCheck, default_status_page,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::condition_form::{ConditionForm, operators};
use super::{CsrfForm, Page, local_date, server_error};
use crate::alerting::NameTaken;
use crate::app_state::AppState;
use crate::condition_builder::Builder;
use crate::facts::unflatten;
use crate::models::{ConfigRule, RuleInput, RuleTemplate};
use crate::registration::HostState;
use crate::rule_engine::{self, CompiledRule, Host, OPERATING_SYSTEMS};
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
    command_names: String,
    counter_names: String,
    service_names: String,
    file_paths: String,
    apache_urls: String,
    nginx_urls: String,
    php_fpm_urls: String,
    openmetrics_urls: String,
    openmetrics_names: String,
    openmetrics_local: String,
    checks: String,
    local_checks: String,
    databases: String,
    collectors: Vec<CollectorChoice>,
    operating_systems: Vec<SystemChoice>,
    /// Whether it comes with MaxNines, so only turning it on or off is allowed.
    built_in: bool,
    /// When an upgrade last changed it, for a built-in rule.
    built_in_changed: Option<String>,
    /// For a built-in rule, the template it's the settings of.
    template: Option<RuleTemplate>,
}

/// Whether a rule is for one operating system.
#[derive(Serialize)]
struct SystemChoice {
    key: &'static str,
    label: &'static str,
    checked: bool,
}

fn systems(checked: impl Fn(&str) -> bool) -> Vec<SystemChoice> {
    OPERATING_SYSTEMS
        .iter()
        .map(|(key, label)| SystemChoice {
            key,
            label,
            checked: checked(key),
        })
        .collect()
}

/// Operating systems in words, such as "Linux and Windows".
fn systems_label(keys: &[String]) -> Option<String> {
    let labels: Vec<&str> = OPERATING_SYSTEMS
        .iter()
        .filter(|(key, _)| keys.iter().any(|wanted| wanted == key))
        .map(|(_, label)| *label)
        .collect();
    match labels.as_slice() {
        [] => None,
        [one] => Some((*one).to_string()),
        [rest @ .., last] => Some(format!("{} and {last}", rest.join(", "))),
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
            applies_to: ConditionForm::blank(),
            collectors: choices(|_| "inherit".to_string()),
            operating_systems: systems(|_| false),
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
            command_names: lines(&rule.settings["collectors"]["commands"]["names"]),
            counter_names: lines(&rule.settings["collectors"]["counters"]["names"]),
            service_names: lines(&rule.settings["collectors"]["services"]["names"]),
            file_paths: lines(&rule.settings["collectors"]["files"]["paths"]),
            apache_urls: lines(&rule.settings["collectors"]["apache"]["urls"]),
            nginx_urls: lines(&rule.settings["collectors"]["nginx"]["urls"]),
            php_fpm_urls: lines(&rule.settings["collectors"]["php_fpm"]["urls"]),
            openmetrics_urls: lines(&rule.settings["collectors"]["openmetrics"]["urls"]),
            openmetrics_names: lines(&rule.settings["collectors"]["openmetrics"]["names"]),
            openmetrics_local: lines(&rule.settings["collectors"]["openmetrics"]["local_pages"]),
            checks: check_lines(&rule.settings["collectors"]["checks"]["checks"]),
            local_checks: local_check_lines(&rule.settings["collectors"]["checks"]["local_checks"]),
            databases: database_lines(&rule.settings["collectors"]["databases"]["databases"]),
            collectors: choices(|name| {
                match rule.settings["collectors"][name]["enabled"].as_bool() {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => "inherit",
                }
                .to_string()
            }),
            applies_to: ConditionForm::from_condition(rule.applies_to.as_deref()),
            operating_systems: systems(|key| rule.operating_systems.iter().any(|os| os == key)),
            built_in: false,
            built_in_changed: None,
            template: None,
        }
    }

    /// A saved rule, saying whether it's built in.
    fn from_saved(saved: &ConfigRule) -> Self {
        Self {
            built_in: saved.built_in.is_some(),
            built_in_changed: saved.built_in_changed_at.map(local_date),
            template: saved.template.clone(),
            ..Self::from_rule(&saved.rule)
        }
    }

    /// A new rule that applies just after `saved`, to the same hosts, to change
    /// what it sets.
    fn after(saved: &ConfigRule) -> Self {
        Self {
            name: format!("{} changes", saved.rule.name),
            priority: (saved.rule.priority + 1).to_string(),
            applies_to: ConditionForm::from_condition(saved.rule.applies_to.as_deref()),
            operating_systems: systems(|key| {
                saved.rule.operating_systems.iter().any(|os| os == key)
            }),
            ..Self::blank()
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
            command_names: text("command_names"),
            counter_names: text("counter_names"),
            service_names: text("service_names"),
            file_paths: text("file_paths"),
            apache_urls: text("apache_urls"),
            nginx_urls: text("nginx_urls"),
            php_fpm_urls: text("php_fpm_urls"),
            openmetrics_urls: text("openmetrics_urls"),
            openmetrics_names: text("openmetrics_names"),
            openmetrics_local: text("openmetrics_local"),
            checks: text("checks"),
            local_checks: text("local_checks"),
            databases: text("databases"),
            collectors: choices(|name| text(&format!("collector_{name}"))),
            operating_systems: systems(|key| fields.contains_key(&format!("os_{key}"))),
            built_in: false,
            built_in_changed: None,
            template: None,
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
            let lists = match collector.name {
                "disk" => vec![("mount_points", &self.mount_points)],
                "processes" => vec![("names", &self.process_names)],
                "custom" => vec![("names", &self.custom_names)],
                "commands" => vec![("names", &self.command_names)],
                "counters" => vec![("names", &self.counter_names)],
                "services" => vec![("names", &self.service_names)],
                "files" => vec![("paths", &self.file_paths)],
                "apache" => vec![("urls", &self.apache_urls)],
                "nginx" => vec![("urls", &self.nginx_urls)],
                "php_fpm" => vec![("urls", &self.php_fpm_urls)],
                "openmetrics" => vec![
                    ("urls", &self.openmetrics_urls),
                    ("local_pages", &self.openmetrics_local),
                    ("names", &self.openmetrics_names),
                ],
                _ => Vec::new(),
            };
            for (name, text) in lists {
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
                let local = parse_local_checks(&self.local_checks)?;
                if !local.is_empty() {
                    fields.insert("local_checks".to_string(), json!(local));
                }
            }
            if collector.name == "databases" {
                let databases = parse_databases(&self.databases)?;
                if !databases.is_empty() {
                    fields.insert("databases".to_string(), json!(databases));
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
            applies_to: self.applies_to.expression(known)?,
            operating_systems: self
                .operating_systems
                .iter()
                .filter(|system| system.checked)
                .map(|system| system.key.to_string())
                .collect(),
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
        "timeout" => check.timeout = Some(Duration::from_secs(number()?)),
        "interval" => check.interval = Some(Duration::from_secs(number()?)),
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
        (
            "timeout",
            check.timeout.map(|value| value.as_secs().to_string()),
        ),
        (
            "interval",
            check.interval.map(|value| value.as_secs().to_string()),
        ),
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

/// Checks an agent's own config defines are typed one per line, by name, with
/// `timeout=5` or `interval=300` after it if wanted.
fn parse_local_checks(text: &str) -> Result<Vec<LocalCheck>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let words = split_words(line)?;
            let [name, options @ ..] = &words[..] else {
                bail!("{line:?} should start with a check's name");
            };
            let mut check = LocalCheck::new(name);
            for option in options {
                let (key, value) = option.split_once('=').unwrap_or((option, ""));
                let seconds = || -> Result<Option<Duration>> {
                    let seconds = value.parse().with_context(|| {
                        format!("{key} should be a whole number of seconds, in {line:?}")
                    })?;
                    Ok(Some(Duration::from_secs(seconds)))
                };
                match key {
                    "timeout" => check.timeout = seconds()?,
                    "interval" => check.interval = seconds()?,
                    other => bail!(
                        "{other:?} isn't an option here, where only timeout and interval \
                         are, in {line:?}"
                    ),
                }
            }
            Ok(check)
        })
        .collect()
}

/// Databases an agent's own config defines are typed one per line, by name,
/// with any extras to read after it, such as `orders sizes`.
fn parse_databases(text: &str) -> Result<Vec<DatabaseChoice>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut words = line.split_whitespace().map(str::to_string);
            let name = words.next().unwrap_or_default();
            Ok(DatabaseChoice {
                name,
                extras: words.collect(),
            })
        })
        .collect()
}

fn database_lines(value: &Value) -> String {
    let databases: Vec<DatabaseChoice> = serde_json::from_value(value.clone()).unwrap_or_default();
    let lines: Vec<String> = databases
        .iter()
        .map(|database| {
            std::iter::once(database.name.as_str())
                .chain(database.extras.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    lines.join("\n")
}

fn local_check_lines(value: &Value) -> String {
    let checks: Vec<LocalCheck> = serde_json::from_value(value.clone()).unwrap_or_default();
    let lines: Vec<String> = checks
        .iter()
        .map(|check| {
            let mut words = vec![quote(&check.name)];
            if let Some(timeout) = check.timeout {
                words.push(format!("timeout={}", timeout.as_secs()));
            }
            if let Some(interval) = check.interval {
                words.push(format!("interval={}", interval.as_secs()));
            }
            words.join(" ")
        })
        .collect();
    lines.join("\n")
}

fn check_lines(value: &Value) -> String {
    let checks: Vec<Check> = serde_json::from_value(value.clone()).unwrap_or_default();
    let lines: Vec<String> = checks.iter().map(check_line).collect();
    lines.join("\n")
}

/// Where each status page collector looks when a rule doesn't say.
fn default_pages() -> BTreeMap<&'static str, &'static str> {
    COLLECTORS
        .iter()
        .filter_map(|name| Some((*name, default_status_page(name)?)))
        .collect()
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
    applies_to: Option<String>,
    /// Which hosts in plain words, if it's simple enough.
    description: Option<String>,
    enabled: bool,
    summary: String,
    /// How many approved agents it applies to.
    hosts: usize,
    /// The operating systems it's limited to, in words.
    systems: Option<String>,
    built_in: bool,
    built_in_changed: Option<String>,
    /// Whether it's turned on but not in force, as its template is turned off.
    template_off: bool,
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
    let hosts: Vec<(String, Value)> = state
        .registry
        .list()
        .await
        .into_iter()
        // Config rules are for agents, so a host with none never matches one.
        .filter(|host| {
            host.state == HostState::Approved && !host.is_local() && !host.is_agentless()
        })
        .map(|host| {
            // No facts yet is an empty set, as it is when a config is worked out,
            // or `has()` in a condition would fail here and pass there.
            let shape = facts
                .get(&host.id)
                .map_or_else(|| Value::Object(Map::new()), unflatten);
            (host.id, shape)
        })
        .collect();

    // Each host's facts are made ready for conditions once, for every rule.
    let hosts: Vec<Host> = hosts
        .iter()
        .map(|(id, facts)| Host::new(facts, id))
        .collect();
    let compiled = match rules
        .into_iter()
        .map(CompiledRule::new)
        .collect::<Result<Vec<_>>>()
    {
        Ok(compiled) => compiled,
        Err(error) => return server_error(&error),
    };
    let rows: Vec<RuleRow> = compiled
        .into_iter()
        .map(|compiled| {
            (
                hosts.iter().filter(|host| compiled.matches(host)).count(),
                compiled.rule,
            )
        })
        .map(|(matching, rule)| RuleRow {
            id: rule.id,
            hosts: matching,
            summary: summarize(&rule.rule.settings),
            systems: systems_label(&rule.rule.operating_systems),
            built_in: rule.built_in.is_some(),
            built_in_changed: rule.built_in_changed_at.map(local_date),
            template_off: rule.rule.enabled && !rule.in_force(),
            description: rule
                .rule
                .applies_to
                .as_deref()
                .and_then(Builder::from_expression)
                .map(|builder| builder.describe()),
            name: rule.rule.name,
            priority: rule.rule.priority,
            applies_to: rule.rule.applies_to,
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
    // What agents' own configs allow, to choose from. The form works without.
    let mut allowed = BTreeMap::new();
    for list in ["custom_metrics", "check_commands", "checks", "openmetrics"] {
        let names = state
            .database
            .listed_by_agents(&format!("agent.{list}"))
            .await
            .unwrap_or_default();
        allowed.insert(list, names);
    }
    // Databases are named with their kind, `{"orders": "postgres"}`.
    let databases = state.database.keyed_by_agents("agent.databases").await;
    allowed.insert("databases", databases.unwrap_or_default());

    Page::new(state, token, "rules/form.html")
        .with("allowed", &allowed)
        .with("database_extras", &DATABASE_EXTRAS)
        .with("id", &id)
        .with("rule", form)
        .with("operators", &operators())
        .with("known_facts", &known)
        .with("default_pages", &default_pages())
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

#[derive(Deserialize)]
struct NewParams {
    /// A rule the new one is to change, which it applies just after.
    from: Option<i64>,
}

async fn new(
    State(state): State<AppState>,
    Query(params): Query<NewParams>,
    token: CsrfToken,
) -> Response {
    let form = match params.from {
        None => RuleForm::blank(),
        Some(id) => match state.database.get_rule(id).await {
            Ok(Some(saved)) => RuleForm::after(&saved),
            Ok(None) => RuleForm::blank(),
            Err(error) => return server_error(&error),
        },
    };
    form_page(&state, &token, None, &form, None).await
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_rule(id).await {
        Ok(Some(rule)) => {
            form_page(&state, &token, Some(id), &RuleForm::from_saved(&rule), None).await
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
async fn validate(state: &AppState, form: &RuleForm) -> Result<RuleInput> {
    let input = form.to_rule(&known_facts(state).await)?;
    rule_engine::check_rule(&input)?;
    // A name another rule has is refused as the rule is saved, as only the database
    // can tell for certain.
    Ok(input)
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let mut fields = RuleForm::from_fields(&form.fields);
    if let Some(response) = without_saving(&state, None, &mut fields, &form).await {
        return response;
    }

    let input = match validate(&state, &fields).await {
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
        Err(error) if error.is::<NameTaken>() => {
            let message = format!("{error:#}");
            form_page(&state, &form.token, None, &fields, Some(&message)).await
        }
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    // A built-in rule's form only sends whether it's on, the rest being locked.
    match state.database.get_rule(id).await {
        Ok(Some(saved)) if saved.built_in.is_some() => {
            let enabled = form.fields.contains_key("enabled");
            return match state.database.set_rule_enabled(id, enabled).await {
                Ok(true) => {
                    state.config_changed();
                    (form.token, Redirect::to("/rules")).into_response()
                }
                Ok(false) => not_found(&state, &form.token),
                Err(error) => server_error(&error),
            };
        }
        Ok(_) => {}
        Err(error) => return server_error(&error),
    }
    let mut fields = RuleForm::from_fields(&form.fields);
    if let Some(response) = without_saving(&state, Some(id), &mut fields, &form).await {
        return response;
    }

    let input = match validate(&state, &fields).await {
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
        Err(error) if error.is::<NameTaken>() => {
            let message = format!("{error:#}");
            form_page(&state, &form.token, Some(id), &fields, Some(&message)).await
        }
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.get_rule(id).await {
        Ok(Some(saved)) if saved.built_in.is_some() => {
            let why = "A rule that comes with MaxNines can't be deleted, but it can be turned off.";
            let fields = RuleForm::from_saved(&saved);
            return form_page(&state, &form.token, Some(id), &fields, Some(why)).await;
        }
        Ok(_) => {}
        Err(error) => return server_error(&error),
    }
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
            applies_to: Some("true".to_string()),
            operating_systems: Vec::new(),
            enabled: false,
            settings,
        }
    }

    #[test]
    fn databases_are_named_with_their_extras() {
        let databases = parse_databases("orders sizes\n\n  cache  ").unwrap();
        assert_eq!(databases[0].name, "orders");
        assert_eq!(databases[0].extras, ["sizes"]);
        assert!(databases[1].extras.is_empty());
        assert_eq!(database_lines(&json!(databases)), "orders sizes\ncache");
    }

    #[test]
    fn checks_from_the_agents_config_are_named_with_their_timing() {
        let checks =
            parse_local_checks("bastion\n\n \"mail box\" interval=300 timeout=5 ").unwrap();
        assert_eq!(checks[0], LocalCheck::new("bastion"));
        assert_eq!(checks[1].name, "mail box");
        assert_eq!(checks[1].interval, Some(Duration::from_secs(300)));
        assert_eq!(checks[1].timeout, Some(Duration::from_secs(5)));
        let lines = local_check_lines(&json!(checks));
        assert_eq!(lines, "bastion\n\"mail box\" timeout=5 interval=300");
        assert_eq!(parse_local_checks(&lines).unwrap(), checks);
        for bad in ["bastion target=x", "bastion interval=soon"] {
            assert!(parse_local_checks(bad).is_err(), "{bad}");
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
        let line = r#"http site https://example.com/ timeout=5 interval=300 regex="Welcome \"back\"" insecure"#;
        let checks = parse_checks(line).unwrap();
        assert_eq!(checks[0].timeout, Some(Duration::from_secs(5)));
        assert_eq!(checks[0].interval, Some(Duration::from_secs(300)));
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
                "commands": { "enabled": true, "names": ["raid", "smart.sda"] },
                "counters": {
                    "enabled": true,
                    "names": ["\\Memory\\Available MBytes", "\\PhysicalDisk(*)\\Disk Reads/sec"]
                },
                "files": { "enabled": true, "paths": ["/var/backup/latest.tar"] },
                "apache": { "urls": ["http://localhost/server-status?auto"] },
                "php_fpm": {
                    "enabled": true,
                    "urls": ["http://localhost/status-www", "http://localhost/status-api"]
                },
                "openmetrics": {
                    "urls": ["http://localhost:9100/metrics", "http://localhost:9187/metrics"],
                    "names": ["node_load*", "pg_up"]
                },
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
        form.applies_to.text = "   ".to_string();

        assert_eq!(form.to_rule(&BTreeMap::new()).unwrap().applies_to, None);
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
            form.to_rule(&known()).unwrap().applies_to.as_deref(),
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
            form.to_rule(&known()).unwrap().applies_to.as_deref(),
            Some(r#"facts.os.family == "linux""#)
        );
        assert_eq!(
            built(vec![ClauseRow::blank()])
                .to_rule(&known())
                .unwrap()
                .applies_to,
            None
        );
    }

    #[test]
    fn a_simple_condition_opens_in_the_builder() {
        let mut input = rule(json!({}));
        input.applies_to = Some(r#"facts.os.family == "linux""#.to_string());

        let form = RuleForm::from_rule(&input);

        assert!(!form.applies_to.use_expression);
        assert_eq!(form.applies_to.clauses[0].fact, "os.family");
        assert_eq!(form.applies_to.clauses[0].value, "linux");
        assert_eq!(form.to_rule(&known()).unwrap(), input);
    }

    #[test]
    fn a_complex_condition_stays_as_written() {
        let mut input = rule(json!({}));
        input.applies_to = Some(r#"(facts.a == "x" || facts.b == "y") && true"#.to_string());

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
        assert_eq!(form.applies_to.text, r#"facts.os.family == "linux""#);
    }

    #[test]
    fn switching_back_reads_the_expression_or_explains_why_not() {
        let mut form = RuleForm::blank();
        form.applies_to.use_expression = true;
        form.applies_to.text = r#"facts.os.family == "linux""#.to_string();
        form.applies_to.apply_action("use_builder", &known());
        assert!(!form.applies_to.use_expression);
        assert_eq!(form.applies_to.clauses[0].value, "linux");

        let mut form = RuleForm::blank();
        form.applies_to.use_expression = true;
        form.applies_to.text = "1 + 1 == 2".to_string();
        form.applies_to.apply_action("use_builder", &known());
        assert!(form.applies_to.use_expression);
        assert!(form.applies_to.note.is_some());
        assert_eq!(form.applies_to.text, "1 + 1 == 2");
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
