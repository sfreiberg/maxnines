use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context as _, Result};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use chrono::TimeDelta;
use serde::Serialize;

use maxnines_protocol::actions::DEFAULT_ACTION_TIMEOUT;

use super::condition_form::{ConditionForm, operators};
use super::{CsrfForm, Page, server_error};
use crate::actions::{RuleAction, RunOn};
use crate::alert_replay::{Replay, replay};
use crate::alerting::{AlertRuleInput, NameTaken};
use crate::app_state::AppState;
use crate::calculations::Calculation;
use crate::condition_builder::Builder;
use crate::dashboards::grouping_fields;
use crate::metrics::{METRICS, Unit};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts/rules", get(index).post(create))
        .route("/alerts/rules/new", get(new))
        .route("/alerts/rules/{id}", post(update))
        .route("/alerts/rules/{id}/edit", get(edit))
        .route("/alerts/rules/{id}/delete", post(delete))
}

/// A rule as its form shows it, including whatever was just typed. The condition
/// fields for which hosts are flattened so the shared part of the form finds them.
#[derive(Serialize)]
struct AlertRuleForm {
    name: String,
    warning: String,
    critical: String,
    summary: String,
    resolved_summary: String,
    for_secs: String,
    enabled: bool,
    channels: BTreeSet<i64>,
    all_channels: bool,
    /// Empty for a rule about each host on its own.
    calculation: String,
    metric: String,
    group_by: String,
    fact: String,
    filter: String,
    /// Empty for the usual.
    window_secs: String,
    remind_every_minutes: String,
    /// What to run on the alert's host, one per line.
    actions: String,
    #[serde(flatten)]
    applies_to: ConditionForm,
}

/// An action is typed as its name, then when it runs and how long it gets if
/// they're not the usual: `disk_space on=critical timeout=120`.
fn parse_actions(text: &str) -> Result<Vec<RuleAction>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut words = line.split_whitespace();
            let action = words.next().unwrap_or_default().to_string();
            let mut wanted = RuleAction {
                action,
                run_on: RunOn::First,
                timeout: None,
            };
            for option in words {
                match option.split_once('=') {
                    Some(("on", when)) => {
                        wanted.run_on = RunOn::parse(when).with_context(|| {
                            format!("on= is first, warning or critical, in {line:?}")
                        })?;
                    }
                    Some(("timeout", secs)) => {
                        let secs = secs.parse().with_context(|| {
                            format!("timeout= has to be a number of seconds, in {line:?}")
                        })?;
                        wanted.timeout = Some(Duration::from_secs(secs));
                    }
                    _ => anyhow::bail!("{option:?} isn't an option, in {line:?}"),
                }
            }
            Ok(wanted)
        })
        .collect()
}

fn action_lines(actions: &[RuleAction]) -> String {
    let lines: Vec<String> = actions
        .iter()
        .map(|wanted| {
            let mut line = wanted.action.clone();
            if wanted.run_on != RunOn::First {
                line.push_str(&format!(" on={}", wanted.run_on.as_str()));
            }
            if wanted.timeout() != DEFAULT_ACTION_TIMEOUT {
                line.push_str(&format!(" timeout={}", wanted.timeout().as_secs()));
            }
            line
        })
        .collect();
    lines.join("\n")
}

impl AlertRuleForm {
    fn blank() -> Self {
        Self {
            name: String::new(),
            warning: String::new(),
            critical: String::new(),
            summary: String::new(),
            resolved_summary: String::new(),
            for_secs: "300".to_string(),
            enabled: true,
            channels: BTreeSet::new(),
            all_channels: false,
            calculation: String::new(),
            metric: METRICS[0].name.to_string(),
            group_by: "nothing".to_string(),
            fact: String::new(),
            filter: String::new(),
            window_secs: String::new(),
            remind_every_minutes: String::new(),
            actions: String::new(),
            applies_to: ConditionForm::blank(),
        }
    }

    fn from_rule(rule: &AlertRuleInput) -> Self {
        let blank = Self::blank();
        let (group_by, fact) = grouping_fields(rule.group_by.as_deref().unwrap_or_default());
        let text = |text: &Option<String>| text.clone().unwrap_or_default();
        Self {
            name: rule.name.clone(),
            warning: text(&rule.warning),
            critical: text(&rule.critical),
            summary: text(&rule.summary),
            resolved_summary: text(&rule.resolved_summary),
            for_secs: rule.hold.num_seconds().to_string(),
            enabled: rule.enabled,
            channels: rule.channels.iter().copied().collect(),
            all_channels: rule.all_channels,
            calculation: rule
                .calculation
                .map_or(String::new(), |c| c.as_str().to_string()),
            metric: rule.metric.clone().unwrap_or(blank.metric),
            group_by,
            fact,
            filter: text(&rule.filter),
            window_secs: rule
                .window
                .map(|window| window.num_seconds().to_string())
                .unwrap_or_default(),
            // Shown in minutes, with a fraction when the API set something finer.
            remind_every_minutes: rule
                .remind_every
                .map(|every| {
                    let secs = every.num_seconds();
                    if secs % 60 == 0 {
                        (secs / 60).to_string()
                    } else {
                        (secs as f64 / 60.0).to_string()
                    }
                })
                .unwrap_or_default(),
            actions: action_lines(&rule.actions),
            applies_to: ConditionForm::from_condition(rule.applies_to.as_deref()),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            name: text("name"),
            warning: text("warning"),
            critical: text("critical"),
            summary: text("summary"),
            resolved_summary: text("resolved_summary"),
            for_secs: text("for_secs"),
            enabled: fields.contains_key("enabled"),
            channels: fields
                .keys()
                .filter_map(|name| name.strip_prefix("channel_")?.parse().ok())
                .collect(),
            all_channels: fields.contains_key("all_channels"),
            calculation: text("calculation"),
            metric: text("metric"),
            group_by: text("group_by"),
            fact: text("fact").trim().to_string(),
            filter: text("filter").trim().to_string(),
            window_secs: text("window_secs").trim().to_string(),
            remind_every_minutes: text("remind_every_minutes").trim().to_string(),
            actions: text("actions"),
            applies_to: ConditionForm::from_fields(fields),
        }
    }

    fn to_rule(&self, known: &BTreeMap<String, String>) -> Result<AlertRuleInput> {
        let hold = whole_seconds(&self.for_secs)
            .context("the duration must be a whole number of seconds")?;
        let remind_every = match self.remind_every_minutes.as_str() {
            "" => None,
            text => {
                let minutes: f64 = text
                    .parse()
                    .ok()
                    .filter(|minutes: &f64| minutes.is_finite() && *minutes >= 0.0)
                    .context("reminders must be a number of minutes")?;
                Some(rounded_seconds(minutes * 60.0).context("reminders are too far apart")?)
            }
        };
        let calculation = match self.calculation.as_str() {
            "" => None,
            text => Some(
                Calculation::parse(text)
                    .with_context(|| format!("unknown calculation {text:?}"))?,
            ),
        };
        let window = match self.window_secs.as_str() {
            "" => None,
            text => Some(
                whole_seconds(text).context("how far back has to be a whole number of seconds")?,
            ),
        };
        let is_calculation = calculation.is_some();
        // The form always sends these, and they only mean something for a calculation.
        let only_for_calculations = |value: String| is_calculation.then_some(value);
        let group_by = if self.group_by == "fact" {
            format!("fact:{}", self.fact)
        } else {
            self.group_by.clone()
        };
        let applies_to = if is_calculation {
            None
        } else {
            self.applies_to.expression(known)?
        };
        let text = |text: &str| crate::text::trimmed(text);

        Ok(AlertRuleInput {
            name: self.name.trim().to_string(),
            warning: text(&self.warning),
            critical: text(&self.critical),
            summary: text(&self.summary),
            resolved_summary: text(&self.resolved_summary),
            hold,
            applies_to,
            enabled: self.enabled,
            channels: self.channels.iter().copied().collect(),
            all_channels: self.all_channels,
            calculation,
            metric: only_for_calculations(self.metric.clone()),
            group_by: only_for_calculations(group_by),
            filter: only_for_calculations(self.filter.clone()).filter(|text| !text.is_empty()),
            window,
            remind_every,
            actions: parse_actions(&self.actions)?,
        })
    }
}

/// Whole seconds typed into the form.
fn whole_seconds(text: &str) -> Option<TimeDelta> {
    let secs: u64 = text.trim().parse().ok()?;
    TimeDelta::try_seconds(i64::try_from(secs).ok()?)
}

/// A number of seconds worked out from what was typed, to the nearest second, as rules
/// keep them.
fn rounded_seconds(secs: f64) -> Option<TimeDelta> {
    let secs = secs.round();
    // Far beyond anything a rule allows, and still a length chrono can hold.
    (secs < 1e15).then(|| TimeDelta::seconds(secs as i64))
}

#[derive(Serialize)]
struct CalculationOption {
    value: &'static str,
    label: &'static str,
}

fn calculation_options() -> Vec<CalculationOption> {
    Calculation::ALL
        .into_iter()
        .map(|calculation| CalculationOption {
            value: calculation.as_str(),
            label: calculation.label(),
        })
        .collect()
}

#[derive(Serialize)]
struct MetricOption {
    name: &'static str,
    label: String,
}

/// The unit goes on the label, as a calculation's value is compared in it.
fn metric_options() -> Vec<MetricOption> {
    METRICS
        .iter()
        .map(|metric| MetricOption {
            name: metric.name,
            label: match metric.unit {
                Unit::Percent => format!("{} (%)", metric.title),
                Unit::Number => metric.title.to_string(),
                Unit::BytesPerSecond => format!("{} (bytes per second)", metric.title),
                Unit::PerSecond => format!("{} (per second)", metric.title),
                Unit::Bytes => format!("{} (bytes)", metric.title),
                Unit::Seconds => format!("{} (seconds)", metric.title),
                Unit::Celsius => format!("{} (°C)", metric.title),
            },
        })
        .collect()
}

#[derive(Serialize)]
struct ChannelChoice {
    id: i64,
    name: String,
    selected: bool,
}

/// Names to suggest. The form still works without them, and agents may not have
/// reported yet, so a failure here isn't worth stopping for.
async fn known_facts(state: &AppState) -> BTreeMap<String, String> {
    state.database.known_facts().await.unwrap_or_default()
}

async fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &AlertRuleForm,
    error: Option<&str>,
) -> Response {
    form_page_with(state, token, id, form, error, None).await
}

/// The form, with how often the rule as typed would have alerted, if that was asked.
async fn form_page_with(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    form: &AlertRuleForm,
    error: Option<&str>,
    replay: Option<&Replay>,
) -> Response {
    let channels = match state.database.list_channels().await {
        Ok(channels) => channels,
        Err(error) => return server_error(&error),
    };
    let channels: Vec<ChannelChoice> = channels
        .into_iter()
        .map(|channel| ChannelChoice {
            selected: form.channels.contains(&channel.id),
            id: channel.id,
            name: channel.channel.name,
        })
        .collect();
    let known: Vec<String> = known_facts(state).await.into_keys().collect();
    // What can be typed into the form's Actions box, with what each needs.
    let known_actions: Vec<String> = match state.database.known_actions().await {
        Ok(actions) => actions
            .into_iter()
            .map(|(name, needed)| match needed.as_slice() {
                [] => name,
                needed => format!("{name} (needs {{{}}})", needed.join("}, {")),
            })
            .collect(),
        Err(error) => return server_error(&error),
    };

    let page = Page::new(state, token, "alert_rules/form.html")
        .with("id", &id)
        .with("rule", form)
        .with("metrics", &metric_options())
        .with("calculations", &calculation_options())
        .with("channels", &channels)
        .with("operators", &operators())
        .with("known_facts", &known)
        .with("known_actions", &known_actions)
        .with("replay", &replay)
        .with("error", &error);
    match error {
        Some(_) => page.with_status(StatusCode::UNPROCESSABLE_ENTITY).render(),
        None => page.render(),
    }
}

#[derive(Serialize)]
struct RuleRow {
    id: i64,
    name: String,
    /// Each condition with its severity, mildest first.
    conditions: Vec<ConditionRow>,
    /// The calculation, and how long the problem has to last.
    watches: String,
    applies_to: String,
    channels: String,
    enabled: bool,
}

#[derive(Serialize)]
struct ConditionRow {
    severity: &'static str,
    text: String,
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let rows = async {
        let rules = state.database.list_alert_rules().await?;
        let channels = state.database.list_channels().await?;
        anyhow::Ok((rules, channels))
    };
    let (rules, channels) = match rows.await {
        Ok(rows) => rows,
        Err(error) => return server_error(&error),
    };

    let rows: Vec<RuleRow> = rules
        .into_iter()
        .map(|rule| {
            let names: Vec<&str> = channels
                .iter()
                .filter(|channel| rule.rule.channels.contains(&channel.id))
                .map(|channel| channel.channel.name.as_str())
                .collect();
            let conditions = [
                ("warning", &rule.rule.warning),
                ("critical", &rule.rule.critical),
            ]
            .into_iter()
            .filter_map(|(severity, text)| {
                Some(ConditionRow {
                    severity,
                    text: text.clone()?,
                })
            })
            .collect();
            RuleRow {
                id: rule.id,
                conditions,
                watches: rule.rule.describe(),
                applies_to: match (rule.rule.is_calculation(), rule.rule.applies_to.as_deref()) {
                    // A calculation picks its hosts with a filter, not a condition.
                    (true, _) => match rule.rule.filter.as_deref() {
                        None | Some("") => "Every host".to_string(),
                        Some(filter) => filter.to_string(),
                    },
                    (false, None) => "Every host".to_string(),
                    (false, Some(condition)) => Builder::from_expression(condition)
                        .map_or_else(|| condition.to_string(), |builder| builder.describe()),
                },
                channels: if rule.rule.all_channels {
                    "Every channel".to_string()
                } else {
                    names.join(", ")
                },
                enabled: rule.rule.enabled,
                name: rule.rule.name,
            }
        })
        .collect();

    Page::new(&state, &token, "alert_rules/index.html")
        .with("rules", &rows)
        .render()
}

async fn new(State(state): State<AppState>, token: CsrfToken) -> Response {
    form_page(&state, &token, None, &AlertRuleForm::blank(), None).await
}

fn not_found(state: &AppState, token: &CsrfToken) -> Response {
    let page = Page::new(state, token, "errors/not_found.html");
    page.with_status(StatusCode::NOT_FOUND).render()
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_alert_rule(id).await {
        Ok(Some(rule)) => {
            let form = AlertRuleForm::from_rule(&rule.rule);
            form_page(&state, &token, Some(id), &form, None).await
        }
        Ok(None) => not_found(&state, &token),
        Err(error) => server_error(&error),
    }
}

/// Turns the form into a valid rule, or explains what's wrong with it.
async fn validate(state: &AppState, form: &AlertRuleForm) -> Result<AlertRuleInput> {
    let input = form.to_rule(&known_facts(state).await)?;
    state.check_alert_rule(&input).await?;
    Ok(input)
}

/// Handles the builder's buttons, which show the form again without saving it,
/// so a response means there's nothing left to do.
async fn without_saving(
    state: &AppState,
    id: Option<i64>,
    fields: &mut AlertRuleForm,
    form: &CsrfForm,
) -> Option<Response> {
    let action = form.fields.get("form_action").cloned().unwrap_or_default();
    if action == "replay" {
        // Tried as it would be saved, so a mistake says what it would on saving.
        let replayed = match validate(state, fields).await {
            Ok(input) => replay(&state.sources(), &input, crate::times::now()).await,
            Err(error) => Err(error),
        };
        return Some(match replayed {
            Ok(replayed) => {
                form_page_with(state, &form.token, id, fields, None, Some(&replayed)).await
            }
            Err(error) => {
                let message = format!("{error:#}");
                form_page(state, &form.token, id, fields, Some(&message)).await
            }
        });
    }
    fields
        .applies_to
        .apply_action(&action, &known_facts(state).await)
        .then_some(())?;
    Some(form_page(state, &form.token, id, fields, None).await)
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let mut fields = AlertRuleForm::from_fields(&form.fields);
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

    match state.database.create_alert_rule(&input).await {
        Ok(_) => (form.token, Redirect::to("/alerts/rules")).into_response(),
        Err(error) if error.is::<NameTaken>() => {
            let message = format!("{error:#}");
            form_page(&state, &form.token, None, &fields, Some(&message)).await
        }
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let mut fields = AlertRuleForm::from_fields(&form.fields);
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

    match state.database.update_alert_rule(id, &input).await {
        Ok(true) => (form.token, Redirect::to("/alerts/rules")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) if error.is::<NameTaken>() => {
            let message = format!("{error:#}");
            form_page(&state, &form.token, Some(id), &fields, Some(&message)).await
        }
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state
        .database
        .delete_alert_rule(id, crate::times::now())
        .await
    {
        Ok(true) => (form.token, Redirect::to("/alerts/rules")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> AlertRuleInput {
        AlertRuleInput {
            summary: Some("{{ hostname }}: {{ series }} is {{ value }}".to_string()),
            resolved_summary: Some("{{ series }} is fine".to_string()),
            hold: TimeDelta::seconds(60),
            applies_to: Some("true".to_string()),
            enabled: false,
            channels: vec![2, 5],
            window: Some(TimeDelta::hours(2)),
            remind_every: Some(TimeDelta::seconds(90)),
            ..AlertRuleInput::with_conditions(
                "Disk full",
                Some("disk.usage > 80"),
                Some("forecast(disk.usage, duration('4h')) >= 100 && series != '/boot'"),
            )
        }
    }

    fn through_the_form(original: &AlertRuleInput) -> AlertRuleInput {
        let mut form = AlertRuleForm::from_rule(original);
        if original.applies_to.is_some() {
            form.applies_to.use_expression = true;
            form.applies_to.text = "true".to_string();
        }
        form.to_rule(&BTreeMap::new()).unwrap()
    }

    #[test]
    fn a_rule_survives_the_trip_through_its_form() {
        let original = rule();
        assert_eq!(through_the_form(&original), original);
        let warning_only = AlertRuleInput {
            critical: None,
            summary: None,
            resolved_summary: None,
            window: None,
            ..rule()
        };
        assert_eq!(through_the_form(&warning_only), warning_only);
    }

    #[test]
    fn a_calculation_survives_the_trip_through_its_form() {
        let original = AlertRuleInput {
            calculation: Some(Calculation::Max),
            metric: Some("cpu.usage".to_string()),
            group_by: Some("fact:os.name".to_string()),
            filter: Some("os=linux".to_string()),
            window: Some(TimeDelta::minutes(10)),
            ..AlertRuleInput::with_conditions("Busy", None, Some("value > 80"))
        };
        assert_eq!(through_the_form(&original), original);
    }

    #[test]
    fn a_rule_about_each_host_ignores_the_calculation_fields_the_form_still_sends() {
        let mut form = AlertRuleForm::blank();
        form.name = "Gone".to_string();
        form.critical = "  !online ".to_string();
        form.filter = "os=linux".to_string();
        form.group_by = "host".to_string();

        let input = form.to_rule(&BTreeMap::new()).unwrap();
        assert_eq!(input.critical.as_deref(), Some("!online"));
        assert_eq!(input.warning, None);
        assert_eq!(input.metric, None);
        assert_eq!(input.group_by, None);
        assert_eq!(input.filter, None);
        crate::alerting::check_rule(&input).unwrap();
    }

    #[test]
    fn typing_mistakes_are_explained() {
        for (change, expected) in [
            (("for_secs", "soon"), "whole number"),
            (("for_secs", "-1"), "whole number"),
            (("calculation", "nonsense"), "unknown calculation"),
            (("window_secs", "a while"), "whole number of seconds"),
            (("remind_every_minutes", "often"), "number of minutes"),
        ] {
            let mut form = AlertRuleForm::blank();
            form.critical = "cpu.usage > 90".to_string();
            let (field, value) = change;
            let target = match field {
                "for_secs" => &mut form.for_secs,
                "calculation" => &mut form.calculation,
                "window_secs" => &mut form.window_secs,
                _ => &mut form.remind_every_minutes,
            };
            *target = value.to_string();
            let error = format!("{:#}", form.to_rule(&BTreeMap::new()).unwrap_err());
            assert!(error.contains(expected), "{field}: {error}");
        }
    }

    #[test]
    fn chosen_channels_come_from_their_checkboxes() {
        let fields = BTreeMap::from([
            ("channel_3".to_string(), "on".to_string()),
            ("channel_1".to_string(), "on".to_string()),
            ("channel_x".to_string(), "on".to_string()),
        ]);
        let form = AlertRuleForm::from_fields(&fields);
        assert_eq!(form.channels, BTreeSet::from([1, 3]));
    }

    #[test]
    fn metric_options_name_the_unit_to_type_in() {
        let options = metric_options();
        let label = |name: &str| {
            let option = options.iter().find(|option| option.name == name).unwrap();
            option.label.clone()
        };
        assert_eq!(label("cpu.usage"), "CPU usage (%)");
        assert_eq!(label("cpu.load"), "Load average");
        assert!(label("network.received").ends_with("(bytes per second)"));
    }
}
