use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::Serialize;

use super::condition_form::{ConditionForm, operators};
use super::{CsrfForm, Page, server_error};
use crate::alerting::{AlertRuleInput, Comparison, RuleKind, Severity};
use crate::app_state::AppState;
use crate::calculations::Calculation;
use crate::condition_builder::Builder;
use crate::dashboards::grouping_fields;
use crate::metrics::{METRICS, Unit, now_ms};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts/rules", get(index).post(create))
        .route("/alerts/rules/new", get(new))
        .route("/alerts/rules/{id}", post(update))
        .route("/alerts/rules/{id}/edit", get(edit))
        .route("/alerts/rules/{id}/delete", post(delete))
}

/// A rule as its form shows it, including whatever was just typed. The condition
/// fields are flattened so the shared part of the form finds them.
#[derive(Serialize)]
struct AlertRuleForm {
    name: String,
    kind: String,
    metric: String,
    series: String,
    comparison: String,
    threshold: String,
    for_secs: String,
    severity: String,
    enabled: bool,
    channels: BTreeSet<i64>,
    calculation: String,
    group_by: String,
    fact: String,
    filter: String,
    window_secs: String,
    remind_every_minutes: String,
    #[serde(flatten)]
    applies_to: ConditionForm,
}

impl AlertRuleForm {
    fn blank() -> Self {
        Self {
            name: String::new(),
            kind: RuleKind::Metric.as_str().to_string(),
            metric: METRICS[0].name.to_string(),
            series: String::new(),
            comparison: Comparison::Above.as_str().to_string(),
            threshold: String::new(),
            for_secs: "300".to_string(),
            severity: Severity::Warning.as_str().to_string(),
            enabled: true,
            channels: BTreeSet::new(),
            calculation: Calculation::Avg.as_str().to_string(),
            group_by: "nothing".to_string(),
            fact: String::new(),
            filter: String::new(),
            window_secs: "300".to_string(),
            remind_every_minutes: String::new(),
            applies_to: ConditionForm::blank(),
        }
    }

    fn from_rule(rule: &AlertRuleInput) -> Self {
        let blank = Self::blank();
        let (group_by, fact) = grouping_fields(rule.group_by.as_deref().unwrap_or_default());
        Self {
            calculation: rule
                .calculation
                .map_or(blank.calculation, |c| c.as_str().to_string()),
            group_by,
            fact,
            filter: rule.filter.clone().unwrap_or_default(),
            window_secs: rule.window().to_string(),
            remind_every_minutes: rule
                .remind_every_secs
                .map(|secs| (secs / 60).to_string())
                .unwrap_or_default(),
            name: rule.name.clone(),
            kind: rule.kind.as_str().to_string(),
            metric: rule.metric.clone().unwrap_or(blank.metric),
            series: rule.series.clone().unwrap_or_default(),
            comparison: rule
                .comparison
                .map_or(blank.comparison, |c| c.as_str().to_string()),
            threshold: rule.threshold.map(|t| t.to_string()).unwrap_or_default(),
            for_secs: rule.for_secs.to_string(),
            severity: rule.severity.as_str().to_string(),
            enabled: rule.enabled,
            channels: rule.channels.iter().copied().collect(),
            applies_to: ConditionForm::from_condition(rule.condition.as_deref()),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            calculation: text("calculation"),
            group_by: text("group_by"),
            fact: text("fact").trim().to_string(),
            filter: text("filter").trim().to_string(),
            window_secs: text("window_secs"),
            remind_every_minutes: text("remind_every_minutes").trim().to_string(),
            name: text("name"),
            kind: text("kind"),
            metric: text("metric"),
            series: text("series"),
            comparison: text("comparison"),
            threshold: text("threshold"),
            for_secs: text("for_secs"),
            severity: text("severity"),
            enabled: fields.contains_key("enabled"),
            channels: fields
                .keys()
                .filter_map(|name| name.strip_prefix("channel_")?.parse().ok())
                .collect(),
            applies_to: ConditionForm::from_fields(fields),
        }
    }

    fn to_rule(&self, known: &BTreeMap<String, String>) -> Result<AlertRuleInput> {
        let kind = RuleKind::parse(&self.kind)?;
        let for_secs: u64 = self
            .for_secs
            .trim()
            .parse()
            .context("the duration must be a whole number of seconds")?;
        let remind_every_secs = match self.remind_every_minutes.as_str() {
            "" => None,
            text => {
                let minutes: u64 = text
                    .parse()
                    .context("reminders must be a whole number of minutes")?;
                Some(minutes.saturating_mul(60))
            }
        };

        // The form always sends these, and they only mean something for metrics.
        let (metric, series, comparison, threshold) = match kind {
            RuleKind::Offline => (None, None, None, None),
            RuleKind::Calculation => {
                let threshold = self
                    .threshold
                    .trim()
                    .parse()
                    .context("the threshold must be a number")?;
                (
                    Some(self.metric.clone()),
                    None,
                    Some(Comparison::parse(&self.comparison)?),
                    Some(threshold),
                )
            }
            RuleKind::Metric => {
                let threshold = self.threshold.trim();
                if threshold.is_empty() {
                    bail!("a metric rule needs a threshold");
                }
                let threshold: f64 = threshold
                    .parse()
                    .context("the threshold must be a number")?;
                let series = self.series.trim();
                (
                    Some(self.metric.clone()),
                    (!series.is_empty()).then(|| series.to_string()),
                    Some(Comparison::parse(&self.comparison)?),
                    Some(threshold),
                )
            }
        };

        let is_calculation = kind == RuleKind::Calculation;
        let only_for_calculations = |value: String| is_calculation.then_some(value);
        let group_by = if self.group_by == "fact" {
            format!("fact:{}", self.fact)
        } else {
            self.group_by.clone()
        };
        let window_secs = if is_calculation {
            let secs = self.window_secs.trim().parse();
            Some(secs.context("how far back has to be a whole number of seconds")?)
        } else {
            None
        };
        let condition = if is_calculation {
            None
        } else {
            self.applies_to.expression(known)?
        };

        Ok(AlertRuleInput {
            calculation: is_calculation
                .then(|| Calculation::parse(&self.calculation))
                .flatten(),
            group_by: only_for_calculations(group_by),
            filter: only_for_calculations(self.filter.clone()).filter(|text| !text.is_empty()),
            window_secs,
            remind_every_secs,
            name: self.name.trim().to_string(),
            kind,
            metric,
            series,
            comparison,
            threshold,
            for_secs,
            severity: Severity::parse(&self.severity)?,
            condition,
            enabled: self.enabled,
            channels: self.channels.iter().copied().collect(),
        })
    }
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

/// The unit goes on the label, because thresholds are typed as plain numbers.
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
                Unit::Milliseconds => format!("{} (milliseconds)", metric.title),
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

    let page = Page::new(state, token, "alert_rules/form.html")
        .with("id", &id)
        .with("rule", form)
        .with("metrics", &metric_options())
        .with("calculations", &calculation_options())
        .with("channels", &channels)
        .with("operators", &operators())
        .with("known_facts", &known)
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
    watches: String,
    applies_to: String,
    severity: &'static str,
    channels: String,
    enabled: bool,
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
            RuleRow {
                id: rule.id,
                watches: rule.rule.describe(),
                applies_to: match rule.rule.condition.as_deref() {
                    None => "Every agent".to_string(),
                    Some(condition) => Builder::from_expression(condition)
                        .map_or_else(|| condition.to_string(), |builder| builder.describe()),
                },
                severity: rule.rule.severity.as_str(),
                channels: names.join(", "),
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
async fn validate(
    state: &AppState,
    form: &AlertRuleForm,
    id: Option<i64>,
) -> Result<AlertRuleInput> {
    let input = form.to_rule(&known_facts(state).await)?;
    state.check_alert_rule(&input, id).await?;
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

    let input = match validate(&state, &fields, None).await {
        Ok(input) => input,
        Err(error) => {
            let message = format!("{error:#}");
            return form_page(&state, &form.token, None, &fields, Some(&message)).await;
        }
    };

    match state.database.create_alert_rule(&input).await {
        Ok(_) => (form.token, Redirect::to("/alerts/rules")).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let mut fields = AlertRuleForm::from_fields(&form.fields);
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

    match state.database.update_alert_rule(id, &input).await {
        Ok(true) => (form.token, Redirect::to("/alerts/rules")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.delete_alert_rule(id, now_ms()).await {
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
            name: "Disk full".to_string(),
            kind: RuleKind::Metric,
            metric: Some("disk.usage".to_string()),
            series: Some("/data*".to_string()),
            comparison: Some(Comparison::Below),
            threshold: Some(12.5),
            for_secs: 60,
            severity: Severity::Critical,
            condition: Some("true".to_string()),
            enabled: false,
            channels: vec![2, 5],
            calculation: None,
            group_by: None,
            filter: None,
            window_secs: None,
            remind_every_secs: None,
        }
    }

    #[test]
    fn a_rule_survives_the_trip_through_its_form() {
        let original = rule();
        let mut form = AlertRuleForm::from_rule(&original);
        form.applies_to.use_expression = true;
        form.applies_to.condition = "true".to_string();
        assert_eq!(form.to_rule(&BTreeMap::new()).unwrap(), original);
    }

    #[test]
    fn an_offline_rule_ignores_the_metric_fields_the_form_still_sends() {
        let mut form = AlertRuleForm::blank();
        form.name = "Gone".to_string();
        form.kind = "offline".to_string();
        form.threshold = "not a number".to_string();
        form.series = "/".to_string();

        let input = form.to_rule(&BTreeMap::new()).unwrap();
        assert_eq!(input.metric, None);
        assert_eq!(input.series, None);
        assert_eq!(input.comparison, None);
        assert_eq!(input.threshold, None);
        crate::alerting::check_rule(&input).unwrap();
    }

    #[test]
    fn typing_mistakes_are_explained() {
        for (change, expected) in [
            (("threshold", ""), "needs a threshold"),
            (("threshold", "lots"), "must be a number"),
            (("for_secs", "soon"), "whole number"),
            (("for_secs", "-1"), "whole number"),
            (("kind", "nonsense"), "unknown rule kind"),
            (("severity", "nonsense"), "unknown severity"),
            (("comparison", "nonsense"), "unknown comparison"),
        ] {
            let mut form = AlertRuleForm::blank();
            form.threshold = "90".to_string();
            let (field, value) = change;
            let target = match field {
                "threshold" => &mut form.threshold,
                "for_secs" => &mut form.for_secs,
                "kind" => &mut form.kind,
                "severity" => &mut form.severity,
                _ => &mut form.comparison,
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
