//! What alerting is made of: rules that say what to watch, channels that say who
//! to tell, and the alerts that result. [`crate::alert_evaluator`] decides when
//! alerts start and end, and [`crate::notifier`] delivers them.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::actions::{ActionRun, RuleAction, check_rule_actions};
use crate::alert_conditions::{Conditions, MetricUse, Names, Scope};
use crate::calculations::{Calculation, Question};
use crate::catalog::Catalog;
use crate::channels;
use crate::metrics::{INSTANCE_LABEL, Metric, Source, Unit};
use crate::times::Timestamp;

/// Why an alert ends when its rule goes, however it goes.
pub const RULE_GONE_REASON: &str = "The rule was deleted or disabled";

/// What the database columns hold.
const MAX_NAME_LEN: usize = 255;
const MAX_TARGET_LEN: usize = 2048;
/// Summaries are a line or two, and what's filled in is kept to that too.
pub const MAX_SUMMARY_LEN: usize = 1000;

/// A rule can't wait longer than this before firing.
const MAX_HOLD: TimeDelta = TimeDelta::days(7);

/// A calculation needs a finished minute to look at.
const MIN_WINDOW: TimeDelta = TimeDelta::minutes(1);
const MAX_WINDOW: TimeDelta = TimeDelta::days(1);
const DEFAULT_WINDOW: TimeDelta = TimeDelta::minutes(5);

/// How far back a forecast looks by default, and at least. Less than an hour is
/// mostly noise, and more than a day is a lot to read every few minutes.
pub const DEFAULT_FORECAST_WINDOW: TimeDelta = TimeDelta::hours(6);
const MIN_FORECAST_WINDOW: TimeDelta = TimeDelta::hours(1);

/// Mildest first, so the worse of two is the greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "warning" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            other => bail!("unknown severity {other:?}"),
        }
    }
}

/// A rule as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: i64,
    #[serde(flatten)]
    pub rule: AlertRuleInput,
    /// The template whose alert it is, for one that's a template's.
    #[serde(default)]
    pub template: Option<TemplateLink>,
    /// Its conditions, read once as it's loaded. None for ones that can't be read,
    /// which saving a rule doesn't allow.
    #[serde(skip)]
    pub conditions: Option<Arc<Conditions>>,
}

/// How a rule is one of a template's alerts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateLink {
    /// The template's ID.
    pub id: i64,
    /// The template's key, which starts its metrics' names: the rule's conditions
    /// and summaries can use them by their short names, `lag` for `postgres.lag`.
    pub key: String,
    /// The alert's key in the template.
    pub alert: String,
    /// For someone's own copy of a built-in template's rule, the rule it's used in
    /// place of.
    pub replaces_id: Option<i64>,
    /// For a built-in or imported template's own rule, what someone chose in place
    /// of whether the template ships it on, or nothing while it follows the template.
    pub enabled_choice: Option<bool>,
    /// Whether the template is on. Its alerts aren't checked while it's off.
    pub template_enabled: bool,
    /// Whether the template runs for each database, rather than once on a host.
    pub per_database: bool,
    /// CEL over what the template's discovery found, picking the databases the
    /// alert is for.
    pub when: Option<String>,
    /// The version the alert is for from, as discovery found it.
    pub since: Option<String>,
    /// When an upgrade last changed the built-in rule this is a copy of.
    pub original_changed_at: Option<Timestamp>,
}

impl AlertRule {
    /// A rule as stored, with its conditions read against the metrics there are.
    pub fn new(
        id: i64,
        rule: AlertRuleInput,
        template: Option<TemplateLink>,
        catalog: &Catalog,
    ) -> Self {
        Self::unread(id, rule, template).read(catalog)
    }

    /// A rule as stored, with its conditions still to read.
    pub fn unread(id: i64, rule: AlertRuleInput, template: Option<TemplateLink>) -> Self {
        Self {
            id,
            rule,
            template,
            conditions: None,
        }
    }

    /// The rule with its conditions read against the metrics there are.
    pub fn read(mut self, catalog: &Catalog) -> Self {
        self.conditions = self
            .rule
            .conditions(&self.names(catalog))
            .ok()
            .map(Arc::new);
        self
    }

    /// Where the rule's names are looked up: a template's alert can use the
    /// template's metrics by their short names.
    pub fn names<'a>(&'a self, catalog: &'a Catalog) -> Names<'a> {
        Names {
            catalog,
            template: self.template_key(),
        }
    }

    /// Whether it's only for the databases where what its template's discovery
    /// found says so.
    pub fn picks_by_discovery(&self) -> bool {
        self.template
            .as_ref()
            .is_some_and(|template| template.when.is_some() || template.since.is_some())
    }

    /// Whether it's checked: it's on, and if it's a template's alert, so is the
    /// template.
    pub fn runs(&self) -> bool {
        self.rule.enabled
            && self
                .template
                .as_ref()
                .is_none_or(|template| template.template_enabled)
    }

    /// The template whose metrics the rule can use by their short names, if it's
    /// one's alert.
    pub fn template_key(&self) -> Option<&str> {
        self.template.as_ref().map(|template| template.key.as_str())
    }

    /// See [`AlertRuleInput::watched`].
    pub fn watched(&self, catalog: &Catalog) -> Option<(Arc<Metric>, Option<String>)> {
        self.rule.watched(self.conditions.as_deref()?, catalog)
    }

    /// See [`AlertRuleInput::thresholds`].
    pub fn thresholds(&self) -> Vec<(Severity, f64)> {
        self.conditions
            .as_deref()
            .map_or_else(Vec::new, |conditions| self.rule.thresholds(conditions))
    }
}

/// What can be set on a rule. Validated by [`check_rule`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRuleInput {
    pub name: String,
    /// When it's a warning: CEL over metrics by their names, such as
    /// `disk.usage > 80`. A rule has this, `critical` or both, and one alert covers
    /// both, at the worse of the two.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub warning: Option<String>,
    /// When it's critical, the same way.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub critical: Option<String>,
    /// What an alert says, filled in like a custom webhook's body: `{{ hostname }}`,
    /// `{{ series }}`, `{{ value }}` and the metrics the conditions use, such as
    /// `{{ disk.usage }}`. Without it, the rule's name and the reading.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub summary: Option<String>,
    /// What an alert says as it clears, the same way.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub resolved_summary: Option<String>,
    /// How long the problem has to last before the alert fires. It resolves as
    /// soon as the problem is gone.
    #[serde(rename = "for_secs", with = "crate::times::whole_seconds")]
    pub hold: TimeDelta,
    /// Which hosts, as CEL over facts. None is every host. A rule with a
    /// calculation picks its hosts with `filter` instead.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub applies_to: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Who to tell. With none, the alert only shows in the web interface.
    #[serde(default)]
    pub channels: Vec<i64>,
    /// Tell every channel instead, including ones added later.
    #[serde(default)]
    pub all_channels: bool,
    /// How to combine hosts, for a rule about a group of hosts rather than each
    /// one, whose conditions are about the calculated `value`.
    #[serde(default)]
    pub calculation: Option<Calculation>,
    /// What a calculation combines, by its name in the metric catalog.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub metric: Option<String>,
    /// What's watched separately, for calculation rules, as in a dashboard widget.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub group_by: Option<String>,
    /// Which hosts, for calculation rules, as on the Hosts list. None is all.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub filter: Option<String>,
    /// How far back a calculation looks, so one busy moment isn't a problem, or
    /// how much of a metric's past `forecast()` draws its line through.
    #[serde(
        default,
        rename = "window_secs",
        with = "crate::times::optional_whole_seconds"
    )]
    pub window: Option<TimeDelta>,
    /// How often to say an alert is still firing, until someone acknowledges it. Never,
    /// if empty. On-call services are left out, as repeating is their job.
    #[serde(
        default,
        rename = "remind_every_secs",
        with = "crate::times::optional_whole_seconds"
    )]
    pub remind_every: Option<TimeDelta>,
    /// What to run on an alert's host, and when. Not for a calculation, whose
    /// alerts are about a group of hosts.
    #[serde(default)]
    pub actions: Vec<RuleAction>,
}

fn default_enabled() -> bool {
    true
}

/// The shortest time between reminders. Any more often and people stop reading them.
const MIN_REMINDER: TimeDelta = TimeDelta::minutes(5);

/// Checks a rule before it's saved, with no host's facts to try its conditions on.
#[cfg(test)]
pub fn check_rule(rule: &AlertRuleInput) -> Result<()> {
    check_rule_in(rule, &Value::Null, &Names::of(&Catalog::built_in())).map(|_| ())
}

/// Checks a rule before it's saved, trying its conditions on `facts`, a real host's
/// if there is one, and gives its conditions, read. A template's alert's conditions
/// and summaries can use the template's own metrics by their short names too.
/// Whether its channels exist is up to the caller, which can see them.
pub fn check_rule_in(rule: &AlertRuleInput, facts: &Value, names: &Names) -> Result<Conditions> {
    ensure!(!rule.name.trim().is_empty(), "a rule needs a name");
    ensure!(rule.name.len() <= MAX_NAME_LEN, "the rule name is too long");
    ensure!(
        rule.hold <= MAX_HOLD,
        "the duration can't be longer than 7 days"
    );
    check_rule_actions(rule)?;
    ensure!(
        rule.remind_every.is_none_or(|every| every >= MIN_REMINDER),
        "reminders can't be more often than every 5 minutes"
    );
    ensure!(
        !(rule.all_channels && !rule.channels.is_empty()),
        "choose every channel or some of them, not both"
    );

    let conditions = rule.conditions(names)?;
    // A calculation's value is in the unit it's worked out in.
    let value_unit = rule
        .question(names.catalog)
        .map_or(Unit::Number, |question| question.unit());
    conditions.dry_run(facts, value_unit)?;
    if let Some(applies_to) = &rule.applies_to {
        ensure!(
            !rule.is_calculation(),
            "a rule with a calculation picks its hosts with a filter"
        );
        cel::Program::compile(applies_to)
            .map_err(|error| anyhow!("invalid condition for which hosts: {error}"))?;
    }
    if rule.is_calculation() {
        rule.question(names.catalog)
            .map_err(|error| anyhow!("{error}"))?;
        ensure!(
            (MIN_WINDOW..=MAX_WINDOW).contains(&rule.window()),
            "the window has to be between a minute and a day"
        );
    } else {
        ensure!(
            rule.metric.is_none() && rule.group_by.is_none() && rule.filter.is_none(),
            "only a rule with a calculation takes a metric, grouping or filter"
        );
        if conditions.forecast_metrics().is_empty() {
            ensure!(
                rule.window.is_none(),
                "only a calculation or forecast() looks back over a window"
            );
        } else {
            ensure!(
                (MIN_FORECAST_WINDOW..=MAX_WINDOW).contains(&rule.window()),
                "forecast() has to look back between an hour and a day"
            );
        }
    }
    for (template, which) in [
        (&rule.summary, "summary"),
        (&rule.resolved_summary, "resolved summary"),
    ] {
        if let Some(template) = template {
            rule.check_summary(template, &conditions, names)
                .map_err(|error| anyhow!("the {which}: {error:#}"))?;
        }
    }
    Ok(conditions)
}

/// The readings a summary can show, written in their units, by where they go in the
/// template: `disk.usage` as `{"disk": {"usage": "92%"}}`.
pub struct SummaryValues {
    pub hostname: String,
    pub series: String,
    /// The first metric's reading, or the calculated value.
    pub value: Option<String>,
    pub metrics: Vec<(String, Value)>,
    /// What a template's alert can show besides.
    pub template: Option<TemplateValues>,
}

/// What a template's alert can show besides what any rule can.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateValues {
    /// The template's key, which starts its metrics' full names.
    pub prefix: String,
    /// Its metrics' readings by their short names.
    pub metrics: Map<String, Value>,
    /// What it's running for, such as a database's name.
    pub instance: String,
    /// The series' labels, such as `slot`.
    pub labels: Map<String, Value>,
}

impl SummaryValues {
    fn context(&self) -> Value {
        let mut fields = Map::new();
        for (name, value) in &self.metrics {
            insert_at(&mut fields, name, value.clone());
        }
        if let Some(template) = &self.template {
            // The template's metrics the conditions use, by their short names too.
            let prefix = format!("{}.", template.prefix);
            for (name, value) in &self.metrics {
                if let Some(short) = name.strip_prefix(&prefix) {
                    fields.entry(short).or_insert_with(|| value.clone());
                }
            }
            for (short, value) in &template.metrics {
                fields.entry(short.clone()).or_insert_with(|| value.clone());
                insert_at(
                    &mut fields,
                    &format!("{}.{short}", template.prefix),
                    value.clone(),
                );
            }
            fields.insert("instance".to_string(), json!(template.instance));
            fields.insert("labels".to_string(), Value::Object(template.labels.clone()));
        }
        fields.insert("hostname".to_string(), json!(self.hostname));
        fields.insert("series".to_string(), json!(self.series));
        fields.insert("value".to_string(), json!(self.value));
        Value::Object(fields)
    }
}

/// The dotted names a summary shows, between `{{` and `}}`.
fn summary_names(text: &str) -> impl Iterator<Item = &str> {
    text.split("{{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}"))
        .flat_map(|(shown, _)| {
            shown
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .filter(|name| !name.is_empty())
        })
}

/// A template's metric's name within the template: `lag` for `postgres.lag`.
pub fn short_name<'a>(metric: &'a Metric, template: &str) -> &'a str {
    metric
        .name
        .strip_prefix(template)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(&metric.name)
}

/// Puts `value` at a dotted name, leaving anything already there.
fn insert_at(fields: &mut Map<String, Value>, name: &str, value: Value) {
    match name.split_once('.') {
        None => {
            fields.entry(name).or_insert(value);
        }
        Some((first, rest)) => {
            let inner = fields
                .entry(first)
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(inner) = inner {
                insert_at(inner, rest, value);
            }
        }
    }
}

/// Fills in a summary template, which is plain text, so nothing is escaped, and
/// control characters an agent sent can't start a line of their own.
pub fn fill_summary(template: &str, values: &SummaryValues) -> Result<String> {
    let context = tera::Context::from_serialize(&values.context())?;
    let filled = tera::Tera::one_off(template, &context, false)
        .map_err(|error| anyhow!("{}", crate::channels::custom_webhook::explain_tera(&error)))?;
    Ok(clean_long(&filled, MAX_SUMMARY_LEN))
}

impl AlertRuleInput {
    pub fn is_calculation(&self) -> bool {
        self.calculation.is_some()
    }

    /// The rule's conditions, read, with names looked up in `names`. Saving a rule
    /// checks they can be.
    pub fn conditions(&self, names: &Names) -> Result<Conditions> {
        let scope = match self.is_calculation() {
            true => Scope::Calculation,
            false => Scope::Hosts,
        };
        Conditions::compile(
            self.warning.as_deref(),
            self.critical.as_deref(),
            scope,
            names,
        )
    }

    /// What a calculation rule asks. The error says what's wrong, to show whoever chose it.
    pub fn question(&self, catalog: &Catalog) -> Result<Question, String> {
        Question::new(
            catalog,
            self.metric.as_deref().unwrap_or_default(),
            self.calculation.map_or("", Calculation::as_str),
            self.group_by.as_deref().unwrap_or_default(),
            self.filter.as_deref().unwrap_or_default(),
        )
    }

    pub fn window(&self) -> TimeDelta {
        self.window.unwrap_or(match self.is_calculation() {
            true => DEFAULT_WINDOW,
            false => DEFAULT_FORECAST_WINDOW,
        })
    }

    /// The severities the rule can alert at, mildest first.
    pub fn severities(&self) -> Vec<Severity> {
        let warning = self.warning.as_ref().map(|_| Severity::Warning);
        let critical = self.critical.as_ref().map(|_| Severity::Critical);
        warning.into_iter().chain(critical).collect()
    }

    /// The worst severity the rule can alert at.
    pub fn worst_severity(&self) -> Severity {
        match self.critical {
            Some(_) => Severity::Critical,
            None => Severity::Warning,
        }
    }

    /// The levels to draw across a chart of what the rule's alerts watch, mildest
    /// first: one for each condition that only compares that metric, or the
    /// calculated value, with a number, such as `disk.usage > 90`.
    pub fn thresholds(&self, conditions: &Conditions) -> Vec<(Severity, f64)> {
        let charted = match self.is_calculation() {
            true => (None, None),
            false => match conditions.primary() {
                Some(primary) => (Some(primary.metric.name.clone()), primary.picked.clone()),
                None => return Vec::new(),
            },
        };
        conditions
            .levels()
            .into_iter()
            .filter_map(|(severity, condition)| {
                let threshold = condition.threshold()?;
                ((threshold.metric, threshold.picked) == charted)
                    .then_some((severity, threshold.level))
            })
            .collect()
    }

    /// The metric the rule's alerts are about, which they chart: the calculation's,
    /// or the first one its conditions use, with the series that one picks out.
    pub fn watched(
        &self,
        conditions: &Conditions,
        catalog: &Catalog,
    ) -> Option<(Arc<Metric>, Option<String>)> {
        if self.is_calculation() {
            let question = self.question(catalog).ok()?;
            return Some((question.metric, None));
        }
        let primary: &MetricUse = conditions.primary()?;
        Some((primary.metric.clone(), primary.picked.clone()))
    }

    /// What the rule watches, in a few words, beside its conditions.
    pub fn describe(&self, catalog: &Catalog) -> String {
        let mut words = Vec::new();
        if self.is_calculation()
            && let Ok(question) = self.question(catalog)
        {
            words.push(format!(
                "{} of {} over {}",
                question.calculation.label(),
                question.metric.title,
                format_duration(self.window())
            ));
        }
        if !self.hold.is_zero() {
            words.push(format!("for {}", format_duration(self.hold)));
        }
        words.join(", ")
    }

    /// The metrics of the template `key` that the rule's summaries name, by their
    /// short or full names, so a template's alert can show any of them.
    pub fn summary_metrics(&self, catalog: &Catalog, key: &str) -> Vec<Arc<Metric>> {
        let texts = [&self.summary, &self.resolved_summary];
        let named: BTreeSet<&str> = texts
            .into_iter()
            .flatten()
            .flat_map(|text| summary_names(text))
            .collect();
        let mut metrics: Vec<Arc<Metric>> = catalog
            .of_template(key)
            .filter(|metric| {
                named.contains(metric.name.as_str()) || named.contains(short_name(metric, key))
            })
            .cloned()
            .collect();
        metrics.sort_by(|a, b| a.name.cmp(&b.name));
        metrics
    }

    /// Fills in a summary template with example values, to find mistakes when a
    /// rule is saved: a metric the conditions don't use can't be shown.
    fn check_summary(&self, template: &str, conditions: &Conditions, names: &Names) -> Result<()> {
        ensure!(
            template.len() <= MAX_SUMMARY_LEN,
            "it can be up to {MAX_SUMMARY_LEN} characters"
        );
        let mut metrics = Vec::new();
        for used in conditions.uses() {
            let example = conditions.format(&used.metric, 50.0);
            let value = match &used.metric.source {
                Source::Fields(fields) if used.bracketed => Value::Object(
                    fields
                        .iter()
                        .map(|(name, _)| (name.to_string(), json!(example)))
                        .collect(),
                ),
                _ if used.bracketed => Value::Object(
                    used.picked
                        .iter()
                        .map(|name| (name.clone(), json!(example)))
                        .collect(),
                ),
                _ => json!(example),
            };
            metrics.push((used.metric.name.clone(), value));
        }
        let mut example = SummaryValues {
            hostname: "web-1".to_string(),
            series: "/".to_string(),
            value: Some("50%".to_string()),
            metrics,
            template: None,
        };
        // A template's alert can show any of its metrics, by either name, what it's
        // running for and its series' labels.
        if let Some(key) = names.template {
            let mut labels = Map::new();
            let mut metrics = Map::new();
            for metric in names.catalog.of_template(key) {
                metrics.insert(short_name(metric, key).to_string(), json!("50"));
                for label in metric.labels().iter().filter(|l| *l != INSTANCE_LABEL) {
                    labels.insert(label.clone(), json!("main"));
                }
            }
            example.template = Some(TemplateValues {
                prefix: key.to_string(),
                metrics,
                instance: "main".to_string(),
                labels,
            });
        }
        fill_summary(template, &example)?;
        Ok(())
    }

    /// What an alert says when it fires, or changes severity: the rule's summary,
    /// or its name and the reading. A summary that can't be filled in, such as one
    /// showing a metric with no reading, says the usual instead.
    pub fn summary_for(&self, values: &SummaryValues, subject: Option<&str>) -> String {
        if let Some(template) = &self.summary
            && let Ok(filled) = fill_summary(template, values)
        {
            return filled;
        }
        let name = &self.name;
        let about = match self.is_calculation() {
            true => name.clone(),
            false => format!("{name} on {}", values.hostname),
        };
        match (&values.value, subject) {
            (Some(value), Some(subject)) => format!("{about}: {subject} is {value}"),
            (Some(value), None) => format!("{about}: {value}"),
            (None, _) => about,
        }
    }

    /// What an alert says as it clears, the same way, or nothing for a rule with
    /// no reading to give.
    pub fn resolved_summary_for(
        &self,
        values: &SummaryValues,
        subject: Option<&str>,
    ) -> Option<String> {
        if let Some(template) = &self.resolved_summary
            && let Ok(filled) = fill_summary(template, values)
        {
            return Some(filled);
        }
        let name = &self.name;
        let about = match self.is_calculation() {
            true => name.clone(),
            false => format!("{name} on {}", values.hostname),
        };
        let value = values.value.as_ref()?;
        Some(match subject {
            Some(subject) => format!("{about}: {subject} is now {value}"),
            None => format!("{about}: now {value}"),
        })
    }

    /// What an alert says about something that describes its own state, such as a
    /// service that's `failed`.
    pub fn state_summary(noun: &str, hostname: &str, series: &str, state: &str) -> String {
        format!("{noun} {series} on {hostname} is {state}")
    }
}

#[cfg(test)]
impl AlertRuleInput {
    /// A rule with these conditions that tells nobody and waits for nothing, for
    /// tests to change what they need.
    pub fn with_conditions(name: &str, warning: Option<&str>, critical: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            warning: warning.map(str::to_string),
            critical: critical.map(str::to_string),
            summary: None,
            resolved_summary: None,
            hold: TimeDelta::zero(),
            applies_to: None,
            enabled: true,
            channels: Vec::new(),
            all_channels: false,
            calculation: None,
            metric: None,
            group_by: None,
            filter: None,
            window: None,
            remind_every: None,
            actions: Vec::new(),
        }
    }
}

/// What a reading is of, in an alert's words: its series where it has one of
/// several, or the metric's title, with the series picked out of it if any.
pub fn subject(metric: &Metric, series: &str, picked: Option<&str>) -> String {
    if !series.is_empty() {
        return series.to_string();
    }
    match picked {
        Some(picked) => format!("{} ({picked})", metric.title),
        None => metric.title.clone(),
    }
}

/// Text from agents or a template, cleaned as [`clean`] does, to `max` characters.
fn clean_long(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Agents choose hostnames and series names, so anything kept from them loses
/// control characters, which could forge lines in an email or log and which
/// Postgres refuses, and is cut to what the database columns hold.
pub fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_LEN)
        .collect()
}

/// A length of time in the largest unit it's a whole number of, such as "5 minutes".
pub fn format_duration(length: TimeDelta) -> String {
    let plural = |count: i64, unit: &str| match count {
        1 => format!("1 {unit}"),
        _ => format!("{count} {unit}s"),
    };
    match length.num_seconds() {
        secs if secs % 86_400 == 0 && secs > 0 => plural(secs / 86_400, "day"),
        secs if secs % 3600 == 0 && secs > 0 => plural(secs / 3600, "hour"),
        secs if secs % 60 == 0 && secs > 0 => plural(secs / 60, "minute"),
        secs => plural(secs, "second"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Webhook,
    Email,
    Discord,
    Slack,
    #[serde(rename = "pagerduty")]
    PagerDuty,
    #[serde(rename = "alertops")]
    AlertOps,
    Signl4,
    Telegram,
    /// A Teams channel, through the workflow Teams makes to post what's sent to it.
    Teams,
    /// Email through Resend's API, rather than a mail server.
    Resend,
    /// A webhook whose request is written by whoever sets it up.
    CustomWebhook,
}

impl ChannelKind {
    /// Whether it needs a token beside its destination.
    pub fn has_credential(self) -> bool {
        channels::of(self).has_credential()
    }

    /// Whether it sends email, with a from address and maybe a mail server.
    pub fn sends_mail(self) -> bool {
        channels::of(self).sends_mail()
    }

    /// Whether the service keeps after people itself until someone responds.
    pub fn is_on_call(self) -> bool {
        channels::of(self).is_on_call()
    }

    /// Whether it's told when an alert is acknowledged, to stop paging people.
    pub fn acknowledges(self) -> bool {
        channels::of(self).acknowledges()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Email => "email",
            Self::Discord => "discord",
            Self::Slack => "slack",
            Self::PagerDuty => "pagerduty",
            Self::AlertOps => "alertops",
            Self::Signl4 => "signl4",
            Self::Telegram => "telegram",
            Self::Teams => "teams",
            Self::Resend => "resend",
            Self::CustomWebhook => "custom_webhook",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        channels::ALL
            .into_iter()
            .find(|kind| kind.as_str() == text)
            .with_context(|| format!("unknown channel kind {text:?}"))
    }
}

/// Somewhere notifications go. A webhook's URL often is its password, so
/// `target` is never sent back out: see [`ChannelInput::target_preview`].
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub id: i64,
    pub channel: ChannelInput,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ChannelInput {
    pub name: String,
    pub kind: ChannelKind,
    /// A webhook's URL, email addresses separated by commas, a Slack channel, a
    /// PagerDuty integration key, the URL AlertOps or SIGNL4 gave out, or a
    /// Telegram chat.
    pub target: String,
    /// Slack's or Telegram's bot token, a mail server's password, Resend's API key,
    /// or a custom webhook's headers. Like a webhook's URL, it can be set but not
    /// read back.
    #[serde(default)]
    pub credential: Option<String>,
    /// A Slack app's own token, so the server hears its buttons being pressed.
    /// Write-only too.
    #[serde(default)]
    pub app_token: Option<String>,
    /// Which alerts it's sent, so warnings can stay off a pager. A channel hears of
    /// an alert once it reaches one of these, and then of every change until it
    /// resolves.
    #[serde(default = "every_severity")]
    pub severities: BTreeSet<Severity>,
    /// Who email comes from, and for an email channel, the mail server it goes
    /// through. Only email and Resend channels have it.
    #[serde(default)]
    pub mail: Option<Mail>,
    /// The request a custom webhook sends. Its headers are the channel's
    /// `credential`, as they usually hold a token.
    #[serde(default)]
    pub request: Option<WebhookRequest>,
    /// Which of PagerDuty's service regions its account is in. Only PagerDuty
    /// channels have one, and leaving it out means the US.
    #[serde(default)]
    pub region: Option<PagerDutyRegion>,
}

/// Where a PagerDuty account lives, which decides where its events are sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PagerDutyRegion {
    #[default]
    Us,
    Eu,
}

impl PagerDutyRegion {
    pub const ALL: [Self; 2] = [Self::Us, Self::Eu];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::Eu => "eu",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|region| region.as_str() == text)
            .with_context(|| format!("unknown PagerDuty region {text:?}, which should be us or eu"))
    }
}

/// What a custom webhook sends, apart from its headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookRequest {
    #[serde(default)]
    pub method: WebhookMethod,
    /// Like `application/json`. JSON bodies have what's filled in escaped for JSON.
    pub content_type: String,
    /// A Tera template, filled in with the notification.
    pub body: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WebhookMethod {
    #[default]
    Post,
    Put,
    Patch,
}

impl WebhookMethod {
    pub const ALL: [Self; 3] = [Self::Post, Self::Put, Self::Patch];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str() == text)
            .with_context(|| format!("unknown method {text:?}, which should be POST, PUT or PATCH"))
    }
}

/// How a channel sends email. The mail server's password is the channel's
/// `credential`, so it's write-only like every other secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mail {
    /// Who it's from, like `MaxNines <alerts@example.com>`.
    pub from: String,
    /// The mail server, for an email channel. Resend is its own.
    #[serde(default)]
    pub server: Option<MailServer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailServer {
    pub hostname: String,
    /// The usual port for `security` if empty.
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub security: MailSecurity,
    /// Empty for a server that doesn't ask anyone to sign in.
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailSecurity {
    /// Encrypted from the first byte, usually on port 465.
    Tls,
    /// Upgrades to encryption after connecting, usually on port 587.
    #[default]
    Starttls,
    /// No encryption, which only suits a relay on the same host or network.
    None,
}

impl MailSecurity {
    pub const ALL: [Self; 3] = [Self::Starttls, Self::Tls, Self::None];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Starttls => "starttls",
            Self::None => "none",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|security| security.as_str() == text)
            .with_context(|| format!("unknown mail security {text:?}"))
    }
}

pub fn every_severity() -> BTreeSet<Severity> {
    BTreeSet::from([Severity::Warning, Severity::Critical])
}

pub fn check_channel(channel: &ChannelInput) -> Result<()> {
    ensure!(!channel.name.trim().is_empty(), "a channel needs a name");
    ensure!(
        !channel.severities.is_empty(),
        "choose warnings, critical alerts or both"
    );
    let kind = channels::of(channel.kind);
    ensure!(
        channel.app_token.is_none() || kind.takes_app_token(),
        "only Slack channels take an app-level token"
    );
    ensure!(
        channel.mail.is_none() || kind.sends_mail(),
        "only email channels have mail settings"
    );
    ensure!(
        channel.request.is_none() || channel.kind == ChannelKind::CustomWebhook,
        "only custom webhooks have a request to send"
    );
    ensure!(
        channel.region.is_none() || channel.kind == ChannelKind::PagerDuty,
        "only PagerDuty channels have a region"
    );
    ensure!(
        channel.name.len() <= MAX_NAME_LEN,
        "the channel name is too long"
    );
    ensure!(
        channel.target.len() <= MAX_TARGET_LEN,
        "the channel's destination is too long"
    );
    kind.check(channel)
}

impl ChannelInput {
    /// Enough to recognize a channel, without giving away a webhook's secret.
    pub fn target_preview(&self) -> String {
        channels::of(self.kind).preview(&self.target)
    }
}

/// One rule firing for one agent, or one of its series.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    pub id: i64,
    pub rule_id: i64,
    /// What the rule's called now, even once it's deleted.
    pub rule_name: String,
    pub severity: Severity,
    pub host_id: String,
    /// What the host's called now.
    pub hostname: String,
    /// None for alerts about the agent as a whole.
    pub series: Option<String>,
    /// The reading that started the alert.
    pub value: Option<f64>,
    pub summary: String,
    /// When the alert fired.
    pub started_at: Timestamp,
    /// When the problem began, such as when a host went offline: earlier than the
    /// alert started by however long its rule waited before firing.
    pub breached_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub resolve_reason: Option<String>,
    /// Where things stood as the problem cleared, such as the reading then. Nothing
    /// for an alert closed for another reason, such as its rule being deleted.
    pub resolved_summary: Option<String>,
    /// Who said they're dealing with it.
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<Timestamp>,
}

/// What's needed to start an alert.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    pub rule_id: i64,
    pub severity: Severity,
    pub host_id: String,
    pub series: Option<String>,
    pub value: Option<f64>,
    pub summary: String,
    pub started_at: Timestamp,
    /// When the problem began, which the rule waited on before firing.
    pub breached_at: Timestamp,
}

/// An open alert becoming a warning or critical, with what it says then.
#[derive(Debug, Clone, PartialEq)]
pub struct SeverityChange {
    pub alert_id: i64,
    pub severity: Severity,
    pub value: Option<f64>,
    pub summary: String,
    pub changed_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Firing,
    /// A warning became critical.
    Escalated,
    /// A critical alert went back to being a warning.
    Eased,
    Reminder,
    Resolved,
    /// What one of the alert's actions printed.
    Action,
    /// Someone said they're dealing with it, or a silence started covering it,
    /// which an on-call service hears so it stops paging people.
    Acknowledged,
    Test,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firing => "firing",
            Self::Escalated => "escalated",
            Self::Eased => "eased",
            Self::Reminder => "reminder",
            Self::Resolved => "resolved",
            Self::Action => "action",
            Self::Acknowledged => "acknowledged",
            Self::Test => "test",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "firing" => Ok(Self::Firing),
            "escalated" => Ok(Self::Escalated),
            "eased" => Ok(Self::Eased),
            "reminder" => Ok(Self::Reminder),
            "resolved" => Ok(Self::Resolved),
            "action" => Ok(Self::Action),
            "acknowledged" => Ok(Self::Acknowledged),
            other => bail!("unknown event {other:?}"),
        }
    }
}

/// A notification that's due, with what it needs for sending.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivery {
    pub id: i64,
    /// What the service called the notification before this one for the alert.
    pub reply_to: Option<String>,
    pub event: Event,
    pub attempts: i32,
    pub created_at: Timestamp,
    pub alert: Alert,
    pub channel: Channel,
    /// The run whose output this sends, for an `action` notification.
    pub action: Option<ActionRun>,
}

/// A name another of its kind already has, as names are compared: ignoring case and
/// the spaces around them. Alert rules and channels that are deleted don't count, and
/// a check's name only has to differ from the others about the same host. The
/// database keeps each to one, so two saved at once can't both have it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameTaken {
    AlertRule(String),
    Channel(String),
    ConfigRule(String),
    RemoteCheck(String),
    Template(String),
    TemplateKey(String),
}

impl std::fmt::Display for NameTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlertRule(name) => write!(f, "an alert rule named {name:?} already exists"),
            Self::Channel(name) => write!(f, "a channel named {name:?} already exists"),
            Self::ConfigRule(name) => write!(f, "a rule named {name:?} already exists"),
            Self::RemoteCheck(name) => {
                write!(f, "a check named {name:?} already exists for this host")
            }
            Self::Template(name) => write!(f, "a template named {name:?} already exists"),
            Self::TemplateKey(key) => {
                write!(f, "a template with the key {key:?} already exists")
            }
        }
    }
}

impl std::error::Error for NameTaken {}

/// A notification that was given up on, or is still being retried.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeliveryProblem {
    pub channel: String,
    pub summary: String,
    pub event: Event,
    pub state: String,
    pub attempts: i32,
    pub error: String,
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_rule() -> AlertRuleInput {
        AlertRuleInput {
            name: "High CPU".to_string(),
            warning: None,
            critical: Some("cpu.usage > 90".to_string()),
            summary: None,
            resolved_summary: None,
            hold: TimeDelta::seconds(300),
            applies_to: None,
            enabled: true,
            channels: Vec::new(),
            all_channels: false,
            calculation: None,
            metric: None,
            group_by: None,
            filter: None,
            window: None,
            remind_every: None,
            actions: Vec::new(),
        }
    }

    fn calculation_rule() -> AlertRuleInput {
        AlertRuleInput {
            name: "Busy fleet".to_string(),
            critical: Some("value > 80".to_string()),
            calculation: Some(Calculation::Avg),
            metric: Some("cpu.usage".to_string()),
            ..metric_rule()
        }
    }

    fn refused(rule: AlertRuleInput, expected: &str) {
        let error = format!("{:#}", check_rule(&rule).unwrap_err());
        assert!(error.contains(expected), "{expected:?}: {error}");
    }

    #[test]
    fn good_rules_pass() {
        check_rule(&metric_rule()).unwrap();
        check_rule(&calculation_rule()).unwrap();
        // A calculation's value is in its metric's unit, here seconds.
        let slow = AlertRuleInput {
            critical: Some("value > duration('2s')".to_string()),
            metric: Some("check.response".to_string()),
            ..calculation_rule()
        };
        check_rule(&slow).unwrap();
        let counted = AlertRuleInput {
            critical: Some("value < 1".to_string()),
            calculation: Some(Calculation::Count),
            ..slow
        };
        check_rule(&counted).unwrap();
        for (warning, critical) in [
            (Some("disk.usage > 80"), Some("disk.usage > 90")),
            (Some("!reporting"), None),
            (None, Some("!online")),
            (
                Some("forecast(disk.usage, duration('24h')) >= 100"),
                Some("forecast(disk.usage, duration('4h')) >= 100"),
            ),
        ] {
            let rule = AlertRuleInput {
                warning: warning.map(str::to_string),
                critical: critical.map(str::to_string),
                summary: Some("{{ hostname }}: {{ series }} is {{ value }}".to_string()),
                ..metric_rule()
            };
            check_rule(&rule).unwrap_or_else(|error| panic!("{warning:?} {critical:?}: {error:#}"));
        }
    }

    #[test]
    fn bad_rules_are_refused_with_a_reason() {
        refused(
            AlertRuleInput {
                name: " ".to_string(),
                ..metric_rule()
            },
            "needs a name",
        );
        refused(
            AlertRuleInput {
                critical: None,
                ..metric_rule()
            },
            "needs a warning or critical condition",
        );
        refused(
            AlertRuleInput {
                warning: Some("cpu.usage >".to_string()),
                ..metric_rule()
            },
            "the warning condition: ",
        );
        refused(
            AlertRuleInput {
                critical: Some("clock.difference > 30".to_string()),
                ..metric_rule()
            },
            "the critical condition: can't compare a length of time with a number",
        );
        refused(
            AlertRuleInput {
                hold: TimeDelta::days(8),
                ..metric_rule()
            },
            "longer than 7 days",
        );
        refused(
            AlertRuleInput {
                remind_every: Some(TimeDelta::minutes(1)),
                ..metric_rule()
            },
            "every 5 minutes",
        );
        refused(
            AlertRuleInput {
                all_channels: true,
                channels: vec![1],
                ..metric_rule()
            },
            "not both",
        );
        refused(
            AlertRuleInput {
                applies_to: Some("facts.os ==".to_string()),
                ..metric_rule()
            },
            "invalid condition for which hosts",
        );
        refused(
            AlertRuleInput {
                metric: Some("cpu.usage".to_string()),
                ..metric_rule()
            },
            "only a rule with a calculation takes a metric",
        );
        refused(
            AlertRuleInput {
                window: Some(TimeDelta::hours(2)),
                ..metric_rule()
            },
            "only a calculation or forecast() looks back",
        );
        refused(
            AlertRuleInput {
                critical: Some("forecast(disk.usage, duration('4h')) >= 100".to_string()),
                window: Some(TimeDelta::minutes(10)),
                ..metric_rule()
            },
            "between an hour and a day",
        );
        refused(
            AlertRuleInput {
                applies_to: Some("true".to_string()),
                ..calculation_rule()
            },
            "picks its hosts with a filter",
        );
        refused(
            AlertRuleInput {
                window: Some(TimeDelta::seconds(10)),
                ..calculation_rule()
            },
            "between a minute and a day",
        );
        refused(
            AlertRuleInput {
                critical: Some("cpu.usage > 80".to_string()),
                ..calculation_rule()
            },
            "watches the calculated value",
        );
        refused(
            AlertRuleInput {
                metric: Some("cpu.nonsense".to_string()),
                ..calculation_rule()
            },
            "Choose a metric",
        );
        refused(
            AlertRuleInput {
                summary: Some("{{ host ".to_string()),
                ..metric_rule()
            },
            "the summary: ",
        );
        refused(
            AlertRuleInput {
                resolved_summary: Some("{{ disk.usage }}".to_string()),
                ..metric_rule()
            },
            "the resolved summary: ",
        );
    }

    fn values(series: &str, value: Option<&str>) -> SummaryValues {
        SummaryValues {
            hostname: "web-1".to_string(),
            series: series.to_string(),
            value: value.map(str::to_string),
            metrics: vec![
                ("disk.usage".to_string(), json!("92%")),
                ("cpu.load".to_string(), json!({ "5 minutes": "4.2" })),
            ],
            template: None,
        }
    }

    #[test]
    fn summaries_say_the_rule_and_the_reading_unless_the_rule_says_otherwise() {
        let disk = AlertRuleInput {
            name: "Disk filling up".to_string(),
            critical: Some("disk.usage > 90".to_string()),
            ..metric_rule()
        };
        let firing = values("/", Some("92%"));
        assert_eq!(
            disk.summary_for(&firing, Some("/")),
            "Disk filling up on web-1: / is 92%"
        );
        assert_eq!(
            disk.resolved_summary_for(&values("/", Some("70%")), Some("/"))
                .unwrap(),
            "Disk filling up on web-1: / is now 70%"
        );
        let offline = AlertRuleInput {
            name: "Host offline".to_string(),
            critical: Some("!online".to_string()),
            ..metric_rule()
        };
        assert_eq!(
            offline.summary_for(&values("", None), None),
            "Host offline on web-1"
        );
        assert_eq!(offline.resolved_summary_for(&values("", None), None), None);

        let written = AlertRuleInput {
            summary: Some(
                "{{ hostname }}: {{ series }} is {{ disk.usage }}, load {{ cpu.load['5 minutes'] }}\nsoon"
                    .to_string(),
            ),
            resolved_summary: Some("{{ hostname }}: {{ series }} is fine at {{ value }}".to_string()),
            ..disk
        };
        assert_eq!(
            written.summary_for(&firing, Some("/")),
            "web-1: / is 92%, load 4.2soon"
        );
        assert_eq!(
            written.resolved_summary_for(&firing, Some("/")).unwrap(),
            "web-1: / is fine at 92%"
        );
        // One that can't be filled in, such as with a reading missing, says the usual.
        let missing = AlertRuleInput {
            summary: Some("{{ disk.inodes }}".to_string()),
            ..written
        };
        assert_eq!(
            missing.summary_for(&firing, Some("/")),
            "Disk filling up on web-1: / is 92%"
        );
        assert_eq!(
            calculation_rule().summary_for(&values("linux", Some("85%")), Some("linux")),
            "Busy fleet: linux is 85%"
        );
    }

    #[test]
    fn a_summary_can_show_the_metrics_the_conditions_use() {
        let rule = AlertRuleInput {
            warning: Some("cpu.load['5 minutes'] > 4".to_string()),
            critical: Some("disk.usage > 90 && clock.difference > duration('1m')".to_string()),
            summary: Some(
                "{{ cpu.load['5 minutes'] }} {{ disk.usage }} {{ clock.difference }} {{ value }}"
                    .to_string(),
            ),
            ..metric_rule()
        };
        check_rule(&rule).unwrap();
    }

    #[test]
    fn a_metric_is_named_by_its_series_or_its_title() {
        let disk = crate::metrics::find("disk.usage").unwrap();
        let load = crate::metrics::find("cpu.load").unwrap();
        let cpu = crate::metrics::find("cpu.usage").unwrap();
        assert_eq!(subject(&disk, "/", None), "/");
        assert_eq!(
            subject(&load, "", Some("5 minutes")),
            "Load average (5 minutes)"
        );
        assert_eq!(subject(&cpu, "", None), "CPU usage");
    }

    #[test]
    fn rules_describe_their_thresholds_and_what_they_chart() {
        let stored = |rule: AlertRuleInput| AlertRule::new(1, rule, None, &Catalog::built_in());
        let disk = stored(AlertRuleInput {
            warning: Some("disk.usage > 80".to_string()),
            critical: Some("disk.usage > 90 && series != '/boot'".to_string()),
            ..metric_rule()
        });
        assert_eq!(disk.thresholds(), [(Severity::Warning, 80.0)]);
        assert_eq!(
            disk.rule.severities(),
            [Severity::Warning, Severity::Critical]
        );
        assert_eq!(disk.rule.worst_severity(), Severity::Critical);
        assert_eq!(
            disk.watched(&Catalog::built_in()).unwrap().0.name,
            "disk.usage"
        );
        assert_eq!(disk.rule.describe(&Catalog::built_in()), "for 5 minutes");

        let load = stored(AlertRuleInput {
            warning: Some("cpu.load['5 minutes'] > 4".to_string()),
            critical: Some("cpu.load['15 minutes'] > 8".to_string()),
            hold: TimeDelta::zero(),
            ..metric_rule()
        });
        assert_eq!(load.rule.worst_severity(), Severity::Critical);
        assert_eq!(
            load.watched(&Catalog::built_in()),
            Some((
                crate::metrics::find("cpu.load").unwrap(),
                Some("5 minutes".to_string())
            ))
        );
        // Only the level of the series charted is drawn on it.
        assert_eq!(load.thresholds(), [(Severity::Warning, 4.0)]);
        assert_eq!(load.rule.describe(&Catalog::built_in()), "");

        // And only that metric's: a level of another would be at the wrong height.
        let two = stored(AlertRuleInput {
            warning: Some("disk.usage > 80".to_string()),
            critical: Some("cpu.usage > 95".to_string()),
            ..metric_rule()
        });
        assert_eq!(two.thresholds(), [(Severity::Warning, 80.0)]);

        let busy = stored(calculation_rule());
        assert_eq!(busy.thresholds(), [(Severity::Critical, 80.0)]);
        assert_eq!(
            busy.watched(&Catalog::built_in()).unwrap().0.name,
            "cpu.usage"
        );
        assert_eq!(
            busy.rule.describe(&Catalog::built_in()),
            "Average of CPU usage over 5 minutes, for 5 minutes"
        );

        let offline = stored(AlertRuleInput {
            critical: Some("!online".to_string()),
            ..metric_rule()
        });
        assert_eq!(offline.watched(&Catalog::built_in()), None);
        assert!(offline.thresholds().is_empty());
    }

    #[test]
    fn forecasts_look_back_six_hours_unless_told_otherwise() {
        let rule = AlertRuleInput {
            critical: Some("forecast(disk.usage, duration('4h')) >= 100".to_string()),
            ..metric_rule()
        };
        assert_eq!(rule.window(), DEFAULT_FORECAST_WINDOW);
        assert_eq!(calculation_rule().window(), TimeDelta::minutes(5));
    }

    fn webhook(target: &str) -> ChannelInput {
        ChannelInput {
            name: "Ops".to_string(),
            kind: ChannelKind::Webhook,
            target: target.to_string(),
            credential: None,
            app_token: None,
            severities: every_severity(),
            mail: None,
            request: None,
            region: None,
        }
    }

    fn email(target: &str) -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Email,
            mail: Some(Mail {
                from: "MaxNines <alerts@example.com>".to_string(),
                server: Some(MailServer {
                    hostname: "smtp.example.com".to_string(),
                    port: None,
                    security: MailSecurity::Starttls,
                    username: None,
                }),
            }),
            ..webhook(target)
        }
    }

    #[test]
    fn an_email_channel_needs_a_from_address_and_a_mail_server() {
        let mut channel = email("a@example.com");
        channel.mail.as_mut().unwrap().from = "not an address".to_string();
        assert!(format!("{:#}", check_channel(&channel).unwrap_err()).contains("from address"));
        let mut channel = email("a@example.com");
        channel.mail.as_mut().unwrap().server = None;
        assert!(format!("{:#}", check_channel(&channel).unwrap_err()).contains("mail server"));
        for hostname in ["", "smtp.example.com/x", "smtp example.com"] {
            let mut channel = email("a@example.com");
            channel
                .mail
                .as_mut()
                .unwrap()
                .server
                .as_mut()
                .unwrap()
                .hostname = hostname.to_string();
            assert!(check_channel(&channel).is_err(), "{hostname:?}");
        }
    }

    #[test]
    fn only_email_channels_have_mail_settings() {
        let channel = ChannelInput {
            mail: email("a@example.com").mail,
            ..webhook("https://example.com/")
        };
        let error = format!("{:#}", check_channel(&channel).unwrap_err());
        assert!(error.contains("only email channels"), "{error}");
    }

    #[test]
    fn what_agents_choose_is_cleaned() {
        assert_eq!(clean("web\r\nBcc: x@y\0"), "webBcc: x@y");
        assert_eq!(clean(&"é".repeat(300)).chars().count(), 255);
    }

    #[test]
    fn durations_use_the_largest_whole_unit() {
        for (secs, text) in [
            (0, "0 seconds"),
            (1, "1 second"),
            (90, "90 seconds"),
            (60, "1 minute"),
            (300, "5 minutes"),
            (3600, "1 hour"),
            (7200, "2 hours"),
            (86_400, "1 day"),
        ] {
            assert_eq!(format_duration(TimeDelta::seconds(secs)), text);
        }
    }

    #[test]
    fn webhooks_need_a_web_address() {
        check_channel(&webhook("https://hooks.example.com/abc")).unwrap();
        check_channel(&webhook("http://10.0.0.1:8080/hook")).unwrap();
        for target in ["", "hooks.example.com", "ftp://x/y", "file:///etc/passwd"] {
            assert!(check_channel(&webhook(target)).is_err(), "{target}");
        }
    }

    fn discord(target: &str) -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Discord,
            ..webhook(target)
        }
    }

    #[test]
    fn a_teams_channel_needs_a_workflow_url_and_keeps_it_hidden() {
        let teams = |target: &str| of_kind(ChannelKind::Teams, target);
        for good in [
            "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=secret",
            "https://default1234.56.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?sig=secret",
        ] {
            check_channel(&teams(good)).unwrap();
            assert!(!teams(good).target_preview().contains("secret"));
        }
        for bad in [
            "https://example.webhook.office.com/webhookb2/abc",
            "http://prod-12.westus.logic.azure.com/workflows/abc",
            "https://logic.azure.com.example.net/workflows/abc",
            "https://prod-12.westus.logic.azure.com/other",
            "not a url",
        ] {
            let error = check_channel(&teams(bad)).unwrap_err().to_string();
            assert!(error.contains("Teams workflow"), "{bad}: {error}");
            assert!(!error.contains("abc"), "{error}");
        }
    }

    fn of_kind(kind: ChannelKind, target: &str) -> ChannelInput {
        ChannelInput {
            kind,
            ..webhook(target)
        }
    }

    #[test]
    fn an_alertops_url_has_to_look_like_one() {
        for good in [
            "https://notify.alertops.com/POSTAlert/8f14e45f/Custom",
            "https://acme.alertops.com/POSTAlert/8f14e45f/Custom",
        ] {
            check_channel(&of_kind(ChannelKind::AlertOps, good)).unwrap();
        }
        for bad in [
            "http://notify.alertops.com/POSTAlert/8f14e45f/Custom",
            "https://notify.alertops.com/POSTAlert/",
            "https://notify.alertops.com/other/8f14e45f",
            "https://alertops.com.example.org/POSTAlert/8f14e45f",
            "8f14e45f",
        ] {
            assert!(
                check_channel(&of_kind(ChannelKind::AlertOps, bad)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_signl4_url_has_to_look_like_one() {
        check_channel(&of_kind(
            ChannelKind::Signl4,
            "https://connect.signl4.com/webhook/abc123",
        ))
        .unwrap();
        for bad in [
            "http://connect.signl4.com/webhook/abc123",
            "https://connect.signl4.com/webhook/",
            "https://connect.signl4.com/api/abc123",
            "https://signl4.com.example.org/webhook/abc123",
            "abc123",
        ] {
            assert!(
                check_channel(&of_kind(ChannelKind::Signl4, bad)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_refused_service_url_is_not_repeated() {
        for kind in [ChannelKind::AlertOps, ChannelKind::Signl4] {
            for bad in [
                "https://exa mple/secret-token",
                "https://example.com/secret-token",
            ] {
                let error = check_channel(&of_kind(kind, bad)).unwrap_err();
                assert!(!error.to_string().contains("secret-token"), "{error}");
            }
        }
    }

    fn slack(target: &str, token: Option<&str>) -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Slack,
            credential: token.map(String::from),
            ..webhook(target)
        }
    }

    #[test]
    fn slack_channels_need_a_channel_and_a_bot_token() {
        check_channel(&slack("#alerts", Some("xoxb-1"))).unwrap();
        check_channel(&slack("C0123456789", Some("xoxb-1"))).unwrap();

        for bad in [
            slack("", Some("xoxb-1")),
            slack("two words", Some("xoxb-1")),
            slack(&"x".repeat(82), Some("xoxb-1")),
            slack("#alerts", None),
            slack("#alerts", Some("xoxp-user-token")),
            slack("#alerts", Some("https://hooks.slack.com/services/x")),
        ] {
            assert!(check_channel(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_app_level_token_is_only_for_slack_and_must_look_right() {
        let with = |kind: ChannelInput, token: &str| ChannelInput {
            app_token: Some(token.to_string()),
            ..kind
        };
        check_channel(&with(slack("#alerts", Some("xoxb-1")), "xapp-1-A1-abc")).unwrap();
        assert!(check_channel(&with(slack("#alerts", Some("xoxb-1")), "xoxb-2")).is_err());
        assert!(
            check_channel(&with(
                discord("https://discord.com/api/webhooks/1/t"),
                "xapp-1"
            ))
            .is_err()
        );
    }

    #[test]
    fn a_slack_channel_is_shown_but_its_token_is_not() {
        let channel = slack("#alerts", Some("xoxb-secret"));
        assert_eq!(channel.target_preview(), "#alerts");
    }

    fn telegram(target: &str, token: Option<&str>) -> ChannelInput {
        ChannelInput {
            name: "Telegram".to_string(),
            kind: ChannelKind::Telegram,
            target: target.to_string(),
            credential: token.map(str::to_string),
            app_token: None,
            severities: every_severity(),
            mail: None,
            request: None,
            region: None,
        }
    }

    const TELEGRAM_TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

    #[test]
    fn telegram_channels_need_a_chat_and_a_bot_token() {
        for chat in ["-1001234567890", "123456789", "@alerts_room"] {
            check_channel(&telegram(chat, Some(TELEGRAM_TOKEN))).unwrap();
        }
        for bad in [
            telegram("", Some(TELEGRAM_TOKEN)),
            telegram("0", Some(TELEGRAM_TOKEN)),
            telegram("#alerts", Some(TELEGRAM_TOKEN)),
            telegram("@abc", Some(TELEGRAM_TOKEN)),
            telegram("@has space", Some(TELEGRAM_TOKEN)),
            telegram("https://t.me/alerts", Some(TELEGRAM_TOKEN)),
            telegram("-100123", None),
            telegram("-100123", Some("xoxb-1")),
            telegram("-100123", Some("123456789:short")),
            telegram("-100123", Some("bot:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw")),
        ] {
            assert!(check_channel(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_telegram_chat_is_shown_but_its_token_is_not() {
        let channel = telegram("-1001234567890", Some(TELEGRAM_TOKEN));
        assert_eq!(channel.target_preview(), "-1001234567890");
        let error = check_channel(&telegram("-100123", Some("123:wrong-secret")))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("wrong-secret"), "{error}");
    }

    #[test]
    fn discord_channels_need_a_discord_webhook_url() {
        for good in [
            "https://discord.com/api/webhooks/123/token",
            "https://discordapp.com/api/webhooks/123/token",
            "https://canary.discord.com/api/webhooks/123/token",
        ] {
            check_channel(&discord(good)).unwrap();
        }
        for bad in [
            "",
            "http://discord.com/api/webhooks/123/token",
            "https://discord.com/channels/123",
            "https://evil.example.com/api/webhooks/123/token",
            "https://discord.com.evil.example/api/webhooks/1/t",
        ] {
            assert!(check_channel(&discord(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_discord_url_is_treated_as_a_secret() {
        let channel = discord("https://discord.com/api/webhooks/123/secret-token");
        assert_eq!(channel.target_preview(), "https://discord.com/…");

        let error = check_channel(&discord("https://exa mple/secret-token")).unwrap_err();
        assert!(!format!("{error:#}").contains("secret-token"));
    }

    #[test]
    fn a_bad_webhook_url_is_not_repeated_in_the_error() {
        let error = check_channel(&webhook("https://exa mple.com/secret-token")).unwrap_err();
        assert!(!format!("{error:#}").contains("secret-token"));
    }

    #[test]
    fn email_channels_need_valid_addresses() {
        check_channel(&email("a@example.com, b@example.com")).unwrap();
        assert!(check_channel(&email("")).is_err());
        assert!(check_channel(&email(" , ")).is_err());
        assert!(check_channel(&email("not an address")).is_err());
        let many = vec!["a@example.com"; crate::channels::email::MAX_RECIPIENTS + 1].join(",");
        assert!(check_channel(&email(&many)).is_err());
    }

    #[test]
    fn previews_hide_a_webhooks_path_and_credentials() {
        let channel = webhook("https://user:pass@hooks.example.com/services/secret?key=1");
        assert_eq!(channel.target_preview(), "https://hooks.example.com/…");
        assert_eq!(email("a@example.com").target_preview(), "a@example.com");
    }

    #[test]
    fn channels_can_be_told_apart_from_rules_of_any_length() {
        let long = ChannelInput {
            name: "x".repeat(256),
            ..webhook("https://example.com/")
        };
        assert!(check_channel(&long).is_err());
        let huge = webhook(&format!("https://example.com/{}", "x".repeat(3000)));
        assert!(check_channel(&huge).is_err());
    }
}
