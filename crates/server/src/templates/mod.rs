//! Templates on the server: the built-in ones it ships, what it checks that the
//! format can't by itself, and how a template's alerts become alert rules.
//!
//! The format is [`maxnines_protocol::templates`], which the agent reads too. Here,
//! on top of what [`Template::check`] finds, every CEL expression has to compile,
//! queries' SQL has to say what columns it gives, and alerts go through the same
//! checks as alert rules, with the template's own metrics known by their short and
//! full names.

pub mod built_in;

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use cel::{Context as CelContext, Program, Value as CelValue};
use chrono::TimeDelta;
use serde_json::Value;
use sqlparser::ast::{Expr, SelectItem, SetExpr, Statement};
use sqlparser::dialect::{Dialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

use maxnines_protocol::templates::{
    Alert, Place, Problem, Problems, Target, Template, filled_sql, is_key, parse_duration,
};

use crate::alert_conditions::{LocalKind, LocalMetric, LocalMetrics, Variable};
use crate::alerting::{AlertRuleInput, check_rule_in};

/// Something that can't be done to a template or one of its alert rules, such as
/// changing a built-in template's HCL, which says why to whoever asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// What an agent sends for a database template whether it can sign in or not.
pub const UP: &str = "up";

/// Reads a template from HCL and checks it, saying everything that's wrong with it.
pub fn load(text: &str, facts: &Value) -> Result<Template> {
    let template = maxnines_protocol::templates::parse(text)?;
    let problems = check(&template, facts);
    if !problems.is_empty() {
        bail!(Problems::new(&template, problems));
    }
    Ok(template)
}

/// Everything wrong with a template, with conditions tried on `facts`, a real host's
/// if there is one.
pub fn check(template: &Template, facts: &Value) -> Vec<Problem> {
    let mut problems = template.check();
    let mut say = |place: Place, field: &str, message: String| {
        problems.push(Problem::new(place, field, message));
    };

    let mut cel = |place: Place, field: &str, text: &Option<String>| {
        if let Some(text) = text
            && let Err(error) = Program::compile(text)
        {
            say(place, field, format!("isn't CEL: {error}"));
        }
    };
    for (index, notice) in template.notices.iter().enumerate() {
        cel(Place::Notice(index), "when", &notice.when);
    }
    for (index, query) in template.queries.iter().enumerate() {
        cel(Place::Query(index), "when", &query.when);
        for (number, metric) in query.metrics.iter().enumerate() {
            cel(Place::QueryMetric(index, number), "value", &metric.value);
        }
    }
    for (index, counters) in template.counters.iter().enumerate() {
        cel(Place::Counters(index), "when", &counters.when);
        for (number, metric) in counters.metrics.iter().enumerate() {
            cel(Place::CountersMetric(index, number), "value", &metric.value);
        }
    }
    for (index, alert) in template.alerts.iter().enumerate() {
        cel(Place::Alert(index), "when", &alert.when);
    }

    let dialect = dialect_for(template.target.as_ref());
    if let Some(sql) = template.discover.as_ref().and_then(|d| d.sql.as_ref())
        && let Err(message) = columns(dialect.as_ref(), sql)
    {
        problems.push(Problem::new(Place::Discover, "sql", message));
    }
    for (index, query) in template.queries.iter().enumerate() {
        let place = Place::Query(index);
        let columns = match query_columns(dialect.as_ref(), query) {
            Ok(columns) => columns,
            Err(message) => {
                problems.push(Problem::new(place, "sql", message));
                continue;
            }
        };
        for label in &query.labels {
            if !columns.contains(label) {
                problems.push(Problem::new(
                    place,
                    "labels",
                    format!("{label:?} isn't one of the query's columns"),
                ));
            }
        }
        for (number, metric) in query.metrics.iter().enumerate() {
            if metric.value.is_none() && !columns.contains(&metric.key) {
                problems.push(Problem::new(
                    Place::QueryMetric(index, number),
                    "",
                    format!(
                        "{:?} isn't one of the query's columns, so it needs a value worked out from them",
                        metric.key
                    ),
                ));
            }
        }
    }

    let local = local_metrics(template);
    for short in local.metrics.keys() {
        if let Some(variable) = Variable::ALL.iter().find(|v| v.name() == short) {
            problems.push(Problem::new(
                Place::Template,
                "",
                format!(
                    "a metric can't be called {short}, which conditions use for {}",
                    variable.describe()
                ),
            ));
        }
    }
    for (index, alert) in template.alerts.iter().enumerate() {
        // Lengths of time that are wrong, which the format's checks have said, are
        // left out, so the rest is still checked.
        let without_lengths = Alert {
            hold: None,
            window: None,
            ..alert.clone()
        };
        let Ok(rule) =
            alert_rule(template, alert).or_else(|_| alert_rule(template, &without_lengths))
        else {
            continue;
        };
        if let Err(error) = check_rule_in(&rule, facts, Some(&local)) {
            let message = format!("{error:#}");
            let (field, message) = field_of(&message);
            problems.push(Problem::new(Place::Alert(index), field, message));
        }
    }
    problems
}

/// The alert field a rule's check means, from how its message starts, and the rest
/// of the message.
fn field_of(message: &str) -> (&'static str, String) {
    for (start, field) in [
        ("the warning condition: ", "warning"),
        ("the critical condition: ", "critical"),
        ("the resolved summary: ", "resolved_summary"),
        ("the summary: ", "summary"),
    ] {
        if let Some(rest) = message.strip_prefix(start) {
            return (field, rest.to_string());
        }
    }
    if message.starts_with("the duration") {
        return ("for", message.to_string());
    }
    if message.starts_with("forecast()") || message.starts_with("only a calculation or forecast()")
    {
        return ("window", message.to_string());
    }
    if message.starts_with("the rule name") || message.starts_with("a rule needs a name") {
        return ("name", message.to_string());
    }
    ("", message.to_string())
}

fn dialect_for(target: Option<&Target>) -> Box<dyn Dialect> {
    match target {
        Some(Target::Database(kind)) => match kind.as_str() {
            "postgres" => Box::new(PostgreSqlDialect {}),
            "mysql" => Box::new(MySqlDialect {}),
            "mssql" | "sqlserver" => Box::new(MsSqlDialect {}),
            _ => Box::new(GenericDialect {}),
        },
        _ => Box::new(GenericDialect {}),
    }
}

/// The columns a template's query gives, or none if they can't be read.
pub fn query_columns_of(
    template: &Template,
    query: &maxnines_protocol::templates::Query,
) -> Vec<String> {
    query_columns(dialect_for(template.target.as_ref()).as_ref(), query).unwrap_or_default()
}

/// The columns of a query, with each version's fills filled in, each once.
fn query_columns(
    dialect: &dyn Dialect,
    query: &maxnines_protocol::templates::Query,
) -> Result<Vec<String>, String> {
    let mut all = Vec::new();
    for sql in filled_sql(query) {
        for column in columns(dialect, &sql)? {
            if !all.contains(&column) {
                all.push(column);
            }
        }
    }
    Ok(all)
}

/// The names of the columns a `SELECT` gives, which have to be names a metric can
/// have.
pub fn columns(dialect: &dyn Dialect, sql: &str) -> Result<Vec<String>, String> {
    let statements =
        Parser::parse_sql(dialect, sql).map_err(|error| format!("can't be read: {error}"))?;
    let [Statement::Query(query)] = statements.as_slice() else {
        return Err("has to be one SELECT".to_string());
    };
    let mut body = query.body.as_ref();
    let select = loop {
        match body {
            SetExpr::Select(select) => break select,
            SetExpr::Query(inner) => body = inner.body.as_ref(),
            SetExpr::SetOperation { left, .. } => body = left.as_ref(),
            _ => return Err("has to be a SELECT".to_string()),
        }
    };
    let mut names = Vec::new();
    for (index, item) in select.projection.iter().enumerate() {
        let ident = match item {
            SelectItem::ExprWithAlias { alias, .. } => alias,
            SelectItem::UnnamedExpr(Expr::Identifier(ident)) => ident,
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                parts.last().expect("a compound identifier has parts")
            }
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => {
                return Err("has to name each column rather than use *".to_string());
            }
            _ => {
                return Err(format!(
                    "column {} needs a name: add AS and the name it's to have",
                    index + 1
                ));
            }
        };
        // Names that aren't quoted are lowercase to the database.
        let name = match ident.quote_style {
            Some(_) => ident.value.clone(),
            None => ident.value.to_lowercase(),
        };
        if !is_key(&name) {
            return Err(format!(
                "the column {name:?} can't be a metric's name: name it with AS in lowercase letters, digits and underscores"
            ));
        }
        if names.contains(&name) {
            return Err(format!("has two columns called {name:?}"));
        }
        names.push(name);
    }
    Ok(names)
}

/// What a metric's `value` gives, tried on a sample: true or false, or a number.
fn kind_of_value(value: &str) -> LocalKind {
    let Ok(program) = Program::compile(value) else {
        return LocalKind::Number;
    };
    let mut context = CelContext::default();
    context.add_variable_from_value("value", CelValue::Float(50.0));
    match program.execute(&context) {
        Ok(CelValue::Bool(_)) => LocalKind::Flag,
        _ => LocalKind::Number,
    }
}

fn kind_of(metric: &maxnines_protocol::templates::Metric, column: bool) -> LocalKind {
    if metric.unit.as_deref() == Some("s") {
        return LocalKind::Seconds;
    }
    if let Some(value) = &metric.value {
        return kind_of_value(value);
    }
    if !metric.states.is_empty() || metric.total || metric.unit.is_some() || !column {
        return LocalKind::Number;
    }
    // A column whose type only the database knows.
    LocalKind::Unknown
}

/// The template's own metrics, as its conditions see them: each query's columns
/// that aren't labels, the metrics worked out from them, each counter, and whether a
/// database template's database is answering.
pub fn local_metrics(template: &Template) -> LocalMetrics {
    let mut metrics: BTreeMap<String, LocalMetric> = BTreeMap::new();
    if let Some(Target::Database(_)) = template.target {
        metrics.insert(
            UP.to_string(),
            LocalMetric {
                kind: LocalKind::Flag,
                labels: Vec::new(),
            },
        );
    }
    let dialect = dialect_for(template.target.as_ref());
    for query in &template.queries {
        let columns = query_columns(dialect.as_ref(), query).unwrap_or_default();
        for column in columns
            .iter()
            .filter(|column| !query.labels.contains(column))
        {
            let detail = query.metrics.iter().find(|metric| &metric.key == column);
            let kind = detail.map_or(LocalKind::Unknown, |metric| kind_of(metric, true));
            metrics.entry(column.clone()).or_insert(LocalMetric {
                kind,
                labels: query.labels.clone(),
            });
        }
        for metric in query.metrics.iter().filter(|m| !columns.contains(&m.key)) {
            metrics.entry(metric.key.clone()).or_insert(LocalMetric {
                kind: kind_of(metric, false),
                labels: query.labels.clone(),
            });
        }
    }
    for counters in &template.counters {
        let labels = counters.labels();
        for metric in &counters.metrics {
            metrics.entry(metric.key.clone()).or_insert(LocalMetric {
                kind: kind_of(metric, false),
                labels: labels.clone(),
            });
        }
    }
    LocalMetrics {
        prefix: template.key.clone(),
        metrics,
    }
}

/// A length of time a template wrote, which its checks have made sure is one.
fn seconds(text: &Option<String>) -> Result<Option<TimeDelta>> {
    text.as_deref()
        .map(|text| {
            let secs = parse_duration(text).map_err(anyhow::Error::msg)?;
            Ok(TimeDelta::seconds(i64::try_from(secs)?))
        })
        .transpose()
}

/// Which hosts a template's alerts are for, as an alert rule says it: those running
/// one of its operating systems.
pub fn applies_to(template: &Template) -> Option<String> {
    match &template.target {
        Some(Target::Os(systems)) => {
            let quoted: Vec<String> = systems.iter().map(|system| format!("'{system}'")).collect();
            Some(format!("facts.os.family in [{}]", quoted.join(", ")))
        }
        _ => None,
    }
}

/// An alert as the template has it, as an alert rule: telling every channel, as
/// what's added to it is the people's own.
pub fn alert_rule(template: &Template, alert: &Alert) -> Result<AlertRuleInput> {
    Ok(AlertRuleInput {
        name: alert.name.clone(),
        warning: alert.warning.clone(),
        critical: alert.critical.clone(),
        summary: alert.summary.clone(),
        resolved_summary: alert.resolved_summary.clone(),
        hold: seconds(&alert.hold)?.unwrap_or_default(),
        applies_to: applies_to(template),
        enabled: alert.enabled,
        channels: Vec::new(),
        all_channels: true,
        calculation: None,
        metric: None,
        group_by: None,
        filter: None,
        window: seconds(&alert.window)?,
        remind_every: None,
        actions: Vec::new(),
    })
}

#[cfg(test)]
mod tests;
