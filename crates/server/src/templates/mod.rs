//! Templates on the server: the built-in ones it ships, what it checks that the
//! format can't by itself, and how a template's alerts become alert rules.
//!
//! The format is [`maxnines_protocol::templates`], which the agent reads too. Here,
//! on top of what [`Template::check`] finds, every CEL expression has to compile,
//! queries' SQL has to say what columns it gives, and alerts go through the same
//! checks as alert rules, with the template's own metrics known by their short and
//! full names.

pub mod agentless;
pub mod built_in;
pub mod hosts;
pub mod own_database;
pub mod values;
pub mod work;

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

use crate::alert_conditions::{Names, Variable};
use crate::alerting::{AlertRuleInput, check_rule_in};
use crate::catalog::Catalog;
use crate::metrics::{INSTANCE_LABEL, Kind, Labelled, Metric, ShowChart, Source, Unit};

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
pub fn load(text: &str, facts: &Value, catalog: &Catalog) -> Result<Template> {
    let template = maxnines_protocol::templates::parse(text)?;
    let problems = check(&template, facts, catalog);
    if !problems.is_empty() {
        bail!(Problems::new(&template, problems));
    }
    Ok(template)
}

/// Everything wrong with a template, with conditions tried on `facts`, a real host's
/// if there is one, and names looked up in `catalog`, the metrics there are besides
/// the template's own.
pub fn check(template: &Template, facts: &Value, catalog: &Catalog) -> Vec<Problem> {
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
    cel(Place::Template, "applies_to", &template.applies_to);
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
    // SQL runs on a database, so only a template for a kind of database has any.
    if !matches!(template.target, Some(Target::Database(_))) {
        const NO_DATABASE: &str =
            "needs a database to run on: SQL is only for a template with database = \"<kind>\"";
        for (index, discover) in template.discover.iter().enumerate() {
            if discover.sql.is_some() {
                problems.push(Problem::new(Place::Discover(index), "sql", NO_DATABASE));
            }
        }
        for index in 0..template.queries.len() {
            problems.push(Problem::new(Place::Query(index), "sql", NO_DATABASE));
        }
    }
    // What each discover block finds is looked at together, so no two find the same.
    // The format checks registry values and counter sets against each other, so here
    // it's columns against each other and against those.
    let mut found: Vec<(String, usize, bool)> = Vec::new();
    for (index, discover) in template.discover.iter().enumerate() {
        let place = Place::Discover(index);
        let columns = match discover
            .sql
            .as_deref()
            .map(|sql| columns(dialect.as_ref(), sql))
        {
            Some(Ok(columns)) => columns,
            Some(Err(message)) => {
                problems.push(Problem::new(place, "sql", message));
                Vec::new()
            }
            None => Vec::new(),
        };
        let others = discover
            .registry
            .iter()
            .flat_map(|read| read.values.keys().map(|name| (name, "registry")))
            .chain(
                discover
                    .counter_sets
                    .keys()
                    .map(|name| (name, "counter_sets")),
            );
        let named = columns.iter().map(|name| (name, "sql")).chain(others);
        for (name, field) in named {
            let column = field == "sql";
            let earlier = found
                .iter()
                .find(|(seen, _, seen_column)| seen == name && (column || *seen_column));
            if let Some((_, block, _)) = earlier {
                let message = match *block == index {
                    true => format!("{name:?} is found twice"),
                    false => format!("{name:?} is found by another discover block too"),
                };
                problems.push(Problem::new(place, field, message));
            }
            found.push((name.clone(), index, column));
        }
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
        let runs_for_each = matches!(template.target, Some(Target::Database(_)));
        for label in &query.labels {
            if !columns.contains(label) {
                problems.push(Problem::new(
                    place,
                    "labels",
                    format!("{label:?} isn't one of the query's columns"),
                ));
            } else if runs_for_each && label == INSTANCE_LABEL {
                problems.push(Problem::new(
                    place,
                    "labels",
                    format!(
                        "a label can't be called {INSTANCE_LABEL}, which every series already has for the database it's from"
                    ),
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

    let own = metrics_of(template);
    let short = |metric: &Metric| metric.name[template.key.len() + 1..].to_string();
    // Two metrics can't share a name, and the ones MaxNines reads itself are there
    // first. Said once for each query or counters block, however many it has.
    let mut taken: Vec<(Place, &'static str, Vec<String>)> = Vec::new();
    for (metric, _) in &own {
        let short = short(metric);
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
        if crate::metrics::find(&metric.name).is_some() {
            let (place, how) = taken_place(template, &short);
            match taken.iter_mut().find(|(seen, ..)| *seen == place) {
                Some((.., names)) => names.push(metric.name.clone()),
                None => taken.push((place, how, vec![metric.name.clone()])),
            }
        }
    }
    // An alert about a name that's taken would be read as being about the built-in
    // metric, so there's nothing to learn from checking the alerts until it isn't.
    let names_taken = !taken.is_empty();
    for (place, how, names) in taken {
        let message = match names.as_slice() {
            [name] => {
                format!("its metric {name} would have the name of one MaxNines has built in: {how}")
            }
            names => format!(
                "its metrics {} would have the names of ones MaxNines has built in: {how}",
                names.join(", ")
            ),
        };
        problems.push(Problem::new(place, "", message));
    }
    let catalog = catalog.with_template(template);
    let names = Names {
        catalog: &catalog,
        template: Some(&template.key),
    };
    let alerts = template.alerts.iter().enumerate();
    for (index, alert) in alerts.filter(|_| !names_taken) {
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
        if let Err(error) = check_rule_in(&rule, facts, &names) {
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

/// What a template's discovery finds, by the names `when` uses: its SQL's columns,
/// its registry values and its counter sets.
pub fn discovered_names(template: &Template) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for discover in &template.discover {
        names.extend(
            discover
                .sql
                .as_deref()
                .and_then(|sql| columns(dialect_for(template.target.as_ref()).as_ref(), sql).ok())
                .unwrap_or_default(),
        );
        names.extend(
            discover
                .registry
                .iter()
                .flat_map(|read| read.values.keys().cloned()),
        );
        names.extend(discover.counter_sets.keys().cloned());
    }
    names
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
fn kind_of_value(value: &str) -> Kind {
    let Ok(program) = Program::compile(value) else {
        return Kind::Number;
    };
    let mut context = CelContext::default();
    context.add_variable_from_value("value", CelValue::Float(50.0));
    match program.execute(&context) {
        Ok(CelValue::Bool(_)) => Kind::Flag,
        _ => Kind::Number,
    }
}

fn kind_of(metric: &maxnines_protocol::templates::Metric, column: bool) -> Kind {
    if metric.unit.as_deref() == Some("s") {
        return Kind::Seconds;
    }
    if let Some(value) = &metric.value {
        return kind_of_value(value);
    }
    if !metric.states.is_empty() || metric.total || metric.unit.is_some() || !column {
        return Kind::Number;
    }
    // A column whose type only the database knows.
    Kind::Unknown
}

/// The unit a template gives a metric, by how templates write units.
fn unit_named(unit: &str) -> Option<Unit> {
    Some(match unit {
        "%" => Unit::Percent,
        "s" => Unit::Seconds,
        "bytes" => Unit::Bytes,
        "bytes/s" => Unit::BytesPerSecond,
        "/s" => Unit::PerSecond,
        "°C" => Unit::Celsius,
        _ => return None,
    })
}

/// The unit Windows' own name for a performance counter says it's in.
fn counter_unit(counter: &str) -> Unit {
    let counter = counter.trim();
    let bytes = counter.starts_with("Bytes");
    match counter.to_lowercase().ends_with("/sec") {
        true if bytes => Unit::BytesPerSecond,
        true => Unit::PerSecond,
        false if bytes => Unit::Bytes,
        false if counter.starts_with('%') => Unit::Percent,
        false => Unit::Number,
    }
}

/// What a metric is measured in: what the template says, or what a counter's name
/// does, with a running total read as a rate each second.
fn unit_of(metric: Option<&maxnines_protocol::templates::Metric>) -> Unit {
    let Some(metric) = metric else {
        return Unit::Number;
    };
    let said = metric.unit.as_deref().and_then(unit_named);
    let unit = match (said, &metric.counter) {
        (Some(unit), _) => unit,
        (None, Some(counter)) if metric.value.is_none() => counter_unit(counter),
        _ => Unit::Number,
    };
    match (metric.total, unit) {
        (true, Unit::Bytes) => Unit::BytesPerSecond,
        (true, Unit::Number) => Unit::PerSecond,
        (_, unit) => unit,
    }
}

/// The collector a template's samples are stored under, which no collector an
/// agent has built in can be called, as a key has no dot.
pub fn collector_of(key: &str) -> String {
    maxnines_protocol::templates::work::collector_of(key)
}

/// The template's metrics, as they're read, each with whether it's on: each query's
/// columns that aren't labels, the metrics worked out from them, each counter, and
/// whether a database template's database is answering. One is on if the template
/// and a query or counters block that gives it are.
///
/// A database template runs once for each database, so each of its series is
/// labelled with which, before the query's own labels. A metric that several
/// queries give has the labels of them all.
pub fn metrics_of(template: &Template) -> Vec<(Metric, bool)> {
    struct Found {
        key: String,
        kind: Kind,
        unit: Unit,
        description: Option<String>,
        total: bool,
        labels: Vec<String>,
        on: bool,
    }
    let mut found: Vec<Found> = Vec::new();
    let mut add = |new: Found| match found.iter_mut().find(|seen| seen.key == new.key) {
        Some(seen) => {
            for label in new.labels {
                if !seen.labels.contains(&label) {
                    seen.labels.push(label);
                }
            }
            seen.on |= new.on;
        }
        None => found.push(new),
    };

    let instance = matches!(template.target, Some(Target::Database(_)));
    let labelled = |own: &[String]| -> Vec<String> {
        let instance = instance.then(|| INSTANCE_LABEL.to_string());
        let own = own.iter().filter(|label| *label != INSTANCE_LABEL).cloned();
        instance.into_iter().chain(own).collect()
    };
    if instance {
        add(Found {
            key: UP.to_string(),
            kind: Kind::Flag,
            unit: Unit::Number,
            description: Some("Whether the database is answering".to_string()),
            total: false,
            labels: labelled(&[]),
            on: template.enabled,
        });
    }
    let dialect = dialect_for(template.target.as_ref());
    for query in &template.queries {
        let on = template.enabled && query.enabled;
        let columns = query_columns(dialect.as_ref(), query).unwrap_or_default();
        let metrics = columns
            .iter()
            .filter(|column| !query.labels.contains(column))
            .map(|column| (column, true))
            .chain(
                query
                    .metrics
                    .iter()
                    .filter(|metric| !columns.contains(&metric.key))
                    .map(|metric| (&metric.key, false)),
            );
        for (key, column) in metrics {
            let detail = query.metrics.iter().find(|metric| &metric.key == key);
            add(Found {
                key: key.clone(),
                kind: detail.map_or(Kind::Unknown, |metric| kind_of(metric, column)),
                unit: unit_of(detail),
                description: detail.and_then(|metric| metric.description.clone()),
                total: detail.is_some_and(|metric| metric.total),
                labels: labelled(&query.labels),
                on,
            });
        }
    }
    for counters in &template.counters {
        let labels = labelled(&counters.labels());
        for metric in &counters.metrics {
            add(Found {
                key: metric.key.clone(),
                kind: kind_of(metric, false),
                unit: unit_of(Some(metric)),
                description: metric.description.clone(),
                total: metric.total,
                labels: labels.clone(),
                on: template.enabled && counters.enabled,
            });
        }
    }

    found
        .into_iter()
        // What's read is written into the stores' queries by name, so only names
        // a template's checks allow are read.
        .filter(|metric| {
            is_key(&template.key)
                && is_key(&metric.key)
                && metric.labels.iter().all(|label| is_key(label))
        })
        .map(|metric| {
            let read = Metric {
                name: format!("{}.{}", template.key, metric.key),
                title: format!("{} {}", template.name, metric.key.replace('_', " ")),
                unit: metric.unit,
                collector: collector_of(&template.key),
                description: metric.description,
                template: Some(template.key.clone()),
                kind: metric.kind,
                source: Source::Labelled(Labelled {
                    field: metric.key,
                    labels: metric.labels,
                    total: metric.total,
                }),
                chart: ShowChart::WithData,
            };
            (read, metric.on)
        })
        .collect()
}

/// Where a template gives a metric whose name is taken, and what to do about it.
fn taken_place(template: &Template, short: &str) -> (Place, &'static str) {
    let dialect = dialect_for(template.target.as_ref());
    for (index, query) in template.queries.iter().enumerate() {
        let columns = query_columns(dialect.as_ref(), query).unwrap_or_default();
        if columns.iter().any(|column| column == short)
            || query.metrics.iter().any(|metric| metric.key == short)
        {
            return (
                Place::Query(index),
                "give the columns other names, or the template another key",
            );
        }
    }
    for (index, counters) in template.counters.iter().enumerate() {
        if counters.metrics.iter().any(|metric| metric.key == short) {
            return (
                Place::Counters(index),
                "give the metrics other names, or the template another key",
            );
        }
    }
    // Whether its database is answering, which every database template has.
    (Place::Template, "give the template another key")
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

/// The PostgreSQL example from the docs, under the key `pg`. As written its key is
/// `postgres`, which would give its metrics the names of the ones MaxNines reads
/// from PostgreSQL itself, so it's refused: tests that need a template like it use
/// this.
#[cfg(test)]
pub fn postgres_example() -> String {
    include_str!("../../../../docs/examples/postgres.hcl").replacen(
        "template \"postgres\"",
        "template \"pg\"",
        1,
    )
}

#[cfg(test)]
mod tests;
