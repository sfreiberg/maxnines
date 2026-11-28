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
pub mod runs;
pub mod values;
pub mod work;

use anyhow::{Result, bail};
use cel::{Context as CelContext, Program, Value as CelValue};
use chrono::TimeDelta;
use serde_json::Value;
use sqlparser::ast::{Expr, SelectItem, SetExpr, Statement};
use sqlparser::dialect::{
    ClickHouseDialect, Dialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect,
};
use sqlparser::parser::Parser;

use maxnines_protocol::templates::{
    Alert, Asked, Place, Problem, Problems, Target, Template, check_command, filled_sql, is_key,
    is_show, parse_duration, redis_command,
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

    // Its settings are a config rule's, checked as one is.
    if let Some(rule) = crate::built_in_rules::of_template(template)
        && let Err(error) = crate::rule_engine::check_rule(&rule.rule)
    {
        say(Place::Template, "config", format!("{error:#}"));
    }

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
    let statement = statement_field(template);
    for (index, discover) in template.discover.iter().enumerate() {
        let place = Place::Discover(index);
        let columns = match discover_columns(template, discover) {
            Ok(columns) => columns,
            Err((field, message)) => {
                problems.push(Problem::new(place, field, message));
                Vec::new()
            }
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
        let named = columns.iter().map(|name| (name, statement)).chain(others);
        for (name, field) in named {
            let column = field == statement;
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
        let columns = match query_columns(template, query) {
            Ok(columns) => columns,
            Err((field, message)) => {
                problems.push(Problem::new(place, field, message));
                continue;
            }
        };
        if query.columns.is_empty() && filled_sql(query).iter().any(|sql| is_show(sql)) {
            problems.push(Problem::new(
                place,
                "columns",
                "has to name the columns a SHOW statement reads, such as lag = \"Seconds_Behind_Source\"",
            ));
        }
        for label in &query.labels {
            if !columns.contains(label) {
                problems.push(Problem::new(
                    place,
                    "labels",
                    format!("{label:?} isn't one of the query's columns"),
                ));
            } else if label == INSTANCE_LABEL {
                problems.push(Problem::new(place, "labels", instance_taken()));
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

    for (index, counters) in template.counters.iter().enumerate() {
        if counters
            .labels()
            .iter()
            .any(|label| label == INSTANCE_LABEL)
        {
            problems.push(Problem::new(Place::Counters(index), "", instance_taken()));
        }
    }

    let own = metrics_of(template);
    let short = |metric: &Metric| metric.name[template.key.len() + 1..].to_string();
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
    }
    // Each prefix is one source's, so a template's metrics can't be named among the
    // ones MaxNines reads itself. One with only alerts about other metrics has none.
    // An alert of one that has would be read as being about the built-in metrics, so
    // there's nothing to learn from checking the alerts until its key is another.
    let names_taken = key_is_taken(template);
    if let (true, Some((metric, _))) = (names_taken, own.first()) {
        problems.push(Problem::new(
            Place::Template,
            "key",
            format!(
                "{:?} is what metrics MaxNines has built in start with, and this template's \
                 own, such as {}, would be named among them: give it another key",
                template.key, metric.name
            ),
        ));
    }
    // `facts.os.family` and a summary's `{{ labels.slot }}` are read a part at a
    // time, so a template's metric `facts.os` would be what they found first.
    if KEYS_CONDITIONS_USE.contains(&template.key.as_str()) {
        problems.push(Problem::new(
            Place::Template,
            "key",
            format!(
                "{:?} is what conditions and summaries call something of their own, as in \
                 {}, so a template can't be called it",
                template.key,
                match template.key.as_str() {
                    "facts" => "facts.os.family",
                    _ => "{{ labels.slot }}",
                }
            ),
        ));
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

/// The keys no template can have, as conditions and summaries read names that start
/// with them a part at a time: a host's facts, and a series' labels.
pub const KEYS_CONDITIONS_USE: [&str; 2] = ["facts", "labels"];

/// Whether a template has metrics of its own under a key that the metrics MaxNines
/// has built in start with.
pub fn key_is_taken(template: &Template) -> bool {
    crate::metrics::prefixes().contains(template.key.as_str()) && !metrics_of(template).is_empty()
}

/// Why no label can be called `instance`, in any template.
fn instance_taken() -> String {
    format!(
        "a label can't be called {INSTANCE_LABEL}, which MaxNines keeps for the database a series is from"
    )
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
            "clickhouse" => Box::new(ClickHouseDialect {}),
            "mssql" | "sqlserver" => Box::new(MsSqlDialect {}),
            _ => Box::new(GenericDialect {}),
        },
        _ => Box::new(GenericDialect {}),
    }
}

/// What the field holding a template's statements is called: `command` for
/// MongoDB's and Redis', and `sql` for the rest.
pub fn statement_field(template: &Template) -> &'static str {
    match template.asked().with_commands() {
        true => "command",
        false => "sql",
    }
}

/// A command as its kind of database writes one, MongoDB's or Redis', checked.
fn check_asked_command(asked: Asked, text: &str) -> Result<(), (&'static str, String)> {
    let checked = match asked {
        Asked::Redis => redis_command(text).map(drop),
        _ => check_command(text).map(drop),
    };
    checked.map_err(|message| ("command", message))
}

/// What a discover block's statement finds, by name: its SQL's columns, or the
/// fields its MongoDB or Redis command's `columns` name. What's wrong says which
/// field.
fn discover_columns(
    template: &Template,
    discover: &maxnines_protocol::templates::Discover,
) -> Result<Vec<String>, (&'static str, String)> {
    let Some(sql) = discover.sql.as_deref() else {
        return Ok(Vec::new());
    };
    let asked = template.asked();
    if asked.with_commands() {
        check_asked_command(asked, sql)?;
        if discover.columns.is_empty() {
            return Err((
                "columns",
                "has to name what it finds in the reply, such as version = \"version\"".to_string(),
            ));
        }
        return Ok(discover.columns.keys().cloned().collect());
    }
    columns(dialect_for(template.target.as_ref()).as_ref(), sql).map_err(|message| ("sql", message))
}

/// What a template's discovery finds, by the names `when` uses: its SQL's columns
/// or MongoDB's fields, its registry values and its counter sets.
pub fn discovered_names(template: &Template) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for discover in &template.discover {
        names.extend(discover_columns(template, discover).unwrap_or_default());
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
    query_columns(template, query).unwrap_or_default()
}

/// The columns of a query, with each version's fills filled in, each once. A SHOW
/// statement's are the names its `columns` gives them, as what it gives isn't known
/// until it runs, as are a MongoDB or Redis command's. What's wrong says which
/// field.
fn query_columns(
    template: &Template,
    query: &maxnines_protocol::templates::Query,
) -> Result<Vec<String>, (&'static str, String)> {
    let asked = template.asked();
    if asked.with_commands() {
        for command in filled_sql(query) {
            check_asked_command(asked, &command)?;
        }
        if query.columns.is_empty() {
            return Err((
                "columns",
                "has to name the fields it reads from the reply, such as connections = \"connections.current\"".to_string(),
            ));
        }
        return Ok(query.columns.keys().cloned().collect());
    }
    sql_columns(dialect_for(template.target.as_ref()).as_ref(), query)
        .map_err(|message| ("sql", message))
}

fn sql_columns(
    dialect: &dyn Dialect,
    query: &maxnines_protocol::templates::Query,
) -> Result<Vec<String>, String> {
    let mut all = Vec::new();
    for sql in filled_sql(query) {
        if one_show(dialect, &sql)? {
            for name in query.columns.keys() {
                if !all.contains(name) {
                    all.push(name.clone());
                }
            }
            continue;
        }
        if !query.columns.is_empty() {
            return Err(
                "names its columns in columns, which is only for a SHOW statement: name them with AS"
                    .to_string(),
            );
        }
        for column in columns(dialect, &sql)? {
            if !all.contains(&column) {
                all.push(column);
            }
        }
    }
    Ok(all)
}

/// Whether a statement is one SHOW, which any the database takes can be, as what a
/// template may read is up to its account. Anything else has to be one SELECT,
/// which [`columns`] checks.
fn one_show(dialect: &dyn Dialect, sql: &str) -> Result<bool, String> {
    if !is_show(sql) {
        return Ok(false);
    }
    let statements =
        Parser::parse_sql(dialect, sql).map_err(|error| format!("can't be read: {error}"))?;
    match statements.as_slice() {
        [one] if one.to_string().to_ascii_uppercase().starts_with("SHOW") => Ok(true),
        _ => Err("has to be one SELECT or SHOW statement".to_string()),
    }
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

/// What a metric's `value` gives, tried on a sample of `names`, each a number:
/// true or false, or a number.
fn kind_of_value(value: &str, names: &[String]) -> Kind {
    let Ok(program) = Program::compile(value) else {
        return Kind::Number;
    };
    let mut context = CelContext::default();
    context.add_variable_from_value("value", CelValue::Float(50.0));
    for name in names {
        context.add_variable_from_value(name.as_str(), CelValue::Float(50.0));
    }
    match program.execute(&context) {
        Ok(CelValue::Bool(_)) => Kind::Flag,
        _ => Kind::Number,
    }
}

fn kind_of(
    metric: &maxnines_protocol::templates::Metric,
    column: bool,
    columns: &[String],
) -> Kind {
    if metric.unit.as_deref() == Some("s") {
        return Kind::Seconds;
    }
    if let Some(value) = &metric.value {
        return kind_of_value(value, columns);
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
        title: Option<String>,
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
            seen.title = seen.title.take().or(new.title);
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
            title: Some(format!("{} up", template.name)),
            kind: Kind::Flag,
            unit: Unit::Number,
            description: Some("Whether the database is answering".to_string()),
            total: false,
            labels: labelled(&[]),
            on: template.enabled,
        });
    }
    for query in &template.queries {
        let on = template.enabled && query.enabled;
        let columns = query_columns(template, query).unwrap_or_default();
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
                title: detail.and_then(|metric| metric.title.clone()),
                kind: detail.map_or(Kind::Unknown, |metric| kind_of(metric, column, &columns)),
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
                title: metric.title.clone(),
                kind: kind_of(metric, false, &[]),
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
                title: metric.title.unwrap_or_else(|| {
                    format!("{} {}", template.name, metric.key.replace('_', " "))
                }),
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

/// The built-in PostgreSQL template under the key `pg`, named PG, its alerts too,
/// for tests that import a template like it beside the built-in one, whose key and
/// names it would otherwise have.
#[cfg(test)]
pub fn postgres_as_pg() -> String {
    include_str!("../../templates/postgres.hcl")
        .replacen("template \"postgres\"", "template \"pg\"", 1)
        .replace("= \"PostgreSQL", "= \"PG")
}

#[cfg(test)]
mod tests;
