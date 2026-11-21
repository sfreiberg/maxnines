//! Alert rules become a warning and a critical condition, each CEL over metrics by
//! their names, instead of a kind, a metric, a comparison and thresholds.

use cel::common::ast::{Expr as Cel, IdedExpr, LiteralValue, operators};
use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

use super::{AlertRules, Alerts, column, mysql_has_column};
use crate::metrics::{self, Source, Unit};

pub(super) struct AlertConditions;

impl MigrationName for AlertConditions {
    fn name(&self) -> &str {
        "m20261120_000003_alert_conditions"
    }
}

/// What a rule said before, as it was kept.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct OldRule {
    pub kind: String,
    pub metric: Option<String>,
    pub series: Option<String>,
    pub comparison: Option<String>,
    pub threshold: Option<f64>,
    pub warning_threshold: Option<f64>,
    pub severity: String,
    pub forecast_secs: Option<i64>,
    pub warning_forecast_secs: Option<i64>,
}

/// What it says now.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct NewRule {
    pub warning: Option<String>,
    pub critical: Option<String>,
    pub summary: Option<String>,
    pub resolved_summary: Option<String>,
    /// Only a calculation keeps its metric.
    pub metric: Option<String>,
}

const OLD_COLUMNS: [&str; 9] = [
    "kind",
    "series",
    "comparison",
    "threshold",
    "warning_threshold",
    "severity",
    "forecast_secs",
    "warning_forecast_secs",
    "condition_expr",
];
const NEW_COLUMNS: [&str; 5] = [
    "warning",
    "critical",
    "summary",
    "resolved_summary",
    "applies_to",
];

/// The words the offline and no-metrics rules said before, which they keep.
const OFFLINE: (&str, &str) = ("{{ hostname }} is offline", "{{ hostname }} is back online");
const NO_METRICS: (&str, &str) = (
    "{{ hostname }} is connected but sending no metrics",
    "{{ hostname }} is sending metrics again",
);

/// Text in single quotes for CEL.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// A number as CEL reads it, without a fraction when it has none.
fn number(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

/// A number of seconds as CEL's length of time, in the largest whole unit.
fn duration(secs: f64) -> String {
    let text = if secs.fract() != 0.0 {
        format!("{}ms", (secs * 1000.0).round() as i64)
    } else {
        let secs = secs as i64;
        match secs {
            0 => "0s".to_string(),
            _ if secs % 3600 == 0 => format!("{}h", secs / 3600),
            _ if secs % 60 == 0 => format!("{}m", secs / 60),
            _ => format!("{secs}s"),
        }
    };
    format!("duration('{text}')")
}

/// A series pattern with `*` and `?` as a regular expression for `matches`.
fn pattern(glob: &str) -> String {
    let mut regex = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            c if "\\.+()|[]{}^$#&-~".contains(c) => {
                regex.push('\\');
                regex.push(c);
            }
            c => regex.push(c),
        }
    }
    regex.push('$');
    regex
}

/// The pattern back from what [`pattern`] made of it.
fn glob(regex: &str) -> Option<String> {
    let inner = regex.strip_prefix('^')?.strip_suffix('$')?;
    let mut glob = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => glob.push(chars.next()?),
            '.' if chars.peek() == Some(&'*') => {
                chars.next();
                glob.push('*');
            }
            '.' => glob.push('?'),
            c => glob.push(c),
        }
    }
    Some(glob)
}

impl OldRule {
    pub(super) fn convert(&self) -> NewRule {
        let critical = self.severity != "warning";
        let mut new = NewRule::default();
        let mut set = |main: Option<String>, warning: Option<String>| {
            if critical {
                new.critical = main;
                new.warning = warning;
            } else {
                new.warning = main;
            }
        };
        let level = |value: f64| match self.metric.as_deref().and_then(metrics::find) {
            Some(metric) if metric.unit == Unit::Seconds => duration(value),
            _ => number(value),
        };
        let above = self.comparison.as_deref() != Some("below");
        let op = if above { ">" } else { "<" };
        match self.kind.as_str() {
            "offline" => {
                set(Some("!online".to_string()), None);
                new.summary = Some(OFFLINE.0.to_string());
                new.resolved_summary = Some(OFFLINE.1.to_string());
            }
            "no_metrics" => {
                set(Some("!reporting".to_string()), None);
                new.summary = Some(NO_METRICS.0.to_string());
                new.resolved_summary = Some(NO_METRICS.1.to_string());
            }
            "calculation" => {
                let compare = |value: f64| format!("value {op} {}", level(value));
                set(
                    self.threshold.map(compare),
                    self.warning_threshold.map(compare),
                );
                new.metric = self.metric.clone();
            }
            "forecast" => {
                let op = if above { ">=" } else { "<=" };
                let (watched, only) = self.watched();
                // A forecast is of one series, so of several fixed ones, the first.
                let watched = match watched.strip_prefix('\u{0}') {
                    Some(name) => {
                        let first = match metrics::find(name).map(|metric| metric.source) {
                            Some(Source::Fields(fields)) => fields[0].0,
                            _ => "",
                        };
                        format!("{name}[{}]", quoted(first))
                    }
                    None => watched,
                };
                let goal = self.threshold.map(level).unwrap_or_default();
                let ahead = |secs: i64| {
                    let forecast =
                        format!("forecast({watched}, {}) {op} {goal}", duration(secs as f64));
                    with_series(&only, forecast)
                };
                set(
                    self.forecast_secs.map(ahead),
                    self.warning_forecast_secs.map(ahead),
                );
            }
            _ => {
                let (watched, only) = self.watched();
                let compare =
                    |value: f64| with_series(&only, format!("{watched} {op} {}", level(value)));
                set(
                    self.threshold.map(compare),
                    self.warning_threshold.map(compare),
                );
            }
        }
        new
    }

    /// How a condition names the metric, and what it says about the series first.
    fn watched(&self) -> (String, Option<String>) {
        let name = self.metric.clone().unwrap_or_default();
        let only = self.series.as_deref().map(|series| {
            if series.contains(['*', '?']) {
                format!("series.matches({})", quoted(&pattern(series)))
            } else {
                format!("series == {}", quoted(series))
            }
        });
        match metrics::find(&name).map(|metric| metric.source) {
            // A metric with several fixed series picks the one, or each, in brackets.
            Some(Source::Fields(fields)) if fields.len() > 1 => {
                let picked: Vec<&str> = fields
                    .iter()
                    .map(|(field, _)| *field)
                    .filter(|field| match self.series.as_deref() {
                        None => true,
                        Some(series) => wildmatch::WildMatch::new(series).matches(field),
                    })
                    .collect();
                let one = |field: &str| format!("{name}[{}]", quoted(field));
                match picked.as_slice() {
                    [field] => (one(field), None),
                    // A threshold compares each, and any of them crossing it is the
                    // problem, as one alert rather than one each.
                    _ => (format!("\u{0}{name}"), None),
                }
            }
            Some(Source::Fields(_)) => (name, None),
            _ => (name, only),
        }
    }
}

/// Puts what a condition says about the series before the rest.
fn with_series(only: &Option<String>, condition: String) -> String {
    // Several fixed series, compared each: `memory.usage['Memory'] > 90 || ...`.
    let condition = match condition.strip_prefix('\u{0}') {
        Some(rest) => {
            let (name, comparison) = rest.split_once(' ').unwrap_or((rest, ""));
            let fields = match metrics::find(name).map(|metric| metric.source) {
                Some(Source::Fields(fields)) => fields.iter().map(|(field, _)| *field).collect(),
                _ => Vec::new(),
            };
            fields
                .iter()
                .map(|field| format!("{name}[{}] {comparison}", quoted(field)))
                .collect::<Vec<_>>()
                .join(" || ")
        }
        None => condition,
    };
    match only {
        Some(only) => format!("{only} && {condition}"),
        None => condition,
    }
}

/// What a condition the migration made says, read back for going down. Anything
/// else can't be said the old way.
#[derive(Debug, PartialEq)]
struct Read {
    kind: &'static str,
    metric: Option<String>,
    series: Option<String>,
    above: bool,
    level: Option<f64>,
    ahead: Option<i64>,
}

fn name_of(expr: &Cel) -> Option<String> {
    match expr {
        Cel::Ident(name) => Some(name.clone()),
        Cel::Select(select) if !select.test => Some(format!(
            "{}.{}",
            name_of(&select.operand.expr)?,
            select.field
        )),
        _ => None,
    }
}

fn text_of(expr: &Cel) -> Option<String> {
    match expr {
        Cel::Literal(LiteralValue::String(text)) => Some(text.inner().to_string()),
        _ => None,
    }
}

fn call<'a>(expr: &'a IdedExpr, name: &str) -> Option<&'a [IdedExpr]> {
    match &expr.expr {
        Cel::Call(call) if call.func_name == name && call.target.is_none() => Some(&call.args),
        _ => None,
    }
}

fn level_of(expr: &IdedExpr) -> Option<f64> {
    match &expr.expr {
        Cel::Literal(LiteralValue::Int(number)) => Some(*number.inner() as f64),
        Cel::Literal(LiteralValue::UInt(number)) => Some(*number.inner() as f64),
        Cel::Literal(LiteralValue::Double(number)) => Some(*number.inner()),
        _ => {
            if let Some([inner]) = call(expr, operators::NEGATE) {
                return level_of(inner).map(|level| -level);
            }
            let [text] = call(expr, "duration")? else {
                return None;
            };
            let text = text_of(&text.expr)?;
            let secs = humantime::parse_duration(&text).ok()?;
            Some(secs.as_secs_f64())
        }
    }
}

fn read(text: &str) -> Option<Read> {
    let program = cel::Program::compile(text).ok()?;
    let expr = program.expression();
    let blank = |kind| Read {
        kind,
        metric: None,
        series: None,
        above: true,
        level: None,
        ahead: None,
    };
    if let Some([inner]) = call(expr, operators::LOGICAL_NOT) {
        return match name_of(&inner.expr)?.as_str() {
            "online" => Some(blank("offline")),
            "reporting" => Some(blank("no_metrics")),
            _ => None,
        };
    }
    // What it says about the series first, if anything.
    let (series, compared) = match call(expr, operators::LOGICAL_AND) {
        Some([only, rest]) => {
            let series = if let Some([name, value]) = call(only, operators::EQUALS) {
                (name_of(&name.expr)? == "series").then_some(())?;
                text_of(&value.expr)?
            } else {
                let Cel::Call(matches) = &only.expr else {
                    return None;
                };
                let target = matches.target.as_ref()?;
                (matches.func_name == "matches" && name_of(&target.expr)? == "series")
                    .then_some(())?;
                glob(&text_of(&matches.args.first()?.expr)?)?
            };
            (Some(series), rest)
        }
        _ => (None, expr),
    };
    // Each of several fixed series is the old rule with no series.
    let compared = match call(compared, operators::LOGICAL_OR) {
        Some([first, _]) => {
            let mut first = first;
            while let Some([left, _]) = call(first, operators::LOGICAL_OR) {
                first = left;
            }
            let read = read_comparison(first)?;
            return Some(Read {
                series: None,
                ..read
            });
        }
        _ => compared,
    };
    let read = read_comparison(compared)?;
    Some(Read {
        series: series.or(read.series.clone()),
        ..read
    })
}

fn read_comparison(expr: &IdedExpr) -> Option<Read> {
    let Cel::Call(compare) = &expr.expr else {
        return None;
    };
    let above = match compare.func_name.as_str() {
        operators::GREATER | operators::GREATER_EQUALS => true,
        operators::LESS | operators::LESS_EQUALS => false,
        _ => return None,
    };
    let [watched, level] = compare.args.as_slice() else {
        return None;
    };
    let level = level_of(level)?;
    let (watched, ahead, kind) = match call(watched, "forecast") {
        Some([metric, ahead]) => (metric, Some(level_of(ahead)? as i64), "forecast"),
        _ => (watched, None, "metric"),
    };
    let (metric, series) = match call(watched, operators::INDEX) {
        Some([metric, series]) => (name_of(&metric.expr)?, Some(text_of(&series.expr)?)),
        _ => (name_of(&watched.expr)?, None),
    };
    let kind = if metric == "value" {
        "calculation"
    } else {
        kind
    };
    Some(Read {
        kind,
        metric: (kind != "calculation").then_some(metric),
        series,
        above,
        level: Some(level),
        ahead,
    })
}

/// The old rule a new one can be said as, if it can.
pub(super) fn convert_back(new: &NewRule) -> Option<OldRule> {
    let main_text = new.critical.as_ref().or(new.warning.as_ref())?;
    let main = read(main_text)?;
    let warning = match (&new.critical, &new.warning) {
        (Some(_), Some(warning)) => Some(read(warning)?),
        _ => None,
    };
    if let Some(warning) = &warning
        && (warning.kind != main.kind
            || warning.metric != main.metric
            || warning.series != main.series
            || warning.above != main.above
            || (main.kind == "forecast" && warning.level != main.level))
    {
        return None;
    }
    let comparison = match main.kind {
        "offline" | "no_metrics" => None,
        _ => Some(if main.above { "above" } else { "below" }.to_string()),
    };
    let (threshold, warning_threshold, forecast_secs, warning_forecast_secs) = match main.kind {
        "forecast" => (
            main.level,
            None,
            main.ahead,
            warning.as_ref().and_then(|warning| warning.ahead),
        ),
        _ => (
            main.level,
            warning.as_ref().and_then(|warning| warning.level),
            None,
            None,
        ),
    };
    Some(OldRule {
        kind: main.kind.to_string(),
        metric: main.metric.or(new.metric.clone()),
        series: main.series,
        comparison,
        threshold,
        warning_threshold,
        severity: if new.critical.is_some() {
            "critical"
        } else {
            "warning"
        }
        .to_string(),
        forecast_secs,
        warning_forecast_secs,
    })
}

async fn has_columns(
    manager: &SchemaManager<'_>,
    table: &str,
    names: &[&str],
) -> Result<Vec<bool>, DbErr> {
    let db = manager.get_connection();
    let mut found = Vec::new();
    for name in names {
        found.push(match manager.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => mysql_has_column(db, table, name).await?,
            // Elsewhere a migration happens all at once or not at all.
            _ => true,
        });
    }
    Ok(found)
}

fn text_column(name: &str) -> ColumnDef {
    ColumnDef::new(Alias::new(name)).text().to_owned()
}

/// Each rule becomes conditions: `disk.usage > 90` for a threshold, `!online` for
/// a host going offline, `!reporting` for one sending no metrics, a pair of
/// `forecast()`s for a forecast, and `value > 80` for a calculation. Which hosts
/// it's for moves to `applies_to`, and only a calculation keeps a metric.
///
/// MySQL commits each change as it's made, so each can be made again.
#[async_trait::async_trait]
impl MigrationTrait for AlertConditions {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let is_mysql = manager.get_database_backend() == sea_orm::DatabaseBackend::MySql;
        for name in NEW_COLUMNS {
            if is_mysql && mysql_has_column(db, "alert_rules", name).await? {
                continue;
            }
            let add = Table::alter()
                .table(AlertRules::Table)
                .add_column(text_column(name))
                .to_owned();
            manager.alter_table(add).await?;
        }
        let old = has_columns(manager, "alert_rules", &OLD_COLUMNS).await?;
        if old.iter().all(|found| *found) {
            let rows = db
                .query_all_raw(sea_orm::Statement::from_string(
                    manager.get_database_backend(),
                    "SELECT id, kind, metric, series, comparison, threshold, warning_threshold,
                         severity, forecast_secs, warning_forecast_secs, condition_expr
                     FROM alert_rules",
                ))
                .await?;
            for row in rows {
                let id: i64 = column(&row, 0)?;
                let old = OldRule {
                    kind: column(&row, 1)?,
                    metric: column(&row, 2)?,
                    series: column(&row, 3)?,
                    comparison: column(&row, 4)?,
                    threshold: column(&row, 5)?,
                    warning_threshold: column(&row, 6)?,
                    severity: column(&row, 7)?,
                    forecast_secs: column(&row, 8)?,
                    warning_forecast_secs: column(&row, 9)?,
                };
                let applies_to: Option<String> = column(&row, 10)?;
                let new = old.convert();
                let update = Query::update()
                    .table(AlertRules::Table)
                    .values([
                        (Alias::new("warning").into_iden(), new.warning.into()),
                        (Alias::new("critical").into_iden(), new.critical.into()),
                        (Alias::new("summary").into_iden(), new.summary.into()),
                        (
                            Alias::new("resolved_summary").into_iden(),
                            new.resolved_summary.into(),
                        ),
                        (Alias::new("applies_to").into_iden(), applies_to.into()),
                        (AlertRules::Metric.into_iden(), new.metric.into()),
                    ])
                    .and_where(Expr::col(AlertRules::Id).eq(id))
                    .to_owned();
                manager.exec_stmt(update).await?;
            }
        }
        for (name, found) in OLD_COLUMNS.into_iter().zip(old) {
            if !found {
                continue;
            }
            let drop = Table::alter()
                .table(AlertRules::Table)
                .drop_column(Alias::new(name))
                .to_owned();
            manager.alter_table(drop).await?;
        }
        Ok(())
    }

    /// Each rule goes back to the kind its conditions say, if they're ones the
    /// server before this could have kept. Any other goes, with its alerts, whose
    /// notifications and action runs go with them.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let is_mysql = manager.get_database_backend() == sea_orm::DatabaseBackend::MySql;
        let old_columns = [
            ColumnDef::new(AlertRules::Kind)
                .string_len(16)
                .not_null()
                .default("metric")
                .to_owned(),
            ColumnDef::new(AlertRules::Series)
                .string_len(255)
                .to_owned(),
            ColumnDef::new(AlertRules::Comparison)
                .string_len(16)
                .to_owned(),
            ColumnDef::new(AlertRules::Threshold).double().to_owned(),
            ColumnDef::new(AlertRules::WarningThreshold)
                .double()
                .to_owned(),
            ColumnDef::new(AlertRules::Severity)
                .string_len(16)
                .not_null()
                .default("critical")
                .to_owned(),
            ColumnDef::new(AlertRules::ForecastSecs)
                .big_integer()
                .to_owned(),
            ColumnDef::new(AlertRules::WarningForecastSecs)
                .big_integer()
                .to_owned(),
            ColumnDef::new(AlertRules::ConditionExpr).text().to_owned(),
        ];
        for mut column in old_columns {
            let name = column.get_column_name();
            if is_mysql && mysql_has_column(db, "alert_rules", &name).await? {
                continue;
            }
            let add = Table::alter()
                .table(AlertRules::Table)
                .add_column(&mut column)
                .to_owned();
            manager.alter_table(add).await?;
        }
        let new = has_columns(manager, "alert_rules", &NEW_COLUMNS).await?;
        if new.iter().all(|found| *found) {
            let rows = db
                .query_all_raw(sea_orm::Statement::from_string(
                    manager.get_database_backend(),
                    "SELECT id, warning, critical, metric, applies_to FROM alert_rules",
                ))
                .await?;
            for row in rows {
                let id: i64 = column(&row, 0)?;
                let new = NewRule {
                    warning: column(&row, 1)?,
                    critical: column(&row, 2)?,
                    metric: column(&row, 3)?,
                    ..NewRule::default()
                };
                let applies_to: Option<String> = column(&row, 4)?;
                let Some(old) = convert_back(&new) else {
                    let alerts = Query::delete()
                        .from_table(Alerts::Table)
                        .and_where(Expr::col(Alerts::RuleId).eq(id))
                        .to_owned();
                    manager.exec_stmt(alerts).await?;
                    let rule = Query::delete()
                        .from_table(AlertRules::Table)
                        .and_where(Expr::col(AlertRules::Id).eq(id))
                        .to_owned();
                    manager.exec_stmt(rule).await?;
                    continue;
                };
                let update = Query::update()
                    .table(AlertRules::Table)
                    .values([
                        (AlertRules::Kind.into_iden(), old.kind.into()),
                        (AlertRules::Metric.into_iden(), old.metric.into()),
                        (AlertRules::Series.into_iden(), old.series.into()),
                        (AlertRules::Comparison.into_iden(), old.comparison.into()),
                        (AlertRules::Threshold.into_iden(), old.threshold.into()),
                        (
                            AlertRules::WarningThreshold.into_iden(),
                            old.warning_threshold.into(),
                        ),
                        (AlertRules::Severity.into_iden(), old.severity.into()),
                        (
                            AlertRules::ForecastSecs.into_iden(),
                            old.forecast_secs.into(),
                        ),
                        (
                            AlertRules::WarningForecastSecs.into_iden(),
                            old.warning_forecast_secs.into(),
                        ),
                        (AlertRules::ConditionExpr.into_iden(), applies_to.into()),
                    ])
                    .and_where(Expr::col(AlertRules::Id).eq(id))
                    .to_owned();
                manager.exec_stmt(update).await?;
            }
        }
        for (name, found) in NEW_COLUMNS.into_iter().zip(new) {
            if !found {
                continue;
            }
            let drop = Table::alter()
                .table(AlertRules::Table)
                .drop_column(Alias::new(name))
                .to_owned();
            manager.alter_table(drop).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn old(kind: &str, metric: Option<&str>, comparison: &str, threshold: f64) -> OldRule {
        OldRule {
            kind: kind.to_string(),
            metric: metric.map(str::to_string),
            comparison: Some(comparison.to_string()),
            threshold: Some(threshold),
            severity: "critical".to_string(),
            ..OldRule::default()
        }
    }

    fn agent(kind: &str, severity: &str) -> OldRule {
        OldRule {
            kind: kind.to_string(),
            severity: severity.to_string(),
            ..OldRule::default()
        }
    }

    /// Every kind of rule, as the migration says it, and back.
    #[test]
    fn each_kind_of_rule_becomes_conditions_and_back() {
        let cases: Vec<(OldRule, Option<&str>, Option<&str>)> = vec![
            (
                OldRule {
                    warning_threshold: Some(80.0),
                    ..old("metric", Some("disk.usage"), "above", 90.0)
                },
                Some("disk.usage > 80"),
                Some("disk.usage > 90"),
            ),
            (
                OldRule {
                    severity: "warning".to_string(),
                    ..old("metric", Some("cpu.usage"), "above", 95.5)
                },
                Some("cpu.usage > 95.5"),
                None,
            ),
            (
                old("metric", Some("service.running"), "below", 1.0),
                None,
                Some("service.running < 1"),
            ),
            (
                OldRule {
                    warning_threshold: Some(5.0),
                    ..old("metric", Some("clock.difference"), "above", 30.0)
                },
                Some("clock.difference > duration('5s')"),
                Some("clock.difference > duration('30s')"),
            ),
            (
                OldRule {
                    series: Some("/data".to_string()),
                    ..old("metric", Some("disk.usage"), "above", 90.0)
                },
                None,
                Some("series == '/data' && disk.usage > 90"),
            ),
            (
                OldRule {
                    series: Some("/data*".to_string()),
                    ..old("metric", Some("disk.usage"), "above", 90.0)
                },
                None,
                Some("series.matches('^/data.*$') && disk.usage > 90"),
            ),
            (
                OldRule {
                    series: Some("5 minutes".to_string()),
                    ..old("metric", Some("cpu.load"), "above", 4.0)
                },
                None,
                Some("cpu.load['5 minutes'] > 4"),
            ),
            (
                old("metric", Some("memory.usage"), "above", 90.0),
                None,
                Some("memory.usage['Memory'] > 90 || memory.usage['Swap'] > 90"),
            ),
            (
                OldRule {
                    forecast_secs: Some(14_400),
                    warning_forecast_secs: Some(86_400),
                    ..old("forecast", Some("disk.usage"), "above", 100.0)
                },
                Some("forecast(disk.usage, duration('24h')) >= 100"),
                Some("forecast(disk.usage, duration('4h')) >= 100"),
            ),
            (
                OldRule {
                    forecast_secs: Some(90),
                    severity: "warning".to_string(),
                    series: Some("/".to_string()),
                    ..old("forecast", Some("disk.usage"), "below", 5.0)
                },
                Some("series == '/' && forecast(disk.usage, duration('90s')) <= 5"),
                None,
            ),
            (
                OldRule {
                    warning_threshold: Some(-2.0),
                    ..old("calculation", Some("cpu.usage"), "below", -5.0)
                },
                Some("value < -2"),
                Some("value < -5"),
            ),
            (agent("offline", "critical"), None, Some("!online")),
            (agent("no_metrics", "warning"), Some("!reporting"), None),
        ];
        for (old, warning, critical) in cases {
            let new = old.convert();
            assert_eq!(new.warning.as_deref(), warning, "{old:?}");
            assert_eq!(new.critical.as_deref(), critical, "{old:?}");
            assert_eq!(new.metric.is_some(), old.kind == "calculation", "{old:?}");
            // Each is a rule this server can keep.
            let scope = match old.kind.as_str() {
                "calculation" => crate::alert_conditions::Scope::Calculation,
                _ => crate::alert_conditions::Scope::Hosts,
            };
            crate::alert_conditions::Conditions::compile(
                new.warning.as_deref(),
                new.critical.as_deref(),
                scope,
            )
            .unwrap()
            .dry_run(&serde_json::Value::Null, crate::metrics::Unit::Number)
            .unwrap_or_else(|error| panic!("{old:?}: {error:#}"));
            // And can be said the old way again, though several fixed series watched
            // each come back as the one rule they became.
            let back = convert_back(&new).unwrap();
            let expected = OldRule {
                metric: old.metric.clone(),
                comparison: match old.kind.as_str() {
                    "offline" | "no_metrics" => None,
                    _ => old.comparison.clone(),
                },
                ..old.clone()
            };
            assert_eq!(back, expected);
        }
        assert_eq!(
            agent("offline", "critical").convert().summary.as_deref(),
            Some(OFFLINE.0)
        );
    }

    #[test]
    fn conditions_the_old_rules_could_not_say_have_no_way_back() {
        for (warning, critical) in [
            (None, Some("disk.usage > 90 && disk.inodes > 90")),
            (Some("cpu.usage > 80"), Some("disk.usage > 90")),
            (None, Some("facts.os.family == 'linux'")),
        ] {
            let new = NewRule {
                warning: warning.map(str::to_string),
                critical: critical.map(str::to_string),
                ..NewRule::default()
            };
            assert_eq!(convert_back(&new), None, "{critical:?}");
        }
    }

    #[test]
    fn a_series_pattern_survives_becoming_a_regular_expression() {
        for glob_text in ["/data*", "eth?", "C:\\", "a.b+c", "x's"] {
            assert_eq!(glob(&pattern(glob_text)).as_deref(), Some(glob_text));
            assert!(
                regex_matches(&pattern(glob_text), &glob_text.replace(['*', '?'], "z")),
                "{glob_text}"
            );
        }
    }

    fn regex_matches(regex: &str, text: &str) -> bool {
        let condition = format!("{}.matches({})", quoted(text), quoted(regex));
        cel::Program::compile(&condition)
            .unwrap()
            .execute(&cel::Context::default())
            == Ok(cel::Value::Bool(true))
    }
}
