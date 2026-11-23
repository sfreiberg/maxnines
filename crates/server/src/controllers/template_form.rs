//! A template as its form shows it: a field for each part, with blocks that repeat,
//! such as queries and alerts, as rows that can be added and removed. The form reads
//! and writes the same [`Template`] the HCL does, and is checked the same way, with
//! each problem shown beside the field it's about.

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde::Serialize;

use maxnines_protocol::templates::{
    Alert, Counters, Discover, Fill, Join, Metric, Notice, OPERATING_SYSTEMS, Place, Problem,
    Query, RegistryRead, Target, Template,
};

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TemplateForm {
    pub key: String,
    pub name: String,
    pub description: String,
    /// `database`, `service`, `os`, or empty for every host.
    pub target: String,
    pub database: String,
    pub service: String,
    pub os: Vec<String>,
    /// CEL over a host's facts saying which hosts it's for, or empty for all.
    pub applies_to: String,
    pub min_version: String,
    /// Comma separated.
    pub renamed_from: String,
    /// Comma separated.
    pub services: String,
    pub enabled: bool,
    pub discover: Vec<DiscoverForm>,
    pub notices: Vec<NoticeForm>,
    pub queries: Vec<QueryForm>,
    pub counters: Vec<CountersForm>,
    pub alerts: Vec<AlertForm>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DiscoverForm {
    pub key: String,
    pub interval: String,
    pub sql: String,
    /// `name = Counter set` on each line.
    pub counter_sets: String,
    pub registry: Vec<RegistryForm>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RegistryForm {
    pub key: String,
    /// `name = Value name` on each line.
    pub values: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct NoticeForm {
    pub key: String,
    pub when: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct QueryForm {
    pub key: String,
    pub sql: String,
    pub interval: String,
    pub since: String,
    pub when: String,
    pub enabled: bool,
    /// Comma separated.
    pub labels: String,
    pub fills: Vec<FillForm>,
    pub metrics: Vec<MetricForm>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct FillForm {
    pub key: String,
    pub versions: Vec<VersionForm>,
    pub older: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct VersionForm {
    pub from: String,
    pub sql: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MetricForm {
    pub key: String,
    pub counter: String,
    pub unit: String,
    pub total: bool,
    pub description: String,
    pub value: String,
    pub since: String,
    /// `number = Word` on each line.
    pub states: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CountersForm {
    pub key: String,
    pub object: String,
    pub label: String,
    pub pattern: String,
    pub instance: String,
    /// One on each line.
    pub exclude: String,
    /// `group = Counter` on each line.
    pub groups: String,
    pub join_object: String,
    pub join_pattern: String,
    pub when: String,
    pub since: String,
    pub interval: String,
    pub enabled: bool,
    pub metrics: Vec<MetricForm>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AlertForm {
    pub key: String,
    pub name: String,
    pub warning: String,
    pub critical: String,
    /// What HCL calls `for`.
    pub hold: String,
    pub window: String,
    pub summary: String,
    pub resolved_summary: String,
    pub when: String,
    pub since: String,
    pub enabled: bool,
}

fn text(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn optional(value: &str) -> Option<String> {
    crate::text::trimmed(value)
}

/// A long text kept as typed, but for the line endings browsers send, and nothing at
/// all when there's nothing in it.
fn long_text(value: &str) -> Option<String> {
    let value = value.replace("\r\n", "\n");
    (!value.trim().is_empty()).then_some(value)
}

fn comma_list(values: &[String]) -> String {
    values.join(", ")
}

fn from_comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn lines(values: &[String]) -> String {
    values.join("\n")
}

fn from_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn pairs(values: &IndexMap<String, String>) -> String {
    let lines: Vec<String> = values
        .iter()
        .map(|(name, value)| format!("{name} = {value}"))
        .collect();
    lines.join("\n")
}

/// `name = value` on each line, or what's wrong with a line.
fn from_pairs(value: &str) -> Result<IndexMap<String, String>, String> {
    let mut map = IndexMap::new();
    for (number, line) in value.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("line {} needs a name, = and a value", number + 1));
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() || value.is_empty() {
            return Err(format!("line {} needs a name, = and a value", number + 1));
        }
        if map.insert(name.to_string(), value.to_string()).is_some() {
            return Err(format!("{name:?} is given twice"));
        }
    }
    Ok(map)
}

impl MetricForm {
    fn new(metric: &Metric) -> Self {
        Self {
            key: metric.key.clone(),
            counter: text(&metric.counter),
            unit: text(&metric.unit),
            total: metric.total,
            description: text(&metric.description),
            value: text(&metric.value),
            since: text(&metric.since),
            states: pairs(&metric.states),
        }
    }

    fn to_metric(&self, place: Place, problems: &mut Vec<Problem>) -> Metric {
        let states = from_pairs(&self.states).unwrap_or_else(|message| {
            problems.push(Problem::new(place, "states", message));
            IndexMap::new()
        });
        Metric {
            key: self.key.trim().to_string(),
            counter: optional(&self.counter),
            unit: optional(&self.unit),
            total: self.total,
            description: optional(&self.description),
            value: optional(&self.value),
            since: optional(&self.since),
            states,
        }
    }
}

impl TemplateForm {
    /// A new template's form: one that's on, with nothing in it yet.
    pub fn blank() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    pub fn from_template(template: &Template) -> Self {
        let (target, database, service, os) = match &template.target {
            None => ("", String::new(), String::new(), Vec::new()),
            Some(Target::Database(kind)) => ("database", kind.clone(), String::new(), Vec::new()),
            Some(Target::Service(name)) => ("service", String::new(), name.clone(), Vec::new()),
            Some(Target::Os(systems)) => ("os", String::new(), String::new(), systems.clone()),
        };
        let discover = template
            .discover
            .iter()
            .map(|d| DiscoverForm {
                key: d.key.clone(),
                interval: text(&d.interval),
                sql: text(&d.sql),
                counter_sets: pairs(&d.counter_sets),
                registry: d
                    .registry
                    .iter()
                    .map(|read| RegistryForm {
                        key: read.key.clone(),
                        values: pairs(&read.values),
                    })
                    .collect(),
            })
            .collect();
        Self {
            key: template.key.clone(),
            name: template.name.clone(),
            description: text(&template.description),
            target: target.to_string(),
            database,
            service,
            os,
            applies_to: text(&template.applies_to),
            min_version: text(&template.min_version),
            renamed_from: comma_list(&template.renamed_from),
            services: comma_list(&template.services),
            enabled: template.enabled,
            discover,
            notices: template
                .notices
                .iter()
                .map(|notice| NoticeForm {
                    key: notice.key.clone(),
                    when: text(&notice.when),
                    text: notice.text.clone(),
                })
                .collect(),
            queries: template
                .queries
                .iter()
                .map(|query| QueryForm {
                    key: query.key.clone(),
                    sql: query.sql.clone(),
                    interval: text(&query.interval),
                    since: text(&query.since),
                    when: text(&query.when),
                    enabled: query.enabled,
                    labels: comma_list(&query.labels),
                    fills: query
                        .fills
                        .iter()
                        .map(|fill| FillForm {
                            key: fill.key.clone(),
                            versions: fill
                                .versions
                                .iter()
                                .map(|(from, sql)| VersionForm {
                                    from: from.clone(),
                                    sql: sql.clone(),
                                })
                                .collect(),
                            older: text(&fill.older),
                        })
                        .collect(),
                    metrics: query.metrics.iter().map(MetricForm::new).collect(),
                })
                .collect(),
            counters: template
                .counters
                .iter()
                .map(|counters| CountersForm {
                    key: counters.key.clone(),
                    object: counters.object.clone(),
                    label: text(&counters.label),
                    pattern: text(&counters.pattern),
                    instance: text(&counters.instance),
                    exclude: lines(&counters.exclude),
                    groups: pairs(&counters.groups),
                    join_object: counters
                        .join
                        .as_ref()
                        .map_or_else(String::new, |join| join.object.clone()),
                    join_pattern: counters
                        .join
                        .as_ref()
                        .map_or_else(String::new, |join| join.pattern.clone()),
                    when: text(&counters.when),
                    since: text(&counters.since),
                    interval: text(&counters.interval),
                    enabled: counters.enabled,
                    metrics: counters.metrics.iter().map(MetricForm::new).collect(),
                })
                .collect(),
            alerts: template
                .alerts
                .iter()
                .map(|alert| AlertForm {
                    key: alert.key.clone(),
                    name: alert.name.clone(),
                    warning: text(&alert.warning),
                    critical: text(&alert.critical),
                    hold: text(&alert.hold),
                    window: text(&alert.window),
                    summary: text(&alert.summary),
                    resolved_summary: text(&alert.resolved_summary),
                    when: text(&alert.when),
                    since: text(&alert.since),
                    enabled: alert.enabled,
                })
                .collect(),
        }
    }

    /// The template the form says, and what's wrong with what was typed in a way that
    /// stops it being read, such as a line of `name = value` without the `=`.
    pub fn to_template(&self) -> (Template, Vec<Problem>) {
        let mut problems = Vec::new();
        let target = match self.target.as_str() {
            "database" => Some(Target::Database(self.database.trim().to_string())),
            "service" => Some(Target::Service(self.service.trim().to_string())),
            "os" => Some(Target::Os(self.os.clone())),
            _ => None,
        };
        let discover = self
            .discover
            .iter()
            .enumerate()
            .map(|(index, form)| {
                let place = Place::Discover(index);
                let counter_sets = from_pairs(&form.counter_sets).unwrap_or_else(|message| {
                    problems.push(Problem::new(place, "counter_sets", message));
                    IndexMap::new()
                });
                let registry = form
                    .registry
                    .iter()
                    .map(|read| RegistryRead {
                        key: read.key.trim().to_string(),
                        values: from_pairs(&read.values).unwrap_or_else(|message| {
                            problems.push(Problem::new(place, "registry", message));
                            IndexMap::new()
                        }),
                    })
                    .collect();
                Discover {
                    key: form.key.trim().to_string(),
                    interval: optional(&form.interval),
                    sql: long_text(&form.sql),
                    registry,
                    counter_sets,
                }
            })
            .collect();
        let notices = self
            .notices
            .iter()
            .map(|notice| Notice {
                key: notice.key.trim().to_string(),
                when: optional(&notice.when),
                text: notice.text.trim().to_string(),
            })
            .collect();
        let queries = self
            .queries
            .iter()
            .enumerate()
            .map(|(index, query)| Query {
                key: query.key.trim().to_string(),
                sql: long_text(&query.sql).unwrap_or_default(),
                interval: optional(&query.interval),
                since: optional(&query.since),
                when: optional(&query.when),
                enabled: query.enabled,
                labels: from_comma_list(&query.labels),
                fills: query
                    .fills
                    .iter()
                    .map(|fill| Fill {
                        key: fill.key.trim().to_string(),
                        versions: fill
                            .versions
                            .iter()
                            .map(|version| {
                                (
                                    version.from.trim().to_string(),
                                    long_text(&version.sql).unwrap_or_default(),
                                )
                            })
                            .collect(),
                        older: long_text(&fill.older),
                    })
                    .collect(),
                metrics: query
                    .metrics
                    .iter()
                    .enumerate()
                    .map(|(number, metric)| {
                        metric.to_metric(Place::QueryMetric(index, number), &mut problems)
                    })
                    .collect(),
            })
            .collect();
        let counters = self
            .counters
            .iter()
            .enumerate()
            .map(|(index, counters)| {
                let groups = from_pairs(&counters.groups).unwrap_or_else(|message| {
                    problems.push(Problem::new(Place::Counters(index), "groups", message));
                    IndexMap::new()
                });
                let join = (!counters.join_object.trim().is_empty()
                    || !counters.join_pattern.trim().is_empty())
                .then(|| Join {
                    object: counters.join_object.trim().to_string(),
                    pattern: counters.join_pattern.trim().to_string(),
                });
                Counters {
                    key: counters.key.trim().to_string(),
                    object: counters.object.trim().to_string(),
                    label: optional(&counters.label),
                    pattern: optional(&counters.pattern),
                    instance: optional(&counters.instance),
                    exclude: from_lines(&counters.exclude),
                    groups,
                    join,
                    when: optional(&counters.when),
                    since: optional(&counters.since),
                    interval: optional(&counters.interval),
                    enabled: counters.enabled,
                    metrics: counters
                        .metrics
                        .iter()
                        .enumerate()
                        .map(|(number, metric)| {
                            metric.to_metric(Place::CountersMetric(index, number), &mut problems)
                        })
                        .collect(),
                }
            })
            .collect();
        let alerts = self
            .alerts
            .iter()
            .map(|alert| Alert {
                key: alert.key.trim().to_string(),
                name: alert.name.trim().to_string(),
                warning: optional(&alert.warning),
                critical: optional(&alert.critical),
                hold: optional(&alert.hold),
                window: optional(&alert.window),
                summary: optional(&alert.summary),
                resolved_summary: optional(&alert.resolved_summary),
                when: optional(&alert.when),
                since: optional(&alert.since),
                enabled: alert.enabled,
            })
            .collect();
        let template = Template {
            key: self.key.trim().to_string(),
            name: self.name.trim().to_string(),
            description: optional(&self.description),
            target,
            applies_to: optional(&self.applies_to),
            min_version: optional(&self.min_version),
            renamed_from: from_comma_list(&self.renamed_from),
            enabled: self.enabled,
            services: from_comma_list(&self.services),
            discover,
            notices,
            queries,
            counters,
            alerts,
        };
        (template, problems)
    }

    /// Reads the form as a browser sends it: `query.0.sql`, `alert.2.for` and such.
    pub fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let get = |name: &str| fields.get(name).cloned().unwrap_or_default();
        let on = |name: &str| fields.contains_key(name);
        let rows = |prefix: &str| -> usize {
            fields
                .keys()
                .filter_map(|name| {
                    let rest = name.strip_prefix(prefix)?;
                    let (number, _) = rest.split_once('.')?;
                    number.parse::<usize>().ok()
                })
                .max()
                .map_or(0, |last| last + 1)
        };
        let metric = |prefix: &str| MetricForm {
            key: get(&format!("{prefix}key")),
            counter: get(&format!("{prefix}counter")),
            unit: get(&format!("{prefix}unit")),
            total: on(&format!("{prefix}total")),
            description: get(&format!("{prefix}description")),
            value: get(&format!("{prefix}value")),
            since: get(&format!("{prefix}since")),
            states: get(&format!("{prefix}states")),
        };
        Self {
            key: get("key"),
            name: get("name"),
            description: get("description"),
            target: get("target"),
            database: get("database"),
            service: get("service"),
            os: OPERATING_SYSTEMS
                .iter()
                .filter(|system| on(&format!("os.{system}")))
                .map(|system| system.to_string())
                .collect(),
            applies_to: get("applies_to"),
            min_version: get("min_version"),
            renamed_from: get("renamed_from"),
            services: get("services"),
            enabled: on("enabled"),
            discover: (0..rows("discover."))
                .map(|index| {
                    let prefix = format!("discover.{index}.");
                    DiscoverForm {
                        key: get(&format!("{prefix}key")),
                        interval: get(&format!("{prefix}interval")),
                        sql: get(&format!("{prefix}sql")),
                        counter_sets: get(&format!("{prefix}counter_sets")),
                        registry: (0..rows(&format!("{prefix}registry.")))
                            .map(|number| RegistryForm {
                                key: get(&format!("{prefix}registry.{number}.key")),
                                values: get(&format!("{prefix}registry.{number}.values")),
                            })
                            .collect(),
                    }
                })
                .collect(),
            notices: (0..rows("notice."))
                .map(|index| NoticeForm {
                    key: get(&format!("notice.{index}.key")),
                    when: get(&format!("notice.{index}.when")),
                    text: get(&format!("notice.{index}.text")),
                })
                .collect(),
            queries: (0..rows("query."))
                .map(|index| {
                    let prefix = format!("query.{index}.");
                    QueryForm {
                        key: get(&format!("{prefix}key")),
                        sql: get(&format!("{prefix}sql")),
                        interval: get(&format!("{prefix}interval")),
                        since: get(&format!("{prefix}since")),
                        when: get(&format!("{prefix}when")),
                        enabled: on(&format!("{prefix}enabled")),
                        labels: get(&format!("{prefix}labels")),
                        fills: (0..rows(&format!("{prefix}fill.")))
                            .map(|fill| {
                                let prefix = format!("{prefix}fill.{fill}.");
                                FillForm {
                                    key: get(&format!("{prefix}key")),
                                    versions: (0..rows(&format!("{prefix}version.")))
                                        .map(|version| VersionForm {
                                            from: get(&format!("{prefix}version.{version}.from")),
                                            sql: get(&format!("{prefix}version.{version}.sql")),
                                        })
                                        .collect(),
                                    older: get(&format!("{prefix}older")),
                                }
                            })
                            .collect(),
                        metrics: (0..rows(&format!("{prefix}metric.")))
                            .map(|number| metric(&format!("{prefix}metric.{number}.")))
                            .collect(),
                    }
                })
                .collect(),
            counters: (0..rows("counters."))
                .map(|index| {
                    let prefix = format!("counters.{index}.");
                    CountersForm {
                        key: get(&format!("{prefix}key")),
                        object: get(&format!("{prefix}object")),
                        label: get(&format!("{prefix}label")),
                        pattern: get(&format!("{prefix}pattern")),
                        instance: get(&format!("{prefix}instance")),
                        exclude: get(&format!("{prefix}exclude")),
                        groups: get(&format!("{prefix}groups")),
                        join_object: get(&format!("{prefix}join.object")),
                        join_pattern: get(&format!("{prefix}join.pattern")),
                        when: get(&format!("{prefix}when")),
                        since: get(&format!("{prefix}since")),
                        interval: get(&format!("{prefix}interval")),
                        enabled: on(&format!("{prefix}enabled")),
                        metrics: (0..rows(&format!("{prefix}metric.")))
                            .map(|number| metric(&format!("{prefix}metric.{number}.")))
                            .collect(),
                    }
                })
                .collect(),
            alerts: (0..rows("alert."))
                .map(|index| {
                    let prefix = format!("alert.{index}.");
                    AlertForm {
                        key: get(&format!("{prefix}key")),
                        name: get(&format!("{prefix}name")),
                        warning: get(&format!("{prefix}warning")),
                        critical: get(&format!("{prefix}critical")),
                        hold: get(&format!("{prefix}for")),
                        window: get(&format!("{prefix}window")),
                        summary: get(&format!("{prefix}summary")),
                        resolved_summary: get(&format!("{prefix}resolved_summary")),
                        when: get(&format!("{prefix}when")),
                        since: get(&format!("{prefix}since")),
                        enabled: on(&format!("{prefix}enabled")),
                    }
                })
                .collect(),
        }
    }

    /// Adds or removes a row, as one of the form's buttons asks: `add:query`,
    /// `remove:query.1`, `add:query.1.metric`, `remove:query.1.fill.0.version.2`
    /// and so on. False for anything else, which isn't a button of this form.
    pub fn apply_action(&mut self, action: &str) -> bool {
        let (verb, path) = match action.split_once(':') {
            Some(("add", path)) => (true, path),
            Some(("remove", path)) => (false, path),
            _ => return false,
        };
        let parts: Vec<&str> = path.split('.').collect();
        let number = |text: &str| text.parse::<usize>().ok();
        fn change<T: Default>(rows: &mut Vec<T>, add: bool, at: Option<usize>) -> bool {
            match (add, at) {
                (true, None) => {
                    rows.push(T::default());
                    true
                }
                (false, Some(at)) if at < rows.len() => {
                    rows.remove(at);
                    true
                }
                _ => false,
            }
        }
        match parts.as_slice() {
            ["discover"] | ["discover", _] => change(
                &mut self.discover,
                verb,
                parts.get(1).and_then(|p| number(p)),
            ),
            ["discover", at, "registry", rest @ ..] => {
                let Some(discover) = number(at).and_then(|at| self.discover.get_mut(at)) else {
                    return false;
                };
                change(
                    &mut discover.registry,
                    verb,
                    rest.first().and_then(|p| number(p)),
                )
            }
            ["notice"] | ["notice", _] => change(
                &mut self.notices,
                verb,
                parts.get(1).and_then(|p| number(p)),
            ),
            ["query"] => {
                self.queries.push(QueryForm {
                    enabled: true,
                    ..QueryForm::default()
                });
                verb
            }
            ["query", at] => change(&mut self.queries, verb, number(at)),
            ["query", at, "metric", rest @ ..] => {
                let Some(query) = number(at).and_then(|at| self.queries.get_mut(at)) else {
                    return false;
                };
                change(
                    &mut query.metrics,
                    verb,
                    rest.first().and_then(|p| number(p)),
                )
            }
            ["query", at, "fill"] | ["query", at, "fill", _] => {
                let Some(query) = number(at).and_then(|at| self.queries.get_mut(at)) else {
                    return false;
                };
                change(&mut query.fills, verb, parts.get(3).and_then(|p| number(p)))
            }
            ["query", at, "fill", fill, "version", rest @ ..] => {
                let fill = number(at)
                    .and_then(|at| self.queries.get_mut(at))
                    .and_then(|query| number(fill).and_then(|fill| query.fills.get_mut(fill)));
                let Some(fill) = fill else {
                    return false;
                };
                change(
                    &mut fill.versions,
                    verb,
                    rest.first().and_then(|p| number(p)),
                )
            }
            ["counters"] => {
                self.counters.push(CountersForm {
                    enabled: true,
                    ..CountersForm::default()
                });
                verb
            }
            ["counters", at] => change(&mut self.counters, verb, number(at)),
            ["counters", at, "metric", rest @ ..] => {
                let Some(counters) = number(at).and_then(|at| self.counters.get_mut(at)) else {
                    return false;
                };
                change(
                    &mut counters.metrics,
                    verb,
                    rest.first().and_then(|p| number(p)),
                )
            }
            ["alert"] => {
                self.alerts.push(AlertForm {
                    enabled: true,
                    ..AlertForm::default()
                });
                verb
            }
            ["alert", at] => change(&mut self.alerts, verb, number(at)),
            _ => false,
        }
    }

    /// The form as a browser would send it back, for tests to fill in.
    #[cfg(test)]
    pub fn to_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        let mut put = |name: String, value: &str| {
            fields.insert(name, value.to_string());
        };
        let tick = |on: bool| on.then_some("on");
        put("key".into(), &self.key);
        put("name".into(), &self.name);
        put("description".into(), &self.description);
        put("target".into(), &self.target);
        put("database".into(), &self.database);
        put("service".into(), &self.service);
        for system in &self.os {
            put(format!("os.{system}"), "on");
        }
        put("applies_to".into(), &self.applies_to);
        put("min_version".into(), &self.min_version);
        put("renamed_from".into(), &self.renamed_from);
        put("services".into(), &self.services);
        if let Some(on) = tick(self.enabled) {
            put("enabled".into(), on);
        }
        for (index, discover) in self.discover.iter().enumerate() {
            let prefix = format!("discover.{index}.");
            put(format!("{prefix}key"), &discover.key);
            put(format!("{prefix}interval"), &discover.interval);
            put(format!("{prefix}sql"), &discover.sql);
            put(format!("{prefix}counter_sets"), &discover.counter_sets);
            for (number, read) in discover.registry.iter().enumerate() {
                put(format!("{prefix}registry.{number}.key"), &read.key);
                put(format!("{prefix}registry.{number}.values"), &read.values);
            }
        }
        for (index, notice) in self.notices.iter().enumerate() {
            put(format!("notice.{index}.key"), &notice.key);
            put(format!("notice.{index}.when"), &notice.when);
            put(format!("notice.{index}.text"), &notice.text);
        }
        let metric = |prefix: String, metric: &MetricForm, put: &mut dyn FnMut(String, &str)| {
            put(format!("{prefix}key"), &metric.key);
            put(format!("{prefix}counter"), &metric.counter);
            put(format!("{prefix}unit"), &metric.unit);
            if metric.total {
                put(format!("{prefix}total"), "on");
            }
            put(format!("{prefix}description"), &metric.description);
            put(format!("{prefix}value"), &metric.value);
            put(format!("{prefix}since"), &metric.since);
            put(format!("{prefix}states"), &metric.states);
        };
        for (index, query) in self.queries.iter().enumerate() {
            let prefix = format!("query.{index}.");
            put(format!("{prefix}key"), &query.key);
            put(format!("{prefix}sql"), &query.sql);
            put(format!("{prefix}interval"), &query.interval);
            put(format!("{prefix}since"), &query.since);
            put(format!("{prefix}when"), &query.when);
            if query.enabled {
                put(format!("{prefix}enabled"), "on");
            }
            put(format!("{prefix}labels"), &query.labels);
            for (number, fill) in query.fills.iter().enumerate() {
                let prefix = format!("{prefix}fill.{number}.");
                put(format!("{prefix}key"), &fill.key);
                put(format!("{prefix}older"), &fill.older);
                for (version, at) in fill.versions.iter().enumerate() {
                    put(format!("{prefix}version.{version}.from"), &at.from);
                    put(format!("{prefix}version.{version}.sql"), &at.sql);
                }
            }
            for (number, each) in query.metrics.iter().enumerate() {
                metric(format!("{prefix}metric.{number}."), each, &mut put);
            }
        }
        for (index, counters) in self.counters.iter().enumerate() {
            let prefix = format!("counters.{index}.");
            put(format!("{prefix}key"), &counters.key);
            put(format!("{prefix}object"), &counters.object);
            put(format!("{prefix}label"), &counters.label);
            put(format!("{prefix}pattern"), &counters.pattern);
            put(format!("{prefix}instance"), &counters.instance);
            put(format!("{prefix}exclude"), &counters.exclude);
            put(format!("{prefix}groups"), &counters.groups);
            put(format!("{prefix}join.object"), &counters.join_object);
            put(format!("{prefix}join.pattern"), &counters.join_pattern);
            put(format!("{prefix}when"), &counters.when);
            put(format!("{prefix}since"), &counters.since);
            put(format!("{prefix}interval"), &counters.interval);
            if counters.enabled {
                put(format!("{prefix}enabled"), "on");
            }
            for (number, each) in counters.metrics.iter().enumerate() {
                metric(format!("{prefix}metric.{number}."), each, &mut put);
            }
        }
        for (index, alert) in self.alerts.iter().enumerate() {
            let prefix = format!("alert.{index}.");
            put(format!("{prefix}key"), &alert.key);
            put(format!("{prefix}name"), &alert.name);
            put(format!("{prefix}warning"), &alert.warning);
            put(format!("{prefix}critical"), &alert.critical);
            put(format!("{prefix}for"), &alert.hold);
            put(format!("{prefix}window"), &alert.window);
            put(format!("{prefix}summary"), &alert.summary);
            put(format!("{prefix}resolved_summary"), &alert.resolved_summary);
            put(format!("{prefix}when"), &alert.when);
            put(format!("{prefix}since"), &alert.since);
            if alert.enabled {
                put(format!("{prefix}enabled"), "on");
            }
        }
        fields
    }
}

/// Each problem by the form field it's about, for showing beside it. Those about a
/// block as a whole are under its prefix, such as `query.1.`, and those about the
/// template as a whole under the empty name.
pub fn field_errors(problems: &[Problem]) -> BTreeMap<String, String> {
    let mut errors: BTreeMap<String, String> = BTreeMap::new();
    for problem in problems {
        let field = problem.form_field();
        let entry = errors.entry(field).or_default();
        if !entry.is_empty() {
            entry.push_str("; ");
        }
        entry.push_str(&problem.message);
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxnines_protocol::templates::{parse, to_hcl};

    const POSTGRES: &str = include_str!("../../templates/postgres.hcl");
    const IIS: &str = include_str!("../../../../docs/examples/iis.hcl");

    #[test]
    fn a_template_goes_through_its_form_to_hcl_and_back_unchanged() {
        for text in [POSTGRES, IIS] {
            let template = parse(text).unwrap();
            let form = TemplateForm::from_template(&template);
            // As a browser sends it.
            let sent = TemplateForm::from_fields(&form.to_fields());
            assert_eq!(sent, form);
            let (from_form, problems) = sent.to_template();
            assert!(problems.is_empty(), "{problems:?}");
            assert_eq!(from_form, template);
            let again = parse(&to_hcl(&from_form)).unwrap();
            assert_eq!(again, template);
        }
    }

    #[test]
    fn rows_are_added_and_removed() {
        let mut form = TemplateForm::from_template(&parse(POSTGRES).unwrap());
        let queries = form.queries.len();
        assert!(form.apply_action("add:query"));
        assert_eq!(form.queries.len(), queries + 1);
        assert!(form.queries.last().unwrap().enabled, "a new query is on");
        assert!(form.apply_action("remove:query.0"));
        assert_eq!(form.queries[0].key, "throughput");
        assert!(form.apply_action("add:query.0.fill.0.version"));
        assert_eq!(form.queries[0].fills[0].versions.len(), 2);
        assert!(form.apply_action("remove:query.0.fill.0.version.0"));
        assert!(form.apply_action("add:query.0.metric"));
        assert!(form.apply_action("add:alert"));
        assert!(form.apply_action("remove:alert.0"));
        assert!(form.apply_action("add:discover.0.registry"));
        assert_eq!(form.discover[0].registry.len(), 1);
        assert!(form.apply_action("add:discover"));
        assert!(form.apply_action("remove:discover.2"));
        assert!(form.apply_action("add:notice"));
        assert!(
            !form.apply_action("add:counters.0.metric"),
            "it has no counters"
        );
        for nonsense in [
            "",
            "save",
            "add:widget",
            "remove:query.99",
            "remove:query",
            "add:query.x.metric",
        ] {
            assert!(!form.apply_action(nonsense), "{nonsense}");
        }
    }

    #[test]
    fn mistakes_in_typing_are_said_beside_their_fields() {
        let mut form = TemplateForm::blank();
        form.key = "app".to_string();
        form.name = "App".to_string();
        form.discover.push(DiscoverForm {
            key: "iis".to_string(),
            counter_sets: "asp_net ASP.NET".to_string(),
            ..DiscoverForm::default()
        });
        form.counters.push(CountersForm {
            key: "c".to_string(),
            object: "Process".to_string(),
            groups: "pid = ID Process\npid = Again".to_string(),
            metrics: vec![MetricForm {
                key: "m".to_string(),
                counter: "X".to_string(),
                states: "1 =".to_string(),
                ..MetricForm::default()
            }],
            ..CountersForm::default()
        });
        let (_, problems) = form.to_template();
        let errors = field_errors(&problems);
        assert_eq!(
            errors["discover.0.counter_sets"],
            "line 1 needs a name, = and a value"
        );
        assert_eq!(errors["counters.0.groups"], "\"pid\" is given twice");
        assert_eq!(
            errors["counters.0.metric.0.states"],
            "line 1 needs a name, = and a value"
        );
    }
}
