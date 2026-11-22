//! Templates: what MaxNines collects and alerts on for something it monitors, such as
//! PostgreSQL or IIS, written in HCL with CEL for anything dynamic. A template file
//! holds one `template "<key>" { … }` block.
//!
//! This is the format and the checks that need nothing but the template itself:
//! names, lengths of time, versions, regular expressions and which pieces of SQL
//! fill which query. The server checks the rest, such as whether each CEL
//! expression compiles and whether alerts name metrics that exist.

mod parse;
pub mod work;
mod write;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;
use std::time::Duration;

use indexmap::IndexMap;
use regex_lite::Regex;
use serde::{Deserialize, Serialize};

pub use parse::parse;
pub use write::to_hcl;

/// The longest a key can be, as it starts the names of a template's metrics.
pub const MAX_KEY_LEN: usize = 64;
/// What names and descriptions can hold.
pub const MAX_NAME_LEN: usize = 255;
pub const MAX_DESCRIPTION_LEN: usize = 1000;

/// The operating systems a template can be for, by the `os.family` agents report.
pub const OPERATING_SYSTEMS: [&str; 4] = ["freebsd", "linux", "macos", "windows"];

/// How often a discover block runs when it doesn't say.
pub const DEFAULT_DISCOVERY_INTERVAL: Duration = Duration::from_secs(3600);

/// The units a metric can be given, when its name or its column's type doesn't say.
pub const UNITS: [&str; 6] = ["%", "s", "bytes", "bytes/s", "/s", "°C"];

/// A template, as written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Template {
    /// What it's known by, which never changes, and which its metrics' names start
    /// with: `postgres` for `postgres.lag`.
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    /// What it runs once for on each host. With none, it runs once on every host.
    pub target: Option<Target>,
    /// CEL over a host's facts saying which hosts it's for, before what it runs for
    /// is looked for on them. With none, it's for every host.
    pub applies_to: Option<String>,
    /// The oldest version it's for.
    pub min_version: Option<String>,
    /// Keys it had before, so a renamed template keeps what people changed.
    #[serde(default)]
    pub renamed_from: Vec<String>,
    /// False ships it turned off.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Services that the host's own service alerts should watch.
    #[serde(default)]
    pub services: Vec<String>,
    /// What's found first, each on its own schedule.
    #[serde(default)]
    pub discover: Vec<Discover>,
    #[serde(default)]
    pub notices: Vec<Notice>,
    #[serde(default)]
    pub queries: Vec<Query>,
    #[serde(default)]
    pub counters: Vec<Counters>,
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

fn yes() -> bool {
    true
}

/// What a template runs once for on each host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    /// Each database of this kind in the agent's config, such as `postgres`.
    Database(String),
    /// Each Windows host with this service, such as `W3SVC`.
    Service(String),
    /// Each host running one of these, by `os.family`.
    Os(Vec<String>),
}

impl Target {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Database(_) => "database",
            Self::Service(_) => "service",
            Self::Os(_) => "os",
        }
    }

    /// What it's for, as one piece of text: operating systems are comma separated.
    pub fn value(&self) -> String {
        match self {
            Self::Database(value) | Self::Service(value) => value.clone(),
            Self::Os(systems) => systems.join(","),
        }
    }

    /// From its kind and [`Self::value`]. None for a kind there isn't.
    pub fn from_parts(kind: &str, value: &str) -> Option<Self> {
        match kind {
            "database" => Some(Self::Database(value.to_string())),
            "service" => Some(Self::Service(value.to_string())),
            "os" => Some(Self::Os(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|system| !system.is_empty())
                    .map(str::to_string)
                    .collect(),
            )),
            _ => None,
        }
    }
}

/// What runs first, then every `interval` and whenever what's monitored restarts.
/// What it finds is what `when` and `since` look at. A template can have several, so
/// what changes quickly, such as which server is the primary, can be looked at more
/// often than what hardly does.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Discover {
    pub key: String,
    /// How often it runs, or [`DEFAULT_DISCOVERY_INTERVAL`].
    pub interval: Option<String>,
    /// Its columns each become something to look at, by their names.
    pub sql: Option<String>,
    /// Windows registry values, each named by what it becomes.
    #[serde(default)]
    pub registry: Vec<RegistryRead>,
    /// Performance counter sets, each true or false for whether the host has it.
    #[serde(default)]
    pub counter_sets: IndexMap<String, String>,
}

/// Values read from one registry key, by what each becomes: `version = "VersionString"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryRead {
    pub key: String,
    pub values: IndexMap<String, String>,
}

/// Something shown on the host page while `when` holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notice {
    pub key: String,
    pub when: Option<String>,
    pub text: String,
}

/// SQL whose columns become metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Query {
    pub key: String,
    pub sql: String,
    pub interval: Option<String>,
    pub since: Option<String>,
    pub when: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Text columns that tell rows apart, one series per row.
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub fills: Vec<Fill>,
    /// More about some columns, or metrics worked out from them.
    #[serde(default)]
    pub metrics: Vec<Metric>,
}

/// A piece of SQL picked by version, filling `{{ key }}` in a query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fill {
    pub key: String,
    /// The SQL from each version onwards.
    pub versions: IndexMap<String, String>,
    /// The SQL for versions before all of them.
    pub older: Option<String>,
}

/// Windows performance counters that become metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    pub key: String,
    /// The counter set.
    pub object: String,
    /// Gives each instance its own series, labelled this.
    pub label: Option<String>,
    /// Picks instances by name, its named groups becoming labels.
    pub pattern: Option<String>,
    /// Reads only this instance.
    pub instance: Option<String>,
    /// Instances left out.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Groups whose values are read from a counter, rather than the instance's name.
    #[serde(default)]
    pub groups: IndexMap<String, String>,
    pub join: Option<Join>,
    pub when: Option<String>,
    pub since: Option<String>,
    pub interval: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub metrics: Vec<Metric>,
}

/// Another counter set whose instances are matched to these by a group named in
/// both patterns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Join {
    pub object: String,
    pub pattern: String,
}

/// A metric: a counter, or more about a query's column, or one worked out with CEL.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// Its name, after the template's key: `lag` for `postgres.lag`.
    pub key: String,
    /// The performance counter it reads, for counters.
    pub counter: Option<String>,
    pub unit: Option<String>,
    /// A running total, kept as a rate.
    #[serde(default)]
    pub total: bool,
    pub description: Option<String>,
    /// CEL working it out as each sample arrives.
    pub value: Option<String>,
    pub since: Option<String>,
    /// A word for each number it can be.
    #[serde(default)]
    pub states: IndexMap<String, String>,
}

impl Metric {
    /// Whether it's only a counter's name, which HCL writes as a string.
    pub fn is_only_counter(&self) -> bool {
        self.counter.is_some()
            && Self {
                key: self.key.clone(),
                counter: self.counter.clone(),
                ..Self::default()
            } == *self
    }
}

/// An alert, which becomes an alert rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub key: String,
    pub name: String,
    pub warning: Option<String>,
    pub critical: Option<String>,
    /// How long it has to last.
    #[serde(rename = "for")]
    pub hold: Option<String>,
    /// How much of the past `forecast()` draws its line through.
    pub window: Option<String>,
    pub summary: Option<String>,
    pub resolved_summary: Option<String>,
    pub when: Option<String>,
    pub since: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// Where in a template something is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Template,
    Discover(usize),
    Notice(usize),
    Query(usize),
    Fill(usize, usize),
    Counters(usize),
    Join(usize),
    QueryMetric(usize, usize),
    CountersMetric(usize, usize),
    Alert(usize),
}

impl Place {
    /// What a form calls the fields here, with a dot after it: `alert.2.`.
    pub fn form_prefix(self) -> String {
        match self {
            Self::Template => String::new(),
            Self::Discover(index) => format!("discover.{index}."),
            Self::Notice(index) => format!("notice.{index}."),
            Self::Query(index) => format!("query.{index}."),
            Self::Fill(query, index) => format!("query.{query}.fill.{index}."),
            Self::Counters(index) => format!("counters.{index}."),
            Self::Join(index) => format!("counters.{index}.join."),
            Self::QueryMetric(query, index) => format!("query.{query}.metric.{index}."),
            Self::CountersMetric(block, index) => format!("counters.{block}.metric.{index}."),
            Self::Alert(index) => format!("alert.{index}."),
        }
    }

    /// The place in words, as HCL writes it: `query "sessions", fill "checksums"`.
    pub fn describe(self, template: &Template) -> String {
        let key = |keys: &[&String], index: usize| {
            keys.get(index)
                .map_or_else(|| format!("#{}", index + 1), |key| format!("{key:?}"))
        };
        let queries: Vec<&String> = template.queries.iter().map(|q| &q.key).collect();
        let counters: Vec<&String> = template.counters.iter().map(|c| &c.key).collect();
        let query_part = |index: usize| format!("query {}", key(&queries, index));
        let counters_part = |index: usize| format!("counters {}", key(&counters, index));
        let metric_of = |metrics: Option<&Vec<Metric>>, index: usize| {
            let keys: Vec<&String> =
                metrics.map_or_else(Vec::new, |m| m.iter().map(|m| &m.key).collect());
            format!("metric {}", key(&keys, index))
        };
        match self {
            Self::Template => String::new(),
            Self::Discover(index) => {
                let keys: Vec<&String> = template.discover.iter().map(|d| &d.key).collect();
                format!("discover {}", key(&keys, index))
            }
            Self::Notice(index) => {
                let keys: Vec<&String> = template.notices.iter().map(|n| &n.key).collect();
                format!("notice {}", key(&keys, index))
            }
            Self::Query(index) => query_part(index),
            Self::Fill(query, index) => {
                let keys: Vec<&String> = template
                    .queries
                    .get(query)
                    .map_or_else(Vec::new, |q| q.fills.iter().map(|f| &f.key).collect());
                format!("{}, fill {}", query_part(query), key(&keys, index))
            }
            Self::Counters(index) => counters_part(index),
            Self::Join(index) => format!("{}, join", counters_part(index)),
            Self::QueryMetric(query, index) => format!(
                "{}, {}",
                query_part(query),
                metric_of(template.queries.get(query).map(|q| &q.metrics), index)
            ),
            Self::CountersMetric(block, index) => format!(
                "{}, {}",
                counters_part(block),
                metric_of(template.counters.get(block).map(|c| &c.metrics), index)
            ),
            Self::Alert(index) => {
                let keys: Vec<&String> = template.alerts.iter().map(|a| &a.key).collect();
                format!("alert {}", key(&keys, index))
            }
        }
    }
}

/// Something wrong with a template, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub place: Place,
    /// The field, as HCL names it, or empty for the block as a whole.
    pub field: String,
    pub message: String,
}

impl Problem {
    pub fn new(place: Place, field: &str, message: impl Into<String>) -> Self {
        Self {
            place,
            field: field.to_string(),
            message: message.into(),
        }
    }

    /// Where it is and what's wrong, naming the template, block and field.
    pub fn describe(&self, template: &Template) -> String {
        let mut parts = vec![format!("template {:?}", template.key)];
        let place = self.place.describe(template);
        if !place.is_empty() {
            parts.push(place);
        }
        if !self.field.is_empty() {
            parts.push(self.field.clone());
        }
        format!("{}: {}", parts.join(", "), self.message)
    }

    /// The form field it's about: `alert.2.warning`.
    pub fn form_field(&self) -> String {
        format!("{}{}", self.place.form_prefix(), self.field)
    }
}

/// Every problem found with a template, said as one error.
#[derive(Debug, Clone)]
pub struct Problems {
    pub described: Vec<String>,
    pub problems: Vec<Problem>,
}

impl Problems {
    pub fn new(template: &Template, problems: Vec<Problem>) -> Self {
        Self {
            described: problems.iter().map(|p| p.describe(template)).collect(),
            problems,
        }
    }
}

impl fmt::Display for Problems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.described.join("; "))
    }
}

impl std::error::Error for Problems {}

/// A version as templates compare them: numbers separated by dots, so 9.6 < 13 < 16.2.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(Vec<u64>);

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let parts: Option<Vec<u64>> = text.split('.').map(|part| part.parse().ok()).collect();
        let mut parts = parts?;
        // 13 and 13.0 are the same version.
        while parts.len() > 1 && parts.last() == Some(&0) {
            parts.pop();
        }
        Some(Self(parts))
    }

    /// The first version in some text, as a server describes itself: `16.4` in
    /// `16.4 (Debian 16.4-1)`, or `10.0` in `Version 10.0`.
    pub fn find(text: &str) -> Option<Self> {
        let start = text.find(|c: char| c.is_ascii_digit())?;
        let rest = &text[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        Self::parse(rest[..end].trim_end_matches('.'))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.0.iter().map(u64::to_string).collect();
        f.write_str(&parts.join("."))
    }
}

/// A length of time as templates write it, such as `1m` or `90s`, in whole seconds.
pub fn parse_duration(text: &str) -> Result<u64, String> {
    let length = humantime::parse_duration(text.trim())
        .map_err(|_| format!("{text:?} isn't a length of time, like \"30s\", \"5m\" or \"1h\""))?;
    if length.subsec_nanos() != 0 {
        return Err(format!("{text:?} has to be whole seconds"));
    }
    Ok(length.as_secs())
}

/// Whole seconds as templates write them: `1m`, `1h 30m`.
pub fn format_duration(secs: u64) -> String {
    humantime::format_duration(Duration::from_secs(secs)).to_string()
}

/// The names `{{ name }}` in a query's SQL asks fills for.
pub fn fill_names(sql: &str) -> Vec<String> {
    static PLACE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").expect("valid"));
    let mut names = Vec::new();
    for captures in PLACE.captures_iter(sql) {
        let name = captures[1].to_string();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// A query's SQL with each fill filled for a version: the SQL given from the highest
/// version at or below it, or the fill's `older` below them all or with no version.
pub fn fill(query: &Query, at: Option<&Version>) -> String {
    let pick = |fill: &Fill| -> String {
        let chosen = at.and_then(|at| {
            fill.versions
                .iter()
                .filter_map(|(from, sql)| Some((Version::parse(from)?, sql)))
                .filter(|(from, _)| from <= at)
                .max_by(|a, b| a.0.cmp(&b.0))
                .map(|(_, sql)| sql.clone())
        });
        chosen.or_else(|| fill.older.clone()).unwrap_or_default()
    };
    let mut sql = query.sql.clone();
    for fill in &query.fills {
        let filled = pick(fill);
        let re = Regex::new(&format!(
            r"\{{\{{\s*{}\s*\}}\}}",
            regex_lite::escape(&fill.key)
        ))
        .expect("a key is a name");
        sql = re
            .replace_all(&sql, regex_lite::NoExpand(&filled))
            .into_owned();
    }
    sql
}

/// The SQL each version range would run, with every fill filled: once with each
/// fill's `older` and once from each version any fill names.
pub fn filled_sql(query: &Query) -> Vec<String> {
    let mut versions: BTreeSet<Version> = BTreeSet::new();
    for fill in &query.fills {
        versions.extend(fill.versions.keys().filter_map(|v| Version::parse(v)));
    }
    let mut all = vec![fill(query, None)];
    for version in &versions {
        let sql = fill(query, Some(version));
        if !all.contains(&sql) {
            all.push(sql);
        }
    }
    all
}

/// The named groups of a regular expression, or why it doesn't compile.
pub fn named_groups(pattern: &str) -> Result<Vec<String>, String> {
    let regex =
        Regex::new(pattern).map_err(|error| format!("isn't a regular expression: {error}"))?;
    Ok(regex
        .capture_names()
        .flatten()
        .map(str::to_string)
        .collect())
}

/// Whether a name can be a key or a label: lowercase letters, digits and
/// underscores, starting with a letter, so CEL and metric names can use it.
pub fn is_key(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && name.len() <= MAX_KEY_LEN
}

const KEY_RULE: &str = "has to be lowercase letters, digits and underscores, starting with a letter, up to 64 characters";

impl Template {
    /// Everything wrong with it that it can say itself, in the order it's written.
    pub fn check(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        let mut say = |place: Place, field: &str, message: String| {
            problems.push(Problem::new(place, field, message));
        };
        let top = Place::Template;

        if !is_key(&self.key) {
            say(top, "key", format!("{:?} {KEY_RULE}", self.key));
        }
        check_name(&self.name, &mut |message| say(top, "name", message));
        if let Some(description) = &self.description
            && description.len() > MAX_DESCRIPTION_LEN
        {
            say(
                top,
                "description",
                format!("can be up to {MAX_DESCRIPTION_LEN} characters"),
            );
        }
        match &self.target {
            Some(Target::Database(kind)) if kind.trim().is_empty() => {
                say(top, "database", "can't be empty".to_string());
            }
            Some(Target::Service(service)) if service.trim().is_empty() => {
                say(top, "service", "can't be empty".to_string());
            }
            Some(Target::Os(systems)) => {
                if systems.is_empty() {
                    say(top, "os", "lists at least one operating system".to_string());
                }
                for (index, system) in systems.iter().enumerate() {
                    if !OPERATING_SYSTEMS.contains(&system.as_str()) {
                        say(
                            top,
                            "os",
                            format!(
                                "{system:?} isn't an operating system: use {}",
                                OPERATING_SYSTEMS.join(", ")
                            ),
                        );
                    } else if systems[..index].contains(system) {
                        say(top, "os", format!("{system:?} is listed twice"));
                    }
                }
            }
            _ => {}
        }
        if let Some(version) = &self.min_version {
            check_version(version, &mut |message| say(top, "min_version", message));
        }
        for (index, old) in self.renamed_from.iter().enumerate() {
            if self.renamed_from[..index].contains(old) {
                say(top, "renamed_from", format!("{old:?} is listed twice"));
            } else if !is_key(old) {
                say(top, "renamed_from", format!("{old:?} {KEY_RULE}"));
            } else if *old == self.key {
                say(
                    top,
                    "renamed_from",
                    "can't name the template's own key".to_string(),
                );
            }
        }
        for (index, service) in self.services.iter().enumerate() {
            if service.trim().is_empty() {
                say(top, "services", "can't have an empty name".to_string());
            } else if self.services[..index].contains(service) {
                say(top, "services", format!("{service:?} is listed twice"));
            }
        }

        check_keys(
            self.discover.iter().map(|d| &d.key),
            Place::Discover,
            &mut say,
        );
        // What every discover block finds is looked at together, by name.
        let mut found = BTreeSet::new();
        for (index, discover) in self.discover.iter().enumerate() {
            let place = Place::Discover(index);
            if let Some(interval) = &discover.interval {
                check_run_interval(interval, &mut |message| say(place, "interval", message));
            }
            if let Some(sql) = &discover.sql {
                check_sql_len(sql, &mut |message| say(place, "sql", message));
            }
            if discover.sql.is_none()
                && discover.registry.is_empty()
                && discover.counter_sets.is_empty()
            {
                say(
                    place,
                    "",
                    "needs sql, a registry block or counter_sets".to_string(),
                );
            }
            if discover
                .sql
                .as_deref()
                .is_some_and(|sql| sql.trim().is_empty())
            {
                say(place, "sql", "can't be empty".to_string());
            }
            let mut keys = BTreeSet::new();
            for read in &discover.registry {
                if !keys.insert(&read.key) {
                    say(
                        place,
                        "registry",
                        format!("{:?} is read twice: put its values in one block", read.key),
                    );
                }
                if read.key.trim().is_empty() {
                    say(place, "registry", "needs a registry key".to_string());
                }
                if read.values.is_empty() {
                    say(place, "registry", format!("{:?} reads no values", read.key));
                }
                for name in read.values.keys() {
                    if !is_key(name) {
                        say(place, "registry", format!("{name:?} {KEY_RULE}"));
                    } else if !found.insert(name.clone()) {
                        say(place, "registry", format!("{name:?} is found twice"));
                    }
                }
            }
            for name in discover.counter_sets.keys() {
                if !is_key(name) {
                    say(place, "counter_sets", format!("{name:?} {KEY_RULE}"));
                } else if !found.insert(name.clone()) {
                    say(place, "counter_sets", format!("{name:?} is found twice"));
                }
            }
        }

        check_keys(self.notices.iter().map(|n| &n.key), Place::Notice, &mut say);
        for (index, notice) in self.notices.iter().enumerate() {
            if notice.text.trim().is_empty() {
                say(Place::Notice(index), "text", "can't be empty".to_string());
            }
        }

        // An agent is sent its discover blocks and queries together, which has a limit.
        if self.discover.len() + self.queries.len() > work::MAX_STATEMENTS {
            say(
                top,
                "",
                format!(
                    "has more than {} discover blocks and queries together",
                    work::MAX_STATEMENTS
                ),
            );
        }
        check_keys(self.queries.iter().map(|q| &q.key), Place::Query, &mut say);
        for (index, query) in self.queries.iter().enumerate() {
            check_query(index, query, &mut say);
        }

        check_keys(
            self.counters.iter().map(|c| &c.key),
            Place::Counters,
            &mut say,
        );
        for (index, counters) in self.counters.iter().enumerate() {
            check_counters(index, counters, &mut say);
        }

        check_keys(self.alerts.iter().map(|a| &a.key), Place::Alert, &mut say);
        for (index, alert) in self.alerts.iter().enumerate() {
            let place = Place::Alert(index);
            check_name(&alert.name, &mut |message| say(place, "name", message));
            if alert.warning.is_none() && alert.critical.is_none() {
                say(
                    place,
                    "",
                    "needs a warning or critical condition, or both".to_string(),
                );
            }
            if let Some(hold) = &alert.hold
                && let Err(message) = parse_duration(hold)
            {
                say(place, "for", message);
            }
            if let Some(window) = &alert.window {
                check_interval(window, &mut |message| say(place, "window", message));
            }
            if let Some(since) = &alert.since {
                check_version(since, &mut |message| say(place, "since", message));
            }
        }
        problems
    }

    /// Its metrics' keys, each once, in the order they're written.
    pub fn metric_keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = Vec::new();
        let all = self
            .queries
            .iter()
            .flat_map(|q| &q.metrics)
            .chain(self.counters.iter().flat_map(|c| &c.metrics));
        for metric in all {
            if !keys.contains(&metric.key.as_str()) {
                keys.push(&metric.key);
            }
        }
        keys
    }
}

fn check_name(name: &str, say: &mut dyn FnMut(String)) {
    if name.trim().is_empty() {
        say("can't be empty".to_string());
    } else if name.len() > MAX_NAME_LEN {
        say(format!("can be up to {MAX_NAME_LEN} characters"));
    }
}

fn check_version(version: &str, say: &mut dyn FnMut(String)) {
    if Version::parse(version).is_none() {
        say(format!(
            "{version:?} isn't a version, like \"13\" or \"8.0\""
        ));
    }
}

fn check_interval(interval: &str, say: &mut dyn FnMut(String)) {
    match parse_duration(interval) {
        Ok(0) => say("has to be longer than nothing".to_string()),
        Ok(_) => {}
        Err(message) => say(message),
    }
}

/// How often something an agent runs runs: more than nothing, and at least daily,
/// as an agent takes.
fn check_run_interval(interval: &str, say: &mut dyn FnMut(String)) {
    match parse_duration(interval) {
        Ok(secs) if secs > crate::MAX_INTERVAL.as_secs() => {
            say("can be up to a day, \"24h\"".to_string());
        }
        _ => check_interval(interval, say),
    }
}

fn check_sql_len(sql: &str, say: &mut dyn FnMut(String)) {
    if sql.len() > work::MAX_SQL_LEN {
        say(format!(
            "can be up to {} KB, with what fills it",
            work::MAX_SQL_LEN / 1024
        ));
    }
}

fn check_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    place: impl Fn(usize) -> Place,
    say: &mut dyn FnMut(Place, &str, String),
) {
    let mut seen = BTreeSet::new();
    for (index, key) in keys.enumerate() {
        if !is_key(key) {
            say(place(index), "key", format!("{key:?} {KEY_RULE}"));
        } else if !seen.insert(key) {
            say(place(index), "key", format!("{key:?} is used twice"));
        }
    }
}

fn check_metric(
    place: Place,
    metric: &Metric,
    counters: bool,
    say: &mut dyn FnMut(Place, &str, String),
) {
    match (&metric.counter, counters) {
        (Some(_), false) => say(place, "counter", "is only for counters".to_string()),
        (None, true) => say(place, "counter", "needs the counter it reads".to_string()),
        (Some(counter), true) if counter.trim().is_empty() => {
            say(place, "counter", "can't be empty".to_string());
        }
        _ => {}
    }
    if let Some(unit) = &metric.unit
        && !UNITS.contains(&unit.as_str())
    {
        say(
            place,
            "unit",
            format!("{unit:?} isn't a unit: use {}", UNITS.join(", ")),
        );
    }
    if let Some(description) = &metric.description
        && description.len() > MAX_DESCRIPTION_LEN
    {
        say(
            place,
            "description",
            format!("can be up to {MAX_DESCRIPTION_LEN} characters"),
        );
    }
    if let Some(since) = &metric.since {
        check_version(since, &mut |message| say(place, "since", message));
    }
    for number in metric.states.keys() {
        if number.trim().parse::<i64>().is_err() {
            say(place, "states", format!("{number:?} isn't a whole number"));
        }
    }
}

fn check_query(index: usize, query: &Query, say: &mut dyn FnMut(Place, &str, String)) {
    let place = Place::Query(index);
    if query.sql.trim().is_empty() {
        say(place, "sql", "can't be empty".to_string());
    }
    if let Some(interval) = &query.interval {
        check_run_interval(interval, &mut |message| say(place, "interval", message));
    }
    for sql in filled_sql(query) {
        check_sql_len(&sql, &mut |message| say(place, "sql", message));
    }
    if query.labels.len() > work::MAX_COLUMNS {
        say(
            place,
            "labels",
            format!("can be up to {}", work::MAX_COLUMNS),
        );
    }
    if query.metrics.len() > work::MAX_COLUMNS {
        say(
            place,
            "metrics",
            format!("can be up to {}", work::MAX_COLUMNS),
        );
    }
    if let Some(since) = &query.since {
        check_version(since, &mut |message| say(place, "since", message));
    }
    let mut seen = BTreeSet::new();
    for label in &query.labels {
        if label.trim().is_empty() {
            say(place, "labels", "can't have an empty name".to_string());
        } else if !seen.insert(label) {
            say(place, "labels", format!("{label:?} is listed twice"));
        }
    }

    let wanted = fill_names(&query.sql);
    for name in &wanted {
        if !query.fills.iter().any(|fill| &fill.key == name) {
            say(place, "sql", format!("{{{{ {name} }}}} has no fill block"));
        }
    }
    check_keys(
        query.fills.iter().map(|f| &f.key),
        |fill| Place::Fill(index, fill),
        say,
    );
    for (number, fill) in query.fills.iter().enumerate() {
        let place = Place::Fill(index, number);
        if !wanted.contains(&fill.key) {
            say(
                place,
                "",
                format!("the query's SQL has no {{{{ {} }}}} for it", fill.key),
            );
        }
        if fill.versions.is_empty() {
            say(place, "versions", "needs at least one version".to_string());
        }
        if fill.older.is_none() {
            say(
                place,
                "older",
                "needs the SQL for older versions".to_string(),
            );
        }
        let mut seen = BTreeSet::new();
        for version in fill.versions.keys() {
            match Version::parse(version) {
                Some(parsed) if !seen.insert(parsed.clone()) => {
                    say(place, "versions", format!("{version:?} is given twice"));
                }
                Some(_) => {}
                None => check_version(version, &mut |message| say(place, "versions", message)),
            }
        }
    }

    check_keys(
        query.metrics.iter().map(|m| &m.key),
        |metric| Place::QueryMetric(index, metric),
        say,
    );
    for (number, metric) in query.metrics.iter().enumerate() {
        check_metric(Place::QueryMetric(index, number), metric, false, say);
    }
}

fn check_counters(index: usize, counters: &Counters, say: &mut dyn FnMut(Place, &str, String)) {
    let place = Place::Counters(index);
    if counters.object.trim().is_empty() {
        say(place, "object", "needs the counter set".to_string());
    }
    let ways = [
        counters.label.is_some(),
        counters.pattern.is_some(),
        counters.instance.is_some(),
    ];
    if ways.iter().filter(|way| **way).count() > 1 {
        say(
            place,
            "",
            "picks instances with label, pattern or instance, not more than one".to_string(),
        );
    }
    if let Some(label) = &counters.label
        && !is_key(label)
    {
        say(place, "label", format!("{label:?} {KEY_RULE}"));
    }
    if let Some(interval) = &counters.interval {
        check_run_interval(interval, &mut |message| say(place, "interval", message));
    }
    if let Some(since) = &counters.since {
        check_version(since, &mut |message| say(place, "since", message));
    }
    for (index, instance) in counters.exclude.iter().enumerate() {
        if counters.exclude[..index].contains(instance) {
            say(place, "exclude", format!("{instance:?} is listed twice"));
        }
    }
    for name in counters.groups.keys() {
        if !is_key(name) {
            say(place, "groups", format!("{name:?} {KEY_RULE}"));
        }
    }

    let mut groups: Vec<String> = counters.groups.keys().cloned().collect();
    if let Some(pattern) = &counters.pattern {
        match named_groups(pattern) {
            Ok(named) => {
                for name in named {
                    if !is_key(&name) {
                        say(place, "pattern", format!("the group {name:?} {KEY_RULE}"));
                    } else if groups.contains(&name) {
                        say(place, "pattern", format!("{name:?} is also in groups"));
                    } else {
                        groups.push(name);
                    }
                }
            }
            Err(message) => say(place, "pattern", message),
        }
    }
    if let Some(join) = &counters.join {
        let join_place = Place::Join(index);
        if join.object.trim().is_empty() {
            say(join_place, "object", "needs the counter set".to_string());
        }
        if counters.pattern.is_none() && counters.groups.is_empty() {
            say(
                join_place,
                "",
                "needs a pattern or groups to join by".to_string(),
            );
        }
        match named_groups(&join.pattern) {
            Ok(theirs) => {
                if !theirs.iter().any(|name| groups.contains(name)) {
                    say(
                        join_place,
                        "pattern",
                        format!(
                            "has no group named in both patterns to join by: this one has {}, the counters have {}",
                            list_or_none(&theirs),
                            list_or_none(&groups)
                        ),
                    );
                }
                for name in theirs.iter().filter(|name| !is_key(name)) {
                    say(
                        join_place,
                        "pattern",
                        format!("the group {name:?} {KEY_RULE}"),
                    );
                }
            }
            Err(message) => say(join_place, "pattern", message),
        }
    } else if !counters.groups.is_empty() {
        say(
            place,
            "groups",
            "only mean something with a join".to_string(),
        );
    }
    if counters.metrics.is_empty() {
        say(place, "metrics", "needs at least one metric".to_string());
    }
    check_keys(
        counters.metrics.iter().map(|m| &m.key),
        |metric| Place::CountersMetric(index, metric),
        say,
    );
    for (number, metric) in counters.metrics.iter().enumerate() {
        check_metric(Place::CountersMetric(index, number), metric, true, say);
    }
}

fn list_or_none(names: &[String]) -> String {
    match names {
        [] => "none".to_string(),
        names => names.join(", "),
    }
}

impl Counters {
    /// What each series is labelled with: the label, or the patterns' groups that
    /// aren't only for joining.
    pub fn labels(&self) -> Vec<String> {
        if let Some(label) = &self.label {
            return vec![label.clone()];
        }
        let mut own: Vec<String> = self.groups.keys().cloned().collect();
        if let Some(pattern) = &self.pattern {
            own.extend(named_groups(pattern).unwrap_or_default());
        }
        let Some(join) = &self.join else {
            return own;
        };
        let theirs = named_groups(&join.pattern).unwrap_or_default();
        // A group in both is only for joining; theirs that aren't are labels.
        let mut labels: Vec<String> = own
            .iter()
            .filter(|n| !theirs.contains(n))
            .cloned()
            .collect();
        labels.extend(theirs.iter().filter(|n| !own.contains(n)).cloned());
        labels
    }
}

#[cfg(test)]
mod tests;
