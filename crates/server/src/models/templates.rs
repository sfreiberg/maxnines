//! Templates, kept as rows: one for the template, one for each of its parts in the
//! table for its kind, and an alert rule for each of its alerts. HCL is how
//! templates come in and go out, and is written from the rows.
//!
//! A built-in template's rows belong to the server, which rewrites them as it
//! starts. Someone changing one of its alerts makes a copy of their own: a second
//! rule, pointing at the built-in one with `replaces_id`, which is used in its
//! place while it's there. Putting the alert back deletes the copy. Whether a
//! built-in template or one of its alerts is on is a flag on its own row, which
//! starting never writes. People's own templates are the same rows, changed directly.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context, Result, bail};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use serde::Serialize;
use serde_json::json;

use maxnines_protocol::templates::{
    Alert, Counters, Discover, Fill, Join, Metric, Notice, Query, RegistryRead, Target, Template,
    format_duration, parse_duration, to_hcl,
};

use super::alerting::{
    alert_rule_row, alert_rule_snapshot, delete_rule_in, load_alert_rule, record_alert_rule,
    refuse_taken_name, save_actions, save_links, write_rule_in,
};
use super::audit::record_change;
use super::{
    Database, alert, alert_rule, maintenance_window, name_key, name_taken_or, silence, template,
    template_counters, template_discovery, template_fill, template_fill_version, template_host,
    template_items, template_metric, template_notice, template_query, template_registry_read,
};
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::audit::{Kind, Snapshot};
use crate::catalog::Catalog;
use crate::templates::built_in::BuiltIn;
use crate::templates::hosts::{Running, RunningTemplates};
use crate::templates::{Refused, alert_rule as template_values};
use crate::times::Timestamp;

/// Where a template came from, which says whose it is to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// It comes with MaxNines, which rewrites it as it starts.
    BuiltIn,
    /// Someone imported it, and importing a newer version rewrites it.
    Imported,
    /// Someone made it here, and changes it directly.
    Own,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::Imported => "imported",
            Self::Own => "own",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "built_in" => Ok(Self::BuiltIn),
            "imported" => Ok(Self::Imported),
            "own" => Ok(Self::Own),
            other => bail!("unknown template origin {other:?}"),
        }
    }

    /// Whether its rows are an original that isn't people's to change: they make
    /// copies of its parts instead, and a newer version rewrites it.
    pub fn is_original(self) -> bool {
        self != Self::Own
    }
}

/// What importing a template did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Imported {
    Added,
    Updated,
    /// It says what the one already imported says.
    Unchanged,
}

/// A template as stored.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StoredTemplate {
    pub id: i64,
    pub template: Template,
    pub origin: Origin,
    /// Whether it's on: what someone chose, or what the template ships.
    pub enabled: bool,
    /// What someone chose, for a built-in or imported one, or nothing while it
    /// follows what the template ships.
    pub enabled_choice: Option<bool>,
    /// Which hosts it's for, by their facts: what someone chose for a built-in or
    /// imported one, or what the template says.
    pub applies_to: Option<String>,
    /// Whether someone chose that, for a built-in or imported one.
    pub applies_to_chosen: bool,
    /// The hosts given it by hand, on top of those `applies_to` picks.
    pub host_ids: Vec<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// When an upgrade last changed it, for a built-in one.
    pub upgraded_at: Option<Timestamp>,
    /// What's been made of each of its discover blocks, queries and counters
    /// blocks that someone has changed or turned on or off.
    pub choices: Vec<PartChoice>,
    /// Someone's copies of its parts, for a built-in or imported one, each used in
    /// place of the part with its key.
    pub copies: Vec<Part>,
}

/// A kind of a template's part that can be someone's own copy, or, but for a
/// discover block, turned off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartKind {
    Discover,
    Query,
    Counters,
}

impl PartKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Query => "query",
            Self::Counters => "counters",
        }
    }

    /// Whether it can be turned off. A discover block can't, as what it finds is
    /// waited on.
    pub fn turns_off(self) -> bool {
        self != Self::Discover
    }
}

/// One of a template's discover blocks, queries or counters blocks.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Part {
    Discover(Discover),
    Query(Query),
    Counters(Counters),
}

impl Part {
    pub fn kind(&self) -> PartKind {
        match self {
            Self::Discover(_) => PartKind::Discover,
            Self::Query(_) => PartKind::Query,
            Self::Counters(_) => PartKind::Counters,
        }
    }

    pub fn key(&self) -> &str {
        match self {
            Self::Discover(part) => &part.key,
            Self::Query(part) => &part.key,
            Self::Counters(part) => &part.key,
        }
    }

    /// The part of `kind` with `key` in `template`, and where it comes.
    pub fn of(template: &Template, kind: PartKind, key: &str) -> Option<(usize, Self)> {
        match kind {
            PartKind::Discover => template
                .discover
                .iter()
                .position(|part| part.key == key)
                .map(|at| (at, Self::Discover(template.discover[at].clone()))),
            PartKind::Query => template
                .queries
                .iter()
                .position(|part| part.key == key)
                .map(|at| (at, Self::Query(template.queries[at].clone()))),
            PartKind::Counters => template
                .counters
                .iter()
                .position(|part| part.key == key)
                .map(|at| (at, Self::Counters(template.counters[at].clone()))),
        }
    }

    /// Puts this part in `template` in place of the one with its key, if it has
    /// one. Returns whether it did.
    pub fn put_in(self, template: &mut Template) -> bool {
        match self {
            Self::Discover(part) => put(&mut template.discover, part, |p| &p.key),
            Self::Query(part) => put(&mut template.queries, part, |p| &p.key),
            Self::Counters(part) => put(&mut template.counters, part, |p| &p.key),
        }
    }

    /// Whether it's on: a discover block always is.
    fn enabled(&self) -> bool {
        match self {
            Self::Discover(_) => true,
            Self::Query(part) => part.enabled,
            Self::Counters(part) => part.enabled,
        }
    }

    fn set_enabled(&mut self, enabled: bool) {
        match self {
            Self::Discover(_) => {}
            Self::Query(part) => part.enabled = enabled,
            Self::Counters(part) => part.enabled = enabled,
        }
    }
}

fn put<T>(parts: &mut [T], part: T, key: impl Fn(&T) -> &String) -> bool {
    match parts.iter().position(|one| key(one) == key(&part)) {
        Some(at) => {
            parts[at] = part;
            true
        }
        None => false,
    }
}

/// What someone has made of one of a template's parts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PartChoice {
    pub kind: PartKind,
    pub key: String,
    /// Whether they have their own copy of it, used in its place.
    pub copied: bool,
    /// Whether they chose it on or off, for a built-in or imported template.
    pub enabled_choice: Option<bool>,
    /// When a newer version of the template changed what their copy is a copy of.
    pub original_changed_at: Option<Timestamp>,
}

impl StoredTemplate {
    /// The template as HCL, written from its rows.
    pub fn hcl(&self) -> String {
        to_hcl(&self.template)
    }
}

/// One of a template's alerts: its rule, and for a built-in template, someone's
/// copy of it if they've made one, which is the one in use.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemplateAlert {
    pub key: String,
    /// The template's own rule.
    pub rule: AlertRule,
    /// Someone's own copy of it.
    pub copy: Option<AlertRule>,
}

impl TemplateAlert {
    /// The rule in use.
    pub fn in_use(&self) -> &AlertRule {
        self.copy.as_ref().unwrap_or(&self.rule)
    }
}

/// A length of time a template wrote, as rows keep it. Saving a template checks
/// they can all be read.
fn secs(text: &Option<String>) -> Result<Option<i64>> {
    text.as_deref()
        .map(|text| {
            let secs = parse_duration(text).map_err(anyhow::Error::msg)?;
            Ok(i64::try_from(secs)?)
        })
        .transpose()
}

fn length(secs: Option<i64>) -> Option<String> {
    secs.and_then(|secs| u64::try_from(secs).ok())
        .map(format_duration)
}

async fn to_metric<C: ConnectionTrait>(
    connection: &C,
    row: template_metric::Model,
) -> Result<Metric> {
    Ok(Metric {
        states: template_items::metric_states::read(connection, row.id).await?,
        key: row.key,
        title: row.title,
        counter: row.counter,
        unit: row.unit,
        total: row.total,
        description: row.description,
        value: row.value,
        since: row.since,
    })
}

async fn to_metrics<C: ConnectionTrait>(
    connection: &C,
    rows: Vec<template_metric::Model>,
) -> Result<Vec<Metric>> {
    let mut metrics = Vec::with_capacity(rows.len());
    for row in rows {
        metrics.push(to_metric(connection, row).await?);
    }
    Ok(metrics)
}

/// Which of a template's rows are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// The template as it was written: copies of its parts are someone's own, and
    /// aren't the template's.
    AsWritten,
    /// The template as it runs: someone's copy of a query, counters or one of their
    /// parts in place of the part it's a copy of, and each of them, and the
    /// template, on or off as someone chose.
    AsRun,
}

/// The rows of a kind of part to read: the template's own, or for a template as it
/// runs, each of someone's copies in place of the row it's a copy of.
macro_rules! parts {
    ($entity:ident, $reading:expr, $connection:expr, $parent:ident, $id:expr, $what:literal) => {{
        let mut rows = $entity::Entity::find()
            .filter($entity::Column::$parent.eq($id))
            .order_by_asc($entity::Column::Position)
            .all($connection)
            .await
            .context(concat!("loading ", $what))?;
        let copied: BTreeSet<i64> = rows.iter().filter_map(|row| row.replaces_id).collect();
        rows.retain(|row| match $reading {
            Reading::AsWritten => row.replaces_id.is_none(),
            Reading::AsRun => !copied.contains(&row.id),
        });
        rows
    }};
}

/// A template's own rows of a kind of part that can be copied, in its order, each
/// with the row read in its place: someone's copy of it, for a template as it runs,
/// or the row itself. Whether it's on is always the template's own row's say.
macro_rules! chosen_parts {
    ($entity:ident, $reading:expr, $connection:expr, $id:expr, $what:literal) => {{
        let rows = $entity::Entity::find()
            .filter($entity::Column::TemplateId.eq($id))
            .order_by_asc($entity::Column::Position)
            .all($connection)
            .await
            .context(concat!("loading ", $what))?;
        let mut copies: HashMap<i64, $entity::Model> = HashMap::new();
        let mut originals = Vec::new();
        for row in rows {
            match row.replaces_id {
                Some(of) => {
                    copies.insert(of, row);
                }
                None => originals.push(row),
            }
        }
        originals
            .into_iter()
            .map(|original| {
                let read = match $reading {
                    Reading::AsRun => copies.remove(&original.id),
                    Reading::AsWritten => None,
                };
                (read.unwrap_or_else(|| original.clone()), original)
            })
            .collect::<Vec<($entity::Model, $entity::Model)>>()
    }};
}

/// The template a row and its parts' rows say.
async fn read_template<C: ConnectionTrait>(
    connection: &C,
    row: &template::Model,
    reading: Reading,
) -> Result<Template> {
    let id = row.id;
    let on = |enabled: bool, choice: Option<bool>| match reading {
        Reading::AsWritten => enabled,
        Reading::AsRun => choice.unwrap_or(enabled),
    };
    let mut discover = Vec::new();
    for (found, _) in chosen_parts!(
        template_discovery,
        reading,
        connection,
        id,
        "a template's discovery"
    ) {
        let registry = template_registry_read::Entity::find()
            .filter(template_registry_read::Column::DiscoveryId.eq(found.id))
            .filter(template_registry_read::Column::ReplacesId.is_null())
            .order_by_asc(template_registry_read::Column::Position)
            .all(connection)
            .await
            .context("loading a template's registry reads")?;
        let mut reads = Vec::with_capacity(registry.len());
        for read in registry {
            reads.push(RegistryRead {
                values: template_items::registry_values::read(connection, read.id).await?,
                key: read.key,
            });
        }
        discover.push(Discover {
            interval: length(found.interval_secs),
            sql: found.sql,
            registry: reads,
            counter_sets: template_items::counter_sets::read(connection, found.id).await?,
            key: found.key,
        });
    }

    let notices = template_notice::Entity::find()
        .filter(template_notice::Column::TemplateId.eq(id))
        .filter(template_notice::Column::ReplacesId.is_null())
        .order_by_asc(template_notice::Column::Position)
        .all(connection)
        .await
        .context("loading a template's notices")?
        .into_iter()
        .map(|notice| Notice {
            key: notice.key,
            when: notice.when_condition,
            text: notice.text,
        })
        .collect();

    let mut queries = Vec::new();
    for (query, original) in chosen_parts!(
        template_query,
        reading,
        connection,
        id,
        "a template's queries"
    ) {
        let mut fills = Vec::new();
        for fill in parts!(
            template_fill,
            reading,
            connection,
            QueryId,
            query.id,
            "a query's fills"
        ) {
            let versions = parts!(
                template_fill_version,
                reading,
                connection,
                FillId,
                fill.id,
                "a fill's versions"
            );
            fills.push(Fill {
                key: fill.key,
                versions: versions
                    .into_iter()
                    .map(|version| (version.version, version.sql))
                    .collect(),
                older: fill.older,
            });
        }
        let metrics = parts!(
            template_metric,
            reading,
            connection,
            QueryId,
            query.id,
            "a query's metrics"
        );
        queries.push(Query {
            key: query.key,
            sql: query.sql,
            interval: length(query.interval_secs),
            since: query.since,
            when: query.when_condition,
            enabled: on(original.enabled, original.enabled_choice),
            labels: template_items::query_labels::read(connection, query.id).await?,
            columns: template_items::query_columns::read(connection, query.id).await?,
            fills,
            metrics: to_metrics(connection, metrics).await?,
        });
    }

    let mut counters = Vec::new();
    for (block, original) in chosen_parts!(
        template_counters,
        reading,
        connection,
        id,
        "a template's counters"
    ) {
        let metrics = parts!(
            template_metric,
            reading,
            connection,
            CountersId,
            block.id,
            "counters' metrics"
        );
        counters.push(Counters {
            key: block.key,
            object: block.object,
            label: block.label,
            pattern: block.pattern,
            instance: block.instance,
            exclude: template_items::counters_excludes::read(connection, block.id).await?,
            groups: template_items::counters_groups::read(connection, block.id).await?,
            join: match (block.join_object, block.join_pattern) {
                (None, None) => None,
                (object, pattern) => Some(Join {
                    object: object.unwrap_or_default(),
                    pattern: pattern.unwrap_or_default(),
                }),
            },
            when: block.when_condition,
            since: block.since,
            interval: length(block.interval_secs),
            enabled: on(original.enabled, original.enabled_choice),
            metrics: to_metrics(connection, metrics).await?,
        });
    }

    let alerts = own_rules(connection, id)
        .await?
        .into_iter()
        .map(|rule| Alert {
            key: rule.template_alert.unwrap_or_default(),
            name: rule.name,
            warning: rule.warning,
            critical: rule.critical,
            hold: length((rule.for_secs > 0).then_some(rule.for_secs)),
            window: length(rule.window_secs),
            summary: rule.summary,
            resolved_summary: rule.resolved_summary,
            when: rule.when_condition,
            since: rule.since,
            enabled: rule.enabled,
        })
        .collect();

    let target = match (&row.target_kind, &row.target) {
        (Some(kind), Some(value)) => Target::from_parts(kind, value),
        _ => None,
    };
    Ok(Template {
        key: row.key.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        target,
        applies_to: match reading {
            Reading::AsWritten => row.applies_to.clone(),
            Reading::AsRun => applies_to_of(row),
        },
        min_version: row.min_version.clone(),
        renamed_from: template_items::renames::read(connection, row.id).await?,
        enabled: on(row.enabled, row.enabled_choice),
        services: template_items::services::read(connection, row.id).await?,
        discover,
        notices,
        queries,
        counters,
        alerts,
    })
}

/// A template's own alert rules, in its order: not anyone's copies of them.
async fn own_rules<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Vec<alert_rule::Model>> {
    alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::TemplateId.eq(id))
        .filter(alert_rule::Column::ReplacesId.is_null())
        .order_by_asc(alert_rule::Column::TemplatePosition)
        .all(connection)
        .await
        .context("loading a template's alert rules")
}

/// Someone's copy of a built-in template's rule, if there is one.
async fn copy_of<C: ConnectionTrait>(
    connection: &C,
    original: i64,
) -> Result<Option<alert_rule::Model>> {
    alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::ReplacesId.eq(original))
        .one(connection)
        .await
        .context("loading a rule's copy")
}

async fn to_stored<C: ConnectionTrait>(
    connection: &C,
    row: template::Model,
) -> Result<StoredTemplate> {
    let choices = part_choices(connection, row.id).await?;
    let mut copies = Vec::new();
    if choices.iter().any(|choice| choice.copied) {
        let as_run = read_template(connection, &row, Reading::AsRun).await?;
        for choice in choices.iter().filter(|choice| choice.copied) {
            if let Some((_, part)) = Part::of(&as_run, choice.kind, &choice.key) {
                copies.push(part);
            }
        }
    }
    Ok(StoredTemplate {
        template: read_template(connection, &row, Reading::AsWritten).await?,
        id: row.id,
        origin: Origin::parse(&row.origin)?,
        enabled: row.enabled_choice.unwrap_or(row.enabled),
        enabled_choice: row.enabled_choice,
        applies_to: applies_to_of(&row),
        applies_to_chosen: row.applies_to_chosen,
        host_ids: hosts_given(connection, row.id).await?,
        created_at: row.created_at,
        updated_at: row.updated_at,
        upgraded_at: row.upgraded_at,
        choices,
        copies,
    })
}

/// Writes one row of a template's parts as `$expected` says: over the row that's
/// there for its key if anything of it differs, keeping its ID, or as a new row.
/// Gives the row's ID.
macro_rules! put_part {
    ($entity:ident, $connection:expr, $expected:expr, $existing:expr) => {{
        let expected: $entity::Model = $expected;
        match $existing {
            Some(row) => {
                let row: $entity::Model = row;
                if row != expected {
                    $entity::ActiveModel::from(expected)
                        .reset_all()
                        .update($connection)
                        .await
                        .context("saving a template's part")?;
                }
                row.id
            }
            None => {
                let mut active = $entity::ActiveModel::from(expected).reset_all();
                active.id = sea_orm::ActiveValue::NotSet;
                active
                    .insert($connection)
                    .await
                    .context("saving a template's part")?
                    .id
            }
        }
    }};
}

/// Deletes the rows of a template's parts that it no longer has.
macro_rules! drop_parts {
    ($entity:ident, $connection:expr, $left:expr) => {{
        let gone: Vec<i64> = $left.into_values().map(|row| row.id).collect();
        if !gone.is_empty() {
            $entity::Entity::delete_many()
                .filter($entity::Column::Id.is_in(gone))
                .exec($connection)
                .await
                .context("deleting a template's parts")?;
        }
    }};
}

/// Writes a block's metrics over the ones it has, each matched by its key.
async fn write_metrics<C: ConnectionTrait>(
    connection: &C,
    metrics: &[Metric],
    query: Option<i64>,
    counters: Option<i64>,
) -> Result<()> {
    let mut rows =
        template_metric::Entity::find().filter(template_metric::Column::ReplacesId.is_null());
    rows = match (query, counters) {
        (Some(query), _) => rows.filter(template_metric::Column::QueryId.eq(query)),
        (None, counters) => rows.filter(template_metric::Column::CountersId.eq(counters)),
    };
    let mut left: HashMap<String, template_metric::Model> = rows
        .all(connection)
        .await
        .context("loading a template's metrics")?
        .into_iter()
        .map(|row| (row.key.clone(), row))
        .collect();
    for (position, metric) in metrics.iter().enumerate() {
        let existing = left.remove(&metric.key);
        let expected = template_metric::Model {
            id: existing.as_ref().map_or(0, |row| row.id),
            query_id: query,
            counters_id: counters,
            key: metric.key.clone(),
            position: i32::try_from(position)?,
            title: metric.title.clone(),
            counter: metric.counter.clone(),
            unit: metric.unit.clone(),
            total: metric.total,
            description: metric.description.clone(),
            value: metric.value.clone(),
            since: metric.since.clone(),
            replaces_id: None,
        };
        let metric_id = put_part!(template_metric, connection, expected, existing);
        template_items::metric_states::write(connection, metric_id, &metric.states).await?;
    }
    drop_parts!(template_metric, connection, left);
    Ok(())
}

/// Writes one discover block, over `existing` if it has a row, or as a new row: for
/// a template, or with `replaces` for someone's copy of the template's block. Gives
/// the row's ID.
async fn write_discover<C: ConnectionTrait>(
    connection: &C,
    template_id: i64,
    position: usize,
    discover: &Discover,
    existing: Option<template_discovery::Model>,
    replaces: Option<i64>,
) -> Result<i64> {
    let expected = template_discovery::Model {
        id: existing.as_ref().map_or(0, |row| row.id),
        template_id,
        key: discover.key.clone(),
        position: i32::try_from(position)?,
        interval_secs: secs(&discover.interval)?,
        sql: discover.sql.clone(),
        replaces_id: replaces,
        original_changed_at: existing.as_ref().and_then(|row| row.original_changed_at),
    };
    let discovery = put_part!(template_discovery, connection, expected, existing);
    template_items::counter_sets::write(connection, discovery, &discover.counter_sets).await?;

    let mut reads: HashMap<String, template_registry_read::Model> =
        template_registry_read::Entity::find()
            .filter(template_registry_read::Column::DiscoveryId.eq(discovery))
            .filter(template_registry_read::Column::ReplacesId.is_null())
            .all(connection)
            .await
            .context("loading a template's registry reads")?
            .into_iter()
            .map(|row| (row.key.clone(), row))
            .collect();
    for (position, read) in discover.registry.iter().enumerate() {
        let existing = reads.remove(&read.key);
        let expected = template_registry_read::Model {
            id: existing.as_ref().map_or(0, |row| row.id),
            discovery_id: discovery,
            key: read.key.clone(),
            position: i32::try_from(position)?,
            replaces_id: None,
        };
        let read_id = put_part!(template_registry_read, connection, expected, existing);
        template_items::registry_values::write(connection, read_id, &read.values).await?;
    }
    drop_parts!(template_registry_read, connection, reads);
    Ok(discovery)
}

/// Writes one query, with its fills and metrics, as [`write_discover`] does a
/// discover block. Whether someone chose it on or off is only ever kept on the
/// template's own row, so it stays as it is.
async fn write_query<C: ConnectionTrait>(
    connection: &C,
    template_id: i64,
    position: usize,
    query: &Query,
    existing: Option<template_query::Model>,
    replaces: Option<i64>,
) -> Result<i64> {
    let expected = template_query::Model {
        id: existing.as_ref().map_or(0, |row| row.id),
        template_id,
        key: query.key.clone(),
        position: i32::try_from(position)?,
        sql: query.sql.clone(),
        interval_secs: secs(&query.interval)?,
        since: query.since.clone(),
        when_condition: query.when.clone(),
        enabled: query.enabled,
        enabled_choice: existing.as_ref().and_then(|row| row.enabled_choice),
        replaces_id: replaces,
        original_changed_at: existing.as_ref().and_then(|row| row.original_changed_at),
    };
    let query_id = put_part!(template_query, connection, expected, existing);
    template_items::query_labels::write(connection, query_id, &query.labels).await?;
    template_items::query_columns::write(connection, query_id, &query.columns).await?;

    let mut fills_left: HashMap<String, template_fill::Model> = template_fill::Entity::find()
        .filter(template_fill::Column::QueryId.eq(query_id))
        .filter(template_fill::Column::ReplacesId.is_null())
        .all(connection)
        .await
        .context("loading a query's fills")?
        .into_iter()
        .map(|row| (row.key.clone(), row))
        .collect();
    for (position, fill) in query.fills.iter().enumerate() {
        let existing = fills_left.remove(&fill.key);
        let expected = template_fill::Model {
            id: existing.as_ref().map_or(0, |row| row.id),
            query_id,
            key: fill.key.clone(),
            position: i32::try_from(position)?,
            older: fill.older.clone(),
            replaces_id: None,
        };
        let fill_id = put_part!(template_fill, connection, expected, existing);

        let mut versions_left: HashMap<String, template_fill_version::Model> =
            template_fill_version::Entity::find()
                .filter(template_fill_version::Column::FillId.eq(fill_id))
                .filter(template_fill_version::Column::ReplacesId.is_null())
                .all(connection)
                .await
                .context("loading a fill's versions")?
                .into_iter()
                .map(|row| (row.version.clone(), row))
                .collect();
        for (position, (version, sql)) in fill.versions.iter().enumerate() {
            let existing = versions_left.remove(version);
            let expected = template_fill_version::Model {
                id: existing.as_ref().map_or(0, |row| row.id),
                fill_id,
                version: version.clone(),
                position: i32::try_from(position)?,
                sql: sql.clone(),
                replaces_id: None,
            };
            put_part!(template_fill_version, connection, expected, existing);
        }
        drop_parts!(template_fill_version, connection, versions_left);
    }
    drop_parts!(template_fill, connection, fills_left);
    write_metrics(connection, &query.metrics, Some(query_id), None).await?;
    Ok(query_id)
}

/// Writes one counters block, with its metrics, as [`write_query`] does a query.
async fn write_counters<C: ConnectionTrait>(
    connection: &C,
    template_id: i64,
    position: usize,
    counters: &Counters,
    existing: Option<template_counters::Model>,
    replaces: Option<i64>,
) -> Result<i64> {
    let expected = template_counters::Model {
        id: existing.as_ref().map_or(0, |row| row.id),
        template_id,
        key: counters.key.clone(),
        position: i32::try_from(position)?,
        object: counters.object.clone(),
        label: counters.label.clone(),
        pattern: counters.pattern.clone(),
        instance: counters.instance.clone(),
        join_object: counters.join.as_ref().map(|join| join.object.clone()),
        join_pattern: counters.join.as_ref().map(|join| join.pattern.clone()),
        when_condition: counters.when.clone(),
        since: counters.since.clone(),
        interval_secs: secs(&counters.interval)?,
        enabled: counters.enabled,
        enabled_choice: existing.as_ref().and_then(|row| row.enabled_choice),
        replaces_id: replaces,
        original_changed_at: existing.as_ref().and_then(|row| row.original_changed_at),
    };
    let counters_id = put_part!(template_counters, connection, expected, existing);
    template_items::counters_excludes::write(connection, counters_id, &counters.exclude).await?;
    template_items::counters_groups::write(connection, counters_id, &counters.groups).await?;
    write_metrics(connection, &counters.metrics, None, Some(counters_id)).await?;
    Ok(counters_id)
}

/// The rows of a template's own parts of one kind, but not anyone's copies of
/// them, by key.
macro_rules! own_parts {
    ($entity:ident, $connection:expr, $id:expr, $what:literal) => {{
        let rows: HashMap<String, $entity::Model> = $entity::Entity::find()
            .filter($entity::Column::TemplateId.eq($id))
            .filter($entity::Column::ReplacesId.is_null())
            .all($connection)
            .await
            .context(concat!("loading ", $what))?
            .into_iter()
            .map(|row| (row.key.clone(), row))
            .collect();
        rows
    }};
}

/// Writes a template's parts, but for its alerts, over the ones it has. Each is
/// matched by its key within what it's part of: a row that's still there keeps its
/// ID, so what points at it, whether someone chose it on or off and their copy of
/// it stay, and is only written if something of it changed; new parts are added,
/// and only those the template no longer has are deleted, with any copy of them.
/// A part given another key is a new part.
async fn write_parts<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    template: &Template,
) -> Result<()> {
    template_items::renames::write(connection, id, &template.renamed_from).await?;
    template_items::services::write(connection, id, &template.services).await?;
    let mut left = own_parts!(template_discovery, connection, id, "a template's discovery");
    for (position, discover) in template.discover.iter().enumerate() {
        let existing = left.remove(&discover.key);
        write_discover(connection, id, position, discover, existing, None).await?;
    }
    drop_parts!(template_discovery, connection, left);

    let mut left = own_parts!(template_notice, connection, id, "a template's notices");
    for (position, notice) in template.notices.iter().enumerate() {
        let existing = left.remove(&notice.key);
        let expected = template_notice::Model {
            id: existing.as_ref().map_or(0, |row| row.id),
            template_id: id,
            key: notice.key.clone(),
            position: i32::try_from(position)?,
            when_condition: notice.when.clone(),
            text: notice.text.clone(),
            replaces_id: None,
        };
        put_part!(template_notice, connection, expected, existing);
    }
    drop_parts!(template_notice, connection, left);

    let mut left = own_parts!(template_query, connection, id, "a template's queries");
    for (position, query) in template.queries.iter().enumerate() {
        let existing = left.remove(&query.key);
        write_query(connection, id, position, query, existing, None).await?;
    }
    drop_parts!(template_query, connection, left);

    let mut left = own_parts!(template_counters, connection, id, "a template's counters");
    for (position, counters) in template.counters.iter().enumerate() {
        let existing = left.remove(&counters.key);
        write_counters(connection, id, position, counters, existing, None).await?;
    }
    drop_parts!(template_counters, connection, left);
    Ok(())
}

#[cfg(test)]
impl Database {
    /// See [`part_ids`].
    pub async fn template_part_ids(&self, id: i64) -> std::collections::BTreeMap<String, i64> {
        part_ids(&self.connection, id).await.unwrap()
    }

    /// Whether someone chose a query on or off, which nothing on the pages sets yet.
    pub async fn query_choice(&self, query_id: i64) -> Option<bool> {
        let row = template_query::Entity::find_by_id(query_id)
            .one(&self.connection)
            .await
            .unwrap()
            .unwrap();
        row.enabled_choice
    }

    pub async fn set_query_choice(&self, query_id: i64, choice: Option<bool>) {
        template_query::ActiveModel {
            id: Set(query_id),
            enabled_choice: Set(choice),
            ..Default::default()
        }
        .update(&self.connection)
        .await
        .unwrap();
        self.refresh_catalog().await.unwrap();
    }
}

/// The ID of every row of a template's parts, by what it is and its keys, such as
/// `query sessions` or `query slots fill lost version 17`, for tests to see which
/// rows a change kept.
#[cfg(test)]
async fn part_ids<C: ConnectionTrait>(
    connection: &C,
    id: i64,
) -> Result<std::collections::BTreeMap<String, i64>> {
    let mut ids = std::collections::BTreeMap::new();
    for discovery in template_discovery::Entity::find()
        .filter(template_discovery::Column::TemplateId.eq(id))
        .all(connection)
        .await?
    {
        for row in template_registry_read::Entity::find()
            .filter(template_registry_read::Column::DiscoveryId.eq(discovery.id))
            .all(connection)
            .await?
        {
            ids.insert(
                format!("discover {} registry {}", discovery.key, row.key),
                row.id,
            );
        }
        ids.insert(format!("discover {}", discovery.key), discovery.id);
    }
    for row in template_notice::Entity::find()
        .filter(template_notice::Column::TemplateId.eq(id))
        .all(connection)
        .await?
    {
        ids.insert(format!("notice {}", row.key), row.id);
    }
    for query in template_query::Entity::find()
        .filter(template_query::Column::TemplateId.eq(id))
        .all(connection)
        .await?
    {
        ids.insert(format!("query {}", query.key), query.id);
        for fill in template_fill::Entity::find()
            .filter(template_fill::Column::QueryId.eq(query.id))
            .all(connection)
            .await?
        {
            ids.insert(format!("query {} fill {}", query.key, fill.key), fill.id);
            for version in template_fill_version::Entity::find()
                .filter(template_fill_version::Column::FillId.eq(fill.id))
                .all(connection)
                .await?
            {
                let name = format!(
                    "query {} fill {} version {}",
                    query.key, fill.key, version.version
                );
                ids.insert(name, version.id);
            }
        }
        for metric in template_metric::Entity::find()
            .filter(template_metric::Column::QueryId.eq(query.id))
            .all(connection)
            .await?
        {
            ids.insert(
                format!("query {} metric {}", query.key, metric.key),
                metric.id,
            );
        }
    }
    for counters in template_counters::Entity::find()
        .filter(template_counters::Column::TemplateId.eq(id))
        .all(connection)
        .await?
    {
        ids.insert(format!("counters {}", counters.key), counters.id);
        for metric in template_metric::Entity::find()
            .filter(template_metric::Column::CountersId.eq(counters.id))
            .all(connection)
            .await?
        {
            let name = format!("counters {} metric {}", counters.key, metric.key);
            ids.insert(name, metric.id);
        }
    }
    Ok(ids)
}

/// A template as the audit log compares them: what it says, field by field, and
/// whether it's on.
fn template_snapshot(stored: &StoredTemplate) -> Result<Snapshot> {
    let mut fields = serde_json::to_value(&stored.template).context("recording a template")?;
    fields["enabled"] = json!(stored.enabled);
    fields["origin"] = json!(stored.origin.as_str());
    fields["applies_to"] = json!(stored.applies_to);
    fields["host_ids"] = json!(stored.host_ids);
    if !stored.choices.is_empty() {
        let choices: BTreeMap<String, Option<bool>> = stored
            .choices
            .iter()
            .filter(|choice| choice.enabled_choice.is_some())
            .map(|choice| {
                let name = format!("{} {}", choice.kind.as_str(), choice.key);
                (name, choice.enabled_choice)
            })
            .collect();
        fields["enabled_choices"] = json!(choices);
        fields["copies"] = json!(stored.copies);
    }
    Ok(Snapshot::new(stored.template.name.clone(), fields))
}

/// What someone has made of a template's parts: each that has a copy, or that
/// they chose on or off.
async fn part_choices<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Vec<PartChoice>> {
    let mut choices = Vec::new();
    macro_rules! choices_of {
        ($entity:ident, $kind:expr, $choice:expr) => {{
            let rows = $entity::Entity::find()
                .filter($entity::Column::TemplateId.eq(id))
                .order_by_asc($entity::Column::Position)
                .all(connection)
                .await
                .context("loading a template's parts")?;
            let copies: HashMap<i64, &$entity::Model> = rows
                .iter()
                .filter_map(|row| Some((row.replaces_id?, row)))
                .collect();
            for row in rows.iter().filter(|row| row.replaces_id.is_none()) {
                let copy = copies.get(&row.id);
                let enabled_choice: Option<bool> = $choice(row);
                if copy.is_some() || enabled_choice.is_some() {
                    choices.push(PartChoice {
                        kind: $kind,
                        key: row.key.clone(),
                        copied: copy.is_some(),
                        enabled_choice,
                        original_changed_at: copy.and_then(|copy| copy.original_changed_at),
                    });
                }
            }
        }};
    }
    choices_of!(template_discovery, PartKind::Discover, |_| None);
    choices_of!(
        template_query,
        PartKind::Query,
        |row: &template_query::Model| row.enabled_choice
    );
    choices_of!(
        template_counters,
        PartKind::Counters,
        |row: &template_counters::Model| row.enabled_choice
    );
    Ok(choices)
}

/// Someone's copies of a template's parts that the latest upgrade changed the
/// part of, as `query "sessions"`.
async fn changed_part_copies<C: ConnectionTrait>(
    connection: &C,
    row: &template::Model,
) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    let Some(upgraded_at) = row.upgraded_at else {
        return Ok(changed);
    };
    macro_rules! changed_of {
        ($entity:ident, $kind:expr) => {{
            let copies = $entity::Entity::find()
                .filter($entity::Column::TemplateId.eq(row.id))
                .filter($entity::Column::ReplacesId.is_not_null())
                .filter($entity::Column::OriginalChangedAt.gte(upgraded_at))
                .order_by_asc($entity::Column::Position)
                .all(connection)
                .await
                .context("loading a template's parts")?;
            changed.extend(
                copies
                    .into_iter()
                    .map(|copy| format!("{} {:?}", $kind.as_str(), copy.key)),
            );
        }};
    }
    changed_of!(template_discovery, PartKind::Discover);
    changed_of!(template_query, PartKind::Query);
    changed_of!(template_counters, PartKind::Counters);
    Ok(changed)
}

/// Notes that a template changed now.
async fn touch<C: ConnectionTrait>(connection: &C, id: i64, now: Timestamp) -> Result<()> {
    template::Entity::update_many()
        .col_expr(template::Column::UpdatedAt, Expr::value(now))
        .filter(template::Column::Id.eq(id))
        .exec(connection)
        .await
        .context("saving template")?;
    Ok(())
}

/// Which hosts a template is for by their facts: what someone chose, or what the
/// template says.
fn applies_to_of(row: &template::Model) -> Option<String> {
    match row.applies_to_chosen {
        true => row.applies_to_choice.clone(),
        false => row.applies_to.clone(),
    }
}

/// The hosts given a template by hand.
async fn hosts_given<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Vec<String>> {
    Ok(template_host::Entity::find()
        .filter(template_host::Column::TemplateId.eq(id))
        .order_by_asc(template_host::Column::HostId)
        .all(connection)
        .await
        .context("loading a template's hosts")?
        .into_iter()
        .map(|row| row.host_id)
        .collect())
}

async fn load_template<C: ConnectionTrait>(
    connection: &C,
    id: i64,
) -> Result<Option<StoredTemplate>> {
    let row = template::Entity::find_by_id(id)
        .filter(template::Column::DeletedAt.is_null())
        .one(connection)
        .await
        .context("loading template")?;
    match row {
        Some(row) => to_stored(connection, row).await.map(Some),
        None => Ok(None),
    }
}

async fn record_template<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&Snapshot>,
) -> Result<()> {
    let after = match load_template(connection, id).await? {
        Some(stored) => Some(template_snapshot(&stored)?),
        None => None,
    };
    record_change(connection, Kind::Template, id, before, after.as_ref(), None).await
}

/// A name for a rule moved aside for a built-in template's: `Disk (yours)`, then
/// `Disk (yours 2)` and so on.
async fn free_name<C: ConnectionTrait>(connection: &C, name: &str) -> Result<String> {
    let taken: BTreeSet<String> = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .all(connection)
        .await
        .context("loading alert rules")?
        .into_iter()
        .map(|row| row.name_key)
        .collect();
    let mut candidate = format!("{name} (yours)");
    let mut number = 2;
    while taken.contains(&name_key(&candidate)) {
        candidate = format!("{name} (yours {number})");
        number += 1;
    }
    Ok(candidate)
}

/// Moves any other rule that has `name`, as names are compared, out of the way of a
/// built-in template's alert, under a name of its own. The alert's own rule and
/// someone's copy of it are left.
async fn make_room<C: ConnectionTrait>(connection: &C, name: &str, own: Option<i64>) -> Result<()> {
    let clashing = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::NameKey.eq(name_key(name)))
        .all(connection)
        .await
        .context("loading alert rules")?;
    for row in clashing {
        if Some(row.id) == own || (own.is_some() && row.replaces_id == own) {
            continue;
        }
        let before = match load_alert_rule(connection, row.id).await? {
            Some(rule) => Some(alert_rule_snapshot(connection, &rule).await?),
            None => None,
        };
        let new_name = free_name(connection, &row.name).await?;
        let id = row.id;
        let mut active: alert_rule::ActiveModel = row.into();
        active.name_key = Set(name_key(&new_name));
        active.name = Set(new_name);
        active
            .update(connection)
            .await
            .context("renaming an alert rule")?;
        record_alert_rule(connection, id, before.as_ref()).await?;
    }
    Ok(())
}

/// Writes a template's alerts as its own alert rules. One that's there is written
/// over with what the template says, keeping who it tells and what else people set
/// on it; for a built-in or imported template, whether it's on is kept too, and
/// someone's copy of it is left alone, only noting that what it's a copy of changed.
/// New alerts get rules, and the rules of alerts it no longer has are deleted;
/// someone's copy of one of those becomes an ordinary rule of theirs, and the names
/// of those are given back. A rule in the way of a built-in template's is moved aside, as the
/// server has to start; for any other template it's an error.
async fn write_rules<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    template: &Template,
    origin: Origin,
    now: Timestamp,
) -> Result<Vec<String>> {
    let original = origin.is_original();
    let mut kept = Vec::new();
    let rows = own_rules(connection, id).await?;
    for (position, alert) in template.alerts.iter().enumerate() {
        let theirs = template_values(template, alert)?;
        let position = i32::try_from(position)?;
        let existing = rows
            .iter()
            .find(|row| row.template_alert.as_deref() == Some(alert.key.as_str()));

        if origin == Origin::BuiltIn {
            make_room(connection, &theirs.name, existing.map(|row| row.id)).await?;
        } else {
            let own: Vec<i64> = existing.iter().map(|row| row.id).collect();
            refuse_taken_name(connection, &theirs.name, &own).await?;
        }
        let Some(row) = existing else {
            let mut active = alert_rule_row(&theirs)?;
            active.template_id = Set(Some(id));
            active.template_alert = Set(Some(alert.key.clone()));
            active.template_position = Set(Some(position));
            active.when_condition = Set(alert.when.clone());
            active.since = Set(alert.since.clone());
            let rule_id = alert_rule::Entity::insert(active)
                .exec(connection)
                .await
                .map_err(|error| {
                    let taken = NameTaken::AlertRule(theirs.name.clone());
                    name_taken_or(error, taken, "saving a template's alert rule")
                })?
                .last_insert_id;
            save_links(connection, rule_id, &theirs.channels).await?;
            save_actions(connection, rule_id, &theirs.actions).await?;
            record_alert_rule(connection, rule_id, None).await?;
            continue;
        };

        let hold = theirs.hold.num_seconds();
        let window = theirs.window.map(|window| window.num_seconds());
        let applies_to = match original {
            true => theirs.applies_to.clone(),
            false => row.applies_to.clone(),
        };
        // What the template ships. Someone's own choice is kept beside it.
        let enabled = alert.enabled;
        let says_the_same = row.name == theirs.name
            && row.warning == theirs.warning
            && row.critical == theirs.critical
            && row.summary == theirs.summary
            && row.resolved_summary == theirs.resolved_summary
            && row.for_secs == hold
            && row.window_secs == window
            && row.when_condition == alert.when
            && row.since == alert.since
            && row.applies_to == applies_to;
        let same =
            says_the_same && row.enabled == enabled && row.template_position == Some(position);
        if same {
            continue;
        }
        let before = match load_alert_rule(connection, row.id).await? {
            Some(rule) => Some(alert_rule_snapshot(connection, &rule).await?),
            None => None,
        };
        alert_rule::ActiveModel {
            id: Set(row.id),
            name: Set(theirs.name.clone()),
            name_key: Set(name_key(&theirs.name)),
            warning: Set(theirs.warning.clone()),
            critical: Set(theirs.critical.clone()),
            summary: Set(theirs.summary.clone()),
            resolved_summary: Set(theirs.resolved_summary.clone()),
            for_secs: Set(hold),
            window_secs: Set(window),
            applies_to: Set(applies_to),
            enabled: Set(enabled),
            template_position: Set(Some(position)),
            when_condition: Set(alert.when.clone()),
            since: Set(alert.since.clone()),
            ..Default::default()
        }
        .update(connection)
        .await
        .map_err(|error| {
            let taken = NameTaken::AlertRule(theirs.name.clone());
            name_taken_or(error, taken, "saving a template's alert rule")
        })?;
        record_alert_rule(connection, row.id, before.as_ref()).await?;
        // Someone's copy stays as they made it, and says what it's a copy of changed.
        if !says_the_same && let Some(copy) = copy_of(connection, row.id).await? {
            alert_rule::Entity::update_many()
                .col_expr(alert_rule::Column::OriginalChangedAt, Expr::value(now))
                .col_expr(
                    alert_rule::Column::WhenCondition,
                    Expr::value(alert.when.clone()),
                )
                .col_expr(alert_rule::Column::Since, Expr::value(alert.since.clone()))
                .filter(alert_rule::Column::Id.eq(copy.id))
                .exec(connection)
                .await
                .context("noting a rule's copy")?;
        }
    }
    let gone = rows.iter().filter(|row| {
        !template
            .alerts
            .iter()
            .any(|alert| row.template_alert.as_deref() == Some(alert.key.as_str()))
    });
    for row in gone {
        let copy = copy_of(connection, row.id).await?;
        delete_rule_in(connection, row.id, now).await?;
        // Someone's copy of an alert the template no longer has is theirs to keep,
        // as an ordinary rule, and the notice of the new version says so.
        if let Some(copy) = copy {
            keep_copy(connection, &copy).await?;
            kept.push(copy.name);
        }
    }
    Ok(kept)
}

/// Makes someone's copy of a template's alert, whose original is going, an ordinary
/// rule of theirs.
async fn keep_copy<C: ConnectionTrait>(connection: &C, copy: &alert_rule::Model) -> Result<()> {
    let before = match load_alert_rule(connection, copy.id).await? {
        Some(rule) => Some(alert_rule_snapshot(connection, &rule).await?),
        None => None,
    };
    alert_rule::ActiveModel {
        id: Set(copy.id),
        template_id: Set(None),
        template_alert: Set(None),
        template_position: Set(None),
        replaces_id: Set(None),
        when_condition: Set(None),
        since: Set(None),
        original_changed_at: Set(None),
        ..Default::default()
    }
    .update(connection)
    .await
    .map_err(|error| {
        let taken = NameTaken::AlertRule(copy.name.clone());
        name_taken_or(error, taken, "keeping a copy of a template's alert rule")
    })?;
    record_alert_rule(connection, copy.id, before.as_ref()).await
}

/// Deletes a template, marking it deleted, and its rules with it. People's copies of
/// its alerts stay, as ordinary rules of theirs, and the notice of it going says so.
async fn delete_in<C: ConnectionTrait>(
    connection: &C,
    stored: &StoredTemplate,
    now: Timestamp,
) -> Result<()> {
    let before = template_snapshot(stored)?;
    let mut kept = Vec::new();
    for rule in own_rules(connection, stored.id).await? {
        let copy = copy_of(connection, rule.id).await?;
        delete_rule_in(connection, rule.id, now).await?;
        if let Some(copy) = copy {
            keep_copy(connection, &copy).await?;
            kept.push(copy.name);
        }
    }
    let note = (!kept.is_empty()).then(|| {
        format!(
            "your own copy of {} is kept as a rule of yours",
            kept.join(", ")
        )
    });
    template::Entity::update_many()
        .col_expr(template::Column::UpgradeNote, Expr::value(note))
        .filter(template::Column::Id.eq(stored.id))
        .exec(connection)
        .await
        .context("noting what became of a template's copies")?;
    template::Entity::update_many()
        .col_expr(template::Column::DeletedAt, Expr::value(now))
        .filter(template::Column::Id.eq(stored.id))
        .exec(connection)
        .await
        .context("deleting a template")?;
    record_change(
        connection,
        Kind::Template,
        stored.id,
        Some(&before),
        None,
        None,
    )
    .await
}

/// What a template's own row says of it.
fn described(row: &mut template::ActiveModel, template: &Template) {
    row.key = Set(template.key.clone());
    row.name = Set(template.name.clone());
    row.name_key = Set(name_key(&template.name));
    row.description = Set(template.description.clone());
    row.target_kind = Set(template.target.as_ref().map(|t| t.kind().to_string()));
    row.target = Set(template.target.as_ref().map(Target::value));
    row.applies_to = Set(template.applies_to.clone());
    row.min_version = Set(template.min_version.clone());
}

/// A template's name in use by another template, which is the one unique index on
/// templates left once [`refuse_taken`] has checked the key.
fn taken(error: sea_orm::DbErr, template: &Template) -> anyhow::Error {
    name_taken_or(
        error,
        NameTaken::Template(template.name.clone()),
        "saving a template",
    )
}

/// A key for someone's own template in the way of a built-in one's: `postgres_yours`,
/// then `postgres_yours_2` and so on.
fn free_key(key: &str, taken: &BTreeSet<String>) -> String {
    let mut candidate = format!("{key}_yours");
    let mut number = 2;
    while taken.contains(&candidate) {
        candidate = format!("{key}_yours_{number}");
        number += 1;
    }
    candidate
}

/// Moves someone's own template out of the way of a built-in one with the same key
/// or name, keeping everything it has under a key and name of its own.
async fn move_aside<C: ConnectionTrait>(
    connection: &C,
    built_in: &Template,
    now: Timestamp,
) -> Result<()> {
    let rows = template::Entity::find()
        .filter(template::Column::DeletedAt.is_null())
        .all(connection)
        .await
        .context("loading templates")?;
    let mut keys: BTreeSet<String> = rows.iter().map(|row| row.key.clone()).collect();
    let mut names: BTreeSet<String> = rows.iter().map(|row| row.name_key.clone()).collect();
    let in_the_way = rows.into_iter().filter(|row| {
        row.origin != Origin::BuiltIn.as_str()
            && (row.key == built_in.key || row.name_key == name_key(&built_in.name))
    });
    for row in in_the_way {
        let stored = to_stored(connection, row.clone()).await?;
        let before = template_snapshot(&stored)?;
        let mut active: template::ActiveModel = row.clone().into();
        if row.key == built_in.key {
            let key = free_key(&row.key, &keys);
            keys.insert(key.clone());
            active.key = Set(key);
        }
        if row.name_key == name_key(&built_in.name) {
            let mut name = format!("{} (yours)", row.name);
            let mut number = 2;
            while names.contains(&name_key(&name)) {
                name = format!("{} (yours {number})", row.name);
                number += 1;
            }
            names.insert(name_key(&name));
            active.name_key = Set(name_key(&name));
            active.name = Set(name);
        }
        active.updated_at = Set(now);
        active
            .update(connection)
            .await
            .context("renaming a template")?;
        record_template(connection, stored.id, Some(&before)).await?;
    }
    Ok(())
}

/// Writes a newer version of a built-in or imported template over the one that's
/// there, noting that it changed. Whether it and its alerts are on, and people's
/// copies of its alerts, are left.
async fn rewrite_original<C: ConnectionTrait>(
    connection: &C,
    row: &template::Model,
    template: &Template,
    fingerprint: &str,
    now: Timestamp,
) -> Result<()> {
    let origin = Origin::parse(&row.origin)?;
    let stored = to_stored(connection, row.clone()).await?;
    let before = template_snapshot(&stored)?;
    // Someone's copy of a part this version no longer has goes with it.
    let gone: Vec<String> = stored
        .choices
        .iter()
        .filter(|choice| choice.copied)
        .filter(|choice| Part::of(template, choice.kind, &choice.key).is_none())
        .map(|choice| format!("{} {:?}", choice.kind.as_str(), choice.key))
        .collect();
    let mut active = template::ActiveModel {
        id: Set(row.id),
        fingerprint: Set(Some(fingerprint.to_string())),
        // What it ships. Someone's own choice is kept beside it.
        enabled: Set(template.enabled),
        updated_at: Set(now),
        upgraded_at: Set(Some(now)),
        upgrade_seen: Set(false),
        ..Default::default()
    };
    described(&mut active, template);
    active
        .update(connection)
        .await
        .map_err(|error| taken(error, template))?;
    write_parts(connection, row.id, template).await?;
    note_changed_copies(connection, &stored, template, now).await?;
    let kept = write_rules(connection, row.id, template, origin, now).await?;
    // What the notice of this version adds: copies that are people's own rules now,
    // and copies of parts that went.
    let mut said = Vec::new();
    if !kept.is_empty() {
        said.push(format!(
            "it no longer has {}, so your own copy is now a rule of yours",
            kept.join(", ")
        ));
    }
    if !gone.is_empty() {
        said.push(format!(
            "it no longer has {}, so your own copy went with it",
            gone.join(", ")
        ));
    }
    let note = (!said.is_empty()).then(|| said.join("; "));
    template::Entity::update_many()
        .col_expr(template::Column::UpgradeNote, Expr::value(note))
        .filter(template::Column::Id.eq(row.id))
        .exec(connection)
        .await
        .context("noting what a newer template changed")?;
    record_template(connection, row.id, Some(&before)).await
}

/// Notes on each of someone's copies of a template's parts whose part a newer
/// version, `template`, changed, that it did, as their copy is left as it is.
async fn note_changed_copies<C: ConnectionTrait>(
    connection: &C,
    before: &StoredTemplate,
    template: &Template,
    now: Timestamp,
) -> Result<()> {
    for choice in before.choices.iter().filter(|choice| choice.copied) {
        let (Some((_, mut was)), Some((_, mut now_says))) = (
            Part::of(&before.template, choice.kind, &choice.key),
            Part::of(template, choice.kind, &choice.key),
        ) else {
            continue;
        };
        // Whether it ships on isn't what a copy says.
        was.set_enabled(true);
        now_says.set_enabled(true);
        if was == now_says {
            continue;
        }
        macro_rules! note {
            ($entity:ident) => {{
                let own = $entity::Entity::find()
                    .filter($entity::Column::TemplateId.eq(before.id))
                    .filter($entity::Column::ReplacesId.is_null())
                    .filter($entity::Column::Key.eq(choice.key.clone()))
                    .one(connection)
                    .await
                    .context("loading a template's part")?;
                if let Some(own) = own {
                    $entity::Entity::update_many()
                        .col_expr($entity::Column::OriginalChangedAt, Expr::value(now))
                        .filter($entity::Column::ReplacesId.eq(own.id))
                        .exec(connection)
                        .await
                        .context("noting a part's copy")?;
                }
            }};
        }
        match choice.kind {
            PartKind::Discover => note!(template_discovery),
            PartKind::Query => note!(template_query),
            PartKind::Counters => note!(template_counters),
        }
    }
    Ok(())
}

/// Adds a built-in or imported template, with a notice of it if `noticed`.
async fn add_original<C: ConnectionTrait>(
    connection: &C,
    template: &Template,
    origin: Origin,
    fingerprint: &str,
    noticed: bool,
    now: Timestamp,
) -> Result<i64> {
    let mut active = template::ActiveModel {
        origin: Set(origin.as_str().to_string()),
        fingerprint: Set(Some(fingerprint.to_string())),
        enabled: Set(template.enabled),
        created_at: Set(now),
        updated_at: Set(now),
        upgraded_at: Set(noticed.then_some(now)),
        upgrade_seen: Set(!noticed),
        ..Default::default()
    };
    described(&mut active, template);
    let id = template::Entity::insert(active)
        .exec(connection)
        .await
        .map_err(|error| taken(error, template))?
        .last_insert_id;
    write_parts(connection, id, template).await?;
    write_rules(connection, id, template, origin, now).await?;
    record_template(connection, id, None).await?;
    Ok(id)
}

/// Hands what one rule is watching to another, as someone's copy takes over from a
/// template's rule or gives way to it again: its open alerts, which stay the same
/// alerts and tell nobody, its silences that haven't ended and its maintenance
/// windows.
pub(super) async fn move_rule_state<C: ConnectionTrait>(
    connection: &C,
    from: i64,
    to: i64,
    now: Timestamp,
) -> Result<()> {
    alert::Entity::update_many()
        .col_expr(alert::Column::RuleId, Expr::value(to))
        .filter(alert::Column::RuleId.eq(from))
        .filter(alert::Column::ResolvedAt.is_null())
        .exec(connection)
        .await
        .context("moving a rule's open alerts")?;
    silence::Entity::update_many()
        .col_expr(silence::Column::RuleId, Expr::value(Some(to)))
        .filter(silence::Column::RuleId.eq(from))
        .filter(silence::Column::EndsAt.gt(now))
        .exec(connection)
        .await
        .context("moving a rule's silences")?;
    maintenance_window::Entity::update_many()
        .col_expr(maintenance_window::Column::RuleId, Expr::value(Some(to)))
        .filter(maintenance_window::Column::RuleId.eq(from))
        .exec(connection)
        .await
        .context("moving a rule's maintenance windows")?;
    Ok(())
}

/// What's known of the template a rule is one of the alerts of.
#[derive(Debug, Clone)]
pub struct TemplateRule {
    pub template: StoredTemplate,
    /// The alert's key.
    pub alert: String,
    /// The template's own rule.
    pub original: i64,
    /// Someone's copy of it, for a built-in template, if they've made one.
    pub copy: Option<i64>,
}

async fn template_rule_in<C: ConnectionTrait>(
    connection: &C,
    rule_id: i64,
) -> Result<Option<TemplateRule>> {
    let Some(row) = alert_rule::Entity::find_by_id(rule_id)
        .filter(alert_rule::Column::DeletedAt.is_null())
        .one(connection)
        .await
        .context("loading alert rule")?
    else {
        return Ok(None);
    };
    let (Some(template_id), Some(alert)) = (row.template_id, row.template_alert.clone()) else {
        return Ok(None);
    };
    let template = load_template(connection, template_id)
        .await?
        .context("a rule's template went missing")?;
    let (original, copy) = match row.replaces_id {
        Some(original) => (original, Some(row.id)),
        None => (
            row.id,
            copy_of(connection, row.id).await?.map(|copy| copy.id),
        ),
    };
    Ok(Some(TemplateRule {
        template,
        alert,
        original,
        copy,
    }))
}

impl Database {
    /// Writes the templates this version ships over the built-in ones: adding new
    /// ones, rewriting changed ones, following renames, and deleting those no longer
    /// shipped. Whether each template and alert is on, and people's copies of their
    /// alerts, stay. Someone's own template with a built-in one's key or name is
    /// moved aside, as is any rule in the way of a built-in one's. Gives the names of
    /// the templates this changed, which on a new server is none.
    pub async fn sync_templates(&self, shipped: &[BuiltIn], now: Timestamp) -> Result<Vec<String>> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("updating built-in templates")?;
        let rows = template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .filter(template::Column::Origin.eq(Origin::BuiltIn.as_str()))
            .all(&transaction)
            .await
            .context("loading templates")?;
        // A server's first start adds the built-in templates without a notice.
        let upgrading = !rows.is_empty();
        let mut changed = Vec::new();
        let mut kept = BTreeSet::new();

        for built_in in shipped {
            let template = &built_in.template;
            let existing = rows.iter().find(|row| row.key == template.key).or_else(|| {
                rows.iter()
                    .find(|row| template.renamed_from.contains(&row.key))
            });
            if let Some(row) = existing {
                kept.insert(row.id);
            }
            let same = existing.is_some_and(|row| {
                row.key == template.key
                    && row.fingerprint.as_deref() == Some(built_in.fingerprint.as_str())
            });
            if same {
                continue;
            }
            move_aside(&transaction, template, now).await?;
            let id = match existing {
                Some(row) => {
                    rewrite_original(&transaction, row, template, &built_in.fingerprint, now)
                        .await?;
                    changed.push(template.name.clone());
                    row.id
                }
                None => {
                    let id = add_original(
                        &transaction,
                        template,
                        Origin::BuiltIn,
                        &built_in.fingerprint,
                        upgrading,
                        now,
                    )
                    .await?;
                    if upgrading {
                        changed.push(template.name.clone());
                    }
                    id
                }
            };
            kept.insert(id);
        }

        for row in rows.iter().filter(|row| !kept.contains(&row.id)) {
            let stored = to_stored(&transaction, row.clone()).await?;
            // Kept unseen, so the notice says it went.
            template::Entity::update_many()
                .col_expr(template::Column::UpgradeSeen, Expr::value(false))
                .filter(template::Column::Id.eq(row.id))
                .exec(&transaction)
                .await
                .context("updating a template")?;
            delete_in(&transaction, &stored, now).await?;
            changed.push(stored.template.name);
        }

        transaction
            .commit()
            .await
            .context("updating built-in templates")?;
        self.refresh_catalog().await?;
        Ok(changed)
    }

    /// What importing `template` would do, or why it can't be imported: its key or
    /// name is a built-in template's, or one of people's own.
    pub async fn import_outcome(&self, template: &Template) -> Result<Imported> {
        import_outcome_in(&self.connection, template)
            .await
            .map(|(outcome, _)| outcome)
    }

    /// Imports a template, checked already: adds it, or writes it over the one of
    /// the same key imported before, as an upgrade does a built-in one, keeping
    /// what's turned off and people's copies of its alerts.
    pub async fn import_template(
        &self,
        template: &Template,
        now: Timestamp,
    ) -> Result<(i64, Imported)> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("importing template")?;
        let (outcome, existing) = import_outcome_in(&transaction, template).await?;
        let fingerprint = crate::templates::built_in::fingerprint(template);
        let id = match (outcome, existing) {
            (Imported::Unchanged, Some(row)) => return Ok((row.id, outcome)),
            (_, Some(row)) => {
                rewrite_original(&transaction, &row, template, &fingerprint, now).await?;
                row.id
            }
            (_, None) => {
                add_original(
                    &transaction,
                    template,
                    Origin::Imported,
                    &fingerprint,
                    false,
                    now,
                )
                .await?
            }
        };
        transaction.commit().await.context("importing template")?;
        self.refresh_catalog().await?;
        Ok((id, outcome))
    }

    /// Makes the catalog of metrics again from the templates there are now, each as
    /// it runs, and says again which hosts each is for, telling agents' connections.
    /// Everything here that changes a template, turns one or a part of one on or off,
    /// or changes which hosts it's for, ends with this, so nothing waits for a restart.
    pub async fn refresh_catalog(&self) -> Result<()> {
        let rows = template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .order_by_asc(template::Column::Id)
            .all(&self.connection)
            .await
            .context("loading templates")?;
        let mut given: HashMap<i64, BTreeSet<String>> = HashMap::new();
        for row in template_host::Entity::find()
            .all(&self.connection)
            .await
            .context("loading templates' hosts")?
        {
            given
                .entry(row.template_id)
                .or_default()
                .insert(row.host_id);
        }
        let mut templates = Vec::with_capacity(rows.len());
        for row in &rows {
            templates.push(Running {
                id: row.id,
                template: read_template(&self.connection, row, Reading::AsRun).await?,
                host_ids: given.remove(&row.id).unwrap_or_default(),
            });
        }
        self.catalog.set(Catalog::with_templates(
            templates.iter().map(|t| &t.template),
        ));
        self.templates.set(RunningTemplates::new(templates));
        self.template_changes.send_modify(|revision| *revision += 1);
        Ok(())
    }

    /// Built-in, imported and people's own, sorted by name.
    pub async fn list_templates(&self) -> Result<Vec<StoredTemplate>> {
        let rows = template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .order_by_asc(template::Column::Name)
            .all(&self.connection)
            .await
            .context("loading templates")?;
        let mut all = Vec::with_capacity(rows.len());
        for row in rows {
            all.push(to_stored(&self.connection, row).await?);
        }
        Ok(all)
    }

    /// Each template's name by its ID.
    pub async fn template_names(&self) -> Result<std::collections::BTreeMap<i64, String>> {
        let rows: Vec<(i64, String)> = {
            use sea_orm::QuerySelect;
            template::Entity::find()
                .select_only()
                .column(template::Column::Id)
                .column(template::Column::Name)
                .filter(template::Column::DeletedAt.is_null())
                .into_tuple()
                .all(&self.connection)
                .await
                .context("loading templates")?
        };
        Ok(rows.into_iter().collect())
    }

    pub async fn get_template(&self, id: i64) -> Result<Option<StoredTemplate>> {
        load_template(&self.connection, id).await
    }

    /// A template's alerts, in its order, each with its own rule and someone's copy
    /// of it if there is one.
    pub async fn template_alerts(&self, id: i64) -> Result<Vec<TemplateAlert>> {
        let mut alerts = Vec::new();
        for row in own_rules(&self.connection, id).await? {
            let catalog = self.catalog();
            let rule = load_alert_rule(&self.connection, row.id)
                .await?
                .context("a template's rule went missing")?
                .read(&catalog);
            let copy = match copy_of(&self.connection, row.id).await? {
                Some(copy) => load_alert_rule(&self.connection, copy.id)
                    .await?
                    .map(|copy| copy.read(&catalog)),
                None => None,
            };
            alerts.push(TemplateAlert {
                key: row.template_alert.unwrap_or_default(),
                rule,
                copy,
            });
        }
        Ok(alerts)
    }

    /// Adds someone's own template, checked already, with its alerts as rules.
    pub async fn create_template(&self, template: &Template, now: Timestamp) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving template")?;
        refuse_taken(&transaction, template, None).await?;
        let mut active = template::ActiveModel {
            origin: Set(Origin::Own.as_str().to_string()),
            enabled: Set(template.enabled),
            created_at: Set(now),
            updated_at: Set(now),
            upgrade_seen: Set(true),
            ..Default::default()
        };
        described(&mut active, template);
        let id = template::Entity::insert(active)
            .exec(&transaction)
            .await
            .map_err(|error| taken(error, template))?
            .last_insert_id;
        write_parts(&transaction, id, template).await?;
        write_rules(&transaction, id, template, Origin::Own, now).await?;
        record_template(&transaction, id, None).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(id)
    }

    /// Replaces someone's own template, checked already. The alerts it still has
    /// keep their rules, with who each tells. Returns false if there's no such
    /// template.
    pub async fn update_template(
        &self,
        id: i64,
        template: &Template,
        now: Timestamp,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        if stored.origin.is_original() {
            bail!(Refused(match stored.origin {
                Origin::Imported => "an imported template can't be changed, as importing a newer version replaces it: disable it, or change its alerts".to_string(),
                _ => "a built-in template can't be changed, as upgrades replace it: disable it, or change its alerts".to_string(),
            }));
        }
        refuse_taken(&transaction, template, Some(id)).await?;
        let before = template_snapshot(&stored)?;
        let mut active = template::ActiveModel {
            id: Set(id),
            enabled: Set(template.enabled),
            updated_at: Set(now),
            ..Default::default()
        };
        described(&mut active, template);
        active
            .update(&transaction)
            .await
            .map_err(|error| taken(error, template))?;
        write_parts(&transaction, id, template).await?;
        write_rules(&transaction, id, template, Origin::Own, now).await?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// Deletes someone's own template and its alert rules. Returns false if there's
    /// no such template.
    pub async fn delete_template(&self, id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        if stored.origin == Origin::BuiltIn {
            bail!(Refused(
                "a built-in template can't be deleted, but it can be disabled".to_string()
            ));
        }
        delete_in(&transaction, &stored, now).await?;
        transaction.commit().await.context("deleting template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// Turns a template, and so its alerts, on or off, which starting never undoes.
    /// Returns false if there's no such template.
    pub async fn set_template_enabled(
        &self,
        id: i64,
        enabled: bool,
        now: Timestamp,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        let before = template_snapshot(&stored)?;
        // For a built-in or imported one it's their choice, kept beside what it
        // ships; their own is simply changed.
        let mut active = template::ActiveModel {
            id: Set(id),
            updated_at: Set(now),
            ..Default::default()
        };
        match stored.origin.is_original() {
            true => active.enabled_choice = Set(Some(enabled)),
            false => active.enabled = Set(enabled),
        }
        active
            .update(&transaction)
            .await
            .context("saving template")?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// Goes back to following whether a built-in or imported template ships on,
    /// forgetting what someone chose. Returns false if there's no such template.
    pub async fn follow_template_enabled(&self, id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        let before = template_snapshot(&stored)?;
        template::ActiveModel {
            id: Set(id),
            enabled_choice: Set(None),
            updated_at: Set(now),
            ..Default::default()
        }
        .update(&transaction)
        .await
        .context("saving template")?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// Says which hosts a template is for: those `applies_to` picks by their facts,
    /// and `host_ids` given it by hand. For a built-in or imported template the
    /// condition is someone's choice, kept beside what the template says, and
    /// choosing what it says again goes back to following it. Returns false if
    /// there's no such template.
    pub async fn set_template_hosts(
        &self,
        id: i64,
        applies_to: Option<String>,
        host_ids: &BTreeSet<String>,
        now: Timestamp,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        let before = template_snapshot(&stored)?;
        let mut active = template::ActiveModel {
            id: Set(id),
            updated_at: Set(now),
            ..Default::default()
        };
        match stored.origin.is_original() {
            true => {
                // Choosing what it ships goes back to following it.
                let chosen = applies_to != stored.template.applies_to;
                active.applies_to_chosen = Set(chosen);
                active.applies_to_choice = Set(applies_to.filter(|_| chosen));
            }
            false => active.applies_to = Set(applies_to),
        }
        active
            .update(&transaction)
            .await
            .context("saving template")?;
        template_host::Entity::delete_many()
            .filter(template_host::Column::TemplateId.eq(id))
            .exec(&transaction)
            .await
            .context("saving a template's hosts")?;
        if !host_ids.is_empty() {
            template_host::Entity::insert_many(host_ids.iter().map(|host_id| {
                template_host::ActiveModel {
                    template_id: Set(id),
                    host_id: Set(host_id.clone()),
                    ..Default::default()
                }
            }))
            .exec(&transaction)
            .await
            .context("saving a template's hosts")?;
        }
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// The templates as they run, each with which hosts it's for.
    pub fn running_templates(&self) -> std::sync::Arc<RunningTemplates> {
        self.templates.get()
    }

    /// Told each time a template, or which hosts one is for, changes.
    pub fn template_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.template_changes.subscribe()
    }

    /// The template a rule is one of the alerts of, whether it's the template's own
    /// rule or someone's copy. None for a rule that isn't a template's.
    pub async fn template_rule(&self, rule_id: i64) -> Result<Option<TemplateRule>> {
        template_rule_in(&self.connection, rule_id).await
    }

    /// Saves one of a template's alerts as `wanted`. For someone's own template, or
    /// a copy that's there, it's written over. For a built-in template's own rule,
    /// which isn't theirs to change, the first change makes a copy of their own,
    /// used in its place from then on; turning it on or off and nothing else is
    /// only the flag on the built-in rule. Returns false if there's no such rule.
    pub async fn update_template_rule(
        &self,
        rule_id: i64,
        wanted: &AlertRuleInput,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let Some(found) = template_rule_in(&transaction, rule_id).await? else {
            return Ok(false);
        };
        if wanted.is_calculation() {
            bail!(Refused(
                "a template's alert is about each host, so it can't have a calculation".to_string()
            ));
        }
        let original = alert_rule::Entity::find_by_id(found.original)
            .one(&transaction)
            .await
            .context("loading alert rule")?
            .context("a template's rule went missing")?;
        let own = [found.original, found.copy.unwrap_or(found.original)];
        refuse_taken_name(&transaction, &wanted.name, &own).await?;

        let target = match (found.template.origin.is_original(), found.copy) {
            (false, _) => found.original,
            (true, Some(copy)) => copy,
            (true, None) => {
                let theirs = load_alert_rule(&transaction, found.original)
                    .await?
                    .context("a template's rule went missing")?;
                let mut same_but_on = wanted.clone();
                same_but_on.enabled = theirs.rule.enabled;
                same_but_on.channels.sort_unstable();
                let mut theirs_sorted = theirs.rule.clone();
                theirs_sorted.channels.sort_unstable();
                if same_but_on == theirs_sorted {
                    if wanted.enabled != theirs.rule.enabled {
                        let before = alert_rule_snapshot(&transaction, &theirs).await?;
                        alert_rule::Entity::update_many()
                            .col_expr(
                                alert_rule::Column::EnabledChoice,
                                Expr::value(Some(wanted.enabled)),
                            )
                            .filter(alert_rule::Column::Id.eq(found.original))
                            .exec(&transaction)
                            .await
                            .context("saving alert rule")?;
                        record_alert_rule(&transaction, found.original, Some(&before)).await?;
                    }
                    transaction.commit().await.context("saving alert rule")?;
                    return Ok(true);
                }
                let mut active = alert_rule_row(wanted)?;
                active.template_id = Set(original.template_id);
                active.template_alert = Set(original.template_alert.clone());
                active.template_position = Set(original.template_position);
                active.when_condition = Set(original.when_condition.clone());
                active.since = Set(original.since.clone());
                active.replaces_id = Set(Some(found.original));
                let copy = alert_rule::Entity::insert(active)
                    .exec(&transaction)
                    .await
                    .context("saving a copy of a template's alert rule")?
                    .last_insert_id;
                save_links(&transaction, copy, &wanted.channels).await?;
                save_actions(&transaction, copy, &wanted.actions).await?;
                record_alert_rule(&transaction, copy, None).await?;
                // The problems it's watching carry on under the copy.
                move_rule_state(&transaction, found.original, copy, crate::times::now()).await?;
                transaction.commit().await.context("saving alert rule")?;
                return Ok(true);
            }
        };
        write_rule_in(&transaction, target, wanted).await?;
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// Puts one of a built-in or imported template's alerts back to the template's
    /// own: deletes someone's copy of it, handing what the copy was watching back,
    /// and forgets whether they chose it on or off. Returns false if there's no such
    /// rule, or nothing of theirs to put back.
    pub async fn reset_template_rule(&self, rule_id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let Some(found) = template_rule_in(&transaction, rule_id).await? else {
            return Ok(false);
        };
        let original = alert_rule::Entity::find_by_id(found.original)
            .one(&transaction)
            .await
            .context("loading alert rule")?
            .context("a template's rule went missing")?;
        if found.copy.is_none() && original.enabled_choice.is_none() {
            return Ok(false);
        }
        if let Some(copy) = found.copy {
            // The problems it's watching carry on under the template's own rule.
            move_rule_state(&transaction, copy, found.original, now).await?;
            delete_rule_in(&transaction, copy, now).await?;
        }
        if original.enabled_choice.is_some() {
            let before = match load_alert_rule(&transaction, found.original).await? {
                Some(rule) => Some(alert_rule_snapshot(&transaction, &rule).await?),
                None => None,
            };
            alert_rule::Entity::update_many()
                .col_expr(alert_rule::Column::EnabledChoice, Expr::value(None::<bool>))
                .filter(alert_rule::Column::Id.eq(found.original))
                .exec(&transaction)
                .await
                .context("saving alert rule")?;
            record_alert_rule(&transaction, found.original, before.as_ref()).await?;
        }
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// A template as it runs: someone's copies of its parts in their place, and
    /// each part on or off as they chose.
    pub async fn template_as_run(&self, id: i64) -> Result<Option<Template>> {
        let row = template::Entity::find_by_id(id)
            .filter(template::Column::DeletedAt.is_null())
            .one(&self.connection)
            .await
            .context("loading template")?;
        match row {
            Some(row) => Ok(Some(
                read_template(&self.connection, &row, Reading::AsRun).await?,
            )),
            None => Ok(None),
        }
    }

    /// Saves one of a template's discover blocks, queries or counters blocks as
    /// `part` says, found by its kind and key, checked in the template already.
    /// Someone's own template has it changed in place. A built-in or imported one
    /// isn't theirs to change, so the first change makes a copy of their own, used
    /// in its place from then on, and later ones change the copy; saving what the
    /// template's own part says deletes the copy. Whether it's on stays as it is.
    /// Returns false if there's no such template or part.
    pub async fn save_template_part(&self, id: i64, part: Part, now: Timestamp) -> Result<bool> {
        let Some(stored) = self.get_template(id).await? else {
            return Ok(false);
        };
        let Some((_, original)) = Part::of(&stored.template, part.kind(), part.key()) else {
            return Ok(false);
        };
        let mut part = part;
        part.set_enabled(original.enabled());
        if !stored.origin.is_original() {
            let mut template = stored.template.clone();
            part.put_in(&mut template);
            return self.update_template(id, &template, now).await;
        }
        let transaction = self.connection.begin().await.context("saving template")?;
        let before = template_snapshot(&stored)?;
        let same = part == original;
        macro_rules! copy_of_part {
            ($entity:ident, $write:ident, $value:expr) => {{
                let own = $entity::Entity::find()
                    .filter($entity::Column::TemplateId.eq(id))
                    .filter($entity::Column::ReplacesId.is_null())
                    .filter($entity::Column::Key.eq(part.key()))
                    .one(&transaction)
                    .await
                    .context("loading a template's part")?
                    .context("a template's part went missing")?;
                let copy = $entity::Entity::find()
                    .filter($entity::Column::ReplacesId.eq(own.id))
                    .one(&transaction)
                    .await
                    .context("loading a template's part")?;
                match (same, copy) {
                    (true, Some(copy)) => {
                        $entity::Entity::delete_by_id(copy.id)
                            .exec(&transaction)
                            .await
                            .context("deleting a copy of a template's part")?;
                    }
                    (true, None) => {}
                    (false, copy) => {
                        let position = usize::try_from(own.position)?;
                        $write(&transaction, id, position, $value, copy, Some(own.id)).await?;
                    }
                }
            }};
        }
        match &part {
            Part::Discover(discover) => {
                copy_of_part!(template_discovery, write_discover, discover);
            }
            Part::Query(query) => copy_of_part!(template_query, write_query, query),
            Part::Counters(counters) => {
                copy_of_part!(template_counters, write_counters, counters);
            }
        }
        touch(&transaction, id, now).await?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// Turns one of a template's queries or counters blocks on or off: for a
    /// built-in or imported template it's someone's choice, kept beside what the
    /// template says, which upgrades leave alone; their own is simply changed.
    /// Returns false if there's no such template or part.
    pub async fn set_template_part_enabled(
        &self,
        id: i64,
        kind: PartKind,
        key: &str,
        enabled: bool,
        now: Timestamp,
    ) -> Result<bool> {
        if !kind.turns_off() {
            bail!(Refused(
                "a discover block can't be turned off, as what it finds is waited on: change it instead"
                    .to_string()
            ));
        }
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        if Part::of(&stored.template, kind, key).is_none() {
            return Ok(false);
        }
        let before = template_snapshot(&stored)?;
        let original = stored.origin.is_original();
        macro_rules! turn {
            ($entity:ident) => {{
                let update = $entity::Entity::update_many();
                let update = match original {
                    true => {
                        update.col_expr($entity::Column::EnabledChoice, Expr::value(Some(enabled)))
                    }
                    false => update.col_expr($entity::Column::Enabled, Expr::value(enabled)),
                };
                update
                    .filter($entity::Column::TemplateId.eq(id))
                    .filter($entity::Column::ReplacesId.is_null())
                    .filter($entity::Column::Key.eq(key))
                    .exec(&transaction)
                    .await
                    .context("saving a template's part")?;
            }};
        }
        match kind {
            PartKind::Query => turn!(template_query),
            PartKind::Counters => turn!(template_counters),
            PartKind::Discover => unreachable!("refused above"),
        }
        touch(&transaction, id, now).await?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// Puts one of a built-in or imported template's parts back to the template's
    /// own: deletes someone's copy of it, and forgets whether they chose it on or
    /// off. Returns false if there's no such part, or nothing of theirs to put back.
    pub async fn reset_template_part(
        &self,
        id: i64,
        kind: PartKind,
        key: &str,
        now: Timestamp,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        let Some(choice) = stored
            .choices
            .iter()
            .find(|choice| choice.kind == kind && choice.key == key)
        else {
            return Ok(false);
        };
        let copied = choice.copied;
        let before = template_snapshot(&stored)?;
        macro_rules! reset {
            ($entity:ident, $clear:expr) => {{
                let own = $entity::Entity::find()
                    .filter($entity::Column::TemplateId.eq(id))
                    .filter($entity::Column::ReplacesId.is_null())
                    .filter($entity::Column::Key.eq(key))
                    .one(&transaction)
                    .await
                    .context("loading a template's part")?
                    .context("a template's part went missing")?;
                if copied {
                    $entity::Entity::delete_many()
                        .filter($entity::Column::ReplacesId.eq(own.id))
                        .exec(&transaction)
                        .await
                        .context("deleting a copy of a template's part")?;
                }
                $clear(own.id).await?;
            }};
        }
        let none = |_: i64| async { anyhow::Ok(()) };
        match kind {
            PartKind::Discover => reset!(template_discovery, none),
            PartKind::Query => reset!(template_query, |own: i64| {
                template_query::Entity::update_many()
                    .col_expr(
                        template_query::Column::EnabledChoice,
                        Expr::value(None::<bool>),
                    )
                    .filter(template_query::Column::Id.eq(own))
                    .exec(&transaction)
            }),
            PartKind::Counters => reset!(template_counters, |own: i64| {
                template_counters::Entity::update_many()
                    .col_expr(
                        template_counters::Column::EnabledChoice,
                        Expr::value(None::<bool>),
                    )
                    .filter(template_counters::Column::Id.eq(own))
                    .exec(&transaction)
            }),
        }
        touch(&transaction, id, now).await?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        self.refresh_catalog().await?;
        Ok(true)
    }

    /// What admins haven't dismissed of what an upgrade changed in the built-in
    /// templates: each one's name, with the alerts people have copies of that it
    /// changed under them.
    pub async fn template_upgrades(&self) -> Result<Vec<String>> {
        let rows = template::Entity::find()
            .filter(template::Column::Origin.ne(Origin::Own.as_str()))
            .filter(template::Column::UpgradeSeen.eq(false))
            .order_by_asc(template::Column::Name)
            .all(&self.connection)
            .await
            .context("loading templates")?;
        let mut notices = Vec::new();
        for row in rows {
            if row.deleted_at.is_some() {
                notices.push(match &row.upgrade_note {
                    Some(note) => format!("{} (removed; {note})", row.name),
                    None => format!("{} (removed)", row.name),
                });
                continue;
            }
            let copies: Vec<String> = alert_rule::Entity::find()
                .filter(alert_rule::Column::DeletedAt.is_null())
                .filter(alert_rule::Column::TemplateId.eq(row.id))
                .filter(alert_rule::Column::ReplacesId.is_not_null())
                .filter(alert_rule::Column::OriginalChangedAt.gte(row.upgraded_at))
                .order_by_asc(alert_rule::Column::Name)
                .all(&self.connection)
                .await
                .context("loading alert rules")?
                .into_iter()
                .map(|copy| copy.name)
                .collect();
            let mut copies = copies;
            copies.extend(changed_part_copies(&self.connection, &row).await?);
            let mut said = Vec::new();
            if !copies.is_empty() {
                said.push(format!(
                    "its version of {} changed, which you have your own of",
                    copies.join(", ")
                ));
            }
            said.extend(row.upgrade_note.clone());
            notices.push(match said.is_empty() {
                true => row.name,
                false => format!("{} ({})", row.name, said.join("; ")),
            });
        }
        Ok(notices)
    }

    /// Dismisses the notice of what an upgrade changed in the built-in templates.
    pub async fn dismiss_template_upgrades(&self) -> Result<()> {
        template::Entity::update_many()
            .col_expr(template::Column::UpgradeSeen, Expr::value(true))
            .filter(template::Column::UpgradeSeen.eq(false))
            .exec(&self.connection)
            .await
            .context("saving templates")?;
        Ok(())
    }
}

async fn import_outcome_in<C: ConnectionTrait>(
    connection: &C,
    template: &Template,
) -> Result<(Imported, Option<template::Model>)> {
    let live = template::Entity::find()
        .filter(template::Column::DeletedAt.is_null())
        .all(connection)
        .await
        .context("loading templates")?;
    let key = name_key(&template.name);
    for row in &live {
        let same_key = row.key == template.key;
        let same_name = row.name_key == key;
        match Origin::parse(&row.origin)? {
            Origin::BuiltIn if same_key => bail!(Refused(format!(
                "{:?} is the key of the built-in template {}, so a template can't be imported under it",
                template.key, row.name
            ))),
            Origin::BuiltIn if same_name => bail!(Refused(format!(
                "{:?} is the name of a built-in template, so a template can't be imported under it",
                template.name
            ))),
            Origin::Own if same_key => bail!(Refused(format!(
                "{:?} is the key of your own template {}: delete or rename that first",
                template.key, row.name
            ))),
            _ if same_name && !same_key => bail!(NameTaken::Template(template.name.clone())),
            _ => {}
        }
    }
    let existing = live.into_iter().find(|row| row.key == template.key);
    let fingerprint = crate::templates::built_in::fingerprint(template);
    let outcome = match &existing {
        None => Imported::Added,
        Some(row) if row.fingerprint.as_deref() == Some(fingerprint.as_str()) => {
            Imported::Unchanged
        }
        Some(_) => Imported::Updated,
    };
    Ok((outcome, existing))
}

/// Someone's own template can't have a key another template has, built-in or not.
async fn refuse_taken<C: ConnectionTrait>(
    connection: &C,
    template: &Template,
    except: Option<i64>,
) -> Result<()> {
    let mut same_key = template::Entity::find()
        .filter(template::Column::DeletedAt.is_null())
        .filter(template::Column::Key.eq(template.key.clone()));
    if let Some(except) = except {
        same_key = same_key.filter(template::Column::Id.ne(except));
    }
    if same_key
        .one(connection)
        .await
        .context("loading templates")?
        .is_some()
    {
        bail!(NameTaken::TemplateKey(template.key.clone()));
    }
    Ok(())
}
