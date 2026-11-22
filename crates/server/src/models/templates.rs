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

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use serde::Serialize;
use serde_json::{Value, json};

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
    Database, alert_rule, name_key, name_taken_or, template, template_counters, template_discovery,
    template_fill, template_fill_version, template_metric, template_notice, template_query,
    template_registry_read,
};
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::audit::{Kind, Snapshot};
use crate::templates::built_in::BuiltIn;
use crate::templates::{Refused, alert_rule as template_values, local_metrics};
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
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// When an upgrade last changed it, for a built-in one.
    pub upgraded_at: Option<Timestamp>,
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

fn text_list(value: &Option<Value>) -> Vec<String> {
    value
        .as_ref()
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn text_map(value: &Option<Value>) -> IndexMap<String, String> {
    value
        .as_ref()
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn list_json(values: &[String]) -> Option<Value> {
    (!values.is_empty()).then(|| json!(values))
}

fn map_json(values: &IndexMap<String, String>) -> Option<Value> {
    (!values.is_empty()).then(|| json!(values))
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

fn to_metric(row: template_metric::Model) -> Metric {
    Metric {
        key: row.key,
        counter: row.counter,
        unit: row.unit,
        total: row.total,
        description: row.description,
        value: row.value,
        since: row.since,
        states: text_map(&row.states),
    }
}

/// The template a row and its parts' rows say. Copies of parts are someone's own,
/// and aren't the template's.
async fn read_template<C: ConnectionTrait>(
    connection: &C,
    row: &template::Model,
) -> Result<Template> {
    let id = row.id;
    let discover = template_discovery::Entity::find()
        .filter(template_discovery::Column::TemplateId.eq(id))
        .filter(template_discovery::Column::ReplacesId.is_null())
        .one(connection)
        .await
        .context("loading a template's discovery")?;
    let registry = template_registry_read::Entity::find()
        .filter(template_registry_read::Column::TemplateId.eq(id))
        .filter(template_registry_read::Column::ReplacesId.is_null())
        .order_by_asc(template_registry_read::Column::Position)
        .all(connection)
        .await
        .context("loading a template's registry reads")?;
    let discover = discover.map(|found| Discover {
        interval: length(found.interval_secs),
        sql: found.sql,
        registry: registry
            .into_iter()
            .map(|read| RegistryRead {
                key: read.key,
                values: text_map(&Some(read.value_names)),
            })
            .collect(),
        counter_sets: text_map(&found.counter_sets),
    });

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
    for query in template_query::Entity::find()
        .filter(template_query::Column::TemplateId.eq(id))
        .filter(template_query::Column::ReplacesId.is_null())
        .order_by_asc(template_query::Column::Position)
        .all(connection)
        .await
        .context("loading a template's queries")?
    {
        let mut fills = Vec::new();
        for fill in template_fill::Entity::find()
            .filter(template_fill::Column::QueryId.eq(query.id))
            .filter(template_fill::Column::ReplacesId.is_null())
            .order_by_asc(template_fill::Column::Position)
            .all(connection)
            .await
            .context("loading a query's fills")?
        {
            let versions = template_fill_version::Entity::find()
                .filter(template_fill_version::Column::FillId.eq(fill.id))
                .filter(template_fill_version::Column::ReplacesId.is_null())
                .order_by_asc(template_fill_version::Column::Position)
                .all(connection)
                .await
                .context("loading a fill's versions")?;
            fills.push(Fill {
                key: fill.key,
                versions: versions
                    .into_iter()
                    .map(|version| (version.version, version.sql))
                    .collect(),
                older: fill.older,
            });
        }
        let metrics = template_metric::Entity::find()
            .filter(template_metric::Column::QueryId.eq(query.id))
            .filter(template_metric::Column::ReplacesId.is_null())
            .order_by_asc(template_metric::Column::Position)
            .all(connection)
            .await
            .context("loading a query's metrics")?;
        queries.push(Query {
            key: query.key,
            sql: query.sql,
            interval: length(query.interval_secs),
            since: query.since,
            when: query.when_condition,
            enabled: query.enabled,
            labels: text_list(&query.labels),
            fills,
            metrics: metrics.into_iter().map(to_metric).collect(),
        });
    }

    let mut counters = Vec::new();
    for block in template_counters::Entity::find()
        .filter(template_counters::Column::TemplateId.eq(id))
        .filter(template_counters::Column::ReplacesId.is_null())
        .order_by_asc(template_counters::Column::Position)
        .all(connection)
        .await
        .context("loading a template's counters")?
    {
        let metrics = template_metric::Entity::find()
            .filter(template_metric::Column::CountersId.eq(block.id))
            .filter(template_metric::Column::ReplacesId.is_null())
            .order_by_asc(template_metric::Column::Position)
            .all(connection)
            .await
            .context("loading counters' metrics")?;
        counters.push(Counters {
            key: block.key,
            object: block.object,
            label: block.label,
            pattern: block.pattern,
            instance: block.instance,
            exclude: text_list(&block.exclude),
            groups: text_map(&block.groups),
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
            enabled: block.enabled,
            metrics: metrics.into_iter().map(to_metric).collect(),
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
        min_version: row.min_version.clone(),
        renamed_from: text_list(&row.renamed_from),
        enabled: row.enabled,
        services: text_list(&row.services),
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
    Ok(StoredTemplate {
        template: read_template(connection, &row).await?,
        id: row.id,
        origin: Origin::parse(&row.origin)?,
        enabled: row.enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
        upgraded_at: row.upgraded_at,
    })
}

async fn metric_rows<C: ConnectionTrait>(
    connection: &C,
    metrics: &[Metric],
    query: Option<i64>,
    counters: Option<i64>,
) -> Result<()> {
    for (position, metric) in metrics.iter().enumerate() {
        template_metric::ActiveModel {
            query_id: Set(query),
            counters_id: Set(counters),
            key: Set(metric.key.clone()),
            position: Set(i32::try_from(position)?),
            counter: Set(metric.counter.clone()),
            unit: Set(metric.unit.clone()),
            total: Set(metric.total),
            description: Set(metric.description.clone()),
            value: Set(metric.value.clone()),
            since: Set(metric.since.clone()),
            states: Set(map_json(&metric.states)),
            ..Default::default()
        }
        .insert(connection)
        .await
        .context("saving a template's metric")?;
    }
    Ok(())
}

/// Writes a template's parts, but for its alerts, in place of the ones it had: the
/// fills, versions and metrics of a query or counters block go with it.
async fn write_parts<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    template: &Template,
) -> Result<()> {
    template_discovery::Entity::delete_many()
        .filter(template_discovery::Column::TemplateId.eq(id))
        .exec(connection)
        .await
        .context("replacing a template's discovery")?;
    template_registry_read::Entity::delete_many()
        .filter(template_registry_read::Column::TemplateId.eq(id))
        .exec(connection)
        .await
        .context("replacing a template's registry reads")?;
    template_notice::Entity::delete_many()
        .filter(template_notice::Column::TemplateId.eq(id))
        .exec(connection)
        .await
        .context("replacing a template's notices")?;
    template_query::Entity::delete_many()
        .filter(template_query::Column::TemplateId.eq(id))
        .exec(connection)
        .await
        .context("replacing a template's queries")?;
    template_counters::Entity::delete_many()
        .filter(template_counters::Column::TemplateId.eq(id))
        .exec(connection)
        .await
        .context("replacing a template's counters")?;

    if let Some(discover) = &template.discover {
        template_discovery::ActiveModel {
            template_id: Set(id),
            interval_secs: Set(secs(&discover.interval)?),
            sql: Set(discover.sql.clone()),
            counter_sets: Set(map_json(&discover.counter_sets)),
            ..Default::default()
        }
        .insert(connection)
        .await
        .context("saving a template's discovery")?;
        for (position, read) in discover.registry.iter().enumerate() {
            template_registry_read::ActiveModel {
                template_id: Set(id),
                key: Set(read.key.clone()),
                position: Set(i32::try_from(position)?),
                value_names: Set(json!(read.values)),
                ..Default::default()
            }
            .insert(connection)
            .await
            .context("saving a template's registry read")?;
        }
    }
    for (position, notice) in template.notices.iter().enumerate() {
        template_notice::ActiveModel {
            template_id: Set(id),
            key: Set(notice.key.clone()),
            position: Set(i32::try_from(position)?),
            when_condition: Set(notice.when.clone()),
            text: Set(notice.text.clone()),
            ..Default::default()
        }
        .insert(connection)
        .await
        .context("saving a template's notice")?;
    }
    for (position, query) in template.queries.iter().enumerate() {
        let saved = template_query::ActiveModel {
            template_id: Set(id),
            key: Set(query.key.clone()),
            position: Set(i32::try_from(position)?),
            sql: Set(query.sql.clone()),
            interval_secs: Set(secs(&query.interval)?),
            since: Set(query.since.clone()),
            when_condition: Set(query.when.clone()),
            enabled: Set(query.enabled),
            labels: Set(list_json(&query.labels)),
            ..Default::default()
        }
        .insert(connection)
        .await
        .context("saving a template's query")?;
        for (position, fill) in query.fills.iter().enumerate() {
            let saved_fill = template_fill::ActiveModel {
                query_id: Set(saved.id),
                key: Set(fill.key.clone()),
                position: Set(i32::try_from(position)?),
                older: Set(fill.older.clone()),
                ..Default::default()
            }
            .insert(connection)
            .await
            .context("saving a query's fill")?;
            for (position, (version, sql)) in fill.versions.iter().enumerate() {
                template_fill_version::ActiveModel {
                    fill_id: Set(saved_fill.id),
                    version: Set(version.clone()),
                    position: Set(i32::try_from(position)?),
                    sql: Set(sql.clone()),
                    ..Default::default()
                }
                .insert(connection)
                .await
                .context("saving a fill's version")?;
            }
        }
        metric_rows(connection, &query.metrics, Some(saved.id), None).await?;
    }
    for (position, counters) in template.counters.iter().enumerate() {
        let saved = template_counters::ActiveModel {
            template_id: Set(id),
            key: Set(counters.key.clone()),
            position: Set(i32::try_from(position)?),
            object: Set(counters.object.clone()),
            label: Set(counters.label.clone()),
            pattern: Set(counters.pattern.clone()),
            instance: Set(counters.instance.clone()),
            exclude: Set(list_json(&counters.exclude)),
            groups: Set(map_json(&counters.groups)),
            join_object: Set(counters.join.as_ref().map(|join| join.object.clone())),
            join_pattern: Set(counters.join.as_ref().map(|join| join.pattern.clone())),
            when_condition: Set(counters.when.clone()),
            since: Set(counters.since.clone()),
            interval_secs: Set(secs(&counters.interval)?),
            enabled: Set(counters.enabled),
            ..Default::default()
        }
        .insert(connection)
        .await
        .context("saving a template's counters")?;
        metric_rows(connection, &counters.metrics, None, Some(saved.id)).await?;
    }
    Ok(())
}

/// A template as the audit log compares them: what it says, field by field, and
/// whether it's on.
fn template_snapshot(stored: &StoredTemplate) -> Result<Snapshot> {
    let mut fields = serde_json::to_value(&stored.template).context("recording a template")?;
    fields["enabled"] = json!(stored.enabled);
    fields["origin"] = json!(stored.origin.as_str());
    Ok(Snapshot::new(stored.template.name.clone(), fields))
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

/// Whether a template's alert needs what only agents running the template would
/// send: what its discovery finds, or the template's own metrics.
fn waits_for_agents(
    template: &Template,
    when: &Option<String>,
    since: &Option<String>,
    rule: &AlertRuleInput,
) -> bool {
    let local = local_metrics(template);
    when.is_some()
        || since.is_some()
        || rule
            .conditions_in(Some(&local))
            .is_ok_and(|conditions| conditions.uses_local())
}

async fn set_waits<C: ConnectionTrait>(connection: &C, rule_id: i64, waits: bool) -> Result<()> {
    alert_rule::Entity::update_many()
        .col_expr(alert_rule::Column::WaitsForAgents, Expr::value(waits))
        .filter(alert_rule::Column::Id.eq(rule_id))
        .exec(connection)
        .await
        .context("saving alert rule")?;
    Ok(())
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
/// New alerts get rules, and the rules of alerts it no longer has are deleted, with
/// any copies. A rule in the way of a built-in template's is moved aside, as the
/// server has to start; for any other template it's an error.
async fn write_rules<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    template: &Template,
    origin: Origin,
    now: Timestamp,
) -> Result<()> {
    let original = origin.is_original();
    let rows = own_rules(connection, id).await?;
    for (position, alert) in template.alerts.iter().enumerate() {
        let theirs = template_values(template, alert)?;
        let waits = waits_for_agents(template, &alert.when, &alert.since, &theirs);
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
            active.waits_for_agents = Set(waits);
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
        let enabled = match original {
            true => row.enabled,
            false => alert.enabled,
        };
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
        let same = says_the_same
            && row.enabled == enabled
            && row.template_position == Some(position)
            && row.waits_for_agents == waits;
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
            waits_for_agents: Set(waits),
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
        if let Some(copy) = copy_of(connection, row.id).await? {
            delete_rule_in(connection, copy.id, now).await?;
        }
        delete_rule_in(connection, row.id, now).await?;
    }
    Ok(())
}

/// Deletes a template, marking it deleted, and its rules and their copies with it.
async fn delete_in<C: ConnectionTrait>(
    connection: &C,
    stored: &StoredTemplate,
    now: Timestamp,
) -> Result<()> {
    let before = template_snapshot(stored)?;
    let rules: Vec<alert_rule::Model> = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::TemplateId.eq(stored.id))
        .order_by_desc(alert_rule::Column::ReplacesId)
        .all(connection)
        .await
        .context("loading a template's alert rules")?;
    for rule in rules {
        delete_rule_in(connection, rule.id, now).await?;
    }
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
    row.min_version = Set(template.min_version.clone());
    row.renamed_from = Set(list_json(&template.renamed_from));
    row.services = Set(list_json(&template.services));
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
    let before = template_snapshot(&to_stored(connection, row.clone()).await?)?;
    let mut active = template::ActiveModel {
        id: Set(row.id),
        fingerprint: Set(Some(fingerprint.to_string())),
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
    write_rules(connection, row.id, template, origin, now).await?;
    record_template(connection, row.id, Some(&before)).await
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
        Ok((id, outcome))
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
            let rule = load_alert_rule(&self.connection, row.id)
                .await?
                .context("a template's rule went missing")?;
            let copy = match copy_of(&self.connection, row.id).await? {
                Some(copy) => load_alert_rule(&self.connection, copy.id).await?,
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
        if stored.enabled == enabled {
            return Ok(true);
        }
        let before = template_snapshot(&stored)?;
        template::ActiveModel {
            id: Set(id),
            enabled: Set(enabled),
            updated_at: Set(now),
            ..Default::default()
        }
        .update(&transaction)
        .await
        .context("saving template")?;
        record_template(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving template")?;
        Ok(true)
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
        let waits = waits_for_agents(
            &found.template.template,
            &original.when_condition,
            &original.since,
            wanted,
        );
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
                            .col_expr(alert_rule::Column::Enabled, Expr::value(wanted.enabled))
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
                active.waits_for_agents = Set(waits);
                let copy = alert_rule::Entity::insert(active)
                    .exec(&transaction)
                    .await
                    .context("saving a copy of a template's alert rule")?
                    .last_insert_id;
                save_links(&transaction, copy, &wanted.channels).await?;
                save_actions(&transaction, copy, &wanted.actions).await?;
                record_alert_rule(&transaction, copy, None).await?;
                transaction.commit().await.context("saving alert rule")?;
                return Ok(true);
            }
        };
        write_rule_in(&transaction, target, wanted).await?;
        set_waits(&transaction, target, waits).await?;
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// Puts one of a built-in template's alerts back to the template's own rule, by
    /// deleting someone's copy of it. Returns false if there's no such rule, or no
    /// copy of it.
    pub async fn reset_template_rule(&self, rule_id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let Some(found) = template_rule_in(&transaction, rule_id).await? else {
            return Ok(false);
        };
        let Some(copy) = found.copy else {
            return Ok(false);
        };
        delete_rule_in(&transaction, copy, now).await?;
        transaction.commit().await.context("saving alert rule")?;
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
                notices.push(format!("{} (removed)", row.name));
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
            notices.push(match copies.is_empty() {
                true => row.name,
                false => format!(
                    "{} (its version of {} changed, which you have your own of)",
                    row.name,
                    copies.join(", ")
                ),
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
