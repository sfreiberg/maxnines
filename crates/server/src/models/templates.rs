//! Templates, and the alert rules their alerts become.
//!
//! A template's alert is an ordinary alert rule, which holds what's in effect: the
//! template's values with what people changed. What they changed is kept on its own,
//! in the rule's `overrides`, by field. A template changing, by an upgrade or by
//! whoever owns it, only ever rewrites the template's values, and works the rule out
//! again from them and the same overrides.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use maxnines_protocol::templates::{Alert, Template};

use super::alerting::{
    alert_rule_row, alert_rule_snapshot, delete_rule_in, load_alert_rule, record_alert_rule,
    save_actions, save_links,
};
use super::audit::record_change;
use super::{Database, alert_rule, alert_rule_channel, name_key, name_taken_or, template};
use crate::alert_conditions::LocalMetrics;
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::audit::{Kind, Snapshot};
use crate::templates::built_in::BuiltIn;
use crate::templates::{Refused, alert_rule as template_values, local_metrics};
use crate::times::Timestamp;

/// A template as stored.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StoredTemplate {
    pub id: i64,
    pub template: Template,
    /// Its HCL.
    pub source: String,
    pub built_in: bool,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// When an upgrade last changed it, for a built-in one.
    pub upgraded_at: Option<Timestamp>,
}

fn to_stored(row: template::Model) -> Result<StoredTemplate> {
    let template = maxnines_protocol::templates::parse(&row.source)
        .with_context(|| format!("reading the template {:?}", row.key))?;
    Ok(StoredTemplate {
        id: row.id,
        template,
        source: row.source,
        built_in: row.built_in,
        enabled: row.enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
        upgraded_at: row.upgraded_at,
    })
}

/// A template as the audit log compares them: what it says, field by field, and
/// whether it's on.
fn template_snapshot(stored: &StoredTemplate) -> Result<Snapshot> {
    let mut fields = serde_json::to_value(&stored.template).context("recording a template")?;
    fields["enabled"] = json!(stored.enabled);
    fields["built_in"] = json!(stored.built_in);
    Ok(Snapshot::new(stored.template.name.clone(), fields))
}

async fn load_template<C: ConnectionTrait>(
    connection: &C,
    id: i64,
) -> Result<Option<StoredTemplate>> {
    template::Entity::find_by_id(id)
        .filter(template::Column::DeletedAt.is_null())
        .one(connection)
        .await
        .context("loading template")?
        .map(to_stored)
        .transpose()
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

/// The rule a template's alert is with what people changed of it: the template's
/// values, with each field in `overrides` in place of the template's.
pub fn effective_rule(
    template: &Template,
    alert: &Alert,
    overrides: &Map<String, Value>,
) -> Result<AlertRuleInput> {
    let mut fields = serde_json::to_value(template_values(template, alert)?)?;
    for (field, value) in overrides {
        fields[field] = value.clone();
    }
    serde_json::from_value(fields).context("applying what was changed of a template's alert")
}

/// The fields of `wanted` that aren't the template's values, as the API names them.
pub fn overrides_of(
    theirs: &AlertRuleInput,
    wanted: &AlertRuleInput,
) -> Result<Map<String, Value>> {
    let ordered = |rule: &AlertRuleInput| {
        let mut rule = rule.clone();
        rule.channels.sort_unstable();
        rule.channels.dedup();
        serde_json::to_value(rule)
    };
    let Value::Object(theirs) = ordered(theirs)? else {
        bail!("a rule is a map of fields");
    };
    let Value::Object(wanted) = ordered(wanted)? else {
        bail!("a rule is a map of fields");
    };
    Ok(wanted
        .into_iter()
        .filter(|(field, value)| theirs.get(field) != Some(value))
        .collect())
}

/// Whether a template's alert needs what only agents running the template would
/// send: what its discovery finds, or the template's own metrics.
fn waits_for_agents(alert: &Alert, rule: &AlertRuleInput, local: &LocalMetrics) -> bool {
    alert.when.is_some()
        || alert.since.is_some()
        || rule
            .conditions_in(Some(local))
            .is_ok_and(|conditions| conditions.uses_local())
}

/// What a rule's overrides are, as stored.
fn overrides_in(row: &alert_rule::Model) -> Map<String, Value> {
    match &row.overrides {
        Some(Value::Object(fields)) => fields.clone(),
        _ => Map::new(),
    }
}

/// A name for a rule moved aside for a template's, as names are compared: `Disk
/// (yours)`, then `Disk (yours 2)` and so on.
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

/// Moves another rule that has `name`, as names are compared, out of the way of a
/// built-in template's alert, under a name of its own. One that's a template's alert
/// keeps its new name as something changed of it.
async fn make_room<C: ConnectionTrait>(
    connection: &C,
    name: &str,
    except: Option<i64>,
) -> Result<()> {
    let mut clashing = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::NameKey.eq(name_key(name)));
    if let Some(except) = except {
        clashing = clashing.filter(alert_rule::Column::Id.ne(except));
    }
    let Some(row) = clashing
        .one(connection)
        .await
        .context("loading alert rules")?
    else {
        return Ok(());
    };
    let before = match load_alert_rule(connection, row.id).await? {
        Some(rule) => Some(alert_rule_snapshot(connection, &rule).await?),
        None => None,
    };
    let new_name = free_name(connection, &row.name).await?;
    let mut overrides = overrides_in(&row);
    let has_template = row.template_id.is_some();
    let id = row.id;
    let mut active: alert_rule::ActiveModel = row.into();
    if has_template {
        overrides.insert("name".to_string(), json!(new_name));
        active.overrides = Set(Some(Value::Object(overrides)));
    }
    active.name_key = Set(name_key(&new_name));
    active.name = Set(new_name);
    active
        .update(connection)
        .await
        .context("renaming an alert rule")?;
    record_alert_rule(connection, id, before.as_ref()).await
}

/// Writes a template's alerts as its alert rules: each worked out from the template
/// and what people changed of it, which is kept. Alerts that are new get rules, and
/// the rules of those it no longer has are deleted. A rule in the way is moved aside
/// when `moving_aside`, as for a built-in template as the server starts; otherwise
/// it's an error.
async fn write_rules<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    template: &Template,
    enabled: bool,
    moving_aside: bool,
    now: Timestamp,
) -> Result<()> {
    let rows = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::TemplateId.eq(id))
        .all(connection)
        .await
        .context("loading a template's alert rules")?;
    let local = local_metrics(template);
    for alert in &template.alerts {
        let existing = rows
            .iter()
            .find(|row| row.template_alert.as_deref() == Some(alert.key.as_str()));
        let overrides = existing.map(overrides_in).unwrap_or_default();
        let own = effective_rule(template, alert, &overrides)?;
        let waits = waits_for_agents(alert, &own, &local);
        let mut in_effect = own;
        in_effect.enabled &= enabled;

        if let Some(row) = existing {
            let current = load_alert_rule(connection, row.id)
                .await?
                .context("a template's rule went missing")?;
            if current.rule == in_effect && row.waits_for_agents == waits {
                continue;
            }
            if moving_aside {
                make_room(connection, &in_effect.name, Some(row.id)).await?;
            }
            let before = alert_rule_snapshot(connection, &current).await?;
            let mut active = alert_rule_row(&in_effect)?;
            active.id = Set(row.id);
            active.waits_for_agents = Set(waits);
            alert_rule::Entity::update(active)
                .exec(connection)
                .await
                .map_err(|error| {
                    let taken = NameTaken::AlertRule(in_effect.name.clone());
                    name_taken_or(error, taken, "saving a template's alert rule")
                })?;
            alert_rule_channel::Entity::delete_many()
                .filter(alert_rule_channel::Column::RuleId.eq(row.id))
                .exec(connection)
                .await
                .context("saving alert rule channels")?;
            save_links(connection, row.id, &in_effect.channels).await?;
            save_actions(connection, row.id, &in_effect.actions).await?;
            record_alert_rule(connection, row.id, Some(&before)).await?;
            continue;
        }

        if moving_aside {
            make_room(connection, &in_effect.name, None).await?;
        }
        let mut active = alert_rule_row(&in_effect)?;
        active.template_id = Set(Some(id));
        active.template_alert = Set(Some(alert.key.clone()));
        active.waits_for_agents = Set(waits);
        let rule_id = alert_rule::Entity::insert(active)
            .exec(connection)
            .await
            .map_err(|error| {
                let taken = NameTaken::AlertRule(in_effect.name.clone());
                name_taken_or(error, taken, "saving a template's alert rule")
            })?
            .last_insert_id;
        save_links(connection, rule_id, &in_effect.channels).await?;
        save_actions(connection, rule_id, &in_effect.actions).await?;
        record_alert_rule(connection, rule_id, None).await?;
    }
    let gone = rows.iter().filter(|row| {
        !template
            .alerts
            .iter()
            .any(|alert| row.template_alert.as_deref() == Some(alert.key.as_str()))
    });
    for row in gone {
        delete_rule_in(connection, row.id, now).await?;
    }
    Ok(())
}

/// Deletes a template, marking it deleted, and its rules with it.
async fn delete_in<C: ConnectionTrait>(
    connection: &C,
    stored: &StoredTemplate,
    now: Timestamp,
) -> Result<()> {
    let before = template_snapshot(stored)?;
    template::Entity::update_many()
        .col_expr(template::Column::DeletedAt, Expr::value(now))
        .filter(template::Column::Id.eq(stored.id))
        .exec(connection)
        .await
        .context("deleting a template")?;
    let rules: Vec<alert_rule::Model> = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::TemplateId.eq(stored.id))
        .all(connection)
        .await
        .context("loading a template's alert rules")?;
    for rule in rules {
        delete_rule_in(connection, rule.id, now).await?;
    }
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

/// A template's key and name, as a row that's new or rewritten gets them.
fn named(row: &mut template::ActiveModel, template: &Template) {
    row.key = Set(template.key.clone());
    row.name = Set(template.name.clone());
    row.name_key = Set(name_key(&template.name));
    row.description = Set(template.description.clone());
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
/// or name, keeping everything it has under a key and name of its own. Its HCL is
/// written out again, with the new key.
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
        !row.built_in && (row.key == built_in.key || row.name_key == name_key(&built_in.name))
    });
    for row in in_the_way {
        let stored = to_stored(row.clone())?;
        let before = template_snapshot(&stored)?;
        let mut template = stored.template.clone();
        if template.key == built_in.key {
            template.key = free_key(&template.key, &keys);
            keys.insert(template.key.clone());
        }
        if name_key(&template.name) == name_key(&built_in.name) {
            let mut name = format!("{} (yours)", template.name);
            let mut number = 2;
            while names.contains(&name_key(&name)) {
                name = format!("{} (yours {number})", template.name);
                number += 1;
            }
            names.insert(name_key(&name));
            template.name = name;
        }
        let mut active: template::ActiveModel = row.into();
        named(&mut active, &template);
        active.source = Set(maxnines_protocol::templates::to_hcl(&template));
        active.updated_at = Set(now);
        active
            .update(connection)
            .await
            .context("renaming a template")?;
        record_template(connection, stored.id, Some(&before)).await?;
    }
    Ok(())
}

impl Database {
    /// Writes the templates this version ships over the built-in ones: adding new
    /// ones, rewriting changed ones, following renames, and deleting those no longer
    /// shipped. Whether each is on, and what people changed of their alerts, stays.
    /// Someone's own template with a built-in one's key or name is moved aside, as
    /// is any rule in the way of a built-in one's. Gives the names of the templates
    /// this changed, which on a new server is none.
    pub async fn sync_templates(&self, shipped: &[BuiltIn], now: Timestamp) -> Result<Vec<String>> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("updating built-in templates")?;
        let rows = template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .filter(template::Column::BuiltIn.eq(true))
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
            let same = existing.is_some_and(|row| {
                row.key == template.key
                    && row.fingerprint.as_deref() == Some(built_in.fingerprint.as_str())
            });
            if !same {
                move_aside(&transaction, template, now).await?;
            }
            let id = match existing {
                Some(row) => {
                    kept.insert(row.id);
                    if same {
                        // Only its comments or layout, if anything, changed.
                        if row.source != built_in.source {
                            let mut active: template::ActiveModel = row.clone().into();
                            active.source = Set(built_in.source.clone());
                            active
                                .update(&transaction)
                                .await
                                .context("updating a template")?;
                        }
                    } else {
                        let before = template_snapshot(&to_stored(row.clone())?)?;
                        let mut active: template::ActiveModel = row.clone().into();
                        named(&mut active, template);
                        active.source = Set(built_in.source.clone());
                        active.fingerprint = Set(Some(built_in.fingerprint.clone()));
                        active.updated_at = Set(now);
                        active.upgraded_at = Set(Some(now));
                        active.upgrade_seen = Set(false);
                        active
                            .update(&transaction)
                            .await
                            .map_err(|error| taken(error, template))?;
                        record_template(&transaction, row.id, Some(&before)).await?;
                        changed.push(template.name.clone());
                    }
                    row.id
                }
                None => {
                    let mut active = template::ActiveModel {
                        built_in: Set(true),
                        source: Set(built_in.source.clone()),
                        fingerprint: Set(Some(built_in.fingerprint.clone())),
                        enabled: Set(template.enabled),
                        created_at: Set(now),
                        updated_at: Set(now),
                        upgraded_at: Set(upgrading.then_some(now)),
                        upgrade_seen: Set(!upgrading),
                        ..Default::default()
                    };
                    named(&mut active, template);
                    let id = template::Entity::insert(active)
                        .exec(&transaction)
                        .await
                        .map_err(|error| taken(error, template))?
                        .last_insert_id;
                    record_template(&transaction, id, None).await?;
                    if upgrading {
                        changed.push(template.name.clone());
                    }
                    id
                }
            };
            let enabled = load_template(&transaction, id)
                .await?
                .context("a template went missing")?
                .enabled;
            write_rules(&transaction, id, template, enabled, true, now).await?;
        }

        for row in rows.iter().filter(|row| !kept.contains(&row.id)) {
            let stored = to_stored(row.clone())?;
            delete_in(&transaction, &stored, now).await?;
            changed.push(stored.template.name);
        }

        transaction
            .commit()
            .await
            .context("updating built-in templates")?;
        Ok(changed)
    }

    /// Built-in and people's own, sorted by name.
    pub async fn list_templates(&self) -> Result<Vec<StoredTemplate>> {
        template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .order_by_asc(template::Column::Name)
            .all(&self.connection)
            .await
            .context("loading templates")?
            .into_iter()
            .map(to_stored)
            .collect()
    }

    pub async fn get_template(&self, id: i64) -> Result<Option<StoredTemplate>> {
        load_template(&self.connection, id).await
    }

    /// The rules a template's alerts are, in the template's order.
    pub async fn template_rules(&self, stored: &StoredTemplate) -> Result<Vec<AlertRule>> {
        let rules = self.list_alert_rules().await?;
        let mut mine: Vec<AlertRule> = rules
            .into_iter()
            .filter(|rule| rule.template.as_ref().is_some_and(|t| t.id == stored.id))
            .collect();
        let position = |rule: &AlertRule| {
            let key = rule.template.as_ref().map(|t| t.alert.as_str());
            stored
                .template
                .alerts
                .iter()
                .position(|alert| Some(alert.key.as_str()) == key)
        };
        mine.sort_by_key(position);
        Ok(mine)
    }

    /// Adds someone's own template, checked already, with its alerts as rules.
    pub async fn create_template(
        &self,
        template: &Template,
        source: &str,
        now: Timestamp,
    ) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving template")?;
        refuse_taken(&transaction, template, None).await?;
        let mut active = template::ActiveModel {
            built_in: Set(false),
            source: Set(source.to_string()),
            enabled: Set(template.enabled),
            created_at: Set(now),
            updated_at: Set(now),
            upgrade_seen: Set(true),
            ..Default::default()
        };
        named(&mut active, template);
        let id = template::Entity::insert(active)
            .exec(&transaction)
            .await
            .map_err(|error| taken(error, template))?
            .last_insert_id;
        record_template(&transaction, id, None).await?;
        write_rules(&transaction, id, template, template.enabled, false, now).await?;
        transaction.commit().await.context("saving template")?;
        Ok(id)
    }

    /// Replaces someone's own template, checked already, keeping what people changed
    /// of the alerts it still has. Returns false if there's no such template.
    pub async fn update_template(
        &self,
        id: i64,
        template: &Template,
        source: &str,
        now: Timestamp,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving template")?;
        let Some(stored) = load_template(&transaction, id).await? else {
            return Ok(false);
        };
        if stored.built_in {
            bail!(Refused(
                "a built-in template can't be changed, as upgrades replace it: disable it, or change its alerts".to_string()
            ));
        }
        refuse_taken(&transaction, template, Some(id)).await?;
        let before = template_snapshot(&stored)?;
        let mut active = template::ActiveModel {
            id: Set(id),
            source: Set(source.to_string()),
            updated_at: Set(now),
            ..Default::default()
        };
        named(&mut active, template);
        active
            .update(&transaction)
            .await
            .map_err(|error| taken(error, template))?;
        record_template(&transaction, id, Some(&before)).await?;
        write_rules(&transaction, id, template, stored.enabled, false, now).await?;
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
        if stored.built_in {
            bail!(Refused(
                "a built-in template can't be deleted, but it can be disabled".to_string()
            ));
        }
        delete_in(&transaction, &stored, now).await?;
        transaction.commit().await.context("deleting template")?;
        Ok(true)
    }

    /// Turns a template, and so its alert rules, on or off. Returns false if there's
    /// no such template.
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
        write_rules(&transaction, id, &stored.template, enabled, false, now).await?;
        transaction.commit().await.context("saving template")?;
        Ok(true)
    }

    /// The template a rule is one of the alerts of, that alert, and the rule as the
    /// template and what people changed make it, before the template being off
    /// turns it off. None for a rule that isn't a template's.
    pub async fn template_rule(
        &self,
        rule_id: i64,
    ) -> Result<Option<(StoredTemplate, Alert, Map<String, Value>, AlertRuleInput)>> {
        template_rule_in(&self.connection, rule_id).await
    }

    /// Saves what's different in `wanted` from a template's values for one of its
    /// alerts as what people changed of it, and the rule as that makes it. Returns
    /// false if there's no such rule.
    pub async fn override_template_rule(
        &self,
        rule_id: i64,
        wanted: &AlertRuleInput,
        now: Timestamp,
    ) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let Some((stored, alert, _, _)) = template_rule_in(&transaction, rule_id).await? else {
            return Ok(false);
        };
        if wanted.is_calculation() {
            bail!(Refused(
                "a template's alert is about each host, so it can't have a calculation".to_string()
            ));
        }
        let theirs = template_values(&stored.template, &alert)?;
        let overrides = overrides_of(&theirs, wanted)?;
        save_overrides(&transaction, rule_id, overrides).await?;
        write_rules(
            &transaction,
            stored.id,
            &stored.template,
            stored.enabled,
            false,
            now,
        )
        .await?;
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// Puts one of a template's alerts back to the template's values. Returns false if
    /// there's no such rule.
    pub async fn reset_template_rule(&self, rule_id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let Some((stored, ..)) = template_rule_in(&transaction, rule_id).await? else {
            return Ok(false);
        };
        save_overrides(&transaction, rule_id, Map::new()).await?;
        write_rules(
            &transaction,
            stored.id,
            &stored.template,
            stored.enabled,
            false,
            now,
        )
        .await?;
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// The names of built-in templates an upgrade changed that admins haven't
    /// dismissed the notice of.
    pub async fn template_upgrades(&self) -> Result<Vec<String>> {
        let rows = template::Entity::find()
            .filter(template::Column::BuiltIn.eq(true))
            .filter(template::Column::UpgradeSeen.eq(false))
            .order_by_asc(template::Column::Name)
            .all(&self.connection)
            .await
            .context("loading templates")?;
        Ok(rows
            .into_iter()
            .map(|row| match row.deleted_at {
                Some(_) => format!("{} (removed)", row.name),
                None => row.name,
            })
            .collect())
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

async fn save_overrides<C: ConnectionTrait>(
    connection: &C,
    rule_id: i64,
    overrides: Map<String, Value>,
) -> Result<()> {
    let overrides = (!overrides.is_empty()).then_some(Value::Object(overrides));
    alert_rule::Entity::update_many()
        .col_expr(alert_rule::Column::Overrides, Expr::value(overrides))
        .filter(alert_rule::Column::Id.eq(rule_id))
        .exec(connection)
        .await
        .context("saving what was changed of a template's alert")?;
    Ok(())
}

async fn template_rule_in<C: ConnectionTrait>(
    connection: &C,
    rule_id: i64,
) -> Result<Option<(StoredTemplate, Alert, Map<String, Value>, AlertRuleInput)>> {
    let Some(row) = alert_rule::Entity::find_by_id(rule_id)
        .filter(alert_rule::Column::DeletedAt.is_null())
        .one(connection)
        .await
        .context("loading alert rule")?
    else {
        return Ok(None);
    };
    let (Some(template_id), Some(key)) = (row.template_id, &row.template_alert) else {
        return Ok(None);
    };
    let stored = load_template(connection, template_id)
        .await?
        .context("a rule's template went missing")?;
    let alert = stored
        .template
        .alerts
        .iter()
        .find(|alert| &alert.key == key)
        .cloned()
        .context("a rule's alert went missing from its template")?;
    let overrides = overrides_in(&row);
    let own = effective_rule(&stored.template, &alert, &overrides)?;
    Ok(Some((stored, alert, overrides, own)))
}
