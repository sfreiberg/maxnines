//! Keeping the built-in config rules in the database the same as the ones this
//! version of the server ships with.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, TransactionTrait,
};

use super::audit::record;
use super::{
    ConfigRule, Database, RuleInput, config_rule, config_rule_setting, load_rule, name_key,
    rule_snapshot, save_settings, systems_text,
};
use crate::audit::{Actor, Kind, Record};
use crate::built_in_rules::BuiltInRule;
use crate::facts::{flatten, unflatten};
use crate::times::Timestamp;

/// Whether two rules set the same things for the same hosts. Whether they're turned
/// on is left out, as that's for people to decide, even for a built-in rule.
pub fn same_rule(a: &RuleInput, b: &RuleInput) -> bool {
    // Stored settings come back from their rows, so both are compared as stored.
    let stored = |rule: &RuleInput| flatten(&rule.settings).map(|flat| unflatten(&flat)).ok();
    a.name == b.name
        && a.priority == b.priority
        && a.applies_to == b.applies_to
        && a.operating_systems == b.operating_systems
        && stored(a) == stored(b)
}

/// Records a change to a rule that the server made itself, as it started.
async fn record_by_server(
    connection: &impl ConnectionTrait,
    id: i64,
    before: Option<&ConfigRule>,
) -> Result<()> {
    let after = load_rule(connection, id).await?;
    let before = before.map(rule_snapshot).transpose()?;
    let after = after.as_ref().map(rule_snapshot).transpose()?;
    match Record::of_change(Kind::ConfigRule, id, before.as_ref(), after.as_ref(), None) {
        Some(entry) => record(connection, entry.by(Actor::MaxNines)).await,
        None => Ok(()),
    }
}

impl Database {
    /// Writes `shipped` over the built-in rules, adding any that are new and
    /// removing any no longer shipped. Whether each is turned on stays as it was. A
    /// rule of someone's own that has a built-in rule's name, as names are compared,
    /// keeps everything it had under a name of its own. Gives the names of the rules
    /// this changed.
    pub async fn sync_built_in_rules(
        &self,
        shipped: &[BuiltInRule],
        now: Timestamp,
    ) -> Result<Vec<String>> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("updating built-in rules")?;
        let rows = config_rule::Entity::find()
            .all(&transaction)
            .await
            .context("loading rules")?;
        let mut changed = Vec::new();
        // Names in use, as they're compared, kept up to date as rules are renamed.
        let mut taken: BTreeSet<String> = rows.iter().map(|row| row.name_key.clone()).collect();

        for built_in in shipped {
            let key = name_key(&built_in.rule.name);
            let existing = rows
                .iter()
                .find(|row| row.built_in.as_deref() == Some(built_in.key));

            // Someone's own rule with this name, as names are compared, keeps
            // everything it had under a name of its own.
            let named = rows
                .iter()
                .find(|row| row.built_in.is_none() && row.name_key == key);
            if let Some(row) = named {
                let before = load_rule(&transaction, row.id)
                    .await?
                    .context("a rule went missing")?;
                let mut active: config_rule::ActiveModel = row.clone().into();
                let mut name = format!("{} (yours)", built_in.rule.name);
                let mut number = 2;
                while taken.contains(&name_key(&name)) {
                    name = format!("{} (yours {number})", built_in.rule.name);
                    number += 1;
                }
                taken.insert(name_key(&name));
                active.name_key = Set(name_key(&name));
                active.name = Set(name);
                active
                    .update(&transaction)
                    .await
                    .context("renaming a rule")?;
                record_by_server(&transaction, row.id, Some(&before)).await?;
            }
            taken.insert(key.clone());

            if let Some(row) = existing {
                let before = load_rule(&transaction, row.id)
                    .await?
                    .context("a built-in rule went missing")?;
                if same_rule(&before.rule, &built_in.rule) {
                    continue;
                }
                let mut active: config_rule::ActiveModel = row.clone().into();
                active.name = Set(built_in.rule.name.clone());
                active.name_key = Set(key);
                active.priority = Set(built_in.rule.priority);
                active.applies_to = Set(built_in.rule.applies_to.clone());
                active.operating_systems = Set(systems_text(&built_in.rule.operating_systems));
                active.built_in_changed_at = Set(Some(now));
                active
                    .update(&transaction)
                    .await
                    .context("updating a built-in rule")?;
                config_rule_setting::Entity::delete_many()
                    .filter(config_rule_setting::Column::RuleId.eq(row.id))
                    .exec(&transaction)
                    .await
                    .context("replacing a built-in rule's settings")?;
                save_settings(&transaction, row.id, &built_in.rule.settings).await?;
                record_by_server(&transaction, row.id, Some(&before)).await?;
                changed.push(built_in.rule.name.clone());
                continue;
            }

            let row = config_rule::ActiveModel {
                name: Set(built_in.rule.name.clone()),
                name_key: Set(key),
                priority: Set(built_in.rule.priority),
                applies_to: Set(built_in.rule.applies_to.clone()),
                enabled: Set(built_in.rule.enabled),
                operating_systems: Set(systems_text(&built_in.rule.operating_systems)),
                built_in: Set(Some(built_in.key.to_string())),
                built_in_changed_at: Set(Some(now)),
                ..Default::default()
            }
            .insert(&transaction)
            .await
            .context("adding a built-in rule")?;
            save_settings(&transaction, row.id, &built_in.rule.settings).await?;
            record_by_server(&transaction, row.id, None).await?;
            changed.push(built_in.rule.name.clone());
        }

        let gone = rows.iter().filter(|row| {
            row.built_in
                .as_deref()
                .is_some_and(|key| !shipped.iter().any(|built_in| built_in.key == key))
        });
        // Their settings go with them.
        for row in gone {
            let before = load_rule(&transaction, row.id).await?;
            config_rule::Entity::delete_by_id(row.id)
                .exec(&transaction)
                .await
                .context("removing a built-in rule")?;
            record_by_server(&transaction, row.id, before.as_ref()).await?;
            changed.push(row.name.clone());
        }

        transaction
            .commit()
            .await
            .context("updating built-in rules")?;
        Ok(changed)
    }
}
