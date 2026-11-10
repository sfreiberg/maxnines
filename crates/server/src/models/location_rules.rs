//! Location rules, which say where machines are for the map.

use anyhow::{Context, Result};
use sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Set, TransactionTrait};

use super::audit::record_change;
use super::{Database, location_rule};
use crate::audit::{Kind, Snapshot};
use crate::locations::{LocationRule, LocationRuleInput};

fn to_rule(row: location_rule::Model) -> LocationRule {
    LocationRule {
        id: row.id,
        rule: LocationRuleInput {
            name: row.name,
            filter: row.filter,
            place: row.place,
            latitude: row.latitude,
            longitude: row.longitude,
            priority: row.priority,
        },
    }
}

fn rule_row(input: &LocationRuleInput) -> location_rule::ActiveModel {
    location_rule::ActiveModel {
        name: Set(input.name.trim().to_string()),
        filter: Set(input.filter.trim().to_string()),
        place: Set(input.place.trim().to_string()),
        latitude: Set(input.latitude),
        longitude: Set(input.longitude),
        priority: Set(input.priority),
        ..Default::default()
    }
}

async fn load<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<LocationRule>> {
    let row = location_rule::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading location rule")?;
    Ok(row.map(to_rule))
}

/// Records how a rule changed from `before`, reading it as it is now.
async fn record<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&LocationRule>,
) -> Result<()> {
    let after = load(connection, id).await?;
    let snapshot = |rule: &LocationRule| Snapshot::of(rule.rule.name.clone(), &rule.rule);
    let before = before.map(snapshot).transpose()?;
    let after = after.as_ref().map(snapshot).transpose()?;
    record_change(
        connection,
        Kind::LocationRule,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
}

impl Database {
    /// Highest priority first, then by name.
    pub async fn list_location_rules(&self) -> Result<Vec<LocationRule>> {
        let rows = location_rule::Entity::find()
            .order_by_desc(location_rule::Column::Priority)
            .order_by_asc(location_rule::Column::Name)
            .all(&self.connection)
            .await
            .context("loading location rules")?;
        Ok(rows.into_iter().map(to_rule).collect())
    }

    pub async fn get_location_rule(&self, id: i64) -> Result<Option<LocationRule>> {
        load(&self.connection, id).await
    }

    pub async fn create_location_rule(&self, input: &LocationRuleInput) -> Result<i64> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving location rule")?;
        let id = location_rule::Entity::insert(rule_row(input))
            .exec(&transaction)
            .await
            .context("saving location rule")?
            .last_insert_id;
        record(&transaction, id, None).await?;
        transaction.commit().await.context("saving location rule")?;
        Ok(id)
    }

    /// Returns false if there's no such rule.
    pub async fn update_location_rule(&self, id: i64, input: &LocationRuleInput) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving location rule")?;
        let Some(before) = load(&transaction, id).await? else {
            return Ok(false);
        };
        let mut row = rule_row(input);
        row.id = Set(id);
        location_rule::Entity::update(row)
            .exec(&transaction)
            .await
            .context("saving location rule")?;
        record(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving location rule")?;
        Ok(true)
    }

    /// Returns false if there's no such rule.
    pub async fn delete_location_rule(&self, id: i64) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("deleting location rule")?;
        let before = load(&transaction, id).await?;
        let result = location_rule::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting location rule")?;
        record(&transaction, id, before.as_ref()).await?;
        transaction
            .commit()
            .await
            .context("deleting location rule")?;
        Ok(result.rows_affected > 0)
    }
}
