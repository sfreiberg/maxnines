//! Location rules, which say where machines are for the map.

use anyhow::{Context, Result};
use sea_orm::{EntityTrait, QueryOrder, Set};

use super::{Database, location_rule};
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
        let row = location_rule::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading location rule")?;
        Ok(row.map(to_rule))
    }

    pub async fn create_location_rule(&self, input: &LocationRuleInput) -> Result<i64> {
        let result = location_rule::Entity::insert(rule_row(input))
            .exec(&self.connection)
            .await
            .context("saving location rule")?;
        Ok(result.last_insert_id)
    }

    /// Returns false if there's no such rule.
    pub async fn update_location_rule(&self, id: i64, input: &LocationRuleInput) -> Result<bool> {
        if self.get_location_rule(id).await?.is_none() {
            return Ok(false);
        }
        let mut row = rule_row(input);
        row.id = Set(id);
        location_rule::Entity::update(row)
            .exec(&self.connection)
            .await
            .context("saving location rule")?;
        Ok(true)
    }

    /// Returns false if there's no such rule.
    pub async fn delete_location_rule(&self, id: i64) -> Result<bool> {
        let result = location_rule::Entity::delete_by_id(id)
            .exec(&self.connection)
            .await
            .context("deleting location rule")?;
        Ok(result.rows_affected > 0)
    }
}
