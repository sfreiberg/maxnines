//! Maintenance windows, which keep notifications back on a schedule.

use anyhow::{Context, Result};
use sea_orm::{EntityTrait, QueryOrder, Set};

use super::{Database, maintenance_window};
use crate::maintenance::{MaintenanceWindow, MaintenanceWindowInput};

fn to_window(row: maintenance_window::Model) -> MaintenanceWindow {
    MaintenanceWindow {
        id: row.id,
        window: MaintenanceWindowInput {
            name: row.name,
            rule_id: row.rule_id,
            filter: row.filter,
            days: row.days.split(',').map(String::from).collect(),
            start_time: row.start_time,
            duration_minutes: u32::try_from(row.duration_minutes).unwrap_or_default(),
            time_zone: row.time_zone,
        },
    }
}

fn window_row(input: &MaintenanceWindowInput) -> maintenance_window::ActiveModel {
    maintenance_window::ActiveModel {
        name: Set(input.name.trim().to_string()),
        rule_id: Set(input.rule_id),
        filter: Set(input.filter.trim().to_string()),
        days: Set(input.days.join(",")),
        start_time: Set(input.start_time.clone()),
        duration_minutes: Set(i64::from(input.duration_minutes)),
        time_zone: Set(input.time_zone.clone()),
        ..Default::default()
    }
}

impl Database {
    /// Sorted by name.
    pub async fn list_maintenance_windows(&self) -> Result<Vec<MaintenanceWindow>> {
        let rows = maintenance_window::Entity::find()
            .order_by_asc(maintenance_window::Column::Name)
            .all(&self.connection)
            .await
            .context("loading maintenance windows")?;
        Ok(rows.into_iter().map(to_window).collect())
    }

    pub async fn get_maintenance_window(&self, id: i64) -> Result<Option<MaintenanceWindow>> {
        let row = maintenance_window::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading maintenance window")?;
        Ok(row.map(to_window))
    }

    pub async fn create_maintenance_window(&self, input: &MaintenanceWindowInput) -> Result<i64> {
        let result = maintenance_window::Entity::insert(window_row(input))
            .exec(&self.connection)
            .await
            .context("saving maintenance window")?;
        Ok(result.last_insert_id)
    }

    /// Returns false if there's no such window.
    pub async fn update_maintenance_window(
        &self,
        id: i64,
        input: &MaintenanceWindowInput,
    ) -> Result<bool> {
        if self.get_maintenance_window(id).await?.is_none() {
            return Ok(false);
        }
        let mut row = window_row(input);
        row.id = Set(id);
        maintenance_window::Entity::update(row)
            .exec(&self.connection)
            .await
            .context("saving maintenance window")?;
        Ok(true)
    }

    /// Returns false if there's no such window.
    pub async fn delete_maintenance_window(&self, id: i64) -> Result<bool> {
        let result = maintenance_window::Entity::delete_by_id(id)
            .exec(&self.connection)
            .await
            .context("deleting maintenance window")?;
        Ok(result.rows_affected > 0)
    }
}
