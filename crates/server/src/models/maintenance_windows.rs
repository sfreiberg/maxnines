//! Maintenance windows, which keep notifications back on a schedule.

use anyhow::{Context, Result};
use sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Set, TransactionTrait};

use super::audit::record_change;
use super::{Database, maintenance_window};
use crate::audit::{Kind, Snapshot};
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
            duration_secs: u32::try_from(row.duration_secs).unwrap_or_default(),
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
        duration_secs: Set(i64::from(input.duration_secs)),
        time_zone: Set(input.time_zone.clone()),
        ..Default::default()
    }
}

async fn load<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<MaintenanceWindow>> {
    let row = maintenance_window::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading maintenance window")?;
    Ok(row.map(to_window))
}

/// Records how a window changed from `before`, reading it as it is now.
async fn record<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&MaintenanceWindow>,
) -> Result<()> {
    let after = load(connection, id).await?;
    let snapshot = |w: &MaintenanceWindow| Snapshot::of(w.window.name.clone(), &w.window);
    let before = before.map(snapshot).transpose()?;
    let after = after.as_ref().map(snapshot).transpose()?;
    record_change(
        connection,
        Kind::MaintenanceWindow,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
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
        load(&self.connection, id).await
    }

    pub async fn create_maintenance_window(&self, input: &MaintenanceWindowInput) -> Result<i64> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving maintenance window")?;
        let id = maintenance_window::Entity::insert(window_row(input))
            .exec(&transaction)
            .await
            .context("saving maintenance window")?
            .last_insert_id;
        record(&transaction, id, None).await?;
        transaction
            .commit()
            .await
            .context("saving maintenance window")?;
        Ok(id)
    }

    /// Returns false if there's no such window.
    pub async fn update_maintenance_window(
        &self,
        id: i64,
        input: &MaintenanceWindowInput,
    ) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving maintenance window")?;
        let Some(before) = load(&transaction, id).await? else {
            return Ok(false);
        };
        let mut row = window_row(input);
        row.id = Set(id);
        maintenance_window::Entity::update(row)
            .exec(&transaction)
            .await
            .context("saving maintenance window")?;
        record(&transaction, id, Some(&before)).await?;
        transaction
            .commit()
            .await
            .context("saving maintenance window")?;
        Ok(true)
    }

    /// Returns false if there's no such window.
    pub async fn delete_maintenance_window(&self, id: i64) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("deleting maintenance window")?;
        let before = load(&transaction, id).await?;
        let result = maintenance_window::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting maintenance window")?;
        record(&transaction, id, before.as_ref()).await?;
        transaction
            .commit()
            .await
            .context("deleting maintenance window")?;
        Ok(result.rows_affected > 0)
    }
}
