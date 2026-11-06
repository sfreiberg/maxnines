//! Dashboards and their widgets.

use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};

use super::{Database, dashboard, dashboard_widget};
use crate::dashboards::{Dashboard, DashboardSummary, Placed, Placement, Widget, WidgetInput};

fn to_widget(row: dashboard_widget::Model) -> Widget {
    Widget {
        id: row.id,
        input: WidgetInput {
            title: row.title,
            kind: row.kind,
            metric: row.metric,
            calculation: row.calculation,
            group_by: row.group_by,
            filter: row.filter,
            placement: Placement {
                x: row.x,
                y: row.y,
                w: row.w,
                h: row.h,
            },
        },
    }
}

fn to_row(dashboard_id: i64, input: &WidgetInput) -> dashboard_widget::ActiveModel {
    let placement = input.placement;
    dashboard_widget::ActiveModel {
        dashboard_id: Set(dashboard_id),
        title: Set(input.title.clone()),
        kind: Set(input.kind.clone()),
        metric: Set(input.metric.clone()),
        calculation: Set(input.calculation.clone()),
        group_by: Set(input.group_by.clone()),
        filter: Set(input.filter.clone()),
        x: Set(placement.x),
        y: Set(placement.y),
        w: Set(placement.w),
        h: Set(placement.h),
        ..Default::default()
    }
}

impl Database {
    /// Sorted by name.
    pub async fn list_dashboards(&self) -> Result<Vec<DashboardSummary>> {
        let rows = dashboard::Entity::find()
            .order_by_asc(dashboard::Column::Name)
            .all(&self.connection)
            .await
            .context("loading dashboards")?;
        let mut dashboards = Vec::with_capacity(rows.len());
        for row in rows {
            let widgets = dashboard_widget::Entity::find()
                .filter(dashboard_widget::Column::DashboardId.eq(row.id))
                .count(&self.connection)
                .await
                .context("counting widgets")?;
            dashboards.push(DashboardSummary {
                id: row.id,
                name: row.name,
                widgets,
            });
        }
        Ok(dashboards)
    }

    /// With its widgets, from the top of the page down.
    pub async fn get_dashboard(&self, id: i64) -> Result<Option<Dashboard>> {
        let Some(row) = dashboard::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading dashboard")?
        else {
            return Ok(None);
        };
        let widgets = dashboard_widget::Entity::find()
            .filter(dashboard_widget::Column::DashboardId.eq(id))
            .order_by_asc(dashboard_widget::Column::Y)
            .order_by_asc(dashboard_widget::Column::X)
            .all(&self.connection)
            .await
            .context("loading widgets")?;
        Ok(Some(Dashboard {
            id: row.id,
            name: row.name,
            widgets: widgets.into_iter().map(to_widget).collect(),
        }))
    }

    pub async fn create_dashboard(&self, name: &str, now_ms: i64) -> Result<i64> {
        let row = dashboard::ActiveModel {
            name: Set(name.to_string()),
            created_ms: Set(now_ms),
            ..Default::default()
        };
        let result = dashboard::Entity::insert(row)
            .exec(&self.connection)
            .await
            .context("saving dashboard")?;
        Ok(result.last_insert_id)
    }

    /// Returns false if there's no such dashboard.
    pub async fn rename_dashboard(&self, id: i64, name: &str) -> Result<bool> {
        let result = dashboard::Entity::update_many()
            .col_expr(dashboard::Column::Name, name.into())
            .filter(dashboard::Column::Id.eq(id))
            .exec(&self.connection)
            .await
            .context("saving dashboard")?;
        Ok(result.rows_affected > 0)
    }

    /// Returns false if there's no such dashboard. Not every database enforces the
    /// link between the tables the same way, so its widgets are removed here.
    pub async fn delete_dashboard(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await?;
        dashboard_widget::Entity::delete_many()
            .filter(dashboard_widget::Column::DashboardId.eq(id))
            .exec(&transaction)
            .await
            .context("removing widgets")?;
        let result = dashboard::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("removing dashboard")?;
        transaction.commit().await?;
        Ok(result.rows_affected > 0)
    }

    pub async fn create_widget(&self, dashboard_id: i64, input: &WidgetInput) -> Result<i64> {
        let result = dashboard_widget::Entity::insert(to_row(dashboard_id, input))
            .exec(&self.connection)
            .await
            .context("saving widget")?;
        Ok(result.last_insert_id)
    }

    /// Only if it's on this dashboard.
    pub async fn get_widget(&self, dashboard_id: i64, id: i64) -> Result<Option<Widget>> {
        let row = dashboard_widget::Entity::find_by_id(id)
            .filter(dashboard_widget::Column::DashboardId.eq(dashboard_id))
            .one(&self.connection)
            .await
            .context("loading widget")?;
        Ok(row.map(to_widget))
    }

    /// Returns false if it isn't on this dashboard.
    pub async fn update_widget(
        &self,
        dashboard_id: i64,
        id: i64,
        input: &WidgetInput,
    ) -> Result<bool> {
        if self.get_widget(dashboard_id, id).await?.is_none() {
            return Ok(false);
        }
        let mut row = to_row(dashboard_id, input);
        row.id = Set(id);
        dashboard_widget::Entity::update(row)
            .exec(&self.connection)
            .await
            .context("saving widget")?;
        Ok(true)
    }

    /// Returns false if it isn't on this dashboard.
    pub async fn delete_widget(&self, dashboard_id: i64, id: i64) -> Result<bool> {
        let result = dashboard_widget::Entity::delete_many()
            .filter(dashboard_widget::Column::Id.eq(id))
            .filter(dashboard_widget::Column::DashboardId.eq(dashboard_id))
            .exec(&self.connection)
            .await
            .context("removing widget")?;
        Ok(result.rows_affected > 0)
    }

    /// Moves widgets together, so a layout is never left half saved. Widgets that
    /// aren't on this dashboard are left alone.
    pub async fn place_widgets(&self, dashboard_id: i64, widgets: &[Placed]) -> Result<()> {
        let transaction = self.connection.begin().await?;
        for widget in widgets {
            let placement = widget.placement;
            dashboard_widget::Entity::update_many()
                .col_expr(dashboard_widget::Column::X, placement.x.into())
                .col_expr(dashboard_widget::Column::Y, placement.y.into())
                .col_expr(dashboard_widget::Column::W, placement.w.into())
                .col_expr(dashboard_widget::Column::H, placement.h.into())
                .filter(dashboard_widget::Column::Id.eq(widget.id))
                .filter(dashboard_widget::Column::DashboardId.eq(dashboard_id))
                .exec(&transaction)
                .await
                .context("moving widget")?;
        }
        transaction.commit().await?;
        Ok(())
    }
}
