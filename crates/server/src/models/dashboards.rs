//! Dashboards and their widgets.

use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use serde_json::{Map, Value, json};

use super::audit::record_change;
use super::{Database, dashboard, dashboard_variable, dashboard_widget};
use crate::audit::{Kind, Snapshot};
use crate::dashboard_variables::{Variable, VariableKind};
use crate::dashboards::{Dashboard, DashboardSummary, Placed, Placement, Widget, WidgetInput};

/// A row is only ever written from a checked variable, so an unknown kind is a
/// database someone changed by hand, and it's read as a fact rather than lost.
fn to_variable(row: dashboard_variable::Model) -> Variable {
    Variable {
        name: row.name,
        label: row.label,
        kind: VariableKind::parse(&row.kind).unwrap_or(VariableKind::Fact),
        fact: row.fact,
        filter: row.filter,
    }
}

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

/// With its widgets, from the top of the page down.
async fn load<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<Dashboard>> {
    let Some(row) = dashboard::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading dashboard")?
    else {
        return Ok(None);
    };
    let widgets = dashboard_widget::Entity::find()
        .filter(dashboard_widget::Column::DashboardId.eq(id))
        .order_by_asc(dashboard_widget::Column::Y)
        .order_by_asc(dashboard_widget::Column::X)
        .all(connection)
        .await
        .context("loading widgets")?;
    let variables = dashboard_variable::Entity::find()
        .filter(dashboard_variable::Column::DashboardId.eq(id))
        .order_by_asc(dashboard_variable::Column::Position)
        .all(connection)
        .await
        .context("loading variables")?;
    Ok(Some(Dashboard {
        id: row.id,
        name: row.name,
        variables: variables.into_iter().map(to_variable).collect(),
        widgets: widgets.into_iter().map(to_widget).collect(),
    }))
}

/// A dashboard as the audit log compares them, with each widget under its ID so
/// one being removed doesn't look like every one after it changing.
fn snapshot(dashboard: &Dashboard) -> Result<Snapshot> {
    let mut widgets = Map::new();
    for widget in &dashboard.widgets {
        let fields = serde_json::to_value(&widget.input).context("recording a widget")?;
        widgets.insert(widget.id.to_string(), fields);
    }
    let fields = json!({
        "name": dashboard.name,
        "variables": dashboard.variables,
        "widgets": Value::Object(widgets),
    });
    Ok(Snapshot::new(dashboard.name.clone(), fields))
}

/// Records how a dashboard changed from `before`, reading it as it is now.
async fn record<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&Dashboard>,
) -> Result<()> {
    let after = load(connection, id).await?;
    let before = before.map(snapshot).transpose()?;
    let after = after.as_ref().map(snapshot).transpose()?;
    record_change(
        connection,
        Kind::Dashboard,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
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
        load(&self.connection, id).await
    }

    pub async fn create_dashboard(&self, name: &str, now_ms: i64) -> Result<i64> {
        let row = dashboard::ActiveModel {
            name: Set(name.to_string()),
            created_ms: Set(now_ms),
            ..Default::default()
        };
        let transaction = self.connection.begin().await.context("saving dashboard")?;
        let id = dashboard::Entity::insert(row)
            .exec(&transaction)
            .await
            .context("saving dashboard")?
            .last_insert_id;
        record(&transaction, id, None).await?;
        transaction.commit().await.context("saving dashboard")?;
        Ok(id)
    }

    /// Returns false if there's no such dashboard.
    pub async fn rename_dashboard(&self, id: i64, name: &str) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving dashboard")?;
        let before = load(&transaction, id).await?;
        let result = dashboard::Entity::update_many()
            .col_expr(dashboard::Column::Name, name.into())
            .filter(dashboard::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("saving dashboard")?;
        record(&transaction, id, before.as_ref()).await?;
        transaction.commit().await.context("saving dashboard")?;
        Ok(result.rows_affected > 0)
    }

    /// Returns false if there's no such dashboard. Not every database enforces the
    /// link between the tables the same way, so its widgets are removed here.
    pub async fn delete_dashboard(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await?;
        let before = load(&transaction, id).await?;
        dashboard_widget::Entity::delete_many()
            .filter(dashboard_widget::Column::DashboardId.eq(id))
            .exec(&transaction)
            .await
            .context("removing widgets")?;
        dashboard_variable::Entity::delete_many()
            .filter(dashboard_variable::Column::DashboardId.eq(id))
            .exec(&transaction)
            .await
            .context("removing variables")?;
        let result = dashboard::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("removing dashboard")?;
        record(&transaction, id, before.as_ref()).await?;
        transaction.commit().await?;
        Ok(result.rows_affected > 0)
    }

    pub async fn create_widget(&self, dashboard_id: i64, input: &WidgetInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving widget")?;
        let before = load(&transaction, dashboard_id).await?;
        let id = dashboard_widget::Entity::insert(to_row(dashboard_id, input))
            .exec(&transaction)
            .await
            .context("saving widget")?
            .last_insert_id;
        record(&transaction, dashboard_id, before.as_ref()).await?;
        transaction.commit().await.context("saving widget")?;
        Ok(id)
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
        let transaction = self.connection.begin().await.context("saving widget")?;
        let before = load(&transaction, dashboard_id).await?;
        let mut row = to_row(dashboard_id, input);
        row.id = Set(id);
        dashboard_widget::Entity::update(row)
            .exec(&transaction)
            .await
            .context("saving widget")?;
        record(&transaction, dashboard_id, before.as_ref()).await?;
        transaction.commit().await.context("saving widget")?;
        Ok(true)
    }

    /// Returns false if it isn't on this dashboard.
    pub async fn delete_widget(&self, dashboard_id: i64, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("removing widget")?;
        let before = load(&transaction, dashboard_id).await?;
        let result = dashboard_widget::Entity::delete_many()
            .filter(dashboard_widget::Column::Id.eq(id))
            .filter(dashboard_widget::Column::DashboardId.eq(dashboard_id))
            .exec(&transaction)
            .await
            .context("removing widget")?;
        record(&transaction, dashboard_id, before.as_ref()).await?;
        transaction.commit().await.context("removing widget")?;
        Ok(result.rows_affected > 0)
    }

    /// Replaces a dashboard's variables with these, in this order. Returns false if
    /// there's no such dashboard.
    pub async fn save_variables(&self, dashboard_id: i64, variables: &[Variable]) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving variables")?;
        let Some(before) = load(&transaction, dashboard_id).await? else {
            return Ok(false);
        };
        dashboard_variable::Entity::delete_many()
            .filter(dashboard_variable::Column::DashboardId.eq(dashboard_id))
            .exec(&transaction)
            .await
            .context("saving variables")?;
        for (position, variable) in (0..).zip(variables) {
            let row = dashboard_variable::ActiveModel {
                dashboard_id: Set(dashboard_id),
                position: Set(position),
                name: Set(variable.name.clone()),
                label: Set(variable.label.clone()),
                kind: Set(variable.kind.as_str().to_string()),
                fact: Set(variable.fact.clone()),
                filter: Set(variable.filter.clone()),
                ..Default::default()
            };
            dashboard_variable::Entity::insert(row)
                .exec(&transaction)
                .await
                .context("saving variables")?;
        }
        record(&transaction, dashboard_id, Some(&before)).await?;
        transaction.commit().await.context("saving variables")?;
        Ok(true)
    }

    /// Moves widgets together, so a layout is never left half saved. Widgets that
    /// aren't on this dashboard are left alone.
    pub async fn place_widgets(&self, dashboard_id: i64, widgets: &[Placed]) -> Result<()> {
        let transaction = self.connection.begin().await?;
        let before = load(&transaction, dashboard_id).await?;
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
        record(&transaction, dashboard_id, before.as_ref()).await?;
        transaction.commit().await?;
        Ok(())
    }
}
