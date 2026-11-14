//! OpenMetrics pages the server reads for hosts with no agent.

use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};

use super::audit::record_change;
use super::{Database, metrics_page};
use crate::audit::{Kind, Snapshot};
use crate::metrics_pages::{MetricsPage, MetricsPageInput, check_names};

fn to_page(row: metrics_page::Model) -> Result<MetricsPage> {
    Ok(MetricsPage {
        id: row.id,
        host_id: row.host_id,
        input: MetricsPageInput {
            url: row.url,
            names: row.names.lines().map(str::to_string).collect(),
            interval_secs: u64::try_from(row.interval_secs)?,
            enabled: row.enabled,
            username: row.username,
            password: row.password,
            password_env: row.password_env,
        },
    })
}

fn to_row(host_id: &str, input: &MetricsPageInput) -> Result<metrics_page::ActiveModel> {
    Ok(metrics_page::ActiveModel {
        host_id: Set(host_id.to_string()),
        url: Set(input.url.clone()),
        names: Set(input.names.join("\n")),
        interval_secs: Set(i64::try_from(input.interval_secs)?),
        enabled: Set(input.enabled),
        username: Set(input.username.clone()),
        password: Set(input.password.clone()),
        password_env: Set(input.password_env.clone()),
        ..Default::default()
    })
}

async fn load<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<MetricsPage>> {
    let row = metrics_page::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading metrics page")?;
    row.map(to_page).transpose()
}

async fn of_host<C: ConnectionTrait>(connection: &C, host_id: &str) -> Result<Vec<MetricsPage>> {
    let rows = metrics_page::Entity::find()
        .filter(metrics_page::Column::HostId.eq(host_id))
        .order_by_asc(metrics_page::Column::Url)
        .all(connection)
        .await
        .context("loading metrics pages")?;
    rows.into_iter().map(to_page).collect()
}

/// Records how a page changed from `before`, reading it as it is now. A password
/// only ever shows as having changed.
async fn record<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&MetricsPage>,
) -> Result<()> {
    let after = load(connection, id).await?;
    let snapshot = |page: &MetricsPage| Snapshot::of(page.input.name(), &page.input);
    let before = before.map(snapshot).transpose()?;
    let after = after.as_ref().map(snapshot).transpose()?;
    record_change(
        connection,
        Kind::MetricsPage,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
}

impl Database {
    /// Every host's pages.
    pub async fn list_metrics_pages(&self) -> Result<Vec<MetricsPage>> {
        let rows = metrics_page::Entity::find()
            .order_by_asc(metrics_page::Column::Id)
            .all(&self.connection)
            .await
            .context("loading metrics pages")?;
        rows.into_iter().map(to_page).collect()
    }

    /// One host's pages, sorted by address.
    pub async fn metrics_pages_of(&self, host_id: &str) -> Result<Vec<MetricsPage>> {
        of_host(&self.connection, host_id).await
    }

    pub async fn get_metrics_page(&self, id: i64) -> Result<Option<MetricsPage>> {
        load(&self.connection, id).await
    }

    /// Fails if the host's pages couldn't be told apart with this one among them.
    pub async fn create_metrics_page(
        &self,
        host_id: &str,
        input: &MetricsPageInput,
    ) -> Result<i64> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving metrics page")?;
        let others = of_host(&transaction, host_id).await?;
        check_names(others.iter().map(|page| &page.input).chain([input]))?;
        let id = metrics_page::Entity::insert(to_row(host_id, input)?)
            .exec(&transaction)
            .await
            .context("saving metrics page")?
            .last_insert_id;
        record(&transaction, id, None).await?;
        transaction.commit().await.context("saving metrics page")?;
        Ok(id)
    }

    /// Returns false if there's no such page. A change that gives no password
    /// keeps the one that's saved.
    pub async fn update_metrics_page(&self, id: i64, input: MetricsPageInput) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving metrics page")?;
        let Some(before) = load(&transaction, id).await? else {
            return Ok(false);
        };
        let input = input.keeping_password_of(&before.input);
        let others = of_host(&transaction, &before.host_id).await?;
        let others = others.iter().filter(|page| page.id != id);
        check_names(others.map(|page| &page.input).chain([&input]))?;
        let mut row = to_row(&before.host_id, &input)?;
        row.id = Set(id);
        metrics_page::Entity::update(row)
            .exec(&transaction)
            .await
            .context("saving metrics page")?;
        record(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving metrics page")?;
        Ok(true)
    }

    /// Returns false if there's no such page.
    pub async fn delete_metrics_page(&self, id: i64) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("deleting metrics page")?;
        let before = load(&transaction, id).await?;
        let result = metrics_page::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting metrics page")?;
        record(&transaction, id, before.as_ref()).await?;
        transaction
            .commit()
            .await
            .context("deleting metrics page")?;
        Ok(result.rows_affected > 0)
    }
}
