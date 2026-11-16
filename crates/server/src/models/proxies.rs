//! What admins decided about proxies in front of the server.

use anyhow::{Context, Result};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde_json::json;

use super::audit::record_change;
use super::{Database, proxy};
use crate::audit::{Kind, Snapshot};
use crate::proxies::Decision;

impl From<proxy::Model> for Decision {
    fn from(row: proxy::Model) -> Self {
        Self {
            id: row.id,
            address: row.address,
            trusted: row.trusted,
            created_ms: row.created_ms,
        }
    }
}

fn snapshot(row: &proxy::Model) -> Snapshot {
    Snapshot::new(
        row.address.clone(),
        json!({ "address": row.address, "trusted": row.trusted }),
    )
}

impl Database {
    /// Every decision, in the order they were made.
    pub async fn list_proxies(&self) -> Result<Vec<Decision>> {
        let rows = proxy::Entity::find()
            .order_by_asc(proxy::Column::Id)
            .all(&self.connection)
            .await
            .context("loading proxies")?;
        Ok(rows.into_iter().map(Decision::from).collect())
    }

    /// Decides about `address`, which [`crate::proxies::check_address`] has checked,
    /// changing an earlier decision about the same one.
    pub async fn decide_proxy(
        &self,
        address: &str,
        trusted: bool,
        now_ms: i64,
    ) -> Result<Decision> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let existing = proxy::Entity::find()
            .filter(proxy::Column::Address.eq(address))
            .one(&transaction)
            .await
            .context("loading a proxy")?;
        let row = match existing {
            Some(row) if row.trusted == trusted => row,
            Some(row) => {
                let before = snapshot(&row);
                let mut changed: proxy::ActiveModel = row.into();
                changed.trusted = Set(trusted);
                let row = changed
                    .update(&transaction)
                    .await
                    .context("saving a proxy")?;
                let after = snapshot(&row);
                record_change(
                    &transaction,
                    Kind::Proxy,
                    row.id,
                    Some(&before),
                    Some(&after),
                    None,
                )
                .await?;
                row
            }
            None => {
                let row = proxy::ActiveModel {
                    address: Set(address.to_string()),
                    trusted: Set(trusted),
                    created_ms: Set(now_ms),
                    ..Default::default()
                }
                .insert(&transaction)
                .await
                .context("saving a proxy")?;
                let after = snapshot(&row);
                record_change(&transaction, Kind::Proxy, row.id, None, Some(&after), None).await?;
                row
            }
        };
        transaction.commit().await.context("saving a proxy")?;
        Ok(row.into())
    }

    /// Forgets a decision. Gives back whether there was one.
    pub async fn delete_proxy(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("starting a save")?;
        let Some(row) = proxy::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading a proxy")?
        else {
            return Ok(false);
        };
        proxy::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting a proxy")?;
        let before = snapshot(&row);
        record_change(&transaction, Kind::Proxy, row.id, Some(&before), None, None).await?;
        transaction.commit().await.context("deleting a proxy")?;
        Ok(true)
    }
}
