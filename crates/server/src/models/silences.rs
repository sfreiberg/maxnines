//! Silences, which keep notifications back for a while.

use anyhow::{Context, Result};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set};

use super::{Database, silence};
use crate::silences::{Silence, SilenceInput};

fn to_silence(row: silence::Model) -> Silence {
    Silence {
        id: row.id,
        rule_id: row.rule_id,
        filter: row.filter,
        reason: row.reason,
        created_by: row.created_by,
        starts_ms: row.starts_ms,
        ends_ms: row.ends_ms,
    }
}

impl Database {
    /// The one that lasts longest comes first.
    pub async fn active_silences(&self, now_ms: i64) -> Result<Vec<Silence>> {
        let rows = silence::Entity::find()
            .filter(silence::Column::StartsMs.lte(now_ms))
            .filter(silence::Column::EndsMs.gt(now_ms))
            .order_by_desc(silence::Column::EndsMs)
            .order_by_desc(silence::Column::Id)
            .all(&self.connection)
            .await
            .context("loading silences")?;
        Ok(rows.into_iter().map(to_silence).collect())
    }

    /// The ones that ended most recently.
    pub async fn ended_silences(&self, now_ms: i64, limit: u64) -> Result<Vec<Silence>> {
        let rows = silence::Entity::find()
            .filter(silence::Column::EndsMs.lte(now_ms))
            .order_by_desc(silence::Column::EndsMs)
            .order_by_desc(silence::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading silences")?;
        Ok(rows.into_iter().map(to_silence).collect())
    }

    pub async fn get_silence(&self, id: i64) -> Result<Option<Silence>> {
        let row = silence::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading silence")?;
        Ok(row.map(to_silence))
    }

    /// Starts now, and `by` says who asked for it.
    pub async fn create_silence(&self, input: &SilenceInput, by: &str, now_ms: i64) -> Result<i64> {
        let lasts_ms = i64::try_from(input.duration_secs)
            .context("invalid duration")?
            .saturating_mul(1000);
        let row = silence::ActiveModel {
            rule_id: Set(input.rule_id),
            filter: Set(input.filter.trim().to_string()),
            reason: Set(input.reason.trim().to_string()),
            created_by: Set(by.to_string()),
            starts_ms: Set(now_ms),
            ends_ms: Set(now_ms.saturating_add(lasts_ms)),
            ..Default::default()
        };
        let result = silence::Entity::insert(row)
            .exec(&self.connection)
            .await
            .context("saving silence")?;
        Ok(result.last_insert_id)
    }

    /// Returns false if there's no such silence running.
    pub async fn end_silence(&self, id: i64, now_ms: i64) -> Result<bool> {
        let result = silence::Entity::update_many()
            .col_expr(silence::Column::EndsMs, Expr::value(now_ms))
            .filter(silence::Column::Id.eq(id))
            .filter(silence::Column::EndsMs.gt(now_ms))
            .exec(&self.connection)
            .await
            .context("ending silence")?;
        Ok(result.rows_affected > 0)
    }
}
