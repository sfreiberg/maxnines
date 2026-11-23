//! What heartbeat checks have been pinged with, and the addresses they're pinged at.

use std::collections::HashMap;

use anyhow::{Context, Result};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};

use super::{Database, heartbeat, remote_check, remote_checks};
use crate::heartbeats::{Ping, Pings};
use crate::remote_checks::RemoteCheck;
use crate::times::Timestamp;

fn to_pings(row: heartbeat::Model) -> Pings {
    Pings {
        pinged_at: row.pinged_at,
        failed: row.failed,
        started_at: row.started_at,
        run_secs: row.run_secs,
    }
}

impl Database {
    /// The heartbeat check pinged at `token`, if there's one.
    pub async fn heartbeat_by_token(&self, token: &str) -> Result<Option<RemoteCheck>> {
        let row = remote_check::Entity::find()
            .filter(remote_check::Column::PingToken.eq(token))
            .one(&self.connection)
            .await
            .context("loading check")?;
        row.map(remote_checks::to_remote_check).transpose()
    }

    /// What each heartbeat check that's been pinged was last pinged with, by its ID.
    pub async fn heartbeat_pings(&self) -> Result<HashMap<i64, Pings>> {
        let rows = heartbeat::Entity::find()
            .all(&self.connection)
            .await
            .context("loading heartbeats")?;
        Ok(rows
            .into_iter()
            .map(|row| (row.remote_check_id, to_pings(row)))
            .collect())
    }

    /// Notes a ping of check `id` at `at`, and gives what it's been pinged with since.
    pub async fn record_ping(&self, id: i64, ping: Ping, at: Timestamp) -> Result<Pings> {
        let transaction = self.connection.begin().await.context("saving a ping")?;
        let saved = heartbeat::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("saving a ping")?;
        let before = saved.clone().map(to_pings).unwrap_or_default();
        let after = before.after(ping, at);
        let row = heartbeat::ActiveModel {
            remote_check_id: Set(id),
            pinged_at: Set(after.pinged_at),
            failed: Set(after.failed),
            started_at: Set(after.started_at),
            run_secs: Set(after.run_secs),
        };
        if saved.is_some() {
            heartbeat::Entity::update(row).exec(&transaction).await
        } else {
            heartbeat::Entity::insert(row)
                .exec_without_returning(&transaction)
                .await
                .map(|_| heartbeat::Model {
                    remote_check_id: id,
                    pinged_at: after.pinged_at,
                    failed: after.failed,
                    started_at: after.started_at,
                    run_secs: after.run_secs,
                })
        }
        .context("saving a ping")?;
        transaction.commit().await.context("saving a ping")?;
        Ok(after)
    }

    /// Gives heartbeat check `id` a new address to be pinged at, so the old one stops
    /// working. Gives the new one's token, or nothing if there's no such heartbeat.
    pub async fn new_ping_token(&self, id: i64) -> Result<Option<String>> {
        remote_checks::renew_ping_token(&self.connection, id).await
    }
}
