//! Checks the server runs itself.

use anyhow::{Context, Result};
use maxnines_protocol::{Check, CheckKind};
use sea_orm::{EntityTrait, QueryOrder, Set};

use super::{Database, remote_check};
use crate::remote_checks::{RemoteCheck, RemoteCheckInput};

fn to_remote_check(row: remote_check::Model) -> Result<RemoteCheck> {
    let kind = CheckKind::parse(&row.kind).context("unknown kind of check")?;
    let mut check = Check::new(&row.name, kind, &row.target);
    check.timeout_secs = row.timeout_secs.map(u64::try_from).transpose()?;
    check.method = row.method;
    check.body = row.body;
    check.regex = row.regex;
    check.insecure = row.insecure;
    check.server = row.server;
    check.record = row.record;
    check.count = row.count.map(u32::try_from).transpose()?;
    Ok(RemoteCheck {
        id: row.id,
        input: RemoteCheckInput {
            check,
            interval_secs: u64::try_from(row.interval_secs)?,
            enabled: row.enabled,
        },
    })
}

fn to_row(input: &RemoteCheckInput) -> Result<remote_check::ActiveModel> {
    let check = &input.check;
    Ok(remote_check::ActiveModel {
        name: Set(check.name.clone()),
        kind: Set(check.kind.as_str().to_string()),
        target: Set(check.target.clone()),
        timeout_secs: Set(check.timeout_secs.map(i64::try_from).transpose()?),
        method: Set(check.method.clone()),
        body: Set(check.body.clone()),
        regex: Set(check.regex.clone()),
        insecure: Set(check.insecure),
        server: Set(check.server.clone()),
        record: Set(check.record.clone()),
        count: Set(check.count.map(i32::try_from).transpose()?),
        interval_secs: Set(i64::try_from(input.interval_secs)?),
        enabled: Set(input.enabled),
        ..Default::default()
    })
}

impl Database {
    /// Sorted by name.
    pub async fn list_remote_checks(&self) -> Result<Vec<RemoteCheck>> {
        let rows = remote_check::Entity::find()
            .order_by_asc(remote_check::Column::Name)
            .all(&self.connection)
            .await
            .context("loading checks")?;
        rows.into_iter().map(to_remote_check).collect()
    }

    pub async fn get_remote_check(&self, id: i64) -> Result<Option<RemoteCheck>> {
        let row = remote_check::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading check")?;
        row.map(to_remote_check).transpose()
    }

    pub async fn create_remote_check(&self, input: &RemoteCheckInput) -> Result<i64> {
        let result = remote_check::Entity::insert(to_row(input)?)
            .exec(&self.connection)
            .await
            .context("saving check")?;
        Ok(result.last_insert_id)
    }

    /// Returns false if there's no such check.
    pub async fn update_remote_check(&self, id: i64, input: &RemoteCheckInput) -> Result<bool> {
        if self.get_remote_check(id).await?.is_none() {
            return Ok(false);
        }
        let mut row = to_row(input)?;
        row.id = Set(id);
        remote_check::Entity::update(row)
            .exec(&self.connection)
            .await
            .context("saving check")?;
        Ok(true)
    }

    /// Returns false if there's no such check.
    pub async fn delete_remote_check(&self, id: i64) -> Result<bool> {
        let result = remote_check::Entity::delete_by_id(id)
            .exec(&self.connection)
            .await
            .context("deleting check")?;
        Ok(result.rows_affected > 0)
    }
}
