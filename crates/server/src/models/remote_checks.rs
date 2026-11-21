//! Checks the server runs itself.

use std::time::Duration;

use anyhow::{Context, Result};
use maxnines_protocol::{Check, CheckKind};
use sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Set, TransactionTrait};

use super::audit::record_change;
use super::{Database, name_key, name_taken_or, remote_check, save_host_in};
use crate::alerting::NameTaken;
use crate::audit::{Kind, Snapshot};
use crate::registration::HostRecord;
use crate::remote_checks::{RemoteCheck, RemoteCheckInput, SignIn};

fn to_remote_check(row: remote_check::Model) -> Result<RemoteCheck> {
    let kind = CheckKind::parse(&row.kind).context("unknown kind of check")?;
    let mut check = Check::new(&row.name, kind, &row.target);
    check.timeout = row
        .timeout_secs
        .map(u64::try_from)
        .transpose()?
        .map(Duration::from_secs);
    check.method = row.method;
    check.body = row.body;
    check.regex = row.regex;
    check.insecure = row.insecure;
    check.server = row.server;
    check.record = row.record;
    check.count = row.count.map(u32::try_from).transpose()?;
    check.database = row.database;
    check.tls = row.tls;
    check.host_key = row.host_key;
    check.domain_expiry = row.domain_expiry;
    Ok(RemoteCheck {
        id: row.id,
        input: RemoteCheckInput {
            host_id: row.host_id,
            check,
            interval: Duration::from_secs(u64::try_from(row.interval_secs)?),
            enabled: row.enabled,
            read_stats: row.read_stats,
            extras: row
                .extras
                .map(|extras| extras.split(',').map(String::from).collect())
                .unwrap_or_default(),
            sign_in: SignIn {
                username: row.username,
                password: row.password,
                password_env: row.password_env,
                private_key: row.private_key,
                private_key_env: row.private_key_env,
            },
        },
    })
}

fn to_row(input: &RemoteCheckInput) -> Result<remote_check::ActiveModel> {
    let check = &input.check;
    Ok(remote_check::ActiveModel {
        host_id: Set(input.host_id.clone()),
        name: Set(check.name.clone()),
        name_key: Set(name_key(&check.name)),
        kind: Set(check.kind.as_str().to_string()),
        target: Set(check.target.clone()),
        timeout_secs: Set(check
            .timeout
            .map(|timeout| i64::try_from(timeout.as_secs()))
            .transpose()?),
        method: Set(check.method.clone()),
        body: Set(check.body.clone()),
        regex: Set(check.regex.clone()),
        insecure: Set(check.insecure),
        server: Set(check.server.clone()),
        record: Set(check.record.clone()),
        count: Set(check.count.map(i32::try_from).transpose()?),
        interval_secs: Set(i64::try_from(input.interval.as_secs())?),
        enabled: Set(input.enabled),
        database: Set(check.database.clone()),
        tls: Set(check.tls),
        host_key: Set(check.host_key.clone()),
        domain_expiry: Set(check.domain_expiry),
        read_stats: Set(input.read_stats),
        extras: Set((!input.extras.is_empty()).then(|| input.extras.join(","))),
        username: Set(input.sign_in.username.clone()),
        password: Set(input.sign_in.password.clone()),
        password_env: Set(input.sign_in.password_env.clone()),
        private_key: Set(input.sign_in.private_key.clone()),
        private_key_env: Set(input.sign_in.private_key_env.clone()),
        ..Default::default()
    })
}

/// What saving a check whose name another about the same host has is refused with.
fn name_taken(input: &RemoteCheckInput) -> NameTaken {
    NameTaken::RemoteCheck(input.check.name.clone())
}

/// Adds a check, and records it, in `connection`'s transaction.
async fn insert<C: ConnectionTrait>(connection: &C, input: &RemoteCheckInput) -> Result<i64> {
    let id = remote_check::Entity::insert(to_row(input)?)
        .exec(connection)
        .await
        .map_err(|error| name_taken_or(error, name_taken(input), "saving check"))?
        .last_insert_id;
    record(connection, id, None).await?;
    Ok(id)
}

async fn load<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<RemoteCheck>> {
    let row = remote_check::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading check")?;
    row.map(to_remote_check).transpose()
}

/// Records how a check changed from `before`, reading it as it is now.
async fn record<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&RemoteCheck>,
) -> Result<()> {
    let after = load(connection, id).await?;
    let snapshot = |c: &RemoteCheck| Snapshot::of(c.input.check.name.clone(), &c.input);
    let before = before.map(snapshot).transpose()?;
    let after = after.as_ref().map(snapshot).transpose()?;
    record_change(
        connection,
        Kind::RemoteCheck,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
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
        load(&self.connection, id).await
    }

    pub async fn create_remote_check(&self, input: &RemoteCheckInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving check")?;
        let id = insert(&transaction, input).await?;
        transaction.commit().await.context("saving check")?;
        Ok(id)
    }

    /// Adds `host` and a check about it together, so that either both are saved, with
    /// what the audit log says of each, or neither is.
    pub async fn create_host_with_check(
        &self,
        host: &HostRecord,
        input: &RemoteCheckInput,
    ) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving check")?;
        save_host_in(&transaction, host).await?;
        let id = insert(&transaction, input).await?;
        transaction.commit().await.context("saving check")?;
        Ok(id)
    }

    /// Returns false if there's no such check.
    pub async fn update_remote_check(&self, id: i64, input: &RemoteCheckInput) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving check")?;
        let Some(before) = load(&transaction, id).await? else {
            return Ok(false);
        };
        let mut row = to_row(input)?;
        row.id = Set(id);
        remote_check::Entity::update(row)
            .exec(&transaction)
            .await
            .map_err(|error| name_taken_or(error, name_taken(input), "saving check"))?;
        record(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving check")?;
        Ok(true)
    }

    /// Returns false if there's no such check.
    pub async fn delete_remote_check(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting check")?;
        let before = load(&transaction, id).await?;
        let result = remote_check::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting check")?;
        record(&transaction, id, before.as_ref()).await?;
        transaction.commit().await.context("deleting check")?;
        Ok(result.rows_affected > 0)
    }
}
