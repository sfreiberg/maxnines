//! Writing the audit log, always in the transaction making the change, and
//! reading it back.

use anyhow::{Context, Result};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};

use super::{Database, audit_entry};
use crate::audit::{
    self, Action, Entry, EntryActor, EntrySubject, EntryVia, Kind, Record, Snapshot, Via,
};
use crate::times;

/// The longest name kept, in characters, as the columns allow.
const MAX_NAME_CHARS: usize = 255;
const MAX_ID_CHARS: usize = 128;

fn clip(text: &str, chars: usize) -> String {
    text.chars().take(chars).collect()
}

/// Adds to the log through `connection`, which should be the change's transaction.
pub(super) async fn record<C: ConnectionTrait>(connection: &C, record: Record) -> Result<()> {
    record_all(connection, [record]).await
}

/// Adds entries to the log in one statement, in order, as [`record`] adds one.
pub(super) async fn record_all<C: ConnectionTrait>(
    connection: &C,
    records: impl IntoIterator<Item = Record>,
) -> Result<()> {
    let rows: Vec<_> = records.into_iter().map(entry_row).collect();
    if rows.is_empty() {
        return Ok(());
    }
    audit_entry::Entity::insert_many(rows)
        .exec_without_returning(connection)
        .await
        .context("adding to the audit log")?;
    Ok(())
}

/// An entry as it's kept, by whoever is acting now unless it says otherwise.
fn entry_row(record: Record) -> audit_entry::ActiveModel {
    let acting = audit::current();
    let actor = record.actor.unwrap_or(acting.actor);
    audit_entry::ActiveModel {
        occurred_at: Set(times::now()),
        actor_kind: Set(actor.kind().to_string()),
        actor_id: Set(actor.id()),
        actor_name: Set(clip(&actor.name(), MAX_NAME_CHARS)),
        via_kind: Set(acting.via.as_ref().map(|via| via.kind().to_string())),
        via_id: Set(acting.via.as_ref().and_then(Via::id)),
        via_name: Set(acting
            .via
            .as_ref()
            .map(|via| clip(&via.name(), MAX_NAME_CHARS))),
        source: Set(acting.source.map(|ip| ip.to_string())),
        forwarded_for: Set(acting.forwarded_for.map(|ip| ip.to_string())),
        action: Set(record.action.as_str().to_string()),
        subject_kind: Set(record.subject.kind.as_str().to_string()),
        subject_id: Set(record.subject.id.map(|id| clip(&id, MAX_ID_CHARS))),
        subject_name: Set(clip(&record.subject.name, MAX_NAME_CHARS)),
        changes: Set(audit_entry::Changes(record.changes)),
        ..Default::default()
    }
}

/// Records the difference between two snapshots, if there is one. A missing
/// `before` means created and a missing `after` deleted, unless `action` says.
pub(super) async fn record_change<C: ConnectionTrait>(
    connection: &C,
    kind: Kind,
    id: impl ToString,
    before: Option<&Snapshot>,
    after: Option<&Snapshot>,
    action: Option<Action>,
) -> Result<()> {
    match Record::of_change(kind, id, before, after, action) {
        Some(entry) => record(connection, entry).await,
        None => Ok(()),
    }
}

fn to_entry(row: audit_entry::Model) -> Entry {
    Entry {
        id: row.id,
        occurred_at: row.occurred_at,
        actor: EntryActor {
            kind: row.actor_kind,
            id: row.actor_id,
            name: row.actor_name,
        },
        via: row.via_kind.map(|kind| EntryVia {
            kind,
            id: row.via_id,
            name: row.via_name.unwrap_or_default(),
        }),
        source: row.source,
        forwarded_for: row.forwarded_for,
        action: row.action,
        subject: EntrySubject {
            kind: row.subject_kind,
            id: row.subject_id,
            name: row.subject_name,
        },
        changes: row.changes.0,
    }
}

impl Database {
    /// Adds an entry that isn't part of a change, like a failed sign in.
    pub async fn record_audit(&self, entry: Record) -> Result<()> {
        record(&self.connection, entry).await
    }

    /// Newest first, up to `limit` of them, from before the entry `before` if given.
    pub async fn audit_log(&self, before: Option<i64>, limit: u64) -> Result<Vec<Entry>> {
        let mut query = audit_entry::Entity::find().order_by_desc(audit_entry::Column::Id);
        if let Some(before) = before {
            query = query.filter(audit_entry::Column::Id.lt(before));
        }
        let rows = query
            .limit(limit)
            .all(&self.connection)
            .await
            .context("reading the audit log")?;
        Ok(rows.into_iter().map(to_entry).collect())
    }
}
