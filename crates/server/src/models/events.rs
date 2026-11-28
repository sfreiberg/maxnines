//! Events marked on charts: annotations, recorded by people and their scripts, what the
//! server noticed itself, and a host's whole timeline, which adds its alerts and
//! updates from what's kept about them. An event keeps the hosts it was for when it was
//! recorded, so it stays on those and isn't put on hosts added later.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, JoinType, QueryFilter,
    QueryOrder, QuerySelect, RelationDef, Set, TransactionTrait,
};
use serde_json::json;

use super::alerting::to_alerts;
use super::audit::record_change;
use super::{Database, alert, event, event_host, host, host_boot, host_fact, to_fact_version};
use crate::audit::{self, Kind, Snapshot};
use crate::events::{Event, EventKind, SERVER, TimelineEvent, UPDATE_FACTS};
use crate::host_filter;
use crate::times::Timestamp;

/// The most of a host's events a timeline holds, newest first.
pub const MAX_TIMELINE: u64 = 500;
/// How many of an event's hosts are saved in one statement, well under every
/// database's limit on the values one can hold.
const HOSTS_AT_ONCE: usize = 1_000;

fn snapshot(row: &event::Model) -> Snapshot {
    let fields = json!({
        "kind": row.kind,
        "title": row.title,
        "detail": row.detail,
        "time": audit::time(row.occurred_at),
        "filter": row.filter,
    });
    Snapshot::new(&row.title, fields)
}

fn to_event(row: event::Model) -> Event {
    Event {
        id: row.id,
        occurred_at: row.occurred_at,
        kind: EventKind::parse(&row.kind).unwrap_or(EventKind::Note),
        title: row.title,
        detail: row.detail,
        filter: row.filter,
        created_by: row.created_by,
        created_at: row.created_at,
    }
}

/// What a fact held, as a person would write it.
fn written(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// What someone records, ready to save.
pub struct NewEvent<'a> {
    pub kind: EventKind,
    pub occurred_at: Timestamp,
    pub title: &'a str,
    pub detail: Option<&'a str>,
    /// Which hosts it's for, as a host filter. None for every host.
    pub filter: Option<&'a str>,
    /// The hosts that filter picked as it was recorded, which it's kept for.
    pub hosts: &'a [String],
}

async fn insert_event<C: ConnectionTrait>(
    connection: &C,
    new: &NewEvent<'_>,
    by: &str,
    now: Timestamp,
) -> Result<Option<event::Model>> {
    // Only hosts that are still there, as one may have been deleted since they
    // were picked, and an event is never kept for no host.
    let mut hosts = Vec::new();
    for asked in new.hosts.chunks(HOSTS_AT_ONCE) {
        let kept: Vec<String> = host::Entity::find()
            .select_only()
            .column(host::Column::Id)
            .filter(host::Column::Id.is_in(asked.iter().cloned()))
            .into_tuple()
            .all(connection)
            .await
            .context("loading an event's hosts")?;
        hosts.extend(kept);
    }
    if hosts.is_empty() {
        return Ok(None);
    }
    let row = event::ActiveModel {
        occurred_at: Set(new.occurred_at),
        kind: Set(new.kind.as_str().to_string()),
        title: Set(new.title.to_string()),
        detail: Set(new.detail.map(str::to_string)),
        filter: Set(new.filter.map(str::to_string)),
        created_by: Set(by.to_string()),
        created_at: Set(now),
        ..Default::default()
    };
    let row = row.insert(connection).await.context("saving event")?;
    for hosts in hosts.chunks(HOSTS_AT_ONCE) {
        let rows = hosts.iter().map(|host_id| event_host::ActiveModel {
            event_id: Set(row.id),
            host_id: Set(host_id.clone()),
            ..Default::default()
        });
        event_host::Entity::insert_many(rows)
            .exec_without_returning(connection)
            .await
            .context("saving an event's hosts")?;
    }
    Ok(Some(row))
}

impl Database {
    /// Saves an annotation, with the change in the audit log. None if none of its
    /// hosts are left, as they may have been deleted since they were picked.
    pub async fn record_event(
        &self,
        new: &NewEvent<'_>,
        by: &str,
        now: Timestamp,
    ) -> Result<Option<i64>> {
        let transaction = self.connection.begin().await.context("saving event")?;
        let Some(row) = insert_event(&transaction, new, by, now).await? else {
            return Ok(None);
        };
        let after = snapshot(&row);
        record_change(
            &transaction,
            Kind::Annotation,
            row.id,
            None,
            Some(&after),
            None,
        )
        .await?;
        transaction.commit().await.context("saving event")?;
        Ok(Some(row.id))
    }

    /// Saves something the server noticed about one host, for that host alone, and
    /// nothing if the host has just been deleted. These aren't changes anyone made,
    /// so they stay out of the audit log.
    pub async fn record_server_event(
        &self,
        kind: EventKind,
        host_id: &str,
        occurred_at: Timestamp,
        title: &str,
        detail: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        let filter = host_filter::only(host_id);
        let new = NewEvent {
            kind,
            occurred_at,
            title,
            detail,
            filter: Some(&filter),
            hosts: &[host_id.to_string()],
        };
        let transaction = self.connection.begin().await.context("saving event")?;
        insert_event(&transaction, &new, SERVER, now).await?;
        transaction.commit().await.context("saving event")?;
        Ok(())
    }

    /// An annotation, or nothing for anything else, as only those are anyone's to
    /// read or delete one at a time.
    pub async fn get_annotation(&self, id: i64) -> Result<Option<Event>> {
        let row = event::Entity::find_by_id(id)
            .filter(event::Column::CreatedBy.ne(SERVER))
            .one(&self.connection)
            .await
            .context("loading event")?;
        Ok(row.map(to_event))
    }

    /// Returns false if there was no such annotation. What the server recorded about a
    /// host is part of its history, so it isn't one.
    pub async fn delete_annotation(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting event")?;
        let Some(before) = event::Entity::find_by_id(id)
            .filter(event::Column::CreatedBy.ne(SERVER))
            .one(&transaction)
            .await
            .context("loading event")?
        else {
            return Ok(false);
        };
        event::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting event")?;
        let before = snapshot(&before);
        record_change(
            &transaction,
            Kind::Annotation,
            id,
            Some(&before),
            None,
            None,
        )
        .await?;
        transaction.commit().await.context("deleting event")?;
        Ok(true)
    }

    /// Annotations people and their scripts recorded between two times, both included,
    /// so one made the moment `to` is now still counts, newest first.
    pub async fn list_annotations(
        &self,
        from: Timestamp,
        to: Timestamp,
        limit: u64,
    ) -> Result<Vec<Event>> {
        let rows = event::Entity::find()
            .filter(event::Column::OccurredAt.gte(from))
            .filter(event::Column::OccurredAt.lte(to))
            .filter(event::Column::CreatedBy.ne(SERVER))
            .order_by_desc(event::Column::OccurredAt)
            .order_by_desc(event::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading events")?;
        Ok(rows.into_iter().map(to_event).collect())
    }

    /// Everything that happened to a host between two times, both included, newest
    /// first: the events recorded for it, its alerts starting and ending, and its
    /// agent, OS and kernel being updated.
    pub async fn timeline(
        &self,
        host_id: &str,
        from: Timestamp,
        to: Timestamp,
    ) -> Result<Vec<TimelineEvent>> {
        // Two recorded in the same moment are newest first by when they were added,
        // as the list of annotations has them, and the sort below keeps that.
        let of_event: RelationDef = event_host::Entity::belongs_to(event::Entity)
            .from(event_host::Column::EventId)
            .to(event::Column::Id)
            .into();
        let rows = event::Entity::find()
            .join(JoinType::InnerJoin, of_event.rev())
            .filter(event_host::Column::HostId.eq(host_id))
            .filter(event::Column::OccurredAt.gte(from))
            .filter(event::Column::OccurredAt.lte(to))
            .order_by_desc(event::Column::OccurredAt)
            .order_by_desc(event::Column::Id)
            .limit(MAX_TIMELINE)
            .all(&self.connection)
            .await
            .context("loading events")?;
        let mut timeline: Vec<TimelineEvent> = rows
            .into_iter()
            .map(|row| TimelineEvent {
                occurred_at: row.occurred_at,
                kind: EventKind::parse(&row.kind).unwrap_or(EventKind::Note),
                title: row.title,
                detail: row.detail,
                created_by: (row.created_by != SERVER).then_some(row.created_by),
                id: Some(row.id),
            })
            .collect();

        let in_range =
            |column: alert::Column| Condition::all().add(column.gte(from)).add(column.lte(to));
        let alerts = alert::Entity::find()
            .filter(alert::Column::HostId.eq(host_id))
            .filter(
                Condition::any()
                    .add(in_range(alert::Column::StartedAt))
                    .add(in_range(alert::Column::ResolvedAt)),
            )
            .order_by_desc(alert::Column::StartedAt)
            .limit(MAX_TIMELINE)
            .all(&self.connection)
            .await
            .context("loading a host's alerts")?;
        for row in to_alerts(&self.connection, alerts).await? {
            let title = format!("{} ({})", row.rule_name, row.severity.as_str());
            if (from..=to).contains(&row.started_at) {
                timeline.push(TimelineEvent {
                    occurred_at: row.started_at,
                    kind: EventKind::Alert,
                    title: title.clone(),
                    detail: Some(row.summary.clone()),
                    created_by: None,
                    id: None,
                });
            }
            if let Some(resolved) = row.resolved_at.filter(|time| (from..=to).contains(time)) {
                timeline.push(TimelineEvent {
                    occurred_at: resolved,
                    kind: EventKind::Resolved,
                    title,
                    detail: row
                        .resolved_summary
                        .clone()
                        .or_else(|| row.resolve_reason.clone()),
                    created_by: None,
                    id: None,
                });
            }
        }

        // A version is an update only if one came before it.
        let names: Vec<&str> = UPDATE_FACTS.iter().map(|(name, _)| *name).collect();
        let rows = host_fact::Entity::find()
            .filter(host_fact::Column::HostId.eq(host_id))
            .filter(host_fact::Column::Name.is_in(names))
            .filter(host_fact::Column::ValidFrom.lte(to))
            .order_by_asc(host_fact::Column::ValidFrom)
            .all(&self.connection)
            .await
            .context("loading a host's updates")?;
        let mut before: HashMap<String, serde_json::Value> = HashMap::new();
        for row in rows {
            let version = to_fact_version(row)?;
            if let Some(previous) = before.get(&version.name)
                && version.valid_from >= from
                && *previous != version.value
            {
                let label = UPDATE_FACTS
                    .iter()
                    .find(|(name, _)| *name == version.name)
                    .map_or("Software", |(_, label)| label);
                timeline.push(TimelineEvent {
                    occurred_at: version.valid_from,
                    kind: EventKind::Update,
                    title: format!("{label} updated to {}", written(&version.value)),
                    detail: Some(format!("It was {}.", written(previous))),
                    created_by: None,
                    id: None,
                });
            }
            before.insert(version.name, version.value);
        }

        timeline.sort_by_key(|event| std::cmp::Reverse(event.occurred_at));
        timeline.truncate(MAX_TIMELINE as usize);
        Ok(timeline)
    }

    /// When a host last started, as far as the server knows.
    pub async fn boot_time(&self, host_id: &str) -> Result<Option<Timestamp>> {
        let row = host_boot::Entity::find_by_id(host_id)
            .one(&self.connection)
            .await
            .context("loading a boot time")?;
        Ok(row.map(|row| row.booted_at))
    }

    /// Notes when a host started, and marks a restart if it had started before.
    pub async fn save_boot_time(
        &self,
        host_id: &str,
        booted_at: Timestamp,
        restarted: bool,
        now: Timestamp,
    ) -> Result<()> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving a boot time")?;
        let row = host_boot::ActiveModel {
            host_id: Set(host_id.to_string()),
            booted_at: Set(booted_at),
        };
        host_boot::Entity::insert(row)
            .on_conflict(
                OnConflict::column(host_boot::Column::HostId)
                    .update_column(host_boot::Column::BootedAt)
                    .to_owned(),
            )
            .exec_without_returning(&transaction)
            .await
            .context("saving a boot time")?;
        if restarted {
            let filter = host_filter::only(host_id);
            let new = NewEvent {
                kind: EventKind::Restart,
                occurred_at: booted_at,
                title: "Host started",
                detail: None,
                filter: Some(&filter),
                hosts: &[host_id.to_string()],
            };
            insert_event(&transaction, &new, SERVER, now).await?;
        }
        transaction.commit().await.context("saving a boot time")?;
        Ok(())
    }
}

/// Forgets what was recorded about one host alone, as part of deleting it: the
/// events it was the only host of. Events for other hosts too stay, on those.
pub(super) async fn delete_host_events<C: ConnectionTrait>(
    connection: &C,
    host_id: &str,
) -> Result<()> {
    let ids: Vec<i64> = event_host::Entity::find()
        .select_only()
        .column(event_host::Column::EventId)
        .filter(event_host::Column::HostId.eq(host_id))
        .into_tuple()
        .all(connection)
        .await
        .context("loading a host's events")?;
    for ids in ids.chunks(HOSTS_AT_ONCE) {
        let shared: HashSet<i64> = event_host::Entity::find()
            .select_only()
            .column(event_host::Column::EventId)
            .distinct()
            .filter(event_host::Column::EventId.is_in(ids.iter().copied()))
            .filter(event_host::Column::HostId.ne(host_id))
            .into_tuple::<i64>()
            .all(connection)
            .await
            .context("loading a host's events")?
            .into_iter()
            .collect();
        let alone = ids.iter().copied().filter(|id| !shared.contains(id));
        event::Entity::delete_many()
            .filter(event::Column::Id.is_in(alone))
            .exec(connection)
            .await
            .context("deleting a host's events")?;
    }
    Ok(())
}
