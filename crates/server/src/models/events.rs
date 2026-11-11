//! Events marked on charts: those recorded by people and by the server, and a machine's
//! whole timeline, which adds its alerts and updates from what's kept about them.

use std::collections::HashMap;

use anyhow::{Context, Result};
use sea_orm::sea_query::{Expr, ExprTrait, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set, TransactionTrait,
};
use serde_json::json;

use super::audit::record_change;
use super::{Database, agent_boot, agent_fact, alert, event, event_agent, to_fact_version};
use crate::audit::{self, Kind, Snapshot};
use crate::events::{Event, EventKind, SERVER, TimelineEvent, UPDATE_FACTS};

/// The most of a machine's events a timeline holds, newest first.
pub const MAX_TIMELINE: u64 = 500;

fn snapshot(row: &event::Model, machines: usize) -> Snapshot {
    let fields = json!({
        "kind": row.kind,
        "title": row.title,
        "detail": row.detail,
        "time": audit::time(row.time_ms),
        "filter": row.filter,
        "machines": machines,
    });
    Snapshot::new(&row.title, fields)
}

fn to_event(row: event::Model, machines: u64) -> Event {
    Event {
        id: row.id,
        time_ms: row.time_ms,
        kind: EventKind::parse(&row.kind).unwrap_or(EventKind::Note),
        title: row.title,
        detail: row.detail,
        filter: row.filter,
        created_by: row.created_by,
        created_ms: row.created_ms,
        machines,
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
    pub time_ms: i64,
    pub title: &'a str,
    pub detail: Option<&'a str>,
    pub filter: &'a str,
    pub agents: &'a [String],
}

async fn insert_event<C: ConnectionTrait>(
    connection: &C,
    new: &NewEvent<'_>,
    by: &str,
    now_ms: i64,
) -> Result<event::Model> {
    let row = event::ActiveModel {
        time_ms: Set(new.time_ms),
        kind: Set(new.kind.as_str().to_string()),
        title: Set(new.title.to_string()),
        detail: Set(new.detail.map(str::to_string)),
        filter: Set(new.filter.to_string()),
        created_by: Set(by.to_string()),
        created_ms: Set(now_ms),
        ..Default::default()
    };
    let row = row.insert(connection).await.context("saving event")?;
    // In pieces, as databases limit how much one statement can hold.
    for agents in new.agents.chunks(500) {
        let links = agents.iter().map(|agent_id| event_agent::ActiveModel {
            event_id: Set(row.id),
            agent_id: Set(agent_id.clone()),
        });
        event_agent::Entity::insert_many(links)
            .exec_without_returning(connection)
            .await
            .context("saving which machines an event is for")?;
    }
    Ok(row)
}

impl Database {
    /// Saves what someone recorded, for the machines given, with the change in the
    /// audit log.
    pub async fn record_event(&self, new: &NewEvent<'_>, by: &str, now_ms: i64) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving event")?;
        let row = insert_event(&transaction, new, by, now_ms).await?;
        let after = snapshot(&row, new.agents.len());
        record_change(&transaction, Kind::Event, row.id, None, Some(&after), None).await?;
        transaction.commit().await.context("saving event")?;
        Ok(row.id)
    }

    /// Saves something the server noticed about one machine. These aren't changes
    /// anyone made, so they stay out of the audit log.
    pub async fn record_server_event(
        &self,
        kind: EventKind,
        agent_id: &str,
        time_ms: i64,
        title: &str,
        detail: Option<&str>,
        now_ms: i64,
    ) -> Result<()> {
        let agents = [agent_id.to_string()];
        let new = NewEvent {
            kind,
            time_ms,
            title,
            detail,
            filter: "",
            agents: &agents,
        };
        let transaction = self.connection.begin().await.context("saving event")?;
        insert_event(&transaction, &new, SERVER, now_ms).await?;
        transaction.commit().await.context("saving event")?;
        Ok(())
    }

    pub async fn get_event(&self, id: i64) -> Result<Option<Event>> {
        let Some(row) = event::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading event")?
        else {
            return Ok(None);
        };
        let machines = self.machine_counts(&[id]).await?;
        Ok(Some(to_event(row, machines.get(&id).copied().unwrap_or(0))))
    }

    /// Returns false if there was no such event.
    pub async fn delete_event(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting event")?;
        let Some(before) = event::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading event")?
        else {
            return Ok(false);
        };
        let machines = event_agent::Entity::find()
            .filter(event_agent::Column::EventId.eq(id))
            .count(&transaction)
            .await
            .context("counting an event's machines")?;
        event_agent::Entity::delete_many()
            .filter(event_agent::Column::EventId.eq(id))
            .exec(&transaction)
            .await
            .context("deleting event")?;
        event::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting event")?;
        let before = snapshot(&before, machines as usize);
        record_change(&transaction, Kind::Event, id, Some(&before), None, None).await?;
        transaction.commit().await.context("deleting event")?;
        Ok(true)
    }

    async fn machine_counts(&self, ids: &[i64]) -> Result<HashMap<i64, u64>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let counts: Vec<(i64, i64)> = event_agent::Entity::find()
            .select_only()
            .column(event_agent::Column::EventId)
            .column_as(Expr::col(event_agent::Column::AgentId).count(), "machines")
            .filter(event_agent::Column::EventId.is_in(ids.iter().copied()))
            .group_by(event_agent::Column::EventId)
            .into_tuple()
            .all(&self.connection)
            .await
            .context("counting events' machines")?;
        Ok(counts
            .into_iter()
            .map(|(id, machines)| (id, u64::try_from(machines).unwrap_or(0)))
            .collect())
    }

    /// What people recorded between two times, newest first.
    pub async fn list_events(&self, from_ms: i64, to_ms: i64, limit: u64) -> Result<Vec<Event>> {
        let rows = event::Entity::find()
            .filter(event::Column::TimeMs.gte(from_ms))
            .filter(event::Column::TimeMs.lt(to_ms))
            .filter(event::Column::CreatedBy.ne(SERVER))
            .order_by_desc(event::Column::TimeMs)
            .order_by_desc(event::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading events")?;
        let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
        let counts = self.machine_counts(&ids).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let machines = counts.get(&row.id).copied().unwrap_or(0);
                to_event(row, machines)
            })
            .collect())
    }

    /// Everything that happened to a machine between two times, newest first: what was
    /// recorded for it, its alerts starting and ending, and its agent, OS and kernel
    /// being updated.
    pub async fn timeline(
        &self,
        agent_id: &str,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<TimelineEvent>> {
        let mut timeline = Vec::new();

        let linked = event_agent::Entity::find()
            .select_only()
            .column(event_agent::Column::EventId)
            .filter(event_agent::Column::AgentId.eq(agent_id))
            .into_query();
        let recorded = event::Entity::find()
            .filter(event::Column::Id.in_subquery(linked))
            .filter(event::Column::TimeMs.gte(from_ms))
            .filter(event::Column::TimeMs.lt(to_ms))
            .order_by_desc(event::Column::TimeMs)
            .limit(MAX_TIMELINE)
            .all(&self.connection)
            .await
            .context("loading a machine's events")?;
        timeline.extend(recorded.into_iter().map(|row| TimelineEvent {
            time_ms: row.time_ms,
            kind: EventKind::parse(&row.kind).unwrap_or(EventKind::Note),
            title: row.title,
            detail: row.detail,
            by: (row.created_by != SERVER).then_some(row.created_by),
            id: Some(row.id),
        }));

        let in_range = |column: alert::Column| {
            Condition::all()
                .add(column.gte(from_ms))
                .add(column.lt(to_ms))
        };
        let alerts = alert::Entity::find()
            .filter(alert::Column::AgentId.eq(agent_id))
            .filter(
                Condition::any()
                    .add(in_range(alert::Column::StartedMs))
                    .add(in_range(alert::Column::ResolvedMs)),
            )
            .order_by_desc(alert::Column::StartedMs)
            .limit(MAX_TIMELINE)
            .all(&self.connection)
            .await
            .context("loading a machine's alerts")?;
        for row in alerts {
            let title = format!("{} ({})", row.rule_name, row.severity);
            if (from_ms..to_ms).contains(&row.started_ms) {
                timeline.push(TimelineEvent {
                    time_ms: row.started_ms,
                    kind: EventKind::Alert,
                    title: title.clone(),
                    detail: Some(row.summary.clone()),
                    by: None,
                    id: None,
                });
            }
            if let Some(resolved) = row
                .resolved_ms
                .filter(|time| (from_ms..to_ms).contains(time))
            {
                timeline.push(TimelineEvent {
                    time_ms: resolved,
                    kind: EventKind::Resolved,
                    title,
                    detail: row.resolve_reason.clone(),
                    by: None,
                    id: None,
                });
            }
        }

        // A version is an update only if one came before it.
        let names: Vec<&str> = UPDATE_FACTS.iter().map(|(name, _)| *name).collect();
        let rows = agent_fact::Entity::find()
            .filter(agent_fact::Column::AgentId.eq(agent_id))
            .filter(agent_fact::Column::Name.is_in(names))
            .filter(agent_fact::Column::ValidFromMs.lt(to_ms))
            .order_by_asc(agent_fact::Column::ValidFromMs)
            .all(&self.connection)
            .await
            .context("loading a machine's updates")?;
        let mut before: HashMap<String, serde_json::Value> = HashMap::new();
        for row in rows {
            let version = to_fact_version(row)?;
            let from = version.valid_from_ms as i64;
            if let Some(previous) = before.get(&version.name)
                && from >= from_ms
                && *previous != version.value
            {
                let label = UPDATE_FACTS
                    .iter()
                    .find(|(name, _)| *name == version.name)
                    .map_or("Software", |(_, label)| label);
                timeline.push(TimelineEvent {
                    time_ms: from,
                    kind: EventKind::Update,
                    title: format!("{label} updated to {}", written(&version.value)),
                    detail: Some(format!("It was {}.", written(previous))),
                    by: None,
                    id: None,
                });
            }
            before.insert(version.name, version.value);
        }

        timeline.sort_by_key(|event| std::cmp::Reverse(event.time_ms));
        timeline.truncate(MAX_TIMELINE as usize);
        Ok(timeline)
    }

    /// When a machine last started, as far as the server knows.
    pub async fn boot_time(&self, agent_id: &str) -> Result<Option<i64>> {
        let row = agent_boot::Entity::find_by_id(agent_id)
            .one(&self.connection)
            .await
            .context("loading a boot time")?;
        Ok(row.map(|row| row.boot_ms))
    }

    /// Notes when a machine started, and marks a restart if it had started before.
    pub async fn save_boot_time(
        &self,
        agent_id: &str,
        boot_ms: i64,
        restarted: bool,
        now_ms: i64,
    ) -> Result<()> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving a boot time")?;
        let row = agent_boot::ActiveModel {
            agent_id: Set(agent_id.to_string()),
            boot_ms: Set(boot_ms),
        };
        agent_boot::Entity::insert(row)
            .on_conflict(
                OnConflict::column(agent_boot::Column::AgentId)
                    .update_column(agent_boot::Column::BootMs)
                    .to_owned(),
            )
            .exec_without_returning(&transaction)
            .await
            .context("saving a boot time")?;
        if restarted {
            let agents = [agent_id.to_string()];
            let new = NewEvent {
                kind: EventKind::Restart,
                time_ms: boot_ms,
                title: "Machine started",
                detail: None,
                filter: "",
                agents: &agents,
            };
            insert_event(&transaction, &new, SERVER, now_ms).await?;
        }
        transaction.commit().await.context("saving a boot time")?;
        Ok(())
    }
}

/// Forgets a machine's part in events and when it started, as part of deleting it.
pub(super) async fn delete_agent_events<C: ConnectionTrait>(
    connection: &C,
    agent_id: &str,
) -> Result<()> {
    event_agent::Entity::delete_many()
        .filter(event_agent::Column::AgentId.eq(agent_id))
        .exec(connection)
        .await
        .context("deleting an agent's events")?;
    agent_boot::Entity::delete_by_id(agent_id)
        .exec(connection)
        .await
        .context("deleting an agent's boot time")?;
    Ok(())
}
