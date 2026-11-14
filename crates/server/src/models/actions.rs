//! Action runs, and which actions each host's agent says it has.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use maxnines_protocol::actions::ActionOutcome;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde_json::Value;

use super::alerting::queue_action_output;
use super::audit::record;
use super::{Database, action_run, host, host_fact};
use crate::actions::{ActionRun, Finished, KnownActions, NewRun};
use crate::audit::{Action, Change, Kind, Record, Subject};

/// Where an agent lists its actions among its facts, and what each needs.
const NAMES: &str = "agent.actions[";
const VARIABLES: &str = "agent.action_variables.";

pub(super) fn to_run(row: action_run::Model) -> Result<ActionRun> {
    Ok(ActionRun {
        id: row.id,
        host_id: row.host_id,
        alert_id: row.alert_id,
        action: row.action,
        run_on: row.run_on,
        variables: serde_json::from_str(&row.variables).context("reading a run's variables")?,
        requested_by: row.requested_by,
        requested_ms: row.requested_ms,
        timeout_secs: u64::try_from(row.timeout_secs)?,
        outcome: row.outcome.as_deref().and_then(ActionOutcome::parse),
        exit_code: row.exit_code,
        error: row.error,
        output: row.output,
        truncated: row.truncated,
        duration_ms: row.duration_ms.map(u64::try_from).transpose()?,
        finished_ms: row.finished_ms,
    })
}

/// Reads actions out of fact rows: every name, and what those that need
/// something need. Hosts are merged, so an action needs what any host's does.
fn known(facts: Vec<host_fact::Model>) -> KnownActions {
    let mut known = KnownActions::new();
    for fact in &facts {
        if fact.name.starts_with(NAMES) {
            known.entry(fact.value.clone()).or_default();
        }
    }
    for fact in &facts {
        let Some(rest) = fact.name.strip_prefix(VARIABLES) else {
            continue;
        };
        let Some((action, _)) = rest.split_once('[') else {
            continue;
        };
        if let Some(needed) = known.get_mut(action)
            && !needed.contains(&fact.value)
        {
            needed.push(fact.value.clone());
        }
    }
    known
}

fn action_facts() -> sea_orm::Condition {
    sea_orm::Condition::any()
        .add(host_fact::Column::Name.starts_with(NAMES))
        .add(host_fact::Column::Name.starts_with(VARIABLES))
}

impl Database {
    /// The actions one host's agent has, and what each needs to be given.
    pub async fn host_actions(&self, host_id: &str) -> Result<KnownActions> {
        let facts = host_fact::Entity::find()
            .filter(host_fact::Column::HostId.eq(host_id))
            .filter(host_fact::Column::ValidToMs.is_null())
            .filter(action_facts())
            .all(&self.connection)
            .await
            .context("loading a host's actions")?;
        Ok(known(facts))
    }

    /// Every action any host has.
    pub async fn known_actions(&self) -> Result<KnownActions> {
        let facts = host_fact::Entity::find()
            .filter(host_fact::Column::ValidToMs.is_null())
            .filter(action_facts())
            .all(&self.connection)
            .await
            .context("loading actions")?;
        Ok(known(facts))
    }

    /// One a person asked for goes in the audit log, with what it was given. One
    /// an alert asked for is the server's own doing, and is kept with the alert.
    pub async fn create_action_run(&self, new: &NewRun) -> Result<i64> {
        let row = action_run::ActiveModel {
            host_id: Set(new.host_id.clone()),
            alert_id: Set(new.alert_id),
            action: Set(new.action.clone()),
            run_on: Set(new.run_on.clone()),
            variables: Set(serde_json::to_string(&new.variables)?),
            requested_by: Set(new.requested_by.clone()),
            requested_ms: Set(new.requested_ms),
            timeout_secs: Set(i64::try_from(new.timeout_secs)?),
            outcome: Set(None),
            exit_code: Set(None),
            error: Set(None),
            output: Set(String::new()),
            truncated: Set(false),
            duration_ms: Set(None),
            finished_ms: Set(None),
            ..Default::default()
        };
        let transaction = self.connection.begin().await;
        let transaction = transaction.context("saving an action run")?;
        let saved = action_run::Entity::insert(row)
            .exec(&transaction)
            .await
            .context("saving an action run")?;
        if new.requested_by.is_some() {
            let host = host::Entity::find_by_id(&new.host_id)
                .one(&transaction)
                .await
                .context("loading host")?;
            let hostname = host.map_or_else(|| new.host_id.clone(), |host| host.hostname);
            let given = |field: &str, value: &str| Change {
                field: field.to_string(),
                before: None,
                after: Some(Value::from(value)),
                secret: false,
            };
            let mut changes = vec![given("action", &new.action)];
            changes.extend(new.variables.iter().map(|(name, value)| given(name, value)));
            let subject = Subject::new(Kind::Host, &new.host_id, hostname);
            let entry = Record::new(Action::Ran, subject).with_changes(changes);
            record(&transaction, entry).await?;
        }
        transaction.commit().await.context("saving an action run")?;
        Ok(saved.last_insert_id)
    }

    /// Records how a run ended, if it's that host's and still waiting, and queues
    /// what it printed for the channels its alert went to. Returns whether it was.
    pub async fn finish_action_run(
        &self,
        id: i64,
        host_id: &str,
        finished: &Finished,
        now_ms: i64,
    ) -> Result<bool> {
        let duration_ms = finished.duration_ms.map(i64::try_from).transpose()?;
        let transaction = self.connection.begin().await;
        let transaction = transaction.context("saving an action's result")?;
        let changed = action_run::Entity::update_many()
            .col_expr(
                action_run::Column::Outcome,
                Expr::value(finished.outcome.as_str()),
            )
            .col_expr(
                action_run::Column::ExitCode,
                Expr::value(finished.exit_code),
            )
            .col_expr(
                action_run::Column::Error,
                Expr::value(finished.error.clone()),
            )
            .col_expr(
                action_run::Column::Output,
                Expr::value(finished.output.clone()),
            )
            .col_expr(
                action_run::Column::Truncated,
                Expr::value(finished.truncated),
            )
            .col_expr(action_run::Column::DurationMs, Expr::value(duration_ms))
            .col_expr(action_run::Column::FinishedMs, Expr::value(now_ms))
            .filter(action_run::Column::Id.eq(id))
            .filter(action_run::Column::HostId.eq(host_id))
            .filter(action_run::Column::FinishedMs.is_null())
            .exec(&transaction)
            .await
            .context("saving an action's result")?;
        let recorded = changed.rows_affected > 0;
        if recorded {
            queue_action_output(&transaction, id, now_ms).await?;
        }
        transaction
            .commit()
            .await
            .context("saving an action's result")?;
        Ok(recorded)
    }

    pub async fn get_action_run(&self, id: i64) -> Result<Option<ActionRun>> {
        action_run::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading an action run")?
            .map(to_run)
            .transpose()
    }

    /// An alert's runs, oldest first.
    pub async fn action_runs_for_alert(&self, alert_id: i64) -> Result<Vec<ActionRun>> {
        action_run::Entity::find()
            .filter(action_run::Column::AlertId.eq(alert_id))
            .order_by_asc(action_run::Column::Id)
            .all(&self.connection)
            .await
            .context("loading an alert's action runs")?
            .into_iter()
            .map(to_run)
            .collect()
    }

    /// A host's runs, newest first.
    pub async fn action_runs_for_host(&self, host_id: &str, limit: u64) -> Result<Vec<ActionRun>> {
        action_run::Entity::find()
            .filter(action_run::Column::HostId.eq(host_id))
            .order_by_desc(action_run::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading a host's action runs")?
            .into_iter()
            .map(to_run)
            .collect()
    }

    /// Whether an alert has already run this action for this moment.
    pub async fn has_action_run(&self, alert_id: i64, action: &str, run_on: &str) -> Result<bool> {
        let found = action_run::Entity::find()
            .filter(action_run::Column::AlertId.eq(alert_id))
            .filter(action_run::Column::Action.eq(action))
            .filter(action_run::Column::RunOn.eq(run_on))
            .one(&self.connection)
            .await
            .context("looking for an action run")?;
        Ok(found.is_some())
    }

    /// Runs still waiting for an answer.
    pub async fn unanswered_action_runs(&self) -> Result<Vec<ActionRun>> {
        action_run::Entity::find()
            .filter(action_run::Column::FinishedMs.is_null())
            .all(&self.connection)
            .await
            .context("loading unanswered action runs")?
            .into_iter()
            .map(to_run)
            .collect()
    }

    /// How many runs each alert has, for alerts that have any.
    pub async fn action_run_counts(&self, alert_ids: &[i64]) -> Result<BTreeMap<i64, u64>> {
        let mut counts = BTreeMap::new();
        if alert_ids.is_empty() {
            return Ok(counts);
        }
        let rows = action_run::Entity::find()
            .filter(action_run::Column::AlertId.is_in(alert_ids.to_vec()))
            .all(&self.connection)
            .await
            .context("counting action runs")?;
        for row in rows {
            if let Some(alert_id) = row.alert_id {
                *counts.entry(alert_id).or_default() += 1;
            }
        }
        Ok(counts)
    }
}
