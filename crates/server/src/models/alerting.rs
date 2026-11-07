//! Alert rules, notification channels, alerts and the notification queue.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context, Result};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};

use super::{Database, alert, alert_rule, alert_rule_channel, notification, notification_channel};
use crate::alerting::{
    Alert, AlertRule, AlertRuleInput, Channel, ChannelInput, ChannelKind, Comparison, Delivery,
    DeliveryProblem, Event, NewAlert, RuleKind, Severity,
};
use crate::calculations::Calculation;

const PENDING: &str = "pending";
const SENT: &str = "sent";
const FAILED: &str = "failed";
/// Kept back by a silence.
const HELD: &str = "held";

/// How much of the queue is looked at each time. Anything beyond this waits for
/// the rows in front of it to be sent or given up on.
const QUEUE_WINDOW: u64 = 500;

fn to_alert_rule(row: alert_rule::Model, channels: Vec<i64>) -> Result<AlertRule> {
    Ok(AlertRule {
        id: row.id,
        rule: AlertRuleInput {
            name: row.name,
            kind: RuleKind::parse(&row.kind)?,
            metric: row.metric,
            series: row.series,
            comparison: row
                .comparison
                .as_deref()
                .map(Comparison::parse)
                .transpose()?,
            threshold: row.threshold,
            for_secs: u64::try_from(row.for_secs).context("invalid duration")?,
            severity: Severity::parse(&row.severity)?,
            condition: row.condition_expr,
            enabled: row.enabled,
            channels,
            calculation: row.calculation.as_deref().and_then(Calculation::parse),
            group_by: row.group_by,
            filter: row.filter,
            window_secs: row
                .window_secs
                .map(u64::try_from)
                .transpose()
                .context("invalid window")?,
        },
    })
}

fn alert_rule_row(input: &AlertRuleInput) -> Result<alert_rule::ActiveModel> {
    Ok(alert_rule::ActiveModel {
        name: Set(input.name.clone()),
        kind: Set(input.kind.as_str().to_string()),
        metric: Set(input.metric.clone()),
        series: Set(input.series.clone()),
        comparison: Set(input.comparison.map(|c| c.as_str().to_string())),
        threshold: Set(input.threshold),
        for_secs: Set(i64::try_from(input.for_secs).context("invalid duration")?),
        severity: Set(input.severity.as_str().to_string()),
        condition_expr: Set(input.condition.clone()),
        enabled: Set(input.enabled),
        calculation: Set(input.calculation.map(|c| c.as_str().to_string())),
        group_by: Set(input.group_by.clone()),
        filter: Set(input.filter.clone()),
        window_secs: Set(input
            .window_secs
            .map(i64::try_from)
            .transpose()
            .context("invalid window")?),
        ..Default::default()
    })
}

fn to_channel(row: notification_channel::Model) -> Result<Channel> {
    Ok(Channel {
        id: row.id,
        channel: ChannelInput {
            name: row.name,
            kind: ChannelKind::parse(&row.kind)?,
            target: row.target,
            credential: row.credential,
        },
    })
}

fn to_alert(row: alert::Model) -> Result<Alert> {
    Ok(Alert {
        id: row.id,
        rule_id: row.rule_id,
        rule_name: row.rule_name,
        severity: Severity::parse(&row.severity)?,
        agent_id: row.agent_id,
        host: row.host,
        series: row.series,
        value: row.value,
        summary: row.summary,
        started_ms: row.started_ms,
        resolved_ms: row.resolved_ms,
        resolve_reason: row.resolve_reason,
    })
}

fn links(rule_id: i64, channels: &[i64]) -> Vec<alert_rule_channel::ActiveModel> {
    let unique: BTreeSet<i64> = channels.iter().copied().collect();
    unique
        .into_iter()
        .map(|channel_id| alert_rule_channel::ActiveModel {
            rule_id: Set(rule_id),
            channel_id: Set(channel_id),
        })
        .collect()
}

fn queued(alert_id: i64, channel_id: i64, event: Event, now_ms: i64) -> notification::ActiveModel {
    notification::ActiveModel {
        alert_id: Set(alert_id),
        channel_id: Set(channel_id),
        event: Set(event.as_str().to_string()),
        state: Set(PENDING.to_string()),
        attempts: Set(0),
        next_attempt_ms: Set(now_ms),
        last_error: Set(None),
        created_ms: Set(now_ms),
        sent_ms: Set(None),
        external_id: Set(None),
        ..Default::default()
    }
}

impl Database {
    /// Sorted by name.
    pub async fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let rows = alert_rule::Entity::find()
            .order_by_asc(alert_rule::Column::Name)
            .all(&self.connection)
            .await
            .context("loading alert rules")?;

        let mut channels: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for link in alert_rule_channel::Entity::find()
            .all(&self.connection)
            .await
            .context("loading alert rule channels")?
        {
            channels
                .entry(link.rule_id)
                .or_default()
                .push(link.channel_id);
        }

        rows.into_iter()
            .map(|row| {
                let mine = channels.remove(&row.id).unwrap_or_default();
                to_alert_rule(row, mine)
            })
            .collect()
    }

    pub async fn get_alert_rule(&self, id: i64) -> Result<Option<AlertRule>> {
        let Some(row) = alert_rule::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading alert rule")?
        else {
            return Ok(None);
        };
        let channels = alert_rule_channel::Entity::find()
            .filter(alert_rule_channel::Column::RuleId.eq(id))
            .all(&self.connection)
            .await
            .context("loading alert rule channels")?;
        let channels = channels.into_iter().map(|link| link.channel_id).collect();
        to_alert_rule(row, channels).map(Some)
    }

    pub async fn create_alert_rule(&self, input: &AlertRuleInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let id = alert_rule::Entity::insert(alert_rule_row(input)?)
            .exec(&transaction)
            .await
            .context("saving alert rule")?
            .last_insert_id;

        let rows = links(id, &input.channels);
        if !rows.is_empty() {
            alert_rule_channel::Entity::insert_many(rows)
                .exec_without_returning(&transaction)
                .await
                .context("saving alert rule channels")?;
        }
        transaction.commit().await.context("saving alert rule")?;
        Ok(id)
    }

    /// Returns false if there's no such rule.
    pub async fn update_alert_rule(&self, id: i64, input: &AlertRuleInput) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        let found = alert_rule::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading alert rule")?;
        if found.is_none() {
            return Ok(false);
        }

        let mut row = alert_rule_row(input)?;
        row.id = Set(id);
        alert_rule::Entity::update(row)
            .exec(&transaction)
            .await
            .context("saving alert rule")?;

        alert_rule_channel::Entity::delete_many()
            .filter(alert_rule_channel::Column::RuleId.eq(id))
            .exec(&transaction)
            .await
            .context("saving alert rule channels")?;
        let rows = links(id, &input.channels);
        if !rows.is_empty() {
            alert_rule_channel::Entity::insert_many(rows)
                .exec_without_returning(&transaction)
                .await
                .context("saving alert rule channels")?;
        }
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// Alerts from the rule stay as history. Returns false if there's no such rule.
    pub async fn delete_alert_rule(&self, id: i64) -> Result<bool> {
        let result = alert_rule::Entity::delete_by_id(id)
            .exec(&self.connection)
            .await
            .context("deleting alert rule")?;
        Ok(result.rows_affected > 0)
    }
}

impl Database {
    /// Sorted by name.
    pub async fn list_channels(&self) -> Result<Vec<Channel>> {
        let rows = notification_channel::Entity::find()
            .order_by_asc(notification_channel::Column::Name)
            .all(&self.connection)
            .await
            .context("loading channels")?;
        rows.into_iter().map(to_channel).collect()
    }

    pub async fn get_channel(&self, id: i64) -> Result<Option<Channel>> {
        let row = notification_channel::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading channel")?;
        row.map(to_channel).transpose()
    }

    pub async fn create_channel(&self, input: &ChannelInput) -> Result<i64> {
        let row = notification_channel::ActiveModel {
            name: Set(input.name.clone()),
            kind: Set(input.kind.as_str().to_string()),
            target: Set(input.target.clone()),
            credential: Set(input.credential.clone()),
            ..Default::default()
        };
        let result = notification_channel::Entity::insert(row)
            .exec(&self.connection)
            .await
            .context("saving channel")?;
        Ok(result.last_insert_id)
    }

    /// Returns false if there's no such channel.
    pub async fn update_channel(&self, id: i64, input: &ChannelInput) -> Result<bool> {
        if self.get_channel(id).await?.is_none() {
            return Ok(false);
        }
        let row = notification_channel::ActiveModel {
            id: Set(id),
            name: Set(input.name.clone()),
            kind: Set(input.kind.as_str().to_string()),
            target: Set(input.target.clone()),
            credential: Set(input.credential.clone()),
        };
        notification_channel::Entity::update(row)
            .exec(&self.connection)
            .await
            .context("saving channel")?;
        Ok(true)
    }

    /// Anything still queued for the channel goes with it. Returns false if
    /// there's no such channel.
    pub async fn delete_channel(&self, id: i64) -> Result<bool> {
        let result = notification_channel::Entity::delete_by_id(id)
            .exec(&self.connection)
            .await
            .context("deleting channel")?;
        Ok(result.rows_affected > 0)
    }
}

impl Database {
    /// Newest first.
    pub async fn open_alerts(&self) -> Result<Vec<Alert>> {
        let rows = alert::Entity::find()
            .filter(alert::Column::ResolvedMs.is_null())
            .order_by_desc(alert::Column::StartedMs)
            .order_by_desc(alert::Column::Id)
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        rows.into_iter().map(to_alert).collect()
    }

    /// The newest alerts that have ended.
    pub async fn resolved_alerts(&self, limit: u64) -> Result<Vec<Alert>> {
        let rows = alert::Entity::find()
            .filter(alert::Column::ResolvedMs.is_not_null())
            .order_by_desc(alert::Column::StartedMs)
            .order_by_desc(alert::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        rows.into_iter().map(to_alert).collect()
    }

    /// Starts an alert and queues its notifications together, so an alert can't
    /// exist without them.
    pub async fn fire_alert(&self, new: &NewAlert, channels: &[i64]) -> Result<i64> {
        let row = alert::ActiveModel {
            rule_id: Set(Some(new.rule_id)),
            rule_name: Set(new.rule_name.clone()),
            severity: Set(new.severity.as_str().to_string()),
            agent_id: Set(new.agent_id.clone()),
            host: Set(new.host.clone()),
            series: Set(new.series.clone()),
            value: Set(new.value),
            summary: Set(new.summary.clone()),
            started_ms: Set(new.started_ms),
            resolved_ms: Set(None),
            resolve_reason: Set(None),
            ..Default::default()
        };

        let transaction = self.connection.begin().await.context("saving alert")?;
        let id = alert::Entity::insert(row)
            .exec(&transaction)
            .await
            .context("saving alert")?
            .last_insert_id;

        let unique: BTreeSet<i64> = channels.iter().copied().collect();
        let rows: Vec<_> = unique
            .into_iter()
            .map(|channel| queued(id, channel, Event::Firing, new.started_ms))
            .collect();
        if !rows.is_empty() {
            notification::Entity::insert_many(rows)
                .exec_without_returning(&transaction)
                .await
                .context("queueing notifications")?;
        }
        transaction.commit().await.context("saving alert")?;
        Ok(id)
    }

    /// Ends an alert and tells whoever was told it started, even if the rule
    /// has since changed or gone. Anyone a silence kept it from never hears of it.
    pub async fn resolve_alert(&self, id: i64, now_ms: i64, reason: &str) -> Result<()> {
        let transaction = self.connection.begin().await.context("resolving alert")?;
        let result = alert::Entity::update_many()
            .col_expr(alert::Column::ResolvedMs, Expr::value(now_ms))
            .col_expr(alert::Column::ResolveReason, Expr::value(reason))
            .filter(alert::Column::Id.eq(id))
            .filter(alert::Column::ResolvedMs.is_null())
            .exec(&transaction)
            .await
            .context("resolving alert")?;

        if result.rows_affected > 0 {
            notification::Entity::delete_many()
                .filter(notification::Column::AlertId.eq(id))
                .filter(notification::Column::State.eq(HELD))
                .exec(&transaction)
                .await
                .context("dropping notifications")?;
            let told = notification::Entity::find()
                .filter(notification::Column::AlertId.eq(id))
                .filter(notification::Column::Event.eq(Event::Firing.as_str()))
                .all(&transaction)
                .await
                .context("loading notifications")?;
            let rows: Vec<_> = told
                .into_iter()
                .map(|row| queued(id, row.channel_id, Event::Resolved, now_ms))
                .collect();
            if !rows.is_empty() {
                notification::Entity::insert_many(rows)
                    .exec_without_returning(&transaction)
                    .await
                    .context("queueing notifications")?;
            }
        }
        transaction.commit().await.context("resolving alert")?;
        Ok(())
    }

    /// What can be sent now. Each channel hears about an alert in order: a
    /// resolved notification waits while its firing one is being retried, or a
    /// receiver would see the alert start after it ended, and never close it.
    pub async fn due_deliveries(&self, now_ms: i64, limit: usize) -> Result<Vec<Delivery>> {
        let rows = notification::Entity::find()
            .filter(notification::Column::State.eq(PENDING))
            .order_by_asc(notification::Column::Id)
            .limit(QUEUE_WINDOW)
            .all(&self.connection)
            .await
            .context("loading notifications")?;

        let mut seen = HashSet::new();
        let due: Vec<notification::Model> = rows
            .into_iter()
            .filter(|row| seen.insert((row.alert_id, row.channel_id)))
            .filter(|row| row.next_attempt_ms <= now_ms)
            .take(limit)
            .collect();
        if due.is_empty() {
            return Ok(Vec::new());
        }

        let alert_ids: BTreeSet<i64> = due.iter().map(|row| row.alert_id).collect();
        let alerts: BTreeMap<i64, Alert> = alert::Entity::find()
            .filter(alert::Column::Id.is_in(alert_ids))
            .all(&self.connection)
            .await
            .context("loading alerts")?
            .into_iter()
            .map(|row| to_alert(row).map(|alert| (alert.id, alert)))
            .collect::<Result<_>>()?;
        let channels: BTreeMap<i64, Channel> = self
            .list_channels()
            .await?
            .into_iter()
            .map(|channel| (channel.id, channel))
            .collect();

        // A resolved notification may need what its firing one was called.
        let earlier: BTreeMap<(i64, i64), String> = notification::Entity::find()
            .filter(notification::Column::AlertId.is_in(due.iter().map(|row| row.alert_id)))
            .filter(notification::Column::Event.eq(Event::Firing.as_str()))
            .all(&self.connection)
            .await
            .context("loading notifications")?
            .into_iter()
            .filter_map(|row| Some(((row.alert_id, row.channel_id), row.external_id?)))
            .collect();

        due.into_iter()
            .map(|row| {
                Ok(Delivery {
                    reply_to: earlier.get(&(row.alert_id, row.channel_id)).cloned(),
                    id: row.id,
                    event: Event::parse(&row.event)?,
                    attempts: row.attempts,
                    created_ms: row.created_ms,
                    alert: alerts.get(&row.alert_id).context("missing alert")?.clone(),
                    channel: channels
                        .get(&row.channel_id)
                        .context("missing channel")?
                        .clone(),
                })
            })
            .collect()
    }

    /// Keeps a notification back because of a silence. An alert that's already over
    /// has nothing to wait for, so nobody hears about it starting or ending.
    pub async fn hold_delivery(&self, delivery: &Delivery) -> Result<()> {
        if delivery.alert.resolved_ms.is_some() {
            notification::Entity::delete_many()
                .filter(notification::Column::AlertId.eq(delivery.alert.id))
                .filter(notification::Column::ChannelId.eq(delivery.channel.id))
                .filter(notification::Column::State.eq(PENDING))
                .exec(&self.connection)
                .await
                .context("dropping notifications")?;
            return Ok(());
        }

        notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(HELD))
            .col_expr(notification::Column::Attempts, Expr::value(0))
            .col_expr(notification::Column::LastError, Expr::value(None::<String>))
            .filter(notification::Column::Id.eq(delivery.id))
            .exec(&self.connection)
            .await
            .context("saving notification")?;
        Ok(())
    }

    /// The alerts behind what silences are keeping back, with what's kept back for each.
    pub async fn held_deliveries(&self) -> Result<Vec<(Alert, Vec<i64>)>> {
        let rows = notification::Entity::find()
            .filter(notification::Column::State.eq(HELD))
            .all(&self.connection)
            .await
            .context("loading notifications")?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let mut held: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for row in rows {
            held.entry(row.alert_id).or_default().push(row.id);
        }
        let alerts = alert::Entity::find()
            .filter(alert::Column::Id.is_in(held.keys().copied()))
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        alerts
            .into_iter()
            .map(|row| {
                let ids = held.remove(&row.id).unwrap_or_default();
                Ok((to_alert(row)?, ids))
            })
            .collect()
    }

    /// Lets held notifications go. The day they get to arrive starts now, however long
    /// they waited.
    pub async fn release_deliveries(&self, ids: &[i64], now_ms: i64) -> Result<()> {
        notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(PENDING))
            .col_expr(notification::Column::NextAttemptMs, Expr::value(now_ms))
            .col_expr(notification::Column::CreatedMs, Expr::value(now_ms))
            .filter(notification::Column::Id.is_in(ids.iter().copied()))
            .exec(&self.connection)
            .await
            .context("saving notifications")?;
        Ok(())
    }

    /// `external_id` is what the service called it, if that's needed later.
    pub async fn delivery_sent(
        &self,
        id: i64,
        attempts: i32,
        now_ms: i64,
        external_id: Option<&str>,
    ) -> Result<()> {
        notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(SENT))
            .col_expr(notification::Column::Attempts, Expr::value(attempts))
            .col_expr(notification::Column::SentMs, Expr::value(now_ms))
            .col_expr(
                notification::Column::ExternalId,
                Expr::value(external_id.map(String::from)),
            )
            .col_expr(notification::Column::LastError, Expr::value(None::<String>))
            .filter(notification::Column::Id.eq(id))
            .exec(&self.connection)
            .await
            .context("saving notification")?;
        Ok(())
    }

    /// Tries again at `next_attempt_ms`, or gives up if there's no such time.
    pub async fn delivery_failed(
        &self,
        id: i64,
        attempts: i32,
        error: &str,
        next_attempt_ms: Option<i64>,
    ) -> Result<()> {
        let mut update = notification::Entity::update_many()
            .col_expr(notification::Column::Attempts, Expr::value(attempts))
            .col_expr(notification::Column::LastError, Expr::value(error));
        update = match next_attempt_ms {
            Some(time) => update.col_expr(notification::Column::NextAttemptMs, Expr::value(time)),
            None => update.col_expr(notification::Column::State, Expr::value(FAILED)),
        };
        update
            .filter(notification::Column::Id.eq(id))
            .exec(&self.connection)
            .await
            .context("saving notification")?;
        Ok(())
    }

    /// The newest deliveries that haven't worked, whether given up on or not.
    pub async fn delivery_problems(&self, limit: u64) -> Result<Vec<DeliveryProblem>> {
        let rows = notification::Entity::find()
            .filter(notification::Column::LastError.is_not_null())
            .order_by_desc(notification::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading notifications")?;

        let alert_ids: BTreeSet<i64> = rows.iter().map(|row| row.alert_id).collect();
        let summaries: BTreeMap<i64, String> = alert::Entity::find()
            .filter(alert::Column::Id.is_in(alert_ids))
            .all(&self.connection)
            .await
            .context("loading alerts")?
            .into_iter()
            .map(|row| (row.id, row.summary))
            .collect();
        let channels: BTreeMap<i64, String> = self
            .list_channels()
            .await?
            .into_iter()
            .map(|channel| (channel.id, channel.channel.name))
            .collect();

        rows.into_iter()
            .map(|row| {
                Ok(DeliveryProblem {
                    channel: channels.get(&row.channel_id).cloned().unwrap_or_default(),
                    summary: summaries.get(&row.alert_id).cloned().unwrap_or_default(),
                    event: Event::parse(&row.event)?,
                    state: row.state,
                    attempts: row.attempts,
                    error: row.last_error.unwrap_or_default(),
                    created_ms: row.created_ms,
                })
            })
            .collect()
    }
}
