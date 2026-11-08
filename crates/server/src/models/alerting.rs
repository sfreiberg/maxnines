//! Alert rules, notification channels, alerts and the notification queue.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Query};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};

use super::{Database, alert, alert_rule, alert_rule_channel, notification, notification_channel};
use crate::alerting::{
    Alert, AlertRule, AlertRuleInput, Channel, ChannelInput, ChannelKind, Comparison, Delivery,
    DeliveryProblem, Event, NewAlert, RULE_GONE_REASON, RuleKind, Severity,
};
use crate::calculations::Calculation;

const PENDING: &str = "pending";
const SENT: &str = "sent";
const FAILED: &str = "failed";
/// Kept back by a silence.
const HELD: &str = "held";

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
            remind_every_secs: row
                .remind_every_secs
                .map(u64::try_from)
                .transpose()
                .context("invalid reminder")?,
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
        remind_every_secs: Set(input
            .remind_every_secs
            .map(i64::try_from)
            .transpose()
            .context("invalid reminder")?),
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
            app_token: row.app_token,
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
        acknowledged_by: row.acknowledged_by,
        acknowledged_ms: row.acknowledged_ms,
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

    /// Alerts from the rule stay as history, and its open ones end now. The rule's
    /// silences go with it, so an alert they were holding back has to end in the
    /// same step, or its notifications would go out in the moments before the
    /// evaluator noticed. Returns false if there's no such rule.
    pub async fn delete_alert_rule(&self, id: i64, now_ms: i64) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("deleting alert rule")?;
        let open = alert::Entity::find()
            .filter(alert::Column::RuleId.eq(id))
            .filter(alert::Column::ResolvedMs.is_null())
            .all(&transaction)
            .await
            .context("loading alerts")?;
        for alert in open {
            resolve_in(&transaction, alert.id, now_ms, RULE_GONE_REASON).await?;
        }
        let result = alert_rule::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting alert rule")?;
        transaction.commit().await.context("deleting alert rule")?;
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
            app_token: Set(input.app_token.clone()),
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
            app_token: Set(input.app_token.clone()),
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

/// Ends an alert within a transaction: see [`Database::resolve_alert`].
async fn resolve_in<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    now_ms: i64,
    reason: &str,
) -> Result<()> {
    let result = alert::Entity::update_many()
        .col_expr(alert::Column::ResolvedMs, Expr::value(now_ms))
        .col_expr(alert::Column::ResolveReason, Expr::value(reason))
        .filter(alert::Column::Id.eq(id))
        .filter(alert::Column::ResolvedMs.is_null())
        .exec(connection)
        .await
        .context("resolving alert")?;
    if result.rows_affected == 0 {
        return Ok(());
    }

    notification::Entity::delete_many()
        .filter(notification::Column::AlertId.eq(id))
        .filter(notification::Column::State.eq(HELD))
        .exec(connection)
        .await
        .context("dropping notifications")?;
    let told = notification::Entity::find()
        .filter(notification::Column::AlertId.eq(id))
        .filter(notification::Column::Event.eq(Event::Firing.as_str()))
        .all(connection)
        .await
        .context("loading notifications")?;
    let rows: Vec<_> = told
        .into_iter()
        .map(|row| queued(id, row.channel_id, Event::Resolved, now_ms))
        .collect();
    if !rows.is_empty() {
        notification::Entity::insert_many(rows)
            .exec_without_returning(connection)
            .await
            .context("queueing notifications")?;
    }
    Ok(())
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
            acknowledged_by: Set(None),
            acknowledged_ms: Set(None),
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
        resolve_in(&transaction, id, now_ms, reason).await?;
        transaction.commit().await.context("resolving alert")?;
        Ok(())
    }

    /// What can be sent now. Each channel hears about an alert in order: a
    /// resolved notification waits while its firing one is being retried, or a
    /// receiver would see the alert start after it ended, and never close it.
    pub async fn due_deliveries(&self, now_ms: i64, limit: usize) -> Result<Vec<Delivery>> {
        // Both conditions are in the query, so rows waiting to be retried cost
        // nothing: a channel that's down can't hold up the others.
        let earlier = Alias::new("earlier");
        let waiting_behind_another = Query::select()
            .expr(Expr::val(1))
            .from_as(notification::Entity, earlier.clone())
            .and_where(
                Expr::col((earlier.clone(), notification::Column::AlertId))
                    .equals((notification::Entity, notification::Column::AlertId)),
            )
            .and_where(
                Expr::col((earlier.clone(), notification::Column::ChannelId))
                    .equals((notification::Entity, notification::Column::ChannelId)),
            )
            .and_where(Expr::col((earlier.clone(), notification::Column::State)).eq(PENDING))
            .and_where(
                Expr::col((earlier, notification::Column::Id))
                    .lt(Expr::col((notification::Entity, notification::Column::Id))),
            )
            .to_owned();
        let due = notification::Entity::find()
            .filter(notification::Column::State.eq(PENDING))
            .filter(notification::Column::NextAttemptMs.lte(now_ms))
            .filter(Expr::not_exists(waiting_behind_another))
            .order_by_asc(notification::Column::Id)
            .limit(limit as u64)
            .all(&self.connection)
            .await
            .context("loading notifications")?;
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

    /// Says someone is dealing with an alert. The first person to say so stays on it.
    /// Returns false if there's no such alert firing.
    pub async fn get_alert(&self, id: i64) -> Result<Option<Alert>> {
        let row = alert::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading alert")?;
        row.map(to_alert).transpose()
    }

    pub async fn acknowledge_alert(&self, id: i64, by: &str, now_ms: i64) -> Result<bool> {
        let firing = alert::Entity::find_by_id(id)
            .filter(alert::Column::ResolvedMs.is_null())
            .one(&self.connection)
            .await
            .context("loading alert")?;
        if firing.is_none() {
            return Ok(false);
        }
        alert::Entity::update_many()
            .col_expr(alert::Column::AcknowledgedBy, Expr::value(by))
            .col_expr(alert::Column::AcknowledgedMs, Expr::value(now_ms))
            .filter(alert::Column::Id.eq(id))
            .filter(alert::Column::AcknowledgedMs.is_null())
            .exec(&self.connection)
            .await
            .context("saving alert")?;
        Ok(true)
    }

    /// Returns false if there's no such alert firing.
    pub async fn unacknowledge_alert(&self, id: i64) -> Result<bool> {
        let result = alert::Entity::update_many()
            .col_expr(alert::Column::AcknowledgedBy, Expr::value(None::<String>))
            .col_expr(alert::Column::AcknowledgedMs, Expr::value(None::<i64>))
            .filter(alert::Column::Id.eq(id))
            .filter(alert::Column::ResolvedMs.is_null())
            .exec(&self.connection)
            .await
            .context("saving alert")?;
        Ok(result.rows_affected > 0)
    }

    /// Alerts that nobody has acknowledged, on rules that send reminders, with how often.
    pub async fn alerts_to_remind(&self) -> Result<Vec<(Alert, i64)>> {
        let rules: BTreeMap<i64, i64> = alert_rule::Entity::find()
            .filter(alert_rule::Column::RemindEverySecs.is_not_null())
            .all(&self.connection)
            .await
            .context("loading alert rules")?
            .into_iter()
            .filter_map(|row| Some((row.id, row.remind_every_secs?)))
            .collect();
        if rules.is_empty() {
            return Ok(Vec::new());
        }

        let rows = alert::Entity::find()
            .filter(alert::Column::RuleId.is_in(rules.keys().copied()))
            .filter(alert::Column::ResolvedMs.is_null())
            .filter(alert::Column::AcknowledgedMs.is_null())
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        rows.into_iter()
            .filter_map(|row| Some((rules.get(&row.rule_id?).copied()?, row)))
            .map(|(every, row)| Ok((to_alert(row)?, every)))
            .collect()
    }

    /// Queues a reminder for each channel that was told an alert started and hasn't heard
    /// about it for as long as the alert's rule says. Each alert comes with that time, in
    /// seconds. On-call services are left out.
    pub async fn queue_reminders(&self, alerts: &[(i64, i64)], now_ms: i64) -> Result<()> {
        if alerts.is_empty() {
            return Ok(());
        }
        let rows = notification::Entity::find()
            .filter(notification::Column::AlertId.is_in(alerts.iter().map(|(id, _)| *id)))
            .all(&self.connection)
            .await
            .context("loading notifications")?;

        let mut last_told: BTreeMap<(i64, i64), i64> = BTreeMap::new();
        let mut waiting = BTreeSet::new();
        for row in rows {
            let key = (row.alert_id, row.channel_id);
            match row.sent_ms {
                Some(sent) => {
                    let last = last_told.entry(key).or_default();
                    *last = std::cmp::max(sent, *last);
                }
                None if row.state != FAILED => {
                    waiting.insert(key);
                }
                None => {}
            }
        }

        let every_ms: BTreeMap<i64, i64> = alerts
            .iter()
            .map(|(id, secs)| (*id, secs.saturating_mul(1000)))
            .collect();
        let on_call: BTreeSet<i64> = self
            .list_channels()
            .await?
            .into_iter()
            .filter(|channel| channel.channel.kind.is_on_call())
            .map(|channel| channel.id)
            .collect();
        let rows: Vec<_> = last_told
            .into_iter()
            .filter(|(key, _)| !waiting.contains(key) && !on_call.contains(&key.1))
            .filter(|((alert, _), told)| {
                every_ms
                    .get(alert)
                    .is_some_and(|every| now_ms - told >= *every)
            })
            .map(|((alert, channel), _)| queued(alert, channel, Event::Reminder, now_ms))
            .collect();
        if !rows.is_empty() {
            notification::Entity::insert_many(rows)
                .exec_without_returning(&self.connection)
                .await
                .context("queueing notifications")?;
        }
        Ok(())
    }

    /// Forgets a notification that no longer has anything to say.
    pub async fn drop_delivery(&self, id: i64) -> Result<()> {
        notification::Entity::delete_by_id(id)
            .exec(&self.connection)
            .await
            .context("dropping notification")?;
        Ok(())
    }

    /// Keeps a notification back because of a silence. An alert that's already over
    /// has nothing to wait for, so nobody hears about it starting or ending. The
    /// alert can end between the queue being read and this, so the database decides
    /// from the alert as it is now, not as the queue saw it.
    pub async fn hold_delivery(&self, delivery: &Delivery) -> Result<()> {
        let still_open = sea_orm::sea_query::Query::select()
            .column(alert::Column::Id)
            .from(alert::Entity)
            .and_where(alert::Column::Id.eq(delivery.alert.id))
            .and_where(alert::Column::ResolvedMs.is_null())
            .to_owned();
        let held = notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(HELD))
            .col_expr(notification::Column::Attempts, Expr::value(0))
            .col_expr(notification::Column::LastError, Expr::value(None::<String>))
            .filter(notification::Column::Id.eq(delivery.id))
            .filter(notification::Column::State.eq(PENDING))
            .filter(notification::Column::AlertId.in_subquery(still_open))
            .exec(&self.connection)
            .await
            .context("saving notification")?;
        if held.rows_affected == 0 {
            self.drop_unsent(delivery.alert.id, delivery.channel.id)
                .await?;
        }
        Ok(())
    }

    /// Forgets what a channel was never told about an alert, held or waiting.
    async fn drop_unsent(&self, alert_id: i64, channel_id: i64) -> Result<()> {
        notification::Entity::delete_many()
            .filter(notification::Column::AlertId.eq(alert_id))
            .filter(notification::Column::ChannelId.eq(channel_id))
            .filter(notification::Column::State.is_in([PENDING, HELD]))
            .exec(&self.connection)
            .await
            .context("dropping notifications")?;
        Ok(())
    }

    /// Drops everything held back about an alert that has since ended, along with
    /// anything else queued for the same channels: they never heard it start, so
    /// they shouldn't hear it end.
    pub async fn drop_held_for(&self, alert_id: i64) -> Result<()> {
        let held = notification::Entity::find()
            .filter(notification::Column::AlertId.eq(alert_id))
            .filter(notification::Column::State.eq(HELD))
            .all(&self.connection)
            .await
            .context("loading notifications")?;
        let channels: BTreeSet<i64> = held.into_iter().map(|row| row.channel_id).collect();
        for channel_id in channels {
            self.drop_unsent(alert_id, channel_id).await?;
        }
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
