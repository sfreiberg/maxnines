//! Alert rules, notification channels, alerts and the notification queue.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::TimeDelta;
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Order, Query, SelectStatement};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait,
};
use tracing::warn;

use serde_json::json;

use super::actions::to_run;
use super::audit::{record, record_change};
use super::{
    Database, action_run, alert, alert_rule, alert_rule_action, alert_rule_channel, host,
    maintenance_window, name_key, name_taken_or, notification, notification_channel, silence,
    template,
};
use crate::actions::{ActionRun, RuleAction, RunOn};
use crate::alerting::{
    Alert, AlertRule, AlertRuleInput, Channel, ChannelInput, ChannelKind, Delivery,
    DeliveryProblem, Event, Mail, MailSecurity, MailServer, NameTaken, NewAlert, RULE_GONE_REASON,
    Severity, SeverityChange, TemplateLink, WebhookMethod, WebhookRequest,
};
use crate::audit::{Action, Kind, Record, Snapshot, Subject};
use crate::calculations::Calculation;
use crate::channels;
use crate::times::Timestamp;

pub(super) const PENDING: &str = "pending";
const SENT: &str = "sent";
pub(super) const FAILED: &str = "failed";
/// Kept back by a silence.
pub(super) const HELD: &str = "held";

fn to_alert_rule(
    row: alert_rule::Model,
    channels: Vec<i64>,
    actions: Vec<RuleAction>,
    templates: &BTreeMap<i64, (String, bool)>,
) -> Result<AlertRule> {
    let template = match (row.template_id, &row.template_alert) {
        (Some(id), Some(alert)) => {
            let (key, on) = templates
                .get(&id)
                .cloned()
                .context("a rule's template is missing")?;
            Some(TemplateLink {
                id,
                key,
                alert: alert.clone(),
                replaces_id: row.replaces_id,
                template_enabled: on,
                enabled_choice: row.enabled_choice,
                waits_for_discovery: row.when_condition.is_some() || row.since.is_some(),
                original_changed_at: row.original_changed_at,
            })
        }
        _ => None,
    };
    Ok(AlertRule::unread(
        row.id,
        AlertRuleInput {
            name: row.name,
            warning: row.warning,
            critical: row.critical,
            summary: row.summary,
            resolved_summary: row.resolved_summary,
            hold: whole_seconds(row.for_secs).context("invalid duration")?,
            applies_to: row.applies_to,
            enabled: row.enabled_choice.unwrap_or(row.enabled),
            channels,
            all_channels: row.all_channels,
            calculation: row.calculation.as_deref().and_then(Calculation::parse),
            metric: row.metric,
            group_by: row.group_by,
            filter: row.filter,
            window: row
                .window_secs
                .map(whole_seconds)
                .transpose()
                .context("invalid window")?,
            remind_every: row
                .remind_every_secs
                .map(whole_seconds)
                .transpose()
                .context("invalid reminder")?,
            actions,
        },
        template,
    ))
}

/// A length the database keeps in whole seconds, as rules are written. One that's
/// negative was never saved by the server.
fn whole_seconds(seconds: i64) -> Result<TimeDelta> {
    (seconds >= 0)
        .then(|| TimeDelta::try_seconds(seconds))
        .flatten()
        .context("not a length of time")
}

pub(super) fn alert_rule_row(input: &AlertRuleInput) -> Result<alert_rule::ActiveModel> {
    Ok(alert_rule::ActiveModel {
        name: Set(input.name.clone()),
        name_key: Set(name_key(&input.name)),
        warning: Set(input.warning.clone()),
        critical: Set(input.critical.clone()),
        summary: Set(input.summary.clone()),
        resolved_summary: Set(input.resolved_summary.clone()),
        for_secs: Set(input.hold.num_seconds()),
        applies_to: Set(input.applies_to.clone()),
        enabled: Set(input.enabled),
        calculation: Set(input.calculation.map(|c| c.as_str().to_string())),
        metric: Set(input.metric.clone()),
        group_by: Set(input.group_by.clone()),
        filter: Set(input.filter.clone()),
        window_secs: Set(input.window.map(|window| window.num_seconds())),
        remind_every_secs: Set(input.remind_every.map(|every| every.num_seconds())),
        all_channels: Set(input.all_channels),
        ..Default::default()
    })
}

fn channel_row(input: &ChannelInput) -> notification_channel::ActiveModel {
    let mail = input.mail.as_ref();
    let server = mail.and_then(|mail| mail.server.as_ref());
    let request = input.request.as_ref();
    notification_channel::ActiveModel {
        name: Set(input.name.clone()),
        name_key: Set(name_key(&input.name)),
        kind: Set(input.kind.as_str().to_string()),
        target: Set(input.target.clone()),
        credential: Set(input.credential.clone()),
        app_token: Set(input.app_token.clone()),
        sends_warnings: Set(input.severities.contains(&Severity::Warning)),
        sends_critical: Set(input.severities.contains(&Severity::Critical)),
        mail_from: Set(mail.map(|mail| mail.from.trim().to_string())),
        mail_hostname: Set(server.map(|server| server.hostname.trim().to_string())),
        mail_port: Set(server.and_then(|server| server.port).map(i32::from)),
        mail_security: Set(server.map(|server| server.security.as_str().to_string())),
        mail_username: Set(server.and_then(|server| server.username.clone())),
        request_method: Set(request.map(|request| request.method.as_str().to_string())),
        request_content_type: Set(request.map(|request| request.content_type.trim().to_string())),
        request_body: Set(request.map(|request| request.body.clone())),
        ..Default::default()
    }
}

/// How a channel sends email, if it does. A channel saved before email channels had
/// their own mail server has none, and is told so when it's next used.
fn to_mail(row: &notification_channel::Model) -> Result<Option<Mail>> {
    let Some(from) = row.mail_from.clone() else {
        return Ok(None);
    };
    let server = match &row.mail_hostname {
        None => None,
        Some(hostname) => Some(MailServer {
            hostname: hostname.clone(),
            port: row
                .mail_port
                .map(u16::try_from)
                .transpose()
                .context("invalid mail port")?,
            security: row
                .mail_security
                .as_deref()
                .map(MailSecurity::parse)
                .transpose()?
                .unwrap_or_default(),
            username: row.mail_username.clone(),
        }),
    };
    Ok(Some(Mail { from, server }))
}

/// What a custom webhook sends, if it is one.
fn to_request(row: &notification_channel::Model) -> Result<Option<WebhookRequest>> {
    let Some(method) = &row.request_method else {
        return Ok(None);
    };
    Ok(Some(WebhookRequest {
        method: WebhookMethod::parse(method)?,
        content_type: row.request_content_type.clone().unwrap_or_default(),
        body: row.request_body.clone().unwrap_or_default(),
    }))
}

fn to_channel(row: notification_channel::Model) -> Result<Channel> {
    let mail = to_mail(&row)?;
    let request = to_request(&row)?;
    Ok(Channel {
        id: row.id,
        channel: ChannelInput {
            name: row.name,
            kind: ChannelKind::parse(&row.kind)?,
            target: row.target,
            credential: row.credential,
            app_token: row.app_token,
            severities: [
                (Severity::Warning, row.sends_warnings),
                (Severity::Critical, row.sends_critical),
            ]
            .into_iter()
            .filter_map(|(severity, sent)| sent.then_some(severity))
            .collect(),
            mail,
            request,
        },
    })
}

/// Alerts as they're shown, named by their rule and host as those are called now. The
/// names are read for every alert at once, rather than for each in turn.
pub(super) async fn to_alerts<C: ConnectionTrait>(
    connection: &C,
    rows: Vec<alert::Model>,
) -> Result<Vec<Alert>> {
    each_alert(connection, rows).await?.into_iter().collect()
}

/// Each alert as [`to_alerts`] reads them, or why it can't be read, for when one that
/// can't shouldn't stop the rest.
async fn each_alert<C: ConnectionTrait>(
    connection: &C,
    rows: Vec<alert::Model>,
) -> Result<Vec<Result<Alert>>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let rule_ids: BTreeSet<i64> = rows.iter().map(|row| row.rule_id).collect();
    let host_ids: BTreeSet<&str> = rows.iter().map(|row| row.host_id.as_str()).collect();
    // A deleted rule is only marked so, and its alerts still go by its name.
    let rule_names: BTreeMap<i64, String> = alert_rule::Entity::find()
        .select_only()
        .column(alert_rule::Column::Id)
        .column(alert_rule::Column::Name)
        .filter(alert_rule::Column::Id.is_in(rule_ids))
        .into_tuple()
        .all(connection)
        .await
        .context("loading the names of alerts' rules")?
        .into_iter()
        .collect();
    let hostnames: BTreeMap<String, String> = host::Entity::find()
        .select_only()
        .column(host::Column::Id)
        .column(host::Column::Hostname)
        .filter(host::Column::Id.is_in(host_ids))
        .into_tuple()
        .all(connection)
        .await
        .context("loading the names of alerts' hosts")?
        .into_iter()
        .collect();
    Ok(rows
        .into_iter()
        .map(|row| to_alert(row, &rule_names, &hostnames))
        .collect())
}

/// One alert, as [`to_alerts`] reads them.
async fn to_one_alert<C: ConnectionTrait>(connection: &C, row: alert::Model) -> Result<Alert> {
    let mut alerts = to_alerts(connection, vec![row]).await?;
    alerts.pop().context("reading an alert")
}

fn to_alert(
    row: alert::Model,
    rule_names: &BTreeMap<i64, String>,
    hostnames: &BTreeMap<String, String>,
) -> Result<Alert> {
    // Foreign keys keep both there.
    let rule_name = rule_names
        .get(&row.rule_id)
        .with_context(|| format!("alert {} has no rule", row.id))?;
    let hostname = hostnames
        .get(&row.host_id)
        .with_context(|| format!("alert {} has no host", row.id))?;
    Ok(Alert {
        id: row.id,
        rule_id: row.rule_id,
        rule_name: rule_name.clone(),
        severity: Severity::parse(&row.severity)?,
        host_id: row.host_id,
        hostname: hostname.clone(),
        series: row.series,
        value: row.value,
        summary: row.summary,
        started_at: row.started_at,
        breached_at: row.breached_at,
        resolved_at: row.resolved_at,
        resolve_reason: row.resolve_reason,
        resolved_summary: row.resolved_summary,
        acknowledged_by: row.acknowledged_by,
        acknowledged_at: row.acknowledged_at,
    })
}

/// A rule's actions as rows, in the order they were given.
fn action_rows(
    rule_id: i64,
    actions: &[RuleAction],
) -> Result<Vec<alert_rule_action::ActiveModel>> {
    actions
        .iter()
        .enumerate()
        .map(|(position, wanted)| {
            Ok(alert_rule_action::ActiveModel {
                rule_id: Set(rule_id),
                action: Set(wanted.action.clone()),
                run_on: Set(wanted.run_on.as_str().to_string()),
                timeout_secs: Set(i64::try_from(wanted.timeout().as_secs())?),
                position: Set(i32::try_from(position)?),
                ..Default::default()
            })
        })
        .collect()
}

fn to_rule_action(row: alert_rule_action::Model) -> Result<RuleAction> {
    Ok(RuleAction {
        run_on: RunOn::parse(&row.run_on).context("invalid moment for an action")?,
        timeout: Some(Duration::from_secs(u64::try_from(row.timeout_secs)?)),
        action: row.action,
    })
}

/// Replaces a rule's actions with these.
pub(super) async fn save_actions<C: ConnectionTrait>(
    connection: &C,
    rule_id: i64,
    actions: &[RuleAction],
) -> Result<()> {
    alert_rule_action::Entity::delete_many()
        .filter(alert_rule_action::Column::RuleId.eq(rule_id))
        .exec(connection)
        .await
        .context("saving alert rule actions")?;
    let rows = action_rows(rule_id, actions)?;
    if !rows.is_empty() {
        alert_rule_action::Entity::insert_many(rows)
            .exec_without_returning(connection)
            .await
            .context("saving alert rule actions")?;
    }
    Ok(())
}

/// Links a rule to each of `channels` that hasn't been deleted. They're locked as
/// [`live_channels`] locks them, so one being deleted meanwhile is waited for and
/// left out, and one deleted after can't miss the link to drop it.
pub(super) async fn save_links<C: ConnectionTrait>(
    connection: &C,
    rule_id: i64,
    channels: &[i64],
) -> Result<()> {
    let wanted: BTreeSet<i64> = channels.iter().copied().collect();
    if wanted.is_empty() {
        return Ok(());
    }
    let live: Vec<i64> = notification_channel::Entity::find()
        .select_only()
        .column(notification_channel::Column::Id)
        .filter(notification_channel::Column::Id.is_in(wanted))
        .filter(notification_channel::Column::DeletedAt.is_null())
        .lock_shared()
        .into_tuple()
        .all(connection)
        .await
        .context("loading alert rule channels")?;
    let rows: Vec<_> = live
        .into_iter()
        .map(|channel_id| alert_rule_channel::ActiveModel {
            rule_id: Set(rule_id),
            channel_id: Set(channel_id),
        })
        .collect();
    if !rows.is_empty() {
        alert_rule_channel::Entity::insert_many(rows)
            .exec_without_returning(connection)
            .await
            .context("saving alert rule channels")?;
    }
    Ok(())
}

fn queued(
    alert_id: i64,
    channel_id: i64,
    event: Event,
    now: Timestamp,
) -> notification::ActiveModel {
    notification::ActiveModel {
        alert_id: Set(alert_id),
        channel_id: Set(channel_id),
        event: Set(event.as_str().to_string()),
        state: Set(PENDING.to_string()),
        attempts: Set(0),
        next_attempt_at: Set(now),
        last_error: Set(None),
        created_at: Set(now),
        sent_at: Set(None),
        external_id: Set(None),
        action_run_id: Set(None),
        ..Default::default()
    }
}

/// The channels that haven't been deleted, which are the only ones anything is
/// queued for. They're locked until the transaction ends, so a channel being deleted
/// meanwhile is waited for, and left out, and one can't be deleted until what's
/// queued for it is there to be dropped. Deleting one marks it first for that.
fn live_channels() -> SelectStatement {
    Query::select()
        .column(notification_channel::Column::Id)
        .from(notification_channel::Entity)
        .and_where(notification_channel::Column::DeletedAt.is_null())
        .lock_shared()
        .to_owned()
}

/// Queues `event` about an alert for each of `channels` that hasn't been deleted, in
/// the order of their IDs. Whether one has been is decided by the statement that
/// queues, which locks them as [`live_channels`] does, so one deleted since they were
/// chosen is left out.
pub(super) async fn queue_for_live_channels<C: ConnectionTrait>(
    connection: &C,
    alert_id: i64,
    channels: impl IntoIterator<Item = i64>,
    event: Event,
    now: Timestamp,
) -> Result<()> {
    let channels: BTreeSet<i64> = channels.into_iter().collect();
    if channels.is_empty() {
        return Ok(());
    }
    let live = Query::select()
        .expr(Expr::val(alert_id))
        .column(notification_channel::Column::Id)
        .from(notification_channel::Entity)
        .and_where(notification_channel::Column::Id.is_in(channels))
        .and_where(notification_channel::Column::DeletedAt.is_null())
        .order_by(notification_channel::Column::Id, Order::Asc)
        .lock_shared()
        .to_owned();
    queue_selected(connection, live, event, now).await
}

/// Queues `event` for each alert and channel `selected` gives, as its first and second
/// columns, in its order.
async fn queue_selected<C: ConnectionTrait>(
    connection: &C,
    mut selected: SelectStatement,
    event: Event,
    now: Timestamp,
) -> Result<()> {
    selected
        .expr(Expr::val(event.as_str()))
        .expr(Expr::val(PENDING))
        .expr(Expr::val(0))
        .expr(Expr::val(now))
        .expr(Expr::val(now));
    let insert = Query::insert()
        .into_table(notification::Entity)
        .columns([
            notification::Column::AlertId,
            notification::Column::ChannelId,
            notification::Column::Event,
            notification::Column::State,
            notification::Column::Attempts,
            notification::Column::NextAttemptAt,
            notification::Column::CreatedAt,
        ])
        .select_from(selected)
        .context("queueing notifications")?
        .to_owned();
    connection
        .execute(&insert)
        .await
        .context("queueing notifications")?;
    Ok(())
}

/// Queues what an alert's action printed for every channel that was told about
/// the alert, in the order they heard, so it follows the message it's about.
/// On-call services are left out, as it would only page someone again, and so
/// is a custom webhook whose body doesn't use it. A run a person started has no
/// alert, and goes nowhere.
pub(super) async fn queue_action_output<C: ConnectionTrait>(
    connection: &C,
    run_id: i64,
    now: Timestamp,
) -> Result<()> {
    let alert_id: Option<Option<i64>> = action_run::Entity::find_by_id(run_id)
        .select_only()
        .column(action_run::Column::AlertId)
        .into_tuple()
        .one(connection)
        .await
        .context("loading an action run")?;
    let Some(alert_id) = alert_id.flatten() else {
        return Ok(());
    };
    let told: Vec<i64> = notification::Entity::find()
        .select_only()
        .column(notification::Column::ChannelId)
        .distinct()
        .filter(notification::Column::AlertId.eq(alert_id))
        .into_tuple()
        .all(connection)
        .await
        .context("loading notifications")?;
    let channels = notification_channel::Entity::find()
        .filter(notification_channel::Column::Id.is_in(told))
        .filter(notification_channel::Column::DeletedAt.is_null())
        .order_by_asc(notification_channel::Column::Id)
        .lock_shared()
        .all(connection)
        .await
        .context("loading channels")?;
    let rows: Vec<_> = channels
        .into_iter()
        .map(to_channel)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|channel| {
            let kind = channel.channel.kind;
            !kind.is_on_call() && channels::of(kind).takes_action_output(&channel.channel)
        })
        .map(|channel| notification::ActiveModel {
            action_run_id: Set(Some(run_id)),
            ..queued(alert_id, channel.id, Event::Action, now)
        })
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
    /// Sorted by name.
    pub async fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let rows = alert_rule::Entity::find()
            .filter(alert_rule::Column::DeletedAt.is_null())
            .order_by_asc(alert_rule::Column::Name)
            .all(&self.connection)
            .await
            .context("loading alert rules")?;
        // A built-in template's rule that someone has a copy of gives way to it.
        let replaced: BTreeSet<i64> = rows.iter().filter_map(|row| row.replaces_id).collect();
        let rows: Vec<_> = rows
            .into_iter()
            .filter(|row| !replaced.contains(&row.id))
            .collect();
        let templates = template_links(&self.connection).await?;
        let catalog = self.catalog();

        // Only the links and actions of rules that aren't deleted.
        let live = || {
            Query::select()
                .column(alert_rule::Column::Id)
                .from(alert_rule::Entity)
                .and_where(alert_rule::Column::DeletedAt.is_null())
                .to_owned()
        };
        let mut channels: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for link in alert_rule_channel::Entity::find()
            .filter(alert_rule_channel::Column::RuleId.in_subquery(live()))
            .all(&self.connection)
            .await
            .context("loading alert rule channels")?
        {
            channels
                .entry(link.rule_id)
                .or_default()
                .push(link.channel_id);
        }

        let mut actions: BTreeMap<i64, Vec<RuleAction>> = BTreeMap::new();
        for row in alert_rule_action::Entity::find()
            .filter(alert_rule_action::Column::RuleId.in_subquery(live()))
            .order_by_asc(alert_rule_action::Column::Position)
            .all(&self.connection)
            .await
            .context("loading alert rule actions")?
        {
            let rule_id = row.rule_id;
            actions
                .entry(rule_id)
                .or_default()
                .push(to_rule_action(row)?);
        }

        rows.into_iter()
            .map(|row| {
                let mine = channels.remove(&row.id).unwrap_or_default();
                let run = actions.remove(&row.id).unwrap_or_default();
                Ok(to_alert_rule(row, mine, run, &templates)?.read(&catalog))
            })
            .collect()
    }

    pub async fn get_alert_rule(&self, id: i64) -> Result<Option<AlertRule>> {
        let rule = load_alert_rule(&self.connection, id).await?;
        Ok(rule.map(|rule| rule.read(&self.catalog())))
    }

    pub async fn create_alert_rule(&self, input: &AlertRuleInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        refuse_taken_name(&transaction, &input.name, &[]).await?;
        let id = alert_rule::Entity::insert(alert_rule_row(input)?)
            .exec(&transaction)
            .await
            .map_err(|error| {
                let taken = NameTaken::AlertRule(input.name.clone());
                name_taken_or(error, taken, "saving alert rule")
            })?
            .last_insert_id;

        save_links(&transaction, id, &input.channels).await?;
        save_actions(&transaction, id, &input.actions).await?;
        record_alert_rule(&transaction, id, None).await?;
        transaction.commit().await.context("saving alert rule")?;
        Ok(id)
    }

    /// Returns false if there's no such rule.
    /// Returns false if there's no such rule. A template's alert is saved as
    /// [`Database::update_template_rule`] saves it: for a built-in template, as
    /// someone's own copy of it.
    pub async fn update_alert_rule(&self, id: i64, input: &AlertRuleInput) -> Result<bool> {
        if self.template_rule(id).await?.is_some() {
            return self.update_template_rule(id, input).await;
        }
        let transaction = self.connection.begin().await.context("saving alert rule")?;
        refuse_taken_name(&transaction, &input.name, &[id]).await?;
        if !write_rule_in(&transaction, id, input).await? {
            return Ok(false);
        }
        transaction.commit().await.context("saving alert rule")?;
        Ok(true)
    }

    /// Every rule's name by its ID, deleted ones too, for what still points at them,
    /// like a silence that has ended. Deleted ones say so.
    pub async fn alert_rule_names(&self) -> Result<BTreeMap<i64, String>> {
        let rows: Vec<(i64, String, Option<Timestamp>)> = alert_rule::Entity::find()
            .select_only()
            .column(alert_rule::Column::Id)
            .column(alert_rule::Column::Name)
            .column(alert_rule::Column::DeletedAt)
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading alert rules")?;
        Ok(rows
            .into_iter()
            .map(|(id, name, deleted_at)| {
                let name = match deleted_at {
                    Some(_) => format!("{name} (deleted)"),
                    None => name,
                };
                (id, name)
            })
            .collect())
    }

    /// The rule is kept, marked deleted, so its alerts still say which rule they came
    /// from, and its open ones end now, all at once. Its silences that haven't ended
    /// and its maintenance windows go, so an alert they were holding back has to end in
    /// the same step, or its notifications would go out in the moments before the
    /// evaluator noticed. Returns false if there's no such rule.
    pub async fn delete_alert_rule(&self, id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("deleting alert rule")?;
        let row = alert_rule::Entity::find_by_id(id)
            .filter(alert_rule::Column::DeletedAt.is_null())
            .one(&transaction)
            .await
            .context("loading alert rule")?;
        // Someone's copy of a template's alert can go, which puts the template's back.
        if row
            .as_ref()
            .is_some_and(|row| row.template_id.is_some() && row.replaces_id.is_none())
        {
            bail!(crate::templates::Refused(
                "this rule is one of a template's alerts, so it can be disabled but not deleted"
                    .to_string()
            ));
        }
        // Deleting someone's copy puts the template's own rule back, with the copy's
        // open alerts, silences and maintenance windows.
        if let Some(original) = row.as_ref().and_then(|row| row.replaces_id) {
            super::templates::move_rule_state(&transaction, id, original, now).await?;
        }
        let deleted = delete_rule_in(&transaction, id, now).await?;
        transaction.commit().await.context("deleting alert rule")?;
        Ok(deleted)
    }
}

/// Deletes a rule as [`Database::delete_alert_rule`] does, inside a transaction of
/// the caller's, whoever's rule it is. Returns false if there's no such rule.
pub(super) async fn delete_rule_in<C: ConnectionTrait>(
    transaction: &C,
    id: i64,
    now: Timestamp,
) -> Result<bool> {
    // Locked first, so an alert can't start for it meanwhile: firing one waits
    // for this, and then finds the rule deleted.
    let live = alert_rule::Entity::find_by_id(id)
        .select_only()
        .column(alert_rule::Column::Id)
        .filter(alert_rule::Column::DeletedAt.is_null())
        .lock_exclusive()
        .into_tuple::<i64>()
        .one(transaction)
        .await
        .context("loading alert rule")?;
    if live.is_none() {
        return Ok(false);
    }
    let Some(rule) = load_alert_rule(transaction, id).await? else {
        return Ok(false);
    };
    let before = alert_rule_snapshot(transaction, &rule).await?;
    alert_rule::Entity::update_many()
        .col_expr(alert_rule::Column::DeletedAt, Expr::value(now))
        .filter(alert_rule::Column::Id.eq(id))
        .exec(transaction)
        .await
        .context("deleting alert rule")?;
    // Its open alerts, locked, so one ending some other way meanwhile is either
    // waited for and left out, or waits and then finds it ended.
    let open: Vec<i64> = alert::Entity::find()
        .select_only()
        .column(alert::Column::Id)
        .filter(alert::Column::RuleId.eq(id))
        .filter(alert::Column::ResolvedAt.is_null())
        .lock_exclusive()
        .into_tuple()
        .all(transaction)
        .await
        .context("loading the rule's alerts")?;
    if !open.is_empty() {
        alert::Entity::update_many()
            .col_expr(alert::Column::ResolvedAt, Expr::value(now))
            .col_expr(alert::Column::ResolveReason, Expr::value(RULE_GONE_REASON))
            .col_expr(alert::Column::ResolvedSummary, Expr::value(None::<String>))
            .filter(alert::Column::Id.is_in(open.iter().copied()))
            .exec(transaction)
            .await
            .context("resolving the rule's alerts")?;
        let ended = Query::select()
            .column(alert::Column::Id)
            .from(alert::Entity)
            .and_where(alert::Column::Id.is_in(open))
            .to_owned();
        tell_of_ending(transaction, ended, now).await?;
    }
    silence::Entity::delete_many()
        .filter(silence::Column::RuleId.eq(id))
        .filter(silence::Column::EndsAt.gt(now))
        .exec(transaction)
        .await
        .context("deleting the rule's silences")?;
    maintenance_window::Entity::delete_many()
        .filter(maintenance_window::Column::RuleId.eq(id))
        .exec(transaction)
        .await
        .context("deleting the rule's maintenance windows")?;
    record_change(transaction, Kind::AlertRule, id, Some(&before), None, None).await?;
    Ok(true)
}

impl Database {
    /// Sorted by name.
    pub async fn list_channels(&self) -> Result<Vec<Channel>> {
        let rows = notification_channel::Entity::find()
            .filter(notification_channel::Column::DeletedAt.is_null())
            .order_by_asc(notification_channel::Column::Name)
            .all(&self.connection)
            .await
            .context("loading channels")?;
        rows.into_iter().map(to_channel).collect()
    }

    pub async fn get_channel(&self, id: i64) -> Result<Option<Channel>> {
        load_channel(&self.connection, id).await
    }

    pub async fn create_channel(&self, input: &ChannelInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving channel")?;
        let id = notification_channel::Entity::insert(channel_row(input))
            .exec(&transaction)
            .await
            .map_err(|error| {
                let taken = NameTaken::Channel(input.name.clone());
                name_taken_or(error, taken, "saving channel")
            })?
            .last_insert_id;
        record_channel(&transaction, id, None).await?;
        transaction.commit().await.context("saving channel")?;
        Ok(id)
    }

    /// Returns false if there's no such channel.
    pub async fn update_channel(&self, id: i64, input: &ChannelInput) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving channel")?;
        let Some(before) = load_channel(&transaction, id).await? else {
            return Ok(false);
        };
        let mut row = channel_row(input);
        row.id = Set(id);
        notification_channel::Entity::update(row)
            .exec(&transaction)
            .await
            .map_err(|error| {
                let taken = NameTaken::Channel(input.name.clone());
                name_taken_or(error, taken, "saving channel")
            })?;
        record_channel(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving channel")?;
        Ok(true)
    }

    /// The channel is kept, marked deleted, so what was sent through it still says
    /// where it went. Anything still waiting to go, or held back by a silence, goes,
    /// and rules stop naming it. It's marked first, which locks it, so whatever was
    /// queued for it before then is there to be dropped, and anything queuing for it
    /// meanwhile waits and then leaves it out: see [`live_channels`].
    /// Returns false if there's no such channel.
    pub async fn delete_channel(&self, id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting channel")?;
        let Some(before) = load_channel(&transaction, id).await? else {
            return Ok(false);
        };
        // Only one of two deletes at once does it.
        let marked = notification_channel::Entity::update_many()
            .col_expr(notification_channel::Column::DeletedAt, Expr::value(now))
            .filter(notification_channel::Column::Id.eq(id))
            .filter(notification_channel::Column::DeletedAt.is_null())
            .exec(&transaction)
            .await
            .context("deleting channel")?;
        if marked.rows_affected == 0 {
            return Ok(false);
        }
        notification::Entity::delete_many()
            .filter(notification::Column::ChannelId.eq(id))
            .filter(notification::Column::State.is_in([PENDING, HELD]))
            .exec(&transaction)
            .await
            .context("deleting the channel's unsent notifications")?;
        alert_rule_channel::Entity::delete_many()
            .filter(alert_rule_channel::Column::ChannelId.eq(id))
            .exec(&transaction)
            .await
            .context("deleting the channel from rules")?;
        let before = channel_snapshot(&before);
        record_change(&transaction, Kind::Channel, id, Some(&before), None, None).await?;
        transaction.commit().await.context("deleting channel")?;
        Ok(true)
    }
}

/// A rule that hasn't been deleted, with its conditions still to read: see
/// [`AlertRule::read`].
pub(super) async fn load_alert_rule<C: ConnectionTrait>(
    connection: &C,
    id: i64,
) -> Result<Option<AlertRule>> {
    let Some(row) = alert_rule::Entity::find_by_id(id)
        .filter(alert_rule::Column::DeletedAt.is_null())
        .one(connection)
        .await
        .context("loading alert rule")?
    else {
        return Ok(None);
    };
    let channels = alert_rule_channel::Entity::find()
        .filter(alert_rule_channel::Column::RuleId.eq(id))
        .all(connection)
        .await
        .context("loading alert rule channels")?;
    let channels = channels.into_iter().map(|link| link.channel_id).collect();
    let actions = alert_rule_action::Entity::find()
        .filter(alert_rule_action::Column::RuleId.eq(id))
        .order_by_asc(alert_rule_action::Column::Position)
        .all(connection)
        .await
        .context("loading alert rule actions")?
        .into_iter()
        .map(to_rule_action)
        .collect::<Result<_>>()?;
    let templates = template_links(connection).await?;
    to_alert_rule(row, channels, actions, &templates).map(Some)
}

/// Each template's key and whether it's on, by its ID. The alerts of one that's
/// off don't run.
async fn template_links<C: ConnectionTrait>(
    connection: &C,
) -> Result<BTreeMap<i64, (String, bool)>> {
    let rows: Vec<(i64, String, bool, Option<bool>)> = template::Entity::find()
        .select_only()
        .column(template::Column::Id)
        .column(template::Column::Key)
        .column(template::Column::Enabled)
        .column(template::Column::EnabledChoice)
        .into_tuple()
        .all(connection)
        .await
        .context("loading templates")?;
    Ok(rows
        .into_iter()
        .map(|(id, key, enabled, choice)| (id, (key, choice.unwrap_or(enabled))))
        .collect())
}

/// Writes `input` over a rule that's there, with its channels and actions, and
/// records the change. What links it to a template is left as it is.
pub(super) async fn write_rule_in<C: ConnectionTrait>(
    transaction: &C,
    id: i64,
    input: &AlertRuleInput,
) -> Result<bool> {
    let Some(before) = load_alert_rule(transaction, id).await? else {
        return Ok(false);
    };
    let before = alert_rule_snapshot(transaction, &before).await?;

    let mut row = alert_rule_row(input)?;
    row.id = Set(id);
    alert_rule::Entity::update(row)
        .exec(transaction)
        .await
        .map_err(|error| {
            let taken = NameTaken::AlertRule(input.name.clone());
            name_taken_or(error, taken, "saving alert rule")
        })?;

    alert_rule_channel::Entity::delete_many()
        .filter(alert_rule_channel::Column::RuleId.eq(id))
        .exec(transaction)
        .await
        .context("saving alert rule channels")?;
    save_links(transaction, id, &input.channels).await?;
    save_actions(transaction, id, &input.actions).await?;
    record_alert_rule(transaction, id, Some(&before)).await?;
    Ok(true)
}

/// Someone's own copy of a built-in template's rule keeps its original's name until
/// it's renamed, so copies' names are checked here and not by the database: a name
/// is taken if any rule but `own` and what it's a copy of has it.
pub(super) async fn refuse_taken_name<C: ConnectionTrait>(
    connection: &C,
    name: &str,
    own: &[i64],
) -> Result<()> {
    let same = alert_rule::Entity::find()
        .filter(alert_rule::Column::DeletedAt.is_null())
        .filter(alert_rule::Column::NameKey.eq(name_key(name)))
        .all(connection)
        .await
        .context("loading alert rules")?;
    let taken = same.iter().any(|row| {
        !own.contains(&row.id)
            && !row
                .replaces_id
                .is_some_and(|original| own.contains(&original))
    });
    if taken {
        bail!(NameTaken::AlertRule(name.to_string()));
    }
    Ok(())
}

/// A rule as the audit log compares them, with its channels by name.
pub(super) async fn alert_rule_snapshot<C: ConnectionTrait>(
    connection: &C,
    rule: &AlertRule,
) -> Result<Snapshot> {
    let mut fields = serde_json::to_value(&rule.rule).context("recording an alert rule")?;
    let names: BTreeMap<i64, String> = notification_channel::Entity::find()
        .filter(notification_channel::Column::Id.is_in(rule.rule.channels.clone()))
        .all(connection)
        .await
        .context("loading channels")?
        .into_iter()
        .map(|channel| (channel.id, channel.name))
        .collect();
    let mut channels: Vec<String> = rule
        .rule
        .channels
        .iter()
        .map(|id| names.get(id).cloned().unwrap_or_else(|| format!("#{id}")))
        .collect();
    channels.sort();
    fields["channels"] = json!(channels);
    Ok(Snapshot::new(rule.rule.name.clone(), fields))
}

/// Records how an alert rule changed from `before`, reading it as it is now.
pub(super) async fn record_alert_rule<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&Snapshot>,
) -> Result<()> {
    let after = match load_alert_rule(connection, id).await? {
        Some(rule) => Some(alert_rule_snapshot(connection, &rule).await?),
        None => None,
    };
    record_change(
        connection,
        Kind::AlertRule,
        id,
        before,
        after.as_ref(),
        None,
    )
    .await
}

/// A channel that hasn't been deleted.
async fn load_channel<C: ConnectionTrait>(connection: &C, id: i64) -> Result<Option<Channel>> {
    let row = notification_channel::Entity::find_by_id(id)
        .filter(notification_channel::Column::DeletedAt.is_null())
        .one(connection)
        .await
        .context("loading channel")?;
    row.map(to_channel).transpose()
}

/// A channel as the audit log compares them. Tokens are secrets, and so is the
/// target for kinds where it works as a password, like a webhook's URL.
fn channel_snapshot(channel: &Channel) -> Snapshot {
    let input = &channel.channel;
    let severities: Vec<&str> = input.severities.iter().map(|s| s.as_str()).collect();
    let fields = json!({
        "name": input.name,
        "kind": input.kind.as_str(),
        "target": input.target,
        "credential": input.credential,
        "app_token": input.app_token,
        "severities": severities,
        "mail": input.mail,
        "request": input.request,
    });
    let snapshot =
        Snapshot::new(input.name.clone(), fields).with_secrets(&["credential", "app_token"]);
    if channels::of(input.kind).hides_target() {
        snapshot.with_secrets(&["target"])
    } else {
        snapshot
    }
}

async fn record_channel<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    before: Option<&Channel>,
) -> Result<()> {
    let after = load_channel(connection, id).await?;
    let before = before.map(channel_snapshot);
    let after = after.as_ref().map(channel_snapshot);
    record_change(
        connection,
        Kind::Channel,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
}

/// An alert, named by its rule and host as the alerts page shows it.
async fn alert_subject<C: ConnectionTrait>(connection: &C, row: alert::Model) -> Result<Subject> {
    let alert = to_one_alert(connection, row).await?;
    Ok(Subject::new(
        Kind::Alert,
        alert.id,
        format!("{} on {}", alert.rule_name, alert.hostname),
    ))
}

/// Ends an alert within a transaction: see [`Database::resolve_alert`].
async fn resolve_in<C: ConnectionTrait>(
    connection: &C,
    id: i64,
    now: Timestamp,
    reason: &str,
    summary: Option<&str>,
) -> Result<()> {
    let result = alert::Entity::update_many()
        .col_expr(alert::Column::ResolvedAt, Expr::value(now))
        .col_expr(alert::Column::ResolveReason, Expr::value(reason))
        .col_expr(alert::Column::ResolvedSummary, Expr::value(summary))
        .filter(alert::Column::Id.eq(id))
        .filter(alert::Column::ResolvedAt.is_null())
        .exec(connection)
        .await
        .context("resolving alert")?;
    if result.rows_affected == 0 {
        return Ok(());
    }
    let ended = Query::select()
        .column(alert::Column::Id)
        .from(alert::Entity)
        .and_where(alert::Column::Id.eq(id))
        .to_owned();
    tell_of_ending(connection, ended, now).await
}

/// What follows alerts ending, for every alert `ended` selects, whatever their
/// number: what a silence was holding back about them is dropped, and each channel
/// that heard one start hears it ended. A channel whose firing notification was given
/// up on never heard the alert start, so it doesn't hear it end either, and nor does
/// one that's been deleted.
async fn tell_of_ending<C: ConnectionTrait>(
    connection: &C,
    ended: SelectStatement,
    now: Timestamp,
) -> Result<()> {
    notification::Entity::delete_many()
        .filter(notification::Column::AlertId.in_subquery(ended.clone()))
        .filter(notification::Column::State.eq(HELD))
        .exec(connection)
        .await
        .context("dropping notifications")?;
    let told = Query::select()
        .column(notification::Column::AlertId)
        .column(notification::Column::ChannelId)
        .from(notification::Entity)
        .and_where(notification::Column::AlertId.in_subquery(ended))
        .and_where(notification::Column::Event.eq(Event::Firing.as_str()))
        .and_where(notification::Column::State.ne(FAILED))
        .and_where(notification::Column::ChannelId.in_subquery(live_channels()))
        .order_by(notification::Column::Id, Order::Asc)
        .to_owned();
    queue_selected(connection, told, Event::Resolved, now).await
}

impl Database {
    /// Newest first.
    pub async fn open_alerts(&self) -> Result<Vec<Alert>> {
        let rows = alert::Entity::find()
            .filter(alert::Column::ResolvedAt.is_null())
            .order_by_desc(alert::Column::StartedAt)
            .order_by_desc(alert::Column::Id)
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        to_alerts(&self.connection, rows).await
    }

    /// How many alerts are open.
    pub async fn open_alert_count(&self) -> Result<u64> {
        use sea_orm::PaginatorTrait;
        alert::Entity::find()
            .filter(alert::Column::ResolvedAt.is_null())
            .count(&self.connection)
            .await
            .context("counting alerts")
    }

    /// The alerts that ended most recently, newest first, however long ago each
    /// started.
    pub async fn resolved_alerts(&self, limit: u64) -> Result<Vec<Alert>> {
        let rows = alert::Entity::find()
            .filter(alert::Column::ResolvedAt.is_not_null())
            .order_by_desc(alert::Column::ResolvedAt)
            .order_by_desc(alert::Column::Id)
            .limit(limit)
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        to_alerts(&self.connection, rows).await
    }

    /// Starts an alert and queues its notifications together, so an alert can't
    /// exist without them. Gives `None` if the rule has been deleted, which it waits
    /// for if that's happening now, so a rule's alerts can't outlast it.
    pub async fn fire_alert(&self, new: &NewAlert, channels: &[i64]) -> Result<Option<i64>> {
        let row = alert::ActiveModel {
            rule_id: Set(new.rule_id),
            severity: Set(new.severity.as_str().to_string()),
            host_id: Set(new.host_id.clone()),
            series: Set(new.series.clone()),
            value: Set(new.value),
            summary: Set(new.summary.clone()),
            started_at: Set(new.started_at),
            breached_at: Set(new.breached_at),
            resolved_at: Set(None),
            resolve_reason: Set(None),
            resolved_summary: Set(None),
            acknowledged_by: Set(None),
            acknowledged_at: Set(None),
            ..Default::default()
        };

        let hearing = self.channels_hearing(channels, new.severity).await?;
        let transaction = self.connection.begin().await.context("saving alert")?;
        let rule = alert_rule::Entity::find_by_id(new.rule_id)
            .select_only()
            .column(alert_rule::Column::Id)
            .filter(alert_rule::Column::DeletedAt.is_null())
            .lock_shared()
            .into_tuple::<i64>()
            .one(&transaction)
            .await
            .context("loading the alert's rule")?;
        if rule.is_none() {
            return Ok(None);
        }
        let id = alert::Entity::insert(row)
            .exec(&transaction)
            .await
            .context("saving alert")?
            .last_insert_id;

        queue_for_live_channels(&transaction, id, hearing, Event::Firing, new.started_at).await?;
        transaction.commit().await.context("saving alert")?;
        Ok(Some(id))
    }

    /// Makes an open alert a warning or critical, with what it says now, and tells
    /// each channel that heard it start. One whose first notification hasn't gone yet
    /// gets the alert as it is now when it does. Getting worse needs someone to
    /// acknowledge it again. Returns false if the alert isn't open or is already at
    /// that severity.
    pub async fn change_severity(&self, change: &SeverityChange, channels: &[i64]) -> Result<bool> {
        let taking = self.channel_severities(channels).await?;
        let takes = |channel: i64, severity: Severity| {
            taking
                .get(&channel)
                .is_some_and(|severities| severities.contains(&severity))
        };
        let transaction = self.connection.begin().await.context("saving alert")?;
        let Some(alert) = alert::Entity::find_by_id(change.alert_id)
            .filter(alert::Column::ResolvedAt.is_null())
            .one(&transaction)
            .await
            .context("loading alert")?
        else {
            return Ok(false);
        };
        let before = Severity::parse(&alert.severity)?;
        if before == change.severity {
            return Ok(false);
        }
        let worse = change.severity > before;

        let mut update = alert::Entity::update_many()
            .col_expr(
                alert::Column::Severity,
                Expr::value(change.severity.as_str()),
            )
            .col_expr(alert::Column::Value, Expr::value(change.value))
            .col_expr(alert::Column::Summary, Expr::value(change.summary.clone()))
            .filter(alert::Column::Id.eq(change.alert_id));
        if worse {
            update = update
                .col_expr(alert::Column::AcknowledgedBy, Expr::value(None::<String>))
                .col_expr(
                    alert::Column::AcknowledgedAt,
                    Expr::value(None::<Timestamp>),
                );
        }
        update.exec(&transaction).await.context("saving alert")?;

        // A deleted channel has nothing waiting, and hears nothing more.
        let firing = notification::Entity::find()
            .filter(notification::Column::AlertId.eq(change.alert_id))
            .filter(notification::Column::Event.eq(Event::Firing.as_str()))
            .filter(notification::Column::ChannelId.in_subquery(live_channels()))
            .all(&transaction)
            .await
            .context("loading notifications")?;
        let event = if worse {
            Event::Escalated
        } else {
            Event::Eased
        };
        let told = firing
            .iter()
            .filter(|row| row.state == SENT)
            .map(|row| row.channel_id);
        let heard: BTreeSet<i64> = firing.iter().map(|row| row.channel_id).collect();
        // Channels that take this severity and not the one before hear of the
        // alert starting now.
        let starting = taking.keys().copied().filter(|channel| {
            takes(*channel, change.severity) && !takes(*channel, before) && !heard.contains(channel)
        });
        // What hasn't been sent yet to channels that don't take this severity
        // would now tell them of an alert they don't want.
        let not_taking: Vec<i64> = firing
            .iter()
            .filter(|row| row.state != SENT && !takes(row.channel_id, change.severity))
            .map(|row| row.channel_id)
            .collect();
        if !not_taking.is_empty() {
            notification::Entity::delete_many()
                .filter(notification::Column::AlertId.eq(change.alert_id))
                .filter(notification::Column::ChannelId.is_in(not_taking))
                .filter(notification::Column::State.is_in([PENDING, HELD]))
                .exec(&transaction)
                .await
                .context("dropping notifications")?;
        }
        let (alert_id, at) = (change.alert_id, change.changed_at);
        queue_for_live_channels(&transaction, alert_id, told, event, at).await?;
        queue_for_live_channels(&transaction, alert_id, starting, Event::Firing, at).await?;
        transaction.commit().await.context("saving alert")?;
        Ok(true)
    }

    /// Which of these channels hear of an alert at this severity.
    async fn channels_hearing(
        &self,
        channels: &[i64],
        severity: Severity,
    ) -> Result<BTreeSet<i64>> {
        let taking = self.channel_severities(channels).await?;
        Ok(taking
            .into_iter()
            .filter(|(_, severities)| severities.contains(&severity))
            .map(|(channel, _)| channel)
            .collect())
    }

    /// Which of these are channels that haven't been deleted.
    pub async fn live_channel_ids(&self, channels: &[i64]) -> Result<BTreeSet<i64>> {
        let wanted: BTreeSet<i64> = channels.iter().copied().collect();
        if wanted.is_empty() {
            return Ok(BTreeSet::new());
        }
        let live: Vec<i64> = notification_channel::Entity::find()
            .select_only()
            .column(notification_channel::Column::Id)
            .filter(notification_channel::Column::Id.is_in(wanted))
            .filter(notification_channel::Column::DeletedAt.is_null())
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading channels")?;
        Ok(live.into_iter().collect())
    }

    /// Which alerts each of these channels takes. One that's gone isn't there.
    async fn channel_severities(
        &self,
        channels: &[i64],
    ) -> Result<BTreeMap<i64, BTreeSet<Severity>>> {
        let wanted: BTreeSet<i64> = channels.iter().copied().collect();
        if wanted.is_empty() {
            return Ok(BTreeMap::new());
        }
        let rows = notification_channel::Entity::find()
            .filter(notification_channel::Column::Id.is_in(wanted))
            .filter(notification_channel::Column::DeletedAt.is_null())
            .all(&self.connection)
            .await
            .context("loading channels")?;
        rows.into_iter()
            .map(|row| Ok((row.id, to_channel(row)?.channel.severities)))
            .collect()
    }

    /// Rewords an open alert, without telling anyone, for a detail that changed
    /// while the problem carried on.
    pub async fn reword_alert(&self, id: i64, summary: &str) -> Result<()> {
        alert::Entity::update_many()
            .col_expr(alert::Column::Summary, Expr::value(summary))
            .filter(alert::Column::Id.eq(id))
            .filter(alert::Column::ResolvedAt.is_null())
            .exec(&self.connection)
            .await
            .context("rewording alert")?;
        Ok(())
    }

    /// Ends an alert and tells whoever was told it started, even if the rule
    /// has since changed or gone. Anyone a silence kept it from never hears of it.
    /// `summary` says where things stand now, when the problem cleared.
    pub async fn resolve_alert(
        &self,
        id: i64,
        now: Timestamp,
        reason: &str,
        summary: Option<&str>,
    ) -> Result<()> {
        let transaction = self.connection.begin().await.context("resolving alert")?;
        resolve_in(&transaction, id, now, reason, summary).await?;
        transaction.commit().await.context("resolving alert")?;
        Ok(())
    }

    /// What can be sent now. Each channel hears about an alert in order: a
    /// resolved notification waits while its firing one is being retried, or a
    /// receiver would see the alert start after it ended, and never close it.
    pub async fn due_deliveries(&self, now: Timestamp, limit: usize) -> Result<Vec<Delivery>> {
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
            .filter(notification::Column::NextAttemptAt.lte(now))
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
        let rows = alert::Entity::find()
            .filter(alert::Column::Id.is_in(alert_ids))
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        // Nor is an alert that can't be read.
        let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
        let alerts: BTreeMap<i64, Result<Alert>> = ids
            .into_iter()
            .zip(each_alert(&self.connection, rows).await?)
            .collect();
        // A channel that can't be read is only a problem for what's going to it.
        let channel_ids: BTreeSet<i64> = due.iter().map(|row| row.channel_id).collect();
        let channels: BTreeMap<i64, Result<Channel>> = notification_channel::Entity::find()
            .filter(notification_channel::Column::Id.is_in(channel_ids))
            .filter(notification_channel::Column::DeletedAt.is_null())
            .all(&self.connection)
            .await
            .context("loading channels")?
            .into_iter()
            .map(|row| (row.id, to_channel(row)))
            .collect();
        // What an action printed goes with the notification about it, and its
        // notifications go with the run.
        let run_ids: BTreeSet<i64> = due.iter().filter_map(|row| row.action_run_id).collect();
        let runs: BTreeMap<i64, Result<ActionRun>> = action_run::Entity::find()
            .filter(action_run::Column::Id.is_in(run_ids))
            .all(&self.connection)
            .await
            .context("loading action runs")?
            .into_iter()
            .map(|row| (row.id, to_run(row)))
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

        let delivery = |row: &notification::Model| -> Result<Delivery> {
            let channel = match channels.get(&row.channel_id) {
                Some(Ok(channel)) => channel.clone(),
                Some(Err(error)) => bail!("its channel can't be read: {error:#}"),
                None => bail!("its channel has been deleted"),
            };
            let action = match row.action_run_id.map(|id| runs.get(&id)) {
                None => None,
                Some(Some(Ok(run))) => Some(run.clone()),
                Some(Some(Err(error))) => bail!("its action run can't be read: {error:#}"),
                Some(None) => bail!("its action run has been deleted"),
            };
            Ok(Delivery {
                reply_to: earlier.get(&(row.alert_id, row.channel_id)).cloned(),
                id: row.id,
                event: Event::parse(&row.event)?,
                attempts: row.attempts,
                created_at: row.created_at,
                alert: match alerts.get(&row.alert_id) {
                    Some(Ok(alert)) => alert.clone(),
                    Some(Err(error)) => bail!("its alert can't be read: {error:#}"),
                    None => bail!("its alert is gone"),
                },
                channel,
                action,
            })
        };
        // One that can't be sent is given up on, so it can't hold up the rest.
        let mut deliveries = Vec::with_capacity(due.len());
        let mut given_up: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        for row in &due {
            match delivery(row) {
                Ok(delivery) => deliveries.push(delivery),
                Err(error) => {
                    let why = format!("{error:#}");
                    warn!(
                        notification = row.id,
                        error = why,
                        "a notification can't be sent"
                    );
                    given_up.entry(why).or_default().push(row.id);
                }
            }
        }
        for (why, ids) in given_up {
            self.give_up_on(ids, &why).await?;
        }
        Ok(deliveries)
    }

    /// Stops trying to send notifications that can't be, all for the same reason.
    async fn give_up_on(&self, ids: Vec<i64>, why: &str) -> Result<()> {
        notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(FAILED))
            .col_expr(notification::Column::LastError, Expr::value(why))
            .filter(notification::Column::Id.is_in(ids))
            .exec(&self.connection)
            .await
            .context("saving notification")?;
        Ok(())
    }

    /// Says someone is dealing with an alert. The first person to say so stays on it.
    /// Returns false if there's no such alert firing.
    pub async fn get_alert(&self, id: i64) -> Result<Option<Alert>> {
        let row = alert::Entity::find_by_id(id)
            .one(&self.connection)
            .await
            .context("loading alert")?;
        match row {
            Some(row) => Ok(Some(to_one_alert(&self.connection, row).await?)),
            None => Ok(None),
        }
    }

    pub async fn acknowledge_alert(&self, id: i64, by: &str, now: Timestamp) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert")?;
        let firing = alert::Entity::find_by_id(id)
            .filter(alert::Column::ResolvedAt.is_null())
            .one(&transaction)
            .await
            .context("loading alert")?;
        let Some(firing) = firing else {
            return Ok(false);
        };
        let updated = alert::Entity::update_many()
            .col_expr(alert::Column::AcknowledgedBy, Expr::value(by))
            .col_expr(alert::Column::AcknowledgedAt, Expr::value(now))
            .filter(alert::Column::Id.eq(id))
            .filter(alert::Column::AcknowledgedAt.is_null())
            .exec(&transaction)
            .await
            .context("saving alert")?;
        if updated.rows_affected > 0 {
            let subject = alert_subject(&transaction, firing).await?;
            let entry = Record::new(Action::Acknowledged, subject);
            record(&transaction, entry).await?;
        }
        transaction.commit().await.context("saving alert")?;
        Ok(true)
    }

    /// Returns false if there's no such alert firing.
    pub async fn unacknowledge_alert(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving alert")?;
        let firing = alert::Entity::find_by_id(id)
            .filter(alert::Column::ResolvedAt.is_null())
            .one(&transaction)
            .await
            .context("loading alert")?;
        let Some(firing) = firing else {
            return Ok(false);
        };
        alert::Entity::update_many()
            .col_expr(alert::Column::AcknowledgedBy, Expr::value(None::<String>))
            .col_expr(
                alert::Column::AcknowledgedAt,
                Expr::value(None::<Timestamp>),
            )
            .filter(alert::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("saving alert")?;
        if firing.acknowledged_at.is_some() {
            let subject = alert_subject(&transaction, firing).await?;
            let entry = Record::new(Action::Unacknowledged, subject);
            record(&transaction, entry).await?;
        }
        transaction.commit().await.context("saving alert")?;
        Ok(true)
    }

    /// Alerts that nobody has acknowledged, on rules that send reminders, with how often.
    pub async fn alerts_to_remind(&self) -> Result<Vec<(Alert, TimeDelta)>> {
        let rules: BTreeMap<i64, TimeDelta> = alert_rule::Entity::find()
            .filter(alert_rule::Column::RemindEverySecs.is_not_null())
            .filter(alert_rule::Column::DeletedAt.is_null())
            .all(&self.connection)
            .await
            .context("loading alert rules")?
            .into_iter()
            .filter_map(|row| Some((row.id, whole_seconds(row.remind_every_secs?).ok()?)))
            .collect();
        if rules.is_empty() {
            return Ok(Vec::new());
        }

        let rows = alert::Entity::find()
            .filter(alert::Column::RuleId.is_in(rules.keys().copied()))
            .filter(alert::Column::ResolvedAt.is_null())
            .filter(alert::Column::AcknowledgedAt.is_null())
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        let alerts = to_alerts(&self.connection, rows).await?;
        Ok(alerts
            .into_iter()
            .filter_map(|alert| Some((rules.get(&alert.rule_id).copied()?, alert)))
            .map(|(every, alert)| (alert, every))
            .collect())
    }

    /// Queues a reminder for each channel that was told an alert started and hasn't heard
    /// about it for as long as the alert's rule says. Each alert comes with that time.
    /// On-call services are left out, and so is a channel whose kind can't be read, as
    /// it can't be sent to. Only alerts still open that nobody has acknowledged are
    /// reminded of: they're locked first, so one ending or acknowledged meanwhile is
    /// waited for and left out, and one ending after waits, so it's said to have ended
    /// after the reminder.
    pub async fn queue_reminders(&self, alerts: &[(i64, TimeDelta)], now: Timestamp) -> Result<()> {
        if alerts.is_empty() {
            return Ok(());
        }
        let transaction = self
            .connection
            .begin()
            .await
            .context("queueing reminders")?;
        let still: Vec<i64> = alert::Entity::find()
            .select_only()
            .column(alert::Column::Id)
            .filter(alert::Column::Id.is_in(alerts.iter().map(|(id, _)| *id)))
            .filter(alert::Column::ResolvedAt.is_null())
            .filter(alert::Column::AcknowledgedAt.is_null())
            .lock_shared()
            .into_tuple()
            .all(&transaction)
            .await
            .context("loading alerts")?;
        if still.is_empty() {
            return Ok(());
        }
        // A deleted channel hears nothing more.
        let rows: Vec<(i64, i64, Option<Timestamp>, String)> = notification::Entity::find()
            .select_only()
            .column(notification::Column::AlertId)
            .column(notification::Column::ChannelId)
            .column(notification::Column::SentAt)
            .column(notification::Column::State)
            .filter(notification::Column::AlertId.is_in(still))
            .filter(notification::Column::ChannelId.in_subquery(live_channels()))
            .into_tuple()
            .all(&transaction)
            .await
            .context("loading notifications")?;

        let mut last_told: BTreeMap<(i64, i64), Timestamp> = BTreeMap::new();
        let mut waiting = BTreeSet::new();
        for (alert_id, channel_id, sent_at, state) in rows {
            let key = (alert_id, channel_id);
            match sent_at {
                Some(sent) => {
                    let last = last_told.entry(key).or_insert(sent);
                    *last = std::cmp::max(sent, *last);
                }
                None if state != FAILED => {
                    waiting.insert(key);
                }
                None => {}
            }
        }
        if last_told.is_empty() {
            return Ok(());
        }

        let every: BTreeMap<i64, TimeDelta> = alerts.iter().copied().collect();
        let told: BTreeSet<i64> = last_told.keys().map(|(_, channel)| *channel).collect();
        let kinds: Vec<(i64, String)> = notification_channel::Entity::find()
            .select_only()
            .column(notification_channel::Column::Id)
            .column(notification_channel::Column::Kind)
            .filter(notification_channel::Column::Id.is_in(told))
            .into_tuple()
            .all(&transaction)
            .await
            .context("loading channels")?;
        let mut reminded = BTreeSet::new();
        for (id, kind) in kinds {
            match ChannelKind::parse(&kind) {
                Ok(kind) if !kind.is_on_call() => {
                    reminded.insert(id);
                }
                Ok(_) => {}
                Err(error) => warn!(
                    channel = id,
                    error = format!("{error:#}"),
                    "a channel can't be read, so it isn't reminded of alerts"
                ),
            }
        }
        let rows: Vec<_> = last_told
            .into_iter()
            .filter(|(key, _)| !waiting.contains(key) && reminded.contains(&key.1))
            .filter(|((alert, _), told)| {
                every.get(alert).is_some_and(|every| now - *told >= *every)
            })
            .map(|((alert, channel), _)| queued(alert, channel, Event::Reminder, now))
            .collect();
        if !rows.is_empty() {
            notification::Entity::insert_many(rows)
                .exec_without_returning(&transaction)
                .await
                .context("queueing notifications")?;
        }
        transaction.commit().await.context("queueing reminders")?;
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
            .and_where(alert::Column::ResolvedAt.is_null())
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
    /// they shouldn't hear it end. MySQL can't delete from a table by what a query of
    /// the same table finds, so the channels are read first.
    pub async fn drop_held_for(&self, alert_id: i64) -> Result<()> {
        let channels: Vec<i64> = notification::Entity::find()
            .select_only()
            .column(notification::Column::ChannelId)
            .distinct()
            .filter(notification::Column::AlertId.eq(alert_id))
            .filter(notification::Column::State.eq(HELD))
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading notifications")?;
        if channels.is_empty() {
            return Ok(());
        }
        notification::Entity::delete_many()
            .filter(notification::Column::AlertId.eq(alert_id))
            .filter(notification::Column::ChannelId.is_in(channels))
            .filter(notification::Column::State.is_in([PENDING, HELD]))
            .exec(&self.connection)
            .await
            .context("dropping notifications")?;
        Ok(())
    }

    /// The alerts behind what silences are keeping back, with what's kept back for each.
    pub async fn held_deliveries(&self) -> Result<Vec<(Alert, Vec<i64>)>> {
        let rows: Vec<(i64, i64)> = notification::Entity::find()
            .select_only()
            .column(notification::Column::Id)
            .column(notification::Column::AlertId)
            .filter(notification::Column::State.eq(HELD))
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading notifications")?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let mut held: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for (id, alert_id) in rows {
            held.entry(alert_id).or_default().push(id);
        }
        let alerts = alert::Entity::find()
            .filter(alert::Column::Id.is_in(held.keys().copied()))
            .all(&self.connection)
            .await
            .context("loading alerts")?;
        let alerts = to_alerts(&self.connection, alerts).await?;
        Ok(alerts
            .into_iter()
            .map(|alert| {
                let ids = held.remove(&alert.id).unwrap_or_default();
                (alert, ids)
            })
            .collect())
    }

    /// Lets held notifications go. The day they get to arrive starts now, however long
    /// they waited. One whose channel has since been deleted stays where it is, for
    /// deleting the channel to drop.
    pub async fn release_deliveries(&self, ids: &[i64], now: Timestamp) -> Result<()> {
        notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(PENDING))
            .col_expr(notification::Column::NextAttemptAt, Expr::value(now))
            .col_expr(notification::Column::CreatedAt, Expr::value(now))
            .filter(notification::Column::Id.is_in(ids.iter().copied()))
            .filter(notification::Column::ChannelId.in_subquery(live_channels()))
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
        now: Timestamp,
        external_id: Option<&str>,
    ) -> Result<()> {
        notification::Entity::update_many()
            .col_expr(notification::Column::State, Expr::value(SENT))
            .col_expr(notification::Column::Attempts, Expr::value(attempts))
            .col_expr(notification::Column::SentAt, Expr::value(now))
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

    /// Tries again at `next_attempt_at`, or gives up if there's no such time.
    pub async fn delivery_failed(
        &self,
        id: i64,
        attempts: i32,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> Result<()> {
        let mut update = notification::Entity::update_many()
            .col_expr(notification::Column::Attempts, Expr::value(attempts))
            .col_expr(notification::Column::LastError, Expr::value(error));
        update = match next_attempt_at {
            Some(time) => update.col_expr(notification::Column::NextAttemptAt, Expr::value(time)),
            None => update.col_expr(notification::Column::State, Expr::value(FAILED)),
        };
        update
            .filter(notification::Column::Id.eq(id))
            .exec(&self.connection)
            .await
            .context("saving notification")?;
        Ok(())
    }

    /// How many notifications a channel has, sent or not, for tests.
    #[cfg(test)]
    pub async fn notifications_of(&self, channel_id: i64) -> u64 {
        use sea_orm::PaginatorTrait;
        notification::Entity::find()
            .filter(notification::Column::ChannelId.eq(channel_id))
            .count(&self.connection)
            .await
            .unwrap()
    }

    /// The newest deliveries that haven't worked, whether given up on or not. One that
    /// worked in the end has no error any more, so isn't one. A deleted channel's
    /// problems are nobody's to fix any more.
    pub async fn delivery_problems(&self, limit: u64) -> Result<Vec<DeliveryProblem>> {
        #[derive(FromQueryResult)]
        struct Problem {
            channel: String,
            summary: String,
            event: String,
            state: String,
            attempts: i32,
            error: String,
            created_at: Timestamp,
        }

        let (notifications, channels, alerts) = (
            notification::Entity,
            notification_channel::Entity,
            alert::Entity,
        );
        let query = Query::select()
            .expr_as(
                Expr::col((channels, notification_channel::Column::Name)),
                Alias::new("channel"),
            )
            .expr_as(
                Expr::col((alerts, alert::Column::Summary)),
                Alias::new("summary"),
            )
            .columns([
                (notifications, notification::Column::Event),
                (notifications, notification::Column::State),
                (notifications, notification::Column::Attempts),
            ])
            .expr_as(
                Expr::col((notifications, notification::Column::LastError)),
                Alias::new("error"),
            )
            .column((notifications, notification::Column::CreatedAt))
            .from(notifications)
            .inner_join(
                channels,
                Expr::col((channels, notification_channel::Column::Id))
                    .equals((notifications, notification::Column::ChannelId)),
            )
            .inner_join(
                alerts,
                Expr::col((alerts, alert::Column::Id))
                    .equals((notifications, notification::Column::AlertId)),
            )
            .and_where(Expr::col((notifications, notification::Column::LastError)).is_not_null())
            .and_where(Expr::col((channels, notification_channel::Column::DeletedAt)).is_null())
            .order_by((notifications, notification::Column::Id), Order::Desc)
            .limit(limit)
            .to_owned();
        let backend = self.connection.get_database_backend();
        let rows = Problem::find_by_statement(backend.build(&query))
            .all(&self.connection)
            .await
            .context("loading notifications")?;
        rows.into_iter()
            .map(|row| {
                Ok(DeliveryProblem {
                    channel: row.channel,
                    summary: row.summary,
                    event: Event::parse(&row.event)?,
                    state: row.state,
                    attempts: row.attempts,
                    error: row.error,
                    created_at: row.created_at,
                })
            })
            .collect()
    }
}
