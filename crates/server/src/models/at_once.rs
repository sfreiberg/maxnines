//! What happens when two requests change the same rows at once. Each test holds a
//! transaction open partway through one change, as if it had got that far, and makes
//! the other change meanwhile. That one has to wait for the first, or leave nothing
//! the first would have to undo. Only databases with more than one connection can do
//! two things at once, so these run on PostgreSQL and MySQL: SQLite's one connection
//! does one at a time.

use std::time::{Duration, Instant};

use chrono::TimeDelta;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, Statement,
    TransactionTrait,
};
use tokio::task::JoinHandle;

use super::alerting::{HELD, PENDING, queue_for_live_channels};
use super::{Database, alert, alert_rule, alert_rule_channel, api_key, notification};
use super::{UserChange, host_fact, notification_channel, user};
use crate::alerting::{
    AlertRuleInput, ChannelInput, ChannelKind, Event, NewAlert, RuleKind, Severity, every_severity,
};
use crate::facts::FlatFacts;
use crate::registration::{HostKind, HostRecord, HostState};
use crate::roles::Role;
use crate::times::Timestamp;
use serde_json::json;

fn webhook() -> ChannelInput {
    ChannelInput {
        name: "Ops".to_string(),
        kind: ChannelKind::Webhook,
        target: "https://example.com/hook".to_string(),
        credential: None,
        app_token: None,
        severities: every_severity(),
        mail: None,
        request: None,
    }
}

fn offline_rule(channels: Vec<i64>) -> AlertRuleInput {
    AlertRuleInput {
        name: "Gone".to_string(),
        kind: RuleKind::Offline,
        metric: None,
        series: None,
        comparison: None,
        threshold: None,
        warning_threshold: None,
        hold: TimeDelta::seconds(60),
        severity: Severity::Critical,
        condition: None,
        enabled: true,
        channels,
        all_channels: false,
        calculation: None,
        group_by: None,
        filter: None,
        window: None,
        remind_every: Some(TimeDelta::minutes(5)),
        forecast: None,
        warning_forecast: None,
        actions: Vec::new(),
    }
}

fn new_alert(rule_id: i64, now: Timestamp) -> NewAlert {
    NewAlert {
        rule_id,
        severity: Severity::Critical,
        host_id: "server".to_string(),
        series: None,
        value: None,
        summary: "the server is offline".to_string(),
        started_at: now,
        breached_at: now,
    }
}

/// A database with connections of its own, or `None` for SQLite.
async fn several_connections() -> Option<Database> {
    let database = Database::for_test().await;
    let backend = database.connection().get_database_backend();
    (backend != DatabaseBackend::Sqlite).then_some(database)
}

/// Whether a connection to this database is waiting for another's lock.
async fn someone_waits(database: &Database) -> bool {
    let connection = database.connection();
    let backend = connection.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Postgres => {
            "SELECT COUNT(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND datname = current_database()"
        }
        _ => {
            "SELECT COUNT(*) FROM information_schema.innodb_trx \
             WHERE trx_state = 'LOCK WAIT' AND trx_mysql_thread_id IN \
             (SELECT id FROM information_schema.processlist WHERE db = DATABASE())"
        }
    };
    let row = connection
        .query_one_raw(Statement::from_string(backend, sql))
        .await
        .unwrap()
        .unwrap();
    row.try_get_by_index::<i64>(0).unwrap() > 0
}

/// Until `task` has finished, or is waiting for a lock another connection holds.
/// MySQL only reads its transactions again when they weren't asked for in the last
/// tenth of a second, so this asks less often than that.
async fn until_done_or_waiting<T>(database: &Database, task: &JoinHandle<T>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !task.is_finished() && !someone_waits(database).await {
        assert!(Instant::now() < deadline, "it neither finished nor waited");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Deleting a channel marks it deleted, and then drops what's waiting for it.
async fn mark_channel_deleted(transaction: &impl ConnectionTrait, id: i64, now: Timestamp) {
    notification_channel::Entity::update_many()
        .col_expr(notification_channel::Column::DeletedAt, Expr::value(now))
        .filter(notification_channel::Column::Id.eq(id))
        .exec(transaction)
        .await
        .unwrap();
}

async fn drop_what_waits_for(transaction: &impl ConnectionTrait, channel: i64) {
    notification::Entity::delete_many()
        .filter(notification::Column::ChannelId.eq(channel))
        .filter(notification::Column::State.is_in([PENDING, HELD]))
        .exec(transaction)
        .await
        .unwrap();
    alert_rule_channel::Entity::delete_many()
        .filter(alert_rule_channel::Column::ChannelId.eq(channel))
        .exec(transaction)
        .await
        .unwrap();
}

#[tokio::test]
async fn nothing_is_left_queued_for_a_channel_deleted_while_it_was_queued_for() {
    let Some(database) = several_connections().await else {
        return;
    };
    let now = crate::times::now();
    let channel = database.create_channel(&webhook()).await.unwrap();
    let rule = database
        .create_alert_rule(&offline_rule(Vec::new()))
        .await
        .unwrap();
    let alert = database
        .fire_alert(&new_alert(rule, now), &[])
        .await
        .unwrap()
        .unwrap();

    let deleting = database.connection().begin().await.unwrap();
    mark_channel_deleted(&deleting, channel, now).await;
    let queueing = database.connection().begin().await.unwrap();
    let task = tokio::spawn(async move {
        queue_for_live_channels(&queueing, alert, [channel], Event::Firing, now)
            .await
            .unwrap();
        queueing
    });
    until_done_or_waiting(&database, &task).await;
    drop_what_waits_for(&deleting, channel).await;
    deleting.commit().await.unwrap();
    task.await.unwrap().commit().await.unwrap();

    assert_eq!(database.notifications_of(channel).await, 0);
}

#[tokio::test]
async fn a_rule_saved_while_its_channel_is_deleted_is_left_without_it() {
    let Some(database) = several_connections().await else {
        return;
    };
    let now = crate::times::now();
    let channel = database.create_channel(&webhook()).await.unwrap();

    let deleting = database.connection().begin().await.unwrap();
    mark_channel_deleted(&deleting, channel, now).await;
    let saving = database.clone();
    let task = tokio::spawn(async move {
        saving
            .create_alert_rule(&offline_rule(vec![channel]))
            .await
            .unwrap()
    });
    until_done_or_waiting(&database, &task).await;
    drop_what_waits_for(&deleting, channel).await;
    deleting.commit().await.unwrap();
    let rule = task.await.unwrap();

    let saved = database.get_alert_rule(rule).await.unwrap().unwrap();
    assert!(saved.rule.channels.is_empty(), "{:?}", saved.rule.channels);
}

#[tokio::test]
async fn an_alert_firing_while_its_rule_is_deleted_never_starts() {
    let Some(database) = several_connections().await else {
        return;
    };
    let now = crate::times::now();
    let rule = database
        .create_alert_rule(&offline_rule(Vec::new()))
        .await
        .unwrap();

    // Deleting the rule marks it before it ends its alerts.
    let deleting = database.connection().begin().await.unwrap();
    alert_rule::Entity::update_many()
        .col_expr(alert_rule::Column::DeletedAt, Expr::value(now))
        .filter(alert_rule::Column::Id.eq(rule))
        .exec(&deleting)
        .await
        .unwrap();
    let firing = database.clone();
    let task =
        tokio::spawn(async move { firing.fire_alert(&new_alert(rule, now), &[]).await.unwrap() });
    until_done_or_waiting(&database, &task).await;
    deleting.commit().await.unwrap();

    assert_eq!(task.await.unwrap(), None);
    assert!(database.open_alerts().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_alert_that_ends_while_reminders_are_queued_is_not_reminded_of_after() {
    let Some(database) = several_connections().await else {
        return;
    };
    let channel = database.create_channel(&webhook()).await.unwrap();
    let rule = database
        .create_alert_rule(&offline_rule(vec![channel]))
        .await
        .unwrap();
    let then = crate::times::now() - TimeDelta::hours(1);
    let alert = database
        .fire_alert(&new_alert(rule, then), &[channel])
        .await
        .unwrap()
        .unwrap();
    let firing = database.due_deliveries(then, 10).await.unwrap();
    database
        .delivery_sent(firing[0].id, 1, then, None)
        .await
        .unwrap();

    // Ending it has started, and isn't finished.
    let now = crate::times::now();
    let ending = database.connection().begin().await.unwrap();
    alert::Entity::update_many()
        .col_expr(alert::Column::ResolvedAt, Expr::value(now))
        .filter(alert::Column::Id.eq(alert))
        .exec(&ending)
        .await
        .unwrap();
    let reminding = database.clone();
    let task = tokio::spawn(async move {
        let every = TimeDelta::minutes(5);
        reminding
            .queue_reminders(&[(alert, every)], now)
            .await
            .unwrap();
    });
    until_done_or_waiting(&database, &task).await;
    ending.commit().await.unwrap();
    task.await.unwrap();

    let reminders = notification::Entity::find()
        .filter(notification::Column::Event.eq(Event::Reminder.as_str()))
        .all(database.connection())
        .await
        .unwrap();
    assert!(reminders.is_empty(), "{reminders:?}");
}

async fn admin(database: &Database, email: &str) -> i64 {
    let now = crate::times::now();
    let (user, _) = database
        .create_user(email, "Admin", Role::Admin, now)
        .await
        .unwrap()
        .unwrap();
    user.id
}

#[tokio::test]
async fn two_admins_each_demoting_the_other_leave_one() {
    let Some(database) = several_connections().await else {
        return;
    };
    let ann = admin(&database, "ann@example.com").await;
    let bob = admin(&database, "bob@example.com").await;

    // Bob is being made a viewer, as setting his role would once it had checked.
    let demoting = database.connection().begin().await.unwrap();
    user::Entity::update_many()
        .col_expr(user::Column::Role, Expr::value(Role::Viewer.as_str()))
        .filter(user::Column::Id.eq(bob))
        .exec(&demoting)
        .await
        .unwrap();
    let other = database.clone();
    let task = tokio::spawn(async move { other.set_role(ann, Role::Viewer).await.unwrap() });
    until_done_or_waiting(&database, &task).await;
    demoting.commit().await.unwrap();

    assert_eq!(task.await.unwrap(), UserChange::LastAdmin);
    let ann = database.user(ann).await.unwrap().unwrap();
    assert_eq!(ann.role, Role::Admin);
}

#[tokio::test]
async fn two_admins_each_disabling_the_other_leave_one() {
    let Some(database) = several_connections().await else {
        return;
    };
    let ann = admin(&database, "ann@example.com").await;
    let bob = admin(&database, "bob@example.com").await;
    let now = crate::times::now();

    // Bob is being disabled, as disabling him would once it had checked.
    let disabling = database.connection().begin().await.unwrap();
    user::Entity::update_many()
        .col_expr(user::Column::DisabledAt, Expr::value(now))
        .filter(user::Column::Id.eq(bob))
        .exec(&disabling)
        .await
        .unwrap();
    let other = database.clone();
    let task = tokio::spawn(async move { other.disable_user(ann, now).await.unwrap() });
    until_done_or_waiting(&database, &task).await;
    disabling.commit().await.unwrap();

    assert_eq!(task.await.unwrap(), UserChange::LastAdmin);
    let ann = database.user(ann).await.unwrap().unwrap();
    assert!(ann.disabled_at.is_none());
}

#[tokio::test]
async fn a_user_enabled_while_being_deleted_is_kept() {
    let Some(database) = several_connections().await else {
        return;
    };
    admin(&database, "ann@example.com").await;
    let bob = admin(&database, "bob@example.com").await;
    let now = crate::times::now();
    database.disable_user(bob, now).await.unwrap();

    let enabling = database.connection().begin().await.unwrap();
    user::Entity::update_many()
        .col_expr(user::Column::DisabledAt, Expr::value(None::<Timestamp>))
        .filter(user::Column::Id.eq(bob))
        .exec(&enabling)
        .await
        .unwrap();
    let other = database.clone();
    let task = tokio::spawn(async move { other.delete_user(bob).await.unwrap() });
    until_done_or_waiting(&database, &task).await;
    enabling.commit().await.unwrap();

    assert_eq!(task.await.unwrap(), UserChange::StillEnabled);
    assert!(database.user(bob).await.unwrap().is_some());
}

#[tokio::test]
async fn an_address_taken_while_a_user_is_added_is_refused_as_taken() {
    let Some(database) = several_connections().await else {
        return;
    };
    let now = crate::times::now();
    let adding = database.connection().begin().await.unwrap();
    user::Entity::insert(user::ActiveModel {
        email: sea_orm::Set("ann@example.com".to_string()),
        name: sea_orm::Set("Ann".to_string()),
        role: sea_orm::Set(Role::Admin.as_str().to_string()),
        theme: sea_orm::Set(super::DEFAULT_THEME.to_string()),
        time_zone: sea_orm::Set("UTC".to_string()),
        created_at: sea_orm::Set(now),
        ..Default::default()
    })
    .exec(&adding)
    .await
    .unwrap();
    let other = database.clone();
    let task = tokio::spawn(async move {
        other
            .create_user("ann@example.com", "Ann", Role::Admin, now)
            .await
            .unwrap()
    });
    until_done_or_waiting(&database, &task).await;
    adding.commit().await.unwrap();

    assert!(task.await.unwrap().is_none());
}

#[tokio::test]
async fn a_key_revoked_twice_at_once_keeps_the_first_time() {
    let Some(database) = several_connections().await else {
        return;
    };
    let ann = admin(&database, "ann@example.com").await;
    let then = crate::times::now() - TimeDelta::hours(1);
    let (key, _) = database
        .create_api_key("ci", ann, Role::Admin, None, then)
        .await
        .unwrap();

    let revoking = database.connection().begin().await.unwrap();
    api_key::Entity::update_many()
        .col_expr(api_key::Column::RevokedAt, Expr::value(then))
        .filter(api_key::Column::Id.eq(key.id))
        .exec(&revoking)
        .await
        .unwrap();
    let other = database.clone();
    let task = tokio::spawn(async move { other.revoke_api_key(key.id, crate::times::now()).await });
    until_done_or_waiting(&database, &task).await;
    revoking.commit().await.unwrap();
    assert!(task.await.unwrap().unwrap());

    let keys = database.list_api_keys().await.unwrap();
    assert_eq!(keys[0].revoked_at, Some(then));
}

#[tokio::test]
async fn facts_saved_twice_at_once_keep_one_current_value() {
    let Some(database) = several_connections().await else {
        return;
    };
    let now = crate::times::now();
    let host = HostRecord {
        kind: HostKind::Agent,
        id: "web".to_string(),
        public_key: Some("ab".repeat(32)),
        hostname: "web-1".to_string(),
        state: HostState::Approved,
        decided_by: None,
        first_seen_at: now,
        decided_at: None,
        hello: Default::default(),
    };
    database.save_host(&host).await.unwrap();
    let facts = |value: &str| FlatFacts::from([("os.name".to_string(), json!(value))]);
    database
        .record_facts("web", &facts("a"), now)
        .await
        .unwrap();

    // One connection is saving "b", as recording facts would once it had read them.
    let saving = database.connection().begin().await.unwrap();
    host_fact::Entity::update_many()
        .col_expr(host_fact::Column::ValidTo, Expr::value(now))
        .filter(host_fact::Column::HostId.eq("web"))
        .exec(&saving)
        .await
        .unwrap();
    host_fact::Entity::insert(host_fact::ActiveModel {
        host_id: sea_orm::Set("web".to_string()),
        name: sea_orm::Set("os.name".to_string()),
        value: sea_orm::Set("b".to_string()),
        value_type: sea_orm::Set("string".to_string()),
        valid_from: sea_orm::Set(now),
        valid_to: sea_orm::Set(None),
        ..Default::default()
    })
    .exec(&saving)
    .await
    .unwrap();
    let other = database.clone();
    let task = tokio::spawn(async move { other.record_facts("web", &facts("c"), now).await });
    until_done_or_waiting(&database, &task).await;
    saving.commit().await.unwrap();

    // The second is refused, and tried again with the agent's next facts.
    assert!(task.await.unwrap().is_err());
    let current = database.current_facts("web").await.unwrap();
    assert_eq!(current.len(), 1, "{current:?}");
    assert_eq!(current[0].value, json!("b"));
}
