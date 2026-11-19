//! The main database's tables, made by one migration: what `database/README.md`
//! draws. A change to a table is a new migration after this one, with the README
//! changed to match.

use sea_orm_migration::prelude::*;

pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(CreateTables), Box::new(ConvertMoments)]
    }
}

/// Every moment kept as milliseconds since 1970, the column it becomes, and whether it
/// can be empty. Durations, such as how long an action ran, stay numbers.
const MOMENTS: &[(&str, &str, &str, bool)] = &[
    ("action_runs", "finished_ms", "finished_at", false),
    ("action_runs", "requested_ms", "requested_at", true),
    ("alert_rules", "deleted_ms", "deleted_at", false),
    ("alerts", "acknowledged_ms", "acknowledged_at", false),
    ("alerts", "resolved_ms", "resolved_at", false),
    ("alerts", "started_ms", "started_at", true),
    ("api_keys", "created_ms", "created_at", true),
    ("api_keys", "expires_ms", "expires_at", false),
    ("api_keys", "last_used_ms", "last_used_at", false),
    ("api_keys", "revoked_ms", "revoked_at", false),
    (
        "app_sign_ins",
        "access_expires_ms",
        "access_expires_at",
        true,
    ),
    ("app_sign_ins", "created_ms", "created_at", true),
    ("app_sign_ins", "last_used_ms", "last_used_at", false),
    (
        "app_sign_ins",
        "refresh_expires_ms",
        "refresh_expires_at",
        true,
    ),
    ("app_sign_ins", "revoked_ms", "revoked_at", false),
    ("app_sign_ins", "rotated_ms", "rotated_at", false),
    ("audit_log", "time_ms", "occurred_at", true),
    (
        "config_rules",
        "built_in_changed_ms",
        "built_in_changed_at",
        false,
    ),
    ("dashboards", "created_ms", "created_at", true),
    ("events", "created_ms", "created_at", true),
    ("events", "time_ms", "occurred_at", true),
    ("host_boots", "boot_ms", "booted_at", true),
    ("host_config_status", "reported_ms", "reported_at", true),
    ("host_facts", "valid_from_ms", "valid_from", true),
    ("host_facts", "valid_to_ms", "valid_to", false),
    ("hosts", "decided_ms", "decided_at", false),
    ("hosts", "first_seen_ms", "first_seen_at", true),
    ("notification_channels", "deleted_ms", "deleted_at", false),
    ("notifications", "created_ms", "created_at", true),
    ("notifications", "next_attempt_ms", "next_attempt_at", true),
    ("notifications", "sent_ms", "sent_at", false),
    ("proxies", "created_ms", "created_at", true),
    ("recovery_codes", "used_ms", "used_at", false),
    ("sign_in_challenges", "expires_ms", "expires_at", true),
    ("silences", "ends_ms", "ends_at", true),
    ("silences", "starts_ms", "starts_at", true),
    ("user_sessions", "created_ms", "created_at", true),
    ("user_sessions", "expires_ms", "expires_at", true),
    ("user_sessions", "last_used_ms", "last_used_at", false),
    ("users", "created_ms", "created_at", true),
    ("users", "disabled_ms", "disabled_at", false),
    ("users", "last_sign_in_ms", "last_sign_in_at", false),
    ("users", "setup_expires_ms", "setup_expires_at", false),
];

/// The indexes on those columns, which are made again on the new ones: their name,
/// table, and columns before and after.
const MOMENT_INDEXES: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "idx_alerts_resolved",
        "alerts",
        &["resolved_ms"],
        &["resolved_at"],
    ),
    (
        "idx_alerts_started",
        "alerts",
        &["started_ms"],
        &["started_at"],
    ),
    ("idx_silences_ends", "silences", &["ends_ms"], &["ends_at"]),
    (
        "idx_notifications_due",
        "notifications",
        &["state", "next_attempt_ms"],
        &["state", "next_attempt_at"],
    ),
    ("idx_events_time", "events", &["time_ms"], &["occurred_at"]),
    (
        "idx_host_facts_host",
        "host_facts",
        &["host_id", "valid_to_ms"],
        &["host_id", "valid_to"],
    ),
    (
        "idx_action_runs_host",
        "action_runs",
        &["host_id", "requested_ms"],
        &["host_id", "requested_at"],
    ),
    (
        "idx_action_runs_finished",
        "action_runs",
        &["finished_ms"],
        &["finished_at"],
    ),
];

/// Every moment becomes a timestamp: `timestamptz` on PostgreSQL, `DATETIME(3)` in UTC
/// on MySQL, which has no time zone to shift it by and lasts past 2038 as `TIMESTAMP`
/// doesn't, and ISO 8601 text in UTC on SQLite, which has no type for it, written as
/// the server writes them, so they sort and compare as text as they do as times. The
/// data is converted, not lost, and alerts learn when their problem began, as their
/// start less their rule's wait, or their start if their rule's gone.
struct ConvertMoments;

impl MigrationName for ConvertMoments {
    fn name(&self) -> &str {
        "m20261119_000001_convert_moments"
    }
}

/// `column` as the timestamp text the server writes on SQLite: to the second, then the
/// milliseconds only if there are any, and `+00:00`.
fn sqlite_moment(column: &str) -> String {
    format!(
        "strftime('%Y-%m-%dT%H:%M:%S', {column} / 1000, 'unixepoch') || \
         CASE WHEN {column} % 1000 = 0 THEN '' ELSE printf('.%03d', {column} % 1000) END \
         || '+00:00'"
    )
}

#[async_trait::async_trait]
impl MigrationTrait for ConvertMoments {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();
        add_stand_ins(manager).await?;
        for (name, table, _, _) in MOMENT_INDEXES {
            manager
                .drop_index(
                    Index::drop()
                        .name(*name)
                        .table(Alias::new(*table))
                        .to_owned(),
                )
                .await?;
        }
        // When each alert's problem began, from what's there before it changes.
        let mut moments: Vec<(&str, &str, &str, bool)> = MOMENTS.to_vec();
        db.execute_unprepared(
            "ALTER TABLE alerts ADD COLUMN breached_ms BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        db.execute_unprepared(
            "UPDATE alerts SET breached_ms = started_ms - 1000 * COALESCE(
                (SELECT for_secs FROM alert_rules WHERE alert_rules.id = alerts.rule_id), 0)",
        )
        .await?;
        if backend == sea_orm::DatabaseBackend::Postgres {
            db.execute_unprepared("ALTER TABLE alerts ALTER COLUMN breached_ms DROP DEFAULT")
                .await?;
        }
        moments.push(("alerts", "breached_ms", "breached_at", true));

        for (table, from, to, required) in moments {
            match backend {
                sea_orm::DatabaseBackend::Postgres => {
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" ALTER COLUMN \"{from}\" TYPE timestamptz \
                         USING TIMESTAMPTZ 'epoch' + \"{from}\" * INTERVAL '1 millisecond'"
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" RENAME COLUMN \"{from}\" TO \"{to}\""
                    ))
                    .await?;
                }
                sea_orm::DatabaseBackend::MySql => {
                    db.execute_unprepared(&format!(
                        "ALTER TABLE `{table}` ADD COLUMN `{to}` DATETIME(3) NULL"
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "UPDATE `{table}` SET `{to}` = \
                         TIMESTAMPADD(MICROSECOND, `{from}` * 1000, '1970-01-01 00:00:00')"
                    ))
                    .await?;
                    let required = if required { " NOT NULL" } else { " NULL" };
                    db.execute_unprepared(&format!(
                        "ALTER TABLE `{table}` DROP COLUMN `{from}`, \
                         MODIFY `{to}` DATETIME(3){required}"
                    ))
                    .await?;
                }
                _ => {
                    // SQLite can only add a column that can't be empty with a default,
                    // for the rows already there, which are all filled in next.
                    let required = if required {
                        " NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'"
                    } else {
                        ""
                    };
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" ADD COLUMN \"{to}\" TEXT{required}"
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "UPDATE \"{table}\" SET \"{to}\" = {} WHERE \"{from}\" IS NOT NULL",
                        sqlite_moment(&format!("\"{from}\""))
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" DROP COLUMN \"{from}\""
                    ))
                    .await?;
                }
            }
        }
        for (name, table, _, after) in MOMENT_INDEXES {
            let mut index = Index::create();
            index.name(*name).table(Alias::new(*table));
            for column in *after {
                index.col(Alias::new(*column));
            }
            manager.create_index(index.to_owned()).await?;
        }
        drop_stand_ins(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();
        add_stand_ins(manager).await?;
        for (name, table, _, _) in MOMENT_INDEXES {
            manager
                .drop_index(
                    Index::drop()
                        .name(*name)
                        .table(Alias::new(*table))
                        .to_owned(),
                )
                .await?;
        }
        let mut moments: Vec<(&str, &str, &str, bool)> = MOMENTS.to_vec();
        moments.push(("alerts", "breached_ms", "breached_at", true));
        for (table, from, to, required) in moments {
            match backend {
                sea_orm::DatabaseBackend::Postgres => {
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" ALTER COLUMN \"{to}\" TYPE bigint \
                         USING (EXTRACT(EPOCH FROM \"{to}\") * 1000)::bigint"
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" RENAME COLUMN \"{to}\" TO \"{from}\""
                    ))
                    .await?;
                }
                sea_orm::DatabaseBackend::MySql => {
                    db.execute_unprepared(&format!(
                        "ALTER TABLE `{table}` ADD COLUMN `{from}` BIGINT NULL"
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "UPDATE `{table}` SET `{from}` = \
                         TIMESTAMPDIFF(MICROSECOND, '1970-01-01 00:00:00', `{to}`) DIV 1000"
                    ))
                    .await?;
                    let required = if required { " NOT NULL" } else { " NULL" };
                    db.execute_unprepared(&format!(
                        "ALTER TABLE `{table}` DROP COLUMN `{to}`, MODIFY `{from}` BIGINT{required}"
                    ))
                    .await?;
                }
                _ => {
                    let required = if required { " NOT NULL DEFAULT 0" } else { "" };
                    db.execute_unprepared(&format!(
                        "ALTER TABLE \"{table}\" ADD COLUMN \"{from}\" INTEGER{required}"
                    ))
                    .await?;
                    db.execute_unprepared(&format!(
                        "UPDATE \"{table}\" SET \"{from}\" = \
                         CAST(strftime('%s', \"{to}\") AS INTEGER) * 1000 \
                         + CAST(substr(strftime('%f', \"{to}\"), 4) AS INTEGER) \
                         WHERE \"{to}\" IS NOT NULL"
                    ))
                    .await?;
                    db.execute_unprepared(&format!("ALTER TABLE \"{table}\" DROP COLUMN \"{to}\""))
                        .await?;
                }
            }
        }
        db.execute_unprepared("ALTER TABLE alerts DROP COLUMN breached_ms")
            .await?;
        for (name, table, before, _) in MOMENT_INDEXES {
            let mut index = Index::create();
            index.name(*name).table(Alias::new(*table));
            for column in *before {
                index.col(Alias::new(*column));
            }
            manager.create_index(index.to_owned()).await?;
        }
        drop_stand_ins(manager).await
    }
}

/// MySQL won't drop an index a foreign key needs, and those on a host's facts and its
/// actions lead with the host. While they're made again, a stand-in on the columns
/// ahead of the moment covers for each index that has any.
fn stand_ins() -> impl Iterator<Item = (String, &'static str, &'static [&'static str])> {
    MOMENT_INDEXES
        .iter()
        .filter(|(_, _, before, _)| before.len() > 1)
        .map(|(name, table, before, _)| {
            (
                format!("{name}_meanwhile"),
                *table,
                &before[..before.len() - 1],
            )
        })
}

async fn add_stand_ins(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    if manager.get_database_backend() != sea_orm::DatabaseBackend::MySql {
        return Ok(());
    }
    for (name, table, columns) in stand_ins() {
        let mut index = Index::create();
        index.name(name).table(Alias::new(table));
        for column in columns {
            index.col(Alias::new(*column));
        }
        manager.create_index(index.to_owned()).await?;
    }
    Ok(())
}

async fn drop_stand_ins(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    if manager.get_database_backend() != sea_orm::DatabaseBackend::MySql {
        return Ok(());
    }
    for (name, table, _) in stand_ins() {
        manager
            .drop_index(Index::drop().name(name).table(Alias::new(table)).to_owned())
            .await?;
    }
    Ok(())
}

/// A big integer that counts up from 1, which is what every `id` column is.
fn id(column: impl IntoIden) -> ColumnDef {
    ColumnDef::new(column)
        .big_integer()
        .not_null()
        .auto_increment()
        .primary_key()
        .to_owned()
}

struct CreateTables;

impl MigrationName for CreateTables {
    fn name(&self) -> &str {
        "m20261117_000001_create_tables"
    }
}

/// Every table, in the order their foreign keys need, and what a new server starts
/// with: the server itself and the fleet as hosts, a default config rule, and the
/// built-in alert rules.
#[async_trait::async_trait]
impl MigrationTrait for CreateTables {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // MySQL's text holds 64 KB, which a big config rule's before and after could
        // pass, and a change mustn't fail for want of room to record it.
        let mut changes = ColumnDef::new(AuditLog::Changes);
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => changes.custom(Alias::new("LONGTEXT")),
            _ => changes.text(),
        };
        changes.not_null();

        manager
            .create_table(
                Table::create()
                    .table(Hosts::Table)
                    .col(
                        ColumnDef::new(Hosts::Id)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Hosts::Kind)
                            .string_len(16)
                            .not_null()
                            .default("agent"),
                    )
                    .col(ColumnDef::new(Hosts::PublicKey).string_len(64).not_null())
                    .col(ColumnDef::new(Hosts::Hostname).string_len(255).not_null())
                    .col(ColumnDef::new(Hosts::State).string_len(16).not_null())
                    .col(ColumnDef::new(Hosts::DecidedBy).text())
                    .col(ColumnDef::new(Hosts::FirstSeenMs).big_integer().not_null())
                    .col(ColumnDef::new(Hosts::DecidedMs).big_integer())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(HostFacts::Table)
                    .col(id(HostFacts::Id))
                    .col(ColumnDef::new(HostFacts::HostId).string_len(32).not_null())
                    .col(ColumnDef::new(HostFacts::Name).string_len(255).not_null())
                    .col(ColumnDef::new(HostFacts::Value).string_len(255).not_null())
                    .col(
                        ColumnDef::new(HostFacts::ValueType)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HostFacts::ValidFromMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(HostFacts::ValidToMs).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_host_facts_host_id")
                            .from(HostFacts::Table, HostFacts::HostId)
                            .to(Hosts::Table, Hosts::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_host_facts_host")
                    .table(HostFacts::Table)
                    .col(HostFacts::HostId)
                    .col(HostFacts::ValidToMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_host_facts_name_value")
                    .table(HostFacts::Table)
                    .col(HostFacts::Name)
                    .col(HostFacts::Value)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(HostConfigStatus::Table)
                    .col(
                        ColumnDef::new(HostConfigStatus::HostId)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(HostConfigStatus::Version)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(HostConfigStatus::Error).text())
                    .col(
                        ColumnDef::new(HostConfigStatus::ReportedMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_host_config_status_host_id")
                            .from(HostConfigStatus::Table, HostConfigStatus::HostId)
                            .to(Hosts::Table, Hosts::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(HostBoots::Table)
                    .col(
                        ColumnDef::new(HostBoots::HostId)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(HostBoots::BootMs).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_host_boots_host_id")
                            .from(HostBoots::Table, HostBoots::HostId)
                            .to(Hosts::Table, Hosts::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(MetricsPages::Table)
                    .col(id(MetricsPages::Id))
                    .col(
                        ColumnDef::new(MetricsPages::HostId)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(MetricsPages::Url).string_len(255).not_null())
                    .col(ColumnDef::new(MetricsPages::Names).text().not_null())
                    .col(
                        ColumnDef::new(MetricsPages::IntervalSecs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(MetricsPages::Enabled).boolean().not_null())
                    .col(ColumnDef::new(MetricsPages::Username).string_len(255))
                    .col(ColumnDef::new(MetricsPages::Password).text())
                    .col(ColumnDef::new(MetricsPages::PasswordEnv).string_len(255))
                    .col(ColumnDef::new(MetricsPages::Token).text())
                    .col(ColumnDef::new(MetricsPages::TokenEnv).string_len(255))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_metrics_pages_host_id")
                            .from(MetricsPages::Table, MetricsPages::HostId)
                            .to(Hosts::Table, Hosts::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_metrics_pages_host")
                    .table(MetricsPages::Table)
                    .col(MetricsPages::HostId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(ConfigRules::Table)
                    .col(id(ConfigRules::Id))
                    .col(
                        ColumnDef::new(ConfigRules::Name)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(ConfigRules::Priority).integer().not_null())
                    .col(ColumnDef::new(ConfigRules::ConditionExpr).text())
                    .col(ColumnDef::new(ConfigRules::Enabled).boolean().not_null())
                    .col(ColumnDef::new(ConfigRules::OperatingSystems).string_len(64))
                    .col(ColumnDef::new(ConfigRules::BuiltIn).string_len(32))
                    .col(ColumnDef::new(ConfigRules::BuiltInChangedMs).big_integer())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(ConfigRuleSettings::Table)
                    .col(id(ConfigRuleSettings::Id))
                    .col(
                        ColumnDef::new(ConfigRuleSettings::RuleId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigRuleSettings::Name)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigRuleSettings::Value)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigRuleSettings::ValueType)
                            .string_len(16)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_config_rule_settings_rule_id")
                            .from(ConfigRuleSettings::Table, ConfigRuleSettings::RuleId)
                            .to(ConfigRules::Table, ConfigRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_config_rule_settings_rule_name")
                    .table(ConfigRuleSettings::Table)
                    .col(ConfigRuleSettings::RuleId)
                    .col(ConfigRuleSettings::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .col(id(Users::Id))
                    .col(
                        ColumnDef::new(Users::Email)
                            .string_len(254)
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::Name).string_len(100).not_null())
                    .col(ColumnDef::new(Users::PasswordHash).string_len(255))
                    .col(
                        ColumnDef::new(Users::Role)
                            .string_len(16)
                            .not_null()
                            .default("admin"),
                    )
                    .col(
                        ColumnDef::new(Users::Theme)
                            .string_len(20)
                            .not_null()
                            .default("carbon"),
                    )
                    .col(
                        ColumnDef::new(Users::TimeZone)
                            .string_len(64)
                            .not_null()
                            .default("UTC"),
                    )
                    .col(
                        ColumnDef::new(Users::SetupTokenHash)
                            .string_len(64)
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::SetupExpiresMs).big_integer())
                    .col(ColumnDef::new(Users::TotpSecret).string_len(128))
                    .col(
                        ColumnDef::new(Users::TotpEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::TotpLastStep).big_integer())
                    .col(ColumnDef::new(Users::CreatedMs).big_integer().not_null())
                    .col(ColumnDef::new(Users::LastSignInMs).big_integer())
                    .col(ColumnDef::new(Users::DisabledMs).big_integer())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(UserSessions::Table)
                    .col(id(UserSessions::Id))
                    .col(
                        ColumnDef::new(UserSessions::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserSessions::TokenHash)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(UserSessions::CreatedMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserSessions::ExpiresMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserSessions::LastUsedMs).big_integer())
                    .col(ColumnDef::new(UserSessions::LastAddress).string_len(64))
                    .col(ColumnDef::new(UserSessions::LastForwardedFor).string_len(64))
                    .col(ColumnDef::new(UserSessions::UserAgent).string_len(255))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_sessions_user_id")
                            .from(UserSessions::Table, UserSessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_user_id")
                    .table(UserSessions::Table)
                    .col(UserSessions::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .col(id(ApiKeys::Id))
                    .col(ColumnDef::new(ApiKeys::UserId).big_integer().not_null())
                    .col(ColumnDef::new(ApiKeys::Name).string_len(100).not_null())
                    .col(ColumnDef::new(ApiKeys::Hint).string_len(16).not_null())
                    .col(
                        ColumnDef::new(ApiKeys::TokenHash)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(ApiKeys::Role)
                            .string_len(16)
                            .not_null()
                            .default("admin"),
                    )
                    .col(ColumnDef::new(ApiKeys::CreatedMs).big_integer().not_null())
                    .col(ColumnDef::new(ApiKeys::ExpiresMs).big_integer())
                    .col(ColumnDef::new(ApiKeys::LastUsedMs).big_integer())
                    .col(ColumnDef::new(ApiKeys::RevokedMs).big_integer())
                    .col(ColumnDef::new(ApiKeys::LastAddress).string_len(64))
                    .col(ColumnDef::new(ApiKeys::LastForwardedFor).string_len(64))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_keys_user_id")
                            .from(ApiKeys::Table, ApiKeys::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await?;
        {
            use AppSignIns as T;
            let hash = |column: T| ColumnDef::new(column).string_len(64).not_null().to_owned();
            manager
                .create_table(
                    Table::create()
                        .table(T::Table)
                        .col(id(T::Id))
                        .col(ColumnDef::new(T::UserId).big_integer().not_null())
                        .col(ColumnDef::new(T::ClientId).string_len(64).not_null())
                        .col(ColumnDef::new(T::Device).string_len(100).not_null())
                        .col(ColumnDef::new(T::Role).string_len(16).not_null())
                        .col(hash(T::AccessHash).unique_key().to_owned())
                        .col(ColumnDef::new(T::AccessExpiresMs).big_integer().not_null())
                        .col(hash(T::RefreshHash).unique_key().to_owned())
                        .col(ColumnDef::new(T::PreviousRefreshHash).string_len(64))
                        .col(ColumnDef::new(T::RotatedMs).big_integer())
                        .col(ColumnDef::new(T::RefreshExpiresMs).big_integer().not_null())
                        .col(ColumnDef::new(T::CreatedMs).big_integer().not_null())
                        .col(ColumnDef::new(T::LastUsedMs).big_integer())
                        .col(ColumnDef::new(T::RevokedMs).big_integer())
                        .col(ColumnDef::new(T::LastAddress).string_len(64))
                        .col(ColumnDef::new(T::LastForwardedFor).string_len(64))
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_app_sign_ins_user_id")
                                .from(T::Table, T::UserId)
                                .to(Users::Table, Users::Id),
                        )
                        .to_owned(),
                )
                .await?;
            for (name, column) in [
                ("idx_app_sign_ins_user_id", T::UserId),
                (
                    "idx_app_sign_ins_previous_refresh_hash",
                    T::PreviousRefreshHash,
                ),
            ] {
                manager
                    .create_index(
                        Index::create()
                            .name(name)
                            .table(T::Table)
                            .col(column)
                            .to_owned(),
                    )
                    .await?;
            }
        }
        manager
            .create_table(
                Table::create()
                    .table(RecoveryCodes::Table)
                    .col(id(RecoveryCodes::Id))
                    .col(
                        ColumnDef::new(RecoveryCodes::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RecoveryCodes::CodeHash)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(ColumnDef::new(RecoveryCodes::UsedMs).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_recovery_codes_user_id")
                            .from(RecoveryCodes::Table, RecoveryCodes::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(SignInChallenges::Table)
                    .col(id(SignInChallenges::Id))
                    .col(
                        ColumnDef::new(SignInChallenges::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SignInChallenges::TokenHash)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(SignInChallenges::ExpiresMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sign_in_challenges_user_id")
                            .from(SignInChallenges::Table, SignInChallenges::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(NotificationChannels::Table)
                    .col(id(NotificationChannels::Id))
                    .col(
                        ColumnDef::new(NotificationChannels::Name)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Kind)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Target)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(NotificationChannels::Credential).text())
                    .col(ColumnDef::new(NotificationChannels::AppToken).text())
                    .col(
                        ColumnDef::new(NotificationChannels::SendsWarnings)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::SendsCritical)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(NotificationChannels::MailFrom).string_len(320))
                    .col(ColumnDef::new(NotificationChannels::MailHostname).string_len(255))
                    .col(ColumnDef::new(NotificationChannels::MailPort).integer())
                    .col(ColumnDef::new(NotificationChannels::MailSecurity).string_len(16))
                    .col(ColumnDef::new(NotificationChannels::MailUsername).string_len(255))
                    .col(ColumnDef::new(NotificationChannels::RequestMethod).string_len(8))
                    .col(ColumnDef::new(NotificationChannels::RequestContentType).string_len(255))
                    .col(ColumnDef::new(NotificationChannels::RequestBody).text())
                    .col(ColumnDef::new(NotificationChannels::DeletedMs).big_integer())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AlertRules::Table)
                    .col(id(AlertRules::Id))
                    .col(ColumnDef::new(AlertRules::Name).string_len(255).not_null())
                    .col(ColumnDef::new(AlertRules::Kind).string_len(16).not_null())
                    .col(ColumnDef::new(AlertRules::Metric).string_len(64))
                    .col(ColumnDef::new(AlertRules::Series).string_len(255))
                    .col(ColumnDef::new(AlertRules::Comparison).string_len(16))
                    .col(ColumnDef::new(AlertRules::Threshold).double())
                    .col(ColumnDef::new(AlertRules::WarningThreshold).double())
                    .col(ColumnDef::new(AlertRules::ForSecs).big_integer().not_null())
                    .col(
                        ColumnDef::new(AlertRules::Severity)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AlertRules::ConditionExpr).text())
                    .col(ColumnDef::new(AlertRules::Enabled).boolean().not_null())
                    .col(
                        ColumnDef::new(AlertRules::AllChannels)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(AlertRules::Calculation).string_len(16))
                    .col(ColumnDef::new(AlertRules::GroupBy).string_len(255))
                    .col(ColumnDef::new(AlertRules::Filter).string_len(500))
                    .col(ColumnDef::new(AlertRules::WindowSecs).big_integer())
                    .col(ColumnDef::new(AlertRules::RemindEverySecs).big_integer())
                    .col(ColumnDef::new(AlertRules::ForecastSecs).big_integer())
                    .col(ColumnDef::new(AlertRules::WarningForecastSecs).big_integer())
                    .col(ColumnDef::new(AlertRules::DeletedMs).big_integer())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AlertRuleChannels::Table)
                    .col(
                        ColumnDef::new(AlertRuleChannels::RuleId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRuleChannels::ChannelId)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(AlertRuleChannels::RuleId)
                            .col(AlertRuleChannels::ChannelId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_alert_rule_channels_channel_id")
                            .from(AlertRuleChannels::Table, AlertRuleChannels::ChannelId)
                            .to(NotificationChannels::Table, NotificationChannels::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_alert_rule_channels_rule_id")
                            .from(AlertRuleChannels::Table, AlertRuleChannels::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Alerts::Table)
                    .col(id(Alerts::Id))
                    .col(ColumnDef::new(Alerts::RuleId).big_integer())
                    .col(ColumnDef::new(Alerts::RuleName).string_len(255).not_null())
                    .col(ColumnDef::new(Alerts::Severity).string_len(16).not_null())
                    .col(ColumnDef::new(Alerts::HostId).string_len(32).not_null())
                    .col(ColumnDef::new(Alerts::Hostname).string_len(255).not_null())
                    .col(ColumnDef::new(Alerts::Series).string_len(255).not_null())
                    .col(ColumnDef::new(Alerts::Value).double())
                    .col(ColumnDef::new(Alerts::Summary).text().not_null())
                    .col(ColumnDef::new(Alerts::StartedMs).big_integer().not_null())
                    .col(ColumnDef::new(Alerts::ResolvedMs).big_integer())
                    .col(ColumnDef::new(Alerts::ResolveReason).text())
                    .col(ColumnDef::new(Alerts::ResolvedSummary).text())
                    .col(ColumnDef::new(Alerts::AcknowledgedBy).string_len(255))
                    .col(ColumnDef::new(Alerts::AcknowledgedMs).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_alerts_host_id")
                            .from(Alerts::Table, Alerts::HostId)
                            .to(Hosts::Table, Hosts::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_alerts_rule_id")
                            .from(Alerts::Table, Alerts::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_alerts_resolved")
                    .table(Alerts::Table)
                    .col(Alerts::ResolvedMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_alerts_started")
                    .table(Alerts::Table)
                    .col(Alerts::StartedMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Notifications::Table)
                    .col(id(Notifications::Id))
                    .col(
                        ColumnDef::new(Notifications::AlertId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Notifications::ChannelId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Notifications::Event)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Notifications::State)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Notifications::Attempts).integer().not_null())
                    .col(
                        ColumnDef::new(Notifications::NextAttemptMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Notifications::LastError).text())
                    .col(
                        ColumnDef::new(Notifications::CreatedMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Notifications::SentMs).big_integer())
                    .col(ColumnDef::new(Notifications::ExternalId).string_len(128))
                    .col(ColumnDef::new(Notifications::ActionRunId).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_notifications_alert_id")
                            .from(Notifications::Table, Notifications::AlertId)
                            .to(Alerts::Table, Alerts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_notifications_channel_id")
                            .from(Notifications::Table, Notifications::ChannelId)
                            .to(NotificationChannels::Table, NotificationChannels::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_notifications_alert")
                    .table(Notifications::Table)
                    .col(Notifications::AlertId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_notifications_due")
                    .table(Notifications::Table)
                    .col(Notifications::State)
                    .col(Notifications::NextAttemptMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Silences::Table)
                    .col(id(Silences::Id))
                    .col(ColumnDef::new(Silences::RuleId).big_integer())
                    .col(ColumnDef::new(Silences::Filter).string_len(500).not_null())
                    .col(ColumnDef::new(Silences::Reason).string_len(255).not_null())
                    .col(
                        ColumnDef::new(Silences::CreatedBy)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Silences::StartsMs).big_integer().not_null())
                    .col(ColumnDef::new(Silences::EndsMs).big_integer().not_null())
                    .col(
                        ColumnDef::new(Silences::Series)
                            .string_len(255)
                            .not_null()
                            .default(""),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_silences_rule_id")
                            .from(Silences::Table, Silences::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_silences_ends")
                    .table(Silences::Table)
                    .col(Silences::EndsMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(MaintenanceWindows::Table)
                    .col(id(MaintenanceWindows::Id))
                    .col(
                        ColumnDef::new(MaintenanceWindows::Name)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(MaintenanceWindows::RuleId).big_integer())
                    .col(
                        ColumnDef::new(MaintenanceWindows::Filter)
                            .string_len(500)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::Days)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::StartTime)
                            .string_len(5)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::DurationSecs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::TimeZone)
                            .string_len(64)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_maintenance_windows_rule_id")
                            .from(MaintenanceWindows::Table, MaintenanceWindows::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AlertRuleActions::Table)
                    .col(id(AlertRuleActions::Id))
                    .col(
                        ColumnDef::new(AlertRuleActions::RuleId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRuleActions::Action)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRuleActions::RunOn)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRuleActions::TimeoutSecs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertRuleActions::Position)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_alert_rule_actions_rule_id")
                            .from(AlertRuleActions::Table, AlertRuleActions::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_alert_rule_actions_rule")
                    .table(AlertRuleActions::Table)
                    .col(AlertRuleActions::RuleId)
                    .to_owned(),
            )
            .await?;

        // As with the audit log, MySQL's text is too small for what this holds.
        let mut output = ColumnDef::new(ActionRuns::Output);
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => output.custom(Alias::new("LONGTEXT")),
            _ => output.text(),
        };
        output.not_null();
        manager
            .create_table(
                Table::create()
                    .table(ActionRuns::Table)
                    .col(id(ActionRuns::Id))
                    .col(ColumnDef::new(ActionRuns::HostId).string_len(32).not_null())
                    .col(ColumnDef::new(ActionRuns::AlertId).big_integer())
                    .col(ColumnDef::new(ActionRuns::Action).string_len(64).not_null())
                    .col(ColumnDef::new(ActionRuns::RunOn).string_len(16).not_null())
                    .col(ColumnDef::new(ActionRuns::Variables).text().not_null())
                    .col(ColumnDef::new(ActionRuns::RequestedBy).string_len(255))
                    .col(
                        ColumnDef::new(ActionRuns::RequestedMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ActionRuns::TimeoutSecs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ActionRuns::Outcome).string_len(16))
                    .col(ColumnDef::new(ActionRuns::ExitCode).integer())
                    .col(ColumnDef::new(ActionRuns::Error).text())
                    .col(output)
                    .col(ColumnDef::new(ActionRuns::Truncated).boolean().not_null())
                    .col(ColumnDef::new(ActionRuns::DurationMs).big_integer())
                    .col(ColumnDef::new(ActionRuns::FinishedMs).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_action_runs_host_id")
                            .from(ActionRuns::Table, ActionRuns::HostId)
                            .to(Hosts::Table, Hosts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_action_runs_alert_id")
                            .from(ActionRuns::Table, ActionRuns::AlertId)
                            .to(Alerts::Table, Alerts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_action_runs_alert")
                    .table(ActionRuns::Table)
                    .col(ActionRuns::AlertId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_action_runs_host")
                    .table(ActionRuns::Table)
                    .col(ActionRuns::HostId)
                    .col(ActionRuns::RequestedMs)
                    .to_owned(),
            )
            .await?;
        // What's still waiting for an answer, which is looked for on every pass.
        manager
            .create_index(
                Index::create()
                    .name("idx_action_runs_finished")
                    .table(ActionRuns::Table)
                    .col(ActionRuns::FinishedMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(RemoteChecks::Table)
                    .col(id(RemoteChecks::Id))
                    .col(ColumnDef::new(RemoteChecks::Name).string_len(64).not_null())
                    .col(ColumnDef::new(RemoteChecks::Kind).string_len(16).not_null())
                    .col(
                        ColumnDef::new(RemoteChecks::Target)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(RemoteChecks::TimeoutSecs).big_integer())
                    .col(ColumnDef::new(RemoteChecks::Method).string_len(16))
                    .col(ColumnDef::new(RemoteChecks::Body).text())
                    .col(ColumnDef::new(RemoteChecks::Regex).text())
                    .col(ColumnDef::new(RemoteChecks::Insecure).boolean())
                    .col(ColumnDef::new(RemoteChecks::Server).string_len(255))
                    .col(ColumnDef::new(RemoteChecks::Record).string_len(16))
                    .col(ColumnDef::new(RemoteChecks::Count).integer())
                    .col(
                        ColumnDef::new(RemoteChecks::IntervalSecs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RemoteChecks::Enabled).boolean().not_null())
                    .col(
                        ColumnDef::new(RemoteChecks::HostId)
                            .string_len(32)
                            .not_null()
                            .default("server"),
                    )
                    .col(ColumnDef::new(RemoteChecks::Database).string_len(63))
                    .col(ColumnDef::new(RemoteChecks::Tls).boolean())
                    .col(ColumnDef::new(RemoteChecks::HostKey).string_len(100))
                    .col(ColumnDef::new(RemoteChecks::Username).string_len(255))
                    .col(ColumnDef::new(RemoteChecks::Password).text())
                    .col(ColumnDef::new(RemoteChecks::PasswordEnv).string_len(255))
                    .col(ColumnDef::new(RemoteChecks::PrivateKey).text())
                    .col(ColumnDef::new(RemoteChecks::PrivateKeyEnv).string_len(255))
                    .col(ColumnDef::new(RemoteChecks::DomainExpiry).boolean())
                    .col(
                        ColumnDef::new(RemoteChecks::ReadStats)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(RemoteChecks::Extras).string_len(255))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_remote_checks_host_id")
                            .from(RemoteChecks::Table, RemoteChecks::HostId)
                            .to(Hosts::Table, Hosts::Id),
                    )
                    .to_owned(),
            )
            .await?;
        // A check's name only has to differ from the others about the same host.
        manager
            .create_index(
                Index::create()
                    .name("idx_remote_checks_host_name")
                    .table(RemoteChecks::Table)
                    .col(RemoteChecks::HostId)
                    .col(RemoteChecks::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Dashboards::Table)
                    .col(id(Dashboards::Id))
                    .col(ColumnDef::new(Dashboards::Name).string_len(100).not_null())
                    .col(
                        ColumnDef::new(Dashboards::CreatedMs)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DashboardWidgets::Table)
                    .col(id(DashboardWidgets::Id))
                    .col(
                        ColumnDef::new(DashboardWidgets::DashboardId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardWidgets::Title)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardWidgets::Kind)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardWidgets::Metric)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardWidgets::Calculation)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardWidgets::GroupBy)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardWidgets::Filter)
                            .string_len(500)
                            .not_null(),
                    )
                    .col(ColumnDef::new(DashboardWidgets::X).integer().not_null())
                    .col(ColumnDef::new(DashboardWidgets::Y).integer().not_null())
                    .col(ColumnDef::new(DashboardWidgets::W).integer().not_null())
                    .col(ColumnDef::new(DashboardWidgets::H).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_dashboard_widgets_dashboard_id")
                            .from(DashboardWidgets::Table, DashboardWidgets::DashboardId)
                            .to(Dashboards::Table, Dashboards::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_dashboard_widgets_dashboard")
                    .table(DashboardWidgets::Table)
                    .col(DashboardWidgets::DashboardId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DashboardVariables::Table)
                    .col(id(DashboardVariables::Id))
                    .col(
                        ColumnDef::new(DashboardVariables::DashboardId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardVariables::Position)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardVariables::Name)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardVariables::Label)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardVariables::Kind)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardVariables::Fact)
                            .string_len(200)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DashboardVariables::Filter)
                            .string_len(500)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_dashboard_variables_dashboard_id")
                            .from(DashboardVariables::Table, DashboardVariables::DashboardId)
                            .to(Dashboards::Table, Dashboards::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_dashboard_variables_dashboard")
                    .table(DashboardVariables::Table)
                    .col(DashboardVariables::DashboardId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(LocationRules::Table)
                    .col(id(LocationRules::Id))
                    .col(
                        ColumnDef::new(LocationRules::Name)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(LocationRules::Filter)
                            .string_len(500)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(LocationRules::Place)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(LocationRules::Latitude).double().not_null())
                    .col(ColumnDef::new(LocationRules::Longitude).double().not_null())
                    .col(ColumnDef::new(LocationRules::Priority).integer().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Events::Table)
                    .col(id(Events::Id))
                    .col(ColumnDef::new(Events::TimeMs).big_integer().not_null())
                    .col(ColumnDef::new(Events::Kind).string_len(16).not_null())
                    .col(ColumnDef::new(Events::Title).string_len(200).not_null())
                    .col(ColumnDef::new(Events::Detail).text())
                    .col(ColumnDef::new(Events::Filter).string_len(500).not_null())
                    .col(ColumnDef::new(Events::CreatedBy).string_len(255).not_null())
                    .col(ColumnDef::new(Events::CreatedMs).big_integer().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_time")
                    .table(Events::Table)
                    .col(Events::TimeMs)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AuditLog::Table)
                    .col(id(AuditLog::Id))
                    .col(ColumnDef::new(AuditLog::TimeMs).big_integer().not_null())
                    .col(
                        ColumnDef::new(AuditLog::ActorKind)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditLog::ActorId).string_len(64))
                    .col(
                        ColumnDef::new(AuditLog::ActorName)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditLog::ViaKind).string_len(16))
                    .col(ColumnDef::new(AuditLog::ViaId).string_len(64))
                    .col(ColumnDef::new(AuditLog::ViaName).string_len(255))
                    .col(ColumnDef::new(AuditLog::Source).string_len(45))
                    .col(ColumnDef::new(AuditLog::ForwardedFor).string_len(64))
                    .col(ColumnDef::new(AuditLog::Action).string_len(32).not_null())
                    .col(
                        ColumnDef::new(AuditLog::SubjectKind)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditLog::SubjectId).string_len(128))
                    .col(
                        ColumnDef::new(AuditLog::SubjectName)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(changes)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(ServerSettings::Table)
                    .col(
                        ColumnDef::new(ServerSettings::Name)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ServerSettings::Value)
                            .string_len(255)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(ServerSecrets::Table)
                    .col(
                        ColumnDef::new(ServerSecrets::Name)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ServerSecrets::Value).text().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Proxies::Table)
                    .col(id(Proxies::Id))
                    .col(
                        ColumnDef::new(Proxies::Address)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Proxies::Trusted).boolean().not_null())
                    .col(ColumnDef::new(Proxies::CreatedMs).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        add_built_ins(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "proxies",
            "server_secrets",
            "server_settings",
            "audit_log",
            "events",
            "location_rules",
            "dashboard_variables",
            "dashboard_widgets",
            "dashboards",
            "remote_checks",
            "action_runs",
            "alert_rule_actions",
            "maintenance_windows",
            "silences",
            "notifications",
            "alerts",
            "alert_rule_channels",
            "alert_rules",
            "notification_channels",
            "sign_in_challenges",
            "recovery_codes",
            "app_sign_ins",
            "api_keys",
            "user_sessions",
            "users",
            "config_rule_settings",
            "config_rules",
            "metrics_pages",
            "host_boots",
            "host_config_status",
            "host_facts",
            "hosts",
        ] {
            manager
                .drop_table(Table::drop().table(Alias::new(table)).to_owned())
                .await?;
        }
        Ok(())
    }
}

/// The two hosts that aren't machines: the server records its own checks and
/// numbers under one, and alerts about many hosts at once under the other.
const BUILT_IN_HOSTS: [(&str, &str); 2] = [("server", "MaxNines server"), ("fleet", "Fleet")];

/// What every agent collects unless a config rule says otherwise.
const DEFAULT_SETTINGS: [(&str, &str, &str); 8] = [
    ("interval_secs", "15", "number"),
    ("facts_interval_secs", "3600", "number"),
    ("collectors.host.enabled", "true", "boolean"),
    ("collectors.cpu.enabled", "true", "boolean"),
    ("collectors.memory.enabled", "true", "boolean"),
    ("collectors.disk.enabled", "true", "boolean"),
    ("collectors.network.enabled", "true", "boolean"),
    ("collectors.system.enabled", "true", "boolean"),
];

/// One built-in alert rule. Each tells every channel, and is critical, with a warning
/// first where it has a warning threshold or a longer forecast.
struct BuiltInRule {
    name: &'static str,
    kind: &'static str,
    metric: Option<&'static str>,
    comparison: Option<&'static str>,
    threshold: Option<f64>,
    warning_threshold: Option<f64>,
    for_secs: i64,
    window_secs: Option<i64>,
    forecast_secs: Option<i64>,
    warning_forecast_secs: Option<i64>,
}

const BUILT_IN_RULES: [BuiltInRule; 7] = [
    BuiltInRule {
        name: "Host offline",
        kind: "offline",
        metric: None,
        comparison: None,
        threshold: None,
        warning_threshold: None,
        for_secs: 60,
        window_secs: None,
        forecast_secs: None,
        warning_forecast_secs: None,
    },
    BuiltInRule {
        name: "Disk filling up",
        kind: "metric",
        metric: Some("disk.usage"),
        comparison: Some("above"),
        threshold: Some(90.0),
        warning_threshold: Some(80.0),
        for_secs: 300,
        window_secs: None,
        forecast_secs: None,
        warning_forecast_secs: None,
    },
    BuiltInRule {
        name: "Container down",
        kind: "metric",
        metric: Some("container.up"),
        comparison: Some("below"),
        threshold: Some(1.0),
        warning_threshold: None,
        for_secs: 60,
        window_secs: None,
        forecast_secs: None,
        warning_forecast_secs: None,
    },
    BuiltInRule {
        name: "Disk will be full soon",
        kind: "forecast",
        metric: Some("disk.usage"),
        comparison: Some("above"),
        threshold: Some(100.0),
        warning_threshold: None,
        for_secs: 1800,
        window_secs: Some(21_600),
        forecast_secs: Some(14_400),
        warning_forecast_secs: Some(86_400),
    },
    BuiltInRule {
        name: "Disk running out of inodes",
        kind: "metric",
        metric: Some("disk.inodes"),
        comparison: Some("above"),
        threshold: Some(90.0),
        warning_threshold: Some(80.0),
        for_secs: 300,
        window_secs: None,
        forecast_secs: None,
        warning_forecast_secs: None,
    },
    BuiltInRule {
        name: "Clock is wrong",
        kind: "metric",
        metric: Some("clock.difference"),
        comparison: Some("above"),
        threshold: Some(30.0),
        warning_threshold: Some(5.0),
        for_secs: 60,
        window_secs: None,
        forecast_secs: None,
        warning_forecast_secs: None,
    },
    BuiltInRule {
        name: "Service stopped",
        kind: "metric",
        metric: Some("service.running"),
        comparison: Some("below"),
        threshold: Some(1.0),
        warning_threshold: None,
        // Long enough for a restart, and no longer: a service that's down is down.
        for_secs: 60,
        window_secs: None,
        forecast_secs: None,
        warning_forecast_secs: None,
    },
];

async fn add_built_ins(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let mut hosts = Query::insert()
        .into_table(Hosts::Table)
        .columns([
            Hosts::Id,
            Hosts::Kind,
            Hosts::PublicKey,
            Hosts::Hostname,
            Hosts::State,
            Hosts::DecidedBy,
            Hosts::FirstSeenMs,
        ])
        .to_owned();
    for (id, hostname) in BUILT_IN_HOSTS {
        hosts.values_panic([
            id.into(),
            "built_in".into(),
            "".into(),
            hostname.into(),
            "approved".into(),
            "built-in".into(),
            0i64.into(),
        ]);
    }
    manager.exec_stmt(hosts).await?;

    let rule = Query::insert()
        .into_table(ConfigRules::Table)
        .columns([
            ConfigRules::Name,
            ConfigRules::Priority,
            ConfigRules::Enabled,
        ])
        .values_panic(["Default".into(), 0.into(), true.into()])
        .to_owned();
    manager.exec_stmt(rule).await?;
    for (name, value, value_type) in DEFAULT_SETTINGS {
        let setting = Query::insert()
            .into_table(ConfigRuleSettings::Table)
            .columns([
                ConfigRuleSettings::RuleId,
                ConfigRuleSettings::Name,
                ConfigRuleSettings::Value,
                ConfigRuleSettings::ValueType,
            ])
            .select_from(
                Query::select()
                    .column(ConfigRules::Id)
                    .expr(Expr::val(name))
                    .expr(Expr::val(value))
                    .expr(Expr::val(value_type))
                    .from(ConfigRules::Table)
                    .and_where(Expr::col(ConfigRules::Name).eq("Default"))
                    .to_owned(),
            )
            .map_err(|error| DbErr::Migration(error.to_string()))?
            .to_owned();
        manager.exec_stmt(setting).await?;
    }

    for rule in &BUILT_IN_RULES {
        add_built_in_rule(manager, rule).await?;
    }
    Ok(())
}

async fn add_built_in_rule(manager: &SchemaManager<'_>, rule: &BuiltInRule) -> Result<(), DbErr> {
    {
        let insert = Query::insert()
            .into_table(AlertRules::Table)
            .columns([
                AlertRules::Name,
                AlertRules::Kind,
                AlertRules::Metric,
                AlertRules::Comparison,
                AlertRules::Threshold,
                AlertRules::WarningThreshold,
                AlertRules::ForSecs,
                AlertRules::Severity,
                AlertRules::Enabled,
                AlertRules::AllChannels,
                AlertRules::WindowSecs,
                AlertRules::ForecastSecs,
                AlertRules::WarningForecastSecs,
            ])
            .values_panic([
                rule.name.into(),
                rule.kind.into(),
                rule.metric.into(),
                rule.comparison.into(),
                rule.threshold.into(),
                rule.warning_threshold.into(),
                rule.for_secs.into(),
                "critical".into(),
                true.into(),
                true.into(),
                rule.window_secs.into(),
                rule.forecast_secs.into(),
                rule.warning_forecast_secs.into(),
            ])
            .to_owned();
        manager.exec_stmt(insert).await
    }
}

#[derive(Iden)]
enum Hosts {
    Table,
    Id,
    Kind,
    PublicKey,
    Hostname,
    State,
    DecidedBy,
    FirstSeenMs,
    DecidedMs,
}

#[derive(Iden)]
enum HostFacts {
    Table,
    Id,
    HostId,
    Name,
    Value,
    ValueType,
    ValidFromMs,
    ValidToMs,
}

#[derive(Iden)]
enum HostConfigStatus {
    Table,
    HostId,
    Version,
    Error,
    ReportedMs,
}

#[derive(Iden)]
enum HostBoots {
    Table,
    HostId,
    BootMs,
}

#[derive(Iden)]
enum ConfigRules {
    Table,
    Id,
    Name,
    Priority,
    ConditionExpr,
    Enabled,
    OperatingSystems,
    BuiltIn,
    BuiltInChangedMs,
}

#[derive(Iden)]
enum ConfigRuleSettings {
    Table,
    Id,
    RuleId,
    Name,
    Value,
    ValueType,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
    Email,
    Name,
    PasswordHash,
    Role,
    Theme,
    TimeZone,
    SetupTokenHash,
    SetupExpiresMs,
    TotpSecret,
    TotpEnabled,
    TotpLastStep,
    CreatedMs,
    LastSignInMs,
    DisabledMs,
}

#[derive(Iden)]
enum UserSessions {
    Table,
    Id,
    UserId,
    TokenHash,
    CreatedMs,
    ExpiresMs,
    LastUsedMs,
    LastAddress,
    UserAgent,
    LastForwardedFor,
}

#[derive(Iden)]
enum ApiKeys {
    Table,
    LastAddress,
    LastForwardedFor,
    Id,
    UserId,
    Name,
    Hint,
    TokenHash,
    Role,
    CreatedMs,
    ExpiresMs,
    LastUsedMs,
    RevokedMs,
}

#[derive(Iden)]
enum RecoveryCodes {
    Table,
    Id,
    UserId,
    CodeHash,
    UsedMs,
}

#[derive(Iden)]
enum SignInChallenges {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresMs,
}

#[derive(Iden)]
enum NotificationChannels {
    Table,
    Id,
    Name,
    Kind,
    Target,
    Credential,
    AppToken,
    SendsWarnings,
    SendsCritical,
    MailFrom,
    MailHostname,
    MailPort,
    MailSecurity,
    MailUsername,
    RequestMethod,
    RequestContentType,
    RequestBody,
    DeletedMs,
}

#[derive(Iden)]
enum AlertRules {
    Table,
    Id,
    Name,
    Kind,
    Metric,
    Series,
    Comparison,
    Threshold,
    WarningThreshold,
    ForSecs,
    Severity,
    ConditionExpr,
    Enabled,
    AllChannels,
    Calculation,
    GroupBy,
    Filter,
    WindowSecs,
    RemindEverySecs,
    ForecastSecs,
    WarningForecastSecs,
    DeletedMs,
}

#[derive(Iden)]
enum AlertRuleChannels {
    Table,
    RuleId,
    ChannelId,
}

#[derive(Iden)]
enum Alerts {
    Table,
    Id,
    RuleId,
    RuleName,
    Severity,
    HostId,
    Hostname,
    Series,
    Value,
    Summary,
    StartedMs,
    ResolvedMs,
    ResolveReason,
    ResolvedSummary,
    AcknowledgedBy,
    AcknowledgedMs,
}

#[derive(Iden)]
enum Notifications {
    Table,
    Id,
    AlertId,
    ChannelId,
    Event,
    State,
    Attempts,
    NextAttemptMs,
    LastError,
    CreatedMs,
    SentMs,
    ExternalId,
    ActionRunId,
}

#[derive(Iden)]
enum Silences {
    Table,
    Id,
    RuleId,
    Filter,
    Series,
    Reason,
    CreatedBy,
    StartsMs,
    EndsMs,
}

#[derive(Iden)]
enum MaintenanceWindows {
    Table,
    Id,
    Name,
    RuleId,
    Filter,
    Days,
    StartTime,
    DurationSecs,
    TimeZone,
}

#[derive(Iden)]
enum RemoteChecks {
    Table,
    Id,
    HostId,
    Name,
    Kind,
    Target,
    TimeoutSecs,
    Method,
    Body,
    Regex,
    Insecure,
    Server,
    Record,
    Count,
    IntervalSecs,
    Enabled,
    Database,
    Tls,
    HostKey,
    Username,
    Password,
    PasswordEnv,
    PrivateKey,
    PrivateKeyEnv,
    DomainExpiry,
    ReadStats,
    Extras,
}

#[derive(Iden)]
enum Dashboards {
    Table,
    Id,
    Name,
    CreatedMs,
}

#[derive(Iden)]
enum DashboardWidgets {
    Table,
    Id,
    DashboardId,
    Title,
    Kind,
    Metric,
    Calculation,
    GroupBy,
    Filter,
    X,
    Y,
    W,
    H,
}

#[derive(Iden)]
enum DashboardVariables {
    Table,
    Id,
    DashboardId,
    Position,
    Name,
    Label,
    Kind,
    Fact,
    Filter,
}

#[derive(Iden)]
enum LocationRules {
    Table,
    Id,
    Name,
    Filter,
    Place,
    Latitude,
    Longitude,
    Priority,
}

#[derive(Iden)]
enum Events {
    Table,
    Id,
    TimeMs,
    Kind,
    Title,
    Detail,
    Filter,
    CreatedBy,
    CreatedMs,
}

#[derive(Iden)]
enum AuditLog {
    Table,
    Id,
    TimeMs,
    ActorKind,
    ActorId,
    ActorName,
    ViaKind,
    ViaId,
    ViaName,
    Source,
    ForwardedFor,
    Action,
    SubjectKind,
    SubjectId,
    SubjectName,
    Changes,
}

#[derive(Iden)]
enum ServerSettings {
    Table,
    Name,
    Value,
}

#[derive(Iden)]
enum ServerSecrets {
    Table,
    Name,
    Value,
}

#[derive(Iden)]
enum AppSignIns {
    Table,
    Id,
    UserId,
    ClientId,
    Device,
    Role,
    AccessHash,
    AccessExpiresMs,
    RefreshHash,
    PreviousRefreshHash,
    RotatedMs,
    RefreshExpiresMs,
    CreatedMs,
    LastUsedMs,
    RevokedMs,
    LastAddress,
    LastForwardedFor,
}

#[derive(Iden)]
enum Proxies {
    Table,
    Id,
    Address,
    Trusted,
    CreatedMs,
}

#[derive(DeriveIden)]
enum MetricsPages {
    Table,
    Id,
    HostId,
    Url,
    Names,
    IntervalSecs,
    Enabled,
    Username,
    Password,
    PasswordEnv,
    Token,
    TokenEnv,
}

#[derive(DeriveIden)]
enum AlertRuleActions {
    Table,
    Id,
    RuleId,
    Action,
    RunOn,
    TimeoutSecs,
    Position,
}

#[derive(DeriveIden)]
enum ActionRuns {
    Table,
    Id,
    HostId,
    AlertId,
    Action,
    RunOn,
    Variables,
    RequestedBy,
    RequestedMs,
    TimeoutSecs,
    Outcome,
    ExitCode,
    Error,
    Output,
    Truncated,
    DurationMs,
    FinishedMs,
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, Statement};

    use super::*;

    async fn fresh() -> sea_orm::DatabaseConnection {
        let options = ConnectOptions::new("sqlite::memory:")
            .max_connections(1)
            .to_owned();
        Database::connect(options).await.unwrap()
    }

    async fn texts(connection: &impl ConnectionTrait, sql: &str) -> Vec<String> {
        let query = Statement::from_string(connection.get_database_backend(), sql);
        let rows = connection.query_all_raw(query).await.unwrap();
        rows.iter()
            .map(|row| row.try_get_by_index(0).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn a_new_database_starts_with_the_built_ins() {
        let connection = fresh().await;
        Migrator::up(&connection, None).await.unwrap();

        let hosts = texts(&connection, "SELECT hostname FROM hosts ORDER BY id").await;
        assert_eq!(hosts, ["Fleet", "MaxNines server"]);
        let rules = texts(&connection, "SELECT name FROM alert_rules ORDER BY id").await;
        assert_eq!(
            rules,
            [
                "Host offline",
                "Disk filling up",
                "Container down",
                "Disk will be full soon",
                "Disk running out of inodes",
                "Clock is wrong",
                "Service stopped",
            ]
        );
        let settings = "SELECT s.name FROM config_rule_settings s
                        JOIN config_rules r ON r.id = s.rule_id
                        WHERE r.name = 'Default' ORDER BY s.id";
        let names = texts(&connection, settings).await;
        assert_eq!(names.len(), DEFAULT_SETTINGS.len());
        assert_eq!(names[0], "interval_secs");
    }

    #[tokio::test]
    async fn alerts_from_before_learn_when_their_problem_began() {
        let connection = fresh().await;
        Migrator::up(&connection, Some(1)).await.unwrap();
        // Host offline waits a minute before firing; the other rule has gone.
        let sql = "INSERT INTO alerts (rule_id, rule_name, severity, host_id, hostname,
                       series, summary, started_ms)
                   SELECT r.id, r.name, 'critical', h.id, h.hostname, '', 'x', 600000
                   FROM alert_rules r, hosts h
                   WHERE r.name = 'Host offline' AND h.hostname = 'Fleet'
                   UNION ALL
                   SELECT NULL, 'Gone', 'warning', h.id, h.hostname, '', 'y', 700000
                   FROM hosts h WHERE h.hostname = 'Fleet'";
        connection.execute_unprepared(sql).await.unwrap();
        let wait = texts(
            &connection,
            "SELECT CAST(for_secs AS TEXT) FROM alert_rules WHERE name = 'Host offline'",
        )
        .await;
        let wait_ms: i64 = wait[0].parse::<i64>().unwrap() * 1000;

        Migrator::up(&connection, None).await.unwrap();
        let began = texts(&connection, "SELECT breached_at FROM alerts ORDER BY id").await;
        let at = |ms| as_sqlx_writes(crate::times::from_ms(ms));
        assert_eq!(began, [at(600_000 - wait_ms), at(700_000)]);
        assert_eq!(began[1], "1970-01-01T00:11:40+00:00");
    }

    /// A moment as sqlx writes it to SQLite, which keeps it as text.
    fn as_sqlx_writes(time: crate::times::Timestamp) -> String {
        time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
    }

    #[tokio::test]
    async fn milliseconds_become_the_same_moments() {
        // 2026-11-19 01:57:17.828 UTC, and 02:30 that day, on the second.
        const WITH_MILLISECONDS: i64 = 1_795_053_437_828;
        const ON_THE_SECOND: i64 = 1_795_055_400_000;
        let folder = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            folder.path().join("maxnines.db").display()
        );
        let options = ConnectOptions::new(&url).max_connections(1).to_owned();
        let connection = Database::connect(options).await.unwrap();
        Migrator::up(&connection, Some(1)).await.unwrap();
        let rows = format!(
            "INSERT INTO alerts (rule_id, rule_name, severity, host_id, hostname, series,
                 summary, started_ms, acknowledged_by, acknowledged_ms)
             SELECT r.id, r.name, 'critical', 'fleet', 'Fleet', '', 'x', {WITH_MILLISECONDS},
                 'sam', {ON_THE_SECOND}
             FROM alert_rules r WHERE r.name = 'Host offline';
             INSERT INTO host_facts (host_id, name, value, value_type, valid_from_ms)
             VALUES ('fleet', 'os.family', 'linux', 'string', {WITH_MILLISECONDS});"
        );
        connection.execute_unprepared(&rows).await.unwrap();
        let wait = texts(
            &connection,
            "SELECT CAST(for_secs AS TEXT) FROM alert_rules WHERE name = 'Host offline'",
        )
        .await;
        let wait_ms = wait[0].parse::<i64>().unwrap() * 1000;
        connection.close().await.unwrap();

        // Connecting runs the rest of the migrations, and the rows read back through
        // the entities as the moments they were.
        let database = crate::models::Database::connect(&url).await.unwrap();
        let alert = database.open_alerts().await.unwrap().remove(0);
        let at = crate::times::from_ms;
        assert_eq!(alert.started_at, at(WITH_MILLISECONDS));
        assert_eq!(alert.breached_at, at(WITH_MILLISECONDS - wait_ms));
        assert_eq!(alert.acknowledged_at, Some(at(ON_THE_SECOND)));
        assert_eq!(alert.resolved_at, None);
        let facts = database.facts_history("fleet").await.unwrap();
        assert_eq!(
            (facts[0].valid_from, facts[0].valid_to),
            (at(WITH_MILLISECONDS), None)
        );
        drop(database);

        // On SQLite they're text, exactly as sqlx writes them, so that they sort and
        // compare with the ones written from now on.
        let options = ConnectOptions::new(&url).max_connections(1).to_owned();
        let connection = Database::connect(options).await.unwrap();
        let saved = texts(
            &connection,
            "SELECT started_at || ' ' || acknowledged_at || ' ' || COALESCE(resolved_at, 'empty')
             FROM alerts",
        )
        .await;
        assert_eq!(
            saved,
            ["2026-11-19T01:57:17.828+00:00 2026-11-19T02:30:00+00:00 empty"]
        );
        let written = Statement::from_sql_and_values(
            connection.get_database_backend(),
            "SELECT ? || ' ' || ?",
            [at(WITH_MILLISECONDS).into(), at(ON_THE_SECOND).into()],
        );
        let written: String = connection
            .query_one_raw(written)
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(
            saved[0],
            format!("{written} empty"),
            "the migration and sqlx write moments differently"
        );
        assert_eq!(
            written,
            format!(
                "{} {}",
                as_sqlx_writes(at(WITH_MILLISECONDS)),
                as_sqlx_writes(at(ON_THE_SECOND))
            )
        );
        let fact = texts(&connection, "SELECT valid_from FROM host_facts").await;
        assert_eq!(fact, ["2026-11-19T01:57:17.828+00:00"]);

        // And back again.
        Migrator::down(&connection, Some(1)).await.unwrap();
        let kept = texts(
            &connection,
            "SELECT CAST(started_ms AS TEXT) || ' ' || CAST(acknowledged_ms AS TEXT) FROM alerts",
        )
        .await;
        assert_eq!(kept, [format!("{WITH_MILLISECONDS} {ON_THE_SECOND}")]);
        Migrator::up(&connection, None).await.unwrap();
    }

    #[tokio::test]
    async fn the_tables_can_be_dropped_and_made_again() {
        let connection = fresh().await;
        Migrator::up(&connection, None).await.unwrap();
        Migrator::down(&connection, None).await.unwrap();
        let left = texts(
            &connection,
            "SELECT name FROM sqlite_master WHERE type = 'table'
             AND name NOT IN ('seaql_migrations', 'sqlite_sequence')",
        )
        .await;
        assert!(left.is_empty(), "{left:?}");
        Migrator::up(&connection, None).await.unwrap();
    }

    #[tokio::test]
    async fn a_check_must_be_about_a_host() {
        let connection = fresh().await;
        Migrator::up(&connection, None).await.unwrap();
        let add = |name: &str, host: &str| {
            let sql = format!(
                "INSERT INTO remote_checks (name, kind, target, interval_secs, enabled, host_id)
                 VALUES ('{name}', 'ping', 'example.com', 60, TRUE, '{host}')"
            );
            let connection = &connection;
            async move { connection.execute_unprepared(&sql).await }
        };
        assert!(add("Nowhere", "nobody").await.is_err());
        connection
            .execute_unprepared(
                "INSERT INTO hosts (id, hostname, public_key, state, first_seen_at, kind)
                 VALUES ('abc', 'db', '', 'approved', '1970-01-01T00:00:00.001+00:00', 'agentless')",
            )
            .await
            .unwrap();
        add("Database", "abc").await.unwrap();
        let gone = "DELETE FROM hosts WHERE id = 'abc'";
        assert!(connection.execute_unprepared(gone).await.is_err());

        // One with no host given is the server's.
        connection
            .execute_unprepared(
                "INSERT INTO remote_checks (name, kind, target, interval_secs, enabled)
                 VALUES ('Site', 'http', 'https://example.com', 60, TRUE)",
            )
            .await
            .unwrap();
        let about = "SELECT host_id FROM remote_checks WHERE name = 'Site'";
        assert_eq!(texts(&connection, about).await, ["server"]);

        // A name only has to differ from the other checks about the same host.
        add("Site", "abc").await.unwrap();
        assert!(add("Site", "abc").await.is_err(), "one to a host");
        assert!(add("Site", "server").await.is_err());
    }
}
