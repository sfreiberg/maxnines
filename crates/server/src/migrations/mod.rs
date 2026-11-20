//! The main database's tables, made by one migration: what `database/README.md`
//! draws. A change to a table is a new migration after this one, with the README
//! changed to match. Until the first release, those are squashed back into this one
//! now and then, as if the design had been right from the start, and a database made
//! before then has its `seaql_migrations` rows changed to name this one alone.

use sea_orm::{DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(CreateTables),
            Box::new(AddNoMetricsRule),
            Box::new(KeysAndIndexes),
            Box::new(NamesAndUniqueness),
            Box::new(ExactFactsAndEndedAlerts),
            Box::new(DurationsInSeconds),
            Box::new(AgentHellos),
        ]
    }
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

/// A moment in UTC to the millisecond: `timestamptz` on PostgreSQL, `DATETIME(3)` on
/// MySQL, which has no time zone to shift it by and lasts past 2038 as `TIMESTAMP`
/// doesn't, and text on SQLite, which has no type for it. There it's ISO 8601 as sqlx
/// writes it, so moments sort and compare as text as they do as times.
fn moment(backend: DatabaseBackend, column: impl IntoIden) -> ColumnDef {
    let mut moment = ColumnDef::new(column);
    match backend {
        DatabaseBackend::Postgres => moment.timestamp_with_time_zone(),
        DatabaseBackend::MySql => moment.custom(Alias::new("DATETIME(3)")),
        _ => moment.custom(Alias::new("TEXT")),
    };
    moment
}

/// JSON: `jsonb` on PostgreSQL and `json` on MySQL, which both check it, and text on
/// SQLite, which has no type for it.
fn json(backend: DatabaseBackend, column: impl IntoIden) -> ColumnDef {
    let mut json = ColumnDef::new(column);
    match backend {
        DatabaseBackend::Postgres => json.json_binary(),
        DatabaseBackend::MySql => json.json(),
        _ => json.text(),
    };
    json
}

struct CreateTables;

impl MigrationName for CreateTables {
    fn name(&self) -> &str {
        "m20261119_000001_create_tables"
    }
}

/// Every table, in the order their foreign keys need, and what a new server starts
/// with: the server itself and the fleet as hosts, a default config rule, and the
/// built-in alert rules. A column that can be empty is NULL when it is, never an empty
/// string, so it says plainly when there's nothing in it.
#[async_trait::async_trait]
impl MigrationTrait for CreateTables {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
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
                    .col(ColumnDef::new(Hosts::PublicKey).string_len(64))
                    .col(ColumnDef::new(Hosts::Hostname).string_len(255).not_null())
                    .col(ColumnDef::new(Hosts::State).string_len(16).not_null())
                    .col(ColumnDef::new(Hosts::DecidedBy).text())
                    .col(moment(backend, Hosts::FirstSeenAt).not_null())
                    .col(moment(backend, Hosts::DecidedAt))
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
                    .col(moment(backend, HostFacts::ValidFrom).not_null())
                    .col(moment(backend, HostFacts::ValidTo))
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
                    .col(HostFacts::ValidTo)
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
                    .col(moment(backend, HostConfigStatus::ReportedAt).not_null())
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
                    .col(moment(backend, HostBoots::BootedAt).not_null())
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
                    .col(ColumnDef::new(MetricsPages::Names).text())
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
                    .col(moment(backend, ConfigRules::BuiltInChangedAt))
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
                    .col(moment(backend, Users::SetupExpiresAt))
                    .col(ColumnDef::new(Users::TotpSecret).string_len(128))
                    .col(
                        ColumnDef::new(Users::TotpEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::TotpLastStep).big_integer())
                    .col(moment(backend, Users::CreatedAt).not_null())
                    .col(moment(backend, Users::LastSignInAt))
                    .col(moment(backend, Users::DisabledAt))
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
                    .col(moment(backend, UserSessions::CreatedAt).not_null())
                    .col(moment(backend, UserSessions::ExpiresAt).not_null())
                    .col(moment(backend, UserSessions::LastUsedAt))
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
                    .col(moment(backend, ApiKeys::CreatedAt).not_null())
                    .col(moment(backend, ApiKeys::ExpiresAt))
                    .col(moment(backend, ApiKeys::LastUsedAt))
                    .col(moment(backend, ApiKeys::RevokedAt))
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
                        .col(ColumnDef::new(T::Device).string_len(100))
                        .col(ColumnDef::new(T::Role).string_len(16).not_null())
                        .col(hash(T::AccessHash).unique_key().to_owned())
                        .col(moment(backend, T::AccessExpiresAt).not_null())
                        .col(hash(T::RefreshHash).unique_key().to_owned())
                        .col(ColumnDef::new(T::PreviousRefreshHash).string_len(64))
                        .col(moment(backend, T::RotatedAt))
                        .col(moment(backend, T::RefreshExpiresAt).not_null())
                        .col(moment(backend, T::CreatedAt).not_null())
                        .col(moment(backend, T::LastUsedAt))
                        .col(moment(backend, T::RevokedAt))
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
                    .col(moment(backend, RecoveryCodes::UsedAt))
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
                    .col(moment(backend, SignInChallenges::ExpiresAt).not_null())
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
                    .col(moment(backend, NotificationChannels::DeletedAt))
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
                    .col(moment(backend, AlertRules::DeletedAt))
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
        // An alert keeps no copy of its rule's name or its host's, which would only go
        // stale when either was renamed. Rules are only ever marked deleted, and a
        // host's alerts go with it, so both are always there to be read.
        manager
            .create_table(
                Table::create()
                    .table(Alerts::Table)
                    .col(id(Alerts::Id))
                    .col(ColumnDef::new(Alerts::RuleId).big_integer().not_null())
                    .col(ColumnDef::new(Alerts::Severity).string_len(16).not_null())
                    .col(ColumnDef::new(Alerts::HostId).string_len(32).not_null())
                    .col(ColumnDef::new(Alerts::Series).string_len(255))
                    .col(ColumnDef::new(Alerts::Value).double())
                    .col(ColumnDef::new(Alerts::Summary).text().not_null())
                    .col(moment(backend, Alerts::StartedAt).not_null())
                    .col(moment(backend, Alerts::BreachedAt).not_null())
                    .col(moment(backend, Alerts::ResolvedAt))
                    .col(ColumnDef::new(Alerts::ResolveReason).text())
                    .col(ColumnDef::new(Alerts::ResolvedSummary).text())
                    .col(ColumnDef::new(Alerts::AcknowledgedBy).string_len(255))
                    .col(moment(backend, Alerts::AcknowledgedAt))
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
                            .to(AlertRules::Table, AlertRules::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_alerts_resolved")
                    .table(Alerts::Table)
                    .col(Alerts::ResolvedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_alerts_started")
                    .table(Alerts::Table)
                    .col(Alerts::StartedAt)
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
                    .col(moment(backend, Notifications::NextAttemptAt).not_null())
                    .col(ColumnDef::new(Notifications::LastError).text())
                    .col(moment(backend, Notifications::CreatedAt).not_null())
                    .col(moment(backend, Notifications::SentAt))
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
                    .col(Notifications::NextAttemptAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Silences::Table)
                    .col(id(Silences::Id))
                    .col(ColumnDef::new(Silences::RuleId).big_integer())
                    .col(ColumnDef::new(Silences::Filter).string_len(500))
                    .col(ColumnDef::new(Silences::Reason).string_len(255).not_null())
                    .col(
                        ColumnDef::new(Silences::CreatedBy)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(moment(backend, Silences::StartsAt).not_null())
                    .col(moment(backend, Silences::EndsAt).not_null())
                    .col(ColumnDef::new(Silences::Series).string_len(255))
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
                    .col(Silences::EndsAt)
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
                    .col(ColumnDef::new(MaintenanceWindows::Filter).string_len(500))
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

        // MySQL's text holds 64 KB, which what an action prints can pass.
        let mut output = ColumnDef::new(ActionRuns::Output);
        match backend {
            DatabaseBackend::MySql => output.custom(Alias::new("LONGTEXT")),
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
                    .col(json(backend, ActionRuns::Variables).not_null())
                    .col(ColumnDef::new(ActionRuns::RequestedBy).string_len(255))
                    .col(moment(backend, ActionRuns::RequestedAt).not_null())
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
                    .col(moment(backend, ActionRuns::FinishedAt))
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
                    .col(ActionRuns::RequestedAt)
                    .to_owned(),
            )
            .await?;
        // What's still waiting for an answer, which is looked for on every pass.
        manager
            .create_index(
                Index::create()
                    .name("idx_action_runs_finished")
                    .table(ActionRuns::Table)
                    .col(ActionRuns::FinishedAt)
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
                    .col(moment(backend, Dashboards::CreatedAt).not_null())
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
                    .col(ColumnDef::new(DashboardWidgets::Title).string_len(100))
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
                    .col(ColumnDef::new(DashboardWidgets::Filter).string_len(500))
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
                    .col(ColumnDef::new(DashboardVariables::Label).string_len(100))
                    .col(
                        ColumnDef::new(DashboardVariables::Kind)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(ColumnDef::new(DashboardVariables::Fact).string_len(200))
                    .col(ColumnDef::new(DashboardVariables::Filter).string_len(500))
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
                    .col(ColumnDef::new(LocationRules::Filter).string_len(500))
                    .col(ColumnDef::new(LocationRules::Place).string_len(255))
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
                    .col(moment(backend, Events::OccurredAt).not_null())
                    .col(ColumnDef::new(Events::Kind).string_len(16).not_null())
                    .col(ColumnDef::new(Events::Title).string_len(200).not_null())
                    .col(ColumnDef::new(Events::Detail).text())
                    .col(ColumnDef::new(Events::Filter).string_len(500))
                    .col(ColumnDef::new(Events::CreatedBy).string_len(255).not_null())
                    .col(moment(backend, Events::CreatedAt).not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_time")
                    .table(Events::Table)
                    .col(Events::OccurredAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AuditLog::Table)
                    .col(id(AuditLog::Id))
                    .col(moment(backend, AuditLog::OccurredAt).not_null())
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
                    .col(json(backend, AuditLog::Changes).not_null())
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
                    .col(moment(backend, Proxies::CreatedAt).not_null())
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
            Hosts::Hostname,
            Hosts::State,
            Hosts::DecidedBy,
            Hosts::FirstSeenAt,
        ])
        .to_owned();
    // They have no key, and were there from the start, which they're given as 1970.
    for (id, hostname) in BUILT_IN_HOSTS {
        hosts.values_panic([
            id.into(),
            "built_in".into(),
            hostname.into(),
            "approved".into(),
            "built-in".into(),
            chrono::DateTime::<chrono::Utc>::UNIX_EPOCH.into(),
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

struct AddNoMetricsRule;

impl MigrationName for AddNoMetricsRule {
    fn name(&self) -> &str {
        "m20261119_000002_add_no_metrics_rule"
    }
}

/// A connected agent whose samples all stop being stored, such as after a change to
/// what agents send, never goes offline, so nothing else notices.
const NO_METRICS_RULE: BuiltInRule = BuiltInRule {
    name: "Host sending no metrics",
    kind: "no_metrics",
    metric: None,
    comparison: None,
    threshold: None,
    warning_threshold: None,
    for_secs: 300,
    window_secs: None,
    forecast_secs: None,
    warning_forecast_secs: None,
};

/// Adds the built-in rule for an agent that's connected but sending no metrics, to
/// new servers and ones made before it, as upgrades leave the rules a server has
/// alone. One that already has a rule of that name keeps it rather than getting a
/// second, as names are each used once.
#[async_trait::async_trait]
impl MigrationTrait for AddNoMetricsRule {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let same = Query::select()
            .column(AlertRules::Id)
            .from(AlertRules::Table)
            .and_where(Expr::col(AlertRules::DeletedAt).is_null())
            .and_where(
                Expr::col(AlertRules::Name)
                    .eq(NO_METRICS_RULE.name)
                    .or(Expr::col(AlertRules::Kind).eq(NO_METRICS_RULE.kind)),
            )
            .limit(1)
            .to_owned();
        if manager.get_connection().query_one(&same).await?.is_some() {
            return Ok(());
        }
        add_built_in_rule(manager, &NO_METRICS_RULE).await
    }

    /// The server before this can't read a rule of this kind, so every one goes, with
    /// its alerts, whose notifications and action runs go with them.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let rules = Query::select()
            .column(AlertRules::Id)
            .from(AlertRules::Table)
            .and_where(Expr::col(AlertRules::Kind).eq(NO_METRICS_RULE.kind))
            .to_owned();
        let alerts = Query::delete()
            .from_table(Alerts::Table)
            .and_where(Expr::col(Alerts::RuleId).in_subquery(rules))
            .to_owned();
        manager.exec_stmt(alerts).await?;
        let rules = Query::delete()
            .from_table(AlertRules::Table)
            .and_where(Expr::col(AlertRules::Kind).eq(NO_METRICS_RULE.kind))
            .to_owned();
        manager.exec_stmt(rules).await
    }
}

struct KeysAndIndexes;

impl MigrationName for KeysAndIndexes {
    fn name(&self) -> &str {
        "m20261119_000003_keys_and_indexes"
    }
}

/// What happens to a row when the row its foreign key points at is deleted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnDelete {
    /// The delete is refused while the row is there, which is the default.
    Refuse,
    /// The row goes too.
    Cascade,
}

impl OnDelete {
    /// How SQLite's definition of a table writes it after the key.
    fn sqlite(self) -> &'static str {
        match self {
            Self::Refuse => "",
            Self::Cascade => " ON DELETE CASCADE",
        }
    }
}

/// A foreign key on `table.column` to `parent.id`, named as the first migration
/// names them, and what deleting the parent did before this migration and does after.
struct KeyChange {
    table: &'static str,
    column: &'static str,
    parent: &'static str,
    was: OnDelete,
    now: OnDelete,
}

impl KeyChange {
    fn name(&self) -> String {
        format!("fk_{}_{}", self.table, self.column)
    }
}

const fn key(
    table: &'static str,
    column: &'static str,
    parent: &'static str,
    was: OnDelete,
    now: OnDelete,
) -> KeyChange {
    KeyChange {
        table,
        column,
        parent,
        was,
        now,
    }
}

/// What the database does when a host or user is deleted is what the server means:
/// everything kept about a host or by a user goes with it, as each was already deleted
/// by hand. A notification keeps its channel, which is only ever marked deleted so
/// what was sent through it still names it, as an alert keeps its rule.
const CHANGED_KEYS: [KeyChange; 11] = {
    use OnDelete::{Cascade, Refuse};
    [
        key("host_facts", "host_id", "hosts", Refuse, Cascade),
        key("host_config_status", "host_id", "hosts", Refuse, Cascade),
        key("host_boots", "host_id", "hosts", Refuse, Cascade),
        key("metrics_pages", "host_id", "hosts", Refuse, Cascade),
        key("remote_checks", "host_id", "hosts", Refuse, Cascade),
        key("alerts", "host_id", "hosts", Refuse, Cascade),
        key("api_keys", "user_id", "users", Refuse, Cascade),
        key("app_sign_ins", "user_id", "users", Refuse, Cascade),
        key("recovery_codes", "user_id", "users", Refuse, Cascade),
        key("sign_in_challenges", "user_id", "users", Refuse, Cascade),
        key(
            "notifications",
            "channel_id",
            "notification_channels",
            Cascade,
            Refuse,
        ),
    ]
};

/// The foreign key this adds: what an action printed goes with the action run.
const ADDED_KEY: KeyChange = key(
    "notifications",
    "action_run_id",
    "action_runs",
    OnDelete::Refuse,
    OnDelete::Cascade,
);

/// An index this adds: its name, table and columns, and whether its first column is
/// a foreign key the first migration made, for which MySQL made an index of its own
/// that this one replaces.
struct NewIndex {
    name: &'static str,
    table: &'static str,
    columns: &'static [&'static str],
    replaces_mysql_key_index: bool,
}

const NEW_INDEXES: [NewIndex; 9] = [
    // A host's timeline, newest first, and finding its alerts to delete with it.
    NewIndex {
        name: "idx_alerts_host_started",
        table: "alerts",
        columns: &["host_id", "started_at"],
        replaces_mysql_key_index: true,
    },
    // A rule's open alerts, to end them when it's deleted or remind people of them.
    NewIndex {
        name: "idx_alerts_rule_resolved",
        table: "alerts",
        columns: &["rule_id", "resolved_at"],
        replaces_mysql_key_index: true,
    },
    // What's waiting for a channel, dropped when it's deleted.
    NewIndex {
        name: "idx_notifications_channel",
        table: "notifications",
        columns: &["channel_id", "state"],
        replaces_mysql_key_index: true,
    },
    NewIndex {
        name: "idx_notifications_action_run",
        table: "notifications",
        columns: &["action_run_id"],
        replaces_mysql_key_index: false,
    },
    NewIndex {
        name: "idx_alert_rule_channels_channel",
        table: "alert_rule_channels",
        columns: &["channel_id"],
        replaces_mysql_key_index: true,
    },
    NewIndex {
        name: "idx_api_keys_user_id",
        table: "api_keys",
        columns: &["user_id"],
        replaces_mysql_key_index: true,
    },
    NewIndex {
        name: "idx_recovery_codes_user_id",
        table: "recovery_codes",
        columns: &["user_id"],
        replaces_mysql_key_index: true,
    },
    NewIndex {
        name: "idx_sign_in_challenges_user_id",
        table: "sign_in_challenges",
        columns: &["user_id"],
        replaces_mysql_key_index: true,
    },
    // Sessions that have run out, which every sign in clears.
    NewIndex {
        name: "idx_user_sessions_expires",
        table: "user_sessions",
        columns: &["expires_at"],
        replaces_mysql_key_index: false,
    },
];

/// Tables whose names are each used once among the rows that aren't deleted.
const LIVE_NAMES: [&str; 2] = ["alert_rules", "notification_channels"];

/// Foreign keys say what the server means, and the indexes its queries and foreign
/// keys need are there:
///
/// - Deleting a host or a user deletes what's kept about them, and a notification
///   keeps its channel, as [`CHANGED_KEYS`] says.
/// - A notification of what an action printed points at its run, and goes with it.
///   Ones whose run has already gone are deleted first.
/// - The indexes in [`NEW_INDEXES`], and on PostgreSQL and SQLite one of
///   notifications that failed, newest first, for the alerts page. MySQL has no
///   index of only some rows, and it's only worth having as one.
/// - A name is used once among the alert rules that aren't deleted, and among the
///   channels, which the database now makes sure of. PostgreSQL and SQLite index the
///   name of those rows alone. MySQL can't, so it indexes a column it works out
///   itself, holding the name while the row isn't deleted and NULL once it is, which
///   a unique index lets repeat. It compares names as the table's collation does, as
///   it does every other unique name. A later rule or channel sharing a name with an
///   earlier one, which only two saved at once could do, has its ID added to its name.
#[async_trait::async_trait]
impl MigrationTrait for KeysAndIndexes {
    /// SQLite can only change a foreign key by making the table again, with foreign
    /// keys off, which can't be done inside a transaction, so this starts its own.
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        without_foreign_keys(manager, |manager| Box::pin(keys_and_indexes_up(manager))).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        without_foreign_keys(manager, |manager| Box::pin(keys_and_indexes_down(manager))).await
    }
}

async fn keys_and_indexes_up(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = manager.get_database_backend();

    db.execute_unprepared(
        "DELETE FROM notifications WHERE action_run_id IS NOT NULL \
         AND action_run_id NOT IN (SELECT id FROM action_runs)",
    )
    .await?;
    match backend {
        DatabaseBackend::Sqlite => {
            for table in tables_with_changed_keys() {
                remake_sqlite_table(db, table, |definition| {
                    let mut definition = definition.to_string();
                    for change in CHANGED_KEYS.iter().filter(|change| change.table == table) {
                        definition = with_on_delete(&definition, change, change.was, change.now)?;
                    }
                    if table == ADDED_KEY.table {
                        definition = with_key_added(&definition, &ADDED_KEY)?;
                    }
                    Ok(definition)
                })
                .await?;
            }
        }
        // MySQL commits each change to a table as it's made, so one stopped partway
        // carries on from where it got to when it's run again.
        _ => {
            for change in CHANGED_KEYS.iter().chain([&ADDED_KEY]) {
                match key_on_delete(db, change).await? {
                    Some(now) if now == change.now => {}
                    Some(_) => {
                        drop_key(manager, change).await?;
                        add_key(manager, change, change.now).await?;
                    }
                    None => add_key(manager, change, change.now).await?,
                }
            }
        }
    }

    for index in &NEW_INDEXES {
        if backend == DatabaseBackend::MySql && mysql_has_index(db, index.table, index.name).await?
        {
            continue;
        }
        let mut create = Index::create();
        create.name(index.name).table(Alias::new(index.table));
        for column in index.columns {
            create.col(Alias::new(*column));
        }
        manager.create_index(create).await?;
        // MySQL drops the index it made for a foreign key once another can do its job,
        // but not one made again by going down, so that one goes here.
        let key_index = format!("fk_{}_{}", index.table, index.columns[0]);
        if backend == DatabaseBackend::MySql
            && index.replaces_mysql_key_index
            && mysql_has_index(db, index.table, &key_index).await?
        {
            drop_index(manager, &key_index, index.table).await?;
        }
    }
    if backend != DatabaseBackend::MySql {
        manager
            .create_index(
                Index::create()
                    .name("idx_notifications_problems")
                    .table(Notifications::Table)
                    .col(Notifications::Id)
                    .and_where(Expr::col(Notifications::LastError).is_not_null())
                    .to_owned(),
            )
            .await?;
    }

    for table in LIVE_NAMES {
        rename_repeated_live_names(manager, table).await?;
        let index = format!("idx_{table}_live_name");
        if backend == DatabaseBackend::MySql {
            if mysql_has_column(db, table, "live_name").await? {
                continue;
            }
            db.execute_unprepared(&format!(
                "ALTER TABLE `{table}` \
                 ADD COLUMN `live_name` varchar(255) \
                 AS (CASE WHEN `deleted_at` IS NULL THEN `name` END) STORED, \
                 ADD UNIQUE INDEX `{index}` (`live_name`)"
            ))
            .await?;
        } else {
            manager
                .create_index(
                    Index::create()
                        .name(&index)
                        .table(Alias::new(table))
                        .col(Alias::new("name"))
                        .unique()
                        .and_where(Expr::col(Alias::new("deleted_at")).is_null())
                        .to_owned(),
                )
                .await?;
        }
    }
    Ok(())
}

async fn keys_and_indexes_down(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = manager.get_database_backend();

    for table in LIVE_NAMES {
        let index = format!("idx_{table}_live_name");
        if backend == DatabaseBackend::MySql {
            db.execute_unprepared(&format!(
                "ALTER TABLE `{table}` DROP INDEX `{index}`, DROP COLUMN `live_name`"
            ))
            .await?;
        } else {
            drop_index(manager, &index, table).await?;
        }
    }
    if backend != DatabaseBackend::MySql {
        drop_index(manager, "idx_notifications_problems", "notifications").await?;
    }

    // MySQL won't drop an index a foreign key needs, so the keys go first, and the
    // index MySQL had made for each, named after the key, is made again before the
    // index that replaced it goes.
    if backend == DatabaseBackend::MySql {
        for change in CHANGED_KEYS.iter().chain([&ADDED_KEY]) {
            drop_key(manager, change).await?;
        }
    }
    for index in &NEW_INDEXES {
        if backend == DatabaseBackend::MySql && index.replaces_mysql_key_index {
            let column = index.columns[0];
            manager
                .create_index(
                    Index::create()
                        .name(format!("fk_{}_{column}", index.table))
                        .table(Alias::new(index.table))
                        .col(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        drop_index(manager, index.name, index.table).await?;
    }

    match backend {
        DatabaseBackend::Sqlite => {
            for table in tables_with_changed_keys() {
                remake_sqlite_table(db, table, |definition| {
                    let mut definition = definition.to_string();
                    if table == ADDED_KEY.table {
                        definition = without_key_added(&definition, &ADDED_KEY)?;
                    }
                    for change in CHANGED_KEYS.iter().filter(|change| change.table == table) {
                        definition = with_on_delete(&definition, change, change.now, change.was)?;
                    }
                    Ok(definition)
                })
                .await?;
            }
        }
        DatabaseBackend::MySql => {
            for change in &CHANGED_KEYS {
                add_key(manager, change, change.was).await?;
            }
        }
        _ => {
            for change in &CHANGED_KEYS {
                drop_key(manager, change).await?;
                add_key(manager, change, change.was).await?;
            }
            drop_key(manager, &ADDED_KEY).await?;
        }
    }
    Ok(())
}

/// Whether a MySQL table has an index of this name.
async fn mysql_has_index(
    db: &impl ConnectionTrait,
    table: &str,
    name: &str,
) -> Result<bool, DbErr> {
    let count: i64 = one_value(
        db,
        &format!(
            "SELECT COUNT(*) FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = '{table}' AND index_name = '{name}'"
        ),
    )
    .await?;
    Ok(count > 0)
}

/// Whether a MySQL table has a column of this name.
async fn mysql_has_column(
    db: &impl ConnectionTrait,
    table: &str,
    name: &str,
) -> Result<bool, DbErr> {
    let count: i64 = one_value(
        db,
        &format!(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = '{table}' AND column_name = '{name}'"
        ),
    )
    .await?;
    Ok(count > 0)
}

/// What a foreign key on PostgreSQL or MySQL does on delete, or `None` if there's
/// no such key.
async fn key_on_delete(
    db: &impl ConnectionTrait,
    key: &KeyChange,
) -> Result<Option<OnDelete>, DbErr> {
    let schema = match db.get_database_backend() {
        DatabaseBackend::MySql => "DATABASE()",
        _ => "current_schema()",
    };
    let rules: Vec<String> = all_values(
        db,
        &format!(
            "SELECT CAST(delete_rule AS CHAR(16)) FROM information_schema.referential_constraints \
             WHERE constraint_schema = {schema} AND constraint_name = '{}'",
            key.name()
        ),
    )
    .await?;
    Ok(rules.first().map(|rule| match rule.trim() {
        "CASCADE" => OnDelete::Cascade,
        _ => OnDelete::Refuse,
    }))
}

/// Each table with a foreign key that changes, once, in the order they're first
/// named.
fn tables_with_changed_keys() -> Vec<&'static str> {
    let mut tables: Vec<&str> = Vec::new();
    for table in CHANGED_KEYS
        .iter()
        .chain([&ADDED_KEY])
        .map(|change| change.table)
    {
        if !tables.contains(&table) {
            tables.push(table);
        }
    }
    tables
}

async fn drop_index(manager: &SchemaManager<'_>, name: &str, table: &str) -> Result<(), DbErr> {
    manager
        .drop_index(Index::drop().name(name).table(Alias::new(table)).to_owned())
        .await
}

async fn drop_key(manager: &SchemaManager<'_>, key: &KeyChange) -> Result<(), DbErr> {
    manager
        .drop_foreign_key(
            ForeignKey::drop()
                .name(key.name())
                .table(Alias::new(key.table))
                .to_owned(),
        )
        .await
}

/// Adds a foreign key on PostgreSQL or MySQL. One that refuses is written without
/// saying so, as the first migration wrote them.
async fn add_key(
    manager: &SchemaManager<'_>,
    key: &KeyChange,
    on_delete: OnDelete,
) -> Result<(), DbErr> {
    let mut create = ForeignKey::create();
    create
        .name(key.name())
        .from(Alias::new(key.table), Alias::new(key.column))
        .to(Alias::new(key.parent), Alias::new("id"));
    if on_delete == OnDelete::Cascade {
        create.on_delete(ForeignKeyAction::Cascade);
    }
    manager.create_foreign_key(create).await
}

/// Adds a later rule's or channel's ID to its name where one before it that isn't
/// deleted has the same name, so a unique index can be made. Names are compared as
/// that index will compare them. A name made that way that's already taken, as
/// another rule could have been named like that, gets a number after the ID too.
async fn rename_repeated_live_names(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let (quote, backend) = match db.get_database_backend() {
        DatabaseBackend::MySql => ('`', DatabaseBackend::MySql),
        backend => ('"', backend),
    };
    let table_name = format!("{quote}{table}{quote}");
    let repeated = db
        .query_all_raw(Statement::from_string(
            backend,
            format!(
                "SELECT later.id, later.name FROM {table_name} later \
                 WHERE later.deleted_at IS NULL AND EXISTS (SELECT 1 FROM {table_name} earlier \
                 WHERE earlier.name = later.name AND earlier.id < later.id \
                 AND earlier.deleted_at IS NULL) ORDER BY later.id"
            ),
        ))
        .await?;
    for row in repeated {
        let id: i64 = column(&row, 0)?;
        let name: String = column(&row, 1)?;
        let base: String = name.chars().take(230).collect();
        let mut number = 1;
        let renamed = loop {
            let candidate = match number {
                1 => format!("{base} ({id})"),
                _ => format!("{base} ({id}, {number})"),
            };
            let taken = Query::select()
                .expr(Expr::col(Alias::new("id")).count())
                .from(Alias::new(table))
                .and_where(Expr::col(Alias::new("deleted_at")).is_null())
                .and_where(Expr::col(Alias::new("name")).eq(candidate.as_str()))
                .to_owned();
            let row = db
                .query_one(&taken)
                .await?
                .ok_or_else(|| DbErr::Migration(format!("counting names in {table}")))?;
            let count: i64 = column(&row, 0)?;
            if count == 0 {
                break candidate;
            }
            number += 1;
        };
        let rename = Query::update()
            .table(Alias::new(table))
            .value(Alias::new("name"), renamed)
            .and_where(Expr::col(Alias::new("id")).eq(id))
            .to_owned();
        db.execute(&rename).await?;
    }
    Ok(())
}

struct NamesAndUniqueness;

impl MigrationName for NamesAndUniqueness {
    fn name(&self) -> &str {
        "m20261119_000004_names_and_uniqueness"
    }
}

/// How long a name can be as it's compared: lowercased, which can make it longer, from
/// a name of up to 255 characters.
const NAME_KEY_LEN: usize = 512;

/// How the column holding a name as it's compared is added, with a default only so
/// rows already there can have one until they're filled in.
const NAME_KEY_ADDED: &str = "\"name_key\" varchar(512) NOT NULL DEFAULT ''";

/// A table whose names are each used once, compared as [`crate::models::name_key`]
/// compares them.
struct NamedTable {
    table: &'static str,
    /// How many characters its names can have.
    longest: usize,
    /// Each host's names are its own.
    per_host: bool,
    /// Only rows that aren't deleted count.
    live_only: bool,
    /// The unique index of its names.
    index: &'static str,
}

const NAMED_TABLES: [NamedTable; 4] = [
    NamedTable {
        table: "alert_rules",
        longest: 255,
        per_host: false,
        live_only: true,
        index: "idx_alert_rules_live_name",
    },
    NamedTable {
        table: "notification_channels",
        longest: 255,
        per_host: false,
        live_only: true,
        index: "idx_notification_channels_live_name",
    },
    NamedTable {
        table: "config_rules",
        longest: 255,
        per_host: false,
        live_only: false,
        index: "idx_config_rules_name",
    },
    NamedTable {
        table: "remote_checks",
        longest: 64,
        per_host: true,
        live_only: false,
        index: "idx_remote_checks_host_name",
    },
];

/// How SQLite's definition of `config_rules` writes its name, which was unique as
/// written until this migration.
const CONFIG_RULE_NAME: &str = "\"name\" varchar(255) NOT NULL";

/// Indexes this adds for clearing what's run out, as each sign in does.
const CLEARING_INDEXES: [(&str, &str, &str); 3] = [
    (
        "idx_sign_in_challenges_expires",
        "sign_in_challenges",
        "expires_at",
    ),
    ("idx_app_sign_ins_revoked", "app_sign_ins", "revoked_at"),
    (
        "idx_app_sign_ins_refresh_expires",
        "app_sign_ins",
        "refresh_expires_at",
    ),
];

/// What the database keeps unique, it compares the same way on every database:
///
/// - Names of alert rules, channels, config rules and checks are compared ignoring
///   case and the spaces around them, as people read them, by a column holding each
///   name as it's compared, `name_key`, which the server fills in. MySQL compares it
///   exactly, as the other databases do, rather than by its collation. A name that's
///   now the same as an earlier one's gets its ID added, and more if that's taken.
/// - A host has one current value of each fact, and a rule one open alert about each
///   host and series. Any repeats a server before this made are closed: the earlier
///   fact, as the later one is what the host said last, and the later alert.
///   PostgreSQL and SQLite index those rows alone, and MySQL a column it works out,
///   as it does for names.
/// - The facts every host has now are indexed by name, rather than every value any
///   host has had by name and value, which nothing looked up.
/// - What's cleared on every sign in is indexed.
///
/// MySQL commits each change to a table as it's made, so this checks what's there
/// before each change, and one stopped partway carries on when it's run again.
#[async_trait::async_trait]
impl MigrationTrait for NamesAndUniqueness {
    /// SQLite can only drop a column's default by making the table again, which needs
    /// its own transaction: see [`without_foreign_keys`].
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        without_foreign_keys(manager, |manager| {
            Box::pin(names_and_uniqueness_up(manager))
        })
        .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        without_foreign_keys(manager, |manager| {
            Box::pin(names_and_uniqueness_down(manager))
        })
        .await
    }
}

async fn names_and_uniqueness_up(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = manager.get_database_backend();
    let mysql = backend == DatabaseBackend::MySql;

    for named in &NAMED_TABLES {
        let table = named.table;
        if !mysql || !mysql_has_column(db, table, "name_key").await? {
            let added = match backend {
                DatabaseBackend::MySql => NAME_KEY_ADDED.replace('"', "`").replace(
                    "NOT NULL",
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL",
                ),
                _ => NAME_KEY_ADDED.to_string(),
            };
            db.execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN {added}"))
                .await?;
        }
        fill_name_keys(db, named).await?;
    }

    // The default was only for the rows already there.
    for named in &NAMED_TABLES {
        let table = named.table;
        if backend == DatabaseBackend::Sqlite {
            remake_sqlite_table(db, table, |definition| {
                let without = NAME_KEY_ADDED.replace(" DEFAULT ''", "");
                let definition = replace_once(definition, NAME_KEY_ADDED, &without)?;
                if table == "config_rules" {
                    let unique = format!("{CONFIG_RULE_NAME} UNIQUE");
                    return replace_once(&definition, &unique, CONFIG_RULE_NAME);
                }
                Ok(definition)
            })
            .await?;
        } else {
            db.execute_unprepared(&format!(
                "ALTER TABLE {table} ALTER COLUMN name_key DROP DEFAULT"
            ))
            .await?;
        }
    }

    for named in &NAMED_TABLES {
        index_name_keys(db, named).await?;
    }
    one_current_fact(db).await?;
    one_open_alert(db).await?;
    for (index, table, column) in CLEARING_INDEXES {
        if !mysql || !mysql_has_index(db, table, index).await? {
            db.execute_unprepared(&format!("CREATE INDEX {index} ON {table} ({column})"))
                .await?;
        }
    }
    Ok(())
}

/// `definition` with `old` in it, just once, changed to `new`, or an error if it isn't
/// there just once, when the table isn't the one this was written for.
fn replace_once(definition: &str, old: &str, new: &str) -> Result<String, DbErr> {
    if definition.matches(old).count() != 1 {
        return Err(DbErr::Migration(format!(
            "a table isn't made the way it's expected to be: no {old}"
        )));
    }
    Ok(definition.replacen(old, new, 1))
}

/// Fills in each row's name as it's compared. Where one that counts has the same name
/// as an earlier one, its ID is added to its name, and a number too if that's taken.
async fn fill_name_keys(db: &impl ConnectionTrait, named: &NamedTable) -> Result<(), DbErr> {
    let table = named.table;
    let backend = db.get_database_backend();
    let save = |id: i64, name: Option<&str>, key: &str| {
        let mut update = Query::update();
        update
            .table(Alias::new(table))
            .value(Alias::new("name_key"), key)
            .and_where(Expr::col(Alias::new("id")).eq(id));
        if let Some(name) = name {
            update.value(Alias::new("name"), name);
        }
        update.to_owned()
    };

    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            format!("SELECT id, name, name_key FROM {table}"),
        ))
        .await?;
    for row in rows {
        let (id, name, saved): (i64, String, String) =
            (column(&row, 0)?, column(&row, 1)?, column(&row, 2)?);
        let key = crate::models::name_key(&name);
        if key != saved {
            db.execute(&save(id, None, &key)).await?;
        }
    }

    let scope = if named.per_host { "host_id" } else { "id" };
    let live = if named.live_only {
        " WHERE deleted_at IS NULL"
    } else {
        ""
    };
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            format!("SELECT id, name, name_key, {scope} FROM {table}{live} ORDER BY id"),
        ))
        .await?;
    let mut counted = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = column(&row, 0)?;
        let scope = if named.per_host {
            column::<String>(&row, 3)?
        } else {
            String::new()
        };
        counted.push((
            id,
            column::<String>(&row, 1)?,
            scope,
            column::<String>(&row, 2)?,
        ));
    }
    let mut taken: std::collections::HashSet<(String, String)> = counted
        .iter()
        .map(|(_, _, scope, key)| (scope.clone(), key.clone()))
        .collect();
    let mut kept: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for (id, name, scope, key) in counted {
        if kept.insert((scope.clone(), key)) {
            continue;
        }
        let mut number = 1;
        let (renamed, key) = loop {
            let suffix = match number {
                1 => format!(" ({id})"),
                _ => format!(" ({id}, {number})"),
            };
            let room = named.longest.saturating_sub(suffix.chars().count());
            let candidate: String = name.chars().take(room).collect::<String>() + &suffix;
            let key = crate::models::name_key(&candidate);
            if !taken.contains(&(scope.clone(), key.clone())) {
                break (candidate, key);
            }
            number += 1;
        };
        taken.insert((scope.clone(), key.clone()));
        kept.insert((scope, key.clone()));
        db.execute(&save(id, Some(&renamed), &key)).await?;
    }
    Ok(())
}

/// Makes the index that keeps each table's names unique use their `name_key`.
async fn index_name_keys(db: &impl ConnectionTrait, named: &NamedTable) -> Result<(), DbErr> {
    let (table, index) = (named.table, named.index);
    let backend = db.get_database_backend();
    match (backend, table) {
        (DatabaseBackend::MySql, "config_rules") => {
            if mysql_has_index(db, table, "name").await? {
                db.execute_unprepared("ALTER TABLE config_rules DROP INDEX `name`")
                    .await?;
            }
            if !mysql_has_index(db, table, index).await? {
                db.execute_unprepared(&format!(
                    "CREATE UNIQUE INDEX {index} ON {table} (name_key)"
                ))
                .await?;
            }
        }
        (DatabaseBackend::MySql, "remote_checks") => {
            if !mysql_index_has_column(db, table, index, "name_key").await? {
                db.execute_unprepared(&format!(
                    "ALTER TABLE {table} DROP INDEX {index}, \
                     ADD UNIQUE INDEX {index} (host_id, name_key)"
                ))
                .await?;
            }
        }
        (DatabaseBackend::MySql, _) => {
            if !mysql_generates_from(db, table, "live_name", "name_key").await? {
                db.execute_unprepared(&format!(
                    "ALTER TABLE {table} DROP INDEX {index}, DROP COLUMN live_name, \
                     ADD COLUMN live_name varchar({NAME_KEY_LEN}) \
                     CHARACTER SET utf8mb4 COLLATE utf8mb4_bin \
                     AS (CASE WHEN deleted_at IS NULL THEN name_key END) STORED, \
                     ADD UNIQUE INDEX {index} (live_name)"
                ))
                .await?;
            }
        }
        (_, "config_rules") => {
            if backend == DatabaseBackend::Postgres {
                // The constraint the first migration made, named by PostgreSQL.
                let unique: Vec<String> = all_values(
                    db,
                    "SELECT conname::text FROM pg_constraint \
                     WHERE conrelid = 'config_rules'::regclass AND contype = 'u'",
                )
                .await?;
                for constraint in unique {
                    db.execute_unprepared(&format!(
                        "ALTER TABLE config_rules DROP CONSTRAINT \"{constraint}\""
                    ))
                    .await?;
                }
            }
            db.execute_unprepared(&format!(
                "CREATE UNIQUE INDEX {index} ON {table} (name_key)"
            ))
            .await?;
        }
        (_, "remote_checks") => {
            db.execute_unprepared(&format!("DROP INDEX {index}"))
                .await?;
            db.execute_unprepared(&format!(
                "CREATE UNIQUE INDEX {index} ON {table} (host_id, name_key)"
            ))
            .await?;
        }
        _ => {
            db.execute_unprepared(&format!("DROP INDEX {index}"))
                .await?;
            db.execute_unprepared(&format!(
                "CREATE UNIQUE INDEX {index} ON {table} (name_key) WHERE deleted_at IS NULL"
            ))
            .await?;
        }
    }
    Ok(())
}

/// One current value of each fact for each host, and the facts hosts have now
/// indexed by name.
async fn one_current_fact(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mysql = db.get_database_backend() == DatabaseBackend::MySql;
    if mysql {
        db.execute_unprepared(
            "UPDATE host_facts earlier JOIN host_facts later \
             ON later.host_id = earlier.host_id AND BINARY later.name = BINARY earlier.name \
             AND later.valid_to IS NULL AND later.id > earlier.id \
             SET earlier.valid_to = earlier.valid_from WHERE earlier.valid_to IS NULL",
        )
        .await?;
        if !mysql_has_column(db, "host_facts", "current_name").await? {
            db.execute_unprepared(
                "ALTER TABLE host_facts ADD COLUMN current_name varchar(255) \
                 CHARACTER SET utf8mb4 COLLATE utf8mb4_bin \
                 AS (CASE WHEN valid_to IS NULL THEN name END) STORED, \
                 ADD UNIQUE INDEX idx_host_facts_current (host_id, current_name)",
            )
            .await?;
        }
        if !mysql_has_index(db, "host_facts", "idx_host_facts_current_name").await? {
            db.execute_unprepared(
                "CREATE INDEX idx_host_facts_current_name ON host_facts (valid_to, name)",
            )
            .await?;
        }
        if mysql_has_index(db, "host_facts", "idx_host_facts_name_value").await? {
            db.execute_unprepared("DROP INDEX idx_host_facts_name_value ON host_facts")
                .await?;
        }
        return Ok(());
    }
    db.execute_unprepared(
        "UPDATE host_facts SET valid_to = valid_from WHERE valid_to IS NULL \
         AND EXISTS (SELECT 1 FROM host_facts later WHERE later.host_id = host_facts.host_id \
         AND later.name = host_facts.name AND later.valid_to IS NULL \
         AND later.id > host_facts.id)",
    )
    .await?;
    for sql in [
        "CREATE UNIQUE INDEX idx_host_facts_current ON host_facts (host_id, name) \
         WHERE valid_to IS NULL",
        "CREATE INDEX idx_host_facts_current_name ON host_facts (name) WHERE valid_to IS NULL",
        "DROP INDEX idx_host_facts_name_value",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

/// Why an alert a server before this opened a second time was closed.
const REPEAT_REASON: &str = "another alert was already open for this";

/// One open alert from each rule about each host and series. A host as a whole has
/// no series, which counts as one of its own.
async fn one_open_alert(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    if db.get_database_backend() == DatabaseBackend::MySql {
        db.execute_unprepared(&format!(
            "UPDATE alerts later JOIN alerts earlier \
             ON earlier.rule_id = later.rule_id AND earlier.host_id = later.host_id \
             AND BINARY COALESCE(earlier.series, '') = BINARY COALESCE(later.series, '') \
             AND earlier.resolved_at IS NULL AND earlier.id < later.id \
             SET later.resolved_at = later.started_at, later.resolve_reason = '{REPEAT_REASON}' \
             WHERE later.resolved_at IS NULL"
        ))
        .await?;
        if !mysql_has_column(db, "alerts", "open_series").await? {
            db.execute_unprepared(
                "ALTER TABLE alerts ADD COLUMN open_series varchar(255) \
                 CHARACTER SET utf8mb4 COLLATE utf8mb4_bin \
                 AS (CASE WHEN resolved_at IS NULL THEN COALESCE(series, '') END) STORED, \
                 ADD UNIQUE INDEX idx_alerts_open (rule_id, host_id, open_series)",
            )
            .await?;
        }
        return Ok(());
    }
    db.execute_unprepared(&format!(
        "UPDATE alerts SET resolved_at = started_at, resolve_reason = '{REPEAT_REASON}' \
         WHERE resolved_at IS NULL AND EXISTS (SELECT 1 FROM alerts earlier \
         WHERE earlier.rule_id = alerts.rule_id AND earlier.host_id = alerts.host_id \
         AND COALESCE(earlier.series, '') = COALESCE(alerts.series, '') \
         AND earlier.resolved_at IS NULL AND earlier.id < alerts.id)"
    ))
    .await?;
    db.execute_unprepared(
        "CREATE UNIQUE INDEX idx_alerts_open ON alerts (rule_id, host_id, COALESCE(series, '')) \
         WHERE resolved_at IS NULL",
    )
    .await?;
    Ok(())
}

async fn names_and_uniqueness_down(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = manager.get_database_backend();
    let mysql = backend == DatabaseBackend::MySql;
    let dropped = |index: &str, table: &str| match backend {
        DatabaseBackend::MySql => format!("DROP INDEX {index} ON {table}"),
        _ => format!("DROP INDEX {index}"),
    };

    for (index, table, _) in CLEARING_INDEXES {
        db.execute_unprepared(&dropped(index, table)).await?;
    }
    if mysql {
        for sql in [
            "ALTER TABLE alerts DROP INDEX idx_alerts_open, DROP COLUMN open_series",
            "ALTER TABLE host_facts DROP INDEX idx_host_facts_current, DROP COLUMN current_name",
        ] {
            db.execute_unprepared(sql).await?;
        }
    } else {
        db.execute_unprepared(&dropped("idx_alerts_open", "alerts"))
            .await?;
        db.execute_unprepared(&dropped("idx_host_facts_current", "host_facts"))
            .await?;
    }
    db.execute_unprepared(&dropped("idx_host_facts_current_name", "host_facts"))
        .await?;
    db.execute_unprepared("CREATE INDEX idx_host_facts_name_value ON host_facts (name, value)")
        .await?;

    for named in &NAMED_TABLES {
        let (table, index) = (named.table, named.index);
        match (backend, table) {
            (_, "config_rules") => {
                db.execute_unprepared(&dropped(index, table)).await?;
            }
            (DatabaseBackend::MySql, "remote_checks") => {
                db.execute_unprepared(&format!(
                    "ALTER TABLE {table} DROP INDEX {index}, ADD UNIQUE INDEX {index} (host_id, name)"
                ))
                .await?;
            }
            (_, "remote_checks") => {
                db.execute_unprepared(&dropped(index, table)).await?;
                db.execute_unprepared(&format!(
                    "CREATE UNIQUE INDEX {index} ON {table} (host_id, name)"
                ))
                .await?;
            }
            (DatabaseBackend::MySql, _) => {
                db.execute_unprepared(&format!(
                    "ALTER TABLE {table} DROP INDEX {index}, DROP COLUMN live_name, \
                     ADD COLUMN live_name varchar(255) \
                     AS (CASE WHEN deleted_at IS NULL THEN name END) STORED, \
                     ADD UNIQUE INDEX {index} (live_name)"
                ))
                .await?;
            }
            _ => {
                db.execute_unprepared(&dropped(index, table)).await?;
                db.execute_unprepared(&format!(
                    "CREATE UNIQUE INDEX {index} ON {table} (name) WHERE deleted_at IS NULL"
                ))
                .await?;
            }
        }
        db.execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN name_key"))
            .await?;
    }
    match backend {
        DatabaseBackend::MySql => {
            db.execute_unprepared("ALTER TABLE config_rules ADD UNIQUE INDEX `name` (name)")
                .await?;
        }
        DatabaseBackend::Postgres => {
            db.execute_unprepared(
                "ALTER TABLE config_rules ADD CONSTRAINT config_rules_name_key UNIQUE (name)",
            )
            .await?;
        }
        _ => {
            remake_sqlite_table(db, "config_rules", |definition| {
                replace_once(
                    definition,
                    CONFIG_RULE_NAME,
                    &format!("{CONFIG_RULE_NAME} UNIQUE"),
                )
            })
            .await?;
        }
    }
    Ok(())
}

/// Whether one of a MySQL table's indexes has this column.
async fn mysql_index_has_column(
    db: &impl ConnectionTrait,
    table: &str,
    index: &str,
    name: &str,
) -> Result<bool, DbErr> {
    let count: i64 = one_value(
        db,
        &format!(
            "SELECT COUNT(*) FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = '{table}' \
             AND index_name = '{index}' AND column_name = '{name}'"
        ),
    )
    .await?;
    Ok(count > 0)
}

/// Whether a column MySQL works out is worked out from `from`.
async fn mysql_generates_from(
    db: &impl ConnectionTrait,
    table: &str,
    name: &str,
    from: &str,
) -> Result<bool, DbErr> {
    let count: i64 = one_value(
        db,
        &format!(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = '{table}' \
             AND column_name = '{name}' AND generation_expression LIKE '%{from}%'"
        ),
    )
    .await?;
    Ok(count > 0)
}

struct ExactFactsAndEndedAlerts;

impl MigrationName for ExactFactsAndEndedAlerts {
    fn name(&self) -> &str {
        "m20261119_000005_exact_facts_and_ended_alerts"
    }
}

/// The columns of `host_facts` that agents fill in.
const FACT_TEXT: [&str; 2] = ["name", "value"];

/// Facts are what agents report, so `os.Family` isn't `os.family`, and `Ubuntu` isn't
/// `ubuntu`. PostgreSQL and SQLite compare them exactly. MySQL and MariaDB compared
/// them by the table's collation, usually ignoring case and accents, so looking one
/// up, or listing each value once, found or merged others. They compare them
/// exactly now too, and going back gives them the table's collation again. Nothing
/// changes on the other databases.
///
/// Ended alerts are listed by when they ended, newest first, so the index of when
/// alerts ended takes their IDs too, for ones that ended at the same moment.
///
/// MySQL commits each change as it's made, so each can be made again.
#[async_trait::async_trait]
impl MigrationTrait for ExactFactsAndEndedAlerts {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        fact_text_collation(manager, "CHARACTER SET utf8mb4 COLLATE utf8mb4_bin").await?;
        index_when_alerts_ended(manager, &["resolved_at", "id"]).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        index_when_alerts_ended(manager, &["resolved_at"]).await?;
        fact_text_collation(manager, "").await
    }
}

/// Makes `idx_alerts_resolved` of these columns, unless MySQL already has.
async fn index_when_alerts_ended(
    manager: &SchemaManager<'_>,
    columns: &[&str],
) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let (index, list) = ("idx_alerts_resolved", columns.join(", "));
    if manager.get_database_backend() == DatabaseBackend::MySql {
        let with_id = mysql_index_has_column(db, "alerts", index, "id").await?;
        if with_id != columns.contains(&"id") {
            db.execute_unprepared(&format!(
                "ALTER TABLE alerts DROP INDEX {index}, ADD INDEX {index} ({list})"
            ))
            .await?;
        }
        return Ok(());
    }
    db.execute_unprepared(&format!("DROP INDEX {index}"))
        .await?;
    db.execute_unprepared(&format!("CREATE INDEX {index} ON alerts ({list})"))
        .await?;
    Ok(())
}

/// Defines MySQL's fact names and values with `collation`, or the table's own when
/// it's empty.
async fn fact_text_collation(manager: &SchemaManager<'_>, collation: &str) -> Result<(), DbErr> {
    if manager.get_database_backend() != DatabaseBackend::MySql {
        return Ok(());
    }
    let changes: Vec<String> = FACT_TEXT
        .iter()
        .map(|column| format!("MODIFY {column} varchar(255) {collation} NOT NULL"))
        .collect();
    manager
        .get_connection()
        .execute_unprepared(&format!("ALTER TABLE host_facts {}", changes.join(", ")))
        .await?;
    Ok(())
}

struct DurationsInSeconds;

impl MigrationName for DurationsInSeconds {
    fn name(&self) -> &str {
        "m20261119_000006_durations_in_seconds"
    }
}

/// How long an action ran is a number of seconds, as every other length is, with a
/// fraction, as many take less than one: `duration_secs` takes the place of
/// `duration_ms`.
///
/// MySQL commits each change as it's made, so each can be made again.
#[async_trait::async_trait]
impl MigrationTrait for DurationsInSeconds {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let seconds = ColumnDef::new(ActionRuns::DurationSecs).double().to_owned();
        let from_ms = "duration_ms / 1000.0";
        move_column(manager, "duration_ms", seconds, from_ms).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let ms = ColumnDef::new(ActionRuns::DurationMs)
            .big_integer()
            .to_owned();
        let from_secs = "ROUND(duration_secs * 1000)";
        move_column(manager, "duration_secs", ms, from_secs).await
    }
}

/// Replaces an action run's column `old` with `new`, worked out from it by `value`.
async fn move_column(
    manager: &SchemaManager<'_>,
    old: &str,
    mut new: ColumnDef,
    value: &str,
) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let is_mysql = manager.get_database_backend() == DatabaseBackend::MySql;
    let name = new.get_column_name();
    if !is_mysql || !mysql_has_column(db, "action_runs", &name).await? {
        let add = Table::alter()
            .table(ActionRuns::Table)
            .add_column(&mut new)
            .to_owned();
        manager.alter_table(add).await?;
    }
    if !is_mysql || mysql_has_column(db, "action_runs", old).await? {
        db.execute_unprepared(&format!("UPDATE action_runs SET {name} = {value}"))
            .await?;
        let drop = Table::alter()
            .table(ActionRuns::Table)
            .drop_column(Alias::new(old))
            .to_owned();
        manager.alter_table(drop).await?;
    }
    Ok(())
}

struct AgentHellos;

impl MigrationName for AgentHellos {
    fn name(&self) -> &str {
        "m20261120_000001_agent_hellos"
    }
}

/// What a host's agent said in its last hello: the version of the protocol it
/// speaks and its own version, and when and why it was last turned away for its
/// protocol, until one it says is taken. Each is NULL until it's said, and always for
/// a host with no agent.
///
/// MySQL commits each change as it's made, so each can be made again.
#[async_trait::async_trait]
impl MigrationTrait for AgentHellos {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let columns = [
            ColumnDef::new(Hosts::AgentProtocol)
                .big_integer()
                .to_owned(),
            ColumnDef::new(Hosts::AgentVersion)
                .string_len(64)
                .to_owned(),
            moment(backend, Hosts::RefusedAt),
            ColumnDef::new(Hosts::RefuseReason).text().to_owned(),
        ];
        let db = manager.get_connection();
        for mut column in columns {
            let name = column.get_column_name();
            if backend == DatabaseBackend::MySql && mysql_has_column(db, "hosts", &name).await? {
                continue;
            }
            let add = Table::alter()
                .table(Hosts::Table)
                .add_column(&mut column)
                .to_owned();
            manager.alter_table(add).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let db = manager.get_connection();
        for name in [
            "agent_protocol",
            "agent_version",
            "refused_at",
            "refuse_reason",
        ] {
            if backend == DatabaseBackend::MySql && !mysql_has_column(db, "hosts", name).await? {
                continue;
            }
            let drop = Table::alter()
                .table(Hosts::Table)
                .drop_column(Alias::new(name))
                .to_owned();
            manager.alter_table(drop).await?;
        }
        Ok(())
    }
}

/// How SQLite's definition of a table writes a foreign key, before what it does on
/// delete.
fn sqlite_key(key: &KeyChange) -> String {
    format!(
        "FOREIGN KEY (\"{}\") REFERENCES \"{}\" (\"id\")",
        key.column, key.parent
    )
}

/// A SQLite table's definition with what one of its foreign keys does on delete
/// changed from `from` to `to`. The key has to be there just once, doing `from`, or
/// the table isn't the one this was written for and nothing is changed.
fn with_on_delete(
    definition: &str,
    key: &KeyChange,
    from: OnDelete,
    to: OnDelete,
) -> Result<String, DbErr> {
    let old = format!("{}{}", sqlite_key(key), from.sqlite());
    // A key ends where the next one starts or the table does.
    let found: Vec<usize> = definition
        .match_indices(&old)
        .map(|(at, _)| at)
        .filter(|at| {
            let after = definition[at + old.len()..].trim_start();
            after.starts_with(',') || after.starts_with(')')
        })
        .collect();
    let [at] = found[..] else {
        return Err(DbErr::Migration(format!(
            "{}.{} isn't the foreign key expected",
            key.table, key.column
        )));
    };
    Ok(format!(
        "{}{}{}{}",
        &definition[..at],
        sqlite_key(key),
        to.sqlite(),
        &definition[at + old.len()..]
    ))
}

/// A SQLite table's definition with a foreign key added after everything else.
fn with_key_added(definition: &str, key: &KeyChange) -> Result<String, DbErr> {
    if definition.contains(&sqlite_key(key)) {
        return Err(DbErr::Migration(format!(
            "{}.{} already has a foreign key",
            key.table, key.column
        )));
    }
    let end = definition
        .rfind(')')
        .ok_or_else(|| DbErr::Migration(format!("{} has no columns", key.table)))?;
    Ok(format!(
        "{}, {}{} {}",
        definition[..end].trim_end(),
        sqlite_key(key),
        key.now.sqlite(),
        &definition[end..]
    ))
}

/// A SQLite table's definition without the foreign key [`with_key_added`] added.
fn without_key_added(definition: &str, key: &KeyChange) -> Result<String, DbErr> {
    let added = format!(", {}{}", sqlite_key(key), key.now.sqlite());
    if definition.matches(&added).count() != 1 {
        return Err(DbErr::Migration(format!(
            "{}.{} isn't the foreign key expected",
            key.table, key.column
        )));
    }
    Ok(definition.replacen(&added, "", 1))
}

/// Makes a SQLite table again from its own definition as `edit` changes it, the way
/// SQLite's documentation gives for what `ALTER TABLE` can't change, like a foreign
/// key: a new table made, the rows copied, the old one dropped and the new one
/// renamed, and its indexes made again. Its numbering carries on from where it was,
/// so a deleted row's ID is never used again. Foreign keys have to be off, or
/// dropping the old table would delete what points at it; see
/// [`without_foreign_keys`].
async fn remake_sqlite_table(
    db: &impl ConnectionTrait,
    table: &str,
    edit: impl FnOnce(&str) -> Result<String, DbErr>,
) -> Result<(), DbErr> {
    let definition: String = one_value(
        db,
        &format!("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
    )
    .await?;
    // Indexes SQLite made itself, for a unique column, have no SQL, and come back
    // with the table.
    let indexes: Vec<String> = all_values(
        db,
        &format!(
            "SELECT sql FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = '{table}' AND sql IS NOT NULL"
        ),
    )
    .await?;
    let made = format!("CREATE TABLE \"{table}\" ");
    let new = format!("{table}_new");
    let changed = edit(&definition)?;
    let columns = changed.strip_prefix(&made).ok_or_else(|| {
        DbErr::Migration(format!("{table} isn't made the way it's expected to be"))
    })?;
    db.execute_unprepared(&format!("CREATE TABLE \"{new}\" {columns}"))
        .await?;
    db.execute_unprepared(&format!("INSERT INTO \"{new}\" SELECT * FROM \"{table}\""))
        .await?;
    db.execute_unprepared(&format!("DELETE FROM sqlite_sequence WHERE name = '{new}'"))
        .await?;
    db.execute_unprepared(&format!(
        "INSERT INTO sqlite_sequence (name, seq) \
         SELECT '{new}', seq FROM sqlite_sequence WHERE name = '{table}'"
    ))
    .await?;
    db.execute_unprepared(&format!("DROP TABLE \"{table}\""))
        .await?;
    db.execute_unprepared(&format!("ALTER TABLE \"{new}\" RENAME TO \"{table}\""))
        .await?;
    for index in indexes {
        db.execute_unprepared(&index).await?;
    }
    Ok(())
}

type Step<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>>;

/// Runs `step` in a transaction, with SQLite's foreign keys off around it, as its way of
/// making a table again needs. They're checked before it commits instead, and turned
/// back on whether it worked or not. The server's SQLite has one connection, so the
/// transaction is on the connection they were turned off for, which is checked too.
/// MySQL commits each change to a table as it's made, whatever the transaction.
async fn without_foreign_keys<F>(manager: &SchemaManager<'_>, step: F) -> Result<(), DbErr>
where
    F: for<'a> FnOnce(&'a SchemaManager<'static>) -> Step<'a>,
{
    let sqlite = manager.get_database_backend() == DatabaseBackend::Sqlite;
    let db = manager.get_connection();
    if sqlite {
        db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
    }
    let result = async {
        let transaction = manager.begin().await?;
        if sqlite {
            let on: i64 = one_value(transaction.get_connection(), "PRAGMA foreign_keys").await?;
            if on != 0 {
                return Err(DbErr::Migration(
                    "SQLite's foreign keys have to be off to make tables again".to_string(),
                ));
            }
        }
        step(&transaction).await?;
        if sqlite {
            let broken: Vec<String> =
                all_values(transaction.get_connection(), "PRAGMA foreign_key_check").await?;
            if !broken.is_empty() {
                return Err(DbErr::Migration(format!(
                    "rows in {} would break a foreign key",
                    broken.join(", ")
                )));
            }
        }
        transaction.commit().await
    }
    .await;
    if sqlite {
        db.execute_unprepared("PRAGMA foreign_keys = ON").await?;
    }
    result
}

/// One column of a row a query gave.
fn column<T: sea_orm::TryGetable>(row: &sea_orm::QueryResult, index: usize) -> Result<T, DbErr> {
    row.try_get_by_index(index)
        .map_err(|error| DbErr::Migration(error.to_string()))
}

/// The first column of the one row `sql` gives.
async fn one_value<T: sea_orm::TryGetable>(
    db: &impl ConnectionTrait,
    sql: &str,
) -> Result<T, DbErr> {
    let row = db
        .query_one_raw(Statement::from_string(db.get_database_backend(), sql))
        .await?
        .ok_or_else(|| DbErr::Migration(format!("no answer to {sql}")))?;
    row.try_get_by_index(0)
        .map_err(|error| DbErr::Migration(error.to_string()))
}

/// The first column of every row `sql` gives.
async fn all_values<T: sea_orm::TryGetable>(
    db: &impl ConnectionTrait,
    sql: &str,
) -> Result<Vec<T>, DbErr> {
    db.query_all_raw(Statement::from_string(db.get_database_backend(), sql))
        .await?
        .iter()
        .map(|row| {
            row.try_get_by_index(0)
                .map_err(|error| DbErr::Migration(error.to_string()))
        })
        .collect()
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
    FirstSeenAt,
    DecidedAt,
    AgentProtocol,
    AgentVersion,
    RefusedAt,
    RefuseReason,
}

#[derive(Iden)]
enum HostFacts {
    Table,
    Id,
    HostId,
    Name,
    Value,
    ValueType,
    ValidFrom,
    ValidTo,
}

#[derive(Iden)]
enum HostConfigStatus {
    Table,
    HostId,
    Version,
    Error,
    ReportedAt,
}

#[derive(Iden)]
enum HostBoots {
    Table,
    HostId,
    BootedAt,
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
    BuiltInChangedAt,
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
    SetupExpiresAt,
    TotpSecret,
    TotpEnabled,
    TotpLastStep,
    CreatedAt,
    LastSignInAt,
    DisabledAt,
}

#[derive(Iden)]
enum UserSessions {
    Table,
    Id,
    UserId,
    TokenHash,
    CreatedAt,
    ExpiresAt,
    LastUsedAt,
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
    CreatedAt,
    ExpiresAt,
    LastUsedAt,
    RevokedAt,
}

#[derive(Iden)]
enum RecoveryCodes {
    Table,
    Id,
    UserId,
    CodeHash,
    UsedAt,
}

#[derive(Iden)]
enum SignInChallenges {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
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
    DeletedAt,
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
    DeletedAt,
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
    Severity,
    HostId,
    Series,
    Value,
    Summary,
    StartedAt,
    BreachedAt,
    ResolvedAt,
    ResolveReason,
    ResolvedSummary,
    AcknowledgedBy,
    AcknowledgedAt,
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
    NextAttemptAt,
    LastError,
    CreatedAt,
    SentAt,
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
    StartsAt,
    EndsAt,
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
    CreatedAt,
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
    OccurredAt,
    Kind,
    Title,
    Detail,
    Filter,
    CreatedBy,
    CreatedAt,
}

#[derive(Iden)]
enum AuditLog {
    Table,
    Id,
    OccurredAt,
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
    AccessExpiresAt,
    RefreshHash,
    PreviousRefreshHash,
    RotatedAt,
    RefreshExpiresAt,
    CreatedAt,
    LastUsedAt,
    RevokedAt,
    LastAddress,
    LastForwardedFor,
}

#[derive(Iden)]
enum Proxies {
    Table,
    Id,
    Address,
    Trusted,
    CreatedAt,
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
    RequestedAt,
    TimeoutSecs,
    Outcome,
    ExitCode,
    Error,
    Output,
    Truncated,
    DurationMs,
    DurationSecs,
    FinishedAt,
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

    /// An empty database of its own on the server `MAXNINES_TEST_DATABASE_URL` names,
    /// or SQLite in memory.
    async fn empty() -> sea_orm::DatabaseConnection {
        match std::env::var("MAXNINES_TEST_DATABASE_URL") {
            Ok(server) => {
                let url = crate::models::fresh_test_database(&server).await;
                let options = ConnectOptions::new(url).max_connections(1).to_owned();
                Database::connect(options).await.unwrap()
            }
            Err(_) => fresh().await,
        }
    }

    /// Where a migration comes in the list.
    fn place(migration: &dyn MigrationName) -> u32 {
        let name = migration.name();
        let place = Migrator::migrations()
            .iter()
            .position(|each| each.name() == name)
            .unwrap_or_else(|| panic!("{name} isn't in the list"));
        <u32 as std::convert::TryFrom<usize>>::try_from(place).unwrap()
    }

    async fn applied(connection: &sea_orm::DatabaseConnection) -> u32 {
        let applied = Migrator::get_applied_migrations(connection).await.unwrap();
        <u32 as std::convert::TryFrom<usize>>::try_from(applied.len()).unwrap()
    }

    /// Runs the migrations up to and including `migration`, whatever comes after it.
    async fn up_to(connection: &sea_orm::DatabaseConnection, migration: &dyn MigrationName) {
        let steps = place(migration) + 1 - applied(connection).await;
        Migrator::up(connection, Some(steps)).await.unwrap();
    }

    /// Rolls back `migration` and everything after it, however many came after.
    async fn down_through(connection: &sea_orm::DatabaseConnection, migration: &dyn MigrationName) {
        let steps = applied(connection).await - place(migration);
        Migrator::down(connection, Some(steps)).await.unwrap();
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
        let connection = empty().await;
        Migrator::up(&connection, None).await.unwrap();

        let hosts = texts(&connection, "SELECT hostname FROM hosts ORDER BY id").await;
        assert_eq!(hosts, ["Fleet", "MaxNines server"]);
        let keyless = "SELECT id FROM hosts WHERE public_key IS NULL ORDER BY id";
        assert_eq!(texts(&connection, keyless).await, ["fleet", "server"]);
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
                "Host sending no metrics",
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
    async fn a_server_made_before_the_no_metrics_rule_gets_it_on_upgrading() {
        let connection = empty().await;
        Migrator::up(&connection, Some(1)).await.unwrap();
        Migrator::up(&connection, None).await.unwrap();

        let added = "SELECT kind FROM alert_rules
                     WHERE name = 'Host sending no metrics' AND for_secs = 300
                     AND severity = 'critical' AND enabled AND all_channels";
        assert_eq!(texts(&connection, added).await, ["no_metrics"]);
    }

    #[tokio::test]
    async fn a_rule_of_its_own_by_that_name_is_kept_instead() {
        let connection = empty().await;
        Migrator::up(&connection, Some(1)).await.unwrap();
        connection
            .execute_unprepared(
                "UPDATE alert_rules SET name = 'Host sending no metrics'
                 WHERE name = 'Clock is wrong'",
            )
            .await
            .unwrap();

        Migrator::up(&connection, None).await.unwrap();

        let named = "SELECT kind FROM alert_rules WHERE name = 'Host sending no metrics'";
        assert_eq!(texts(&connection, named).await, ["metric"]);
    }

    #[tokio::test]
    async fn the_tables_can_be_dropped_and_made_again() {
        let connection = empty().await;
        Migrator::up(&connection, None).await.unwrap();
        Migrator::down(&connection, None).await.unwrap();
        let tables = match connection.get_database_backend() {
            DatabaseBackend::Postgres => {
                "SELECT table_name::text FROM information_schema.tables
                 WHERE table_schema = current_schema()"
            }
            DatabaseBackend::MySql => {
                "SELECT CAST(table_name AS CHAR) FROM information_schema.tables
                 WHERE table_schema = DATABASE()"
            }
            _ => "SELECT name FROM sqlite_master WHERE type = 'table'",
        };
        let left: Vec<String> = texts(&connection, tables)
            .await
            .into_iter()
            .filter(|table| !["seaql_migrations", "sqlite_sequence"].contains(&table.as_str()))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        Migrator::up(&connection, None).await.unwrap();
    }

    #[tokio::test]
    async fn a_check_must_be_about_a_host() {
        let connection = fresh().await;
        Migrator::up(&connection, None).await.unwrap();
        let add = |name: &str, host: &str| {
            let key = crate::models::name_key(name);
            let sql = format!(
                "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs, enabled,
                     host_id)
                 VALUES ('{name}', '{key}', 'ping', 'example.com', 60, TRUE, '{host}')"
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

        // One with no host given is the server's.
        connection
            .execute_unprepared(
                "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs, enabled)
                 VALUES ('Site', 'site', 'http', 'https://example.com', 60, TRUE)",
            )
            .await
            .unwrap();
        let about = "SELECT host_id FROM remote_checks WHERE name = 'Site'";
        assert_eq!(texts(&connection, about).await, ["server"]);

        // A name only has to differ from the other checks about the same host, as
        // names are compared.
        add("Site", "abc").await.unwrap();
        assert!(add("Site", "abc").await.is_err(), "one to a host");
        assert!(add("SITE", "abc").await.is_err(), "whatever the case");
        assert!(add("Site", "server").await.is_err());

        // A host's checks go with it.
        let gone = "DELETE FROM hosts WHERE id = 'abc'";
        connection.execute_unprepared(gone).await.unwrap();
        let left = "SELECT host_id FROM remote_checks ORDER BY id";
        assert_eq!(texts(&connection, left).await, ["server"]);
    }

    async fn run(connection: &impl ConnectionTrait, sql: &str) {
        if let Err(error) = connection.execute_unprepared(sql).await {
            panic!("{sql}: {error}");
        }
    }

    async fn number(connection: &impl ConnectionTrait, sql: &str) -> i64 {
        let query = Statement::from_string(connection.get_database_backend(), sql);
        let row = connection.query_one_raw(query).await.unwrap().unwrap();
        row.try_get_by_index(0).unwrap()
    }

    async fn count(connection: &impl ConnectionTrait, table: &str) -> i64 {
        number(connection, &format!("SELECT COUNT(*) FROM {table}")).await
    }

    /// Something in every table a foreign key changes on, as a server before the
    /// keys and indexes migration kept it, with two rules and two channels sharing
    /// names, and a notification whose action run has gone.
    async fn fill_before_keys_and_indexes(connection: &impl ConnectionTrait) {
        // A moment every database reads.
        let at = "'2026-11-19 00:00:00+00:00'";
        for sql in [
            format!(
                "INSERT INTO hosts (id, kind, hostname, state, first_seen_at)
                 VALUES ('h1', 'agent', 'web', 'approved', {at})"
            ),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from)
                 VALUES ('h1', 'os.family', 'linux', 'string', {at})"
            ),
            format!(
                "INSERT INTO host_config_status (host_id, version, reported_at)
                 VALUES ('h1', 'v1', {at})"
            ),
            format!("INSERT INTO host_boots (host_id, booted_at) VALUES ('h1', {at})"),
            "INSERT INTO metrics_pages (host_id, url, interval_secs, enabled)
             VALUES ('h1', 'http://web/metrics', 60, TRUE)"
                .to_string(),
            "INSERT INTO remote_checks (name, kind, target, interval_secs, enabled, host_id)
             VALUES ('Ping', 'ping', 'web', 60, TRUE, 'h1')"
                .to_string(),
            format!(
                "INSERT INTO alert_rules (name, kind, for_secs, severity, enabled, deleted_at)
                 VALUES ('Twice', 'offline', 60, 'critical', TRUE, NULL),
                        ('Twice', 'offline', 60, 'critical', TRUE, NULL),
                        ('Gone', 'offline', 60, 'critical', TRUE, {at}),
                        ('Gone', 'offline', 60, 'critical', TRUE, NULL)"
            ),
            format!(
                "INSERT INTO notification_channels (name, kind, target, deleted_at)
                 VALUES ('Ops', 'webhook', 'http://ops', NULL),
                        ('Ops', 'webhook', 'http://ops', NULL),
                        ('Old', 'webhook', 'http://old', {at})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at)
                 VALUES (1, 'critical', 'h1', 'web is offline', {at}, {at}),
                        (1, 'critical', 'h1', 'deleted below', {at}, {at})"
            ),
            "DELETE FROM alerts WHERE id = 2".to_string(),
            format!(
                "INSERT INTO action_runs (host_id, alert_id, action, run_on, variables,
                     requested_at, timeout_secs, output, truncated)
                 VALUES ('h1', 1, 'restart', 'first', '{{}}', {at}, 60, '', FALSE)"
            ),
            format!(
                "INSERT INTO notifications (alert_id, channel_id, event, state, attempts,
                     next_attempt_at, created_at, action_run_id)
                 VALUES (1, 1, 'firing', 'sent', 1, {at}, {at}, NULL),
                        (1, 1, 'action', 'pending', 0, {at}, {at}, 1),
                        (1, 1, 'action', 'pending', 0, {at}, {at}, 99),
                        (1, 3, 'firing', 'sent', 1, {at}, {at}, NULL)"
            ),
            format!(
                "INSERT INTO users (email, name, created_at)
                 VALUES ('ann@example.com', 'Ann', {at})"
            ),
            format!(
                "INSERT INTO user_sessions (user_id, token_hash, created_at, expires_at)
                 VALUES (1, 'session', {at}, {at})"
            ),
            format!(
                "INSERT INTO api_keys (user_id, name, hint, token_hash, created_at)
                 VALUES (1, 'ci', 'mx_1', 'key', {at})"
            ),
            format!(
                "INSERT INTO app_sign_ins (user_id, client_id, role, access_hash,
                     access_expires_at, refresh_hash, refresh_expires_at, created_at)
                 VALUES (1, 'cli', 'admin', 'access', {at}, 'refresh', {at}, {at})"
            ),
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, 'code')".to_string(),
            format!(
                "INSERT INTO sign_in_challenges (user_id, token_hash, expires_at)
                 VALUES (1, 'challenge', {at})"
            ),
        ] {
            run(connection, &sql).await;
        }
    }

    /// Every table a host or user has rows in, with how many each has.
    const KEPT: [(&str, i64); 13] = [
        ("hosts", 3),
        ("host_facts", 1),
        ("host_config_status", 1),
        ("host_boots", 1),
        ("metrics_pages", 1),
        ("remote_checks", 1),
        ("alerts", 1),
        ("action_runs", 1),
        ("users", 1),
        ("user_sessions", 1),
        ("api_keys", 1),
        ("app_sign_ins", 1),
        ("recovery_codes", 1),
    ];

    async fn assert_kept(connection: &impl ConnectionTrait) {
        for (table, rows) in KEPT {
            assert_eq!(count(connection, table).await, rows, "{table}");
        }
        assert_eq!(count(connection, "sign_in_challenges").await, 1);
    }

    #[tokio::test]
    async fn keys_and_indexes_keep_what_was_there_and_are_enforced() {
        let connection = empty().await;
        Migrator::up(&connection, Some(2)).await.unwrap();
        fill_before_keys_and_indexes(&connection).await;
        Migrator::up(&connection, Some(1)).await.unwrap();

        assert_kept(&connection).await;
        let notifications = "SELECT event FROM notifications ORDER BY id";
        assert_eq!(
            texts(&connection, notifications).await,
            ["firing", "action", "firing"],
            "only the one whose action run had gone goes"
        );
        let rules = "SELECT name FROM alert_rules WHERE id > 8 ORDER BY id";
        assert_eq!(
            texts(&connection, rules).await,
            ["Twice", "Twice (10)", "Gone", "Gone"]
        );
        let channels = "SELECT name FROM notification_channels ORDER BY id";
        assert_eq!(
            texts(&connection, channels).await,
            ["Ops", "Ops (2)", "Old"]
        );
        // A deleted alert's ID isn't used again.
        run(
            &connection,
            "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at)
             SELECT rule_id, severity, host_id, summary, started_at, breached_at
             FROM alerts WHERE id = 1",
        )
        .await;
        assert_eq!(number(&connection, "SELECT MAX(id) FROM alerts").await, 3);
        run(&connection, "DELETE FROM alerts WHERE id = 3").await;

        // A name is used once among rules and channels that aren't deleted.
        let rule = |name: &str, deleted: &str| {
            format!(
                "INSERT INTO alert_rules (name, kind, for_secs, severity, enabled, deleted_at)
                 VALUES ('{name}', 'offline', 60, 'critical', TRUE, {deleted})"
            )
        };
        let at = "'2026-11-19 00:00:00+00:00'";
        assert!(
            connection
                .execute_unprepared(&rule("Twice", "NULL"))
                .await
                .is_err()
        );
        run(&connection, &rule("Twice", at)).await;
        run(&connection, &rule("Twice (2)", "NULL")).await;
        assert!(
            connection
                .execute_unprepared(
                    "INSERT INTO notification_channels (name, kind, target)
                     VALUES ('Ops', 'webhook', 'http://ops')"
                )
                .await
                .is_err()
        );
        run(
            &connection,
            "INSERT INTO notification_channels (name, kind, target)
             VALUES ('Old', 'webhook', 'http://old')",
        )
        .await;

        // A notification's action run has to be there, and a channel can't be
        // deleted while anything was sent through it.
        assert!(
            connection
                .execute_unprepared(&format!(
                    "INSERT INTO notifications (alert_id, channel_id, event, state, attempts,
                         next_attempt_at, created_at, action_run_id)
                     VALUES (1, 1, 'action', 'pending', 0, {at}, {at}, 99)"
                ))
                .await
                .is_err()
        );
        assert!(
            connection
                .execute_unprepared("DELETE FROM notification_channels WHERE id = 3")
                .await
                .is_err()
        );

        // Back down, everything is still there, and a host can't be deleted while
        // anything is kept about it.
        Migrator::down(&connection, Some(1)).await.unwrap();
        assert_kept(&connection).await;
        assert!(
            connection
                .execute_unprepared("DELETE FROM hosts WHERE id = 'h1'")
                .await
                .is_err()
        );
        assert!(
            connection
                .execute_unprepared("DELETE FROM users WHERE id = 1")
                .await
                .is_err()
        );
        run(&connection, &rule("Twice", "NULL")).await;
        run(&connection, "DELETE FROM alert_rules WHERE name = 'Twice'").await;

        // Up again, a host's or user's rows go with them, and an action run's
        // notifications with it.
        Migrator::up(&connection, Some(1)).await.unwrap();
        assert_kept(&connection).await;
        run(&connection, "DELETE FROM action_runs WHERE id = 1").await;
        assert_eq!(count(&connection, "notifications").await, 2);
        run(&connection, "DELETE FROM hosts WHERE id = 'h1'").await;
        run(&connection, "DELETE FROM users WHERE id = 1").await;
        for (table, _) in KEPT.iter().skip(1) {
            assert_eq!(count(&connection, table).await, 0, "{table}");
        }
        assert_eq!(count(&connection, "sign_in_challenges").await, 0);
        assert_eq!(count(&connection, "notifications").await, 0);
    }

    #[tokio::test]
    async fn a_live_name_made_for_a_repeat_is_never_one_already_taken() {
        let connection = empty().await;
        Migrator::up(&connection, Some(2)).await.unwrap();
        run(
            &connection,
            "INSERT INTO alert_rules (name, kind, for_secs, severity, enabled)
             VALUES ('Disk', 'offline', 60, 'critical', TRUE),
                    ('Disk (11)', 'offline', 60, 'critical', TRUE),
                    ('Disk', 'offline', 60, 'critical', TRUE)",
        )
        .await;

        Migrator::up(&connection, Some(1)).await.unwrap();

        let rules = "SELECT name FROM alert_rules WHERE id > 8 ORDER BY id";
        assert_eq!(
            texts(&connection, rules).await,
            ["Disk", "Disk (11)", "Disk (11, 2)"]
        );
    }

    /// A server before names were compared ignoring case and the spaces around them,
    /// with names that are the same but for those, facts that are current twice and
    /// alerts open twice. MySQL already compared case, by its collation, but not
    /// spaces before a name.
    async fn fill_before_names_and_uniqueness(connection: &impl ConnectionTrait) {
        let at = "'2026-11-19 00:00:00+00:00'";
        let later = "'2026-11-19 00:01:00+00:00'";
        for sql in [
            format!(
                "INSERT INTO hosts (id, kind, hostname, state, first_seen_at)
                 VALUES ('h1', 'agentless', 'web', 'approved', {at})"
            ),
            format!(
                "INSERT INTO alert_rules (name, kind, for_secs, severity, enabled, deleted_at)
                 VALUES ('Disk', 'offline', 60, 'critical', TRUE, NULL),
                        (' disk', 'offline', 60, 'critical', TRUE, NULL),
                        ('disk (10)', 'offline', 60, 'critical', TRUE, NULL),
                        ('DISK', 'offline', 60, 'critical', TRUE, {at})"
            ),
            "INSERT INTO notification_channels (name, kind, target)
             VALUES ('Ops', 'webhook', 'http://ops'), (' OPS', 'webhook', 'http://ops')"
                .to_string(),
            "INSERT INTO config_rules (name, priority, enabled) VALUES (' default', 1, TRUE)"
                .to_string(),
            "INSERT INTO remote_checks (name, kind, target, interval_secs, enabled, host_id)
             VALUES ('Ping', 'ping', 'web', 60, TRUE, 'h1'),
                    (' PING', 'ping', 'web', 60, TRUE, 'h1'),
                    ('ping', 'ping', 'web', 60, TRUE, 'server')"
                .to_string(),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from)
                 VALUES ('h1', 'os.family', 'linux', 'string', {at}),
                        ('h1', 'os.family', 'bsd', 'string', {later}),
                        ('h1', 'OS.family', 'linux', 'string', {at})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, series, summary, started_at,
                     breached_at)
                 VALUES (9, 'critical', 'h1', NULL, 'first', {at}, {at}),
                        (9, 'critical', 'h1', NULL, 'again', {later}, {later}),
                        (9, 'critical', 'h1', '/', 'a disk', {at}, {at}),
                        (9, 'critical', 'h1', '/data', 'a disk', {at}, {at}),
                        (9, 'critical', 'h1', '/Data', 'another', {at}, {at})"
            ),
        ] {
            run(connection, &sql).await;
        }
    }

    #[tokio::test]
    async fn names_and_uniqueness_keep_what_was_there_and_are_enforced() {
        let connection = empty().await;
        Migrator::up(&connection, Some(3)).await.unwrap();
        fill_before_names_and_uniqueness(&connection).await;
        Migrator::up(&connection, Some(1)).await.unwrap();

        let rules = "SELECT name FROM alert_rules WHERE id > 8 ORDER BY id";
        assert_eq!(
            texts(&connection, rules).await,
            ["Disk", " disk (10, 2)", "disk (10)", "DISK"],
            "a repeat gets its ID, and more when that's taken, and deleted ones don't count"
        );
        let keys = "SELECT name_key FROM alert_rules WHERE id > 8 ORDER BY id";
        assert_eq!(
            texts(&connection, keys).await,
            ["disk", "disk (10, 2)", "disk (10)", "disk"]
        );
        let channels = "SELECT name FROM notification_channels ORDER BY id";
        assert_eq!(texts(&connection, channels).await, ["Ops", " OPS (2)"]);
        let rules = "SELECT name FROM config_rules ORDER BY id";
        assert_eq!(texts(&connection, rules).await, ["Default", " default (2)"]);
        let checks = "SELECT name FROM remote_checks ORDER BY id";
        assert_eq!(
            texts(&connection, checks).await,
            ["Ping", " PING (2)", "ping"],
            "each host's names are its own"
        );
        let current = "SELECT value FROM host_facts WHERE valid_to IS NULL ORDER BY id";
        assert_eq!(
            texts(&connection, current).await,
            ["bsd", "linux"],
            "the value said last stays current, and a name differing in case is another fact"
        );
        let open = "SELECT summary FROM alerts WHERE resolved_at IS NULL ORDER BY id";
        assert_eq!(
            texts(&connection, open).await,
            ["first", "a disk", "a disk", "another"]
        );

        // Each is enforced, whatever the case.
        let at = "'2026-11-19 00:00:00+00:00'";
        let refused = [
            "INSERT INTO alert_rules (name, name_key, kind, for_secs, severity, enabled)
             VALUES ('DISK', 'disk', 'offline', 60, 'critical', TRUE)"
                .to_string(),
            "INSERT INTO notification_channels (name, name_key, kind, target)
             VALUES ('ops', 'ops', 'webhook', 'http://ops')"
                .to_string(),
            "INSERT INTO config_rules (name, name_key, priority, enabled)
             VALUES ('DEFAULT', 'default', 1, TRUE)"
                .to_string(),
            "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs, enabled,
                 host_id)
             VALUES ('ping', 'ping', 'ping', 'web', 60, TRUE, 'h1')"
                .to_string(),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from)
                 VALUES ('h1', 'os.family', 'linux', 'string', {at})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at)
                 VALUES (9, 'critical', 'h1', 'third', {at}, {at})"
            ),
        ];
        for sql in &refused {
            assert!(connection.execute_unprepared(sql).await.is_err(), "{sql}");
        }
        for sql in [
            format!(
                "INSERT INTO alert_rules (name, name_key, kind, for_secs, severity, enabled,
                     deleted_at)
                 VALUES ('DISK', 'disk', 'offline', 60, 'critical', TRUE, {at})"
            ),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from, valid_to)
                 VALUES ('h1', 'os.family', 'linux', 'string', {at}, {at})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at,
                     resolved_at)
                 VALUES (9, 'critical', 'h1', 'over', {at}, {at}, {at})"
            ),
        ] {
            run(&connection, &sql).await;
        }

        // Back down and up again, everything is still there.
        Migrator::down(&connection, Some(1)).await.unwrap();
        assert_eq!(count(&connection, "remote_checks").await, 3);
        Migrator::up(&connection, Some(1)).await.unwrap();
        assert_eq!(texts(&connection, open).await.len(), 4);
    }

    /// MySQL commits each change to a table as it's made, so a migration that stopped
    /// before it was recorded runs again over what it already did. Each of its steps
    /// leaves alone what's already done, which this tries at its hardest: all of it.
    #[tokio::test]
    async fn on_mysql_a_migration_that_stopped_carries_on_when_run_again() {
        let connection = empty().await;
        if connection.get_database_backend() != DatabaseBackend::MySql {
            return;
        }
        Migrator::up(&connection, Some(2)).await.unwrap();
        fill_before_keys_and_indexes(&connection).await;
        keys_and_indexes_up(&SchemaManager::new(&connection))
            .await
            .unwrap();
        Migrator::up(&connection, Some(1)).await.unwrap();
        assert_kept(&connection).await;

        let connection = empty().await;
        Migrator::up(&connection, Some(3)).await.unwrap();
        fill_before_names_and_uniqueness(&connection).await;
        names_and_uniqueness_up(&SchemaManager::new(&connection))
            .await
            .unwrap();
        Migrator::up(&connection, None).await.unwrap();
        let channels = "SELECT name FROM notification_channels ORDER BY id";
        assert_eq!(texts(&connection, channels).await, ["Ops", " OPS (2)"]);

        let manager = SchemaManager::new(&connection);
        ExactFactsAndEndedAlerts.up(&manager).await.unwrap();
        let indexed = "SELECT CAST(column_name AS CHAR) FROM information_schema.statistics
                       WHERE table_schema = DATABASE() AND index_name = 'idx_alerts_resolved'
                       ORDER BY seq_in_index";
        assert_eq!(texts(&connection, indexed).await, ["resolved_at", "id"]);
    }

    #[tokio::test]
    async fn how_long_an_action_ran_is_kept_in_seconds_going_up_and_down() {
        let connection = empty().await;
        up_to(&connection, &ExactFactsAndEndedAlerts).await;
        let at = "'2026-11-19 00:00:00+00:00'";
        run(
            &connection,
            &format!(
                "INSERT INTO hosts (id, kind, hostname, state, first_seen_at)
                 VALUES ('h1', 'agent', 'web', 'approved', {at})"
            ),
        )
        .await;
        for duration in ["1500", "NULL"] {
            run(
                &connection,
                &format!(
                    "INSERT INTO action_runs (host_id, action, run_on, variables, requested_at,
                         timeout_secs, output, truncated, duration_ms)
                     VALUES ('h1', 'restart', 'manual', '{{}}', {at}, 30, '', FALSE, {duration})"
                ),
            )
            .await;
        }

        Migrator::up(&connection, None).await.unwrap();
        let seconds = "SELECT CAST(duration_secs * 1000 AS CHAR(20)) FROM action_runs
                       WHERE duration_secs IS NOT NULL";
        let seconds = match connection.get_database_backend() {
            DatabaseBackend::MySql => seconds.to_string(),
            _ => seconds.replace("CHAR(20)", "TEXT"),
        };
        let kept: Vec<f64> = texts(&connection, &seconds)
            .await
            .iter()
            .map(|text| text.parse().unwrap())
            .collect();
        assert_eq!(kept, [1500.0]);
        let empty = "SELECT COUNT(*) FROM action_runs WHERE duration_secs IS NULL";
        assert_eq!(number(&connection, empty).await, 1);

        // Running it again where MySQL stopped partway changes nothing more.
        if connection.get_database_backend() == DatabaseBackend::MySql {
            DurationsInSeconds
                .up(&SchemaManager::new(&connection))
                .await
                .unwrap();
        }
        down_through(&connection, &DurationsInSeconds).await;
        let ms = "SELECT duration_ms FROM action_runs WHERE duration_ms IS NOT NULL";
        assert_eq!(number(&connection, ms).await, 1500);
    }

    #[tokio::test]
    async fn what_an_agent_said_in_its_hello_is_kept_with_its_host() {
        let connection = empty().await;
        up_to(&connection, &DurationsInSeconds).await;
        let at = "'2026-11-20 00:00:00+00:00'";
        run(
            &connection,
            &format!(
                "INSERT INTO hosts (id, kind, hostname, state, first_seen_at)
                 VALUES ('h1', 'agent', 'web', 'approved', {at})"
            ),
        )
        .await;

        Migrator::up(&connection, None).await.unwrap();
        let empty = "SELECT COUNT(*) FROM hosts WHERE id = 'h1' AND agent_protocol IS NULL
                     AND agent_version IS NULL AND refused_at IS NULL AND refuse_reason IS NULL";
        assert_eq!(number(&connection, empty).await, 1);
        run(
            &connection,
            &format!(
                "UPDATE hosts SET agent_protocol = 0, agent_version = '0.1.0',
                     refused_at = {at}, refuse_reason = 'Upgrade the agent.'
                 WHERE id = 'h1'"
            ),
        )
        .await;
        let reason = "SELECT refuse_reason FROM hosts WHERE id = 'h1'";
        assert_eq!(texts(&connection, reason).await, ["Upgrade the agent."]);

        // Running it again where MySQL stopped partway changes nothing more.
        if connection.get_database_backend() == DatabaseBackend::MySql {
            AgentHellos
                .up(&SchemaManager::new(&connection))
                .await
                .unwrap();
        }
        down_through(&connection, &AgentHellos).await;
        assert_eq!(count(&connection, "hosts").await, 3);
        Migrator::up(&connection, None).await.unwrap();
        assert_eq!(number(&connection, empty).await, 1);
    }
}
