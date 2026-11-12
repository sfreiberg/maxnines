//! The main database's tables, made by one migration: what `database/README.md`
//! draws. A change to a table is a new migration after this one, with the README
//! changed to match.

use sea_orm::{DbBackend, Statement};
use sea_orm_migration::prelude::*;

pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(CreateTables),
            Box::new(SoftDeleteRulesAndChannels),
            Box::new(Actions),
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

struct CreateTables;

impl MigrationName for CreateTables {
    fn name(&self) -> &str {
        "m20261111_000001_create_tables"
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
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_keys_user_id")
                            .from(ApiKeys::Table, ApiKeys::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await?;
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
                            .not_null()
                            .unique_key(),
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
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AlertRules::Table)
                    .col(id(AlertRules::Id))
                    .col(
                        ColumnDef::new(AlertRules::Name)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
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
                    .table(RemoteChecks::Table)
                    .col(id(RemoteChecks::Id))
                    .col(
                        ColumnDef::new(RemoteChecks::Name)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
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

        add_built_ins(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "server_secrets",
            "server_settings",
            "audit_log",
            "events",
            "location_rules",
            "dashboard_variables",
            "dashboard_widgets",
            "dashboards",
            "remote_checks",
            "maintenance_windows",
            "silences",
            "notifications",
            "alerts",
            "alert_rule_channels",
            "alert_rules",
            "notification_channels",
            "sign_in_challenges",
            "recovery_codes",
            "api_keys",
            "user_sessions",
            "users",
            "config_rule_settings",
            "config_rules",
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

const BUILT_IN_RULES: [BuiltInRule; 5] = [
    BuiltInRule {
        name: "Host offline",
        kind: "offline",
        metric: None,
        comparison: None,
        threshold: None,
        warning_threshold: None,
        for_secs: 300,
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
        for_secs: 300,
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
];

async fn add_built_ins(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let mut hosts = Query::insert()
        .into_table(Hosts::Table)
        .columns([
            Hosts::Id,
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

    for rule in BUILT_IN_RULES {
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
        manager.exec_stmt(insert).await?;
    }
    Ok(())
}

#[derive(Iden)]
enum Hosts {
    Table,
    Id,
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
}

#[derive(Iden)]
enum ApiKeys {
    Table,
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
}

#[derive(Iden)]
enum Silences {
    Table,
    Id,
    RuleId,
    Filter,
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

struct SoftDeleteRulesAndChannels;

impl MigrationName for SoftDeleteRulesAndChannels {
    fn name(&self) -> &str {
        "m20261111_000002_soft_delete_rules_and_channels"
    }
}

/// Alert rules and notification channels are marked deleted instead of going, so an
/// alert still says which rule raised it and a notification where it was sent. A
/// deleted one's name is free to use again, so the server checks names are unique
/// among those left, not the database. SQLite can only drop a unique constraint by
/// making the table again, and as other tables point at these two, that has to be
/// done with foreign keys switched off, which SQLite only allows outside a
/// transaction. Its pool has a single connection, so the switch holds for every
/// step.
#[async_trait::async_trait]
impl MigrationTrait for SoftDeleteRulesAndChannels {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => {
                remake_on_sqlite(
                    manager,
                    &[
                        (
                            "alert_rules",
                            alert_rules_after_soft_delete(),
                            ALERT_RULE_COLUMNS,
                        ),
                        (
                            "notification_channels",
                            notification_channels_after_soft_delete(),
                            CHANNEL_COLUMNS,
                        ),
                    ],
                )
                .await
            }
            backend => {
                for table in ["alert_rules", "notification_channels"] {
                    let unique = if backend == sea_orm::DatabaseBackend::MySql {
                        format!("ALTER TABLE {table} DROP INDEX name")
                    } else {
                        format!("ALTER TABLE {table} DROP CONSTRAINT {table}_name_key")
                    };
                    connection.execute_unprepared(&unique).await?;
                    manager
                        .alter_table(
                            Table::alter()
                                .table(Alias::new(table))
                                .add_column(ColumnDef::new(Alias::new("deleted_ms")).big_integer())
                                .to_owned(),
                        )
                        .await?;
                }
                Ok(())
            }
        }
    }

    /// Deleted ones go for good, as there's nowhere to keep them.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared(
                "DELETE FROM alert_rule_channels WHERE rule_id IN \
                 (SELECT id FROM alert_rules WHERE deleted_ms IS NOT NULL)",
            )
            .await?;
        connection
            .execute_unprepared(
                "UPDATE alerts SET rule_id = NULL WHERE rule_id IN \
                 (SELECT id FROM alert_rules WHERE deleted_ms IS NOT NULL)",
            )
            .await?;
        for table in ["silences", "maintenance_windows"] {
            connection
                .execute_unprepared(&format!(
                    "DELETE FROM {table} WHERE rule_id IN \
                     (SELECT id FROM alert_rules WHERE deleted_ms IS NOT NULL)"
                ))
                .await?;
        }
        connection
            .execute_unprepared(
                "DELETE FROM notifications WHERE channel_id IN \
                 (SELECT id FROM notification_channels WHERE deleted_ms IS NOT NULL)",
            )
            .await?;
        for table in ["alert_rules", "notification_channels"] {
            connection
                .execute_unprepared(&format!("DELETE FROM {table} WHERE deleted_ms IS NOT NULL"))
                .await?;
        }
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            return remake_on_sqlite(
                manager,
                &[
                    (
                        "alert_rules",
                        alert_rules_before_soft_delete(),
                        ALERT_RULE_COLUMNS,
                    ),
                    (
                        "notification_channels",
                        notification_channels_before_soft_delete(),
                        CHANNEL_COLUMNS,
                    ),
                ],
            )
            .await;
        }
        for table in ["alert_rules", "notification_channels"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new("deleted_ms"))
                        .to_owned(),
                )
                .await?;
            let unique = if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
                format!("ALTER TABLE {table} ADD UNIQUE INDEX name (name)")
            } else {
                format!("ALTER TABLE {table} ADD CONSTRAINT {table}_name_key UNIQUE (name)")
            };
            connection.execute_unprepared(&unique).await?;
        }
        Ok(())
    }
}

/// The columns both versions of each table have, to copy from one to the other.
const ALERT_RULE_COLUMNS: &str = "id, name, kind, metric, series, comparison, threshold, \
     warning_threshold, for_secs, severity, condition_expr, enabled, all_channels, \
     calculation, group_by, filter, window_secs, remind_every_secs, forecast_secs, \
     warning_forecast_secs";
const CHANNEL_COLUMNS: &str = "id, name, kind, target, credential, app_token, \
     sends_warnings, sends_critical, mail_from, mail_hostname, mail_port, mail_security, \
     mail_username, request_method, request_content_type, request_body";

/// Makes each table again as given on SQLite, keeping its rows and the next ID it
/// would give, with foreign keys off so tables pointing at it are left alone, then
/// checks nothing points anywhere it shouldn't before keeping the result. This is
/// the order SQLite's own documentation gives for changes ALTER TABLE can't make.
async fn remake_on_sqlite(
    manager: &SchemaManager<'_>,
    tables: &[(&str, TableCreateStatement, &str)],
) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    connection
        .execute_unprepared("PRAGMA foreign_keys = OFF")
        .await?;
    let remade = async {
        connection.execute_unprepared("BEGIN").await?;
        for (table, create, columns) in tables {
            let made = format!("{table}_remade");
            let mut create = create.clone();
            create.table(Alias::new(&made));
            manager.create_table(create).await?;
            connection
                .execute_unprepared(&format!(
                    "INSERT INTO {made} ({columns}) SELECT {columns} FROM {table}"
                ))
                .await?;
            let next = format!("SELECT seq FROM sqlite_sequence WHERE name = '{table}'");
            let seq: Option<i64> = connection
                .query_one_raw(Statement::from_string(DbBackend::Sqlite, next))
                .await?
                .map(|row| row.try_get_by_index(0))
                .transpose()?;
            connection
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
            connection
                .execute_unprepared(&format!("ALTER TABLE {made} RENAME TO {table}"))
                .await?;
            if let Some(seq) = seq {
                connection
                    .execute_unprepared(&format!(
                        "UPDATE sqlite_sequence SET seq = max(seq, {seq}) WHERE name = '{table}'"
                    ))
                    .await?;
            }
        }
        let broken = connection
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check",
            ))
            .await?;
        if !broken.is_empty() {
            return Err(DbErr::Migration(format!(
                "{} rows would point at nothing",
                broken.len()
            )));
        }
        connection.execute_unprepared("COMMIT").await?;
        Ok(())
    }
    .await;
    if remade.is_err() {
        connection.execute_unprepared("ROLLBACK").await.ok();
    }
    connection
        .execute_unprepared("PRAGMA foreign_keys = ON")
        .await?;
    remade
}

/// `alert_rules` as migration 1 made it, for going back on SQLite.
fn alert_rules_before_soft_delete() -> TableCreateStatement {
    Table::create()
        .table(AlertRules::Table)
        .col(id(AlertRules::Id))
        .col(
            ColumnDef::new(AlertRules::Name)
                .string_len(255)
                .not_null()
                .unique_key(),
        )
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
        .to_owned()
}

/// `notification_channels` as migration 1 made it, for going back on SQLite.
fn notification_channels_before_soft_delete() -> TableCreateStatement {
    Table::create()
        .table(NotificationChannels::Table)
        .col(id(NotificationChannels::Id))
        .col(
            ColumnDef::new(NotificationChannels::Name)
                .string_len(255)
                .not_null()
                .unique_key(),
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
        .to_owned()
}

/// `alert_rules` as it is after migration 2, for making it again on SQLite.
fn alert_rules_after_soft_delete() -> TableCreateStatement {
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
        .to_owned()
}

/// `notification_channels` as it is after migration 2, for making it again on SQLite.
fn notification_channels_after_soft_delete() -> TableCreateStatement {
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
        .to_owned()
}

struct Actions;

impl MigrationName for Actions {
    fn name(&self) -> &str {
        "m20261111_000003_actions"
    }
}

/// Actions: what each alert rule asks a host to run, and every time one was asked
/// for, by an alert or by a person, with what it printed.
#[async_trait::async_trait]
impl MigrationTrait for Actions {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["action_runs", "alert_rule_actions"] {
            manager
                .drop_table(Table::drop().table(Alias::new(table)).to_owned())
                .await?;
        }
        Ok(())
    }
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
    async fn rules_and_channels_keep_their_rows_and_references_through_soft_delete() {
        let connection = fresh().await;
        Migrator::up(&connection, Some(1)).await.unwrap();
        connection
            .execute_unprepared(
                "INSERT INTO notification_channels
                   (id, name, kind, target, sends_warnings, sends_critical)
                 VALUES (7, 'Ops', 'webhook', 'https://ops', TRUE, TRUE);
                 INSERT INTO alert_rule_channels (rule_id, channel_id) VALUES (1, 7);
                 INSERT INTO alerts (id, rule_id, rule_name, severity, host_id, hostname,
                                     series, summary, started_ms)
                 VALUES (3, 1, 'Host offline', 'critical', 'server', 'MaxNines server',
                         '', 'Gone', 1);
                 INSERT INTO notifications (alert_id, channel_id, event, state, attempts,
                                            next_attempt_ms, created_ms)
                 VALUES (3, 7, 'firing', 'sent', 1, 1, 1)",
            )
            .await
            .unwrap();

        Migrator::up(&connection, None).await.unwrap();

        let count = |sql: &'static str| {
            let connection = &connection;
            async move { texts(connection, sql).await }
        };
        assert_eq!(
            count("SELECT name FROM notification_channels").await,
            ["Ops"]
        );
        assert_eq!(
            count("SELECT CAST(rule_id AS TEXT) FROM alerts").await,
            ["1"]
        );
        assert_eq!(count("SELECT event FROM notifications").await, ["firing"]);
        let links = "SELECT CAST(channel_id AS TEXT) FROM alert_rule_channels";
        assert_eq!(count(links).await, ["7"]);
        // Names needn't be unique now, and references are still checked.
        connection
            .execute_unprepared(
                "UPDATE notification_channels SET deleted_ms = 5;
                 INSERT INTO notification_channels
                   (name, kind, target, sends_warnings, sends_critical)
                 VALUES ('Ops', 'webhook', 'https://new', TRUE, TRUE)",
            )
            .await
            .unwrap();
        let dangling = "INSERT INTO alert_rule_channels (rule_id, channel_id) VALUES (1, 99)";
        assert!(connection.execute_unprepared(dangling).await.is_err());
        let next = "SELECT CAST(max(id) AS TEXT) FROM notification_channels";
        assert_eq!(
            count(next).await,
            ["8"],
            "IDs carry on from where they were"
        );

        // The actions migration after it, then this one.
        Migrator::down(&connection, Some(2)).await.unwrap();
        assert_eq!(
            count("SELECT target FROM notification_channels").await,
            ["https://new"]
        );
        assert!(count("SELECT event FROM notifications").await.is_empty());
        let twice = "INSERT INTO notification_channels
                       (name, kind, target, sends_warnings, sends_critical)
                     VALUES ('Ops', 'webhook', 'https://x', TRUE, TRUE)";
        assert!(
            connection.execute_unprepared(twice).await.is_err(),
            "unique again"
        );
    }
}
