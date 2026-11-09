//! The main database's schema, as a few migrations that each create the tables
//! for one part of the server. Applied ones are recorded in the database, so once
//! a migration has shipped it's never edited: a change goes in a new one instead.
//!
//! Times are milliseconds since the Unix epoch, in columns ending in `_ms`.

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(CreateAgents),
            Box::new(CreateConfigRules),
            Box::new(CreateUsers),
            Box::new(CreateAlerting),
            Box::new(CreateRemoteChecks),
            Box::new(CreateDashboards),
            Box::new(CreateLocationRules),
            Box::new(AddUserTimeZones),
            Box::new(AddBuiltInAlerts),
            Box::new(AddBuiltInDiskAlerts),
            Box::new(AddWarningThresholds),
            Box::new(AddChannelSeverities),
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

async fn drop_tables(manager: &SchemaManager<'_>, tables: &[&str]) -> Result<(), DbErr> {
    for table in tables {
        manager
            .drop_table(Table::drop().table(Alias::new(*table)).to_owned())
            .await?;
    }
    Ok(())
}

// ---- Agents

struct CreateAgents;

impl MigrationName for CreateAgents {
    fn name(&self) -> &str {
        "m20261108_000001_create_agents"
    }
}

#[derive(Iden)]
enum Agents {
    Table,
    /// A hash of the agent's public key, which is its identity. Names aren't unique.
    Id,
    PublicKey,
    Host,
    State,
    /// Who approved it: "admin", someone's address, or "rule:<name>".
    DecidedBy,
    FirstSeenMs,
    DecidedAtMs,
}

#[derive(Iden)]
enum AgentFacts {
    Table,
    Id,
    AgentId,
    Name,
    Value,
    ValueType,
    ValidFromMs,
    ValidToMs,
}

#[derive(Iden)]
enum AgentConfigStatus {
    Table,
    AgentId,
    Version,
    Error,
    ReportedAtMs,
}

/// Two agents that aren't machines. The server records its own checks under
/// `server`, and alerts about the machines as a whole belong to `fleet`. No key
/// hashes to either ID, as real ones are 32 hex characters, so nothing can
/// connect as them.
const BUILT_IN_AGENTS: &str = "
    INSERT INTO agents (id, public_key, host, state, decided_by, first_seen_ms)
    VALUES ('server', '', 'MaxNines server', 'approved', 'built-in', 0),
           ('fleet', '', 'Fleet', 'approved', 'built-in', 0)
";

/// Agents and what they report about themselves. A fact is one row per value it
/// has had, with `valid_to_ms` empty for the current one, so one table answers
/// what's true now and what was true before.
#[async_trait::async_trait]
impl MigrationTrait for CreateAgents {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Agents::Table)
                    .col(
                        ColumnDef::new(Agents::Id)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Agents::PublicKey).string_len(64).not_null())
                    .col(ColumnDef::new(Agents::Host).string_len(255).not_null())
                    .col(ColumnDef::new(Agents::State).string_len(16).not_null())
                    .col(ColumnDef::new(Agents::DecidedBy).text())
                    .col(ColumnDef::new(Agents::FirstSeenMs).big_integer().not_null())
                    .col(ColumnDef::new(Agents::DecidedAtMs).big_integer())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AgentFacts::Table)
                    .col(id(AgentFacts::Id))
                    .col(
                        ColumnDef::new(AgentFacts::AgentId)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AgentFacts::Name).string_len(255).not_null())
                    .col(ColumnDef::new(AgentFacts::Value).string_len(255).not_null())
                    .col(
                        ColumnDef::new(AgentFacts::ValueType)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AgentFacts::ValidFromMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AgentFacts::ValidToMs).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .from(AgentFacts::Table, AgentFacts::AgentId)
                            .to(Agents::Table, Agents::Id),
                    )
                    .to_owned(),
            )
            .await?;
        // Reading one agent's facts.
        manager
            .create_index(
                Index::create()
                    .name("idx_agent_facts_agent")
                    .table(AgentFacts::Table)
                    .col(AgentFacts::AgentId)
                    .col(AgentFacts::ValidToMs)
                    .to_owned(),
            )
            .await?;
        // Finding agents by a fact, such as every machine on one OS version.
        manager
            .create_index(
                Index::create()
                    .name("idx_agent_facts_name_value")
                    .table(AgentFacts::Table)
                    .col(AgentFacts::Name)
                    .col(AgentFacts::Value)
                    .to_owned(),
            )
            .await?;

        // What each agent last said about the config it was sent.
        manager
            .create_table(
                Table::create()
                    .table(AgentConfigStatus::Table)
                    .col(
                        ColumnDef::new(AgentConfigStatus::AgentId)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AgentConfigStatus::Version)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AgentConfigStatus::Error).text())
                    .col(
                        ColumnDef::new(AgentConfigStatus::ReportedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(AgentConfigStatus::Table, AgentConfigStatus::AgentId)
                            .to(Agents::Table, Agents::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(BUILT_IN_AGENTS)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(manager, &["agent_config_status", "agent_facts", "agents"]).await
    }
}

// ---- Config rules

struct CreateConfigRules;

impl MigrationName for CreateConfigRules {
    fn name(&self) -> &str {
        "m20261108_000002_create_config_rules"
    }
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

/// What a new install monitors until someone changes it.
const DEFAULT_RULE: &str = "
    INSERT INTO config_rules (name, priority, enabled) VALUES ('Default', 0, TRUE)
";
const DEFAULT_SETTINGS: [(&str, &str, &str); 7] = [
    ("interval_secs", "15", "number"),
    ("facts_interval_secs", "3600", "number"),
    ("collectors.host.enabled", "true", "boolean"),
    ("collectors.cpu.enabled", "true", "boolean"),
    ("collectors.memory.enabled", "true", "boolean"),
    ("collectors.disk.enabled", "true", "boolean"),
    ("collectors.network.enabled", "true", "boolean"),
];

/// Rules that choose each agent's settings from its facts. Settings are stored
/// flat, one row per leaf, so any shape of setting works without a schema change.
#[async_trait::async_trait]
impl MigrationTrait for CreateConfigRules {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

        let connection = manager.get_connection();
        connection.execute_unprepared(DEFAULT_RULE).await?;
        for (name, value, value_type) in DEFAULT_SETTINGS {
            connection
                .execute_unprepared(&format!(
                    "INSERT INTO config_rule_settings (rule_id, name, value, value_type)
                     SELECT id, '{name}', '{value}', '{value_type}'
                     FROM config_rules WHERE name = 'Default'"
                ))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(manager, &["config_rule_settings", "config_rules"]).await
    }
}

// ---- Users, API keys and the server's own secrets

struct CreateUsers;

impl MigrationName for CreateUsers {
    fn name(&self) -> &str {
        "m20261108_000003_create_users"
    }
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
    Email,
    Name,
    /// Empty until the setup link is used, or for ways of signing in without one.
    PasswordHash,
    Theme,
    SetupTokenHash,
    SetupExpiresMs,
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
    Name,
    /// The start of the key, to recognize it by.
    Hint,
    TokenHash,
    CreatedMs,
    /// Empty means it never expires.
    ExpiresMs,
    LastUsedMs,
    RevokedMs,
}

#[derive(Iden)]
enum ServerSecrets {
    Table,
    Name,
    Value,
}

/// People who can sign in, their sessions, keys for the API, and what the server
/// generates for itself, such as the CSRF key. Sessions, setup links and API keys
/// are only ever stored as hashes. Revoked keys stay, to show what existed and
/// when it stopped.
#[async_trait::async_trait]
impl MigrationTrait for CreateUsers {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                        ColumnDef::new(Users::Theme)
                            .string_len(20)
                            .not_null()
                            .default("carbon"),
                    )
                    .col(
                        ColumnDef::new(Users::SetupTokenHash)
                            .string_len(64)
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::SetupExpiresMs).big_integer())
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
                    .col(ColumnDef::new(ApiKeys::Name).string_len(100).not_null())
                    .col(ColumnDef::new(ApiKeys::Hint).string_len(16).not_null())
                    .col(
                        ColumnDef::new(ApiKeys::TokenHash)
                            .string_len(64)
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(ApiKeys::CreatedMs).big_integer().not_null())
                    .col(ColumnDef::new(ApiKeys::ExpiresMs).big_integer())
                    .col(ColumnDef::new(ApiKeys::LastUsedMs).big_integer())
                    .col(ColumnDef::new(ApiKeys::RevokedMs).big_integer())
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(
            manager,
            &["server_secrets", "api_keys", "user_sessions", "users"],
        )
        .await
    }
}

// ---- Alerting

struct CreateAlerting;

impl MigrationName for CreateAlerting {
    fn name(&self) -> &str {
        "m20261108_000004_create_alerting"
    }
}

#[derive(Iden)]
enum AlertRules {
    Table,
    Id,
    Name,
    /// metric, offline or calculation.
    Kind,
    Metric,
    /// Which of a metric's series to watch, as a pattern. Empty for all of them.
    Series,
    Comparison,
    Threshold,
    /// How long the condition has to hold before the alert fires, and clears.
    ForSecs,
    Severity,
    /// Which agents the rule applies to, as a CEL expression over their facts.
    ConditionExpr,
    Enabled,
    /// For a calculation across machines: what to work out, what gets a line of
    /// its own, which machines, and how far back to look.
    Calculation,
    GroupBy,
    Filter,
    WindowSecs,
    /// How often to repeat while firing and unacknowledged. Empty means never.
    RemindEverySecs,
}

#[derive(Iden)]
enum NotificationChannels {
    Table,
    Id,
    Name,
    Kind,
    /// A webhook's URL, email addresses, a Slack channel, a PagerDuty key, an
    /// AlertOps or SIGNL4 URL, or a Telegram chat. Write-only, as it's often a secret.
    Target,
    /// A bot token, for Slack and Telegram. Write-only.
    Credential,
    /// A Slack app-level token, for hearing buttons through Socket Mode. Write-only.
    AppToken,
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
    /// Empty once the rule is deleted; the alert keeps its own copy of the rest.
    RuleId,
    RuleName,
    Severity,
    AgentId,
    Host,
    /// Empty for alerts about the agent as a whole.
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
    /// firing, resolved or reminder.
    Event,
    /// pending, sent, failed, or held back by a silence.
    State,
    Attempts,
    NextAttemptMs,
    LastError,
    CreatedMs,
    SentMs,
    /// What the service called the message, for updating or replying to it later.
    ExternalId,
}

#[derive(Iden)]
enum Silences {
    Table,
    Id,
    /// Every rule, if empty.
    RuleId,
    /// Which machines, in the host filter's form. Every machine, if empty.
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
    /// The weekdays it starts on, by name.
    Days,
    /// "HH:MM" in the window's time zone.
    StartTime,
    DurationMinutes,
    TimeZone,
}

/// Rules say what to watch and channels say who to tell. An alert is one rule
/// firing for one agent, and stays as history once it resolves, so it keeps its
/// own copy of what it was about. Notifications are a queue, which lets a delivery
/// survive a restart and be retried. Silences and maintenance windows hold
/// notifications back for a while; a rule's go with it when it's deleted, as an
/// empty rule would mean every rule.
#[async_trait::async_trait]
impl MigrationTrait for CreateAlerting {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                    .col(ColumnDef::new(AlertRules::ForSecs).big_integer().not_null())
                    .col(
                        ColumnDef::new(AlertRules::Severity)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AlertRules::ConditionExpr).text())
                    .col(ColumnDef::new(AlertRules::Enabled).boolean().not_null())
                    .col(ColumnDef::new(AlertRules::Calculation).string_len(16))
                    .col(ColumnDef::new(AlertRules::GroupBy).string_len(255))
                    .col(ColumnDef::new(AlertRules::Filter).string_len(500))
                    .col(ColumnDef::new(AlertRules::WindowSecs).big_integer())
                    .col(ColumnDef::new(AlertRules::RemindEverySecs).big_integer())
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
                            .from(AlertRuleChannels::Table, AlertRuleChannels::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(AlertRuleChannels::Table, AlertRuleChannels::ChannelId)
                            .to(NotificationChannels::Table, NotificationChannels::Id)
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
                    .col(ColumnDef::new(Alerts::AgentId).string_len(32).not_null())
                    .col(ColumnDef::new(Alerts::Host).string_len(255).not_null())
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
                            .from(Alerts::Table, Alerts::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Alerts::Table, Alerts::AgentId)
                            .to(Agents::Table, Agents::Id),
                    )
                    .to_owned(),
            )
            .await?;
        // Finding what's firing, which happens on every evaluation.
        manager
            .create_index(
                Index::create()
                    .name("idx_alerts_resolved")
                    .table(Alerts::Table)
                    .col(Alerts::ResolvedMs)
                    .to_owned(),
            )
            .await?;
        // Showing the newest history.
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
                            .from(Notifications::Table, Notifications::AlertId)
                            .to(Alerts::Table, Alerts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Notifications::Table, Notifications::ChannelId)
                            .to(NotificationChannels::Table, NotificationChannels::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // Finding what's due to be sent, which happens every few seconds.
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
        // Finding who heard about an alert, to tell them when it resolves.
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
                            .from(Silences::Table, Silences::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // Finding what's running, which happens every few seconds.
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
                        ColumnDef::new(MaintenanceWindows::DurationMinutes)
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
                            .from(MaintenanceWindows::Table, MaintenanceWindows::RuleId)
                            .to(AlertRules::Table, AlertRules::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(
            manager,
            &[
                "maintenance_windows",
                "silences",
                "notifications",
                "alerts",
                "alert_rule_channels",
                "notification_channels",
                "alert_rules",
            ],
        )
        .await
    }
}

// ---- Checks the server runs itself

struct CreateRemoteChecks;

impl MigrationName for CreateRemoteChecks {
    fn name(&self) -> &str {
        "m20261108_000005_create_remote_checks"
    }
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

/// Checks the server runs against remote sites. Their results are stored under
/// the built-in `server` agent, so charts and alert rules work on them like any
/// other metric.
#[async_trait::async_trait]
impl MigrationTrait for CreateRemoteChecks {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(manager, &["remote_checks"]).await
    }
}

// ---- Dashboards

struct CreateDashboards;

impl MigrationName for CreateDashboards {
    fn name(&self) -> &str {
        "m20261108_000006_create_dashboards"
    }
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
    /// Where it sits on a grid of 12 columns.
    X,
    Y,
    W,
    H,
}

/// Dashboards everyone signed in shares, and what's on them. A widget keeps its
/// question as what was chosen.
#[async_trait::async_trait]
impl MigrationTrait for CreateDashboards {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(manager, &["dashboard_widgets", "dashboards"]).await
    }
}

// ---- Where machines are

struct CreateLocationRules;

impl MigrationName for CreateLocationRules {
    fn name(&self) -> &str {
        "m20261108_000007_create_location_rules"
    }
}

#[derive(Iden)]
enum LocationRules {
    Table,
    Id,
    /// What the map calls the machines it covers.
    Name,
    /// Which machines, in the host filter's form. Every machine, if empty.
    Filter,
    /// Where it is in words, such as "Leeds, England, United Kingdom".
    Place,
    Latitude,
    Longitude,
    /// When several rules match a machine, the highest wins.
    Priority,
}

/// Rules that say where machines are, for the map. A machine placed by hand is a
/// rule whose filter is its ID.
#[async_trait::async_trait]
impl MigrationTrait for CreateLocationRules {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_tables(manager, &["location_rules"]).await
    }
}

// ---- Each person's time zone

struct AddUserTimeZones;

impl MigrationName for AddUserTimeZones {
    fn name(&self) -> &str {
        "m20261109_000008_add_user_time_zones"
    }
}

#[derive(Iden)]
enum UserTimeZones {
    #[iden = "users"]
    Table,
    /// A name from the time zone database, like `Europe/London`, for showing times.
    TimeZone,
}

/// The time zone each person reads times in. Everyone starts on UTC.
#[async_trait::async_trait]
impl MigrationTrait for AddUserTimeZones {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(UserTimeZones::Table)
                    .add_column(
                        ColumnDef::new(UserTimeZones::TimeZone)
                            .string_len(64)
                            .not_null()
                            .default("UTC"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(UserTimeZones::Table)
                    .drop_column(UserTimeZones::TimeZone)
                    .to_owned(),
            )
            .await
    }
}

// ---- Built-in alerts

struct AddBuiltInAlerts;

impl MigrationName for AddBuiltInAlerts {
    fn name(&self) -> &str {
        "m20261109_000009_add_built_in_alerts"
    }
}

#[derive(Iden)]
enum EveryChannel {
    #[iden = "alert_rules"]
    Table,
    /// Tells every channel, including ones added later, instead of the ones chosen.
    AllChannels,
}

/// What a new or upgraded server alerts on before anyone sets up a rule.
const OFFLINE_RULE_NAME: &str = "Agent offline";
const OFFLINE_RULE_SECS: i64 = 300;

/// Lets a rule tell every channel, and adds a rule for agents going offline, which
/// is what anyone monitoring wants first. Once it's here it's an ordinary rule to
/// change or delete, so it's only ever added once, and not to a server that has an
/// offline rule of its own already.
#[async_trait::async_trait]
impl MigrationTrait for AddBuiltInAlerts {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(EveryChannel::Table)
                    .add_column(
                        ColumnDef::new(EveryChannel::AllChannels)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        let offline = Query::select()
            .column(AlertRules::Id)
            .from(AlertRules::Table)
            .and_where(Expr::col(AlertRules::Kind).eq("offline"))
            .limit(1)
            .to_owned();
        if manager
            .get_connection()
            .query_one(&offline)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let rule = Query::insert()
            .into_table(AlertRules::Table)
            .columns([
                AlertRules::Name.into_iden(),
                AlertRules::Kind.into_iden(),
                AlertRules::ForSecs.into_iden(),
                AlertRules::Severity.into_iden(),
                AlertRules::Enabled.into_iden(),
                EveryChannel::AllChannels.into_iden(),
            ])
            .values([
                OFFLINE_RULE_NAME.into(),
                "offline".into(),
                OFFLINE_RULE_SECS.into(),
                "critical".into(),
                true.into(),
                true.into(),
            ])
            .map_err(|error| DbErr::Custom(error.to_string()))?
            .to_owned();
        manager.exec_stmt(rule).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(EveryChannel::Table)
                    .drop_column(EveryChannel::AllChannels)
                    .to_owned(),
            )
            .await
    }
}

// ---- Built-in disk alerts

struct AddBuiltInDiskAlerts;

impl MigrationName for AddBuiltInDiskAlerts {
    fn name(&self) -> &str {
        "m20261109_000010_add_built_in_disk_alerts"
    }
}

const DISK_USAGE: &str = "disk.usage";
const DISK_RULE_SECS: i64 = 300;
/// Each rule's name, how full a disk is when it fires, and how bad that is.
const DISK_RULES: [(&str, f64, &str); 2] = [
    ("Disk filling up", 80.0, "warning"),
    ("Disk nearly full", 90.0, "critical"),
];

/// Adds a warning for any disk over 80% full and a critical alert over 90%, telling
/// every channel, like the offline rule. They're ordinary rules once added, so a
/// server with a disk usage rule of its own already doesn't get them.
#[async_trait::async_trait]
impl MigrationTrait for AddBuiltInDiskAlerts {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let disk_rule = Query::select()
            .column(AlertRules::Id)
            .from(AlertRules::Table)
            .and_where(Expr::col(AlertRules::Metric).eq(DISK_USAGE))
            .limit(1)
            .to_owned();
        if manager
            .get_connection()
            .query_one(&disk_rule)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let mut rules = Query::insert()
            .into_table(AlertRules::Table)
            .columns([
                AlertRules::Name.into_iden(),
                AlertRules::Kind.into_iden(),
                AlertRules::Metric.into_iden(),
                AlertRules::Comparison.into_iden(),
                AlertRules::Threshold.into_iden(),
                AlertRules::ForSecs.into_iden(),
                AlertRules::Severity.into_iden(),
                AlertRules::Enabled.into_iden(),
                EveryChannel::AllChannels.into_iden(),
            ])
            .to_owned();
        for (name, threshold, severity) in DISK_RULES {
            rules
                .values([
                    name.into(),
                    "metric".into(),
                    DISK_USAGE.into(),
                    "above".into(),
                    threshold.into(),
                    DISK_RULE_SECS.into(),
                    severity.into(),
                    true.into(),
                    true.into(),
                ])
                .map_err(|error| DbErr::Custom(error.to_string()))?;
        }
        manager.exec_stmt(rules).await
    }

    /// The rules are left, as they may have been changed since.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

// ---- Warning thresholds

struct AddWarningThresholds;

impl MigrationName for AddWarningThresholds {
    fn name(&self) -> &str {
        "m20261109_000011_add_warning_thresholds"
    }
}

#[derive(Iden)]
enum WarningThresholds {
    #[iden = "alert_rules"]
    Table,
    /// For a critical rule, where it's a warning first.
    WarningThreshold,
}

/// What the two built-in disk rules become: one alert per disk, at the worse of
/// the two.
const MERGED_DISK_RULE_NAME: &str = "Disk filling up";

/// Lets one rule be a warning first and critical later, and makes the built-in
/// disk rules one rule like that, so a full disk sends a critical alert instead of
/// a warning and a critical one. They're only joined if both are still as added.
#[async_trait::async_trait]
impl MigrationTrait for AddWarningThresholds {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WarningThresholds::Table)
                    .add_column(ColumnDef::new(WarningThresholds::WarningThreshold).double())
                    .to_owned(),
            )
            .await?;

        let connection = manager.get_connection();
        let mut built_in = Vec::new();
        for (name, threshold, severity) in DISK_RULES {
            let rule = Query::select()
                .column(AlertRules::Id)
                .from(AlertRules::Table)
                .and_where(Expr::col(AlertRules::Name).eq(name))
                .and_where(Expr::col(AlertRules::Kind).eq("metric"))
                .and_where(Expr::col(AlertRules::Metric).eq(DISK_USAGE))
                .and_where(Expr::col(AlertRules::Series).is_null())
                .and_where(Expr::col(AlertRules::Comparison).eq("above"))
                .and_where(Expr::col(AlertRules::Threshold).eq(threshold))
                .and_where(Expr::col(AlertRules::ForSecs).eq(DISK_RULE_SECS))
                .and_where(Expr::col(AlertRules::Severity).eq(severity))
                .and_where(Expr::col(AlertRules::ConditionExpr).is_null())
                .and_where(Expr::col(AlertRules::RemindEverySecs).is_null())
                .and_where(Expr::col(AlertRules::Enabled).eq(true))
                .and_where(Expr::col(EveryChannel::AllChannels).eq(true))
                .to_owned();
            match connection.query_one(&rule).await? {
                Some(row) => built_in.push(row.try_get::<i64>("", "id")?),
                None => return Ok(()),
            }
        }
        let [warning, critical] = built_in[..] else {
            return Ok(());
        };

        // Its open alerts end, with notifications, as for any deleted rule. It goes
        // first, as the one kept takes its name.
        let gone = Query::delete()
            .from_table(AlertRules::Table)
            .and_where(Expr::col(AlertRules::Id).eq(warning))
            .to_owned();
        manager.exec_stmt(gone).await?;
        let merged = Query::update()
            .table(AlertRules::Table)
            .value(AlertRules::Name, MERGED_DISK_RULE_NAME)
            .value(WarningThresholds::WarningThreshold, DISK_RULES[0].1)
            .and_where(Expr::col(AlertRules::Id).eq(critical))
            .to_owned();
        manager.exec_stmt(merged).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WarningThresholds::Table)
                    .drop_column(WarningThresholds::WarningThreshold)
                    .to_owned(),
            )
            .await
    }
}

// ---- Which alerts each channel hears of

struct AddChannelSeverities;

impl MigrationName for AddChannelSeverities {
    fn name(&self) -> &str {
        "m20261109_000012_add_channel_severities"
    }
}

#[derive(Iden)]
enum ChannelSeverities {
    #[iden = "notification_channels"]
    Table,
    /// The mildest alert a channel hears of: warning, or critical to keep
    /// warnings off a pager.
    MinSeverity,
}

/// Every channel starts out hearing of every alert, as it did before.
#[async_trait::async_trait]
impl MigrationTrait for AddChannelSeverities {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ChannelSeverities::Table)
                    .add_column(
                        ColumnDef::new(ChannelSeverities::MinSeverity)
                            .string_len(16)
                            .not_null()
                            .default("warning"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ChannelSeverities::Table)
                    .drop_column(ChannelSeverities::MinSeverity)
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, Statement};

    use super::*;

    async fn offline_rules(connection: &impl ConnectionTrait) -> Vec<String> {
        let query = Statement::from_string(
            connection.get_database_backend(),
            "SELECT name FROM alert_rules WHERE kind = 'offline' ORDER BY id",
        );
        let rows = connection.query_all_raw(query).await.unwrap();
        rows.iter()
            .map(|row| row.try_get::<String>("", "name").unwrap())
            .collect()
    }

    #[tokio::test]
    async fn the_built_in_offline_rule_is_not_added_beside_one_already_there() {
        let options = ConnectOptions::new("sqlite::memory:")
            .max_connections(1)
            .to_owned();
        let connection = Database::connect(options).await.unwrap();
        let before = Migrator::migrations().len() as u32 - 4;
        Migrator::up(&connection, Some(before)).await.unwrap();
        connection
            .execute_unprepared(
                "INSERT INTO alert_rules (name, kind, for_secs, severity, enabled)
                 VALUES ('Gone', 'offline', 60, 'warning', TRUE)",
            )
            .await
            .unwrap();

        Migrator::up(&connection, None).await.unwrap();

        assert_eq!(offline_rules(&connection).await, ["Gone"]);
    }

    #[tokio::test]
    async fn the_built_in_disk_rules_are_not_added_beside_one_already_there() {
        let options = ConnectOptions::new("sqlite::memory:")
            .max_connections(1)
            .to_owned();
        let connection = Database::connect(options).await.unwrap();
        let before = Migrator::migrations().len() as u32 - 3;
        Migrator::up(&connection, Some(before)).await.unwrap();
        connection
            .execute_unprepared(
                "INSERT INTO alert_rules
                   (name, kind, metric, comparison, threshold, for_secs, severity, enabled)
                 VALUES ('Full', 'metric', 'disk.usage', 'above', 95, 60, 'critical', TRUE)",
            )
            .await
            .unwrap();

        Migrator::up(&connection, None).await.unwrap();

        let query = Statement::from_string(
            connection.get_database_backend(),
            "SELECT name FROM alert_rules WHERE metric = 'disk.usage'",
        );
        let rows = connection.query_all_raw(query).await.unwrap();
        let names: Vec<String> = rows
            .iter()
            .map(|row| row.try_get::<String>("", "name").unwrap())
            .collect();
        assert_eq!(names, ["Full"]);
    }

    async fn disk_rules(connection: &impl ConnectionTrait) -> Vec<(String, f64, Option<f64>)> {
        let query = Statement::from_string(
            connection.get_database_backend(),
            "SELECT name, threshold, warning_threshold FROM alert_rules
             WHERE metric = 'disk.usage' ORDER BY id",
        );
        let rows = connection.query_all_raw(query).await.unwrap();
        rows.iter()
            .map(|row| {
                (
                    row.try_get("", "name").unwrap(),
                    row.try_get("", "threshold").unwrap(),
                    row.try_get("", "warning_threshold").unwrap(),
                )
            })
            .collect()
    }

    async fn fresh() -> sea_orm::DatabaseConnection {
        let options = ConnectOptions::new("sqlite::memory:")
            .max_connections(1)
            .to_owned();
        Database::connect(options).await.unwrap()
    }

    #[tokio::test]
    async fn the_built_in_disk_rules_become_one_unless_they_were_changed() {
        let connection = fresh().await;
        Migrator::up(&connection, None).await.unwrap();
        assert_eq!(
            disk_rules(&connection).await,
            [("Disk filling up".to_string(), 90.0, Some(80.0))]
        );

        let connection = fresh().await;
        let before = Migrator::migrations().len() as u32 - 2;
        Migrator::up(&connection, Some(before)).await.unwrap();
        connection
            .execute_unprepared(
                "UPDATE alert_rules SET threshold = 85 WHERE name = 'Disk filling up'",
            )
            .await
            .unwrap();
        Migrator::up(&connection, None).await.unwrap();
        assert_eq!(
            disk_rules(&connection).await,
            [
                ("Disk filling up".to_string(), 85.0, None),
                ("Disk nearly full".to_string(), 90.0, None),
            ]
        );
    }
}
