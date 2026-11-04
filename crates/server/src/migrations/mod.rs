use sea_orm_migration::prelude::*;

/// Every schema change, in order. Applied ones are recorded in the database,
/// so never edit one that has shipped: add a new one instead.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(CreateAgents),
            Box::new(CreateAgentFacts),
            Box::new(CreateConfigRules),
        ]
    }
}

struct CreateAgents;

impl MigrationName for CreateAgents {
    fn name(&self) -> &str {
        "m20261103_000001_create_agents"
    }
}

#[derive(Iden)]
enum Agents {
    Table,
    Id,
    PublicKey,
    Host,
    State,
    DecidedBy,
    FirstSeenMs,
    DecidedAtMs,
}

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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Agents::Table).to_owned())
            .await
    }
}

struct CreateAgentFacts;

impl MigrationName for CreateAgentFacts {
    fn name(&self) -> &str {
        "m20261103_000002_create_agent_facts"
    }
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

/// One row per value a fact has had. `valid_to_ms` is empty for current values,
/// so the same table answers what's true now and what was true before.
#[async_trait::async_trait]
impl MigrationTrait for CreateAgentFacts {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AgentFacts::Table)
                    .col(
                        ColumnDef::new(AgentFacts::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AgentFacts::Table).to_owned())
            .await
    }
}

struct CreateConfigRules;

impl MigrationName for CreateConfigRules {
    fn name(&self) -> &str {
        "m20261103_000003_create_config_rules"
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

#[derive(Iden)]
enum AgentConfigStatus {
    Table,
    AgentId,
    Version,
    Error,
    ReportedAtMs,
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

#[async_trait::async_trait]
impl MigrationTrait for CreateConfigRules {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ConfigRules::Table)
                    .col(
                        ColumnDef::new(ConfigRules::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
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
                    .col(
                        ColumnDef::new(ConfigRuleSettings::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
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
        manager
            .drop_table(Table::drop().table(AgentConfigStatus::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ConfigRuleSettings::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ConfigRules::Table).to_owned())
            .await
    }
}
