use sea_orm_migration::prelude::*;

/// Every schema change, in order. Applied ones are recorded in the database,
/// so never edit one that has shipped: add a new one instead.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(CreateAgents), Box::new(CreateAgentFacts)]
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
