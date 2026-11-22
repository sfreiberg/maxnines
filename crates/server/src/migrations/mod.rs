//! The main database's tables, made by one migration: what `database/README.md`
//! draws. Until the first release there are no upgrade steps: a change to a table is
//! made to this migration, with the README changed to match, and a database made
//! before the change is deleted and made again.

use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(CreateTables)]
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

/// Text compared exactly, as it's written. MySQL and MariaDB would otherwise compare
/// it by the table's collation, usually ignoring case and accents, as the other
/// databases never do.
fn exact_text(backend: DatabaseBackend, column: impl IntoIden, length: u32) -> ColumnDef {
    let mut text = ColumnDef::new(column);
    match backend {
        DatabaseBackend::MySql => text.custom(Alias::new(format!(
            "varchar({length}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
        ))),
        _ => text.string_len(length),
    };
    text
}

/// How long a name can be as it's compared: lowercased, which can make it longer, from
/// a name of up to 255 characters.
const NAME_KEY_LEN: u32 = 512;

/// A name as it's compared, ignoring case and the spaces around it, which is what's
/// kept unique. The server fills it in, as [`crate::models::name_key`] works it out,
/// so every database compares names the same way.
fn name_key(backend: DatabaseBackend) -> ColumnDef {
    exact_text(backend, Alias::new("name_key"), NAME_KEY_LEN)
        .not_null()
        .to_owned()
}

/// For MySQL, which can't index only some rows: a column it works out itself, holding
/// `value` while `only` holds and NULL otherwise, which a unique index lets repeat.
fn only_while(column: &str, length: u32, only: &str, value: &str) -> ColumnDef {
    exact_text(DatabaseBackend::MySql, Alias::new(column), length)
        .generated(
            Expr::cust(format!("CASE WHEN {only} THEN {value} END")),
            true,
        )
        .to_owned()
}

#[derive(Clone, Copy)]
enum IndexKind {
    Unique,
    Plain,
}

use IndexKind::{Plain, Unique};

/// Makes an index of `columns`, as SQL writes them, of only the rows `only` picks when
/// it's given, which MySQL can't do.
async fn index_of(
    manager: &SchemaManager<'_>,
    kind: IndexKind,
    name: &str,
    table: &str,
    columns: &str,
    only: Option<&str>,
) -> Result<(), DbErr> {
    let unique = match kind {
        Unique => "UNIQUE ",
        Plain => "",
    };
    let only = only
        .map(|only| format!(" WHERE {only}"))
        .unwrap_or_default();
    manager
        .get_connection()
        .execute_unprepared(&format!(
            "CREATE {unique}INDEX {name} ON {table} ({columns}){only}"
        ))
        .await?;
    Ok(())
}

/// Makes `table`, whose names are each used once among the rows that aren't deleted.
async fn live_names(
    manager: &SchemaManager<'_>,
    table: TableCreateStatement,
    name: &str,
) -> Result<(), DbErr> {
    live_names_while(manager, table, name, "deleted_at IS NULL").await
}

/// Makes `table`, whose names are each used once among the rows `live` picks.
async fn live_names_while(
    manager: &SchemaManager<'_>,
    mut table: TableCreateStatement,
    name: &str,
    live: &str,
) -> Result<(), DbErr> {
    let index = format!("idx_{name}_live_name");
    if manager.get_database_backend() == DatabaseBackend::MySql {
        table.col(only_while("live_name", NAME_KEY_LEN, live, "name_key"));
        manager.create_table(table).await?;
        index_of(manager, Unique, &index, name, "live_name", None).await
    } else {
        manager.create_table(table).await?;
        index_of(manager, Unique, &index, name, "name_key", Some(live)).await
    }
}

/// A column of one of the tables holding a template's parts, which are named as
/// the HCL names them.
fn part(name: &str) -> ColumnDef {
    ColumnDef::new(Alias::new(name))
}

/// The tables holding the parts of a template, one row to a block or entry, each
/// with its key and where it comes among the others. Every one has a `replaces_id`,
/// for someone's own copy of a built-in template's part, as alert rules have.
async fn template_parts(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let backend = manager.get_database_backend();
    let key = || {
        exact_text(backend, Alias::new("key"), 255)
            .not_null()
            .to_owned()
    };
    let position = || part("position").integer().not_null().to_owned();
    // What every part has, and the template, query, counters or fill it's part of.
    let table = |name: &str, parents: &[(&str, &str, bool)]| {
        let mut table = Table::create()
            .table(Alias::new(name))
            .col(id(Alias::new("id")))
            .to_owned();
        for (column, parent, required) in parents {
            let mut owner = part(column).big_integer().to_owned();
            if *required {
                owner.not_null();
            }
            table.col(owner).foreign_key(
                ForeignKey::create()
                    .name(format!("fk_{name}_{column}"))
                    .from(Alias::new(name), Alias::new(*column))
                    .to(Alias::new(*parent), Alias::new("id"))
                    .on_delete(ForeignKeyAction::Cascade),
            );
        }
        table.col(part("replaces_id").big_integer()).foreign_key(
            ForeignKey::create()
                .name(format!("fk_{name}_replaces_id"))
                .from(Alias::new(name), Alias::new("replaces_id"))
                .to(Alias::new(name), Alias::new("id"))
                .on_delete(ForeignKeyAction::Cascade),
        );
        table
    };
    let template = [("template_id", "templates", true)];

    let mut discoveries = table("template_discoveries", &template);
    discoveries
        .col(part("interval_secs").big_integer())
        .col(part("sql").text())
        .col(json(backend, Alias::new("counter_sets")));
    manager.create_table(discoveries).await?;

    let mut registry = table("template_registry_reads", &template);
    registry
        .col(key())
        .col(position())
        .col(json(backend, Alias::new("value_names")).not_null());
    manager.create_table(registry).await?;

    let mut notices = table("template_notices", &template);
    notices
        .col(key())
        .col(position())
        .col(part("when_condition").text())
        .col(part("text").text().not_null());
    manager.create_table(notices).await?;

    let mut queries = table("template_queries", &template);
    queries
        .col(key())
        .col(position())
        .col(part("sql").text().not_null())
        .col(part("interval_secs").big_integer())
        .col(part("since").string_len(64))
        .col(part("when_condition").text())
        .col(part("enabled").boolean().not_null())
        .col(part("enabled_choice").boolean())
        .col(json(backend, Alias::new("labels")));
    manager.create_table(queries).await?;

    let mut fills = table("template_fills", &[("query_id", "template_queries", true)]);
    fills.col(key()).col(position()).col(part("older").text());
    manager.create_table(fills).await?;

    let mut versions = table(
        "template_fill_versions",
        &[("fill_id", "template_fills", true)],
    );
    versions
        .col(part("version").string_len(64).not_null())
        .col(position())
        .col(part("sql").text().not_null());
    manager.create_table(versions).await?;

    let mut counters = table("template_counters", &template);
    counters
        .col(key())
        .col(position())
        .col(part("object").string_len(255).not_null())
        .col(part("label").string_len(64))
        .col(part("pattern").text())
        .col(part("instance").string_len(255))
        .col(json(backend, Alias::new("exclude")))
        .col(json(backend, Alias::new("groups")))
        .col(part("join_object").string_len(255))
        .col(part("join_pattern").text())
        .col(part("when_condition").text())
        .col(part("since").string_len(64))
        .col(part("interval_secs").big_integer())
        .col(part("enabled").boolean().not_null())
        .col(part("enabled_choice").boolean());
    manager.create_table(counters).await?;

    // A metric is a query's or a counters block's.
    let mut metrics = table(
        "template_metrics",
        &[
            ("query_id", "template_queries", false),
            ("counters_id", "template_counters", false),
        ],
    );
    metrics
        .col(key())
        .col(position())
        .col(part("counter").string_len(255))
        .col(part("unit").string_len(16))
        .col(part("total").boolean().not_null())
        .col(part("description").text())
        .col(part("value").text())
        .col(part("since").string_len(64))
        .col(json(backend, Alias::new("states")));
    manager.create_table(metrics).await?;

    for (name, table, columns) in [
        (
            "idx_template_discoveries_template",
            "template_discoveries",
            "template_id",
        ),
        (
            "idx_template_registry_reads_template",
            "template_registry_reads",
            "template_id, position",
        ),
        (
            "idx_template_notices_template",
            "template_notices",
            "template_id, position",
        ),
        (
            "idx_template_queries_template",
            "template_queries",
            "template_id, position",
        ),
        (
            "idx_template_fills_query",
            "template_fills",
            "query_id, position",
        ),
        (
            "idx_template_fill_versions_fill",
            "template_fill_versions",
            "fill_id, position",
        ),
        (
            "idx_template_counters_template",
            "template_counters",
            "template_id, position",
        ),
        (
            "idx_template_metrics_query",
            "template_metrics",
            "query_id, position",
        ),
        (
            "idx_template_metrics_counters",
            "template_metrics",
            "counters_id, position",
        ),
    ] {
        index_of(manager, Plain, name, table, columns, None).await?;
    }
    Ok(())
}

struct CreateTables;

impl MigrationName for CreateTables {
    fn name(&self) -> &str {
        "m20261119_000001_create_tables"
    }
}

/// Every table, in the order their foreign keys need, and what a new server starts
/// with: the server itself and the fleet as hosts. The built-in config rules and
/// templates, and the alert rules templates have, are written each time the server
/// starts instead. A column that can be empty is NULL when it is, never an empty
/// string, so it says plainly when there's nothing in it.
#[async_trait::async_trait]
impl MigrationTrait for CreateTables {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let mysql = backend == DatabaseBackend::MySql;
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
                    // Why the server refuses the host's agent, while it does, for the
                    // protocol it speaks.
                    .col(moment(backend, Hosts::RefusedAt))
                    .col(ColumnDef::new(Hosts::RefusedReason).text())
                    .col(ColumnDef::new(Hosts::RefusedProtocol).big_integer())
                    .to_owned(),
            )
            .await?;
        // Facts are what agents report, so `os.Family` isn't `os.family`: names and
        // values are compared exactly. A host has one current value of each fact.
        let mut host_facts = Table::create()
            .table(HostFacts::Table)
            .col(id(HostFacts::Id))
            .col(ColumnDef::new(HostFacts::HostId).string_len(32).not_null())
            .col(exact_text(backend, HostFacts::Name, 255).not_null())
            .col(exact_text(backend, HostFacts::Value, 255).not_null())
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
                    .to(Hosts::Table, Hosts::Id)
                    .on_delete(ForeignKeyAction::Cascade),
            )
            .to_owned();
        if mysql {
            host_facts.col(only_while("current_name", 255, "valid_to IS NULL", "name"));
        }
        manager.create_table(host_facts).await?;
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
        // One current value of each fact, and the facts hosts have now by name.
        let current = "valid_to IS NULL";
        if mysql {
            let (table, unique) = ("host_facts", "idx_host_facts_current");
            index_of(
                manager,
                Unique,
                unique,
                table,
                "host_id, current_name",
                None,
            )
            .await?;
            index_of(
                manager,
                Plain,
                "idx_host_facts_current_name",
                table,
                "valid_to, name",
                None,
            )
            .await?;
        } else {
            let (table, unique) = ("host_facts", "idx_host_facts_current");
            index_of(
                manager,
                Unique,
                unique,
                table,
                "host_id, name",
                Some(current),
            )
            .await?;
            index_of(
                manager,
                Plain,
                "idx_host_facts_current_name",
                table,
                "name",
                Some(current),
            )
            .await?;
        }
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
                    // The collectors in the config that the agent doesn't know, as it's
                    // older than the server, one to a line.
                    .col(ColumnDef::new(HostConfigStatus::SkippedCollectors).text())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_host_config_status_host_id")
                            .from(HostConfigStatus::Table, HostConfigStatus::HostId)
                            .to(Hosts::Table, Hosts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
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
                            .to(Hosts::Table, Hosts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
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
                            .to(Hosts::Table, Hosts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
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
                    .col(ColumnDef::new(ConfigRules::Name).string_len(255).not_null())
                    .col(name_key(backend))
                    .col(ColumnDef::new(ConfigRules::Priority).integer().not_null())
                    .col(ColumnDef::new(ConfigRules::AppliesTo).text())
                    .col(ColumnDef::new(ConfigRules::Enabled).boolean().not_null())
                    .col(ColumnDef::new(ConfigRules::OperatingSystems).string_len(64))
                    .col(ColumnDef::new(ConfigRules::BuiltIn).string_len(32))
                    .col(moment(backend, ConfigRules::BuiltInChangedAt))
                    .to_owned(),
            )
            .await?;
        index_of(
            manager,
            Unique,
            "idx_config_rules_name",
            "config_rules",
            "name_key",
            None,
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
        // Sessions that have run out, which every sign in clears.
        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_expires")
                    .table(UserSessions::Table)
                    .col(UserSessions::ExpiresAt)
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
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_user_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::UserId)
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
                                .to(Users::Table, Users::Id)
                                .on_delete(ForeignKeyAction::Cascade),
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
                // What's cleared on every sign in.
                ("idx_app_sign_ins_revoked", T::RevokedAt),
                ("idx_app_sign_ins_refresh_expires", T::RefreshExpiresAt),
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
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_recovery_codes_user_id")
                    .table(RecoveryCodes::Table)
                    .col(RecoveryCodes::UserId)
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
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        for (name, column) in [
            ("idx_sign_in_challenges_user_id", SignInChallenges::UserId),
            // What's cleared on every sign in.
            (
                "idx_sign_in_challenges_expires",
                SignInChallenges::ExpiresAt,
            ),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(SignInChallenges::Table)
                        .col(column)
                        .to_owned(),
                )
                .await?;
        }
        // A channel is only ever marked deleted, so what was sent through it still
        // names it, and its name is used once among those that aren't.
        let channels = Table::create()
            .table(NotificationChannels::Table)
            .col(id(NotificationChannels::Id))
            .col(
                ColumnDef::new(NotificationChannels::Name)
                    .string_len(255)
                    .not_null(),
            )
            .col(name_key(backend))
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
            .to_owned();
        live_names(manager, channels, "notification_channels").await?;
        // A template is only ever marked deleted, as its alert rules point at it. Its
        // key and its name are each used once among those that aren't.
        let templates = Table::create()
            .table(Templates::Table)
            .col(id(Templates::Id))
            .col(exact_text(backend, Templates::Key, 64).not_null())
            .col(ColumnDef::new(Templates::Name).string_len(255).not_null())
            .col(name_key(backend))
            .col(ColumnDef::new(Templates::Description).text())
            // Where it came from: built_in, imported or own.
            .col(ColumnDef::new(Templates::Origin).string_len(16).not_null())
            // What it runs once for on each host: a kind of database, a service or
            // operating systems, comma separated. Neither for every host.
            .col(ColumnDef::new(Templates::TargetKind).string_len(16))
            .col(ColumnDef::new(Templates::Target).string_len(255))
            .col(ColumnDef::new(Templates::MinVersion).string_len(64))
            .col(json(backend, Templates::RenamedFrom))
            .col(json(backend, Templates::Services))
            // What a built-in one says, hashed, so an upgrade can tell it changed.
            .col(ColumnDef::new(Templates::Fingerprint).string_len(64))
            // Whether it ships on, and what someone chose instead, if they have: until
            // they do, a newer version's say is followed.
            .col(ColumnDef::new(Templates::Enabled).boolean().not_null())
            .col(ColumnDef::new(Templates::EnabledChoice).boolean())
            .col(moment(backend, Templates::CreatedAt).not_null())
            .col(moment(backend, Templates::UpdatedAt).not_null())
            // When an upgrade last changed a built-in one, and whether admins have
            // dismissed the notice saying so.
            .col(moment(backend, Templates::UpgradedAt))
            .col(
                ColumnDef::new(Templates::UpgradeSeen)
                    .boolean()
                    .not_null()
                    .default(true),
            )
            .col(moment(backend, Templates::DeletedAt))
            .to_owned();
        let live = "deleted_at IS NULL";
        let mut templates = templates;
        if mysql {
            templates.col(only_while("live_key", 64, live, "`key`"));
        }
        live_names(manager, templates, "templates").await?;
        if mysql {
            index_of(
                manager,
                Unique,
                "idx_templates_live_key",
                "templates",
                "live_key",
                None,
            )
            .await?;
        } else {
            index_of(
                manager,
                Unique,
                "idx_templates_live_key",
                "templates",
                "\"key\"",
                Some(live),
            )
            .await?;
        }
        template_parts(manager).await?;
        // A rule is only ever marked deleted, as its alerts keep it, and its name is
        // used once among those that aren't. A template's alert is a rule, which for
        // a built-in template belongs to the server: someone changing it makes a copy
        // of their own, a second rule that `replaces_id` points from, and that one
        // is used while it's there. Copies' names aren't in the index, as each has
        // its original's until it's renamed.
        let rules = Table::create()
            .table(AlertRules::Table)
            .col(id(AlertRules::Id))
            .col(ColumnDef::new(AlertRules::Name).string_len(255).not_null())
            .col(name_key(backend))
            .col(ColumnDef::new(AlertRules::Warning).text())
            .col(ColumnDef::new(AlertRules::Critical).text())
            .col(ColumnDef::new(AlertRules::Summary).text())
            .col(ColumnDef::new(AlertRules::ResolvedSummary).text())
            .col(ColumnDef::new(AlertRules::ForSecs).big_integer().not_null())
            .col(ColumnDef::new(AlertRules::AppliesTo).text())
            .col(ColumnDef::new(AlertRules::Enabled).boolean().not_null())
            .col(
                ColumnDef::new(AlertRules::AllChannels)
                    .boolean()
                    .not_null()
                    .default(false),
            )
            .col(ColumnDef::new(AlertRules::Calculation).string_len(16))
            .col(ColumnDef::new(AlertRules::Metric).string_len(64))
            .col(ColumnDef::new(AlertRules::GroupBy).string_len(255))
            .col(ColumnDef::new(AlertRules::Filter).string_len(500))
            .col(ColumnDef::new(AlertRules::WindowSecs).big_integer())
            .col(ColumnDef::new(AlertRules::RemindEverySecs).big_integer())
            .col(ColumnDef::new(AlertRules::TemplateId).big_integer())
            .col(exact_text(backend, AlertRules::TemplateAlert, 64))
            // For a built-in or imported template's rule, what someone chose in place
            // of the template's `enabled`, if they have.
            .col(ColumnDef::new(AlertRules::EnabledChoice).boolean())
            .col(ColumnDef::new(AlertRules::ReplacesId).big_integer())
            // Where a template's alert comes among its alerts, and what only a
            // template's alert has: which of what discovery found it's for.
            .col(ColumnDef::new(AlertRules::TemplatePosition).integer())
            .col(ColumnDef::new(AlertRules::WhenCondition).text())
            .col(ColumnDef::new(AlertRules::Since).string_len(64))
            // When an upgrade last changed the built-in rule under someone's copy.
            .col(moment(backend, AlertRules::OriginalChangedAt))
            // Until agents run templates, one whose alert needs what only they'd send,
            // the template's own metrics or what its discovery finds, isn't checked.
            .col(
                ColumnDef::new(AlertRules::WaitsForAgents)
                    .boolean()
                    .not_null()
                    .default(false),
            )
            .col(moment(backend, AlertRules::DeletedAt))
            .foreign_key(
                ForeignKey::create()
                    .name("fk_alert_rules_template_id")
                    .from(AlertRules::Table, AlertRules::TemplateId)
                    .to(Templates::Table, Templates::Id),
            )
            .foreign_key(
                ForeignKey::create()
                    .name("fk_alert_rules_replaces_id")
                    .from(AlertRules::Table, AlertRules::ReplacesId)
                    .to(AlertRules::Table, AlertRules::Id),
            )
            .to_owned();
        let own = "deleted_at IS NULL AND replaces_id IS NULL";
        let mut rules = rules;
        if mysql {
            rules.col(only_while("live_template_alert", 64, own, "template_alert"));
            rules.col(
                ColumnDef::new(Alias::new("live_replaces_id"))
                    .big_integer()
                    .generated(
                        Expr::cust(format!("CASE WHEN {live} THEN replaces_id END")),
                        true,
                    )
                    .to_owned(),
            );
        }
        live_names_while(manager, rules, "alert_rules", own).await?;
        // Each of a template's alerts is one rule, and has at most one copy, among
        // those that aren't deleted.
        if mysql {
            index_of(
                manager,
                Unique,
                "idx_alert_rules_template_alert",
                "alert_rules",
                "template_id, live_template_alert",
                None,
            )
            .await?;
            index_of(
                manager,
                Unique,
                "idx_alert_rules_replaces",
                "alert_rules",
                "live_replaces_id",
                None,
            )
            .await?;
        } else {
            index_of(
                manager,
                Unique,
                "idx_alert_rules_template_alert",
                "alert_rules",
                "template_id, template_alert",
                Some("deleted_at IS NULL AND replaces_id IS NULL AND template_id IS NOT NULL"),
            )
            .await?;
            index_of(
                manager,
                Unique,
                "idx_alert_rules_replaces",
                "alert_rules",
                "replaces_id",
                Some("deleted_at IS NULL AND replaces_id IS NOT NULL"),
            )
            .await?;
        }
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
            .create_index(
                Index::create()
                    .name("idx_alert_rule_channels_channel")
                    .table(AlertRuleChannels::Table)
                    .col(AlertRuleChannels::ChannelId)
                    .to_owned(),
            )
            .await?;
        // An alert keeps no copy of its rule's name or its host's, which would only go
        // stale when either was renamed. Rules are only ever marked deleted, and a
        // host's alerts go with it, so both are always there to be read.
        let mut alerts = Table::create()
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
                    .to(Hosts::Table, Hosts::Id)
                    .on_delete(ForeignKeyAction::Cascade),
            )
            .foreign_key(
                ForeignKey::create()
                    .name("fk_alerts_rule_id")
                    .from(Alerts::Table, Alerts::RuleId)
                    .to(AlertRules::Table, AlertRules::Id),
            )
            .to_owned();
        let open = "resolved_at IS NULL";
        if mysql {
            alerts.col(only_while("open_series", 255, open, "COALESCE(series, '')"));
        }
        manager.create_table(alerts).await?;
        // One open alert from each rule about each host and series. A host as a whole
        // has no series, which counts as one of its own.
        if mysql {
            let columns = "rule_id, host_id, open_series";
            index_of(manager, Unique, "idx_alerts_open", "alerts", columns, None).await?;
        } else {
            let columns = "rule_id, host_id, COALESCE(series, '')";
            index_of(
                manager,
                Unique,
                "idx_alerts_open",
                "alerts",
                columns,
                Some(open),
            )
            .await?;
        }
        for (name, columns) in [
            // Ended alerts, newest first, in the order they ended.
            ("idx_alerts_resolved", vec![Alerts::ResolvedAt, Alerts::Id]),
            ("idx_alerts_started", vec![Alerts::StartedAt]),
            // A host's timeline, newest first.
            (
                "idx_alerts_host_started",
                vec![Alerts::HostId, Alerts::StartedAt],
            ),
            // A rule's open alerts, to end them when it's deleted or remind people.
            (
                "idx_alerts_rule_resolved",
                vec![Alerts::RuleId, Alerts::ResolvedAt],
            ),
        ] {
            let mut index = Index::create();
            index.name(name).table(Alerts::Table);
            for column in columns {
                index.col(column);
            }
            manager.create_index(index).await?;
        }
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
                    // In seconds, with a fraction, as many take less than one.
                    .col(ColumnDef::new(ActionRuns::DurationSecs).double())
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
                            .to(NotificationChannels::Table, NotificationChannels::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_notifications_action_run_id")
                            .from(Notifications::Table, Notifications::ActionRunId)
                            .to(ActionRuns::Table, ActionRuns::Id)
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
        for (name, columns) in [
            // What's waiting for a channel.
            (
                "idx_notifications_channel",
                vec![Notifications::ChannelId, Notifications::State],
            ),
            (
                "idx_notifications_action_run",
                vec![Notifications::ActionRunId],
            ),
        ] {
            let mut index = Index::create();
            index.name(name).table(Notifications::Table);
            for column in columns {
                index.col(column);
            }
            manager.create_index(index).await?;
        }
        // Notifications that failed, newest first, for the alerts page. MySQL can't
        // index only some rows, and it's only worth having as one.
        if !mysql {
            let failed = Some("last_error IS NOT NULL");
            index_of(
                manager,
                Plain,
                "idx_notifications_problems",
                "notifications",
                "id",
                failed,
            )
            .await?;
        }
        manager
            .create_table(
                Table::create()
                    .table(RemoteChecks::Table)
                    .col(id(RemoteChecks::Id))
                    .col(ColumnDef::new(RemoteChecks::Name).string_len(64).not_null())
                    .col(name_key(backend))
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
                            .not_null(),
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
                            .to(Hosts::Table, Hosts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // A check's name only has to differ from the others about the same host.
        let (name, columns) = ("idx_remote_checks_host_name", "host_id, name_key");
        index_of(manager, Unique, name, "remote_checks", columns, None).await?;
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
}

/// The two hosts that aren't machines: the server records its own checks and
/// numbers under one, and alerts about many hosts at once under the other.
const BUILT_IN_HOSTS: [(&str, &str); 2] = [("server", "MaxNines server"), ("fleet", "Fleet")];

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
    manager.exec_stmt(hosts).await
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
    RefusedAt,
    RefusedReason,
    RefusedProtocol,
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
    SkippedCollectors,
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
    AppliesTo,
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
    Warning,
    Critical,
    Summary,
    ResolvedSummary,
    ForSecs,
    AppliesTo,
    Enabled,
    AllChannels,
    Calculation,
    Metric,
    GroupBy,
    Filter,
    WindowSecs,
    RemindEverySecs,
    TemplateId,
    TemplateAlert,
    EnabledChoice,
    ReplacesId,
    TemplatePosition,
    WhenCondition,
    Since,
    OriginalChangedAt,
    WaitsForAgents,
    DeletedAt,
}

#[derive(Iden)]
enum Templates {
    Table,
    Id,
    Key,
    Name,
    Description,
    Origin,
    TargetKind,
    Target,
    MinVersion,
    RenamedFrom,
    Services,
    Fingerprint,
    Enabled,
    EnabledChoice,
    CreatedAt,
    UpdatedAt,
    UpgradedAt,
    UpgradeSeen,
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
    /// or SQLite in memory, with the tables made.
    async fn migrated() -> sea_orm::DatabaseConnection {
        let connection = match std::env::var("MAXNINES_TEST_DATABASE_URL") {
            Ok(server) => {
                let url = crate::models::fresh_test_database(&server).await;
                let options = ConnectOptions::new(url).max_connections(1).to_owned();
                Database::connect(options).await.unwrap()
            }
            Err(_) => fresh().await,
        };
        Migrator::up(&connection, None).await.unwrap();
        connection
    }

    async fn texts(connection: &impl ConnectionTrait, sql: &str) -> Vec<String> {
        let query = Statement::from_string(connection.get_database_backend(), sql);
        let rows = connection.query_all_raw(query).await.unwrap();
        rows.iter()
            .map(|row| row.try_get_by_index(0).unwrap())
            .collect()
    }

    async fn run(connection: &impl ConnectionTrait, sql: &str) {
        if let Err(error) = connection.execute_unprepared(sql).await {
            panic!("{sql}: {error}");
        }
    }

    async fn refused(connection: &impl ConnectionTrait, sql: &str) {
        assert!(connection.execute_unprepared(sql).await.is_err(), "{sql}");
    }

    async fn count(connection: &impl ConnectionTrait, table: &str) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let query = Statement::from_string(connection.get_database_backend(), sql);
        let row = connection.query_one_raw(query).await.unwrap().unwrap();
        row.try_get_by_index(0).unwrap()
    }

    /// A moment every database reads.
    const AT: &str = "'2026-11-19 00:00:00+00:00'";

    #[tokio::test]
    async fn a_new_database_starts_with_the_built_ins() {
        let connection = migrated().await;

        let hosts = texts(&connection, "SELECT hostname FROM hosts ORDER BY id").await;
        assert_eq!(hosts, ["Fleet", "MaxNines server"]);
        let keyless = "SELECT id FROM hosts WHERE public_key IS NULL ORDER BY id";
        assert_eq!(texts(&connection, keyless).await, ["fleet", "server"]);
        for table in ["config_rules", "templates", "alert_rules"] {
            assert_eq!(
                count(&connection, table).await,
                0,
                "the server writes the built-in {table} as it starts"
            );
        }
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

        // Every check names its host.
        let hostless = "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs,
                            enabled)
                        VALUES ('Site', 'site', 'http', 'https://example.com', 60, TRUE)";
        assert!(connection.execute_unprepared(hostless).await.is_err());

        // A name only has to differ from the other checks about the same host, as
        // names are compared.
        connection
            .execute_unprepared(
                "INSERT INTO hosts (id, hostname, public_key, state, first_seen_at, kind)
                 VALUES ('def', 'web', '', 'approved', '1970-01-01T00:00:00.001+00:00', 'agentless')",
            )
            .await
            .unwrap();
        add("Site", "abc").await.unwrap();
        assert!(add("Site", "abc").await.is_err(), "one to a host");
        assert!(add("SITE", "abc").await.is_err(), "whatever the case");
        add("Site", "def").await.unwrap();

        // A host's checks go with it, and only its own.
        let gone = "DELETE FROM hosts WHERE id = 'abc'";
        connection.execute_unprepared(gone).await.unwrap();
        let left = "SELECT host_id FROM remote_checks ORDER BY id";
        assert_eq!(texts(&connection, left).await, ["def"]);

        // A check going leaves its host.
        connection
            .execute_unprepared("DELETE FROM remote_checks")
            .await
            .unwrap();
        let host = "SELECT hostname FROM hosts WHERE id = 'def'";
        assert_eq!(texts(&connection, host).await, ["web"]);
    }

    /// Every table a host or user has rows in.
    const KEPT_ABOUT_THEM: [&str; 12] = [
        "host_facts",
        "host_config_status",
        "host_boots",
        "metrics_pages",
        "remote_checks",
        "alerts",
        "action_runs",
        "user_sessions",
        "api_keys",
        "app_sign_ins",
        "recovery_codes",
        "sign_in_challenges",
    ];

    #[tokio::test]
    async fn what_is_kept_about_a_host_or_user_goes_with_them() {
        let connection = migrated().await;
        for sql in [
            format!(
                "INSERT INTO hosts (id, kind, hostname, state, first_seen_at)
                 VALUES ('h1', 'agent', 'web', 'approved', {AT})"
            ),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from)
                 VALUES ('h1', 'os.family', 'linux', 'string', {AT})"
            ),
            format!(
                "INSERT INTO host_config_status (host_id, version, reported_at)
                 VALUES ('h1', 'v1', {AT})"
            ),
            format!("INSERT INTO host_boots (host_id, booted_at) VALUES ('h1', {AT})"),
            "INSERT INTO metrics_pages (host_id, url, interval_secs, enabled)
             VALUES ('h1', 'http://web/metrics', 60, TRUE)"
                .to_string(),
            "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs, enabled,
                 host_id)
             VALUES ('Ping', 'ping', 'ping', 'web', 60, TRUE, 'h1')"
                .to_string(),
            "INSERT INTO notification_channels (name, name_key, kind, target)
             VALUES ('Ops', 'ops', 'webhook', 'http://ops')"
                .to_string(),
            "INSERT INTO alert_rules (name, name_key, critical, for_secs, enabled)
             VALUES ('Offline', 'offline', '!online', 60, TRUE)"
                .to_string(),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at)
                 VALUES (1, 'critical', 'h1', 'web is offline', {AT}, {AT})"
            ),
            format!(
                "INSERT INTO action_runs (host_id, alert_id, action, run_on, variables,
                     requested_at, timeout_secs, output, truncated)
                 VALUES ('h1', 1, 'restart', 'first', '{{}}', {AT}, 60, '', FALSE)"
            ),
            format!(
                "INSERT INTO notifications (alert_id, channel_id, event, state, attempts,
                     next_attempt_at, created_at, action_run_id)
                 VALUES (1, 1, 'firing', 'sent', 1, {AT}, {AT}, NULL),
                        (1, 1, 'action', 'pending', 0, {AT}, {AT}, 1)"
            ),
            format!(
                "INSERT INTO users (email, name, created_at)
                 VALUES ('ann@example.com', 'Ann', {AT})"
            ),
            format!(
                "INSERT INTO user_sessions (user_id, token_hash, created_at, expires_at)
                 VALUES (1, 'session', {AT}, {AT})"
            ),
            format!(
                "INSERT INTO api_keys (user_id, name, hint, token_hash, created_at)
                 VALUES (1, 'ci', 'mx_1', 'key', {AT})"
            ),
            format!(
                "INSERT INTO app_sign_ins (user_id, client_id, role, access_hash,
                     access_expires_at, refresh_hash, refresh_expires_at, created_at)
                 VALUES (1, 'cli', 'admin', 'access', {AT}, 'refresh', {AT}, {AT})"
            ),
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, 'code')".to_string(),
            format!(
                "INSERT INTO sign_in_challenges (user_id, token_hash, expires_at)
                 VALUES (1, 'challenge', {AT})"
            ),
        ] {
            run(&connection, &sql).await;
        }

        // A notification of what an action printed points at its run, and a channel
        // can't be deleted while anything was sent through it, as it's only ever
        // marked deleted.
        refused(
            &connection,
            &format!(
                "INSERT INTO notifications (alert_id, channel_id, event, state, attempts,
                     next_attempt_at, created_at, action_run_id)
                 VALUES (1, 1, 'action', 'pending', 0, {AT}, {AT}, 99)"
            ),
        )
        .await;
        refused(
            &connection,
            "DELETE FROM notification_channels WHERE id = 1",
        )
        .await;
        run(&connection, "DELETE FROM action_runs WHERE id = 1").await;
        assert_eq!(count(&connection, "notifications").await, 1);

        run(&connection, "DELETE FROM hosts WHERE id = 'h1'").await;
        run(&connection, "DELETE FROM users WHERE id = 1").await;
        for table in KEPT_ABOUT_THEM.iter().chain(&["notifications"]) {
            assert_eq!(count(&connection, table).await, 0, "{table}");
        }
    }

    #[tokio::test]
    async fn names_facts_and_open_alerts_are_each_kept_unique() {
        let connection = migrated().await;
        let later = "'2026-11-19 00:01:00+00:00'";
        for sql in [
            format!(
                "INSERT INTO hosts (id, kind, hostname, state, first_seen_at)
                 VALUES ('h1', 'agentless', 'web', 'approved', {AT})"
            ),
            format!(
                "INSERT INTO alert_rules (name, name_key, critical, for_secs, enabled,
                     deleted_at)
                 VALUES ('Disk', 'disk', '!online', 60, TRUE, NULL),
                        ('DISK', 'disk', '!online', 60, TRUE, {AT})"
            ),
            "INSERT INTO notification_channels (name, name_key, kind, target)
             VALUES ('Ops', 'ops', 'webhook', 'http://ops')"
                .to_string(),
            "INSERT INTO config_rules (name, name_key, priority, enabled)
             VALUES ('Linux', 'linux', 1, TRUE)"
                .to_string(),
            "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs, enabled,
                 host_id)
             VALUES ('Ping', 'ping', 'ping', 'web', 60, TRUE, 'h1'),
                    ('ping', 'ping', 'ping', 'web', 60, TRUE, 'server')"
                .to_string(),
            // A fact's name is compared exactly, so these are two facts.
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from, valid_to)
                 VALUES ('h1', 'os.family', 'bsd', 'string', {AT}, {later}),
                        ('h1', 'os.family', 'linux', 'string', {later}, NULL),
                        ('h1', 'OS.family', 'linux', 'string', {AT}, NULL)"
            ),
            // So is a series, and a host as a whole counts as a series of its own.
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, series, summary, started_at,
                     breached_at, resolved_at)
                 VALUES (1, 'critical', 'h1', NULL, 'over', {AT}, {AT}, {later}),
                        (1, 'critical', 'h1', NULL, 'first', {later}, {later}, NULL),
                        (1, 'critical', 'h1', '/data', 'a disk', {AT}, {AT}, NULL),
                        (1, 'critical', 'h1', '/Data', 'another', {AT}, {AT}, NULL)"
            ),
        ] {
            run(&connection, &sql).await;
        }

        for sql in [
            "INSERT INTO alert_rules (name, name_key, critical, for_secs, enabled)
             VALUES ('disk ', 'disk', '!online', 60, TRUE)"
                .to_string(),
            "INSERT INTO notification_channels (name, name_key, kind, target)
             VALUES ('OPS', 'ops', 'webhook', 'http://ops')"
                .to_string(),
            "INSERT INTO config_rules (name, name_key, priority, enabled)
             VALUES ('LINUX', 'linux', 1, TRUE)"
                .to_string(),
            "INSERT INTO remote_checks (name, name_key, kind, target, interval_secs, enabled,
                 host_id)
             VALUES ('PING', 'ping', 'ping', 'web', 60, TRUE, 'h1')"
                .to_string(),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from)
                 VALUES ('h1', 'os.family', 'linux', 'string', {AT})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at)
                 VALUES (1, 'critical', 'h1', 'second', {AT}, {AT})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, series, summary, started_at,
                     breached_at)
                 VALUES (1, 'critical', 'h1', '/data', 'again', {AT}, {AT})"
            ),
        ] {
            refused(&connection, &sql).await;
        }

        // Deleted rules and channels, past facts and ended alerts don't count.
        for sql in [
            format!(
                "INSERT INTO alert_rules (name, name_key, critical, for_secs, enabled,
                     deleted_at)
                 VALUES ('Disk', 'disk', '!online', 60, TRUE, {AT})"
            ),
            format!(
                "INSERT INTO notification_channels (name, name_key, kind, target, deleted_at)
                 VALUES ('Ops', 'ops', 'webhook', 'http://ops', {AT})"
            ),
            format!(
                "INSERT INTO host_facts (host_id, name, value, value_type, valid_from, valid_to)
                 VALUES ('h1', 'os.family', 'linux', 'string', {AT}, {AT})"
            ),
            format!(
                "INSERT INTO alerts (rule_id, severity, host_id, summary, started_at, breached_at,
                     resolved_at)
                 VALUES (1, 'critical', 'h1', 'over', {AT}, {AT}, {AT})"
            ),
        ] {
            run(&connection, &sql).await;
        }
    }
}
