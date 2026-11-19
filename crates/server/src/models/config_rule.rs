use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "config_rules")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    pub priority: i32,
    pub condition_expr: Option<String>,
    pub enabled: bool,
    /// The systems it's for, comma separated, or nothing for all of them.
    pub operating_systems: Option<String>,
    /// Which built-in rule it is, for one that ships with the server.
    pub built_in: Option<String>,
    /// When an upgrade last changed a built-in rule.
    pub built_in_changed_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
