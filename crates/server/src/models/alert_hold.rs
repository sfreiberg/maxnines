use sea_orm::entity::prelude::*;

/// Since when a level of a rule has been crossed for a host and series, without
/// an alert yet or while one is open, so a long wait carries on after a restart.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_holds")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub rule_id: i64,
    pub host_id: String,
    /// Empty for the host as a whole.
    pub series: String,
    pub severity: String,
    pub breached_since: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
