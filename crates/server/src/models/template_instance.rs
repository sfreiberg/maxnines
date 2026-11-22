use sea_orm::entity::prelude::*;

/// A database a template runs for on a host, with when its discovery last
/// reported what it found there.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_instances")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub host_id: String,
    pub template_id: i64,
    /// Its name in the agent's config.
    pub database_name: String,
    pub discovered_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
