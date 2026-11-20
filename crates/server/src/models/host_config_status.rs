use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "host_config_status")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub host_id: String,
    pub version: String,
    pub error: Option<String>,
    pub reported_at: DateTimeUtc,
    /// Collectors in the config that the agent doesn't know, one to a line, or NULL
    /// for none.
    pub skipped_collectors: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
