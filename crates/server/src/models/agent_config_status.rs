use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "agent_config_status")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub agent_id: String,
    pub version: String,
    pub error: Option<String>,
    pub reported_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
