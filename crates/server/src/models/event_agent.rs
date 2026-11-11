use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "event_agents")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub event_id: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub agent_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
