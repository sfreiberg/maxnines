use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "agent_facts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub agent_id: String,
    pub name: String,
    pub value: String,
    pub value_type: String,
    pub valid_from_ms: i64,
    pub valid_to_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
