use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "silences")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub rule_id: Option<i64>,
    pub filter: String,
    pub reason: String,
    pub created_by: String,
    pub starts_ms: i64,
    pub ends_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
