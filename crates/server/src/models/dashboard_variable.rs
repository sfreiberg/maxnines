use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "dashboard_variables")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub dashboard_id: i64,
    pub position: i32,
    pub name: String,
    pub label: String,
    pub kind: String,
    pub fact: String,
    pub filter: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
