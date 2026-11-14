use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "dashboard_widgets")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub dashboard_id: i64,
    pub title: String,
    pub kind: String,
    pub metric: String,
    pub calculation: String,
    pub group_by: String,
    pub filter: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
