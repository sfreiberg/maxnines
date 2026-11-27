use sea_orm::entity::prelude::*;

/// A host an event is for, found when it was recorded.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "event_hosts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub event_id: i64,
    pub host_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
