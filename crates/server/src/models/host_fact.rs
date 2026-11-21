use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "host_facts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub host_id: String,
    pub name: String,
    pub value: String,
    pub value_type: String,
    pub valid_from: DateTimeUtc,
    pub valid_to: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
