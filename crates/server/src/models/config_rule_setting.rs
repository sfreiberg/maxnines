use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "config_rule_settings")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub rule_id: i64,
    pub name: String,
    pub value: String,
    pub value_type: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
