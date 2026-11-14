use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_rule_channels")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub rule_id: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub channel_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
