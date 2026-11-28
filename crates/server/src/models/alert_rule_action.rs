use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_rule_actions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub rule_id: i64,
    pub action: String,
    pub run_on: String,
    pub timeout_secs: i64,
    pub position: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
