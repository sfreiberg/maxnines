use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "action_runs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub host_id: String,
    pub alert_id: Option<i64>,
    pub action: String,
    pub run_on: String,
    pub variables: String,
    pub requested_by: Option<String>,
    pub requested_ms: i64,
    pub timeout_secs: i64,
    pub outcome: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub output: String,
    pub truncated: bool,
    pub duration_ms: Option<i64>,
    pub finished_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
