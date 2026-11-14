use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "notifications")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub alert_id: i64,
    pub channel_id: i64,
    pub event: String,
    pub state: String,
    pub attempts: i32,
    pub next_attempt_ms: i64,
    pub last_error: Option<String>,
    pub created_ms: i64,
    pub sent_ms: Option<i64>,
    pub external_id: Option<String>,
    /// The action run whose output this sends, for an `action` notification.
    pub action_run_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
