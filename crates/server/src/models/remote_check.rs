use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remote_checks")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// The host it's about: one with no agent, or the server itself.
    pub host_id: String,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub timeout_secs: Option<i64>,
    pub method: Option<String>,
    pub body: Option<String>,
    pub regex: Option<String>,
    pub insecure: Option<bool>,
    pub server: Option<String>,
    pub record: Option<String>,
    pub count: Option<i32>,
    pub interval_secs: i64,
    pub enabled: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
