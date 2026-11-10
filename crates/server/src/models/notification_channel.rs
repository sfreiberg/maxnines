use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "notification_channels")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub credential: Option<String>,
    pub app_token: Option<String>,
    pub sends_warnings: bool,
    pub sends_critical: bool,
    pub mail_from: Option<String>,
    pub mail_host: Option<String>,
    pub mail_port: Option<i32>,
    pub mail_security: Option<String>,
    pub mail_username: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
