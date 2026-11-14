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
    pub mail_hostname: Option<String>,
    pub mail_port: Option<i32>,
    pub mail_security: Option<String>,
    pub mail_username: Option<String>,
    pub request_method: Option<String>,
    pub request_content_type: Option<String>,
    pub request_body: Option<String>,
    /// When it was deleted. Its notifications keep pointing at it.
    pub deleted_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
