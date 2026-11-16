use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_sessions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub user_id: i64,
    /// Only the hash is kept, so reading the database doesn't sign anyone in.
    pub token_hash: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    /// When it was last used, to about a minute.
    pub last_used_ms: Option<i64>,
    /// The address it was last used from.
    pub last_address: Option<String>,
    /// What the browser said it was when it signed in.
    pub user_agent: Option<String>,
    /// The address an untrusted proxy said it was passing on, so unconfirmed.
    pub last_forwarded_for: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
