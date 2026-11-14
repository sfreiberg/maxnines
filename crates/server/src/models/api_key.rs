use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    /// Who it acts as.
    pub user_id: i64,
    /// `viewer`, `responder`, `editor` or `admin`.
    pub role: String,
    /// The start of the key, to tell keys apart once the key itself is gone.
    pub hint: String,
    /// Only the hash is kept, so reading the database doesn't give anyone a key.
    pub token_hash: String,
    pub created_ms: i64,
    /// Empty means it never expires.
    pub expires_ms: Option<i64>,
    pub last_used_ms: Option<i64>,
    pub revoked_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
