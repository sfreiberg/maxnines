use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// Lowercase, as this is what someone signs in with.
    pub email: String,
    pub name: String,
    /// Empty until they've set one, and for anyone who only signs in another way.
    pub password_hash: Option<String>,
    pub theme: String,
    /// The link for setting a password. Only the hash is kept.
    pub setup_token_hash: Option<String>,
    pub setup_expires_ms: Option<i64>,
    pub created_ms: i64,
    pub last_sign_in_ms: Option<i64>,
    pub disabled_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
