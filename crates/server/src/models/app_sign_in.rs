use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "app_sign_ins")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// Who it acts as.
    pub user_id: i64,
    /// Which app, such as `maxnines-cli`.
    pub client_id: String,
    /// What the app calls the computer it's on.
    pub device: Option<String>,
    /// The most it may do: `viewer`, `responder`, `editor` or `admin`.
    pub role: String,
    /// Only hashes are kept, so reading the database doesn't sign anything in.
    pub access_hash: String,
    pub access_expires_at: DateTimeUtc,
    pub refresh_hash: String,
    /// The refresh token this one replaced, which still works for a moment.
    pub previous_refresh_hash: Option<String>,
    pub rotated_at: Option<DateTimeUtc>,
    pub refresh_expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,
    pub last_used_at: Option<DateTimeUtc>,
    /// The address it was last used from.
    pub last_address: Option<String>,
    /// The address an untrusted proxy said it was passing on, so unconfirmed.
    pub last_forwarded_for: Option<String>,
    pub revoked_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
