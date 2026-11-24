use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remote_checks")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// The host with no agent it's about.
    pub host_id: String,
    pub name: String,
    /// The name as it's compared, which is what's kept unique: see
    /// [`super::name_key`].
    pub name_key: String,
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
    pub database: Option<String>,
    pub tls: Option<bool>,
    pub host_key: Option<String>,
    pub username: Option<String>,
    /// As it was typed in, when it was.
    pub password: Option<String>,
    /// The server's environment variable that holds it, when one does.
    pub password_env: Option<String>,
    /// As it was typed in, when it was.
    pub private_key: Option<String>,
    pub private_key_env: Option<String>,
    pub domain_expiry: Option<bool>,
    /// For a database: whether to read its health and replication too.
    pub read_stats: bool,
    /// For a heartbeat: how late a ping can be.
    pub grace_secs: Option<i64>,
    /// For a heartbeat: the token in the address it's pinged at.
    pub ping_token: Option<String>,
    /// For UniFi: the one site to read, if not all.
    pub site: Option<String>,
    /// For UniFi: the API key, as it was typed in, when it was.
    pub api_key: Option<String>,
    pub api_key_env: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
