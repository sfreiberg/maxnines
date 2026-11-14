use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "metrics_pages")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub host_id: String,
    pub url: String,
    /// The metrics to keep, one to a line. Empty keeps them all.
    pub names: String,
    pub interval_secs: i64,
    pub enabled: bool,
    pub username: Option<String>,
    /// As it was typed in, when it was.
    pub password: Option<String>,
    /// The server's environment variable that holds it, when one does.
    pub password_env: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
