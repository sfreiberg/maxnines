use sea_orm::entity::prelude::*;

/// What an admin decided about an address or range in front of the server.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "proxies")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// An address, or a range such as `10.0.0.0/16`.
    pub address: String,
    /// A proxy to believe, or not a proxy.
    pub trusted: bool,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
