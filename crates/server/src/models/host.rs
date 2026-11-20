use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "hosts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// `agent`, `agentless` or `built_in`.
    pub kind: String,
    /// None for a host with no agent, which has no key.
    pub public_key: Option<String>,
    pub hostname: String,
    pub state: String,
    pub decided_by: Option<String>,
    pub first_seen_at: DateTimeUtc,
    pub decided_at: Option<DateTimeUtc>,
    /// When the server began refusing its agent for the protocol it speaks, why, and
    /// that protocol, while it does.
    pub refused_at: Option<DateTimeUtc>,
    pub refused_reason: Option<String>,
    pub refused_protocol: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
