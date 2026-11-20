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
    /// What its agent said in its last hello.
    pub agent_protocol: Option<i64>,
    pub agent_version: Option<String>,
    /// When and why its agent was last turned away for its protocol, until one it
    /// says is taken.
    pub refused_at: Option<DateTimeUtc>,
    pub refuse_reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
