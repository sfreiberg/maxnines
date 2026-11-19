use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::audit::Change;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_log")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub occurred_at: DateTimeUtc,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub actor_name: String,
    pub via_kind: Option<String>,
    pub via_id: Option<String>,
    pub via_name: Option<String>,
    pub source: Option<String>,
    /// The address an untrusted proxy said it was passing on, so unconfirmed.
    pub forwarded_for: Option<String>,
    pub action: String,
    pub subject_kind: String,
    pub subject_id: Option<String>,
    pub subject_name: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub changes: Changes,
}

/// What changed, kept as a JSON list.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, FromJsonQueryResult)]
pub struct Changes(pub Vec<Change>);

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
