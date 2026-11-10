use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_log")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub at_ms: i64,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub actor_name: String,
    pub source: Option<String>,
    pub action: String,
    pub subject_kind: String,
    pub subject_id: Option<String>,
    pub subject_name: String,
    /// JSON, a list of [`crate::audit::Change`].
    pub changes: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
