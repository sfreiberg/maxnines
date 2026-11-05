use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "alerts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub rule_id: Option<i64>,
    pub rule_name: String,
    pub severity: String,
    pub agent_id: String,
    pub host: String,
    pub series: String,
    pub value: Option<f64>,
    pub summary: String,
    pub started_ms: i64,
    pub resolved_ms: Option<i64>,
    pub resolve_reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
