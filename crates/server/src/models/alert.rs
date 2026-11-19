use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "alerts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub rule_id: Option<i64>,
    pub rule_name: String,
    pub severity: String,
    pub host_id: String,
    pub hostname: String,
    pub series: String,
    pub value: Option<f64>,
    pub summary: String,
    pub started_at: DateTimeUtc,
    pub breached_at: DateTimeUtc,
    pub resolved_at: Option<DateTimeUtc>,
    pub resolve_reason: Option<String>,
    pub resolved_summary: Option<String>,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
