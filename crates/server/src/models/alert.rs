use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "alerts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// Rules are only ever marked deleted, so it's always there to name the alert.
    pub rule_id: i64,
    pub severity: String,
    pub host_id: String,
    /// None for an alert about the host as a whole.
    pub series: Option<String>,
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
