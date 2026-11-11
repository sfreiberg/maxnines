use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_rules")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub metric: Option<String>,
    pub series: Option<String>,
    pub comparison: Option<String>,
    pub threshold: Option<f64>,
    pub warning_threshold: Option<f64>,
    pub for_secs: i64,
    pub severity: String,
    pub condition_expr: Option<String>,
    pub enabled: bool,
    pub calculation: Option<String>,
    pub group_by: Option<String>,
    pub filter: Option<String>,
    pub window_secs: Option<i64>,
    pub remind_every_secs: Option<i64>,
    pub all_channels: bool,
    pub forecast_secs: Option<i64>,
    pub warning_forecast_secs: Option<i64>,
    /// When it was deleted. Its alerts keep pointing at it.
    pub deleted_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
