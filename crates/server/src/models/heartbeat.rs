use sea_orm::entity::prelude::*;

/// What a heartbeat check has been pinged with. A row is made by its first ping.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "heartbeats")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub remote_check_id: i64,
    /// When it last said a run finished, or failed.
    pub pinged_at: Option<DateTimeUtc>,
    /// Whether that last ping said the run failed.
    pub failed: bool,
    /// When a run it's said it started began, until that run finishes or fails.
    pub started_at: Option<DateTimeUtc>,
    /// How long the last run took, when it said when it started.
    pub run_secs: Option<f64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
