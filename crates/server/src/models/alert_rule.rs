use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_rules")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    /// The name as it's compared, which is what's kept unique: see
    /// [`super::name_key`].
    pub name_key: String,
    pub warning: Option<String>,
    pub critical: Option<String>,
    pub summary: Option<String>,
    pub resolved_summary: Option<String>,
    pub for_secs: i64,
    pub applies_to: Option<String>,
    pub enabled: bool,
    pub calculation: Option<String>,
    pub metric: Option<String>,
    pub group_by: Option<String>,
    pub filter: Option<String>,
    pub window_secs: Option<i64>,
    pub remind_every_secs: Option<i64>,
    pub all_channels: bool,
    /// The template whose alert it is, if it's one.
    pub template_id: Option<i64>,
    /// Which of the template's alerts.
    pub template_alert: Option<String>,
    /// What people changed of the template's values, by field, as the API names
    /// them. The rest of the row is what's in effect.
    pub overrides: Option<Json>,
    /// Whether it needs what only agents running its template would send.
    pub waits_for_agents: bool,
    /// When it was deleted. Its alerts keep pointing at it.
    pub deleted_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
