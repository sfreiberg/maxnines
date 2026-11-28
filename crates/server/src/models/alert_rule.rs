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
    /// Whether it's on, which for a built-in or imported template's rule is what
    /// the template ships.
    pub enabled: bool,
    /// What someone chose instead of what the template ships, if they have.
    pub enabled_choice: Option<bool>,
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
    /// The built-in template's rule this is someone's own copy of, which is used
    /// in its place.
    pub replaces_id: Option<i64>,
    /// Where it comes among its template's alerts.
    pub template_position: Option<i32>,
    /// Which of what its template's discovery found it's for, as CEL.
    pub when_condition: Option<String>,
    /// The version it's from.
    pub since: Option<String>,
    /// When an upgrade last changed the built-in rule this is a copy of.
    pub original_changed_at: Option<DateTimeUtc>,
    /// When it was deleted. Its alerts keep pointing at it.
    pub deleted_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
