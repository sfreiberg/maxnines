use sea_orm::entity::prelude::*;

/// Performance counters of a template's that become metrics.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_counters")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub template_id: i64,
    pub key: String,
    pub position: i32,
    pub object: String,
    pub label: Option<String>,
    pub pattern: Option<String>,
    pub instance: Option<String>,
    pub exclude: Option<Json>,
    pub groups: Option<Json>,
    pub join_object: Option<String>,
    pub join_pattern: Option<String>,
    pub when_condition: Option<String>,
    pub since: Option<String>,
    pub interval_secs: Option<i64>,
    pub enabled: bool,
    /// What someone chose in place of the template's `enabled`, if they have.
    pub enabled_choice: Option<bool>,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
