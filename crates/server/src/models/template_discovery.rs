use sea_orm::entity::prelude::*;

/// What a template's discovery runs.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_discoveries")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub template_id: i64,
    pub interval_secs: Option<i64>,
    pub sql: Option<String>,
    pub counter_sets: Option<Json>,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
