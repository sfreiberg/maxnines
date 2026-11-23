use sea_orm::entity::prelude::*;

/// One of a template's discover blocks.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_discoveries")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub template_id: i64,
    pub key: String,
    pub position: i32,
    pub interval_secs: Option<i64>,
    pub sql: Option<String>,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
    /// On someone's copy: when a newer version changed what it's a copy of.
    pub original_changed_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
