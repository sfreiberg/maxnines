use sea_orm::entity::prelude::*;

/// A fill's SQL from one version on.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_fill_versions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub fill_id: i64,
    pub version: String,
    pub position: i32,
    pub sql: String,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
