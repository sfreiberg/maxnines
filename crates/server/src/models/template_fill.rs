use sea_orm::entity::prelude::*;

/// A piece of a query's SQL picked by version.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_fills")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub query_id: i64,
    pub key: String,
    pub position: i32,
    pub older: Option<String>,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
