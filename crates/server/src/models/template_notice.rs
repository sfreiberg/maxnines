use sea_orm::entity::prelude::*;

/// A notice a template shows.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_notices")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub template_id: i64,
    pub key: String,
    pub position: i32,
    pub when_condition: Option<String>,
    pub text: String,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
