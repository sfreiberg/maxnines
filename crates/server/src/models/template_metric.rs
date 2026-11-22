use sea_orm::entity::prelude::*;

/// A metric of a template's query or counters.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_metrics")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub query_id: Option<i64>,
    pub counters_id: Option<i64>,
    pub key: String,
    pub position: i32,
    pub counter: Option<String>,
    pub unit: Option<String>,
    pub total: bool,
    pub description: Option<String>,
    pub value: Option<String>,
    pub since: Option<String>,
    pub states: Option<Json>,
    /// The built-in part this is someone's own copy of, if it's one.
    pub replaces_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
