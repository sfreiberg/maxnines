use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "dashboard_variables")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub dashboard_id: i64,
    pub position: i32,
    pub name: String,
    /// None uses the name.
    pub label: Option<String>,
    pub kind: String,
    /// None for a host variable, which offers hosts rather than a fact's values.
    pub fact: Option<String>,
    /// None for every host.
    pub filter: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
