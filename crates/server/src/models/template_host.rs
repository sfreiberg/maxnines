use sea_orm::entity::prelude::*;

/// A host given a template by hand, on top of those its condition picks.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_hosts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub template_id: i64,
    pub host_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
