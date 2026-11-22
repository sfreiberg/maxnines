use sea_orm::entity::prelude::*;

/// One column a template's discovery found for a database, kept as a fact is.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_instance_values")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub instance_id: i64,
    pub name: String,
    pub value: String,
    /// `string`, `number` or `boolean`, as facts have.
    pub value_type: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
