use sea_orm::entity::prelude::*;

/// Something going wrong reading a template for a database on a host, or on the
/// host, with an empty database name.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "template_errors")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub host_id: String,
    pub template_id: i64,
    pub database_name: String,
    /// What went wrong: `connecting`, `account`, or a part, as `query sessions`.
    pub part: String,
    pub message: String,
    /// When it first said this.
    pub since: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
