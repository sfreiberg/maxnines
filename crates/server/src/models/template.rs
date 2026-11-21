use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "templates")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// What it's known by, which starts its metrics' names.
    pub key: String,
    pub name: String,
    /// The name as it's compared, which is what's kept unique: see
    /// [`super::name_key`].
    pub name_key: String,
    pub description: Option<String>,
    pub built_in: bool,
    /// The template in HCL.
    pub source: String,
    /// For a built-in one, a hash of what it says.
    pub fingerprint: Option<String>,
    pub enabled: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    /// When an upgrade last changed it.
    pub upgraded_at: Option<DateTimeUtc>,
    /// Whether admins have dismissed the notice of that upgrade.
    pub upgrade_seen: bool,
    pub deleted_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
