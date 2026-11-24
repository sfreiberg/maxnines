use sea_orm::entity::prelude::*;

/// A device a UniFi check found, and the host without an agent it's kept under.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "unifi_devices")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub remote_check_id: i64,
    /// The console's ID for the device.
    pub device_id: String,
    pub host_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
