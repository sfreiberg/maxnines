//! The devices UniFi checks have found, each kept under a host of its own.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};

use super::{Database, save_host_in, unifi_device};
use crate::registration::HostRecord;

impl Database {
    /// The host each device a UniFi check has found is kept under, by the
    /// console's ID for the device.
    pub async fn unifi_device_hosts(&self, check_id: i64) -> Result<BTreeMap<String, String>> {
        let rows = unifi_device::Entity::find()
            .filter(unifi_device::Column::RemoteCheckId.eq(check_id))
            .all(&self.connection)
            .await
            .context("loading UniFi devices")?;
        Ok(rows
            .into_iter()
            .map(|row| (row.device_id, row.host_id))
            .collect())
    }

    /// Saves a new host for a device a UniFi check found, with which device it's
    /// for, together, so a device never gets two.
    pub async fn save_unifi_device_host(
        &self,
        host: &HostRecord,
        check_id: i64,
        device_id: &str,
    ) -> Result<()> {
        let transaction = self.connection.begin().await.context("saving host")?;
        save_host_in(&transaction, host).await?;
        let row = unifi_device::ActiveModel {
            remote_check_id: Set(check_id),
            device_id: Set(device_id.to_string()),
            host_id: Set(host.id.clone()),
            ..Default::default()
        };
        unifi_device::Entity::insert(row)
            .exec(&transaction)
            .await
            .context("saving a UniFi device")?;
        transaction.commit().await.context("saving host")?;
        Ok(())
    }
}
