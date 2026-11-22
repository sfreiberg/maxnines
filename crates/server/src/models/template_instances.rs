//! What templates' discovery found, for each database a template runs for on each
//! host. Agents report it with their samples, and the server works out from it which
//! queries each runs and which databases a template's alerts with `when` or `since`
//! are for.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde_json::{Map, Value};

use maxnines_protocol::templates::work::Discovered;

use super::{Database, template, template_instance, template_instance_value};
use crate::facts::{decode, encode};
use crate::templates::work::Discoveries;
use crate::times::Timestamp;

/// The most columns one database's discovery is kept for.
pub const MAX_VALUES: usize = 256;
/// The longest a name or a piece of text found can be.
pub const MAX_VALUE_LEN: usize = 1024;

/// Whether what an agent says discovery found could be kept.
pub fn can_keep(found: &Discovered) -> bool {
    found.values.len() <= MAX_VALUES
        && found.database.len() <= 255
        && found.values.iter().all(|(name, value)| {
            !name.is_empty()
                && name.len() <= 255
                && match value {
                    Value::String(text) => text.len() <= MAX_VALUE_LEN,
                    Value::Bool(_) | Value::Number(_) | Value::Null => true,
                    _ => false,
                }
        })
}

impl Database {
    /// Keeps what discovery found on a host, at `at`, the time of the sample that
    /// said it. A sample older than what's kept, as an agent sends samples it kept
    /// while away after its live ones, changes nothing, and nor does one for a
    /// template there isn't. Returns whether anything found changed.
    pub async fn save_discovered(
        &self,
        host_id: &str,
        found: &[Discovered],
        at: Timestamp,
    ) -> Result<bool> {
        let keys: Vec<&str> = found.iter().map(|one| one.template.as_str()).collect();
        let templates: HashMap<String, i64> = template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .filter(template::Column::Key.is_in(keys))
            .all(&self.connection)
            .await
            .context("loading templates")?
            .into_iter()
            .map(|row| (row.key, row.id))
            .collect();
        let transaction = self
            .connection
            .begin()
            .await
            .context("saving what discovery found")?;
        let mut changed = false;
        for one in found.iter().filter(|one| can_keep(one)) {
            let Some(template_id) = templates.get(&one.template) else {
                continue;
            };
            let existing = template_instance::Entity::find()
                .filter(template_instance::Column::HostId.eq(host_id))
                .filter(template_instance::Column::TemplateId.eq(*template_id))
                .filter(template_instance::Column::DatabaseName.eq(&one.database))
                .one(&transaction)
                .await
                .context("loading what discovery found")?;
            let instance_id = match existing {
                Some(row) if row.discovered_at > at => continue,
                Some(row) => {
                    let id = row.id;
                    let mut row: template_instance::ActiveModel = row.into();
                    row.discovered_at = Set(at);
                    row.update(&transaction)
                        .await
                        .context("saving what discovery found")?;
                    id
                }
                None => {
                    template_instance::Entity::insert(template_instance::ActiveModel {
                        host_id: Set(host_id.to_string()),
                        template_id: Set(*template_id),
                        database_name: Set(one.database.clone()),
                        discovered_at: Set(at),
                        ..Default::default()
                    })
                    .exec(&transaction)
                    .await
                    .context("saving what discovery found")?
                    .last_insert_id
                }
            };
            let kept = values_of(&transaction, instance_id).await?;
            if kept == one.values {
                continue;
            }
            changed = true;
            template_instance_value::Entity::delete_many()
                .filter(template_instance_value::Column::InstanceId.eq(instance_id))
                .exec(&transaction)
                .await
                .context("saving what discovery found")?;
            if !one.values.is_empty() {
                let rows = one.values.iter().map(|(name, value)| {
                    let (value, value_type) = encode(value);
                    template_instance_value::ActiveModel {
                        instance_id: Set(instance_id),
                        name: Set(name.clone()),
                        value: Set(value),
                        value_type: Set(value_type.to_string()),
                        ..Default::default()
                    }
                });
                template_instance_value::Entity::insert_many(rows)
                    .exec(&transaction)
                    .await
                    .context("saving what discovery found")?;
            }
        }
        transaction
            .commit()
            .await
            .context("saving what discovery found")?;
        Ok(changed)
    }

    /// What discovery found on one host.
    pub async fn discoveries(&self, host_id: &str) -> Result<Discoveries> {
        let instances = template_instance::Entity::find()
            .filter(template_instance::Column::HostId.eq(host_id))
            .all(&self.connection)
            .await
            .context("loading what discovery found")?;
        let mut found = Discoveries::new();
        for instance in instances {
            let values = values_of(&self.connection, instance.id).await?;
            found.insert((instance.template_id, instance.database_name), values);
        }
        Ok(found)
    }

    /// What discovery found on every host, by host ID.
    pub async fn all_discoveries(&self) -> Result<BTreeMap<String, Discoveries>> {
        let instances: HashMap<i64, template_instance::Model> = template_instance::Entity::find()
            .all(&self.connection)
            .await
            .context("loading what discovery found")?
            .into_iter()
            .map(|row| (row.id, row))
            .collect();
        let mut values: HashMap<i64, Map<String, Value>> = HashMap::new();
        for row in template_instance_value::Entity::find()
            .all(&self.connection)
            .await
            .context("loading what discovery found")?
        {
            let value = decode(&row.value, &row.value_type)?;
            values
                .entry(row.instance_id)
                .or_default()
                .insert(row.name, value);
        }
        let mut found: BTreeMap<String, Discoveries> = BTreeMap::new();
        for (id, instance) in instances {
            found.entry(instance.host_id).or_default().insert(
                (instance.template_id, instance.database_name),
                values.remove(&id).unwrap_or_default(),
            );
        }
        Ok(found)
    }
}

async fn values_of<C: sea_orm::ConnectionTrait>(
    connection: &C,
    instance_id: i64,
) -> Result<Map<String, Value>> {
    let mut values = Map::new();
    for row in template_instance_value::Entity::find()
        .filter(template_instance_value::Column::InstanceId.eq(instance_id))
        .all(connection)
        .await
        .context("loading what discovery found")?
    {
        values.insert(row.name, decode(&row.value, &row.value_type)?);
    }
    Ok(values)
}
