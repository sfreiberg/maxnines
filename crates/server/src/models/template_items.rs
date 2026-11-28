//! The short lists and maps of a template's parts, a row to an item: a query's
//! labels, a metric's states and so on. Each table has what its items belong to, the
//! item's key, where it comes among the others, and for a map, its value. Items are
//! written over the rows they have, matched by key, as the parts themselves are.

/// A table of items that are only a name, such as a query's labels.
macro_rules! list_table {
    ($module:ident, $table:literal, $parent:ident, $Parent:ident, $key:ident, $Key:ident) => {
        pub mod $module {
            use std::collections::HashMap;

            use anyhow::{Context, Result};
            use sea_orm::entity::prelude::*;
            use sea_orm::{ActiveValue, QueryOrder};

            #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
            #[sea_orm(table_name = $table)]
            pub struct Model {
                #[sea_orm(primary_key)]
                pub id: i64,
                pub $parent: i64,
                pub $key: String,
                pub position: i32,
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}

            /// The items of what `parent` is, in order.
            pub async fn read<C: ConnectionTrait>(
                connection: &C,
                parent: i64,
            ) -> Result<Vec<String>> {
                let rows = Entity::find()
                    .filter(Column::$Parent.eq(parent))
                    .order_by_asc(Column::Position)
                    .all(connection)
                    .await
                    .context(concat!("loading ", $table))?;
                Ok(rows.into_iter().map(|row| row.$key).collect())
            }

            /// Writes the items over the rows there are, each matched by its name, an
            /// item listed twice to two of them, so writing the same again changes
            /// nothing.
            pub async fn write<C: ConnectionTrait>(
                connection: &C,
                parent: i64,
                items: &[String],
            ) -> Result<()> {
                let mut left: HashMap<String, Vec<Model>> = HashMap::new();
                let rows = Entity::find()
                    .filter(Column::$Parent.eq(parent))
                    .order_by_desc(Column::Position)
                    .all(connection)
                    .await
                    .context(concat!("loading ", $table))?;
                for row in rows {
                    left.entry(row.$key.clone()).or_default().push(row);
                }
                for (position, item) in items.iter().enumerate() {
                    let position = i32::try_from(position)?;
                    match left.get_mut(item).and_then(Vec::pop) {
                        Some(row) if row.position == position => {}
                        Some(row) => {
                            let mut active: ActiveModel = row.into();
                            active.position = ActiveValue::Set(position);
                            active
                                .update(connection)
                                .await
                                .context(concat!("saving ", $table))?;
                        }
                        None => {
                            ActiveModel {
                                $parent: ActiveValue::Set(parent),
                                $key: ActiveValue::Set(item.clone()),
                                position: ActiveValue::Set(position),
                                ..Default::default()
                            }
                            .insert(connection)
                            .await
                            .context(concat!("saving ", $table))?;
                        }
                    }
                }
                let gone: Vec<i64> = left.into_values().flatten().map(|row| row.id).collect();
                if !gone.is_empty() {
                    Entity::delete_many()
                        .filter(Column::Id.is_in(gone))
                        .exec(connection)
                        .await
                        .context(concat!("deleting ", $table))?;
                }
                Ok(())
            }
        }
    };
}

/// A table of items that are a name and what it stands for, such as a metric's
/// states.
macro_rules! map_table {
    ($module:ident, $table:literal, $parent:ident, $Parent:ident, $key:ident, $value:ident) => {
        pub mod $module {
            use std::collections::HashMap;

            use anyhow::{Context, Result};
            use indexmap::IndexMap;
            use sea_orm::entity::prelude::*;
            use sea_orm::{ActiveValue, QueryOrder};

            #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
            #[sea_orm(table_name = $table)]
            pub struct Model {
                #[sea_orm(primary_key)]
                pub id: i64,
                pub $parent: i64,
                pub $key: String,
                pub position: i32,
                pub $value: String,
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}

            /// The items of what `parent` is, in order.
            pub async fn read<C: ConnectionTrait>(
                connection: &C,
                parent: i64,
            ) -> Result<IndexMap<String, String>> {
                let rows = Entity::find()
                    .filter(Column::$Parent.eq(parent))
                    .order_by_asc(Column::Position)
                    .all(connection)
                    .await
                    .context(concat!("loading ", $table))?;
                Ok(rows.into_iter().map(|row| (row.$key, row.$value)).collect())
            }

            /// Writes the items over the rows there are, each matched by its name.
            pub async fn write<C: ConnectionTrait>(
                connection: &C,
                parent: i64,
                items: &IndexMap<String, String>,
            ) -> Result<()> {
                let mut left: HashMap<String, Model> = Entity::find()
                    .filter(Column::$Parent.eq(parent))
                    .all(connection)
                    .await
                    .context(concat!("loading ", $table))?
                    .into_iter()
                    .map(|row| (row.$key.clone(), row))
                    .collect();
                for (position, (name, value)) in items.iter().enumerate() {
                    let position = i32::try_from(position)?;
                    match left.remove(name) {
                        Some(row) if row.position == position && row.$value == *value => {}
                        Some(row) => {
                            let mut active: ActiveModel = row.into();
                            active.position = ActiveValue::Set(position);
                            active.$value = ActiveValue::Set(value.clone());
                            active
                                .update(connection)
                                .await
                                .context(concat!("saving ", $table))?;
                        }
                        None => {
                            ActiveModel {
                                $parent: ActiveValue::Set(parent),
                                $key: ActiveValue::Set(name.clone()),
                                position: ActiveValue::Set(position),
                                $value: ActiveValue::Set(value.clone()),
                                ..Default::default()
                            }
                            .insert(connection)
                            .await
                            .context(concat!("saving ", $table))?;
                        }
                    }
                }
                let gone: Vec<i64> = left.into_values().map(|row| row.id).collect();
                if !gone.is_empty() {
                    Entity::delete_many()
                        .filter(Column::Id.is_in(gone))
                        .exec(connection)
                        .await
                        .context(concat!("deleting ", $table))?;
                }
                Ok(())
            }
        }
    };
}

list_table!(
    renames,
    "template_renames",
    template_id,
    TemplateId,
    old_key,
    OldKey
);
list_table!(
    services,
    "template_services",
    template_id,
    TemplateId,
    service,
    Service
);
list_table!(
    query_labels,
    "template_query_labels",
    query_id,
    QueryId,
    label,
    Label
);
list_table!(
    counters_excludes,
    "template_counters_excludes",
    counters_id,
    CountersId,
    instance,
    Instance
);
map_table!(
    counter_sets,
    "template_counter_sets",
    discovery_id,
    DiscoveryId,
    key,
    counter_set
);
map_table!(
    discovery_columns,
    "template_discovery_columns",
    discovery_id,
    DiscoveryId,
    name,
    source
);
map_table!(
    query_columns,
    "template_query_columns",
    query_id,
    QueryId,
    name,
    source
);
map_table!(
    registry_values,
    "template_registry_values",
    registry_read_id,
    RegistryReadId,
    key,
    value_name
);
map_table!(
    counters_groups,
    "template_counters_groups",
    counters_id,
    CountersId,
    key,
    counter
);
map_table!(
    metric_states,
    "template_metric_states",
    metric_id,
    MetricId,
    number,
    word
);
