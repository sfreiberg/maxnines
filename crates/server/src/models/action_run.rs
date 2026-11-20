use std::collections::BTreeMap;

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "action_runs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub host_id: String,
    pub alert_id: Option<i64>,
    pub action: String,
    pub run_on: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub variables: Variables,
    pub requested_by: Option<String>,
    pub requested_at: DateTimeUtc,
    pub timeout_secs: i64,
    pub outcome: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub output: String,
    pub truncated: bool,
    pub duration_secs: Option<f64>,
    pub finished_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// What a run was given, by name, kept as a JSON object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, FromJsonQueryResult)]
pub struct Variables(pub BTreeMap<String, String>);
