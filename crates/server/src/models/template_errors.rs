//! What's going wrong reading templates: for each template and database a host
//! reads, or on the host, each thing that went wrong the last time, such as a query
//! the database refused, with what it said and since when. Agents say it with their
//! samples whenever it changes, as the server does for hosts with no agent, and each
//! time replaces what was said before, so what's kept is only what's wrong now.

use std::collections::HashMap;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde::Serialize;

use maxnines_protocol::templates::work::{MAX_ERROR_LEN, MAX_ERRORS, TemplateErrors};

use super::{Database, template, template_error};
use crate::templates::work::{ON_HOST, instance_of};
use crate::times::Timestamp;

/// The longest what went wrong can be called: `query ` and a key.
const MAX_PART_LEN: usize = 300;

/// Whether what an agent says is going wrong could be kept.
pub fn can_keep(said: &TemplateErrors) -> bool {
    said.errors.len() <= MAX_ERRORS
        && said.database.as_ref().is_none_or(|name| name.len() <= 255)
        && said.errors.iter().all(|(part, message)| {
            !part.is_empty()
                && part.len() <= MAX_PART_LEN
                && message.chars().count() <= MAX_ERROR_LEN
        })
}

/// Something going wrong reading a template on a host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemplateError {
    pub host_id: String,
    pub template_id: i64,
    /// The database it's reading, or none for a template that runs once on the host.
    pub database: Option<String>,
    /// What went wrong: `connecting`, `account`, or a part, as `query sessions`.
    pub part: String,
    pub message: String,
    /// When it first said this.
    pub since: Timestamp,
}

impl From<template_error::Model> for TemplateError {
    fn from(row: template_error::Model) -> Self {
        Self {
            host_id: row.host_id,
            template_id: row.template_id,
            database: (row.database_name != ON_HOST).then_some(row.database_name),
            part: row.part,
            message: row.message,
            since: row.since,
        }
    }
}

impl Database {
    /// Keeps what a host says is going wrong reading templates, as a sample taken
    /// at `at` said it: for each template and database it says anything of, what's
    /// wrong now in place of what was before. Something still saying the same keeps
    /// when it began. Anything said of a template there isn't, or more than could
    /// be kept, is let go.
    pub async fn save_template_errors(
        &self,
        host_id: &str,
        said: &[TemplateErrors],
        at: Timestamp,
    ) -> Result<()> {
        let keys: Vec<&str> = said.iter().map(|one| one.template.as_str()).collect();
        let templates: HashMap<String, i64> = template::Entity::find()
            .filter(template::Column::DeletedAt.is_null())
            .filter(template::Column::Key.is_in(keys))
            .all(&self.connection)
            .await
            .context("loading templates")?
            .into_iter()
            .map(|row| (row.key, row.id))
            .collect();
        for one in said.iter().filter(|one| can_keep(one)) {
            let Some(&template_id) = templates.get(&one.template) else {
                continue;
            };
            let database = instance_of(one.database.as_deref());
            let mut left: HashMap<String, template_error::Model> = template_error::Entity::find()
                .filter(template_error::Column::HostId.eq(host_id))
                .filter(template_error::Column::TemplateId.eq(template_id))
                .filter(template_error::Column::DatabaseName.eq(database.clone()))
                .all(&self.connection)
                .await
                .context("loading what's going wrong")?
                .into_iter()
                .map(|row| (row.part.clone(), row))
                .collect();
            for (part, message) in &one.errors {
                match left.remove(part) {
                    Some(row) if row.message == *message => {}
                    Some(row) => {
                        let mut active: template_error::ActiveModel = row.into();
                        active.message = Set(message.clone());
                        active.since = Set(at);
                        active
                            .update(&self.connection)
                            .await
                            .context("saving what's going wrong")?;
                    }
                    None => {
                        template_error::ActiveModel {
                            host_id: Set(host_id.to_string()),
                            template_id: Set(template_id),
                            database_name: Set(database.clone()),
                            part: Set(part.clone()),
                            message: Set(message.clone()),
                            since: Set(at),
                            ..Default::default()
                        }
                        .insert(&self.connection)
                        .await
                        .context("saving what's going wrong")?;
                    }
                }
            }
            let gone: Vec<i64> = left.into_values().map(|row| row.id).collect();
            if !gone.is_empty() {
                template_error::Entity::delete_many()
                    .filter(template_error::Column::Id.is_in(gone))
                    .exec(&self.connection)
                    .await
                    .context("forgetting what's going wrong")?;
            }
        }
        Ok(())
    }

    /// What's going wrong reading templates, on one host or every host, for one
    /// template or every template.
    pub async fn template_errors(
        &self,
        host_id: Option<&str>,
        template_id: Option<i64>,
    ) -> Result<Vec<TemplateError>> {
        let mut rows = template_error::Entity::find();
        if let Some(host_id) = host_id {
            rows = rows.filter(template_error::Column::HostId.eq(host_id));
        }
        if let Some(template_id) = template_id {
            rows = rows.filter(template_error::Column::TemplateId.eq(template_id));
        }
        Ok(rows
            .order_by_asc(template_error::Column::Id)
            .all(&self.connection)
            .await
            .context("loading what's going wrong")?
            .into_iter()
            .map(TemplateError::from)
            .collect())
    }

    /// Forgets what's going wrong on a host for any template and database it isn't
    /// sent to read any more, by template key and database, empty for one on the
    /// host.
    pub async fn forget_template_errors(
        &self,
        host_id: &str,
        sent: &[(String, String)],
    ) -> Result<()> {
        let rows = template_error::Entity::find()
            .filter(template_error::Column::HostId.eq(host_id))
            .all(&self.connection)
            .await
            .context("loading what's going wrong")?;
        if rows.is_empty() {
            return Ok(());
        }
        let templates = self.running_templates();
        let key_of = |id: i64| templates.get(id).map(|t| t.template().key.clone());
        let gone: Vec<i64> = rows
            .into_iter()
            .filter(|row| {
                key_of(row.template_id)
                    .is_none_or(|key| !sent.contains(&(key, row.database_name.clone())))
            })
            .map(|row| row.id)
            .collect();
        if !gone.is_empty() {
            template_error::Entity::delete_many()
                .filter(template_error::Column::Id.is_in(gone))
                .exec(&self.connection)
                .await
                .context("forgetting what's going wrong")?;
        }
        Ok(())
    }
}
