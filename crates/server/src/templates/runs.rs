//! Where each template runs: for each host it's on and for, each database it reads
//! there, or the host itself, what discovery found, which of its discover blocks,
//! queries and counters blocks are read there now, and what's going wrong reading
//! them. Worked out as each host's agent, or the server for a host with no agent,
//! is sent what to read, so it's what they read.

use std::collections::BTreeMap;

use anyhow::Result;
use maxnines_checks::databases::is_database;
use serde::Serialize;
use serde_json::{Map, Value};

use super::hosts::{DatabaseKinds, agent_databases};
use super::work::{Discoveries, assigned_work, instance_of};
use crate::app_state::AppState;
use crate::facts::unflatten;
use crate::registration::HostState;
use crate::rule_engine::Host;
use crate::times::Timestamp;

/// A template read on a host, for a database or the host itself.
#[derive(Debug, Clone, Serialize)]
pub struct RunsOn {
    pub host_id: String,
    pub hostname: String,
    pub template_id: i64,
    pub template_key: String,
    pub template_name: String,
    /// The database it reads, or none for a template that runs once on the host.
    pub database: Option<String>,
    /// What discovery found there, by name, or nothing yet.
    pub found: Map<String, Value>,
    /// The keys of its discover blocks read there.
    pub discover: Vec<String>,
    /// The keys of its queries read there now, as what discovery found picks.
    pub queries: Vec<String>,
    /// The keys of its counters blocks read there now.
    pub counters: Vec<String>,
    /// What's going wrong reading it there.
    pub errors: Vec<RunError>,
}

/// Something going wrong reading a template somewhere.
#[derive(Debug, Clone, Serialize)]
pub struct RunError {
    /// `connecting`, `account`, or a part, as `query sessions`.
    pub part: String,
    pub message: String,
    pub since: Timestamp,
}

/// Where templates run: on the host `host_id`, or every host, of the template
/// `template_id`, or every template. Those going wrong come first.
pub async fn runs(
    state: &AppState,
    host_id: Option<&str>,
    template_id: Option<i64>,
) -> Result<Vec<RunsOn>> {
    let hosts: Vec<_> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|host| host.state == HostState::Approved && !host.is_local())
        .filter(|host| host_id.is_none_or(|id| host.id == id))
        .collect();
    let facts = match host_id {
        Some(id) => state.database.facts_of(&[id]).await?,
        None => state.database.all_current_facts().await?,
    };
    let checks = state.database.list_remote_checks().await?;
    let discoveries = state.database.all_discoveries().await?;
    let mut errors: BTreeMap<(String, i64, Option<String>), Vec<RunError>> = BTreeMap::new();
    for error in state.database.template_errors(host_id, template_id).await? {
        errors
            .entry((error.host_id, error.template_id, error.database))
            .or_default()
            .push(RunError {
                part: error.part,
                message: error.message,
                since: error.since,
            });
    }
    let templates = state.database.running_templates();
    let none = Discoveries::new();

    let mut runs = Vec::new();
    for host in hosts {
        let flat = facts.get(&host.id).cloned().unwrap_or_default();
        let facts = unflatten(&flat);
        let databases: DatabaseKinds = match host.is_agentless() {
            // What the server reads itself, through its database checks.
            true => checks
                .iter()
                .filter(|check| {
                    check.input.host_id == host.id
                        && check.input.enabled
                        && check.input.read_stats
                        && is_database(check.input.check.kind)
                })
                .map(|check| {
                    let kind = check.input.check.kind.as_str().to_string();
                    (check.input.check.name.clone(), kind)
                })
                .collect(),
            false => agent_databases(&facts),
        };
        let on = Host::new(&facts, &host.id);
        let found = discoveries.get(&host.id).unwrap_or(&none);
        for assigned in templates.for_host(&on) {
            if template_id.is_some_and(|id| id != assigned.id()) {
                continue;
            }
            for work in assigned_work(assigned, &on, &databases, found) {
                let instance = instance_of(work.database.as_deref());
                let key = (host.id.clone(), assigned.id(), work.database.clone());
                runs.push(RunsOn {
                    host_id: host.id.clone(),
                    hostname: host.hostname.clone(),
                    template_id: assigned.id(),
                    template_key: assigned.template().key.clone(),
                    template_name: assigned.template().name.clone(),
                    found: found
                        .get(&(assigned.id(), instance))
                        .cloned()
                        .unwrap_or_default(),
                    discover: work.discover.iter().map(|d| d.key.clone()).collect(),
                    queries: work.queries.iter().map(|q| q.key.clone()).collect(),
                    counters: work.counters.iter().map(|c| c.key.clone()).collect(),
                    errors: errors.remove(&key).unwrap_or_default(),
                    database: work.database,
                });
            }
        }
    }
    runs.sort_by(|a, b| {
        (
            a.errors.is_empty(),
            &a.hostname,
            &a.template_name,
            &a.database,
        )
            .cmp(&(
                b.errors.is_empty(),
                &b.hostname,
                &b.template_name,
                &b.database,
            ))
    });
    Ok(runs)
}
