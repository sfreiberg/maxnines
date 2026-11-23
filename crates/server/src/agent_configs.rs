//! What each agent should be running, worked out from the config rules. The rules are
//! loaded and compiled once each time they change, and shared by every agent, so a
//! change doesn't have every connection read them at once.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{Mutex, watch};

use crate::facts::{FlatFacts, unflatten};
use crate::models::Database;
use crate::rule_engine::{ConfigRules, Host, ResolvedConfig};
use crate::templates::hosts::agent_databases;
use crate::templates::work::work_for;

pub struct AgentConfigs {
    database: Database,
    /// Bumped when rules change, so live connections work out their config again.
    changes: watch::Sender<u64>,
    /// The rules as they were at a revision. Whoever finds them out of date loads them,
    /// while everyone else waits for that rather than loading them too.
    rules: Mutex<Option<(u64, Arc<ConfigRules>)>>,
}

impl AgentConfigs {
    pub fn new(database: Database) -> Self {
        Self {
            database,
            changes: watch::Sender::new(0),
            rules: Mutex::new(None),
        }
    }

    /// Tells live connections that rules changed. Called once they're saved.
    pub fn changed(&self) {
        self.changes.send_modify(|revision| *revision += 1);
    }

    /// Told each time the rules change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// How many times the rules have changed since the server started.
    #[cfg(test)]
    pub fn revision(&self) -> u64 {
        *self.changes.borrow()
    }

    /// The rules as they are now, compiled.
    pub async fn rules(&self) -> Result<Arc<ConfigRules>> {
        // Read before loading, so rules saved while they load are loaded again next
        // time, as they may have been missed.
        let revision = *self.changes.borrow();
        let mut kept = self.rules.lock().await;
        if let Some((loaded_at, rules)) = kept.as_ref()
            && *loaded_at == revision
        {
            return Ok(rules.clone());
        }
        let rules = Arc::new(ConfigRules::new(self.database.list_rules().await?)?);
        *kept = Some((revision, rules.clone()));
        Ok(rules)
    }

    /// Works out what an agent should be running right now: what the config rules
    /// say, and what its templates have it read.
    pub async fn config_for(&self, host_id: &str) -> Result<ResolvedConfig> {
        let rules = self.rules().await?;
        let facts: FlatFacts = self
            .database
            .current_facts(host_id)
            .await?
            .into_iter()
            .map(|fact| (fact.name, fact.value))
            .collect();
        let facts = unflatten(&facts);
        let host = Host::new(&facts, host_id);
        let mut resolved = rules.resolve(&host)?;
        let templates = self.database.running_templates();
        let discoveries = self.database.discoveries(host_id).await?;
        let databases = agent_databases(&facts);
        resolved.config.templates = work_for(&templates, &host, &databases, &discoveries);
        resolved.version = resolved.config.version()?;
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_agent_shares_the_rules_until_they_change() {
        let configs = AgentConfigs::new(Database::for_test().await);

        let first = configs.rules().await.unwrap();
        assert!(Arc::ptr_eq(&first, &configs.rules().await.unwrap()));

        configs.changed();
        let after = configs.rules().await.unwrap();
        assert!(!Arc::ptr_eq(&first, &after));
        assert!(Arc::ptr_eq(&after, &configs.rules().await.unwrap()));
    }
}
