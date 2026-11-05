use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::FromRef;
use axum_csrf::CsrfConfig;
use ipnet::IpNet;
use tokio::sync::{mpsc, watch};

use crate::facts::{FlatFacts, unflatten};
use crate::metrics::Metrics;
use crate::models::{Database, RuleInput};
use crate::presence::Presence;
use crate::registration::{AgentState, Registry};
use crate::rule_engine::{self, ResolvedConfig};
use crate::rule_preview::{self, Preview, PreviewAgent};
use crate::store::WriterCommand;
use crate::views::Views;

#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    pub interval: Duration,
    pub timeout: Duration,
}

/// What every request and connection shares.
#[derive(Clone)]
pub struct AppState {
    pub presence: Arc<Presence>,
    pub registry: Arc<Registry>,
    pub database: Database,
    /// Bumped when rules change, so live connections work out their config again.
    pub config_changes: Arc<watch::Sender<u64>>,
    pub writer: mpsc::Sender<WriterCommand>,
    pub metrics: Metrics,
    pub heartbeat: Heartbeat,
    /// The URL agents must have signed.
    pub audience: Arc<str>,
    pub trusted_proxies: Arc<[IpNet]>,
    pub admin_token_hash: Arc<[u8]>,
    pub views: Arc<Views>,
    pub csrf: CsrfConfig,
}

impl FromRef<AppState> for CsrfConfig {
    fn from_ref(state: &AppState) -> Self {
        state.csrf.clone()
    }
}

impl AppState {
    /// Works out what an agent should be running right now.
    pub async fn config_for(&self, agent_id: &str) -> Result<ResolvedConfig> {
        let rules = self.database.list_rules().await?;
        let facts: FlatFacts = self
            .database
            .current_facts(agent_id)
            .await?
            .into_iter()
            .map(|fact| (fact.name, fact.value))
            .collect();
        rule_engine::resolve(&rules, &unflatten(&facts), agent_id)
    }

    /// Works out what saving `rule` would do, without saving it. `id` is the
    /// saved rule it would replace. Only approved agents are ever sent a config.
    pub async fn preview_rule(&self, id: Option<i64>, rule: RuleInput) -> Result<Preview> {
        let rules = self.database.list_rules().await?;
        let mut facts = self.database.all_current_facts().await?;
        let agents: Vec<PreviewAgent> = self
            .registry
            .list()
            .await
            .into_iter()
            .filter(|agent| agent.state == AgentState::Approved)
            .map(|agent| PreviewAgent {
                online: self.presence.get(&agent.id).is_some_and(|p| p.online),
                facts: unflatten(&facts.remove(&agent.id).unwrap_or_default()),
                id: agent.id,
                host: agent.host,
            })
            .collect();

        // Evaluating every agent can take a while, and a panic stays in here.
        tokio::task::spawn_blocking(move || rule_preview::preview(&rules, id, &rule, &agents))
            .await
            .context("working out the preview")
    }

    /// Tells live connections that rules changed.
    pub fn config_changed(&self) {
        self.config_changes.send_modify(|revision| *revision += 1);
    }
}
