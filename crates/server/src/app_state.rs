use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use axum::extract::FromRef;
use axum_csrf::CsrfConfig;
use ipnet::IpNet;
use tokio::sync::{mpsc, watch};

use crate::alerting::{self, AlertRuleInput, ChannelInput};
use crate::calculations::Sources;
use crate::facts::{FlatFacts, unflatten};
use crate::maintenance::{self, MaintenanceWindowInput};
use crate::metrics::Metrics;
use crate::models::{Database, RuleInput};
use crate::notifier::Senders;
use crate::passwords::SignInThrottle;
use crate::presence::Presence;
use crate::registration::{AgentState, Registry};
use crate::remote_checks::{self, LatestResults, RemoteCheckInput};
use crate::rule_engine::{self, ResolvedConfig};
use crate::rule_preview::{self, Preview, PreviewAgent};
use crate::server_stats::ServerStatus;
use crate::silences::{self, SilenceInput};
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
    /// What sending notifications needs.
    pub senders: Senders,
    /// How the checks the server runs itself last went.
    pub check_results: Arc<LatestResults>,
    pub status: Arc<ServerStatus>,
    pub heartbeat: Heartbeat,
    /// The URL agents must have signed.
    pub audience: Arc<str>,
    pub trusted_proxies: Arc<[IpNet]>,
    pub admin_token_hash: Arc<[u8]>,
    pub views: Arc<Views>,
    pub csrf: CsrfConfig,
    /// Where people reach the site, for links they're given.
    pub web_url: Arc<str>,
    pub sign_ins: Arc<SignInThrottle>,
}

impl FromRef<AppState> for CsrfConfig {
    fn from_ref(state: &AppState) -> Self {
        state.csrf.clone()
    }
}

impl AppState {
    /// Works out what an agent should be running right now.
    /// Where calculations get their answers.
    pub fn sources(&self) -> Sources<'_> {
        Sources {
            database: &self.database,
            registry: &self.registry,
            metrics: &self.metrics,
        }
    }

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
            .filter(|agent| agent.state == AgentState::Approved && !agent.is_local())
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

    /// Everything that has to be true for an alert rule to be saved. `id` is the
    /// saved rule it would replace.
    pub async fn check_alert_rule(&self, input: &AlertRuleInput, id: Option<i64>) -> Result<()> {
        alerting::check_rule(input)?;

        let rules = self.database.list_alert_rules().await?;
        let taken = rules
            .iter()
            .any(|rule| rule.rule.name == input.name && Some(rule.id) != id);
        ensure!(
            !taken,
            "an alert rule named {:?} already exists",
            input.name
        );

        let channels = self.database.list_channels().await?;
        for wanted in &input.channels {
            if !channels.iter().any(|channel| channel.id == *wanted) {
                bail!("there's no notification channel {wanted}");
            }
        }
        Ok(())
    }

    /// Everything that has to be true for a maintenance window to be saved.
    pub async fn check_maintenance_window(&self, input: &MaintenanceWindowInput) -> Result<()> {
        maintenance::check_window(input)?;
        if let Some(id) = input.rule_id {
            ensure!(
                self.database.get_alert_rule(id).await?.is_some(),
                "there's no alert rule {id}"
            );
        }
        Ok(())
    }

    /// Everything that has to be true for a silence to start.
    pub async fn check_silence(&self, input: &SilenceInput) -> Result<()> {
        silences::check_silence(input)?;
        if let Some(id) = input.rule_id {
            ensure!(
                self.database.get_alert_rule(id).await?.is_some(),
                "there's no alert rule {id}"
            );
        }
        Ok(())
    }

    /// Everything that has to be true for a channel to be saved. `id` is the
    /// saved channel it would replace.
    pub async fn check_channel(&self, input: &ChannelInput, id: Option<i64>) -> Result<()> {
        alerting::check_channel(input)?;
        let channels = self.database.list_channels().await?;
        let taken = channels
            .iter()
            .any(|channel| channel.channel.name == input.name && Some(channel.id) != id);
        ensure!(!taken, "a channel named {:?} already exists", input.name);
        Ok(())
    }

    /// Everything that has to be true for a server check to be saved. `id` is the
    /// saved check it would replace.
    pub async fn check_remote_check(
        &self,
        input: &RemoteCheckInput,
        id: Option<i64>,
    ) -> Result<()> {
        remote_checks::check_input(input)?;
        let checks = self.database.list_remote_checks().await?;
        let name = &input.check.name;
        let taken = checks
            .iter()
            .any(|check| check.input.check.name == *name && Some(check.id) != id);
        ensure!(!taken, "a check named {name:?} already exists");
        Ok(())
    }

    /// Tells live connections that rules changed.
    pub fn config_changed(&self) {
        self.config_changes.send_modify(|revision| *revision += 1);
    }
}
