use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use axum::extract::FromRef;
use axum_csrf::CsrfConfig;
use tokio::sync::mpsc;

use crate::actions::Actions;
use crate::agent_configs::AgentConfigs;
use crate::alert_conditions::Conditions;
use crate::alerting::{self, AlertRuleInput};
use crate::calculations::Sources;
use crate::events::{EventInput, TimelineEvent};
use crate::facts::unflatten;
use crate::host_filter::HostFilter;
use crate::maintenance::{self, MaintenanceWindowInput};
use crate::metrics::Metrics;
use crate::metrics_pages::{self, MetricsPageInput, PageReads, SignIn};
use crate::models::{Database, NewEvent, RuleInput};
use crate::notifier::Senders;
use crate::passwords::SignInThrottle;
use crate::presence::Presence;
use crate::registration::{HostRecord, HostState, Registry};
use crate::remote_checks::{self, LatestResults, RemoteCheckInput};
use crate::rule_engine::ResolvedConfig;
use crate::rule_preview::{self, Preview, PreviewHost};
use crate::server_stats::ServerStatus;
use crate::silences::{self, SilenceInput};
use crate::store::{self, WriterCommand};
use crate::times::Timestamp;
use crate::views::Views;

/// What came of deleting an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDeletion {
    Deleted,
    NoSuchHost,
    /// Only a revoked agent can be deleted, so it always takes two steps, and one
    /// that's sending can't be deleted halfway through a report.
    NotRevoked,
}

#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    pub interval: Duration,
    pub timeout: Duration,
    /// How often an agent is asked what its clock says.
    pub clock_every: Duration,
}

/// What every request and connection shares.
#[derive(Clone)]
pub struct AppState {
    pub presence: Arc<Presence>,
    pub registry: Arc<Registry>,
    pub database: Database,
    /// Asks agents to run actions, and records how they went.
    pub actions: Arc<Actions>,
    /// What each agent should be running, and telling live connections when that
    /// changes.
    pub configs: Arc<AgentConfigs>,
    pub writer: mpsc::Sender<WriterCommand>,
    pub metrics: Metrics,
    /// What sending notifications needs.
    pub senders: Senders,
    /// How the checks the server runs itself last went.
    pub check_results: Arc<LatestResults>,
    /// How the metrics pages the server reads itself last went.
    pub page_reads: Arc<PageReads>,
    pub status: Arc<ServerStatus>,
    pub heartbeat: Heartbeat,
    /// The URL agents must have signed.
    pub audience: Arc<str>,
    /// Proxies in front of the server, trusted and not.
    pub proxies: Arc<crate::proxies::Proxies>,
    pub views: Arc<Views>,
    pub csrf: CsrfConfig,
    /// Where people reach the site, for links they're given.
    pub web_url: Arc<str>,
    pub sign_ins: Arc<SignInThrottle>,
    /// Whether everyone has to set up two-factor before using the pages. Kept
    /// here so each request doesn't ask the database.
    pub require_two_factor: Arc<std::sync::atomic::AtomicBool>,
    /// Apps approved in the browser, waiting to collect their tokens.
    pub pending_sign_ins: Arc<crate::app_sign_ins::PendingSignIns>,
    /// How long the health check waits on each database before calling it failing.
    pub health_limit: std::time::Duration,
}

impl FromRef<AppState> for CsrfConfig {
    fn from_ref(state: &AppState) -> Self {
        state.csrf.clone()
    }
}

/// Why an event couldn't be recorded, in words for whoever sent it, or a failure.
pub enum EventRefusal {
    Invalid(String),
    Failed(anyhow::Error),
}

impl AppState {
    /// Records an annotation, as `by`. Its filter is kept as it is, and matched against each
    /// host when a chart is drawn, so one that picks nothing yet is fine.
    pub async fn record_event(
        &self,
        mut input: EventInput,
        by: &str,
        now: Timestamp,
    ) -> Result<i64, EventRefusal> {
        input.tidy();
        let kind = input.check(now).map_err(EventRefusal::Invalid)?;
        let new = NewEvent {
            kind,
            occurred_at: input.occurred_at.unwrap_or(now),
            title: &input.title,
            detail: input.detail.as_deref(),
            filter: input.filter.as_deref(),
        };
        self.database
            .record_event(&new, by, now)
            .await
            .map_err(EventRefusal::Failed)
    }

    /// Everything that happened to a host between two times, newest first, with the
    /// annotations whose filters pick it by its current facts.
    pub async fn timeline(
        &self,
        host_id: &str,
        from: Timestamp,
        to: Timestamp,
    ) -> Result<Vec<TimelineEvent>> {
        let hostname = self
            .registry
            .get(host_id)
            .await
            .map(|host| host.hostname)
            .unwrap_or_default();
        let facts = self.database.facts_of(&[host_id]).await?;
        let facts = facts.get(host_id);
        let picks = |filter: Option<&str>| {
            HostFilter::parse_optional(filter)
                .is_ok_and(|filter| filter.matches(host_id, &hostname, facts))
        };
        self.database.timeline(host_id, from, to, picks).await
    }

    /// Deletes a revoked agent and everything kept about it. Metrics go first: if
    /// anything fails, the agent is still listed, revoked, to try again. A host
    /// without an agent needn't be revoked, so its checks and pages can still be
    /// running: the metrics writer drops what the server records about a host once
    /// it has deleted it, so one that finishes afterwards can't put it back.
    pub async fn delete_host(&self, id: &str) -> Result<HostDeletion> {
        match self.registry.get(id).await {
            None => return Ok(HostDeletion::NoSuchHost),
            Some(host) if host.is_local() => return Ok(HostDeletion::NoSuchHost),
            // Revoking stops an agent connecting, and there's none to stop.
            Some(host) if host.state != HostState::Revoked && !host.is_agentless() => {
                return Ok(HostDeletion::NotRevoked);
            }
            Some(_) => {}
        }
        store::delete_host(&self.writer, id).await?;
        self.database.delete_host(id).await?;
        self.registry.forget(id).await;
        self.presence.forget(id);
        tracing::info!(host_id = id, "deleted a host and its metrics");
        Ok(HostDeletion::Deleted)
    }

    /// Where calculations get their answers.
    pub fn sources(&self) -> Sources<'_> {
        Sources {
            database: &self.database,
            registry: &self.registry,
            metrics: &self.metrics,
        }
    }

    /// Works out what an agent should be running right now.
    pub async fn config_for(&self, host_id: &str) -> Result<ResolvedConfig> {
        self.configs.config_for(host_id).await
    }

    /// Works out what saving `rule` would do, without saving it. `id` is the
    /// saved rule it would replace. Only approved agents are ever sent a config.
    pub async fn preview_rule(&self, id: Option<i64>, rule: RuleInput) -> Result<Preview> {
        let rules = self.database.list_rules().await?;
        let mut facts = self.database.all_current_facts().await?;
        let hosts: Vec<PreviewHost> = self
            .registry
            .list()
            .await
            .into_iter()
            // Config rules are for agents, so a host with none never matches one.
            .filter(|host| {
                host.state == HostState::Approved && !host.is_local() && !host.is_agentless()
            })
            .map(|host| PreviewHost {
                online: self.presence.get(&host.id).is_some_and(|p| p.online),
                facts: unflatten(&facts.remove(&host.id).unwrap_or_default()),
                id: host.id,
                hostname: host.hostname,
            })
            .collect();

        // Evaluating every agent can take a while, and a panic stays in here.
        tokio::task::spawn_blocking(move || rule_preview::preview(&rules, id, &rule, &hosts))
            .await
            .context("working out the preview")?
    }

    /// Everything that has to be true for an alert rule to be saved, giving its
    /// conditions, read.
    pub async fn check_alert_rule(&self, input: &AlertRuleInput) -> Result<Conditions> {
        // Conditions are tried on a real host's facts, so a fact used the wrong way
        // shows, when there's a host with an agent to take them from.
        let hosts = self.registry.list().await;
        let example = hosts.iter().find(|host| {
            host.state == HostState::Approved && !host.is_agentless() && !host.is_local()
        });
        let facts = match example {
            Some(host) => {
                let mut facts = self.database.facts_of(&[host.id.as_str()]).await?;
                unflatten(&facts.remove(&host.id).unwrap_or_default())
            }
            // With no host yet, conditions are tried on a host with no facts, so any
            // fact they use is missing, as a host's are until its agent says.
            None => serde_json::Value::Object(serde_json::Map::new()),
        };
        let conditions = alerting::check_rule_with(input, &facts)?;
        if !input.actions.is_empty() {
            let known = self.database.known_actions().await?;
            crate::actions::check_against_hosts(input, &conditions, &known)?;
        }

        // A name another rule has is refused as the rule is saved, as only the
        // database can tell for certain.
        let live = self.database.live_channel_ids(&input.channels).await?;
        if let Some(wanted) = input.channels.iter().find(|id| !live.contains(id)) {
            bail!("there's no notification channel {wanted}");
        }
        Ok(conditions)
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

    /// Everything that has to be true for a server check to be saved. A name another
    /// check about the same host has is refused as the check is saved, as only the
    /// database can tell for certain.
    pub async fn check_remote_check(&self, input: &RemoteCheckInput) -> Result<()> {
        remote_checks::check_input(input)?;
        let about = &input.host_id;
        ensure!(
            about == remote_checks::LOCAL_HOST_ID || self.agentless_host(about).await.is_some(),
            "a check is about a host with no agent, or the server itself"
        );
        Ok(())
    }

    /// A host with no agent, which is the only kind the server reads pages for.
    pub async fn agentless_host(&self, id: &str) -> Option<HostRecord> {
        let host = self.registry.get(id).await?;
        (host.is_agentless() && host.state == HostState::Approved).then_some(host)
    }

    /// A metrics page as it would be saved for a host, or why it can't be. `id` is
    /// the saved page it would replace, whose password or token it keeps unless
    /// given another, and `sign_in` how the change says to sign in, when it says.
    pub async fn checked_metrics_page(
        &self,
        host_id: &str,
        id: Option<i64>,
        input: MetricsPageInput,
        sign_in: Option<SignIn>,
    ) -> Result<MetricsPageInput> {
        let pages = self.database.metrics_pages_of(host_id).await?;
        let saved = pages.iter().find(|page| Some(page.id) == id);
        let input = match saved {
            Some(saved) => input.keeping_secrets_of(&saved.input, sign_in),
            None => input,
        };
        metrics_pages::check_input(&input)?;
        metrics_pages::check_sign_in(&input, sign_in)?;
        let others = pages.iter().filter(|page| Some(page.id) != id);
        metrics_pages::check_names(others.map(|page| &page.input).chain([&input]))?;
        Ok(input)
    }

    /// Tells live connections that rules changed.
    pub fn config_changed(&self) {
        self.configs.changed();
    }
}
