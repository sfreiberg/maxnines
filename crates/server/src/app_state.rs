use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use axum::extract::FromRef;
use axum_csrf::CsrfConfig;
use ipnet::IpNet;
use tokio::sync::{mpsc, watch};

use crate::alerting::{self, AlertRuleInput, ChannelInput};
use crate::calculations::Sources;
use crate::events::{EventInput, TimelineEvent};
use crate::facts::{FlatFacts, unflatten};
use crate::host_filter::HostFilter;
use crate::maintenance::{self, MaintenanceWindowInput};
use crate::metrics::Metrics;
use crate::models::{Database, NewEvent, RuleInput};
use crate::notifier::Senders;
use crate::passwords::SignInThrottle;
use crate::presence::Presence;
use crate::registration::{HostState, Registry};
use crate::remote_checks::{self, LatestResults, RemoteCheckInput};
use crate::rule_engine::{self, ResolvedConfig};
use crate::rule_preview::{self, Preview, PreviewHost};
use crate::server_stats::ServerStatus;
use crate::silences::{self, SilenceInput};
use crate::store::{self, WriterCommand};
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
    pub views: Arc<Views>,
    pub csrf: CsrfConfig,
    /// Where people reach the site, for links they're given.
    pub web_url: Arc<str>,
    pub sign_ins: Arc<SignInThrottle>,
    /// Whether everyone has to set up two-factor before using the pages. Kept
    /// here so each request doesn't ask the database.
    pub require_two_factor: Arc<std::sync::atomic::AtomicBool>,
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
        now_ms: i64,
    ) -> Result<i64, EventRefusal> {
        input.tidy();
        let kind = input.check(now_ms).map_err(EventRefusal::Invalid)?;
        let filter = input.filter.clone().unwrap_or_default();
        let new = NewEvent {
            kind,
            time_ms: input.time_ms.unwrap_or(now_ms),
            title: &input.title,
            detail: input.detail.as_deref(),
            filter: &filter,
        };
        self.database
            .record_event(&new, by, now_ms)
            .await
            .map_err(EventRefusal::Failed)
    }

    /// Everything that happened to a host between two times, newest first, with the
    /// annotations whose filters pick it by its current facts.
    pub async fn timeline(
        &self,
        host_id: &str,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<TimelineEvent>> {
        let hostname = self
            .registry
            .get(host_id)
            .await
            .map(|host| host.hostname)
            .unwrap_or_default();
        let facts = self.database.facts_of(&[host_id]).await?;
        let facts = facts.get(host_id);
        let picks = |filter: &str| {
            HostFilter::parse(filter).is_ok_and(|filter| filter.matches(host_id, &hostname, facts))
        };
        self.database.timeline(host_id, from_ms, to_ms, picks).await
    }

    /// Deletes a revoked agent and everything kept about it. Metrics go first: if
    /// anything fails, the agent is still listed, revoked, to try again.
    pub async fn delete_host(&self, id: &str) -> Result<HostDeletion> {
        match self.registry.get(id).await {
            None => return Ok(HostDeletion::NoSuchHost),
            Some(host) if host.is_local() => return Ok(HostDeletion::NoSuchHost),
            Some(host) if host.state != HostState::Revoked => {
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

    /// Works out what an agent should be running right now.
    /// Where calculations get their answers.
    pub fn sources(&self) -> Sources<'_> {
        Sources {
            database: &self.database,
            registry: &self.registry,
            metrics: &self.metrics,
        }
    }

    pub async fn config_for(&self, host_id: &str) -> Result<ResolvedConfig> {
        let rules = self.database.list_rules().await?;
        let facts: FlatFacts = self
            .database
            .current_facts(host_id)
            .await?
            .into_iter()
            .map(|fact| (fact.name, fact.value))
            .collect();
        rule_engine::resolve(&rules, &unflatten(&facts), host_id)
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
            .filter(|host| host.state == HostState::Approved && !host.is_local())
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
