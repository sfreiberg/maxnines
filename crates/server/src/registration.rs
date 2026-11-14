//! Decides which agents may connect. Agents are identified by a key they prove
//! they hold. New agents wait for an admin unless a rule decides first.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use maxnines_protocol::RegistrationStatus;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use tracing::{info, warn};
use wildmatch::WildMatch;

use crate::config::{RegistrationConfig, RuleAction, RuleConfig, parse_network};
use crate::models::Database;
use crate::remote_checks::{FLEET_HOST_ID, LOCAL_HOST_ID};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Pending,
    Approved,
    Revoked,
}

/// What a host is: one with an agent that reports on it, one the server reads
/// from itself, or one of the two that aren't machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    #[default]
    Agent,
    Agentless,
    BuiltIn,
}

impl HostKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Agentless => "agentless",
            Self::BuiltIn => "built_in",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "agent" => Some(Self::Agent),
            "agentless" => Some(Self::Agentless),
            "built_in" => Some(Self::BuiltIn),
            _ => None,
        }
    }
}

/// How long a host's name can be, which is what the database's column holds.
const MAX_HOSTNAME_LEN: usize = 255;

/// A name someone typed for a host with no agent, tidied, or why it won't do.
pub fn agentless_hostname(typed: &str) -> Result<String> {
    let hostname = typed.trim();
    ensure!(!hostname.is_empty(), "the host needs a name");
    ensure!(
        hostname.len() <= MAX_HOSTNAME_LEN,
        "the name can be up to {MAX_HOSTNAME_LEN} characters"
    );
    ensure!(
        !hostname.chars().any(char::is_control),
        "the name can't hold control characters"
    );
    Ok(hostname.to_string())
}

fn is_built_in(id: &str) -> bool {
    id == LOCAL_HOST_ID || id == FLEET_HOST_ID
}

impl HostRecord {
    /// Whether this is a built-in agent, which isn't a host anyone registered, so
    /// it stays out of lists and can't be changed.
    pub fn is_local(&self) -> bool {
        is_built_in(&self.id)
    }

    /// Whether the server reads from this host itself, as it has no agent.
    pub fn is_agentless(&self) -> bool {
        self.kind == HostKind::Agentless
    }
}

impl HostState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// An agent the server has heard from, or the built-in one that holds the results
/// of checks the server runs itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostRecord {
    pub id: String,
    #[serde(default)]
    pub kind: HostKind,
    /// Empty for a host with no agent, which has no key.
    pub public_key: String,
    pub hostname: String,
    pub state: HostState,
    /// Who approved it: "admin", someone's address, or "rule:<name>".
    pub decided_by: Option<String>,
    pub first_seen_ms: u64,
    pub decided_ms: Option<u64>,
}

/// Enough of an agent's ID to tell it from another with the same name, where the
/// whole thing would be clutter. IDs are hashes, so the start is as good as any part.
pub const SHORT_ID_LEN: usize = 8;

pub fn short_id(id: &str) -> &str {
    id.get(..SHORT_ID_LEN).unwrap_or(id)
}

/// A verified agent asking to connect. The key is proven, but the host and
/// token are only what the agent claims.
pub struct Admission<'a> {
    pub id: &'a str,
    pub public_key: &'a str,
    pub hostname: &'a str,
    pub source: IpAddr,
    pub token: Option<&'a str>,
}

struct Rule {
    name: String,
    action: RuleAction,
    networks: Vec<IpNet>,
    hostname: Option<WildMatch>,
    token_hash: Option<Vec<u8>>,
}

impl Rule {
    fn compile(name: &str, config: &RuleConfig) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            action: config.action,
            networks: config
                .source_cidrs
                .iter()
                .map(|text| parse_network(text))
                .collect::<Result<_>>()?,
            hostname: config.hostname.as_deref().map(WildMatch::new),
            token_hash: config.token_file.as_deref().map(read_token).transpose()?,
        })
    }

    fn matches(&self, request: &Admission) -> bool {
        let source_matches =
            self.networks.is_empty() || self.networks.iter().any(|n| n.contains(&request.source));
        let host_matches = self
            .hostname
            .as_ref()
            .is_none_or(|h| h.matches(request.hostname));
        let token_matches = self
            .token_hash
            .as_ref()
            .is_none_or(|hash| request.token.is_some_and(|t| *hash == hash_token(t)));

        source_matches && host_matches && token_matches
    }
}

/// Comparing hashes means a timing difference reveals nothing about the token.
pub fn hash_token(token: &str) -> Vec<u8> {
    digest(&SHA256, token.as_bytes()).as_ref().to_vec()
}

fn read_token(path: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading token file {}", path.display()))?;
    let token = text.trim();
    ensure!(!token.is_empty(), "token file {} is empty", path.display());
    Ok(hash_token(token))
}

pub struct Rules(Vec<Rule>);

impl Rules {
    pub fn compile(config: &RegistrationConfig) -> Result<Self> {
        let rules = config
            .rule
            .iter()
            .map(|(name, rule)| Rule::compile(name, rule).with_context(|| format!("rule {name:?}")))
            .collect::<Result<_>>()?;
        Ok(Self(rules))
    }

    /// The first matching rule decides.
    fn decide(&self, request: &Admission) -> Option<&Rule> {
        self.0.iter().find(|rule| rule.matches(request))
    }
}

pub struct Registry {
    hosts: Mutex<BTreeMap<String, HostRecord>>,
    /// When each waiting agent last tried to connect. In memory, as it asks again.
    asked_ms: std::sync::Mutex<BTreeMap<String, u64>>,
    rules: Rules,
    max_pending: usize,
    database: Database,
    /// Bumped on every admin change, so live connections re-check themselves.
    revisions: watch::Sender<u64>,
}

impl Registry {
    pub fn new(
        hosts: Vec<HostRecord>,
        rules: Rules,
        max_pending: usize,
        database: Database,
    ) -> Self {
        Self {
            hosts: Mutex::new(hosts.into_iter().map(|a| (a.id.clone(), a)).collect()),
            asked_ms: std::sync::Mutex::default(),
            rules,
            max_pending,
            database,
            revisions: watch::Sender::new(0),
        }
    }

    pub async fn admit(&self, request: &Admission<'_>) -> Result<RegistrationStatus> {
        let mut hosts = self.hosts.lock().await;
        let existing = hosts.get(request.id).cloned();

        match existing.as_ref().map(|host| host.state) {
            // No rule can bring back a revoked agent.
            Some(HostState::Revoked) => return Ok(RegistrationStatus::Rejected),
            Some(HostState::Approved) => {
                // Names aren't unique: the key is the identity, and a name is what
                // the host says it's called, which hosts on different networks
                // can share.
                let mut host = existing.expect("state came from this record");
                if host.hostname != request.hostname {
                    host.hostname = request.hostname.to_string();
                    // An approved agent stays approved while the database is away.
                    // The old name stays in memory, so the save is tried again next time.
                    match self.database.save_host(&host).await {
                        Ok(()) => {
                            hosts.insert(host.id.clone(), host);
                        }
                        Err(error) => warn!(
                            host_id = request.id,
                            error = format!("{error:#}"),
                            "couldn't save the host's new hostname, trying again next time"
                        ),
                    }
                }
                return Ok(RegistrationStatus::Approved);
            }
            Some(HostState::Pending) | None => {}
        }

        let rule = self.rules.decide(request);
        if let Some(rule) = rule.filter(|r| r.action == RuleAction::Reject) {
            info!(host_id = request.id, rule = rule.name, "rejected by rule");
            return Ok(RegistrationStatus::Rejected);
        }

        let pending = hosts
            .values()
            .filter(|a| a.state == HostState::Pending)
            .count();
        if existing.is_none() && pending >= self.max_pending {
            warn!(
                host_id = request.id,
                "too many pending hosts, ignoring request"
            );
            return Ok(RegistrationStatus::Pending);
        }
        if existing.is_some() {
            self.note_asked(request.id);
        }

        let now = now_ms();
        let mut host = existing.clone().unwrap_or_else(|| HostRecord {
            id: request.id.to_string(),
            kind: HostKind::Agent,
            public_key: request.public_key.to_string(),
            hostname: request.hostname.to_string(),
            state: HostState::Pending,
            decided_by: None,
            first_seen_ms: now,
            decided_ms: None,
        });
        host.hostname = request.hostname.to_string();

        if let Some(rule) = rule {
            info!(host_id = request.id, rule = rule.name, "approved by rule");
            host.state = HostState::Approved;
            host.decided_by = Some(format!("rule:{}", rule.name));
            host.decided_ms = Some(now);
        }

        let status = match host.state {
            HostState::Approved => RegistrationStatus::Approved,
            _ => RegistrationStatus::Pending,
        };
        if status == RegistrationStatus::Pending {
            self.note_asked(request.id);
        }
        if existing.as_ref() != Some(&host) {
            if existing.is_none() && status == RegistrationStatus::Pending {
                info!(
                    host_id = request.id,
                    hostname = request.hostname,
                    "new host waiting for approval"
                );
            }
            self.save(&mut hosts, host).await?;
        }
        Ok(status)
    }

    fn note_asked(&self, id: &str) {
        self.asked_ms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_string(), now_ms());
    }

    /// When a waiting agent last tried to connect, if it has since the server started.
    pub fn last_asked_ms(&self, id: &str) -> Option<u64> {
        self.asked_ms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .copied()
    }

    /// A decision made through the API or the command line.
    pub async fn decide(&self, id: &str, state: HostState) -> Result<Option<HostRecord>> {
        self.decide_as(id, state, "admin").await
    }

    /// A decision someone made, to show who it was. Returns `None` for an unknown agent.
    pub async fn decide_as(
        &self,
        id: &str,
        state: HostState,
        by: &str,
    ) -> Result<Option<HostRecord>> {
        if is_built_in(id) {
            return Ok(None);
        }
        let mut hosts = self.hosts.lock().await;
        let Some(mut host) = hosts.get(id).cloned() else {
            return Ok(None);
        };

        host.state = state;
        host.decided_by = Some(by.to_string());
        host.decided_ms = Some(now_ms());
        self.save(&mut hosts, host.clone()).await?;
        drop(hosts);
        self.asked_ms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);

        info!(host_id = id, state = state.as_str(), "admin decision");
        self.revisions.send_modify(|revision| *revision += 1);
        Ok(Some(host))
    }

    /// Adds a host with no agent, for the server to read from itself. There's no
    /// agent to vouch for, so whoever adds it has approved it. Its ID is random,
    /// and looks like any other.
    pub async fn add_agentless(&self, hostname: &str, by: &str) -> Result<HostRecord> {
        let hostname = agentless_hostname(hostname)?;
        let mut id = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| anyhow::anyhow!("no random numbers to make an ID from"))?;
        let now = now_ms();
        let host = HostRecord {
            id: hex::encode(id),
            kind: HostKind::Agentless,
            public_key: String::new(),
            hostname,
            state: HostState::Approved,
            decided_by: Some(by.to_string()),
            first_seen_ms: now,
            decided_ms: Some(now),
        };
        let mut hosts = self.hosts.lock().await;
        self.save(&mut hosts, host.clone()).await?;
        drop(hosts);
        info!(host_id = host.id, "added a host with no agent");
        self.revisions.send_modify(|revision| *revision += 1);
        Ok(host)
    }

    /// Renames a host with no agent, as it has no agent to say what it's called.
    /// Returns `None` for any other host, or none at all.
    pub async fn rename_agentless(&self, id: &str, hostname: &str) -> Result<Option<HostRecord>> {
        let hostname = agentless_hostname(hostname)?;
        let mut hosts = self.hosts.lock().await;
        let Some(mut host) = hosts.get(id).filter(|host| host.is_agentless()).cloned() else {
            return Ok(None);
        };
        host.hostname = hostname;
        self.save(&mut hosts, host.clone()).await?;
        Ok(Some(host))
    }

    /// Takes a deleted agent off the list. If it connects again, it's new.
    pub async fn forget(&self, id: &str) {
        self.hosts.lock().await.remove(id);
        self.asked_ms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        self.revisions.send_modify(|revision| *revision += 1);
    }

    /// Adds an agent as if it had been loaded at startup.
    #[cfg(test)]
    pub async fn insert_for_test(&self, host: HostRecord) {
        self.hosts.lock().await.insert(host.id.clone(), host);
    }

    pub async fn list(&self) -> Vec<HostRecord> {
        self.hosts.lock().await.values().cloned().collect()
    }

    pub async fn get(&self, id: &str) -> Option<HostRecord> {
        self.hosts.lock().await.get(id).cloned()
    }

    pub async fn is_approved(&self, id: &str) -> bool {
        let hosts = self.hosts.lock().await;
        hosts
            .get(id)
            .is_some_and(|a| a.state == HostState::Approved)
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revisions.subscribe()
    }

    /// Saves first, so memory never claims something the database doesn't have.
    async fn save(&self, hosts: &mut BTreeMap<String, HostRecord>, host: HostRecord) -> Result<()> {
        self.database.save_host(&host).await?;
        hosts.insert(host.id.clone(), host);
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;

    fn rules(body: &str) -> (Rules, usize) {
        let text =
            format!("metrics \"duckdb\" {{\n  path = \"x\"\n}}\nregistration {{\n{body}\n}}\n");
        let config = Config::parse(&text).unwrap();
        (
            Rules::compile(&config.registration).unwrap(),
            config.registration.max_pending,
        )
    }

    async fn registry_with(body: &str, database: Database) -> Registry {
        let mut hosts = database.load_hosts().await.unwrap();
        hosts.retain(|host| !host.is_local());
        let (rules, max_pending) = rules(body);
        Registry::new(hosts, rules, max_pending, database)
    }

    async fn registry(body: &str) -> Registry {
        registry_with(body, Database::for_test().await).await
    }

    fn request<'a>(id: &'a str, hostname: &'a str, source: &str) -> Admission<'a> {
        Admission {
            id,
            public_key: "ab",
            hostname,
            source: source.parse().unwrap(),
            token: None,
        }
    }

    const SUBNET_RULE: &str = r#"
        rule "subnet" {
          action       = "approve"
          source_cidrs = ["10.0.0.0/8"]
        }
    "#;

    #[tokio::test]
    async fn a_new_agent_waits_for_approval() {
        let registry = registry("").await;
        let status = registry
            .admit(&request("a", "web-1", "1.2.3.4"))
            .await
            .unwrap();

        assert_eq!(status, RegistrationStatus::Pending);
        assert_eq!(registry.list().await[0].state, HostState::Pending);
    }

    #[tokio::test]
    async fn an_admin_can_approve_then_revoke() {
        let registry = registry("").await;
        let host = request("a", "web-1", "1.2.3.4");
        registry.admit(&host).await.unwrap();

        let record = registry
            .decide("a", HostState::Approved)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.decided_by.as_deref(), Some("admin"));
        assert!(record.decided_ms.is_some());
        assert_eq!(
            registry.admit(&host).await.unwrap(),
            RegistrationStatus::Approved
        );

        registry.decide("a", HostState::Revoked).await.unwrap();
        assert_eq!(
            registry.admit(&host).await.unwrap(),
            RegistrationStatus::Rejected
        );
        assert!(!registry.is_approved("a").await);
    }

    #[tokio::test]
    async fn deciding_on_an_unknown_agent_returns_none() {
        let registry = registry("").await;
        assert!(
            registry
                .decide("nope", HostState::Approved)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_matching_rule_approves_and_is_recorded() {
        let registry = registry(SUBNET_RULE).await;
        let status = registry
            .admit(&request("a", "web-1", "10.1.2.3"))
            .await
            .unwrap();

        assert_eq!(status, RegistrationStatus::Approved);
        assert_eq!(
            registry.list().await[0].decided_by.as_deref(),
            Some("rule:subnet")
        );
    }

    #[tokio::test]
    async fn no_matching_rule_means_pending() {
        let registry = registry(SUBNET_RULE).await;
        let status = registry
            .admit(&request("a", "web-1", "192.168.1.1"))
            .await
            .unwrap();
        assert_eq!(status, RegistrationStatus::Pending);
    }

    #[tokio::test]
    async fn every_condition_in_a_rule_must_match() {
        let registry = registry(
            r#"
            rule "web-subnet" {
              action       = "approve"
              source_cidrs = ["10.0.0.0/8"]
              hostname     = "web-*"
            }
            "#,
        )
        .await;

        let wrong_host = request("a", "db-1", "10.0.0.1");
        assert_eq!(
            registry.admit(&wrong_host).await.unwrap(),
            RegistrationStatus::Pending
        );

        let wrong_network = request("b", "web-1", "1.2.3.4");
        assert_eq!(
            registry.admit(&wrong_network).await.unwrap(),
            RegistrationStatus::Pending
        );

        let both = request("c", "web-2", "10.0.0.1");
        assert_eq!(
            registry.admit(&both).await.unwrap(),
            RegistrationStatus::Approved
        );
    }

    #[tokio::test]
    async fn the_first_matching_rule_wins() {
        let registry = registry(
            r#"
            rule "block-guests" {
              action       = "reject"
              source_cidrs = ["10.99.0.0/16"]
            }
            rule "everything-else" {
              action       = "approve"
              source_cidrs = ["10.0.0.0/8"]
            }
            "#,
        )
        .await;

        let guest = request("a", "web-1", "10.99.0.1");
        assert_eq!(
            registry.admit(&guest).await.unwrap(),
            RegistrationStatus::Rejected
        );

        let normal = request("b", "web-2", "10.1.0.1");
        assert_eq!(
            registry.admit(&normal).await.unwrap(),
            RegistrationStatus::Approved
        );
    }

    #[tokio::test]
    async fn rejected_agents_are_not_stored() {
        let registry = registry("rule \"all\" {\n  action = \"reject\"\n}\n").await;
        registry
            .admit(&request("a", "web-1", "1.2.3.4"))
            .await
            .unwrap();
        assert!(registry.list().await.is_empty());
    }

    #[tokio::test]
    async fn a_token_rule_needs_the_right_token() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("token");
        std::fs::write(&path, "secret\n").unwrap();
        let registry = registry(&format!(
            "rule \"token\" {{\n  action = \"approve\"\n  token_file = {:?}\n}}\n",
            path.display().to_string()
        ))
        .await;

        let none = request("a", "h1", "1.2.3.4");
        assert_eq!(
            registry.admit(&none).await.unwrap(),
            RegistrationStatus::Pending
        );

        let wrong = Admission {
            token: Some("wrong"),
            ..request("b", "h2", "1.2.3.4")
        };
        assert_eq!(
            registry.admit(&wrong).await.unwrap(),
            RegistrationStatus::Pending
        );

        let right = Admission {
            token: Some("secret"),
            ..request("c", "h3", "1.2.3.4")
        };
        assert_eq!(
            registry.admit(&right).await.unwrap(),
            RegistrationStatus::Approved
        );
    }

    #[test]
    fn an_empty_token_file_is_refused_at_startup() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("token");
        std::fs::write(&path, "  \n").unwrap();
        let text = format!(
            "metrics \"duckdb\" {{\n  path = \"x\"\n}}\nregistration {{\nrule \"t\" {{\n  action = \"approve\"\n  token_file = {:?}\n}}\n}}\n",
            path.display().to_string()
        );

        let config = Config::parse(&text).unwrap();
        assert!(Rules::compile(&config.registration).is_err());
    }

    #[tokio::test]
    async fn a_rule_can_not_bring_back_a_revoked_agent() {
        let registry = registry(SUBNET_RULE).await;
        let host = request("a", "web-1", "10.0.0.1");
        registry.admit(&host).await.unwrap();
        registry.decide("a", HostState::Revoked).await.unwrap();

        assert_eq!(
            registry.admit(&host).await.unwrap(),
            RegistrationStatus::Rejected
        );
    }

    /// Hosts on different networks can share a name, such as a caching name
    /// server in every office. The key tells them apart, not the name.
    #[tokio::test]
    async fn agents_can_share_a_hostname() {
        let registry = registry(SUBNET_RULE).await;
        registry
            .admit(&request("a", "cache", "10.0.0.1"))
            .await
            .unwrap();

        assert_eq!(
            registry
                .admit(&request("b", "cache", "10.1.0.1"))
                .await
                .unwrap(),
            RegistrationStatus::Approved
        );
        assert_eq!(
            registry
                .admit(&request("a", "cache-2", "10.0.0.1"))
                .await
                .unwrap(),
            RegistrationStatus::Approved
        );
        assert_eq!(
            registry
                .admit(&request("a", "cache", "10.0.0.1"))
                .await
                .unwrap(),
            RegistrationStatus::Approved,
            "renaming onto a shared name is fine too"
        );
        let hosts: Vec<String> = registry
            .list()
            .await
            .into_iter()
            .map(|a| a.hostname)
            .collect();
        assert_eq!(hosts, ["cache", "cache"]);
    }

    #[tokio::test]
    async fn a_pending_agent_is_approved_once_a_rule_matches() {
        let registry = registry(SUBNET_RULE).await;
        registry
            .admit(&request("a", "web-1", "1.2.3.4"))
            .await
            .unwrap();

        let moved = request("a", "web-1", "10.0.0.1");
        assert_eq!(
            registry.admit(&moved).await.unwrap(),
            RegistrationStatus::Approved
        );
    }

    #[tokio::test]
    async fn the_pending_list_can_not_grow_without_limit() {
        let registry = registry("max_pending = 2\n").await;

        for id in ["a", "b", "c", "d"] {
            registry.admit(&request(id, id, "1.2.3.4")).await.unwrap();
        }

        assert_eq!(registry.list().await.len(), 2);
    }

    #[tokio::test]
    async fn decisions_survive_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            folder.path().join("hosts.db").display()
        );
        let host = request("a", "web-1", "1.2.3.4");

        let first = registry_with("", Database::connect(&url).await.unwrap()).await;
        first.admit(&host).await.unwrap();
        first.decide("a", HostState::Approved).await.unwrap();

        let second = registry_with("", Database::connect(&url).await.unwrap()).await;
        assert_eq!(
            second.admit(&host).await.unwrap(),
            RegistrationStatus::Approved
        );
    }

    #[tokio::test]
    async fn a_failed_save_refuses_the_agent() {
        let database = Database::for_test().await;
        let registry = registry_with(SUBNET_RULE, database.clone()).await;
        database.break_for_test().await;

        let result = registry.admit(&request("a", "web-1", "10.0.0.1")).await;

        assert!(result.is_err());
        assert!(!registry.is_approved("a").await);
        assert!(registry.list().await.is_empty());
    }

    #[tokio::test]
    async fn approved_agents_can_connect_while_the_database_is_down() {
        let database = Database::for_test().await;
        let registry = registry_with(SUBNET_RULE, database.clone()).await;
        let host = request("a", "web-1", "10.0.0.1");
        registry.admit(&host).await.unwrap();

        database.break_for_test().await;

        assert_eq!(
            registry.admit(&host).await.unwrap(),
            RegistrationStatus::Approved
        );
    }

    #[tokio::test]
    async fn an_approved_agent_can_change_hostname() {
        let registry = registry(SUBNET_RULE).await;
        registry
            .admit(&request("a", "old", "10.0.0.1"))
            .await
            .unwrap();

        registry
            .admit(&request("a", "new", "10.0.0.1"))
            .await
            .unwrap();

        assert_eq!(registry.list().await[0].hostname, "new");
    }

    #[tokio::test]
    async fn a_renamed_agent_still_connects_while_the_database_is_down() {
        let database = Database::for_test().await;
        let registry = registry_with(SUBNET_RULE, database.clone()).await;
        registry
            .admit(&request("a", "old", "10.0.0.1"))
            .await
            .unwrap();

        database.break_for_test().await;

        assert_eq!(
            registry
                .admit(&request("a", "new", "10.0.0.1"))
                .await
                .unwrap(),
            RegistrationStatus::Approved
        );
        assert_eq!(
            registry.get("a").await.unwrap().hostname,
            "old",
            "the name the database still has, until it can be saved"
        );
    }
}
