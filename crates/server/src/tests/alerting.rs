//! Alerting from end to end: real rules in a real database, agents on real
//! sockets, and webhooks and email delivered to local servers. Readings are
//! scripted so each test decides what the metrics say, and time is passed in.

use std::sync::Mutex;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{any, post};
use tokio::io::{AsyncBufReadExt, BufReader};

use super::*;
use crate::alert_evaluator::Evaluator;
use crate::alerting::{
    AlertRuleInput, Channel, ChannelInput, ChannelKind, Comparison, Delivery, Event, NewAlert,
    RuleKind, Severity, check_rule,
};
use crate::metrics::{Metric, NewestReading};
use crate::notifier::{ACKNOWLEDGE_ACTION, Mailer, Notice, Notifier, SILENCE_HOUR_ACTION, Senders};
use crate::slack_actions::SlackActions;
use hyper_util::client::legacy::connect::HttpConnector;
use slack_morphism::SlackClient;
use slack_morphism::prelude::{SlackClientHyperConnector, SlackInteractionBlockActionsEvent};

const MINUTE_MS: i64 = 60_000;

/// What the metrics store will say next.
#[derive(Clone, Default)]
struct Script {
    readings: Arc<Mutex<Vec<NewestReading>>>,
    broken: Arc<Mutex<bool>>,
}

impl Script {
    fn set(&self, readings: Vec<NewestReading>) {
        *self.readings.lock().unwrap() = readings;
    }

    fn set_broken(&self, broken: bool) {
        *self.broken.lock().unwrap() = broken;
    }
}

impl MetricsReader for Script {
    fn series(
        &self,
        _query: &crate::metrics::SeriesQuery,
    ) -> anyhow::Result<crate::metrics::SeriesResult> {
        Ok(Default::default())
    }

    fn last_samples(
        &self,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::LastSample>> {
        Ok(Vec::new())
    }

    fn latest_output(
        &self,
        _agent_id: &str,
        _collector: &str,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        Ok(None)
    }

    fn newest(
        &self,
        _metric: &Metric,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<NewestReading>> {
        if *self.broken.lock().unwrap() {
            anyhow::bail!("deliberate test failure");
        }
        Ok(self.readings.lock().unwrap().clone())
    }

    fn stats(&self, _hour_ago_ms: i64) -> anyhow::Result<crate::store::StoreStats> {
        Ok(Default::default())
    }

    fn series_count(&self) -> anyhow::Result<u64> {
        Ok(0)
    }

    fn calculate(
        &self,
        _query: &crate::calculations::CalculationQuery,
    ) -> anyhow::Result<crate::metrics::SeriesResult> {
        anyhow::bail!("deliberate test failure");
    }
}

/// A server with one connected agent, and an evaluator that started an hour ago.
struct Harness {
    server: TestServer,
    script: Script,
    evaluator: Evaluator,
    agent: Identity,
    client: Option<Client>,
    /// A time to count from. Later than any presence change in the test.
    now: i64,
}

impl Harness {
    async fn start() -> Self {
        let script = Script::default();
        let saved = Saved::default();
        let store = Box::new(crate::store::testing::MemoryStore(saved.clone()));
        let server = start_on("", store, Arc::new(script.clone()), saved, None).await;

        let agent = identity();
        let client = server.connect_approved(&agent, "web-1").await;
        let now = now_ms() + MINUTE_MS;
        let evaluator = evaluator(&server, now - 60 * MINUTE_MS);
        Self {
            server,
            script,
            evaluator,
            agent,
            client: Some(client),
            now,
        }
    }

    fn database(&self) -> &Database {
        &self.server.state.database
    }

    fn id(&self) -> String {
        self.agent.id()
    }

    fn reading(&self, series: &str, time_ms: i64, value: f64) -> NewestReading {
        NewestReading {
            agent_id: self.id(),
            series: series.to_string(),
            time_ms,
            value,
        }
    }

    /// Checks rules at `offset_ms` with a new CPU reading.
    async fn cpu(&mut self, offset_ms: i64, value: f64) {
        let time = self.now + offset_ms;
        self.script.set(vec![self.reading("CPU", time, value)]);
        self.evaluate(offset_ms).await;
    }

    async fn evaluate(&mut self, offset_ms: i64) {
        self.evaluator.evaluate(self.now + offset_ms).await.unwrap();
    }

    async fn open(&self) -> Vec<crate::alerting::Alert> {
        self.database().open_alerts().await.unwrap()
    }

    async fn resolved(&self) -> Vec<crate::alerting::Alert> {
        self.database().resolved_alerts(100).await.unwrap()
    }

    async fn go_offline(&mut self) {
        self.client.take();
        self.server.wait_for_online(&self.id(), false).await;
    }
}

fn evaluator(server: &TestServer, started_ms: i64) -> Evaluator {
    Evaluator::new(
        server.state.database.clone(),
        server.state.registry.clone(),
        server.state.presence.clone(),
        server.state.metrics.clone(),
        server.state.status.clone(),
        started_ms,
    )
}

fn cpu_rule() -> AlertRuleInput {
    AlertRuleInput {
        name: "High CPU".to_string(),
        kind: RuleKind::Metric,
        metric: Some("cpu.usage".to_string()),
        series: None,
        comparison: Some(Comparison::Above),
        threshold: Some(90.0),
        warning_threshold: None,
        for_secs: 120,
        severity: Severity::Critical,
        condition: None,
        enabled: true,
        channels: Vec::new(),
        all_channels: false,
        calculation: None,
        group_by: None,
        filter: None,
        window_secs: None,
        remind_every_secs: None,
    }
}

fn offline_rule() -> AlertRuleInput {
    AlertRuleInput {
        name: "Gone".to_string(),
        kind: RuleKind::Offline,
        metric: None,
        comparison: None,
        threshold: None,
        for_secs: 60,
        ..cpu_rule()
    }
}

// ---- when alerts start and end

#[tokio::test]
async fn a_metric_alert_fires_once_and_resolves_when_it_clears() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();

    test.cpu(0, 95.0).await;
    test.cpu(MINUTE_MS, 95.0).await;
    assert!(test.open().await.is_empty(), "it hasn't lasted long enough");

    test.cpu(2 * MINUTE_MS, 96.5).await;
    let open = test.open().await;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].value, Some(96.5));
    assert_eq!(open[0].host, "web-1");
    assert_eq!(open[0].severity, Severity::Critical);
    assert_eq!(
        open[0].summary,
        "CPU usage on web-1 is 96.5%, above 90% for 2 minutes"
    );

    test.cpu(3 * MINUTE_MS, 97.0).await;
    assert_eq!(
        test.open().await.len(),
        1,
        "one alert, however long it lasts"
    );

    test.cpu(4 * MINUTE_MS, 10.0).await;
    test.cpu(5 * MINUTE_MS, 10.0).await;
    assert_eq!(
        test.open().await.len(),
        1,
        "it hasn't been clear long enough"
    );

    test.cpu(6 * MINUTE_MS, 10.0).await;
    assert!(test.open().await.is_empty());
    let resolved = test.resolved().await;
    assert_eq!(resolved.len(), 1);
    assert_eq!(
        resolved[0].resolve_reason.as_deref(),
        Some("The problem cleared")
    );
    assert_eq!(resolved[0].resolved_ms, Some(test.now + 6 * MINUTE_MS));
}

#[tokio::test]
async fn a_short_spike_does_not_alert() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();

    test.cpu(0, 95.0).await;
    test.cpu(MINUTE_MS, 10.0).await;
    test.cpu(2 * MINUTE_MS, 95.0).await;
    test.cpu(3 * MINUTE_MS, 95.0).await;
    assert!(test.open().await.is_empty());
}

#[tokio::test]
async fn the_same_sample_is_not_counted_twice() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();

    test.cpu(0, 95.0).await;
    // Time passes, but the agent hasn't reported anything new.
    test.evaluate(5 * MINUTE_MS).await;
    assert!(test.open().await.is_empty());

    test.cpu(6 * MINUTE_MS, 95.0).await;
    assert_eq!(test.open().await.len(), 1);
}

#[tokio::test]
async fn below_rules_fire_on_low_readings() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        comparison: Some(Comparison::Below),
        threshold: Some(5.0),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    test.cpu(0, 6.0).await;
    assert!(test.open().await.is_empty());
    test.cpu(MINUTE_MS, 4.0).await;
    assert_eq!(test.open().await.len(), 1);
}

#[tokio::test]
async fn each_series_alerts_separately() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    let readings = vec![
        test.reading("/", test.now, 95.0),
        test.reading("/data", test.now, 96.0),
        test.reading("/tmp", test.now, 5.0),
    ];
    test.script.set(readings);
    test.evaluate(0).await;

    let mut series: Vec<String> = test.open().await.into_iter().map(|a| a.series).collect();
    series.sort();
    assert_eq!(series, ["/", "/data"]);
}

#[tokio::test]
async fn a_rule_can_be_limited_to_some_series() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        series: Some("/data*".to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    let readings = vec![
        test.reading("/", test.now, 95.0),
        test.reading("/data/logs", test.now, 96.0),
    ];
    test.script.set(readings);
    test.evaluate(0).await;

    let open = test.open().await;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].series, "/data/logs");
}

#[tokio::test]
async fn a_condition_limits_which_agents_a_rule_watches() {
    let mut test = Harness::start().await;
    let other = identity();
    let _client = test.server.connect_approved(&other, "db-1").await;
    let facts = |role: &str| FlatFacts::from([("custom.role".to_string(), json!(role))]);
    let now = now_ms() as u64;
    test.database()
        .record_facts(&test.id(), &facts("web"), now)
        .await
        .unwrap();
    test.database()
        .record_facts(&other.id(), &facts("db"), now)
        .await
        .unwrap();

    let rule = AlertRuleInput {
        condition: Some(r#"facts.custom.role == "db""#.to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    let mut readings = vec![test.reading("CPU", test.now, 95.0)];
    readings.push(NewestReading {
        agent_id: other.id(),
        ..test.reading("CPU", test.now, 95.0)
    });
    test.script.set(readings);
    test.evaluate(0).await;

    let open = test.open().await;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].host, "db-1");
}

#[tokio::test]
async fn a_disabled_rule_watches_nothing_and_closes_its_alerts() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    let id = test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    assert_eq!(test.open().await.len(), 1);

    let disabled = AlertRuleInput {
        enabled: false,
        ..rule
    };
    test.database()
        .update_alert_rule(id, &disabled)
        .await
        .unwrap();
    test.cpu(MINUTE_MS, 96.0).await;

    assert!(test.open().await.is_empty());
    assert_eq!(
        test.resolved().await[0].resolve_reason.as_deref(),
        Some("The rule was deleted or disabled")
    );
}

#[tokio::test]
async fn deleting_a_rule_closes_its_alerts_and_keeps_the_history() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    let id = test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    assert!(
        test.database()
            .delete_alert_rule(id, test.now)
            .await
            .unwrap()
    );
    test.evaluate(MINUTE_MS).await;

    assert!(test.open().await.is_empty());
    let resolved = test.resolved().await;
    assert_eq!(resolved[0].rule_id, None);
    assert_eq!(resolved[0].rule_name, "High CPU");
}

#[tokio::test]
async fn a_rule_that_stops_matching_closes_its_alerts() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    let id = test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    let narrowed = AlertRuleInput {
        condition: Some("false".to_string()),
        ..rule
    };
    test.database()
        .update_alert_rule(id, &narrowed)
        .await
        .unwrap();
    test.cpu(MINUTE_MS, 96.0).await;

    assert_eq!(
        test.resolved().await[0].resolve_reason.as_deref(),
        Some("The rule no longer applies to this agent")
    );
}

#[tokio::test]
async fn revoking_an_agent_closes_its_alerts() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    let id = test.id();
    test.server
        .state
        .registry
        .decide(&id, AgentState::Revoked)
        .await
        .unwrap();
    test.cpu(MINUTE_MS, 96.0).await;

    assert_eq!(
        test.resolved().await[0].resolve_reason.as_deref(),
        Some("The agent is no longer approved")
    );
}

#[tokio::test]
async fn missing_data_does_not_close_an_alert() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    test.script.set(Vec::new());
    test.evaluate(10 * MINUTE_MS).await;
    assert_eq!(test.open().await.len(), 1);
}

#[tokio::test]
async fn a_failed_metrics_read_changes_nothing() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    test.script.set_broken(true);
    test.evaluate(MINUTE_MS).await;
    assert_eq!(test.open().await.len(), 1);

    test.script.set_broken(false);
    test.cpu(2 * MINUTE_MS, 10.0).await;
    assert!(test.open().await.is_empty());
}

#[tokio::test]
async fn a_series_that_disappears_closes_its_alert() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    let readings = vec![
        test.reading("/mnt/usb", test.now, 95.0),
        test.reading("/", test.now, 5.0),
    ];
    test.script.set(readings);
    test.evaluate(0).await;
    assert_eq!(test.open().await.len(), 1);

    // The agent is still reporting, so the disk really has gone.
    let time = test.now + MINUTE_MS;
    let readings = vec![test.reading("/", time, 5.0)];
    test.script.set(readings);
    test.evaluate(MINUTE_MS).await;

    assert!(test.open().await.is_empty());
    assert_eq!(
        test.resolved().await[0].resolve_reason.as_deref(),
        Some("This series is no longer reported")
    );
}

/// The disk is still there; the rule was changed to leave it out, and the reason
/// should say so rather than blame the agent.
#[tokio::test]
async fn a_series_the_rule_stops_watching_closes_with_that_reason() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    let id = test.database().create_alert_rule(&rule).await.unwrap();
    test.script
        .set(vec![test.reading("/mnt/usb", test.now, 95.0)]);
    test.evaluate(0).await;
    assert_eq!(test.open().await.len(), 1);

    let narrowed = AlertRuleInput {
        series: Some("/data*".to_string()),
        ..rule
    };
    test.database()
        .update_alert_rule(id, &narrowed)
        .await
        .unwrap();
    let time = test.now + MINUTE_MS;
    test.script.set(vec![test.reading("/mnt/usb", time, 95.0)]);
    test.evaluate(MINUTE_MS).await;

    assert!(test.open().await.is_empty());
    assert_eq!(
        test.resolved().await[0].resolve_reason.as_deref(),
        Some("The rule no longer covers this series")
    );
}

#[tokio::test]
async fn a_restart_does_not_repeat_an_open_alert() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    test.evaluator = evaluator(&test.server, test.now);
    test.cpu(MINUTE_MS, 95.0).await;
    assert_eq!(test.open().await.len(), 1);
    assert!(test.resolved().await.is_empty());

    test.cpu(2 * MINUTE_MS, 10.0).await;
    assert!(test.open().await.is_empty());
}

#[tokio::test]
async fn names_agents_choose_are_cleaned_before_they_are_kept() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    let long = format!("/evil\r\nBcc: x@example.com\0{}", "x".repeat(400));
    let readings = vec![test.reading(&long, test.now, 95.0)];
    test.script.set(readings);
    test.evaluate(0).await;
    let readings = vec![test.reading(&long, test.now + 1, 95.0)];
    test.script.set(readings);
    test.evaluate(1).await;

    let open = test.open().await;
    assert_eq!(open.len(), 1, "the cleaned name still matches itself");
    assert!(!open[0].series.chars().any(char::is_control));
    assert!(!open[0].summary.chars().any(char::is_control));
    assert_eq!(open[0].series.chars().count(), 255);
}

#[tokio::test]
async fn an_agent_cannot_flood_alerts_by_inventing_series() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();

    let readings = (0..500)
        .map(|index| test.reading(&format!("/m{index:03}"), test.now, 95.0))
        .collect();
    test.script.set(readings);
    test.evaluate(0).await;

    assert_eq!(test.open().await.len(), 64);
}

#[tokio::test]
async fn an_agent_going_offline_alerts_after_the_wait() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&offline_rule())
        .await
        .unwrap();

    test.evaluate(0).await;
    assert!(test.open().await.is_empty(), "it's online");

    test.go_offline().await;
    let gone = test.server.state.presence.get(&test.id()).unwrap().since_ms as i64;

    test.evaluator.evaluate(gone + 59_000).await.unwrap();
    assert!(test.open().await.is_empty());

    test.evaluator.evaluate(gone + 60_000).await.unwrap();
    let open = test.open().await;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].summary, "web-1 has been offline for 1 minute");
    assert_eq!(open[0].series, "");
}

/// The rules every server starts with, as the migrations add them.
async fn built_in_rules() -> Vec<AlertRuleInput> {
    let fresh = Database::for_test().await;
    let rules = fresh.list_alert_rules().await.unwrap();
    rules.into_iter().map(|rule| rule.rule).collect()
}

async fn built_in_offline_rule() -> AlertRuleInput {
    let rules = built_in_rules().await;
    let mut offline = rules
        .into_iter()
        .filter(|rule| rule.kind == RuleKind::Offline);
    let rule = offline.next().unwrap();
    assert!(offline.next().is_none());
    rule
}

#[tokio::test]
async fn every_server_starts_with_rules_for_agents_going_offline_and_disks_filling() {
    let names: Vec<String> = built_in_rules()
        .await
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    assert_eq!(names, ["Agent offline", "Disk filling up"]);
}

#[tokio::test]
async fn every_server_starts_with_a_rule_for_agents_going_offline() {
    let rule = built_in_offline_rule().await;

    assert_eq!(rule.name, "Agent offline");
    assert_eq!(rule.kind, RuleKind::Offline);
    assert_eq!(rule.for_secs, 300);
    assert_eq!(rule.severity, Severity::Critical);
    assert!(rule.enabled);
    assert!(rule.all_channels);
    assert!(rule.channels.is_empty());
    check_rule(&rule).unwrap();
}

#[tokio::test]
async fn the_built_in_rule_tells_every_channel_once_an_agent_is_gone_5_minutes() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&built_in_offline_rule().await)
        .await
        .unwrap();
    // Added after the rule, and told all the same.
    let channel = webhook_channel("http://127.0.0.1:9/hook");
    let channel = test.database().create_channel(&channel).await.unwrap();

    test.go_offline().await;
    let gone = test.server.state.presence.get(&test.id()).unwrap().since_ms as i64;
    test.evaluator.evaluate(gone + 299_000).await.unwrap();
    assert!(test.open().await.is_empty());

    test.evaluator.evaluate(gone + 300_000).await.unwrap();
    let open = test.open().await;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].summary, "web-1 has been offline for 5 minutes");
    let deliveries = test.database().due_deliveries(i64::MAX, 10).await.unwrap();
    let told: Vec<i64> = deliveries
        .iter()
        .map(|delivery| delivery.channel.id)
        .collect();
    assert_eq!(told, [channel]);
}

#[tokio::test]
async fn every_server_starts_with_a_warning_at_80_percent_full_and_critical_at_90() {
    let rules = built_in_rules().await;
    let disk: Vec<&AlertRuleInput> = rules
        .iter()
        .filter(|rule| rule.metric.as_deref() == Some("disk.usage"))
        .collect();
    let [rule] = disk[..] else {
        panic!("{disk:?}");
    };
    assert_eq!(rule.name, "Disk filling up");
    assert_eq!(
        rule.levels(),
        [(Severity::Warning, 80.0), (Severity::Critical, 90.0)]
    );
    assert_eq!(rule.comparison, Some(Comparison::Above));
    assert_eq!(rule.series, None);
    assert_eq!(rule.for_secs, 300);
    assert!(rule.enabled);
    assert!(rule.all_channels);
    check_rule(rule).unwrap();
}

/// Marks everything due as sent, as if it had been delivered, and says what it was.
async fn deliver_all(test: &Harness) -> Vec<Event> {
    let due = test.database().due_deliveries(i64::MAX, 100).await.unwrap();
    for delivery in &due {
        test.database()
            .delivery_sent(delivery.id, 1, test.now, None)
            .await
            .unwrap();
    }
    due.iter().map(|delivery| delivery.event).collect()
}

/// Checks rules after a reading of `/` at `minute`, and gives what's open.
async fn disk_at(test: &mut Harness, minute: i64, percent: f64) -> Vec<crate::alerting::Alert> {
    let offset = minute * MINUTE_MS;
    let reading = test.reading("/", test.now + offset, percent);
    test.script.set(vec![reading]);
    test.evaluate(offset).await;
    test.open().await
}

#[tokio::test]
async fn one_disk_alert_is_a_warning_then_critical_then_a_warning_again_until_it_clears() {
    let mut test = Harness::start().await;
    for rule in built_in_rules().await {
        if rule.kind == RuleKind::Metric {
            test.database().create_alert_rule(&rule).await.unwrap();
        }
    }
    let channel = webhook_channel("http://127.0.0.1:9/hook");
    test.database().create_channel(&channel).await.unwrap();

    disk_at(&mut test, 0, 85.0).await;
    let open = disk_at(&mut test, 5, 85.0).await;
    assert_eq!(open.len(), 1);
    let alert = &open[0];
    assert_eq!(alert.severity, Severity::Warning);
    assert!(alert.summary.contains("above 80%"), "{}", alert.summary);
    assert_eq!(deliver_all(&test).await, [Event::Firing]);
    test.database()
        .acknowledge_alert(alert.id, "sam", test.now)
        .await
        .unwrap();

    disk_at(&mut test, 6, 95.0).await;
    let open = disk_at(&mut test, 11, 95.0).await;
    assert_eq!(open.len(), 1, "one alert, not a warning and a critical one");
    assert_eq!(open[0].id, alert.id);
    assert_eq!(open[0].severity, Severity::Critical);
    assert!(open[0].summary.contains("above 90%"), "{}", open[0].summary);
    assert_eq!(
        open[0].acknowledged_by, None,
        "worse needs acknowledging again"
    );
    assert_eq!(deliver_all(&test).await, [Event::Escalated]);

    disk_at(&mut test, 12, 85.0).await;
    let open = disk_at(&mut test, 17, 85.0).await;
    assert_eq!(open[0].severity, Severity::Warning);
    assert_eq!(deliver_all(&test).await, [Event::Eased]);

    disk_at(&mut test, 18, 50.0).await;
    assert!(disk_at(&mut test, 23, 50.0).await.is_empty());
    assert_eq!(deliver_all(&test).await, [Event::Resolved]);
}

#[tokio::test]
async fn a_channel_not_told_yet_hears_of_the_alert_as_it_is_when_it_does() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        threshold: Some(90.0),
        warning_threshold: Some(80.0),
        for_secs: 0,
        all_channels: true,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    let channel = webhook_channel("http://127.0.0.1:9/hook");
    test.database().create_channel(&channel).await.unwrap();

    disk_at(&mut test, 0, 85.0).await;
    disk_at(&mut test, 1, 95.0).await;

    let due = test.database().due_deliveries(i64::MAX, 10).await.unwrap();
    let events: Vec<Event> = due.iter().map(|delivery| delivery.event).collect();
    assert_eq!(events, [Event::Firing]);
    assert_eq!(due[0].alert.severity, Severity::Critical);
}

/// A webhook channel that only hears of critical alerts, like a pager.
fn pager(url: &str) -> ChannelInput {
    ChannelInput {
        name: "Pager".to_string(),
        severities: std::collections::BTreeSet::from([Severity::Critical]),
        ..webhook_channel(url)
    }
}

/// What's due for each channel, marked sent, by channel.
async fn deliver_by_channel(test: &Harness) -> Vec<(i64, Event)> {
    let due = test.database().due_deliveries(i64::MAX, 100).await.unwrap();
    for delivery in &due {
        test.database()
            .delivery_sent(delivery.id, 1, test.now, None)
            .await
            .unwrap();
    }
    let mut told: Vec<(i64, Event)> = due
        .iter()
        .map(|delivery| (delivery.channel.id, delivery.event))
        .collect();
    told.sort_by_key(|(channel, _)| *channel);
    told
}

#[tokio::test]
async fn a_critical_only_channel_hears_of_an_alert_once_it_is_critical() {
    let mut test = Harness::start().await;
    for rule in built_in_rules().await {
        if rule.kind == RuleKind::Metric {
            test.database().create_alert_rule(&rule).await.unwrap();
        }
    }
    let chat = webhook_channel("http://127.0.0.1:9/chat");
    let chat = test.database().create_channel(&chat).await.unwrap();
    let pager = pager("http://127.0.0.1:9/pager");
    let pager = test.database().create_channel(&pager).await.unwrap();

    disk_at(&mut test, 0, 85.0).await;
    disk_at(&mut test, 5, 85.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(chat, Event::Firing)]);

    disk_at(&mut test, 6, 95.0).await;
    disk_at(&mut test, 11, 95.0).await;
    assert_eq!(
        deliver_by_channel(&test).await,
        [(chat, Event::Escalated), (pager, Event::Firing)]
    );

    disk_at(&mut test, 12, 85.0).await;
    disk_at(&mut test, 17, 85.0).await;
    assert_eq!(
        deliver_by_channel(&test).await,
        [(chat, Event::Eased), (pager, Event::Eased)]
    );

    disk_at(&mut test, 18, 50.0).await;
    disk_at(&mut test, 23, 50.0).await;
    assert_eq!(
        deliver_by_channel(&test).await,
        [(chat, Event::Resolved), (pager, Event::Resolved)]
    );
}

#[tokio::test]
async fn a_warnings_only_channel_follows_a_warning_that_goes_critical_but_not_one_critical_at_once()
{
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        threshold: Some(90.0),
        warning_threshold: Some(80.0),
        for_secs: 0,
        all_channels: true,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    let mail = ChannelInput {
        name: "Mail".to_string(),
        severities: std::collections::BTreeSet::from([Severity::Warning]),
        ..webhook_channel("http://127.0.0.1:9/mail")
    };
    let mail = test.database().create_channel(&mail).await.unwrap();

    disk_at(&mut test, 0, 85.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(mail, Event::Firing)]);
    disk_at(&mut test, 1, 95.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(mail, Event::Escalated)]);
    disk_at(&mut test, 2, 50.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(mail, Event::Resolved)]);

    disk_at(&mut test, 3, 95.0).await;
    assert_eq!(test.open().await[0].severity, Severity::Critical);
    assert_eq!(deliver_by_channel(&test).await, []);
}

#[tokio::test]
async fn a_pager_is_not_sent_an_alert_that_eased_before_it_went() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        metric: Some("disk.usage".to_string()),
        threshold: Some(90.0),
        warning_threshold: Some(80.0),
        for_secs: 0,
        all_channels: true,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    let chat = webhook_channel("http://127.0.0.1:9/chat");
    let chat = test.database().create_channel(&chat).await.unwrap();
    let pager = pager("http://127.0.0.1:9/pager");
    test.database().create_channel(&pager).await.unwrap();

    disk_at(&mut test, 0, 85.0).await;
    disk_at(&mut test, 1, 95.0).await;
    disk_at(&mut test, 2, 85.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(chat, Event::Firing)]);

    disk_at(&mut test, 3, 50.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(chat, Event::Resolved)]);
}

#[tokio::test]
async fn a_critical_alert_reaches_a_critical_only_channel_straight_away() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        all_channels: true,
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    let pager = pager("http://127.0.0.1:9/pager");
    let pager = test.database().create_channel(&pager).await.unwrap();

    test.cpu(0, 99.0).await;
    assert_eq!(deliver_by_channel(&test).await, [(pager, Event::Firing)]);
}

#[tokio::test]
async fn alerts_lead_with_the_machine_and_keep_its_id_for_hovering() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    let client = test.client.as_mut().unwrap();
    send(client, &facts("24.04")).await;
    test.server.wait_for_facts(&test.id(), 2).await;
    test.cpu(0, 95.0).await;
    let short = crate::registration::short_id(&test.id()).to_string();

    let mut browser = Browser::default();
    let alerts = browser.get(&test.server, "/alerts").await;
    assert!(
        alerts.body.contains(&format!(
            r#"title="Agent {short}"><span class="os-icon os-linux""#
        )),
        "{}",
        alerts.body
    );
    assert!(
        !alerts
            .body
            .contains(&format!(r#"<span class="agent-id">{short}"#))
    );

    let overview = browser.get(&test.server, "/").await;
    let host = overview
        .body
        .find(r#"class="host-name problem-host""#)
        .unwrap();
    let summary = overview.body.find("CPU usage on web-1 is 95%").unwrap();
    assert!(host < summary, "{}", overview.body);
    assert!(overview.body.contains("os-linux"));
}

#[tokio::test]
async fn a_rule_can_not_have_every_channel_and_some_of_them() {
    let rule = AlertRuleInput {
        all_channels: true,
        channels: vec![1],
        ..offline_rule()
    };
    let error = check_rule(&rule).unwrap_err().to_string();
    assert!(error.contains("not both"), "{error}");
}

#[tokio::test]
async fn an_agent_coming_back_resolves_after_the_wait() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&offline_rule())
        .await
        .unwrap();
    test.go_offline().await;
    let gone = test.server.state.presence.get(&test.id()).unwrap().since_ms as i64;
    test.evaluator.evaluate(gone + 60_000).await.unwrap();
    assert_eq!(test.open().await.len(), 1);

    let mut client = test.server.connect().await;
    let status = handshake(&mut client, &test.agent, "web-1", None).await;
    assert_eq!(status, RegistrationStatus::Approved);
    test.server.wait_for_online(&test.id(), true).await;
    let back = test.server.state.presence.get(&test.id()).unwrap().since_ms as i64;

    test.evaluator.evaluate(back + 59_000).await.unwrap();
    assert_eq!(test.open().await.len(), 1);
    test.evaluator.evaluate(back + 60_000).await.unwrap();
    assert!(test.open().await.is_empty());
}

#[tokio::test]
async fn a_restart_does_not_look_like_the_fleet_going_down() {
    let test = Harness::start().await;
    test.database()
        .create_alert_rule(&offline_rule())
        .await
        .unwrap();

    // As after a restart: nothing has connected yet, as far as this knows.
    let server = start().await;
    let agent = identity();
    server
        .state
        .database
        .create_alert_rule(&offline_rule())
        .await
        .unwrap();
    server.connect_approved(&agent, "web-1").await;
    server.wait_for_online(&agent.id(), false).await;

    let started = now_ms() + MINUTE_MS;
    let mut restarted = evaluator(&server, started);
    restarted.evaluate(started + 119_000).await.unwrap();
    assert!(
        server
            .state
            .database
            .open_alerts()
            .await
            .unwrap()
            .is_empty()
    );

    // The grace period is over, and it really is gone.
    restarted.evaluate(started + 120_000).await.unwrap();
    assert_eq!(server.state.database.open_alerts().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_open_offline_alert_survives_the_grace_period_after_a_restart() {
    let mut test = Harness::start().await;
    test.database()
        .create_alert_rule(&offline_rule())
        .await
        .unwrap();
    test.go_offline().await;
    let gone = test.server.state.presence.get(&test.id()).unwrap().since_ms as i64;
    test.evaluator.evaluate(gone + 60_000).await.unwrap();

    let restart = gone + 120_000;
    let mut restarted = evaluator(&test.server, restart);
    restarted.evaluate(restart + 1000).await.unwrap();

    assert_eq!(test.open().await.len(), 1);
    assert!(test.resolved().await.is_empty());
}

#[tokio::test]
async fn an_agent_never_seen_since_a_restart_counts_as_offline() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect().await;
    assert_eq!(
        handshake(&mut client, &agent, "quiet-1", None).await,
        RegistrationStatus::Pending
    );
    server.approve(&agent).await;
    drop(client);

    // A fresh presence table, as after a restart, for an agent that stays away.
    let mut state = server.state.clone();
    state.presence = Arc::new(Presence::default());
    state
        .database
        .create_alert_rule(&offline_rule())
        .await
        .unwrap();

    let started = now_ms();
    let mut restarted = Evaluator::new(
        state.database.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.metrics.clone(),
        state.status.clone(),
        started,
    );
    restarted.evaluate(started + 120_000).await.unwrap();

    let open = state.database.open_alerts().await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].host, "quiet-1");
}

#[tokio::test]
async fn a_stopped_process_alerts_from_what_an_agent_really_sends() {
    let server = start_with_metrics().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let rule = AlertRuleInput {
        name: "nginx down".to_string(),
        metric: Some("process.count".to_string()),
        series: Some("nginx".to_string()),
        comparison: Some(Comparison::Below),
        threshold: Some(1.0),
        for_secs: 0,
        ..cpu_rule()
    };
    server
        .state
        .database
        .create_alert_rule(&rule)
        .await
        .unwrap();

    let sample = |timestamp_ms: i64, count: u64| {
        AgentMessage::Sample(Sample {
            timestamp_ms: timestamp_ms as u64,
            metrics: BTreeMap::from([(
                "processes".to_string(),
                json!([
                    { "name": "nginx", "count": count, "cpu_percent": 0.0, "memory_percent": 0.0 },
                    { "name": "sshd", "count": 0, "cpu_percent": 0.0, "memory_percent": 0.0 },
                ]),
            )]),
        })
    };
    let wait_for = |count: f64, after: i64| {
        let metrics = server.state.metrics.clone();
        async move {
            let metric = crate::metrics::find("process.count").unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let rows = metrics.newest(metric, now_ms()).await.unwrap();
                if rows
                    .iter()
                    .any(|r| r.series == "nginx" && r.value == count && r.time_ms >= after)
                {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
            panic!("the reading never arrived");
        }
    };

    let mut evaluator = evaluator(&server, now_ms() - 60 * MINUTE_MS);
    let first = now_ms() - 2000;
    send(&mut client, &sample(first, 2)).await;
    wait_for(2.0, first).await;
    evaluator.evaluate(now_ms()).await.unwrap();
    assert!(
        server
            .state
            .database
            .open_alerts()
            .await
            .unwrap()
            .is_empty()
    );

    let second = now_ms() - 1000;
    send(&mut client, &sample(second, 0)).await;
    wait_for(0.0, second).await;
    evaluator.evaluate(now_ms()).await.unwrap();

    let open = server.state.database.open_alerts().await.unwrap();
    assert_eq!(open.len(), 1, "only the rule's own process");
    assert_eq!(
        open[0].summary,
        "Running processes (nginx) on web-1 is 0, below 1"
    );
}

#[tokio::test]
async fn process_charts_only_appear_for_agents_that_report_processes() {
    let server = start_with_metrics().await;
    let (plain, _plain_client) = report_samples(&server, "/").await;

    let watching = identity();
    let mut client = server.connect_approved(&watching, "web-2").await;
    let time = now_ms() - 1000;
    let sample = AgentMessage::Sample(Sample {
        timestamp_ms: time as u64,
        metrics: BTreeMap::from([(
            "processes".to_string(),
            json!([{ "name": "nginx", "count": 2, "cpu_percent": 1.0, "memory_percent": 1.0 }]),
        )]),
    });
    send(&mut client, &sample).await;

    let metric = crate::metrics::find("process.count").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server
        .state
        .metrics
        .newest(metric, now_ms())
        .await
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < deadline, "the sample never arrived");
        sleep(Duration::from_millis(10)).await;
    }

    let mut browser = Browser::default();
    let page = browser
        .get(&server, &format!("/agents/{}/metrics", plain.id()))
        .await;
    assert!(page.body.contains("CPU usage"));
    assert!(!page.body.contains("Running processes"), "{}", page.body);

    let page = browser
        .get(&server, &format!("/agents/{}/metrics", watching.id()))
        .await;
    assert!(page.body.contains("Running processes"), "{}", page.body);
    assert!(page.body.contains("Process CPU usage"));
    assert!(page.body.contains("nginx"));
}

#[tokio::test]
async fn a_metric_for_alerts_only_gets_no_chart_but_can_still_be_read() {
    let server = start_with_metrics().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let time = now_ms() - 1000;
    let sample = AgentMessage::Sample(Sample {
        timestamp_ms: time as u64,
        metrics: BTreeMap::from([(
            "network".to_string(),
            json!({ "en0": { "received_bytes": 0, "transmitted_bytes": 0, "link_up": 1 } }),
        )]),
    });
    send(&mut client, &sample).await;

    let metric = crate::metrics::find("network.link").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server
        .state
        .metrics
        .newest(metric, now_ms())
        .await
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < deadline, "the sample never arrived");
        sleep(Duration::from_millis(10)).await;
    }

    let page = Browser::default()
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;
    assert!(!page.body.contains("Network link up"), "{}", page.body);
}

#[tokio::test]
async fn an_agents_page_shows_how_its_checks_last_went() {
    let server = start_with_metrics().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let time = now_ms() - 1000;
    let sample = AgentMessage::Sample(Sample {
        timestamp_ms: time as u64,
        metrics: BTreeMap::from([(
            "checks".to_string(),
            json!([
                {
                    "name": "site", "kind": "http", "up": 1, "response_ms": 120.5,
                    "first_byte_ms": 80.25, "status": 200, "protocol": "HTTP/2.0",
                    "tls_version": "TLS 1.3", "cert_days_left": 42,
                },
                {
                    "name": "<script>alert(1)</script>", "kind": "tcp", "up": 0,
                    "error": "<b>couldn't connect</b>",
                },
                { "kind": "tcp", "up": "not a name, so this row is skipped" },
                7,
            ]),
        )]),
    });
    send(&mut client, &sample).await;

    let metric = crate::metrics::find("check.up").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server
        .state
        .metrics
        .newest(metric, now_ms())
        .await
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < deadline, "the sample never arrived");
        sleep(Duration::from_millis(10)).await;
    }

    let page = Browser::default()
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Latest checks"));
    for text in ["120.5 ms", "80.2 ms", "HTTP/2.0", "TLS 1.3", ">42<", "Down"] {
        assert!(page.body.contains(text), "{text}: {}", page.body);
    }
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("<b>couldn"), "{}", page.body);
}

#[tokio::test]
async fn an_agents_page_shows_its_custom_metrics_without_trusting_them() {
    let server = start_with_metrics().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let sample = AgentMessage::Sample(Sample {
        timestamp_ms: (now_ms() - 1000) as u64,
        metrics: BTreeMap::from([(
            "custom".to_string(),
            json!([
                { "name": "queue", "ok": 1, "value": 12.5 },
                { "name": "many", "ok": 1 },
                { "name": "many.depth", "value": 3 },
                { "name": "<script>alert(1)</script>", "ok": 0, "error": "<b>timed out</b>" },
                { "ok": 1, "value": 9 },
                "nonsense",
            ]),
        )]),
    });
    send(&mut client, &sample).await;

    let metric = crate::metrics::find("custom.ok").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server
        .state
        .metrics
        .newest(metric, now_ms())
        .await
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < deadline, "the sample never arrived");
        sleep(Duration::from_millis(10)).await;
    }

    let page = Browser::default()
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Latest custom metrics"));
    assert_eq!(page.body.matches("badge good").count(), 3, "{}", page.body);
    assert_eq!(page.body.matches("badge bad").count(), 1, "{}", page.body);
    assert!(page.body.contains(">12.5<"), "{}", page.body);
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("<b>timed"), "{}", page.body);
}

#[tokio::test]
async fn a_rule_can_choose_custom_metrics_by_name_but_not_commands() {
    let server = start().await;
    for settings in [
        json!({ "names": ["/bin/sh -c id"] }),
        json!({ "command": ["/bin/sh"] }),
    ] {
        let rule = json!({
            "name": "Bad",
            "priority": 100,
            "settings": { "collectors": { "custom": settings } },
        });
        let (status, body) = api(&server, "POST", "/api/v1/rules", &rule).await;
        assert!((400..500).contains(&status), "{status}: {body}");
    }
}

#[tokio::test]
async fn charts_keep_the_catalog_order_however_their_queries_finish() {
    let server = start_with_metrics().await;
    let (agent, _client) = report_samples(&server, "/").await;

    let page = Browser::default()
        .get(&server, &format!("/agents/{}/metrics", agent.id()))
        .await;
    let position = |title: &str| page.body.find(&format!("<h2>{title}</h2>")).unwrap();
    assert!(position("CPU usage") < position("Load average"));
    assert!(position("Load average") < position("Memory usage"));
    assert!(position("Memory usage") < position("Disk usage"));
    assert!(position("Disk usage") < position("Network received"));
    assert!(position("Network received") < position("Network sent"));
}

// ---- delivery

/// A webhook that records what it's sent and answers with the next status.
#[derive(Clone, Default)]
struct Hook {
    received: Arc<Mutex<Vec<Value>>>,
    statuses: Arc<Mutex<Vec<StatusCode>>>,
}

impl Hook {
    async fn start(&self) -> String {
        let hook = self.clone();
        let router = Router::new()
            .route(
                "/secret-token",
                post(move |body: String| async move {
                    hook.received
                        .lock()
                        .unwrap()
                        .push(serde_json::from_str(&body).unwrap());
                    let mut statuses = hook.statuses.lock().unwrap();
                    if statuses.is_empty() {
                        StatusCode::OK
                    } else {
                        statuses.remove(0)
                    }
                }),
            )
            .route(
                "/moved",
                post(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/secret-token")],
                    )
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        format!("http://{address}")
    }

    fn events(&self) -> Vec<String> {
        let received = self.received.lock().unwrap();
        received
            .iter()
            .map(|body| body["event"].as_str().unwrap().to_string())
            .collect()
    }
}

fn webhook_channel(url: &str) -> ChannelInput {
    ChannelInput {
        name: "Ops".to_string(),
        kind: ChannelKind::Webhook,
        target: url.to_string(),
        credential: None,
        app_token: None,
        severities: crate::alerting::every_severity(),
    }
}

/// A firing alert with a channel, ready to deliver.
async fn firing_with_channel(test: &mut Harness, url: &str) -> Notifier {
    let database = test.database().clone();
    let channel = database
        .create_channel(&webhook_channel(url))
        .await
        .unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    database.create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    Notifier::new(database, Senders::default())
}

async fn due(test: &Harness, at_ms: i64) -> Vec<Delivery> {
    test.database().due_deliveries(at_ms, 16).await.unwrap()
}

#[tokio::test]
async fn a_webhook_hears_about_an_alert_starting_and_ending_once_each() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    let url = format!("{}/secret-token", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;

    notifier.deliver_due(test.now).await.unwrap();
    notifier.deliver_due(test.now + 1).await.unwrap();
    assert_eq!(hook.events(), ["firing"]);

    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();
    assert_eq!(hook.events(), ["firing", "resolved"]);

    let received = hook.received.lock().unwrap();
    assert_eq!(received[0]["version"], 1);
    assert_eq!(received[0]["alert"]["host"], "web-1");
    assert_eq!(received[0]["alert"]["severity"], "critical");
    assert_eq!(received[0]["text"], "CPU usage on web-1 is 95%, above 90%");
    assert_eq!(
        received[1]["text"],
        "Resolved: CPU usage on web-1 is 95%, above 90%"
    );
    assert_eq!(
        received[1]["alert"]["resolve_reason"],
        "The problem cleared"
    );
    assert_ne!(received[0]["id"], received[1]["id"]);
}

#[tokio::test]
async fn a_discord_channel_gets_discords_message_format() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    let url = format!("{}/secret-token", hook.start().await);
    let channel = ChannelInput {
        name: "Discord".to_string(),
        kind: ChannelKind::Discord,
        target: url,
        credential: None,
        app_token: None,
        severities: crate::alerting::every_severity(),
    };
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    Notifier::new(test.database().clone(), Senders::default())
        .deliver_due(test.now)
        .await
        .unwrap();

    let received = hook.received.lock().unwrap();
    assert_eq!(
        received[0],
        json!({
            "content": "**CRITICAL** CPU usage on web-1 is 95%, above 90%",
            "allowed_mentions": { "parse": [] },
        })
    );
}

#[tokio::test]
async fn a_discord_channel_can_be_made_from_the_form_and_keeps_its_url_hidden() {
    let server = start().await;
    let mut browser = Browser::default();
    let url = "https://discord.com/api/webhooks/123/secret-token";
    let fields = [
        ("name", "Team"),
        ("kind", "discord"),
        ("target", url),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];

    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let page = browser.get(&server, "/alerts/channels").await;
    assert!(page.body.contains("Discord"), "{}", page.body);
    assert!(page.body.contains("https://discord.com/…"));
    assert!(!page.body.contains("secret-token"));

    let id = server.state.database.list_channels().await.unwrap()[0].id;
    let page = browser
        .get(&server, &format!("/alerts/channels/{id}/edit"))
        .await;
    assert!(!page.body.contains("secret-token"), "{}", page.body);
    assert!(
        page.body.contains(r#"value="discord" selected"#),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_wrong_url_for_discord_is_refused_on_the_form() {
    let server = start().await;
    let fields = [
        ("name", "Team"),
        ("kind", "discord"),
        ("target", "https://hooks.slack.com/services/x"),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = Browser::default()
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("Discord webhook URL"), "{}", page.body);
}

/// A stand-in for Slack's API. It keeps what it's sent, and answers each call with
/// the next error if there is one. `user` is who it says pressed a button, and
/// `connect_error` is what it says about an app-level token.
#[derive(Clone, Default)]
struct FakeSlack {
    calls: Arc<Mutex<Vec<(String, String, Value)>>>,
    errors: Arc<Mutex<Vec<&'static str>>>,
    user: Arc<Mutex<Value>>,
    connect_error: Arc<Mutex<Option<&'static str>>>,
    /// Where it's listening, once started.
    address: Arc<Mutex<String>>,
}

impl FakeSlack {
    async fn start(&self) -> String {
        let answer = |method: &'static str, slack: FakeSlack| {
            move |headers: axum::http::HeaderMap, body: String| async move {
                let auth = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body: Value =
                    serde_json::from_str(&body).unwrap_or_else(|_| Value::String(body.clone()));
                slack
                    .calls
                    .lock()
                    .unwrap()
                    .push((method.to_string(), auth, body));
                let refused = *slack.connect_error.lock().unwrap();
                if let (Some(code), "connect") = (refused, method) {
                    return axum::Json(json!({ "ok": false, "error": code }));
                }
                let mut errors = slack.errors.lock().unwrap();
                if errors.is_empty() {
                    let address = slack.address.lock().unwrap().clone();
                    axum::Json(json!({
                        "ok": true,
                        "channel": "C123",
                        "ts": "1700000000.000100",
                        "message": { "ts": "1700000000.000100", "text": "sent" },
                        "url": "wss://slack.invalid/link",
                        "user": slack.user.lock().unwrap().clone(),
                        "upload_url": format!("{address}/upload"),
                        "file_id": "F123",
                        "files": [],
                    }))
                } else {
                    axum::Json(json!({ "ok": false, "error": errors.remove(0) }))
                }
            }
        };
        let router = Router::new()
            .route("/api/chat.postMessage", post(answer("post", self.clone())))
            .route("/api/chat.update", post(answer("update", self.clone())))
            .route("/api/users.info", any(answer("users.info", self.clone())))
            .route(
                "/api/apps.connections.open",
                post(answer("connect", self.clone())),
            )
            .route("/respond", post(answer("respond", self.clone())))
            .route(
                "/api/files.getUploadURLExternal",
                any(answer("upload_url", self.clone())),
            )
            .route(
                "/api/files.completeUploadExternal",
                post(answer("complete", self.clone())),
            )
            .route("/upload", post(upload(self.clone())));
        // The file itself, which is kept as its size.
        fn upload(
            slack: FakeSlack,
        ) -> impl Fn(axum::body::Bytes) -> std::future::Ready<&'static str> + Clone {
            move |body: axum::body::Bytes| {
                slack.calls.lock().unwrap().push((
                    "upload".to_string(),
                    String::new(),
                    json!(body.len()),
                ));
                std::future::ready("OK")
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        *self.address.lock().unwrap() = format!("http://{address}");
        format!("http://{address}/api")
    }

    /// A client for the server's side of a Slack app, pointed here.
    fn client(&self) -> SlackClient<SlackClientHyperConnector<HttpConnector>> {
        let url = format!("{}/api", self.address.lock().unwrap());
        let connector = SlackClientHyperConnector::with_connector(HttpConnector::new())
            .with_slack_api_url(&url);
        SlackClient::new(connector)
    }

    /// The last thing a button press was answered with.
    fn answer(&self) -> Value {
        let calls = self.calls();
        let (_, _, body) = calls.iter().rev().find(|call| call.0 == "respond").unwrap();
        body.clone()
    }

    fn calls(&self) -> Vec<(String, String, Value)> {
        self.calls.lock().unwrap().clone()
    }

    fn methods(&self) -> Vec<String> {
        self.calls().into_iter().map(|call| call.0).collect()
    }
}

/// Stands in for an on-call service, and answers with these statuses in turn, then 202.
#[derive(Clone, Default)]
struct FakeOnCall {
    events: Arc<Mutex<Vec<Value>>>,
    statuses: Arc<Mutex<Vec<u16>>>,
}

impl FakeOnCall {
    async fn start(&self) -> String {
        let fake = self.clone();
        let router = Router::new().fallback(post(move |axum::Json(event): axum::Json<Value>| {
            let fake = fake.clone();
            async move {
                fake.events.lock().unwrap().push(event);
                let mut statuses = fake.statuses.lock().unwrap();
                if statuses.is_empty() {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::from_u16(statuses.remove(0)).unwrap()
                }
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        format!("http://{address}/v2/enqueue")
    }

    fn events(&self) -> Vec<Value> {
        self.events.lock().unwrap().clone()
    }
}

const PAGERDUTY_KEY: &str = "abcdefghijklmnopqrstuvwxyz012345";

async fn firing_on_pagerduty(test: &mut Harness, pagerduty: &FakeOnCall) -> Notifier {
    let url = pagerduty.start().await;
    let senders = Senders {
        web_url: Some("https://monitor.example.com".to_string()),
        pagerduty_url: Some(url),
        ..Senders::default()
    };
    firing_on(test, ChannelKind::PagerDuty, PAGERDUTY_KEY, senders).await
}

async fn firing_on(
    test: &mut Harness,
    kind: ChannelKind,
    target: &str,
    senders: Senders,
) -> Notifier {
    let channel = ChannelInput {
        name: "On call".to_string(),
        kind,
        target: target.to_string(),
        credential: None,
        app_token: None,
        severities: crate::alerting::every_severity(),
    };
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    Notifier::new(test.database().clone(), senders)
}

fn with_web_url() -> Senders {
    Senders {
        web_url: Some("https://monitor.example.com".to_string()),
        ..Senders::default()
    }
}

#[tokio::test]
async fn an_alert_opens_and_closes_in_alertops() {
    let mut test = Harness::start().await;
    let alertops = FakeOnCall::default();
    let url = alertops.start().await;
    let notifier = firing_on(&mut test, ChannelKind::AlertOps, &url, with_web_url()).await;

    notifier.deliver_due(test.now).await.unwrap();
    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    let events = alertops.events();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["status"], "open");
    assert_eq!(events[0]["subject"], "High CPU");
    assert_eq!(events[0]["message"], "CPU usage on web-1 is 95%, above 90%");
    assert_eq!(events[0]["severity"], "critical");
    assert_eq!(events[0]["host"], "web-1");
    assert_eq!(events[0]["link"], "https://monitor.example.com/alerts");
    assert_eq!(events[1]["status"], "closed");
    assert_eq!(events[1]["alert_id"], events[0]["alert_id"]);
}

#[tokio::test]
async fn an_alert_opens_and_closes_in_signl4() {
    let mut test = Harness::start().await;
    let signl4 = FakeOnCall::default();
    let url = signl4.start().await;
    let notifier = firing_on(&mut test, ChannelKind::Signl4, &url, with_web_url()).await;

    notifier.deliver_due(test.now).await.unwrap();
    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    let events = signl4.events();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["X-S4-Status"], "new");
    assert_eq!(events[0]["Title"], "High CPU");
    assert_eq!(events[0]["Message"], "CPU usage on web-1 is 95%, above 90%");
    assert_eq!(events[0]["Severity"], "critical");
    assert_eq!(events[0]["Link"], "https://monitor.example.com/alerts");
    assert_eq!(events[1]["X-S4-Status"], "resolved");
    assert_eq!(events[1]["X-S4-ExternalID"], events[0]["X-S4-ExternalID"]);
}

#[tokio::test]
async fn a_failure_names_the_service_without_its_secret_url() {
    for (kind, name) in [
        (ChannelKind::AlertOps, "AlertOps"),
        (ChannelKind::Signl4, "SIGNL4"),
    ] {
        let mut test = Harness::start().await;
        let service = FakeOnCall::default();
        service.statuses.lock().unwrap().push(404);
        let url = format!("{}/secret-token", service.start().await);
        let notifier = firing_on(&mut test, kind, &url, Senders::default()).await;

        notifier.deliver_due(test.now).await.unwrap();

        let problems = test.database().delivery_problems(10).await.unwrap();
        assert_eq!(problems[0].error, format!("{name} returned status 404"));
    }
}

#[tokio::test]
async fn a_test_opens_an_incident_and_closes_it_again_on_every_service() {
    for (kind, status, id) in [
        (ChannelKind::AlertOps, "status", "alert_id"),
        (ChannelKind::Signl4, "X-S4-Status", "X-S4-ExternalID"),
    ] {
        let service = FakeOnCall::default();
        let channel = Channel {
            id: 1,
            channel: ChannelInput {
                name: "On call".to_string(),
                kind,
                target: service.start().await,
                credential: None,
                app_token: None,
                severities: crate::alerting::every_severity(),
            },
        };

        crate::notifier::send(channel, Notice::test(), None, Senders::default())
            .await
            .unwrap();

        let events = service.events();
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(["open", "new"].contains(&events[0][status].as_str().unwrap()));
        assert!(["closed", "resolved"].contains(&events[1][status].as_str().unwrap()));
        assert_eq!(events[0][id], events[1][id]);
    }
}

#[tokio::test]
async fn a_service_url_is_set_but_never_shown_again() {
    let server = start().await;
    for (kind, name, target, preview) in [
        (
            "alertops",
            "AlertOps",
            "https://notify.alertops.com/POSTAlert/secret-token/Custom",
            "https://notify.alertops.com/…",
        ),
        (
            "signl4",
            "SIGNL4",
            "https://connect.signl4.com/webhook/secret-token",
            "https://connect.signl4.com/…",
        ),
    ] {
        let body = json!({ "name": name, "kind": kind, "target": target });
        let (status, made) = api(&server, "POST", "/api/v1/notification-channels", &body).await;
        assert_eq!(status, 201, "{made}");
        assert!(!made.to_string().contains("secret-token"), "{made}");

        let id = made["id"].as_i64().unwrap();
        let (_, listed) = api(
            &server,
            "GET",
            "/api/v1/notification-channels",
            &Value::Null,
        )
        .await;
        assert!(!listed.to_string().contains("secret-token"), "{listed}");
        let saved = listed.as_array().unwrap().iter().find(|c| c["id"] == id);
        assert_eq!(saved.unwrap()["target_preview"], preview);

        let mut browser = Browser::default();
        let edit = browser
            .get(&server, &format!("/alerts/channels/{id}/edit"))
            .await;
        assert!(!edit.body.contains("secret-token"), "{}", edit.body);
        let list = browser.get(&server, "/alerts/channels").await;
        assert!(!list.body.contains("secret-token"), "{}", list.body);
        assert!(list.body.contains(name), "{}", list.body);
    }
}

#[tokio::test]
async fn the_channel_form_offers_what_alertops_needs_to_map_from() {
    let server = start().await;
    let mut browser = Browser::default();
    let form = browser.get(&server, "/alerts/channels/new").await;

    for choice in ["pagerduty", "alertops", "signl4"] {
        assert!(
            form.body.contains(&format!("value=\"{choice}\"")),
            "{choice}"
        );
    }
    let sample = crate::notifier::alertops_sample();
    let docs = include_str!("../../../../docs/notifications.md");
    for line in sample.lines() {
        assert!(
            docs.contains(line),
            "the docs' sample is out of date: {line}"
        );
    }
    let sample: Value = serde_json::from_str(&sample).unwrap();
    for key in ["alert_id", "status", "subject", "message", "link"] {
        assert!(!sample[key].is_null(), "{key}");
        assert!(form.body.contains(key), "{key}");
    }
}

#[tokio::test]
async fn an_alert_opens_a_pagerduty_incident() {
    let mut test = Harness::start().await;
    let pagerduty = FakeOnCall::default();
    let notifier = firing_on_pagerduty(&mut test, &pagerduty).await;

    notifier.deliver_due(test.now).await.unwrap();

    let events = pagerduty.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["routing_key"], PAGERDUTY_KEY);
    assert_eq!(event["event_action"], "trigger");
    assert_eq!(
        event["payload"]["summary"],
        "CPU usage on web-1 is 95%, above 90%"
    );
    assert_eq!(event["payload"]["source"], "web-1");
    assert_eq!(event["payload"]["severity"], "critical");
    assert_eq!(event["client_url"], "https://monitor.example.com/alerts");
    assert!(
        event["dedup_key"]
            .as_str()
            .unwrap()
            .starts_with("maxnines-alert-")
    );
}

#[tokio::test]
async fn resolving_closes_the_same_pagerduty_incident() {
    let mut test = Harness::start().await;
    let pagerduty = FakeOnCall::default();
    let notifier = firing_on_pagerduty(&mut test, &pagerduty).await;
    notifier.deliver_due(test.now).await.unwrap();

    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    let events = pagerduty.events();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[1]["event_action"], "resolve");
    assert_eq!(events[1]["dedup_key"], events[0]["dedup_key"]);
    assert_eq!(events[1]["routing_key"], PAGERDUTY_KEY);
}

#[tokio::test]
async fn pagerduty_being_busy_is_tried_again_with_the_same_incident() {
    let mut test = Harness::start().await;
    let pagerduty = FakeOnCall::default();
    pagerduty.statuses.lock().unwrap().push(429);
    let notifier = firing_on_pagerduty(&mut test, &pagerduty).await;

    notifier.deliver_due(test.now).await.unwrap();
    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(problems[0].error, "PagerDuty returned status 429");

    notifier.deliver_due(test.now + 60_000).await.unwrap();

    let events = pagerduty.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["dedup_key"], events[1]["dedup_key"]);
}

#[tokio::test]
async fn a_pagerduty_key_never_appears_in_a_saved_error() {
    let mut test = Harness::start().await;
    let pagerduty = FakeOnCall::default();
    pagerduty.statuses.lock().unwrap().push(400);
    let notifier = firing_on_pagerduty(&mut test, &pagerduty).await;

    notifier.deliver_due(test.now).await.unwrap();

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert!(
        !problems[0].error.contains(PAGERDUTY_KEY),
        "{}",
        problems[0].error
    );
}

#[tokio::test]
async fn a_pagerduty_test_opens_an_incident_and_closes_it_again() {
    let pagerduty = FakeOnCall::default();
    let url = pagerduty.start().await;
    let channel = Channel {
        id: 1,
        channel: ChannelInput {
            name: "On call".to_string(),
            kind: ChannelKind::PagerDuty,
            target: PAGERDUTY_KEY.to_string(),
            credential: None,
            app_token: None,
            severities: crate::alerting::every_severity(),
        },
    };
    let senders = Senders {
        pagerduty_url: Some(url),
        ..Senders::default()
    };

    crate::notifier::send(channel, Notice::test(), None, senders)
        .await
        .unwrap();

    let events = pagerduty.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event_action"], "trigger");
    assert_eq!(events[0]["payload"]["severity"], "info");
    assert_eq!(events[1]["event_action"], "resolve");
    assert_eq!(events[0]["dedup_key"], events[1]["dedup_key"]);
}

#[tokio::test]
async fn a_pagerduty_key_is_set_but_never_shown_again() {
    let server = start().await;
    let body = json!({
        "name": "On call", "kind": "pagerduty", "target": PAGERDUTY_KEY,
    });
    let (status, made) = api(&server, "POST", "/api/v1/notification-channels", &body).await;
    assert_eq!(status, 201, "{made}");

    let (_, listed) = api(
        &server,
        "GET",
        "/api/v1/notification-channels",
        &Value::Null,
    )
    .await;
    assert!(!listed.to_string().contains(PAGERDUTY_KEY), "{listed}");
    assert_eq!(listed[0]["target_preview"], "Key ending 2345");

    let id = made["id"].as_i64().unwrap();
    let mut browser = Browser::default();
    let edit = browser
        .get(&server, &format!("/alerts/channels/{id}/edit"))
        .await;
    assert!(!edit.body.contains(PAGERDUTY_KEY), "{}", edit.body);
    let list = browser.get(&server, "/alerts/channels").await;
    assert!(!list.body.contains(PAGERDUTY_KEY), "{}", list.body);
    assert!(list.body.contains("PagerDuty"), "{}", list.body);
}

#[tokio::test]
async fn a_pagerduty_key_has_to_look_like_one() {
    let server = start().await;
    for target in ["too-short", "has spaces in it and is 32 long..", ""] {
        let body = json!({ "name": "x", "kind": "pagerduty", "target": target });
        let (status, answer) = api(&server, "POST", "/api/v1/notification-channels", &body).await;
        assert_eq!(status, 422, "{target}: {answer}");
        assert!(!answer.to_string().contains("too-short"), "{answer}");
    }
}

const TELEGRAM_TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

/// A stand-in for Telegram's bot API. It keeps the path and body of each call,
/// and answers with the next queued status and body, or else a sent message.
#[derive(Clone, Default)]
struct FakeTelegram {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    answers: Arc<Mutex<Vec<(u16, Value)>>>,
}

impl FakeTelegram {
    async fn start(&self) -> String {
        let fake = self.clone();
        // A photo comes as a form, which is kept as text.
        let router = Router::new().fallback(post(
            move |uri: axum::http::Uri, body: axum::body::Bytes| {
                let fake = fake.clone();
                async move {
                    let body = serde_json::from_slice(&body).unwrap_or_else(|_| {
                        Value::String(String::from_utf8_lossy(&body).into_owned())
                    });
                    let mut calls = fake.calls.lock().unwrap();
                    calls.push((uri.path().to_string(), body));
                    let mut answers = fake.answers.lock().unwrap();
                    let (status, answer) = if answers.is_empty() {
                        let id = 100 + calls.len();
                        (200, json!({ "ok": true, "result": { "message_id": id } }))
                    } else {
                        answers.remove(0)
                    };
                    (StatusCode::from_u16(status).unwrap(), axum::Json(answer))
                }
            },
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        format!("http://{address}")
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }
}

/// A firing alert with a Telegram channel, ready to deliver.
async fn firing_on_telegram(test: &mut Harness, telegram: &FakeTelegram) -> Notifier {
    let url = telegram.start().await;
    let channel = ChannelInput {
        name: "Telegram".to_string(),
        kind: ChannelKind::Telegram,
        target: "-1001234567890".to_string(),
        credential: Some(TELEGRAM_TOKEN.to_string()),
        app_token: None,
        severities: crate::alerting::every_severity(),
    };
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    Notifier::new(
        test.database().clone(),
        Senders {
            web_url: Some("https://monitor.example.com".to_string()),
            telegram_api_url: Some(url),
            ..Senders::default()
        },
    )
}

#[tokio::test]
async fn an_alert_posts_to_telegram_and_resolving_replies_to_it() {
    let mut test = Harness::start().await;
    let telegram = FakeTelegram::default();
    let notifier = firing_on_telegram(&mut test, &telegram).await;
    notifier.deliver_due(test.now).await.unwrap();
    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    let calls = telegram.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let (path, firing) = &calls[0];
    assert_eq!(path, &format!("/bot{TELEGRAM_TOKEN}/sendMessage"));
    assert_eq!(firing["chat_id"], "-1001234567890");
    assert_eq!(firing["parse_mode"], "HTML");
    let text = firing["text"].as_str().unwrap();
    assert!(
        text.starts_with("<b>CRITICAL</b> CPU usage on web-1 is 95%, above 90%"),
        "{text}"
    );
    assert!(firing.get("reply_parameters").is_none());

    let resolved = &calls[1].1;
    assert!(
        resolved["text"]
            .as_str()
            .unwrap()
            .starts_with("<b>RESOLVED</b>"),
        "{resolved}"
    );
    assert_eq!(resolved["reply_parameters"]["message_id"], 101);
    assert!(
        test.database()
            .delivery_problems(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_telegram_error_is_retried_and_never_shows_the_token() {
    let mut test = Harness::start().await;
    let telegram = FakeTelegram::default();
    telegram.answers.lock().unwrap().push((
        400,
        json!({ "ok": false, "error_code": 400, "description": "Bad Request: chat not found" }),
    ));
    let notifier = firing_on_telegram(&mut test, &telegram).await;

    notifier.deliver_due(test.now).await.unwrap();

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert!(
        problems[0]
            .error
            .starts_with("Telegram can't find that chat"),
        "{}",
        problems[0].error
    );
    assert_eq!(problems[0].state, "pending");
    let page = Browser::default().get(&test.server, "/alerts").await;
    assert!(page.body.contains("find that chat"), "{}", page.body);
    assert!(!page.body.contains("AAHdqTcv"), "{}", page.body);

    notifier.deliver_due(test.now + 30_000).await.unwrap();
    assert_eq!(telegram.calls().len(), 2);
    assert!(
        test.database()
            .delivery_problems(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn not_reaching_telegram_says_so_without_the_token() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let channel = Channel {
        id: 1,
        channel: ChannelInput {
            name: "Telegram".to_string(),
            kind: ChannelKind::Telegram,
            target: "-100123".to_string(),
            credential: Some(TELEGRAM_TOKEN.to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
        },
    };
    let senders = Senders {
        telegram_api_url: Some(format!("http://{address}")),
        ..Senders::default()
    };

    let error = crate::notifier::send(channel, Notice::test(), None, senders)
        .await
        .unwrap_err();

    assert_eq!(format!("{error:#}"), "couldn't connect to Telegram");
}

#[tokio::test]
async fn a_telegram_channel_can_be_made_from_the_form_and_keeps_its_token_hidden() {
    let server = start().await;
    let mut browser = Browser::default();
    let fields = [
        ("name", "Team"),
        ("kind", "telegram"),
        ("target", "-1001234567890"),
        ("credential", TELEGRAM_TOKEN),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];

    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let saved = server.state.database.list_channels().await.unwrap();
    assert_eq!(saved[0].channel.credential.as_deref(), Some(TELEGRAM_TOKEN));

    let page = browser.get(&server, "/alerts/channels").await;
    assert!(page.body.contains("-1001234567890"), "{}", page.body);
    assert!(!page.body.contains("AAHdqTcv"));

    let page = browser
        .get(&server, &format!("/alerts/channels/{}/edit", saved[0].id))
        .await;
    assert!(!page.body.contains("AAHdqTcv"), "{}", page.body);
    assert!(
        page.body.contains(r#"value="telegram" selected"#),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_telegram_channel_needs_its_token_on_the_form() {
    let server = start().await;
    let fields = [
        ("name", "Team"),
        ("kind", "telegram"),
        ("target", "-1001234567890"),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = Browser::default()
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(
        page.body.contains("bot token from BotFather"),
        "{}",
        page.body
    );
}

/// A firing alert with a Slack channel, ready to deliver.
async fn firing_on_slack(test: &mut Harness, slack: &FakeSlack) -> Notifier {
    firing_on_slack_app(test, slack, None).await
}

/// The same, for a Slack app the server listens to when it has an app-level token.
async fn firing_on_slack_app(
    test: &mut Harness,
    slack: &FakeSlack,
    app_token: Option<&str>,
) -> Notifier {
    let url = slack.start().await;
    let channel = ChannelInput {
        name: "Slack".to_string(),
        kind: ChannelKind::Slack,
        target: "#alerts".to_string(),
        credential: Some("xoxb-secret-token".to_string()),
        app_token: app_token.map(str::to_string),
        severities: crate::alerting::every_severity(),
    };
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    Notifier::new(
        test.database().clone(),
        Senders {
            web_url: Some("https://monitor.example.com".to_string()),
            slack_api_url: Some(url),
            ..Senders::default()
        },
    )
}

const SLACK_MEMBER: &str = "sam@example.com";

/// A firing alert on a Slack channel with buttons, already posted, and a MaxNines
/// account for whoever Slack says is pressing them.
async fn slack_buttons(test: &mut Harness, slack: &FakeSlack) -> (SlackActions, i64) {
    let notifier = firing_on_slack_app(test, slack, Some("xapp-secret-token")).await;
    notifier.deliver_due(test.now).await.unwrap();
    test.database()
        .create_user(SLACK_MEMBER, "Sam", test.now)
        .await
        .unwrap();
    *slack.user.lock().unwrap() = json!({ "id": "U1", "profile": { "email": "Sam@Example.com" } });
    let actions = SlackActions::new(
        test.database().clone(),
        Some("https://monitor.example.com".to_string()),
        "xoxb-secret-token",
    );
    (actions, test.open().await[0].id)
}

/// What Slack sends over Socket Mode when someone presses a button.
async fn press(slack: &FakeSlack, actions: &SlackActions, action: &str, alert_id: i64) {
    let event: SlackInteractionBlockActionsEvent = serde_json::from_value(json!({
        "team": { "id": "T1" },
        "user": { "id": "U1" },
        "api_app_id": "A1",
        "container": { "type": "message", "message_ts": "1700000000.000100", "channel_id": "C123" },
        "trigger_id": "1.2.3",
        "response_url": format!("{}/respond", slack.address.lock().unwrap()),
        "actions": [{ "type": "button", "action_id": action, "value": alert_id.to_string() }],
    }))
    .unwrap();
    actions.handle(&slack.client(), event).await;
}

/// The buttons a message still offers.
fn buttons(message: &Value) -> Vec<String> {
    message["attachments"][0]["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|block| block["type"] == "actions")
        .flat_map(|block| block["elements"].as_array().unwrap().clone())
        .map(|button| button["action_id"].as_str().unwrap().to_string())
        .collect()
}

/// What a message says has been done about it.
fn status(message: &Value) -> String {
    message["attachments"][0]["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|block| block["type"] == "context")
        .map(|block| block["elements"][0]["text"].as_str().unwrap().to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn slack_alerts_get_buttons_when_the_server_listens_to_the_app() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let notifier = firing_on_slack_app(&mut test, &slack, Some("xapp-1")).await;
    notifier.deliver_due(test.now).await.unwrap();

    let posted = &slack.calls()[0].2;
    assert_eq!(buttons(posted), [ACKNOWLEDGE_ACTION, SILENCE_HOUR_ACTION]);
    let alert_id = test.open().await[0].id.to_string();
    let first = &posted["attachments"][0]["blocks"][1]["elements"][0];
    assert_eq!(first["value"], alert_id);
    assert_eq!(first["style"], "primary");

    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();
    let update = &slack.calls()[1].2;
    assert!(buttons(update).is_empty(), "{update}");
}

#[tokio::test]
async fn a_slack_member_with_an_account_can_acknowledge() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;

    press(&slack, &actions, ACKNOWLEDGE_ACTION, alert_id).await;

    let alert = &test.open().await[0];
    assert_eq!(alert.acknowledged_by.as_deref(), Some(SLACK_MEMBER));
    let answer = slack.answer();
    assert_eq!(answer["replace_original"], true);
    assert_eq!(status(&answer), "Acknowledged by sam@example.com");
    assert_eq!(buttons(&answer), [SILENCE_HOUR_ACTION]);
    let (_, auth, _) = slack
        .calls()
        .into_iter()
        .find(|call| call.0 == "users.info")
        .unwrap();
    assert_eq!(auth, "Bearer xoxb-secret-token");
}

#[tokio::test]
async fn silencing_from_slack_covers_just_that_alert_for_an_hour() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;

    press(&slack, &actions, SILENCE_HOUR_ACTION, alert_id).await;
    press(&slack, &actions, SILENCE_HOUR_ACTION, alert_id).await;

    let silences = test.database().active_silences(now_ms()).await.unwrap();
    assert_eq!(silences.len(), 1, "{silences:?}");
    let silence = &silences[0];
    assert_eq!(silence.rule_id, test.open().await[0].rule_id);
    assert_eq!(
        silence.filter,
        format!("id={}", test.open().await[0].agent_id),
        "by ID, as another machine could share the name"
    );
    assert_eq!(silence.created_by, SLACK_MEMBER);
    assert_eq!(silence.reason, "Silenced from Slack");
    assert_eq!(silence.ends_ms - silence.starts_ms, 3_600_000);

    let answer = slack.answer();
    assert!(
        status(&answer).starts_with("Silenced by sam@example.com until "),
        "{answer}"
    );
    assert_eq!(buttons(&answer), [ACKNOWLEDGE_ACTION]);
}

#[tokio::test]
async fn someone_without_an_account_is_told_and_nothing_changes() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;
    *slack.user.lock().unwrap() =
        json!({ "id": "U1", "profile": { "email": "other@example.com" } });

    press(&slack, &actions, ACKNOWLEDGE_ACTION, alert_id).await;

    assert_eq!(test.open().await[0].acknowledged_by, None);
    let answer = slack.answer();
    assert_eq!(answer["replace_original"], false);
    let text = answer["text"].as_str().unwrap();
    assert!(
        text.contains("no MaxNines account for other@example.com"),
        "{text}"
    );
}

#[tokio::test]
async fn slack_guests_cannot_act() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;
    *slack.user.lock().unwrap() = json!({
        "id": "U1",
        "is_restricted": true,
        "profile": { "email": SLACK_MEMBER },
    });

    press(&slack, &actions, ACKNOWLEDGE_ACTION, alert_id).await;

    assert_eq!(test.open().await[0].acknowledged_by, None);
    let text = slack.answer()["text"].as_str().unwrap().to_string();
    assert!(text.contains("Only full members"), "{text}");
}

#[tokio::test]
async fn slack_is_asked_who_someone_is_only_once_in_a_while() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;

    press(&slack, &actions, SILENCE_HOUR_ACTION, alert_id).await;
    press(&slack, &actions, ACKNOWLEDGE_ACTION, alert_id).await;

    let lookups = slack
        .calls()
        .into_iter()
        .filter(|call| call.0 == "users.info")
        .count();
    assert_eq!(lookups, 1);
    assert_eq!(
        test.open().await[0].acknowledged_by.as_deref(),
        Some(SLACK_MEMBER)
    );
}

#[tokio::test]
async fn a_disabled_account_stops_working_at_once() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;
    press(&slack, &actions, SILENCE_HOUR_ACTION, alert_id).await;

    let user = test
        .database()
        .active_user_by_email(SLACK_MEMBER)
        .await
        .unwrap()
        .unwrap();
    test.database()
        .disable_user(user.id, now_ms())
        .await
        .unwrap();
    press(&slack, &actions, ACKNOWLEDGE_ACTION, alert_id).await;

    assert_eq!(test.open().await[0].acknowledged_by, None);
    assert_eq!(slack.answer()["replace_original"], false);
}

#[tokio::test]
async fn a_button_on_a_resolved_alert_shows_that_it_resolved() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let (actions, alert_id) = slack_buttons(&mut test, &slack).await;
    test.cpu(MINUTE_MS, 10.0).await;

    press(&slack, &actions, SILENCE_HOUR_ACTION, alert_id).await;

    let answer = slack.answer();
    assert!(buttons(&answer).is_empty(), "{answer}");
    let text = answer["attachments"][0]["blocks"][0]["text"]["text"]
        .as_str()
        .unwrap();
    assert!(text.starts_with("*RESOLVED*"), "{text}");
    assert!(
        test.database()
            .active_silences(now_ms())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_slack_test_says_when_the_app_level_token_is_wrong() {
    let slack = FakeSlack::default();
    let url = slack.start().await;
    *slack.connect_error.lock().unwrap() = Some("invalid_auth");
    let channel = Channel {
        id: 1,
        channel: ChannelInput {
            name: "Slack".to_string(),
            kind: ChannelKind::Slack,
            target: "#alerts".to_string(),
            credential: Some("xoxb-secret-token".to_string()),
            app_token: Some("xapp-secret-token".to_string()),
            severities: crate::alerting::every_severity(),
        },
    };
    let senders = Senders {
        slack_api_url: Some(url),
        ..Senders::default()
    };

    let error = crate::notifier::send(channel, Notice::test(), None, senders)
        .await
        .unwrap_err();

    assert_eq!(
        format!("{error:#}"),
        "the test message was sent, but the buttons won't work: Slack didn't accept the \
         app-level token (invalid_auth)"
    );
    let (_, auth, _) = slack
        .calls()
        .into_iter()
        .find(|call| call.0 == "connect")
        .unwrap();
    assert_eq!(auth, "Bearer xapp-secret-token");
}

#[tokio::test]
async fn an_app_level_token_can_be_set_on_the_form_and_stays_hidden() {
    let server = start().await;
    let mut browser = Browser::default();
    let page = browser.get(&server, "/alerts/channels/new").await;
    assert!(page.body.contains("Create the Slack app"), "{}", page.body);
    assert!(
        page.body.contains("new_app=1&amp;manifest_json="),
        "{}",
        page.body
    );
    for id in ["slack-manifest", "alertops-sample"] {
        assert!(
            page.body.contains(&format!(r#"<pre id="{id}">"#)),
            "{}",
            page.body
        );
        assert!(
            page.body.contains(&format!(r#"data-copy="{id}""#)),
            "{}",
            page.body
        );
    }

    let fields = [
        ("name", "Team"),
        ("kind", "slack"),
        ("target", "#alerts"),
        ("credential", "xoxb-secret"),
        ("app_token", "xapp-secret"),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let saved = server.state.database.list_channels().await.unwrap();
    assert_eq!(saved[0].channel.app_token.as_deref(), Some("xapp-secret"));

    let page = browser
        .get(&server, &format!("/alerts/channels/{}/edit", saved[0].id))
        .await;
    assert!(!page.body.contains("xapp-secret"), "{}", page.body);
    assert!(page.body.contains("remove_app_token"), "{}", page.body);

    let fields = [
        ("name", "Team"),
        ("kind", "slack"),
        ("target", "#alerts"),
        ("app_token", "not-a-token"),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser
        .submit(
            &server,
            &format!("/alerts/channels/{}/edit", saved[0].id),
            &format!("/alerts/channels/{}", saved[0].id),
            &fields,
        )
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("starts with xapp-"), "{}", page.body);
}

#[tokio::test]
async fn an_alert_posts_to_slack_with_the_bot_token() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let notifier = firing_on_slack(&mut test, &slack).await;

    notifier.deliver_due(test.now).await.unwrap();

    let calls = slack.calls();
    let (method, auth, body) = &calls[0];
    assert_eq!(method, "post");
    assert_eq!(auth, "Bearer xoxb-secret-token");
    assert_eq!(body["channel"], "#alerts");
    assert_eq!(body["text"], "CPU usage on web-1 is 95%, above 90%");
    assert_eq!(body["attachments"][0]["color"], "#b3261e");
    assert_eq!(body["unfurl_links"], false);
    assert_eq!(body["unfurl_media"], false);
    let text = body["attachments"][0]["blocks"][0]["text"]["text"]
        .as_str()
        .unwrap();
    assert!(body["attachments"][0]["blocks"][1].is_null(), "{body}");
    assert!(
        text.contains("<https://monitor.example.com/alerts|View alerts>"),
        "{text}"
    );
    assert!(
        test.database()
            .delivery_problems(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn resolving_updates_the_slack_message_and_replies_in_its_thread() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let notifier = firing_on_slack(&mut test, &slack).await;
    notifier.deliver_due(test.now).await.unwrap();

    test.cpu(MINUTE_MS, 10.0).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    assert_eq!(slack.methods(), ["post", "update", "post"]);
    let calls = slack.calls();
    let update = &calls[1].2;
    assert_eq!(update["channel"], "C123");
    assert_eq!(update["ts"], "1700000000.000100");
    assert_eq!(update["attachments"][0]["color"], "#0b6b4b");
    let reply = &calls[2].2;
    assert_eq!(reply["thread_ts"], "1700000000.000100");
    assert_eq!(reply["text"], "The problem cleared");
}

#[tokio::test]
async fn a_deleted_slack_message_gets_a_new_one_when_resolving() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    let notifier = firing_on_slack(&mut test, &slack).await;
    notifier.deliver_due(test.now).await.unwrap();

    test.cpu(MINUTE_MS, 10.0).await;
    slack.errors.lock().unwrap().push("message_not_found");
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    assert_eq!(slack.methods(), ["post", "update", "post"]);
    let calls = slack.calls();
    assert_eq!(calls[2].2["channel"], "#alerts");
    assert!(calls[2].2.get("thread_ts").is_none());
    assert!(
        test.database()
            .delivery_problems(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_slack_error_is_retried_and_says_what_slack_said() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    slack.errors.lock().unwrap().push("not_in_channel");
    let notifier = firing_on_slack(&mut test, &slack).await;

    notifier.deliver_due(test.now).await.unwrap();

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(
        problems[0].error,
        "the app isn't in that channel, so invite it (not_in_channel)"
    );
    assert_eq!(problems[0].state, "pending");

    notifier.deliver_due(test.now + 30_000).await.unwrap();
    assert_eq!(slack.methods(), ["post", "post"]);
    assert!(
        test.database()
            .delivery_problems(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn not_reaching_slack_says_so_without_any_detail() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let channel = crate::alerting::Channel {
        id: 1,
        channel: ChannelInput {
            name: "Slack".to_string(),
            kind: ChannelKind::Slack,
            target: "#alerts".to_string(),
            credential: Some("xoxb-secret-token".to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
        },
    };
    let senders = Senders {
        slack_api_url: Some(format!("http://{address}/api")),
        ..Senders::default()
    };

    let error = crate::notifier::send(channel, Notice::test(), None, senders)
        .await
        .unwrap_err();

    assert_eq!(format!("{error:#}"), "couldn't reach Slack");
}

#[tokio::test]
async fn a_slack_token_never_appears_in_a_saved_error() {
    let mut test = Harness::start().await;
    let slack = FakeSlack::default();
    slack.errors.lock().unwrap().push("invalid_auth");
    let notifier = firing_on_slack(&mut test, &slack).await;
    notifier.deliver_due(test.now).await.unwrap();

    let page = Browser::default().get(&test.server, "/alerts").await;
    assert!(page.body.contains("(invalid_auth)"), "{}", page.body);
    assert!(!page.body.contains("xoxb"), "{}", page.body);
}

#[tokio::test]
async fn a_slack_channel_can_be_made_from_the_form_and_hides_its_token() {
    let server = start().await;
    let mut browser = Browser::default();
    let fields = [
        ("name", "Team"),
        ("kind", "slack"),
        ("target", "#alerts"),
        ("credential", "xoxb-secret-token"),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let id = server.state.database.list_channels().await.unwrap()[0].id;
    let edit = format!("/alerts/channels/{id}/edit");
    for path in ["/alerts/channels", edit.as_str()] {
        let page = browser.get(&server, path).await;
        assert!(page.body.contains("#alerts"), "{path}");
        assert!(!page.body.contains("xoxb-secret"), "{path}: {}", page.body);
    }

    let (status, shown) = api(
        &server,
        "GET",
        &format!("/api/v1/notification-channels/{id}"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert!(!shown.to_string().contains("xoxb"), "{shown}");

    // Saving without retyping it keeps it.
    let fields = [
        ("name", "Renamed"),
        ("kind", "slack"),
        ("target", "#ops"),
        ("credential", ""),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser
        .submit(&server, &edit, &format!("/alerts/channels/{id}"), &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let channel = server
        .state
        .database
        .get_channel(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        channel.channel.credential.as_deref(),
        Some("xoxb-secret-token")
    );
    assert_eq!(channel.channel.target, "#ops");
}

#[tokio::test]
async fn a_plain_webhook_into_slack_gets_a_warning() {
    let server = start().await;
    server
        .state
        .database
        .create_channel(&webhook_channel("https://hooks.slack.com/services/x"))
        .await
        .unwrap();
    let page = Browser::default().get(&server, "/alerts/channels").await;
    assert!(page.body.contains("Slack is moving away"), "{}", page.body);
}

#[tokio::test]
async fn an_alert_with_no_channels_sends_nothing() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    test.cpu(MINUTE_MS, 10.0).await;
    assert!(due(&test, test.now + 2 * MINUTE_MS).await.is_empty());
}

#[tokio::test]
async fn a_failed_delivery_is_retried_later_and_shown_until_it_works() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    hook.statuses
        .lock()
        .unwrap()
        .push(StatusCode::INTERNAL_SERVER_ERROR);
    let url = format!("{}/secret-token", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;

    notifier.deliver_due(test.now).await.unwrap();
    assert_eq!(hook.events().len(), 1);

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(problems[0].error, "the webhook returned status 500");
    assert_eq!(problems[0].state, "pending");
    assert_eq!(problems[0].attempts, 1);

    assert!(due(&test, test.now + 29_999).await.is_empty(), "too soon");
    notifier.deliver_due(test.now + 30_000).await.unwrap();
    assert_eq!(hook.events().len(), 2);
    assert!(
        test.database()
            .delivery_problems(10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(due(&test, test.now + 10 * MINUTE_MS).await.is_empty());
}

#[tokio::test]
async fn a_resolved_notice_waits_for_its_firing_notice() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    hook.statuses
        .lock()
        .unwrap()
        .push(StatusCode::SERVICE_UNAVAILABLE);
    let url = format!("{}/secret-token", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;

    notifier.deliver_due(test.now).await.unwrap();
    test.cpu(1000, 10.0).await;

    notifier.deliver_due(test.now + 2000).await.unwrap();
    assert_eq!(hook.events(), ["firing"], "only the failed attempt so far");

    notifier.deliver_due(test.now + 31_000).await.unwrap();
    notifier.deliver_due(test.now + 31_001).await.unwrap();
    assert_eq!(hook.events(), ["firing", "firing", "resolved"]);
}

/// Hundreds of alerts on a channel that's down sit in the queue being retried.
/// They mustn't hide what's queued for channels that work.
#[tokio::test]
async fn a_channel_that_is_down_does_not_hold_up_the_others() {
    let test = Harness::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nowhere = format!("http://{}/hook", listener.local_addr().unwrap());
    drop(listener);
    let channel = |name: &str, target: String| ChannelInput {
        name: name.to_string(),
        kind: ChannelKind::Webhook,
        target,
        credential: None,
        app_token: None,
        severities: crate::alerting::every_severity(),
    };
    let dead = test
        .database()
        .create_channel(&channel("Dead", nowhere))
        .await
        .unwrap();
    let hook = FakeOnCall::default();
    let healthy = test
        .database()
        .create_channel(&channel("Healthy", hook.start().await))
        .await
        .unwrap();
    let rule = test
        .database()
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();
    // One alert per disk on the test's agent, as alerts belong to registered agents.
    let alert = |series: &str| NewAlert {
        rule_id: rule,
        rule_name: "Disk full".to_string(),
        severity: Severity::Critical,
        agent_id: test.id(),
        host: "web-1".to_string(),
        series: series.to_string(),
        value: Some(99.0),
        summary: format!("{series} on web-1 is 99% full"),
        started_ms: test.now,
    };
    for n in 0..600 {
        test.database()
            .fire_alert(&alert(&format!("/disk{n:03}")), &[dead])
            .await
            .unwrap();
    }
    test.database()
        .fire_alert(&alert("/lucky"), &[healthy])
        .await
        .unwrap();
    let notifier = Notifier::new(test.database().clone(), Senders::default());

    // Each pass takes a batch. The dead channel's rows fail at once and wait to be
    // retried, so the healthy channel's turn comes within a few dozen passes.
    for pass in 0..60 {
        notifier.deliver_due(test.now + pass).await.unwrap();
        if !hook.events().is_empty() {
            break;
        }
    }

    assert_eq!(hook.events().len(), 1, "the healthy channel was told");
    let problems = test.database().delivery_problems(1000).await.unwrap();
    assert_eq!(
        problems.len(),
        600,
        "every dead delivery is waiting to be retried"
    );
}

#[tokio::test]
async fn a_delivery_is_given_up_on_after_a_day_and_says_so() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    hook.statuses
        .lock()
        .unwrap()
        .extend([StatusCode::BAD_GATEWAY, StatusCode::BAD_GATEWAY]);
    let url = format!("{}/secret-token", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;

    notifier.deliver_due(test.now).await.unwrap();
    let day = 24 * 60 * MINUTE_MS;
    notifier.deliver_due(test.now + day).await.unwrap();

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(problems[0].state, "failed");
    assert!(due(&test, test.now + 2 * day).await.is_empty());

    let page = Browser::default().get(&test.server, "/alerts").await;
    assert!(page.body.contains("Gave up"), "{}", page.body);
    assert!(page.body.contains("the webhook returned status 502"));

    // The channel never heard the alert start, so it doesn't hear it end.
    test.cpu(2 * day, 10.0).await;
    notifier
        .deliver_due(test.now + 2 * day + 1000)
        .await
        .unwrap();
    assert_eq!(hook.events(), ["firing", "firing"]);
    assert!(due(&test, test.now + 2 * day + 2000).await.is_empty());
}

#[tokio::test]
async fn queued_notifications_survive_a_restart() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    let url = format!("{}/secret-token", hook.start().await);
    firing_with_channel(&mut test, &url).await;

    let restarted = Notifier::new(test.database().clone(), Senders::default());
    restarted.deliver_due(test.now).await.unwrap();
    assert_eq!(hook.events(), ["firing"]);
}

#[tokio::test]
async fn resolved_notices_go_to_whoever_heard_it_fired_even_if_the_rule_is_gone() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    let url = format!("{}/secret-token", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;
    notifier.deliver_due(test.now).await.unwrap();

    let rule = test.database().list_alert_rules().await.unwrap()[0].id;
    test.database()
        .delete_alert_rule(rule, test.now)
        .await
        .unwrap();
    test.evaluate(MINUTE_MS).await;
    notifier.deliver_due(test.now + MINUTE_MS).await.unwrap();

    assert_eq!(hook.events(), ["firing", "resolved"]);
}

#[tokio::test]
async fn resolving_an_alert_twice_only_tells_people_once() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    let url = format!("{}/secret-token", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;
    notifier.deliver_due(test.now).await.unwrap();

    let alert = test.open().await[0].id;
    let later = test.now + MINUTE_MS;
    test.database()
        .resolve_alert(alert, later, "first")
        .await
        .unwrap();
    test.database()
        .resolve_alert(alert, later + 1, "second")
        .await
        .unwrap();
    notifier.deliver_due(later + 2).await.unwrap();
    notifier.deliver_due(later + 3).await.unwrap();

    assert_eq!(hook.events(), ["firing", "resolved"]);
    assert_eq!(
        test.resolved().await[0].resolve_reason.as_deref(),
        Some("first")
    );
}

#[tokio::test]
async fn deleting_a_channel_drops_what_was_queued_for_it() {
    let mut test = Harness::start().await;
    let notifier = firing_with_channel(&mut test, "http://127.0.0.1:1/x").await;

    let channel = test.database().list_channels().await.unwrap()[0].id;
    assert!(test.database().delete_channel(channel).await.unwrap());

    notifier.deliver_due(test.now).await.unwrap();
    assert!(due(&test, test.now).await.is_empty());
    assert_eq!(test.open().await.len(), 1, "the alert itself stays");
}

#[tokio::test]
async fn a_webhook_url_never_appears_in_a_saved_error() {
    let mut test = Harness::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{address}/secret-token");
    let notifier = firing_with_channel(&mut test, &url).await;

    notifier.deliver_due(test.now).await.unwrap();

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(problems[0].error, "couldn't connect to the webhook");
    let page = Browser::default().get(&test.server, "/alerts").await;
    assert!(!page.body.contains("secret-token"));
}

#[tokio::test]
async fn webhook_redirects_are_not_followed() {
    let mut test = Harness::start().await;
    let hook = Hook::default();
    let url = format!("{}/moved", hook.start().await);
    let notifier = firing_with_channel(&mut test, &url).await;

    notifier.deliver_due(test.now).await.unwrap();

    assert!(hook.events().is_empty());
    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(problems[0].error, "the webhook returned status 307");
}

/// A mail server that accepts one message and hands back everything it heard.
async fn start_mail_server() -> (u16, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer.write_all(b"220 test ESMTP\r\n").await.unwrap();

        let mut heard = String::new();
        let mut in_data = false;
        while let Some(line) = lines.next_line().await.unwrap() {
            heard.push_str(&line);
            heard.push('\n');
            let reply: &[u8] = if in_data {
                if line != "." {
                    continue;
                }
                in_data = false;
                b"250 ok\r\n"
            } else if line.starts_with("DATA") {
                in_data = true;
                b"354 go\r\n"
            } else if line.starts_with("QUIT") {
                writer.write_all(b"221 bye\r\n").await.unwrap();
                break;
            } else {
                b"250 ok\r\n"
            };
            writer.write_all(reply).await.unwrap();
        }
        heard
    });
    (port, handle)
}

fn mailer(port: u16) -> Arc<Mailer> {
    let text = format!(
        "email {{\n  host = \"127.0.0.1\"\n  port = {port}\n  security = \"none\"\n  \
         from = \"MaxNines <alerts@example.com>\"\n}}\n\
         metrics \"duckdb\" {{\n  path = \"x\"\n}}\n"
    );
    let config = Config::parse(&text).unwrap();
    Arc::new(Mailer::new(config.email.as_ref().unwrap()).unwrap())
}

#[tokio::test]
async fn email_channels_send_a_message_to_every_address() {
    let mut test = Harness::start().await;
    let channel = ChannelInput {
        name: "On call".to_string(),
        kind: ChannelKind::Email,
        target: "a@example.com, b@example.com".to_string(),
        credential: None,
        app_token: None,
        severities: crate::alerting::every_severity(),
    };
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    let (port, heard) = start_mail_server().await;
    let notifier = Notifier::new(
        test.database().clone(),
        Senders {
            mailer: Some(mailer(port)),
            ..Senders::default()
        },
    );
    notifier.deliver_due(test.now).await.unwrap();

    let heard = heard.await.unwrap();
    assert!(heard.contains("MAIL FROM:<alerts@example.com>"), "{heard}");
    assert!(heard.contains("RCPT TO:<a@example.com>"), "{heard}");
    assert!(heard.contains("RCPT TO:<b@example.com>"), "{heard}");
    assert!(
        heard.contains("Subject: [MaxNines CRITICAL] CPU usage on web-1 is 95%, above 90%"),
        "{heard}"
    );
    assert!(heard.contains("Rule: High CPU"), "{heard}");
    assert!(due(&test, test.now + 10 * MINUTE_MS).await.is_empty());
}

#[tokio::test]
async fn an_email_channel_without_a_mail_server_says_so() {
    let mut test = Harness::start().await;
    let channel = ChannelInput {
        name: "On call".to_string(),
        kind: ChannelKind::Email,
        target: "a@example.com".to_string(),
        credential: None,
        app_token: None,
        severities: crate::alerting::every_severity(),
    };
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    Notifier::new(test.database().clone(), Senders::default())
        .deliver_due(test.now)
        .await
        .unwrap();

    let problems = test.database().delivery_problems(10).await.unwrap();
    assert_eq!(problems[0].error, "email isn't set up in the server config");
}

#[test]
fn an_unencrypted_mail_server_cannot_be_given_a_password() {
    let text = "email {\n  host = \"x\"\n  security = \"none\"\n  username = \"u\"\n  \
                password_file = \"p\"\n  from = \"a@example.com\"\n}\n\
                metrics \"duckdb\" {\n  path = \"x\"\n}\n";
    let error = format!("{:#}", Config::parse(text).unwrap_err());
    assert!(error.contains("unencrypted"), "{error}");
}

#[test]
fn a_username_needs_a_password_file() {
    let text = "email {\n  host = \"x\"\n  username = \"u\"\n  from = \"a@example.com\"\n}\n\
                metrics \"duckdb\" {\n  path = \"x\"\n}\n";
    let error = format!("{:#}", Config::parse(text).unwrap_err());
    assert!(error.contains("password_file"), "{error}");
}

// ---- pages

const ALERT_RULE_FIELDS: [(&str, &str); 9] = [
    ("name", "High CPU"),
    ("kind", "metric"),
    ("metric", "cpu.usage"),
    ("comparison", "above"),
    ("critical_threshold", "90"),
    ("series", ""),
    ("for_secs", "120"),
    ("severity", "critical"),
    ("enabled", "on"),
];

#[tokio::test]
async fn every_alert_page_renders() {
    let server = start().await;
    let rule = server
        .state
        .database
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();
    let channel = server
        .state
        .database
        .create_channel(&webhook_channel("https://example.com/x"))
        .await
        .unwrap();
    let mut browser = Browser::default();

    for path in [
        "/alerts".to_string(),
        "/alerts/rules".to_string(),
        "/alerts/rules/new".to_string(),
        format!("/alerts/rules/{rule}/edit"),
        "/alerts/channels".to_string(),
        "/alerts/channels/new".to_string(),
        format!("/alerts/channels/{channel}/edit"),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
        assert!(page.body.contains("MaxNines"), "{path}");
    }
}

#[tokio::test]
async fn missing_alert_things_are_not_found() {
    let server = start().await;
    let mut browser = Browser::default();
    for path in ["/alerts/rules/99/edit", "/alerts/channels/99/edit"] {
        assert_eq!(browser.get(&server, path).await.status, 404, "{path}");
    }
}

#[tokio::test]
async fn an_alert_rule_can_be_created_changed_and_deleted_from_the_form() {
    let server = start().await;
    let mut browser = Browser::default();

    let page = browser
        .submit(
            &server,
            "/alerts/rules/new",
            "/alerts/rules",
            &ALERT_RULE_FIELDS,
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let rules = server.state.database.list_alert_rules().await.unwrap();
    assert_eq!(rules[0].rule, cpu_rule());
    let id = rules[0].id;

    let list = browser.get(&server, "/alerts/rules").await;
    assert!(
        list.body.contains("CPU usage above 90% for 2 minutes"),
        "{}",
        list.body
    );
    assert!(list.body.contains("Every agent"));

    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields[4] = ("critical_threshold", "75.5");
    let path = format!("/alerts/rules/{id}");
    let edit = format!("/alerts/rules/{id}/edit");
    let page = browser.submit(&server, &edit, &path, &fields).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rule = server.state.database.get_alert_rule(id).await.unwrap();
    assert_eq!(rule.unwrap().rule.threshold, Some(75.5));

    let page = browser
        .submit(&server, &edit, &format!("/alerts/rules/{id}/delete"), &[])
        .await;
    assert_eq!(page.status, 303);
    assert!(
        server
            .state
            .database
            .list_alert_rules()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_rule_can_warn_first_and_go_critical_later_from_the_form() {
    let server = start().await;
    let mut browser = Browser::default();
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields.push(("warning_threshold", "80"));

    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rules = server.state.database.list_alert_rules().await.unwrap();
    assert_eq!(
        rules[0].rule.levels(),
        [(Severity::Warning, 80.0), (Severity::Critical, 90.0)]
    );

    let list = browser.get(&server, "/alerts/rules").await;
    assert!(
        list.body
            .contains("CPU usage above 80% (warning), 90% (critical) for 2 minutes"),
        "{}",
        list.body
    );
    assert!(list.body.contains(
        r#"<span class="badge warn">Warning</span> <span class="badge bad">Critical</span>"#
    ));

    let edit = format!("/alerts/rules/{}/edit", rules[0].id);
    let form = browser.get(&server, &edit).await;
    assert!(form.body.contains(r#"name="warning_threshold" value="80""#));
    assert!(
        form.body
            .contains(r#"name="critical_threshold" value="90""#)
    );
}

#[tokio::test]
async fn an_offline_rule_can_be_made_from_the_form() {
    let server = start().await;
    let mut browser = Browser::default();
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields[0] = ("name", "Gone");
    fields[1] = ("kind", "offline");
    fields[4] = ("critical_threshold", "");
    fields[6] = ("for_secs", "60");

    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rules = server.state.database.list_alert_rules().await.unwrap();
    assert_eq!(rules[0].rule, offline_rule());
}

#[tokio::test]
async fn a_rejected_rule_keeps_what_was_typed_and_says_why() {
    let server = start().await;
    let mut browser = Browser::default();
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields[0] = ("name", "Typed name");
    fields[4] = ("critical_threshold", "lots");

    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(
        page.body
            .contains("the critical threshold must be a number"),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"value="Typed name""#));
    assert!(page.body.contains(r#"value="lots""#));
    assert!(
        server
            .state
            .database
            .list_alert_rules()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn two_rules_cannot_share_a_name() {
    let server = start().await;
    server
        .state
        .database
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();

    let page = Browser::default()
        .submit(
            &server,
            "/alerts/rules/new",
            "/alerts/rules",
            &ALERT_RULE_FIELDS,
        )
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("already exists"), "{}", page.body);
}

#[tokio::test]
async fn the_condition_builder_works_on_alert_rules() {
    let server = start().await;
    let mut browser = Browser::default();
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields.extend([
        ("clause_fact_0", "custom.role"),
        ("clause_operator_0", "equals"),
        ("clause_value_0", "web"),
        ("clause_kind_0", "text"),
    ]);

    let mut pressed = fields.clone();
    pressed.push(("form_action", "add_clause"));
    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &pressed)
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("clause_fact_1"), "{}", page.body);
    assert!(
        server
            .state
            .database
            .list_alert_rules()
            .await
            .unwrap()
            .is_empty()
    );

    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rules = server.state.database.list_alert_rules().await.unwrap();
    assert_eq!(
        rules[0].rule.condition.as_deref(),
        Some(r#"facts.custom.role == "web""#)
    );
}

#[tokio::test]
async fn a_rule_can_choose_its_channels_from_the_form() {
    let server = start().await;
    let channel = server
        .state
        .database
        .create_channel(&webhook_channel("https://example.com/x"))
        .await
        .unwrap();
    let box_name = format!("channel_{channel}");
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields.push((box_name.as_str(), "on"));

    let mut browser = Browser::default();
    let form = browser.get(&server, "/alerts/rules/new").await;
    assert!(form.body.contains(&box_name), "{}", form.body);

    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rules = server.state.database.list_alert_rules().await.unwrap();
    assert_eq!(rules[0].rule.channels, [channel]);

    let edit = format!("/alerts/rules/{}/edit", rules[0].id);
    let page = browser.get(&server, &edit).await;
    assert!(
        page.body.contains(&format!(r#"name="{box_name}" checked"#)),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_rule_can_tell_every_channel_from_the_form() {
    let server = start().await;
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields.push(("all_channels", "on"));
    let mut browser = Browser::default();

    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rules = server.state.database.list_alert_rules().await.unwrap();
    assert!(rules[0].rule.all_channels);
    assert!(rules[0].rule.channels.is_empty());

    let page = browser.get(&server, "/alerts/rules").await;
    assert!(page.body.contains("Every channel"), "{}", page.body);
    let edit = format!("/alerts/rules/{}/edit", rules[0].id);
    let page = browser.get(&server, &edit).await;
    assert!(
        page.body.contains(r#"name="all_channels" checked"#),
        "{}",
        page.body
    );

    // Not both at once.
    let channel = server
        .state
        .database
        .create_channel(&webhook_channel("https://example.com/x"))
        .await
        .unwrap();
    let box_name = format!("channel_{channel}");
    fields.push((box_name.as_str(), "on"));
    let page = browser
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("not both"), "{}", page.body);

    let body = json!({
        "name": "Gone", "kind": "offline", "for_secs": 300, "severity": "critical",
        "all_channels": true,
    });
    let (status, created) = api(&server, "POST", "/api/v1/alert-rules", &body).await;
    assert_eq!(status, 201, "{created}");
    let path = format!("/api/v1/alert-rules/{}", created["id"]);
    let (_, rule) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(rule["all_channels"], true, "{rule}");
}

#[tokio::test]
async fn a_rule_cannot_use_a_channel_that_does_not_exist() {
    let server = start().await;
    let mut fields = ALERT_RULE_FIELDS.to_vec();
    fields.push(("channel_99", "on"));

    let page = Browser::default()
        .submit(&server, "/alerts/rules/new", "/alerts/rules", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(
        page.body.contains("no notification channel 99"),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn alert_forms_refuse_a_bad_csrf_token() {
    let server = start().await;
    let id = server
        .state
        .database
        .create_alert_rule(&cpu_rule())
        .await
        .unwrap();
    let channel = server
        .state
        .database
        .create_channel(&webhook_channel("https://example.com/x"))
        .await
        .unwrap();

    let mut browser = Browser::default();
    browser.get(&server, "/alerts/rules/new").await;
    for path in [
        "/alerts/rules".to_string(),
        format!("/alerts/rules/{id}"),
        format!("/alerts/rules/{id}/delete"),
        "/alerts/channels".to_string(),
        format!("/alerts/channels/{channel}"),
        format!("/alerts/channels/{channel}/delete"),
        format!("/alerts/channels/{channel}/test"),
    ] {
        let page = browser
            .post(&server, &path, &[("authenticity_token", "wrong")])
            .await;
        assert_eq!(page.status, 403, "{path}");
    }
    assert_eq!(
        server
            .state
            .database
            .list_alert_rules()
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server.state.database.list_channels().await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn a_channel_can_take_warnings_critical_alerts_or_both_from_the_form_and_the_api() {
    let server = start().await;
    let mut browser = Browser::default();
    let fields = [
        ("name", "Pager"),
        ("kind", "pagerduty"),
        ("target", PAGERDUTY_KEY),
        ("sends_critical", "on"),
    ];
    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let channel = &server.state.database.list_channels().await.unwrap()[0];
    assert_eq!(
        channel.channel.severities,
        std::collections::BTreeSet::from([Severity::Critical])
    );

    let list = browser.get(&server, "/alerts/channels").await;
    assert!(list.body.contains("Critical alerts only"), "{}", list.body);
    let edit = format!("/alerts/channels/{}/edit", channel.id);
    let form = browser.get(&server, &edit).await;
    assert!(
        form.body
            .contains(r#"<input type="checkbox" name="sends_warnings"> Warnings"#)
    );
    assert!(
        form.body
            .contains(r#"<input type="checkbox" name="sends_critical" checked> Critical alerts"#)
    );

    let (_, listed) = api(
        &server,
        "GET",
        "/api/v1/notification-channels",
        &Value::Null,
    )
    .await;
    assert_eq!(listed[0]["severities"], json!(["critical"]));

    let body =
        json!({ "name": "Chat", "kind": "webhook", "target": "https://hooks.example.com/a" });
    let (status, made) = api(&server, "POST", "/api/v1/notification-channels", &body).await;
    assert_eq!(status, 201, "{made}");
    let id = made["id"].as_i64().unwrap();
    let chat = server
        .state
        .database
        .get_channel(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chat.channel.severities, crate::alerting::every_severity());

    let body = json!({
        "name": "Mail", "kind": "webhook", "target": "https://hooks.example.com/b",
        "severities": ["warning"],
    });
    let (status, made) = api(&server, "POST", "/api/v1/notification-channels", &body).await;
    assert_eq!(status, 201, "{made}");
    let list = browser.get(&server, "/alerts/channels").await;
    assert!(list.body.contains("Warnings only"), "{}", list.body);

    let body = json!({
        "name": "Nothing", "kind": "webhook", "target": "https://hooks.example.com/c",
        "severities": [],
    });
    let (status, answer) = api(&server, "POST", "/api/v1/notification-channels", &body).await;
    assert_eq!(status, 422, "{answer}");
    let fields = [
        ("name", "Odd"),
        ("kind", "webhook"),
        ("target", "https://hooks.example.com/d"),
    ];
    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(
        page.body
            .contains("choose warnings, critical alerts or both")
    );
}

#[tokio::test]
async fn a_saved_webhook_url_is_never_shown_again() {
    let server = start().await;
    let mut browser = Browser::default();
    let url = "https://hooks.example.com/services/secret-token";

    let fields = [
        ("name", "Ops"),
        ("kind", "webhook"),
        ("target", url),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let id = server.state.database.list_channels().await.unwrap()[0].id;

    let edit = format!("/alerts/channels/{id}/edit");
    for path in ["/alerts/channels", edit.as_str(), "/alerts/rules/new"] {
        let page = browser.get(&server, path).await;
        assert!(!page.body.contains("secret-token"), "{path}");
    }
    let page = browser.get(&server, "/alerts/channels").await;
    assert!(
        page.body.contains("https://hooks.example.com/…"),
        "{}",
        page.body
    );

    // A failed save shows the form again, and mustn't bring it back either.
    let path = format!("/alerts/channels/{id}");
    let fields = [
        ("name", ""),
        ("kind", "webhook"),
        ("target", ""),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser.submit(&server, &edit, &path, &fields).await;
    assert_eq!(page.status, 422);
    assert!(!page.body.contains("secret-token"));

    // Saving without touching the box keeps it.
    let fields = [
        ("name", "Renamed"),
        ("kind", "webhook"),
        ("target", ""),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = browser.submit(&server, &edit, &path, &fields).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let channel = server
        .state
        .database
        .get_channel(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.channel.name, "Renamed");
    assert_eq!(channel.channel.target, url);

    let page = browser
        .submit(&server, &edit, &format!("{path}/delete"), &[])
        .await;
    assert_eq!(page.status, 303);
    assert!(
        server
            .state
            .database
            .list_channels()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_bad_channel_is_refused_without_repeating_the_url() {
    let server = start().await;
    let fields = [
        ("name", "Ops"),
        ("kind", "webhook"),
        ("target", "ftp://example.com/nope"),
        ("sends_warnings", "on"),
        ("sends_critical", "on"),
    ];
    let page = Browser::default()
        .submit(&server, "/alerts/channels/new", "/alerts/channels", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("must start with http"), "{}", page.body);
}

#[tokio::test]
async fn the_test_button_says_how_it_went() {
    let server = start().await;
    let hook = Hook::default();
    let url = format!("{}/secret-token", hook.start().await);
    let id = server
        .state
        .database
        .create_channel(&webhook_channel(&url))
        .await
        .unwrap();
    let path = format!("/alerts/channels/{id}/test");
    let mut browser = Browser::default();

    let page = browser
        .submit(&server, "/alerts/channels", &path, &[])
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("A test notification was sent to Ops."),
        "{}",
        page.body
    );
    assert_eq!(hook.events(), ["test"]);

    hook.statuses.lock().unwrap().push(StatusCode::FORBIDDEN);
    let page = browser
        .submit(&server, "/alerts/channels", &path, &[])
        .await;
    assert!(
        page.body.contains("the webhook returned status 403"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("secret-token"));
}

#[tokio::test]
async fn the_alerts_page_shows_what_is_firing_and_what_ended() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    let mut browser = Browser::default();

    let page = browser.get(&test.server, "/alerts").await;
    assert!(page.body.contains("Nothing is firing."), "{}", page.body);

    test.cpu(0, 95.0).await;
    let page = browser.get(&test.server, "/alerts").await;
    assert!(!page.body.contains("Nothing is firing."));
    assert!(page.body.contains("CPU usage on web-1 is 95%, above 90%"));
    assert!(page.body.contains("Critical"));

    test.cpu(MINUTE_MS, 10.0).await;
    let page = browser.get(&test.server, "/alerts").await;
    assert!(page.body.contains("Nothing is firing."));
    assert!(page.body.contains("The problem cleared"), "{}", page.body);
}

#[tokio::test]
async fn names_from_agents_are_escaped_on_the_alerts_page() {
    let server = start_with("").await;
    let agent = identity();
    let host = "<script>alert(1)</script>";
    let _client = server.connect_approved(&agent, host).await;
    let rule_id = server
        .state
        .database
        .create_alert_rule(&AlertRuleInput {
            for_secs: 0,
            ..offline_rule()
        })
        .await
        .unwrap();
    server
        .state
        .database
        .fire_alert(
            &crate::alerting::NewAlert {
                rule_id,
                rule_name: "<b>rule</b>".to_string(),
                severity: Severity::Warning,
                agent_id: agent.id(),
                host: host.to_string(),
                series: "<i>series</i>".to_string(),
                value: None,
                summary: format!("{host} is offline"),
                started_ms: 1000,
            },
            &[],
        )
        .await
        .unwrap();

    let page = Browser::default().get(&server, "/alerts").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("<b>rule"), "{}", page.body);
    assert!(page.body.contains("&lt;script&gt;"), "{}", page.body);
}

#[tokio::test]
async fn alert_pages_keep_the_strict_security_policy() {
    let server = start().await;
    let mut browser = Browser::default();
    for path in ["/alerts", "/alerts/rules/new", "/alerts/channels/new"] {
        let page = browser.get(&server, path).await;
        let policy = page.header("content-security-policy").unwrap();
        assert!(policy.starts_with("default-src 'none'"), "{path}");
        assert!(page.has_only_our_scripts(), "{path}");
        assert!(!page.body.contains(" style="), "{path}");
    }
}

// ---- the API

async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let body = body.to_string();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        server.api_key,
        body.len()
    );
    let page = Browser::default().send(server, request).await;
    let body = page.body.lines().find(|line| line.starts_with(['{', '[']));
    (
        page.status,
        body.map_or(Value::Null, |text| serde_json::from_str(text).unwrap()),
    )
}

#[tokio::test]
async fn deleting_an_agent_takes_everything_about_it_once_it_is_revoked() {
    let mut test = Harness::start().await;
    let id = test.id();
    let other = identity();
    let _other_client = test.server.connect_approved(&other, "db-1").await;

    // An alert with a notification waiting to go, facts, and a place on the map.
    let channel = webhook_channel("http://127.0.0.1:9/hook");
    let channel = test.database().create_channel(&channel).await.unwrap();
    let rule = AlertRuleInput {
        for_secs: 0,
        channels: vec![channel],
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;
    assert_eq!(test.open().await.len(), 1);
    let database = test.database().clone();
    let deliveries = || async { database.due_deliveries(i64::MAX, 10).await.unwrap() };
    assert_eq!(deliveries().await.len(), 1);
    let client = test.client.as_mut().unwrap();
    let facts = AgentMessage::Facts {
        facts: json!({ "agent": { "version": "1.0.0" } }),
    };
    send(client, &facts).await;
    test.server.wait_for_facts(&id, 1).await;
    for filter in [crate::host_filter::only(&id), String::new()] {
        let place = crate::locations::LocationRuleInput {
            name: "Leeds".to_string(),
            filter,
            place: String::new(),
            latitude: 53.8,
            longitude: -1.5,
            priority: 0,
        };
        test.database().create_location_rule(&place).await.unwrap();
    }
    let mut browser = Browser::default();
    let page = format!("/agents/{id}");
    let api_path = format!("/api/v1/agents/{id}");

    // Only once it's revoked.
    let response = browser
        .submit(&test.server, &page, &format!("{page}/delete"), &[])
        .await;
    assert_eq!(response.status, 409);
    let (status, body) = api(&test.server, "DELETE", &api_path, &Value::Null).await;
    assert_eq!(status, 409);
    assert_eq!(body["error"], "Revoke the agent before deleting it");
    assert!(
        !browser
            .get(&test.server, &page)
            .await
            .body
            .contains("/delete\"")
    );

    let response = browser
        .submit(&test.server, &page, &format!("{page}/revoke"), &[])
        .await;
    assert_eq!(response.status, 303);
    assert!(
        browser
            .get(&test.server, &page)
            .await
            .body
            .contains(&format!("{page}/delete"))
    );
    let response = browser
        .submit(&test.server, &page, &format!("{page}/delete"), &[])
        .await;
    assert_eq!(response.status, 303);
    assert!(
        response.headers.contains("location: /agents\r\n"),
        "{}",
        response.headers
    );

    assert!(test.server.state.registry.get(&id).await.is_none());
    assert!(test.server.state.presence.get(&id).is_none());
    assert!(database.current_facts(&id).await.unwrap().is_empty());
    assert!(database.config_status(&id).await.unwrap().is_none());
    assert!(test.open().await.is_empty());
    assert!(test.resolved().await.is_empty());
    assert!(deliveries().await.is_empty());
    let places = database.list_location_rules().await.unwrap();
    assert_eq!(places.len(), 1, "the one for every machine stays");
    assert_eq!(
        *test.server.saved.deleted.lock().unwrap(),
        std::slice::from_ref(&id)
    );
    assert_eq!(browser.get(&test.server, &page).await.status, 404);
    assert_eq!(
        api(&test.server, "GET", &api_path, &Value::Null).await.0,
        404
    );
    assert_eq!(
        api(&test.server, "DELETE", &api_path, &Value::Null).await.0,
        404
    );
    assert!(test.server.state.registry.get(&other.id()).await.is_some());

    // If the machine still runs it, it's new, and waits to be approved.
    let mut again = test.server.connect().await;
    let status = handshake(&mut again, &test.agent, "web-1", None).await;
    assert_eq!(status, RegistrationStatus::Pending);
}

#[tokio::test]
async fn the_servers_own_agents_can_not_be_deleted() {
    let server = start().await;
    for id in [
        crate::remote_checks::LOCAL_AGENT_ID,
        crate::remote_checks::FLEET_AGENT_ID,
    ] {
        let path = format!("/api/v1/agents/{id}");
        assert_eq!(
            api(&server, "DELETE", &path, &Value::Null).await.0,
            404,
            "{id}"
        );
    }
}

#[tokio::test]
async fn the_alert_api_needs_an_api_key() {
    let server = start().await;
    for path in [
        "/api/v1/alerts",
        "/api/v1/alert-rules",
        "/api/v1/alert-rules/1",
        "/api/v1/notification-channels",
        "/api/v1/notification-channels/1",
    ] {
        let response = server.http("GET", path, None).await;
        assert!(response.starts_with("HTTP/1.1 401"), "{path}: {response}");
    }
}

#[tokio::test]
async fn alert_rules_can_be_managed_through_the_api() {
    let server = start().await;
    let rule = json!({
        "name": "High CPU",
        "kind": "metric",
        "metric": "cpu.usage",
        "comparison": "above",
        "threshold": 90,
        "for_secs": 120,
        "severity": "critical",
    });

    let (status, created) = api(&server, "POST", "/api/v1/alert-rules", &rule).await;
    assert_eq!(status, 201, "{created}");
    let path = format!("/api/v1/alert-rules/{}", created["id"]);

    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(shown["name"], "High CPU");
    assert_eq!(shown["enabled"], true);

    let mut changed = rule.clone();
    changed["threshold"] = json!(50);
    assert_eq!(api(&server, "PUT", &path, &changed).await.0, 204);
    let (_, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(shown["threshold"], 50.0);

    let (status, list) = api(&server, "GET", "/api/v1/alert-rules", &Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);

    assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 204);
    assert_eq!(api(&server, "GET", &path, &Value::Null).await.0, 404);
    assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 404);
    assert_eq!(api(&server, "PUT", &path, &rule).await.0, 404);
}

#[tokio::test]
async fn the_api_refuses_bad_rules_and_says_why() {
    let server = start().await;
    let rule = json!({
        "name": "Bad",
        "kind": "metric",
        "metric": "nonsense",
        "comparison": "above",
        "threshold": 1,
        "for_secs": 0,
        "severity": "warning",
    });
    let (status, body) = api(&server, "POST", "/api/v1/alert-rules", &rule).await;
    assert_eq!(status, 422);
    assert!(
        body["error"].as_str().unwrap().contains("unknown metric"),
        "{body}"
    );

    let mut rule = rule;
    rule["metric"] = json!("cpu.usage");
    rule["channels"] = json!([42]);
    let (status, body) = api(&server, "POST", "/api/v1/alert-rules", &rule).await;
    assert_eq!(status, 422);
    assert!(
        body["error"].as_str().unwrap().contains("channel 42"),
        "{body}"
    );
}

#[tokio::test]
async fn the_api_takes_a_webhook_url_but_never_gives_it_back() {
    let server = start().await;
    let channel = json!({
        "name": "Ops",
        "kind": "webhook",
        "target": "https://hooks.example.com/secret-token",
    });

    let (status, created) = api(&server, "POST", "/api/v1/notification-channels", &channel).await;
    assert_eq!(status, 201, "{created}");
    let path = format!("/api/v1/notification-channels/{}", created["id"]);

    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(shown["target_preview"], "https://hooks.example.com/…");
    assert!(!shown.to_string().contains("secret-token"));

    let (_, list) = api(
        &server,
        "GET",
        "/api/v1/notification-channels",
        &Value::Null,
    )
    .await;
    assert!(!list.to_string().contains("secret-token"));

    let mut changed = channel.clone();
    changed["name"] = json!("Renamed");
    assert_eq!(api(&server, "PUT", &path, &changed).await.0, 204);
    assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 204);
    assert_eq!(api(&server, "GET", &path, &Value::Null).await.0, 404);
}

#[tokio::test]
async fn the_api_lists_open_and_resolved_alerts() {
    let mut test = Harness::start().await;
    let rule = AlertRuleInput {
        for_secs: 0,
        ..cpu_rule()
    };
    test.database().create_alert_rule(&rule).await.unwrap();
    test.cpu(0, 95.0).await;

    let (status, alerts) = api(&test.server, "GET", "/api/v1/alerts", &Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(alerts["open"][0]["rule_name"], "High CPU");
    assert_eq!(alerts["resolved"].as_array().unwrap().len(), 0);

    test.cpu(MINUTE_MS, 10.0).await;
    let (_, alerts) = api(&test.server, "GET", "/api/v1/alerts", &Value::Null).await;
    assert_eq!(alerts["open"].as_array().unwrap().len(), 0);
    assert_eq!(
        alerts["resolved"][0]["resolve_reason"],
        "The problem cleared"
    );
}

#[tokio::test]
async fn the_api_lists_notifications_that_have_not_arrived() {
    let mut test = Harness::start().await;
    let hook = FakeOnCall::default();
    hook.statuses.lock().unwrap().push(500);
    let url = hook.start().await;
    let notifier = firing_on(&mut test, ChannelKind::Webhook, &url, Senders::default()).await;
    let path = "/api/v1/alerts/delivery-problems";

    let (status, problems) = api(&test.server, "GET", path, &Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(problems, json!([]));

    notifier.deliver_due(test.now).await.unwrap();
    let (_, problems) = api(&test.server, "GET", path, &Value::Null).await;
    assert_eq!(problems[0]["channel"], "On call");
    assert_eq!(problems[0]["event"], "firing");
    assert_eq!(problems[0]["state"], "pending");
    assert_eq!(problems[0]["attempts"], 1);
    assert_eq!(problems[0]["error"], "the webhook returned status 500");

    notifier.deliver_due(test.now + 30_000).await.unwrap();
    let (_, problems) = api(&test.server, "GET", path, &Value::Null).await;
    assert_eq!(problems, json!([]), "sent, so no longer a problem");
}

#[test]
fn events_read_back_as_written() {
    assert_eq!(Event::parse(Event::Firing.as_str()).unwrap(), Event::Firing);
    assert_eq!(
        Event::parse(Event::Resolved.as_str()).unwrap(),
        Event::Resolved
    );
    assert!(Event::parse("test").is_err(), "tests are never queued");
}

// ---- checks the server runs itself

mod remote {
    use super::*;
    use crate::remote_checks::{LOCAL_AGENT_ID, RemoteCheckInput, Scheduler};
    use maxnines_protocol::{Check, CheckKind};

    /// A server that knows about its built-in agent, as a real one does.
    async fn server() -> TestServer {
        let server = start_with_metrics().await;
        let local = server.state.database.load_agents().await.unwrap();
        let local = local.into_iter().find(|a| a.id == LOCAL_AGENT_ID).unwrap();
        server.state.registry.insert_for_test(local).await;
        server
    }

    fn scheduler(server: &TestServer) -> Scheduler {
        Scheduler::new(
            server.state.database.clone(),
            server.state.writer.clone(),
            server.state.check_results.clone(),
        )
    }

    fn tcp_input(name: &str, target: &str) -> RemoteCheckInput {
        RemoteCheckInput {
            check: Check::new(name, CheckKind::Tcp, target),
            interval_secs: 60,
            enabled: true,
        }
    }

    async fn run_due(scheduler: &mut Scheduler, now: i64) -> usize {
        let started = scheduler.start_due(now).await.unwrap();
        let count = started.len();
        for task in started {
            task.await.unwrap();
        }
        count
    }

    fn open_port() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        (listener, target)
    }

    #[tokio::test]
    async fn a_check_runs_when_due_and_waits_for_its_interval() {
        let server = server().await;
        let (_listener, target) = open_port();
        let input = tcp_input("db", &target);
        server
            .state
            .database
            .create_remote_check(&input)
            .await
            .unwrap();
        let mut scheduler = scheduler(&server);

        let now = now_ms();
        assert_eq!(run_due(&mut scheduler, now).await, 1);
        assert_eq!(run_due(&mut scheduler, now + 59_000).await, 0);
        assert_eq!(run_due(&mut scheduler, now + 60_000).await, 1);
        assert_eq!(server.state.check_results.all()["db"]["up"], 1);
    }

    #[tokio::test]
    async fn a_disabled_check_does_not_run() {
        let server = server().await;
        let (_listener, target) = open_port();
        let input = RemoteCheckInput {
            enabled: false,
            ..tcp_input("db", &target)
        };
        server
            .state
            .database
            .create_remote_check(&input)
            .await
            .unwrap();

        assert_eq!(run_due(&mut scheduler(&server), now_ms()).await, 0);
    }

    #[tokio::test]
    async fn a_deleted_checks_result_is_forgotten() {
        let server = server().await;
        let (_listener, target) = open_port();
        let input = tcp_input("db", &target);
        let id = server
            .state
            .database
            .create_remote_check(&input)
            .await
            .unwrap();
        let mut scheduler = scheduler(&server);
        run_due(&mut scheduler, now_ms()).await;

        server.state.database.delete_remote_check(id).await.unwrap();
        run_due(&mut scheduler, now_ms()).await;
        assert!(server.state.check_results.all().is_empty());
    }

    #[tokio::test]
    async fn a_failing_server_check_can_alert_like_anything_else() {
        let server = server().await;
        let (listener, target) = open_port();
        drop(listener);
        let input = tcp_input("db", &target);
        server
            .state
            .database
            .create_remote_check(&input)
            .await
            .unwrap();
        let rule = AlertRuleInput {
            name: "Check failing".to_string(),
            metric: Some("check.up".to_string()),
            comparison: Some(Comparison::Below),
            threshold: Some(1.0),
            for_secs: 0,
            ..cpu_rule()
        };
        server
            .state
            .database
            .create_alert_rule(&rule)
            .await
            .unwrap();

        run_due(&mut scheduler(&server), now_ms()).await;

        let metric = crate::metrics::find("check.up").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while server
            .state
            .metrics
            .newest(metric, now_ms())
            .await
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < deadline, "the result was never saved");
            sleep(Duration::from_millis(10)).await;
        }

        let mut evaluator = evaluator(&server, now_ms() - 60 * MINUTE_MS);
        evaluator.evaluate(now_ms()).await.unwrap();
        let open = server.state.database.open_alerts().await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].agent_id, LOCAL_AGENT_ID);
        assert_eq!(
            open[0].summary,
            "Checks passing (db) on MaxNines server is 0, below 1"
        );
    }

    #[tokio::test]
    async fn the_built_in_agent_never_counts_as_offline() {
        let server = server().await;
        server
            .state
            .database
            .create_alert_rule(&offline_rule())
            .await
            .unwrap();

        let mut evaluator = evaluator(&server, now_ms() - 60 * MINUTE_MS);
        evaluator.evaluate(now_ms()).await.unwrap();
        assert!(
            server
                .state
                .database
                .open_alerts()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_built_in_agent_stays_out_of_lists_and_cannot_be_changed() {
        let server = server().await;
        let mut browser = Browser::default();

        for path in ["/agents", "/metrics"] {
            let page = browser.get(&server, path).await;
            assert!(!page.body.contains("MaxNines server"), "{path}");
        }
        let page = browser.get(&server, "/agents/server").await;
        assert_eq!(page.status, 404);
        let page = browser.get(&server, "/agents/server/metrics").await;
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(!page.body.contains("Agent details"));

        let response = server
            .http("GET", "/api/v1/agents", Some(&server.api_key))
            .await;
        assert!(!response.contains("MaxNines server"));

        let revoked = server
            .state
            .registry
            .decide(LOCAL_AGENT_ID, AgentState::Revoked)
            .await;
        assert_eq!(revoked.unwrap(), None);
        assert!(server.state.registry.is_approved(LOCAL_AGENT_ID).await);
    }

    const FIELDS: [(&str, &str); 6] = [
        ("name", "Site"),
        ("kind", "http"),
        ("target", "https://example.com/"),
        ("interval_secs", "120"),
        ("regex", "Welcome back"),
        ("enabled", "on"),
    ];

    #[tokio::test]
    async fn a_check_can_be_managed_from_its_form() {
        let server = server().await;
        let mut browser = Browser::default();

        let page = browser
            .submit(&server, "/checks/new", "/checks", &FIELDS)
            .await;
        assert_eq!(page.status, 303, "{}", page.body);
        let saved = server.state.database.list_remote_checks().await.unwrap();
        assert_eq!(saved[0].input.check.regex.as_deref(), Some("Welcome back"));
        assert_eq!(saved[0].input.interval_secs, 120);
        let id = saved[0].id;

        let page = browser.get(&server, "/checks").await;
        assert!(page.body.contains("Site"));
        assert!(page.body.contains("Waiting"), "{}", page.body);

        let edit = format!("/checks/{id}/edit");
        let page = browser.get(&server, &edit).await;
        assert!(
            page.body.contains(r#"value="Welcome back""#),
            "{}",
            page.body
        );

        let mut fields = FIELDS.to_vec();
        fields[3] = ("interval_secs", "300");
        let page = browser
            .submit(&server, &edit, &format!("/checks/{id}"), &fields)
            .await;
        assert_eq!(page.status, 303, "{}", page.body);
        let saved = server.state.database.get_remote_check(id).await.unwrap();
        assert_eq!(saved.unwrap().input.interval_secs, 300);

        let delete = format!("/checks/{id}/delete");
        let page = browser.submit(&server, &edit, &delete, &[]).await;
        assert_eq!(page.status, 303);
        assert!(
            server
                .state
                .database
                .list_remote_checks()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_bad_check_keeps_what_was_typed_and_says_why() {
        let server = server().await;
        let mut fields = FIELDS.to_vec();
        fields[2] = ("target", "example.com");

        let page = Browser::default()
            .submit(&server, "/checks/new", "/checks", &fields)
            .await;
        assert_eq!(page.status, 422);
        assert!(page.body.contains("starting with http"), "{}", page.body);
        assert!(page.body.contains(r#"value="Site""#));
    }

    #[tokio::test]
    async fn two_checks_cannot_share_a_name() {
        let server = server().await;
        let mut browser = Browser::default();
        browser
            .submit(&server, "/checks/new", "/checks", &FIELDS)
            .await;
        let page = browser
            .submit(&server, "/checks/new", "/checks", &FIELDS)
            .await;
        assert_eq!(page.status, 422);
        assert!(page.body.contains("already exists"), "{}", page.body);
    }

    #[tokio::test]
    async fn check_forms_refuse_a_bad_csrf_token() {
        let server = server().await;
        let input = tcp_input("db", "example.com:80");
        let id = server
            .state
            .database
            .create_remote_check(&input)
            .await
            .unwrap();
        let mut browser = Browser::default();
        browser.get(&server, "/checks/new").await;

        for path in [
            "/checks".to_string(),
            format!("/checks/{id}"),
            format!("/checks/{id}/delete"),
        ] {
            let page = browser
                .post(&server, &path, &[("authenticity_token", "wrong")])
                .await;
            assert_eq!(page.status, 403, "{path}");
        }
        assert_eq!(
            server
                .state
                .database
                .list_remote_checks()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn results_show_on_the_checks_page_and_agent_page() {
        let server = server().await;
        let (listener, target) = open_port();
        drop(listener);
        let input = tcp_input("<b>db</b>", &target);
        server
            .state
            .database
            .create_remote_check(&input)
            .await
            .unwrap();
        run_due(&mut scheduler(&server), now_ms()).await;

        let mut browser = Browser::default();
        for path in ["/checks", "/agents/server/metrics"] {
            let page = browser.get(&server, path).await;
            assert_eq!(page.status, 200, "{path}");
            assert!(page.body.contains("Down"), "{path}: {}", page.body);
            assert!(page.body.contains("connect"), "{path}");
            assert!(!page.body.contains("<b>db"), "{path}");
        }
    }

    #[tokio::test]
    async fn the_api_manages_checks_and_needs_the_token() {
        let server = server().await;
        let response = server.http("GET", "/api/v1/remote-checks", None).await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");

        let body = json!({
            "check": { "name": "db", "kind": "tcp", "target": "example.com:80" },
            "interval_secs": 60,
        });
        let (status, created) = api(&server, "POST", "/api/v1/remote-checks", &body).await;
        assert_eq!(status, 201, "{created}");
        let path = format!("/api/v1/remote-checks/{}", created["id"]);

        let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(shown["check"]["target"], "example.com:80");
        assert_eq!(shown["enabled"], true);

        let mut changed = body.clone();
        changed["interval_secs"] = json!(120);
        assert_eq!(api(&server, "PUT", &path, &changed).await.0, 204);

        changed["interval_secs"] = json!(1);
        let (status, refused) = api(&server, "PUT", &path, &changed).await;
        assert_eq!(status, 422);
        assert!(
            refused["error"].as_str().unwrap().contains("interval"),
            "{refused}"
        );

        assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 204);
        assert_eq!(api(&server, "GET", &path, &Value::Null).await.0, 404);
    }

    #[tokio::test]
    async fn check_pages_keep_the_strict_security_policy() {
        let server = server().await;
        let mut browser = Browser::default();
        for path in ["/checks", "/checks/new"] {
            let page = browser.get(&server, path).await;
            let policy = page.header("content-security-policy").unwrap();
            assert!(policy.starts_with("default-src 'none'"), "{path}");
            assert!(page.has_only_our_scripts(), "{path}");
            assert!(!page.body.contains(" style="), "{path}");
        }
    }
}

// ---- the redesigned pages

mod silences {
    use super::*;
    use crate::silences::SilenceInput;

    const HOUR_SECS: u64 = 3600;
    const HOUR_MS: i64 = 3_600_000;

    fn silence(filter: &str) -> SilenceInput {
        SilenceInput {
            rule_id: None,
            filter: filter.to_string(),
            reason: "Upgrading".to_string(),
            duration_secs: HOUR_SECS,
        }
    }

    /// Delivers notifications at `offset_ms`, and says how many have arrived in all.
    async fn deliver(
        test: &Harness,
        notifier: &Notifier,
        hook: &FakeOnCall,
        offset_ms: i64,
    ) -> usize {
        notifier.deliver_due(test.now + offset_ms).await.unwrap();
        hook.events().len()
    }

    async fn on_a_webhook(test: &mut Harness, hook: &FakeOnCall) -> Notifier {
        let url = hook.start().await;
        firing_on(test, ChannelKind::Webhook, &url, Senders::default()).await
    }

    #[tokio::test]
    async fn a_silenced_alert_still_fires_but_nobody_is_told() {
        let mut test = Harness::start().await;
        test.database()
            .create_silence(&silence(""), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;

        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);
        assert_eq!(test.open().await.len(), 1);
    }

    /// Deleting a rule takes its silences with it. Its alerts have to end in the
    /// same step, or the notifications the silence was holding back would go out
    /// in the moments before the evaluator closed them.
    #[tokio::test]
    async fn deleting_a_silenced_rule_tells_nobody() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;
        let rule = test.open().await[0].rule_id.unwrap();
        let silence = SilenceInput {
            rule_id: Some(rule),
            ..silence("")
        };
        test.database()
            .create_silence(&silence, "sam", test.now)
            .await
            .unwrap();
        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);

        test.database()
            .delete_alert_rule(rule, test.now + 2000)
            .await
            .unwrap();

        assert_eq!(deliver(&test, &notifier, &hook, 3000).await, 0);
        assert!(test.open().await.is_empty());
        assert_eq!(
            test.resolved().await[0].resolve_reason.as_deref(),
            Some("The rule was deleted or disabled")
        );
    }

    /// The evaluator can end an alert between the notifier reading the queue and
    /// holding a notification from it. Holding it anyway would send it as a new
    /// alert when the silence ended, with nothing ever closing it.
    #[tokio::test]
    async fn a_hold_decided_before_the_alert_ended_does_not_happen() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;
        let due = test.database().due_deliveries(test.now, 16).await.unwrap();
        assert_eq!(due.len(), 1);

        test.cpu(MINUTE_MS, 10.0).await;
        test.database().hold_delivery(&due[0]).await.unwrap();

        assert!(test.database().held_deliveries().await.unwrap().is_empty());
        assert_eq!(deliver(&test, &notifier, &hook, MINUTE_MS + 1000).await, 0);
        assert_eq!(
            deliver(&test, &notifier, &hook, HOUR_MS + MINUTE_MS).await,
            0
        );
    }

    #[tokio::test]
    async fn notifications_go_out_when_the_silence_ends_if_it_is_still_firing() {
        let mut test = Harness::start().await;
        test.database()
            .create_silence(&silence(""), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;
        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);

        assert_eq!(deliver(&test, &notifier, &hook, HOUR_MS + 1000).await, 1);
        assert_eq!(deliver(&test, &notifier, &hook, HOUR_MS + 2000).await, 1);
    }

    #[tokio::test]
    async fn ending_a_silence_early_lets_notifications_go() {
        let mut test = Harness::start().await;
        let id = test
            .database()
            .create_silence(&silence(""), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;
        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);

        let ended = test.database().end_silence(id, test.now + 2000).await;
        assert!(ended.unwrap());

        assert_eq!(deliver(&test, &notifier, &hook, 3000).await, 1);
    }

    #[tokio::test]
    async fn an_alert_that_ends_during_a_silence_is_never_mentioned() {
        let mut test = Harness::start().await;
        test.database()
            .create_silence(&silence(""), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;
        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);

        let open = test.open().await;
        let resolved = test
            .database()
            .resolve_alert(open[0].id, test.now + 2000, "Fixed");
        resolved.await.unwrap();

        assert_eq!(deliver(&test, &notifier, &hook, 3000).await, 0);
        assert_eq!(deliver(&test, &notifier, &hook, HOUR_MS + 1000).await, 0);
    }

    #[tokio::test]
    async fn an_alert_that_starts_and_ends_between_passes_is_never_mentioned() {
        let mut test = Harness::start().await;
        test.database()
            .create_silence(&silence(""), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;

        let open = test.open().await;
        let resolved = test
            .database()
            .resolve_alert(open[0].id, test.now + 500, "Fixed");
        resolved.await.unwrap();

        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);
        assert_eq!(deliver(&test, &notifier, &hook, 2000).await, 0);
        assert_eq!(deliver(&test, &notifier, &hook, HOUR_MS + 1000).await, 0);
    }

    #[tokio::test]
    async fn whoever_was_told_it_started_hears_it_ended_even_during_a_silence() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;
        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 1);

        test.database()
            .create_silence(&silence(""), "sam", test.now + 2000)
            .await
            .unwrap();
        let open = test.open().await;
        let resolved = test
            .database()
            .resolve_alert(open[0].id, test.now + 3000, "Fixed");
        resolved.await.unwrap();

        assert_eq!(deliver(&test, &notifier, &hook, 4000).await, 2);
    }

    #[tokio::test]
    async fn a_silence_only_covers_the_hosts_in_its_filter() {
        let mut test = Harness::start().await;
        test.database()
            .create_silence(&silence("hostname=db*"), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;

        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 1);
    }

    #[tokio::test]
    async fn a_silence_can_follow_a_fact() {
        let mut test = Harness::start().await;
        let facts = BTreeMap::from([("os.family".to_string(), json!("linux"))]);
        test.database()
            .record_facts(&test.id(), &facts, test.now as u64)
            .await
            .unwrap();
        test.database()
            .create_silence(&silence("os=linux"), "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;

        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 0);
    }

    #[tokio::test]
    async fn a_silence_for_one_rule_leaves_the_others_alone() {
        let mut test = Harness::start().await;
        let other = AlertRuleInput {
            name: "Something else".to_string(),
            ..cpu_rule()
        };
        let other = test.database().create_alert_rule(&other).await.unwrap();
        let input = SilenceInput {
            rule_id: Some(other),
            ..silence("")
        };
        test.database()
            .create_silence(&input, "sam", test.now)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let notifier = on_a_webhook(&mut test, &hook).await;

        assert_eq!(deliver(&test, &notifier, &hook, 1000).await, 1);
    }

    #[tokio::test]
    async fn deleting_a_rule_ends_its_silences_rather_than_widening_them() {
        let test = Harness::start().await;
        let rule = test.database().create_alert_rule(&cpu_rule()).await;
        let rule = rule.unwrap();
        let input = SilenceInput {
            rule_id: Some(rule),
            ..silence("")
        };
        let id = test
            .database()
            .create_silence(&input, "sam", test.now)
            .await;
        let id = id.unwrap();

        test.database()
            .delete_alert_rule(rule, test.now)
            .await
            .unwrap();

        assert_eq!(test.database().get_silence(id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_alerts_page_offers_a_silence_for_the_alert_and_shows_one_running() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        on_a_webhook(&mut test, &hook).await;

        let rule = test.database().list_alert_rules().await.unwrap()[0].id;
        let page = Browser::default().get(&test.server, "/alerts").await;
        assert!(
            page.body
                .contains(&format!("/alerts/silences/new?rule_id={rule}")),
            "{}",
            page.body
        );

        test.database()
            .create_silence(&silence(""), "sam", now_ms())
            .await
            .unwrap();
        let page = Browser::default().get(&test.server, "/alerts").await;
        assert!(page.body.contains("silenced until"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_form_starts_from_the_alert_and_saves_who_asked() {
        let test = Harness::start().await;
        let rule = test
            .database()
            .create_alert_rule(&cpu_rule())
            .await
            .unwrap();
        let mut browser = Browser::default();
        let form = format!("/alerts/silences/new?rule_id={rule}&filter=hostname%3Dweb-1");
        let form = form.as_str();

        let page = browser.get(&test.server, form).await;
        assert!(
            page.body.contains("value=\"hostname=web-1\""),
            "{}",
            page.body
        );
        let chosen = format!("value=\"{rule}\" selected");
        assert!(page.body.contains(&chosen), "{}", page.body);

        let rule_id = rule.to_string();
        let fields = [
            ("reason", "Upgrading"),
            ("rule_id", rule_id.as_str()),
            ("filter", "hostname=web-1"),
            ("duration_secs", "3600"),
        ];
        let page = browser
            .submit(&test.server, form, "/alerts/silences", &fields)
            .await;
        assert_eq!(page.status, 303, "{}", page.body);

        let silences = test.database().active_silences(now_ms()).await.unwrap();
        assert_eq!(silences.len(), 1);
        assert_eq!(silences[0].rule_id, Some(rule));
        assert!(!silences[0].created_by.is_empty());

        let page = browser.get(&test.server, "/alerts/silences").await;
        assert!(page.body.contains("Upgrading"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_form_explains_what_is_wrong_and_keeps_what_was_typed() {
        let test = Harness::start().await;
        let mut browser = Browser::default();
        let form = "/alerts/silences/new";
        let fields = [
            ("reason", "  "),
            ("rule_id", ""),
            ("filter", "hostname=db*"),
            ("duration_secs", "3600"),
        ];

        let page = browser
            .submit(&test.server, form, "/alerts/silences", &fields)
            .await;

        assert_eq!(page.status, 422);
        assert!(page.body.contains("needs a reason"), "{}", page.body);
        assert!(page.body.contains("hostname=db*"), "{}", page.body);
    }

    #[tokio::test]
    async fn a_silence_can_be_ended_from_its_page() {
        let test = Harness::start().await;
        let id = test
            .database()
            .create_silence(&silence(""), "sam", now_ms())
            .await;
        let id = id.unwrap();
        let mut browser = Browser::default();
        let path = format!("/alerts/silences/{id}/end");

        let page = browser
            .submit(&test.server, "/alerts/silences", &path, &[])
            .await;

        assert_eq!(page.status, 303, "{}", page.body);
        let active = test.database().active_silences(now_ms() + 1).await.unwrap();
        assert!(active.is_empty());
    }

    #[tokio::test]
    async fn the_api_starts_lists_and_ends_silences() {
        let test = Harness::start().await;
        let server = &test.server;

        let body =
            json!({ "filter": "hostname=web*", "reason": "Upgrading", "duration_secs": 3600 });
        let (status, created) = api(server, "POST", "/api/v1/silences", &body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_i64().unwrap();

        let (status, listed) = api(server, "GET", "/api/v1/silences", &Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(listed["active"][0]["id"], id);
        assert_eq!(listed["active"][0]["created_by"], "api");

        let path = format!("/api/v1/silences/{id}");
        let (status, shown) = api(server, "GET", &path, &Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(shown["reason"], "Upgrading");

        let (status, _) = api(server, "POST", &format!("{path}/end"), &Value::Null).await;
        assert_eq!(status, 204);
        let (status, _) = api(server, "POST", &format!("{path}/end"), &Value::Null).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn the_api_refuses_a_silence_for_a_rule_that_does_not_exist() {
        let test = Harness::start().await;
        let body = json!({ "rule_id": 99, "reason": "Upgrading", "duration_secs": 3600 });

        let (status, refused) = api(&test.server, "POST", "/api/v1/silences", &body).await;

        assert_eq!(status, 422);
        assert!(
            refused["error"]
                .as_str()
                .unwrap()
                .contains("no alert rule 99")
        );
    }

    #[tokio::test]
    async fn the_api_says_which_silence_covers_an_alert() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        on_a_webhook(&mut test, &hook).await;
        let id = test
            .database()
            .create_silence(&silence(""), "sam", now_ms())
            .await;
        let id = id.unwrap();

        let (_, alerts) = api(&test.server, "GET", "/api/v1/alerts", &Value::Null).await;

        assert_eq!(alerts["open"][0]["silenced_by"], id);
        assert_eq!(alerts["open"][0]["rule_name"], "High CPU");
    }
}

mod maintenance_windows {
    use super::*;
    use crate::maintenance::MaintenanceWindowInput;

    /// Every day from midnight UTC, so `test.now` falls inside it unless a test runs
    /// right at the end of the day.
    fn all_day() -> MaintenanceWindowInput {
        MaintenanceWindowInput {
            name: "Patching".to_string(),
            rule_id: None,
            filter: String::new(),
            days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
                .map(String::from)
                .to_vec(),
            start_time: "00:00".to_string(),
            duration_minutes: 24 * 60,
            time_zone: "UTC".to_string(),
        }
    }

    #[tokio::test]
    async fn a_window_keeps_notifications_back_until_it_is_gone() {
        let mut test = Harness::start().await;
        let window = test.database().create_maintenance_window(&all_day()).await;
        let window = window.unwrap();
        let hook = FakeOnCall::default();
        let url = hook.start().await;
        let notifier = firing_on(&mut test, ChannelKind::Webhook, &url, Senders::default()).await;

        notifier.deliver_due(test.now).await.unwrap();
        assert!(hook.events().is_empty());
        assert_eq!(test.open().await.len(), 1);

        test.database()
            .delete_maintenance_window(window)
            .await
            .unwrap();
        notifier.deliver_due(test.now + 1000).await.unwrap();
        notifier.deliver_due(test.now + 2000).await.unwrap();
        assert_eq!(hook.events().len(), 1);
    }

    #[tokio::test]
    async fn a_window_only_covers_its_hosts() {
        let mut test = Harness::start().await;
        let input = MaintenanceWindowInput {
            filter: "hostname=db*".to_string(),
            ..all_day()
        };
        test.database()
            .create_maintenance_window(&input)
            .await
            .unwrap();
        let hook = FakeOnCall::default();
        let url = hook.start().await;
        let notifier = firing_on(&mut test, ChannelKind::Webhook, &url, Senders::default()).await;

        notifier.deliver_due(test.now).await.unwrap();

        assert_eq!(hook.events().len(), 1);
    }

    #[tokio::test]
    async fn deleting_a_rule_deletes_its_windows() {
        let test = Harness::start().await;
        let rule = test
            .database()
            .create_alert_rule(&cpu_rule())
            .await
            .unwrap();
        let input = MaintenanceWindowInput {
            rule_id: Some(rule),
            ..all_day()
        };
        let id = test
            .database()
            .create_maintenance_window(&input)
            .await
            .unwrap();

        test.database()
            .delete_alert_rule(rule, test.now)
            .await
            .unwrap();

        let found = test.database().get_maintenance_window(id).await.unwrap();
        assert_eq!(found, None);
    }

    #[tokio::test]
    async fn the_api_manages_windows_and_says_which_covers_an_alert() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let url = hook.start().await;
        firing_on(&mut test, ChannelKind::Webhook, &url, Senders::default()).await;
        let server = &test.server;

        let mut body = serde_json::to_value(all_day()).unwrap();
        let (status, created) = api(server, "POST", "/api/v1/maintenance-windows", &body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_i64().unwrap();
        let path = format!("/api/v1/maintenance-windows/{id}");

        let (_, alerts) = api(server, "GET", "/api/v1/alerts", &Value::Null).await;
        assert_eq!(alerts["open"][0]["maintenance_window"], id);
        assert_eq!(alerts["open"][0]["silenced_by"], Value::Null);

        body["name"] = json!("Renamed");
        let (status, _) = api(server, "PUT", &path, &body).await;
        assert_eq!(status, 204);
        let (status, shown) = api(server, "GET", &path, &Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(shown["name"], "Renamed");
        let (_, listed) = api(server, "GET", "/api/v1/maintenance-windows", &Value::Null).await;
        assert_eq!(listed[0]["id"], id);

        body["time_zone"] = json!("Mars/Olympus");
        let (status, _) = api(server, "PUT", &path, &body).await;
        assert_eq!(status, 422);

        let (status, _) = api(server, "DELETE", &path, &Value::Null).await;
        assert_eq!(status, 204);
        let (status, _) = api(server, "GET", &path, &Value::Null).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn windows_are_added_changed_and_deleted_on_the_pages() {
        let test = Harness::start().await;
        let mut browser = Browser::default();
        let fields = [
            ("name", "Weekly patching"),
            ("rule_id", ""),
            ("filter", "env=staging"),
            ("day_sun", "on"),
            ("day_sat", "on"),
            ("start_time", "02:00"),
            ("duration_minutes", "120"),
            ("time_zone", "Europe/London"),
        ];

        let form = "/alerts/maintenance/new";
        let page = browser
            .submit(&test.server, form, "/alerts/maintenance", &fields)
            .await;
        assert_eq!(page.status, 303, "{}", page.body);

        let windows = test.database().list_maintenance_windows().await.unwrap();
        assert_eq!(windows[0].window.days, ["sat", "sun"]);
        let id = windows[0].id;

        let page = browser.get(&test.server, "/alerts/silences").await;
        assert!(page.body.contains("Weekly patching"), "{}", page.body);
        assert!(
            page.body.contains("Saturday, Sunday at 02:00"),
            "{}",
            page.body
        );

        let edit = format!("/alerts/maintenance/{id}/edit");
        let page = browser.get(&test.server, &edit).await;
        assert!(
            page.body.contains("value=\"Europe/London\""),
            "{}",
            page.body
        );
        assert!(
            page.body.contains("name=\"day_sun\" checked"),
            "{}",
            page.body
        );

        let changed = [
            ("name", "Monthly"),
            ("day_mon", "on"),
            ("start_time", "03:00"),
            ("duration_minutes", "60"),
            ("time_zone", "UTC"),
        ];
        let path = format!("/alerts/maintenance/{id}");
        let page = browser.submit(&test.server, &edit, &path, &changed).await;
        assert_eq!(page.status, 303, "{}", page.body);
        let found = test
            .database()
            .get_maintenance_window(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.window.name, "Monthly");

        let path = format!("/alerts/maintenance/{id}/delete");
        let page = browser.submit(&test.server, &edit, &path, &[]).await;
        assert_eq!(page.status, 303, "{}", page.body);
        assert!(
            test.database()
                .list_maintenance_windows()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_form_explains_what_is_wrong_and_keeps_what_was_typed() {
        let test = Harness::start().await;
        let mut browser = Browser::default();
        let fields = [
            ("name", "Weekly patching"),
            ("start_time", "02:00"),
            ("duration_minutes", "120"),
            ("time_zone", "UTC"),
        ];
        let form = "/alerts/maintenance/new";

        let page = browser
            .submit(&test.server, form, "/alerts/maintenance", &fields)
            .await;

        assert_eq!(page.status, 422);
        assert!(page.body.contains("at least one day"), "{}", page.body);
        assert!(page.body.contains("Weekly patching"), "{}", page.body);
    }
}

mod reminders {
    use super::*;
    use crate::silences::SilenceInput;

    const HOUR_MS: i64 = 3_600_000;

    /// A firing alert that's been delivered to a channel, on a rule with hourly reminders.
    async fn firing(
        test: &mut Harness,
        hook: &FakeOnCall,
        kind: ChannelKind,
        target: &str,
    ) -> Notifier {
        let url = hook.start().await;
        let target = if target.is_empty() {
            url.as_str()
        } else {
            target
        };
        let channel = ChannelInput {
            name: "Ops".to_string(),
            kind,
            target: target.to_string(),
            credential: None,
            app_token: None,
            severities: crate::alerting::every_severity(),
        };
        let channel = test.database().create_channel(&channel).await.unwrap();
        let rule = AlertRuleInput {
            for_secs: 0,
            channels: vec![channel],
            remind_every_secs: Some(3600),
            ..cpu_rule()
        };
        test.database().create_alert_rule(&rule).await.unwrap();
        test.cpu(0, 95.0).await;
        let senders = Senders {
            pagerduty_url: Some(url),
            ..Senders::default()
        };
        let notifier = Notifier::new(test.database().clone(), senders);
        notifier.deliver_due(test.now).await.unwrap();
        notifier
    }

    async fn at(test: &Harness, notifier: &Notifier, offset_ms: i64) {
        notifier.deliver_due(test.now + offset_ms).await.unwrap();
    }

    #[tokio::test]
    async fn a_reminder_goes_out_each_time_the_wait_passes() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        assert_eq!(hook.events().len(), 1);

        at(&test, &notifier, HOUR_MS - 1000).await;
        assert_eq!(hook.events().len(), 1, "it's too soon");

        at(&test, &notifier, HOUR_MS).await;
        let events = hook.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["event"], "reminder");
        assert!(
            events[1]["text"]
                .as_str()
                .unwrap()
                .starts_with("Still firing: ")
        );

        at(&test, &notifier, HOUR_MS + 1000).await;
        assert_eq!(hook.events().len(), 2, "the wait starts again");

        at(&test, &notifier, 2 * HOUR_MS).await;
        assert_eq!(hook.events().len(), 3);
    }

    #[tokio::test]
    async fn no_reminders_without_the_setting_on_the_rule() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let url = hook.start().await;
        let notifier = firing_on(&mut test, ChannelKind::Webhook, &url, Senders::default()).await;
        notifier.deliver_due(test.now).await.unwrap();

        at(&test, &notifier, 100 * HOUR_MS).await;

        assert_eq!(hook.events().len(), 1);
    }

    #[tokio::test]
    async fn acknowledging_stops_reminders_and_undoing_it_starts_them_again() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        let id = test.open().await[0].id;

        assert!(
            test.database()
                .acknowledge_alert(id, "sam", test.now)
                .await
                .unwrap()
        );
        at(&test, &notifier, 2 * HOUR_MS).await;
        assert_eq!(hook.events().len(), 1);

        assert!(test.database().unacknowledge_alert(id).await.unwrap());
        at(&test, &notifier, 3 * HOUR_MS).await;
        assert_eq!(hook.events().len(), 2);
    }

    #[tokio::test]
    async fn the_first_to_acknowledge_stays_on_it() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        let id = test.open().await[0].id;

        test.database()
            .acknowledge_alert(id, "sam", test.now)
            .await
            .unwrap();
        test.database()
            .acknowledge_alert(id, "alex", test.now)
            .await
            .unwrap();

        let open = test.open().await;
        assert_eq!(open[0].acknowledged_by.as_deref(), Some("sam"));
        assert_eq!(open[0].acknowledged_ms, Some(test.now));
    }

    #[tokio::test]
    async fn an_alert_that_has_ended_can_not_be_acknowledged() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        let id = test.open().await[0].id;
        test.database()
            .resolve_alert(id, test.now, "Fixed")
            .await
            .unwrap();

        assert!(
            !test
                .database()
                .acknowledge_alert(id, "sam", test.now)
                .await
                .unwrap()
        );
        assert!(!test.database().unacknowledge_alert(id).await.unwrap());
    }

    #[tokio::test]
    async fn on_call_services_are_left_to_repeat_for_themselves() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = firing(&mut test, &hook, ChannelKind::PagerDuty, PAGERDUTY_KEY).await;
        assert_eq!(hook.events().len(), 1);

        at(&test, &notifier, 5 * HOUR_MS).await;

        assert_eq!(hook.events().len(), 1);
    }

    #[tokio::test]
    async fn a_silence_stops_reminders() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        let input = SilenceInput {
            rule_id: None,
            filter: String::new(),
            reason: "Upgrading".to_string(),
            duration_secs: 3 * 3600,
        };
        test.database()
            .create_silence(&input, "sam", test.now)
            .await
            .unwrap();

        at(&test, &notifier, 2 * HOUR_MS).await;
        assert_eq!(hook.events().len(), 1);

        at(&test, &notifier, 3 * HOUR_MS).await;
        assert_eq!(
            hook.events().len(),
            2,
            "it's still firing once the silence is over"
        );
    }

    #[tokio::test]
    async fn a_reminder_still_waiting_when_the_alert_ends_is_dropped() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        let notifier = firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        hook.statuses.lock().unwrap().push(500);
        at(&test, &notifier, HOUR_MS).await;
        assert_eq!(
            hook.events().len(),
            2,
            "the reminder failed and waits to retry"
        );

        let id = test.open().await[0].id;
        test.database()
            .resolve_alert(id, test.now + HOUR_MS, "Fixed")
            .await
            .unwrap();
        at(&test, &notifier, 2 * HOUR_MS).await;
        at(&test, &notifier, 2 * HOUR_MS + 1000).await;

        let events = hook.events();
        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(events[2]["event"], "resolved");
    }

    #[tokio::test]
    async fn someone_can_acknowledge_from_the_alerts_page() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        let id = test.open().await[0].id;
        let mut browser = Browser::default();

        let path = format!("/alerts/{id}/acknowledge");
        let page = browser.submit(&test.server, "/alerts", &path, &[]).await;
        assert_eq!(page.status, 303, "{}", page.body);

        let page = browser.get(&test.server, "/alerts").await;
        assert!(page.body.contains("acknowledged by"), "{}", page.body);
        assert!(page.body.contains("Undo"), "{}", page.body);

        let path = format!("/alerts/{id}/unacknowledge");
        browser.submit(&test.server, "/alerts", &path, &[]).await;
        assert_eq!(test.open().await[0].acknowledged_by, None);
    }

    #[tokio::test]
    async fn the_api_acknowledges_as_the_api() {
        let mut test = Harness::start().await;
        let hook = FakeOnCall::default();
        firing(&mut test, &hook, ChannelKind::Webhook, "").await;
        let id = test.open().await[0].id;
        let path = format!("/api/v1/alerts/{id}");

        let (status, _) = api(
            &test.server,
            "POST",
            &format!("{path}/acknowledge"),
            &Value::Null,
        )
        .await;
        assert_eq!(status, 204);
        let (_, alerts) = api(&test.server, "GET", "/api/v1/alerts", &Value::Null).await;
        assert_eq!(alerts["open"][0]["acknowledged_by"], "api");

        let (status, _) = api(
            &test.server,
            "POST",
            &format!("{path}/unacknowledge"),
            &Value::Null,
        )
        .await;
        assert_eq!(status, 204);
        let (status, _) = api(
            &test.server,
            "POST",
            "/api/v1/alerts/99/acknowledge",
            &Value::Null,
        )
        .await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn the_rule_form_sets_reminders_in_minutes() {
        let test = Harness::start().await;
        let mut browser = Browser::default();
        let fields = [
            ("name", "Busy"),
            ("kind", "metric"),
            ("metric", "cpu.usage"),
            ("comparison", "above"),
            ("critical_threshold", "90"),
            ("for_secs", "60"),
            ("severity", "warning"),
            ("enabled", "on"),
            ("remind_every_minutes", "30"),
        ];
        let form = "/alerts/rules/new";

        let page = browser
            .submit(&test.server, form, "/alerts/rules", &fields)
            .await;
        assert_eq!(page.status, 303, "{}", page.body);

        let rules = test.database().list_alert_rules().await.unwrap();
        assert_eq!(rules[0].rule.remind_every_secs, Some(1800));
        let edit = format!("/alerts/rules/{}/edit", rules[0].id);
        let page = browser.get(&test.server, &edit).await;
        assert!(
            page.body
                .contains("name=\"remind_every_minutes\" value=\"30\""),
            "{}",
            page.body
        );
    }

    #[tokio::test]
    async fn the_rule_form_refuses_reminders_that_are_too_often() {
        let test = Harness::start().await;
        let mut browser = Browser::default();
        let fields = [
            ("name", "Busy"),
            ("kind", "metric"),
            ("metric", "cpu.usage"),
            ("comparison", "above"),
            ("critical_threshold", "90"),
            ("for_secs", "60"),
            ("severity", "warning"),
            ("remind_every_minutes", "1"),
        ];

        let page = browser
            .submit(&test.server, "/alerts/rules/new", "/alerts/rules", &fields)
            .await;

        assert!(page.body.contains("every 5 minutes"), "{}", page.body);
    }
}

mod pages {
    use super::*;
    use crate::alerting::NewAlert;

    fn alert(rule_id: i64, agent: &Identity, severity: Severity, summary: &str) -> NewAlert {
        NewAlert {
            rule_id,
            rule_name: "Rule".to_string(),
            severity,
            agent_id: agent.id(),
            host: "web-1".to_string(),
            series: String::new(),
            value: None,
            summary: summary.to_string(),
            started_ms: 1000,
        }
    }

    #[tokio::test]
    async fn the_overview_leads_with_problems_most_serious_first() {
        let test = Harness::start().await;
        let rule = test
            .database()
            .create_alert_rule(&cpu_rule())
            .await
            .unwrap();
        let (warning, critical) = ("Disk is filling up", "Everything is on fire");
        // Newest comes first otherwise, so this has to be sorted to pass.
        let new = alert(rule, &test.agent, Severity::Critical, critical);
        test.database().fire_alert(&new, &[]).await.unwrap();
        let new = alert(rule, &test.agent, Severity::Warning, warning);
        test.database().fire_alert(&new, &[]).await.unwrap();

        let page = Browser::default().get(&test.server, "/").await;
        assert!(
            page.body.contains("2 problems need attention"),
            "{}",
            page.body
        );
        let (first, second) = (page.body.find(critical), page.body.find(warning));
        assert!(first.unwrap() < second.unwrap(), "{}", page.body);
        assert!(!page.body.contains("All clear"));
        assert!(page.body.contains("1 critical"), "{}", page.body);
    }

    #[tokio::test]
    async fn one_problem_reads_as_one_problem() {
        let test = Harness::start().await;
        let rule = test
            .database()
            .create_alert_rule(&cpu_rule())
            .await
            .unwrap();
        let new = alert(rule, &test.agent, Severity::Warning, "Disk is filling up");
        test.database().fire_alert(&new, &[]).await.unwrap();

        let page = Browser::default().get(&test.server, "/").await;
        assert!(
            page.body.contains("1 problem needs attention"),
            "{}",
            page.body
        );
        assert!(page.body.contains("Warnings only"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_overview_shows_agents_checks_and_who_is_waiting() {
        let test = Harness::start().await;
        let input = crate::remote_checks::RemoteCheckInput {
            check: maxnines_protocol::Check::new("site", maxnines_protocol::CheckKind::Tcp, "a:1"),
            interval_secs: 60,
            enabled: true,
        };
        test.database().create_remote_check(&input).await.unwrap();
        let mut waiting = test.server.connect().await;
        let newcomer = identity();
        handshake(&mut waiting, &newcomer, "new-1", None).await;

        let page = Browser::default().get(&test.server, "/").await;
        assert!(page.body.contains("web-1"), "{}", page.body);
        // The tiles say online with a dot alone, which keeps its word for screen readers.
        let dot = r#"<span class="badge good dot-only" role="img" aria-label="Online" title="Online"></span>"#;
        assert!(page.body.contains(dot), "{}", page.body);
        assert!(
            !page
                .body
                .contains(r#"<span class="badge good">Online</span>"#)
        );
        assert!(page.body.contains("site"), "{}", page.body);
        assert!(page.body.contains("Waiting"), "{}", page.body);
        assert!(
            page.body.contains("1 agent is waiting for approval"),
            "{}",
            page.body
        );
        assert!(page.body.contains("1 / 1"), "{}", page.body);
        assert!(page.body.contains("0 / 1"), "{}", page.body);
        assert!(page.body.contains("Waiting for results"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_navigation_marks_the_current_section_and_counts_what_is_firing() {
        let mut test = Harness::start().await;
        let rule = AlertRuleInput {
            for_secs: 0,
            ..cpu_rule()
        };
        test.database().create_alert_rule(&rule).await.unwrap();
        test.cpu(0, 95.0).await;
        let mut browser = Browser::default();

        for (path, link) in [
            ("/", r#"class="rail-link on" href="/""#),
            ("/agents", r#"class="rail-link on" href="/agents""#),
            ("/metrics", r#"class="rail-link on" href="/metrics""#),
            ("/checks", r#"class="rail-link on" href="/checks""#),
            ("/alerts", r#"class="rail-link on" href="/alerts""#),
            ("/settings", r#"class="rail-link on" href="/settings""#),
            ("/rules", r#"class="rail-link on" href="/settings""#),
            ("/alerts/rules", r#"class="rail-link on" href="/settings""#),
            (
                "/alerts/channels",
                r#"class="rail-link on" href="/settings""#,
            ),
        ] {
            let page = browser.get(&test.server, path).await;
            assert!(page.body.contains(link), "{path}: {}", page.body);
            assert!(
                page.body.contains(r#"<span class="count">1</span>"#),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn nothing_firing_shows_no_count() {
        let server = start().await;
        let page = Browser::default().get(&server, "/").await;
        assert!(!page.body.contains(r#"class="count""#));
    }

    #[tokio::test]
    async fn agents_can_be_filtered_and_seen_as_a_table() {
        let test = Harness::start().await;
        let other = identity();
        let client = test.server.connect_approved(&other, "db-1").await;
        drop(client);
        test.server.wait_for_online(&other.id(), false).await;
        let mut browser = Browser::default();

        let page = browser.get(&test.server, "/agents").await;
        assert!(page.body.contains("1 of 2 online"), "{}", page.body);
        for state in ["Online", "Offline"] {
            let dot =
                format!(r#"dot-only" role="img" aria-label="{state}" title="{state}"></span>"#);
            assert!(page.body.contains(&dot), "{state}: {}", page.body);
            assert!(!page.body.contains(&format!(">{state}</span>")), "{state}");
        }
        assert!(page.body.contains("All 2"), "{}", page.body);
        assert!(page.body.contains("class=\"tile"), "{}", page.body);

        let page = browser.get(&test.server, "/agents?filter=offline").await;
        assert!(page.body.contains("db-1"));
        assert!(!page.body.contains("web-1"), "{}", page.body);

        let page = browser.get(&test.server, "/agents?filter=online").await;
        assert!(page.body.contains("web-1"));
        assert!(!page.body.contains("db-1"), "{}", page.body);

        let page = browser.get(&test.server, "/agents?view=table").await;
        assert!(page.body.contains("<table"), "{}", page.body);
        assert!(
            page.body.contains(r#"aria-label="Online""#),
            "{}",
            page.body
        );
        assert!(!page.body.contains(">Online</span>"));
        assert!(!page.body.contains("class=\"tile"));
    }

    #[tokio::test]
    async fn a_waiting_agent_can_be_approved_or_rejected_from_the_list() {
        let server = start().await;
        let newcomer = identity();
        let mut client = server.connect().await;
        handshake(&mut client, &newcomer, "new-1", None).await;
        let id = newcomer.id();

        let mut browser = Browser::default();
        let page = browser.get(&server, "/agents").await;
        assert!(page.body.contains("Waiting for approval"), "{}", page.body);
        assert!(page.body.contains(&format!("/agents/{id}/approve")));
        assert!(page.body.contains(&format!("/agents/{id}/revoke")));

        let page = browser
            .submit(&server, "/agents", &format!("/agents/{id}/approve"), &[])
            .await;
        assert_eq!(page.status, 303, "{}", page.body);
        assert!(server.state.registry.is_approved(&id).await);

        let page = browser.get(&server, "/agents").await;
        assert!(!page.body.contains("Waiting for approval"), "{}", page.body);
    }

    #[tokio::test]
    async fn an_agents_page_shows_uptime_facts_and_firing_alerts() {
        let server = start_with_metrics().await;
        let agent = identity();
        let mut client = server.connect_approved(&agent, "web-1").await;
        let sample = AgentMessage::Sample(Sample {
            timestamp_ms: now_ms() as u64 - 1000,
            metrics: BTreeMap::from([
                (
                    "host".to_string(),
                    json!({ "uptime_secs": 4_603_242, "boot_time_secs": 1 }),
                ),
                (
                    "agent".to_string(),
                    json!({ "uptime_secs": 7_260, "memory_bytes": 9_000_000, "cpu_percent": 0.1 }),
                ),
            ]),
        });
        send(&mut client, &sample).await;
        let facts = FlatFacts::from([
            ("os.name".to_string(), json!("Ubuntu")),
            ("os.version".to_string(), json!("24.04")),
            ("cpu.logical_cores".to_string(), json!(16)),
        ]);
        server
            .state
            .database
            .record_facts(&agent.id(), &facts, now_ms() as u64)
            .await
            .unwrap();
        let rule = server
            .state
            .database
            .create_alert_rule(&cpu_rule())
            .await
            .unwrap();
        let new = alert(rule, &agent, Severity::Warning, "Disk is filling up");
        server.state.database.fire_alert(&new, &[]).await.unwrap();

        let metric = crate::metrics::find("host.uptime").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while server
            .state
            .metrics
            .newest(metric, now_ms())
            .await
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < deadline, "the sample never arrived");
            sleep(Duration::from_millis(10)).await;
        }

        let page = Browser::default()
            .get(&server, &format!("/agents/{}", agent.id()))
            .await;
        for text in [
            "53 days, 6 hours",
            "Agent uptime",
            "2 hours, 1 minute",
            "Ubuntu 24.04",
            "cpu.logical_cores",
            "Disk is filling up",
            "127.0.0.1",
        ] {
            assert!(page.body.contains(text), "{text}: {}", page.body);
        }
    }

    #[tokio::test]
    async fn a_reboot_can_be_alerted_on() {
        let server = start_with_metrics().await;
        let agent = identity();
        let mut client = server.connect_approved(&agent, "web-1").await;
        let rule = AlertRuleInput {
            name: "Rebooted".to_string(),
            metric: Some("host.uptime".to_string()),
            comparison: Some(Comparison::Below),
            threshold: Some(600.0),
            for_secs: 0,
            ..cpu_rule()
        };
        server
            .state
            .database
            .create_alert_rule(&rule)
            .await
            .unwrap();
        let sample = AgentMessage::Sample(Sample {
            timestamp_ms: now_ms() as u64 - 1000,
            metrics: BTreeMap::from([("host".to_string(), json!({ "uptime_secs": 90 }))]),
        });
        send(&mut client, &sample).await;

        let metric = crate::metrics::find("host.uptime").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while server
            .state
            .metrics
            .newest(metric, now_ms())
            .await
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < deadline, "the sample never arrived");
            sleep(Duration::from_millis(10)).await;
        }
        evaluator(&server, now_ms() - 60 * MINUTE_MS)
            .evaluate(now_ms())
            .await
            .unwrap();

        let open = server.state.database.open_alerts().await.unwrap();
        assert_eq!(open[0].summary, "Uptime on web-1 is 1.5 m, below 10 m");
    }

    #[tokio::test]
    async fn an_agent_that_keeps_restarting_can_be_alerted_on() {
        let server = start_with_metrics().await;
        let agent = identity();
        let mut client = server.connect_approved(&agent, "web-1").await;
        let rule = AlertRuleInput {
            name: "Agent restarted".to_string(),
            metric: Some("agent.uptime".to_string()),
            comparison: Some(Comparison::Below),
            threshold: Some(600.0),
            for_secs: 0,
            ..cpu_rule()
        };
        server
            .state
            .database
            .create_alert_rule(&rule)
            .await
            .unwrap();
        let sample = AgentMessage::Sample(Sample {
            timestamp_ms: now_ms() as u64 - 1000,
            metrics: BTreeMap::from([("agent".to_string(), json!({ "uptime_secs": 90 }))]),
        });
        send(&mut client, &sample).await;

        let metric = crate::metrics::find("agent.uptime").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while server
            .state
            .metrics
            .newest(metric, now_ms())
            .await
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < deadline, "the sample never arrived");
            sleep(Duration::from_millis(10)).await;
        }
        evaluator(&server, now_ms() - 60 * MINUTE_MS)
            .evaluate(now_ms())
            .await
            .unwrap();

        let open = server.state.database.open_alerts().await.unwrap();
        assert_eq!(
            open[0].summary,
            "Agent uptime on web-1 is 1.5 m, below 10 m"
        );
    }

    #[tokio::test]
    async fn config_rules_say_how_many_agents_they_reach() {
        let test = Harness::start().await;
        let page = Browser::default().get(&test.server, "/rules").await;
        assert!(
            page.body.contains(r#"<td class="number">1</td>"#),
            "{}",
            page.body
        );
    }

    #[tokio::test]
    async fn checks_can_be_filtered() {
        let server = start().await;
        let input = |name: &str, enabled| crate::remote_checks::RemoteCheckInput {
            check: maxnines_protocol::Check::new(name, maxnines_protocol::CheckKind::Tcp, "a:1"),
            interval_secs: 60,
            enabled,
        };
        let database = &server.state.database;
        database
            .create_remote_check(&input("on", true))
            .await
            .unwrap();
        database
            .create_remote_check(&input("paused", false))
            .await
            .unwrap();
        let mut browser = Browser::default();

        let page = browser.get(&server, "/checks?filter=disabled").await;
        assert!(page.body.contains("paused"), "{}", page.body);
        assert!(!page.body.contains(">on<"), "{}", page.body);
        assert!(page.body.contains("All 2"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_font_is_served_from_the_binary_and_the_policy_allows_it() {
        let server = start().await;
        let mut browser = Browser::default();
        let page = browser.get(&server, "/assets/fonts/inter.woff2").await;
        assert_eq!(page.status, 200);
        assert_eq!(page.header("content-type"), Some("font/woff2"));

        let policy = page.header("content-security-policy").unwrap();
        assert!(policy.contains("font-src 'self'"), "{policy}");
    }

    #[tokio::test]
    async fn names_from_agents_are_escaped_on_every_new_page() {
        let server = start_with_metrics().await;
        let agent = identity();
        let host = "<script>alert(1)</script>";
        let _client = server.connect_approved(&agent, host).await;
        let facts = FlatFacts::from([("os.name".to_string(), json!(host))]);
        server
            .state
            .database
            .record_facts(&agent.id(), &facts, now_ms() as u64)
            .await
            .unwrap();
        let mut browser = Browser::default();

        for path in [
            "/".to_string(),
            "/agents".to_string(),
            "/agents?view=table".to_string(),
            format!("/agents/{}", agent.id()),
            "/metrics".to_string(),
        ] {
            let page = browser.get(&server, &path).await;
            assert_eq!(page.status, 200, "{path}");
            assert!(page.has_only_our_scripts(), "{path}: {}", page.body);
        }
    }
}

// ---- the server page

mod server_page {
    use super::*;
    use crate::server_stats::{Recorded, record_once};

    #[tokio::test]
    async fn the_server_keeps_a_history_of_its_own_numbers() {
        let server = start_with_metrics().await;
        let local = server.state.database.load_agents().await.unwrap();
        let local = local
            .into_iter()
            .find(|agent| agent.id == crate::remote_checks::LOCAL_AGENT_ID)
            .unwrap();
        server.state.registry.insert_for_test(local).await;
        let (_agent, client) = report_samples(&server, "/").await;
        // Reading answers heartbeats, as an agent would, however long this takes.
        let (_sender, receiver) = client.split();
        tokio::spawn(receiver.for_each(|_| async {}));
        let mut recorded = Recorded::default();
        record_once(&server.state, &mut recorded).await;
        sleep(Duration::from_millis(50)).await;
        record_once(&server.state, &mut recorded).await;

        let deadline = Instant::now() + Duration::from_secs(5);
        let page = loop {
            let page = Browser::default()
                .get(&server, "/agents/server/metrics")
                .await;
            if page.body.contains("Server memory") || Instant::now() > deadline {
                break page;
            }
            sleep(Duration::from_millis(20)).await;
        };

        assert_eq!(page.status, 200);
        assert!(page.body.contains("Server memory"), "{}", page.body);
        assert!(page.body.contains("Agents"), "{}", page.body);
        // Charts for what the server doesn't report would only be empty.
        assert!(!page.body.contains("CPU usage"), "{}", page.body);
        assert!(page.body.contains(r#"href="/server""#));

        let metric = crate::metrics::find("server.agents").unwrap();
        let range = TimeRange::new(now_ms() - 60_000, now_ms() + 60_000).unwrap();
        let agents = server
            .state
            .metrics
            .series("server", metric, range, 8)
            .await;
        let online = agents
            .unwrap()
            .series
            .into_iter()
            .find(|s| s.name == "Online")
            .unwrap();
        // The server also records its numbers by itself, from before the agent
        // connected, so only the newest reading is sure to count it.
        assert_eq!(
            online.points.last().unwrap().max,
            1.0,
            "the agent isn't counted: {:?}",
            online.points
        );
    }

    #[tokio::test]
    async fn the_server_page_links_to_its_history() {
        let server = start().await;
        let page = Browser::default().get(&server, "/server").await;
        assert!(
            page.body
                .contains(r#"href="/agents/server/metrics?range=1h""#)
        );
    }

    #[tokio::test]
    async fn the_servers_own_samples_are_not_counted_as_ingested() {
        use crate::server_stats::{Recorded, record_once};

        let server = start_with_metrics().await;
        record_once(&server.state, &mut Recorded::default()).await;
        sleep(Duration::from_millis(100)).await;

        let writes = &server.state.status.writes;
        let written = writes.written.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(written, 0);
    }

    #[tokio::test]
    async fn the_server_page_reports_on_everything() {
        let server = start_with_metrics().await;
        let (_agent, _client) = report_samples(&server, "/").await;
        evaluator(&server, now_ms())
            .evaluate(now_ms())
            .await
            .unwrap();

        let page = Browser::default().get(&server, "/server").await;
        assert_eq!(page.status, 200, "{}", page.body);
        for text in [
            env!("CARGO_PKG_VERSION"),
            "DuckDB",
            crate::tests::main_database_engine(),
            "Memory limit",
            "Write-ahead log",
            "Samples written",
            "Rows",
            "cpu",
            "Agents",
            "Alert rules last ran",
        ] {
            assert!(page.body.contains(text), "{text}: {}", page.body);
        }
    }

    #[tokio::test]
    async fn the_page_still_works_when_the_metrics_database_does_not() {
        let saved = Saved::default();
        let store = Box::new(crate::store::testing::MemoryStore(saved.clone()));
        let server = start_on("", store, Arc::new(BrokenReader), saved, None).await;

        let page = Browser::default().get(&server, "/server").await;
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(page.body.contains("couldn't be read"), "{}", page.body);
        assert!(
            page.body.contains(crate::tests::main_database_engine()),
            "the other database still shows"
        );
        assert!(
            !page.body.contains("deliberate test failure"),
            "{}",
            page.body
        );
    }

    #[tokio::test]
    async fn the_page_still_works_when_the_main_database_does_not() {
        let server = start().await;
        server.state.database.break_for_test().await;

        let page = Browser::default().get(&server, "/server").await;
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(page.body.contains("couldn't be read"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_page_warns_when_alert_rules_have_stopped_running() {
        let server = start().await;
        let late = now_ms() - 10 * MINUTE_MS;
        evaluator(&server, late).evaluate(late).await.unwrap();

        let page = Browser::default().get(&server, "/server").await;
        assert!(
            page.body.contains("Alert rules haven't run"),
            "{}",
            page.body
        );
    }

    #[tokio::test]
    async fn failed_writes_stand_out() {
        let server = start().await;
        let counts = &server.state.status.writes;
        counts.failed.store(3, std::sync::atomic::Ordering::Relaxed);

        let page = Browser::default().get(&server, "/server").await;
        assert!(
            page.body.contains("3 samples couldn't be saved"),
            "{}",
            page.body
        );
    }

    #[tokio::test]
    async fn the_page_never_shows_a_database_url() {
        let server = start().await;
        let page = Browser::default().get(&server, "/server").await;
        assert!(!page.body.contains("sqlite:"), "{}", page.body);
        assert!(!page.body.contains("://"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_api_gives_the_same_numbers_and_needs_the_token() {
        let server = start().await;
        let response = server.http("GET", "/api/v1/server", None).await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");

        let (status, stats) = api(&server, "GET", "/api/v1/server", &Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(stats["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            stats["database"]["engine"],
            crate::tests::main_database_engine()
        );
        assert!(stats["process"]["memory_bytes"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn the_dashboard_graphs_what_the_server_takes_in() {
        let server = start_with_metrics().await;
        let (_agent, client) = report_samples(&server, "/").await;
        // Reading answers heartbeats, as an agent would, however long this takes.
        let (mut sender, receiver) = client.split();
        tokio::spawn(receiver.for_each(|_| async {}));
        let mut recorded = Recorded::default();
        record_once(&server.state, &mut recorded).await;
        // A rate needs something to have arrived between two records.
        let writes = server.state.status.writes.clone();
        let before = writes.written.load(std::sync::atomic::Ordering::Relaxed);
        let text = serde_json::to_string(&full_sample(now_ms() as u64, "/")).unwrap();
        sender.send(Message::text(text)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while writes.written.load(std::sync::atomic::Ordering::Relaxed) == before {
            assert!(Instant::now() < deadline, "the sample wasn't written");
            sleep(Duration::from_millis(5)).await;
        }
        sleep(Duration::from_millis(50)).await;
        record_once(&server.state, &mut recorded).await;

        let metric = crate::metrics::find("server.metrics").unwrap();
        let range = TimeRange::new(now_ms() - 60_000, now_ms() + 60_000).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let page = loop {
            let found = server.state.metrics.series("server", metric, range, 8);
            if !found.await.unwrap().series.is_empty() {
                break Browser::default().get(&server, "/server").await;
            }
            assert!(Instant::now() < deadline, "no rate was recorded");
            sleep(Duration::from_millis(20)).await;
        };

        assert_eq!(page.status, 200);
        for heading in [
            "Metrics per second",
            "Samples per second",
            "Slowest write",
            "Series stored",
            "Database size",
            "Agents",
            "CPU usage",
        ] {
            assert!(page.body.contains(heading), "{heading}: {}", page.body);
        }
        assert!(page.body.contains(r#"<svg class="chart""#));
        assert!(page.body.contains(r#"href="/server?range=7d""#));
    }

    #[tokio::test]
    async fn the_server_reports_on_its_own_machine() {
        let server = start_with_metrics().await;
        let mut recorded = Recorded::with_machine();
        record_once(&server.state, &mut recorded).await;
        sleep(Duration::from_millis(300)).await;
        record_once(&server.state, &mut recorded).await;

        let metric = crate::metrics::find("memory.usage").unwrap();
        let range = TimeRange::new(now_ms() - 60_000, now_ms() + 60_000).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let found = server.state.metrics.series("server", metric, range, 8);
            if !found.await.unwrap().series.is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "nothing about the machine");
            sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn the_old_address_of_the_server_page_still_works() {
        let server = start().await;
        let response = server
            .http("GET", "/settings/server", Some(&server.api_key))
            .await;
        assert!(response.starts_with("HTTP/1.1 308"), "{response}");
        assert!(
            response.to_lowercase().contains("location: /server"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn settings_links_to_the_server_page() {
        let server = start().await;
        let page = Browser::default().get(&server, "/settings").await;
        assert!(page.body.contains(r#"href="/server""#), "{}", page.body);
    }
}

/// Charts sent with alerts, drawn from what an agent really reported.
mod charts {
    use super::*;
    use crate::alert_charts::ChartSources;
    use crate::alerting::{Alert, NewAlert};

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

    fn sources(server: &TestServer) -> ChartSources {
        ChartSources {
            database: server.state.database.clone(),
            registry: server.state.registry.clone(),
            metrics: server.state.metrics.clone(),
        }
    }

    /// A disk alert for what `agent` reports, told to `channels`.
    async fn disk_alert(
        server: &TestServer,
        agent: &Identity,
        series: &str,
        channels: &[i64],
    ) -> Alert {
        let database = &server.state.database;
        let rule = AlertRuleInput {
            name: format!("Disk {series}"),
            metric: Some("disk.usage".to_string()),
            threshold: Some(90.0),
            warning_threshold: Some(80.0),
            for_secs: 0,
            channels: channels.to_vec(),
            ..cpu_rule()
        };
        let rule_id = database.create_alert_rule(&rule).await.unwrap();
        let new = NewAlert {
            rule_id,
            rule_name: rule.name,
            severity: Severity::Critical,
            agent_id: agent.id(),
            host: "web-1".to_string(),
            series: series.to_string(),
            value: Some(95.0),
            summary: format!("Disk usage ({series}) on web-1 is 95%, above 90%"),
            started_ms: now_ms() - 30_000,
        };
        let id = database.fire_alert(&new, channels).await.unwrap();
        database.get_alert(id).await.unwrap().unwrap()
    }

    /// Each post's content type and body.
    type Posts = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Somewhere that keeps the content type and body of everything posted to it.
    #[derive(Clone, Default)]
    struct Capture {
        posts: Posts,
    }

    impl Capture {
        async fn start(&self) -> String {
            let capture = self.clone();
            let router = Router::new().route(
                "/hook",
                post(
                    move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                        let capture = capture.clone();
                        async move {
                            let kind = headers
                                .get("content-type")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_string();
                            capture.posts.lock().unwrap().push((kind, body.to_vec()));
                            StatusCode::OK
                        }
                    },
                ),
            );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, router).await });
            format!("http://{address}/hook")
        }

        fn posts(&self) -> Vec<(String, String)> {
            self.posts
                .lock()
                .unwrap()
                .iter()
                .map(|(kind, body)| (kind.clone(), String::from_utf8_lossy(body).into_owned()))
                .collect()
        }
    }

    #[tokio::test]
    async fn a_chart_is_drawn_from_what_the_agent_reported() {
        let server = start_with_metrics().await;
        let (agent, _client) = report_samples(&server, "/data").await;
        let charts = sources(&server);
        let now = now_ms();

        let alert = disk_alert(&server, &agent, "/data", &[]).await;
        let png = charts.draw(&alert, now).await.unwrap().unwrap();
        assert_eq!(&png[..8], PNG);

        let missing = disk_alert(&server, &agent, "/elsewhere", &[]).await;
        assert!(charts.draw(&missing, now).await.unwrap().is_none());

        let rule = server
            .state
            .database
            .create_alert_rule(&offline_rule())
            .await
            .unwrap();
        let offline = Alert {
            rule_id: Some(rule),
            series: String::new(),
            ..alert
        };
        assert!(charts.draw(&offline, now).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn discord_gets_the_chart_attached_when_an_alert_starts_but_not_ends() {
        let server = start_with_metrics().await;
        let (agent, _client) = report_samples(&server, "/data").await;
        let capture = Capture::default();
        let channel = ChannelInput {
            name: "Discord".to_string(),
            kind: ChannelKind::Discord,
            target: capture.start().await,
            ..webhook_channel("unused")
        };
        let channel = server
            .state
            .database
            .create_channel(&channel)
            .await
            .unwrap();
        let alert = disk_alert(&server, &agent, "/data", &[channel]).await;
        let notifier = Notifier::new(server.state.database.clone(), Senders::default())
            .with_charts(sources(&server));

        notifier.deliver_due(now_ms()).await.unwrap();
        let posts = capture.posts();
        assert_eq!(posts.len(), 1);
        let (kind, body) = &posts[0];
        assert!(kind.starts_with("multipart/form-data"), "{kind}");
        assert!(body.contains(r#"name="payload_json""#), "{body}");
        assert!(body.contains("**CRITICAL** Disk usage (/data) on web-1 is 95%"));
        assert!(body.contains(r#"name="files[0]"; filename="chart.png""#));
        assert!(body.contains("PNG"));

        server
            .state
            .database
            .resolve_alert(alert.id, now_ms(), "The problem cleared")
            .await
            .unwrap();
        notifier.deliver_due(now_ms()).await.unwrap();
        let posts = capture.posts();
        assert_eq!(posts[1].0, "application/json");
    }

    #[tokio::test]
    async fn telegram_gets_a_photo_with_the_alert_as_its_caption() {
        let server = start_with_metrics().await;
        let (agent, _client) = report_samples(&server, "/data").await;
        let telegram = FakeTelegram::default();
        let url = telegram.start().await;
        let channel = ChannelInput {
            name: "Telegram".to_string(),
            kind: ChannelKind::Telegram,
            target: "-100123".to_string(),
            credential: Some(TELEGRAM_TOKEN.to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
        };
        let channel = server
            .state
            .database
            .create_channel(&channel)
            .await
            .unwrap();
        disk_alert(&server, &agent, "/data", &[channel]).await;
        let senders = Senders {
            telegram_api_url: Some(url),
            ..Senders::default()
        };
        Notifier::new(server.state.database.clone(), senders)
            .with_charts(sources(&server))
            .deliver_due(now_ms())
            .await
            .unwrap();

        let calls = telegram.calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].0.ends_with("/sendPhoto"));
        let form = calls[0].1.as_str().unwrap();
        assert!(form.contains(r#"name="caption""#), "{form}");
        assert!(form.contains("<b>CRITICAL</b> Disk usage (/data) on web-1"));
        assert!(form.contains(r#"name="photo"; filename="chart.png""#));
    }

    #[tokio::test]
    async fn a_message_too_long_for_a_caption_goes_first_with_the_photo_replying() {
        let server = start_with_metrics().await;
        let (agent, _client) = report_samples(&server, "/data").await;
        let telegram = FakeTelegram::default();
        let url = telegram.start().await;
        let channel = ChannelInput {
            name: "Telegram".to_string(),
            kind: ChannelKind::Telegram,
            target: "-100123".to_string(),
            credential: Some(TELEGRAM_TOKEN.to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
        };
        let channel = server
            .state
            .database
            .create_channel(&channel)
            .await
            .unwrap();
        let long = "/".to_string() + &"d".repeat(200);
        let alert = disk_alert(&server, &agent, &long, &[channel]).await;
        let notice = crate::notifier::Notice {
            chart: Some(Arc::new(PNG.to_vec())),
            ..crate::notifier::Notice::for_alert(
                Alert {
                    summary: "x".repeat(1500),
                    ..alert
                },
                Event::Firing,
            )
        };
        let senders = Senders {
            telegram_api_url: Some(url),
            ..Senders::default()
        };
        let channel = server
            .state
            .database
            .get_channel(channel)
            .await
            .unwrap()
            .unwrap();
        let sent = crate::notifier::send(channel, notice, None, senders)
            .await
            .unwrap();

        let calls = telegram.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls[0].0.ends_with("/sendMessage"));
        assert!(calls[1].0.ends_with("/sendPhoto"));
        let form = calls[1].1.as_str().unwrap();
        assert!(!form.contains(r#"name="caption""#));
        assert!(form.contains(r#""message_id":101"#), "{form}");
        assert_eq!(sent.as_deref(), Some("101"));
    }

    #[tokio::test]
    async fn slack_shows_the_chart_and_keeps_it_when_the_alert_resolves() {
        let server = start_with_metrics().await;
        let (agent, _client) = report_samples(&server, "/data").await;
        let slack = FakeSlack::default();
        let url = slack.start().await;
        let channel = ChannelInput {
            name: "Slack".to_string(),
            kind: ChannelKind::Slack,
            target: "#alerts".to_string(),
            credential: Some("xoxb-secret-token".to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
        };
        let channel = server
            .state
            .database
            .create_channel(&channel)
            .await
            .unwrap();
        let alert = disk_alert(&server, &agent, "/data", &[channel]).await;
        let notifier = Notifier::new(
            server.state.database.clone(),
            Senders {
                slack_api_url: Some(url),
                ..Senders::default()
            },
        )
        .with_charts(sources(&server));

        notifier.deliver_due(now_ms()).await.unwrap();
        let methods: Vec<String> = slack.calls().into_iter().map(|call| call.0).collect();
        assert_eq!(methods, ["upload_url", "upload", "complete", "post"]);
        let calls = slack.calls();
        let blocks = &calls[3].2["attachments"][0]["blocks"];
        assert_eq!(blocks[1]["type"], "image", "{blocks}");
        assert_eq!(blocks[1]["slack_file"]["id"], "F123");

        server
            .state
            .database
            .resolve_alert(alert.id, now_ms(), "The problem cleared")
            .await
            .unwrap();
        notifier.deliver_due(now_ms()).await.unwrap();
        let calls = slack.calls();
        let (method, _, update) = &calls[4];
        assert_eq!(method, "update");
        assert_eq!(
            update["attachments"][0]["blocks"][1]["slack_file"]["id"],
            "F123"
        );
    }

    #[tokio::test]
    async fn slack_still_gets_the_alert_when_the_chart_cannot_be_uploaded() {
        let server = start_with_metrics().await;
        let (agent, _client) = report_samples(&server, "/data").await;
        let slack = FakeSlack::default();
        let url = slack.start().await;
        slack.errors.lock().unwrap().push("missing_scope");
        let channel = ChannelInput {
            name: "Slack".to_string(),
            kind: ChannelKind::Slack,
            target: "#alerts".to_string(),
            credential: Some("xoxb-secret-token".to_string()),
            app_token: None,
            severities: crate::alerting::every_severity(),
        };
        let channel = server
            .state
            .database
            .create_channel(&channel)
            .await
            .unwrap();
        disk_alert(&server, &agent, "/data", &[channel]).await;
        Notifier::new(
            server.state.database.clone(),
            Senders {
                slack_api_url: Some(url),
                ..Senders::default()
            },
        )
        .with_charts(sources(&server))
        .deliver_due(now_ms())
        .await
        .unwrap();

        let calls = slack.calls();
        let methods: Vec<&str> = calls.iter().map(|call| call.0.as_str()).collect();
        assert_eq!(methods, ["upload_url", "post"]);
        assert_eq!(
            calls[1].2["attachments"][0]["blocks"][1]["type"],
            json!(null)
        );
        assert!(
            server
                .state
                .database
                .delivery_problems(10)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
