//! What alerting is made of: rules that say what to watch, channels that say who
//! to tell, and the alerts that result. [`crate::alert_evaluator`] decides when
//! alerts start and end, and [`crate::notifier`] delivers them.

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::http::Uri;
use cel::Program;
use lettre::Address;
use serde::{Deserialize, Serialize};
use wildmatch::WildMatch;

use crate::metric_charts::format_value;
use crate::metrics::{self, Metric, Source};

/// What the database columns hold.
const MAX_NAME_LEN: usize = 255;
const MAX_TARGET_LEN: usize = 2048;

/// A rule can't wait longer than this before firing. It also limits how long a
/// rule can take to resolve, since the two match.
const MAX_FOR_SECS: u64 = 7 * 86_400;

const MAX_RECIPIENTS: usize = 20;

/// Where Discord's webhooks live, including its test builds and older domain.
const DISCORD_HOSTS: [&str; 4] = [
    "discord.com",
    "discordapp.com",
    "ptb.discord.com",
    "canary.discord.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Metric,
    Offline,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metric => "metric",
            Self::Offline => "offline",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "metric" => Ok(Self::Metric),
            "offline" => Ok(Self::Offline),
            other => bail!("unknown rule kind {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Above,
    Below,
}

impl Comparison {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Above => "above",
            Self::Below => "below",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "above" => Ok(Self::Above),
            "below" => Ok(Self::Below),
            other => bail!("unknown comparison {other:?}"),
        }
    }

    pub fn is_breached(self, value: f64, threshold: f64) -> bool {
        match self {
            Self::Above => value > threshold,
            Self::Below => value < threshold,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "warning" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            other => bail!("unknown severity {other:?}"),
        }
    }
}

/// A rule as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: i64,
    #[serde(flatten)]
    pub rule: AlertRuleInput,
}

/// What can be set on a rule. Validated by [`check_rule`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRuleInput {
    pub name: String,
    pub kind: RuleKind,
    /// A name from the metric catalog, for metric rules.
    #[serde(default)]
    pub metric: Option<String>,
    /// Limits a metric rule to matching series, with `*` and `?` wildcards.
    /// Every series is watched separately, so empty means each one.
    #[serde(default)]
    pub series: Option<String>,
    #[serde(default)]
    pub comparison: Option<Comparison>,
    #[serde(default)]
    pub threshold: Option<f64>,
    /// How long the problem has to last before the alert fires, and how long it
    /// has to stay gone before the alert resolves.
    pub for_secs: u64,
    pub severity: Severity,
    /// A CEL expression over facts. An empty condition matches every agent.
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Who to tell. With none, the alert only shows in the web interface.
    #[serde(default)]
    pub channels: Vec<i64>,
}

fn default_enabled() -> bool {
    true
}

/// Checks a rule before it's saved. Whether its channels exist is up to the
/// caller, which can see them.
pub fn check_rule(rule: &AlertRuleInput) -> Result<()> {
    ensure!(!rule.name.trim().is_empty(), "a rule needs a name");
    ensure!(rule.name.len() <= MAX_NAME_LEN, "the rule name is too long");
    ensure!(
        rule.for_secs <= MAX_FOR_SECS,
        "the duration can't be longer than 7 days"
    );

    if let Some(condition) = &rule.condition {
        Program::compile(condition).map_err(|error| anyhow!("invalid condition: {error}"))?;
    }

    match rule.kind {
        RuleKind::Metric => {
            let name = rule.metric.as_deref().context("choose a metric")?;
            metrics::find(name).with_context(|| format!("unknown metric {name:?}"))?;
            ensure!(rule.comparison.is_some(), "choose above or below");
            let threshold = rule.threshold.context("a metric rule needs a threshold")?;
            ensure!(threshold.is_finite(), "the threshold must be a number");
            if let Some(series) = &rule.series {
                ensure!(series.len() <= MAX_NAME_LEN, "the series name is too long");
            }
        }
        RuleKind::Offline => {
            ensure!(
                rule.metric.is_none()
                    && rule.series.is_none()
                    && rule.comparison.is_none()
                    && rule.threshold.is_none(),
                "an offline rule doesn't take a metric or threshold"
            );
        }
    }
    Ok(())
}

impl AlertRuleInput {
    pub fn metric(&self) -> Option<&'static Metric> {
        metrics::find(self.metric.as_deref()?)
    }

    pub fn watches_series(&self, series: &str) -> bool {
        self.series
            .as_deref()
            .is_none_or(|pattern| WildMatch::new(pattern).matches(series))
    }

    /// What the rule watches, in a few words.
    pub fn describe(&self) -> String {
        let wait = |text: String| match self.for_secs {
            0 => text,
            secs => format!("{text} for {}", format_duration(secs)),
        };
        let (Some(metric), Some(comparison), Some(threshold)) =
            (self.metric(), self.comparison, self.threshold)
        else {
            return wait("Offline".to_string());
        };
        let series = match &self.series {
            Some(series) => format!(" ({series})"),
            None => String::new(),
        };
        wait(format!(
            "{}{series} {} {}",
            metric.title,
            comparison.as_str(),
            format_value(metric.unit, threshold)
        ))
    }

    /// What a metric alert says when it fires.
    pub fn metric_summary(
        &self,
        metric: &Metric,
        host: &str,
        series: &str,
        value: f64,
    ) -> Result<String> {
        let comparison = self.comparison.context("no comparison")?;
        let threshold = self.threshold.context("no threshold")?;
        let name = match metric.source {
            Source::Fields([_]) => metric.title.to_string(),
            _ => format!("{} ({series})", metric.title),
        };
        let mut summary = format!(
            "{name} on {host} is {}, {} {}",
            format_value(metric.unit, value),
            comparison.as_str(),
            format_value(metric.unit, threshold)
        );
        if self.for_secs > 0 {
            summary.push_str(&format!(" for {}", format_duration(self.for_secs)));
        }
        Ok(summary)
    }

    /// What an offline alert says when it fires.
    pub fn offline_summary(&self, host: &str) -> String {
        match self.for_secs {
            0 => format!("{host} is offline"),
            secs => format!("{host} has been offline for {}", format_duration(secs)),
        }
    }
}

/// Agents choose hostnames and series names, so anything kept from them loses
/// control characters, which could forge lines in an email or log and which
/// Postgres refuses, and is cut to what the database columns hold.
pub fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_LEN)
        .collect()
}

pub fn format_duration(secs: u64) -> String {
    let plural = |count: u64, unit: &str| match count {
        1 => format!("1 {unit}"),
        _ => format!("{count} {unit}s"),
    };
    match secs {
        secs if secs % 86_400 == 0 && secs > 0 => plural(secs / 86_400, "day"),
        secs if secs % 3600 == 0 && secs > 0 => plural(secs / 3600, "hour"),
        secs if secs % 60 == 0 && secs > 0 => plural(secs / 60, "minute"),
        secs => plural(secs, "second"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Webhook,
    Email,
    Discord,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Email => "email",
            Self::Discord => "discord",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "webhook" => Ok(Self::Webhook),
            "email" => Ok(Self::Email),
            "discord" => Ok(Self::Discord),
            other => bail!("unknown channel kind {other:?}"),
        }
    }
}

/// Somewhere notifications go. A webhook's URL often is its password, so
/// `target` is never sent back out: see [`ChannelInput::target_preview`].
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub id: i64,
    pub channel: ChannelInput,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ChannelInput {
    pub name: String,
    pub kind: ChannelKind,
    /// A webhook's URL, or email addresses separated by commas.
    pub target: String,
}

pub fn check_channel(channel: &ChannelInput) -> Result<()> {
    ensure!(!channel.name.trim().is_empty(), "a channel needs a name");
    ensure!(
        channel.name.len() <= MAX_NAME_LEN,
        "the channel name is too long"
    );
    ensure!(
        channel.target.len() <= MAX_TARGET_LEN,
        "the channel's destination is too long"
    );
    match channel.kind {
        ChannelKind::Webhook => {
            webhook_host(&channel.target)?;
        }
        ChannelKind::Discord => check_discord_url(&channel.target)?,
        ChannelKind::Email => {
            let recipients = recipients(&channel.target)?;
            ensure!(!recipients.is_empty(), "add at least one email address");
            ensure!(
                recipients.len() <= MAX_RECIPIENTS,
                "a channel can have at most {MAX_RECIPIENTS} email addresses"
            );
        }
    }
    Ok(())
}

/// Catches pasting the wrong thing here, which would otherwise only show up when
/// the first alert failed to arrive. Errors don't repeat the URL.
fn check_discord_url(url: &str) -> Result<()> {
    let uri: Uri = url
        .trim()
        .parse()
        .map_err(|_| anyhow!("the Discord webhook URL isn't valid"))?;
    let host = uri.host().unwrap_or_default();
    ensure!(
        uri.scheme_str() == Some("https")
            && DISCORD_HOSTS.contains(&host)
            && uri.path().starts_with("/api/webhooks/"),
        "that doesn't look like a Discord webhook URL, which starts with \
         https://discord.com/api/webhooks/"
    );
    Ok(())
}

/// The part of a webhook's URL that's safe to show. Errors don't repeat the URL.
fn webhook_host(url: &str) -> Result<String> {
    let uri: Uri = url
        .trim()
        .parse()
        .map_err(|_| anyhow!("the webhook URL isn't valid"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    ensure!(
        matches!(scheme, "http" | "https"),
        "the webhook URL must start with http:// or https://"
    );
    let host = uri.host().context("the webhook URL needs a host")?;
    Ok(format!("{scheme}://{host}"))
}

/// Email addresses separated by commas.
pub fn recipients(target: &str) -> Result<Vec<Address>> {
    target
        .split(',')
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(|address| {
            address
                .parse()
                .map_err(|_| anyhow!("{address:?} isn't a valid email address"))
        })
        .collect()
}

impl ChannelInput {
    /// Enough to recognize a channel, without giving away a webhook's secret.
    pub fn target_preview(&self) -> String {
        match self.kind {
            ChannelKind::Webhook | ChannelKind::Discord => webhook_host(&self.target)
                .map_or_else(|_| "Unknown".to_string(), |host| format!("{host}/…")),
            ChannelKind::Email => self.target.clone(),
        }
    }
}

/// One rule firing for one agent, or one of its series.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    pub id: i64,
    /// Empty once the rule is deleted.
    pub rule_id: Option<i64>,
    pub rule_name: String,
    pub severity: Severity,
    pub agent_id: String,
    pub host: String,
    /// Empty for alerts about the agent as a whole.
    pub series: String,
    /// The reading that started the alert.
    pub value: Option<f64>,
    pub summary: String,
    pub started_ms: i64,
    pub resolved_ms: Option<i64>,
    pub resolve_reason: Option<String>,
}

/// What's needed to start an alert.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    pub rule_id: i64,
    pub rule_name: String,
    pub severity: Severity,
    pub agent_id: String,
    pub host: String,
    pub series: String,
    pub value: Option<f64>,
    pub summary: String,
    pub started_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Firing,
    Resolved,
    Test,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firing => "firing",
            Self::Resolved => "resolved",
            Self::Test => "test",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "firing" => Ok(Self::Firing),
            "resolved" => Ok(Self::Resolved),
            other => bail!("unknown event {other:?}"),
        }
    }
}

/// A notification that's due, with what it needs for sending.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivery {
    pub id: i64,
    pub event: Event,
    pub attempts: i32,
    pub created_ms: i64,
    pub alert: Alert,
    pub channel: Channel,
}

/// A notification that was given up on, or is still being retried.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeliveryProblem {
    pub channel: String,
    pub summary: String,
    pub event: Event,
    pub state: String,
    pub attempts: i32,
    pub error: String,
    pub created_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_rule() -> AlertRuleInput {
        AlertRuleInput {
            name: "High CPU".to_string(),
            kind: RuleKind::Metric,
            metric: Some("cpu.usage".to_string()),
            series: None,
            comparison: Some(Comparison::Above),
            threshold: Some(90.0),
            for_secs: 300,
            severity: Severity::Critical,
            condition: None,
            enabled: true,
            channels: Vec::new(),
        }
    }

    fn offline_rule() -> AlertRuleInput {
        AlertRuleInput {
            kind: RuleKind::Offline,
            metric: None,
            comparison: None,
            threshold: None,
            for_secs: 60,
            ..metric_rule()
        }
    }

    fn webhook(target: &str) -> ChannelInput {
        ChannelInput {
            name: "Ops".to_string(),
            kind: ChannelKind::Webhook,
            target: target.to_string(),
        }
    }

    fn email(target: &str) -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Email,
            ..webhook(target)
        }
    }

    #[test]
    fn good_rules_pass() {
        check_rule(&metric_rule()).unwrap();
        check_rule(&offline_rule()).unwrap();
    }

    #[test]
    fn bad_rules_are_refused_with_a_reason() {
        for (rule, expected) in [
            (
                AlertRuleInput {
                    name: "  ".to_string(),
                    ..metric_rule()
                },
                "needs a name",
            ),
            (
                AlertRuleInput {
                    name: "x".repeat(256),
                    ..metric_rule()
                },
                "too long",
            ),
            (
                AlertRuleInput {
                    metric: Some("cpu.nonsense".to_string()),
                    ..metric_rule()
                },
                "unknown metric",
            ),
            (
                AlertRuleInput {
                    metric: None,
                    ..metric_rule()
                },
                "choose a metric",
            ),
            (
                AlertRuleInput {
                    comparison: None,
                    ..metric_rule()
                },
                "above or below",
            ),
            (
                AlertRuleInput {
                    threshold: None,
                    ..metric_rule()
                },
                "needs a threshold",
            ),
            (
                AlertRuleInput {
                    threshold: Some(f64::NAN),
                    ..metric_rule()
                },
                "must be a number",
            ),
            (
                AlertRuleInput {
                    for_secs: MAX_FOR_SECS + 1,
                    ..metric_rule()
                },
                "7 days",
            ),
            (
                AlertRuleInput {
                    condition: Some("facts.os ==".to_string()),
                    ..metric_rule()
                },
                "invalid condition",
            ),
            (
                AlertRuleInput {
                    series: Some("x".repeat(256)),
                    ..metric_rule()
                },
                "too long",
            ),
            (
                AlertRuleInput {
                    threshold: Some(1.0),
                    ..offline_rule()
                },
                "doesn't take",
            ),
        ] {
            let error = format!("{:#}", check_rule(&rule).unwrap_err());
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_reading_equal_to_the_threshold_is_not_a_breach() {
        assert!(Comparison::Above.is_breached(90.1, 90.0));
        assert!(!Comparison::Above.is_breached(90.0, 90.0));
        assert!(Comparison::Below.is_breached(9.9, 10.0));
        assert!(!Comparison::Below.is_breached(10.0, 10.0));
    }

    #[test]
    fn series_can_be_limited_with_wildcards() {
        let rule = AlertRuleInput {
            series: Some("/data*".to_string()),
            ..metric_rule()
        };
        assert!(rule.watches_series("/data"));
        assert!(rule.watches_series("/data/logs"));
        assert!(!rule.watches_series("/"));
        assert!(metric_rule().watches_series("anything"));
    }

    #[test]
    fn rules_describe_themselves() {
        assert_eq!(
            metric_rule().describe(),
            "CPU usage above 90% for 5 minutes"
        );
        assert_eq!(offline_rule().describe(), "Offline for 1 minute");
        let rule = AlertRuleInput {
            metric: Some("disk.usage".to_string()),
            series: Some("/".to_string()),
            for_secs: 0,
            ..metric_rule()
        };
        assert_eq!(rule.describe(), "Disk usage (/) above 90%");
    }

    #[test]
    fn a_summary_only_names_the_series_when_there_are_several() {
        let cpu = metric_rule();
        assert_eq!(
            cpu.metric_summary(cpu.metric().unwrap(), "web-1", "CPU", 97.25)
                .unwrap(),
            "CPU usage on web-1 is 97.2%, above 90% for 5 minutes"
        );

        let disk = AlertRuleInput {
            metric: Some("disk.usage".to_string()),
            for_secs: 0,
            ..metric_rule()
        };
        assert_eq!(
            disk.metric_summary(disk.metric().unwrap(), "web-1", "/data", 91.0)
                .unwrap(),
            "Disk usage (/data) on web-1 is 91%, above 90%"
        );
    }

    #[test]
    fn offline_summaries_say_how_long() {
        assert_eq!(
            offline_rule().offline_summary("web-1"),
            "web-1 has been offline for 1 minute"
        );
        let rule = AlertRuleInput {
            for_secs: 0,
            ..offline_rule()
        };
        assert_eq!(rule.offline_summary("web-1"), "web-1 is offline");
    }

    #[test]
    fn what_agents_choose_is_cleaned() {
        assert_eq!(clean("web\r\nBcc: x@y\0"), "webBcc: x@y");
        assert_eq!(clean(&"é".repeat(300)).chars().count(), 255);
    }

    #[test]
    fn durations_use_the_largest_whole_unit() {
        for (secs, text) in [
            (0, "0 seconds"),
            (1, "1 second"),
            (90, "90 seconds"),
            (60, "1 minute"),
            (300, "5 minutes"),
            (3600, "1 hour"),
            (7200, "2 hours"),
            (86_400, "1 day"),
        ] {
            assert_eq!(format_duration(secs), text);
        }
    }

    #[test]
    fn webhooks_need_a_web_address() {
        check_channel(&webhook("https://hooks.example.com/abc")).unwrap();
        check_channel(&webhook("http://10.0.0.1:8080/hook")).unwrap();
        for target in ["", "hooks.example.com", "ftp://x/y", "file:///etc/passwd"] {
            assert!(check_channel(&webhook(target)).is_err(), "{target}");
        }
    }

    fn discord(target: &str) -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Discord,
            ..webhook(target)
        }
    }

    #[test]
    fn discord_channels_need_a_discord_webhook_url() {
        for good in [
            "https://discord.com/api/webhooks/123/token",
            "https://discordapp.com/api/webhooks/123/token",
            "https://canary.discord.com/api/webhooks/123/token",
        ] {
            check_channel(&discord(good)).unwrap();
        }
        for bad in [
            "",
            "http://discord.com/api/webhooks/123/token",
            "https://discord.com/channels/123",
            "https://evil.example.com/api/webhooks/123/token",
            "https://discord.com.evil.example/api/webhooks/1/t",
        ] {
            assert!(check_channel(&discord(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_discord_url_is_treated_as_a_secret() {
        let channel = discord("https://discord.com/api/webhooks/123/secret-token");
        assert_eq!(channel.target_preview(), "https://discord.com/…");

        let error = check_channel(&discord("https://exa mple/secret-token")).unwrap_err();
        assert!(!format!("{error:#}").contains("secret-token"));
    }

    #[test]
    fn a_bad_webhook_url_is_not_repeated_in_the_error() {
        let error = check_channel(&webhook("https://exa mple.com/secret-token")).unwrap_err();
        assert!(!format!("{error:#}").contains("secret-token"));
    }

    #[test]
    fn email_channels_need_valid_addresses() {
        check_channel(&email("a@example.com, b@example.com")).unwrap();
        assert!(check_channel(&email("")).is_err());
        assert!(check_channel(&email(" , ")).is_err());
        assert!(check_channel(&email("not an address")).is_err());
        let many = vec!["a@example.com"; MAX_RECIPIENTS + 1].join(",");
        assert!(check_channel(&email(&many)).is_err());
    }

    #[test]
    fn previews_hide_a_webhooks_path_and_credentials() {
        let channel = webhook("https://user:pass@hooks.example.com/services/secret?key=1");
        assert_eq!(channel.target_preview(), "https://hooks.example.com/…");
        assert_eq!(email("a@example.com").target_preview(), "a@example.com");
    }

    #[test]
    fn channels_can_be_told_apart_from_rules_of_any_length() {
        let long = ChannelInput {
            name: "x".repeat(256),
            ..webhook("https://example.com/")
        };
        assert!(check_channel(&long).is_err());
        let huge = webhook(&format!("https://example.com/{}", "x".repeat(3000)));
        assert!(check_channel(&huge).is_err());
    }
}
