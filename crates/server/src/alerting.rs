//! What alerting is made of: rules that say what to watch, channels that say who
//! to tell, and the alerts that result. [`crate::alert_evaluator`] decides when
//! alerts start and end, and [`crate::notifier`] delivers them.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::http::Uri;
use cel::Program;
use lettre::Address;
use serde::{Deserialize, Serialize};
use wildmatch::WildMatch;

use crate::calculations::{Calculation, Grouping, Question};
use crate::metric_charts::format_value;
use crate::metrics::{self, Metric, Source, Unit};

/// Why an alert ends when its rule goes, however it goes.
pub const RULE_GONE_REASON: &str = "The rule was deleted or disabled";

/// What the database columns hold.
const MAX_NAME_LEN: usize = 255;
const MAX_TARGET_LEN: usize = 2048;

/// A rule can't wait longer than this before firing. It also limits how long a
/// rule can take to resolve, since the two match.
const MAX_FOR_SECS: u64 = 7 * 86_400;

const MAX_RECIPIENTS: usize = 20;

/// A calculation needs a finished minute to look at.
const MIN_WINDOW_SECS: u64 = 60;
const MAX_WINDOW_SECS: u64 = 86_400;
const DEFAULT_WINDOW_SECS: u64 = 300;

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
    /// Something worked out across a group of machines, such as their average CPU.
    Calculation,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metric => "metric",
            Self::Offline => "offline",
            Self::Calculation => "calculation",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "metric" => Ok(Self::Metric),
            "offline" => Ok(Self::Offline),
            "calculation" => Ok(Self::Calculation),
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

/// Mildest first, so the worse of two is the greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// Where the rule's severity starts.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// For a critical rule on a metric or calculation, where it's a warning first.
    /// One alert covers both, at the worse of the two.
    #[serde(default)]
    pub warning_threshold: Option<f64>,
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
    /// Tell every channel instead, including ones added later.
    #[serde(default)]
    pub all_channels: bool,
    /// How to combine machines, for calculation rules.
    #[serde(default)]
    pub calculation: Option<Calculation>,
    /// What's watched separately, for calculation rules, as in a dashboard widget.
    #[serde(default)]
    pub group_by: Option<String>,
    /// Which machines, for calculation rules, as on the host list. Empty is all.
    #[serde(default)]
    pub filter: Option<String>,
    /// How far back a calculation rule looks, so one busy moment isn't a problem.
    #[serde(default)]
    pub window_secs: Option<u64>,
    /// How often to say an alert is still firing, until someone acknowledges it. Never,
    /// if empty. On-call services are left out, as repeating is their job.
    #[serde(default)]
    pub remind_every_secs: Option<u64>,
}

fn default_enabled() -> bool {
    true
}

/// Checks a rule before it's saved. Whether its channels exist is up to the
/// caller, which can see them.
/// Any more often and people stop reading them.
const MIN_REMINDER_SECS: u64 = 300;

pub fn check_rule(rule: &AlertRuleInput) -> Result<()> {
    ensure!(!rule.name.trim().is_empty(), "a rule needs a name");
    ensure!(rule.name.len() <= MAX_NAME_LEN, "the rule name is too long");
    ensure!(
        rule.for_secs <= MAX_FOR_SECS,
        "the duration can't be longer than 7 days"
    );
    ensure!(
        rule.remind_every_secs
            .is_none_or(|secs| secs >= MIN_REMINDER_SECS),
        "reminders can't be more often than every 5 minutes"
    );
    ensure!(
        !(rule.all_channels && !rule.channels.is_empty()),
        "choose every channel or some of them, not both"
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
        RuleKind::Calculation => {
            rule.question().map_err(|error| anyhow!("{error}"))?;
            ensure!(rule.comparison.is_some(), "choose above or below");
            let threshold = rule.threshold.context("a rule needs a threshold")?;
            ensure!(threshold.is_finite(), "the threshold must be a number");
            ensure!(
                (MIN_WINDOW_SECS..=MAX_WINDOW_SECS).contains(&rule.window()),
                "the window has to be between a minute and a day"
            );
            ensure!(
                rule.condition.is_none() && rule.series.is_none(),
                "a calculation picks its machines with a filter"
            );
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
    if let Some(warning) = rule.warning_threshold {
        ensure!(
            rule.kind != RuleKind::Offline,
            "an offline rule doesn't take a warning threshold"
        );
        ensure!(
            warning.is_finite(),
            "the warning threshold must be a number"
        );
        ensure!(
            rule.severity == Severity::Critical,
            "a warning threshold goes with a critical threshold"
        );
        if let (Some(comparison), Some(critical)) = (rule.comparison, rule.threshold) {
            ensure!(
                warning != critical && !comparison.is_breached(warning, critical),
                "the warning threshold has to come before the critical one, so it's {} it",
                match comparison {
                    Comparison::Above => "below",
                    Comparison::Below => "above",
                }
            );
        }
    }
    if rule.kind != RuleKind::Calculation {
        ensure!(
            rule.calculation.is_none()
                && rule.group_by.is_none()
                && rule.filter.is_none()
                && rule.window_secs.is_none(),
            "only a calculation rule takes a calculation, grouping, filter or window"
        );
    }
    Ok(())
}

impl AlertRuleInput {
    /// What a calculation rule asks. The error says what's wrong, to show whoever chose it.
    pub fn question(&self) -> Result<Question, String> {
        Question::new(
            self.metric.as_deref().unwrap_or_default(),
            self.calculation.map_or("", Calculation::as_str),
            self.group_by.as_deref().unwrap_or_default(),
            self.filter.as_deref().unwrap_or_default(),
        )
    }

    /// Each threshold with how bad crossing it is, mildest first. Empty for an
    /// offline rule.
    pub fn levels(&self) -> Vec<(Severity, f64)> {
        let Some(threshold) = self.threshold else {
            return Vec::new();
        };
        let warning = self
            .warning_threshold
            .map(|warning| (Severity::Warning, warning));
        warning
            .into_iter()
            .chain([(self.severity, threshold)])
            .collect()
    }

    fn threshold_for(&self, severity: Severity) -> Result<f64> {
        self.levels()
            .into_iter()
            .find(|(level, _)| *level == severity)
            .map(|(_, threshold)| threshold)
            .with_context(|| format!("no {} threshold", severity.as_str()))
    }

    /// The thresholds, saying which is which when there are two.
    fn thresholds_text(&self, unit: Unit) -> String {
        let levels = self.levels();
        match levels.as_slice() {
            [(_, threshold)] => format_value(unit, *threshold),
            _ => levels
                .iter()
                .map(|(severity, threshold)| {
                    format!("{} ({})", format_value(unit, *threshold), severity.as_str())
                })
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    pub fn window(&self) -> u64 {
        self.window_secs.unwrap_or(DEFAULT_WINDOW_SECS)
    }

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
        let (Some(metric), Some(comparison), Some(_)) =
            (self.metric(), self.comparison, self.threshold)
        else {
            return wait("Offline".to_string());
        };
        if let Ok(question) = self.question() {
            return wait(format!(
                "{} of {} {} {} over {}",
                question.calculation.label(),
                metric.title,
                comparison.as_str(),
                self.thresholds_text(question.unit()),
                format_duration(self.window())
            ));
        }
        let series = match &self.series {
            Some(series) => format!(" ({series})"),
            None => String::new(),
        };
        wait(format!(
            "{}{series} {} {}",
            metric.title,
            comparison.as_str(),
            self.thresholds_text(metric.unit)
        ))
    }

    /// What a metric alert says when it fires, or reaches `severity`.
    pub fn metric_summary(
        &self,
        metric: &Metric,
        host: &str,
        series: &str,
        value: f64,
        severity: Severity,
    ) -> Result<String> {
        let comparison = self.comparison.context("no comparison")?;
        let threshold = self.threshold_for(severity)?;
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

    /// What a calculation alert says when it fires, or reaches `severity`. `line`
    /// is what's being watched.
    pub fn calculation_summary(
        &self,
        question: &Question,
        line: &str,
        value: f64,
        severity: Severity,
    ) -> Result<String> {
        let comparison = self.comparison.context("no comparison")?;
        let threshold = self.threshold_for(severity)?;
        let unit = question.unit();
        let mut summary = format!(
            "{} of {}{} is {}, {} {}",
            question.calculation.label(),
            question.metric.title,
            match question.grouping {
                Grouping::Nothing => String::new(),
                _ => format!(" for {line}"),
            },
            format_value(unit, value),
            comparison.as_str(),
            format_value(unit, threshold)
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
    Slack,
    #[serde(rename = "pagerduty")]
    PagerDuty,
    #[serde(rename = "alertops")]
    AlertOps,
    Signl4,
    Telegram,
}

impl ChannelKind {
    /// Whether it needs a token beside its destination.
    pub fn has_credential(self) -> bool {
        matches!(self, Self::Slack | Self::Telegram)
    }

    /// Whether the service keeps after people itself until someone responds.
    pub fn is_on_call(self) -> bool {
        matches!(self, Self::PagerDuty | Self::AlertOps | Self::Signl4)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Email => "email",
            Self::Discord => "discord",
            Self::Slack => "slack",
            Self::PagerDuty => "pagerduty",
            Self::AlertOps => "alertops",
            Self::Signl4 => "signl4",
            Self::Telegram => "telegram",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "webhook" => Ok(Self::Webhook),
            "email" => Ok(Self::Email),
            "discord" => Ok(Self::Discord),
            "slack" => Ok(Self::Slack),
            "pagerduty" => Ok(Self::PagerDuty),
            "alertops" => Ok(Self::AlertOps),
            "signl4" => Ok(Self::Signl4),
            "telegram" => Ok(Self::Telegram),
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
    /// A webhook's URL, email addresses separated by commas, a Slack channel, a
    /// PagerDuty integration key, the URL AlertOps or SIGNL4 gave out, or a
    /// Telegram chat.
    pub target: String,
    /// Slack's or Telegram's bot token. Like a webhook's URL, it can be set but
    /// not read back.
    #[serde(default)]
    pub credential: Option<String>,
    /// A Slack app's own token, so the server hears its buttons being pressed.
    /// Write-only too.
    #[serde(default)]
    pub app_token: Option<String>,
    /// Which alerts it's sent, so warnings can stay off a pager. A channel hears of
    /// an alert once it reaches one of these, and then of every change until it
    /// resolves.
    #[serde(default = "every_severity")]
    pub severities: BTreeSet<Severity>,
}

pub fn every_severity() -> BTreeSet<Severity> {
    BTreeSet::from([Severity::Warning, Severity::Critical])
}

pub fn check_channel(channel: &ChannelInput) -> Result<()> {
    ensure!(!channel.name.trim().is_empty(), "a channel needs a name");
    ensure!(
        !channel.severities.is_empty(),
        "choose warnings, critical alerts or both"
    );
    ensure!(
        channel.app_token.is_none() || channel.kind == ChannelKind::Slack,
        "only Slack channels take an app-level token"
    );
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
        ChannelKind::Slack => check_slack(channel)?,
        ChannelKind::Telegram => check_telegram(channel)?,
        ChannelKind::PagerDuty => check_pagerduty_key(&channel.target)?,
        ChannelKind::AlertOps => check_service_url(
            &channel.target,
            ".alertops.com",
            "/POSTAlert/",
            "that doesn't look like an AlertOps integration URL, which looks like \
             https://notify.alertops.com/POSTAlert/ followed by its token",
        )?,
        ChannelKind::Signl4 => check_service_url(
            &channel.target,
            ".signl4.com",
            "/webhook/",
            "that doesn't look like a SIGNL4 webhook URL, which is \
             https://connect.signl4.com/webhook/ followed by your secret",
        )?,
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

/// How long PagerDuty's integration keys are.
const PAGERDUTY_KEY_LEN: usize = 32;

/// Says what's wrong without repeating the key, as this ends up on the page.
fn check_pagerduty_key(key: &str) -> Result<()> {
    ensure!(
        key.len() == PAGERDUTY_KEY_LEN && key.chars().all(|c| c.is_ascii_alphanumeric()),
        "that doesn't look like a PagerDuty integration key, which is \
         {PAGERDUTY_KEY_LEN} letters and numbers"
    );
    Ok(())
}

/// Slack's own limit on a channel name, plus its leading `#`.
const MAX_SLACK_CHANNEL_LEN: usize = 81;

fn check_slack(channel: &ChannelInput) -> Result<()> {
    let target = channel.target.trim();
    ensure!(
        !target.is_empty()
            && target.len() <= MAX_SLACK_CHANNEL_LEN
            && !target.contains(char::is_whitespace),
        "enter a Slack channel, such as #alerts or C0123456789"
    );
    let token = channel.credential.as_deref().unwrap_or_default();
    ensure!(
        token.starts_with("xoxb-"),
        "enter the app's bot token, which starts with xoxb-"
    );
    if let Some(token) = &channel.app_token {
        ensure!(
            token.trim().starts_with("xapp-"),
            "the app-level token starts with xapp-. Leave it empty for messages without buttons"
        );
    }
    Ok(())
}

/// Telegram's limits on a public channel's or group's username.
const TELEGRAM_USERNAME_LEN: std::ops::RangeInclusive<usize> = 5..=32;

/// A chat's number, which is negative for groups and channels, or the `@username`
/// of a public one.
fn is_telegram_chat(target: &str) -> bool {
    match target.strip_prefix('@') {
        Some(name) => {
            TELEGRAM_USERNAME_LEN.contains(&name.len())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => target.parse::<i64>().is_ok_and(|id| id != 0),
    }
}

/// The bot's number, a colon, and its secret. Errors don't repeat the token.
fn is_telegram_token(token: &str) -> bool {
    let Some((bot, secret)) = token.split_once(':') else {
        return false;
    };
    !bot.is_empty()
        && bot.chars().all(|c| c.is_ascii_digit())
        && secret.len() >= 30
        && secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn check_telegram(channel: &ChannelInput) -> Result<()> {
    ensure!(
        is_telegram_chat(channel.target.trim()),
        "enter a Telegram chat ID, such as -1001234567890, or a public channel such as \
         @alerts"
    );
    ensure!(
        is_telegram_token(channel.credential.as_deref().unwrap_or_default().trim()),
        "enter the bot token from BotFather, which is a number, a colon, then a long code"
    );
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

/// A URL from an on-call service, which has a secret after `path`. `complaint` is
/// fixed text, as the URL itself mustn't end up on the page.
fn check_service_url(url: &str, domain: &str, path: &str, complaint: &str) -> Result<()> {
    let uri: Uri = url.trim().parse().map_err(|_| anyhow!("{complaint}"))?;
    let secret = uri.path().strip_prefix(path).unwrap_or_default();
    ensure!(
        uri.scheme_str() == Some("https")
            && uri.host().unwrap_or_default().ends_with(domain)
            && !secret.is_empty(),
        "{complaint}"
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
            ChannelKind::Webhook
            | ChannelKind::Discord
            | ChannelKind::AlertOps
            | ChannelKind::Signl4 => webhook_host(&self.target)
                .map_or_else(|_| "Unknown".to_string(), |host| format!("{host}/…")),
            ChannelKind::Email | ChannelKind::Slack | ChannelKind::Telegram => self.target.clone(),
            ChannelKind::PagerDuty => {
                let start = self.target.len().saturating_sub(4);
                format!(
                    "Key ending {}",
                    self.target.get(start..).unwrap_or_default()
                )
            }
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
    /// Who said they're dealing with it.
    pub acknowledged_by: Option<String>,
    pub acknowledged_ms: Option<i64>,
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

/// An open alert becoming a warning or critical, with what it says then.
#[derive(Debug, Clone, PartialEq)]
pub struct SeverityChange {
    pub alert_id: i64,
    pub severity: Severity,
    pub value: Option<f64>,
    pub summary: String,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Firing,
    /// A warning became critical.
    Escalated,
    /// A critical alert went back to being a warning.
    Eased,
    Reminder,
    Resolved,
    Test,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firing => "firing",
            Self::Escalated => "escalated",
            Self::Eased => "eased",
            Self::Reminder => "reminder",
            Self::Resolved => "resolved",
            Self::Test => "test",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "firing" => Ok(Self::Firing),
            "escalated" => Ok(Self::Escalated),
            "eased" => Ok(Self::Eased),
            "reminder" => Ok(Self::Reminder),
            "resolved" => Ok(Self::Resolved),
            other => bail!("unknown event {other:?}"),
        }
    }
}

/// A notification that's due, with what it needs for sending.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivery {
    pub id: i64,
    /// What the service called the notification before this one for the alert.
    pub reply_to: Option<String>,
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
            warning_threshold: None,
            for_secs: 300,
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
            credential: None,
            app_token: None,
            severities: every_severity(),
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
                    remind_every_secs: Some(MIN_REMINDER_SECS - 1),
                    ..metric_rule()
                },
                "every 5 minutes",
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

    fn disk_rule_with_a_warning() -> AlertRuleInput {
        AlertRuleInput {
            metric: Some("disk.usage".to_string()),
            threshold: Some(90.0),
            warning_threshold: Some(80.0),
            ..metric_rule()
        }
    }

    #[test]
    fn a_rule_with_a_warning_describes_both_thresholds_and_says_each_in_its_alerts() {
        let rule = disk_rule_with_a_warning();
        assert_eq!(
            rule.levels(),
            [(Severity::Warning, 80.0), (Severity::Critical, 90.0)]
        );
        assert_eq!(
            rule.describe(),
            "Disk usage above 80% (warning), 90% (critical) for 5 minutes"
        );
        let metric = rule.metric().unwrap();
        assert_eq!(
            rule.metric_summary(metric, "web-1", "/", 85.0, Severity::Warning)
                .unwrap(),
            "Disk usage (/) on web-1 is 85%, above 80% for 5 minutes"
        );
        assert_eq!(
            rule.metric_summary(metric, "web-1", "/", 95.0, Severity::Critical)
                .unwrap(),
            "Disk usage (/) on web-1 is 95%, above 90% for 5 minutes"
        );
        assert_eq!(metric_rule().levels(), [(Severity::Critical, 90.0)]);
        assert!(offline_rule().levels().is_empty());
    }

    #[test]
    fn a_warning_threshold_comes_before_the_critical_one() {
        check_rule(&disk_rule_with_a_warning()).unwrap();
        let below = AlertRuleInput {
            comparison: Some(Comparison::Below),
            threshold: Some(10.0),
            warning_threshold: Some(20.0),
            ..disk_rule_with_a_warning()
        };
        check_rule(&below).unwrap();

        for (rule, expected) in [
            (
                AlertRuleInput {
                    warning_threshold: Some(95.0),
                    ..disk_rule_with_a_warning()
                },
                "below it",
            ),
            (
                AlertRuleInput {
                    warning_threshold: Some(90.0),
                    ..disk_rule_with_a_warning()
                },
                "below it",
            ),
            (
                AlertRuleInput {
                    warning_threshold: Some(5.0),
                    ..below
                },
                "above it",
            ),
            (
                AlertRuleInput {
                    severity: Severity::Warning,
                    ..disk_rule_with_a_warning()
                },
                "goes with a critical threshold",
            ),
            (
                AlertRuleInput {
                    warning_threshold: Some(f64::NAN),
                    ..disk_rule_with_a_warning()
                },
                "must be a number",
            ),
            (
                AlertRuleInput {
                    warning_threshold: Some(1.0),
                    ..offline_rule()
                },
                "offline rule",
            ),
        ] {
            let error = check_rule(&rule).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_summary_only_names_the_series_when_there_are_several() {
        let cpu = metric_rule();
        assert_eq!(
            cpu.metric_summary(
                cpu.metric().unwrap(),
                "web-1",
                "CPU",
                97.25,
                Severity::Critical
            )
            .unwrap(),
            "CPU usage on web-1 is 97.2%, above 90% for 5 minutes"
        );

        let disk = AlertRuleInput {
            metric: Some("disk.usage".to_string()),
            for_secs: 0,
            ..metric_rule()
        };
        assert_eq!(
            disk.metric_summary(
                disk.metric().unwrap(),
                "web-1",
                "/data",
                91.0,
                Severity::Critical
            )
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

    fn of_kind(kind: ChannelKind, target: &str) -> ChannelInput {
        ChannelInput {
            kind,
            ..webhook(target)
        }
    }

    #[test]
    fn an_alertops_url_has_to_look_like_one() {
        for good in [
            "https://notify.alertops.com/POSTAlert/8f14e45f/Custom",
            "https://acme.alertops.com/POSTAlert/8f14e45f/Custom",
        ] {
            check_channel(&of_kind(ChannelKind::AlertOps, good)).unwrap();
        }
        for bad in [
            "http://notify.alertops.com/POSTAlert/8f14e45f/Custom",
            "https://notify.alertops.com/POSTAlert/",
            "https://notify.alertops.com/other/8f14e45f",
            "https://alertops.com.example.org/POSTAlert/8f14e45f",
            "8f14e45f",
        ] {
            assert!(
                check_channel(&of_kind(ChannelKind::AlertOps, bad)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_signl4_url_has_to_look_like_one() {
        check_channel(&of_kind(
            ChannelKind::Signl4,
            "https://connect.signl4.com/webhook/abc123",
        ))
        .unwrap();
        for bad in [
            "http://connect.signl4.com/webhook/abc123",
            "https://connect.signl4.com/webhook/",
            "https://connect.signl4.com/api/abc123",
            "https://signl4.com.example.org/webhook/abc123",
            "abc123",
        ] {
            assert!(
                check_channel(&of_kind(ChannelKind::Signl4, bad)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_refused_service_url_is_not_repeated() {
        for kind in [ChannelKind::AlertOps, ChannelKind::Signl4] {
            for bad in [
                "https://exa mple/secret-token",
                "https://example.com/secret-token",
            ] {
                let error = check_channel(&of_kind(kind, bad)).unwrap_err();
                assert!(!error.to_string().contains("secret-token"), "{error}");
            }
        }
    }

    fn slack(target: &str, token: Option<&str>) -> ChannelInput {
        ChannelInput {
            kind: ChannelKind::Slack,
            credential: token.map(String::from),
            ..webhook(target)
        }
    }

    #[test]
    fn slack_channels_need_a_channel_and_a_bot_token() {
        check_channel(&slack("#alerts", Some("xoxb-1"))).unwrap();
        check_channel(&slack("C0123456789", Some("xoxb-1"))).unwrap();

        for bad in [
            slack("", Some("xoxb-1")),
            slack("two words", Some("xoxb-1")),
            slack(&"x".repeat(82), Some("xoxb-1")),
            slack("#alerts", None),
            slack("#alerts", Some("xoxp-user-token")),
            slack("#alerts", Some("https://hooks.slack.com/services/x")),
        ] {
            assert!(check_channel(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_app_level_token_is_only_for_slack_and_must_look_right() {
        let with = |kind: ChannelInput, token: &str| ChannelInput {
            app_token: Some(token.to_string()),
            ..kind
        };
        check_channel(&with(slack("#alerts", Some("xoxb-1")), "xapp-1-A1-abc")).unwrap();
        assert!(check_channel(&with(slack("#alerts", Some("xoxb-1")), "xoxb-2")).is_err());
        assert!(
            check_channel(&with(
                discord("https://discord.com/api/webhooks/1/t"),
                "xapp-1"
            ))
            .is_err()
        );
    }

    #[test]
    fn a_slack_channel_is_shown_but_its_token_is_not() {
        let channel = slack("#alerts", Some("xoxb-secret"));
        assert_eq!(channel.target_preview(), "#alerts");
    }

    fn telegram(target: &str, token: Option<&str>) -> ChannelInput {
        ChannelInput {
            name: "Telegram".to_string(),
            kind: ChannelKind::Telegram,
            target: target.to_string(),
            credential: token.map(str::to_string),
            app_token: None,
            severities: every_severity(),
        }
    }

    const TELEGRAM_TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

    #[test]
    fn telegram_channels_need_a_chat_and_a_bot_token() {
        for chat in ["-1001234567890", "123456789", "@alerts_room"] {
            check_channel(&telegram(chat, Some(TELEGRAM_TOKEN))).unwrap();
        }
        for bad in [
            telegram("", Some(TELEGRAM_TOKEN)),
            telegram("0", Some(TELEGRAM_TOKEN)),
            telegram("#alerts", Some(TELEGRAM_TOKEN)),
            telegram("@abc", Some(TELEGRAM_TOKEN)),
            telegram("@has space", Some(TELEGRAM_TOKEN)),
            telegram("https://t.me/alerts", Some(TELEGRAM_TOKEN)),
            telegram("-100123", None),
            telegram("-100123", Some("xoxb-1")),
            telegram("-100123", Some("123456789:short")),
            telegram("-100123", Some("bot:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw")),
        ] {
            assert!(check_channel(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_telegram_chat_is_shown_but_its_token_is_not() {
        let channel = telegram("-1001234567890", Some(TELEGRAM_TOKEN));
        assert_eq!(channel.target_preview(), "-1001234567890");
        let error = check_channel(&telegram("-100123", Some("123:wrong-secret")))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("wrong-secret"), "{error}");
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
