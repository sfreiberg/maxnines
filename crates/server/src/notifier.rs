//! Delivers notifications from the queue. Deliveries are at least once: a crash
//! between sending and saving sends it again, so webhooks carry an ID to spot that.
//! What each kind of channel does is in [`crate::channels`].

use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use futures_util::FutureExt;
use serde::Serialize;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, timeout};
use tracing::{error, info, warn};

use crate::alert_charts::ChartSources;
use crate::alerting::{Alert, Channel, Delivery, Event};
use crate::channels::{self, pagerduty, resend, telegram};
use crate::metrics::now_ms;
use crate::models::Database;
use crate::silences::ActiveSilences;

/// How often the queue is checked.
const INTERVAL: Duration = Duration::from_secs(5);

/// How many deliveries run at once, which also limits how many a pass can take.
const BATCH_SIZE: usize = 16;

/// How long one delivery can take, however many requests it makes.
const DELIVERY_LIMIT: Duration = Duration::from_secs(60);

const FIRST_RETRY_MS: i64 = 30_000;
const LONGEST_RETRY_MS: i64 = 30 * 60_000;

/// After this, a notification is too old to be useful and shows as failed.
const GIVE_UP_AFTER_MS: i64 = 24 * 3_600_000;

/// Doubles each time, up to a limit.
fn retry_delay_ms(attempts: i32) -> i64 {
    let doublings = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or(0)
        .min(16);
    (FIRST_RETRY_MS << doublings).min(LONGEST_RETRY_MS)
}

/// What a notification says, in the form every channel starts from.
#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    /// The same for every attempt, so a receiver can spot a repeat.
    pub id: i64,
    pub event: Event,
    pub alert: Option<Alert>,
    /// One line in plain words.
    pub text: String,
    /// A PNG of the last hour, for channels that show pictures.
    #[serde(skip)]
    pub chart: Option<Arc<Vec<u8>>>,
}

impl Notice {
    pub fn for_delivery(delivery: &Delivery) -> Self {
        Self {
            id: delivery.id,
            ..Self::for_alert(delivery.alert.clone(), delivery.event)
        }
    }

    /// What a message about this alert says, outside the queue.
    pub fn for_alert(alert: Alert, event: Event) -> Self {
        let text = match event {
            Event::Escalated => format!("Now critical: {}", alert.summary),
            Event::Eased => format!("Down to a warning: {}", alert.summary),
            Event::Reminder => format!("Still firing: {}", alert.summary),
            Event::Resolved => format!("Resolved: {}", alert.summary),
            _ => alert.summary.clone(),
        };
        Self {
            id: 0,
            event,
            alert: Some(alert),
            text,
            chart: None,
        }
    }

    pub fn test() -> Self {
        Self {
            id: 0,
            event: Event::Test,
            alert: None,
            text: "This is a test notification from MaxNines.".to_string(),
            chart: None,
        }
    }

    /// Words for whoever can't see the chart.
    pub(crate) fn chart_description(&self) -> String {
        let summary = self
            .alert
            .as_ref()
            .map_or(self.text.as_str(), |a| &a.summary);
        format!("The last hour: {summary}")
    }

    /// What happened, in a word or two, which every message starts with.
    pub(crate) fn label(&self) -> String {
        match (self.event, &self.alert) {
            (Event::Firing, Some(alert)) => alert.severity.as_str().to_uppercase(),
            (Event::Escalated, _) => "NOW CRITICAL".to_string(),
            (Event::Eased, _) => "NOW WARNING".to_string(),
            (Event::Reminder, _) => "STILL FIRING".to_string(),
            (Event::Resolved, _) => "RESOLVED".to_string(),
            _ => "TEST".to_string(),
        }
    }
}

pub fn format_ms(ms: i64) -> String {
    u64::try_from(ms).map_or_else(
        |_| ms.to_string(),
        |ms| crate::times::format_time(ms, chrono_tz::Tz::UTC),
    )
}

/// What sending needs beyond the channel itself.
#[derive(Clone, Default)]
pub struct Senders {
    /// Where people reach this server's pages, for links in messages.
    pub web_url: Option<String>,
    /// Where to find a stand-in for Slack.
    #[cfg(test)]
    pub slack_api_url: Option<String>,
    /// Where to find a stand-in for PagerDuty.
    #[cfg(test)]
    pub pagerduty_url: Option<String>,
    /// Where to find a stand-in for Telegram.
    #[cfg(test)]
    pub telegram_api_url: Option<String>,
    /// Where to find a stand-in for Resend.
    #[cfg(test)]
    pub resend_url: Option<String>,
}

impl Senders {
    pub fn new(web_url: Option<String>) -> Self {
        Self {
            web_url,
            #[cfg(test)]
            slack_api_url: None,
            #[cfg(test)]
            pagerduty_url: None,
            #[cfg(test)]
            telegram_api_url: None,
            #[cfg(test)]
            resend_url: None,
        }
    }

    #[cfg(not(test))]
    pub(crate) fn telegram_api_url(&self) -> &str {
        telegram::API_URL
    }

    #[cfg(test)]
    pub(crate) fn telegram_api_url(&self) -> &str {
        self.telegram_api_url
            .as_deref()
            .unwrap_or(telegram::API_URL)
    }

    #[cfg(not(test))]
    pub(crate) fn resend_url(&self) -> &str {
        resend::EMAILS_URL
    }

    #[cfg(test)]
    pub(crate) fn resend_url(&self) -> &str {
        self.resend_url.as_deref().unwrap_or(resend::EMAILS_URL)
    }

    #[cfg(not(test))]
    pub(crate) fn pagerduty_url(&self) -> &str {
        pagerduty::EVENTS_URL
    }

    #[cfg(test)]
    pub(crate) fn pagerduty_url(&self) -> &str {
        self.pagerduty_url
            .as_deref()
            .unwrap_or(pagerduty::EVENTS_URL)
    }
}

/// The address behind the one agents connect to, for links to the web pages.
pub fn web_url(agent_url: impl AsRef<str>) -> Option<String> {
    let agent_url = agent_url.as_ref();
    let (scheme, rest) = agent_url.split_once("://")?;
    let scheme = match scheme {
        "wss" => "https",
        "ws" => "http",
        _ => return None,
    };
    let hostname = rest
        .split('/')
        .next()
        .filter(|hostname| !hostname.is_empty())?;
    Some(format!("{scheme}://{hostname}"))
}

/// Sends one notification, and gives what the service called it if that matters
/// later. A panic or a hang counts as a failed delivery, whichever channel it is, so
/// one delivery can't stop the rest of a pass or be retried straight away.
pub async fn send(
    channel: Channel,
    notice: Notice,
    reply_to: Option<String>,
    senders: Senders,
) -> Result<Option<String>> {
    let kind = channels::of(channel.channel.kind);
    let sending = kind.send(&channel, &notice, reply_to.as_deref(), &senders);
    guarded(kind.name(), DELIVERY_LIMIT, sending).await
}

/// Whether a notification goes with a chart: an alert starting or getting worse,
/// on a channel that shows pictures.
fn shows_chart(delivery: &Delivery) -> bool {
    matches!(delivery.event, Event::Firing | Event::Escalated)
        && channels::of(delivery.channel.channel.kind).shows_charts()
}

/// Runs a send with a time limit, turning a panic into an ordinary failure.
async fn guarded<T>(
    who: &str,
    limit: Duration,
    sending: impl Future<Output = Result<T>>,
) -> Result<T> {
    match timeout(limit, AssertUnwindSafe(sending).catch_unwind()).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(anyhow!("sending to {who} failed unexpectedly")),
        Err(_) => Err(anyhow!("{who} timed out")),
    }
}

#[derive(Clone)]
pub struct Notifier {
    database: Database,
    senders: Senders,
    /// Where charts come from, for channels that show them.
    charts: Option<Arc<ChartSources>>,
}

impl Notifier {
    pub fn new(database: Database, senders: Senders) -> Self {
        Self {
            database,
            senders,
            charts: None,
        }
    }

    /// Sends charts with alerts to the channels that show them.
    pub fn with_charts(mut self, charts: ChartSources) -> Self {
        self.charts = Some(Arc::new(charts));
        self
    }

    /// The chart for a delivery, if it gets one. Drawing one is never a reason not
    /// to send the notification.
    async fn chart_for(&self, delivery: &Delivery, now_ms: i64) -> Option<Arc<Vec<u8>>> {
        let charts = self.charts.as_ref()?;
        if !shows_chart(delivery) {
            return None;
        }
        match charts.draw(&delivery.alert, now_ms).await {
            Ok(chart) => chart.map(Arc::new),
            Err(error) => {
                warn!(
                    alert = delivery.alert.id,
                    error = format!("{error:#}"),
                    "couldn't draw a chart for an alert"
                );
                None
            }
        }
    }

    /// Runs until the server stops. Each pass is its own task, so a panic costs
    /// that pass and the next one starts as usual.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(INTERVAL);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                let notifier = self.clone();
                let pass = tokio::spawn(async move { notifier.deliver_due(now_ms()).await });
                match pass.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        error!(
                            error = format!("{error:#}"),
                            "delivering notifications failed"
                        );
                    }
                    Err(error) => error!(%error, "delivering notifications panicked"),
                }
            }
        })
    }

    /// Lets go of what no silence covers any more. Something held for an alert
    /// that has since ended is dropped instead: the alert ended in the moment
    /// between the queue being read and the hold, and nobody needs to hear of it.
    async fn release_held(&self, silences: &ActiveSilences, now_ms: i64) -> Result<()> {
        let mut ids = Vec::new();
        for (alert, held) in self.database.held_deliveries().await? {
            if alert.resolved_ms.is_some() {
                self.database.drop_held_for(alert.id).await?;
            } else if silences.covering(&alert).is_none() {
                ids.extend(held);
            }
        }
        if !ids.is_empty() {
            self.database.release_deliveries(&ids, now_ms).await?;
        }
        Ok(())
    }

    /// Whether a reminder queued a moment ago still has a point.
    fn reminder_is_stale(delivery: &Delivery, silences: &ActiveSilences) -> bool {
        let alert = &delivery.alert;
        alert.resolved_ms.is_some()
            || alert.acknowledged_ms.is_some()
            || silences.covering(alert).is_some()
    }

    async fn queue_reminders(&self, silences: &ActiveSilences, now_ms: i64) -> Result<()> {
        let alerts: Vec<(i64, i64)> = self
            .database
            .alerts_to_remind()
            .await?
            .into_iter()
            .filter(|(alert, _)| silences.covering(alert).is_none())
            .map(|(alert, every_secs)| (alert.id, every_secs))
            .collect();
        self.database.queue_reminders(&alerts, now_ms).await
    }

    /// Sends what's due, and saves how each one went. Someone who was told an alert
    /// started always hears that it ended, or an on-call incident would stay open.
    pub async fn deliver_due(&self, now_ms: i64) -> Result<()> {
        let silences = ActiveSilences::load(&self.database, now_ms).await?;
        self.release_held(&silences, now_ms).await?;
        self.queue_reminders(&silences, now_ms).await?;
        let due = self.database.due_deliveries(now_ms, BATCH_SIZE).await?;

        let mut sends = JoinSet::new();
        // Each chart is drawn once a pass, however many channels it goes to.
        let mut charts: HashMap<(i64, Event), Option<Arc<Vec<u8>>>> = HashMap::new();
        for delivery in due {
            let tells_of_a_problem = matches!(
                delivery.event,
                Event::Firing | Event::Escalated | Event::Eased
            );
            if tells_of_a_problem && silences.covering(&delivery.alert).is_some() {
                self.database.hold_delivery(&delivery).await?;
                continue;
            }
            if delivery.event == Event::Reminder && Self::reminder_is_stale(&delivery, &silences) {
                self.database.drop_delivery(delivery.id).await?;
                continue;
            }
            let chart = if shows_chart(&delivery) {
                let key = (delivery.alert.id, delivery.event);
                match charts.get(&key) {
                    Some(drawn) => drawn.clone(),
                    None => {
                        let drawn = self.chart_for(&delivery, now_ms).await;
                        charts.insert(key, drawn.clone());
                        drawn
                    }
                }
            } else {
                None
            };
            let senders = self.senders.clone();
            sends.spawn(async move {
                let notice = Notice {
                    chart,
                    ..Notice::for_delivery(&delivery)
                };
                let reply_to = delivery.reply_to.clone();
                let result = send(delivery.channel.clone(), notice, reply_to, senders).await;
                (delivery, result)
            });
        }

        while let Some(finished) = sends.join_next().await {
            match finished {
                Ok((delivery, result)) => self.record(&delivery, result, now_ms).await?,
                // The rest of the batch still gets recorded.
                Err(error) => error!(%error, "a delivery stopped unexpectedly"),
            }
        }
        Ok(())
    }

    async fn record(
        &self,
        delivery: &Delivery,
        result: Result<Option<String>>,
        now_ms: i64,
    ) -> Result<()> {
        let attempts = delivery.attempts.saturating_add(1);
        let channel = &delivery.channel.channel.name;
        match result {
            Ok(external_id) => {
                info!(
                    channel,
                    event = delivery.event.as_str(),
                    "notification sent"
                );
                self.database
                    .delivery_sent(delivery.id, attempts, now_ms, external_id.as_deref())
                    .await
            }
            Err(error) => {
                let message = format!("{error:#}");
                let next = (now_ms - delivery.created_ms < GIVE_UP_AFTER_MS)
                    .then(|| now_ms + retry_delay_ms(attempts));
                warn!(
                    channel,
                    attempts,
                    error = message,
                    gave_up = next.is_none(),
                    "notification failed"
                );
                self.database
                    .delivery_failed(delivery.id, attempts, &message, next)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::testing::{alert, notice};

    #[tokio::test]
    async fn a_send_that_panics_or_hangs_is_an_ordinary_failure() {
        let panicking = async { panic!("deliberate test panic") };
        let error = guarded::<()>("Slack", Duration::from_secs(1), panicking)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "sending to Slack failed unexpectedly");

        let hanging = std::future::pending::<Result<()>>();
        let error = guarded("Slack", Duration::from_millis(10), hanging)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Slack timed out");

        let fine = async { Ok(Some("id".to_string())) };
        let sent = guarded("Slack", Duration::from_secs(1), fine)
            .await
            .unwrap();
        assert_eq!(sent.as_deref(), Some("id"));
    }

    #[test]
    fn retries_slow_down_up_to_a_limit() {
        assert_eq!(retry_delay_ms(1), 30_000);
        assert_eq!(retry_delay_ms(2), 60_000);
        assert_eq!(retry_delay_ms(3), 120_000);
        assert_eq!(retry_delay_ms(7), LONGEST_RETRY_MS);
        assert_eq!(retry_delay_ms(i32::MAX), LONGEST_RETRY_MS);
        assert_eq!(retry_delay_ms(0), 30_000);
    }

    #[test]
    fn links_use_the_address_agents_connect_to() {
        assert_eq!(
            web_url("wss://monitor.example.com/ws").as_deref(),
            Some("https://monitor.example.com")
        );
        assert_eq!(
            web_url("ws://127.0.0.1:9000/ws").as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert_eq!(web_url("nonsense"), None);
        assert_eq!(web_url("ftp://x/y"), None);
    }

    #[test]
    fn a_change_of_severity_says_which_way_it_went() {
        assert_eq!(
            Notice::for_alert(alert(), Event::Escalated).text,
            "Now critical: CPU usage on web-1 is 97%, above 90%"
        );
        let warning = Alert {
            summary: "CPU usage on web-1 is 85%, above 80%".to_string(),
            ..alert()
        };
        assert_eq!(
            Notice::for_alert(warning, Event::Eased).text,
            "Down to a warning: CPU usage on web-1 is 85%, above 80%"
        );
        assert_eq!(notice(Event::Escalated, alert()).label(), "NOW CRITICAL");
        assert_eq!(notice(Event::Eased, alert()).label(), "NOW WARNING");
    }
}
