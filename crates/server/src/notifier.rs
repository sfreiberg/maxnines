//! Delivers notifications from the queue. Deliveries are at least once: a crash
//! between sending and saving sends it again, so webhooks carry an ID to spot that.
//! What each kind of channel does is in [`crate::channels`].

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use chrono::TimeDelta;
use futures_util::FutureExt;
use maxnines_protocol::actions::ActionOutcome;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, timeout};
use tracing::{error, info, warn};

use crate::actions::ActionRun;
use crate::alert_charts::ChartSources;
use crate::alerting::{Alert, Channel, Delivery, Event, PagerDutyRegion, Severity};
use crate::channels::{self, pagerduty, resend, telegram};
use crate::models::{Database, Told};
use crate::silences::ActiveSilences;
use crate::times::Timestamp;

/// How often the queue is checked.
const INTERVAL: Duration = Duration::from_secs(5);

/// How many deliveries run at once, which also limits how many a pass can take.
const BATCH_SIZE: usize = 16;

/// How long one delivery can take, however many requests it makes.
const DELIVERY_LIMIT: Duration = Duration::from_secs(60);

const FIRST_RETRY: TimeDelta = TimeDelta::seconds(30);
const LONGEST_RETRY: TimeDelta = TimeDelta::minutes(30);

/// After this, a notification is too old to be useful and shows as failed.
const GIVE_UP_AFTER: TimeDelta = TimeDelta::hours(24);

/// Doubles each time, up to a limit.
fn retry_delay(attempts: i32) -> TimeDelta {
    let doublings = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or(0)
        .min(16);
    (FIRST_RETRY * 2_i32.pow(doublings)).min(LONGEST_RETRY)
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
    /// The run this is about, when it says what one of the alert's actions
    /// printed.
    #[serde(skip)]
    pub action: Option<ActionRun>,
}

/// What an action printed, as much of it as a message has room for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Printed {
    pub text: String,
    /// Whether there was more, which the alert's Actions page has.
    pub cut: bool,
}

impl Notice {
    pub fn for_delivery(delivery: &Delivery) -> Self {
        let notice = match &delivery.action {
            Some(run) => Self::for_action(delivery.alert.clone(), run.clone()),
            None => Self::for_alert(delivery.alert.clone(), delivery.event),
        };
        Self {
            id: delivery.id,
            ..notice
        }
    }

    /// What a message about one of an alert's actions says: how it went, in a
    /// line, with what it printed for the channel to show as it can.
    pub fn for_action(alert: Alert, run: ActionRun) -> Self {
        let how = match run.outcome {
            Some(ActionOutcome::Succeeded) => "ran",
            Some(ActionOutcome::Failed) => "failed",
            Some(ActionOutcome::TimedOut) => "ran out of time",
            Some(ActionOutcome::NotDefined | ActionOutcome::Refused) | None => "wasn't run",
        };
        let mut text = format!("{} {how} on {}", run.action, alert.hostname);
        match (&run.error, run.exit_code) {
            (Some(error), _) => text.push_str(&format!(": {error}")),
            (None, Some(code)) if code != 0 => text.push_str(&format!(": exit status {code}")),
            _ => {}
        }
        Self {
            id: 0,
            event: Event::Action,
            alert: Some(alert),
            text,
            chart: None,
            action: Some(run),
        }
    }

    /// What a message about this alert says, outside the queue.
    pub fn for_alert(alert: Alert, event: Event) -> Self {
        let text = match event {
            Event::Escalated => format!("Now critical: {}", alert.summary),
            Event::Eased => format!("Down to a warning: {}", alert.summary),
            Event::Reminder => format!("Still firing: {}", alert.summary),
            Event::Resolved => format!("Resolved: {}", said_as(&alert, event)),
            _ => alert.summary.clone(),
        };
        Self {
            id: 0,
            event,
            alert: Some(alert),
            text,
            chart: None,
            action: None,
        }
    }

    pub fn test() -> Self {
        Self {
            id: 0,
            event: Event::Test,
            alert: None,
            text: "This is a test notification from MaxNines.".to_string(),
            chart: None,
            action: None,
        }
    }

    /// What it's about, in a sentence: what's wrong, or how an action went.
    pub(crate) fn summary(&self) -> &str {
        match (&self.action, &self.alert) {
            (None, Some(alert)) => said_as(alert, self.event),
            _ => &self.text,
        }
    }

    /// What it said when it fired, for a resolved notification that leads with
    /// where things stand now instead. Nothing for any other.
    pub(crate) fn fired_summary(&self) -> Option<&str> {
        let alert = self.alert.as_ref()?;
        (self.event == Event::Resolved && alert.resolved_summary.is_some())
            .then_some(alert.summary.as_str())
    }

    /// What the action printed, up to `max` characters, ending at the end of a
    /// line where it can. Nothing for other notifications, or if it printed
    /// nothing.
    pub(crate) fn printed(&self, max: usize) -> Option<Printed> {
        let run = self.action.as_ref()?;
        let all = run.output.trim_end();
        if all.is_empty() {
            return None;
        }
        let mut text: String = all.chars().take(max).collect();
        let cut = text.len() < all.len();
        if cut && let Some(end) = text.rfind('\n').filter(|end| *end > 0) {
            text.truncate(end);
        }
        Some(Printed {
            text,
            cut: cut || run.truncated,
        })
    }

    /// The run as webhooks get it, or null when this isn't about one.
    pub(crate) fn action_fields(&self) -> Value {
        let Some(run) = &self.action else {
            return Value::Null;
        };
        json!({
            "id": run.id,
            "name": run.action,
            "run_on": run.run_on,
            "outcome": run.outcome,
            "exit_code": run.exit_code,
            "error": run.error,
            "output": run.output,
            "truncated": run.truncated,
            "duration_secs": run.duration.map(|duration| duration.as_secs_f64()),
        })
    }

    /// Where all of what the action printed is, for a message that had to cut it.
    /// Where to look: the alert's own page, with its chart, for a notice about one,
    /// and the alerts page for one about none, such as a test.
    pub(crate) fn link(&self, web_url: &str) -> String {
        match &self.alert {
            Some(alert) => format!("{web_url}/alerts/{}", alert.id),
            None => crate::channels::alerts_link(web_url),
        }
    }

    /// What the link to [`Self::link`] says.
    pub(crate) fn link_label(&self) -> &'static str {
        match &self.alert {
            Some(_) => "View alert",
            None => "View alerts",
        }
    }

    pub(crate) fn actions_link(&self, web_url: &str) -> Option<String> {
        let alert = self.alert.as_ref()?;
        self.action
            .as_ref()
            .map(|_| format!("{web_url}/alerts/{}/actions", alert.id))
    }

    /// Words for whoever can't see the chart.
    pub(crate) fn chart_description(&self) -> String {
        let summary = self
            .alert
            .as_ref()
            .map_or(self.text.as_str(), |a| said_as(a, self.event));
        format!("The last hour: {summary}")
    }

    /// How bad things are now, for channels that show it as a colour.
    pub(crate) fn tone(&self) -> Tone {
        match (self.event, &self.alert) {
            (Event::Escalated, _) => Tone::Critical,
            (Event::Eased, _) => Tone::Warning,
            (Event::Firing | Event::Reminder, Some(alert))
                if alert.severity == Severity::Critical =>
            {
                Tone::Critical
            }
            (Event::Firing | Event::Reminder, Some(_)) => Tone::Warning,
            (Event::Resolved, _) => Tone::Clear,
            _ => Tone::Neutral,
        }
    }

    /// What happened, in a word or two, which every message starts with.
    pub(crate) fn label(&self) -> String {
        match (self.event, &self.alert) {
            (Event::Firing, Some(alert)) => alert.severity.as_str().to_uppercase(),
            (Event::Escalated, _) => "NOW CRITICAL".to_string(),
            (Event::Eased, _) => "NOW WARNING".to_string(),
            (Event::Reminder, _) => "STILL FIRING".to_string(),
            (Event::Resolved, _) => "RESOLVED".to_string(),
            (Event::Action, _) => "ACTION".to_string(),
            (Event::Acknowledged, _) => "ACKNOWLEDGED".to_string(),
            _ => "TEST".to_string(),
        }
    }
}

/// How bad a notification is: red, yellow, green, or grey for a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    Critical,
    Warning,
    Clear,
    Neutral,
}

/// What an alert says in a notification about `event`: where things stand now once
/// the problem's cleared, and otherwise what's wrong.
fn said_as(alert: &Alert, event: Event) -> &str {
    match (event, &alert.resolved_summary) {
        (Event::Resolved, Some(now)) => now,
        _ => &alert.summary,
    }
}

/// A time in a message, which has no one person reading it, so is in UTC.
pub fn format_utc(time: Timestamp) -> String {
    crate::times::format_moment(time, chrono_tz::Tz::UTC)
}

/// What sending needs beyond the channel itself.
#[derive(Clone, Default)]
pub struct Senders {
    /// Where people reach this server's pages, for links in messages.
    pub web_url: Option<String>,
    /// Where to find a stand-in for Slack.
    #[cfg(test)]
    pub slack_api_url: Option<String>,
    /// Where to find a stand-in for PagerDuty's US service region.
    #[cfg(test)]
    pub pagerduty_url: Option<String>,
    /// Where to find a stand-in for PagerDuty's EU service region.
    #[cfg(test)]
    pub pagerduty_eu_url: Option<String>,
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
            pagerduty_eu_url: None,
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
    pub(crate) fn pagerduty_url(&self, region: PagerDutyRegion) -> &str {
        pagerduty::events_url(region)
    }

    #[cfg(test)]
    pub(crate) fn pagerduty_url(&self, region: PagerDutyRegion) -> &str {
        let stand_in = match region {
            PagerDutyRegion::Us => &self.pagerduty_url,
            PagerDutyRegion::Eu => &self.pagerduty_eu_url,
        };
        stand_in.as_deref().unwrap_or(pagerduty::events_url(region))
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

/// Whether a notification goes with a chart: an alert starting, getting worse or
/// ending, on a channel that shows pictures.
fn shows_chart(delivery: &Delivery) -> bool {
    matches!(
        delivery.event,
        Event::Firing | Event::Escalated | Event::Resolved
    ) && channels::of(delivery.channel.channel.kind).shows_charts()
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

/// An alert's chart, drawn by the first send of a pass that needs it, for the rest
/// to use too: nothing if there's none to draw.
type SharedChart = OnceCell<Option<Arc<Vec<u8>>>>;

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
    async fn chart_for(&self, delivery: &Delivery, now: Timestamp) -> Option<Arc<Vec<u8>>> {
        let charts = self.charts.as_ref()?;
        if !shows_chart(delivery) {
            return None;
        }
        match charts.draw(&delivery.alert, now).await {
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
                let pass =
                    tokio::spawn(async move { notifier.deliver_due(crate::times::now()).await });
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
    async fn release_held(&self, silences: &ActiveSilences, now: Timestamp) -> Result<()> {
        let mut ids = Vec::new();
        for (alert, held) in self.database.held_deliveries().await? {
            if alert.resolved_at.is_some() {
                self.database.drop_held_for(alert.id).await?;
            } else if silences.covering(&alert).is_none() {
                ids.extend(held);
            }
        }
        if !ids.is_empty() {
            self.database.release_deliveries(&ids, now).await?;
        }
        Ok(())
    }

    /// Whether a reminder queued a moment ago still has a point.
    fn reminder_is_stale(delivery: &Delivery, silences: &ActiveSilences) -> bool {
        let alert = &delivery.alert;
        alert.resolved_at.is_some()
            || alert.acknowledged_at.is_some()
            || silences.covering(alert).is_some()
    }

    async fn queue_reminders(&self, silences: &ActiveSilences, now: Timestamp) -> Result<()> {
        let alerts: Vec<(i64, TimeDelta)> = self
            .database
            .alerts_to_remind()
            .await?
            .into_iter()
            .filter(|(alert, _)| silences.covering(alert).is_none())
            .map(|(alert, every)| (alert.id, every))
            .collect();
        self.database.queue_reminders(&alerts, now).await
    }

    /// Acknowledges the incidents of alerts a silence has started covering, as that
    /// is what stops an on-call service paging people. It isn't resolved, as the
    /// problem isn't fixed. Each pass compares the silences running with the open
    /// alerts anyway, so this is where one starting covering an alert is noticed,
    /// whether it was just added or is a maintenance window coming round.
    async fn acknowledge_silenced(&self, silences: &ActiveSilences, now: Timestamp) -> Result<()> {
        if silences.is_empty() {
            return Ok(());
        }
        let incidents: Vec<(i64, BTreeSet<i64>)> = self
            .database
            .unacknowledged_incidents()
            .await?
            .into_iter()
            .filter(|(alert, _)| silences.covering(alert).is_some())
            .map(|(alert, channels)| (alert.id, channels))
            .collect();
        self.database.acknowledge_incidents(&incidents, now).await
    }

    /// Sends what's due, and saves how each one went. Someone who was told an alert
    /// started always hears that it ended, or an on-call incident would stay open.
    pub async fn deliver_due(&self, now: Timestamp) -> Result<()> {
        let silences = ActiveSilences::load(&self.database, now).await?;
        self.release_held(&silences, now).await?;
        self.queue_reminders(&silences, now).await?;
        self.acknowledge_silenced(&silences, now).await?;
        let due = self.database.due_deliveries(now, BATCH_SIZE).await?;

        let mut sends = JoinSet::new();
        // Each chart is drawn once a pass, however many channels it goes to, by the
        // first send that needs it, so sends start at once and draw side by side.
        let mut charts: HashMap<(i64, Event), Arc<SharedChart>> = HashMap::new();
        for delivery in due {
            // What an action printed is about the problem too.
            let tells_of_a_problem = matches!(
                delivery.event,
                Event::Firing | Event::Escalated | Event::Eased | Event::Action
            );
            if tells_of_a_problem && silences.covering(&delivery.alert).is_some() {
                self.database.hold_delivery(&delivery).await?;
                continue;
            }
            if delivery.event == Event::Reminder && Self::reminder_is_stale(&delivery, &silences) {
                self.database.drop_delivery(delivery.id).await?;
                continue;
            }
            // An incident can only be acknowledged once it's open. One whose
            // opening a silence is holding back waits with it, and one that never
            // opened has nothing to acknowledge.
            if delivery.event == Event::Acknowledged {
                let told = self
                    .database
                    .told_started(delivery.alert.id, delivery.channel.id)
                    .await?;
                match told {
                    Told::Yes => {}
                    Told::NotYet => {
                        self.database.hold_delivery(&delivery).await?;
                        continue;
                    }
                    Told::Never => {
                        self.database.drop_delivery(delivery.id).await?;
                        continue;
                    }
                }
            }
            let chart = shows_chart(&delivery).then(|| {
                let key = (delivery.alert.id, delivery.event);
                charts.entry(key).or_default().clone()
            });
            let senders = self.senders.clone();
            let notifier = self.clone();
            sends.spawn(async move {
                let chart = match chart {
                    Some(chart) => {
                        let drawing = notifier.chart_for(&delivery, now);
                        chart.get_or_init(|| drawing).await.clone()
                    }
                    None => None,
                };
                let notice = Notice {
                    chart,
                    ..Notice::for_delivery(&delivery)
                };
                let reply_to = delivery.reply_to.clone();
                let result = send(delivery.channel.clone(), notice, reply_to, senders).await;
                (delivery, result)
            });
        }

        // Every send that finishes is recorded, whatever happens to the others, or
        // one that arrived would be sent again.
        let mut unrecorded = 0;
        while let Some(finished) = sends.join_next().await {
            match finished {
                Ok((delivery, result)) => {
                    if let Err(error) = self.record(&delivery, result, now).await {
                        let error = format!("{error:#}");
                        error!(error, "recording how a notification went failed");
                        unrecorded += 1;
                    }
                }
                Err(error) => error!(%error, "a delivery stopped unexpectedly"),
            }
        }
        anyhow::ensure!(
            unrecorded == 0,
            "how {unrecorded} notifications went couldn't be recorded"
        );
        Ok(())
    }

    async fn record(
        &self,
        delivery: &Delivery,
        result: Result<Option<String>>,
        now: Timestamp,
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
                    .delivery_sent(delivery.id, attempts, now, external_id.as_deref())
                    .await
            }
            Err(error) => {
                let message = format!("{error:#}");
                let next = (now - delivery.created_at < GIVE_UP_AFTER)
                    .then(|| now + retry_delay(attempts));
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
        assert_eq!(retry_delay(1), TimeDelta::seconds(30));
        assert_eq!(retry_delay(2), TimeDelta::minutes(1));
        assert_eq!(retry_delay(3), TimeDelta::minutes(2));
        assert_eq!(retry_delay(7), LONGEST_RETRY);
        assert_eq!(retry_delay(i32::MAX), LONGEST_RETRY);
        assert_eq!(retry_delay(0), TimeDelta::seconds(30));
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
