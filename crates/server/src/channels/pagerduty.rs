//! PagerDuty, through its Events API: each alert is an incident that opens and
//! closes with it.

use anyhow::{Result, ensure};
use serde_json::{Value, json};

use super::on_call::{self, Incident};
use super::{ChannelType, alerts_link, blocking, post_json};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders};

/// Where PagerDuty takes events.
pub const EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// The longest summary PagerDuty accepts.
const MAX_SUMMARY_CHARS: usize = 1024;

/// How long PagerDuty's integration keys are.
const KEY_LEN: usize = 32;

pub struct PagerDuty;

fn event(notice: &Notice, step: Incident, key: &str, web_url: Option<&str>) -> Value {
    let dedup_key = on_call::id(notice);
    if step == Incident::Close {
        return json!({
            "routing_key": key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        });
    }

    let summary: String = notice.text.chars().take(MAX_SUMMARY_CHARS).collect();
    let details = notice.alert.as_ref().map_or_else(
        || json!({}),
        |alert| {
            json!({
                "rule": alert.rule_name,
                "series": alert.series,
                "value": alert.value,
            })
        },
    );
    let mut event = json!({
        "routing_key": key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "client": "MaxNines",
        "payload": {
            "summary": summary,
            "source": on_call::hostname(notice),
            "severity": on_call::severity(notice),
            "custom_details": details,
        },
    });
    if let Some(url) = web_url {
        event["client_url"] = json!(alerts_link(url));
    }
    event
}

#[async_trait::async_trait]
impl ChannelType for PagerDuty {
    fn name(&self) -> &'static str {
        "PagerDuty"
    }

    /// Says what's wrong without repeating the key, as this ends up on the page.
    fn check(&self, channel: &ChannelInput) -> Result<()> {
        let key = &channel.target;
        ensure!(
            key.len() == KEY_LEN && key.chars().all(|c| c.is_ascii_alphanumeric()),
            "that doesn't look like a PagerDuty integration key, which is \
             {KEY_LEN} letters and numbers"
        );
        Ok(())
    }

    fn preview(&self, target: &str) -> String {
        let start = target.len().saturating_sub(4);
        format!("Key ending {}", target.get(start..).unwrap_or_default())
    }

    fn hides_target(&self) -> bool {
        true
    }

    fn is_on_call(&self) -> bool {
        true
    }

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>> {
        let key = &channel.channel.target;
        let web_url = senders.web_url.as_deref();
        let events: Vec<Value> = on_call::steps(notice)
            .iter()
            .map(|step| event(notice, *step, key, web_url))
            .collect();
        let url = senders.pagerduty_url().to_string();
        blocking(move || {
            for event in &events {
                post_json("PagerDuty", &url, event)?;
            }
            Ok(None)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{Alert, Event, Severity};
    use crate::channels::testing::{alert, notice};

    #[test]
    fn an_eased_alert_updates_the_incident_as_a_warning() {
        let eased = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        let event = event(&notice(Event::Eased, eased), Incident::Open, "key", None);
        assert_eq!(event["event_action"], "trigger");
        assert_eq!(event["payload"]["severity"], "warning");
        assert_eq!(event["dedup_key"], "maxnines-alert-7");
    }

    #[test]
    fn only_the_end_of_a_key_is_shown() {
        assert_eq!(
            PagerDuty.preview("abcdefabcdefabcdefabcdefabcd2345"),
            "Key ending 2345"
        );
    }
}
