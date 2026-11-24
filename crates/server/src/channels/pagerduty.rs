//! PagerDuty, through its Events API: each alert is an incident that opens and
//! closes with it.

use anyhow::{Result, ensure};
use serde_json::{Value, json};

use super::on_call::{self, Incident, Step};
use super::{ChannelType, blocking, post_json};
use crate::alerting::{Channel, ChannelInput, PagerDutyRegion};
use crate::notifier::{Notice, Senders};

/// Where PagerDuty takes events, for an account in its US service region.
pub const EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// Where PagerDuty takes events, for an account in its EU service region.
pub const EU_EVENTS_URL: &str = "https://events.eu.pagerduty.com/v2/enqueue";

/// Where an account in `region` takes events.
pub fn events_url(region: PagerDutyRegion) -> &'static str {
    match region {
        PagerDutyRegion::Us => EVENTS_URL,
        PagerDutyRegion::Eu => EU_EVENTS_URL,
    }
}

/// The longest summary PagerDuty accepts.
const MAX_SUMMARY_CHARS: usize = 1024;

/// How long PagerDuty's integration keys are.
const KEY_LEN: usize = 32;

pub struct PagerDuty;

fn event(notice: &Notice, step: &Step, key: &str, web_url: Option<&str>) -> Value {
    let dedup_key = &step.id;
    let action = match step.incident {
        Incident::Open => "trigger",
        Incident::Acknowledge => "acknowledge",
        Incident::Close => "resolve",
    };
    if step.incident != Incident::Open {
        return json!({
            "routing_key": key,
            "event_action": action,
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
        "event_action": action,
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
        event["client_url"] = json!(notice.link(url));
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

    fn acknowledges(&self) -> bool {
        true
    }

    /// `open` is the alert's incident that's open, and what's open after is given
    /// back, for the next notification about it.
    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        open: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>> {
        let key = &channel.channel.target;
        let web_url = senders.web_url.as_deref();
        let plan = on_call::plan(notice, &channel.channel, open);
        let events: Vec<Value> = plan
            .steps
            .iter()
            .map(|step| event(notice, step, key, web_url))
            .collect();
        let region = channel.channel.region.unwrap_or_default();
        let url = senders.pagerduty_url(region).to_string();
        blocking(move || {
            for event in &events {
                post_json("PagerDuty", &url, event)?;
            }
            Ok(plan.open)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{Alert, Event, Severity};
    use crate::channels::testing::{alert, notice};

    fn on(incident: Incident, id: &str) -> Step {
        Step {
            incident,
            id: id.to_string(),
        }
    }

    #[test]
    fn an_eased_alert_updates_its_incident_as_a_warning() {
        let eased = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        let critical = on(Incident::Open, "maxnines-alert-7-critical");
        let event = event(&notice(Event::Eased, eased), &critical, "key", None);
        assert_eq!(event["event_action"], "trigger");
        assert_eq!(event["payload"]["severity"], "warning");
        assert_eq!(event["dedup_key"], "maxnines-alert-7-critical");
    }

    #[test]
    fn each_severity_carries_over_as_pagerdutys_own() {
        let warning = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        let opened = on(Incident::Open, "maxnines-alert-7-warning");
        let warned = event(&notice(Event::Firing, warning), &opened, "key", None);
        assert_eq!(warned["payload"]["severity"], "warning");
        let paged = event(&notice(Event::Firing, alert()), &opened, "key", None);
        assert_eq!(paged["payload"]["severity"], "critical");
    }

    #[test]
    fn an_incident_links_to_its_alert() {
        let opened = event(
            &notice(Event::Firing, alert()),
            &on(Incident::Open, "maxnines-alert-7-critical"),
            "key",
            Some("https://m.example.com"),
        );
        assert_eq!(opened["client_url"], "https://m.example.com/alerts/7");
    }

    #[test]
    fn acknowledging_names_only_the_incident() {
        let event = event(
            &notice(Event::Acknowledged, alert()),
            &on(Incident::Acknowledge, "maxnines-alert-7-critical"),
            "key",
            Some("https://m.example.com"),
        );
        assert_eq!(
            event,
            json!({
                "routing_key": "key",
                "event_action": "acknowledge",
                "dedup_key": "maxnines-alert-7-critical",
            })
        );
    }

    #[test]
    fn each_region_has_its_own_address() {
        assert_eq!(
            events_url(PagerDutyRegion::Us),
            "https://events.pagerduty.com/v2/enqueue"
        );
        assert_eq!(
            events_url(PagerDutyRegion::Eu),
            "https://events.eu.pagerduty.com/v2/enqueue"
        );
    }

    #[test]
    fn only_the_end_of_a_key_is_shown() {
        assert_eq!(
            PagerDuty.preview("abcdefabcdefabcdefabcdefabcd2345"),
            "Key ending 2345"
        );
    }
}
