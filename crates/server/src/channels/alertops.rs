//! AlertOps, through a custom inbound integration that's mapped from fixed names.

use anyhow::Result;
use serde_json::{Value, json};

use super::on_call::{self, Incident, Step};
use super::{ChannelType, blocking, post_json, url_preview};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders};

pub struct AlertOps;

/// Fixed names only, as AlertOps leaves it to whoever sets up the integration to say
/// which of them means what. The form shows this as the sample to map from. An
/// inbound integration can only open, update and close an alert, so there's nothing
/// to send for acknowledging one, and AlertOps is never queued that.
fn event(notice: &Notice, step: &Step, web_url: Option<&str>) -> Option<Value> {
    let status = match step.incident {
        Incident::Open => "open",
        Incident::Close => "closed",
        Incident::Acknowledge => return None,
    };
    let mut event = json!({
        "alert_id": step.id,
        "status": status,
        "subject": on_call::title(notice),
        "message": notice.text,
        "severity": on_call::severity(notice),
        "hostname": on_call::hostname(notice),
    });
    if let Some(url) = web_url {
        event["link"] = json!(notice.link(url));
    }
    Some(event)
}

/// What AlertOps' sample data box needs, to map its fields from.
pub fn sample() -> String {
    let opened = Step {
        incident: Incident::Open,
        id: on_call::TEST_INCIDENT_ID.to_string(),
    };
    event(
        &Notice::test(),
        &opened,
        Some("https://maxnines.example.com"),
    )
    .and_then(|event| serde_json::to_string_pretty(&event).ok())
    .unwrap_or_default()
}

#[async_trait::async_trait]
impl ChannelType for AlertOps {
    fn name(&self) -> &'static str {
        "AlertOps"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        on_call::check_service_url(
            &channel.target,
            ".alertops.com",
            "/POSTAlert/",
            "that doesn't look like an AlertOps integration URL, which looks like \
             https://notify.alertops.com/POSTAlert/ followed by its token",
        )
    }

    fn preview(&self, target: &str) -> String {
        url_preview(target)
    }

    fn hides_target(&self) -> bool {
        true
    }

    fn is_on_call(&self) -> bool {
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
        let target = channel.channel.target.clone();
        let web_url = senders.web_url.as_deref();
        let plan = on_call::plan(notice, &channel.channel, open);
        let events: Vec<Value> = plan
            .steps
            .iter()
            .filter_map(|step| event(notice, step, web_url))
            .collect();
        blocking(move || {
            for event in &events {
                post_json("AlertOps", &target, event)?;
            }
            Ok(plan.open)
        })
        .await
    }
}
