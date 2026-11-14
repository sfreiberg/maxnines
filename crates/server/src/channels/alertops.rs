//! AlertOps, through a custom inbound integration that's mapped from fixed names.

use anyhow::Result;
use serde_json::{Value, json};

use super::on_call::{self, Incident};
use super::{ChannelType, alerts_link, blocking, post_json, url_preview};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders};

pub struct AlertOps;

/// Fixed names only, as AlertOps leaves it to whoever sets up the integration to say
/// which of them means what. The form shows this as the sample to map from.
fn event(notice: &Notice, step: Incident, web_url: Option<&str>) -> Value {
    let mut event = json!({
        "alert_id": on_call::id(notice),
        "status": if step == Incident::Open { "open" } else { "closed" },
        "subject": on_call::title(notice),
        "message": notice.text,
        "severity": on_call::severity(notice),
        "hostname": on_call::hostname(notice),
    });
    if let Some(url) = web_url {
        event["link"] = json!(alerts_link(url));
    }
    event
}

/// What AlertOps' sample data box needs, to map its fields from.
pub fn sample() -> String {
    let event = event(
        &Notice::test(),
        Incident::Open,
        Some("https://maxnines.example.com"),
    );
    serde_json::to_string_pretty(&event).unwrap_or_default()
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

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        senders: &Senders,
    ) -> Result<Option<String>> {
        let target = channel.channel.target.clone();
        let web_url = senders.web_url.as_deref();
        let events: Vec<Value> = on_call::steps(notice)
            .iter()
            .map(|step| event(notice, *step, web_url))
            .collect();
        blocking(move || {
            for event in &events {
                post_json("AlertOps", &target, event)?;
            }
            Ok(None)
        })
        .await
    }
}
