//! SIGNL4, through its webhook for a team or integration.

use anyhow::Result;
use serde_json::{Value, json};

use super::on_call::{self, Incident};
use super::{ChannelType, alerts_link, blocking, post_json, url_preview};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders};

pub struct Signl4;

/// Names starting `X-S4-` mean something to SIGNL4. It shows the others in the alert.
fn event(notice: &Notice, step: Incident, web_url: Option<&str>) -> Value {
    let id = on_call::id(notice);
    if step == Incident::Close {
        return json!({ "X-S4-ExternalID": id, "X-S4-Status": "resolved" });
    }

    let mut event = json!({
        "Title": on_call::title(notice),
        "Message": notice.text,
        "Severity": on_call::severity(notice),
        "Hostname": on_call::hostname(notice),
        "X-S4-ExternalID": id,
        "X-S4-Status": "new",
        "X-S4-SourceSystem": "MaxNines",
    });
    if let Some(url) = web_url {
        event["Link"] = json!(alerts_link(url));
    }
    event
}

#[async_trait::async_trait]
impl ChannelType for Signl4 {
    fn name(&self) -> &'static str {
        "SIGNL4"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        on_call::check_service_url(
            &channel.target,
            ".signl4.com",
            "/webhook/",
            "that doesn't look like a SIGNL4 webhook URL, which is \
             https://connect.signl4.com/webhook/ followed by your secret",
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
                post_json("SIGNL4", &target, event)?;
            }
            Ok(None)
        })
        .await
    }
}
