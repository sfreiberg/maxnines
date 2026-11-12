//! A plain webhook, which gets the notification as JSON.

use anyhow::Result;
use serde_json::{Value, json};

use super::{ChannelType, blocking, post_json, url_host, url_preview};
use crate::alerting::{Channel, ChannelInput};
use crate::notifier::{Notice, Senders};

pub struct Webhook;

/// `text` is what Slack and tools like it show, so a plain webhook works with them.
/// `version` is for changes to this format.
fn body(notice: &Notice) -> Value {
    json!({
        "version": 1,
        "id": notice.id,
        "event": notice.event,
        "text": notice.text,
        "alert": notice.alert,
        "action": notice.action_fields(),
    })
}

#[async_trait::async_trait]
impl ChannelType for Webhook {
    fn name(&self) -> &'static str {
        "Webhook"
    }

    fn check(&self, channel: &ChannelInput) -> Result<()> {
        url_host(&channel.target).map(|_| ())
    }

    fn preview(&self, target: &str) -> String {
        url_preview(target)
    }

    fn hides_target(&self) -> bool {
        true
    }

    async fn send(
        &self,
        channel: &Channel,
        notice: &Notice,
        _reply_to: Option<&str>,
        _senders: &Senders,
    ) -> Result<Option<String>> {
        let target = channel.channel.target.clone();
        let body = body(notice);
        blocking(move || post_json("the webhook", &target, &body).map(|()| None)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::Event;
    use crate::channels::testing::{alert, notice};

    #[test]
    fn webhooks_get_a_versioned_body_with_plain_text() {
        let body = body(&notice(Event::Firing, alert()));
        assert_eq!(body["version"], 1);
        assert_eq!(body["id"], 3);
        assert_eq!(body["event"], "firing");
        assert_eq!(body["text"], "CPU usage on web-1 is 97%, above 90%");
        assert_eq!(body["alert"]["severity"], "critical");
        assert_eq!(body["alert"]["host_id"], "abc");
        assert_eq!(
            super::body(&notice(Event::Escalated, alert()))["event"],
            "escalated"
        );
    }
}
