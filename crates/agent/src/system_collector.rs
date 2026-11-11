use std::time::Duration;

use anyhow::Result;
use maxnines_collectors::failed_services::failed_services;
use maxnines_collectors::system::{limits, login_sessions, report};
use maxnines_collectors::tcp::tcp_states;
use maxnines_collectors::updates::{pending_updates, reboot_required};
use serde_json::{Value, json};

use crate::background::Background;
use crate::collector::Collector;

/// Package managers take a while and their lists only change now and then, so whether
/// there are updates, and whether a restart is waiting, are looked at this often.
const UPDATES_EVERY: Duration = Duration::from_secs(15 * 60);

/// How close the machine is to its limits, how many people are on it, its TCP
/// connections, services that failed, and whether it has updates or a restart waiting.
pub struct SystemCollector {
    background: Background,
    updates: Background,
}

impl SystemCollector {
    pub fn new(interval: Duration) -> Self {
        let background = Background::start(interval, || async {
            report(
                &limits(),
                login_sessions().await,
                tcp_states().await,
                failed_services().await,
            )
        });
        let updates = Background::start(UPDATES_EVERY, || async {
            let updates = pending_updates().await;
            json!({
                "reboot_required": reboot_required().await.map(u8::from),
                "pending_updates": updates.map(|updates| updates.pending),
                "security_updates": updates.and_then(|updates| updates.security),
            })
        });
        Self {
            background,
            updates,
        }
    }
}

/// The slower round's findings, added to the latest. Neither has anything until its
/// first round is done.
fn merged(mut latest: Value, slower: Value) -> Value {
    if let (Some(latest), Value::Object(slower)) = (latest.as_object_mut(), slower) {
        latest.extend(slower);
    }
    latest
}

impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(merged(self.background.latest(), self.updates.latest()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slower_round_adds_to_the_latest_once_both_have_something() {
        let latest = json!({ "processes": 300 });
        let slower = json!({ "pending_updates": 4, "reboot_required": 1 });
        assert_eq!(
            merged(latest.clone(), slower.clone()),
            json!({ "processes": 300, "pending_updates": 4, "reboot_required": 1 })
        );
        assert_eq!(merged(latest.clone(), Value::Null), latest);
        assert_eq!(merged(Value::Null, slower), Value::Null);
    }
}
