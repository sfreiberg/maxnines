use std::time::Duration;

use anyhow::Result;
use maxnines_collectors::failed_services::failed_services;
use maxnines_collectors::system::{limits, login_sessions, report};
use maxnines_collectors::tcp::tcp_states;
use serde_json::Value;

use crate::background::Background;
use crate::collector::Collector;

/// How close the host is to its limits, how many people are on it, its TCP
/// connections and services that failed. Updates and a restart waiting are the
/// `updates` collector's.
pub struct SystemCollector {
    background: Background,
}

impl SystemCollector {
    pub fn new(interval: Duration) -> Result<Self> {
        let mut background = Background::new();
        background.repeat(
            interval,
            None,
            || async {
                // Each is asked at once, and reading limits blocks, so it's done
                // away from the other collectors' tasks.
                let (limits, sessions, tcp, failed) = tokio::join!(
                    tokio::task::spawn_blocking(limits),
                    login_sessions(),
                    tcp_states(),
                    failed_services(),
                );
                report(&limits.unwrap_or_default(), sessions, tcp, failed)
            },
            Result::unwrap_or_default,
        )?;
        Ok(Self { background })
    }
}

impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest().pop().unwrap_or_default())
    }
}
