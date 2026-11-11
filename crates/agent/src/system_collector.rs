use std::time::Duration;

use anyhow::Result;
use maxnines_collectors::failed_services::failed_services;
use maxnines_collectors::system::{limits, login_sessions, report};
use maxnines_collectors::tcp::tcp_states;
use serde_json::Value;

use crate::background::Background;
use crate::collector::Collector;

/// How close the machine is to its limits, how many people are on it, its TCP
/// connections, and services that failed.
pub struct SystemCollector {
    background: Background,
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
        Self { background }
    }
}

impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}
