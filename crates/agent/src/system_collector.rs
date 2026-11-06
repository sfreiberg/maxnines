use std::time::Duration;

use anyhow::Result;
use maxnines_collectors::system::{limits, login_sessions, report};
use serde_json::Value;

use crate::background::Background;
use crate::collector::Collector;

/// How close the machine is to its limits, and how many people are on it.
pub struct SystemCollector {
    background: Background,
}

impl SystemCollector {
    pub fn new(interval: Duration) -> Self {
        let background = Background::start(interval, || async {
            report(&limits(), login_sessions().await)
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
