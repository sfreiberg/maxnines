//! The checks collector. The checks themselves are in `maxnines_checks`, as the
//! server runs them too.

use std::time::Duration;

use anyhow::Result;
use maxnines_checks::{limit, run, timed_out_report};
use maxnines_protocol::Check;
use serde_json::Value;

use crate::background::{Background, Prober};
use crate::collector::Collector;

/// How long a check gets to report once its own time limit is up.
const GRACE: Duration = Duration::from_secs(1);

pub struct CheckCollector {
    background: Background,
}

impl CheckCollector {
    pub fn new(checks: Vec<Check>, interval: Duration) -> Self {
        let longest = checks.iter().map(limit).max().unwrap_or_default();
        let prober = Prober::new(checks, longest + GRACE);
        let background = Background::start(interval, move || {
            Value::Array(prober.round(run, timed_out_report))
        });
        Self { background }
    }
}

impl Collector for CheckCollector {
    fn name(&self) -> &'static str {
        "checks"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    use maxnines_protocol::CheckKind;

    use super::*;

    #[test]
    fn the_collector_reports_what_its_checks_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let check = Check::new("a", CheckKind::Tcp, &target);
        let mut collector = CheckCollector::new(vec![check], Duration::from_secs(60));

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let output = collector.collect().unwrap();
            if output[0]["up"] == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "{output}");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
