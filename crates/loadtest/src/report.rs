//! What a test found: the results, the verdict and the terminal summary.

use serde::Serialize;

use crate::monitor::Point;
use crate::options::Setting;

/// Pages slower than this are worth knowing about, and this slow is a failure.
const SLOW_PAGE_SECS: f64 = 2.0;
const FAILED_PAGE_SECS: f64 = 5.0;
/// Alert rules run every 15 seconds, so this means they've fallen behind.
const LATE_ALERTS_SECS: f64 = 30.0;
const FAILED_ALERTS_SECS: f64 = 60.0;
/// A little can be in flight when connections are dropped on purpose.
const ACCEPTABLE_LOST_PERCENT: f64 = 0.1;
const BUSY_QUEUE_PERCENT: f64 = 50.0;
const FULL_QUEUE_PERCENT: f64 = 90.0;
/// A load generator this busy can't be trusted to be sending what was asked for.
const BUSY_GENERATOR_PERCENT: f64 = 80.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Warning,
    Fail,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
            Self::Warning => "Warning",
            Self::Fail => "Fail",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub outcome: Outcome,
    pub detail: String,
}

/// Times in milliseconds, from a sorted list.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Spread {
    pub median_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl Spread {
    pub fn of(times_ms: &mut [f64]) -> Self {
        times_ms.sort_by(f64::total_cmp);
        let at = |share: f64| -> f64 {
            let last = times_ms.len().saturating_sub(1);
            times_ms
                .get((last as f64 * share).round() as usize)
                .copied()
                .unwrap_or_default()
        };
        Self {
            median_ms: at(0.5),
            p95_ms: at(0.95),
            p99_ms: at(0.99),
            max_ms: at(1.0),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ServerSummary {
    pub version: String,
    pub commit: String,
    pub os: String,
    pub cores: u64,
    pub memory_gb: f64,
    pub database: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Connections {
    pub wanted: u64,
    /// Some agents will be reconnecting at any moment, if they've been asked to.
    pub churning: bool,
    pub online_at_end: u64,
    pub peak_online: u64,
    pub attempts: u64,
    pub succeeded: u64,
    pub lost: u64,
    pub all_online_after_secs: Option<f64>,
    pub times: Spread,
    pub errors: Vec<ErrorCount>,
}

#[derive(Debug, Serialize)]
pub struct ErrorCount {
    pub error: String,
    pub count: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Samples {
    pub live_sent: u64,
    pub saved_sent: u64,
    pub written: u64,
    pub failed: u64,
    pub average_bytes: f64,
    pub peak_queued: u64,
    pub queue_capacity: u64,
}

impl Samples {
    pub fn sent(&self) -> u64 {
        self.live_sent + self.saved_sent
    }

    /// Sent but never accounted for. The server's own samples can make this negative.
    pub fn missing(&self) -> u64 {
        self.sent().saturating_sub(self.written + self.failed)
    }
}

#[derive(Debug, Serialize)]
pub struct PageResult {
    pub path: String,
    pub loads: usize,
    pub errors: usize,
    pub bytes: usize,
    pub times: Spread,
}

/// What this load would come to over time.
#[derive(Debug, Default, Serialize)]
pub struct Projection {
    pub bytes_per_sample: Option<f64>,
    pub metrics_gb_per_day: Option<f64>,
    pub days_until_disk_full: Option<f64>,
    pub memory_mb_per_agent: Option<f64>,
    pub average_cpu_cores: Option<f64>,
    pub peak_cpu_cores: Option<f64>,
    pub peak_memory_mb: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Event {
    pub time_secs: f64,
    pub text: String,
}

#[derive(Serialize)]
pub struct Report {
    pub started: String,
    pub ran_for_secs: f64,
    pub stopped_early: bool,
    pub outcome: Outcome,
    pub checks: Vec<Check>,
    pub settings: Vec<Setting>,
    pub server: ServerSummary,
    pub connections: Connections,
    pub samples: Samples,
    pub pages: Vec<PageResult>,
    pub projection: Projection,
    pub events: Vec<Event>,
    pub timeline: Vec<Point>,
    pub generator_average_cpu_percent: f64,
}

fn grade(value: f64, warning: f64, failure: f64) -> Outcome {
    if value >= failure {
        Outcome::Fail
    } else if value >= warning {
        Outcome::Warning
    } else {
        Outcome::Pass
    }
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

/// Decides how a test went. Thresholds are for a server someone is looking at, so
/// they're about whether it stayed usable rather than how fast it went.
pub fn judge(
    connections: &Connections,
    samples: &Samples,
    pages: &[PageResult],
    timeline: &[Point],
    generator_average_cpu_percent: f64,
) -> Vec<Check> {
    let mut checks = Vec::new();

    let online = connections.online_at_end;
    checks.push(Check {
        name: "Agents stayed connected",
        outcome: match online {
            all if all >= connections.wanted => Outcome::Pass,
            nearly if percent(nearly, connections.wanted) >= 99.0 => {
                if connections.churning {
                    Outcome::Pass
                } else {
                    Outcome::Warning
                }
            }
            _ => Outcome::Fail,
        },
        detail: format!(
            "{online} of {} online at the end, after {} unexpected disconnects",
            connections.wanted, connections.lost
        ),
    });

    let missing = percent(samples.missing(), samples.sent());
    let outcome = if samples.sent() == 0 || samples.failed > 0 {
        Outcome::Fail
    } else {
        grade(missing, f64::MIN_POSITIVE, ACCEPTABLE_LOST_PERCENT)
    };
    checks.push(Check {
        name: "Samples were saved",
        outcome,
        detail: format!(
            "{} of {} saved, {} failed, {} unaccounted for",
            samples.written,
            samples.sent(),
            samples.failed,
            samples.missing()
        ),
    });

    let queue = percent(samples.peak_queued, samples.queue_capacity);
    checks.push(Check {
        name: "Writes kept up",
        outcome: grade(queue, BUSY_QUEUE_PERCENT, FULL_QUEUE_PERCENT),
        detail: format!(
            "the write queue peaked at {} of {}",
            samples.peak_queued, samples.queue_capacity
        ),
    });

    let slowest = pages
        .iter()
        .max_by(|a, b| a.times.p95_ms.total_cmp(&b.times.p95_ms));
    if let Some(page) = slowest {
        let page_errors: usize = pages.iter().map(|page| page.errors).sum();
        let outcome = grade(page.times.p95_ms / 1000.0, SLOW_PAGE_SECS, FAILED_PAGE_SECS);
        let outcome = outcome.max(if page_errors > 0 {
            Outcome::Warning
        } else {
            Outcome::Pass
        });
        checks.push(Check {
            name: "Pages stayed usable",
            outcome,
            detail: format!(
                "slowest was {} at {:.0} ms (95th percentile), with {page_errors} errors",
                page.path, page.times.p95_ms
            ),
        });
    }

    let oldest_pass = timeline
        .iter()
        .filter_map(|point| point.alert_pass_age_secs)
        .fold(None, |oldest: Option<f64>, age| {
            Some(oldest.map_or(age, |oldest| oldest.max(age)))
        });
    if let Some(age) = oldest_pass {
        checks.push(Check {
            name: "Alert rules ran on time",
            outcome: grade(age, LATE_ALERTS_SECS, FAILED_ALERTS_SECS),
            detail: format!("the longest since a run was {age:.0} seconds"),
        });
    }

    checks.push(Check {
        name: "The load generator kept up",
        outcome: grade(
            generator_average_cpu_percent,
            BUSY_GENERATOR_PERCENT,
            f64::MAX,
        ),
        detail: format!("it averaged {generator_average_cpu_percent:.0}% of this host's CPU"),
    });

    checks
}

pub fn overall(checks: &[Check]) -> Outcome {
    checks
        .iter()
        .map(|check| check.outcome)
        .max()
        .unwrap_or(Outcome::Pass)
}

pub fn clock(seconds: f64) -> String {
    let whole = seconds.max(0.0) as u64;
    format!("{}:{:02}", whole / 60, whole % 60)
}

fn optional(value: Option<f64>, write: impl Fn(f64) -> String) -> String {
    value.map_or_else(|| "not available".to_string(), write)
}

impl Report {
    /// The summary printed at the end of a run.
    pub fn text(&self) -> String {
        let mut out = String::new();
        let mut line = |text: String| {
            out.push_str(&text);
            out.push('\n');
        };

        line(format!(
            "\nResult: {}\n",
            self.outcome.label().to_uppercase()
        ));
        for check in &self.checks {
            line(format!(
                "  {:<8} {}: {}",
                check.outcome.label(),
                check.name,
                check.detail
            ));
        }

        let connections = &self.connections;
        line("\nConnections".to_string());
        line(format!(
            "  {} of {} attempts worked, in {:.0} ms typically and {:.0} ms at the 99th percentile",
            connections.succeeded,
            connections.attempts,
            connections.times.median_ms,
            connections.times.p99_ms
        ));
        if let Some(after) = connections.all_online_after_secs {
            line(format!("  All agents were online after {after:.1} seconds"));
        }
        for error in connections.errors.iter().take(5) {
            line(format!("  {} times: {}", error.count, error.error));
        }

        let samples = &self.samples;
        line("\nSamples".to_string());
        line(format!(
            "  {} live and {} saved sent, about {:.1} KB each",
            samples.live_sent,
            samples.saved_sent,
            samples.average_bytes / 1000.0
        ));
        line(format!(
            "  {} written, {} failed, write queue peaked at {} of {}",
            samples.written, samples.failed, samples.peak_queued, samples.queue_capacity
        ));

        let projection = &self.projection;
        line("\nServer".to_string());
        line(format!(
            "  CPU: {} on average, {} at peak, of {}",
            optional(projection.average_cpu_cores, |c| format!("{c:.2} cores")),
            optional(projection.peak_cpu_cores, |c| format!("{c:.2}")),
            self.server.cores
        ));
        line(format!(
            "  Memory: {} at peak, {} per agent",
            optional(projection.peak_memory_mb, |m| format!("{m:.0} MB")),
            optional(projection.memory_mb_per_agent, |m| format!("{m:.2} MB"))
        ));
        line(format!(
            "  Metrics database: {} per sample, {} per day at this load",
            optional(projection.bytes_per_sample, |b| format!(
                "{:.2} KB",
                b / 1000.0
            )),
            optional(projection.metrics_gb_per_day, |g| format!("{g:.1} GB"))
        ));
        if let Some(days) = projection.days_until_disk_full {
            line(format!("  The disk would fill in about {days:.0} days"));
        }

        if !self.pages.is_empty() {
            line("\nPages (median / 95th percentile / slowest)".to_string());
            for page in &self.pages {
                line(format!(
                    "  {:<28} {:>6.0} ms {:>6.0} ms {:>6.0} ms{}",
                    page.path,
                    page.times.median_ms,
                    page.times.p95_ms,
                    page.times.max_ms,
                    if page.errors > 0 {
                        format!("  {} errors", page.errors)
                    } else {
                        String::new()
                    }
                ));
            }
        }

        if !self.events.is_empty() {
            line("\nEvents".to_string());
            for event in &self.events {
                line(format!("  {:>6}  {}", clock(event.time_secs), event.text));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connections() -> Connections {
        Connections {
            wanted: 100,
            online_at_end: 100,
            ..Connections::default()
        }
    }

    fn samples() -> Samples {
        Samples {
            live_sent: 1000,
            written: 1000,
            queue_capacity: 1024,
            ..Samples::default()
        }
    }

    fn page(p95_ms: f64) -> PageResult {
        PageResult {
            path: "/hosts".to_string(),
            loads: 10,
            errors: 0,
            bytes: 1,
            times: Spread {
                p95_ms,
                ..Spread::default()
            },
        }
    }

    fn outcome_of(checks: &[Check], name: &str) -> Outcome {
        checks.iter().find(|c| c.name == name).unwrap().outcome
    }

    #[test]
    fn a_healthy_run_passes() {
        let checks = judge(&connections(), &samples(), &[page(100.0)], &[], 5.0);
        assert_eq!(overall(&checks), Outcome::Pass);
    }

    #[test]
    fn agents_missing_at_the_end_are_a_problem() {
        let check = |online_at_end| {
            let connections = Connections {
                online_at_end,
                ..connections()
            };
            let checks = judge(&connections, &samples(), &[], &[], 0.0);
            outcome_of(&checks, "Agents stayed connected")
        };
        assert_eq!(check(100), Outcome::Pass);
        assert_eq!(check(99), Outcome::Warning);
        assert_eq!(check(50), Outcome::Fail);
    }

    #[test]
    fn agents_reconnecting_on_purpose_are_not_a_problem() {
        let connections = Connections {
            online_at_end: 99,
            churning: true,
            ..connections()
        };
        let checks = judge(&connections, &samples(), &[], &[], 0.0);
        assert_eq!(
            outcome_of(&checks, "Agents stayed connected"),
            Outcome::Pass
        );
    }

    #[test]
    fn churn_does_not_excuse_most_agents_being_gone() {
        let connections = Connections {
            online_at_end: 50,
            churning: true,
            ..connections()
        };
        let checks = judge(&connections, &samples(), &[], &[], 0.0);
        assert_eq!(
            outcome_of(&checks, "Agents stayed connected"),
            Outcome::Fail
        );
    }

    #[test]
    fn failed_writes_fail_the_test() {
        let samples = Samples {
            failed: 1,
            written: 999,
            ..samples()
        };
        let checks = judge(&connections(), &samples, &[], &[], 0.0);
        assert_eq!(outcome_of(&checks, "Samples were saved"), Outcome::Fail);
    }

    #[test]
    fn missing_samples_depend_on_how_many() {
        let check = |written| {
            let samples = Samples {
                live_sent: 100_000,
                written,
                ..samples()
            };
            let checks = judge(&connections(), &samples, &[], &[], 0.0);
            outcome_of(&checks, "Samples were saved")
        };
        assert_eq!(check(100_000), Outcome::Pass);
        assert_eq!(check(99_950), Outcome::Warning);
        assert_eq!(check(99_000), Outcome::Fail);
    }

    #[test]
    fn sending_nothing_is_not_a_success() {
        let samples = Samples {
            live_sent: 0,
            written: 0,
            ..samples()
        };
        let checks = judge(&connections(), &samples, &[], &[], 0.0);
        assert_eq!(outcome_of(&checks, "Samples were saved"), Outcome::Fail);
    }

    #[test]
    fn a_filling_queue_is_a_problem() {
        let check = |peak_queued| {
            let samples = Samples {
                peak_queued,
                ..samples()
            };
            let checks = judge(&connections(), &samples, &[], &[], 0.0);
            outcome_of(&checks, "Writes kept up")
        };
        assert_eq!(check(10), Outcome::Pass);
        assert_eq!(check(600), Outcome::Warning);
        assert_eq!(check(1000), Outcome::Fail);
    }

    #[test]
    fn slow_pages_are_a_problem() {
        let check = |ms| {
            let checks = judge(&connections(), &samples(), &[page(ms)], &[], 0.0);
            outcome_of(&checks, "Pages stayed usable")
        };
        assert_eq!(check(500.0), Outcome::Pass);
        assert_eq!(check(3000.0), Outcome::Warning);
        assert_eq!(check(6000.0), Outcome::Fail);
    }

    #[test]
    fn page_errors_are_at_least_a_warning() {
        let failing = PageResult {
            errors: 1,
            ..page(10.0)
        };
        let checks = judge(&connections(), &samples(), &[failing], &[], 0.0);
        assert_eq!(outcome_of(&checks, "Pages stayed usable"), Outcome::Warning);
    }

    fn with_alert_age(age: f64) -> Point {
        Point {
            time_secs: 0.0,
            agents_online: 0,
            samples_sent_per_sec: 0.0,
            samples_written_per_sec: 0.0,
            queued: 0,
            cpu_cores: None,
            memory_mb: None,
            metrics_mb: None,
            alert_pass_age_secs: Some(age),
        }
    }

    #[test]
    fn late_alert_rules_are_a_problem() {
        let check = |age| {
            let timeline = [with_alert_age(5.0), with_alert_age(age)];
            let checks = judge(&connections(), &samples(), &[], &timeline, 0.0);
            outcome_of(&checks, "Alert rules ran on time")
        };
        assert_eq!(check(14.0), Outcome::Pass);
        assert_eq!(check(40.0), Outcome::Warning);
        assert_eq!(check(90.0), Outcome::Fail);
    }

    #[test]
    fn a_busy_load_generator_is_a_warning_about_the_test_itself() {
        let checks = judge(&connections(), &samples(), &[], &[], 95.0);
        assert_eq!(overall(&checks), Outcome::Warning);
    }

    #[test]
    fn the_worst_check_decides_the_result() {
        let checks = vec![
            Check {
                name: "a",
                outcome: Outcome::Warning,
                detail: String::new(),
            },
            Check {
                name: "b",
                outcome: Outcome::Fail,
                detail: String::new(),
            },
        ];
        assert_eq!(overall(&checks), Outcome::Fail);
    }

    #[test]
    fn spreads_come_from_sorted_times() {
        let mut times: Vec<f64> = (1..=100).rev().map(f64::from).collect();
        let spread = Spread::of(&mut times);
        assert_eq!(spread.median_ms, 51.0);
        assert_eq!(spread.max_ms, 100.0);
        assert!(spread.p95_ms >= 95.0 && spread.p99_ms >= spread.p95_ms);
        assert_eq!(Spread::of(&mut []).max_ms, 0.0);
    }

    #[test]
    fn clock_times_read_as_minutes_and_seconds() {
        assert_eq!(clock(65.4), "1:05");
        assert_eq!(clock(0.0), "0:00");
    }
}
