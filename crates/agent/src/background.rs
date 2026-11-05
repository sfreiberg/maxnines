//! Runs slow or unreliable work away from the agent's main loop, which also
//! answers the server and can't wait on a dead host or a stuck network drive.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::error;

/// How quickly a stopped collector's thread notices.
const STOP_CHECK: Duration = Duration::from_millis(100);

/// Repeats some work on its own thread and keeps the newest result. It stops
/// when dropped, which happens whenever the agent's config changes.
pub struct Background {
    latest: Arc<Mutex<Value>>,
    stop: Arc<AtomicBool>,
}

impl Background {
    pub fn start(interval: Duration, mut round: impl FnMut() -> Value + Send + 'static) -> Self {
        let latest = Arc::new(Mutex::new(Value::Array(Vec::new())));
        let stop = Arc::new(AtomicBool::new(false));

        let (saved, stopped) = (latest.clone(), stop.clone());
        thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let started = Instant::now();
                match catch_unwind(AssertUnwindSafe(&mut round)) {
                    Ok(value) => *saved.lock().unwrap_or_else(PoisonError::into_inner) = value,
                    Err(_) => error!("a background collector panicked"),
                }
                while started.elapsed() < interval && !stopped.load(Ordering::Relaxed) {
                    thread::sleep(STOP_CHECK.min(interval));
                }
            }
        });

        Self { latest, stop }
    }

    pub fn latest(&self) -> Value {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Clears an item's busy flag however its thread ends.
struct Finished(Arc<AtomicBool>);

impl Drop for Finished {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Probes a list of things at once, each on its own thread with a time limit.
/// Rust can't stop a thread stuck in a system call, so a stuck item is left to
/// finish and isn't started again until it has. That's what stops a dead network
/// mount from using up a new thread on every round.
pub struct Prober<T> {
    items: Vec<(Arc<T>, Arc<AtomicBool>)>,
    timeout: Duration,
}

impl<T: Send + Sync + 'static> Prober<T> {
    pub fn new(items: Vec<T>, timeout: Duration) -> Self {
        let items = items
            .into_iter()
            .map(|item| (Arc::new(item), Arc::new(AtomicBool::new(false))))
            .collect();
        Self { items, timeout }
    }

    /// Gives one result per item, in order. `failed` stands in for anything that
    /// ran out of time, panicked or is still stuck from before.
    pub fn round<O: Send + 'static>(&self, probe: fn(&T) -> O, failed: impl Fn(&T) -> O) -> Vec<O> {
        let (sender, receiver) = mpsc::channel();
        let mut waiting = 0;
        for (index, (item, busy)) in self.items.iter().enumerate() {
            if busy.swap(true, Ordering::Relaxed) {
                continue;
            }
            let (item, finished) = (item.clone(), Finished(busy.clone()));
            let sender = sender.clone();
            waiting += 1;
            thread::spawn(move || {
                let _finished = finished;
                let result = catch_unwind(AssertUnwindSafe(|| probe(&item))).ok();
                let _ = sender.send((index, result));
            });
        }

        let mut results: Vec<Option<O>> = self.items.iter().map(|_| None).collect();
        let deadline = Instant::now() + self.timeout;
        while waiting > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok((index, result)) = receiver.recv_timeout(left) else {
                break;
            };
            results[index] = result;
            waiting -= 1;
        }

        results
            .into_iter()
            .zip(&self.items)
            .map(|(result, (item, _))| result.unwrap_or_else(|| failed(item)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use serde_json::json;

    use super::*;

    const SHORT: Duration = Duration::from_millis(100);

    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "it never happened");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn background_work_repeats_and_keeps_the_newest_result() {
        let mut count = 0;
        let background = Background::start(Duration::from_millis(5), move || {
            count += 1;
            json!(count)
        });

        wait_until(|| background.latest().as_u64().is_some_and(|count| count >= 3));
    }

    #[test]
    fn nothing_is_reported_until_the_first_round_finishes() {
        let background = Background::start(SHORT, || {
            thread::sleep(Duration::from_secs(1));
            json!("late")
        });
        assert_eq!(background.latest(), json!([]));
    }

    #[test]
    fn background_work_stops_when_dropped() {
        let rounds = Arc::new(AtomicUsize::new(0));
        let counted = rounds.clone();
        let background = Background::start(Duration::from_millis(5), move || {
            json!(counted.fetch_add(1, Ordering::Relaxed))
        });
        wait_until(|| rounds.load(Ordering::Relaxed) > 0);

        drop(background);
        thread::sleep(Duration::from_millis(50));
        let after_stopping = rounds.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(rounds.load(Ordering::Relaxed), after_stopping);
    }

    #[test]
    fn a_panic_costs_one_round_and_keeps_the_last_result() {
        let mut count = 0;
        let background = Background::start(Duration::from_millis(5), move || {
            count += 1;
            assert!(count != 2, "deliberate test panic");
            json!(count)
        });

        wait_until(|| background.latest().as_u64().is_some_and(|count| count >= 3));
    }

    #[test]
    fn results_come_back_in_order() {
        let prober = Prober::new(vec![30_u64, 1, 15], Duration::from_secs(5));
        let results = prober.round(
            |delay| {
                thread::sleep(Duration::from_millis(*delay));
                *delay
            },
            |_| 0,
        );
        assert_eq!(results, [30, 1, 15]);
    }

    #[test]
    fn items_run_at_the_same_time() {
        let prober = Prober::new(vec![200_u64; 10], Duration::from_secs(5));
        let started = Instant::now();
        prober.round(|delay| thread::sleep(Duration::from_millis(*delay)), |_| ());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_stuck_item_times_out_without_holding_up_the_rest() {
        let prober = Prober::new(vec![600_u64, 1], SHORT);
        let results = prober.round(
            |delay| {
                thread::sleep(Duration::from_millis(*delay));
                "done"
            },
            |_| "timed out",
        );
        assert_eq!(results, ["timed out", "done"]);
    }

    static STARTED: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn a_stuck_item_is_not_started_again_until_it_finishes() {
        let prober = Prober::new(vec![400_u64], Duration::from_millis(20));
        let probe = |delay: &u64| {
            STARTED.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(*delay));
            "done"
        };

        for _ in 0..4 {
            assert_eq!(prober.round(probe, |_| "timed out"), ["timed out"]);
        }
        assert_eq!(STARTED.load(Ordering::Relaxed), 1);

        wait_until(|| !prober.items[0].1.load(Ordering::Relaxed));
        prober.round(probe, |_| "timed out");
        assert_eq!(STARTED.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_panicking_item_counts_as_failed_and_can_run_again() {
        let prober = Prober::new(vec![1_u64], Duration::from_secs(5));
        let probe = |_: &u64| -> &str { panic!("deliberate test panic") };
        assert_eq!(prober.round(probe, |_| "failed"), ["failed"]);
        wait_until(|| !prober.items[0].1.load(Ordering::Relaxed));
        assert_eq!(prober.round(|_| "ok", |_| "failed"), ["ok"]);
    }
}
