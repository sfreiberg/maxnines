//! Runs slow or unreliable work away from the agent's main loop, which also
//! answers the server and can't wait on a dead host or a stuck network drive.
//!
//! Each background collector gets one thread running its own small tokio
//! runtime, and the things it watches are tasks on it. Work that can only block,
//! like asking the system about a file, goes to that runtime's blocking pool.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};
use tracing::error;

/// How quickly a stopped collector's thread notices.
const STOP_CHECK: Duration = Duration::from_millis(100);

/// How many blocking calls a collector can have stuck at once. Anything beyond
/// this waits, so a dead network mount can't keep adding threads.
const MAX_BLOCKING_THREADS: usize = 8;

/// How long an idle blocking thread hangs around. Rounds are seconds apart, so
/// keeping them longer only holds memory.
const BLOCKING_THREAD_KEEP_ALIVE: Duration = Duration::from_secs(1);

/// A random time up to `limit`, which keeps work on the same schedule from all
/// starting at once, whether that's in one agent or across a fleet.
pub fn jitter(limit: Duration) -> Duration {
    limit.mul_f64(rand::random())
}

/// Sleeps until a time, or until stopped.
fn pause(until: Instant, stopped: &AtomicBool) {
    while !stopped.load(Ordering::Relaxed) {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(STOP_CHECK.min(left));
    }
}

/// Finishes when stopped.
async fn stopping(stopped: &AtomicBool) {
    while !stopped.load(Ordering::Relaxed) {
        sleep(STOP_CHECK).await;
    }
}

fn runtime() -> std::io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .thread_keep_alive(BLOCKING_THREAD_KEEP_ALIVE)
        .build()
}

/// Repeats some work on its own thread and keeps the newest result, starting at a
/// random point in the interval. It stops when dropped, which happens whenever the
/// agent's config changes.
pub struct Background {
    latest: Arc<Mutex<Value>>,
    stop: Arc<AtomicBool>,
}

impl Background {
    pub fn start<Round, Work>(interval: Duration, mut round: Round) -> Self
    where
        Round: FnMut() -> Work + Send + 'static,
        Work: Future<Output = Value>,
    {
        let latest = Arc::new(Mutex::new(Value::Null));
        let stop = Arc::new(AtomicBool::new(false));

        let (saved, stopped) = (latest.clone(), stop.clone());
        thread::spawn(move || {
            let runtime = match runtime() {
                Ok(runtime) => runtime,
                Err(error) => {
                    error!(%error, "starting a background collector failed");
                    return;
                }
            };
            pause(Instant::now() + jitter(interval), &stopped);
            while !stopped.load(Ordering::Relaxed) {
                let started = Instant::now();
                let finished = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(async {
                        tokio::select! {
                            value = round() => Some(value),
                            () = stopping(&stopped) => None,
                        }
                    })
                }));
                match finished {
                    Ok(Some(value)) => {
                        *saved.lock().unwrap_or_else(PoisonError::into_inner) = value;
                    }
                    Ok(None) => {}
                    Err(_) => error!("a background collector panicked"),
                }
                pause(started + interval, &stopped);
            }
            // Something stuck in the blocking pool mustn't hold this thread.
            runtime.shutdown_background();
        });

        Self { latest, stop }
    }

    /// Null until the first round has finished.
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

/// Probes a list of things as tasks with a time limit, each starting at a random
/// point in the first half of the interval. That leaves the second half for them to
/// finish before the next round. Gives one result per item, in order. `failed`
/// stands in for anything that ran out of time or panicked, and running out of time
/// cancels the task.
pub async fn probe_all<T, O, Probe, Work>(
    items: &[Arc<T>],
    interval: Duration,
    limit: Duration,
    probe: Probe,
    failed: impl Fn(&T) -> O,
) -> Vec<O>
where
    Probe: Fn(Arc<T>) -> Work,
    Work: Future<Output = O> + Send + 'static,
    O: Send + 'static,
{
    let tasks: Vec<_> = items
        .iter()
        .map(|item| {
            let work = probe(item.clone());
            let wait = jitter(interval / 2);
            tokio::spawn(async move {
                sleep(wait).await;
                timeout(limit, work).await.ok()
            })
        })
        .collect();

    let mut results = Vec::with_capacity(items.len());
    for (task, item) in tasks.into_iter().zip(items) {
        results.push(match task.await {
            Ok(Some(result)) => result,
            _ => failed(item),
        });
    }
    results
}

/// Marks something as busy until dropped. Blocking work can't be cancelled the
/// way a task can, so this is held by the blocking call itself, and stops a stuck
/// item from being queued again on every round.
pub struct Busy(Arc<AtomicBool>);

impl Busy {
    /// `None` means it's still busy from before.
    pub fn try_start(flag: &Arc<AtomicBool>) -> Option<Self> {
        (!flag.swap(true, Ordering::Relaxed)).then(|| Self(flag.clone()))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
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

    fn items(values: &[u64]) -> Vec<Arc<u64>> {
        values.iter().copied().map(Arc::new).collect()
    }

    #[test]
    fn background_work_repeats_and_keeps_the_newest_result() {
        let mut count = 0;
        let background = Background::start(Duration::from_millis(5), move || {
            count += 1;
            let value = count;
            async move { json!(value) }
        });

        wait_until(|| background.latest().as_u64().is_some_and(|count| count >= 3));
    }

    #[test]
    fn nothing_is_reported_until_the_first_round_finishes() {
        let background = Background::start(SHORT, || async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            json!("late")
        });
        assert_eq!(background.latest(), Value::Null);
    }

    #[test]
    fn background_work_stops_when_dropped() {
        let rounds = Arc::new(AtomicUsize::new(0));
        let counted = rounds.clone();
        let background = Background::start(Duration::from_millis(5), move || {
            let count = counted.fetch_add(1, Ordering::Relaxed);
            async move { json!(count) }
        });
        wait_until(|| rounds.load(Ordering::Relaxed) > 0);

        drop(background);
        thread::sleep(Duration::from_millis(50));
        let after_stopping = rounds.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(rounds.load(Ordering::Relaxed), after_stopping);
    }

    #[test]
    fn a_panic_costs_one_round_and_keeps_going() {
        let mut count = 0;
        let background = Background::start(Duration::from_millis(5), move || {
            count += 1;
            let value = count;
            async move {
                assert!(value != 2, "deliberate test panic");
                json!(value)
            }
        });

        wait_until(|| background.latest().as_u64().is_some_and(|count| count >= 3));
    }

    #[test]
    fn jitter_varies_and_stays_within_its_limit() {
        let limit = Duration::from_secs(10);
        let times: Vec<Duration> = (0..100).map(|_| jitter(limit)).collect();

        assert!(times.iter().all(|time| *time < limit));
        assert!(times.iter().any(|time| *time != times[0]));
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn the_first_round_waits_for_a_random_part_of_the_interval() {
        let rounds = Arc::new(AtomicUsize::new(0));
        let counted = rounds.clone();
        let background = Background::start(Duration::from_secs(36_000), move || {
            counted.fetch_add(1, Ordering::Relaxed);
            async { json!(1) }
        });

        thread::sleep(Duration::from_millis(100));

        assert_eq!(rounds.load(Ordering::Relaxed), 0);
        assert_eq!(background.latest(), Value::Null);
    }

    #[test]
    fn stopping_does_not_wait_for_a_round_to_finish() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let (ended, flag) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let (started, dropped) = (ended.clone(), flag.clone());
        let background = Background::start(Duration::ZERO, move || {
            let (started, guard) = (started.clone(), Flag(dropped.clone()));
            async move {
                started.store(true, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(3600)).await;
                drop(guard);
                json!(1)
            }
        });
        wait_until(|| ended.load(Ordering::Relaxed));

        drop(background);

        wait_until(|| flag.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn items_start_at_different_times_in_the_first_half_of_the_interval() {
        let interval = Duration::from_secs(1);
        let started = Instant::now();
        let waits = probe_all(
            &items(&[0; 20]),
            interval,
            Duration::from_secs(5),
            |_| async move { started.elapsed() },
            |_| Duration::MAX,
        )
        .await;

        let (first, last) = (waits.iter().min().unwrap(), waits.iter().max().unwrap());
        assert!(*last - *first > interval / 10, "{waits:?}");
        assert!(*last < interval / 2 + SHORT, "{waits:?}");
    }

    #[tokio::test]
    async fn waiting_to_start_does_not_use_up_the_time_limit() {
        let results = probe_all(
            &items(&[0; 20]),
            Duration::from_secs(1),
            SHORT,
            |_| async move { "done" },
            |_| "timed out",
        )
        .await;

        assert_eq!(results, ["done"; 20]);
    }

    #[tokio::test]
    async fn results_come_back_in_order() {
        let results = probe_all(
            &items(&[30, 1, 15]),
            Duration::ZERO,
            Duration::from_secs(5),
            |delay| async move {
                tokio::time::sleep(Duration::from_millis(*delay)).await;
                *delay
            },
            |_| 0,
        )
        .await;
        assert_eq!(results, [30, 1, 15]);
    }

    #[tokio::test]
    async fn items_run_at_the_same_time() {
        let started = Instant::now();
        probe_all(
            &items(&[200; 10]),
            Duration::ZERO,
            Duration::from_secs(5),
            |delay| async move { tokio::time::sleep(Duration::from_millis(*delay)).await },
            |_| (),
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_slow_item_times_out_without_holding_up_the_rest() {
        let started = Instant::now();
        let results = probe_all(
            &items(&[5000, 1]),
            Duration::ZERO,
            SHORT,
            |delay| async move {
                tokio::time::sleep(Duration::from_millis(*delay)).await;
                "done"
            },
            |_| "timed out",
        )
        .await;
        assert_eq!(results, ["timed out", "done"]);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_panicking_item_counts_as_failed() {
        let results = probe_all(
            &items(&[1, 2]),
            Duration::ZERO,
            Duration::from_secs(5),
            |value| async move {
                assert!(*value != 1, "deliberate test panic");
                "ok"
            },
            |_| "failed",
        )
        .await;
        assert_eq!(results, ["failed", "ok"]);
    }

    #[test]
    fn busy_items_cannot_start_twice_and_free_up_when_dropped() {
        let flag = Arc::new(AtomicBool::new(false));
        let first = Busy::try_start(&flag);
        assert!(first.is_some());
        assert!(Busy::try_start(&flag).is_none());

        drop(first);
        assert!(Busy::try_start(&flag).is_some());
    }

    #[test]
    fn the_blocking_pool_cannot_grow_past_its_limit() {
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let runtime = runtime().unwrap();

        runtime.block_on(async {
            let mut tasks = Vec::new();
            for _ in 0..(MAX_BLOCKING_THREADS * 3) {
                let (running, most) = (running.clone(), most.clone());
                tasks.push(tokio::task::spawn_blocking(move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(20));
                    running.fetch_sub(1, Ordering::SeqCst);
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });

        assert!(most.load(Ordering::SeqCst) <= MAX_BLOCKING_THREADS);
    }
}
