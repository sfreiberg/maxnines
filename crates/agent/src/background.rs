//! Runs slow or unreliable work away from the agent's main loop, which also
//! answers the server and can't wait on a dead host or a stuck network drive.
//!
//! Every background collector shares one thread, running a small tokio runtime.
//! Each thing a collector watches is a task of its own there, on its own schedule,
//! and its newest result is kept as soon as it has one, so a slow one never holds up
//! the rest. Work that can only block goes to the runtime's blocking pool, whose
//! threads are limited, so blocking calls stuck on a dead network mount can't keep
//! adding threads. The files collector is the exception: each path gets a thread of
//! its own for each look, and never a second while one is stuck, so a dead mount
//! can't take the pool from everything else.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::FutureExt;
use serde_json::Value;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::task::AbortHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at, timeout};
use tracing::error;

/// How many blocking calls can be stuck at once. Anything beyond this waits.
const MAX_BLOCKING_THREADS: usize = 8;

/// How long an idle blocking thread hangs around. Work is seconds apart, so keeping
/// them longer only holds memory.
const BLOCKING_THREAD_KEEP_ALIVE: Duration = Duration::from_secs(1);

/// The runtime every background collector shares, once one has started.
static RUNTIME: Mutex<Option<Handle>> = Mutex::new(None);

/// Keeps work on the same schedule from all starting at once, whether that's in one
/// agent or across a fleet.
pub use maxnines_checks::jitter;

/// Every `every`, first at a random point in the first one. After running late, the
/// next goes at once, and the ones after it keep to the same schedule.
fn schedule(every: Duration) -> Interval {
    let mut schedule = interval_at(Instant::now() + jitter(every), every);
    schedule.set_missed_tick_behavior(MissedTickBehavior::Skip);
    schedule
}

fn build_runtime() -> std::io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .thread_keep_alive(BLOCKING_THREAD_KEEP_ALIVE)
        .build()
}

/// The shared runtime, started on its own thread the first time it's needed. It
/// runs for as long as the agent does.
pub fn runtime() -> Result<Handle> {
    let mut shared = RUNTIME.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(handle) = &*shared {
        return Ok(handle.clone());
    }
    let runtime = build_runtime().context("starting the background collectors")?;
    let handle = runtime.handle().clone();
    thread::Builder::new()
        .name("background".to_string())
        .spawn(move || runtime.block_on(std::future::pending::<()>()))
        .context("starting the background collectors' thread")?;
    *shared = Some(handle.clone());
    Ok(handle)
}

/// Repeats work in the background, each item on its own schedule, and keeps each
/// one's newest result. It stops when dropped, which happens whenever the agent's
/// config changes.
#[derive(Default)]
pub struct Background {
    results: Arc<Mutex<Vec<Value>>>,
    tasks: Vec<AbortHandle>,
}

impl Background {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an item whose result never changes, such as why one can't run.
    pub fn constant(&mut self, value: Value) {
        self.lock().push(value);
    }

    /// Adds an item that runs `round` every `every`, first at a random point in
    /// the first `every`. A round that takes longer than `every` is followed at
    /// once by the next, and the ones after keep to the schedule. `publish` turns
    /// what a round found into the item's result, and is given `None` for a round
    /// that ran out of `limit` or panicked. It runs between rounds, so it can keep
    /// what it needs from one to the next.
    pub fn repeat<Found, Round, Work, Publish>(
        &mut self,
        every: Duration,
        limit: Option<Duration>,
        mut round: Round,
        mut publish: Publish,
    ) -> Result<()>
    where
        Round: FnMut() -> Work + Send + 'static,
        Work: Future<Output = Found> + Send + 'static,
        Found: Send + 'static,
        Publish: FnMut(Option<Found>) -> Value + Send + 'static,
    {
        let runtime = runtime()?;
        let slot = {
            let mut results = self.lock();
            results.push(Value::Null);
            results.len() - 1
        };
        let results = self.results.clone();
        let task = runtime.spawn(async move {
            let mut schedule = schedule(every);
            loop {
                schedule.tick().await;
                let found = match catch_unwind(AssertUnwindSafe(&mut round)) {
                    Ok(work) => {
                        let work = AssertUnwindSafe(work).catch_unwind();
                        match limit {
                            Some(limit) => timeout(limit, work).await.ok(),
                            None => Some(work.await),
                        }
                    }
                    Err(panic) => Some(Err(panic)),
                };
                let found = match found {
                    Some(Err(_)) => {
                        error!("a background collector panicked");
                        None
                    }
                    Some(Ok(found)) => Some(found),
                    None => None,
                };
                match catch_unwind(AssertUnwindSafe(|| publish(found))) {
                    Ok(value) => {
                        results.lock().unwrap_or_else(PoisonError::into_inner)[slot] = value;
                    }
                    Err(_) => error!("a background collector panicked"),
                }
            }
        });
        self.tasks.push(task.abort_handle());
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Value>> {
        self.results.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Each item's newest result, in the order they were added, with null for one
    /// that has none yet.
    pub fn latest(&self) -> Vec<Value> {
        self.lock().clone()
    }

    /// Every item's rows together, a list's items each a row of their own. Null
    /// until something has a result, unless there's nothing to wait for.
    pub fn rows(&self) -> Value {
        let results = self.lock();
        if !results.is_empty() && results.iter().all(Value::is_null) {
            return Value::Null;
        }
        let mut rows = Vec::new();
        for result in results.iter() {
            match result {
                Value::Null => {}
                Value::Array(items) => rows.extend(items.iter().cloned()),
                row => rows.push(row.clone()),
            }
        }
        Value::Array(rows)
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Marks something as busy until dropped. Blocking work can't be cancelled the
/// way a task can, so this is held by the blocking call itself, and stops a stuck
/// item from being started again on every round.
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

    const SHORT: Duration = Duration::from_millis(5);

    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !condition() {
            assert!(std::time::Instant::now() < deadline, "it never happened");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Counts its rounds, giving each one's number.
    fn counting(background: &mut Background, every: Duration) -> Arc<AtomicUsize> {
        let rounds = Arc::new(AtomicUsize::new(0));
        let counted = rounds.clone();
        background
            .repeat(
                every,
                None,
                move || {
                    let count = counted.fetch_add(1, Ordering::Relaxed) + 1;
                    async move { count }
                },
                |found| json!(found),
            )
            .unwrap();
        rounds
    }

    #[test]
    fn work_repeats_and_keeps_the_newest_result() {
        let mut background = Background::new();
        counting(&mut background, SHORT);

        wait_until(|| {
            background.latest()[0]
                .as_u64()
                .is_some_and(|count| count >= 3)
        });
    }

    #[test]
    fn nothing_is_reported_until_something_has_a_result() {
        let mut background = Background::new();
        background
            .repeat(SHORT, None, std::future::pending::<Value>, |found| {
                found.unwrap_or_default()
            })
            .unwrap();
        assert_eq!(background.rows(), Value::Null);
        assert_eq!(Background::new().rows(), json!([]));
    }

    #[test]
    fn work_stops_when_dropped() {
        let mut background = Background::new();
        // Goes when the work does, which is when its task has ended.
        let (alive, gone) = std::sync::mpsc::channel::<()>();
        background
            .repeat(
                SHORT,
                None,
                move || {
                    let _ = &alive;
                    async { 1 }
                },
                |found| json!(found),
            )
            .unwrap();
        wait_until(|| !background.latest()[0].is_null());

        drop(background);
        assert_eq!(
            gone.recv_timeout(Duration::from_secs(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn stopping_does_not_wait_for_a_round_to_finish() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let (started, dropped) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let mut background = Background::new();
        let (starting, flag) = (started.clone(), dropped.clone());
        background
            .repeat(
                SHORT,
                None,
                move || {
                    let (started, guard) = (starting.clone(), Flag(flag.clone()));
                    async move {
                        started.store(true, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        drop(guard);
                    }
                },
                |_| Value::Null,
            )
            .unwrap();
        wait_until(|| started.load(Ordering::Relaxed));

        drop(background);

        wait_until(|| dropped.load(Ordering::Relaxed));
    }

    #[test]
    fn a_panic_costs_one_round_and_keeps_going() {
        let mut background = Background::new();
        let rounds = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(Mutex::new(Vec::new()));
        let (counted, kept) = (rounds.clone(), published.clone());
        background
            .repeat(
                SHORT,
                None,
                move || {
                    let count = counted.fetch_add(1, Ordering::Relaxed) + 1;
                    async move {
                        assert!(count != 2, "deliberate test panic");
                        count
                    }
                },
                move |found| {
                    kept.lock().unwrap().push(found);
                    Value::Null
                },
            )
            .unwrap();

        wait_until(|| published.lock().unwrap().len() >= 3);
        assert_eq!(published.lock().unwrap()[..3], [Some(1), None, Some(3)]);
    }

    #[test]
    fn a_round_that_runs_out_of_time_is_published_as_nothing() {
        let mut background = Background::new();
        background
            .repeat(SHORT, Some(SHORT), std::future::pending::<u8>, |found| {
                json!(found.is_none())
            })
            .unwrap();
        wait_until(|| background.latest()[0] == true);
    }

    #[test]
    fn a_slow_item_does_not_hold_up_the_others() {
        let mut background = Background::new();
        background
            .repeat(SHORT, None, std::future::pending::<u8>, |_| json!("slow"))
            .unwrap();
        let fast = counting(&mut background, SHORT);

        wait_until(|| fast.load(Ordering::Relaxed) >= 3);
        assert_eq!(background.latest()[0], Value::Null);
        assert!(background.latest()[1].as_u64().unwrap() >= 1);
        assert_eq!(background.rows().as_array().unwrap().len(), 1);
    }

    #[test]
    fn rows_from_every_item_go_together() {
        let mut background = Background::new();
        background.constant(json!([{ "name": "a" }, { "name": "b" }]));
        background.constant(json!({ "name": "c" }));
        background.constant(Value::Null);
        assert_eq!(
            background.rows(),
            json!([{ "name": "a" }, { "name": "b" }, { "name": "c" }])
        );
    }

    /// On a paused clock, so a busy host can't change what's measured.
    #[tokio::test(start_paused = true)]
    async fn an_item_keeps_to_its_schedule_when_a_round_runs_late() {
        let every = Duration::from_secs(60);
        let started = Instant::now();
        let mut schedule = schedule(every);
        schedule.tick().await;
        let first = started.elapsed();
        assert!(first < every, "{first:?}");

        // A round that overruns is followed at once by the next, and the ones after
        // keep to the schedule rather than making up for what was missed.
        tokio::time::sleep(every + every / 2).await;
        let late = started.elapsed();
        schedule.tick().await;
        assert_eq!(started.elapsed(), late);
        schedule.tick().await;
        assert_eq!(started.elapsed(), first + every * 2);
    }

    #[test]
    fn the_first_round_waits_for_a_random_part_of_its_interval() {
        let mut background = Background::new();
        let rounds = counting(&mut background, Duration::from_secs(36_000));

        thread::sleep(Duration::from_millis(100));

        assert_eq!(rounds.load(Ordering::Relaxed), 0);
        assert_eq!(background.latest()[0], Value::Null);
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
        let runtime = build_runtime().unwrap();

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
