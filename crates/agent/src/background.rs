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
use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use maxnines_protocol::entries::Entry;
use serde_json::Value;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::task::AbortHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at, timeout};
use tracing::error;

/// Why a round has nothing to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missed {
    /// It ran past its limit.
    OutOfTime,
    /// It panicked, which the agent's log says.
    Panicked,
}

/// What's said of a round that panicked, as the error of whatever it reports.
pub const FAILED_UNEXPECTEDLY: &str =
    "it failed unexpectedly, which the agent's log says more about";

impl Missed {
    /// `late` for a round that ran out of time, or `broke` for one that panicked.
    /// Why there's nothing from a round with this `limit`, as an error says it.
    pub fn why(self, limit: Duration) -> String {
        match self {
            Self::OutOfTime => format!("it didn't finish within {} seconds", limit.as_secs()),
            Self::Panicked => FAILED_UNEXPECTEDLY.to_string(),
        }
    }

    pub fn pick<T: Clone>(self, late: &T, broke: &T) -> T {
        match self {
            Self::OutOfTime => late.clone(),
            Self::Panicked => broke.clone(),
        }
    }
}

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

/// Every `every`, first at a random point in `first_within`. After running late, the
/// next goes at once, and the ones after it keep to the same schedule.
fn schedule(first_within: Duration, every: Duration) -> Interval {
    let mut schedule = interval_at(Instant::now() + jitter(first_within), every);
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

/// An item's newest result.
#[derive(Default)]
struct Kept {
    /// Null until it has one.
    value: Value,
    /// When it was finished.
    read: DateTime<Utc>,
    /// Whether it's still to be handed over as what was read then, which happens
    /// once.
    fresh: bool,
    /// Why the round it's from found nothing, when it ran out of time or panicked,
    /// whatever was published for it.
    missed: Option<Missed>,
}

impl Kept {
    fn now(value: Value, missed: Option<Missed>) -> Self {
        Self {
            value,
            read: maxnines_protocol::time::now(),
            fresh: true,
            missed,
        }
    }
}

/// Repeats work in the background, each item on its own schedule, and keeps each
/// one's newest result. It stops when dropped, which happens whenever the agent's
/// config changes.
#[derive(Default)]
pub struct Background {
    results: Arc<Mutex<Vec<Kept>>>,
    tasks: Vec<AbortHandle>,
}

impl Background {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an item whose result never changes, such as why one can't run.
    pub fn constant(&mut self, value: Value) {
        self.lock().push(Kept::now(value, None));
    }

    /// Adds an item that runs `round` every `every`, first at a random point in
    /// the first `every`. A round that takes longer than `every` is followed at
    /// once by the next, and the ones after keep to the schedule. `publish` turns
    /// what a round found into the item's result, and is told why there's nothing
    /// for a round that ran out of `limit` or panicked. It runs between rounds, so it can keep
    /// what it needs from one to the next.
    pub fn repeat<Found, Round, Work, Publish>(
        &mut self,
        every: Duration,
        limit: Option<Duration>,
        round: Round,
        publish: Publish,
    ) -> Result<()>
    where
        Round: FnMut() -> Work + Send + 'static,
        Work: Future<Output = Found> + Send + 'static,
        Found: Send + 'static,
        Publish: FnMut(Result<Found, Missed>) -> Value + Send + 'static,
    {
        self.repeat_from(every, every, limit, round, publish)
    }

    /// As [`Self::repeat`], but the first round comes at a random point in
    /// `first_within` rather than in the first `every`, for work done so seldom
    /// that waiting a whole `every` for the first result would leave a new agent,
    /// or one whose config changed, with nothing to show for too long.
    pub fn repeat_from<Found, Round, Work, Publish>(
        &mut self,
        first_within: Duration,
        every: Duration,
        limit: Option<Duration>,
        mut round: Round,
        mut publish: Publish,
    ) -> Result<()>
    where
        Round: FnMut() -> Work + Send + 'static,
        Work: Future<Output = Found> + Send + 'static,
        Found: Send + 'static,
        Publish: FnMut(Result<Found, Missed>) -> Value + Send + 'static,
    {
        let runtime = runtime()?;
        let slot = {
            let mut results = self.lock();
            results.push(Kept::default());
            results.len() - 1
        };
        let results = self.results.clone();
        let task = runtime.spawn(async move {
            let mut schedule = schedule(first_within, every);
            loop {
                schedule.tick().await;
                let found = match catch_unwind(AssertUnwindSafe(&mut round)) {
                    Ok(work) => {
                        let work = AssertUnwindSafe(work).catch_unwind();
                        let finished = match limit {
                            Some(limit) => timeout(limit, work).await.ok(),
                            None => Some(work.await),
                        };
                        match finished {
                            Some(Ok(found)) => Ok(found),
                            Some(Err(_)) => Err(Missed::Panicked),
                            None => Err(Missed::OutOfTime),
                        }
                    }
                    Err(_) => Err(Missed::Panicked),
                };
                if matches!(found, Err(Missed::Panicked)) {
                    error!("a background collector panicked");
                }
                let missed = found.as_ref().err().copied();
                match catch_unwind(AssertUnwindSafe(|| publish(found))) {
                    Ok(value) => {
                        results.lock().unwrap_or_else(PoisonError::into_inner)[slot] =
                            Kept::now(value, missed);
                    }
                    Err(_) => error!("a background collector panicked"),
                }
            }
        });
        self.tasks.push(task.abort_handle());
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Kept>> {
        self.results.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Each item's newest result, in the order they were added, with null for one
    /// that has none yet.
    pub fn latest(&self) -> Vec<Value> {
        self.lock().iter().map(|kept| kept.value.clone()).collect()
    }

    /// Each round finished since this was last asked, in the order the items were
    /// added: what was published for it, when it finished, and why it found
    /// nothing if it ran out of time or panicked. Each is handed over once.
    fn finished(&self) -> Vec<(Value, DateTime<Utc>, Option<Missed>)> {
        self.lock()
            .iter_mut()
            .filter_map(|kept| {
                std::mem::take(&mut kept.fresh)
                    .then(|| (kept.value.clone(), kept.read, kept.missed))
            })
            .collect()
    }

    /// Each result finished since this was last asked, with when it was finished,
    /// in the order the items were added. Each is handed over once, so an item
    /// that hasn't finished another round since has nothing here.
    pub fn fresh(&self) -> Vec<(Value, DateTime<Utc>)> {
        self.finished()
            .into_iter()
            .filter(|(result, ..)| !result.is_null())
            .map(|(result, time, _)| (result, time))
            .collect()
    }

    /// What a collector's [`Collector::read`] is: the entries of each fresh result,
    /// read when it was finished.
    ///
    /// [`Collector::read`]: maxnines_collectors::Collector::read
    pub fn read(&self, entries: impl Fn(&Value, DateTime<Utc>) -> Vec<Entry>) -> Vec<Entry> {
        self.fresh()
            .iter()
            .flat_map(|(result, time)| entries(result, *time))
            .collect()
    }

    /// As [`Self::read`], for a collector that publishes what it knew before for a
    /// round that ran out of time or panicked. That isn't a reading, so `missed`
    /// says what such a round's entries are instead, given what was published.
    pub fn read_or(
        &self,
        entries: impl Fn(&Value, DateTime<Utc>) -> Vec<Entry>,
        missed: impl Fn(&Value, Missed, DateTime<Utc>) -> Vec<Entry>,
    ) -> Vec<Entry> {
        self.finished()
            .iter()
            .flat_map(|(result, time, why)| match why {
                Some(why) => missed(result, *why, *time),
                None => entries(result, *time),
            })
            .collect()
    }

    /// Every item's rows together, a list's items each a row of their own. Null
    /// until something has a result, unless there's nothing to wait for.
    pub fn rows(&self) -> Value {
        let results = self.lock();
        if !results.is_empty() && results.iter().all(|kept| kept.value.is_null()) {
            return Value::Null;
        }
        let mut rows = Vec::new();
        for result in results.iter() {
            match &result.value {
                Value::Null => {}
                Value::Array(items) => rows.extend(items.iter().cloned()),
                row => rows.push(row.clone()),
            }
        }
        Value::Array(rows)
    }
}

/// The rows of one result: a list's items, or the one row it is.
pub fn rows_of(result: &Value) -> &[Value] {
    match result {
        Value::Null => &[],
        Value::Array(rows) => rows,
        row => std::slice::from_ref(row),
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

/// What the tests of collectors that read in the background share.
#[cfg(test)]
pub mod testing {
    use super::*;

    impl Background {
        /// Holding these results, each finished just now, and running nothing.
        pub fn holding(results: impl IntoIterator<Item = Value>) -> Self {
            let mut background = Self::new();
            for result in results {
                background.constant(result);
            }
            background
        }

        /// Holding what was published for a round that found nothing, and running
        /// nothing.
        pub fn missing(published: Value, missed: Missed) -> Self {
            let background = Self::new();
            background.lock().push(Kept::now(published, Some(missed)));
            background
        }
    }

    /// What a collector reads of the results it holds, which it has to hand over
    /// once, each entry with when its result was finished rather than when it was
    /// asked.
    pub fn read_once(collector: &mut dyn maxnines_collectors::Collector) -> Vec<Entry> {
        let asked = DateTime::UNIX_EPOCH;
        let read = collector.read(asked).unwrap();
        assert!(read.iter().all(|entry| entry.time > asked));
        assert_eq!(collector.read(asked).unwrap(), []);
        read
    }

    /// One item's reading speaks only for its own series, where an entry with no
    /// series would speak for every other item's too.
    pub fn each_is_for_a_series(entries: &[Entry]) {
        for entry in entries {
            assert!(!entry.series.is_empty(), "{}", entry.metric);
        }
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
                |found| json!(found.ok()),
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

    /// Rounds that each wait to be let through, giving their number, and what lets
    /// one through.
    fn gated(background: &mut Background) -> Arc<tokio::sync::Semaphore> {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (waited, rounds) = (gate.clone(), Arc::new(AtomicUsize::new(0)));
        background
            .repeat(
                SHORT,
                None,
                move || {
                    let (gate, rounds) = (waited.clone(), rounds.clone());
                    async move {
                        gate.acquire().await.unwrap().forget();
                        rounds.fetch_add(1, Ordering::Relaxed) + 1
                    }
                },
                |found| json!(found.unwrap()),
            )
            .unwrap();
        gate
    }

    #[test]
    fn a_result_is_handed_over_once_with_when_it_was_finished() {
        let mut background = Background::new();
        background.constant(json!("can't run"));
        let gate = gated(&mut background);

        // Only what never changes has a result yet, and it's handed over once too.
        let before = maxnines_protocol::time::now();
        let fresh = background.fresh();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].0, json!("can't run"));
        assert!(fresh[0].1 <= before);
        assert_eq!(background.fresh(), []);

        gate.add_permits(1);
        wait_until(|| background.latest()[1] == json!(1));
        let fresh = background.fresh();
        let after = maxnines_protocol::time::now();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].0, json!(1));
        assert!(before <= fresh[0].1 && fresh[0].1 <= after);
        // Nothing has finished since, though the newest result is still kept.
        assert_eq!(background.fresh(), []);
        assert_eq!(background.latest()[1], json!(1));

        gate.add_permits(1);
        wait_until(|| background.latest()[1] == json!(2));
        let next = background.fresh();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0, json!(2));
        assert!(fresh[0].1 <= next[0].1);
    }

    #[test]
    fn a_round_that_found_nothing_is_read_as_what_its_collector_says_of_that() {
        let mut background = Background::new();
        background
            .repeat(
                SHORT,
                Some(SHORT),
                std::future::pending::<Value>,
                |found| match found {
                    Ok(found) => found,
                    Err(_) => json!("what was known before"),
                },
            )
            .unwrap();
        wait_until(|| !background.latest()[0].is_null());
        let entries = |_: &Value, _: DateTime<Utc>| panic!("it wasn't a reading");
        let missed = |published: &Value, why: Missed, time: DateTime<Utc>| {
            assert_eq!(published, &json!("what was known before"));
            assert_eq!(why, Missed::OutOfTime);
            maxnines_collectors::entries::failed(&["round.number"], time, "too slow")
        };
        // Every round runs out of time, so there may be another by the next read.
        let read = background.read_or(entries, missed);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].metric, "round.number");
    }

    #[test]
    fn reading_gives_each_fresh_results_entries_at_its_own_time() {
        let mut background = Background::new();
        let gate = gated(&mut background);
        let entries = |result: &Value, time: DateTime<Utc>| {
            let mut entries = maxnines_collectors::entries::Entries::at(time);
            entries.read("round.number", &[], result);
            entries.done()
        };
        assert_eq!(background.read(entries), []);

        gate.add_permits(1);
        wait_until(|| background.latest()[0] == json!(1));
        let finished = maxnines_protocol::time::now();
        let read = background.read(entries);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].metric, "round.number");
        assert!(read[0].time <= finished);
        assert_eq!(background.read(entries), []);
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
                |found| json!(found.ok()),
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
        assert_eq!(
            published.lock().unwrap()[..3],
            [Ok(1), Err(Missed::Panicked), Ok(3)]
        );
    }

    #[test]
    fn a_round_that_runs_out_of_time_is_published_as_that() {
        let mut background = Background::new();
        background
            .repeat(SHORT, Some(SHORT), std::future::pending::<u8>, |found| {
                json!(found == Err(Missed::OutOfTime))
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
        let mut schedule = schedule(every, every);
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

    #[tokio::test(start_paused = true)]
    async fn a_first_round_can_come_sooner_than_the_interval() {
        let every = Duration::from_secs(900);
        let first_within = Duration::from_secs(60);
        let started = Instant::now();
        let mut schedule = schedule(first_within, every);
        schedule.tick().await;
        let first = started.elapsed();
        assert!(first < first_within, "{first:?}");
        schedule.tick().await;
        assert_eq!(started.elapsed(), first + every);
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
