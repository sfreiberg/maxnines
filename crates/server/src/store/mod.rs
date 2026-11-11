//! Metrics storage. To add a metrics database: implement [`Store`] and
//! [`MetricsReader`] in a new module, add a variant to [`MetricsConfig`], and add
//! a match arm to [`open`].
//! Everything else the server keeps lives in [`crate::models`].

mod clickhouse;
mod duckdb;
mod flatten;
pub mod rollups;
mod shared;

use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Result;
use maxnines_protocol::Sample;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::sync::oneshot;
use tracing::{error, warn};

use crate::calculations::CalculationQuery;
use crate::config::{MetricsConfig, RetentionConfig};
use crate::metrics::{LastSample, Metric, NewestReading, SeriesQuery, SeriesResult, Trend, now_ms};
use crate::remote_checks::LOCAL_HOST_ID;
use rollups::Retention;

/// Samples waiting to be written. When this fills up, connections stop reading
/// from their agents until the database catches up.
pub const WRITE_QUEUE_SIZE: usize = 1024;

/// How often to look for upkeep when there's none going on.
const TIDY_CHECK_EVERY: Duration = Duration::from_secs(60);
/// The pause between pieces of upkeep, so samples don't queue up behind it.
const TIDY_PAUSE: Duration = Duration::from_millis(250);

/// The end of what every store can hold, a little before the year 2300. Agents can
/// send any time at all, so anything later is turned away before it gets this far.
pub const LATEST_SAMPLE_MS: u64 = 10_413_791_999_000;

/// How often to try a batch the store couldn't take, and how many times. That's about
/// two minutes, which is plenty for a database to restart. Agents keep what isn't
/// confirmed, so nothing's lost by giving up after that.
#[cfg(not(test))]
const RETRY_WAIT: Duration = Duration::from_secs(1);
#[cfg(test)]
const RETRY_WAIT: Duration = Duration::from_millis(1);
#[cfg(not(test))]
const RETRIES: usize = 120;
#[cfg(test)]
const RETRIES: usize = 3;

/// How often to look for more samples while waiting for a batch to be due.
const GATHER_EVERY: Duration = Duration::from_millis(10);

/// Enough to cover what an agent can have waiting to hear about: it keeps 64 samples
/// in memory, and sends its backlog one at a time.
const RECENT_SAMPLES_PER_HOST: usize = 80;

/// Somewhere samples are saved.
pub trait Store: Send {
    /// Saves samples together, as waiting on the disk once is what makes this quick:
    /// either all of them are stored or none of them are.
    fn write(&mut self, samples: &[NewSample]) -> Result<()>;

    /// The least time between writes, for a database that wants few, large batches.
    /// With none, samples are written as soon as the last write is done.
    fn batch_every(&self) -> Duration {
        Duration::ZERO
    }

    /// Something to read with, which can run alongside writes.
    fn reader(&self) -> Result<Arc<dyn MetricsReader>>;

    /// Does a piece of whatever upkeep the store needs, on the writer's thread between
    /// writes. Returns whether there's more to do.
    fn tidy(&mut self, _now_ms: i64) -> Result<bool> {
        Ok(false)
    }

    /// Forgets an agent: everything it ever sent, and anything kept in memory about
    /// it. If it sends again, it starts afresh.
    fn delete_host(&mut self, host_id: &str) -> Result<()>;

    /// Called once at shutdown, after the last write.
    fn close(&mut self) -> Result<()>;
}

/// Answers questions about what's been saved.
pub trait MetricsReader: Send + Sync {
    /// Buckets a metric for one agent. Series are sorted by name, and values
    /// that aren't usable numbers are skipped.
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult>;

    /// When each agent last sent anything, between two times.
    fn last_samples(&self, since_ms: i64, until_ms: i64) -> Result<Vec<LastSample>>;

    /// What one of an agent's collectors last sent between two times, including
    /// text like an error. It's an object, or a list for what repeats. Nothing is
    /// `None`, and so is a collector the store doesn't know.
    fn latest_output(
        &self,
        host_id: &str,
        collector: &str,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Option<Value>>;

    /// The newest value of each series of a metric, across every agent, between
    /// two times. Values that aren't usable numbers are skipped.
    fn newest(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<NewestReading>>;

    /// Which way each series of a metric has been heading between two times,
    /// across every agent, from a straight line fitted to its readings. A series
    /// needs two readings at different times to have one.
    fn trends(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<Trend>>;

    /// How the database itself is doing. `hour_ago_ms` is the start of the last
    /// hour, for how much is arriving now.
    fn stats(&self, hour_ago_ms: i64) -> Result<StoreStats>;

    /// How many separate series have been stored, which is what storage grows with.
    fn series_count(&self) -> Result<u64>;

    /// Combines a metric across hosts. Lines are sorted by name, and each point's
    /// `avg`, `min` and `max` are all the calculated value.
    fn calculate(&self, query: &CalculationQuery) -> Result<SeriesResult>;
}

/// How a metrics database is doing. Sizes are as the database words them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StoreStats {
    pub engine: &'static str,
    pub size: String,
    pub write_ahead_log: String,
    pub memory_used: String,
    pub memory_limit: String,
    pub collectors: Vec<CollectorStats>,
    /// Everything stored, where that's more than `collectors` adds up to.
    pub total_rows: Option<i64>,
}

/// What's stored from one collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectorStats {
    pub name: String,
    /// Over all time, where the store can say cheaply. ClickHouse only counts the
    /// last hour, so it leaves this out.
    pub rows: Option<i64>,
    pub rows_last_hour: i64,
    pub oldest_ms: i64,
    pub newest_ms: i64,
}

/// How many samples have been through the writer since the server started.
#[derive(Debug, Default)]
pub struct WriteCounts {
    pub written: AtomicU64,
    pub failed: AtomicU64,
    /// How many readings those samples held.
    pub values: AtomicU64,
    /// The longest write since this was last reset, as a sign of a struggling disk.
    pub slowest_write_ms: AtomicU64,
}

pub fn open(config: &MetricsConfig, retention: RetentionConfig) -> Result<Box<dyn Store>> {
    let retention = Retention::from(retention);
    Ok(match config {
        MetricsConfig::Duckdb { path, memory_limit } => {
            Box::new(duckdb::DuckDbStore::open(path, memory_limit, retention)?)
        }
        MetricsConfig::Clickhouse {
            url,
            database,
            user,
            password_file,
        } => Box::new(clickhouse::ClickHouseStore::open(
            url,
            database,
            user.as_deref(),
            password_file.as_deref(),
            retention,
        )?),
    })
}

pub struct NewSample {
    pub host_id: String,
    pub hostname: String,
    pub sample: Sample,
}

pub enum WriterCommand {
    /// Something the server recorded itself.
    Save(NewSample),
    /// A sample from an agent, which keeps it until told on `acks` that it's stored.
    SaveAndAck {
        sample: NewSample,
        acks: mpsc::Sender<u64>,
    },
    /// Deletes everything an agent sent, after anything queued before this is saved.
    /// `done` hears whether that worked.
    DeleteHost {
        host_id: String,
        done: oneshot::Sender<Result<(), String>>,
    },
    /// Finish queued work and close the database cleanly.
    Stop,
}

/// Deletes everything an agent sent, once the writer gets to it.
pub async fn delete_host(writer: &mpsc::Sender<WriterCommand>, host_id: &str) -> Result<()> {
    let (done, finished) = oneshot::channel();
    let command = WriterCommand::DeleteHost {
        host_id: host_id.to_string(),
        done,
    };
    writer
        .send(command)
        .await
        .map_err(|_| anyhow::anyhow!("the metrics writer has stopped"))?;
    match finished.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => anyhow::bail!("deleting the host's metrics failed: {error}"),
        Err(_) => anyhow::bail!("the metrics writer stopped before deleting the host's metrics"),
    }
}

/// The samples each agent sent last. An agent sends a sample again if it never heard
/// that it was stored, which happens when a connection ends at the wrong moment, and
/// those shouldn't be stored twice. This catches them straight away. A server restart
/// forgets these, so the store also drops repeats when it tidies.
#[derive(Default)]
struct RecentSamples(HashMap<String, VecDeque<u64>>);

impl RecentSamples {
    /// Notes a sample, and returns whether it's already been seen.
    fn seen(&mut self, host_id: &str, timestamp_ms: u64) -> bool {
        if !self.0.contains_key(host_id) {
            self.0.insert(host_id.to_string(), VecDeque::new());
        }
        let Some(recent) = self.0.get_mut(host_id) else {
            return false;
        };
        if recent.contains(&timestamp_ms) {
            return true;
        }
        if recent.len() == RECENT_SAMPLES_PER_HOST {
            recent.pop_front();
        }
        recent.push_back(timestamp_ms);
        false
    }

    /// For a sample that couldn't be stored, which needs to be let in next time.
    fn forget(&mut self, host_id: &str, timestamp_ms: u64) {
        if let Some(recent) = self.0.get_mut(host_id) {
            recent.retain(|time| *time != timestamp_ms);
        }
    }

    /// For an agent that's been deleted, whose samples have gone with it.
    fn forget_host(&mut self, host_id: &str) {
        self.0.remove(host_id);
    }
}

/// Runs the store on its own thread, so slow database calls can't hold up the
/// async tasks that answer heartbeats.
pub fn spawn_writer(
    store: Box<dyn Store>,
    counts: Arc<WriteCounts>,
) -> (mpsc::Sender<WriterCommand>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(WRITE_QUEUE_SIZE);
    let handle = thread::spawn(move || run_writer(store, receiver, &counts));
    (sender, handle)
}

/// Saves whatever has queued up since the last write in one go, so writes grow to
/// keep up with a slow disk or a busy moment, and a quiet server saves each sample
/// as it arrives.
fn run_writer(
    mut store: Box<dyn Store>,
    mut commands: mpsc::Receiver<WriterCommand>,
    counts: &WriteCounts,
) {
    let mut queued = Vec::with_capacity(WRITE_QUEUE_SIZE);
    let mut recent = RecentSamples::default();
    let mut stopping = false;
    let mut next_tidy = Instant::now();
    let every = store.batch_every();
    let mut next_write = Instant::now();
    // What's left from last time goes first, without waiting for more.
    while !stopping
        && (!queued.is_empty() || commands.blocking_recv_many(&mut queued, WRITE_QUEUE_SIZE) > 0)
    {
        gather_until(next_write, &mut commands, &mut queued);
        let mut samples = Vec::with_capacity(queued.len());
        // Every acknowledgement each sample owes: a sample sent twice in one batch is
        // stored once, and both copies hear about it only if the batch is saved.
        let mut acks: Vec<Vec<mpsc::Sender<u64>>> = Vec::with_capacity(queued.len());
        let mut in_batch: HashMap<(String, u64), usize> = HashMap::new();
        // Repeats of samples stored by an earlier batch, which can be answered now.
        let mut answered = Vec::new();
        let mut deletion = None;
        // A batch ends at a delete, so what came before it is deleted with it and what
        // came after is written after it.
        let end = queued
            .iter()
            .position(|command| matches!(command, WriterCommand::DeleteHost { .. }))
            .map_or(queued.len(), |delete| delete + 1);
        for command in queued.drain(..end) {
            match command {
                WriterCommand::Save(sample) => {
                    samples.push(sample);
                    acks.push(Vec::new());
                }
                WriterCommand::SaveAndAck { sample, acks: ack } => {
                    let time = sample.sample.timestamp_ms;
                    let key = (sample.host_id.clone(), time);
                    if let Some(&index) = in_batch.get(&key) {
                        acks[index].push(ack);
                    } else if recent.seen(&sample.host_id, time) {
                        answered.push((ack, time));
                    } else {
                        in_batch.insert(key, samples.len());
                        samples.push(sample);
                        acks.push(vec![ack]);
                    }
                }
                WriterCommand::DeleteHost { host_id, done } => deletion = Some((host_id, done)),
                WriterCommand::Stop => {
                    stopping = true;
                    break;
                }
            }
        }
        next_write = Instant::now() + every;
        if !samples.is_empty() {
            let saved = save(store.as_mut(), &samples, counts);
            for (new, acks) in samples.iter().zip(acks) {
                let time = new.sample.timestamp_ms;
                if saved {
                    answered.extend(acks.into_iter().map(|ack| (ack, time)));
                } else if !acks.is_empty() {
                    recent.forget(&new.host_id, time);
                }
            }
        }
        // An agent that's gone will send the sample again, and hear back then.
        for (ack, time) in answered {
            ack.try_send(time).ok();
        }
        // After the batch, so nothing the agent sent before this is left behind.
        if let Some((host_id, done)) = deletion {
            let result = delete_from(store.as_mut(), &host_id);
            if result.is_ok() {
                recent.forget_host(&host_id);
            }
            done.send(result).ok();
        }
        if Instant::now() >= next_tidy {
            let more = tidy(store.as_mut());
            next_tidy = Instant::now() + if more { TIDY_PAUSE } else { TIDY_CHECK_EVERY };
        }
    }

    match catch_unwind(AssertUnwindSafe(|| store.close())) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(error = format!("{error:#}"), "closing the store failed"),
        Err(_) => error!("store panicked while closing"),
    }
}

/// Collects what arrives until a batch is due. A full batch doesn't wait, so a busy
/// server isn't limited by the timer, and stopping doesn't wait either.
fn gather_until(
    due: Instant,
    commands: &mut mpsc::Receiver<WriterCommand>,
    queued: &mut Vec<WriterCommand>,
) {
    while Instant::now() < due
        && queued.len() < WRITE_QUEUE_SIZE
        && !matches!(queued.last(), Some(WriterCommand::Stop))
    {
        match commands.try_recv() {
            Ok(command) => queued.push(command),
            Err(TryRecvError::Empty) => thread::sleep(GATHER_EVERY),
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

/// Deletes an agent's samples, or says why that didn't work.
fn delete_from(store: &mut dyn Store, host_id: &str) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(|| store.delete_host(host_id))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let error = format!("{error:#}");
            error!(host_id = host_id, error, "deleting a host's metrics failed");
            Err(error)
        }
        Err(_) => {
            error!(
                host_id = host_id,
                "the store panicked deleting a host's metrics"
            );
            Err("the store panicked".to_string())
        }
    }
}

/// Upkeep failing leaves everything readable, so it's only worth saying so.
fn tidy(store: &mut dyn Store) -> bool {
    match catch_unwind(AssertUnwindSafe(|| store.tidy(now_ms()))) {
        Ok(Ok(more)) => more,
        Ok(Err(error)) => {
            error!(error = format!("{error:#}"), "tidying the store failed");
            false
        }
        Err(_) => {
            error!("the store panicked while tidying");
            false
        }
    }
}

/// Writes a batch once, counting it if that works.
fn write_batch(
    store: &mut dyn Store,
    samples: &[NewSample],
    counts: &WriteCounts,
) -> Result<(), String> {
    let started = Instant::now();
    match catch_unwind(AssertUnwindSafe(|| store.write(samples))) {
        Ok(Ok(())) => {
            // From agents, as the server recording itself isn't ingesting anything.
            let from_hosts = || samples.iter().filter(|new| new.host_id != LOCAL_HOST_ID);
            counts
                .written
                .fetch_add(from_hosts().count() as u64, Ordering::Relaxed);
            let values = from_hosts().flat_map(|new| new.sample.metrics.values());
            counts
                .values
                .fetch_add(values.map(count_values).sum(), Ordering::Relaxed);
            counts
                .slowest_write_ms
                .fetch_max(started.elapsed().as_millis() as u64, Ordering::Relaxed);
            Ok(())
        }
        Ok(Err(error)) => Err(format!("{error:#}")),
        Err(_) => Err("the store panicked".to_string()),
    }
}

/// Saves a batch, and returns whether it was. A batch stays together: samples are
/// checked before they get here, so a failure means the database itself has a problem.
/// What isn't saved stays with the agents that sent it, as they only let go of a sample
/// once they hear it's stored.
fn save(store: &mut dyn Store, samples: &[NewSample], counts: &WriteCounts) -> bool {
    let Err(mut error) = write_batch(store, samples, counts) else {
        return true;
    };
    warn!(error, samples = samples.len(), "write failed, trying again");
    for _ in 0..RETRIES {
        thread::sleep(RETRY_WAIT);
        match write_batch(store, samples, counts) {
            Ok(()) => return true,
            Err(failure) => error = failure,
        }
    }
    // From agents, as the saved count is, so the two add up.
    let from_hosts = samples
        .iter()
        .filter(|new| new.host_id != LOCAL_HOST_ID)
        .count();
    counts
        .failed
        .fetch_add(from_hosts as u64, Ordering::Relaxed);
    error!(error, samples = samples.len(), "write failed, not saved");
    false
}

/// How many readings a collector's output holds.
fn count_values(value: &Value) -> u64 {
    match value {
        Value::Null => 0,
        Value::Array(items) => items.iter().map(count_values).sum(),
        Value::Object(fields) => fields.values().map(count_values).sum(),
        _ => 1,
    }
}

#[cfg(test)]
pub mod testing {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    use anyhow::bail;

    use super::*;

    /// What a [`MemoryStore`] has saved, kept by the test after the store moves
    /// to the writer thread.
    #[derive(Clone, Default)]
    pub struct Saved {
        /// (agent ID, host, timestamp)
        pub samples: Arc<Mutex<Vec<(String, String, u64)>>>,
        /// How many samples each successful write held.
        pub writes: Arc<Mutex<Vec<usize>>>,
        pub closed: Arc<Mutex<bool>>,
        /// Holds up writes while it's set, as a slow disk does.
        pub paused: Arc<AtomicBool>,
        /// Agents deleted, in order.
        pub deleted: Arc<Mutex<Vec<String>>>,
    }

    /// Has nothing to report, for tests that aren't about metrics.
    pub struct EmptyReader;

    impl MetricsReader for EmptyReader {
        fn series(&self, _query: &SeriesQuery) -> Result<SeriesResult> {
            Ok(SeriesResult::default())
        }

        fn last_samples(&self, _since_ms: i64, _until_ms: i64) -> Result<Vec<LastSample>> {
            Ok(Vec::new())
        }

        fn latest_output(
            &self,
            _host_id: &str,
            _collector: &str,
            _since_ms: i64,
            _until_ms: i64,
        ) -> Result<Option<Value>> {
            Ok(None)
        }

        fn newest(
            &self,
            _metric: &Metric,
            _since_ms: i64,
            _until_ms: i64,
        ) -> Result<Vec<NewestReading>> {
            Ok(Vec::new())
        }

        fn trends(&self, _metric: &Metric, _since_ms: i64, _until_ms: i64) -> Result<Vec<Trend>> {
            Ok(Vec::new())
        }

        fn stats(&self, _hour_ago_ms: i64) -> Result<StoreStats> {
            Ok(StoreStats::default())
        }

        fn series_count(&self) -> Result<u64> {
            Ok(0)
        }

        fn calculate(&self, _query: &CalculationQuery) -> Result<SeriesResult> {
            Ok(SeriesResult::default())
        }
    }

    /// Fails or panics when given those words as a host name.
    pub struct MemoryStore(pub Saved);

    impl Store for MemoryStore {
        fn write(&mut self, samples: &[NewSample]) -> Result<()> {
            while self.0.paused.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1));
            }
            for new in samples {
                match new.hostname.as_str() {
                    "fail" => bail!("deliberate test failure"),
                    "panic" => panic!("deliberate test panic"),
                    _ => {}
                }
            }
            self.0.writes.lock().unwrap().push(samples.len());
            self.0
                .samples
                .lock()
                .unwrap()
                .extend(samples.iter().map(|new| {
                    (
                        new.host_id.clone(),
                        new.hostname.clone(),
                        new.sample.timestamp_ms,
                    )
                }));
            Ok(())
        }

        fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
            Ok(Arc::new(EmptyReader))
        }

        /// Fails for an agent called "fail".
        fn delete_host(&mut self, host_id: &str) -> Result<()> {
            if host_id == "fail" {
                bail!("deliberate test failure");
            }
            let mut samples = self.0.samples.lock().unwrap();
            samples.retain(|(host, _, _)| host != host_id);
            self.0.deleted.lock().unwrap().push(host_id.to_string());
            Ok(())
        }

        fn close(&mut self) -> Result<()> {
            *self.0.closed.lock().unwrap() = true;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::testing::{MemoryStore, Saved};
    use super::*;

    fn from_host(hostname: &str, timestamp_ms: u64, acks: &mpsc::Sender<u64>) -> WriterCommand {
        WriterCommand::SaveAndAck {
            sample: NewSample {
                host_id: "host-1".to_string(),
                hostname: hostname.to_string(),
                sample: Sample {
                    timestamp_ms,
                    metrics: BTreeMap::new(),
                },
            },
            acks: acks.clone(),
        }
    }

    /// Runs commands through a writer, and returns what it stored and acknowledged.
    fn run(
        commands: impl FnOnce(&mpsc::Sender<u64>) -> Vec<WriterCommand>,
    ) -> (Vec<u64>, Vec<u64>) {
        let saved = Saved::default();
        let store = Box::new(MemoryStore(saved.clone()));
        let (writer, thread) = spawn_writer(store, Arc::default());
        let (acks, mut acked) = mpsc::channel(16);
        for command in commands(&acks) {
            writer.blocking_send(command).unwrap();
        }
        writer.blocking_send(WriterCommand::Stop).unwrap();
        thread.join().unwrap();
        drop(acks);

        let mut times = Vec::new();
        while let Some(time) = acked.blocking_recv() {
            times.push(time);
        }
        let stored = saved.samples.lock().unwrap();
        (stored.iter().map(|sample| sample.2).collect(), times)
    }

    #[test]
    fn a_sample_is_acknowledged_once_it_is_stored() {
        let (stored, acked) =
            run(|acks| vec![from_host("web", 1, acks), from_host("web", 2, acks)]);
        assert_eq!(stored, [1, 2]);
        assert_eq!(acked, [1, 2]);
    }

    #[test]
    fn a_sample_that_could_not_be_stored_is_not_acknowledged() {
        let (stored, acked) = run(|acks| vec![from_host("fail", 1, acks)]);
        assert!(stored.is_empty());
        assert!(acked.is_empty());
    }

    #[test]
    fn a_sample_sent_again_is_acknowledged_without_being_stored_twice() {
        let saved = Saved::default();
        let store = Box::new(MemoryStore(saved.clone()));
        let (writer, thread) = spawn_writer(store, Arc::default());
        let (acks, mut acked) = mpsc::channel(16);

        writer.blocking_send(from_host("web", 1, &acks)).unwrap();
        assert_eq!(acked.blocking_recv(), Some(1));
        writer.blocking_send(from_host("web", 1, &acks)).unwrap();
        assert_eq!(acked.blocking_recv(), Some(1));

        writer.blocking_send(WriterCommand::Stop).unwrap();
        thread.join().unwrap();
        assert_eq!(saved.samples.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_sample_sent_twice_in_one_batch_is_stored_once_and_answered_twice() {
        let (stored, acked) = run(|acks| {
            vec![
                from_host("web", 1, acks),
                from_host("web", 1, acks),
                from_host("web", 2, acks),
            ]
        });
        assert_eq!(stored, [1, 2]);
        assert_eq!(acked, [1, 1, 2]);
    }

    /// An agent sends a sample again after a minute without an answer, which during a
    /// long database outage lands in the same batch as the first copy. Answering the
    /// second copy when the batch fails would make the agent throw the sample away.
    #[test]
    fn a_repeat_in_a_failed_batch_is_not_acknowledged() {
        let (stored, acked) = run(|acks| {
            vec![
                from_host("fail", 1, acks),
                from_host("fail", 1, acks),
                from_host("fail", 2, acks),
            ]
        });
        assert!(stored.is_empty());
        assert!(acked.is_empty(), "{acked:?}");
    }

    #[test]
    fn a_sample_that_failed_can_be_stored_when_it_is_sent_again() {
        let saved = Saved::default();
        let store = Box::new(MemoryStore(saved.clone()));
        let counts = Arc::new(WriteCounts::default());
        let (writer, thread) = spawn_writer(store, counts.clone());
        let (acks, mut acked) = mpsc::channel(16);

        writer.blocking_send(from_host("fail", 1, &acks)).unwrap();
        wait_for_failures(&counts, 1);
        writer.blocking_send(from_host("web", 1, &acks)).unwrap();
        assert_eq!(acked.blocking_recv(), Some(1));

        writer.blocking_send(WriterCommand::Stop).unwrap();
        thread.join().unwrap();
        assert_eq!(saved.samples.lock().unwrap().len(), 1);
    }

    #[test]
    fn every_reading_in_a_collectors_output_is_counted() {
        let output = serde_json::json!({
            "usage": 1.5,
            "name": "text",
            "missing": null,
            "per_core": [1, 2],
            "load": { "one": 1, "five": { "deep": 2 } },
        });
        assert_eq!(count_values(&output), 6);
    }

    /// Fails a set number of times, as a database does while it's out of reach.
    struct Unreachable {
        failures: usize,
        writes: Vec<usize>,
    }

    impl Store for Unreachable {
        fn write(&mut self, samples: &[NewSample]) -> Result<()> {
            self.writes.push(samples.len());
            if self.failures > 0 {
                self.failures -= 1;
                anyhow::bail!("can't reach the database");
            }
            Ok(())
        }

        fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
            Ok(Arc::new(super::testing::EmptyReader))
        }

        fn delete_host(&mut self, _host_id: &str) -> Result<()> {
            Ok(())
        }

        fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    fn batch(size: u64) -> Vec<NewSample> {
        (0..size)
            .map(|time| NewSample {
                host_id: "host-1".to_string(),
                hostname: "web".to_string(),
                sample: Sample {
                    timestamp_ms: time,
                    metrics: BTreeMap::new(),
                },
            })
            .collect()
    }

    fn wait_for_failures(counts: &WriteCounts, failures: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while counts.failed.load(Ordering::Relaxed) < failures {
            assert!(Instant::now() < deadline, "the write never failed");
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Each write's size and when it happened.
    type Writes = Arc<std::sync::Mutex<Vec<(usize, Instant)>>>;

    /// Wants a gap between writes, and says how big each was and when.
    struct Timed(Writes, Duration);

    const BATCH_EVERY: Duration = Duration::from_millis(100);

    impl Store for Timed {
        fn batch_every(&self) -> Duration {
            self.1
        }

        fn write(&mut self, samples: &[NewSample]) -> Result<()> {
            self.0.lock().unwrap().push((samples.len(), Instant::now()));
            Ok(())
        }

        fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
            Ok(Arc::new(super::testing::EmptyReader))
        }

        fn delete_host(&mut self, _host_id: &str) -> Result<()> {
            Ok(())
        }

        fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_store_can_ask_for_samples_to_be_gathered_into_a_batch() {
        let writes: Writes = Arc::default();
        let store = Box::new(Timed(Arc::clone(&writes), BATCH_EVERY));
        let (writer, thread) = spawn_writer(store, Arc::default());

        for time in 0..20 {
            writer.blocking_send(save("web", time)).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        // Stopping writes what's left at once, so it waits for everything first.
        wait_for_written(&writes, 20);
        writer.blocking_send(WriterCommand::Stop).unwrap();
        thread.join().unwrap();

        let writes = writes.lock().unwrap();
        let sizes: Vec<usize> = writes.iter().map(|(size, _)| *size).collect();
        assert_eq!(sizes.iter().sum::<usize>(), 20);
        assert!(sizes.len() < 20, "nothing was gathered: {sizes:?}");
        // Each write waits the store's time after the one before, however the
        // host schedules the threads. The time is counted from just before the
        // previous write starts, so a sliver of it can be spent getting there.
        for pair in writes.windows(2) {
            let gap = pair[1].1 - pair[0].1;
            assert!(
                gap >= BATCH_EVERY - Duration::from_millis(5),
                "{gap:?} in {sizes:?}"
            );
        }
    }

    /// Waits for this many samples to have been written, however long that takes.
    fn wait_for_written(writes: &Writes, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let written = || {
            writes
                .lock()
                .unwrap()
                .iter()
                .map(|(size, _)| size)
                .sum::<usize>()
        };
        while written() < count {
            assert!(Instant::now() < deadline, "only {} were written", written());
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_full_batch_does_not_wait_for_the_timer() {
        // An hour between batches, so only a full one can be written in time.
        let writes: Writes = Arc::default();
        let store = Box::new(Timed(Arc::clone(&writes), Duration::from_secs(3600)));
        let (writer, thread) = spawn_writer(store, Arc::default());

        // The first goes at once, as nothing came before it.
        writer.blocking_send(save("web", 0)).unwrap();
        wait_for_written(&writes, 1);
        for time in 1..=WRITE_QUEUE_SIZE as u64 {
            writer.blocking_send(save("web", time)).unwrap();
        }
        wait_for_written(&writes, 1 + WRITE_QUEUE_SIZE);

        let sizes: Vec<usize> = writes
            .lock()
            .unwrap()
            .iter()
            .map(|(size, _)| *size)
            .collect();
        assert_eq!(sizes, [1, WRITE_QUEUE_SIZE]);
        writer.blocking_send(WriterCommand::Stop).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn a_batch_that_fails_goes_again_whole() {
        let mut store = Unreachable {
            failures: 2,
            writes: Vec::new(),
        };
        let counts = WriteCounts::default();

        assert!(super::save(&mut store, &batch(100), &counts));

        assert_eq!(store.writes, [100, 100, 100]);
        assert_eq!(counts.written.load(Ordering::Relaxed), 100);
        assert_eq!(counts.failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_database_that_stays_away_is_given_up_on_for_agents_to_send_again() {
        let mut store = Unreachable {
            failures: usize::MAX,
            writes: Vec::new(),
        };
        let counts = WriteCounts::default();

        assert!(!super::save(&mut store, &batch(100), &counts));

        assert_eq!(store.writes.len(), 1 + RETRIES);
        assert!(store.writes.iter().all(|size| *size == 100));
        assert_eq!(counts.failed.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn only_the_latest_samples_are_remembered() {
        let mut recent = RecentSamples::default();
        for time in 0..RECENT_SAMPLES_PER_HOST as u64 + 1 {
            assert!(!recent.seen("a", time));
        }

        assert!(recent.seen("a", 1));
        assert!(!recent.seen("a", 0), "pushed out by newer samples");
        assert!(!recent.seen("b", 1), "each host has its own");
    }

    fn save(hostname: &str, timestamp_ms: u64) -> WriterCommand {
        WriterCommand::Save(NewSample {
            host_id: "host-1".to_string(),
            hostname: hostname.to_string(),
            sample: Sample {
                timestamp_ms,
                metrics: BTreeMap::new(),
            },
        })
    }

    /// Queues everything before the writer starts, so it all arrives together.
    fn run_with(commands: Vec<WriterCommand>) -> (Saved, WriteCounts) {
        let saved = Saved::default();
        let counts = WriteCounts::default();
        let (sender, receiver) = mpsc::channel(WRITE_QUEUE_SIZE);
        for command in commands {
            sender.try_send(command).unwrap();
        }
        run_writer(Box::new(MemoryStore(saved.clone())), receiver, &counts);
        (saved, counts)
    }

    fn timestamps(saved: &Saved) -> Vec<u64> {
        saved.samples.lock().unwrap().iter().map(|s| s.2).collect()
    }

    fn delete(host_id: &str) -> (WriterCommand, oneshot::Receiver<Result<(), String>>) {
        let (done, finished) = oneshot::channel();
        let command = WriterCommand::DeleteHost {
            host_id: host_id.to_string(),
            done,
        };
        (command, finished)
    }

    #[test]
    fn an_agent_is_deleted_after_what_was_queued_before_it() {
        let (deletion, mut finished) = delete("host-1");
        let (saved, _) = run_with(vec![save("a", 1), deletion, WriterCommand::Stop]);

        assert_eq!(finished.try_recv().unwrap(), Ok(()));
        assert!(timestamps(&saved).is_empty());
        assert_eq!(*saved.deleted.lock().unwrap(), ["host-1"]);
    }

    #[test]
    fn a_delete_that_fails_says_why() {
        let (deletion, mut finished) = delete("fail");
        run_with(vec![deletion, WriterCommand::Stop]);

        let error = finished.try_recv().unwrap().unwrap_err();
        assert!(error.contains("deliberate test failure"), "{error}");
    }

    #[test]
    fn a_deleted_agent_sending_the_same_moment_again_is_stored_again() {
        let (stored, acked) = run(|acks| {
            let (deletion, _) = delete("host-1");
            vec![from_host("a", 1, acks), deletion, from_host("a", 1, acks)]
        });

        assert_eq!(stored, [1]);
        assert_eq!(acked, [1, 1]);
    }

    #[test]
    fn keeps_writing_after_failures_and_panics() {
        let saved = Saved::default();
        let counts = Arc::new(WriteCounts::default());
        let store = Box::new(MemoryStore(saved.clone()));
        let (sender, handle) = spawn_writer(store, counts.clone());

        sender.blocking_send(save("fail", 1)).unwrap();
        wait_for_failures(&counts, 1);
        sender.blocking_send(save("panic", 2)).unwrap();
        wait_for_failures(&counts, 2);
        sender.blocking_send(save("a", 3)).unwrap();
        sender.blocking_send(WriterCommand::Stop).unwrap();
        handle.join().unwrap();

        assert_eq!(timestamps(&saved), [3]);
    }

    #[test]
    fn samples_that_queue_up_are_written_together() {
        let (saved, counts) = run_with(vec![
            save("a", 1),
            save("a", 2),
            save("a", 3),
            WriterCommand::Stop,
        ]);

        assert_eq!(*saved.writes.lock().unwrap(), [3]);
        assert_eq!(timestamps(&saved), [1, 2, 3]);
        assert_eq!(counts.written.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn a_batch_is_never_split_up() {
        let (saved, counts) = run_with(vec![
            save("a", 1),
            save("fail", 2),
            save("a", 3),
            WriterCommand::Stop,
        ]);

        assert!(timestamps(&saved).is_empty());
        assert_eq!(counts.written.load(Ordering::Relaxed), 0);
        assert_eq!(counts.failed.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn stopping_saves_what_was_queued_first() {
        let (saved, _) = run_with(vec![save("a", 1), WriterCommand::Stop, save("a", 2)]);

        assert_eq!(timestamps(&saved), [1]);
        assert!(*saved.closed.lock().unwrap());
    }

    #[test]
    fn stopping_closes_the_store() {
        let saved = Saved::default();
        let (sender, handle) = spawn_writer(Box::new(MemoryStore(saved.clone())), Arc::default());

        sender.blocking_send(WriterCommand::Stop).unwrap();
        handle.join().unwrap();

        assert!(*saved.closed.lock().unwrap());
    }
}
