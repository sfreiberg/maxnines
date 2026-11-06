//! Metrics storage. To add a metrics database: implement [`Store`] and
//! [`MetricsReader`] in a new module, add a variant to [`MetricsConfig`], and add
//! a match arm to [`open`].
//! Everything else the server keeps lives in [`crate::models`].

mod duckdb;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use anyhow::Result;
use maxnines_protocol::Sample;
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::error;

use crate::config::MetricsConfig;
use crate::metrics::{LatestSample, Metric, NewestReading, SeriesQuery, SeriesResult};

/// Samples waiting to be written. When this fills up, connections stop reading
/// from their agents until the database catches up.
const WRITE_QUEUE_SIZE: usize = 1024;

/// Somewhere samples are saved.
pub trait Store: Send {
    /// Saves samples together, as waiting on the disk once is what makes this quick:
    /// either all of them are stored or none of them are.
    fn write(&mut self, samples: &[NewSample]) -> Result<()>;

    /// Something to read with, which can run alongside writes.
    fn reader(&self) -> Result<Arc<dyn MetricsReader>>;

    /// Called once at shutdown, after the last write.
    fn close(&mut self) -> Result<()>;
}

/// Answers questions about what's been saved.
pub trait MetricsReader: Send + Sync {
    /// Buckets a metric for one agent. Series are sorted by name, and values
    /// that aren't usable numbers are skipped.
    fn series(&self, query: &SeriesQuery) -> Result<SeriesResult>;

    /// The newest sample from each agent's collectors, between two times.
    fn latest(&self, since_ms: i64, until_ms: i64) -> Result<Vec<LatestSample>>;

    /// The newest value of each series of a metric, across every agent, between
    /// two times. Values that aren't usable numbers are skipped.
    fn newest(&self, metric: &Metric, since_ms: i64, until_ms: i64) -> Result<Vec<NewestReading>>;

    /// How the database itself is doing. `hour_ago_ms` is the start of the last
    /// hour, for how much is arriving now.
    fn stats(&self, hour_ago_ms: i64) -> Result<StoreStats>;
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
}

/// What's stored from one collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectorStats {
    pub name: String,
    pub rows: i64,
    pub rows_last_hour: i64,
    pub oldest_ms: i64,
    pub newest_ms: i64,
}

/// How many samples have been through the writer since the server started.
#[derive(Debug, Default)]
pub struct WriteCounts {
    pub written: AtomicU64,
    pub failed: AtomicU64,
}

pub fn open(config: &MetricsConfig) -> Result<Box<dyn Store>> {
    Ok(match config {
        MetricsConfig::Duckdb { path, memory_limit } => {
            Box::new(duckdb::DuckDbStore::open(path, memory_limit)?)
        }
    })
}

pub struct NewSample {
    pub agent_id: String,
    pub host: String,
    pub sample: Sample,
}

pub enum WriterCommand {
    Save(NewSample),
    /// Finish queued work and close the database cleanly.
    Stop,
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
    let mut stopping = false;
    while !stopping && commands.blocking_recv_many(&mut queued, WRITE_QUEUE_SIZE) > 0 {
        let mut samples = Vec::with_capacity(queued.len());
        for command in queued.drain(..) {
            match command {
                WriterCommand::Save(sample) => samples.push(sample),
                WriterCommand::Stop => {
                    stopping = true;
                    break;
                }
            }
        }
        if !samples.is_empty() {
            save(store.as_mut(), &samples, counts);
        }
    }

    match catch_unwind(AssertUnwindSafe(|| store.close())) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(error = format!("{error:#}"), "closing the store failed"),
        Err(_) => error!("store panicked while closing"),
    }
}

/// A failed write or panic loses only the sample that caused it, by trying the rest
/// again one at a time.
fn save(store: &mut dyn Store, samples: &[NewSample], counts: &WriteCounts) {
    let error = match catch_unwind(AssertUnwindSafe(|| store.write(samples))) {
        Ok(Ok(())) => {
            counts
                .written
                .fetch_add(samples.len() as u64, Ordering::Relaxed);
            return;
        }
        Ok(Err(error)) => format!("{error:#}"),
        Err(_) => "the store panicked".to_string(),
    };
    if samples.len() > 1 {
        for sample in samples {
            save(store, std::slice::from_ref(sample), counts);
        }
    } else {
        counts.failed.fetch_add(1, Ordering::Relaxed);
        error!(error, "write failed, sample dropped");
    }
}

#[cfg(test)]
pub mod testing {
    use std::sync::Mutex;

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
    }

    /// Has nothing to report, for tests that aren't about metrics.
    pub struct EmptyReader;

    impl MetricsReader for EmptyReader {
        fn series(&self, _query: &SeriesQuery) -> Result<SeriesResult> {
            Ok(SeriesResult::default())
        }

        fn latest(&self, _since_ms: i64, _until_ms: i64) -> Result<Vec<LatestSample>> {
            Ok(Vec::new())
        }

        fn newest(
            &self,
            _metric: &Metric,
            _since_ms: i64,
            _until_ms: i64,
        ) -> Result<Vec<NewestReading>> {
            Ok(Vec::new())
        }

        fn stats(&self, _hour_ago_ms: i64) -> Result<StoreStats> {
            Ok(StoreStats::default())
        }
    }

    /// Fails or panics when given those words as a host name.
    pub struct MemoryStore(pub Saved);

    impl Store for MemoryStore {
        fn write(&mut self, samples: &[NewSample]) -> Result<()> {
            for new in samples {
                match new.host.as_str() {
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
                        new.agent_id.clone(),
                        new.host.clone(),
                        new.sample.timestamp_ms,
                    )
                }));
            Ok(())
        }

        fn reader(&self) -> Result<Arc<dyn MetricsReader>> {
            Ok(Arc::new(EmptyReader))
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

    fn save(host: &str, timestamp_ms: u64) -> WriterCommand {
        WriterCommand::Save(NewSample {
            agent_id: "agent-1".to_string(),
            host: host.to_string(),
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

    #[test]
    fn keeps_writing_after_failures_and_panics() {
        let saved = Saved::default();
        let (sender, handle) = spawn_writer(Box::new(MemoryStore(saved.clone())), Arc::default());

        for command in [
            save("a", 1),
            save("fail", 2),
            save("panic", 3),
            save("a", 4),
        ] {
            sender.blocking_send(command).unwrap();
        }
        sender.blocking_send(WriterCommand::Stop).unwrap();
        handle.join().unwrap();

        assert_eq!(timestamps(&saved), [1, 4]);
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
    fn a_bad_sample_only_loses_itself_from_a_batch() {
        let (saved, counts) = run_with(vec![
            save("a", 1),
            save("fail", 2),
            save("panic", 3),
            save("a", 4),
            WriterCommand::Stop,
        ]);

        assert_eq!(timestamps(&saved), [1, 4]);
        assert_eq!(counts.written.load(Ordering::Relaxed), 2);
        assert_eq!(counts.failed.load(Ordering::Relaxed), 2);
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
