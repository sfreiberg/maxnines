//! Metrics storage. To add a metrics database: implement [`Store`] and
//! [`MetricsReader`] in a new module, add a variant to [`MetricsConfig`], and add
//! a match arm to [`open`].
//! Everything else the server keeps lives in [`crate::models`].

mod duckdb;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use anyhow::Result;
use maxnines_protocol::Sample;
use tokio::sync::mpsc;
use tracing::error;

use crate::config::MetricsConfig;
use crate::metrics::{LatestSample, Metric, NewestReading, SeriesQuery, SeriesResult};

/// Samples waiting to be written. When this fills up, connections stop reading
/// from their agents until the database catches up.
const WRITE_QUEUE_SIZE: usize = 1024;

/// Somewhere samples are saved.
pub trait Store: Send {
    /// Saves a whole sample: either all of it is stored or none of it is.
    fn write(&mut self, agent_id: &str, host: &str, sample: &Sample) -> Result<()>;

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
}

pub fn open(config: &MetricsConfig) -> Result<Box<dyn Store>> {
    Ok(match config {
        MetricsConfig::Duckdb { path, memory_limit } => {
            Box::new(duckdb::DuckDbStore::open(path, memory_limit)?)
        }
    })
}

pub enum WriterCommand {
    Save {
        agent_id: String,
        host: String,
        sample: Sample,
    },
    /// Finish queued work and close the database cleanly.
    Stop,
}

/// Runs the store on its own thread, so slow database calls can't hold up the
/// async tasks that answer heartbeats.
pub fn spawn_writer(store: Box<dyn Store>) -> (mpsc::Sender<WriterCommand>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(WRITE_QUEUE_SIZE);
    let handle = thread::spawn(move || run_writer(store, receiver));
    (sender, handle)
}

/// A failed write or panic loses that one sample and the writer keeps going.
fn run_writer(mut store: Box<dyn Store>, mut commands: mpsc::Receiver<WriterCommand>) {
    while let Some(command) = commands.blocking_recv() {
        match command {
            WriterCommand::Save {
                agent_id,
                host,
                sample,
            } => match catch_unwind(AssertUnwindSafe(|| store.write(&agent_id, &host, &sample))) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    error!(error = format!("{error:#}"), "write failed, sample dropped");
                }
                Err(_) => error!("store panicked, sample dropped"),
            },
            WriterCommand::Stop => break,
        }
    }

    match catch_unwind(AssertUnwindSafe(|| store.close())) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(error = format!("{error:#}"), "closing the store failed"),
        Err(_) => error!("store panicked while closing"),
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
    }

    /// Fails or panics when given those words as a host name.
    pub struct MemoryStore(pub Saved);

    impl Store for MemoryStore {
        fn write(&mut self, agent_id: &str, host: &str, sample: &Sample) -> Result<()> {
            match host {
                "fail" => bail!("deliberate test failure"),
                "panic" => panic!("deliberate test panic"),
                _ => self.0.samples.lock().unwrap().push((
                    agent_id.to_string(),
                    host.to_string(),
                    sample.timestamp_ms,
                )),
            }
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
        WriterCommand::Save {
            agent_id: "agent-1".to_string(),
            host: host.to_string(),
            sample: Sample {
                timestamp_ms,
                metrics: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn keeps_writing_after_failures_and_panics() {
        let saved = Saved::default();
        let (sender, handle) = spawn_writer(Box::new(MemoryStore(saved.clone())));

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

        let timestamps: Vec<u64> = saved.samples.lock().unwrap().iter().map(|s| s.2).collect();
        assert_eq!(timestamps, [1, 4]);
    }

    #[test]
    fn stopping_closes_the_store() {
        let saved = Saved::default();
        let (sender, handle) = spawn_writer(Box::new(MemoryStore(saved.clone())));

        sender.blocking_send(WriterCommand::Stop).unwrap();
        handle.join().unwrap();

        assert!(*saved.closed.lock().unwrap());
    }
}
