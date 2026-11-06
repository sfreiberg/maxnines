//! Samples waiting for the server. While connected they pass through memory, so a
//! healthy agent doesn't write to disk. While disconnected they're saved to a file,
//! which keeps them through a restart. Either way the newest samples win when space
//! runs out, because recent data is what people want after an outage.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, bail};
use redb::{Database, DatabaseError, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use tokio::sync::Notify;
use tracing::warn;

const SAMPLES: TableDefinition<u64, &str> = TableDefinition::new("samples");

/// Samples kept in memory. This only fills up if the disk can't be used.
const MAX_IN_MEMORY: usize = 64;
/// How much to keep on disk, which takes about twice this in the file. A sample is
/// usually a few KB, so this covers at least a day at the default interval.
const MAX_SAVED_BYTES: u64 = 64 * 1024 * 1024;
/// Removing a sent sample is only forced to disk this often, to send a backlog
/// quickly. Being killed part way through can send up to this many samples twice.
const REMOVALS_PER_SYNC: u32 = 32;

/// Where a sample came from, to remove it once it's been sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Memory,
    Saved(u64),
}

pub struct Spool {
    state: Mutex<State>,
    arrived: Notify,
}

struct State {
    memory: VecDeque<String>,
    saved: Option<Saved>,
    online: bool,
    warned_of_drops: bool,
    warned_of_saving: bool,
}

impl Spool {
    /// Carries on in memory if the file can't be used, because a full or read-only
    /// disk must not stop an agent reporting while it's connected.
    pub fn open(path: &Path) -> Self {
        Self::with_limit(path, MAX_SAVED_BYTES)
    }

    fn with_limit(path: &Path, max_bytes: u64) -> Self {
        let saved = Saved::open(path, max_bytes)
            .inspect_err(|error| {
                let error = format!("{error:#}");
                warn!(error, "can't save samples to disk, keeping them in memory");
            })
            .ok();
        Self {
            state: Mutex::new(State {
                memory: VecDeque::new(),
                saved,
                online: false,
                warned_of_drops: false,
                warned_of_saving: false,
            }),
            arrived: Notify::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn push(&self, text: String) {
        let mut state = self.state();
        state.memory.push_back(text);
        if !state.online {
            state.save_memory();
        }
        if state.memory.len() > MAX_IN_MEMORY {
            state.memory.pop_front();
            state.note_drops(1);
        }
        drop(state);
        self.arrived.notify_one();
    }

    pub fn set_online(&self, online: bool) {
        let mut state = self.state();
        state.online = online;
        if online {
            state.warned_of_drops = false;
            state.warned_of_saving = false;
        } else {
            state.save_memory();
        }
    }

    /// The oldest sample, which stays queued until [`Spool::sent`] says it went.
    pub fn next(&self) -> Option<(String, Place)> {
        let mut state = self.state();
        if let Some(saved) = &state.saved {
            match saved.oldest() {
                Ok(Some((id, text))) => return Some((text, Place::Saved(id))),
                Ok(None) => {}
                Err(error) => state.give_up_on_disk(&error),
            }
        }
        let text = state.memory.front()?.clone();
        Some((text, Place::Memory))
    }

    pub fn sent(&self, place: Place) {
        let mut state = self.state();
        match place {
            Place::Memory => {
                state.memory.pop_front();
            }
            Place::Saved(id) => {
                if let Some(saved) = &mut state.saved
                    && let Err(error) = saved.remove(id)
                {
                    state.give_up_on_disk(&error);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn saved_bytes(&self) -> u64 {
        self.state().saved.as_ref().map_or(0, |saved| saved.bytes)
    }

    /// Waits until there's something to send. Only one task may wait.
    pub async fn wait(&self) {
        while !self.state().has_samples() {
            self.arrived.notified().await;
        }
    }
}

impl State {
    fn has_samples(&self) -> bool {
        !self.memory.is_empty() || self.saved.as_ref().is_some_and(|saved| saved.bytes > 0)
    }

    /// Anything that can't be saved stays in memory.
    fn save_memory(&mut self) {
        let Some(saved) = &mut self.saved else {
            return;
        };
        if self.memory.is_empty() {
            return;
        }
        match saved.append(self.memory.make_contiguous()) {
            Ok(dropped) => {
                self.memory.clear();
                self.note_drops(dropped);
            }
            Err(error) if !self.warned_of_saving => {
                self.warned_of_saving = true;
                let error = format!("{error:#}");
                warn!(error, "saving samples failed, keeping them in memory");
            }
            Err(_) => {}
        }
    }

    fn note_drops(&mut self, dropped: u64) {
        if dropped > 0 && !self.warned_of_drops {
            self.warned_of_drops = true;
            warn!("the sample queue is full, dropping the oldest samples");
        }
    }

    /// A file that can't be read or updated would send the same sample forever.
    fn give_up_on_disk(&mut self, error: &anyhow::Error) {
        let error = format!("{error:#}");
        warn!(
            error,
            "reading saved samples failed, keeping them in memory"
        );
        self.saved = None;
    }
}

struct Saved {
    database: Database,
    next_id: u64,
    bytes: u64,
    max_bytes: u64,
    removals: u32,
}

impl Saved {
    fn open(path: &Path, max_bytes: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let database = open_or_replace(path)?;

        let transaction = database.begin_write()?;
        let (next_id, bytes) = {
            let table = transaction.open_table(SAMPLES)?;
            let next_id = table.last()?.map_or(0, |(id, _)| id.value() + 1);
            let mut bytes = 0;
            for entry in table.iter()? {
                bytes += entry?.1.value().len() as u64;
            }
            (next_id, bytes)
        };
        transaction.commit()?;

        Ok(Self {
            database,
            next_id,
            bytes,
            max_bytes,
            removals: 0,
        })
    }

    /// Saves samples, removing the oldest to stay in the limit, and returns how
    /// many were removed.
    fn append(&mut self, samples: &[String]) -> Result<u64> {
        let mut next_id = self.next_id;
        let mut bytes = self.bytes;
        let mut dropped = 0;

        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(SAMPLES)?;
            for text in samples {
                table.insert(next_id, text.as_str())?;
                next_id += 1;
                bytes += text.len() as u64;
            }
            while bytes > self.max_bytes {
                let Some((_, oldest)) = table.pop_first()? else {
                    break;
                };
                bytes -= oldest.value().len() as u64;
                dropped += 1;
            }
        }
        transaction.commit()?;

        self.next_id = next_id;
        self.bytes = bytes;
        Ok(dropped)
    }

    fn oldest(&self) -> Result<Option<(u64, String)>> {
        if self.bytes == 0 {
            return Ok(None);
        }
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(SAMPLES)?;
        let oldest = table.first()?;
        Ok(oldest.map(|(id, text)| (id.value(), text.value().to_string())))
    }

    fn remove(&mut self, id: u64) -> Result<()> {
        self.removals += 1;
        let mut transaction = self.database.begin_write()?;
        let bytes = {
            let mut table = transaction.open_table(SAMPLES)?;
            let removed = table.remove(id)?;
            let removed = removed.map_or(0, |text| text.value().len() as u64);
            self.bytes.saturating_sub(removed)
        };
        if bytes > 0 && !self.removals.is_multiple_of(REMOVALS_PER_SYNC) {
            transaction.set_durability(Durability::None)?;
        }
        transaction.commit()?;
        self.bytes = bytes;
        if bytes == 0 {
            self.database.compact()?;
        }
        Ok(())
    }
}

/// A damaged file only holds samples that can't be read, so it's started afresh.
fn open_or_replace(path: &Path) -> Result<Database> {
    match Database::create(path) {
        Ok(database) => Ok(database),
        Err(DatabaseError::DatabaseAlreadyOpen) => {
            bail!("{} is in use by another agent", path.display())
        }
        Err(error) if path.is_file() => {
            warn!(%error, "replacing a damaged file of saved samples");
            std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
            Database::create(path).with_context(|| format!("creating {}", path.display()))
        }
        Err(error) => Err(error).with_context(|| format!("opening {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use tempfile::{TempDir, tempdir};
    use tokio::time::timeout;

    use super::*;

    fn file() -> (TempDir, PathBuf) {
        let folder = tempdir().unwrap();
        let path = folder.path().join("samples.redb");
        (folder, path)
    }

    /// Everything queued, oldest first, marking each one as sent.
    fn drain(spool: &Spool) -> Vec<String> {
        let mut texts = Vec::new();
        while let Some((text, place)) = spool.next() {
            spool.sent(place);
            texts.push(text);
        }
        texts
    }

    fn saved_count(spool: &Spool) -> u64 {
        let state = spool.state();
        let transaction = state.saved.as_ref().unwrap().database.begin_read().unwrap();
        let table = transaction.open_table(SAMPLES).unwrap();
        redb::ReadableTableMetadata::len(&table).unwrap()
    }

    #[test]
    fn samples_come_out_oldest_first() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        for text in ["a", "b", "c"] {
            spool.push(text.to_string());
        }

        assert_eq!(drain(&spool), ["a", "b", "c"]);
        assert!(spool.next().is_none());
    }

    #[test]
    fn samples_saved_while_disconnected_survive_a_restart() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        spool.push("a".to_string());
        spool.push("b".to_string());
        drop(spool);

        let spool = Spool::open(&path);
        spool.push("c".to_string());

        assert_eq!(drain(&spool), ["a", "b", "c"]);
    }

    #[test]
    fn a_connected_agent_does_not_write_samples_to_disk() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        spool.set_online(true);

        spool.push("a".to_string());

        assert_eq!(saved_count(&spool), 0);
        assert_eq!(drain(&spool), ["a"]);
    }

    #[test]
    fn losing_the_connection_saves_what_had_not_been_sent() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        spool.set_online(true);
        spool.push("a".to_string());

        spool.set_online(false);
        drop(spool);

        assert_eq!(drain(&Spool::open(&path)), ["a"]);
    }

    #[test]
    fn saved_samples_go_before_newer_ones_in_memory() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        spool.push("offline".to_string());
        spool.set_online(true);
        spool.push("online".to_string());

        assert_eq!(drain(&spool), ["offline", "online"]);
    }

    #[test]
    fn a_sample_stays_queued_until_it_has_been_sent() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        spool.push("a".to_string());

        let (first, _) = spool.next().unwrap();
        let (again, place) = spool.next().unwrap();
        assert_eq!(first, again);

        spool.sent(place);
        assert!(spool.next().is_none());
    }

    #[test]
    fn the_oldest_saved_samples_go_first_when_the_limit_is_reached() {
        let (_folder, path) = file();
        let spool = Spool::with_limit(&path, 20);
        for number in 0..10 {
            spool.push(format!("sample-{number}"));
        }

        assert_eq!(drain(&spool), ["sample-8", "sample-9"]);
    }

    #[test]
    fn the_limit_counts_samples_saved_before_a_restart() {
        let (_folder, path) = file();
        let spool = Spool::with_limit(&path, 20);
        spool.push("sample-0".to_string());
        spool.push("sample-1".to_string());
        drop(spool);

        let spool = Spool::with_limit(&path, 20);
        spool.push("sample-2".to_string());

        assert_eq!(drain(&spool), ["sample-1", "sample-2"]);
    }

    #[test]
    fn sending_a_backlog_frees_its_space() {
        let (_folder, path) = file();
        let spool = Spool::with_limit(&path, 20);
        spool.push("sample-0".to_string());
        drain(&spool);

        spool.push("sample-1".to_string());
        spool.push("sample-2".to_string());

        assert_eq!(drain(&spool), ["sample-1", "sample-2"]);
    }

    #[test]
    fn sending_a_whole_backlog_gives_the_disk_space_back() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        let size = || std::fs::metadata(&path).unwrap().len();
        for _ in 0..100 {
            spool.push("x".repeat(100_000));
        }
        let full = size();

        drain(&spool);

        assert!(size() < full / 4, "{} of {full}", size());
    }

    #[test]
    fn samples_sent_before_a_restart_are_not_sent_again() {
        let (_folder, path) = file();
        let spool = Spool::open(&path);
        for number in 0..100 {
            spool.push(number.to_string());
        }
        for _ in 0..50 {
            let (_, place) = spool.next().unwrap();
            spool.sent(place);
        }
        drop(spool);

        let left = drain(&Spool::open(&path));
        assert!(left.len() <= 50 + REMOVALS_PER_SYNC as usize, "{left:?}");
        assert_eq!(left.last().unwrap(), "99");
    }

    #[test]
    fn an_unusable_location_falls_back_to_memory() {
        let folder = tempdir().unwrap();
        let spool = Spool::open(folder.path());
        assert!(spool.state().saved.is_none());

        spool.push("a".to_string());
        spool.set_online(false);

        assert_eq!(drain(&spool), ["a"]);
    }

    #[test]
    fn a_file_another_agent_has_open_falls_back_to_memory() {
        let (_folder, path) = file();
        let first = Spool::open(&path);
        first.push("a".to_string());

        let second = Spool::open(&path);

        assert!(second.state().saved.is_none());
        assert_eq!(drain(&first), ["a"]);
    }

    #[test]
    fn memory_keeps_the_newest_samples_when_the_disk_can_not_be_used() {
        let folder = tempdir().unwrap();
        let spool = Spool::open(folder.path());
        for number in 0..MAX_IN_MEMORY + 3 {
            spool.push(number.to_string());
        }

        let kept = drain(&spool);
        assert_eq!(kept.len(), MAX_IN_MEMORY);
        assert_eq!(kept[0], "3");
        assert_eq!(kept.last().unwrap(), &(MAX_IN_MEMORY + 2).to_string());
    }

    #[test]
    fn a_damaged_file_is_replaced() {
        let (_folder, path) = file();
        std::fs::write(&path, b"this is not a database").unwrap();

        let spool = Spool::open(&path);
        assert!(spool.state().saved.is_some());
        spool.push("a".to_string());

        assert_eq!(drain(&spool), ["a"]);
    }

    #[tokio::test]
    async fn waiting_ends_when_a_sample_arrives() {
        let (_folder, path) = file();
        let spool = std::sync::Arc::new(Spool::open(&path));
        let waiting = tokio::spawn({
            let spool = spool.clone();
            async move { spool.wait().await }
        });

        tokio::task::yield_now().await;
        spool.push("a".to_string());

        timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn waiting_ends_at_once_for_samples_saved_earlier() {
        let (_folder, path) = file();
        Spool::open(&path).push("a".to_string());

        let spool = Spool::open(&path);

        timeout(Duration::from_secs(5), spool.wait()).await.unwrap();
    }
}
