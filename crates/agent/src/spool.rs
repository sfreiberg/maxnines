//! Samples waiting for the server. While connected they pass through memory, so a
//! healthy agent doesn't write to disk. While disconnected they're saved to files,
//! which keeps them through a restart. Either way the newest samples win when space
//! runs out, because recent data is what people want after an outage.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, bail};
use serde::de::IgnoredAny;
use tokio::sync::Notify;
use tracing::warn;

const EXTENSION: &str = "jsonl";

/// Samples kept in memory. This only fills up if the disk can't be used.
const MAX_IN_MEMORY: usize = 64;
/// How much to keep on disk. A sample is usually a few KB, so this covers at least
/// a day at the default interval.
const MAX_SAVED_BYTES: u64 = 64 * 1024 * 1024;
/// The limit is shared between about this many files, and reaching it deletes the
/// oldest, so this much of the backlog goes at once.
const FILES_KEPT: u64 = 16;

/// Where a sample came from, to remove it once it's been sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Memory,
    Saved { file: u64, end: u64 },
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
    /// Carries on in memory if the folder can't be used, because a full or read-only
    /// disk must not stop an agent reporting while it's connected.
    pub fn open(folder: &Path) -> Self {
        Self::with_limit(folder, MAX_SAVED_BYTES)
    }

    fn with_limit(folder: &Path, max_bytes: u64) -> Self {
        let saved = Saved::open(folder, max_bytes)
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
            state.note_drops();
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
        if let Some(saved) = &mut state.saved {
            match saved.oldest() {
                Ok(Some(oldest)) => return Some(oldest),
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
            Place::Saved { file, end } => {
                if let Some(saved) = &mut state.saved
                    && let Err(error) = saved.remove_through(file, end)
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
                if dropped {
                    self.note_drops();
                }
            }
            Err(error) if !self.warned_of_saving => {
                self.warned_of_saving = true;
                let error = format!("{error:#}");
                warn!(error, "saving samples failed, keeping them in memory");
            }
            Err(_) => {}
        }
    }

    fn note_drops(&mut self) {
        if !self.warned_of_drops {
            self.warned_of_drops = true;
            warn!("the sample queue is full, dropping the oldest samples");
        }
    }

    /// Files that can't be read or updated would send the same sample forever.
    fn give_up_on_disk(&mut self, error: &anyhow::Error) {
        let error = format!("{error:#}");
        warn!(
            error,
            "reading saved samples failed, keeping them in memory"
        );
        self.saved = None;
    }
}

#[derive(Clone, Copy)]
struct SavedFile {
    number: u64,
    size: u64,
}

/// Samples as JSON Lines, one sample per line, spread over numbered files so the
/// oldest can be dropped by deleting a file. Only the newest file is written to, and
/// a restart always starts a new one, so a line cut short by a crash stays at the
/// end of a file where it's skipped.
struct Saved {
    folder: PathBuf,
    /// The file and offset of the oldest unsent sample. Being locked, it also keeps
    /// a second agent out of the folder.
    position: File,
    files: VecDeque<SavedFile>,
    /// How far into the oldest file has been sent.
    offset: u64,
    writer: Option<File>,
    next_number: u64,
    bytes: u64,
    max_bytes: u64,
}

impl Saved {
    fn open(folder: &Path, max_bytes: u64) -> Result<Self> {
        fs::create_dir_all(folder).with_context(|| format!("creating {}", folder.display()))?;
        let position_path = folder.join("position");
        let mut position = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&position_path)
            .with_context(|| format!("opening {}", position_path.display()))?;
        match position.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                bail!("{} is in use by another agent", folder.display())
            }
            Err(TryLockError::Error(error)) => {
                return Err(error).with_context(|| format!("locking {}", folder.display()));
            }
        }

        let (position_file, position_offset) = read_position(&mut position).unwrap_or((0, 0));
        let files = saved_files(folder)?;
        let offset = files
            .front()
            .filter(|oldest| oldest.number == position_file && position_offset <= oldest.size)
            .map_or(0, |_| position_offset);
        let total: u64 = files.iter().map(|file| file.size).sum();
        // A number the position still names can't be reused, or its offset would
        // apply to a new file.
        let newest = files.back().map_or(0, |file| file.number);

        Ok(Self {
            folder: folder.to_path_buf(),
            position,
            offset,
            writer: None,
            next_number: newest.max(position_file) + 1,
            bytes: total - offset,
            max_bytes,
            files,
        })
    }

    fn path_of(&self, number: u64) -> PathBuf {
        self.folder.join(format!("{number}.{EXTENSION}"))
    }

    /// Saves samples, deleting the oldest file to stay in the limit, and returns
    /// whether it did.
    fn append(&mut self, samples: &[String]) -> Result<bool> {
        let lines: String = samples.iter().map(|text| format!("{text}\n")).collect();

        let full = self
            .files
            .back()
            .is_none_or(|newest| newest.size >= self.max_bytes / FILES_KEPT);
        let mut writer = match self.writer.take() {
            Some(writer) if !full => writer,
            _ => self.start_file()?,
        };
        let start = writer.stream_position()?;
        if let Err(error) = writer
            .write_all(lines.as_bytes())
            .and_then(|()| writer.sync_data())
        {
            // The samples stay in memory to be saved again, so they mustn't stay
            // here too. If this fails as well, the next write goes to a new file.
            writer.set_len(start).ok();
            return Err(error).context("writing saved samples");
        }
        self.writer = Some(writer);
        if let Some(newest) = self.files.back_mut() {
            newest.size += lines.len() as u64;
        }
        self.bytes += lines.len() as u64;

        let mut dropped = false;
        while self.bytes > self.max_bytes && self.files.len() > 1 {
            self.remove_oldest()?;
            dropped = true;
        }
        Ok(dropped)
    }

    fn start_file(&mut self) -> Result<File> {
        let number = self.next_number;
        let path = self.path_of(number);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        self.next_number += 1;
        self.files.push_back(SavedFile { number, size: 0 });
        Ok(file)
    }

    /// The oldest sample that can be read. Lines damaged by a crash are skipped,
    /// because the server would reject them and they'd be sent forever.
    fn oldest(&mut self) -> Result<Option<(String, Place)>> {
        while let Some(oldest) = self.files.front().copied() {
            let path = self.path_of(oldest.number);
            let file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(self.offset))?;
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line)?;

            let end = self.offset + line.len() as u64;
            if line.pop() != Some(b'\n') {
                self.remove_oldest()?;
            } else if let Some(text) = whole_sample(line) {
                let place = Place::Saved {
                    file: oldest.number,
                    end,
                };
                return Ok(Some((text, place)));
            } else {
                warn!("skipping a damaged saved sample");
                self.remove_through(oldest.number, end)?;
            }
        }
        Ok(None)
    }

    /// Moves past a sample that ends at `end`, deleting its file if that was the last.
    fn remove_through(&mut self, number: u64, end: u64) -> Result<()> {
        let Some(oldest) = self.files.front().copied() else {
            return Ok(());
        };
        if oldest.number != number {
            return Ok(());
        }
        self.bytes = self.bytes.saturating_sub(end - self.offset);
        self.offset = end;
        self.save_position(number)?;
        if end >= oldest.size {
            self.remove_oldest()?;
        }
        Ok(())
    }

    /// Not forced to disk: losing this in a power cut sends samples twice, and
    /// never loses them.
    fn save_position(&mut self, number: u64) -> Result<()> {
        let text = format!("{number:020} {:020}\n", self.offset);
        self.position.seek(SeekFrom::Start(0))?;
        self.position.write_all(text.as_bytes())?;
        Ok(())
    }

    fn remove_oldest(&mut self) -> Result<()> {
        let Some(oldest) = self.files.pop_front() else {
            return Ok(());
        };
        if self.files.is_empty() {
            self.writer = None;
        }
        self.bytes = self
            .bytes
            .saturating_sub(oldest.size.saturating_sub(self.offset));
        self.offset = 0;
        let path = self.path_of(oldest.number);
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))
    }
}

/// `None` if the file is new or damaged, which starts from the oldest file's beginning.
fn read_position(file: &mut File) -> Option<(u64, u64)> {
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    let (number, offset) = text.trim().split_once(' ')?;
    Some((number.parse().ok()?, offset.parse().ok()?))
}

/// The folder's sample files, oldest first.
fn saved_files(folder: &Path) -> Result<VecDeque<SavedFile>> {
    let mut files = Vec::new();
    let entries = fs::read_dir(folder).with_context(|| format!("reading {}", folder.display()))?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let number = name.to_str().and_then(|name| {
            name.strip_suffix(EXTENSION)?
                .strip_suffix('.')?
                .parse()
                .ok()
        });
        if let Some(number) = number {
            let size = entry.metadata()?.len();
            files.push(SavedFile { number, size });
        }
    }
    files.sort_by_key(|file| file.number);
    Ok(files.into())
}

fn whole_sample(line: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(line).ok()?;
    serde_json::from_str::<IgnoredAny>(&text)
        .is_ok()
        .then_some(text)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use tempfile::{TempDir, tempdir};
    use tokio::time::timeout;

    use super::*;

    fn folder() -> (TempDir, PathBuf) {
        let parent = tempdir().unwrap();
        let path = parent.path().join("samples");
        (parent, path)
    }

    /// The sample files in a folder, oldest first.
    fn files_in(path: &Path) -> Vec<PathBuf> {
        let files = saved_files(path).unwrap();
        let path_of = |file: &SavedFile| path.join(format!("{}.{EXTENSION}", file.number));
        files.iter().map(path_of).collect()
    }

    fn add_to_file(path: &Path, text: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(text).unwrap();
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

    #[test]
    fn samples_come_out_oldest_first() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        for text in ["1", "2", "3"] {
            spool.push(text.to_string());
        }

        assert_eq!(drain(&spool), ["1", "2", "3"]);
        assert!(spool.next().is_none());
    }

    #[test]
    fn samples_saved_while_disconnected_survive_a_restart() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        spool.push("2".to_string());
        drop(spool);

        let spool = Spool::open(&path);
        spool.push("3".to_string());

        assert_eq!(drain(&spool), ["1", "2", "3"]);
    }

    #[test]
    fn a_connected_agent_does_not_write_samples_to_disk() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.set_online(true);

        spool.push("1".to_string());

        assert!(files_in(&path).is_empty());
        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn losing_the_connection_saves_what_had_not_been_sent() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.set_online(true);
        spool.push("1".to_string());

        spool.set_online(false);
        drop(spool);

        assert_eq!(drain(&Spool::open(&path)), ["1"]);
    }

    #[test]
    fn saved_samples_go_before_newer_ones_in_memory() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        spool.set_online(true);
        spool.push("2".to_string());

        assert_eq!(drain(&spool), ["1", "2"]);
    }

    #[test]
    fn a_sample_stays_queued_until_it_has_been_sent() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());

        let (first, _) = spool.next().unwrap();
        let (again, place) = spool.next().unwrap();
        assert_eq!(first, again);

        spool.sent(place);
        assert!(spool.next().is_none());
    }

    #[test]
    fn the_oldest_saved_samples_go_first_when_the_limit_is_reached() {
        let (_parent, path) = folder();
        let spool = Spool::with_limit(&path, 20);
        for number in 0..10 {
            spool.push((10_000_000 + number).to_string());
        }

        assert_eq!(drain(&spool), ["10000008", "10000009"]);
    }

    #[test]
    fn the_limit_counts_samples_saved_before_a_restart() {
        let (_parent, path) = folder();
        let spool = Spool::with_limit(&path, 20);
        spool.push("10000000".to_string());
        spool.push("10000001".to_string());
        drop(spool);

        let spool = Spool::with_limit(&path, 20);
        spool.push("10000002".to_string());

        assert_eq!(drain(&spool), ["10000001", "10000002"]);
    }

    #[test]
    fn sending_a_backlog_frees_its_space() {
        let (_parent, path) = folder();
        let spool = Spool::with_limit(&path, 20);
        spool.push("10000000".to_string());
        drain(&spool);

        spool.push("10000001".to_string());
        spool.push("10000002".to_string());

        assert_eq!(drain(&spool), ["10000001", "10000002"]);
    }

    #[test]
    fn sending_a_whole_backlog_gives_the_disk_space_back() {
        let (_parent, path) = folder();
        let spool = Spool::with_limit(&path, 1_000_000);
        for _ in 0..5 {
            spool.push(format!("\"{}\"", "x".repeat(100_000)));
        }
        assert!(files_in(&path).len() > 1);

        drain(&spool);

        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn samples_sent_before_a_restart_are_not_sent_again() {
        let (_parent, path) = folder();
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
        assert_eq!(left.len(), 50);
        assert_eq!(left[0], "50");
        assert_eq!(left.last().unwrap(), "99");
    }

    #[test]
    fn an_unusable_location_falls_back_to_memory() {
        let (_parent, path) = folder();
        std::fs::write(&path, "a file where the folder should be").unwrap();
        let spool = Spool::open(&path);
        assert!(spool.state().saved.is_none());

        spool.push("1".to_string());
        spool.set_online(false);

        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn a_file_another_agent_has_open_falls_back_to_memory() {
        let (_parent, path) = folder();
        let first = Spool::open(&path);
        first.push("1".to_string());

        let second = Spool::open(&path);

        assert!(second.state().saved.is_none());
        assert_eq!(drain(&first), ["1"]);
    }

    #[test]
    fn memory_keeps_the_newest_samples_when_the_disk_can_not_be_used() {
        let (_parent, path) = folder();
        std::fs::write(&path, "a file where the folder should be").unwrap();
        let spool = Spool::open(&path);
        for number in 0..MAX_IN_MEMORY + 3 {
            spool.push(number.to_string());
        }

        let kept = drain(&spool);
        assert_eq!(kept.len(), MAX_IN_MEMORY);
        assert_eq!(kept[0], "3");
        assert_eq!(kept.last().unwrap(), &(MAX_IN_MEMORY + 2).to_string());
    }

    #[test]
    fn a_line_cut_short_by_a_crash_is_skipped() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        drop(spool);
        add_to_file(&files_in(&path)[0], b"{\"cut sho");

        let spool = Spool::open(&path);
        spool.push("2".to_string());

        assert_eq!(drain(&spool), ["1", "2"]);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn damaged_lines_are_skipped() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        drop(spool);
        add_to_file(&files_in(&path)[0], b"{\"cut\n\0\0\0\n\xff\xfe\n2\n");

        assert_eq!(drain(&Spool::open(&path)), ["1", "2"]);
    }

    #[test]
    fn nothing_is_left_waiting_when_only_damage_remains() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        drop(spool);
        std::fs::write(&files_in(&path)[0], b"{\"cut\n{\"short").unwrap();

        let spool = Spool::open(&path);

        assert!(spool.next().is_none());
        assert_eq!(spool.saved_bytes(), 0);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn a_damaged_position_sends_the_oldest_file_again() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        spool.push("2".to_string());
        let (_, place) = spool.next().unwrap();
        spool.sent(place);
        drop(spool);
        std::fs::write(path.join("position"), "not a position").unwrap();

        assert_eq!(drain(&Spool::open(&path)), ["1", "2"]);
    }

    #[test]
    fn an_old_position_does_not_apply_to_a_new_file() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1000".to_string());
        drain(&spool);
        drop(spool);

        let spool = Spool::open(&path);
        spool.push("2000".to_string());
        spool.push("3000".to_string());
        drop(spool);

        assert_eq!(drain(&Spool::open(&path)), ["2000", "3000"]);
    }

    #[test]
    fn a_restart_keeps_the_order_across_files() {
        let (_parent, path) = folder();
        let spool = Spool::with_limit(&path, 1000);
        for number in 0..30 {
            spool.push(format!("{}", 1000 + number));
        }
        drop(spool);
        let spool = Spool::with_limit(&path, 1000);
        spool.push("2000".to_string());

        let expected: Vec<String> = (1000..1030).chain([2000]).map(|n| n.to_string()).collect();
        assert!(files_in(&path).len() > 2);
        assert_eq!(drain(&spool), expected);
    }

    #[test]
    fn samples_saved_part_way_through_a_backlog_are_kept() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push("1".to_string());
        spool.push("2".to_string());
        let (_, place) = spool.next().unwrap();
        spool.sent(place);

        spool.push("3".to_string());

        assert_eq!(drain(&spool), ["2", "3"]);
    }

    #[test]
    fn samples_are_saved_one_per_line() {
        let (_parent, path) = folder();
        let spool = Spool::open(&path);
        spool.push(r#"{"a":1}"#.to_string());
        spool.push(r#"{"a":2}"#.to_string());

        let text = std::fs::read_to_string(&files_in(&path)[0]).unwrap();

        assert_eq!(text, "{\"a\":1}\n{\"a\":2}\n");
    }

    #[tokio::test]
    async fn waiting_ends_when_a_sample_arrives() {
        let (_parent, path) = folder();
        let spool = std::sync::Arc::new(Spool::open(&path));
        let waiting = tokio::spawn({
            let spool = spool.clone();
            async move { spool.wait().await }
        });

        tokio::task::yield_now().await;
        spool.push("1".to_string());

        timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn waiting_ends_at_once_for_samples_saved_earlier() {
        let (_parent, path) = folder();
        Spool::open(&path).push("1".to_string());

        let spool = Spool::open(&path);

        timeout(Duration::from_secs(5), spool.wait()).await.unwrap();
    }
}
