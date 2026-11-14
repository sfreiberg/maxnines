//! Samples waiting for the server. While connected they pass through memory, so a
//! healthy agent doesn't write to disk. While disconnected they're saved to files,
//! which keeps them through a restart. Either way the newest samples win when space
//! runs out, because recent data is what people want after an outage.
//!
//! A sample stays here until the server says it's stored. Losing the connection puts
//! everything it hadn't confirmed back in line, and the server ignores any sample it
//! did store but couldn't say so in time.
//!
//! After an outage every agent has a backlog at once, so saved samples go at a slow,
//! steady pace behind live ones. That keeps dashboards and alerts current, and keeps
//! the server from being flooded. The server goes by each sample's own time, so it
//! doesn't matter that they arrive out of order.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::sync::Notify;
use tokio::time::{Instant, sleep_until};
use tracing::warn;

const EXTENSION: &str = "jsonl";

/// Samples kept in memory. This only fills up if the server stops confirming them,
/// which moves them to disk, or the disk can't be used, which drops the oldest.
const MAX_IN_MEMORY: usize = 64;
/// How much to keep on disk. A sample is usually a few KB, so this covers at least
/// a day at the default interval.
const MAX_SAVED_BYTES: u64 = 64 * 1024 * 1024;
/// The limit is shared between about this many files, and reaching it deletes the
/// oldest, so this much of the backlog goes at once.
const FILES_KEPT: u64 = 16;
/// The time between saved samples. A day of samples at the default interval takes
/// about an hour and a half to send, and a thousand agents catching up add about
/// 1,000 samples a second.
const BACKLOG_GAP: Duration = Duration::from_secs(1);
/// How long to wait to hear about a saved sample before sending it again.
const ACK_WAIT: Duration = Duration::from_secs(60);
/// How many times a saved sample is sent while the server confirms others but not it.
/// A server that can't store anything confirms nothing, and that never counts, so a
/// database outage can't use these up. It keeps one bad sample from blocking the rest.
const MAX_SENDS: u32 = 5;
const LOCK_WAIT: Duration = Duration::from_millis(500);
const LOCK_RETRY_EVERY: Duration = Duration::from_millis(10);

/// A saved sample that's been sent, to remove it once the server confirms it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SavedPlace {
    taken_at: u64,
    file: u64,
    end: u64,
}

pub struct Spool {
    state: Mutex<State>,
    arrived: Notify,
    backlog_gap: Duration,
    ack_wait: Duration,
}

struct State {
    memory: VecDeque<String>,
    /// How many of the samples in memory have been sent, counting from the oldest.
    unconfirmed: usize,
    saved: Option<Saved>,
    /// Goes one at a time, so the backlog only moves as fast as the server takes it.
    saved_unconfirmed: Option<SavedPlace>,
    /// How many times that sample went while the server was confirming others.
    wasted_sends: u32,
    others_confirmed: bool,
    online: bool,
    backlog_due: Instant,
    warned_of_drops: bool,
    warned_of_saving: bool,
}

impl Spool {
    /// Carries on in memory if the folder can't be used, because a full or read-only
    /// disk must not stop an agent reporting while it's connected.
    pub fn open(folder: &Path) -> Self {
        Self::with_limits(folder, MAX_SAVED_BYTES, BACKLOG_GAP, ACK_WAIT, LOCK_WAIT)
    }

    fn with_limits(
        folder: &Path,
        max_bytes: u64,
        backlog_gap: Duration,
        ack_wait: Duration,
        lock_wait: Duration,
    ) -> Self {
        let saved = Saved::open(folder, max_bytes, lock_wait)
            .inspect_err(|error| {
                let error = format!("{error:#}");
                warn!(error, "can't save samples to disk, keeping them in memory");
            })
            .ok();
        Self {
            state: Mutex::new(State {
                memory: VecDeque::new(),
                unconfirmed: 0,
                saved,
                saved_unconfirmed: None,
                wasted_sends: 0,
                others_confirmed: false,
                online: false,
                backlog_due: Instant::now(),
                warned_of_drops: false,
                warned_of_saving: false,
            }),
            arrived: Notify::new(),
            backlog_gap,
            ack_wait,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn push(&self, text: String) {
        let mut state = self.state();
        state.memory.push_back(text);
        if !state.online || state.memory.len() > MAX_IN_MEMORY {
            state.save_memory();
        }
        if state.memory.len() > MAX_IN_MEMORY {
            state.memory.pop_front();
            state.unconfirmed = state.unconfirmed.saturating_sub(1);
            state.note_drops();
        }
        drop(state);
        self.arrived.notify_one();
    }

    /// Going offline puts everything the server hadn't confirmed back in line.
    pub fn set_online(&self, online: bool) {
        let mut state = self.state();
        state.online = online;
        if online {
            state.warned_of_drops = false;
            state.warned_of_saving = false;
        } else {
            state.unconfirmed = 0;
            state.saved_unconfirmed = None;
            state.wasted_sends = 0;
            state.backlog_due = Instant::now();
            state.save_memory();
        }
    }

    /// The next sample to send, which stays here until [`Spool::acked`]. If sending it
    /// fails the connection ends, and that puts it back in line. Live samples come
    /// first, then saved ones when one is due.
    pub fn next(&self) -> Option<String> {
        let mut state = self.state();
        let unconfirmed = state.unconfirmed;
        if let Some(text) = state.memory.get(unconfirmed).cloned() {
            state.unconfirmed += 1;
            return Some(text);
        }
        if Instant::now() < state.backlog_due {
            return None;
        }
        state.give_up_on_a_stuck_sample();
        match state.saved.as_mut()?.oldest() {
            Ok(Some((text, place))) => {
                state.saved_unconfirmed = Some(place);
                state.backlog_due = Instant::now() + self.ack_wait;
                Some(text)
            }
            Ok(None) => None,
            Err(error) => {
                state.give_up_on_disk(&error);
                None
            }
        }
    }

    /// The server has stored the sample taken at this time.
    pub fn acked(&self, taken_at: u64) {
        let mut state = self.state();
        let place = state.saved_unconfirmed.filter(|p| p.taken_at == taken_at);
        if let Some(place) = place {
            state.backlog_due = Instant::now() + self.backlog_gap;
            state.remove_saved(place);
            drop(state);
            // Whatever's waiting was waiting for longer than it needs to now.
            self.arrived.notify_one();
            return;
        }

        let sent = state.unconfirmed;
        let found = state
            .memory
            .iter()
            .take(sent)
            .position(|text| sample_time(text) == Some(taken_at));
        if let Some(index) = found {
            state.memory.remove(index);
            state.unconfirmed -= 1;
            state.others_confirmed = true;
        }
    }

    #[cfg(test)]
    pub fn is_online(&self) -> bool {
        self.state().online
    }

    /// How many samples have gone to the server and not been confirmed yet.
    #[cfg(test)]
    pub fn unconfirmed(&self) -> usize {
        let state = self.state();
        state.unconfirmed + usize::from(state.saved_unconfirmed.is_some())
    }

    #[cfg(test)]
    pub fn saved_bytes(&self) -> u64 {
        self.state().saved.as_ref().map_or(0, |saved| saved.bytes)
    }

    /// Waits until there's something to send. Only one task may wait.
    pub async fn wait(&self) {
        loop {
            let backlog_due = {
                let state = self.state();
                if state.memory.len() > state.unconfirmed {
                    return;
                }
                state.has_backlog().then_some(state.backlog_due)
            };
            match backlog_due {
                Some(due) => tokio::select! {
                    () = sleep_until(due) => return,
                    () = self.arrived.notified() => {}
                },
                None => self.arrived.notified().await,
            }
        }
    }
}

impl State {
    fn has_backlog(&self) -> bool {
        self.saved.as_ref().is_some_and(|saved| saved.bytes > 0)
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
                self.unconfirmed = 0;
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

    fn remove_saved(&mut self, place: SavedPlace) {
        self.saved_unconfirmed = None;
        self.wasted_sends = 0;
        self.others_confirmed = false;
        if let Some(saved) = &mut self.saved
            && let Err(error) = saved.remove_through(place.file, place.end)
        {
            self.give_up_on_disk(&error);
        }
    }

    /// Called when a saved sample is due to go again, having gone unconfirmed.
    fn give_up_on_a_stuck_sample(&mut self) {
        let Some(place) = self.saved_unconfirmed else {
            return;
        };
        if self.others_confirmed {
            self.wasted_sends += 1;
            self.others_confirmed = false;
        }
        if self.wasted_sends >= MAX_SENDS {
            warn!("the server keeps refusing a saved sample, skipping it");
            self.remove_saved(place);
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
    fn open(folder: &Path, max_bytes: u64, lock_wait: Duration) -> Result<Self> {
        fs::create_dir_all(folder).with_context(|| format!("creating {}", folder.display()))?;
        let position_path = folder.join("position");
        let mut position = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&position_path)
            .with_context(|| format!("opening {}", position_path.display()))?;
        lock_folder(&position, folder, lock_wait)?;

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
    fn oldest(&mut self) -> Result<Option<(String, SavedPlace)>> {
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
            } else if let Some((text, taken_at)) = whole_sample(line) {
                let place = SavedPlace {
                    taken_at,
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

/// Waits a moment for the lock, as it can take that long to be let go. An agent being
/// restarted can overlap with the one before it, and a process being started holds
/// onto this one's files until it's running.
fn lock_folder(position: &File, folder: &Path, lock_wait: Duration) -> Result<()> {
    let began = std::time::Instant::now();
    loop {
        match position.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if began.elapsed() < lock_wait => {
                std::thread::sleep(LOCK_RETRY_EVERY);
            }
            Err(TryLockError::WouldBlock) => {
                bail!("{} is in use by another agent", folder.display())
            }
            Err(TryLockError::Error(error)) => {
                return Err(error).with_context(|| format!("locking {}", folder.display()));
            }
        }
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

fn whole_sample(line: Vec<u8>) -> Option<(String, u64)> {
    let text = String::from_utf8(line).ok()?;
    let taken_at = sample_time(&text)?;
    Some((text, taken_at))
}

/// When a sample was taken, which is how the server says which one it means. Samples
/// are kept as the text that's sent, so this is the one thing read back out of them.
fn sample_time(text: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Taken {
        timestamp_ms: u64,
    }
    serde_json::from_str::<Taken>(text)
        .ok()
        .map(|taken| taken.timestamp_ms)
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

    fn unpaced(folder: &Path) -> Spool {
        limited(folder, MAX_SAVED_BYTES)
    }

    fn limited(folder: &Path, max_bytes: u64) -> Spool {
        Spool::with_limits(folder, max_bytes, Duration::ZERO, ACK_WAIT, LOCK_WAIT)
    }

    fn paced(folder: &Path, gap: Duration) -> Spool {
        Spool::with_limits(folder, MAX_SAVED_BYTES, gap, ACK_WAIT, LOCK_WAIT)
    }

    /// Sends saved samples again as soon as asked for them.
    fn impatient(folder: &Path) -> Spool {
        Spool::with_limits(
            folder,
            MAX_SAVED_BYTES,
            Duration::ZERO,
            Duration::ZERO,
            LOCK_WAIT,
        )
    }

    fn sample(time: u64) -> String {
        format!(r#"{{"timestamp_ms":{time}}}"#)
    }

    /// Takes the next sample and has the server confirm it.
    fn deliver(spool: &Spool) -> Option<u64> {
        let time = sample_time(&spool.next()?).unwrap();
        spool.acked(time);
        Some(time)
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

    /// When everything queued was taken, oldest first, having the server confirm it.
    fn drain(spool: &Spool) -> Vec<String> {
        std::iter::from_fn(|| deliver(spool))
            .map(|time| time.to_string())
            .collect()
    }

    #[test]
    fn samples_come_out_oldest_first() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        for time in 1..=3 {
            spool.push(sample(time));
        }

        assert_eq!(drain(&spool), ["1", "2", "3"]);
        assert!(spool.next().is_none());
    }

    #[test]
    fn samples_saved_while_disconnected_survive_a_restart() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.push(sample(2));
        drop(spool);

        let spool = unpaced(&path);
        spool.push(sample(3));

        assert_eq!(drain(&spool), ["1", "2", "3"]);
    }

    #[test]
    fn a_connected_agent_does_not_write_samples_to_disk() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);

        spool.push(sample(1));

        assert!(files_in(&path).is_empty());
        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn losing_the_connection_saves_what_had_not_been_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1));

        spool.set_online(false);
        drop(spool);

        assert_eq!(drain(&unpaced(&path)), ["1"]);
    }

    #[test]
    fn live_samples_go_before_the_backlog() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.set_online(true);
        spool.push(sample(2));

        assert_eq!(drain(&spool), ["2", "1"]);
    }

    /// On a paused clock, so a busy host can't make the wait look longer or shorter.
    #[tokio::test(start_paused = true)]
    async fn the_backlog_goes_at_a_steady_pace() {
        let (_parent, path) = folder();
        let gap = Duration::from_millis(200);
        let spool = paced(&path, gap);
        spool.push(sample(1));
        spool.push(sample(2));
        spool.set_online(true);

        assert_eq!(deliver(&spool), Some(1));
        let sent = Instant::now();
        assert!(spool.next().is_none(), "the next one isn't due yet");

        spool.wait().await;

        assert_eq!(sent.elapsed(), gap);
        assert_eq!(deliver(&spool), Some(2));
    }

    #[tokio::test]
    async fn live_samples_do_not_wait_for_the_backlog_pace() {
        let (_parent, path) = folder();
        let spool = std::sync::Arc::new(paced(&path, Duration::from_secs(3600)));
        spool.push(sample(1));
        spool.push(sample(2));
        spool.set_online(true);
        deliver(&spool);
        let waiting = tokio::spawn({
            let spool = spool.clone();
            async move { spool.wait().await }
        });

        tokio::task::yield_now().await;
        spool.push(sample(3));

        timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deliver(&spool), Some(3));
    }

    #[test]
    fn a_live_sample_goes_once_and_stays_until_it_is_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1));

        assert_eq!(spool.next(), Some(sample(1)));
        assert_eq!(spool.next(), None, "it's waiting to hear back");

        spool.set_online(false);
        assert_eq!(drain(&spool), ["1"], "the connection went before it did");
    }

    #[test]
    fn a_confirmed_sample_is_gone() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1));
        spool.next();

        spool.acked(1);

        spool.set_online(false);
        assert!(spool.next().is_none());
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn samples_can_be_confirmed_in_any_order() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        for time in 1..=3 {
            spool.push(sample(time));
            spool.next();
        }

        spool.acked(2);
        spool.set_online(false);

        assert_eq!(drain(&spool), ["1", "3"]);
    }

    #[test]
    fn hearing_about_an_unknown_sample_changes_nothing() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1));
        spool.next();

        spool.acked(99);
        spool.set_online(false);

        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn a_saved_sample_survives_a_restart_until_it_is_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.set_online(true);
        assert_eq!(spool.next(), Some(sample(1)));
        drop(spool);

        assert_eq!(drain(&unpaced(&path)), ["1"]);
    }

    #[test]
    fn the_backlog_waits_for_each_sample_to_be_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.push(sample(2));
        spool.set_online(true);

        assert_eq!(spool.next(), Some(sample(1)));
        assert_eq!(spool.next(), None);

        spool.acked(1);
        assert_eq!(spool.next(), Some(sample(2)));
    }

    #[test]
    fn a_saved_sample_goes_again_if_nothing_is_heard() {
        let (_parent, path) = folder();
        let spool = impatient(&path);
        spool.push(sample(1));
        spool.set_online(true);

        assert_eq!(spool.next(), Some(sample(1)));
        assert_eq!(spool.next(), Some(sample(1)));

        spool.acked(1);
        assert_eq!(spool.next(), None);
    }

    #[test]
    fn a_server_confirming_nothing_never_uses_up_a_saved_samples_tries() {
        let (_parent, path) = folder();
        let spool = impatient(&path);
        spool.push(sample(1));
        spool.set_online(true);

        for _ in 0..MAX_SENDS * 3 {
            assert_eq!(spool.next(), Some(sample(1)));
        }
    }

    #[test]
    fn a_saved_sample_the_server_will_not_take_stops_blocking_the_rest() {
        let (_parent, path) = folder();
        let spool = impatient(&path);
        spool.push(sample(1));
        spool.push(sample(2));
        spool.set_online(true);

        for live in 0..MAX_SENDS as u64 {
            assert_eq!(spool.next(), Some(sample(1)));
            spool.push(sample(100 + live));
            assert_eq!(deliver(&spool), Some(100 + live));
        }

        assert_eq!(spool.next(), Some(sample(2)));
    }

    #[test]
    fn samples_the_server_is_slow_to_confirm_move_to_disk() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        let total = MAX_IN_MEMORY as u64 + 1;
        for time in 0..total {
            spool.push(sample(time));
            spool.next();
        }

        assert!(spool.saved_bytes() > 0);
        spool.set_online(false);
        assert_eq!(drain(&spool).len() as u64, total, "none were dropped");
    }

    #[test]
    fn the_oldest_saved_samples_go_first_when_the_limit_is_reached() {
        let (_parent, path) = folder();
        let spool = limited(&path, 60);
        for number in 0..10 {
            spool.push(sample(10_000_000 + number));
        }

        assert_eq!(drain(&spool), ["10000008", "10000009"]);
    }

    #[test]
    fn the_limit_counts_samples_saved_before_a_restart() {
        let (_parent, path) = folder();
        let spool = limited(&path, 60);
        spool.push(sample(10000000));
        spool.push(sample(10000001));
        drop(spool);

        let spool = limited(&path, 60);
        spool.push(sample(10000002));

        assert_eq!(drain(&spool), ["10000001", "10000002"]);
    }

    #[test]
    fn sending_a_backlog_frees_its_space() {
        let (_parent, path) = folder();
        let spool = limited(&path, 60);
        spool.push(sample(10000000));
        drain(&spool);

        spool.push(sample(10000001));
        spool.push(sample(10000002));

        assert_eq!(drain(&spool), ["10000001", "10000002"]);
    }

    #[test]
    fn sending_a_whole_backlog_gives_the_disk_space_back() {
        let (_parent, path) = folder();
        let spool = limited(&path, 1_000_000);
        for time in 0..5 {
            let padding = "x".repeat(100_000);
            spool.push(format!(
                r#"{{"timestamp_ms":{time},"padding":"{padding}"}}"#
            ));
        }
        assert!(files_in(&path).len() > 1);

        drain(&spool);

        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn samples_sent_before_a_restart_are_not_sent_again() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        for number in 0..100 {
            spool.push(sample(number));
        }
        for _ in 0..50 {
            deliver(&spool);
        }
        drop(spool);

        let left = drain(&unpaced(&path));
        assert_eq!(left.len(), 50);
        assert_eq!(left[0], "50");
        assert_eq!(left.last().unwrap(), "99");
    }

    #[test]
    fn an_unusable_location_falls_back_to_memory() {
        let (_parent, path) = folder();
        std::fs::write(&path, "a file where the folder should be").unwrap();
        let spool = unpaced(&path);
        assert!(spool.state().saved.is_none());

        spool.push(sample(1));
        spool.set_online(false);

        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn a_file_another_agent_has_open_falls_back_to_memory() {
        let (_parent, path) = folder();
        let first = unpaced(&path);
        first.push(sample(1));

        let second = unpaced(&path);

        assert!(second.state().saved.is_none());
        assert_eq!(drain(&first), ["1"]);
    }

    #[test]
    fn a_lock_let_go_a_moment_later_is_still_taken() {
        let (_parent, path) = folder();
        let first = unpaced(&path);
        first.push(sample(1));

        let handover = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(first);
        });
        // Waits far longer than it needs to, as a busy host can take its time
        // letting go, and the point is that it's taken once it is.
        let second = Spool::with_limits(
            &path,
            MAX_SAVED_BYTES,
            Duration::ZERO,
            ACK_WAIT,
            Duration::from_secs(30),
        );
        handover.join().unwrap();

        assert!(second.state().saved.is_some());
        assert_eq!(drain(&second), ["1"]);
    }

    #[test]
    fn memory_keeps_the_newest_samples_when_the_disk_can_not_be_used() {
        let (_parent, path) = folder();
        std::fs::write(&path, "a file where the folder should be").unwrap();
        let spool = unpaced(&path);
        for number in 0..MAX_IN_MEMORY + 3 {
            spool.push(sample(number as u64));
        }

        let kept = drain(&spool);
        assert_eq!(kept.len(), MAX_IN_MEMORY);
        assert_eq!(kept[0], "3");
        assert_eq!(kept.last().unwrap(), &(MAX_IN_MEMORY + 2).to_string());
    }

    #[test]
    fn a_line_cut_short_by_a_crash_is_skipped() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        drop(spool);
        add_to_file(&files_in(&path)[0], b"{\"cut sho");

        let spool = unpaced(&path);
        spool.push(sample(2));

        assert_eq!(drain(&spool), ["1", "2"]);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn damaged_lines_are_skipped() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        drop(spool);
        add_to_file(
            &files_in(&path)[0],
            b"{\"cut\n\0\0\0\n\xff\xfe\n{\"timestamp_ms\":2}\n",
        );

        assert_eq!(drain(&unpaced(&path)), ["1", "2"]);
    }

    #[test]
    fn nothing_is_left_waiting_when_only_damage_remains() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        drop(spool);
        std::fs::write(&files_in(&path)[0], b"{\"cut\n{\"short").unwrap();

        let spool = unpaced(&path);

        assert!(spool.next().is_none());
        assert_eq!(spool.saved_bytes(), 0);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn a_damaged_position_sends_the_oldest_file_again() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.push(sample(2));
        deliver(&spool);
        drop(spool);
        std::fs::write(path.join("position"), "not a position").unwrap();

        assert_eq!(drain(&unpaced(&path)), ["1", "2"]);
    }

    #[test]
    fn an_old_position_does_not_apply_to_a_new_file() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1000));
        drain(&spool);
        drop(spool);

        let spool = unpaced(&path);
        spool.push(sample(2000));
        spool.push(sample(3000));
        drop(spool);

        assert_eq!(drain(&unpaced(&path)), ["2000", "3000"]);
    }

    #[test]
    fn a_restart_keeps_the_order_across_files() {
        let (_parent, path) = folder();
        let spool = limited(&path, 1000);
        for number in 0..30 {
            spool.push(sample(1000 + number));
        }
        drop(spool);
        let spool = limited(&path, 1000);
        spool.push(sample(2000));

        let expected: Vec<String> = (1000..1030).chain([2000]).map(|n| n.to_string()).collect();
        assert!(files_in(&path).len() > 2);
        assert_eq!(drain(&spool), expected);
    }

    #[test]
    fn samples_saved_part_way_through_a_backlog_are_kept() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.push(sample(2));
        deliver(&spool);

        spool.push(sample(3));

        assert_eq!(drain(&spool), ["2", "3"]);
    }

    #[test]
    fn samples_are_saved_one_per_line() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1));
        spool.push(sample(2));

        let text = std::fs::read_to_string(&files_in(&path)[0]).unwrap();

        assert_eq!(text, format!("{}\n{}\n", sample(1), sample(2)));
    }

    #[tokio::test]
    async fn waiting_ends_when_a_sample_arrives() {
        let (_parent, path) = folder();
        let spool = std::sync::Arc::new(unpaced(&path));
        let waiting = tokio::spawn({
            let spool = spool.clone();
            async move { spool.wait().await }
        });

        tokio::task::yield_now().await;
        spool.push(sample(1));

        timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn waiting_ends_at_once_for_samples_saved_earlier() {
        let (_parent, path) = folder();
        unpaced(&path).push(sample(1));

        let spool = unpaced(&path);

        timeout(Duration::from_secs(5), spool.wait()).await.unwrap();
    }
}
