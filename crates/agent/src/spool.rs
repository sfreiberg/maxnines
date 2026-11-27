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
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::sync::{Notify, oneshot};
use tokio::time::{Instant, sleep_until};
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tracing::warn;

const EXTENSION: &str = "jsonl";

/// Samples kept in memory. This only fills up if the server stops confirming them,
/// which moves them to disk, or the disk can't be used or keep up, which drops the
/// oldest.
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

/// A sample as it's sent, which is cheap to copy, and when it was taken, which is how
/// the server says which one it means.
#[derive(Debug, Clone)]
struct Entry {
    text: Utf8Bytes,
    taken_at: DateTime<Utc>,
}

/// A saved sample that's been sent, to remove it once the server confirms it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SavedPlace {
    taken_at: DateTime<Utc>,
    file: u64,
    end: u64,
}

/// What the disk is doing for the queue. It's only ever used from a thread of its
/// own, so a slow or stuck disk never holds up the connection to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disk {
    Opening,
    Usable,
    Unusable,
}

/// Asks the disk's thread to do something.
enum Ask {
    /// Catch up with whatever there is to save or remove.
    Work,
    /// Catch up, then call this.
    Flush(Box<dyn FnOnce() + Send>),
    Stop,
}

pub struct Spool {
    shared: Arc<Shared>,
    disk: Sender<Ask>,
    worker: Option<JoinHandle<()>>,
}

struct Shared {
    state: Mutex<State>,
    /// Something new to send.
    arrived: Notify,
    backlog_gap: Duration,
    ack_wait: Duration,
}

/// Only ever held for a moment, and never while the disk is used.
struct State {
    memory: VecDeque<Entry>,
    /// How many of the samples in memory have been sent, counting from the oldest.
    unconfirmed: usize,
    disk: Disk,
    /// Whether the disk's thread has samples it's still saving.
    saving: bool,
    /// Saved samples the server has confirmed, or that were given up on, for the
    /// disk's thread to remove.
    removals: Vec<SavedPlace>,
    /// The oldest saved sample, read ahead by the disk's thread.
    backlog: Option<(Utf8Bytes, SavedPlace)>,
    /// How much is saved, as the disk's thread last said.
    saved_bytes: u64,
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
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                memory: VecDeque::new(),
                unconfirmed: 0,
                disk: Disk::Opening,
                saving: false,
                removals: Vec::new(),
                backlog: None,
                saved_bytes: 0,
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
        });
        let (disk, asked) = mpsc::channel();
        let worker = {
            let (shared, folder) = (shared.clone(), folder.to_path_buf());
            std::thread::Builder::new()
                .name("sample queue".to_string())
                .spawn(move || use_disk(&shared, &folder, max_bytes, lock_wait, &asked))
        };
        let worker = worker
            .inspect_err(|error| {
                warn!(%error, "can't save samples to disk, keeping them in memory");
                shared.state().disk = Disk::Unusable;
            })
            .ok();
        Self {
            shared,
            disk,
            worker,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.shared.state()
    }

    fn ask_disk(&self) {
        // Gone only if the disk can't be used, which leaves nothing for it to do.
        self.disk.send(Ask::Work).ok();
    }

    pub fn push(&self, text: String, taken_at: DateTime<Utc>) {
        let entry = Entry {
            text: text.into(),
            taken_at,
        };
        let mut state = self.state();
        state.memory.push_back(entry);
        if state.memory.len() > MAX_IN_MEMORY && !state.can_save() {
            state.drop_oldest();
        }
        let save = state.wants_saving();
        drop(state);
        if save {
            self.ask_disk();
        }
        self.shared.arrived.notify_one();
    }

    /// Going offline puts everything the server hadn't confirmed back in line, and
    /// saves it.
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
            drop(state);
            self.ask_disk();
        }
    }

    /// Waits until everything that was to be saved or removed has been.
    pub async fn flush(&self) {
        let (done, flushed) = oneshot::channel();
        let done = Box::new(move || {
            done.send(()).ok();
        });
        if self.disk.send(Ask::Flush(done)).is_ok() {
            flushed.await.ok();
        }
    }

    /// The next sample to send, which stays here until [`Spool::acked`]. If sending it
    /// fails the connection ends, and that puts it back in line. Live samples come
    /// first, then saved ones when one is due.
    pub fn next(&self) -> Option<Utf8Bytes> {
        let mut state = self.state();
        let unconfirmed = state.unconfirmed;
        if let Some(entry) = state.memory.get(unconfirmed) {
            let text = entry.text.clone();
            state.unconfirmed += 1;
            return Some(text);
        }
        if Instant::now() < state.backlog_due {
            return None;
        }
        if state.give_up_on_a_stuck_sample() {
            drop(state);
            self.ask_disk();
            return None;
        }
        let (text, place) = state.backlog.clone()?;
        state.saved_unconfirmed = Some(place);
        state.backlog_due = Instant::now() + self.shared.ack_wait;
        Some(text)
    }

    /// The server has stored the sample taken at this time.
    pub fn acked(&self, taken_at: DateTime<Utc>) {
        let mut state = self.state();
        let place = state.saved_unconfirmed.filter(|p| p.taken_at == taken_at);
        if let Some(place) = place {
            state.backlog_due = Instant::now() + self.shared.backlog_gap;
            state.remove_saved(place);
            drop(state);
            self.ask_disk();
            return;
        }

        let sent = state.unconfirmed;
        let found = state
            .memory
            .iter()
            .take(sent)
            .position(|entry| entry.taken_at == taken_at);
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
        self.state().saved_bytes
    }

    /// Waits until there's something to send. Only one task may wait.
    pub async fn wait(&self) {
        loop {
            let backlog_due = {
                let state = self.state();
                if state.memory.len() > state.unconfirmed {
                    return;
                }
                state.backlog.is_some().then_some(state.backlog_due)
            };
            match backlog_due {
                Some(due) => tokio::select! {
                    () = sleep_until(due) => return,
                    () = self.shared.arrived.notified() => {}
                },
                None => self.shared.arrived.notified().await,
            }
        }
    }
}

impl Drop for Spool {
    /// Saves what's waiting to be saved, and lets go of the folder.
    fn drop(&mut self) {
        self.disk.send(Ask::Stop).ok();
        if let Some(worker) = self.worker.take() {
            worker.join().ok();
        }
    }
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    /// Whether samples over the limit in memory can go to disk, rather than the
    /// oldest being dropped: not while the disk is still busy with the last ones.
    fn can_save(&self) -> bool {
        self.disk == Disk::Usable && !self.saving
    }

    fn wants_saving(&self) -> bool {
        self.disk != Disk::Unusable
            && !self.memory.is_empty()
            && (!self.online || self.memory.len() > MAX_IN_MEMORY)
    }

    /// What's to be saved, which leaves memory as it goes.
    fn take_for_saving(&mut self) -> Option<Vec<Entry>> {
        if !self.wants_saving() {
            return None;
        }
        self.unconfirmed = 0;
        self.saving = true;
        Some(self.memory.drain(..).collect())
    }

    /// Samples that couldn't be saved stay in memory, behind those sent since, and
    /// the newest are kept: past the limit, the oldest of them go, as those sent
    /// since are newer.
    fn keep_unsaved(&mut self, samples: Vec<Entry>) {
        let at = self.unconfirmed;
        for (offset, entry) in samples.into_iter().enumerate() {
            self.memory.insert(at + offset, entry);
        }
        while self.memory.len() > MAX_IN_MEMORY {
            if self.memory.len() > self.unconfirmed {
                self.memory.remove(self.unconfirmed);
                self.note_drops();
            } else {
                self.drop_oldest();
            }
        }
    }

    fn drop_oldest(&mut self) {
        self.memory.pop_front();
        self.unconfirmed = self.unconfirmed.saturating_sub(1);
        self.note_drops();
    }

    fn remove_saved(&mut self, place: SavedPlace) {
        self.saved_unconfirmed = None;
        self.wasted_sends = 0;
        self.others_confirmed = false;
        if self
            .backlog
            .as_ref()
            .is_some_and(|(_, ahead)| *ahead == place)
        {
            self.backlog = None;
        }
        self.removals.push(place);
    }

    /// Called when a saved sample is due to go again, having gone unconfirmed.
    /// Returns whether it was given up on.
    fn give_up_on_a_stuck_sample(&mut self) -> bool {
        let Some(place) = self.saved_unconfirmed else {
            return false;
        };
        if self.others_confirmed {
            self.wasted_sends += 1;
            self.others_confirmed = false;
        }
        if self.wasted_sends < MAX_SENDS {
            return false;
        }
        warn!("the server keeps refusing a saved sample, skipping it");
        self.remove_saved(place);
        true
    }

    /// Keeps the oldest saved sample, read while the lock wasn't held. A sample
    /// confirmed meanwhile may be the one that was read, and it's only removed on
    /// the next catching up, which reads again, so the read is let go.
    fn read_ahead(&mut self, text: Utf8Bytes, place: SavedPlace) {
        if self.backlog.is_none() && self.removals.is_empty() {
            self.backlog = Some((text, place));
        }
    }

    fn note_drops(&mut self) {
        if !self.warned_of_drops {
            self.warned_of_drops = true;
            warn!("the sample queue is full, dropping the oldest samples");
        }
    }
}

/// The disk's thread: it saves samples, removes the ones that went, and reads the
/// oldest ahead, for as long as the queue is open.
fn use_disk(
    shared: &Shared,
    folder: &Path,
    max_bytes: u64,
    lock_wait: Duration,
    asked: &Receiver<Ask>,
) {
    let mut saved = match Saved::open(folder, max_bytes, lock_wait) {
        Ok(saved) => {
            shared.state().disk = Disk::Usable;
            Some(saved)
        }
        Err(error) => {
            let error = format!("{error:#}");
            warn!(error, "can't save samples to disk, keeping them in memory");
            shared.state().disk = Disk::Unusable;
            None
        }
    };
    // Once to begin with, for whatever was waiting while the folder opened, and
    // then once for each time it's asked.
    let mut asking = Some(Ask::Work);
    while let Some(ask) = asking {
        if let Some(disk) = &mut saved
            && let Err(error) = catch_up(shared, disk)
        {
            give_up_on_disk(shared, &error);
            saved = None;
        }
        match ask {
            Ask::Work => {}
            Ask::Flush(done) => done(),
            Ask::Stop => return,
        }
        // Gone only when the queue is, which is a stop too.
        asking = Some(asked.recv().unwrap_or(Ask::Stop));
    }
}

/// Saves and removes whatever's waiting, then reads the oldest sample ahead. An
/// error means the files can't be read or updated, which would send the same sample
/// forever.
fn catch_up(shared: &Shared, saved: &mut Saved) -> Result<()> {
    loop {
        let (removals, samples) = {
            let mut state = shared.state();
            (std::mem::take(&mut state.removals), state.take_for_saving())
        };
        if removals.is_empty() && samples.is_none() {
            break;
        }
        for place in removals {
            saved.remove_through(place.file, place.end)?;
        }
        let Some(samples) = samples else { continue };
        let appended = saved.append(&samples);
        let mut state = shared.state();
        state.saving = false;
        match appended {
            Ok(dropped) => {
                if dropped {
                    state.note_drops();
                    // What was read ahead may have gone with them.
                    state.backlog = None;
                }
            }
            Err(error) => {
                state.keep_unsaved(samples);
                if !state.warned_of_saving {
                    state.warned_of_saving = true;
                    let error = format!("{error:#}");
                    warn!(error, "saving samples failed, keeping them in memory");
                }
                // Tried again with the next sample, rather than at once.
                break;
            }
        }
    }

    let needs_reading = shared.state().backlog.is_none();
    let oldest = if needs_reading { saved.oldest()? } else { None };
    let mut state = shared.state();
    state.saved_bytes = saved.bytes;
    if let Some((text, place)) = oldest {
        state.read_ahead(text.into(), place);
    }
    drop(state);
    shared.arrived.notify_one();
    Ok(())
}

fn give_up_on_disk(shared: &Shared, error: &anyhow::Error) {
    let error = format!("{error:#}");
    warn!(
        error,
        "reading saved samples failed, keeping them in memory"
    );
    let mut state = shared.state();
    state.disk = Disk::Unusable;
    state.saving = false;
    state.backlog = None;
    state.saved_unconfirmed = None;
    state.removals.clear();
    state.saved_bytes = 0;
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
    fn append(&mut self, samples: &[Entry]) -> Result<bool> {
        let lines: String = samples
            .iter()
            .map(|entry| format!("{}\n", entry.text.as_str()))
            .collect();

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
            // here too. Cut back, the file takes them next time. If even that
            // fails, what's left of them is a line cut short, which the next
            // samples mustn't follow, so they go to a new file.
            if writer.set_len(start).is_ok() && writer.seek(SeekFrom::Start(start)).is_ok() {
                self.writer = Some(writer);
            }
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
        // Somewhere already gone past.
        if oldest.number != number || end <= self.offset {
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

fn whole_sample(line: Vec<u8>) -> Option<(String, DateTime<Utc>)> {
    let text = String::from_utf8(line).ok()?;
    let taken_at = sample_time(&text)?;
    Some((text, taken_at))
}

/// When a sample was taken, which is how the server says which one it means. Samples
/// are kept as the text that's sent, so this is the one thing read back out of them.
/// One without a time, such as from a version of the agent that wrote it in another
/// way, is skipped as damaged, as the server couldn't take it either.
fn sample_time(text: &str) -> Option<DateTime<Utc>> {
    #[derive(Deserialize)]
    struct Taken {
        time: DateTime<Utc>,
    }
    serde_json::from_str::<Taken>(text)
        .ok()
        .map(|taken| taken.time)
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

    /// Opened, once the disk's thread has caught up.
    fn opened(spool: Spool) -> Spool {
        settle(&spool);
        spool
    }

    fn limited(folder: &Path, max_bytes: u64) -> Spool {
        opened(Spool::with_limits(
            folder,
            max_bytes,
            Duration::ZERO,
            ACK_WAIT,
            LOCK_WAIT,
        ))
    }

    fn paced(folder: &Path, gap: Duration) -> Spool {
        opened(Spool::with_limits(
            folder,
            MAX_SAVED_BYTES,
            gap,
            ACK_WAIT,
            LOCK_WAIT,
        ))
    }

    /// Sends saved samples again as soon as asked for them.
    fn impatient(folder: &Path) -> Spool {
        opened(Spool::with_limits(
            folder,
            MAX_SAVED_BYTES,
            Duration::ZERO,
            Duration::ZERO,
            LOCK_WAIT,
        ))
    }

    /// The moment `number` milliseconds after 1970, which tells samples apart here.
    fn at(number: u64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(i64::try_from(number).unwrap()).unwrap()
    }

    /// Always written to the millisecond, so every sample here is the same size.
    fn sample(number: u64) -> String {
        let time = at(number).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        format!(r#"{{"time":"{time}"}}"#)
    }

    /// Waits for the disk's thread to catch up, as it would in its own time.
    fn settle(spool: &Spool) {
        let (done, flushed) = std::sync::mpsc::channel();
        let done = Box::new(move || done.send(()).unwrap());
        spool.disk.send(Ask::Flush(done)).unwrap();
        flushed.recv().unwrap();
    }

    /// The next sample to send, once the disk's thread has caught up.
    fn next(spool: &Spool) -> Option<String> {
        settle(spool);
        spool.next().map(|text| text.to_string())
    }

    /// Takes the next sample and has the server confirm it, and says which it was.
    fn deliver(spool: &Spool) -> Option<u64> {
        settle(spool);
        let time = sample_time(&next(spool)?).unwrap();
        spool.acked(time);
        settle(spool);
        u64::try_from(time.timestamp_millis()).ok()
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

    /// Samples a failed save gives back are older than those sent meanwhile, so
    /// when there are too many, they're what goes.
    #[test]
    fn samples_that_could_not_be_saved_make_way_for_newer_ones() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        let entry = |time: u64| Entry {
            text: sample(time).into(),
            taken_at: at(time),
        };
        let mut state = spool.state();
        state.memory.clear();
        // Three sent since the save began, waiting to be confirmed.
        state.memory.extend([1001, 1002, 1003].map(entry));
        state.unconfirmed = 3;

        let unsaved: Vec<Entry> = (1..=MAX_IN_MEMORY as u64).map(entry).collect();
        state.keep_unsaved(unsaved);

        let times: Vec<i64> = state
            .memory
            .iter()
            .map(|e| e.taken_at.timestamp())
            .collect();
        assert_eq!(times.len(), MAX_IN_MEMORY);
        assert_eq!(times[..3], [1001, 1002, 1003].map(|t| at(t).timestamp()));
        assert_eq!(times[3], at(4).timestamp(), "the oldest went");
        assert_eq!(*times.last().unwrap(), at(MAX_IN_MEMORY as u64).timestamp());
        assert_eq!(state.unconfirmed, 3);
    }

    #[test]
    fn samples_come_out_oldest_first() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        for time in 1..=3 {
            spool.push(sample(time), at(time));
            settle(&spool);
        }

        assert_eq!(drain(&spool), ["1", "2", "3"]);
        assert!(next(&spool).is_none());
    }

    #[test]
    fn samples_saved_while_disconnected_survive_a_restart() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        drop(spool);

        let spool = unpaced(&path);
        spool.push(sample(3), at(3));
        settle(&spool);

        assert_eq!(drain(&spool), ["1", "2", "3"]);
    }

    #[test]
    fn a_connected_agent_does_not_write_samples_to_disk() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);

        spool.push(sample(1), at(1));

        settle(&spool);

        assert!(files_in(&path).is_empty());
        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn losing_the_connection_saves_what_had_not_been_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1), at(1));
        settle(&spool);

        spool.set_online(false);

        settle(&spool);
        drop(spool);

        assert_eq!(drain(&unpaced(&path)), ["1"]);
    }

    #[test]
    fn live_samples_go_before_the_backlog() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.set_online(true);
        spool.push(sample(2), at(2));
        settle(&spool);

        assert_eq!(drain(&spool), ["2", "1"]);
    }

    /// On a paused clock, so a busy host can't make the wait look longer or shorter.
    #[tokio::test(start_paused = true)]
    async fn the_backlog_goes_at_a_steady_pace() {
        let (_parent, path) = folder();
        let gap = Duration::from_millis(200);
        let spool = paced(&path, gap);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        spool.set_online(true);

        assert_eq!(deliver(&spool), Some(1));
        let sent = Instant::now();
        assert!(next(&spool).is_none(), "the next one isn't due yet");

        spool.wait().await;

        assert_eq!(sent.elapsed(), gap);
        assert_eq!(deliver(&spool), Some(2));
    }

    #[tokio::test]
    async fn live_samples_do_not_wait_for_the_backlog_pace() {
        let (_parent, path) = folder();
        let spool = std::sync::Arc::new(paced(&path, Duration::from_secs(3600)));
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        spool.set_online(true);
        deliver(&spool);
        let waiting = tokio::spawn({
            let spool = spool.clone();
            async move { spool.wait().await }
        });

        tokio::task::yield_now().await;
        spool.push(sample(3), at(3));
        settle(&spool);

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
        spool.push(sample(1), at(1));
        settle(&spool);

        assert_eq!(next(&spool), Some(sample(1)));
        assert_eq!(next(&spool), None, "it's waiting to hear back");

        spool.set_online(false);

        settle(&spool);
        assert_eq!(drain(&spool), ["1"], "the connection went before it did");
    }

    #[test]
    fn a_confirmed_sample_is_gone() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1), at(1));
        settle(&spool);
        next(&spool);

        spool.acked(at(1));

        spool.set_online(false);

        settle(&spool);
        assert!(next(&spool).is_none());
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn samples_can_be_confirmed_in_any_order() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        for time in 1..=3 {
            spool.push(sample(time), at(time));
            settle(&spool);
            next(&spool);
        }

        spool.acked(at(2));
        spool.set_online(false);
        settle(&spool);

        assert_eq!(drain(&spool), ["1", "3"]);
    }

    #[test]
    fn hearing_about_an_unknown_sample_changes_nothing() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        spool.push(sample(1), at(1));
        settle(&spool);
        next(&spool);

        spool.acked(at(99));
        spool.set_online(false);
        settle(&spool);

        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn a_saved_sample_survives_a_restart_until_it_is_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.set_online(true);
        assert_eq!(next(&spool), Some(sample(1)));
        drop(spool);

        assert_eq!(drain(&unpaced(&path)), ["1"]);
    }

    #[test]
    fn the_backlog_waits_for_each_sample_to_be_confirmed() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        spool.set_online(true);

        assert_eq!(next(&spool), Some(sample(1)));
        assert_eq!(next(&spool), None);

        spool.acked(at(1));
        assert_eq!(next(&spool), Some(sample(2)));
    }

    #[test]
    fn a_saved_sample_goes_again_if_nothing_is_heard() {
        let (_parent, path) = folder();
        let spool = impatient(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.set_online(true);

        assert_eq!(next(&spool), Some(sample(1)));
        assert_eq!(next(&spool), Some(sample(1)));

        spool.acked(at(1));
        assert_eq!(next(&spool), None);
    }

    #[test]
    fn a_server_confirming_nothing_never_uses_up_a_saved_samples_tries() {
        let (_parent, path) = folder();
        let spool = impatient(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.set_online(true);

        for _ in 0..MAX_SENDS * 3 {
            assert_eq!(next(&spool), Some(sample(1)));
        }
    }

    #[test]
    fn a_saved_sample_the_server_will_not_take_stops_blocking_the_rest() {
        let (_parent, path) = folder();
        let spool = impatient(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        spool.set_online(true);

        for live in 0..MAX_SENDS as u64 {
            assert_eq!(next(&spool), Some(sample(1)));
            spool.push(sample(100 + live), at(100 + live));
            settle(&spool);
            assert_eq!(deliver(&spool), Some(100 + live));
        }

        // It's given up on, and the next is read while the connection carries on.
        assert_eq!(next(&spool), None);
        assert_eq!(next(&spool), Some(sample(2)));
    }

    #[test]
    fn samples_the_server_is_slow_to_confirm_move_to_disk() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.set_online(true);
        let total = MAX_IN_MEMORY as u64 + 1;
        for time in 0..total {
            spool.push(sample(time), at(time));
            settle(&spool);
            next(&spool);
        }

        assert!(spool.saved_bytes() > 0);
        spool.set_online(false);
        settle(&spool);
        assert_eq!(drain(&spool).len() as u64, total, "none were dropped");
    }

    #[test]
    fn the_oldest_saved_samples_go_first_when_the_limit_is_reached() {
        let (_parent, path) = folder();
        let spool = limited(&path, 80);
        for number in 0..10 {
            spool.push(sample(10_000_000 + number), at(10_000_000 + number));
            settle(&spool);
        }

        assert_eq!(drain(&spool), ["10000008", "10000009"]);
    }

    #[test]
    fn the_limit_counts_samples_saved_before_a_restart() {
        let (_parent, path) = folder();
        let spool = limited(&path, 80);
        spool.push(sample(10000000), at(10000000));
        settle(&spool);
        spool.push(sample(10000001), at(10000001));
        settle(&spool);
        drop(spool);

        let spool = limited(&path, 80);
        spool.push(sample(10000002), at(10000002));
        settle(&spool);

        assert_eq!(drain(&spool), ["10000001", "10000002"]);
    }

    #[test]
    fn sending_a_backlog_frees_its_space() {
        let (_parent, path) = folder();
        let spool = limited(&path, 80);
        spool.push(sample(10000000), at(10000000));
        settle(&spool);
        drain(&spool);

        spool.push(sample(10000001), at(10000001));

        settle(&spool);
        spool.push(sample(10000002), at(10000002));
        settle(&spool);

        assert_eq!(drain(&spool), ["10000001", "10000002"]);
    }

    #[test]
    fn sending_a_whole_backlog_gives_the_disk_space_back() {
        let (_parent, path) = folder();
        let spool = limited(&path, 1_000_000);
        for time in 0..5 {
            let padding = "x".repeat(100_000);
            let text = serde_json::json!({ "time": at(time), "padding": padding }).to_string();
            spool.push(text, at(time));
            settle(&spool);
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
            spool.push(sample(number), at(number));
            settle(&spool);
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
        settle(&spool);
        assert_eq!(spool.state().disk, Disk::Unusable);

        spool.push(sample(1), at(1));

        settle(&spool);
        spool.set_online(false);
        settle(&spool);

        assert_eq!(drain(&spool), ["1"]);
    }

    #[test]
    fn a_file_another_agent_has_open_falls_back_to_memory() {
        let (_parent, path) = folder();
        let first = unpaced(&path);
        first.push(sample(1), at(1));
        settle(&first);

        let second = unpaced(&path);

        settle(&second);
        assert_eq!(second.state().disk, Disk::Unusable);
        assert_eq!(drain(&first), ["1"]);
    }

    #[test]
    fn a_lock_let_go_a_moment_later_is_still_taken() {
        let (_parent, path) = folder();
        let first = unpaced(&path);
        first.push(sample(1), at(1));
        settle(&first);

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

        settle(&second);
        assert_eq!(second.state().disk, Disk::Usable);
        assert_eq!(drain(&second), ["1"]);
    }

    #[test]
    fn a_sample_confirmed_while_the_next_was_being_read_is_not_read_again() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        spool.push(sample(2), at(2));
        settle(&spool);
        spool.set_online(true);
        let (text, place) = spool.state().backlog.clone().unwrap();
        assert_eq!(next(&spool), Some(sample(1)));

        // The disk's thread read the oldest just before it was confirmed, and
        // keeps it once the confirmation is in, before it's removed.
        let mut state = spool.state();
        state.remove_saved(place);
        state.backlog_due = Instant::now();
        state.read_ahead(text, place);
        assert!(state.backlog.is_none());
        drop(state);
        spool.disk.send(Ask::Work).unwrap();

        assert_eq!(drain(&spool), ["2"]);
    }

    #[test]
    fn removing_a_saved_sample_twice_changes_nothing() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        spool.push(sample(2), at(2));
        settle(&spool);
        let (_, place) = spool.state().backlog.clone().unwrap();

        for _ in 0..2 {
            spool.state().remove_saved(place);
            spool.disk.send(Ask::Work).unwrap();
            settle(&spool);
        }

        assert_eq!(drain(&spool), ["2"]);
    }

    #[test]
    fn a_disk_that_is_slow_to_answer_never_holds_up_sending() {
        let (_parent, path) = folder();
        let first = unpaced(&path);
        // Its disk's thread waits for the folder until the first lets go, as one
        // waits for a hung drive.
        let second = Spool::with_limits(
            &path,
            MAX_SAVED_BYTES,
            Duration::ZERO,
            ACK_WAIT,
            Duration::from_secs(600),
        );

        let started = std::time::Instant::now();
        second.push(sample(1), at(1));
        second.set_online(false);
        second.set_online(true);
        assert_eq!(second.next().as_deref(), Some(sample(1).as_str()));
        second.acked(at(1));
        // Well short of the wait, however busy the host.
        assert!(started.elapsed() < Duration::from_secs(60));

        drop(first);
        settle(&second);
        assert_eq!(second.state().disk, Disk::Usable);
    }

    #[test]
    fn memory_keeps_the_newest_samples_when_the_disk_can_not_be_used() {
        let (_parent, path) = folder();
        std::fs::write(&path, "a file where the folder should be").unwrap();
        let spool = unpaced(&path);
        for number in 0..MAX_IN_MEMORY + 3 {
            spool.push(sample(number as u64), at(number as u64));
            settle(&spool);
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
        spool.push(sample(1), at(1));
        settle(&spool);
        drop(spool);
        add_to_file(&files_in(&path)[0], b"{\"cut sho");

        let spool = unpaced(&path);
        spool.push(sample(2), at(2));
        settle(&spool);

        assert_eq!(drain(&spool), ["1", "2"]);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn damaged_lines_are_skipped() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        drop(spool);
        let damage = b"{\"cut\n\0\0\0\n\xff\xfe\n";
        add_to_file(
            &files_in(&path)[0],
            &[&damage[..], sample(2).as_bytes(), b"\n"].concat(),
        );

        assert_eq!(drain(&unpaced(&path)), ["1", "2"]);
    }

    /// An agent upgraded with a backlog saved by an older version, which said when a
    /// sample was taken another way, sends what it can read and drops the rest.
    #[test]
    fn samples_without_a_time_are_skipped() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        drop(spool);
        let older = format!("{{\"timestamp_ms\":2}}\n{}\n", sample(3));
        add_to_file(&files_in(&path)[0], older.as_bytes());

        let spool = unpaced(&path);
        assert_eq!(drain(&spool), ["1", "3"]);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn nothing_is_left_waiting_when_only_damage_remains() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        drop(spool);
        std::fs::write(&files_in(&path)[0], b"{\"cut\n{\"short").unwrap();

        let spool = unpaced(&path);

        assert!(next(&spool).is_none());
        assert_eq!(spool.saved_bytes(), 0);
        assert!(files_in(&path).is_empty());
    }

    #[test]
    fn a_damaged_position_sends_the_oldest_file_again() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        deliver(&spool);
        drop(spool);
        std::fs::write(path.join("position"), "not a position").unwrap();

        assert_eq!(drain(&unpaced(&path)), ["1", "2"]);
    }

    #[test]
    fn an_old_position_does_not_apply_to_a_new_file() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1000), at(1000));
        settle(&spool);
        drain(&spool);
        drop(spool);

        let spool = unpaced(&path);
        spool.push(sample(2000), at(2000));
        settle(&spool);
        spool.push(sample(3000), at(3000));
        settle(&spool);
        drop(spool);

        assert_eq!(drain(&unpaced(&path)), ["2000", "3000"]);
    }

    #[test]
    fn a_restart_keeps_the_order_across_files() {
        let (_parent, path) = folder();
        let spool = limited(&path, 2000);
        for number in 0..30 {
            spool.push(sample(1000 + number), at(1000 + number));
            settle(&spool);
        }
        drop(spool);
        let spool = limited(&path, 2000);
        spool.push(sample(2000), at(2000));
        settle(&spool);

        let expected: Vec<String> = (1000..1030).chain([2000]).map(|n| n.to_string()).collect();
        assert!(files_in(&path).len() > 2);
        assert_eq!(drain(&spool), expected);
    }

    #[test]
    fn samples_saved_part_way_through_a_backlog_are_kept() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);
        deliver(&spool);

        spool.push(sample(3), at(3));

        settle(&spool);

        assert_eq!(drain(&spool), ["2", "3"]);
    }

    #[test]
    fn samples_are_saved_one_per_line() {
        let (_parent, path) = folder();
        let spool = unpaced(&path);
        spool.push(sample(1), at(1));
        settle(&spool);
        spool.push(sample(2), at(2));
        settle(&spool);

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
        spool.push(sample(1), at(1));
        settle(&spool);

        timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn waiting_ends_at_once_for_samples_saved_earlier() {
        let (_parent, path) = folder();
        unpaced(&path).push(sample(1), at(1));

        let spool = unpaced(&path);

        timeout(Duration::from_secs(5), spool.wait()).await.unwrap();
    }
}
