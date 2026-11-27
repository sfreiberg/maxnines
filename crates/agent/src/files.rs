//! Watches files and folders from the outside: whether they exist, how big they
//! are and how long since they changed. Contents are never read, so the server
//! can't use this to see inside a host's files.

use std::fs::{self, Metadata};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};

use crate::background::{Background, Busy, FAILED_UNEXPECTEDLY};
use crate::collector::Collector;

/// Network drives can hang, which shows as this much delay and then a failure.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How many entries of a folder are looked at, so that a huge one can't tie up
/// a thread. Past this, the count and size are lower limits.
const MAX_ENTRIES: usize = 100_000;

pub struct FileCollector {
    background: Background,
}

struct WatchedPath {
    path: String,
    busy: Arc<AtomicBool>,
}

/// There's no async way to ask about a file, so each path gets a thread of its own
/// for the call. A time limit can stop waiting but can't stop the call, so a path
/// that's still stuck from before isn't asked again, and a dead mount holds one
/// thread per path on it rather than starving the paths that work.
async fn check_path(watched: Arc<WatchedPath>) -> Value {
    let Some(busy) = Busy::try_start(&watched.busy) else {
        return timed_out(&watched);
    };
    let path = watched.path.clone();
    let (answer, inspected) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _busy = busy;
        answer
            .send(inspect(&path, maxnines_protocol::time::now()))
            .ok();
    });
    inspected.await.unwrap_or_else(|_| timed_out(&watched))
}

impl FileCollector {
    pub fn new(paths: Vec<String>, interval: Duration) -> Result<Self> {
        let mut background = Background::new();
        for path in paths {
            let watched = Arc::new(WatchedPath {
                path,
                busy: Arc::default(),
            });
            let late = timed_out(&watched);
            let broke = json!({ "path": watched.path, "error": FAILED_UNEXPECTEDLY });
            background.repeat(
                interval,
                Some(TIMEOUT),
                move || check_path(watched.clone()),
                move |found| found.unwrap_or_else(|missed| missed.pick(&late, &broke)),
            )?;
        }
        Ok(Self { background })
    }
}

impl Collector for FileCollector {
    fn name(&self) -> &'static str {
        "files"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }
}

/// A path that can't be reached in time says nothing about whether it exists,
/// so it has no `exists` value, and an alert on it holds its state.
fn timed_out(watched: &WatchedPath) -> Value {
    json!({ "path": watched.path, "error": "timed out" })
}

fn age_secs(metadata: &Metadata, now: DateTime<Utc>) -> Option<f64> {
    let modified = DateTime::<Utc>::from(metadata.modified().ok()?);
    // A file dated in the future hasn't aged at all.
    Some((now - modified).max(TimeDelta::zero()).as_seconds_f64())
}

/// What's directly inside a folder, not counting sub-folders' contents.
fn folder_totals(path: &Path) -> Option<(u64, u64)> {
    let mut entries = 0;
    let mut size = 0_u64;
    for entry in fs::read_dir(path).ok()?.take(MAX_ENTRIES).flatten() {
        entries += 1;
        if let Ok(metadata) = entry.metadata()
            && metadata.is_file()
        {
            size = size.saturating_add(metadata.len());
        }
    }
    Some((entries, size))
}

/// Missing is a clear answer. Anything else, such as a dead network mount or a
/// path through a file, says nothing about whether it exists, so it says why.
fn unreadable(path: &String, error: &io::Error) -> Value {
    match error.kind() {
        io::ErrorKind::NotFound => json!({ "path": path, "exists": 0 }),
        io::ErrorKind::PermissionDenied => json!({ "path": path, "error": "not allowed" }),
        _ => json!({ "path": path, "error": error.to_string() }),
    }
}

fn inspect(path: &String, now: DateTime<Utc>) -> Value {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return unreadable(path, &error),
    };

    let mut output = json!({
        "path": path,
        "exists": 1,
        "is_folder": metadata.is_dir(),
        "age_secs": age_secs(&metadata, now),
    });
    if metadata.is_dir() {
        if let Some((entries, size)) = folder_totals(Path::new(path)) {
            output["entries"] = json!(entries);
            output["size_bytes"] = json!(size);
        }
    } else {
        output["size_bytes"] = json!(metadata.len());
    }
    output
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn path_of(path: &Path) -> String {
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn a_file_reports_its_size_and_age() {
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("backup.tar");
        fs::write(&file, "12345").unwrap();

        let later = maxnines_protocol::time::now() + TimeDelta::hours(1);
        let output = inspect(&path_of(&file), later);

        assert_eq!(output["exists"], 1);
        assert_eq!(output["is_folder"], false);
        assert_eq!(output["size_bytes"], 5);
        let age = output["age_secs"].as_f64().unwrap();
        assert!((3590.0..3700.0).contains(&age), "{age}");
    }

    #[test]
    fn a_missing_path_is_a_clear_answer() {
        let folder = tempfile::tempdir().unwrap();
        let output = inspect(
            &path_of(&folder.path().join("nope")),
            maxnines_protocol::time::now(),
        );

        assert_eq!(output["exists"], 0);
        assert!(output.get("error").is_none());
    }

    #[test]
    fn a_folder_reports_what_is_directly_inside_it() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("a"), "123").unwrap();
        fs::write(folder.path().join("b"), "45").unwrap();
        fs::create_dir(folder.path().join("sub")).unwrap();
        fs::write(folder.path().join("sub/deep"), "ignored").unwrap();

        let output = inspect(&path_of(folder.path()), maxnines_protocol::time::now());

        assert_eq!(output["is_folder"], true);
        assert_eq!(output["entries"], 3);
        assert_eq!(output["size_bytes"], 5);
    }

    #[test]
    fn contents_are_never_reported() {
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("secret.txt");
        fs::write(&file, "the-password").unwrap();

        let output = inspect(&path_of(&file), maxnines_protocol::time::now());
        assert!(!output.to_string().contains("the-password"));
    }

    #[test]
    fn a_file_dated_in_the_future_has_no_age() {
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("x");
        fs::write(&file, "").unwrap();

        let past = maxnines_protocol::time::now() - TimeDelta::hours(1);
        assert_eq!(inspect(&path_of(&file), past)["age_secs"], 0.0);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_cannot_be_read_is_not_called_missing() {
        // A file used as a folder is an error other than "not found".
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("file");
        fs::write(&file, "").unwrap();

        let output = inspect(
            &path_of(&file.join("inside")),
            maxnines_protocol::time::now(),
        );
        assert!(output.get("exists").is_none(), "{output}");
        // Says what's wrong, which isn't a matter of permissions.
        let error = output["error"].as_str().unwrap();
        assert_eq!(
            error,
            io::Error::from_raw_os_error(libc::ENOTDIR).to_string()
        );
    }

    #[test]
    fn only_a_refusal_is_called_not_allowed() {
        let refused = io::Error::from(io::ErrorKind::PermissionDenied);
        let path = "/srv/backups".to_string();
        assert_eq!(unreadable(&path, &refused)["error"], "not allowed");
        let stale = io::Error::other("Stale NFS file handle");
        assert_eq!(unreadable(&path, &stale)["error"], "Stale NFS file handle");
        assert!(unreadable(&path, &stale).get("exists").is_none());
    }

    #[test]
    fn a_path_that_times_out_says_nothing_about_existing() {
        let watched = WatchedPath {
            path: "/mnt/nfs".to_string(),
            busy: Arc::default(),
        };
        let output = timed_out(&watched);
        assert!(output.get("exists").is_none());
    }

    #[tokio::test]
    async fn a_path_still_stuck_from_before_is_not_tried_again() {
        let folder = tempfile::tempdir().unwrap();
        let watched = Arc::new(WatchedPath {
            path: path_of(folder.path()),
            busy: Arc::new(AtomicBool::new(true)),
        });

        assert_eq!(check_path(watched.clone()).await["error"], "timed out");

        watched
            .busy
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(check_path(watched).await["exists"], 1);
    }

    #[test]
    fn the_collector_reports_each_path() {
        let folder = tempfile::tempdir().unwrap();
        let mut collector = FileCollector::new(
            vec![path_of(folder.path()), path_of(&folder.path().join("nope"))],
            Duration::from_millis(20),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let output = collector.collect().unwrap();
            if output.as_array().is_some_and(|items| items.len() == 2) {
                assert_eq!(output[0]["exists"], 1);
                assert_eq!(output[1]["exists"], 0);
                break;
            }
            assert!(Instant::now() < deadline, "{output}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
