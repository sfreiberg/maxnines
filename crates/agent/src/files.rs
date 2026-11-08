//! Watches files and folders from the outside: whether they exist, how big they
//! are and how long since they changed. Contents are never read, so the server
//! can't use this to see inside a machine's files.

use std::fs::{self, Metadata};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use serde_json::{Value, json};

use crate::background::{Background, Busy, probe_all};
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
        answer.send(inspect(&path, SystemTime::now())).ok();
    });
    inspected.await.unwrap_or_else(|_| timed_out(&watched))
}

impl FileCollector {
    pub fn new(paths: Vec<String>, interval: Duration) -> Self {
        let watched: Vec<Arc<WatchedPath>> = paths
            .into_iter()
            .map(|path| {
                Arc::new(WatchedPath {
                    path,
                    busy: Arc::default(),
                })
            })
            .collect();
        let background = Background::start(interval, move || {
            let watched = watched.clone();
            async move {
                Value::Array(probe_all(&watched, interval, TIMEOUT, check_path, timed_out).await)
            }
        });
        Self { background }
    }
}

impl Collector for FileCollector {
    fn name(&self) -> &'static str {
        "files"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

/// A path that can't be reached in time says nothing about whether it exists,
/// so it has no `exists` value, and an alert on it holds its state.
fn timed_out(watched: &WatchedPath) -> Value {
    json!({ "path": watched.path, "error": "timed out" })
}

fn age_secs(metadata: &Metadata, now: SystemTime) -> Option<f64> {
    let modified = metadata.modified().ok()?;
    // A file dated in the future hasn't aged at all.
    Some(
        now.duration_since(modified)
            .map_or(0.0, |age| age.as_secs_f64()),
    )
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

fn inspect(path: &String, now: SystemTime) -> Value {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return json!({ "path": path, "exists": 0 });
        }
        Err(_) => return json!({ "path": path, "error": "not allowed" }),
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

        let later = SystemTime::now() + Duration::from_secs(3600);
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
        let output = inspect(&path_of(&folder.path().join("nope")), SystemTime::now());

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

        let output = inspect(&path_of(folder.path()), SystemTime::now());

        assert_eq!(output["is_folder"], true);
        assert_eq!(output["entries"], 3);
        assert_eq!(output["size_bytes"], 5);
    }

    #[test]
    fn contents_are_never_reported() {
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("secret.txt");
        fs::write(&file, "the-password").unwrap();

        let output = inspect(&path_of(&file), SystemTime::now());
        assert!(!output.to_string().contains("the-password"));
    }

    #[test]
    fn a_file_dated_in_the_future_has_no_age() {
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("x");
        fs::write(&file, "").unwrap();

        let past = SystemTime::now() - Duration::from_secs(3600);
        assert_eq!(inspect(&path_of(&file), past)["age_secs"], 0.0);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_cannot_be_read_is_not_called_missing() {
        // A file used as a folder is an error other than "not found".
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("file");
        fs::write(&file, "").unwrap();

        let output = inspect(&path_of(&file.join("inside")), SystemTime::now());
        assert!(output.get("exists").is_none(), "{output}");
        assert_eq!(output["error"], "not allowed");
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
        );

        let deadline = Instant::now() + Duration::from_secs(5);
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
