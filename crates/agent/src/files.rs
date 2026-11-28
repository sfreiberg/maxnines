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
use maxnines_collectors::entries::{Entries, at};
use maxnines_protocol::entries::Entry;
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

    fn metrics(&self) -> &'static [&'static str] {
        &FILE_METRICS
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let paths = output.as_array().map(Vec::as_slice).unwrap_or_default();
        let named = paths
            .iter()
            .filter_map(|found| Some((found.get("path")?.as_str()?, found)));
        let mut any = false;
        for (path, found) in named {
            any = true;
            // A path that couldn't be looked at says why, which is the error of
            // everything about it.
            let why = at(found, "error")
                .as_str()
                .filter(|why| !why.trim().is_empty());
            for (metric, field) in FILE_FIELDS {
                match why {
                    Some(why) => entries.error(metric, &[path], why),
                    None => entries.read(metric, &[path], at(found, field)),
                }
            }
        }
        // With no paths to watch, or none looked at yet, each metric has nothing.
        if !any {
            for metric in FILE_METRICS {
                entries.nothing(metric, &[]);
            }
        }
        entries.done()
    }
}

/// A path's metrics, and what each is read from. Only a folder has entries, and a
/// path that's missing only says so.
const FILE_FIELDS: [(&str, &str); 5] = [
    ("file.exists", "exists"),
    ("file.size", "size_bytes"),
    ("file.age", "age_secs"),
    ("file.folder", "is_folder"),
    ("file.entries", "entries"),
];

const FILE_METRICS: [&str; 5] = {
    let mut metrics = [""; 5];
    let mut at = 0;
    while at < FILE_FIELDS.len() {
        metrics[at] = FILE_FIELDS[at].0;
        at += 1;
    }
    metrics
};

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
    use crate::collector::test_entries::{every_metric_has_an_entry, said, time};

    fn path_of(path: &Path) -> String {
        path.to_str().unwrap().to_string()
    }

    /// Watching nothing, so nothing is looked at.
    fn watching_nothing() -> FileCollector {
        FileCollector::new(Vec::new(), Duration::from_secs(3600)).unwrap()
    }

    #[test]
    fn file_entries_have_a_series_for_each_path() {
        let collector = watching_nothing();
        let output = json!([
            { "path": "/srv/backup.tar", "exists": 1, "is_folder": false,
              "age_secs": 90.5, "size_bytes": 5 },
            { "path": "/srv/backups", "exists": 1, "is_folder": true,
              "age_secs": 0.0, "entries": 3, "size_bytes": 12 },
            { "path": "/srv/nope", "exists": 0 },
            { "path": "/mnt/nfs", "error": "timed out" },
            // One without a path can't be told from the others.
            { "exists": 1 },
        ]);
        let entries = collector.entries(&output, time());
        let timed_out = json!({ "error": "timed out" });
        assert_eq!(
            said(&entries),
            [
                ("file.exists[/srv/backup.tar]".to_string(), json!(1)),
                ("file.size[/srv/backup.tar]".to_string(), json!(5)),
                ("file.age[/srv/backup.tar]".to_string(), json!(90.5)),
                ("file.folder[/srv/backup.tar]".to_string(), json!(false)),
                ("file.entries[/srv/backup.tar]".to_string(), Value::Null),
                ("file.exists[/srv/backups]".to_string(), json!(1)),
                ("file.size[/srv/backups]".to_string(), json!(12)),
                ("file.age[/srv/backups]".to_string(), json!(0.0)),
                ("file.folder[/srv/backups]".to_string(), json!(true)),
                ("file.entries[/srv/backups]".to_string(), json!(3)),
                // A missing path has nothing else to say.
                ("file.exists[/srv/nope]".to_string(), json!(0)),
                ("file.size[/srv/nope]".to_string(), Value::Null),
                ("file.age[/srv/nope]".to_string(), Value::Null),
                ("file.folder[/srv/nope]".to_string(), Value::Null),
                ("file.entries[/srv/nope]".to_string(), Value::Null),
                // One that couldn't be looked at says why, and not that it's missing.
                ("file.exists[/mnt/nfs]".to_string(), timed_out.clone()),
                ("file.size[/mnt/nfs]".to_string(), timed_out.clone()),
                ("file.age[/mnt/nfs]".to_string(), timed_out.clone()),
                ("file.folder[/mnt/nfs]".to_string(), timed_out.clone()),
                ("file.entries[/mnt/nfs]".to_string(), timed_out),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // With no paths, or none looked at yet, each metric has nothing.
        for output in [json!([]), Value::Null] {
            let none = collector.entries(&output, time());
            assert_eq!(
                said(&none),
                [
                    ("file.exists".to_string(), Value::Null),
                    ("file.size".to_string(), Value::Null),
                    ("file.age".to_string(), Value::Null),
                    ("file.folder".to_string(), Value::Null),
                    ("file.entries".to_string(), Value::Null),
                ]
            );
            every_metric_has_an_entry(&collector, &none);
        }
    }

    #[test]
    fn what_looking_at_a_path_says_becomes_entries() {
        let collector = watching_nothing();
        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("backup.tar");
        fs::write(&file, "12345").unwrap();
        let (file, missing) = (path_of(&file), path_of(&folder.path().join("nope")));
        // An hour on, so the file's age is known whatever its clock says.
        let later = maxnines_protocol::time::now() + TimeDelta::hours(1);
        let refused = io::Error::from(io::ErrorKind::PermissionDenied);
        let output = json!([
            inspect(&file, later),
            inspect(&missing, later),
            unreadable(&"/srv/secret".to_string(), &refused),
        ]);
        let entries = collector.entries(&output, time());
        every_metric_has_an_entry(&collector, &entries);
        let said = said(&entries);
        assert_eq!(said.len(), 3 * 5);
        for (name, value) in [
            (format!("file.exists[{file}]"), json!(1)),
            (format!("file.size[{file}]"), json!(5)),
            (format!("file.folder[{file}]"), json!(false)),
            (format!("file.entries[{file}]"), Value::Null),
            (format!("file.exists[{missing}]"), json!(0)),
            (format!("file.age[{missing}]"), Value::Null),
            (
                "file.exists[/srv/secret]".to_string(),
                json!({ "error": "not allowed" }),
            ),
        ] {
            assert!(said.contains(&(name.clone(), value)), "{name}: {said:?}");
        }
        let age = said
            .iter()
            .find(|(name, _)| name == &format!("file.age[{file}]"))
            .and_then(|(_, age)| age.as_f64());
        assert!(age >= Some(3590.0), "{said:?}");
    }

    #[test]
    fn watching_no_paths_really_collects_nothing_for_each_metric() {
        let mut collector = watching_nothing();
        let output = collector.collect().unwrap();
        assert_eq!(output, json!([]));
        every_metric_has_an_entry(&collector, &collector.entries(&output, time()));
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
