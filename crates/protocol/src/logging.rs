//! Where a program's logs go.

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use tracing::Subscriber;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;

/// A file a day, so two weeks of logs.
const DAILY_FILES_KEPT: usize = 14;

pub fn to_stderr() {
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(std::io::stderr)
        .init();
    std::panic::set_hook(Box::new(log_panic));
}

/// For a program with no terminal, where stderr leads nowhere.
pub fn to_files(folder: &Path, name: &str) -> Result<()> {
    tracing::subscriber::set_global_default(file_subscriber(folder, name)?)
        .context("setting up logging")?;
    std::panic::set_hook(Box::new(log_panic));
    Ok(())
}

/// Panics are recovered from, so each is logged with how the code got there. That
/// needs the function names release builds keep.
fn log_panic(panic: &PanicHookInfo<'_>) {
    let backtrace = Backtrace::force_capture();
    tracing::error!("{panic}\n{backtrace}");
}

fn file_subscriber(folder: &Path, name: &str) -> Result<impl Subscriber + Send + Sync + use<>> {
    let files = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(name)
        .filename_suffix("log")
        .max_log_files(DAILY_FILES_KEPT)
        .build(folder)
        .with_context(|| format!("opening a log file in {}", folder.display()))?;

    Ok(tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(Mutex::new(files))
        .with_ansi(false)
        .finish())
}

fn filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn logs_land_in_a_dated_file_in_a_folder_it_makes() {
        let folder = tempfile::tempdir().unwrap();
        let logs = folder.path().join("logs");

        let subscriber = file_subscriber(&logs, "agent").unwrap();
        tracing::subscriber::with_default(subscriber, || tracing::info!("it started"));

        let files: Vec<_> = fs::read_dir(&logs).unwrap().map(Result::unwrap).collect();
        assert_eq!(files.len(), 1);
        let name = files[0].file_name().into_string().unwrap();
        assert!(
            name.starts_with("agent.") && name.ends_with(".log"),
            "{name}"
        );

        let text = fs::read_to_string(files[0].path()).unwrap();
        assert!(text.contains("it started"), "{text}");
        assert!(!text.contains('\u{1b}'), "colour codes in a file: {text}");
    }

    #[test]
    fn a_panic_is_logged_with_how_it_got_there() {
        let folder = tempfile::tempdir().unwrap();
        let subscriber = file_subscriber(folder.path(), "agent").unwrap();
        tracing::subscriber::with_default(subscriber, || {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(log_panic));
            let result = std::panic::catch_unwind(|| panic!("a test panic"));
            std::panic::set_hook(previous);
            assert!(result.is_err());
        });

        let file = fs::read_dir(folder.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let text = fs::read_to_string(file.path()).unwrap();
        assert!(text.contains("a test panic"), "{text}");
        assert!(text.contains("logging.rs"), "{text}");
        assert!(
            text.contains("a_panic_is_logged_with_how_it_got_there"),
            "{text}"
        );
    }

    #[test]
    fn a_folder_that_cant_be_made_is_an_error_naming_it() {
        let folder = tempfile::tempdir().unwrap();
        let in_the_way = folder.path().join("file");
        fs::write(&in_the_way, "").unwrap();

        let error = file_subscriber(&in_the_way, "agent").err().unwrap();

        assert!(format!("{error:#}").contains("file"), "{error:#}");
    }
}
