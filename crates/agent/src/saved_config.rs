//! The last config that worked, so the agent can keep monitoring if it restarts
//! while the server is unreachable. It's kept as the server sent it, and read again
//! by whichever build loads it, so an upgraded agent runs what an older one couldn't.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::websocket::ConfigUpdate;

#[derive(Serialize, Deserialize)]
struct Saved {
    version: String,
    config: Value,
}

/// A missing or damaged file only means waiting for the server.
pub fn load(path: &Path) -> Option<ConfigUpdate> {
    let text = fs::read_to_string(path).ok()?;
    let read = serde_json::from_str::<Saved>(&text)
        .map_err(anyhow::Error::from)
        .and_then(|saved| ConfigUpdate::read(saved.version, saved.config));
    match read {
        Ok(update) => Some(update),
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "ignoring an unreadable saved config"
            );
            None
        }
    }
}

/// Puts `new`, written in full, in the place of `path`, so that once this returns a
/// power cut leaves one or the other, never an empty file: the new file's contents
/// are on disk before the rename, and the rename is before its folder's listing.
pub fn replace(new: &Path, path: &Path) -> std::io::Result<()> {
    fs::OpenOptions::new().write(true).open(new)?.sync_all()?;
    fs::rename(new, path)?;
    // Windows writes the rename through itself, and can't open a folder this way.
    #[cfg(unix)]
    if let Some(folder) = path.parent() {
        let folder = if folder.as_os_str().is_empty() {
            Path::new(".")
        } else {
            folder
        };
        fs::File::open(folder)?.sync_all()?;
    }
    Ok(())
}

/// Writes a new file then puts it in place, so a crash can't leave half a config.
pub fn save(path: &Path, update: &ConfigUpdate) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating folder {}", parent.display()))?;
    }
    let saved = Saved {
        version: update.version.clone(),
        config: update.sent.clone(),
    };
    let temporary = path.with_extension("json.new");
    fs::write(&temporary, serde_json::to_string_pretty(&saved)?)
        .with_context(|| format!("writing {}", temporary.display()))?;
    replace(&temporary, path).with_context(|| format!("replacing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn update() -> ConfigUpdate {
        ConfigUpdate::read("v1".to_string(), json!({ "interval_secs": 9 })).unwrap()
    }

    #[test]
    fn a_saved_config_loads_back() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/config.json");

        save(&path, &update()).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.version, "v1");
        assert_eq!(loaded.config, update().config);
    }

    /// Read as it was saved, an agent upgraded since would still take the check
    /// for one it can't run, and the new setting would be lost.
    #[test]
    fn a_config_is_kept_as_it_was_sent_and_read_again_when_loaded() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("config.json");
        let sent = json!({
            "collectors": { "checks": { "checks": [
                { "name": "burrow", "kind": "gopher", "target": "gopher.example.com:70" },
            ] } },
            "from_a_newer_server": { "x": 1 },
        });
        let update = ConfigUpdate::read("v1".to_string(), sent.clone()).unwrap();
        let checks = update.config.collectors["checks"].checks.clone().unwrap();
        assert_eq!(checks[0].kind, maxnines_protocol::CheckKind::Unknown);

        save(&path, &update).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.sent, sent);
        let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["config"], sent);
    }

    #[test]
    fn saving_replaces_the_previous_config() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("config.json");
        save(&path, &update()).unwrap();

        let mut newer = update();
        newer.version = "v2".to_string();
        save(&path, &newer).unwrap();

        assert_eq!(load(&path).unwrap().version, "v2");
        assert!(!path.with_extension("json.new").exists());
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let folder = tempfile::tempdir().unwrap();
        assert!(load(&folder.path().join("config.json")).is_none());
    }

    #[test]
    fn a_damaged_file_is_ignored() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("config.json");
        fs::write(&path, "not json").unwrap();

        assert!(load(&path).is_none());
    }
}
