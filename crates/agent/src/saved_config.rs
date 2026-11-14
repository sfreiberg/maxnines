//! The last config that worked, so the agent can keep monitoring if it restarts
//! while the server is unreachable.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use maxnines_protocol::AgentConfig;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::websocket::ConfigUpdate;

#[derive(Serialize, Deserialize)]
struct Saved {
    version: String,
    config: AgentConfig,
}

/// A missing or damaged file only means waiting for the server.
pub fn load(path: &Path) -> Option<ConfigUpdate> {
    let text = fs::read_to_string(path).ok()?;
    match serde_json::from_str::<Saved>(&text) {
        Ok(saved) => Some(ConfigUpdate {
            version: saved.version,
            config: saved.config,
        }),
        Err(error) => {
            warn!(%error, "ignoring an unreadable saved config");
            None
        }
    }
}

/// Writes a new file then renames it, so a crash can't leave half a config.
pub fn save(path: &Path, update: &ConfigUpdate) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating folder {}", parent.display()))?;
    }
    let saved = Saved {
        version: update.version.clone(),
        config: update.config.clone(),
    };
    let temporary = path.with_extension("json.new");
    fs::write(&temporary, serde_json::to_string_pretty(&saved)?)
        .with_context(|| format!("writing {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn update() -> ConfigUpdate {
        ConfigUpdate {
            version: "v1".to_string(),
            config: serde_json::from_value(json!({ "interval_secs": 9 })).unwrap(),
        }
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
