use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use maxnines_protocol::auth::{Identity, write_private_file};
use tracing::info;

/// Loads the agent's key, creating one on first start so that rollouts need no
/// extra step.
pub fn load_or_create(path: &Path) -> Result<Identity> {
    if path.exists() {
        return load(path);
    }
    info!(key_file = %path.display(), "creating a new agent key");
    generate(path, false)
}

pub fn load(path: &Path) -> Result<Identity> {
    let bytes = fs::read(path).with_context(|| format!("reading key file {}", path.display()))?;
    Identity::from_pkcs8(&bytes).with_context(|| format!("loading key file {}", path.display()))
}

/// Writes a new key. Replacing a key creates a new identity, which the server
/// has to approve again, so that takes `force`.
///
/// The new key is written beside the old one and then takes its place, so a key
/// that can't be written leaves the old one as it was.
pub fn generate(path: &Path, force: bool) -> Result<Identity> {
    if path.exists() && !force {
        bail!(
            "key file {} already exists. Replacing it makes this a new host that must be \
             approved again. Use --force to replace it.",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating folder {}", parent.display()))?;
    }

    let bytes = Identity::generate()?;
    let identity = Identity::from_pkcs8(&bytes)?;
    let mut new = path.as_os_str().to_owned();
    new.push(".new");
    let new = PathBuf::from(new);
    // Left by a run that stopped part way, and never the key in use.
    match fs::remove_file(&new) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("removing {}", new.display()));
        }
        _ => {}
    }
    write_private_file(&new, &bytes).with_context(|| format!("writing {}", new.display()))?;
    maxnines_protocol::config_file::swap_in(&new, path)
        .with_context(|| format!("replacing {}", path.display()))?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_then_loading_gives_the_same_identity() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/agent.key");

        let created = load_or_create(&path).unwrap();
        let loaded = load_or_create(&path).unwrap();

        assert_eq!(created.id(), loaded.id());
    }

    #[test]
    fn generate_refuses_to_replace_a_key_without_force() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("agent.key");
        let original = generate(&path, false).unwrap();

        assert!(generate(&path, false).is_err());
        assert_eq!(load(&path).unwrap().id(), original.id());
    }

    #[test]
    fn generate_with_force_creates_a_new_identity() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("agent.key");
        let original = generate(&path, false).unwrap();

        let replaced = generate(&path, true).unwrap();

        assert_ne!(replaced.id(), original.id());
        assert_eq!(load(&path).unwrap().id(), replaced.id());
    }

    #[test]
    fn a_new_key_that_cannot_be_written_leaves_the_old_one() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("agent.key");
        let original = generate(&path, false).unwrap();
        // A folder where the new key would be written first.
        fs::create_dir(folder.path().join("agent.key.new")).unwrap();
        fs::write(folder.path().join("agent.key.new/x"), "").unwrap();

        assert!(generate(&path, true).is_err());

        assert_eq!(load(&path).unwrap().id(), original.id());
    }

    #[test]
    fn a_key_left_half_written_is_replaced() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("agent.key");
        fs::write(folder.path().join("agent.key.new"), "half").unwrap();

        let created = generate(&path, false).unwrap();

        assert_eq!(load(&path).unwrap().id(), created.id());
        assert!(!folder.path().join("agent.key.new").exists());
    }

    #[test]
    fn loading_a_corrupt_key_fails() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("agent.key");
        fs::write(&path, "not a key").unwrap();

        assert!(load(&path).is_err());
        assert!(load_or_create(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_the_key() {
        use std::os::unix::fs::PermissionsExt;

        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("agent.key");
        generate(&path, false).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
