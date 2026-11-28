//! The simulated agents' keys, kept so a second run reuses the same agents rather
//! than adding more to the server.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use maxnines_protocol::auth::Identity;

/// At least `count` identities, generating any that the file doesn't have.
pub fn load(path: &Path, count: usize) -> Result<Vec<Identity>> {
    let mut keys: Vec<String> = match fs::read_to_string(path) {
        Ok(text) => {
            serde_json::from_str(&text).with_context(|| format!("reading {}", path.display()))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };

    if keys.len() < count {
        while keys.len() < count {
            keys.push(hex::encode(Identity::generate()?));
        }
        save(path, &keys)?;
    }

    keys.iter()
        .take(count)
        .map(|key| {
            let bytes = hex::decode(key).context("a key in the file isn't hex")?;
            Identity::from_pkcs8(&bytes)
        })
        .collect()
}

fn save(path: &Path, keys: &[String]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(serde_json::to_string(keys)?.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_kept_between_runs() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("keys.json");

        let first = load(&path, 3).unwrap();
        let second = load(&path, 3).unwrap();

        assert_eq!(first.len(), 3);
        assert_eq!(first[2].id(), second[2].id());
    }

    #[test]
    fn asking_for_more_keeps_the_ones_there_are() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("keys.json");

        let first = load(&path, 2).unwrap();
        let more = load(&path, 4).unwrap();

        assert_eq!(more.len(), 4);
        assert_eq!(first[1].id(), more[1].id());
    }

    #[test]
    fn asking_for_fewer_uses_the_first_ones() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("keys.json");
        let all = load(&path, 3).unwrap();

        let fewer = load(&path, 1).unwrap();

        assert_eq!(fewer.len(), 1);
        assert_eq!(fewer[0].id(), all[0].id());
    }

    #[test]
    fn a_damaged_file_is_an_error_rather_than_new_agents() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("keys.json");
        fs::write(&path, "not json").unwrap();

        assert!(load(&path, 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_the_keys() {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("keys.json");
        load(&path, 1).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();

        assert_eq!(mode & 0o777, 0o600);
    }
}
