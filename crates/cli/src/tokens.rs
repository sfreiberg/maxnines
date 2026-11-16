//! The tokens a context signed in with. On macOS they're kept in the Keychain and on
//! Windows in Credential Manager. Elsewhere they're in a file only its owner can read,
//! as Secret Service would need a library the static Linux binary can't carry.

use std::fs::File;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

/// What a sign in keeps between commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    /// When the access token stops working, in milliseconds since 1970.
    pub access_expires_ms: i64,
    /// Swapped for new tokens before the access token runs out. Only the newest works.
    pub refresh_token: String,
    /// Who it acts as, and the most it may do.
    pub user: String,
    pub role: String,
}

/// Where tokens are kept.
pub trait Store {
    fn load(&self, context: &str) -> Result<Option<Tokens>>;
    fn save(&self, context: &str, tokens: &Tokens) -> Result<()>;
    fn forget(&self, context: &str) -> Result<()>;
}

/// The system's store, as described above. A folder chosen with MAXNINES_CONFIG_DIR
/// keeps everything, tokens included, as in a container.
pub fn system(folder: &Path) -> Box<dyn Store> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        if std::env::var_os("MAXNINES_CONFIG_DIR").is_some() {
            Box::new(FileStore::new(folder))
        } else {
            Box::new(KeyStore)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Box::new(FileStore::new(folder))
    }
}

/// Held while tokens are refreshed, so two commands at once don't both swap the same
/// refresh token, which would sign the slower one out. Released when dropped.
pub fn lock(folder: &Path) -> Result<File> {
    std::fs::create_dir_all(folder).with_context(|| format!("making {}", folder.display()))?;
    let path = folder.join(".refresh.lock");
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.lock()
        .with_context(|| format!("locking {}", path.display()))?;
    Ok(file)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct KeyStore;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl KeyStore {
    const SERVICE: &str = "maxnines-cli";

    fn entry(context: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(Self::SERVICE, context).context("opening the key store")
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Store for KeyStore {
    fn load(&self, context: &str) -> Result<Option<Tokens>> {
        match Self::entry(context)?.get_password() {
            Ok(text) => Ok(serde_json::from_str(&text).ok()),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("reading the key store"),
        }
    }

    fn save(&self, context: &str, tokens: &Tokens) -> Result<()> {
        let text = serde_json::to_string(tokens)?;
        Self::entry(context)?
            .set_password(&text)
            .context("saving to the key store")
    }

    fn forget(&self, context: &str) -> Result<()> {
        match Self::entry(context)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("removing from the key store"),
        }
    }
}

/// Tokens for every context, in one file only its owner can read.
pub struct FileStore {
    path: std::path::PathBuf,
}

impl FileStore {
    pub fn new(folder: &Path) -> Self {
        Self {
            path: folder.join("tokens.json"),
        }
    }

    fn all(&self) -> Result<std::collections::BTreeMap<String, Tokens>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("reading {}", self.path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(error) => Err(error).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    fn write(&self, all: &std::collections::BTreeMap<String, Tokens>) -> Result<()> {
        if let Some(folder) = self.path.parent() {
            std::fs::create_dir_all(folder)
                .with_context(|| format!("making {}", folder.display()))?;
        }
        let partial = self.path.with_extension("json.new");
        let text = serde_json::to_string_pretty(all)?;
        let mut options = File::options();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(&partial)
            .with_context(|| format!("writing {}", partial.display()))?;
        std::io::Write::write_all(&mut file, text.as_bytes())
            .with_context(|| format!("writing {}", partial.display()))?;
        drop(file);
        std::fs::rename(&partial, &self.path)
            .with_context(|| format!("writing {}", self.path.display()))
    }
}

impl Store for FileStore {
    fn load(&self, context: &str) -> Result<Option<Tokens>> {
        Ok(self.all()?.remove(context))
    }

    fn save(&self, context: &str, tokens: &Tokens) -> Result<()> {
        let mut all = self.all()?;
        all.insert(context.to_string(), tokens.clone());
        self.write(&all)
    }

    fn forget(&self, context: &str) -> Result<()> {
        let mut all = self.all()?;
        if all.remove(context).is_some() {
            self.write(&all)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(refresh: &str) -> Tokens {
        Tokens {
            access_token: "mxa_1".to_string(),
            access_expires_ms: 1,
            refresh_token: refresh.to_string(),
            user: "you@example.com".to_string(),
            role: "responder".to_string(),
        }
    }

    #[test]
    fn the_file_keeps_each_contexts_tokens_for_its_owner_alone() {
        let folder = tempfile::tempdir().unwrap();
        let store = FileStore::new(folder.path());
        assert_eq!(store.load("lan").unwrap(), None);
        store.save("lan", &tokens("mxr_1")).unwrap();
        store.save("prod", &tokens("mxr_2")).unwrap();
        store.save("lan", &tokens("mxr_3")).unwrap();
        assert_eq!(store.load("lan").unwrap(), Some(tokens("mxr_3")));
        assert_eq!(store.load("prod").unwrap(), Some(tokens("mxr_2")));
        store.forget("lan").unwrap();
        assert_eq!(store.load("lan").unwrap(), None);
        assert_eq!(store.load("prod").unwrap(), Some(tokens("mxr_2")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(folder.path().join("tokens.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn the_lock_is_held_until_dropped() {
        let folder = tempfile::tempdir().unwrap();
        let held = lock(folder.path()).unwrap();
        let other = File::options()
            .write(true)
            .open(folder.path().join(".refresh.lock"))
            .unwrap();
        assert!(other.try_lock().is_err());
        drop(held);
        assert!(other.try_lock().is_ok());
    }
}
