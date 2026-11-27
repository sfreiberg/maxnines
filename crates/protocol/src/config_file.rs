//! Changing config files for the Windows installers and their Modify button. Only
//! the values set change: comments and anything else in a file are kept as they
//! were. Any file the agent or server keeps is put in place here too, so a power
//! cut can't leave it empty.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use hcl::edit::expr::Expression;
use hcl::edit::structure::{Attribute, Block, Body};
use hcl::edit::{Decorate, Ident};

/// A server's address as people open it in a browser, or as agents connect to it.
#[derive(Debug, PartialEq)]
pub struct Address {
    secure: bool,
    /// Already an agent address, which is kept exactly.
    agent: Option<String>,
    authority: String,
    host: String,
    port: Option<u16>,
    path: String,
}

impl Address {
    pub fn parse(address: &str) -> Result<Self> {
        let address = address.trim();
        let (scheme, rest) = address.split_once("://").ok_or_else(|| {
            anyhow!("the server's address starts with https:// or http://, not {address:?}")
        })?;
        let (secure, agent) = match scheme.to_ascii_lowercase().as_str() {
            "https" => (true, false),
            "http" => (false, false),
            "wss" => (true, true),
            "ws" => (false, true),
            _ => bail!("the server's address starts with https:// or http://, not {address:?}"),
        };
        ensure!(
            !rest.contains(['?', '#']) && !rest.contains(char::is_whitespace),
            "{address:?} isn't just a server's address"
        );
        let (authority, path) = match rest.find('/') {
            Some(slash) => rest.split_at(slash),
            None => (rest, ""),
        };
        let host_and_port = authority.rsplit('@').next().unwrap_or_default();
        let (host, port) = match host_and_port.strip_prefix('[') {
            // An IPv6 address, such as [::1]:9000.
            Some(inside) => {
                let (host, after) = inside
                    .split_once(']')
                    .ok_or_else(|| anyhow!("{address:?} has an unfinished IPv6 address"))?;
                (host, after.strip_prefix(':'))
            }
            None => match host_and_port.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_and_port, None),
            },
        };
        ensure!(!host.is_empty(), "{address:?} has no server name in it");
        let port = port
            .map(|port| {
                port.parse::<u16>()
                    .map_err(|_| anyhow!("{port:?} isn't a port, in {address:?}"))
            })
            .transpose()?;
        Ok(Self {
            secure,
            agent: agent.then(|| address.to_string()),
            authority: authority.to_string(),
            host: host.to_string(),
            port,
            path: path.trim_end_matches('/').to_string(),
        })
    }

    /// What agents connect to: `/ws` on the same host and port. One given as an
    /// agent address is kept exactly, as it has to match the server's public_url.
    pub fn agent_url(&self) -> String {
        if let Some(agent) = &self.agent {
            return agent.clone();
        }
        let scheme = if self.secure { "wss" } else { "ws" };
        let path = if self.path.ends_with("/ws") {
            self.path.clone()
        } else {
            format!("{}/ws", self.path)
        };
        format!("{scheme}://{}{path}", self.authority)
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port in the address, or the one its scheme implies.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(if self.secure { 443 } else { 80 })
    }
}

/// An agent address as people would open the server in a browser, for the
/// installer to show: `/ws` dropped and the scheme swapped. One that doesn't end
/// in `/ws` is kept as it is, which the installer also accepts.
pub fn browser_address(agent_url: &str) -> String {
    let swapped = agent_url
        .strip_prefix("wss://")
        .map(|rest| ("https://", rest))
        .or_else(|| {
            agent_url
                .strip_prefix("ws://")
                .map(|rest| ("http://", rest))
        });
    match swapped {
        Some((scheme, rest)) if rest.ends_with("/ws") => {
            format!("{scheme}{}", &rest[..rest.len() - 3])
        }
        _ => agent_url.to_string(),
    }
}

/// Reads a config file, if there is one yet.
pub fn read(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// The config file's path made absolute, and its folder, which is created.
pub fn locate(config: &Path) -> Result<(PathBuf, PathBuf)> {
    let config = std::path::absolute(config).context("finding the config file")?;
    let folder = config
        .parent()
        .context("the config file has no folder")?
        .to_path_buf();
    std::fs::create_dir_all(&folder).with_context(|| format!("creating {}", folder.display()))?;
    Ok((config, folder))
}

/// Writes beside the file and then swaps it in, so a failure halfway leaves the
/// old one whole.
pub fn replace(path: &Path, text: &str) -> Result<()> {
    replace_prepared(path, text, |_| Ok(()))
}

/// As [`replace`], for a secret such as an enrollment token: on Unix only its
/// owner can read it, from the moment it's written. On Windows it's as private as
/// the folder it's in, which the installers make only Windows and administrators
/// can open.
pub fn replace_secret(path: &Path, text: &str) -> Result<()> {
    replace_with(path, text, true, |_| Ok(()))
}

/// As [`replace`], doing `prepare` to the new file before it's swapped in, such
/// as setting who can open it, so it's never there without that done.
pub fn replace_prepared(
    path: &Path,
    text: &str,
    prepare: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    replace_with(path, text, false, prepare)
}

fn replace_with(
    path: &Path,
    text: &str,
    secret: bool,
    prepare: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    // One left behind keeps whoever could read it, so it goes first.
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("removing {}", temporary.display()));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let written = options.open(&temporary).and_then(|mut file| {
        use std::io::Write;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    });
    written.with_context(|| format!("writing {}", temporary.display()))?;
    if let Err(error) = prepare(&temporary) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    swap_in(&temporary, path).with_context(|| format!("replacing {}", path.display()))
}

/// Puts `new`, whose contents are already on disk, in the place of `path`, so that
/// once this returns a power cut leaves the new one there, whole, never an empty
/// file or the old one: the rename is on disk before this returns, as is the
/// folder's listing it changed.
pub fn swap_in(new: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(new, path)?;
    sync_folder(path)
}

/// Syncs the folder `path` is in, where Unix keeps the names of its files.
#[cfg(unix)]
fn sync_folder(path: &Path) -> std::io::Result<()> {
    let folder = match path.parent() {
        Some(folder) if !folder.as_os_str().is_empty() => folder,
        _ => Path::new("."),
    };
    let synced = std::fs::File::open(folder).and_then(|folder| folder.sync_all());
    match synced {
        // Some filesystems, as some network and FUSE ones, can't sync a folder,
        // and the file is in place regardless.
        Err(error) if can_be_left_unsynced(&error) => Ok(()),
        synced => synced,
    }
}

/// A folder's sync that the filesystem can't do, as it says by EINVAL or ENOTSUP.
#[cfg(unix)]
fn can_be_left_unsynced(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
    )
}

/// Windows can't open a folder to sync it. NTFS keeps a journal of renames, so a
/// power cut leaves one file or the other there, whole, but it may be the old one.
#[cfg(not(unix))]
fn sync_folder(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Replaces an attribute's value, keeping any comment beside it, or adds it at
/// the end with `indent` before it.
pub fn set(body: &mut Body, indent: &str, key: &str, value: impl Into<Expression>) {
    match body.get_attribute_mut(key) {
        Some(mut attribute) => {
            let old = attribute.value_mut();
            let decor = old.decor().clone();
            *old = value.into();
            *old.decor_mut() = decor;
        }
        None => {
            let mut attribute = Attribute::new(Ident::new(key), value);
            attribute.decor_mut().set_prefix(indent.to_string());
            body.push(attribute);
        }
    }
}

/// The first block called `name`, added at the end with `indent` before it if
/// there isn't one.
pub fn block<'a>(body: &'a mut Body, indent: &str, name: &'a str) -> &'a mut Body {
    if body.get_blocks(name).next().is_none() {
        let mut block = Block::new(Ident::new(name));
        // A blank line between it and whatever comes before.
        let gap = if body.is_empty() { "" } else { "\n" };
        block.decor_mut().set_prefix(format!("{gap}{indent}"));
        block.body.decor_mut().set_suffix(indent.to_string());
        body.push(block);
    }
    &mut body
        .get_blocks_mut(name)
        .next()
        .expect("the block was just added")
        .body
}

/// A path as text for a config file.
pub fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("{} isn't valid Unicode", path.display()))
}

/// Saves values where the installer finds them to fill in Modify, under
/// `HKLM\SOFTWARE\MaxNines\<program>`. An empty value is removed.
#[cfg(windows)]
pub fn remember_for_installer(program: &str, values: &[(&str, &str)]) -> Result<()> {
    let key = windows_registry::LOCAL_MACHINE
        .create(format!(r"SOFTWARE\MaxNines\{program}"))
        .context("saving the settings for the installer")?;
    for (name, value) in values {
        if value.is_empty() {
            // Already gone is fine.
            let _ = key.remove_value(name);
        } else {
            key.set_string(name, value)
                .with_context(|| format!("saving {name} for the installer"))?;
        }
    }
    Ok(())
}

/// What [`remember_for_installer`] saved last, for these names. One never saved,
/// or saved empty, isn't there.
#[cfg(windows)]
pub fn remembered_for_installer(
    program: &str,
    names: &[&str],
) -> std::collections::BTreeMap<String, String> {
    let Ok(key) = windows_registry::LOCAL_MACHINE.open(format!(r"SOFTWARE\MaxNines\{program}"))
    else {
        return Default::default();
    };
    names
        .iter()
        .filter_map(|name| Some((name.to_string(), key.get_string(name).ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn a_secret_is_only_ever_its_owners_to_read() {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("enrollment.token");
        // Even where one was left behind that anyone could read.
        let left = folder.path().join("enrollment.token.new");
        std::fs::write(&left, "old").unwrap();
        std::fs::set_permissions(&left, std::fs::Permissions::from_mode(0o644)).unwrap();

        replace_secret(&path, "token").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "token");
        assert!(!left.exists());
    }

    use super::*;

    fn agent_url(address: &str) -> String {
        Address::parse(address).unwrap().agent_url()
    }

    #[test]
    fn a_browser_address_becomes_the_agent_address() {
        for (address, url) in [
            (
                "https://monitor.example.com",
                "wss://monitor.example.com/ws",
            ),
            (
                "https://monitor.example.com/",
                "wss://monitor.example.com/ws",
            ),
            ("  http://10.0.0.5:9000  ", "ws://10.0.0.5:9000/ws"),
            ("HTTP://[::1]:9000", "ws://[::1]:9000/ws"),
            (
                "https://example.com/maxnines/",
                "wss://example.com/maxnines/ws",
            ),
            (
                "https://monitor.example.com/ws",
                "wss://monitor.example.com/ws",
            ),
        ] {
            assert_eq!(agent_url(address), url, "{address}");
        }
    }

    #[test]
    fn an_agent_address_is_kept_exactly() {
        for url in ["wss://monitor.example.com/ws", "ws://10.0.0.5:9000/agents"] {
            assert_eq!(agent_url(url), url);
        }
    }

    #[test]
    fn the_host_and_port_come_from_the_address() {
        let address = Address::parse("https://monitor.example.com").unwrap();
        assert_eq!(
            (address.host(), address.port(), address.is_secure()),
            ("monitor.example.com", 443, true)
        );
        let address = Address::parse("http://MAXNINES:9000").unwrap();
        assert_eq!((address.host(), address.port()), ("MAXNINES", 9000));
        let address = Address::parse("ws://[::1]/ws").unwrap();
        assert_eq!((address.host(), address.port()), ("::1", 80));
    }

    #[test]
    fn the_installer_shows_what_was_typed() {
        for address in [
            "https://monitor.example.com",
            "http://MAXNINES:9000",
            "https://example.com/maxnines",
            "ws://10.0.0.5:9000/agents",
        ] {
            assert_eq!(browser_address(&agent_url(address)), address);
        }
    }

    #[test]
    fn rejects_what_isnt_a_server_address() {
        for address in [
            "",
            "monitor.example.com",
            "ftp://monitor.example.com",
            "https://",
            "https://:9000",
            "https://monitor.example.com:http",
            "https://monitor.example.com/?x=1",
            "https://monitor example.com",
            "http://[::1:9000",
        ] {
            assert!(Address::parse(address).is_err(), "{address:?}");
        }
    }

    #[test]
    fn set_keeps_comments_and_adds_what_is_missing() {
        let mut body: Body = "# Mine\nlisten = \"0.0.0.0:9000\" # here\n"
            .parse()
            .unwrap();
        set(&mut body, "", "listen", "0.0.0.0:443");
        set(&mut body, "", "public_url", "wss://m.example.com/ws");
        let tls = block(&mut body, "", "tls");
        set(tls, "  ", "key_file", "key.pem");

        assert_eq!(
            body.to_string(),
            "# Mine\nlisten = \"0.0.0.0:443\" # here\npublic_url = \"wss://m.example.com/ws\"\n\ntls {\n  key_file = \"key.pem\"\n}\n"
        );
    }

    #[test]
    fn a_failed_preparation_leaves_the_old_file() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("x.hcl");
        replace(&path, "one").unwrap();

        assert!(replace_prepared(&path, "two", |_| anyhow::bail!("no")).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
        assert!(!folder.path().join("x.hcl.new").exists());

        let mut prepared = None;
        replace_prepared(&path, "three", |new| {
            prepared = Some(std::fs::read_to_string(new)?);
            Ok(())
        })
        .unwrap();
        assert_eq!(prepared.as_deref(), Some("three"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "three");
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_that_cant_be_synced_leaves_the_file_in_place_all_the_same() {
        use std::io::{Error, ErrorKind};
        assert!(can_be_left_unsynced(&Error::from(ErrorKind::Unsupported)));
        assert!(can_be_left_unsynced(&Error::from(ErrorKind::InvalidInput)));
        assert!(!can_be_left_unsynced(&Error::from(
            ErrorKind::PermissionDenied
        )));
        assert!(!can_be_left_unsynced(&Error::other("input/output error")));
    }

    #[test]
    fn replace_swaps_in_the_new_text() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("x.hcl");
        replace(&path, "one").unwrap();
        replace(&path, "two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
        assert_eq!(read(&folder.path().join("missing")).unwrap(), None);
    }
}
