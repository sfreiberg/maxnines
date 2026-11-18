//! Sets the server in the config file, for the Windows installer and its Modify
//! button. Only the values it sets change: comments, custom metrics and anything
//! else in the file are kept as they were.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use hcl::edit::expr::Expression;
use hcl::edit::structure::{Attribute, Block, Body};
use hcl::edit::{Decorate, Ident};
use tokio_tungstenite::tungstenite::http::Uri;

use crate::config::Config;

/// The config written when there isn't one yet.
const TEMPLATE: &str = include_str!("../../../packaging/windows/agent.hcl");

/// What the token is saved as, beside the config.
const TOKEN_FILE: &str = "enrollment.token";

/// Turns the address people open the server at in a browser into the address
/// agents connect to, which is `/ws` on the same host and port. An address that
/// is already `ws://` or `wss://` is kept exactly, as it has to match the
/// server's public_url.
pub fn server_url(address: &str) -> Result<String> {
    let address = address.trim();
    let uri: Uri = address
        .parse()
        .map_err(|_| anyhow!("{address:?} isn't a web address"))?;
    let authority = uri
        .authority()
        .filter(|authority| !authority.host().is_empty())
        .ok_or_else(|| anyhow!("{address:?} has no server name in it"))?;
    let scheme = match uri.scheme_str() {
        Some("ws" | "wss") => return Ok(address.to_string()),
        Some("http") => "ws",
        Some("https") => "wss",
        _ => bail!("the server's address starts with https:// or http://, not {address:?}"),
    };
    ensure!(
        uri.query().is_none(),
        "the server's address can't have a query, as {address:?} does"
    );
    let path = uri.path().trim_end_matches('/');
    let path = if path.ends_with("/ws") {
        path.to_string()
    } else {
        format!("{path}/ws")
    };
    Ok(format!("{scheme}://{authority}{path}"))
}

/// The config file's new text: `existing`, or the template when there's no file
/// yet, with the server's URL and, if given, the token file set.
pub fn edit(
    existing: Option<&str>,
    folder: &Path,
    url: &str,
    token_file: Option<&Path>,
) -> Result<String> {
    let mut body: Body = existing
        .unwrap_or(TEMPLATE)
        .parse()
        .context("reading the config file")?;
    if existing.is_none() {
        // Relative paths would mean wherever a command was run from.
        set(
            &mut body,
            "",
            "state_dir",
            path_text(&folder.join("state"))?,
        );
    }

    if body.get_blocks("server").next().is_none() {
        let mut block = Block::new(Ident::new("server"));
        block.decor_mut().set_prefix("\n");
        body.push(block);
    }
    let server = &mut body
        .get_blocks_mut("server")
        .next()
        .context("finding the server block")?
        .body;
    set(server, "  ", "url", url);
    if let Some(token_file) = token_file {
        set(server, "  ", "token_file", path_text(token_file)?);
    }

    let text = body.to_string();
    Config::parse(&text).context("checking the new config")?;
    Ok(text)
}

/// Replaces an attribute's value, keeping any comment beside it, or adds it
/// at the end with `indent` before it.
fn set(body: &mut Body, indent: &str, key: &str, value: &str) {
    match body.get_attribute_mut(key) {
        Some(mut attribute) => {
            let old = attribute.value_mut();
            let decor = old.decor().clone();
            *old = Expression::from(value);
            *old.decor_mut() = decor;
        }
        None => {
            let mut attribute = Attribute::new(Ident::new(key), value);
            attribute.decor_mut().set_prefix(indent.to_string());
            body.push(attribute);
        }
    }
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("{} isn't valid Unicode", path.display()))
}

/// Writes the config, and the token if there is one, returning the URL set.
pub fn write(config: &Path, address: &str, token: Option<&str>) -> Result<String> {
    let config = std::path::absolute(config).context("finding the config file")?;
    let folder = config
        .parent()
        .context("the config file has no folder")?
        .to_path_buf();
    std::fs::create_dir_all(&folder).with_context(|| format!("creating {}", folder.display()))?;

    let url = server_url(address)?;
    let existing = match std::fs::read_to_string(&config) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", config.display()));
        }
    };

    // Blank keeps the token there is, so Modify doesn't have to show it.
    let token = token.map(str::trim).filter(|token| !token.is_empty());
    let token_file = token.map(|_| folder.join(TOKEN_FILE));

    // Everything is checked before anything is written.
    let text = edit(existing.as_deref(), &folder, &url, token_file.as_deref())?;
    if let (Some(token), Some(path)) = (token, &token_file) {
        replace(path, token)?;
    }
    replace(&config, &text)?;
    println!("Set the server to {url} in {}.", config.display());
    Ok(url)
}

/// Writes beside the file and then swaps it in, so a failure halfway leaves
/// the old one whole.
fn replace(path: &Path, text: &str) -> Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, text).with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))
}

/// Where the installer looks for the server to show when it's opened again.
#[cfg(windows)]
pub fn remember_for_installer(url: &str) -> Result<()> {
    windows_registry::LOCAL_MACHINE
        .create(r"SOFTWARE\MaxNines\Agent")
        .and_then(|key| key.set_string("ServerUrl", url))
        .context("saving the server's address for the installer")
}

#[cfg(test)]
mod tests {
    use super::*;

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
            (
                "https://example.com/maxnines/",
                "wss://example.com/maxnines/ws",
            ),
            (
                "https://monitor.example.com/ws",
                "wss://monitor.example.com/ws",
            ),
        ] {
            assert_eq!(server_url(address).unwrap(), url, "{address}");
        }
    }

    #[test]
    fn an_agent_address_is_kept_exactly() {
        for url in ["wss://monitor.example.com/ws", "ws://10.0.0.5:9000/agents"] {
            assert_eq!(server_url(url).unwrap(), url);
        }
    }

    #[test]
    fn rejects_what_isnt_a_server_address() {
        for address in [
            "",
            "monitor.example.com",
            "ftp://monitor.example.com",
            "https://",
            "https://monitor.example.com/?x=1",
            "not an address",
        ] {
            assert!(server_url(address).is_err(), "{address:?}");
        }
    }

    #[test]
    fn a_new_config_comes_from_the_template_with_absolute_paths() {
        let folder = Path::new("/data/MaxNines/Agent");
        let token = folder.join("enrollment.token");
        let text = edit(None, folder, "wss://m.example.com/ws", Some(&token)).unwrap();

        let config = Config::parse(&text).unwrap();
        assert_eq!(config.server.url, "wss://m.example.com/ws");
        assert_eq!(config.server.token_file, Some(token));
        assert_eq!(config.state_dir, folder.join("state"));
        assert!(text.starts_with("# The MaxNines agent's settings"));
    }

    #[test]
    fn only_the_server_changes_in_an_existing_config() {
        let existing = r#"# Mine
server {
  url = "ws://old:9000/ws" # the old one
  ca_file = "ca.pem"
}

state_dir = "D:/agent"

custom_metric "queue" {
  command = ["queue-depth"]
}
"#;
        let text = edit(
            Some(existing),
            Path::new("/ignored"),
            "wss://new.example.com/ws",
            None,
        )
        .unwrap();

        assert_eq!(
            text,
            existing.replace("ws://old:9000/ws", "wss://new.example.com/ws")
        );
    }

    #[test]
    fn adds_what_an_existing_config_is_missing() {
        let text = edit(
            Some("state_dir = \"state\"\n"),
            Path::new("/ignored"),
            "wss://m.example.com/ws",
            Some(Path::new("/data/enrollment.token")),
        )
        .unwrap();

        assert_eq!(
            text,
            r#"state_dir = "state"

server {
  url = "wss://m.example.com/ws"
  token_file = "/data/enrollment.token"
}
"#
        );
    }

    #[test]
    fn writes_the_config_and_token_and_keeps_the_token_when_none_is_given() {
        let folder = tempfile::tempdir().unwrap();
        let config = folder.path().join("Agent").join("agent.hcl");

        write(&config, "https://m.example.com", Some(" secret\n")).unwrap();
        let token = folder.path().join("Agent").join("enrollment.token");
        assert_eq!(std::fs::read_to_string(&token).unwrap(), "secret");

        write(&config, "https://other.example.com", Some("")).unwrap();
        let loaded = Config::load(&config).unwrap();
        assert_eq!(loaded.server.url, "wss://other.example.com/ws");
        assert_eq!(loaded.server.token_file, Some(token.clone()));
        assert_eq!(std::fs::read_to_string(&token).unwrap(), "secret");
    }

    #[test]
    fn a_bad_address_leaves_the_config_alone() {
        let folder = tempfile::tempdir().unwrap();
        let config = folder.path().join("agent.hcl");
        write(&config, "https://m.example.com", None).unwrap();
        let before = std::fs::read_to_string(&config).unwrap();

        assert!(write(&config, "m.example.com", Some("secret")).is_err());

        assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
        assert!(!folder.path().join("enrollment.token").exists());
    }
}
