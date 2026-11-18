//! Sets the server in the config file, for the Windows installer and its Modify
//! button. Only the values it sets change: comments, custom metrics and anything
//! else in the file are kept as they were.

use std::path::Path;

use anyhow::{Context, Result};
use hcl::edit::structure::Body;
use maxnines_protocol::config_file::{self, Address, block, path_text, set};

use crate::config::Config;

/// The config written when there isn't one yet.
const TEMPLATE: &str = include_str!("../../../packaging/windows/agent.hcl");

/// What the token is saved as, beside the config.
const TOKEN_FILE: &str = "enrollment.token";

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

    let server = block(&mut body, "", "server");
    set(server, "  ", "url", url);
    if let Some(token_file) = token_file {
        set(server, "  ", "token_file", path_text(token_file)?);
    }

    let text = body.to_string();
    Config::parse(&text).context("checking the new config")?;
    Ok(text)
}

/// Writes the config, and the token if there is one, returning the URL set.
pub fn write(config: &Path, address: &str, token: Option<&str>) -> Result<String> {
    let url = Address::parse(address)?.agent_url();
    let (config, folder) = config_file::locate(config)?;
    let existing = config_file::read(&config)?;

    // Blank keeps the token there is, so Modify doesn't have to show it.
    let token = token.map(str::trim).filter(|token| !token.is_empty());
    let token_file = token.map(|_| folder.join(TOKEN_FILE));

    // Everything is checked before anything is written.
    let text = edit(existing.as_deref(), &folder, &url, token_file.as_deref())?;
    if let (Some(token), Some(path)) = (token, &token_file) {
        config_file::replace(path, token)?;
    }
    config_file::replace(&config, &text)?;
    println!("Set the server to {url} in {}.", config.display());
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

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
