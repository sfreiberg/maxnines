//! The servers maxnines knows, by name, in `config.hcl`. Tokens aren't kept here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Deserialize;

use crate::failure::Failure;
use crate::tokens;

/// What's in `config.hcl`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Config {
    /// The context used when `--context` doesn't say.
    #[serde(default)]
    pub current: Option<String>,
    #[serde(default, rename = "context")]
    pub contexts: BTreeMap<String, Context>,
}

/// A server, by the name maxnines knows it as.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Context {
    pub server: String,
    /// Where an API key is, for a context that uses one instead of signing in.
    #[serde(default)]
    pub key_env: Option<String>,
}

/// Where maxnines keeps what it knows: `MAXNINES_CONFIG_DIR` if it's set, which tests
/// use, then `%APPDATA%\maxnines` on Windows, or `~/.config/maxnines` elsewhere, as
/// command lines usually do, macOS included.
pub fn folder() -> Result<PathBuf> {
    if let Some(folder) = std::env::var_os("MAXNINES_CONFIG_DIR") {
        return Ok(PathBuf::from(folder));
    }
    if cfg!(windows) {
        let app_data = std::env::var_os("APPDATA").context("APPDATA isn't set")?;
        return Ok(PathBuf::from(app_data).join("maxnines"));
    }
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(config).join("maxnines"));
    }
    let home = std::env::var_os("HOME").context("HOME isn't set")?;
    Ok(PathBuf::from(home).join(".config").join("maxnines"))
}

fn file(folder: &Path) -> PathBuf {
    folder.join("config.hcl")
}

impl Config {
    /// What's saved, or nothing yet.
    pub fn load(folder: &Path) -> Result<Self> {
        let path = file(folder);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        hcl::from_str(&text).with_context(|| format!("reading {}", path.display()))
    }

    /// Saves it, written whole and then moved into place so it's never half there.
    pub fn save(&self, folder: &Path) -> Result<()> {
        std::fs::create_dir_all(folder).with_context(|| format!("making {}", folder.display()))?;
        let path = file(folder);
        let partial = path.with_extension("hcl.new");
        std::fs::write(&partial, self.to_hcl(tokens::system(folder).place()))
            .with_context(|| format!("writing {}", partial.display()))?;
        std::fs::rename(&partial, &path).with_context(|| format!("writing {}", path.display()))
    }

    /// The file, saying where tokens are kept: `tokens_kept`.
    fn to_hcl(&self, tokens_kept: &str) -> String {
        let mut text = format!(
            "# Servers maxnines knows, by name. Signing in keeps a server's tokens in\n\
             # {tokens_kept}, not here.\n"
        );
        if let Some(current) = &self.current {
            text.push_str(&format!("\ncurrent = {}\n", quote(current)));
        }
        for (name, context) in &self.contexts {
            text.push_str(&format!("\ncontext {} {{\n", quote(name)));
            text.push_str(&format!("  server = {}\n", quote(&context.server)));
            if let Some(key_env) = &context.key_env {
                text.push_str(&format!("  key_env = {}\n", quote(key_env)));
            }
            text.push_str("}\n");
        }
        text
    }

    /// The context `name` says, or the current one.
    pub fn pick(&self, name: Option<&str>) -> Result<(String, Context), Failure> {
        let name = match name.or(self.current.as_deref()) {
            Some(name) => name,
            None if self.contexts.is_empty() => {
                return Err(Failure::not_allowed(
                    "Not signed in to a server yet: run maxnines login https://your-server",
                ));
            }
            None => {
                return Err(Failure::usage(
                    "No context is chosen: run maxnines config use <name>, or pass --context",
                ));
            }
        };
        let context = self.contexts.get(name).ok_or_else(|| {
            Failure::not_found(format!(
                "There's no context called {name:?}. maxnines config list shows them"
            ))
        })?;
        Ok((name.to_string(), context.clone()))
    }
}

/// A string as HCL writes it. `${` would start a template, so it's written `$${`.
fn quote(text: &str) -> String {
    let json = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string());
    json.replace("${", "$${").replace("%{", "%%{")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_are_saved_and_read_back() {
        let folder = tempfile::tempdir().unwrap();
        assert_eq!(Config::load(folder.path()).unwrap(), Config::default());

        let mut config = Config {
            current: Some("prod".to_string()),
            ..Config::default()
        };
        config.contexts.insert(
            "lan".to_string(),
            Context {
                server: "http://192.168.0.155:9000".to_string(),
                key_env: None,
            },
        );
        config.contexts.insert(
            "ci \"odd\" ${name}".to_string(),
            Context {
                server: "https://monitor.example.com".to_string(),
                key_env: Some("CI_KEY".to_string()),
            },
        );
        config.save(folder.path()).unwrap();
        let text = std::fs::read_to_string(folder.path().join("config.hcl")).unwrap();
        assert!(
            text.contains("context \"lan\" {\n  server = \"http://192.168.0.155:9000\"\n}"),
            "{text}"
        );
        assert_eq!(Config::load(folder.path()).unwrap(), config);
    }

    #[test]
    fn the_context_used_is_the_one_named_or_the_current_one() {
        let mut config = Config::default();
        assert_eq!(config.pick(None).unwrap_err().code, Failure::NOT_ALLOWED);
        config.contexts.insert(
            "lan".to_string(),
            Context {
                server: "http://192.168.0.155:9000".to_string(),
                key_env: None,
            },
        );
        assert_eq!(config.pick(None).unwrap_err().code, Failure::USAGE);
        config.current = Some("lan".to_string());
        assert_eq!(config.pick(None).unwrap().0, "lan");
        assert_eq!(config.pick(Some("lan")).unwrap().0, "lan");
        assert_eq!(
            config.pick(Some("prod")).unwrap_err().code,
            Failure::NOT_FOUND
        );
    }
}
