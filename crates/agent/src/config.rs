use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use hcl::{Body, Structure};
use serde::Deserialize;
use serde_json::Value;

const FACTS: &str = "facts";

/// What the server's database columns hold. Names also get a `custom.` prefix.
const MAX_FACT_VALUE_LEN: usize = 255;
const MAX_FACT_NAME_LEN: usize = 255 - "custom.".len();

/// Only what's needed to reach the server. What to monitor comes from the
/// server, and custom facts stay here because the server's rules match on them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    /// Where the agent keeps its key and the last config it received.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Your own facts by full name, reported under `custom`. These are gathered
    /// by [`take_facts`] rather than deserialized.
    #[serde(skip)]
    pub facts: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub url: String,
    /// Enrollment token for automatic approval.
    pub token_file: Option<PathBuf>,
    /// Trust this CA instead of the public roots.
    pub ca_file: Option<PathBuf>,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("state")
}

impl Config {
    pub fn key_file(&self) -> PathBuf {
        self.state_dir.join("agent.key")
    }

    pub fn saved_config_file(&self) -> PathBuf {
        self.state_dir.join("config.json")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let body: Body = hcl::from_str(text)?;
        let (body, facts) = take_facts(body)?;
        let mut config: Config = hcl::from_body(body)?;
        config.facts = facts;
        Ok(config)
    }
}

/// Collects every way of writing facts, which can be mixed:
///
/// ```hcl
/// facts = { role = "web", "one.thing" = "x" }
/// facts { rack = 12 }
/// facts "disk" { size = 1 }    # the name becomes disk.size
/// ```
///
/// They're read from the parsed file because deserializing them directly keeps
/// only one form and silently drops the others.
fn take_facts(body: Body) -> Result<(Body, BTreeMap<String, Value>)> {
    let mut facts = BTreeMap::new();
    let mut rest = Vec::new();

    for structure in body {
        match structure {
            Structure::Attribute(attribute) if attribute.key() == FACTS => {
                let body = Body::builder().add_attribute(attribute).build();
                let values: BTreeMap<String, Value> = hcl::from_body(body)?;
                let value = values.get(FACTS).context("reading facts")?;
                ensure!(value.is_object(), "facts must be a map of names to values");
                add_facts("", value, &mut facts)?;
            }
            Structure::Block(block) if block.identifier() == FACTS => {
                let labels: Vec<&str> = block.labels().iter().map(|l| l.as_str()).collect();
                let value: Value = hcl::from_body(block.body().clone())?;
                add_facts(&labels.join("."), &value, &mut facts)?;
            }
            other => rest.push(other),
        }
    }

    Ok((Body::from_iter(rest), facts))
}

/// Nested values become dotted names, and setting a name twice is a mistake.
fn add_facts(prefix: &str, value: &Value, facts: &mut BTreeMap<String, Value>) -> Result<()> {
    if let Value::Object(fields) = value {
        for (name, field) in fields {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            add_facts(&path, field, facts)?;
        }
        return Ok(());
    }

    ensure!(
        is_valid_fact_name(prefix),
        "fact name {prefix:?} must be up to {MAX_FACT_NAME_LEN} bytes of dot-separated parts, \
         using letters, digits, - and _"
    );
    check_fact_value(prefix, value)?;
    ensure!(
        facts.insert(prefix.to_string(), value.clone()).is_none(),
        "fact {prefix:?} is set more than once"
    );
    Ok(())
}

/// Plain values only, because an expression can't be evaluated here. Lists can
/// hold anything a fact can, including other lists and maps.
fn check_fact_value(name: &str, value: &Value) -> Result<()> {
    let text = match value {
        Value::Array(items) => {
            return items
                .iter()
                .try_for_each(|item| check_fact_value(name, item));
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                ensure!(
                    is_valid_fact_name(key),
                    "fact {name:?} contains the invalid name {key:?}"
                );
                check_fact_value(name, field)?;
            }
            return Ok(());
        }
        Value::Null => bail!("fact {name:?} has no value"),
        Value::String(text) => text.clone(),
        scalar => scalar.to_string(),
    };
    ensure!(
        !text.contains("${"),
        "fact {name:?} must be a plain value, not an expression"
    );
    ensure!(
        text.len() <= MAX_FACT_VALUE_LEN,
        "fact {name:?} is longer than {MAX_FACT_VALUE_LEN} bytes"
    );
    Ok(())
}

/// Names can hold dots, like `one.thing`. They're only text to the server, but
/// empty parts like `a..b` are always a mistake.
fn is_valid_fact_name(name: &str) -> bool {
    let is_valid_part = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    name.len() <= MAX_FACT_NAME_LEN && name.split('.').all(is_valid_part)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "server {\n  url = \"ws://127.0.0.1:9000/ws\"\n}\n";

    fn parse(text: &str) -> Result<Config> {
        Config::parse(&format!("{SERVER}{text}"))
    }

    #[test]
    fn shipped_config_parses() {
        let config = Config::parse(include_str!("../config/agent.hcl")).unwrap();

        assert_eq!(config.server.url, "ws://127.0.0.1:9000/ws");
        assert_eq!(config.server.token_file, None);
        assert_eq!(config.key_file(), PathBuf::from("data.nosync/agent.key"));
    }

    #[test]
    fn only_the_server_is_required() {
        let config = parse("").unwrap();

        assert_eq!(config.key_file(), PathBuf::from("state/agent.key"));
        assert_eq!(
            config.saved_config_file(),
            PathBuf::from("state/config.json")
        );
        assert!(config.facts.is_empty());
    }

    #[test]
    fn the_server_is_required() {
        assert!(Config::parse("").is_err());
    }

    #[test]
    fn monitoring_settings_are_refused_because_they_come_from_the_server() {
        for text in [
            "interval_secs = 5\n",
            "facts_interval_secs = 5\n",
            "collector \"cpu\" {}\n",
            "exporter \"stdout\" {}\n",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn taking_facts_leaves_the_rest_of_the_config_alone() {
        let text = "state_dir = \"/var/lib/maxnines\"\nfacts \"a\" {\n  b = 1\n}\n";
        let config = parse(text).unwrap();

        assert_eq!(config.state_dir, PathBuf::from("/var/lib/maxnines"));
        assert_eq!(config.facts["a.b"], 1);
    }

    #[test]
    fn custom_facts_are_read_from_the_facts_block() {
        let config = parse(
            r#"
            facts {
              role       = "web"
              datacenter = "fra1"
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["role"], "web");
        assert_eq!(config.facts["datacenter"], "fra1");
    }

    #[test]
    fn custom_fact_names_can_hold_dots_and_dashes() {
        let config = parse(
            r#"
            facts = {
              "one.thing" = "x"
              "has-dash"  = "y"
              "a.b.c"     = 5
              role        = "web"
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["one.thing"], "x");
        assert_eq!(config.facts["has-dash"], "y");
        assert_eq!(config.facts["a.b.c"], 5);
        assert_eq!(config.facts["role"], "web");
    }

    #[test]
    fn a_labeled_facts_block_prefixes_its_names() {
        let config = parse(
            r#"
            facts "toplevelname" {
              thing1 = "1"
              thing2 = 2
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["toplevelname.thing1"], "1");
        assert_eq!(config.facts["toplevelname.thing2"], 2);
        assert_eq!(config.facts.len(), 2);
    }

    #[test]
    fn every_way_of_writing_facts_can_be_mixed_in_any_order() {
        let attribute = "facts = {\n  role = \"web\"\n  \"one.thing\" = \"x\"\n}\n";
        let plain = "facts {\n  rack = 12\n}\n";
        let labeled = "facts \"disk\" {\n  size = 1\n}\n";
        let another = "facts \"net\" {\n  speed = 10\n}\n";

        for text in [
            [attribute, plain, labeled, another].concat(),
            [another, labeled, plain, attribute].concat(),
            [labeled, attribute, another, plain].concat(),
        ] {
            let config = parse(&text).unwrap();
            assert_eq!(config.facts["role"], "web");
            assert_eq!(config.facts["one.thing"], "x");
            assert_eq!(config.facts["rack"], 12);
            assert_eq!(config.facts["disk.size"], 1);
            assert_eq!(config.facts["net.speed"], 10);
            assert_eq!(config.facts.len(), 5);
        }
    }

    #[test]
    fn the_same_label_twice_merges_its_facts() {
        let text = "facts \"web\" {\n  a = 1\n}\nfacts \"web\" {\n  b = 2\n}\n";
        let config = parse(text).unwrap();

        assert_eq!(config.facts["web.a"], 1);
        assert_eq!(config.facts["web.b"], 2);
    }

    #[test]
    fn nested_facts_become_dotted_names() {
        let config = parse(
            r#"
            facts = {
              a = { b = 1 }
            }
            facts "c" "d" {
              e = 2
            }
            facts "f" {
              g {
                h = 3
              }
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["a.b"], 1);
        assert_eq!(config.facts["c.d.e"], 2);
        assert_eq!(config.facts["f.g.h"], 3);
    }

    #[test]
    fn setting_a_fact_twice_is_an_error_however_it_is_written() {
        for text in [
            "facts \"web\" {\n  a = 1\n}\nfacts \"web\" {\n  a = 2\n}\n",
            "facts {\n  a = 1\n}\nfacts {\n  a = 2\n}\n",
            "facts = {\n  \"web.a\" = 1\n}\nfacts \"web\" {\n  a = 2\n}\n",
            "facts = {\n  a = 1\n}\nfacts {\n  a = 1\n}\n",
        ] {
            let error = format!("{:#}", parse(text).unwrap_err());
            assert!(error.contains("more than once"), "{error}");
        }
    }

    #[test]
    fn facts_must_be_a_map() {
        assert!(parse("facts = 5\n").is_err());
        assert!(parse("facts = \"web\"\n").is_err());
    }

    #[test]
    fn labeled_facts_follow_the_same_rules() {
        for text in [
            "facts \"has space\" {\n  a = 1\n}\n",
            "facts \"web\" {\n  a = var.x\n}\n",
            "facts \"web\" {\n  a = [var.x]\n}\n",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_name_and_a_longer_name_starting_with_it_can_coexist() {
        let text = "facts = {\n  \"one\" = 1\n  \"one.thing\" = 2\n}\n";
        assert_eq!(parse(text).unwrap().facts.len(), 2);
    }

    #[test]
    fn rejects_unusable_fact_names() {
        let long = "x".repeat(249);
        for name in ["", ".", "a..b", ".a", "a.", "has space", "é", long.as_str()] {
            let text = format!("facts = {{\n  \"{name}\" = \"x\"\n}}\n");
            assert!(parse(&text).is_err(), "{name:?}");
        }
    }

    #[test]
    fn the_longest_allowed_fact_name_is_accepted() {
        let text = format!("facts = {{\n  \"{}\" = 1\n}}\n", "x".repeat(248));
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn custom_facts_keep_their_types() {
        let config = parse(
            r#"
            facts {
              role    = "web"
              count   = 5
              ratio   = 1.5
              enabled = true
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["role"], "web");
        assert_eq!(config.facts["count"], 5);
        assert_eq!(config.facts["ratio"], 1.5);
        assert_eq!(config.facts["enabled"], true);
    }

    #[test]
    fn custom_facts_can_be_lists() {
        let config = parse(
            r#"
            facts = {
              tags  = ["web", "prod"]
              ports = [80, 443]
              empty = []
            }
            facts "disk" {
              mounts = ["/", "/data"]
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["tags"], serde_json::json!(["web", "prod"]));
        assert_eq!(config.facts["ports"], serde_json::json!([80, 443]));
        assert_eq!(config.facts["empty"], serde_json::json!([]));
        assert_eq!(
            config.facts["disk.mounts"],
            serde_json::json!(["/", "/data"])
        );
    }

    #[test]
    fn lists_can_hold_maps_and_other_lists() {
        let config = parse(
            r#"
            facts = {
              disks = [{ mount = "/" }, { mount = "/data" }]
              grid  = [[1, 2], [3]]
            }
            "#,
        )
        .unwrap();

        assert_eq!(config.facts["disks"][1]["mount"], "/data");
        assert_eq!(config.facts["grid"][0][1], 2);
    }

    #[test]
    fn every_list_item_has_to_fit_the_database() {
        let text = format!(
            "facts = {{\n  tags = [\"ok\", \"{}\"]\n}}\n",
            "x".repeat(256)
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn custom_facts_must_be_plain_values() {
        for value in [
            "[var.role]",
            "[{ a = var.role }]",
            "[null]",
            "null",
            "var.role",
            "1 + 2",
            "\"${var.role}\"",
            "\"web-${var.id}\"",
        ] {
            let text = format!("facts = {{\n  role = {value}\n}}\n");
            assert!(parse(&text).is_err(), "{value}");
        }
    }

    #[test]
    fn rejects_a_custom_fact_that_is_too_long() {
        let text = format!("facts = {{\n  note = \"{}\"\n}}\n", "x".repeat(256));
        assert!(parse(&text).is_err());
    }
}
