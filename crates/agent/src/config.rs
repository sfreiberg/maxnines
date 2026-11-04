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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Where this agent's private key is stored.
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
    /// How often to report facts, on top of reporting them on every connection.
    #[serde(default = "default_facts_interval_secs")]
    pub facts_interval_secs: u64,
    /// Your own facts by full name, reported under `custom`. These are gathered
    /// by [`take_facts`] rather than deserialized.
    #[serde(skip)]
    pub facts: BTreeMap<String, Value>,
    /// `collector "<name>" { ... }` blocks, keyed by label.
    #[serde(default)]
    pub collector: BTreeMap<String, CollectorConfig>,
    /// `exporter "<name>" { ... }` blocks, keyed by label.
    #[serde(default)]
    pub exporter: BTreeMap<String, ExporterConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Disk collector only: limit output to these mount points.
    pub mount_points: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterConfig {
    /// Stdout exporter only.
    #[serde(default)]
    pub format: OutputFormat,
    /// WebSocket exporter only: the server's address.
    pub url: Option<String>,
    /// WebSocket exporter only: enrollment token for automatic approval.
    pub token_file: Option<PathBuf>,
    /// WebSocket exporter only: trust this CA instead of the public roots.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Json,
    Pretty,
}

fn default_interval_secs() -> u64 {
    15
}

fn default_key_file() -> PathBuf {
    PathBuf::from("agent.key")
}

fn default_facts_interval_secs() -> u64 {
    3600
}

fn default_enabled() -> bool {
    true
}

impl Config {
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
        ensure!(config.interval_secs > 0, "interval_secs must be at least 1");
        ensure!(
            config.facts_interval_secs > 0,
            "facts_interval_secs must be at least 1"
        );
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

    #[test]
    fn shipped_config_parses() {
        let config = Config::parse(include_str!("../agent.hcl")).unwrap();
        assert_eq!(config.interval_secs, 15);
        assert_eq!(config.collector.len(), 5);
        assert_eq!(config.exporter["stdout"].format, OutputFormat::Json);
        assert_eq!(
            config.exporter["websocket"].url.as_deref(),
            Some("ws://127.0.0.1:9000/ws")
        );
    }

    #[test]
    fn labeled_blocks_keep_their_own_settings() {
        let config = Config::parse(
            r#"
            collector "cpu" {
              enabled = false
            }
            collector "disk" {
              mount_points = ["/", "/data"]
            }
            "#,
        )
        .unwrap();

        assert!(!config.collector["cpu"].enabled);
        assert!(config.collector["disk"].enabled);
        assert_eq!(
            config.collector["disk"].mount_points.as_deref(),
            Some(&["/".to_string(), "/data".to_string()][..])
        );
    }

    #[test]
    fn defaults_apply_to_an_empty_file() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.interval_secs, 15);
        assert!(config.collector.is_empty());
    }

    #[test]
    fn custom_facts_are_read_from_the_facts_block() {
        let config = Config::parse(
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
        assert_eq!(config.facts_interval_secs, 3600);
    }

    #[test]
    fn custom_fact_names_can_hold_dots_and_dashes() {
        let config = Config::parse(
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
        let config = Config::parse(
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
            let config = Config::parse(&text).unwrap();
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
        let config = Config::parse(text).unwrap();

        assert_eq!(config.facts["web.a"], 1);
        assert_eq!(config.facts["web.b"], 2);
    }

    #[test]
    fn nested_facts_become_dotted_names() {
        let config = Config::parse(
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
            let error = format!("{:#}", Config::parse(text).unwrap_err());
            assert!(error.contains("more than once"), "{error}");
        }
    }

    #[test]
    fn facts_must_be_a_map() {
        assert!(Config::parse("facts = 5\n").is_err());
        assert!(Config::parse("facts = \"web\"\n").is_err());
    }

    #[test]
    fn labeled_facts_follow_the_same_rules() {
        for text in [
            "facts \"has space\" {\n  a = 1\n}\n",
            "facts \"web\" {\n  a = var.x\n}\n",
            "facts \"web\" {\n  a = [var.x]\n}\n",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn taking_facts_leaves_the_rest_of_the_config_alone() {
        let text = "interval_secs = 7\nfacts \"a\" {\n  b = 1\n}\ncollector \"cpu\" {}\n";
        let config = Config::parse(text).unwrap();

        assert_eq!(config.interval_secs, 7);
        assert_eq!(config.collector.len(), 1);
    }

    #[test]
    fn a_name_and_a_longer_name_starting_with_it_can_coexist() {
        let text = "facts = {\n  \"one\" = 1\n  \"one.thing\" = 2\n}\n";
        assert_eq!(Config::parse(text).unwrap().facts.len(), 2);
    }

    #[test]
    fn rejects_unusable_fact_names() {
        let long = "x".repeat(249);
        for name in ["", ".", "a..b", ".a", "a.", "has space", "é", long.as_str()] {
            let text = format!("facts = {{\n  \"{name}\" = \"x\"\n}}\n");
            assert!(Config::parse(&text).is_err(), "{name:?}");
        }
    }

    #[test]
    fn the_longest_allowed_fact_name_is_accepted() {
        let text = format!("facts = {{\n  \"{}\" = 1\n}}\n", "x".repeat(248));
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn custom_facts_keep_their_types() {
        let config = Config::parse(
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
        let config = Config::parse(
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
        let config = Config::parse(
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
        assert!(Config::parse(&text).is_err());
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
            assert!(Config::parse(&text).is_err(), "{value}");
        }
    }

    #[test]
    fn rejects_a_custom_fact_that_is_too_long() {
        let text = format!("facts = {{\n  note = \"{}\"\n}}\n", "x".repeat(256));
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_a_zero_facts_interval() {
        assert!(Config::parse("facts_interval_secs = 0").is_err());
    }

    #[test]
    fn rejects_zero_interval() {
        assert!(Config::parse("interval_secs = 0").is_err());
    }

    #[test]
    fn rejects_unknown_settings() {
        assert!(Config::parse("intervl_secs = 5").is_err());
        assert!(Config::parse("collector \"cpu\" {\n  enabeld = false\n}\n").is_err());
    }

    #[test]
    fn rejects_unknown_output_format() {
        assert!(Config::parse("exporter \"stdout\" {\n  format = \"xml\"\n}\n").is_err());
    }
}
