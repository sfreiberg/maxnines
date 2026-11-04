//! Works out each agent's config. Rules are evaluated here on the server, so
//! agents only ever receive plain settings and never run an expression.
//!
//! Matching rules apply from lowest priority to highest, and each one's settings
//! are merged over the last. Maps merge key by key, and a list is replaced whole.

use anyhow::{Context, Result, anyhow, ensure};
use cel::{Context as CelContext, Program, Value as CelValue};
use maxnines_protocol::AgentConfig;
use serde::Serialize;
use serde_json::{Map, Value, json};
use tracing::debug;

use crate::facts::{flatten, unflatten};
use crate::models::{ConfigRule, RuleInput};

/// What the database column holds.
const MAX_NAME_LEN: usize = 255;

/// An agent's config, and how it came to be.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedConfig {
    pub version: String,
    pub config: AgentConfig,
    /// The rules that applied, in order.
    pub matched_rules: Vec<String>,
    /// Collectors the rules turned on that this agent can't run.
    pub skipped_collectors: Vec<String>,
}

/// Checks a rule before it's saved, so a mistake is caught by whoever made it
/// and not found later by an agent.
pub fn check_rule(rule: &RuleInput) -> Result<()> {
    ensure!(!rule.name.trim().is_empty(), "a rule needs a name");
    ensure!(rule.name.len() <= MAX_NAME_LEN, "the rule name is too long");

    if let Some(condition) = &rule.condition {
        Program::compile(condition).map_err(|error| anyhow!("invalid condition: {error}"))?;
    }

    ensure!(rule.settings.is_object(), "settings must be a map");
    let config: AgentConfig =
        serde_json::from_value(rule.settings.clone()).context("invalid settings")?;
    config.validate().context("invalid settings")?;

    // Settings are stored flat, and an empty list has no rows to store.
    let flat = flatten(&rule.settings).context("invalid settings")?;
    ensure!(
        unflatten(&flat) == rule.settings || flat.is_empty() && is_empty_map(&rule.settings),
        "invalid settings: empty lists can't be stored, leave the setting out instead"
    );
    Ok(())
}

fn is_empty_map(value: &Value) -> bool {
    value.as_object().is_some_and(Map::is_empty)
}

/// Works out the config for one agent, given its facts in their natural shape.
pub fn resolve(rules: &[ConfigRule], facts: &Value, agent_id: &str) -> Result<ResolvedConfig> {
    let mut merged = Value::Object(Map::new());
    let mut matched_rules = Vec::new();

    for rule in rules {
        if matches(&rule.rule, facts, agent_id) {
            merge(&mut merged, &rule.rule.settings);
            matched_rules.push(rule.rule.name.clone());
        }
    }

    let mut config: AgentConfig =
        serde_json::from_value(merged).context("rules produced invalid settings")?;
    let skipped_collectors = remove_unsupported(&mut config, facts);

    Ok(ResolvedConfig {
        version: config.version()?,
        config,
        matched_rules,
        skipped_collectors,
    })
}

/// A condition that can't be evaluated doesn't match. That's the normal case
/// for a rule about a fact this agent doesn't have.
fn matches(rule: &RuleInput, facts: &Value, agent_id: &str) -> bool {
    if !rule.enabled {
        return false;
    }
    let Some(condition) = &rule.condition else {
        return true;
    };

    match evaluate(condition, facts, agent_id) {
        Ok(result) => result,
        Err(error) => {
            debug!(rule = rule.name, %error, "condition didn't match");
            false
        }
    }
}

/// `facts` is what the agent reports. `trusted` is what the server knows itself.
pub fn evaluate(condition: &str, facts: &Value, agent_id: &str) -> Result<bool> {
    let program = Program::compile(condition).map_err(|error| anyhow!("{error}"))?;

    let mut context = CelContext::default();
    context
        .add_variable("facts", facts)
        .map_err(|error| anyhow!("{error}"))?;
    context
        .add_variable("trusted", json!({ "agent_id": agent_id }))
        .map_err(|error| anyhow!("{error}"))?;

    let result = program
        .execute(&context)
        .map_err(|error| anyhow!("{error}"))?;
    Ok(result == CelValue::Bool(true))
}

fn merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (name, value) in overlay {
                merge(base.entry(name.clone()).or_insert(Value::Null), value);
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

/// An agent that hasn't reported what it supports yet gets everything.
fn remove_unsupported(config: &mut AgentConfig, facts: &Value) -> Vec<String> {
    let Some(supported) = facts["agent"]["collectors"].as_array() else {
        return Vec::new();
    };

    let unsupported: Vec<String> = config
        .collectors
        .keys()
        .filter(|name| !supported.iter().any(|item| item == *name))
        .cloned()
        .collect();
    for name in &unsupported {
        config.collectors.remove(name);
    }
    unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, condition: Option<&str>, settings: Value) -> ConfigRule {
        ConfigRule {
            id: 1,
            rule: RuleInput {
                name: name.to_string(),
                priority: 0,
                condition: condition.map(String::from),
                enabled: true,
                settings,
            },
        }
    }

    fn base() -> ConfigRule {
        rule(
            "Default",
            None,
            json!({
                "interval_secs": 15,
                "collectors": { "cpu": { "enabled": true }, "disk": { "enabled": true } },
            }),
        )
    }

    fn linux() -> Value {
        json!({
            "os": { "family": "linux" },
            "host": { "name": "web-01" },
            "memory": { "total_bytes": 1000 },
            "custom": { "role": "web", "tags": ["prod", "eu"] },
        })
    }

    fn resolve_for(rules: &[ConfigRule], facts: &Value) -> ResolvedConfig {
        resolve(rules, facts, "agent-1").unwrap()
    }

    #[test]
    fn a_rule_with_no_condition_applies_to_everyone() {
        let resolved = resolve_for(&[base()], &json!({}));

        assert_eq!(resolved.config.interval_secs, 15);
        assert_eq!(resolved.matched_rules, ["Default"]);
    }

    #[test]
    fn a_matching_rule_overrides_earlier_ones() {
        let rules = [
            base(),
            rule(
                "linux",
                Some(r#"facts.os.family == "linux""#),
                json!({ "interval_secs": 5 }),
            ),
        ];

        let resolved = resolve_for(&rules, &linux());

        assert_eq!(resolved.config.interval_secs, 5);
        assert_eq!(resolved.config.collectors.len(), 2);
        assert_eq!(resolved.matched_rules, ["Default", "linux"]);
    }

    #[test]
    fn a_rule_that_does_not_match_changes_nothing() {
        let rules = [
            base(),
            rule(
                "windows",
                Some(r#"facts.os.family == "windows""#),
                json!({ "interval_secs": 5 }),
            ),
        ];

        let resolved = resolve_for(&rules, &linux());

        assert_eq!(resolved.config.interval_secs, 15);
        assert_eq!(resolved.matched_rules, ["Default"]);
    }

    #[test]
    fn conditions_can_use_every_kind_of_fact() {
        for condition in [
            r#"facts.host.name.startsWith("web-")"#,
            r#"facts.custom.role == "web" && facts.os.family == "linux""#,
            r#""prod" in facts.custom.tags"#,
            "facts.memory.total_bytes > 500",
            r#"facts.os.family != "windows""#,
            r#"trusted.agent_id == "agent-1""#,
        ] {
            let rules = [
                base(),
                rule("r", Some(condition), json!({ "interval_secs": 5 })),
            ];
            assert_eq!(
                resolve_for(&rules, &linux()).config.interval_secs,
                5,
                "{condition}"
            );
        }
    }

    #[test]
    fn a_condition_about_a_missing_fact_does_not_match() {
        let rules = [
            base(),
            rule(
                "r",
                Some(r#"facts.custom.missing == "x""#),
                json!({ "interval_secs": 5 }),
            ),
        ];

        assert_eq!(resolve_for(&rules, &linux()).config.interval_secs, 15);
    }

    #[test]
    fn a_condition_that_is_not_a_boolean_does_not_match() {
        let rules = [
            base(),
            rule("r", Some("1 + 1"), json!({ "interval_secs": 5 })),
        ];
        assert_eq!(resolve_for(&rules, &linux()).config.interval_secs, 15);
    }

    #[test]
    fn a_disabled_rule_is_skipped() {
        let mut off = rule("off", None, json!({ "interval_secs": 5 }));
        off.rule.enabled = false;

        assert_eq!(
            resolve_for(&[base(), off], &linux()).config.interval_secs,
            15
        );
    }

    #[test]
    fn collector_settings_merge_and_lists_are_replaced_whole() {
        let rules = [
            rule(
                "a",
                None,
                json!({ "collectors": { "disk": { "enabled": true, "mount_points": ["/", "/a"] } } }),
            ),
            rule(
                "b",
                None,
                json!({ "collectors": { "disk": { "mount_points": ["/b"] }, "cpu": {} } }),
            ),
        ];

        let config = resolve_for(&rules, &linux()).config;

        assert_eq!(
            config.collectors["disk"].mount_points.as_deref(),
            Some(&["/b".to_string()][..])
        );
        assert!(config.collectors["disk"].enabled);
        assert!(config.collectors.contains_key("cpu"));
    }

    #[test]
    fn a_later_rule_can_turn_a_collector_off() {
        let rules = [
            base(),
            rule(
                "off",
                None,
                json!({ "collectors": { "cpu": { "enabled": false } } }),
            ),
        ];

        assert!(!resolve_for(&rules, &linux()).config.collectors["cpu"].enabled);
    }

    #[test]
    fn collectors_the_agent_can_not_run_are_left_out_and_recorded() {
        let facts = json!({ "agent": { "collectors": ["cpu"] } });

        let resolved = resolve_for(&[base()], &facts);

        assert!(resolved.config.collectors.contains_key("cpu"));
        assert!(!resolved.config.collectors.contains_key("disk"));
        assert_eq!(resolved.skipped_collectors, ["disk"]);
    }

    #[test]
    fn an_agent_that_has_not_reported_yet_gets_every_collector() {
        let resolved = resolve_for(&[base()], &json!({}));

        assert_eq!(resolved.config.collectors.len(), 2);
        assert!(resolved.skipped_collectors.is_empty());
    }

    #[test]
    fn the_same_rules_and_facts_give_the_same_version() {
        let first = resolve_for(&[base()], &linux());
        let second = resolve_for(&[base()], &linux());
        assert_eq!(first.version, second.version);
    }

    #[test]
    fn no_rules_at_all_still_gives_a_usable_config() {
        let resolved = resolve_for(&[], &linux());

        assert_eq!(resolved.config.interval_secs, 15);
        assert!(resolved.config.collectors.is_empty());
    }

    #[test]
    fn a_rule_with_an_empty_list_is_refused() {
        let input = rule(
            "r",
            None,
            json!({ "collectors": { "disk": { "mount_points": [] } } }),
        );
        let error = format!("{:#}", check_rule(&input.rule).unwrap_err());
        assert!(error.contains("empty lists"), "{error}");
    }

    #[test]
    fn valid_rules_pass_their_checks() {
        for input in [base(), rule("r", Some("true"), json!({}))] {
            assert!(check_rule(&input.rule).is_ok());
        }
    }
}
