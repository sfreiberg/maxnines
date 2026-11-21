//! The config rules that ship with the server. They're written to the database each
//! time it starts, so an upgrade brings its changes to them, while what people add
//! lives in rules of their own, which a start never touches.

use serde_json::json;

use crate::models::RuleInput;

/// A config rule that ships with the server, known by a key that never changes, so it
/// can be renamed or reworked in a later version and still be found.
pub struct BuiltInRule {
    pub key: &'static str,
    pub rule: RuleInput,
}

/// Every built-in rule, in the order they apply among rules of the same priority.
pub fn all() -> Vec<BuiltInRule> {
    vec![
        BuiltInRule {
            key: "default",
            rule: RuleInput {
                name: "Default".to_string(),
                priority: 0,
                applies_to: None,
                operating_systems: Vec::new(),
                enabled: true,
                settings: json!({
                    "interval_secs": 15,
                    "facts_interval_secs": 3600,
                    "collectors": {
                        "host": { "enabled": true },
                        "cpu": { "enabled": true },
                        "memory": { "enabled": true },
                        "disk": { "enabled": true },
                        "network": { "enabled": true },
                        "system": { "enabled": true },
                    },
                }),
            },
        },
        BuiltInRule {
            key: "macos",
            rule: RuleInput {
                name: "macOS".to_string(),
                priority: 0,
                applies_to: None,
                operating_systems: vec!["macos".to_string()],
                enabled: true,
                settings: json!({ "collectors": { "gpu": { "enabled": true } } }),
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_engine::check_rule;

    #[test]
    fn every_built_in_rule_is_one_that_could_be_saved() {
        let rules = all();
        for built_in in &rules {
            check_rule(&built_in.rule)
                .unwrap_or_else(|error| panic!("{}: {error:#}", built_in.key));
        }
        let mut keys: Vec<&str> = rules.iter().map(|rule| rule.key).collect();
        keys.dedup();
        assert_eq!(keys.len(), rules.len(), "keys are each used once");
    }
}
