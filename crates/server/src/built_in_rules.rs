//! The config rules that ship with the server: each built-in template's `config`
//! block, as a rule of its own. They're written to the database each time it
//! starts, so an upgrade brings its changes to them, while what people add lives in
//! rules of their own, which a start never touches.

use anyhow::Result;
use maxnines_protocol::templates::{Target, Template};
use serde_json::Value;

use crate::models::RuleInput;

/// A config rule that ships with the server, known by the key of the template it's
/// from, which never changes, so it can be renamed or reworked in a later version
/// and still be found.
pub struct BuiltInRule {
    pub key: String,
    pub rule: RuleInput,
}

/// A template's settings as the config rule they are: named after it, for the hosts
/// it's for, at the lowest priority, so any rule of someone's own applies over it.
pub fn of_template(template: &Template) -> Option<BuiltInRule> {
    let settings = template.config.clone()?;
    Some(BuiltInRule {
        key: template.key.clone(),
        rule: RuleInput {
            name: template.name.clone(),
            priority: 0,
            applies_to: template.applies_to.clone(),
            operating_systems: match &template.target {
                Some(Target::Os(systems)) => systems.clone(),
                _ => Vec::new(),
            },
            enabled: template.enabled,
            settings: Value::Object(settings),
        },
    })
}

/// Every built-in rule, in the order they apply among rules of the same priority:
/// the one for every host first, then the built-in templates' order.
pub fn all() -> Result<Vec<BuiltInRule>> {
    let mut templates: Vec<Template> = crate::templates::built_in::all()?
        .into_iter()
        .map(|one| one.template)
        .collect();
    templates.sort_by_key(|template| template.target.is_some());
    Ok(templates.iter().filter_map(of_template).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_engine::check_rule;

    #[test]
    fn every_built_in_rule_is_one_that_could_be_saved() {
        let rules = all().unwrap();
        for built_in in &rules {
            check_rule(&built_in.rule)
                .unwrap_or_else(|error| panic!("{}: {error:#}", built_in.key));
        }
        let keys: Vec<&str> = rules.iter().map(|rule| rule.key.as_str()).collect();
        assert_eq!(keys, ["host", "macos"]);
    }
}
