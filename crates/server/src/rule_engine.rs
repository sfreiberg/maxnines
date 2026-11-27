//! Works out each agent's config. Rules are evaluated here on the server, so
//! agents only ever receive plain settings and never run an expression.
//!
//! Matching rules apply from lowest priority to highest, and each one's settings
//! are merged over the last. Maps merge key by key, and a list is replaced whole.

use std::cell::OnceCell;

use anyhow::{Context, Result, anyhow, ensure};
use cel::{Context as CelContext, Program, Value as CelValue};
use maxnines_protocol::AgentConfig;
use serde::Serialize;
use serde_json::{Map, Value, json};
use tracing::debug;

use crate::cel_env::FUNCTIONS;
use crate::facts::{flatten, unflatten};
use crate::models::{ConfigRule, RuleInput};

/// What the database column holds.
const MAX_NAME_LEN: usize = 255;

/// The operating systems a rule can be limited to, by the `os.family` agents report,
/// with their names for people.
pub const OPERATING_SYSTEMS: [(&str, &str); 4] = [
    ("freebsd", "FreeBSD"),
    ("linux", "Linux"),
    ("macos", "macOS"),
    ("windows", "Windows"),
];

/// An agent's config, and how it came to be.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedConfig {
    pub version: String,
    pub config: AgentConfig,
    /// The rules that applied, in order.
    pub matched_rules: Vec<String>,
    /// Collectors the rules turned on that this agent can't run.
    pub skipped_collectors: Vec<String>,
    /// The host's facts it was worked out from, in their natural shape, which the
    /// metrics its templates work out can use.
    #[serde(skip)]
    pub facts: Value,
}

/// Checks a rule before it's saved, so a mistake is caught by whoever made it
/// and not found later by an agent.
pub fn check_rule(rule: &RuleInput) -> Result<()> {
    ensure!(!rule.name.trim().is_empty(), "a rule needs a name");
    ensure!(rule.name.len() <= MAX_NAME_LEN, "the rule name is too long");

    if let Some(condition) = &rule.applies_to {
        Program::compile(condition)
            .map_err(|error| anyhow!("invalid condition for which hosts: {error}"))?;
    }
    for (index, system) in rule.operating_systems.iter().enumerate() {
        ensure!(
            OPERATING_SYSTEMS.iter().any(|(known, _)| known == system),
            "unknown operating system {system:?}: use {}",
            OPERATING_SYSTEMS.map(|(known, _)| known).join(", ")
        );
        ensure!(
            !rule.operating_systems[..index].contains(system),
            "{system:?} is listed twice"
        );
    }

    ensure!(rule.settings.is_object(), "settings must be a map");
    // Agents ignore settings they don't know, so a mistake is only caught here.
    let mut unknown = Vec::new();
    let config: AgentConfig = serde_ignored::deserialize(rule.settings.clone(), |path| {
        unknown.push(path.to_string());
    })
    .context("invalid settings")?;
    ensure!(
        unknown.is_empty(),
        "invalid settings: no such setting as {}",
        unknown.join(", ")
    );
    config.validate().context("invalid settings")?;
    ensure!(
        config.templates.is_empty(),
        "invalid settings: no such setting as templates, which the server works out from templates"
    );

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

/// A condition ready to check against any number of hosts.
pub struct Condition(Program);

impl Condition {
    pub fn compile(text: &str) -> Result<Self> {
        Program::compile(text)
            .map(Self)
            .map_err(|error| anyhow!("{error}"))
    }

    /// Whether it's true of a host. Anything but `true` isn't.
    pub fn check(&self, host: &Host) -> Result<bool> {
        let result = self
            .0
            .execute(host.context()?)
            .map_err(|error| anyhow!("{error}"))?;
        Ok(result == CelValue::Bool(true))
    }
}

impl Condition {
    /// Whether it's true with these as its variables, such as what a template's
    /// discovery found. Anything but `true` isn't, and nor is one naming something
    /// that isn't there.
    pub fn check_values(&self, values: &serde_json::Map<String, Value>) -> bool {
        let mut context = CelContext::with_env(FUNCTIONS.clone());
        for (name, value) in values {
            if context.add_variable(name.as_str(), value).is_err() {
                return false;
            }
        }
        self.0
            .execute(&context)
            .is_ok_and(|result| result == CelValue::Bool(true))
    }
}

/// A host as conditions see it: `facts`, which is what its agent reports, and
/// `trusted`, which is what the server knows itself. They're made ready for conditions
/// the first time one is checked, once however many are.
pub struct Host<'a> {
    pub facts: &'a Value,
    pub id: &'a str,
    context: OnceCell<Result<CelContext<'static, 'static>, String>>,
}

impl<'a> Host<'a> {
    /// `facts` are in their natural shape, as [`unflatten`] gives them.
    pub fn new(facts: &'a Value, id: &'a str) -> Self {
        Self {
            facts,
            id,
            context: OnceCell::new(),
        }
    }

    fn context(&self) -> Result<&CelContext<'static, 'static>> {
        let made = self.context.get_or_init(|| {
            let mut context = CelContext::with_env(FUNCTIONS.clone());
            context
                .add_variable("facts", self.facts)
                .map_err(|error| error.to_string())?;
            context
                .add_variable("trusted", json!({ "host_id": self.id }))
                .map_err(|error| error.to_string())?;
            Ok(context)
        });
        made.as_ref().map_err(|error| anyhow!("{error}"))
    }
}

/// Checks one condition against one host, for tests.
#[cfg(test)]
pub fn evaluate(condition: &str, facts: &Value, host_id: &str) -> Result<bool> {
    Condition::compile(condition)?.check(&Host::new(facts, host_id))
}

/// A config rule with its condition compiled.
pub struct CompiledRule {
    pub rule: ConfigRule,
    condition: Option<Condition>,
}

impl CompiledRule {
    pub fn new(rule: ConfigRule) -> Result<Self> {
        let condition = rule
            .rule
            .applies_to
            .as_deref()
            .map(Condition::compile)
            .transpose()
            .with_context(|| format!("the config rule {:?}", rule.rule.name))?;
        Ok(Self { rule, condition })
    }

    /// Whether the host runs one of the operating systems the rule is for, if it
    /// names any.
    pub fn runs_on(&self, host: &Host) -> bool {
        let systems = &self.rule.rule.operating_systems;
        let family = host.facts["os"]["family"].as_str();
        systems.is_empty()
            || family.is_some_and(|family| systems.iter().any(|system| system == family))
    }

    /// Whether its condition is true of the host, or why it couldn't be checked.
    /// One with no condition is true of every host.
    pub fn condition_holds(&self, host: &Host) -> Result<bool> {
        self.condition
            .as_ref()
            .map_or(Ok(true), |condition| condition.check(host))
    }

    /// A condition that can't be evaluated doesn't match. That's the normal case
    /// for a rule about a fact this agent doesn't have.
    pub fn matches(&self, host: &Host) -> bool {
        if !self.rule.in_force() || !self.runs_on(host) {
            return false;
        }
        let rule = &self.rule.rule;
        // A built-in rule is for the hosts its template is for, as the template
        // says which: those given it by hand, and those its condition picks, or
        // only those given it by hand when it has no condition.
        let given = self
            .rule
            .template
            .as_ref()
            .map_or(&[][..], |template| template.host_ids.as_slice());
        if given.iter().any(|id| id == host.id) {
            return true;
        }
        let Some(condition) = &self.condition else {
            return given.is_empty();
        };
        match condition.check(host) {
            Ok(result) => result,
            Err(error) => {
                debug!(rule = rule.name, %error, "condition didn't match");
                false
            }
        }
    }
}

/// Config rules, compiled once to work out any number of agents' configs, in the order
/// they apply.
pub struct ConfigRules(Vec<CompiledRule>);

impl ConfigRules {
    pub fn new(rules: impl IntoIterator<Item = ConfigRule>) -> Result<Self> {
        rules
            .into_iter()
            .map(CompiledRule::new)
            .collect::<Result<_>>()
            .map(Self)
    }

    /// Works out the config for one agent.
    pub fn resolve(&self, host: &Host) -> Result<ResolvedConfig> {
        let mut merged = Value::Object(Map::new());
        let mut matched_rules = Vec::new();

        for compiled in &self.0 {
            if compiled.matches(host) {
                merge(&mut merged, &compiled.rule.rule.settings);
                matched_rules.push(compiled.rule.rule.name.clone());
            }
        }

        let mut config: AgentConfig =
            serde_json::from_value(merged).context("rules produced invalid settings")?;
        let skipped_collectors = remove_unsupported(&mut config, host.facts);

        Ok(ResolvedConfig {
            version: config.version()?,
            config,
            matched_rules,
            skipped_collectors,
            facts: host.facts.clone(),
        })
    }
}

/// Works out the config for one agent, given its facts in their natural shape, for
/// tests.
#[cfg(test)]
pub fn resolve(rules: &[ConfigRule], facts: &Value, host_id: &str) -> Result<ResolvedConfig> {
    ConfigRules::new(rules.iter().cloned())?.resolve(&Host::new(facts, host_id))
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
    use std::time::Duration;

    use super::*;

    fn rule(name: &str, condition: Option<&str>, settings: Value) -> ConfigRule {
        ConfigRule {
            id: 1,
            built_in: None,
            built_in_changed_at: None,
            template: None,
            rule: RuleInput {
                name: name.to_string(),
                priority: 0,
                applies_to: condition.map(String::from),
                operating_systems: Vec::new(),
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
        resolve(rules, facts, "host-1").unwrap()
    }

    /// Saving a rule doesn't allow one, so one that's stored is a fault to report.
    #[test]
    fn a_stored_condition_that_does_not_compile_is_an_error() {
        let broken = rule("Broken", Some("os.family =="), json!({}));
        let error = resolve(&[base(), broken], &linux(), "host-1").unwrap_err();
        assert!(format!("{error:#}").contains("\"Broken\""), "{error:#}");
    }

    #[test]
    fn a_rule_with_no_condition_applies_to_everyone() {
        let resolved = resolve_for(&[base()], &json!({}));

        assert_eq!(resolved.config.interval, Duration::from_secs(15));
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

        assert_eq!(resolved.config.interval, Duration::from_secs(5));
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

        assert_eq!(resolved.config.interval, Duration::from_secs(15));
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
            r#"trusted.host_id == "host-1""#,
        ] {
            let rules = [
                base(),
                rule("r", Some(condition), json!({ "interval_secs": 5 })),
            ];
            assert_eq!(
                resolve_for(&rules, &linux()).config.interval,
                Duration::from_secs(5),
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

        assert_eq!(
            resolve_for(&rules, &linux()).config.interval,
            Duration::from_secs(15)
        );
    }

    #[test]
    fn a_condition_that_is_not_a_boolean_does_not_match() {
        let rules = [
            base(),
            rule("r", Some("1 + 1"), json!({ "interval_secs": 5 })),
        ];
        assert_eq!(
            resolve_for(&rules, &linux()).config.interval,
            Duration::from_secs(15)
        );
    }

    #[test]
    fn a_disabled_rule_is_skipped() {
        let mut off = rule("off", None, json!({ "interval_secs": 5 }));
        off.rule.enabled = false;

        assert_eq!(
            resolve_for(&[base(), off], &linux()).config.interval,
            Duration::from_secs(15)
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

        assert_eq!(resolved.config.interval, Duration::from_secs(15));
        assert!(resolved.config.collectors.is_empty());
    }

    #[test]
    fn a_rule_with_a_setting_no_agent_knows_is_refused() {
        let input = rule("r", None, json!({ "intervl_secs": 30 }));
        let error = check_rule(&input.rule).unwrap_err().to_string();
        assert_eq!(error, "invalid settings: no such setting as intervl_secs");

        let nested = rule(
            "r",
            None,
            json!({ "collectors": { "disk": { "mounts": ["/"] } } }),
        );
        let error = check_rule(&nested.rule).unwrap_err().to_string();
        assert_eq!(
            error,
            "invalid settings: no such setting as collectors.disk.mounts"
        );
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
