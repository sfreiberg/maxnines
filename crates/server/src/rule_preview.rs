//! Shows what saving a rule would do, before it's saved. This runs the same
//! `resolve` that agents get their config from, once with the saved rules and
//! once with the rule as it stands in the form, and compares the results.

use maxnines_protocol::{AgentConfig, Check, CollectorSettings, default_status_page};
use serde::Serialize;
use serde_json::Value;

use crate::models::{ConfigRule, RuleInput};
use crate::rule_engine::{self, ResolvedConfig};

/// Enough to see the pattern without a page that never ends. Counts still cover
/// every agent, and the agents that change come first.
const MAX_SHOWN: usize = 100;

/// Sorts after every saved rule of the same priority, as a new rule would.
const NEW_RULE_ID: i64 = i64::MAX;

/// An agent to try a rule against, with its facts in their natural shape.
pub struct PreviewAgent {
    pub id: String,
    pub host: String,
    pub online: bool,
    pub facts: Value,
}

#[derive(Debug, Serialize)]
pub struct AgentPreview {
    pub host: String,
    pub online: bool,
    /// Whether the condition matches, even if the rule is turned off.
    pub matches: bool,
    pub changes: Vec<String>,
    /// Why this agent's result might not be what it seems.
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    pub enabled: bool,
    pub total: usize,
    pub matching: usize,
    pub changing: usize,
    pub agents: Vec<AgentPreview>,
    /// How many agents were left out of `agents`.
    pub hidden: usize,
}

/// Tries `rule` against `agents`. `id` is the saved rule it would replace, if
/// there is one, and `rules` are the saved rules in the order they apply.
pub fn preview(
    rules: &[ConfigRule],
    id: Option<i64>,
    rule: &RuleInput,
    agents: &[PreviewAgent],
) -> Preview {
    let proposed = with_rule(rules, id, rule);
    let mut previews: Vec<AgentPreview> = agents
        .iter()
        .map(|agent| preview_agent(rules, &proposed, rule, agent))
        .collect();

    previews.sort_by(|a, b| {
        let rank = |agent: &AgentPreview| (agent.changes.is_empty(), !agent.matches);
        rank(a).cmp(&rank(b)).then_with(|| a.host.cmp(&b.host))
    });

    let total = previews.len();
    let matching = previews.iter().filter(|agent| agent.matches).count();
    let changing = previews.iter().filter(|a| !a.changes.is_empty()).count();
    previews.truncate(MAX_SHOWN);

    Preview {
        enabled: rule.enabled,
        total,
        matching,
        changing,
        hidden: total - previews.len(),
        agents: previews,
    }
}

/// The rules as they'd be after saving, in the order the database would give.
fn with_rule(rules: &[ConfigRule], id: Option<i64>, rule: &RuleInput) -> Vec<ConfigRule> {
    let mut proposed: Vec<ConfigRule> = rules
        .iter()
        .filter(|saved| Some(saved.id) != id)
        .cloned()
        .collect();
    proposed.push(ConfigRule {
        id: id.unwrap_or(NEW_RULE_ID),
        rule: rule.clone(),
    });
    proposed.sort_by_key(|saved| (saved.rule.priority, saved.id));
    proposed
}

fn preview_agent(
    rules: &[ConfigRule],
    proposed: &[ConfigRule],
    rule: &RuleInput,
    agent: &PreviewAgent,
) -> AgentPreview {
    let check = match &rule.condition {
        Some(condition) => rule_engine::evaluate(condition, &agent.facts, &agent.id),
        None => Ok(true),
    };
    let matches = *check.as_ref().unwrap_or(&false);

    let reported = agent.facts.as_object().is_some_and(|f| !f.is_empty());
    let mut note = match check {
        _ if !reported => Some("Hasn't reported any facts yet".to_string()),
        Ok(_) => None,
        Err(error) => Some(format!("Couldn't check this machine: {error:#}")),
    };

    let before = rule_engine::resolve(rules, &agent.facts, &agent.id);
    let after = rule_engine::resolve(proposed, &agent.facts, &agent.id);
    let changes = match (before, after) {
        (Ok(before), Ok(after)) => describe_changes(&before, &after),
        (_, Err(error)) | (Err(error), _) => {
            note = Some(format!("Couldn't work out its config: {error:#}"));
            Vec::new()
        }
    };

    AgentPreview {
        host: agent.host.clone(),
        online: agent.online,
        matches,
        changes,
        note,
    }
}

fn describe_changes(before: &ResolvedConfig, after: &ResolvedConfig) -> Vec<String> {
    let (old, new) = (&before.config, &after.config);
    let mut changes = Vec::new();

    if old.interval_secs != new.interval_secs {
        changes.push(format!(
            "Sample interval: {}s → {}s",
            old.interval_secs, new.interval_secs
        ));
    }
    if old.facts_interval_secs != new.facts_interval_secs {
        changes.push(format!(
            "Fact report interval: {}s → {}s",
            old.facts_interval_secs, new.facts_interval_secs
        ));
    }

    let mut names: Vec<&String> = old.collectors.keys().chain(new.collectors.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let (was, now) = (running(old, name), running(new, name));
        match (was, now) {
            (None, Some(_)) => changes.push(format!("Turns on {name}")),
            (Some(_), None) => changes.push(format!("Turns off {name}")),
            _ => {}
        }
        if let Some(now) = now {
            let old_mounts = was.and_then(|settings| settings.mount_points.as_ref());
            if old_mounts != now.mount_points.as_ref() {
                changes.push(format!(
                    "{name} mount points: {} → {}",
                    describe_mounts(old_mounts),
                    describe_mounts(now.mount_points.as_ref())
                ));
            }
            let old_names = was.and_then(|settings| settings.names.as_ref());
            if old_names != now.names.as_ref() {
                changes.push(format!(
                    "{name} watches: {} → {}",
                    describe_list(old_names),
                    describe_list(now.names.as_ref())
                ));
            }
            let old_paths = was.and_then(|settings| settings.paths.as_ref());
            if old_paths != now.paths.as_ref() {
                changes.push(format!(
                    "{name} watches: {} → {}",
                    describe_list(old_paths),
                    describe_list(now.paths.as_ref())
                ));
            }
            let old_urls = was.and_then(|settings| settings.urls.as_ref());
            if old_urls != now.urls.as_ref() {
                changes.push(format!(
                    "{name} reads: {} → {}",
                    describe_pages(name, old_urls),
                    describe_pages(name, now.urls.as_ref())
                ));
            }
            let old_checks = was.and_then(|settings| settings.checks.as_ref());
            if old_checks != now.checks.as_ref() {
                changes.push(format!(
                    "{name} runs: {} → {}",
                    describe_checks(old_checks),
                    describe_checks(now.checks.as_ref())
                ));
            }
        }
    }

    for name in &after.skipped_collectors {
        if !before.skipped_collectors.contains(name) {
            changes.push(format!("Can't run {name}, so it's left out"));
        }
    }
    changes
}

/// An agent only runs a collector that's listed and enabled.
fn running<'a>(config: &'a AgentConfig, name: &str) -> Option<&'a CollectorSettings> {
    config.collectors.get(name).filter(|c| c.enabled)
}

fn describe_mounts(mounts: Option<&Vec<String>>) -> String {
    mounts.map_or("every disk".to_string(), |mounts| mounts.join(", "))
}

fn describe_list(items: Option<&Vec<String>>) -> String {
    items.map_or("nothing".to_string(), |items| items.join(", "))
}

/// Without a list, a status page collector reads its usual page.
fn describe_pages(collector: &str, urls: Option<&Vec<String>>) -> String {
    match (urls, default_status_page(collector)) {
        (Some(urls), _) => urls.join(", "),
        (None, Some(page)) => page.to_string(),
        (None, None) => "nothing".to_string(),
    }
}

fn describe_checks(checks: Option<&Vec<Check>>) -> String {
    let Some(checks) = checks else {
        return "nothing".to_string();
    };
    let names: Vec<&str> = checks.iter().map(|check| check.name.as_str()).collect();
    names.join(", ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn watched_processes_are_part_of_what_changes() {
        let config = |names: Value| -> AgentConfig {
            serde_json::from_value(json!({ "collectors": { "processes": { "names": names } } }))
                .unwrap()
        };
        let resolved = |config: AgentConfig| ResolvedConfig {
            version: String::new(),
            config,
            matched_rules: Vec::new(),
            skipped_collectors: Vec::new(),
        };
        let changes = describe_changes(
            &resolved(config(json!(["nginx"]))),
            &resolved(config(json!(["nginx", "postgres"]))),
        );
        assert_eq!(changes, ["processes watches: nginx → nginx, postgres"]);
    }

    #[test]
    fn watched_paths_and_checks_are_part_of_what_changes() {
        let resolved = |collectors: Value| ResolvedConfig {
            version: String::new(),
            config: serde_json::from_value(json!({ "collectors": collectors })).unwrap(),
            matched_rules: Vec::new(),
            skipped_collectors: Vec::new(),
        };
        let web = json!({ "name": "web", "kind": "tcp", "target": "a:80" });

        let changes = describe_changes(
            &resolved(json!({ "files": { "paths": ["/a"] }, "checks": {} })),
            &resolved(json!({ "files": { "paths": ["/b"] }, "checks": { "checks": [web] } })),
        );
        assert_eq!(
            changes,
            ["checks runs: nothing → web", "files watches: /a → /b"]
        );
    }

    fn saved(
        id: i64,
        name: &str,
        priority: i32,
        condition: Option<&str>,
        settings: Value,
    ) -> ConfigRule {
        ConfigRule {
            id,
            rule: input(name, priority, condition, settings),
        }
    }

    fn input(name: &str, priority: i32, condition: Option<&str>, settings: Value) -> RuleInput {
        RuleInput {
            name: name.to_string(),
            priority,
            condition: condition.map(String::from),
            enabled: true,
            settings,
        }
    }

    fn default_rule() -> ConfigRule {
        saved(
            1,
            "Default",
            0,
            None,
            json!({
                "interval_secs": 15,
                "facts_interval_secs": 3600,
                "collectors": { "cpu": { "enabled": true }, "disk": { "enabled": true } },
            }),
        )
    }

    fn agent(host: &str, role: &str) -> PreviewAgent {
        PreviewAgent {
            id: format!("id-{host}"),
            host: host.to_string(),
            online: true,
            facts: json!({ "custom": { "role": role } }),
        }
    }

    const WEB: Option<&str> = Some(r#"facts.custom.role == "web""#);

    fn only(preview: &Preview) -> &AgentPreview {
        assert_eq!(preview.agents.len(), 1, "{preview:?}");
        &preview.agents[0]
    }

    #[test]
    fn a_new_rule_shows_who_it_matches_and_what_changes() {
        let rule = input("fast", 100, WEB, json!({ "interval_secs": 5 }));
        let agents = [agent("web-1", "web"), agent("db-1", "db")];

        let preview = preview(&[default_rule()], None, &rule, &agents);

        assert_eq!(
            (preview.total, preview.matching, preview.changing),
            (2, 1, 1)
        );
        assert_eq!(preview.agents[0].host, "web-1");
        assert!(preview.agents[0].matches);
        assert_eq!(preview.agents[0].changes, ["Sample interval: 15s → 5s"]);
        assert!(!preview.agents[1].matches);
        assert!(preview.agents[1].changes.is_empty());
    }

    #[test]
    fn a_rule_with_no_condition_matches_everyone() {
        let rule = input("all", 100, None, json!({}));
        let agents = [agent("web-1", "web"), agent("db-1", "db")];

        assert_eq!(preview(&[default_rule()], None, &rule, &agents).matching, 2);
    }

    #[test]
    fn editing_a_rule_replaces_the_saved_version() {
        let rules = [
            default_rule(),
            saved(2, "fast", 100, None, json!({ "facts_interval_secs": 60 })),
        ];
        let edited = input("fast", 100, None, json!({ "interval_secs": 5 }));

        let preview = preview(&rules, Some(2), &edited, &[agent("web-1", "web")]);

        // The saved setting goes away, rather than the two versions adding up.
        assert_eq!(
            only(&preview).changes,
            [
                "Sample interval: 15s → 5s",
                "Fact report interval: 60s → 3600s"
            ]
        );
    }

    #[test]
    fn an_agent_a_narrowed_rule_stops_matching_still_changes() {
        let rules = [
            default_rule(),
            saved(2, "fast", 100, None, json!({ "interval_secs": 5 })),
        ];
        let narrowed = input("fast", 100, WEB, json!({ "interval_secs": 5 }));

        let preview = preview(&rules, Some(2), &narrowed, &[agent("db-1", "db")]);

        assert!(!only(&preview).matches);
        assert_eq!(only(&preview).changes, ["Sample interval: 5s → 15s"]);
        assert_eq!((preview.matching, preview.changing), (0, 1));
    }

    #[test]
    fn a_higher_priority_rule_can_mean_a_match_changes_nothing() {
        let rules = [
            default_rule(),
            saved(2, "pinned", 200, None, json!({ "interval_secs": 60 })),
        ];
        let rule = input("fast", 100, None, json!({ "interval_secs": 5 }));

        let preview = preview(&rules, None, &rule, &[agent("web-1", "web")]);

        assert!(only(&preview).matches);
        assert!(only(&preview).changes.is_empty());
    }

    #[test]
    fn a_new_rule_applies_after_saved_rules_of_the_same_priority() {
        let rules = [
            default_rule(),
            saved(2, "same", 100, None, json!({ "interval_secs": 60 })),
        ];
        let rule = input("fast", 100, None, json!({ "interval_secs": 5 }));

        let preview = preview(&rules, None, &rule, &[agent("web-1", "web")]);

        assert_eq!(only(&preview).changes, ["Sample interval: 60s → 5s"]);
    }

    #[test]
    fn changing_a_priority_moves_the_rule() {
        let rules = [
            default_rule(),
            saved(2, "a", 100, None, json!({ "interval_secs": 5 })),
            saved(3, "b", 200, None, json!({ "interval_secs": 60 })),
        ];
        let moved = input("a", 300, None, json!({ "interval_secs": 5 }));

        let preview = preview(&rules, Some(2), &moved, &[agent("web-1", "web")]);

        assert_eq!(only(&preview).changes, ["Sample interval: 60s → 5s"]);
    }

    #[test]
    fn a_disabled_rule_matches_but_changes_nothing() {
        let mut rule = input("fast", 100, WEB, json!({ "interval_secs": 5 }));
        rule.enabled = false;

        let preview = preview(&[default_rule()], None, &rule, &[agent("web-1", "web")]);

        assert!(!preview.enabled);
        assert!(only(&preview).matches);
        assert!(only(&preview).changes.is_empty());
    }

    #[test]
    fn disabling_a_saved_rule_shows_what_goes_back() {
        let rules = [
            default_rule(),
            saved(2, "fast", 100, None, json!({ "interval_secs": 5 })),
        ];
        let mut rule = rules[1].rule.clone();
        rule.enabled = false;

        let preview = preview(&rules, Some(2), &rule, &[agent("web-1", "web")]);

        assert_eq!(only(&preview).changes, ["Sample interval: 5s → 15s"]);
    }

    #[test]
    fn collector_changes_are_described() {
        let rule = input(
            "r",
            100,
            None,
            json!({ "collectors": {
                "cpu": { "enabled": false },
                "disk": { "mount_points": ["/", "/data"] },
                "memory": { "enabled": true },
            } }),
        );

        let preview = preview(&[default_rule()], None, &rule, &[agent("web-1", "web")]);

        assert_eq!(
            only(&preview).changes,
            [
                "Turns off cpu",
                "disk mount points: every disk → /, /data",
                "Turns on memory",
            ]
        );
    }

    #[test]
    fn a_collector_turned_on_with_mount_points_shows_both() {
        let rules = [saved(1, "Default", 0, None, json!({}))];
        let rule = input(
            "r",
            100,
            None,
            json!({ "collectors": { "disk": { "mount_points": ["/"] } } }),
        );

        let preview = preview(&rules, None, &rule, &[agent("web-1", "web")]);

        assert_eq!(
            only(&preview).changes,
            ["Turns on disk", "disk mount points: every disk → /"]
        );
    }

    #[test]
    fn a_collector_the_agent_can_not_run_is_called_out() {
        let rule = input(
            "r",
            100,
            None,
            json!({ "collectors": { "memory": { "enabled": true } } }),
        );
        let mut limited = agent("web-1", "web");
        limited.facts = json!({ "agent": { "collectors": ["cpu", "disk"] } });

        let preview = preview(&[default_rule()], None, &rule, &[limited]);

        assert_eq!(
            only(&preview).changes,
            ["Can't run memory, so it's left out"]
        );
    }

    #[test]
    fn a_missing_fact_is_explained() {
        let rule = input("r", 100, Some(r#"facts.os.family == "linux""#), json!({}));

        let preview = preview(&[default_rule()], None, &rule, &[agent("web-1", "web")]);

        let note = only(&preview).note.as_deref().unwrap();
        assert!(note.contains("os"), "{note}");
        assert!(!only(&preview).matches);
    }

    #[test]
    fn a_plain_mismatch_needs_no_explanation() {
        let rule = input("r", 100, WEB, json!({}));

        let preview = preview(&[default_rule()], None, &rule, &[agent("db-1", "db")]);

        assert_eq!(only(&preview).note, None);
    }

    #[test]
    fn an_agent_with_no_facts_says_so() {
        let rule = input("r", 100, WEB, json!({}));
        let mut new = agent("new-1", "");
        new.facts = json!({});

        let preview = preview(&[default_rule()], None, &rule, &[new]);

        assert_eq!(
            only(&preview).note.as_deref(),
            Some("Hasn't reported any facts yet")
        );
    }

    #[test]
    fn agents_that_change_come_first_then_matches_then_the_rest() {
        let rules = [
            default_rule(),
            saved(
                2,
                "pinned",
                200,
                Some(r#"facts.custom.role == "pinned""#),
                json!({ "interval_secs": 5 }),
            ),
        ];
        let rule = input(
            "r",
            100,
            Some(r#"facts.custom.role != "db""#),
            json!({ "interval_secs": 5 }),
        );
        let agents = [
            agent("a-db", "db"),
            agent("b-pinned", "pinned"),
            agent("d-web", "web"),
            agent("c-web", "web"),
        ];

        let preview = preview(&rules, None, &rule, &agents);

        let hosts: Vec<&str> = preview.agents.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(hosts, ["c-web", "d-web", "b-pinned", "a-db"]);
    }

    #[test]
    fn counts_cover_agents_that_are_not_shown() {
        let rule = input("r", 100, WEB, json!({ "interval_secs": 5 }));
        let mut agents: Vec<PreviewAgent> = (0..MAX_SHOWN + 5)
            .map(|index| agent(&format!("web-{index:03}"), "web"))
            .collect();
        agents.push(agent("db-1", "db"));

        let preview = preview(&[default_rule()], None, &rule, &agents);

        assert_eq!(preview.total, MAX_SHOWN + 6);
        assert_eq!(preview.matching, MAX_SHOWN + 5);
        assert_eq!(preview.changing, MAX_SHOWN + 5);
        assert_eq!(preview.agents.len(), MAX_SHOWN);
        assert_eq!(preview.hidden, 6);
    }

    #[test]
    fn what_the_preview_promises_is_what_resolve_gives() {
        let rules = [
            default_rule(),
            saved(2, "pinned", 200, None, json!({ "facts_interval_secs": 60 })),
        ];
        let rule = input(
            "r",
            100,
            WEB,
            json!({ "interval_secs": 5, "facts_interval_secs": 30 }),
        );
        let web = agent("web-1", "web");

        let proposed = with_rule(&rules, None, &rule);
        let resolved = rule_engine::resolve(&proposed, &web.facts, &web.id).unwrap();

        assert_eq!(resolved.matched_rules, ["Default", "r", "pinned"]);
        assert_eq!(resolved.config.interval_secs, 5);
        assert_eq!(resolved.config.facts_interval_secs, 60);
    }
}
