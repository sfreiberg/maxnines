//! Which hosts each template is for, and what it runs for on each.
//!
//! A template is for the hosts given it by hand, and those its `applies_to`
//! condition picks by their facts. With neither, it's for every host. On a host
//! it's for, what it runs for is found from the host's facts: each database of its
//! kind the agent's config has, the service if the host has it, or the host itself.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError, RwLock};

use serde_json::Value;

use maxnines_protocol::templates::{Target, Template};

use super::values::{QueryValues, worked_out};
use crate::rule_engine::{Condition, Host};

/// A template as it runs, with which hosts it's for.
#[derive(Debug, Clone)]
pub struct Running {
    pub id: i64,
    /// As it runs: what someone chose in place of each part, on or off as they chose.
    pub template: Template,
    /// The hosts given it by hand.
    pub host_ids: BTreeSet<String>,
}

/// Which hosts a template's condition picks.
enum Picks {
    /// It has none, so it's for every host, or only those given it by hand.
    Unsaid,
    /// Those it's true of.
    Matching(Condition),
    /// None, as it doesn't compile, as a config rule's doesn't. Saving one is
    /// refused, so only one saved before that could be.
    Broken,
}

/// A template ready to say which hosts it's for.
pub struct Assigned {
    pub running: Running,
    picks: Picks,
}

impl Assigned {
    pub fn new(running: Running) -> Self {
        let picks = match running.template.applies_to.as_deref() {
            None => Picks::Unsaid,
            Some(text) => Condition::compile(text).map_or(Picks::Broken, Picks::Matching),
        };
        Self { running, picks }
    }

    pub fn id(&self) -> i64 {
        self.running.id
    }

    pub fn template(&self) -> &Template {
        &self.running.template
    }

    /// Whether it says which hosts it's for, rather than being for them all, so
    /// working it out needs hosts' facts or IDs.
    pub fn is_narrowed(&self) -> bool {
        !matches!(self.picks, Picks::Unsaid) || !self.running.host_ids.is_empty()
    }

    /// Whether it needs hosts' facts to say which it's for.
    pub fn uses_facts(&self) -> bool {
        matches!(self.picks, Picks::Matching(_))
    }

    /// Whether it's for this host, whether it's on or not.
    pub fn is_for(&self, host: &Host) -> bool {
        let by_hand = self.running.host_ids.contains(host.id);
        by_hand
            || match &self.picks {
                Picks::Unsaid => self.running.host_ids.is_empty(),
                Picks::Matching(condition) => condition.check(host).unwrap_or(false),
                Picks::Broken => false,
            }
    }

    /// What it runs for on a host it's for, from the host's facts: the names of
    /// the databases of its kind in the agent's config, or nothing for a template
    /// that runs once on the host. Empty when it finds nothing to run for.
    pub fn instances(&self, facts: &Value) -> Vec<Option<String>> {
        instances(self.template(), facts)
    }
}

/// What a template runs for on a host with these facts. See [`Assigned::instances`].
pub fn instances(template: &Template, facts: &Value) -> Vec<Option<String>> {
    match &template.target {
        None => vec![None],
        Some(Target::Database(kind)) => facts["agent"]["databases"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, found)| found.as_str() == Some(kind.as_str()))
            .map(|(name, _)| Some(name.clone()))
            .collect(),
        Some(Target::Service(service)) => {
            let has = facts["services"].as_array().is_some_and(|services| {
                services.iter().any(|found| {
                    found
                        .as_str()
                        .is_some_and(|found| found.eq_ignore_ascii_case(service))
                })
            });
            if has { vec![None] } else { Vec::new() }
        }
        Some(Target::Os(systems)) => {
            let family = facts["os"]["family"].as_str();
            if systems.iter().any(|system| Some(system.as_str()) == family) {
                vec![None]
            } else {
                Vec::new()
            }
        }
    }
}

/// Every template there is, each with which hosts it's for, made again whenever
/// a template changes, or the hosts it's for do.
#[derive(Default)]
pub struct RunningTemplates {
    all: Vec<Assigned>,
    /// The metrics those that are on work out with CEL, compiled.
    worked_out: Vec<QueryValues>,
}

impl RunningTemplates {
    pub fn new(running: impl IntoIterator<Item = Running>) -> Self {
        let all: Vec<Assigned> = running.into_iter().map(Assigned::new).collect();
        let worked_out = all
            .iter()
            .flat_map(|assigned| worked_out(assigned.template()))
            .collect();
        Self { all, worked_out }
    }

    /// The metrics templates that are on work out with CEL as samples arrive.
    pub fn worked_out(&self) -> &[QueryValues] {
        &self.worked_out
    }

    pub fn all(&self) -> &[Assigned] {
        &self.all
    }

    pub fn get(&self, id: i64) -> Option<&Assigned> {
        self.all.iter().find(|assigned| assigned.id() == id)
    }

    /// The templates that are on and for this host.
    pub fn for_host<'a>(&'a self, host: &'a Host<'a>) -> impl Iterator<Item = &'a Assigned> + 'a {
        self.all
            .iter()
            .filter(move |assigned| assigned.template().enabled && assigned.is_for(host))
    }
}

/// The templates as they are now, shared by everything that asks which hosts
/// they're for.
#[derive(Clone, Default)]
pub struct SharedTemplates(Arc<RwLock<Arc<RunningTemplates>>>);

impl SharedTemplates {
    pub fn get(&self) -> Arc<RunningTemplates> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set(&self, templates: RunningTemplates) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(templates);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn template(target: Option<Target>, applies_to: Option<&str>) -> Template {
        let mut template = maxnines_protocol::templates::parse(
            r#"template "app" {
                 name = "App"
               }"#,
        )
        .unwrap();
        template.target = target;
        template.applies_to = applies_to.map(str::to_string);
        template
    }

    fn assigned(applies_to: Option<&str>, by_hand: &[&str]) -> Assigned {
        Assigned::new(Running {
            id: 1,
            template: template(None, applies_to),
            host_ids: by_hand.iter().map(|id| (*id).to_string()).collect(),
        })
    }

    #[test]
    fn a_template_is_for_every_host_until_it_says_which() {
        let web = json!({ "custom": { "role": "web" } });
        let db = json!({ "custom": { "role": "db" } });
        let is_for =
            |assigned: &Assigned, facts: &Value, id: &str| assigned.is_for(&Host::new(facts, id));

        let everywhere = assigned(None, &[]);
        assert!(is_for(&everywhere, &web, "a") && is_for(&everywhere, &db, "b"));
        assert!(!everywhere.is_narrowed());

        // Hosts given it by hand are the only ones, without a condition.
        let by_hand = assigned(None, &["b"]);
        assert!(!is_for(&by_hand, &web, "a") && is_for(&by_hand, &db, "b"));

        // With one, they're on top of those it picks.
        let picked = assigned(Some("facts.custom.role == 'web'"), &["b"]);
        assert!(is_for(&picked, &web, "a") && is_for(&picked, &db, "b"));
        assert!(!is_for(&picked, &db, "c"));

        // One that can't be worked out picks nothing.
        let broken = assigned(Some("facts.custom.role =="), &[]);
        assert!(!is_for(&broken, &web, "a"));
    }

    #[test]
    fn what_a_template_runs_for_comes_from_the_hosts_facts() {
        let facts = json!({
            "os": { "family": "windows" },
            "agent": { "databases": { "orders": "postgres", "cache": "mysql", "stock": "postgres" } },
            "services": ["W3SVC", "Spooler"],
        });
        let for_target = |target| instances(&template(Some(target), None), &facts);

        assert_eq!(
            for_target(Target::Database("postgres".into())),
            [Some("orders".to_string()), Some("stock".to_string())]
        );
        assert!(for_target(Target::Database("mongodb".into())).is_empty());
        assert_eq!(for_target(Target::Service("w3svc".into())), [None]);
        assert!(for_target(Target::Service("MSSQLSERVER".into())).is_empty());
        assert_eq!(for_target(Target::Os(vec!["windows".into()])), [None]);
        assert!(for_target(Target::Os(vec!["linux".into()])).is_empty());
        assert_eq!(instances(&template(None, None), &facts), [None]);
    }
}
