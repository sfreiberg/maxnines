//! Where machines are, for the map. A location rule says which machines are where,
//! with the same filter as the Machines list, and when several match a machine the one
//! with the highest priority decides. A machine put somewhere by hand is a rule whose
//! filter is its ID, so there's one way of saying where things are, not two.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::facts::FlatFacts;
use crate::host_filter::HostFilter;
use crate::models::Database;
use crate::silences::check_filter;

const MAX_NAME_CHARS: usize = 255;
const MAX_PLACE_CHARS: usize = 255;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocationRuleInput {
    /// What the map calls the machines it covers, such as "Leeds office".
    pub name: String,
    /// Which machines, in the same form as the Machines list. Every machine, if empty.
    #[serde(default)]
    pub filter: String,
    /// Where it is in words, such as "Leeds, England, United Kingdom".
    #[serde(default)]
    pub place: String,
    pub latitude: f64,
    pub longitude: f64,
    /// When several rules match a machine, the highest wins.
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LocationRule {
    pub id: i64,
    #[serde(flatten)]
    pub rule: LocationRuleInput,
}

pub fn check_rule(input: &LocationRuleInput) -> Result<()> {
    if input.name.trim().is_empty() {
        bail!("A location needs a name, which is what the map shows.");
    }
    if input.name.chars().count() > MAX_NAME_CHARS {
        bail!("The name is too long. It can be up to {MAX_NAME_CHARS} characters.");
    }
    if input.place.chars().count() > MAX_PLACE_CHARS {
        bail!("The place is too long. It can be up to {MAX_PLACE_CHARS} characters.");
    }
    check_filter(&input.filter)?;
    if !(input.latitude.is_finite() && (-90.0..=90.0).contains(&input.latitude)) {
        bail!("The latitude has to be between -90 and 90.");
    }
    if !(input.longitude.is_finite() && (-180.0..=180.0).contains(&input.longitude)) {
        bail!("The longitude has to be between -180 and 180.");
    }
    Ok(())
}

/// Every rule, ready to say where machines are. Loaded fresh for each page, as rules
/// and facts change.
pub struct Locator {
    /// Highest priority first, and the older of two equal ones first, so a result
    /// never depends on the order the database happens to give.
    rules: Vec<(LocationRule, HostFilter)>,
    facts: BTreeMap<String, FlatFacts>,
}

impl Locator {
    pub async fn load(database: &Database) -> Result<Self> {
        let mut rules: Vec<(LocationRule, HostFilter)> = database
            .list_location_rules()
            .await?
            .into_iter()
            // A rule's filter was checked when it was saved. One that no longer reads,
            // after the filter language changed, places nothing rather than everything.
            .filter_map(|rule| {
                let filter = HostFilter::parse(&rule.rule.filter).ok()?;
                Some((rule, filter))
            })
            .collect();
        rules.sort_by(|(a, _), (b, _)| {
            b.rule
                .priority
                .cmp(&a.rule.priority)
                .then_with(|| a.id.cmp(&b.id))
        });
        let names: Vec<&str> = rules
            .iter()
            .flat_map(|(_, filter)| filter.fact_names())
            .collect();
        let facts = if names.is_empty() {
            BTreeMap::new()
        } else {
            database.facts_named(&names).await?
        };
        Ok(Self { rules, facts })
    }

    /// The rule that says where a machine is, if any does.
    pub fn locate(&self, id: &str, host: &str) -> Option<&LocationRule> {
        self.rules
            .iter()
            .find(|(_, filter)| filter.matches(id, host, self.facts.get(id)))
            .map(|(rule, _)| rule)
    }

    pub fn rules(&self) -> impl Iterator<Item = &LocationRule> {
        self.rules.iter().map(|(rule, _)| rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, filter: &str, priority: i32) -> LocationRuleInput {
        LocationRuleInput {
            name: name.to_string(),
            filter: filter.to_string(),
            place: "Leeds, England, United Kingdom".to_string(),
            latitude: 53.8,
            longitude: -1.55,
            priority,
        }
    }

    #[test]
    fn a_rule_needs_a_name_a_readable_filter_and_a_real_point() {
        check_rule(&input("Leeds office", "networking.addresses=10.1.*", 0)).unwrap();
        check_rule(&input("Everywhere else", "", 0)).unwrap();
        for (bad, says) in [
            (input(" ", "", 0), "needs a name"),
            (input(&"x".repeat(256), "", 0), "too long"),
            (input("Leeds", "\"unfinished", 0), "quote"),
            (
                LocationRuleInput {
                    latitude: 91.0,
                    ..input("Leeds", "", 0)
                },
                "latitude",
            ),
            (
                LocationRuleInput {
                    longitude: -181.0,
                    ..input("Leeds", "", 0)
                },
                "longitude",
            ),
            (
                LocationRuleInput {
                    latitude: f64::NAN,
                    ..input("Leeds", "", 0)
                },
                "latitude",
            ),
        ] {
            let error = check_rule(&bad).unwrap_err().to_string();
            assert!(error.contains(says), "{error}");
        }
    }

    async fn locator(rules: &[LocationRuleInput]) -> (Locator, Database) {
        let database = Database::for_test().await;
        for rule in rules {
            database.create_location_rule(rule).await.unwrap();
        }
        (Locator::load(&database).await.unwrap(), database)
    }

    #[tokio::test]
    async fn the_highest_priority_rule_that_matches_decides() {
        let (locator, _) = locator(&[
            input("Everywhere", "", 0),
            input("Web servers", "hostname=web*", 10),
            input("This one", "id=abc", 100),
        ])
        .await;

        let name =
            |id: &str, host: &str| locator.locate(id, host).map(|rule| rule.rule.name.as_str());
        assert_eq!(name("abc", "web-1"), Some("This one"));
        assert_eq!(name("def", "web-2"), Some("Web servers"));
        assert_eq!(name("ghi", "db-1"), Some("Everywhere"));
    }

    #[tokio::test]
    async fn a_machine_no_rule_matches_has_no_location() {
        let (locator, _) = locator(&[input("Web servers", "hostname=web*", 0)]).await;
        assert!(locator.locate("abc", "db-1").is_none());
    }

    #[tokio::test]
    async fn the_older_of_two_equal_rules_wins() {
        let (locator, _) = locator(&[input("First", "", 5), input("Second", "", 5)]).await;
        assert_eq!(locator.locate("abc", "db-1").unwrap().rule.name, "First");
    }
}
