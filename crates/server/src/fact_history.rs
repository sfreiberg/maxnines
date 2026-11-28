//! Turns stored fact rows into what happened and when, for people to read.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::facts::{FlatFacts, unflatten};
use crate::models::FactVersion;
use crate::times::Timestamp;

/// Turns stored versions into what happened and when, in order. Comparing whole
/// rebuilt states, not rows, means a list reads as one change even though each
/// of its items is stored separately.
///
/// The history is walked once, in time order, keeping the facts at each moment,
/// and only the groups a moment changed are rebuilt and compared, so a host whose
/// facts change often costs no more than its changes.
pub fn describe_history(history: &[FactVersion]) -> BTreeMap<Timestamp, Vec<String>> {
    // What starts and what ends at each moment.
    let mut moments: BTreeMap<Timestamp, (Vec<&FactVersion>, Vec<&FactVersion>)> = BTreeMap::new();
    for version in history {
        moments
            .entry(version.valid_from)
            .or_default()
            .0
            .push(version);
        if let Some(end) = version.valid_to {
            moments.entry(end).or_default().1.push(version);
        }
    }

    let mut events = BTreeMap::new();
    let mut current = FlatFacts::new();
    let mut first = true;
    for (time, (starting, ending)) in moments {
        let touched: BTreeSet<&str> = starting
            .iter()
            .chain(&ending)
            .map(|version| group_of(&version.name))
            .collect();
        let before = within(&current, &touched);
        for version in &ending {
            if current.get(&version.name) == Some(&version.value) {
                current.remove(&version.name);
            }
        }
        for version in &starting {
            current.insert(version.name.clone(), version.value.clone());
        }

        let changes = if std::mem::take(&mut first) {
            vec![format!("first report, {} facts", current.len())]
        } else {
            let (before, after) = (unflatten(&before), unflatten(&within(&current, &touched)));
            let mut changes = Vec::new();
            describe_changes("", Some(&before), Some(&after), &mut changes);
            changes
        };
        if !changes.is_empty() {
            events.insert(time, changes);
        }
    }
    events
}

/// The top-level group a fact is in, such as `custom` for `custom.tags[0]`, which
/// holds every list the fact could be part of.
fn group_of(name: &str) -> &str {
    name.split(['.', '[']).next().unwrap_or(name)
}

/// The facts in these groups.
fn within(facts: &FlatFacts, groups: &BTreeSet<&str>) -> FlatFacts {
    let in_group = |name: &str, group: &str| {
        name.strip_prefix(group)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
    };
    groups
        .iter()
        .flat_map(|group| {
            facts
                .range(group.to_string()..)
                .take_while(move |(name, _)| name.starts_with(group))
                .filter(move |(name, _)| in_group(name, group))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Lists are compared whole, because that's how people think of them. A group
/// that appears or disappears is described fact by fact.
fn describe_changes(
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    changes: &mut Vec<String>,
) {
    let fields = |value: Option<&Value>| value.and_then(Value::as_object).cloned();
    let (old_fields, new_fields) = (fields(before), fields(after));

    if old_fields.is_some() && new_fields.is_some()
        || old_fields.is_some() && after.is_none()
        || new_fields.is_some() && before.is_none()
    {
        let (old, new) = (
            old_fields.unwrap_or_default(),
            new_fields.unwrap_or_default(),
        );
        let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        for name in names {
            let child = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            describe_changes(&child, old.get(name), new.get(name), changes);
        }
        return;
    }

    match (before, after) {
        (Some(old), Some(new)) if old != new => changes.push(format!("{path}: {old} -> {new}")),
        (Some(old), None) => changes.push(format!("{path}: removed (was {old})")),
        (None, Some(new)) => changes.push(format!("{path}: added {new}")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::times::from_ms;

    fn version(name: &str, value: Value, from: i64, to: Option<i64>) -> FactVersion {
        FactVersion {
            name: name.to_string(),
            value,
            valid_from: from_ms(from),
            valid_to: to.map(from_ms),
        }
    }

    #[test]
    fn describes_what_happened_from_the_stored_rows() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("os.version", json!("24.04"), 100, Some(300)),
            version("custom.role", json!("web"), 100, Some(300)),
            version("os.version", json!("24.10"), 300, None),
            version("custom.datacenter", json!("fra1"), 300, None),
        ];

        let events = describe_history(&history);

        assert_eq!(events[&from_ms(100)], ["first report, 3 facts"]);
        assert_eq!(
            events[&from_ms(300)],
            [
                r#"custom.datacenter: added "fra1""#,
                r#"custom.role: removed (was "web")"#,
                r#"os.version: "24.04" -> "24.10""#,
            ]
        );
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn a_list_reads_as_one_change() {
        // ["web", "prod", "eu"] became ["prod", "eu"], touching three rows.
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.tags[0]", json!("web"), 100, Some(200)),
            version("custom.tags[1]", json!("prod"), 100, Some(200)),
            version("custom.tags[2]", json!("eu"), 100, Some(200)),
            version("custom.tags[0]", json!("prod"), 200, None),
            version("custom.tags[1]", json!("eu"), 200, None),
        ];

        assert_eq!(
            describe_history(&history)[&from_ms(200)],
            [r#"custom.tags: ["web","prod","eu"] -> ["prod","eu"]"#]
        );
    }

    #[test]
    fn a_fact_that_returns_after_a_gap_is_shown_as_removed_then_added() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.role", json!("web"), 100, Some(200)),
            version("custom.role", json!("db"), 300, None),
        ];

        let events = describe_history(&history);

        assert_eq!(
            events[&from_ms(200)],
            [r#"custom.role: removed (was "web")"#]
        );
        assert_eq!(events[&from_ms(300)], [r#"custom.role: added "db""#]);
    }

    #[test]
    fn a_new_group_of_facts_is_described_fact_by_fact() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.a", json!(1), 200, None),
            version("custom.b.c", json!(2), 200, None),
        ];

        assert_eq!(
            describe_history(&history)[&from_ms(200)],
            ["custom.a: added 1", "custom.b.c: added 2"]
        );
    }

    #[test]
    fn a_type_change_is_shown_as_a_change() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("web.id", json!(1), 100, Some(200)),
            version("web.id", json!("1"), 200, None),
        ];

        assert_eq!(
            describe_history(&history)[&from_ms(200)],
            [r#"web.id: 1 -> "1""#]
        );
    }

    #[test]
    fn a_first_report_is_summarized() {
        let history = [version("a", json!(1), 100, None)];
        assert_eq!(
            describe_history(&history)[&from_ms(100)],
            ["first report, 1 facts"]
        );
    }
}
