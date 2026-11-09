//! Turns stored fact rows into what happened and when, for people to read.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::facts::{FlatFacts, unflatten};
use crate::models::FactVersion;

/// Turns stored versions into what happened and when, in order. Comparing whole
/// rebuilt states, not rows, means a list reads as one change even though each
/// of its items is stored separately.
pub fn describe_history(history: &[FactVersion]) -> BTreeMap<u64, Vec<String>> {
    let mut times: Vec<u64> = history
        .iter()
        .flat_map(|version| [Some(version.valid_from_ms), version.valid_to_ms])
        .flatten()
        .collect();
    times.sort_unstable();
    times.dedup();

    let mut events = BTreeMap::new();
    let mut previous: Option<Value> = None;

    for time in times {
        let facts = facts_at(history, time);
        let state = unflatten(&facts);

        let changes = match &previous {
            None => vec![format!("first report, {} facts", facts.len())],
            Some(before) => {
                let mut changes = Vec::new();
                describe_changes("", Some(before), Some(&state), &mut changes);
                changes
            }
        };
        if !changes.is_empty() {
            events.insert(time, changes);
        }
        previous = Some(state);
    }
    events
}

fn facts_at(history: &[FactVersion], time: u64) -> FlatFacts {
    history
        .iter()
        .filter(|f| f.valid_from_ms <= time && f.valid_to_ms.is_none_or(|end| end > time))
        .map(|f| (f.name.clone(), f.value.clone()))
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

    fn version(name: &str, value: Value, from: u64, to: Option<u64>) -> FactVersion {
        FactVersion {
            name: name.to_string(),
            value,
            valid_from_ms: from,
            valid_to_ms: to,
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

        assert_eq!(events[&100], ["first report, 3 facts"]);
        assert_eq!(
            events[&300],
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
            describe_history(&history)[&200],
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

        assert_eq!(events[&200], [r#"custom.role: removed (was "web")"#]);
        assert_eq!(events[&300], [r#"custom.role: added "db""#]);
    }

    #[test]
    fn a_new_group_of_facts_is_described_fact_by_fact() {
        let history = [
            version("os.family", json!("linux"), 100, None),
            version("custom.a", json!(1), 200, None),
            version("custom.b.c", json!(2), 200, None),
        ];

        assert_eq!(
            describe_history(&history)[&200],
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

        assert_eq!(describe_history(&history)[&200], [r#"web.id: 1 -> "1""#]);
    }

    #[test]
    fn a_first_report_is_summarized() {
        let history = [version("a", json!(1), 100, None)];
        assert_eq!(describe_history(&history)[&100], ["first report, 1 facts"]);
    }
}
