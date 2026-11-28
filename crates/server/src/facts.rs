//! Agents report facts as nested JSON. They're stored as one name and value per
//! row, so a nested fact becomes a name like `os.family`, and a list item a name
//! like `custom.tags[0]`. Anything nested fits, such as `disks[1].mount`. The
//! flat names are only how facts are stored: anything shown to a person is put
//! back together with [`unflatten`].

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value};

/// What the database columns hold.
const MAX_LEN: usize = 255;

/// Fact names and their values, which are always strings, numbers or booleans.
pub type FlatFacts = BTreeMap<String, Value>;

/// A value as it reads to a person.
pub fn fact_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Flattens a report. A fact with no value (null) counts as not being reported,
/// and so does an empty list, which has no items to store.
/// Anything that can't be stored rejects the whole report, because keeping part
/// of it would look like the missing facts had gone away.
pub fn flatten(facts: &Value) -> Result<FlatFacts> {
    ensure!(facts.is_object(), "facts must be an object");
    let mut flat = FlatFacts::new();
    add("", facts, &mut flat)?;
    Ok(flat)
}

fn add(prefix: &str, value: &Value, flat: &mut FlatFacts) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (name, field) in fields {
                ensure!(!name.is_empty(), "a fact has an empty name");
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                add(&path, field, flat)?;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                add(&format!("{prefix}[{index}]"), item, flat)?;
            }
        }
        Value::Null => {}
        scalar => {
            ensure!(prefix.len() <= MAX_LEN, "a fact name is too long");
            ensure!(
                encode(scalar).0.len() <= MAX_LEN,
                "fact {prefix} is too long"
            );
            ensure!(
                flat.insert(prefix.to_string(), scalar.clone()).is_none(),
                "fact {prefix} is reported twice"
            );
        }
    }
    Ok(())
}

/// The text and type stored for a value. Text is stored unquoted, so a query
/// can simply say `value = 'linux'`.
pub fn encode(value: &Value) -> (String, &'static str) {
    match value {
        Value::String(text) => (text.clone(), "string"),
        Value::Bool(flag) => (flag.to_string(), "boolean"),
        other => (other.to_string(), "number"),
    }
}

pub fn decode(text: &str, value_type: &str) -> Result<Value> {
    Ok(match value_type {
        "string" => Value::String(text.to_string()),
        "boolean" | "number" => serde_json::from_str(text).context("not a valid value")?,
        other => bail!("unknown value type {other:?}"),
    })
}

/// Rebuilds nested facts for display, so `tags[0]` and `tags[1]` become a list.
///
/// Flat names can hold things a nested value can't, such as both `one` and
/// `one.thing`. Nothing is dropped: a name that doesn't fit keeps its full text
/// as a key, at the deepest level it does fit.
pub fn unflatten(facts: &FlatFacts) -> Value {
    let mut root = Value::Object(Map::new());
    // A real list has no more items than there are facts, so a larger index
    // can't make a huge list here.
    let max_index = facts.len();

    // Sorted names mean a shorter name always arrives before longer ones.
    for (name, value) in facts {
        let path = parse_name(name);
        if !place(&mut root, &path, value, max_index) {
            root[name] = value.clone();
        }
    }
    root
}

#[derive(Debug, PartialEq)]
enum Segment<'a> {
    Key(&'a str),
    Index(usize),
}

fn parse_name(name: &str) -> Vec<Segment<'_>> {
    let mut path = Vec::new();
    for part in name.split('.') {
        match parse_indexes(part) {
            Some((key, indexes)) => {
                path.push(Segment::Key(key));
                path.extend(indexes.into_iter().map(Segment::Index));
            }
            None => path.push(Segment::Key(part)),
        }
    }
    path
}

/// Splits `tags[1][2]` into `tags` and its indexes. Anything else isn't a list
/// item, and is kept as plain text.
fn parse_indexes(part: &str) -> Option<(&str, Vec<usize>)> {
    let (key, mut rest) = part.split_once('[')?;
    if key.is_empty() {
        return None;
    }

    let mut indexes = Vec::new();
    loop {
        let (index, after) = rest.split_once(']')?;
        indexes.push(index.parse().ok()?);
        match after.strip_prefix('[') {
            Some(next) => rest = next,
            None if after.is_empty() => return Some((key, indexes)),
            None => return None,
        }
    }
}

fn path_text(path: &[Segment]) -> String {
    let mut text = String::new();
    for segment in path {
        match segment {
            Segment::Key(key) if text.is_empty() => text.push_str(key),
            Segment::Key(key) => {
                text.push('.');
                text.push_str(key);
            }
            Segment::Index(index) => text.push_str(&format!("[{index}]")),
        }
    }
    text
}

/// Returns false if the value doesn't fit, leaving the caller to place it.
fn place(node: &mut Value, path: &[Segment], value: &Value, max_index: usize) -> bool {
    let Some((first, rest)) = path.split_first() else {
        if node.is_null() {
            *node = value.clone();
            return true;
        }
        return false;
    };

    match first {
        Segment::Key(key) => {
            if node.is_null() {
                *node = Value::Object(Map::new());
            }
            let Value::Object(fields) = node else {
                return false;
            };

            let child = fields.entry(key.to_string()).or_insert(Value::Null);
            if place(child, rest, value, max_index) {
                return true;
            }
            if child.is_null() {
                fields.remove(*key);
            }
            fields.insert(path_text(path), value.clone());
            true
        }
        Segment::Index(index) => {
            if *index >= max_index {
                return false;
            }
            if node.is_null() {
                *node = Value::Array(Vec::new());
            }
            let Value::Array(items) = node else {
                return false;
            };

            if items.len() <= *index {
                items.resize(index + 1, Value::Null);
            }
            place(&mut items[*index], rest, value, max_index)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn nested_facts_get_dotted_names() {
        let facts = json!({
            "os": { "family": "linux", "release": { "major": 24 } },
            "custom": { "enabled": true },
        });

        let flat = flatten(&facts).unwrap();

        assert_eq!(flat["os.family"], "linux");
        assert_eq!(flat["os.release.major"], 24);
        assert_eq!(flat["custom.enabled"], true);
        assert_eq!(flat.len(), 3);
    }

    #[test]
    fn dots_in_a_name_are_kept_as_written() {
        let flat = flatten(&json!({ "custom": { "one.thing": "x", "one": 1 } })).unwrap();

        assert_eq!(flat["custom.one.thing"], "x");
        assert_eq!(flat["custom.one"], 1);
    }

    #[test]
    fn list_items_get_indexed_names() {
        let flat = flatten(&json!({ "custom": { "tags": ["web", "prod"] } })).unwrap();

        assert_eq!(flat["custom.tags[0]"], "web");
        assert_eq!(flat["custom.tags[1]"], "prod");
        assert_eq!(flat.len(), 2);
    }

    #[test]
    fn anything_nested_in_a_list_gets_a_full_name() {
        let facts = json!({
            "disks": [{ "mount": "/", "ids": [7, 8] }],
            "grid": [[1], [2, 3]],
        });

        let flat = flatten(&facts).unwrap();

        assert_eq!(flat["disks[0].mount"], "/");
        assert_eq!(flat["disks[0].ids[1]"], 8);
        assert_eq!(flat["grid[1][0]"], 2);
        assert_eq!(flat.len(), 6);
    }

    #[test]
    fn one_item_in_a_list_differs_from_a_single_value() {
        let list = flatten(&json!({ "tags": ["web"] })).unwrap();
        let single = flatten(&json!({ "tags": "web" })).unwrap();

        assert!(list.contains_key("tags[0]"));
        assert!(single.contains_key("tags"));
    }

    #[test]
    fn an_empty_list_is_the_same_as_not_reporting() {
        assert!(flatten(&json!({ "tags": [] })).unwrap().is_empty());
    }

    #[test]
    fn facts_without_a_value_are_left_out() {
        let flat = flatten(&json!({ "os": { "version": null, "family": "linux" } })).unwrap();
        assert_eq!(flat.len(), 1);
    }

    #[test]
    fn values_round_trip_with_their_types() {
        for value in [
            json!("linux"),
            json!("24"),
            json!(24),
            json!(1.5),
            json!(true),
        ] {
            let (text, value_type) = encode(&value);
            assert_eq!(decode(&text, value_type).unwrap(), value);
        }
    }

    #[test]
    fn strings_are_stored_without_quotes() {
        assert_eq!(encode(&json!("linux")), ("linux".to_string(), "string"));
    }

    #[test]
    fn a_report_that_can_not_be_stored_is_rejected_whole() {
        let reports = [
            json!([1]),
            json!("text"),
            json!({ "tags": ["ok", "x".repeat(256)] }),
            json!({ "tags[0]": 1, "tags": [2] }),
            json!({ "note": "x".repeat(256) }),
            json!({ "x".repeat(256): 1 }),
            json!({ "": 1 }),
            json!({ "a.b": 1, "a": { "b": 2 } }),
        ];

        for report in reports {
            assert!(flatten(&report).is_err(), "{report}");
        }
    }

    #[test]
    fn the_longest_allowed_value_is_accepted() {
        assert!(flatten(&json!({ "note": "x".repeat(255) })).is_ok());
    }

    #[test]
    fn nested_facts_are_rebuilt_exactly() {
        let facts = json!({
            "os": { "family": "linux", "release": { "major": 24 } },
            "custom": {
                "tags": ["web", "prod"],
                "disks": [{ "mount": "/", "ids": [7, 8] }, { "mount": "/data" }],
                "grid": [[1], [2, 3]],
                "enabled": true,
            },
        });

        assert_eq!(unflatten(&flatten(&facts).unwrap()), facts);
    }

    #[test]
    fn dotted_names_are_shown_nested() {
        let flat = flatten(&json!({ "custom": { "one.thing": "x" } })).unwrap();
        assert_eq!(
            unflatten(&flat),
            json!({ "custom": { "one": { "thing": "x" } } })
        );
    }

    #[test]
    fn list_items_stay_in_numeric_order() {
        let tags: Vec<String> = (0..12).map(|n| format!("t{n}")).collect();
        let facts = json!({ "tags": tags });

        // tags[10] sorts before tags[2] as text.
        assert_eq!(unflatten(&flatten(&facts).unwrap()), facts);
    }

    #[test]
    fn a_name_that_does_not_fit_keeps_its_full_text() {
        let flat = flatten(&json!({ "custom": { "one": 1, "one.thing": 2 } })).unwrap();
        assert_eq!(
            unflatten(&flat),
            json!({ "custom": { "one": 1, "one.thing": 2 } })
        );
    }

    #[test]
    fn a_list_and_a_map_under_one_name_both_survive() {
        let flat = flatten(&json!({ "a.b": 1, "a[0]": 2 })).unwrap();
        assert_eq!(unflatten(&flat), json!({ "a": { "b": 1 }, "a[0]": 2 }));
    }

    #[test]
    fn a_huge_index_does_not_build_a_huge_list() {
        let flat = FlatFacts::from([("tags[999999999]".to_string(), json!("x"))]);
        assert_eq!(unflatten(&flat), json!({ "tags[999999999]": "x" }));
    }

    #[test]
    fn a_missing_item_shows_as_empty() {
        let flat = FlatFacts::from([
            ("tags[0]".to_string(), json!("a")),
            ("tags[2]".to_string(), json!("c")),
            ("other".to_string(), json!(1)),
        ]);
        assert_eq!(
            unflatten(&flat),
            json!({ "tags": ["a", null, "c"], "other": 1 })
        );
    }

    #[test]
    fn text_that_only_looks_like_an_index_is_left_alone() {
        for name in ["a[x]", "a[", "a]", "[0]", "a[0]b", "a[-1]", "a[]"] {
            let flat = FlatFacts::from([(name.to_string(), json!(1))]);
            assert_eq!(unflatten(&flat)[name], 1, "{name}");
        }
    }

    #[test]
    fn a_corrupt_row_is_an_error() {
        assert!(decode("yes", "boolean").is_err());
        assert!(decode("1", "date").is_err());
    }
}
