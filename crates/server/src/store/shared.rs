//! What metrics stores have in common: how far agents can be trusted, and how stored
//! values turn back into what a collector reported.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use super::flatten::{DataType, Top};
use crate::metrics::{METRICS, Source};

/// Agents choose these names and how many series they have, so each is limited to
/// stop one agent filling the database or the server's memory.
pub const MAX_NAME_BYTES: usize = 512;
pub const MAX_TEXT_BYTES: usize = 2048;
pub const MAX_SERIES_PER_HOST: usize = 100_000;

pub fn labels_key(labels: &[(String, String)]) -> String {
    let mut key = String::new();
    for (name, value) in labels {
        key.push_str(name);
        key.push('\0');
        key.push_str(value);
        key.push('\0');
    }
    key
}

/// The catalog knows which collectors report a map of things.
pub fn top_of(collector: &str) -> Top {
    let has_entries = METRICS
        .iter()
        .any(|metric| metric.collector == collector && matches!(metric.source, Source::Entries(_)));
    if has_entries {
        Top::Entries
    } else {
        Top::Fields
    }
}

/// Cut at a character boundary, as text can be anything.
pub fn shortened(text: &str) -> &str {
    if text.len() <= MAX_TEXT_BYTES {
        return text;
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A series of a collector, as its ID, field name, data type and label.
pub type StoredSeries = (i64, String, DataType, Option<(String, String)>);

/// One thing a collector reported on, as its label and its fields.
#[derive(Default)]
struct Item {
    label: Option<(String, String)>,
    fields: serde_json::Map<String, Value>,
}

/// Puts a collector's latest values back together, keeping items in the order they
/// were first seen.
pub fn rebuilt_output(
    series: &[StoredSeries],
    numbers: &HashMap<i64, f64>,
    texts: &HashMap<i64, String>,
) -> Option<Value> {
    // An item with no number in the latest sample wasn't in it.
    let current: HashSet<&Option<(String, String)>> = series
        .iter()
        .filter(|(id, ..)| numbers.contains_key(id))
        .map(|(_, _, _, label)| label)
        .collect();

    let mut items: BTreeMap<String, (i64, Item)> = BTreeMap::new();
    let current_series = series.iter().filter(|(.., label)| current.contains(label));
    for (id, field, data_type, label) in current_series {
        let value = match (numbers.get(id), texts.get(id)) {
            (Some(number), _) => stored_number(*number, *data_type),
            (None, Some(text)) => Value::from(text.clone()),
            (None, None) => continue,
        };
        let key = label
            .as_ref()
            .map_or_else(String::new, |(_, value)| value.clone());
        let (first, item) = items.entry(key).or_insert_with(|| {
            let item = Item {
                label: label.clone(),
                ..Item::default()
            };
            (*id, item)
        });
        *first = (*first).min(*id);
        item.fields.insert(field.clone(), value);
    }
    if items.is_empty() {
        return None;
    }

    let mut items: Vec<(i64, Item)> = items.into_values().collect();
    items.sort_by_key(|(first, _)| *first);
    if items.len() == 1 && items[0].1.label.is_none() {
        return items.pop().map(|(_, item)| Value::Object(item.fields));
    }
    let rebuilt = items.into_iter().map(|(_, mut item)| {
        if let Some((name, value)) = item.label {
            item.fields.insert(name, Value::from(value));
        }
        Value::Object(item.fields)
    });
    Some(Value::Array(rebuilt.collect()))
}

/// Whole numbers come back as whole numbers, as agents sent them.
fn stored_number(number: f64, data_type: DataType) -> Value {
    const LARGEST_EXACT: f64 = 9_007_199_254_740_992.0;
    if data_type == DataType::Bool {
        Value::from(number != 0.0)
    } else if number.fract() == 0.0 && number.abs() < LARGEST_EXACT {
        Value::from(number as i64)
    } else {
        Value::from(number)
    }
}
