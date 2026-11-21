//! Turns a collector's output into separate values, whatever its shape, so a new
//! collector needs no schema change. Agents send this, so it can be anything.

use serde_json::Value;

/// What identifies an item in a list, in order of preference.
const ITEM_KEYS: [&str; 4] = ["mount_point", "path", "label", "name"];
/// The label of an entry in a map of objects, like a network interface.
pub const ENTRY_LABEL: &str = "key";
/// The label of an item with nothing to name it.
const INDEX_LABEL: &str = "index";
/// Deep enough for anything real, and it keeps an agent from exhausting the stack.
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Int,
    Float,
    Bool,
    Text,
}

impl DataType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Text => "text",
        }
    }

    pub fn parse(text: &str) -> Self {
        match text {
            "int" => Self::Int,
            "bool" => Self::Bool,
            "text" => Self::Text,
            _ => Self::Float,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reported<'a> {
    Number(f64, DataType),
    Text(&'a str),
}

/// One value, with the metric it belongs to and what it describes.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading<'a> {
    pub metric: String,
    pub labels: Vec<(String, String)>,
    pub value: Reported<'a>,
}

/// Whether an object's keys name things, like network interfaces, can't be told from
/// its shape, so it's for the caller to say. Anything else that repeats is a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Top {
    Fields,
    Entries,
}

pub fn flatten(output: &Value, top: Top) -> Vec<Reading<'_>> {
    let mut readings = Vec::new();
    match (top, output) {
        (Top::Entries, Value::Object(entries)) => {
            for (key, entry) in entries {
                let labels = with_label(&[], ENTRY_LABEL, key);
                walk(entry, "", &labels, 1, &mut readings);
            }
        }
        _ => walk(output, "", &[], 0, &mut readings),
    }
    readings
}

fn joined(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn with_label(labels: &[(String, String)], name: &str, value: &str) -> Vec<(String, String)> {
    let mut labels = labels.to_vec();
    labels.push((name.to_string(), value.to_string()));
    labels
}

fn walk<'a>(
    value: &'a Value,
    path: &str,
    labels: &[(String, String)],
    depth: usize,
    readings: &mut Vec<Reading<'a>>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut push = |value| {
        if !path.is_empty() {
            readings.push(Reading {
                metric: path.to_string(),
                labels: labels.to_vec(),
                value,
            });
        }
    };
    match value {
        Value::Null => {}
        Value::Bool(flag) => push(Reported::Number(f64::from(u8::from(*flag)), DataType::Bool)),
        Value::Number(number) => {
            let kind = if number.is_f64() {
                DataType::Float
            } else {
                DataType::Int
            };
            if let Some(number) = number.as_f64() {
                push(Reported::Number(number, kind));
            }
        }
        Value::String(text) => push(Reported::Text(text)),
        Value::Object(fields) => {
            for (key, field) in fields {
                walk(field, &joined(path, key), labels, depth + 1, readings);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let named = ITEM_KEYS.iter().find_map(|key| {
                    let name = item.get(*key)?.as_str()?;
                    Some((*key, name))
                });
                match (named, item.as_object()) {
                    (Some((key, name)), Some(fields)) => {
                        let labels = with_label(labels, key, name);
                        for (field, value) in fields.iter().filter(|(field, _)| *field != key) {
                            let path = joined(path, field);
                            walk(value, &path, &labels, depth + 1, readings);
                        }
                    }
                    _ => {
                        let labels = with_label(labels, INDEX_LABEL, &index.to_string());
                        walk(item, path, &labels, depth + 1, readings);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn number(metric: &str, value: f64, kind: DataType) -> Reading<'static> {
        Reading {
            metric: metric.to_string(),
            labels: Vec::new(),
            value: Reported::Number(value, kind),
        }
    }

    fn labelled<'a>(reading: Reading<'a>, name: &str, value: &str) -> Reading<'a> {
        Reading {
            labels: vec![(name.to_string(), value.to_string())],
            ..reading
        }
    }

    #[test]
    fn every_type_of_value_keeps_its_type() {
        let output = json!({ "a": 1, "b": 1.5, "c": true, "d": "up", "e": null });

        assert_eq!(
            flatten(&output, Top::Fields),
            [
                number("a", 1.0, DataType::Int),
                number("b", 1.5, DataType::Float),
                number("c", 1.0, DataType::Bool),
                Reading {
                    metric: "d".to_string(),
                    labels: Vec::new(),
                    value: Reported::Text("up"),
                },
            ]
        );
    }

    #[test]
    fn nested_fields_join_their_path() {
        let output = json!({ "cpu": 1, "load_average": { "one": 2.5 } });
        let readings = flatten(&output, Top::Fields);

        assert_eq!(
            readings[1],
            number("load_average.one", 2.5, DataType::Float)
        );
    }

    #[test]
    fn a_list_of_named_things_gives_each_a_label() {
        let output = json!([{ "mount_point": "/", "name": "sda", "used_bytes": 5 }]);
        let readings = flatten(&output, Top::Fields);

        assert_eq!(readings.len(), 2, "{readings:?}");
        assert!(
            readings.iter().all(|reading| {
                reading.labels == [("mount_point".to_string(), "/".to_string())]
            })
        );
        assert_eq!(
            readings[1],
            labelled(number("used_bytes", 5.0, DataType::Int), "mount_point", "/")
        );
    }

    #[test]
    fn a_map_of_things_gives_each_a_label() {
        let output = json!({ "eth0.100": { "received_bytes": 5 } });

        assert_eq!(
            flatten(&output, Top::Entries),
            [labelled(
                number("received_bytes", 5.0, DataType::Int),
                ENTRY_LABEL,
                "eth0.100"
            )]
        );
    }

    #[test]
    fn an_object_of_objects_is_fields_unless_it_is_said_to_be_entries() {
        let output = json!({ "load_average": { "one": 1.5 } });

        assert_eq!(
            flatten(&output, Top::Fields),
            [number("load_average.one", 1.5, DataType::Float)]
        );
    }

    #[test]
    fn a_plain_list_is_numbered() {
        let output = json!({ "per_core_percent": [10.0, 20.0] });

        assert_eq!(
            flatten(&output, Top::Fields)[1],
            labelled(
                number("per_core_percent", 20.0, DataType::Float),
                INDEX_LABEL,
                "1"
            )
        );
    }

    #[test]
    fn output_with_no_field_names_has_nothing_to_report() {
        for output in [
            json!("text"),
            json!(null),
            json!(7),
            json!([1, 2]),
            json!({}),
        ] {
            assert!(flatten(&output, Top::Fields).is_empty(), "{output}");
        }
    }

    #[test]
    fn something_absurdly_deep_stops_rather_than_crashing() {
        let mut output = json!(1);
        for _ in 0..100 {
            output = json!({ "a": output, "b": 1 });
        }
        assert!(flatten(&output, Top::Fields).len() <= MAX_DEPTH + 1);
    }
}
