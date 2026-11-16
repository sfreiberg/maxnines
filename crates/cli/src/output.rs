//! How what comes back is shown.

use clap::ValueEnum;
use comfy_table::{ContentArrangement, Table, presets};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Columns for people to read.
    Table,
    /// More columns.
    Wide,
    /// The API's own JSON, for scripts.
    Json,
    /// One kind/name a line, for scripts.
    Name,
}

/// Columns lined up under their headings, with no lines between them.
pub fn table(headings: &[&str], rows: &[Vec<String>]) -> String {
    let mut table = Table::new();
    table
        .load_preset(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Disabled)
        .set_header(headings.iter().map(|heading| heading.to_uppercase()));
    for row in rows {
        table.add_row(row);
    }
    for column in table.column_iter_mut() {
        column.set_padding((0, 2));
    }
    let text = table.to_string();
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    lines.join("\n")
}

pub fn json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// How long ago, or how long until, in the largest whole unit, such as `3m` or `2d`.
pub fn span(ms: i64) -> String {
    let secs = ms.max(0) / 1000;
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        3600..86_400 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// Text from a JSON field, or empty.
pub fn text(value: &Value, field: &str) -> String {
    match &value[field] {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Every field of a JSON object as `name value` lines, nested ones with dotted names.
pub fn fields(value: &Value) -> Vec<(String, String)> {
    fn walk(prefix: &str, value: &Value, into: &mut Vec<(String, String)>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    let name = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(&name, value, into);
                }
            }
            Value::String(text) => into.push((prefix.to_string(), text.clone())),
            Value::Null => {}
            other => into.push((prefix.to_string(), other.to_string())),
        }
    }
    let mut into = Vec::new();
    walk("", value, &mut into);
    into
}

/// Names and values in two columns.
pub fn pairs(pairs: &[(String, String)]) -> String {
    let width = pairs
        .iter()
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0);
    pairs
        .iter()
        .map(|(name, value)| format!("{name:width$}  {value}").trim_end().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_table_lines_up_its_columns() {
        let rows = vec![
            vec!["web-1".to_string(), "online".to_string()],
            vec!["orders-db".to_string(), "offline".to_string()],
        ];
        assert_eq!(
            table(&["hostname", "health"], &rows),
            "HOSTNAME   HEALTH\nweb-1      online\norders-db  offline"
        );
    }

    #[test]
    fn spans_use_the_largest_whole_unit() {
        assert_eq!(span(-5), "0s");
        assert_eq!(span(59_000), "59s");
        assert_eq!(span(60_000), "1m");
        assert_eq!(span(7_200_000), "2h");
        assert_eq!(span(200_000_000), "2d");
    }

    #[test]
    fn nested_fields_get_dotted_names() {
        let value = json!({"id": 1, "check": {"name": "Home", "kind": "http"}, "error": null});
        assert_eq!(
            pairs(&fields(&value)),
            "check.kind  http\ncheck.name  Home\nid          1"
        );
    }
}
