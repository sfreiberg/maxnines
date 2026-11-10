//! The audit log page: who changed what, and who signed in, newest first.

use axum::Router;
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Page, local_time, server_error};
use crate::app_state::AppState;
use crate::audit::{Change, Entry};

/// Entries on a page.
pub const PAGE_SIZE: u64 = 100;

pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/audit-log", get(index))
}

#[derive(Deserialize)]
struct Paging {
    /// Only entries older than this one.
    before: Option<i64>,
}

#[derive(Serialize)]
struct Row {
    at: String,
    actor: String,
    /// Like "via API key Deploy job".
    via: Option<String>,
    source: Option<String>,
    action: String,
    kind: String,
    subject: String,
    changes: Vec<ChangeRow>,
}

#[derive(Serialize)]
struct ChangeRow {
    field: String,
    said: String,
}

/// A value as text: strings as they are, anything else as JSON.
fn shown(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A field's dotted name, readable: `settings.disk.interval` as
/// `Settings › disk › interval`.
fn field_label(field: &str) -> String {
    let text = field.replace('_', " ").replace('.', " › ");
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// What happened to a field, in words. Secrets only say whether they were set.
fn said(change: &Change) -> String {
    match (&change.before, &change.after, change.secret) {
        (None, Some(_), true) => "set".to_string(),
        (Some(_), None, true) => "removed".to_string(),
        (_, _, true) => "changed".to_string(),
        (None, Some(after), false) => shown(after),
        (Some(before), None, false) => format!("was {}", shown(before)),
        (Some(before), Some(after), false) => format!("{} → {}", shown(before), shown(after)),
        (None, None, false) => String::new(),
    }
}

fn row(entry: &Entry) -> Row {
    Row {
        at: local_time(entry.at_ms),
        actor: entry.actor_label(),
        via: entry.via_label(),
        source: entry.source.clone(),
        action: entry.action_label(),
        kind: entry.kind_label(),
        subject: entry.subject.name.clone(),
        changes: entry
            .changes
            .iter()
            .map(|change| ChangeRow {
                field: field_label(&change.field),
                said: said(change),
            })
            .collect(),
    }
}

async fn index(
    State(state): State<AppState>,
    token: CsrfToken,
    Query(paging): Query<Paging>,
) -> Response {
    // One more than shown, to know whether there's an older page.
    let mut entries = match state.database.audit_log(paging.before, PAGE_SIZE + 1).await {
        Ok(entries) => entries,
        Err(error) => return server_error(&error),
    };
    let more = entries.len() as u64 > PAGE_SIZE;
    entries.truncate(PAGE_SIZE as usize);
    let older = more
        .then(|| {
            entries
                .last()
                .map(|entry| format!("/settings/audit-log?before={}", entry.id))
        })
        .flatten();
    let rows: Vec<Row> = entries.iter().map(row).collect();
    Page::new(&state, &token, "settings/audit_log.html")
        .with("entries", &rows)
        .with("older", &older)
        .with("paged", &paging.before.is_some())
        .render()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn change(before: Option<Value>, after: Option<Value>, secret: bool) -> Change {
        Change {
            field: "threshold".into(),
            before,
            after,
            secret,
        }
    }

    #[test]
    fn changes_read_as_before_and_after() {
        assert_eq!(
            said(&change(Some(json!(90)), Some(json!(85)), false)),
            "90 → 85"
        );
        assert_eq!(said(&change(None, Some(json!("Disk")), false)), "Disk");
        assert_eq!(said(&change(Some(json!("Disk")), None, false)), "was Disk");
    }

    #[test]
    fn secrets_only_say_whether_they_were_set() {
        let hidden = Some(json!("hidden"));
        assert_eq!(said(&change(None, hidden.clone(), true)), "set");
        assert_eq!(
            said(&change(hidden.clone(), hidden.clone(), true)),
            "changed"
        );
        assert_eq!(said(&change(hidden, None, true)), "removed");
    }

    #[test]
    fn dotted_fields_read_as_a_path() {
        assert_eq!(
            field_label("settings.disk.mount_points"),
            "Settings › disk › mount points"
        );
        assert_eq!(field_label(""), "");
    }
}
