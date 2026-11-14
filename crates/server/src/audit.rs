//! The audit log: who changed what and when, who signed in, and where from.
//!
//! A change is recorded in the same transaction as the change itself, so the log
//! can't miss one or claim one that didn't happen. Whoever is acting is set once per
//! request, by the middleware that works out who sent it, and read here by the
//! database code, so no handler has to pass it along. Anything else, like a rule
//! approving an agent, is MaxNines itself.
//!
//! Entries keep the values before and after. Secrets, like passwords, tokens and
//! webhook addresses that work as a password, are only ever recorded as set,
//! changed or removed.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a secret is recorded as, in place of its value.
pub const HIDDEN: &str = "hidden";

/// Words that make a field secret wherever it is.
const SECRET_WORDS: [&str; 5] = ["password", "secret", "token", "credential", "private_key"];

/// Who made a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    Person {
        id: i64,
        email: String,
    },
    /// The server's own commands, by the account that ran them, if it's known.
    CommandLine {
        account: Option<String>,
    },
    /// The server itself, like an agent approved by a registration rule.
    MaxNines,
    /// Someone who isn't signed in, like a failed sign in.
    Nobody,
}

impl Actor {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Person { .. } => "person",
            Self::CommandLine { .. } => "command_line",
            Self::MaxNines => "maxnines",
            Self::Nobody => "nobody",
        }
    }

    pub fn id(&self) -> Option<String> {
        match self {
            Self::Person { id, .. } => Some(id.to_string()),
            _ => None,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Self::Person { email, .. } => email.clone(),
            Self::CommandLine { account } => match account {
                Some(account) => format!("Command line ({account})"),
                None => "Command line".to_string(),
            },
            Self::MaxNines => "MaxNines".to_string(),
            Self::Nobody => String::new(),
        }
    }
}

/// How someone acted, when it wasn't on the pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// One of their API keys, which acts as them.
    ApiKey { id: i64, name: String },
    /// An alert's buttons in Slack, matched to them by email address.
    Slack,
}

impl Via {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "api_key",
            Self::Slack => "slack",
        }
    }

    pub fn id(&self) -> Option<String> {
        match self {
            Self::ApiKey { id, .. } => Some(id.to_string()),
            Self::Slack => None,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Self::ApiKey { name, .. } => name.clone(),
            Self::Slack => "Slack".to_string(),
        }
    }
}

/// Who is acting, how, and the address their request came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acting {
    pub actor: Actor,
    pub via: Option<Via>,
    pub source: Option<IpAddr>,
}

tokio::task_local! {
    static ACTING: Acting;
}

/// Runs `work` with changes it makes recorded as `acting`'s.
pub async fn acting<F: Future>(acting: Acting, work: F) -> F::Output {
    ACTING.scope(acting, work).await
}

/// Runs `work` as `actor`, acting `via` something if they are, keeping the address
/// the request came from.
pub async fn acting_as<F: Future>(actor: Actor, via: Option<Via>, work: F) -> F::Output {
    let source = source();
    acting(Acting { actor, via, source }, work).await
}

/// Who is acting now. A task spawned from a request doesn't carry this, so a change
/// with nobody acting is MaxNines'.
pub fn current() -> Acting {
    ACTING.try_with(Clone::clone).unwrap_or(Acting {
        actor: Actor::MaxNines,
        via: None,
        source: None,
    })
}

/// The address the current request came from, if there is one.
pub fn source() -> Option<IpAddr> {
    current().source
}

/// What was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Created,
    Changed,
    Deleted,
    SignedIn,
    SignInFailed,
    SignedOut,
    /// A new link for setting a password, which is how one is reset.
    NewSetupLink,
    Acknowledged,
    Unacknowledged,
    /// Someone asked a host to run one of its actions.
    Ran,
}

impl Action {
    pub const ALL: [Self; 10] = [
        Self::Created,
        Self::Changed,
        Self::Deleted,
        Self::SignedIn,
        Self::SignInFailed,
        Self::SignedOut,
        Self::NewSetupLink,
        Self::Acknowledged,
        Self::Unacknowledged,
        Self::Ran,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Changed => "changed",
            Self::Deleted => "deleted",
            Self::SignedIn => "signed_in",
            Self::SignInFailed => "sign_in_failed",
            Self::SignedOut => "signed_out",
            Self::NewSetupLink => "new_setup_link",
            Self::Acknowledged => "acknowledged",
            Self::Unacknowledged => "unacknowledged",
            Self::Ran => "ran_action",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Changed => "Changed",
            Self::Deleted => "Deleted",
            Self::SignedIn => "Signed in",
            Self::SignInFailed => "Failed to sign in",
            Self::SignedOut => "Signed out",
            Self::NewSetupLink => "New password link",
            Self::Acknowledged => "Acknowledged",
            Self::Unacknowledged => "Unacknowledged",
            Self::Ran => "Ran an action",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.as_str() == text)
    }
}

/// The kinds of thing a change can be made to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    User,
    ApiKey,
    Host,
    ConfigRule,
    AlertRule,
    Channel,
    Alert,
    Silence,
    MaintenanceWindow,
    RemoteCheck,
    /// An OpenMetrics page the server reads for a host with no agent.
    MetricsPage,
    LocationRule,
    Dashboard,
    /// A deploy or note marked on charts.
    Annotation,
    /// A setting for the whole server.
    Setting,
}

impl Kind {
    pub const ALL: [Self; 15] = [
        Self::User,
        Self::ApiKey,
        Self::Host,
        Self::ConfigRule,
        Self::AlertRule,
        Self::Channel,
        Self::Alert,
        Self::Silence,
        Self::MaintenanceWindow,
        Self::RemoteCheck,
        Self::MetricsPage,
        Self::LocationRule,
        Self::Dashboard,
        Self::Annotation,
        Self::Setting,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ApiKey => "api_key",
            Self::Host => "host",
            Self::ConfigRule => "config_rule",
            Self::AlertRule => "alert_rule",
            Self::Channel => "notification_channel",
            Self::Alert => "alert",
            Self::Silence => "silence",
            Self::MaintenanceWindow => "maintenance_window",
            Self::RemoteCheck => "remote_check",
            Self::MetricsPage => "metrics_page",
            Self::LocationRule => "location_rule",
            Self::Dashboard => "dashboard",
            Self::Annotation => "annotation",
            Self::Setting => "setting",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::ApiKey => "API key",
            Self::Host => "Host",
            Self::ConfigRule => "Config rule",
            Self::AlertRule => "Alert rule",
            Self::Channel => "Notification channel",
            Self::Alert => "Alert",
            Self::Silence => "Silence",
            Self::MaintenanceWindow => "Maintenance window",
            Self::RemoteCheck => "Remote check",
            Self::MetricsPage => "Metrics page",
            Self::LocationRule => "Location rule",
            Self::Dashboard => "Dashboard",
            Self::Annotation => "Annotation",
            Self::Setting => "Setting",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }
}

/// What a change was made to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub kind: Kind,
    pub id: Option<String>,
    /// What it was called at the time, as it may since have been renamed or deleted.
    pub name: String,
}

impl Subject {
    pub fn new(kind: Kind, id: impl ToString, name: impl Into<String>) -> Self {
        Self {
            kind,
            id: Some(id.to_string()),
            name: name.into(),
        }
    }
}

/// One field's value before and after. A secret's values are only [`HIDDEN`] or
/// missing, which says whether it was set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secret: bool,
}

/// What something looked like at one moment, for working out what changed. The
/// values never leave this: only the differences are kept, with secrets masked.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub name: String,
    /// An object. Nested objects are compared field by field, with dotted names.
    pub fields: Value,
    /// Top level fields whose values are secret.
    pub secrets: Vec<&'static str>,
}

impl Snapshot {
    pub fn new(name: impl Into<String>, fields: Value) -> Self {
        Self {
            name: name.into(),
            fields,
            secrets: Vec::new(),
        }
    }

    /// A snapshot of anything that serializes to an object.
    pub fn of(name: impl Into<String>, value: &impl Serialize) -> anyhow::Result<Self> {
        let fields = serde_json::to_value(value)?;
        Ok(Self::new(name, fields))
    }

    pub fn with_secrets(mut self, secrets: &[&'static str]) -> Self {
        self.secrets.extend_from_slice(secrets);
        self
    }

    fn is_secret(&self, field: &str) -> bool {
        // A setting called something like a password is kept secret wherever it is,
        // as it may be one even in a place that isn't known to hold secrets.
        let last = field.rsplit('.').next().unwrap_or(field).to_lowercase();
        if SECRET_WORDS.iter().any(|word| last.contains(word)) {
            return true;
        }
        self.secrets.iter().any(|secret| {
            field == *secret
                || field
                    .strip_prefix(secret)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    }
}

/// Every field with a value, by its dotted name. Lists are compared whole.
fn flatten(prefix: &str, value: &Value, into: &mut BTreeMap<String, Value>) {
    match value {
        Value::Null => {}
        Value::Object(fields) => {
            for (name, value) in fields {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                flatten(&path, value, into);
            }
        }
        other => {
            into.insert(prefix.to_string(), other.clone());
        }
    }
}

/// The fields that differ between two snapshots, either of which may be missing,
/// as it is for something created or deleted.
pub fn changes(before: Option<&Snapshot>, after: Option<&Snapshot>) -> Vec<Change> {
    let mut old = BTreeMap::new();
    let mut new = BTreeMap::new();
    if let Some(before) = before {
        flatten("", &before.fields, &mut old);
    }
    if let Some(after) = after {
        flatten("", &after.fields, &mut new);
    }
    let is_secret = |field: &str| {
        before.is_some_and(|snapshot| snapshot.is_secret(field))
            || after.is_some_and(|snapshot| snapshot.is_secret(field))
    };

    let mut fields: Vec<&String> = old.keys().chain(new.keys()).collect();
    fields.sort();
    fields.dedup();
    fields
        .into_iter()
        .filter(|field| old.get(*field) != new.get(*field))
        .map(|field| {
            let secret = is_secret(field);
            let shown = |value: Option<&Value>| {
                value.map(|value| {
                    if secret {
                        Value::from(HIDDEN)
                    } else {
                        value.clone()
                    }
                })
            };
            Change {
                field: field.clone(),
                before: shown(old.get(field)),
                after: shown(new.get(field)),
                secret,
            }
        })
        .collect()
}

/// A time as a snapshot keeps it: UTC, readable, and in an order that sorts.
pub fn time(ms: i64) -> Value {
    chrono::DateTime::from_timestamp_millis(ms).map_or(Value::from(ms), |time| {
        Value::from(time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    })
}

/// Something to add to the log.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub action: Action,
    pub subject: Subject,
    pub changes: Vec<Change>,
    /// Who did it, when it isn't whoever is acting, like someone signing in.
    pub actor: Option<Actor>,
}

impl Record {
    pub fn new(action: Action, subject: Subject) -> Self {
        Self {
            action,
            subject,
            changes: Vec::new(),
            actor: None,
        }
    }

    pub fn by(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn with_changes(mut self, changes: Vec<Change>) -> Self {
        self.changes = changes;
        self
    }

    /// What a change from `before` to `after` was, if it changed anything: created,
    /// changed or deleted, unless `action` says otherwise.
    pub fn of_change(
        kind: Kind,
        id: impl ToString,
        before: Option<&Snapshot>,
        after: Option<&Snapshot>,
        action: Option<Action>,
    ) -> Option<Self> {
        let changes = changes(before, after);
        let action = action.unwrap_or(match (before, after) {
            (None, _) => Action::Created,
            (Some(_), None) => Action::Deleted,
            (Some(_), Some(_)) => Action::Changed,
        });
        if changes.is_empty() && action == Action::Changed {
            return None;
        }
        let name = after.or(before).map(|snapshot| snapshot.name.clone())?;
        Some(Self::new(action, Subject::new(kind, id, name)).with_changes(changes))
    }
}

/// Who an entry was by, as the log shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryActor {
    pub kind: String,
    pub id: Option<String>,
    pub name: String,
}

/// How they acted, when it wasn't on the pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryVia {
    pub kind: String,
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntrySubject {
    pub kind: String,
    pub id: Option<String>,
    pub name: String,
}

/// An entry in the log, as it's read back.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub id: i64,
    pub time_ms: i64,
    pub actor: EntryActor,
    pub via: Option<EntryVia>,
    /// The address the request came from.
    pub source: Option<String>,
    pub action: String,
    pub subject: EntrySubject,
    pub changes: Vec<Change>,
}

impl Entry {
    /// Who did it, in words.
    pub fn actor_label(&self) -> String {
        match self.actor.kind.as_str() {
            "nobody" => "Someone".to_string(),
            _ => self.actor.name.clone(),
        }
    }

    /// How they acted, in words, when it wasn't on the pages.
    pub fn via_label(&self) -> Option<String> {
        let via = self.via.as_ref()?;
        Some(match via.kind.as_str() {
            "api_key" => format!("via API key {}", via.name),
            "slack" => "via Slack".to_string(),
            _ => format!("via {}", via.name),
        })
    }

    pub fn action_label(&self) -> String {
        Action::parse(&self.action).map_or_else(|| self.action.clone(), |a| a.label().to_string())
    }

    pub fn kind_label(&self) -> String {
        Kind::parse(&self.subject.kind)
            .map_or_else(|| self.subject.kind.clone(), |k| k.label().to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn snapshot(fields: Value) -> Snapshot {
        Snapshot::new("Thing", fields)
    }

    #[test]
    fn only_fields_that_changed_are_kept_with_both_values() {
        let before = snapshot(json!({"name": "Disk", "threshold": 90, "enabled": true}));
        let after = snapshot(json!({"name": "Disk", "threshold": 85, "enabled": true}));

        assert_eq!(
            changes(Some(&before), Some(&after)),
            [Change {
                field: "threshold".into(),
                before: Some(json!(90)),
                after: Some(json!(85)),
                secret: false,
            }]
        );
    }

    #[test]
    fn nested_fields_are_named_with_dots_and_lists_compared_whole() {
        let before = snapshot(json!({"settings": {"interval": 10}, "channels": [1, 2]}));
        let after = snapshot(json!({"settings": {"interval": 30}, "channels": [1]}));

        let fields: Vec<String> = changes(Some(&before), Some(&after))
            .into_iter()
            .map(|change| change.field)
            .collect();
        assert_eq!(fields, ["channels", "settings.interval"]);
    }

    #[test]
    fn something_created_or_deleted_lists_every_field_it_had() {
        let thing = snapshot(json!({"name": "Disk", "filter": null, "for_secs": 60}));

        let created = changes(None, Some(&thing));
        assert_eq!(created.len(), 2, "an empty field isn't a change");
        assert!(
            created
                .iter()
                .all(|c| c.before.is_none() && c.after.is_some())
        );
        let deleted = changes(Some(&thing), None);
        assert!(
            deleted
                .iter()
                .all(|c| c.before.is_some() && c.after.is_none())
        );
    }

    #[test]
    fn a_secret_is_only_recorded_as_set_or_changed() {
        let fields = |token: Option<&str>| json!({"name": "Ops", "credential": token});
        let before = snapshot(fields(Some("first"))).with_secrets(&["credential"]);
        let after = snapshot(fields(Some("second"))).with_secrets(&["credential"]);
        let removed = snapshot(fields(None)).with_secrets(&["credential"]);

        let changed = changes(Some(&before), Some(&after));
        assert_eq!(
            changed,
            [Change {
                field: "credential".into(),
                before: Some(json!(HIDDEN)),
                after: Some(json!(HIDDEN)),
                secret: true,
            }]
        );
        let gone = changes(Some(&after), Some(&removed));
        assert_eq!(gone[0].after, None);
        let text = serde_json::to_string(&changes(None, Some(&before))).unwrap();
        assert!(!text.contains("first"), "{text}");
    }

    #[test]
    fn a_secret_inside_a_nested_field_is_masked_too() {
        let before = snapshot(json!({"auth": {"token": "a"}})).with_secrets(&["auth"]);
        let after = snapshot(json!({"auth": {"token": "b"}})).with_secrets(&["auth"]);

        assert!(changes(Some(&before), Some(&after))[0].secret);
    }

    #[test]
    fn a_field_named_like_a_secret_is_masked_anywhere() {
        let before = snapshot(json!({"settings": {"postgres": {"password": "a", "port": 1}}}));
        let after = snapshot(json!({"settings": {"postgres": {"password": "b", "port": 2}}}));

        let changed = changes(Some(&before), Some(&after));
        assert!(changed[0].secret, "{changed:?}");
        assert!(!changed[1].secret, "{changed:?}");
    }

    #[test]
    fn times_are_kept_readable() {
        assert_eq!(time(0), json!("1970-01-01T00:00:00Z"));
    }

    #[test]
    fn saving_without_changes_records_nothing() {
        let thing = snapshot(json!({"name": "Disk"}));

        let unchanged = Record::of_change(Kind::AlertRule, 1, Some(&thing), Some(&thing), None);
        assert_eq!(unchanged, None);
        let deleted = Record::of_change(Kind::AlertRule, 1, Some(&thing), None, None).unwrap();
        assert_eq!(deleted.action, Action::Deleted);
        assert_eq!(deleted.subject.name, "Thing");
    }

    #[tokio::test]
    async fn changes_are_maxnines_own_unless_someone_is_acting() {
        assert_eq!(current().actor, Actor::MaxNines);
        let someone = Acting {
            actor: Actor::CommandLine { account: None },
            via: None,
            source: Some([10, 0, 0, 1].into()),
        };

        let seen = acting(someone.clone(), async { current() }).await;

        assert_eq!(seen, someone);
    }

    #[test]
    fn names_read_back_as_they_were_written() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
    }
}
