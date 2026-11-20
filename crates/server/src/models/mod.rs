//! Everything the server keeps except metrics, in SQLite, Postgres or MySQL.
//! The URL picks the database, and SeaORM handles the differences between them.
//! Schema changes live in [`crate::migrations`].

mod action_run;
mod actions;
mod alert;
mod alert_rule;
mod alert_rule_action;
mod alert_rule_channel;
mod alerting;
mod api_key;
mod app_sign_in;
mod app_sign_ins;
#[cfg(test)]
mod at_once;
mod audit;
mod audit_entry;
mod built_in_rules;
mod config_rule;
mod config_rule_setting;
mod dashboard;
mod dashboard_variable;
mod dashboard_widget;
mod dashboards;
mod event;
mod events;
mod host;
mod host_boot;
mod host_config_status;
mod host_fact;
mod location_rule;
mod location_rules;
mod maintenance_window;
mod maintenance_windows;
mod metrics_page;
mod metrics_pages;
mod notification;
mod notification_channel;
mod proxies;
mod proxy;
mod recovery_code;
mod remote_check;
mod remote_checks;
mod server_secret;
mod server_setting;
mod sign_in_challenge;
mod silence;
mod silences;
mod stats;
mod two_factor;
mod user;
mod user_session;
mod users;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use maxnines_protocol::auth::new_nonce;
use sea_orm::sea_query::Expr;
use sea_orm::sea_query::OnConflict;
use sea_orm::sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectOptions, ConnectionTrait, DatabaseConnection,
    DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, SqlErr, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, OwnedMutexGuard};

pub use self::app_sign_ins::{AppSignIn, AppTokens, Refreshed};
use self::audit::record_change;
pub use self::built_in_rules::same_rule;
pub use self::events::{MAX_TIMELINE, NewEvent};
pub use self::stats::DatabaseStats;
pub use self::two_factor::CHALLENGE_LIFETIME;
pub use self::users::{
    DEFAULT_THEME, SESSION_LIFETIME, THEMES, User, UserChange, check_new_password, check_new_user,
    is_theme,
};
use crate::alerting::NameTaken;
use crate::audit::{Kind, Snapshot};
use crate::facts::{FlatFacts, decode, encode, flatten, unflatten};
use crate::host_filter;
use crate::migrations::Migrator;
use crate::registration::{HostKind, HostRecord, HostState};
use crate::roles::Role;
use crate::times::Timestamp;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Registry calls run one at a time, so a small pool is plenty.
const MAX_CONNECTIONS: u32 = 5;

/// A value a fact held for a period. `valid_to` is empty while it's current.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FactVersion {
    pub name: String,
    pub value: Value,
    pub valid_from: Timestamp,
    pub valid_to: Option<Timestamp>,
}

/// A rule as stored, with its settings in their natural shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigRule {
    pub id: i64,
    /// Which built-in rule it is, for one that ships with the server, which only
    /// an upgrade changes, though it can be turned off.
    #[serde(default)]
    pub built_in: Option<String>,
    /// When an upgrade last changed a built-in rule.
    #[serde(skip)]
    pub built_in_changed_at: Option<Timestamp>,
    #[serde(flatten)]
    pub rule: RuleInput,
}

/// What can be set on a rule. Validated by [`crate::rule_engine::check_rule`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleInput {
    pub name: String,
    /// Higher priorities apply later, so they win.
    pub priority: i32,
    /// A CEL expression. No condition matches every agent.
    #[serde(default, deserialize_with = "crate::text::optional")]
    pub condition: Option<String>,
    /// The operating systems it's for, by `os.family`, or none for all of them.
    #[serde(default)]
    pub operating_systems: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub settings: Value,
}

fn default_enabled() -> bool {
    true
}

/// What an agent last said about its config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigStatus {
    pub version: String,
    pub error: Option<String>,
    pub reported_at: Timestamp,
}

#[derive(Clone)]
pub struct Database {
    connection: DatabaseConnection,
    /// Two connections using one agent's key mustn't both update its facts at once,
    /// or each would close the same facts and add its own.
    facts_locks: FactLocks,
}

/// A lock for each host whose facts are being saved, kept only while they are.
#[derive(Clone, Default)]
struct FactLocks(Arc<std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>>);

impl FactLocks {
    fn locks(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Mutex<()>>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for anything else saving this host's facts, then holds them until dropped.
    async fn lock(&self, host_id: &str) -> FactLock {
        let host = self.locks().entry(host_id.to_string()).or_default().clone();
        FactLock {
            locks: self.clone(),
            host_id: host_id.to_string(),
            held: Some(host.lock_owned().await),
        }
    }
}

struct FactLock {
    locks: FactLocks,
    host_id: String,
    held: Option<OwnedMutexGuard<()>>,
}

impl Drop for FactLock {
    /// Forgets the host's lock once nobody else holds or waits for it.
    fn drop(&mut self) {
        let mut locks = self.locks.locks();
        self.held.take();
        if locks
            .get(&self.host_id)
            .is_some_and(|lock| Arc::strong_count(lock) == 1)
        {
            locks.remove(&self.host_id);
        }
    }
}

impl Database {
    /// Connects and brings the schema up to date. Errors don't mention the URL,
    /// because it can hold a password.
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_waiting(url, CONNECT_TIMEOUT).await
    }

    /// As [`connect`](Self::connect), waiting up to `limit` for a connection, to
    /// make one and each time one's needed.
    async fn connect_waiting(url: &str, limit: Duration) -> Result<Self> {
        create_sqlite_folder(url)?;

        // SQLite allows one writer, and each connection to an in-memory
        // database gets its own empty database.
        let is_sqlite = url.starts_with("sqlite:");
        let mut options = ConnectOptions::new(url);
        options
            .max_connections(if is_sqlite { 1 } else { MAX_CONNECTIONS })
            .connect_timeout(limit)
            .acquire_timeout(limit)
            .sqlx_logging(false);
        // The default journal waits on the disk several times for every write, which
        // a fleet reporting at once can't get through on a slow disk. In this mode a
        // power cut can lose the last few writes, but can't damage the database.
        if is_sqlite {
            options.map_sqlx_sqlite_opts(|sqlite| {
                sqlite
                    .journal_mode(SqliteJournalMode::Wal)
                    .synchronous(SqliteSynchronous::Normal)
            });
        }

        let connection = sea_orm::Database::connect(options)
            .await
            .context("connecting to the database")?;
        Migrator::up(&connection, None)
            .await
            .context("updating the database schema")?;
        Ok(Self {
            connection,
            facts_locks: FactLocks::default(),
        })
    }

    pub async fn load_hosts(&self) -> Result<Vec<HostRecord>> {
        let rows = host::Entity::find()
            .all(&self.connection)
            .await
            .context("loading hosts")?;
        rows.into_iter().map(to_record).collect()
    }

    /// Creates or replaces an agent's record.
    pub async fn save_host(&self, record: &HostRecord) -> Result<()> {
        let row = host::ActiveModel {
            id: Set(record.id.clone()),
            kind: Set(record.kind.as_str().to_string()),
            public_key: Set(record.public_key.clone()),
            hostname: Set(record.hostname.clone()),
            state: Set(record.state.as_str().to_string()),
            decided_by: Set(record.decided_by.clone()),
            first_seen_at: Set(record.first_seen_at),
            decided_at: Set(record.decided_at),
        };

        let on_conflict = OnConflict::column(host::Column::Id)
            .update_columns([
                host::Column::PublicKey,
                host::Column::Hostname,
                host::Column::State,
                host::Column::DecidedBy,
                host::Column::FirstSeenAt,
                host::Column::DecidedAt,
            ])
            .to_owned();

        let transaction = self.connection.begin().await.context("saving host")?;
        let before = host::Entity::find_by_id(&record.id)
            .one(&transaction)
            .await
            .context("loading host")?;
        host::Entity::insert(row)
            .on_conflict(on_conflict)
            .exec_without_returning(&transaction)
            .await
            .context("saving host")?;
        let before = before.as_ref().map(host_snapshot);
        let after = host_snapshot_of(record);
        record_change(
            &transaction,
            Kind::Host,
            &record.id,
            before.as_ref(),
            Some(&after),
            None,
        )
        .await?;
        transaction.commit().await.context("saving host")?;
        Ok(())
    }

    /// Deletes an agent and everything kept about it: its facts, what it said about
    /// its config and when it started, its checks and metrics pages, its alerts with
    /// their notifications and action runs, which all go with it, and the events
    /// about it alone and a place on the map made for it alone, which only name it in
    /// a filter. All or nothing. Returns false if there was no such agent.
    pub async fn delete_host(&self, id: &str) -> Result<bool> {
        let _saving_facts = self.facts_locks.lock(id).await;
        let transaction = self.connection.begin().await.context("deleting a host")?;
        let before = host::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading host")?;
        events::delete_host_events(&transaction, id).await?;
        location_rule::Entity::delete_many()
            .filter(location_rule::Column::Filter.eq(host_filter::only(id)))
            .exec(&transaction)
            .await
            .context("deleting a host's place on the map")?;
        let deleted = host::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting a host")?;
        let before = before.as_ref().map(host_snapshot);
        record_change(&transaction, Kind::Host, id, before.as_ref(), None, None).await?;
        transaction.commit().await.context("deleting a host")?;
        Ok(deleted.rows_affected > 0)
    }
}

impl Database {
    /// Closes facts that changed or went away, and adds the new values, all in
    /// one transaction. Returns whether anything changed.
    pub async fn record_facts(
        &self,
        host_id: &str,
        facts: &FlatFacts,
        now: Timestamp,
    ) -> Result<bool> {
        let _only_writer = self.facts_locks.lock(host_id).await;
        let transaction = self.connection.begin().await.context("saving facts")?;

        let current = host_fact::Entity::find()
            .filter(host_fact::Column::HostId.eq(host_id))
            .filter(host_fact::Column::ValidTo.is_null())
            .all(&transaction)
            .await
            .context("loading facts")?;

        let mut unchanged = BTreeSet::new();
        let mut closed = Vec::new();
        for row in current {
            let same = facts.get(&row.name).is_some_and(|value| {
                let (text, value_type) = encode(value);
                text == row.value && value_type == row.value_type
            });
            if same {
                unchanged.insert(row.name);
            } else {
                closed.push(row.id);
            }
        }

        let added: Vec<host_fact::ActiveModel> = facts
            .iter()
            .filter(|(name, _)| !unchanged.contains(*name))
            .map(|(name, value)| {
                let (text, value_type) = encode(value);
                host_fact::ActiveModel {
                    host_id: Set(host_id.to_string()),
                    name: Set(name.clone()),
                    value: Set(text),
                    value_type: Set(value_type.to_string()),
                    valid_from: Set(now),
                    valid_to: Set(None),
                    ..Default::default()
                }
            })
            .collect();

        let changed = !closed.is_empty() || !added.is_empty();

        if !closed.is_empty() {
            host_fact::Entity::update_many()
                .col_expr(host_fact::Column::ValidTo, Expr::value(now))
                .filter(host_fact::Column::Id.is_in(closed))
                .exec(&transaction)
                .await
                .context("closing old facts")?;
        }
        if !added.is_empty() {
            host_fact::Entity::insert_many(added)
                .exec_without_returning(&transaction)
                .await
                .context("saving facts")?;
        }

        transaction.commit().await.context("saving facts")?;
        Ok(changed)
    }

    pub async fn current_facts(&self, host_id: &str) -> Result<Vec<FactVersion>> {
        let rows = host_fact::Entity::find()
            .filter(host_fact::Column::HostId.eq(host_id))
            .filter(host_fact::Column::ValidTo.is_null())
            .order_by_asc(host_fact::Column::Name)
            .all(&self.connection)
            .await
            .context("loading facts")?;
        rows.into_iter().map(to_fact_version).collect()
    }

    /// Every agent's current facts, in one query so that looking across all
    /// agents doesn't cost a query each.
    pub async fn all_current_facts(&self) -> Result<BTreeMap<String, FlatFacts>> {
        let rows = host_fact::Entity::find()
            .filter(host_fact::Column::ValidTo.is_null())
            .all(&self.connection)
            .await
            .context("loading facts")?;
        by_host(rows)
    }

    /// The current facts of some agents, for when a page only shows those.
    pub async fn facts_of(&self, host_ids: &[&str]) -> Result<BTreeMap<String, FlatFacts>> {
        let rows = host_fact::Entity::find()
            .filter(host_fact::Column::ValidTo.is_null())
            .filter(host_fact::Column::HostId.is_in(host_ids.iter().copied()))
            .all(&self.connection)
            .await
            .context("loading facts")?;
        by_host(rows)
    }

    /// Every agent's current values of some facts, including the items of lists.
    pub async fn facts_named(&self, names: &[&str]) -> Result<BTreeMap<String, FlatFacts>> {
        let rows = host_fact::Entity::find()
            .filter(host_fact::Column::ValidTo.is_null())
            .filter(fact_or_its_items(names))
            .all(&self.connection)
            .await
            .context("loading facts")?;
        let rows = rows
            .into_iter()
            .filter(|row| names.iter().any(|name| is_fact_or_item(&row.name, name)))
            .collect();
        by_host(rows)
    }

    /// The names facts are reported under, with a list appearing under its own name.
    pub async fn fact_names(&self) -> Result<Vec<String>> {
        let names: Vec<String> = host_fact::Entity::find()
            .select_only()
            .column(host_fact::Column::Name)
            .distinct()
            .filter(host_fact::Column::ValidTo.is_null())
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading fact names")?;
        let names: BTreeSet<String> = names.into_iter().filter_map(simple_fact_name).collect();
        Ok(names.into_iter().collect())
    }

    /// Different values a fact has containing some text, ignoring case, in order.
    /// They're matched and sorted here rather than by the database, as each compares
    /// and sorts text its own way.
    pub async fn fact_values(&self, name: &str, text: &str, limit: usize) -> Result<Vec<String>> {
        let rows: Vec<(String, String)> = host_fact::Entity::find()
            .select_only()
            .column(host_fact::Column::Name)
            .column(host_fact::Column::Value)
            .distinct()
            .filter(host_fact::Column::ValidTo.is_null())
            .filter(fact_or_its_items(&[name]))
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading fact values")?;
        let wanted = text.to_lowercase();
        let values: BTreeSet<String> = rows
            .into_iter()
            .filter(|(fact, value)| {
                is_fact_or_item(fact, name) && value.to_lowercase().contains(&wanted)
            })
            .map(|(_, value)| value)
            .collect();
        Ok(values.into_iter().take(limit).collect())
    }

    /// Every fact name in use and how its values are written, for offering in
    /// forms. A list appears once under its own name, as a list item's type.
    pub async fn known_facts(&self) -> Result<BTreeMap<String, String>> {
        let rows: Vec<(String, String)> = host_fact::Entity::find()
            .select_only()
            .column(host_fact::Column::Name)
            .column(host_fact::Column::ValueType)
            .distinct()
            .filter(host_fact::Column::ValidTo.is_null())
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading fact names")?;

        let mut known = BTreeMap::new();
        for (name, value_type) in rows {
            if let Some(name) = simple_fact_name(name) {
                known.insert(name, value_type);
            }
        }
        Ok(known)
    }

    /// The names any agent lists under one of its facts, such as the checks its
    /// own config allows, each once and in order.
    pub async fn listed_by_agents(&self, list: &str) -> Result<Vec<String>> {
        let items = format!("{list}[");
        let rows: Vec<(String, String)> = host_fact::Entity::find()
            .select_only()
            .column(host_fact::Column::Name)
            .column(host_fact::Column::Value)
            .distinct()
            .filter(host_fact::Column::ValidTo.is_null())
            .filter(starting_with(host_fact::Column::Name, &items))
            .into_tuple()
            .all(&self.connection)
            .await
            .context("loading what agents list")?;
        let names: BTreeSet<String> = rows
            .into_iter()
            .filter(|(name, _)| name.starts_with(&items))
            .map(|(_, value)| value)
            .collect();
        Ok(names.into_iter().collect())
    }

    /// Every value each fact has had, oldest first. Rows are ordered by ID, not
    /// time, because two reports can share a timestamp and clocks can go back.
    pub async fn facts_history(&self, host_id: &str) -> Result<Vec<FactVersion>> {
        let rows = host_fact::Entity::find()
            .filter(host_fact::Column::HostId.eq(host_id))
            .order_by_asc(host_fact::Column::Id)
            .all(&self.connection)
            .await
            .context("loading facts history")?;
        rows.into_iter().map(to_fact_version).collect()
    }
}

/// What the database column holds.
const MAX_API_KEY_NAME_LEN: usize = 100;
/// How much of a key is kept to tell it apart, which is `mxn_` and 8 of its 64 digits.
const API_KEY_HINT_LEN: usize = 12;
/// How current "last used" stays, so using a key or a signed-in app doesn't write on
/// every request.
const USE_ACCURACY: chrono::TimeDelta = chrono::TimeDelta::minutes(1);

/// Where a session, key or app was last used from: the address that connected, and
/// what an untrusted proxy there said it was passing on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct UsedFrom {
    address: Option<String>,
    forwarded_for: Option<String>,
}

impl UsedFrom {
    /// Where the current request came from.
    fn now() -> Self {
        Self {
            address: crate::audit::source().map(|address| address.to_string()),
            forwarded_for: crate::audit::forwarded_for().map(|address| address.to_string()),
        }
    }
}

/// What to note about a session, key or app being used now, if anything: when, and
/// where from. Nothing while it was noted under a minute ago from the same place, or
/// for a use with no request behind it.
fn noted_use(
    last_used_at: Option<Timestamp>,
    last: &UsedFrom,
    now: Timestamp,
) -> Option<(Timestamp, UsedFrom)> {
    let here = UsedFrom::now();
    let stale = last_used_at.is_none_or(|used| now - used >= USE_ACCURACY);
    let moved = here.address.is_some() && here != *last;
    let from = if here.address.is_some() {
        here
    } else {
        last.clone()
    };
    (stale || moved).then_some((now, from))
}

/// A key for the API, without the key itself, which only exists when it's created.
/// It acts as the person who owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub user_id: i64,
    /// The owner's email address.
    pub owner: String,
    /// The most it can do. It never does more than its owner can either.
    pub role: Role,
    pub hint: String,
    pub created_at: Timestamp,
    /// Empty means it never expires.
    pub expires_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    /// The address it was last used from.
    pub last_address: Option<String>,
    /// What an untrusted proxy there said it was passing on, so unconfirmed.
    pub last_forwarded_for: Option<String>,
    pub revoked_at: Option<Timestamp>,
}

impl ApiKey {
    pub fn has_expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|expires| now >= expires)
    }
}

impl ApiKey {
    fn from_row(row: api_key::Model, owner: String) -> Self {
        Self {
            id: row.id,
            name: row.name,
            user_id: row.user_id,
            owner,
            role: Role::parse(&row.role).unwrap_or(Role::Viewer),
            hint: row.hint,
            created_at: row.created_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            last_address: row.last_address,
            last_forwarded_for: row.last_forwarded_for,
            revoked_at: row.revoked_at,
        }
    }
}

pub fn check_api_key_name(name: &str) -> Result<()> {
    anyhow::ensure!(!name.trim().is_empty(), "A key needs a name.");
    anyhow::ensure!(
        name.len() <= MAX_API_KEY_NAME_LEN,
        "A key's name can be up to {MAX_API_KEY_NAME_LEN} characters."
    );
    Ok(())
}

/// When a key lasting this long from now runs out. Every database keeps times up to
/// the end of the year 9999, so one that would last longer than that is refused.
pub fn expiry_after(lasting: Duration, now: Timestamp) -> Result<Timestamp> {
    anyhow::ensure!(!lasting.is_zero(), "A key has to last longer than that.");
    chrono::TimeDelta::from_std(lasting)
        .ok()
        .and_then(|lasting| now.checked_add_signed(lasting))
        .filter(|expires| chrono::Datelike::year(expires) <= 9999)
        .context("That's too long for a key to last. Leave it out for a key that never expires.")
}

/// These users' email addresses, by their ID, to name keys' and apps' owners.
async fn owner_emails(
    connection: &impl ConnectionTrait,
    user_ids: impl IntoIterator<Item = i64>,
) -> Result<BTreeMap<i64, String>> {
    let wanted: BTreeSet<i64> = user_ids.into_iter().collect();
    if wanted.is_empty() {
        return Ok(BTreeMap::new());
    }
    let emails: Vec<(i64, String)> = user::Entity::find()
        .select_only()
        .column(user::Column::Id)
        .column(user::Column::Email)
        .filter(user::Column::Id.is_in(wanted))
        .into_tuple()
        .all(connection)
        .await
        .context("loading users")?;
    Ok(emails.into_iter().collect())
}

/// A key as the audit log compares them. The key itself is never kept.
fn api_key_snapshot(row: &api_key::Model, owner: &str) -> Snapshot {
    let fields = serde_json::json!({
        "name": row.name,
        "owner": owner,
        "role": row.role,
        "hint": row.hint,
        "expires": row.expires_at.map(crate::audit::time),
        "revoked": row.revoked_at.is_some(),
    });
    Snapshot::new(row.name.clone(), fields)
}

use crate::registration::hex_hash as api_key_hash;

impl Database {
    /// Makes a key that acts as `user_id` with at most `role`, and gives back the
    /// only copy of it there'll ever be. The owner has to be someone who can sign in,
    /// and can't make a key that does more than they can.
    pub async fn create_api_key(
        &self,
        name: &str,
        user_id: i64,
        role: Role,
        expires_at: Option<Timestamp>,
        now: Timestamp,
    ) -> Result<(ApiKey, String)> {
        let key = format!("mxn_{}", new_nonce()?);
        let transaction = self.connection.begin().await.context("saving an API key")?;
        let owner = user::Entity::find_by_id(user_id)
            .filter(user::Column::DisabledAt.is_null())
            .one(&transaction)
            .await
            .context("loading the key's owner")?
            .context("a key's owner has to be a user who isn't disabled")?;
        let most = Role::parse(&owner.role).unwrap_or(Role::Viewer);
        anyhow::ensure!(role <= most, "a key can't do more than its owner");
        let row = api_key::ActiveModel {
            name: Set(name.to_string()),
            user_id: Set(user_id),
            role: Set(role.as_str().to_string()),
            hint: Set(key[..API_KEY_HINT_LEN].to_string()),
            token_hash: Set(api_key_hash(&key)),
            created_at: Set(now),
            expires_at: Set(expires_at),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .context("saving an API key")?;
        let after = api_key_snapshot(&row, &owner.email);
        record_change(&transaction, Kind::ApiKey, row.id, None, Some(&after), None).await?;
        transaction.commit().await.context("saving an API key")?;
        Ok((ApiKey::from_row(row, owner.email), key))
    }

    /// Every key, newest first, including revoked ones.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        let rows = api_key::Entity::find()
            .order_by_desc(api_key::Column::Id)
            .all(&self.connection)
            .await
            .context("loading API keys")?;
        let owners = owner_emails(&self.connection, rows.iter().map(|row| row.user_id)).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let owner = owners.get(&row.user_id).cloned().unwrap_or_default();
                ApiKey::from_row(row, owner)
            })
            .collect())
    }

    /// Stops a key working. Returns false if there's no such key. Revoking it again
    /// keeps the first time: it's locked first, so a second revoke at once waits, and
    /// then finds it revoked.
    pub async fn revoke_api_key(&self, id: i64, now: Timestamp) -> Result<bool> {
        let transaction = self
            .connection
            .begin()
            .await
            .context("revoking an API key")?;
        let Some(row) = api_key::Entity::find_by_id(id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .context("loading an API key")?
        else {
            return Ok(false);
        };
        if row.revoked_at.is_none() {
            let owner = owner_emails(&transaction, [row.user_id])
                .await?
                .remove(&row.user_id)
                .unwrap_or_default();
            let before = api_key_snapshot(&row, &owner);
            let mut row: api_key::ActiveModel = row.into();
            row.revoked_at = Set(Some(now));
            let row = row
                .update(&transaction)
                .await
                .context("revoking an API key")?;
            let after = api_key_snapshot(&row, &owner);
            record_change(
                &transaction,
                Kind::ApiKey,
                id,
                Some(&before),
                Some(&after),
                None,
            )
            .await?;
        }
        transaction.commit().await.context("revoking an API key")?;
        Ok(true)
    }

    /// The key and who it acts as, if it still works, noting that it's been used. A
    /// key stops working while its owner is disabled.
    pub async fn accept_api_key(
        &self,
        key: &str,
        now: Timestamp,
    ) -> Result<Option<(ApiKey, User)>> {
        let row = api_key::Entity::find()
            .filter(api_key::Column::TokenHash.eq(api_key_hash(key)))
            .filter(api_key::Column::RevokedAt.is_null())
            .one(&self.connection)
            .await
            .context("checking an API key")?;
        let Some(row) = row.filter(|row| row.expires_at.is_none_or(|expires| now < expires)) else {
            return Ok(None);
        };
        let Some(mut owner) = users::enabled_user(&self.connection, row.user_id).await? else {
            return Ok(None);
        };
        // The key acts as its owner, with whichever of their roles is less.
        let key_role = Role::parse(&row.role).unwrap_or(Role::Viewer);
        owner.role = owner.role.min(key_role);
        let last = UsedFrom {
            address: row.last_address.clone(),
            forwarded_for: row.last_forwarded_for.clone(),
        };
        let row = if let Some((used, from)) = noted_use(row.last_used_at, &last, now) {
            let mut row: api_key::ActiveModel = row.into();
            row.last_used_at = Set(Some(used));
            row.last_address = Set(from.address);
            row.last_forwarded_for = Set(from.forwarded_for);
            row.update(&self.connection)
                .await
                .context("noting an API key's use")?
        } else {
            row
        };
        Ok(Some((ApiKey::from_row(row, owner.email.clone()), owner)))
    }

    /// A secret the server made for itself, created the first time it's asked for.
    /// Two asking for it at once get the same one, as only the first insert counts
    /// and both read what was saved.
    pub async fn server_secret(&self, name: &str) -> Result<String> {
        let saved = server_secret::Entity::find_by_id(name)
            .one(&self.connection)
            .await
            .with_context(|| format!("reading the {name}"))?;
        if let Some(saved) = saved {
            return Ok(saved.value);
        }

        let row = server_secret::ActiveModel {
            name: Set(name.to_string()),
            value: Set(new_nonce()?),
        };
        server_secret::Entity::insert(row)
            .on_conflict_do_nothing_on([server_secret::Column::Name])
            .exec_without_returning(&self.connection)
            .await
            .with_context(|| format!("saving the {name}"))?;

        let saved = server_secret::Entity::find_by_id(name)
            .one(&self.connection)
            .await
            .with_context(|| format!("reading the {name}"))?;
        Ok(saved
            .with_context(|| format!("the {name} wasn't saved"))?
            .value)
    }
}

impl Database {
    /// Lowest priority first, which is the order they're applied in.
    pub async fn list_rules(&self) -> Result<Vec<ConfigRule>> {
        let rows = config_rule::Entity::find()
            .order_by_asc(config_rule::Column::Priority)
            .order_by_asc(config_rule::Column::Id)
            .all(&self.connection)
            .await
            .context("loading rules")?;

        let settings = config_rule_setting::Entity::find()
            .all(&self.connection)
            .await
            .context("loading rule settings")?;

        let mut rules = rows
            .into_iter()
            .map(|row| {
                let mine = settings.iter().filter(|setting| setting.rule_id == row.id);
                to_rule(row.clone(), mine)
            })
            .collect::<Result<Vec<_>>>()?;
        // Built-in rules apply before people's own of the same priority, so theirs win.
        rules.sort_by_key(|rule| (rule.rule.priority, rule.built_in.is_none(), rule.id));
        Ok(rules)
    }

    /// Turns a rule on or off, and nothing else, which is all a built-in rule allows.
    /// Returns false if there's no such rule.
    pub async fn set_rule_enabled(&self, id: i64, enabled: bool) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving rule")?;
        let before = load_rule(&transaction, id).await?;
        let Some(before) = before else {
            return Ok(false);
        };
        config_rule::Entity::update_many()
            .col_expr(config_rule::Column::Enabled, Expr::value(enabled))
            .filter(config_rule::Column::Id.eq(id))
            .exec(&transaction)
            .await
            .context("saving rule")?;
        record_rule(&transaction, id, Some(&before)).await?;
        transaction.commit().await.context("saving rule")?;
        Ok(true)
    }

    pub async fn get_rule(&self, id: i64) -> Result<Option<ConfigRule>> {
        load_rule(&self.connection, id).await
    }

    pub async fn create_rule(&self, input: &RuleInput) -> Result<i64> {
        let transaction = self.connection.begin().await.context("saving rule")?;
        let row = config_rule::ActiveModel {
            name: Set(input.name.clone()),
            name_key: Set(name_key(&input.name)),
            priority: Set(input.priority),
            condition_expr: Set(input.condition.clone()),
            enabled: Set(input.enabled),
            operating_systems: Set(systems_text(&input.operating_systems)),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(|error| {
            let taken = NameTaken::ConfigRule(input.name.clone());
            name_taken_or(error, taken, "saving rule")
        })?;

        save_settings(&transaction, row.id, &input.settings).await?;
        record_rule(&transaction, row.id, None).await?;
        transaction.commit().await.context("saving rule")?;
        Ok(row.id)
    }

    /// Returns false if there's no such rule.
    pub async fn update_rule(&self, id: i64, input: &RuleInput) -> Result<bool> {
        let transaction = self.connection.begin().await.context("saving rule")?;
        let before = load_rule(&transaction, id).await?;
        let found = config_rule::Entity::find_by_id(id)
            .one(&transaction)
            .await
            .context("loading rule")?;
        let Some(row) = found else {
            return Ok(false);
        };

        let mut row: config_rule::ActiveModel = row.into();
        row.name = Set(input.name.clone());
        row.name_key = Set(name_key(&input.name));
        row.priority = Set(input.priority);
        row.condition_expr = Set(input.condition.clone());
        row.enabled = Set(input.enabled);
        row.operating_systems = Set(systems_text(&input.operating_systems));
        row.update(&transaction).await.map_err(|error| {
            let taken = NameTaken::ConfigRule(input.name.clone());
            name_taken_or(error, taken, "saving rule")
        })?;

        config_rule_setting::Entity::delete_many()
            .filter(config_rule_setting::Column::RuleId.eq(id))
            .exec(&transaction)
            .await
            .context("replacing rule settings")?;
        save_settings(&transaction, id, &input.settings).await?;
        record_rule(&transaction, id, before.as_ref()).await?;

        transaction.commit().await.context("saving rule")?;
        Ok(true)
    }

    /// Returns false if there's no such rule.
    pub async fn delete_rule(&self, id: i64) -> Result<bool> {
        let transaction = self.connection.begin().await.context("deleting rule")?;
        // Its settings go with it.
        let before = load_rule(&transaction, id).await?;
        let deleted = config_rule::Entity::delete_by_id(id)
            .exec(&transaction)
            .await
            .context("deleting rule")?;
        record_rule(&transaction, id, before.as_ref()).await?;
        transaction.commit().await.context("deleting rule")?;
        Ok(deleted.rows_affected > 0)
    }

    pub async fn save_config_status(&self, host_id: &str, status: &ConfigStatus) -> Result<()> {
        let row = host_config_status::ActiveModel {
            host_id: Set(host_id.to_string()),
            version: Set(status.version.clone()),
            error: Set(status.error.clone()),
            reported_at: Set(status.reported_at),
        };
        let on_conflict = OnConflict::column(host_config_status::Column::HostId)
            .update_columns([
                host_config_status::Column::Version,
                host_config_status::Column::Error,
                host_config_status::Column::ReportedAt,
            ])
            .to_owned();

        host_config_status::Entity::insert(row)
            .on_conflict(on_conflict)
            .exec_without_returning(&self.connection)
            .await
            .context("saving config status")?;
        Ok(())
    }

    /// What some agents last said about their config, in one query, by their IDs.
    pub async fn config_statuses(
        &self,
        host_ids: &[&str],
    ) -> Result<BTreeMap<String, ConfigStatus>> {
        let rows = host_config_status::Entity::find()
            .filter(host_config_status::Column::HostId.is_in(host_ids.iter().copied()))
            .all(&self.connection)
            .await
            .context("loading config statuses")?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let status = ConfigStatus {
                    version: row.version,
                    error: row.error,
                    reported_at: row.reported_at,
                };
                (row.host_id, status)
            })
            .collect())
    }

    pub async fn config_status(&self, host_id: &str) -> Result<Option<ConfigStatus>> {
        let row = host_config_status::Entity::find_by_id(host_id)
            .one(&self.connection)
            .await
            .context("loading config status")?;
        Ok(row.map(|row| ConfigStatus {
            version: row.version,
            error: row.error,
            reported_at: row.reported_at,
        }))
    }
}

async fn load_rule(connection: &impl ConnectionTrait, id: i64) -> Result<Option<ConfigRule>> {
    let row = config_rule::Entity::find_by_id(id)
        .one(connection)
        .await
        .context("loading rule")?;
    let Some(row) = row else {
        return Ok(None);
    };
    let settings = config_rule_setting::Entity::find()
        .filter(config_rule_setting::Column::RuleId.eq(id))
        .all(connection)
        .await
        .context("loading rule settings")?;
    to_rule(row, settings.iter()).map(Some)
}

fn rule_snapshot(rule: &ConfigRule) -> Result<Snapshot> {
    let fields = serde_json::to_value(&rule.rule).context("recording a rule")?;
    Ok(Snapshot::new(rule.rule.name.clone(), fields))
}

/// Records how a config rule changed from `before`, reading it as it is now.
async fn record_rule(
    connection: &impl ConnectionTrait,
    id: i64,
    before: Option<&ConfigRule>,
) -> Result<()> {
    let after = load_rule(connection, id).await?;
    let before = before.map(rule_snapshot).transpose()?;
    let after = after.as_ref().map(rule_snapshot).transpose()?;
    record_change(
        connection,
        Kind::ConfigRule,
        id,
        before.as_ref(),
        after.as_ref(),
        None,
    )
    .await
}

async fn save_settings(
    connection: &impl ConnectionTrait,
    rule_id: i64,
    settings: &Value,
) -> Result<()> {
    let rows: Vec<config_rule_setting::ActiveModel> = flatten(settings)?
        .iter()
        .map(|(name, value)| {
            let (text, value_type) = encode(value);
            config_rule_setting::ActiveModel {
                rule_id: Set(rule_id),
                name: Set(name.clone()),
                value: Set(text),
                value_type: Set(value_type.to_string()),
                ..Default::default()
            }
        })
        .collect();

    if !rows.is_empty() {
        config_rule_setting::Entity::insert_many(rows)
            .exec_without_returning(connection)
            .await
            .context("saving rule settings")?;
    }
    Ok(())
}

fn to_rule<'a>(
    row: config_rule::Model,
    settings: impl Iterator<Item = &'a config_rule_setting::Model>,
) -> Result<ConfigRule> {
    let flat = settings
        .map(|setting| {
            let value = decode(&setting.value, &setting.value_type)
                .with_context(|| format!("setting {} has an invalid value", setting.name))?;
            Ok((setting.name.clone(), value))
        })
        .collect::<Result<FlatFacts>>()?;

    Ok(ConfigRule {
        id: row.id,
        built_in: row.built_in,
        built_in_changed_at: row.built_in_changed_at,
        rule: RuleInput {
            name: row.name,
            priority: row.priority,
            condition: row.condition_expr,
            operating_systems: row
                .operating_systems
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .filter(|system| !system.is_empty())
                .map(String::from)
                .collect(),
            enabled: row.enabled,
            settings: unflatten(&flat),
        },
    })
}

/// A name another of its kind has is for whoever saved it to change, not a fault.
/// It's the only thing these tables keep unique besides their IDs.
fn name_taken_or(error: DbErr, taken: NameTaken, doing: &'static str) -> anyhow::Error {
    match error.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(_)) => taken.into(),
        _ => anyhow::Error::new(error).context(doing),
    }
}

/// A name as it's compared with others of its kind, which is what the database keeps
/// unique: ignoring case and the spaces around it, the same way on every database.
pub fn name_key(name: &str) -> String {
    name.trim().to_lowercase()
}

/// Operating systems as they're stored: comma separated, or nothing for all of them.
fn systems_text(systems: &[String]) -> Option<String> {
    (!systems.is_empty()).then(|| systems.join(","))
}

/// A list's own name for an item of it. Items inside lists of maps can't be reached
/// by a simple name, so they have none.
fn simple_fact_name(name: String) -> Option<String> {
    let name = match name.strip_suffix(']').and_then(|n| n.rsplit_once('[')) {
        Some((list, _)) => list.to_string(),
        None => name,
    };
    (!name.contains('[')).then_some(name)
}

/// Facts with these names, or items of lists with them. Databases differ in whether
/// they compare text ignoring case, so this can find more, which
/// [`is_fact_or_item`] leaves out.
fn fact_or_its_items(names: &[&str]) -> Condition {
    names.iter().fold(Condition::any(), |wanted, name| {
        wanted
            .add(host_fact::Column::Name.eq(*name))
            .add(starting_with(host_fact::Column::Name, &format!("{name}[")))
    })
}

/// Whether a fact is `name`, or an item of the list it is, exactly.
fn is_fact_or_item(fact: &str, name: &str) -> bool {
    fact.strip_prefix(name)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('['))
}

/// What LIKE escapes its wildcards with: one no database treats specially in a
/// string, as `\` is to MySQL.
const LIKE_ESCAPE: char = '!';

/// A column starting with `prefix`, taking any `%` or `_` in it as itself. Whether
/// case counts depends on the database, so what this finds needs checking.
pub(super) fn starting_with(column: impl ColumnTrait, prefix: &str) -> Expr {
    use sea_orm::sea_query::{ExprTrait, LikeExpr};
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for character in prefix.chars() {
        if matches!(character, '%' | '_' | LIKE_ESCAPE) {
            pattern.push(LIKE_ESCAPE);
        }
        pattern.push(character);
    }
    pattern.push('%');
    Expr::col(column).like(LikeExpr::new(pattern).escape(LIKE_ESCAPE))
}

fn by_host(rows: Vec<host_fact::Model>) -> Result<BTreeMap<String, FlatFacts>> {
    let mut hosts: BTreeMap<String, FlatFacts> = BTreeMap::new();
    for row in rows {
        let host = row.host_id.clone();
        let fact = to_fact_version(row)?;
        hosts.entry(host).or_default().insert(fact.name, fact.value);
    }
    Ok(hosts)
}

fn to_fact_version(row: host_fact::Model) -> Result<FactVersion> {
    Ok(FactVersion {
        value: decode(&row.value, &row.value_type)
            .with_context(|| format!("fact {} has an invalid value", row.name))?,
        name: row.name,
        valid_from: row.valid_from,
        valid_to: row.valid_to,
    })
}

/// An agent as the audit log compares them: what it's called and whether it's
/// allowed in. Its ID is its key, so neither can change.
fn host_snapshot(row: &host::Model) -> Snapshot {
    host_fields(&row.hostname, &row.state, row.decided_by.as_deref())
}

fn host_snapshot_of(record: &HostRecord) -> Snapshot {
    host_fields(
        &record.hostname,
        record.state.as_str(),
        record.decided_by.as_deref(),
    )
}

fn host_fields(hostname: &str, state: &str, decided_by: Option<&str>) -> Snapshot {
    let fields = serde_json::json!({
        "hostname": hostname,
        "state": state,
        "decided_by": decided_by,
    });
    Snapshot::new(hostname, fields)
}

fn to_record(row: host::Model) -> Result<HostRecord> {
    Ok(HostRecord {
        state: HostState::parse(&row.state)
            .with_context(|| format!("host {} has unknown state {:?}", row.id, row.state))?,
        kind: HostKind::parse(&row.kind)
            .with_context(|| format!("host {} has unknown kind {:?}", row.id, row.kind))?,
        id: row.id,
        public_key: row.public_key,
        hostname: row.hostname,
        decided_by: row.decided_by,
        first_seen_at: row.first_seen_at,
        decided_at: row.decided_at,
    })
}

/// SQLite can create its file but not the folder it goes in.
fn create_sqlite_folder(url: &str) -> Result<()> {
    let Some(rest) = url.strip_prefix("sqlite://") else {
        return Ok(());
    };
    let path = rest.split('?').next().unwrap_or(rest);
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating folder {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
async fn hold_all<DB: sea_orm::sqlx::Database>(
    pool: &sea_orm::sqlx::Pool<DB>,
) -> Vec<sea_orm::sqlx::pool::PoolConnection<DB>> {
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.unwrap());
    }
    held
}

/// Makes a new database on a test server, and returns the URL to reach it.
#[cfg(test)]
pub(crate) async fn fresh_test_database(server: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};

    use sea_orm::ConnectionTrait;

    static MADE: AtomicU32 = AtomicU32::new(0);
    // Process IDs come round again, and test databases are left behind, so the name
    // has when this run started in it too.
    static RUN: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        since.map_or(0, |since| since.as_secs())
    });
    let name = format!(
        "maxnines_test_{}_{}_{}",
        *RUN,
        std::process::id(),
        MADE.fetch_add(1, Ordering::Relaxed)
    );
    let connection = sea_orm::Database::connect(server).await.unwrap();
    connection
        .execute_unprepared(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    connection.close().await.unwrap();
    let (hostname, _) = server.rsplit_once('/').unwrap();
    format!("{hostname}/{name}")
}

#[cfg(test)]
impl Database {
    /// An empty database of its own. SQLite in memory, unless `MAXNINES_TEST_DATABASE_URL`
    /// names a Postgres or MySQL server to run the tests against instead.
    ///
    /// It waits far longer for a connection than a server does, as a CI machine
    /// running every test at once can stall for seconds, which isn't the database
    /// being down.
    pub async fn for_test() -> Self {
        let url = match std::env::var("MAXNINES_TEST_DATABASE_URL") {
            Ok(server) => fresh_test_database(&server).await,
            Err(_) => "sqlite::memory:".to_string(),
        };
        Self::connect_waiting(&url, Duration::from_secs(60))
            .await
            .unwrap()
    }

    /// The connection itself, for tests that look at the rows as they're kept.
    pub fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }

    /// Takes every connection, so that queries wait until it's dropped, as they do on a
    /// database that's stalled.
    pub async fn stall_for_test(&self) -> Box<dyn std::any::Any + Send> {
        use sea_orm::DatabaseBackend;
        match self.connection.get_database_backend() {
            DatabaseBackend::Postgres => {
                Box::new(hold_all(self.connection.get_postgres_connection_pool()).await)
            }
            DatabaseBackend::MySql => {
                Box::new(hold_all(self.connection.get_mysql_connection_pool()).await)
            }
            _ => Box::new(hold_all(self.connection.get_sqlite_connection_pool()).await),
        }
    }

    /// Makes every later query about hosts fail, while signing in still works.
    pub async fn break_for_test(&self) {
        use sea_orm::ConnectionTrait;
        for table in ["host_config_status", "host_facts", "hosts"] {
            self.connection
                .execute_unprepared(&format!("ALTER TABLE {table} RENAME TO {table}_gone"))
                .await
                .unwrap();
        }
    }

    async fn clear_for_test(&self) {
        use sea_orm::ConnectionTrait;
        self.connection
            .execute_unprepared("DELETE FROM host_config_status")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM host_facts")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM config_rules WHERE name <> 'Default'")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM alerts")
            .await
            .unwrap();
        self.connection
            .execute_unprepared("DELETE FROM hosts WHERE id <> 'server'")
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use chrono::TimeDelta;

    use super::*;
    use crate::facts::flatten;

    /// `ms` milliseconds after 1970, as the tests count.
    fn at(ms: i64) -> Timestamp {
        crate::times::from_ms(ms)
    }

    fn record(id: &str) -> HostRecord {
        HostRecord {
            kind: crate::registration::HostKind::Agent,
            id: id.to_string(),
            public_key: Some("ab".repeat(32)),
            hostname: "web-1".to_string(),
            state: HostState::Pending,
            decided_by: None,
            first_seen_at: crate::times::from_ms(1_789_000_000_123),
            decided_at: None,
        }
    }

    /// Everything but the built-in agent, which every database starts with.
    async fn hosts(database: &Database) -> Vec<HostRecord> {
        let mut hosts = database.load_hosts().await.unwrap();
        hosts.retain(|host| !host.is_local());
        hosts
    }

    fn sorted(mut records: Vec<HostRecord>) -> Vec<HostRecord> {
        records.sort_by(|a, b| a.id.cmp(&b.id));
        records
    }

    /// Someone to own keys, made the first time it's asked for.
    async fn owner(database: &Database) -> i64 {
        if let Some(user) = database.list_users().await.unwrap().first() {
            return user.id;
        }
        let made = database
            .create_user(
                "owner@example.com",
                "Owner",
                crate::roles::Role::Admin,
                at(0),
            )
            .await;
        made.unwrap().unwrap().0.id
    }

    #[tokio::test]
    async fn a_key_acts_as_its_owner_and_stops_while_they_are_disabled() {
        let database = Database::for_test().await;
        let id = owner(&database).await;
        database
            .create_user(
                "other@example.com",
                "Other",
                crate::roles::Role::Admin,
                at(0),
            )
            .await
            .unwrap();
        let (key, secret) = database
            .create_api_key("ci", id, crate::roles::Role::Admin, None, at(0))
            .await
            .unwrap();
        assert_eq!(key.owner, "owner@example.com");

        let (_, acts_as) = database
            .accept_api_key(&secret, at(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(acts_as.id, id);
        database.disable_user(id, at(2)).await.unwrap();
        assert!(
            database
                .accept_api_key(&secret, at(3))
                .await
                .unwrap()
                .is_none()
        );
        database.enable_user(id).await.unwrap();
        assert!(
            database
                .accept_api_key(&secret, at(4))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn deleting_someone_deletes_their_keys() {
        let database = Database::for_test().await;
        let id = owner(&database).await;
        database
            .create_user(
                "other@example.com",
                "Other",
                crate::roles::Role::Admin,
                at(0),
            )
            .await
            .unwrap();
        let (_, secret) = database
            .create_api_key("ci", id, crate::roles::Role::Admin, None, at(0))
            .await
            .unwrap();

        database.disable_user(id, at(1)).await.unwrap();
        database.delete_user(id).await.unwrap();

        assert!(database.list_api_keys().await.unwrap().is_empty());
        assert!(
            database
                .accept_api_key(&secret, at(2))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_disabled_or_missing_user_cannot_be_given_a_key() {
        let database = Database::for_test().await;
        let id = owner(&database).await;
        database
            .create_user(
                "other@example.com",
                "Other",
                crate::roles::Role::Admin,
                at(0),
            )
            .await
            .unwrap();
        database.disable_user(id, at(1)).await.unwrap();

        assert!(
            database
                .create_api_key("ci", id, crate::roles::Role::Admin, None, at(2))
                .await
                .is_err()
        );
        assert!(
            database
                .create_api_key("ci", id + 100, crate::roles::Role::Admin, None, at(2))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_api_key_works_until_it_is_revoked() {
        let database = Database::for_test().await;
        let (key, secret) = database
            .create_api_key(
                "backup",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(1000),
            )
            .await
            .unwrap();

        assert!(
            database
                .accept_api_key(&secret, at(2000))
                .await
                .unwrap()
                .is_some()
        );
        assert!(database.revoke_api_key(key.id, at(3000)).await.unwrap());
        assert!(
            database
                .accept_api_key(&secret, at(4000))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn only_a_real_key_is_accepted() {
        let database = Database::for_test().await;
        database
            .create_api_key(
                "backup",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(1000),
            )
            .await
            .unwrap();

        assert!(
            database
                .accept_api_key("mxn_guess", at(2000))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            database
                .accept_api_key("", at(2000))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_key_itself_is_never_stored() {
        let database = Database::for_test().await;
        let (_, secret) = database
            .create_api_key(
                "backup",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(1000),
            )
            .await
            .unwrap();

        let rows = api_key::Entity::find()
            .all(&database.connection)
            .await
            .unwrap();

        assert_ne!(rows[0].token_hash, secret);
        assert!(!format!("{rows:?}").contains(&secret));
        assert!(secret.starts_with(&rows[0].hint));
        assert!(rows[0].hint.len() < secret.len() / 4);
    }

    #[tokio::test]
    async fn each_key_is_different() {
        let database = Database::for_test().await;
        let (_, first) = database
            .create_api_key(
                "a",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(1),
            )
            .await
            .unwrap();
        let (_, second) = database
            .create_api_key(
                "a",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(1),
            )
            .await
            .unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn using_a_key_is_noted_without_writing_every_time() {
        let database = Database::for_test().await;
        let (_, secret) = database
            .create_api_key(
                "backup",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(0),
            )
            .await
            .unwrap();
        let used = async || database.list_api_keys().await.unwrap()[0].last_used_at;
        assert_eq!(used().await, None);

        database.accept_api_key(&secret, at(100_000)).await.unwrap();
        assert_eq!(used().await, Some(crate::times::from_ms(100_000)));

        database.accept_api_key(&secret, at(100_500)).await.unwrap();
        assert_eq!(used().await, Some(crate::times::from_ms(100_000)));

        database.accept_api_key(&secret, at(170_000)).await.unwrap();
        assert_eq!(used().await, Some(crate::times::from_ms(170_000)));
    }

    #[tokio::test]
    async fn revoking_twice_keeps_the_first_time() {
        let database = Database::for_test().await;
        let (key, _) = database
            .create_api_key(
                "backup",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(0),
            )
            .await
            .unwrap();

        database.revoke_api_key(key.id, at(100)).await.unwrap();
        database.revoke_api_key(key.id, at(200)).await.unwrap();

        let keys = database.list_api_keys().await.unwrap();
        assert_eq!(keys[0].revoked_at, Some(crate::times::from_ms(100)));
        assert!(!database.revoke_api_key(999, at(300)).await.unwrap());
    }

    #[tokio::test]
    async fn a_key_stops_working_when_it_expires() {
        let database = Database::for_test().await;
        let (key, secret) = database
            .create_api_key(
                "deploy",
                owner(&database).await,
                crate::roles::Role::Admin,
                Some(crate::times::from_ms(5000)),
                at(1000),
            )
            .await
            .unwrap();

        assert!(
            database
                .accept_api_key(&secret, at(4999))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            database
                .accept_api_key(&secret, at(5000))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            database
                .accept_api_key(&secret, at(9000))
                .await
                .unwrap()
                .is_none()
        );
        assert!(!key.has_expired(at(4999)));
        assert!(key.has_expired(at(5000)));
    }

    #[tokio::test]
    async fn a_key_with_no_expiry_lasts() {
        let database = Database::for_test().await;
        let (key, secret) = database
            .create_api_key(
                "a",
                owner(&database).await,
                crate::roles::Role::Admin,
                None,
                at(0),
            )
            .await
            .unwrap();

        // 2100, as far ahead as there's any need to look.
        let much_later = 4_102_444_800_000;
        assert!(
            database
                .accept_api_key(&secret, at(much_later))
                .await
                .unwrap()
                .is_some()
        );
        assert!(!key.has_expired(Timestamp::MAX_UTC));
    }

    #[test]
    fn expiry_is_counted_from_now() {
        let seconds = Duration::from_secs;
        assert_eq!(expiry_after(seconds(60), at(1000)).unwrap(), at(61_000));
        assert!(expiry_after(Duration::ZERO, at(1000)).is_err());
        assert!(expiry_after(Duration::MAX, at(1000)).is_err());
        // Ten thousand years is more than any database keeps.
        assert!(expiry_after(seconds(10_000 * 366 * 86_400), at(1000)).is_err());
    }

    #[test]
    fn keys_need_a_sensible_name() {
        assert!(check_api_key_name("backup").is_ok());
        assert!(check_api_key_name("  ").is_err());
        assert!(check_api_key_name(&"x".repeat(101)).is_err());
    }

    #[tokio::test]
    async fn sqlite_does_not_wait_on_the_disk_for_every_write() {
        let folder = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}/app.db?mode=rwc", folder.path().display());
        let database = Database::connect(&url).await.unwrap();

        let pragma = async |name: &str| {
            let statement = sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                format!("PRAGMA {name}"),
            );
            let row = database.connection.query_one_raw(statement).await.unwrap();
            row.unwrap()
        };

        let mode: String = pragma("journal_mode")
            .await
            .try_get("", "journal_mode")
            .unwrap();
        let synchronous: i32 = pragma("synchronous")
            .await
            .try_get("", "synchronous")
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(synchronous, 1, "NORMAL");
    }

    #[tokio::test]
    async fn a_server_secret_survives_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}?mode=rwc", folder.path().join("db").display());

        let first = Database::connect(&url).await.unwrap();
        let secret = first.server_secret("csrf_key").await.unwrap();
        drop(first);

        let reopened = Database::connect(&url).await.unwrap();
        assert_eq!(reopened.server_secret("csrf_key").await.unwrap(), secret);
        assert_ne!(reopened.server_secret("csrf_salt").await.unwrap(), secret);
    }

    #[tokio::test]
    async fn each_database_gets_its_own_secrets() {
        let first = Database::for_test()
            .await
            .server_secret("csrf_key")
            .await
            .unwrap();
        let second = Database::for_test()
            .await
            .server_secret("csrf_key")
            .await
            .unwrap();
        assert_ne!(first, second);
    }

    /// Everything each database has to get right. It runs against SQLite
    /// always, and against real servers with `cargo test -- --ignored`.
    async fn exercise(url: &str) {
        let database = Database::connect(url).await.unwrap();
        database.clear_for_test().await;
        assert!(hosts(&database).await.is_empty());

        // Creating.
        let pending = record("host-1");
        database.save_host(&pending).await.unwrap();
        assert_eq!(hosts(&database).await, vec![pending.clone()]);

        // Saving identical data, which MySQL reports as zero rows changed.
        database.save_host(&pending).await.unwrap();
        assert_eq!(hosts(&database).await, vec![pending.clone()]);

        // Replacing, including going from NULL to a value.
        let approved = HostRecord {
            kind: crate::registration::HostKind::Agent,
            state: HostState::Approved,
            decided_by: Some("rule:production-subnet".to_string()),
            decided_at: Some(crate::times::from_ms(1_789_000_000_456)),
            ..pending.clone()
        };
        database.save_host(&approved).await.unwrap();
        assert_eq!(hosts(&database).await, vec![approved.clone()]);

        // The largest hostname allowed, non-ASCII text, and a long rule name.
        let unusual = HostRecord {
            kind: crate::registration::HostKind::Agent,
            hostname: "x".repeat(255),
            decided_by: Some(format!("rule:{}", "é🚀".repeat(200))),
            ..record("host-2")
        };
        database.save_host(&unusual).await.unwrap();
        let unicode = HostRecord {
            kind: crate::registration::HostKind::Agent,
            hostname: "сервер-🚀".to_string(),
            ..record("host-3")
        };
        database.save_host(&unicode).await.unwrap();
        assert_eq!(
            sorted(hosts(&database).await),
            [approved.clone(), unusual.clone(), unicode.clone()]
        );

        exercise_facts(&database, &approved.id, &unusual.id).await;
        exercise_rules(&database).await;
        exercise_config_status(&database, &approved.id).await;

        // A second connection sees it all, and migrating again changes nothing.
        let reopened = Database::connect(url).await.unwrap();
        assert_eq!(sorted(hosts(&reopened).await), [approved, unusual, unicode]);

        database.clear_for_test().await;
    }

    fn flat(pairs: &[(&str, Value)]) -> FlatFacts {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect()
    }

    fn current(versions: &[FactVersion]) -> Vec<(&str, &Value)> {
        versions
            .iter()
            .filter(|version| version.valid_to.is_none())
            .map(|version| (version.name.as_str(), &version.value))
            .collect()
    }

    fn rule_input(name: &str, priority: i32) -> RuleInput {
        RuleInput {
            name: name.to_string(),
            priority,
            condition: Some("facts.os.family == \"linux\"".to_string()),
            operating_systems: Vec::new(),
            enabled: true,
            settings: json!({
                "interval_secs": 10,
                "collectors": {
                    "disk": { "enabled": true, "mount_points": ["/", "/data"] },
                },
            }),
        }
    }

    #[tokio::test]
    async fn known_facts_lists_each_name_once_with_its_type() {
        let database = Database::for_test().await;
        database.save_host(&record("host-1")).await.unwrap();
        database.save_host(&record("host-2")).await.unwrap();
        let facts = flatten(&json!({
            "os": { "family": "linux" },
            "custom": { "tags": ["a", "b"], "rack": 12, "disks": [{ "mount": "/" }] },
        }))
        .unwrap();
        database
            .record_facts("host-1", &facts, at(1))
            .await
            .unwrap();
        database
            .record_facts("host-2", &facts, at(1))
            .await
            .unwrap();

        let known = database.known_facts().await.unwrap();

        assert_eq!(
            known,
            BTreeMap::from([
                ("custom.rack".to_string(), "number".to_string()),
                ("custom.tags".to_string(), "string".to_string()),
                ("os.family".to_string(), "string".to_string()),
            ])
        );
    }

    /// Wildcards in what's searched for are only themselves, and case is ignored the
    /// same way on every database.
    #[tokio::test]
    async fn fact_values_and_lists_match_what_was_typed_exactly() {
        let database = Database::for_test().await;
        for (host, version, check) in [
            ("host-1", "Ubuntu 10.0", "web_1"),
            ("host-2", "1000", "webx1"),
            ("host-3", "10_0 build", "Web_1"),
            ("host-4", "50%", "web_2"),
        ] {
            database.save_host(&record(host)).await.unwrap();
            let facts = flatten(&json!({
                "os": { "version": version },
                "agent": { "checks": [check] },
                "agent_x": { "checks": ["not a check"] },
            }))
            .unwrap();
            database.record_facts(host, &facts, at(1)).await.unwrap();
        }
        let values = |text: &'static str| {
            let database = database.clone();
            async move { database.fact_values("os.version", text, 10).await.unwrap() }
        };

        assert_eq!(values("10_0").await, ["10_0 build"]);
        assert_eq!(values("ubuntu").await, ["Ubuntu 10.0"]);
        assert_eq!(values("%").await, ["50%"]);
        assert_eq!(
            values("").await,
            ["1000", "10_0 build", "50%", "Ubuntu 10.0"]
        );
        assert_eq!(
            database.listed_by_agents("agent.checks").await.unwrap(),
            ["Web_1", "web_1", "web_2", "webx1"]
        );
        assert!(
            database
                .listed_by_agents("agent_checks")
                .await
                .unwrap()
                .is_empty()
        );
    }

    async fn exercise_rules(database: &Database) {
        // A new install has a default rule, from the migration.
        let rules = database.list_rules().await.unwrap();
        assert_eq!(rules[0].rule.name, "Default");
        assert_eq!(rules[0].rule.condition, None);
        assert_eq!(rules[0].rule.settings["interval_secs"], 15);
        assert_eq!(rules[0].rule.settings["collectors"]["cpu"]["enabled"], true);

        // Settings come back with their types and shape.
        let later = database
            .create_rule(&rule_input("later", 200))
            .await
            .unwrap();
        let earlier = database
            .create_rule(&rule_input("earlier", 100))
            .await
            .unwrap();
        let rule = database.get_rule(later).await.unwrap().unwrap();
        assert_eq!(rule.rule, rule_input("later", 200));

        // Lowest priority first.
        let names: Vec<String> = database
            .list_rules()
            .await
            .unwrap()
            .into_iter()
            .map(|rule| rule.rule.name)
            .collect();
        assert_eq!(names, ["Default", "earlier", "later"]);

        // Updating replaces the settings instead of adding to them.
        let mut changed = rule_input("renamed", 300);
        changed.condition = None;
        changed.enabled = false;
        changed.settings = json!({ "interval_secs": 5 });
        assert!(database.update_rule(later, &changed).await.unwrap());
        assert_eq!(
            database.get_rule(later).await.unwrap().unwrap().rule,
            changed
        );

        // Unknown rules are reported, not errors.
        assert!(!database.update_rule(9_999_999, &changed).await.unwrap());
        assert!(!database.delete_rule(9_999_999).await.unwrap());
        assert_eq!(database.get_rule(9_999_999).await.unwrap(), None);

        // A second rule can't take a name that's in use.
        assert!(
            database
                .create_rule(&rule_input("earlier", 1))
                .await
                .is_err()
        );

        assert!(database.delete_rule(later).await.unwrap());
        assert!(database.delete_rule(earlier).await.unwrap());
        assert_eq!(database.list_rules().await.unwrap().len(), 1);
    }

    async fn exercise_config_status(database: &Database, host: &str) {
        assert_eq!(database.config_status(host).await.unwrap(), None);

        let failed = ConfigStatus {
            version: "v1".to_string(),
            error: Some("unknown collector".to_string()),
            reported_at: crate::times::from_ms(100),
        };
        database.save_config_status(host, &failed).await.unwrap();
        assert_eq!(
            database.config_status(host).await.unwrap(),
            Some(failed.clone())
        );

        // Saving identical data, which MySQL reports as zero rows changed.
        database.save_config_status(host, &failed).await.unwrap();

        let applied = ConfigStatus {
            version: "v2".to_string(),
            error: None,
            reported_at: crate::times::from_ms(200),
        };
        database.save_config_status(host, &applied).await.unwrap();
        assert_eq!(
            database.config_status(host).await.unwrap(),
            Some(applied.clone())
        );
        let several = database.config_statuses(&[host, "nobody"]).await.unwrap();
        assert_eq!(several, BTreeMap::from([(host.to_string(), applied)]));
    }

    async fn exercise_facts(database: &Database, host: &str, other: &str) {
        assert!(database.current_facts(host).await.unwrap().is_empty());

        // Every value type, and non-ASCII text.
        let first = flat(&[
            ("os.family", json!("linux")),
            ("os.version", json!("24.04")),
            ("memory.total_bytes", json!(51_539_607_552_u64)),
            ("custom.enabled", json!(true)),
            ("custom.note", json!("сервер-🚀")),
        ]);
        assert!(database.record_facts(host, &first, at(100)).await.unwrap());
        assert!(!database.record_facts(host, &first, at(200)).await.unwrap());

        let facts = database.current_facts(host).await.unwrap();
        assert_eq!(facts.len(), 5);
        let value = |name: &str| {
            let fact = facts.iter().find(|f| f.name == name).unwrap();
            fact.value.clone()
        };
        assert_eq!(value("memory.total_bytes"), json!(51_539_607_552_u64));
        assert_eq!(value("custom.enabled"), json!(true));
        assert_eq!(value("custom.note"), json!("сервер-🚀"));

        // One fact changes, one goes away, one is new, and the rest stay put.
        let second = flat(&[
            ("os.family", json!("linux")),
            ("os.version", json!("24.10")),
            ("memory.total_bytes", json!(51_539_607_552_u64)),
            ("custom.enabled", json!(true)),
            ("custom.role", json!("web")),
        ]);
        assert!(database.record_facts(host, &second, at(300)).await.unwrap());

        let history = database.facts_history(host).await.unwrap();
        assert_eq!(history.len(), 7);
        let family = history.iter().find(|f| f.name == "os.family").unwrap();
        let at = crate::times::from_ms;
        assert_eq!((family.valid_from, family.valid_to), (at(100), None));
        let old = history.iter().find(|f| f.value == json!("24.04")).unwrap();
        assert_eq!((old.valid_from, old.valid_to), (at(100), Some(at(300))));
        let new = history.iter().find(|f| f.value == json!("24.10")).unwrap();
        assert_eq!((new.valid_from, new.valid_to), (at(300), None));
        let gone = history.iter().find(|f| f.name == "custom.note").unwrap();
        assert_eq!(gone.valid_to, Some(at(300)));
        assert_eq!(database.current_facts(host).await.unwrap().len(), 5);
        assert_eq!(current(&history).len(), 5);

        // Going back to earlier values is a change too: os.version and
        // custom.note return, so two more rows.
        assert!(database.record_facts(host, &first, at(400)).await.unwrap());
        assert_eq!(database.facts_history(host).await.unwrap().len(), 9);

        // A value keeps its type: 1 and "1" are different facts.
        let number = flat(&[("custom.level", json!(1))]);
        let text = flat(&[("custom.level", json!("1"))]);
        assert!(
            database
                .record_facts(other, &number, at(500))
                .await
                .unwrap()
        );
        assert!(database.record_facts(other, &text, at(600)).await.unwrap());
        let levels = database.current_facts(other).await.unwrap();

        // Each agent's current values, and none of the ones they replaced.
        assert_eq!(
            database.all_current_facts().await.unwrap(),
            BTreeMap::from([
                (host.to_string(), first.clone()),
                (other.to_string(), text.clone())
            ])
        );

        assert_eq!(levels[0].value, json!("1"));

        // Changing a list only touches the items that changed.
        let names = |facts: &[FactVersion]| -> Vec<(String, Value)> {
            facts
                .iter()
                .filter(|f| f.name.starts_with("custom.tags"))
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect()
        };
        let tags = |value: Value| flatten(&json!({ "custom": { "tags": value } })).unwrap();

        let list = tags(json!(["web", "prod"]));
        assert!(database.record_facts(other, &list, at(700)).await.unwrap());
        assert!(!database.record_facts(other, &list, at(750)).await.unwrap());

        let longer = tags(json!(["web", "prod", "eu"]));
        let before = database.facts_history(other).await.unwrap().len();
        assert!(
            database
                .record_facts(other, &longer, at(800))
                .await
                .unwrap()
        );
        let after = database.facts_history(other).await.unwrap().len();
        assert_eq!(after, before + 1);

        let current = database.current_facts(other).await.unwrap();
        assert_eq!(
            names(&current),
            [
                ("custom.tags[0]".to_string(), json!("web")),
                ("custom.tags[1]".to_string(), json!("prod")),
                ("custom.tags[2]".to_string(), json!("eu")),
            ]
        );

        // Removing the first item shifts the rest and drops the last name.
        let shifted = tags(json!(["prod", "eu"]));
        assert!(
            database
                .record_facts(other, &shifted, at(900))
                .await
                .unwrap()
        );
        let current = database.current_facts(other).await.unwrap();
        assert_eq!(
            names(&current),
            [
                ("custom.tags[0]".to_string(), json!("prod")),
                ("custom.tags[1]".to_string(), json!("eu")),
            ]
        );

        // A single value is a different name from a one-item list.
        let single = tags(json!("prod"));
        assert!(
            database
                .record_facts(other, &single, at(1000))
                .await
                .unwrap()
        );
        let current = database.current_facts(other).await.unwrap();
        assert_eq!(
            names(&current),
            [("custom.tags".to_string(), json!("prod"))]
        );

        // Each agent has its own facts.
        assert_eq!(database.current_facts(host).await.unwrap().len(), 5);

        exercise_alerting(database, host).await;
        exercise_remote_checks(database).await;

        let secret = database.server_secret("csrf_key").await.unwrap();
        assert!(secret.len() >= 32);
        assert_eq!(database.server_secret("csrf_key").await.unwrap(), secret);

        let stats = database.stats().await.unwrap();
        assert!(stats.size_bytes.unwrap_or(0) > 0, "{stats:?}");
        assert!(stats.latest_migration.is_some());
        assert_eq!(stats.tables[0].name, "Hosts");
        assert!(stats.tables[0].rows > 0);
    }

    async fn exercise_remote_checks(database: &Database) {
        use maxnines_protocol::{Check, CheckKind};

        use crate::remote_checks::{LOCAL_HOST_ID, RemoteCheckInput};

        let hosts = database.load_hosts().await.unwrap();
        assert!(hosts.iter().any(|host| host.id == LOCAL_HOST_ID));

        let name = format!("site {}", crate::times::now().timestamp_millis());
        let mut check = Check::new(&name, CheckKind::Http, "https://example.com/");
        check.timeout = Some(std::time::Duration::from_secs(5));
        check.method = Some("POST".to_string());
        check.body = Some("é".repeat(100));
        check.regex = Some("Welcome".to_string());
        check.insecure = Some(true);
        let mut input = RemoteCheckInput {
            host_id: crate::remote_checks::LOCAL_HOST_ID.to_string(),
            check,
            interval: std::time::Duration::from_secs(60),
            enabled: true,
            read_stats: false,
            extras: Vec::new(),
            sign_in: Default::default(),
        };

        let id = database.create_remote_check(&input).await.unwrap();
        let saved = database.get_remote_check(id).await.unwrap().unwrap();
        assert_eq!(saved.input, input);

        input.interval = std::time::Duration::from_secs(120);
        input.check.count = None;
        assert!(database.update_remote_check(id, &input).await.unwrap());
        let list = database.list_remote_checks().await.unwrap();
        let saved = list.iter().find(|check| check.id == id).unwrap();
        assert_eq!(saved.input.interval, std::time::Duration::from_secs(120));

        assert!(database.delete_remote_check(id).await.unwrap());
        assert!(database.get_remote_check(id).await.unwrap().is_none());
    }

    /// Names are unique per run, because real databases keep their rows.
    async fn exercise_alerting(database: &Database, host: &str) {
        use crate::alerting::{
            AlertRuleInput, ChannelInput, ChannelKind, Comparison, Event, NewAlert, RuleKind,
            Severity,
        };

        let suffix = crate::times::now().timestamp_millis();
        let channel = database
            .create_channel(&ChannelInput {
                name: format!("Ops {suffix}"),
                kind: ChannelKind::Webhook,
                target: "https://example.com/hook".to_string(),
                credential: Some("secret".to_string()),
                app_token: None,
                severities: crate::alerting::every_severity(),
                mail: None,
                request: None,
            })
            .await
            .unwrap();
        let mut input = AlertRuleInput {
            name: format!("High CPU {suffix}"),
            kind: RuleKind::Metric,
            metric: Some("cpu.usage".to_string()),
            series: Some("/data*".to_string()),
            comparison: Some(Comparison::Above),
            threshold: Some(90.5),
            warning_threshold: None,
            hold: TimeDelta::seconds(120),
            severity: Severity::Critical,
            condition: Some("true".to_string()),
            enabled: true,
            channels: vec![channel],
            all_channels: false,
            calculation: None,
            group_by: None,
            filter: None,
            window: None,
            remind_every: None,
            forecast: None,
            warning_forecast: None,
            actions: Vec::new(),
        };
        let rule = database.create_alert_rule(&input).await.unwrap();
        assert_eq!(
            database.get_alert_rule(rule).await.unwrap().unwrap().rule,
            input
        );

        input.threshold = Some(75.25);
        assert!(database.update_alert_rule(rule, &input).await.unwrap());
        assert_eq!(
            database.get_alert_rule(rule).await.unwrap().unwrap().rule,
            input
        );

        let started_at = at(suffix);
        let new = NewAlert {
            rule_id: rule,
            severity: input.severity,
            host_id: host.to_string(),
            series: Some("é".repeat(255)),
            value: Some(91.5),
            summary: "x".repeat(5000),
            started_at,
            breached_at: started_at,
        };
        let alert = database
            .fire_alert(&new, &[channel])
            .await
            .unwrap()
            .unwrap();
        let open = database.open_alerts().await.unwrap();
        let saved = open.iter().find(|a| a.id == alert).unwrap();
        // Named by its rule and host as they're called now.
        assert_eq!(saved.rule_name, input.name);
        let hostname = database.load_hosts().await.unwrap();
        let hostname = &hostname.iter().find(|h| h.id == host).unwrap().hostname;
        assert_eq!(&saved.hostname, hostname);
        assert_eq!(saved.series, new.series);
        assert_eq!(saved.value, Some(91.5));

        let due = database.due_deliveries(started_at, 500).await.unwrap();
        let firing = due.iter().find(|d| d.alert.id == alert).unwrap();
        assert_eq!(firing.event, Event::Firing);
        database
            .delivery_failed(
                firing.id,
                1,
                "the webhook returned status 500",
                Some(started_at + TimeDelta::milliseconds(5)),
            )
            .await
            .unwrap();
        let problems = database.delivery_problems(10).await.unwrap();
        assert_eq!(problems[0].error, "the webhook returned status 500");
        database
            .delivery_sent(
                firing.id,
                2,
                started_at + TimeDelta::milliseconds(5),
                Some("C123:1.2"),
            )
            .await
            .unwrap();

        database
            .resolve_alert(
                alert,
                started_at + TimeDelta::milliseconds(10),
                "The problem cleared",
                None,
            )
            .await
            .unwrap();
        let due = database
            .due_deliveries(started_at + TimeDelta::milliseconds(10), 500)
            .await
            .unwrap();
        let resolved = due.iter().find(|d| d.alert.id == alert).unwrap();
        assert_eq!(resolved.event, Event::Resolved);
        assert_eq!(resolved.reply_to.as_deref(), Some("C123:1.2"));
        assert_eq!(
            resolved.channel.channel.credential.as_deref(),
            Some("secret")
        );

        // The alert outlives its rule and still names it, and what was waiting for a
        // deleted channel goes.
        assert!(
            database
                .delete_alert_rule(rule, started_at + TimeDelta::milliseconds(20))
                .await
                .unwrap()
        );
        let history = database.resolved_alerts(10).await.unwrap();
        let ended = history.iter().find(|a| a.id == alert).unwrap();
        assert_eq!(ended.rule_id, rule);
        assert_eq!(ended.rule_name, input.name);
        assert!(
            database
                .delete_channel(channel, started_at + TimeDelta::milliseconds(5))
                .await
                .unwrap()
        );
        let due = database
            .due_deliveries(started_at + TimeDelta::milliseconds(10), 500)
            .await
            .unwrap();
        assert!(!due.iter().any(|d| d.alert.id == alert));
    }

    #[tokio::test]
    async fn facts_need_a_registered_agent() {
        let database = Database::for_test().await;
        let result = database
            .record_facts("nobody", &flat(&[("a", json!(1))]), at(1))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_failed_update_leaves_the_previous_facts_in_place() {
        use sea_orm::ConnectionTrait;

        let database = Database::for_test().await;
        database.save_host(&record("host-1")).await.unwrap();
        let before = flat(&[("os.version", json!("24.04"))]);
        database
            .record_facts("host-1", &before, at(100))
            .await
            .unwrap();

        // The old value is closed first, then adding the new one fails.
        let trigger = match database.connection.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => {
                "CREATE FUNCTION block_new_version() RETURNS trigger AS
                 $$ BEGIN RAISE EXCEPTION 'blocked'; END $$ LANGUAGE plpgsql;
                 CREATE TRIGGER block_new_version BEFORE INSERT ON host_facts
                 FOR EACH ROW EXECUTE FUNCTION block_new_version()"
            }
            sea_orm::DatabaseBackend::MySql => {
                "CREATE TRIGGER block_new_version BEFORE INSERT ON host_facts
                 FOR EACH ROW SIGNAL SQLSTATE '45000'"
            }
            _ => {
                "CREATE TRIGGER block_new_version BEFORE INSERT ON host_facts
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END"
            }
        };
        database
            .connection
            .execute_unprepared(trigger)
            .await
            .unwrap();

        let after = flat(&[("os.version", json!("24.10"))]);
        assert!(
            database
                .record_facts("host-1", &after, at(200))
                .await
                .is_err()
        );

        let facts = database.current_facts("host-1").await.unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].value, json!("24.04"));
    }

    #[tokio::test]
    async fn concurrent_reports_never_leave_two_current_values() {
        let database = Database::for_test().await;
        database.save_host(&record("host-1")).await.unwrap();

        let reports = (0..20).map(|n| {
            let database = database.clone();
            tokio::spawn(async move {
                let facts = flat(&[("os.version", json!(n))]);
                database
                    .record_facts("host-1", &facts, at(n))
                    .await
                    .unwrap();
            })
        });
        for report in reports.collect::<Vec<_>>() {
            report.await.unwrap();
        }

        assert_eq!(database.current_facts("host-1").await.unwrap().len(), 1);
        // Each host's lock goes once nothing's saving its facts.
        assert!(database.facts_locks.locks().is_empty());
    }

    #[tokio::test]
    async fn works_on_sqlite() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested/folder/hosts.db");
        exercise(&format!("sqlite://{}?mode=rwc", path.display())).await;
    }

    #[tokio::test]
    #[ignore = "needs a server: set MAXNINES_TEST_POSTGRES_URL"]
    async fn works_on_postgres() {
        exercise(&std::env::var("MAXNINES_TEST_POSTGRES_URL").unwrap()).await;
    }

    #[tokio::test]
    #[ignore = "needs a server: set MAXNINES_TEST_MYSQL_URL"]
    async fn works_on_mysql() {
        exercise(&std::env::var("MAXNINES_TEST_MYSQL_URL").unwrap()).await;
    }

    #[tokio::test]
    async fn a_corrupt_state_is_an_error_not_a_guess() {
        use sea_orm::ConnectionTrait;

        let database = Database::for_test().await;
        database
            .connection
            .execute_unprepared(
                "INSERT INTO hosts (id, public_key, hostname, state, first_seen_at)
                 VALUES ('a', 'b', 'c', 'trusted', '2026-11-19T00:00:00+00:00')",
            )
            .await
            .unwrap();

        assert!(database.load_hosts().await.is_err());
    }

    #[tokio::test]
    async fn every_migration_can_be_undone_and_applied_again() {
        let database = Database::for_test().await;
        let connection = &database.connection;
        let count = u32::try_from(Migrator::migrations().len()).unwrap();

        for _ in 0..count {
            Migrator::down(connection, Some(1)).await.unwrap();
            Migrator::up(connection, Some(1)).await.unwrap();
        }
        Migrator::down(connection, None).await.unwrap();
        assert!(
            Migrator::get_applied_migrations(connection)
                .await
                .unwrap()
                .is_empty()
        );

        Migrator::up(connection, None).await.unwrap();
        let hosts = database.load_hosts().await.unwrap();
        assert_eq!(hosts.len(), 2, "both built-in hosts are back: {hosts:?}");
    }

    #[tokio::test]
    async fn starting_again_changes_nothing_and_keeps_what_was_saved() {
        let database = Database::for_test().await;
        database.save_host(&record("host-1")).await.unwrap();

        Migrator::up(&database.connection, None).await.unwrap();

        let hosts = database.load_hosts().await.unwrap();
        assert!(hosts.iter().any(|host| host.id == "host-1"));
    }

    #[tokio::test]
    async fn an_unreachable_server_fails_without_showing_the_password() {
        let url = "postgres://user:hunter2@127.0.0.1:1/maxnines";

        let error = match Database::connect(url).await {
            Err(error) => format!("{error:#}"),
            Ok(_) => panic!("connected to nothing"),
        };

        assert!(!error.contains("hunter2"), "{error}");
    }
}
