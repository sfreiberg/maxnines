//! What's shared by everything that reads a database's health, load and
//! replication, which the built-in templates do for each kind, through
//! [`crate::templates`], for the agent's own `database` blocks and for hosts
//! without an agent on the server: which kinds of check are databases, where one is
//! and how to sign in, and how long a round gets. ClickHouse's HTTP client is here
//! too, as its sign-in check uses it.

pub(crate) mod clickhouse;

use std::time::Duration;

use maxnines_protocol::{Check, CheckKind};

use crate::Credentials;

/// How long a round gets, unless the caller asks for less.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Whether this kind of check is a database whose stats its built-in template
/// reads.
pub fn is_database(kind: CheckKind) -> bool {
    matches!(
        kind,
        CheckKind::Postgres | CheckKind::Mysql | CheckKind::Mongodb | CheckKind::Clickhouse
    )
}

/// Where a database is and how to sign in to it.
#[derive(Clone, PartialEq, Eq)]
pub struct Database {
    /// The kind, where to reach it, and its options, as a check would have them.
    pub check: Check,
    pub credentials: Credentials,
}
