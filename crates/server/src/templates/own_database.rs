//! The server's own main database, read for templates with nothing but the built-in
//! templates for its kind as this server was built with them: never a template's
//! rows in the database, so no imported or own template, and no one's copy of a
//! query, ever runs over the server's own connection. Each statement runs as any
//! template's does, in a read-only transaction on a session that's read-only. Its
//! series are on the server's own host, under [`INSTANCE`], and its templates'
//! alerts, with any changes people made to them, apply as to any host.
//!
//! The account is the server's own, which has to be able to write, so what it may
//! do beyond reading isn't reported, as it always could. To read MaxNines' database
//! with templates of your own, add a database check with a monitoring account.
//!
//! SQLite isn't read, as no template is for it, and nothing runs while the server
//! has no built-in template for its database's kind.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use maxnines_checks::Credentials;
use maxnines_checks::databases as stats;
use maxnines_checks::templates::reader::{Reader, Results};
use maxnines_protocol::templates::work::{ACCOUNTS, TemplateWork};
use maxnines_protocol::templates::{Target, Template};
use maxnines_protocol::{Check, CheckKind};
use serde_json::{Map, Value};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::warn;

use super::agentless::{Saving, save_read};
use super::values::{LastSent, QueryValues, worked_out};
use super::work::database_work;
use crate::models::Database;
use crate::remote_checks::{LOCAL_HOST_ID, LOCAL_HOSTNAME};
use crate::store::WriterCommand;

/// What the server's own database is called on its host's charts.
pub const INSTANCE: &str = "maxnines";

/// How often what's been read is saved, as often as the server's other stats.
const EVERY: Duration = Duration::from_secs(15);

/// Where the main database is and how to sign in to it, from its URL, for a kind
/// templates can read: `None` for SQLite.
pub fn database_of(url: &str) -> Result<Option<stats::Database>> {
    let parsed = url::Url::parse(url).context("reading the database url")?;
    let Some((kind, port)) = kind_of(parsed.scheme()) else {
        if parsed.scheme() == "sqlite" {
            return Ok(None);
        }
        bail!("{} databases can't be read by templates", parsed.scheme());
    };
    let Some(host) = parsed.host_str().filter(|host| !host.is_empty()) else {
        bail!("the database url has no host, as for a socket, which templates can't reach");
    };
    let decoded = |text: &str| {
        percent_encoding::percent_decode_str(text)
            .decode_utf8()
            .map(|text| text.into_owned())
    };
    let mut check = Check::new(
        INSTANCE,
        kind,
        &format!("{host}:{}", parsed.port().unwrap_or(port)),
    );
    let name = parsed.path().trim_start_matches('/');
    if !name.is_empty() {
        check.database = Some(decoded(name)?);
    }
    let required = parsed.query_pairs().any(|(name, value)| {
        matches!(
            (&*name.to_ascii_lowercase(), &*value.to_ascii_lowercase()),
            ("sslmode", "require" | "verify-ca" | "verify-full")
                | ("ssl-mode", "required" | "verify_ca" | "verify_identity")
        )
    });
    if required {
        check.tls = Some(true);
    }
    let username = Some(decoded(parsed.username())?).filter(|name| !name.is_empty());
    let password = parsed.password().map(decoded).transpose()?;
    Ok(Some(stats::Database {
        check,
        credentials: Credentials {
            username,
            password,
            private_key: None,
        },
    }))
}

/// The kind of database a URL's scheme says, and the port it's on unless it says,
/// for a kind templates can read.
fn kind_of(scheme: &str) -> Option<(CheckKind, u16)> {
    match scheme {
        "postgres" | "postgresql" => Some((CheckKind::Postgres, 5432)),
        "mysql" | "mariadb" => Some((CheckKind::Mysql, 3306)),
        _ => None,
    }
}

/// Starts reading the server's own database, at `url`, if this server has any
/// built-in templates for its kind, which nothing else ever changes.
pub fn start(url: &str, database: Database, writer: mpsc::Sender<WriterCommand>) {
    let Some((kind, _)) = url::Url::parse(url)
        .ok()
        .and_then(|parsed| kind_of(parsed.scheme()))
    else {
        return;
    };
    let built_in = match super::built_in::all() {
        Ok(built_in) => built_in.into_iter().map(|one| one.template).collect(),
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "reading the built-in templates failed"
            );
            return;
        }
    };
    let templates = for_kind(built_in, kind);
    if templates.is_empty() {
        return;
    }
    match database_of(url) {
        Ok(Some(own)) => spawn(templates, own, database, writer),
        Ok(None) => {}
        Err(error) => warn!(
            error = format!("{error:#}"),
            "the server's own database can't be read with its templates"
        ),
    }
}

/// The built-in templates for a kind of database that are on as they ship.
pub fn for_kind(built_in: Vec<Template>, kind: CheckKind) -> Vec<Template> {
    built_in
        .into_iter()
        .filter(|template| {
            template.enabled
                && matches!(&template.target, Some(Target::Database(of)) if of == kind.as_str())
        })
        .collect()
}

/// What's read of the server's own database: each template's discover blocks, and
/// its queries as what discovery found on it picks, by template key.
fn work(templates: &[Template], found: &BTreeMap<String, Map<String, Value>>) -> Vec<TemplateWork> {
    templates
        .iter()
        .map(|template| database_work(template, INSTANCE, found.get(&template.key)))
        .collect()
}

/// Reads the server's own database with `templates` until the server stops, on
/// the runtime it's started on. With none, nothing's read.
fn spawn(
    templates: Vec<Template>,
    own: stats::Database,
    database: Database,
    writer: mpsc::Sender<WriterCommand>,
) {
    if templates.is_empty() {
        return;
    }
    let mut reading = OwnReader::new(templates, own, database, writer);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(EVERY);
        every.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            if let Err(error) = reading.read_once(EVERY).await {
                warn!(
                    error = format!("{error:#}"),
                    "reading the server's own database failed"
                );
            }
        }
    });
}

/// What reading the server's own database keeps between rounds.
pub struct OwnReader {
    templates: Vec<Template>,
    /// The metrics they work out with CEL, as they ship.
    values: Vec<QueryValues>,
    own: stats::Database,
    database: Database,
    writer: mpsc::Sender<WriterCommand>,
    reader: Reader,
    results: Results,
    sent: Mutex<Vec<TemplateWork>>,
    last_sent: Mutex<LastSent>,
}

impl OwnReader {
    pub fn new(
        templates: Vec<Template>,
        own: stats::Database,
        database: Database,
        writer: mpsc::Sender<WriterCommand>,
    ) -> Self {
        let reader = Reader::new();
        Self {
            values: templates.iter().flat_map(worked_out).collect(),
            templates,
            own,
            database,
            writer,
            results: reader.results(),
            reader,
            sent: Mutex::default(),
            last_sent: Mutex::default(),
        }
    }

    /// Saves what was read since last time, then says what to read next, each
    /// query every `every` unless it says.
    pub async fn read_once(&mut self, every: Duration) -> Result<()> {
        let mut entries = self.results.take();
        // Its account is the server's, which always can do more than read.
        entries.remove(ACCOUNTS);
        let to = Saving {
            database: &self.database,
            writer: &self.writer,
            host_id: LOCAL_HOST_ID.to_string(),
            hostname: LOCAL_HOSTNAME.to_string(),
        };
        save_read(entries, &self.sent, &self.last_sent, &self.values, to).await;

        let running = self.database.running_templates();
        let found: BTreeMap<String, Map<String, Value>> = self
            .database
            .discoveries(LOCAL_HOST_ID)
            .await?
            .into_iter()
            .filter(|((_, name), _)| name == INSTANCE)
            .filter_map(|((id, _), values)| Some((running.get(id)?.template().key.clone(), values)))
            .collect();
        let work = work(&self.templates, &found);
        let own = &self.own;
        self.reader
            .update(&work, every, &Handle::current(), |_| Ok(own.clone()));
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = work;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_main_database_is_found_from_its_url() {
        let database =
            database_of("postgres://monitor:p%40ss@db.internal:6543/maxnines?sslmode=require")
                .unwrap()
                .unwrap();
        assert_eq!(database.check.kind, CheckKind::Postgres);
        assert_eq!(database.check.name, INSTANCE);
        assert_eq!(database.check.target, "db.internal:6543");
        assert_eq!(database.check.database.as_deref(), Some("maxnines"));
        assert_eq!(database.check.tls, Some(true));
        assert_eq!(database.credentials.username.as_deref(), Some("monitor"));
        assert_eq!(database.credentials.password.as_deref(), Some("p@ss"));

        let mysql = database_of("mysql://root@127.0.0.1/maxnines")
            .unwrap()
            .unwrap();
        assert_eq!(mysql.check.kind, CheckKind::Mysql);
        assert_eq!(mysql.check.target, "127.0.0.1:3306");
        assert_eq!(mysql.check.tls, None);
        assert_eq!(mysql.credentials.password, None);

        let ipv6 = database_of("postgresql://u@[::1]/m").unwrap().unwrap();
        assert_eq!(ipv6.check.target, "[::1]:5432");

        assert!(
            database_of("sqlite://maxnines.sqlite?mode=rwc")
                .unwrap()
                .is_none()
        );
        assert!(database_of("postgres:///maxnines?host=/var/run/postgresql").is_err());
        assert!(database_of("redis://cache").is_err());
    }

    #[test]
    fn only_built_in_templates_for_its_kind_that_ship_on_are_read() {
        let parse = |text: &str| maxnines_protocol::templates::parse(text).unwrap();
        let postgres = parse(
            r#"template "pg" {
                 name     = "PG"
                 database = "postgres"
               }"#,
        );
        let mut off = parse(
            r#"template "pg_off" {
                 name     = "PG off"
                 database = "postgres"
               }"#,
        );
        off.enabled = false;
        let mysql = parse(
            r#"template "my" {
                 name     = "My"
                 database = "mysql"
               }"#,
        );
        let host = parse(
            r#"template "host" {
                 name = "Host"
               }"#,
        );
        let kept = for_kind(vec![postgres, off, mysql, host], CheckKind::Postgres);
        let keys: Vec<&str> = kept.iter().map(|t| t.key.as_str()).collect();
        assert_eq!(keys, ["pg"]);
    }
}
