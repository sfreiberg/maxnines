//! The checks collector. The checks themselves are in `maxnines_checks`, as the
//! server runs them too.
//!
//! A config rule gives two sorts. Checks with nothing secret, such as a website's,
//! come whole from the server. Checks that sign in, such as of an SSH or mail
//! server, are `check` blocks in the agent's own config, with where they reach
//! and how they sign in, and the server only picks which of those to run and how
//! often. So a login never comes from the server, never goes to it, and is only
//! ever sent where the agent's own config says.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use maxnines_checks::{Credentials, failed_report, limit, run_signed_in, timed_out_report};
use maxnines_collectors::entries::{Entries, at, filled, percent};
use maxnines_protocol::entries::Entry;
use maxnines_protocol::{Check, CheckKind, LocalCheck, MAX_CHECK_NAME_LEN, is_check_name};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::background::{Background, FAILED_UNEXPECTEDLY};
use crate::collector::Collector;

/// How long a check gets to report once its own time limit is up.
const GRACE: Duration = Duration::from_secs(1);

/// How many checks the agent's config can define.
const MAX_DEFINED: usize = 64;

/// A check the agent's config allows, with how it signs in:
///
/// ```hcl
/// check "bastion" {
///   kind             = "ssh"
///   target           = "bastion.example.com:22"
///   username         = "monitor"
///   private_key_file = "/etc/maxnines/bastion_key"
///   host_key         = "SHA256:Dfij..."
/// }
///
/// check "mail" {
///   kind     = "imap"
///   target   = "mail.example.com:993"
///   tls      = true
///   username = "monitor@example.com"
///   password = env("MAIL_PASSWORD")
/// }
/// ```
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckDefinition {
    kind: String,
    target: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// For SSH: a private key in OpenSSH's format, without a passphrase.
    #[serde(default)]
    private_key_file: Option<PathBuf>,
    /// The key itself, read when the config is.
    #[serde(skip)]
    private_key: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    insecure: Option<bool>,
    #[serde(default)]
    host_key: Option<String>,
    /// For MQTT: where to send a test message.
    #[serde(default)]
    topic: Option<String>,
}

impl fmt::Debug for CheckDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckDefinition")
            .field("kind", &self.kind)
            .field("target", &self.target)
            .field("username", &self.username)
            .field("private_key_file", &self.private_key_file)
            .finish_non_exhaustive()
    }
}

impl CheckDefinition {
    /// The check, timed as the server asks.
    fn check(&self, name: &str, timing: &LocalCheck) -> Result<Check> {
        let kind = CheckKind::parse(&self.kind)
            .with_context(|| format!("{:?} isn't a kind of check", self.kind))?;
        let mut check = Check::new(name, kind, &self.target);
        check.tls = self.tls;
        check.insecure = self.insecure;
        check.host_key = self.host_key.clone();
        check.topic = self.topic.clone();
        check.timeout = timing.timeout;
        check.interval = timing.interval;
        Ok(check)
    }

    fn credentials(&self) -> Option<Credentials> {
        let credentials = Credentials {
            username: self.username.clone(),
            password: self.password.clone(),
            private_key: self.private_key.clone(),
        };
        (credentials != Credentials::default()).then_some(credentials)
    }
}

/// The checks the agent's config allows, by name.
pub type CheckDefinitions = BTreeMap<String, CheckDefinition>;

/// Checks each definition, and reads any key file, so a mistake stops the agent
/// starting rather than every check failing later.
/// A relative key file is from `folder`, the config file's.
pub fn load_check_definitions(definitions: &mut CheckDefinitions, folder: &Path) -> Result<()> {
    ensure!(
        definitions.len() <= MAX_DEFINED,
        "the config can define at most {MAX_DEFINED} checks"
    );
    for (name, definition) in definitions.iter_mut() {
        let problem = |what: &str| anyhow!("check {name:?} in the agent's config {what}");
        // An empty one, as from an environment variable that isn't set, is none, so
        // it's never sent, and never stands in the way of a key.
        for given in [&mut definition.username, &mut definition.password] {
            if given.as_deref() == Some("") {
                *given = None;
            }
        }
        ensure!(
            is_check_name(name),
            problem(&format!(
                "needs a name of up to {MAX_CHECK_NAME_LEN} characters that isn't blank \
                 and has no control characters, such as tabs"
            ))
        );
        let check = definition
            .check(name, &LocalCheck::new(name))
            .map_err(|error| problem(&format!("has a problem: {error:#}")))?;
        // Anything without a login is better given whole by the server.
        ensure!(
            check.kind.signs_in(),
            problem("is a kind that never signs in, so give it in a config rule instead")
        );
        // Reading a database's stats says it's up and that it can be signed in to.
        ensure!(
            !maxnines_checks::databases::is_database(check.kind),
            problem("is a database, so give it as a database block, which reads its stats too")
        );
        check.validate()?;
        let username = definition.username.is_some();
        let secret = definition.password.is_some() || definition.private_key_file.is_some();
        ensure!(
            username || secret,
            problem("needs a username or a password")
        );
        ensure!(
            definition.password.is_none() || definition.private_key_file.is_none(),
            problem("has a password or a private key, not both")
        );
        ensure!(
            definition.private_key_file.is_none()
                || check.kind.sign_in().is_some_and(|needs| needs.key),
            problem("can only sign in with a private key if it's an SSH check")
        );
        if let Some(why) = maxnines_checks::sign_in_problem(&check, username, secret) {
            return Err(problem(&format!("can never sign in: {why}")));
        }
        if let Some(path) = &mut definition.private_key_file {
            *path = folder.join(&*path);
            let key = std::fs::read_to_string(&*path).with_context(|| {
                format!(
                    "reading the private key for check {name:?} from {}",
                    path.display()
                )
            })?;
            definition.private_key = Some(key);
        }
    }
    Ok(())
}

pub struct CheckCollector {
    background: Background,
}

/// A check ready to run, or why one the server asked for can't.
enum Ready {
    Run(Box<Check>, Option<Credentials>),
    Broken { name: String, why: String },
}

impl Ready {
    /// A check the server sent whole.
    fn sent(check: Check) -> Self {
        if check.kind == CheckKind::Unknown {
            return Self::Broken {
                name: check.name,
                why: CheckKind::UNKNOWN_MESSAGE.to_string(),
            };
        }
        Self::Run(Box::new(check), None)
    }

    fn local(choice: &LocalCheck, definitions: &CheckDefinitions) -> Self {
        let name = &choice.name;
        let Some(definition) = definitions.get(name) else {
            return Self::Broken {
                name: name.clone(),
                why: format!("the agent's config has no check named {name:?}"),
            };
        };
        match definition.check(name, choice) {
            Ok(check) => Self::Run(Box::new(check), definition.credentials()),
            Err(error) => Self::Broken {
                name: name.clone(),
                why: format!("{error:#}"),
            },
        }
    }
}

/// A check runs with every sample unless it asks for longer. It never runs more
/// often than samples are sent.
fn every(wanted: Option<Duration>, interval: Duration) -> Duration {
    wanted.unwrap_or(interval).max(interval)
}

impl CheckCollector {
    /// `checks` come whole from the server, and never sign in. `local` picks from
    /// the checks the agent's config defines. Each check's newest result goes with
    /// every sample until it runs again, so a page showing the newest sample still
    /// shows every check.
    pub fn new(
        checks: Vec<Check>,
        local: &[LocalCheck],
        definitions: &CheckDefinitions,
        interval: Duration,
    ) -> Result<Self> {
        let ready = checks
            .into_iter()
            .map(Ready::sent)
            .chain(local.iter().map(|choice| Ready::local(choice, definitions)));
        let mut background = Background::new();
        for item in ready {
            let (check, credentials) = match item {
                Ready::Run(check, credentials) => (check, credentials),
                Ready::Broken { name, why } => {
                    background.constant(json!({ "name": name, "up": 0, "error": why }));
                    continue;
                }
            };
            let late = timed_out_report(&check);
            let broke = failed_report(&check, FAILED_UNEXPECTEDLY);
            let (every, limit) = (every(check.interval, interval), limit(&check) + GRACE);
            let check = Arc::new((check, credentials));
            background.repeat(
                every,
                Some(limit),
                move || {
                    let check = check.clone();
                    async move { run_signed_in(&check.0, check.1.as_ref()).await }
                },
                move |found| found.unwrap_or_else(|missed| missed.pick(&late, &broke)),
            )?;
        }
        Ok(Self { background })
    }
}

impl Collector for CheckCollector {
    fn name(&self) -> &'static str {
        "checks"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.rows())
    }

    fn metrics(&self) -> &'static [&'static str] {
        &CHECK_METRICS
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let checks = output.as_array().map(Vec::as_slice).unwrap_or_default();
        let named = checks
            .iter()
            .filter_map(|check| Some((check.get("name")?.as_str()?, check)));
        for (name, check) in named {
            let series = [name];
            // One that couldn't be run doesn't say its kind, so any metric might
            // be its.
            let kind = at(check, "kind").as_str().and_then(CheckKind::parse);
            // Why the domain's registration couldn't be looked up, which is the
            // error of what the lookup would have said.
            let no_domain = filled(at(check, "domain_error")).as_str();
            for (metric, field, kinds) in &CHECK_FIELDS {
                let read = filled(at(check, field));
                let why = no_domain.filter(|_| read.is_null() && DOMAIN_METRICS.contains(metric));
                match why {
                    Some(why) => entries.error(metric, &series, why),
                    // What it found is said whatever its kind.
                    None if kinds.has(kind) || !read.is_null() => {
                        entries.read(metric, &series, read);
                    }
                    None => {}
                }
            }
            let usage = percent(
                at(check, "memory_used_bytes"),
                at(check, "memory_limit_bytes"),
            );
            if MEMCACHED.has(kind) || usage.is_some() {
                entries.number("check.memory_usage", &series, usage);
            }
        }
        // With no checks, none run yet, or none of the kind a metric is read from,
        // the metric has nothing.
        entries.fill(&CHECK_METRICS);
        entries.done()
    }
}

/// The kinds of check a metric is read from.
enum Kinds {
    Every,
    Only(&'static [CheckKind]),
    Except(&'static [CheckKind]),
}

impl Kinds {
    /// Whether a check of this kind reads the metric. One whose kind isn't known
    /// might.
    fn has(&self, kind: Option<CheckKind>) -> bool {
        let Some(kind) = kind else { return true };
        match self {
            Self::Every => true,
            Self::Only(kinds) => kinds.contains(&kind),
            Self::Except(kinds) => !kinds.contains(&kind),
        }
    }
}

/// Every kind that opens a connection of its own, which looking up a name and
/// pinging don't.
const CONNECTS: Kinds = Kinds::Except(&[CheckKind::Dns, CheckKind::Ping]);
/// Every kind that can use TLS, and so reads a certificate.
const SECURED: Kinds = Kinds::Except(&[CheckKind::Tcp, CheckKind::Dns, CheckKind::Ping]);
/// Every kind that talks to the server it reaches in that server's own protocol,
/// and so can sign in to it or read what version it is.
const SIGNS_IN: Kinds = Kinds::Except(&[
    CheckKind::Tcp,
    CheckKind::Http,
    CheckKind::Tls,
    CheckKind::Dns,
    CheckKind::Ping,
]);
/// The kinds that ask whether TLS is offered without signing in.
const OFFERS_TLS: Kinds = Kinds::Only(&[
    CheckKind::Postgres,
    CheckKind::Smtp,
    CheckKind::Imap,
    CheckKind::Pop3,
    CheckKind::Ftp,
    CheckKind::Ldap,
]);
const HTTP: Kinds = Kinds::Only(&[CheckKind::Http]);
const DNS: Kinds = Kinds::Only(&[CheckKind::Dns]);
const PING: Kinds = Kinds::Only(&[CheckKind::Ping]);
const SSH: Kinds = Kinds::Only(&[CheckKind::Ssh]);
const MEMCACHED: Kinds = Kinds::Only(&[CheckKind::Memcached]);
const LDAP: Kinds = Kinds::Only(&[CheckKind::Ldap]);
const MQTT: Kinds = Kinds::Only(&[CheckKind::Mqtt]);

/// A check's metrics that are read as they are, what each is read from, and the
/// kinds of check that read it. Being down is a value of `check.up`, and why is
/// the text of `check.error`, as a check that's down has still found things out.
const CHECK_FIELDS: [(&str, &str, Kinds); 40] = [
    ("check.up", "up", Kinds::Every),
    ("check.kind", "kind", Kinds::Every),
    ("check.error", "error", Kinds::Every),
    ("check.response", "response_secs", Kinds::Every),
    ("check.dns", "dns_secs", Kinds::Every),
    ("check.connect", "connect_secs", CONNECTS),
    ("check.tls", "tls_secs", SECURED),
    ("check.tls_version", "tls_version", SECURED),
    ("check.cert_valid", "cert_valid", SECURED),
    ("check.hostname_valid", "hostname_valid", SECURED),
    ("check.cert_valid_from", "cert_valid_from", SECURED),
    ("check.cert_valid_until", "cert_valid_until", SECURED),
    ("check.cert_days", "cert_days_left", SECURED),
    ("check.tls_offered", "tls_offered", OFFERS_TLS),
    ("check.server_version", "server_version", SIGNS_IN),
    ("check.signed_in", "signed_in", SIGNS_IN),
    ("check.first_byte", "first_byte_secs", HTTP),
    ("check.download", "download_secs", HTTP),
    ("check.status", "status", HTTP),
    ("check.protocol", "protocol", HTTP),
    ("check.size", "content_length", HTTP),
    ("check.compressed", "compressed", HTTP),
    ("check.regex_matched", "regex_matched", HTTP),
    ("check.domain_days", "domain_days_left", HTTP),
    ("check.domain_expires_at", "domain_expires_at", HTTP),
    ("check.records", "records", DNS),
    ("check.packet_loss", "packet_loss_percent", PING),
    ("check.rtt_min", "rtt_min_secs", PING),
    ("check.rtt_max", "rtt_max_secs", PING),
    ("check.rtt_stddev", "rtt_stddev_secs", PING),
    ("check.host_key", "host_key", SSH),
    ("check.sign_in_methods", "sign_in_methods", SSH),
    ("check.password_sign_in", "password_sign_in", SSH),
    ("check.hit_rate", "hit_rate_percent", MEMCACHED),
    ("check.memory_used", "memory_used_bytes", MEMCACHED),
    ("check.memory_limit", "memory_limit_bytes", MEMCACHED),
    ("check.evictions", "evictions", MEMCACHED),
    ("check.connections", "connections", MEMCACHED),
    ("check.search", "search_secs", LDAP),
    ("check.round_trip", "round_trip_secs", MQTT),
];

/// What looking up a domain's registration says, which have why it couldn't be
/// looked up as their error.
const DOMAIN_METRICS: [&str; 2] = ["check.domain_days", "check.domain_expires_at"];

/// Every metric a check has: those read as they are, then the share of its memory
/// Memcached uses, which is worked out.
const CHECK_METRICS: [&str; 41] = {
    let mut metrics = ["check.memory_usage"; 41];
    let mut at = 0;
    while at < CHECK_FIELDS.len() {
        metrics[at] = CHECK_FIELDS[at].0;
        at += 1;
    }
    metrics
};

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    use super::*;
    use crate::collector::test_entries::{every_metric_has_an_entry, said, time};

    /// Running nothing, so nothing is reached.
    fn checking_nothing() -> CheckCollector {
        CheckCollector::new(
            Vec::new(),
            &[],
            &CheckDefinitions::new(),
            Duration::from_secs(3600),
        )
        .unwrap()
    }

    /// What the entries say of one check, without its name.
    fn said_of(entries: &[Entry], check: &str) -> Vec<(String, Value)> {
        let series = format!("[{check}]");
        said(entries)
            .into_iter()
            .filter_map(|(name, value)| Some((name.strip_suffix(&series)?.to_string(), value)))
            .collect()
    }

    #[test]
    fn check_entries_have_a_series_for_each_check_with_the_metrics_of_its_kind() {
        let collector = checking_nothing();
        let output = json!([
            { "name": "port", "kind": "tcp", "up": 1, "response_secs": 0.02,
              "dns_secs": 0.001, "connect_secs": 0.019 },
            // Down, with what it found out before it failed.
            { "name": "site", "kind": "http", "up": 0, "error": "it answered 503",
              "dns_secs": 0.001, "connect_secs": 0.01, "tls_secs": 0.03,
              "first_byte_secs": 0.2, "download_secs": 0.01, "status": 503,
              "protocol": "HTTP/2.0", "content_length": 512, "compressed": true,
              "tls_version": "TLS 1.3", "cert_valid": true, "hostname_valid": true,
              "cert_valid_from": "2026-10-01T00:00:00Z",
              "cert_valid_until": "2026-12-30T00:00:00Z", "cert_days_left": 32,
              "domain_error": "the registry didn't answer in time" },
            { "name": "cache", "kind": "memcached", "up": 1, "response_secs": 0.01,
              "server_version": "1.6.31", "hit_rate_percent": 90.0, "evictions": 4,
              "memory_used_bytes": 250, "memory_limit_bytes": 1000, "connections": 3 },
            // One without a name can't be told from the others.
            { "kind": "tcp", "up": 1 },
        ]);
        let entries = collector.entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said_of(&entries, "port"),
            [
                (of("check.up"), json!(1)),
                (of("check.kind"), json!("tcp")),
                (of("check.error"), Value::Null),
                (of("check.response"), json!(0.02)),
                (of("check.dns"), json!(0.001)),
                (of("check.connect"), json!(0.019)),
            ]
        );
        assert_eq!(
            said_of(&entries, "site"),
            [
                // Down is what it found, and why is said beside it.
                (of("check.up"), json!(0)),
                (of("check.kind"), json!("http")),
                (of("check.error"), json!("it answered 503")),
                (of("check.response"), Value::Null),
                (of("check.dns"), json!(0.001)),
                (of("check.connect"), json!(0.01)),
                (of("check.tls"), json!(0.03)),
                (of("check.tls_version"), json!("TLS 1.3")),
                (of("check.cert_valid"), json!(true)),
                (of("check.hostname_valid"), json!(true)),
                (of("check.cert_valid_from"), json!("2026-10-01T00:00:00Z")),
                (of("check.cert_valid_until"), json!("2026-12-30T00:00:00Z")),
                (of("check.cert_days"), json!(32)),
                (of("check.first_byte"), json!(0.2)),
                (of("check.download"), json!(0.01)),
                (of("check.status"), json!(503)),
                (of("check.protocol"), json!("HTTP/2.0")),
                (of("check.size"), json!(512)),
                (of("check.compressed"), json!(true)),
                (of("check.regex_matched"), Value::Null),
                // Why the registration couldn't be looked up is the error of what
                // looking it up would have said.
                (
                    of("check.domain_days"),
                    json!({ "error": "the registry didn't answer in time" })
                ),
                (
                    of("check.domain_expires_at"),
                    json!({ "error": "the registry didn't answer in time" })
                ),
            ]
        );
        assert_eq!(
            said_of(&entries, "cache"),
            [
                (of("check.up"), json!(1)),
                (of("check.kind"), json!("memcached")),
                (of("check.error"), Value::Null),
                (of("check.response"), json!(0.01)),
                (of("check.dns"), Value::Null),
                (of("check.connect"), Value::Null),
                (of("check.tls"), Value::Null),
                (of("check.tls_version"), Value::Null),
                (of("check.cert_valid"), Value::Null),
                (of("check.hostname_valid"), Value::Null),
                (of("check.cert_valid_from"), Value::Null),
                (of("check.cert_valid_until"), Value::Null),
                (of("check.cert_days"), Value::Null),
                (of("check.server_version"), json!("1.6.31")),
                (of("check.signed_in"), Value::Null),
                (of("check.hit_rate"), json!(90.0)),
                (of("check.memory_used"), json!(250)),
                (of("check.memory_limit"), json!(1000)),
                (of("check.evictions"), json!(4)),
                (of("check.connections"), json!(3)),
                (of("check.memory_usage"), json!(25.0)),
            ]
        );
        // The metrics no check here is of the kind for have nothing.
        let unread: Vec<(String, Value)> = said(&entries)
            .into_iter()
            .filter(|(name, _)| !name.contains('['))
            .collect();
        assert_eq!(
            unread,
            [
                (of("check.tls_offered"), Value::Null),
                (of("check.records"), Value::Null),
                (of("check.packet_loss"), Value::Null),
                (of("check.rtt_min"), Value::Null),
                (of("check.rtt_max"), Value::Null),
                (of("check.rtt_stddev"), Value::Null),
                (of("check.host_key"), Value::Null),
                (of("check.sign_in_methods"), Value::Null),
                (of("check.password_sign_in"), Value::Null),
                (of("check.search"), Value::Null),
                (of("check.round_trip"), Value::Null),
            ]
        );
        every_metric_has_an_entry(&collector, &entries);

        // With no checks, or none run yet, each metric has nothing.
        for output in [json!([]), Value::Null] {
            let none = collector.entries(&output, time());
            let nothing: Vec<(String, Value)> = CHECK_METRICS
                .iter()
                .map(|metric| (metric.to_string(), Value::Null))
                .collect();
            assert_eq!(said(&none), nothing);
            every_metric_has_an_entry(&collector, &none);
        }
    }

    #[test]
    fn a_check_says_what_it_found_whatever_its_kind_and_one_of_no_kind_might_say_anything() {
        let collector = checking_nothing();
        let output = json!([
            // Not something a TCP check finds out, but it's there.
            { "name": "port", "kind": "tcp", "up": 1, "records": 2,
              "memory_used_bytes": 1, "memory_limit_bytes": 4 },
            // One the agent couldn't run says only that, and why.
            { "name": "nowhere", "up": 0, "error": "the agent's config has no check named \"nowhere\"" },
        ]);
        let entries = collector.entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said_of(&entries, "port"),
            [
                (of("check.up"), json!(1)),
                (of("check.kind"), json!("tcp")),
                (of("check.error"), Value::Null),
                (of("check.response"), Value::Null),
                (of("check.dns"), Value::Null),
                (of("check.connect"), Value::Null),
                (of("check.records"), json!(2)),
                (of("check.memory_used"), json!(1)),
                (of("check.memory_limit"), json!(4)),
                (of("check.memory_usage"), json!(25.0)),
            ]
        );
        let nowhere = said_of(&entries, "nowhere");
        let metrics: Vec<&str> = nowhere.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(metrics, CHECK_METRICS);
        for (metric, value) in &nowhere {
            let expected = match metric.as_str() {
                "check.up" => json!(0),
                "check.error" => json!("the agent's config has no check named \"nowhere\""),
                _ => Value::Null,
            };
            assert_eq!(value, &expected, "{metric}");
        }
        every_metric_has_an_entry(&collector, &entries);
    }

    #[test]
    fn what_a_check_that_never_finished_reports_becomes_entries() {
        let collector = checking_nothing();
        let ping = Check::new("gateway", CheckKind::Ping, "192.0.2.1");
        let web = Check::new("site", CheckKind::Http, "https://example.com/");
        let output = json!([
            timed_out_report(&ping),
            failed_report(&web, FAILED_UNEXPECTEDLY)
        ]);
        let entries = collector.entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said_of(&entries, "gateway"),
            [
                (of("check.up"), json!(0)),
                (of("check.kind"), json!("ping")),
                (of("check.error"), json!("timed out")),
                (of("check.response"), Value::Null),
                (of("check.dns"), Value::Null),
                (of("check.packet_loss"), Value::Null),
                (of("check.rtt_min"), Value::Null),
                (of("check.rtt_max"), Value::Null),
                (of("check.rtt_stddev"), Value::Null),
            ]
        );
        let site = said_of(&entries, "site");
        assert_eq!(site[0], (of("check.up"), json!(0)));
        assert_eq!(site[2], (of("check.error"), json!(FAILED_UNEXPECTEDLY)));
        every_metric_has_an_entry(&collector, &entries);
    }

    #[test]
    fn running_no_checks_really_collects_nothing_for_each_metric() {
        let mut collector = checking_nothing();
        let output = collector.collect().unwrap();
        assert_eq!(output, json!([]));
        every_metric_has_an_entry(&collector, &collector.entries(&output, time()));
    }

    #[test]
    fn the_collector_reports_what_its_checks_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let check = Check::new("a", CheckKind::Tcp, &target);
        let mut collector = CheckCollector::new(
            vec![check],
            &[],
            &CheckDefinitions::new(),
            Duration::from_millis(20),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let output = collector.collect().unwrap();
            if output[0]["up"] == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "{output}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A newer server can add a kind of check without the other checks stopping.
    #[test]
    fn a_check_of_a_kind_it_does_not_know_says_so_and_the_others_run() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let config: maxnines_protocol::AgentConfig = serde_json::from_value(json!({
            "collectors": { "checks": { "checks": [
                { "name": "burrow", "kind": "gopher", "target": "gopher.example.com:70" },
                { "name": "port", "kind": "tcp", "target": target },
            ] } },
        }))
        .unwrap();
        config.validate_sent().unwrap();
        let checks = config.collectors["checks"].checks.clone().unwrap();
        let mut collector = CheckCollector::new(
            checks,
            &[],
            &CheckDefinitions::new(),
            Duration::from_millis(20),
        )
        .unwrap();

        let output = collect_until(&mut collector, |output| {
            output
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["up"] == 1))
        });
        let row = |name: &str| {
            output
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == name)
                .unwrap()
                .clone()
        };
        assert_eq!(row("port")["up"], 1, "{output}");
        assert_eq!(row("burrow")["up"], 0, "{output}");
        assert_eq!(
            row("burrow")["error"],
            CheckKind::UNKNOWN_MESSAGE,
            "{output}"
        );
        assert!(CheckKind::UNKNOWN_MESSAGE.contains("upgrading"));
    }

    #[test]
    fn a_check_runs_as_often_as_it_asks_but_never_more_than_samples_are_sent() {
        let interval = Duration::from_secs(15);
        assert_eq!(every(None, interval), interval);
        assert_eq!(every(Some(Duration::from_secs(1)), interval), interval);
        assert_eq!(
            every(Some(Duration::from_secs(61)), interval),
            Duration::from_secs(61)
        );
    }

    /// The names of the checks in one sample.
    fn names(output: &Value) -> Vec<String> {
        output
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|result| result["name"].as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn a_slower_check_runs_less_often_and_keeps_its_result_between_runs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let fast = Check::new("fast", CheckKind::Tcp, &target);
        // Once a second, where the fast one runs every 20ms.
        let slow = Check {
            interval: Some(Duration::from_secs(1)),
            ..Check::new("slow", CheckKind::Tcp, &target)
        };
        let mut collector = CheckCollector::new(
            vec![fast, slow],
            &[],
            &CheckDefinitions::new(),
            Duration::from_millis(20),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while names(&collector.collect().unwrap()) != ["fast", "slow"] {
            assert!(Instant::now() < deadline, "the slow check never ran");
            thread::sleep(Duration::from_millis(5));
        }
        // Still there on later samples, though it hasn't run again.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(names(&collector.collect().unwrap()), ["fast", "slow"]);
    }

    /// Somewhere to connect to that counts the connections.
    fn counted() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = count.clone();
        thread::spawn(move || {
            for _ in listener.incoming() {
                counting.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        (target, count)
    }

    #[test]
    fn a_slower_check_reaches_its_target_less_often() {
        use std::sync::atomic::Ordering::Relaxed;

        let (fast_target, fast) = counted();
        let (slow_target, slow) = counted();
        let checks = vec![
            Check::new("fast", CheckKind::Tcp, &fast_target),
            Check {
                interval: Some(Duration::from_secs(1)),
                ..Check::new("slow", CheckKind::Tcp, &slow_target)
            },
        ];
        let started = Instant::now();
        let _collector = CheckCollector::new(
            checks,
            &[],
            &CheckDefinitions::new(),
            Duration::from_millis(20),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        while fast.load(Relaxed) < 20 {
            assert!(Instant::now() < deadline, "the fast check stopped");
            thread::sleep(Duration::from_millis(5));
        }
        // The slow one runs once a second, wherever in the first its turn falls.
        // Running it with every sample would make it about as many as the fast one.
        let slow_runs = slow.load(Relaxed) as u64;
        let fast_runs = fast.load(Relaxed);
        let seconds = started.elapsed().as_secs();
        assert!(
            slow_runs <= 1 + seconds,
            "{slow_runs} slow, {fast_runs} fast in {seconds}s"
        );
    }

    fn defined(kind: &str, target: &str) -> CheckDefinition {
        CheckDefinition {
            kind: kind.to_string(),
            target: target.to_string(),
            username: Some("monitor".to_string()),
            password: Some("s3cret".to_string()),
            private_key_file: None,
            private_key: None,
            tls: None,
            insecure: None,
            host_key: None,
            topic: None,
        }
    }

    #[test]
    fn a_defined_check_signs_in_one_way_and_its_key_is_read_at_once() {
        let folder = tempfile::tempdir().unwrap();
        let key = folder.path().join("key");
        std::fs::write(&key, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let mut definitions = CheckDefinitions::from([
            ("mail".to_string(), defined("imap", "mail.example.com:993")),
            (
                "bastion".to_string(),
                CheckDefinition {
                    password: None,
                    private_key_file: Some(key.clone()),
                    ..defined("ssh", "bastion.example.com:22")
                },
            ),
        ]);
        load_check_definitions(&mut definitions, Path::new("")).unwrap();
        let read = definitions["bastion"].private_key.as_deref().unwrap();
        assert!(read.contains("OPENSSH"));
        assert!(!format!("{:?}", definitions["mail"]).contains("s3cret"));

        for (bad, why) in [
            (defined("tcp", "a:1"), "never signs in"),
            (defined("gopher", "a:1"), "isn't a kind of check"),
            // Its database block reads whether it answers along with its stats.
            (
                defined("redis", "127.0.0.1:6379"),
                "give it as a database block",
            ),
            (defined("imap", "noport"), "host:port"),
            // A broker that can't upgrade to TLS is only sent a password on this host.
            (
                defined("mqtt", "mqtt.example.com:1883"),
                "can never sign in: a password is only sent without TLS",
            ),
            (
                CheckDefinition {
                    password: None,
                    ..defined("ldap", "ldap.example.com:389")
                },
                "can never sign in: signing in needs a password",
            ),
            (
                CheckDefinition {
                    username: None,
                    password: None,
                    ..defined("imap", "a:1")
                },
                "needs a username or a password",
            ),
            // As from an environment variable that isn't set.
            (
                CheckDefinition {
                    username: None,
                    password: Some(String::new()),
                    ..defined("imap", "a:1")
                },
                "needs a username or a password",
            ),
            (
                CheckDefinition {
                    password: None,
                    ..defined("ssh", "a:22")
                },
                "can never sign in: signing in needs a password or a private key",
            ),
            (
                CheckDefinition {
                    private_key_file: Some(key.clone()),
                    ..defined("ssh", "a:22")
                },
                "not both",
            ),
            (
                CheckDefinition {
                    password: None,
                    private_key_file: Some(folder.path().join("key")),
                    ..defined("imap", "a:993")
                },
                "only sign in with a private key if it's an SSH check",
            ),
            // A broker elsewhere without TLS would be refused for a password, but
            // what's wrong is the key.
            (
                CheckDefinition {
                    password: None,
                    private_key_file: Some(folder.path().join("key")),
                    ..defined("mqtt", "mqtt.example.com:1883")
                },
                "only sign in with a private key if it's an SSH check",
            ),
            (
                CheckDefinition {
                    password: None,
                    private_key_file: Some(folder.path().join("missing")),
                    ..defined("ssh", "a:22")
                },
                "reading the private key",
            ),
        ] {
            let mut definitions = CheckDefinitions::from([("x".to_string(), bad)]);
            let error = format!(
                "{:#}",
                load_check_definitions(&mut definitions, Path::new("")).unwrap_err()
            );
            assert!(error.contains(why), "{error}");
        }
    }

    /// As from `env("…", "")` with the variable unset, which is no password at all.
    #[test]
    fn an_empty_password_is_none() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(
            folder.path().join("key"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        let mut definitions = CheckDefinitions::from([
            (
                "bastion".to_string(),
                CheckDefinition {
                    password: Some(String::new()),
                    private_key_file: Some(PathBuf::from("key")),
                    ..defined("ssh", "bastion.example.com:22")
                },
            ),
            (
                "broker".to_string(),
                CheckDefinition {
                    password: Some(String::new()),
                    ..defined("mqtt", "127.0.0.1:1883")
                },
            ),
        ]);

        load_check_definitions(&mut definitions, folder.path()).unwrap();

        let broker = definitions["broker"].credentials().unwrap();
        assert_eq!(broker.username.as_deref(), Some("monitor"));
        assert_eq!(broker.password, None);
        assert_eq!(definitions["bastion"].password, None);
    }

    #[test]
    fn a_relative_key_file_is_from_the_config_files_folder() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(
            folder.path().join("key"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        let mut definitions = CheckDefinitions::from([(
            "bastion".to_string(),
            CheckDefinition {
                password: None,
                private_key_file: Some(PathBuf::from("key")),
                ..defined("ssh", "bastion.example.com:22")
            },
        )]);

        load_check_definitions(&mut definitions, folder.path()).unwrap();

        let bastion = &definitions["bastion"];
        assert!(bastion.private_key.as_deref().unwrap().contains("OPENSSH"));
        assert_eq!(bastion.private_key_file, Some(folder.path().join("key")));
    }

    fn collect_until(collector: &mut CheckCollector, done: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let output = collector.collect().unwrap();
            if done(&output) {
                return output;
            }
            assert!(Instant::now() < deadline, "gave up waiting: {output}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_rule_runs_the_checks_the_config_defines_and_only_those() {
        let (target, reached) = counted();
        let definitions = CheckDefinitions::from([("cache".to_string(), defined("smtp", &target))]);
        let local = [
            LocalCheck {
                timeout: Some(Duration::from_secs(1)),
                ..LocalCheck::new("cache")
            },
            LocalCheck::new("nowhere"),
        ];
        let mut collector =
            CheckCollector::new(Vec::new(), &local, &definitions, Duration::from_millis(50))
                .unwrap();

        let output = collect_until(&mut collector, |output| {
            output.as_array().is_some_and(|rows| rows.len() == 2)
        });
        let row = |name: &str| {
            output
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == name)
                .unwrap()
                .clone()
        };
        // It went where the config says, as a mail check.
        assert_eq!(row("cache")["kind"], "smtp", "{output}");
        assert!(reached.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert_eq!(
            row("nowhere"),
            json!({ "name": "nowhere", "up": 0, "error": "the agent's config has no check named \"nowhere\"" })
        );
    }
}
