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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use maxnines_checks::{Credentials, limit, run_signed_in, timed_out_report};
use maxnines_protocol::{Check, CheckKind, LocalCheck, MAX_CHECK_NAME_LEN, is_check_name};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::background::Background;
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
pub fn load_check_definitions(definitions: &mut CheckDefinitions) -> Result<()> {
    ensure!(
        definitions.len() <= MAX_DEFINED,
        "the config can define at most {MAX_DEFINED} checks"
    );
    for (name, definition) in definitions.iter_mut() {
        let problem = |what: &str| anyhow!("check {name:?} in the agent's config {what}");
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
        ensure!(
            definition
                .username
                .as_deref()
                .is_some_and(|username| !username.is_empty())
                || definition.password.is_some(),
            problem("needs a username or a password")
        );
        ensure!(
            definition.password.is_none() || definition.private_key_file.is_none(),
            problem("has a password or a private key, not both")
        );
        ensure!(
            definition.private_key_file.is_none() || check.kind == CheckKind::Ssh,
            problem("can only sign in with a private key if it's an SSH check")
        );
        if let Some(path) = &definition.private_key_file {
            let key = std::fs::read_to_string(path).with_context(|| {
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
            .map(|check| Ready::Run(Box::new(check), None))
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
            let (every, limit) = (every(check.interval, interval), limit(&check) + GRACE);
            let check = Arc::new((check, credentials));
            background.repeat(
                every,
                Some(limit),
                move || {
                    let check = check.clone();
                    async move { run_signed_in(&check.0, check.1.as_ref()).await }
                },
                move |found| found.unwrap_or_else(|| late.clone()),
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
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    use super::*;

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
            // Redis before version 6 has only a password.
            (
                "cache".to_string(),
                CheckDefinition {
                    username: None,
                    ..defined("redis", "127.0.0.1:6379")
                },
            ),
        ]);
        load_check_definitions(&mut definitions).unwrap();
        let read = definitions["bastion"].private_key.as_deref().unwrap();
        assert!(read.contains("OPENSSH"));
        assert!(!format!("{:?}", definitions["mail"]).contains("s3cret"));

        for (bad, why) in [
            (defined("tcp", "a:1"), "never signs in"),
            (defined("gopher", "a:1"), "isn't a kind of check"),
            (defined("imap", "noport"), "host:port"),
            (
                CheckDefinition {
                    username: None,
                    password: None,
                    ..defined("imap", "a:1")
                },
                "needs a username or a password",
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
                load_check_definitions(&mut definitions).unwrap_err()
            );
            assert!(error.contains(why), "{error}");
        }
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
        let definitions = CheckDefinitions::from([(
            "cache".to_string(),
            CheckDefinition {
                username: None,
                ..defined("redis", &target)
            },
        )]);
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
        // It went where the config says, as a Redis check.
        assert_eq!(row("cache")["kind"], "redis", "{output}");
        assert!(reached.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert_eq!(
            row("nowhere"),
            json!({ "name": "nowhere", "up": 0, "error": "the agent's config has no check named \"nowhere\"" })
        );
    }
}
