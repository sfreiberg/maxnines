//! The checks collector. The checks themselves are in `maxnines_checks`, as the
//! server runs them too.
//!
//! A check that signs in, such as one of a database or an SSH server, gets its
//! username and password, or key, from a `check_login` block in the agent's own
//! config, named for the check. They never come from the server, and never go to
//! it.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use maxnines_checks::{Credentials, limit, run_signed_in, timed_out_report};
use maxnines_protocol::Check;
use serde::Deserialize;
use serde_json::Value;

use crate::background::{Background, probe_all};
use crate::collector::Collector;

/// How long a check gets to report once its own time limit is up.
const GRACE: Duration = Duration::from_secs(1);

/// How many checks the agent's config can give a login for.
const MAX_LOGINS: usize = 64;

/// How a check signs in, from the agent's own config:
///
/// ```hcl
/// check_login "orders-db" {
///   username = "maxnines"
///   password = env("ORDERS_DB_PASSWORD")
/// }
///
/// check_login "bastion" {
///   username         = "monitor"
///   private_key_file = "/etc/maxnines/bastion_key"
/// }
/// ```
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckLogin {
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
}

impl fmt::Debug for CheckLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckLogin")
            .field("username", &self.username)
            .field("private_key_file", &self.private_key_file)
            .finish_non_exhaustive()
    }
}

impl CheckLogin {
    fn credentials(&self) -> Credentials {
        Credentials {
            username: self.username.clone(),
            password: self.password.clone(),
            private_key: self.private_key.clone(),
        }
    }
}

/// The logins the agent's config gives, by the check's name.
pub type CheckLogins = BTreeMap<String, CheckLogin>;

/// Checks each login, and reads any key file, so a mistake stops the agent
/// starting rather than every check failing later.
pub fn load_check_logins(logins: &mut CheckLogins) -> Result<()> {
    ensure!(
        logins.len() <= MAX_LOGINS,
        "at most {MAX_LOGINS} checks can have a login"
    );
    for (name, login) in logins.iter_mut() {
        ensure!(
            login
                .username
                .as_deref()
                .is_some_and(|username| !username.is_empty())
                || login.password.is_some(),
            "the login for check {name:?} needs a username or a password"
        );
        ensure!(
            login.password.is_none() || login.private_key_file.is_none(),
            "the login for check {name:?} has a password or a private key, not both"
        );
        if let Some(path) = &login.private_key_file {
            let key = std::fs::read_to_string(path).with_context(|| {
                format!(
                    "reading the private key for check {name:?} from {}",
                    path.display()
                )
            })?;
            login.private_key = Some(key);
        }
    }
    Ok(())
}

pub struct CheckCollector {
    background: Background,
}

/// A check and how often it runs, in rounds of the agent's interval.
struct Scheduled {
    check: Arc<(Check, Option<Credentials>)>,
    every: u64,
    /// Which round of each `every` it runs in, so checks with the same interval
    /// don't all run together.
    offset: u64,
}

/// A check runs with every sample unless it asks for longer, rounded up to whole
/// samples. It never runs more often than samples are sent.
fn rounds(check: &Check, interval: Duration) -> u64 {
    let Some(seconds) = check.interval_secs else {
        return 1;
    };
    let interval_ms = interval.as_millis().max(1);
    let wanted_ms = u128::from(seconds) * 1000;
    u64::try_from(wanted_ms.div_ceil(interval_ms))
        .unwrap_or(u64::MAX)
        .max(1)
}

impl CheckCollector {
    pub fn new(checks: Vec<Check>, logins: &CheckLogins, interval: Duration) -> Self {
        let longest = checks.iter().map(limit).max().unwrap_or_default();
        let scheduled: Vec<Scheduled> = checks
            .into_iter()
            .map(|check| {
                let every = rounds(&check, interval);
                let offset = (rand::random::<f64>() * every as f64) as u64;
                // Only a kind that signs in is given one, so a login named for a
                // web check never goes anywhere.
                let credentials = logins
                    .get(&check.name)
                    .filter(|_| check.kind.signs_in())
                    .map(CheckLogin::credentials);
                Scheduled {
                    check: Arc::new((check, credentials)),
                    every,
                    offset: offset.min(every - 1),
                }
            })
            .collect();
        // Each check's newest result, which goes with every sample until it runs
        // again, so a page showing the newest sample still shows every check.
        let results: Arc<Mutex<Vec<Option<Value>>>> =
            Arc::new(Mutex::new(vec![None; scheduled.len()]));

        let mut round: u64 = 0;
        let background = Background::start(interval, move || {
            let due: Vec<usize> = (0..scheduled.len())
                .filter(|&i| round % scheduled[i].every == scheduled[i].offset)
                .collect();
            round = round.wrapping_add(1);
            let checks: Vec<Arc<(Check, Option<Credentials>)>> =
                due.iter().map(|&i| scheduled[i].check.clone()).collect();
            let results = results.clone();
            async move {
                let probe = |item: Arc<(Check, Option<Credentials>)>| async move {
                    let (check, credentials) = &*item;
                    run_signed_in(check, credentials.as_ref()).await
                };
                let late = |item: &(Check, Option<Credentials>)| timed_out_report(&item.0);
                let found = probe_all(&checks, interval, longest + GRACE, probe, late).await;
                let mut results = results.lock().unwrap_or_else(PoisonError::into_inner);
                for (i, result) in due.into_iter().zip(found) {
                    results[i] = Some(result);
                }
                Value::Array(results.iter().flatten().cloned().collect())
            }
        });
        Self { background }
    }
}

impl Collector for CheckCollector {
    fn name(&self) -> &'static str {
        "checks"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest())
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    use maxnines_protocol::CheckKind;

    use super::*;

    #[test]
    fn the_collector_reports_what_its_checks_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let check = Check::new("a", CheckKind::Tcp, &target);
        let mut collector =
            CheckCollector::new(vec![check], &CheckLogins::new(), Duration::from_millis(20));

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
    fn a_check_runs_every_so_many_samples() {
        let interval = Duration::from_secs(15);
        let with = |seconds| Check {
            interval_secs: seconds,
            ..Check::new("a", CheckKind::Tcp, "a:1")
        };
        assert_eq!(rounds(&with(None), interval), 1);
        assert_eq!(rounds(&with(Some(1)), interval), 1);
        assert_eq!(rounds(&with(Some(15)), interval), 1);
        assert_eq!(rounds(&with(Some(60)), interval), 4);
        assert_eq!(rounds(&with(Some(61)), interval), 5);
        assert_eq!(rounds(&with(Some(86_400)), interval), 5760);
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
        // 50 rounds of 20ms each, so it runs once in the second it covers.
        let slow = Check {
            interval_secs: Some(1),
            ..Check::new("slow", CheckKind::Tcp, &target)
        };
        let mut collector = CheckCollector::new(
            vec![fast, slow],
            &CheckLogins::new(),
            Duration::from_millis(20),
        );

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
                interval_secs: Some(1),
                ..Check::new("slow", CheckKind::Tcp, &slow_target)
            },
        ];
        let _collector =
            CheckCollector::new(checks, &CheckLogins::new(), Duration::from_millis(20));

        let deadline = Instant::now() + Duration::from_secs(10);
        while fast.load(Relaxed) < 20 {
            assert!(Instant::now() < deadline, "the fast check stopped");
            thread::sleep(Duration::from_millis(5));
        }
        // The slow one runs in one round of every 50, wherever its turn falls, and
        // a connection from the round underway may not be counted yet. Running it
        // every round would make it about as many as the fast one.
        let slow_runs = slow.load(Relaxed);
        let fast_runs = fast.load(Relaxed);
        assert!(
            slow_runs <= 2 + fast_runs / 50,
            "{slow_runs} slow, {fast_runs} fast"
        );
    }

    fn login(username: Option<&str>, password: Option<&str>, key: Option<PathBuf>) -> CheckLogin {
        CheckLogin {
            username: username.map(String::from),
            password: password.map(String::from),
            private_key_file: key,
            private_key: None,
        }
    }

    #[test]
    fn a_login_has_one_way_to_sign_in_and_its_key_is_read_at_once() {
        let folder = tempfile::tempdir().unwrap();
        let key = folder.path().join("key");
        std::fs::write(&key, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let mut logins = CheckLogins::from([
            (
                "db".to_string(),
                login(Some("maxnines"), Some("s3cret"), None),
            ),
            (
                "bastion".to_string(),
                login(Some("monitor"), None, Some(key)),
            ),
            // Redis before version 6 has only a password.
            ("cache".to_string(), login(None, Some("s3cret"), None)),
        ]);
        load_check_logins(&mut logins).unwrap();
        assert!(
            logins["bastion"]
                .private_key
                .as_deref()
                .unwrap()
                .contains("OPENSSH")
        );
        assert!(!format!("{:?}", logins["db"]).contains("s3cret"));

        for bad in [
            login(None, None, None),
            login(Some("a"), Some("b"), Some(folder.path().join("key"))),
            login(Some("a"), None, Some(folder.path().join("missing"))),
        ] {
            let mut logins = CheckLogins::from([("x".to_string(), bad)]);
            assert!(load_check_logins(&mut logins).is_err());
        }
    }
}
