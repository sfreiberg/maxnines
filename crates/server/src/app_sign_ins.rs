//! Signing in apps, such as the command line and MaxNines Desktop, through the
//! browser rather than with a pasted API key. It's OAuth 2.0 for native apps: the
//! authorization code flow with PKCE and a loopback redirect (RFC 8252 and 7636), and
//! the device flow for machines with no browser (RFC 8628).
//!
//! The person approves an app on a page behind the usual sign in, so however they
//! sign in to the pages, whether a password and two-factor or one day SSO, is how
//! they sign in an app. The app gets a short-lived access token and a refresh token,
//! and acts as them with at most the role they chose.
//!
//! What's waiting to be approved lives only in memory, for minutes: a restart just
//! means signing in again.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::TimeDelta;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};

use crate::roles::Role;
use crate::times::Timestamp;

/// How long an access token works.
pub const ACCESS_LIFETIME: TimeDelta = TimeDelta::hours(1);
/// How long a refresh token works. Each use gives a new one that lasts this long again.
pub const REFRESH_LIFETIME: TimeDelta = TimeDelta::days(90);
/// How long a refresh token that's just been swapped still works, in case the answer
/// with its replacement was lost on the way. After that, using it again means it was
/// copied, and the sign in is revoked.
pub const REFRESH_GRACE: TimeDelta = TimeDelta::minutes(1);
/// How long an approval has to be collected.
pub const PENDING_LIFETIME: TimeDelta = TimeDelta::minutes(10);
/// How often a device may ask whether it's been approved.
pub const DEVICE_INTERVAL: TimeDelta = TimeDelta::seconds(5);
/// The most devices that can be waiting at once. Anyone can start one, so this keeps
/// someone who starts thousands from using up the server's memory.
pub const MAX_WAITING_DEVICES: usize = 1000;

pub const ACCESS_PREFIX: &str = "mxa_";
pub const REFRESH_PREFIX: &str = "mxr_";
const CODE_PREFIX: &str = "mxc_";
const DEVICE_CODE_PREFIX: &str = "mxd_";

/// The most a device's name can be.
pub const MAX_DEVICE_CHARS: usize = 100;

/// An app being signed in. They're public clients: they can't keep a secret, so they
/// prove themselves with PKCE instead, and their ID is only what they call themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppClient {
    pub id: String,
    /// What people are shown it as: MaxNines' name for one of its own apps, or for any
    /// other, the ID it gave and that it isn't one of MaxNines' own.
    pub name: String,
    /// Whether it's one of MaxNines' own apps.
    pub known: bool,
}

struct KnownApp {
    id: &'static str,
    name: &'static str,
}

/// MaxNines' own apps, which are shown by name.
const KNOWN_APPS: [KnownApp; 4] = [
    KnownApp {
        id: "maxnines-cli",
        name: "MaxNines command line",
    },
    KnownApp {
        id: "maxnines-desktop-mac",
        name: "MaxNines Desktop for Mac",
    },
    KnownApp {
        id: "maxnines-desktop-windows",
        name: "MaxNines Desktop for Windows",
    },
    KnownApp {
        id: "maxnines-desktop-linux",
        name: "MaxNines Desktop for Linux",
    },
];

/// The longest ID an app can give.
pub const MAX_CLIENT_ID_CHARS: usize = 64;

/// One of MaxNines' own apps. Only these can sign in with a code typed on another
/// device, as nothing ties that sign-in to the computer the person is at, which makes
/// it the one someone could be talked into approving for a stranger.
pub fn known_client(id: &str) -> Option<AppClient> {
    KNOWN_APPS
        .iter()
        .find(|app| app.id == id)
        .map(|app| AppClient {
            id: app.id.to_string(),
            name: app.name.to_string(),
            known: true,
        })
}

/// Any app that can sign in through the browser: one of MaxNines' own, or another
/// with an ID of up to 64 lowercase letters, digits, dots, dashes and underscores,
/// starting with a letter or digit. The browser only ever answers on this computer,
/// so another app can't be signed in from elsewhere, whatever it calls itself.
pub fn client(id: &str) -> Option<AppClient> {
    known_client(id).or_else(|| {
        let usable = id.len() <= MAX_CLIENT_ID_CHARS
            && id
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
            && id.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')
            });
        usable.then(|| AppClient {
            id: id.to_string(),
            name: format!("{id} (not one of MaxNines' own)"),
            known: false,
        })
    })
}

/// How an app that's been signed in is shown, in lists and the audit log.
pub fn app_name(id: &str) -> String {
    client(id).map_or_else(|| id.to_string(), |client| client.name)
}

/// What an app's name for the device it's on can be, trimmed. Empty is fine.
/// What an app calls the computer it's on, which it needn't say: none if it's left out.
pub fn check_device(device: &str) -> Result<Option<String>> {
    let device = device.trim();
    ensure!(
        device.chars().count() <= MAX_DEVICE_CHARS,
        "The device name is too long. It can be up to {MAX_DEVICE_CHARS} characters."
    );
    ensure!(
        !device.chars().any(char::is_control),
        "The device name can't have control characters in it."
    );
    Ok(crate::text::non_blank(device))
}

/// Where a browser may be sent back to: a port on 127.0.0.1, written as an IP address,
/// as RFC 8252 asks, since `localhost` can be made to mean somewhere else. Not `[::1]`,
/// as a page's policy can't name an IPv6 address, so the browser would refuse to go
/// back there. Gives back the origin, which the page's policy has to allow.
pub fn check_redirect(redirect_uri: &str) -> Result<String> {
    let Some(rest) = redirect_uri.strip_prefix("http://") else {
        bail!("an app is sent back to http:// on this computer");
    };
    let (authority, path) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    ensure!(
        !path.contains('#'),
        "an app's address can't have a fragment"
    );
    let host_end = authority.rfind(':').unwrap_or(authority.len());
    let (host, port) = authority.split_at(host_end);
    ensure!(
        host == "127.0.0.1",
        "an app is sent back to 127.0.0.1, not {host:?}"
    );
    let port = port.strip_prefix(':').unwrap_or_default();
    ensure!(
        port.parse::<u16>().is_ok_and(|port| port > 0),
        "an app's address needs its port"
    );
    Ok(format!("http://{authority}"))
}

/// Whether `verifier` is the one `challenge` was made from: its SHA-256, in base64url.
pub fn verifier_matches(verifier: &str, challenge: &str) -> bool {
    let well_formed = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte));
    well_formed && URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes())) == challenge
}

/// What a challenge has to look like: a SHA-256 in base64url.
pub fn check_challenge(challenge: &str, method: &str) -> Result<()> {
    ensure!(method == "S256", "the code challenge method has to be S256");
    ensure!(
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "the code challenge has to be a SHA-256 in base64url"
    );
    Ok(())
}

/// A new secret with `prefix`, so one is easy to recognise if it leaks.
pub fn new_secret(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}{}", maxnines_protocol::auth::new_nonce()?))
}

pub use crate::registration::hex_hash as secret_hash;

/// Letters that can't be mistaken for each other or spell much, as RFC 8628 suggests.
const USER_CODE_LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

fn new_user_code() -> Result<String> {
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("making a code"))?;
    let letters: String = bytes
        .iter()
        .map(|byte| USER_CODE_LETTERS[usize::from(*byte) % USER_CODE_LETTERS.len()] as char)
        .collect();
    Ok(format!("{}-{}", &letters[..4], &letters[4..]))
}

/// A code as someone typed it, in the form it was given: capitals, with the dash.
pub fn normalise_user_code(typed: &str) -> String {
    let letters: String = typed
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|letter| letter.to_ascii_uppercase())
        .collect();
    if letters.len() == 8 {
        format!("{}-{}", &letters[..4], &letters[4..])
    } else {
        letters
    }
}

/// Someone's yes to an app: who, which app on which device, and with what role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub user_id: i64,
    pub client: AppClient,
    pub device: Option<String>,
    pub role: Role,
}

#[derive(Debug, Clone)]
struct Code {
    approval: Approval,
    redirect_uri: String,
    challenge: String,
    expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceState {
    Waiting,
    Allowed(Approval),
    Denied,
}

#[derive(Debug, Clone)]
struct DeviceRequest {
    user_code: String,
    client: AppClient,
    device: Option<String>,
    /// The role the app asked for, which the person can lower.
    role: Option<Role>,
    expires_at: Timestamp,
    /// When it may next ask without being told to slow down.
    next_poll_at: Timestamp,
    /// How long it has to wait between asks.
    interval: TimeDelta,
    state: DeviceState,
}

/// A device's request as the approval page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAsk {
    pub user_code: String,
    pub client: AppClient,
    pub device: Option<String>,
    pub role: Option<Role>,
}

/// What a device hears when it asks whether it's been approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Allowed(Approval),
}

/// What a device is given to show its person.
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
}

#[derive(Default)]
struct Waiting {
    /// By the code's hash.
    codes: HashMap<String, Code>,
    /// By the device code's hash.
    devices: HashMap<String, DeviceRequest>,
}

/// Approvals waiting for their app to collect them.
#[derive(Default)]
pub struct PendingSignIns {
    waiting: Mutex<Waiting>,
}

impl PendingSignIns {
    fn lock(&self) -> std::sync::MutexGuard<'_, Waiting> {
        // Nothing here can be left half changed, so a panic elsewhere doesn't matter.
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn forget_expired(waiting: &mut Waiting, now: Timestamp) {
        waiting.codes.retain(|_, code| code.expires_at > now);
        waiting
            .devices
            .retain(|_, request| request.expires_at > now);
    }

    /// Keeps an approval for the app to swap for tokens, giving back the code it's sent.
    pub fn approve_code(
        &self,
        approval: Approval,
        redirect_uri: &str,
        challenge: &str,
        now: Timestamp,
    ) -> Result<String> {
        let code = new_secret(CODE_PREFIX)?;
        let mut waiting = self.lock();
        Self::forget_expired(&mut waiting, now);
        waiting.codes.insert(
            secret_hash(&code),
            Code {
                approval,
                redirect_uri: redirect_uri.to_string(),
                challenge: challenge.to_string(),
                expires_at: now + PENDING_LIFETIME,
            },
        );
        Ok(code)
    }

    /// The approval behind a code, if the app proves it's the one that asked. A code
    /// works once, whether or not the proof was right.
    pub fn take_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        verifier: &str,
        now: Timestamp,
    ) -> Option<Approval> {
        let mut waiting = self.lock();
        Self::forget_expired(&mut waiting, now);
        let found = waiting.codes.remove(&secret_hash(code))?;
        let proven = found.approval.client.id == client_id
            && found.redirect_uri == redirect_uri
            && verifier_matches(verifier, &found.challenge);
        proven.then_some(found.approval)
    }

    /// Starts a device's sign in, unless too many are waiting already.
    pub fn start_device(
        &self,
        client: AppClient,
        device: Option<&str>,
        role: Option<Role>,
        now: Timestamp,
    ) -> Result<Option<DeviceStart>> {
        let device_code = new_secret(DEVICE_CODE_PREFIX)?;
        let mut waiting = self.lock();
        Self::forget_expired(&mut waiting, now);
        if waiting.devices.len() >= MAX_WAITING_DEVICES {
            return Ok(None);
        }
        // Codes are short, so make sure this one isn't already waiting.
        let user_code = loop {
            let code = new_user_code()?;
            if !waiting
                .devices
                .values()
                .any(|request| request.user_code == code)
            {
                break code;
            }
        };
        waiting.devices.insert(
            secret_hash(&device_code),
            DeviceRequest {
                user_code: user_code.clone(),
                client,
                device: device.map(str::to_string),
                role,
                expires_at: now + PENDING_LIFETIME,
                next_poll_at: now,
                interval: DEVICE_INTERVAL,
                state: DeviceState::Waiting,
            },
        );
        Ok(Some(DeviceStart {
            device_code,
            user_code,
        }))
    }

    /// The device waiting under the code someone typed, if any still is.
    pub fn device_asking(&self, user_code: &str, now: Timestamp) -> Option<DeviceAsk> {
        let user_code = normalise_user_code(user_code);
        let mut waiting = self.lock();
        Self::forget_expired(&mut waiting, now);
        waiting
            .devices
            .values()
            .find(|request| request.user_code == user_code && request.state == DeviceState::Waiting)
            .map(|request| DeviceAsk {
                user_code: request.user_code.clone(),
                client: request.client.clone(),
                device: request.device.clone(),
                role: request.role,
            })
    }

    /// Settles a device's request: `Some` approves it as that user with that role,
    /// `None` turns it down. Returns false if nothing is waiting under that code any more.
    pub fn decide_device(
        &self,
        user_code: &str,
        approver: Option<(i64, Role)>,
        now: Timestamp,
    ) -> bool {
        let user_code = normalise_user_code(user_code);
        let mut waiting = self.lock();
        Self::forget_expired(&mut waiting, now);
        let request = waiting.devices.values_mut().find(|request| {
            request.user_code == user_code && request.state == DeviceState::Waiting
        });
        let Some(request) = request else {
            return false;
        };
        request.state = match approver {
            Some((user_id, role)) => DeviceState::Allowed(Approval {
                user_id,
                client: request.client.clone(),
                device: request.device.clone(),
                role,
            }),
            None => DeviceState::Denied,
        };
        true
    }

    /// What a device hears when it asks. An answer is given once.
    pub fn poll_device(&self, device_code: &str, client_id: &str, now: Timestamp) -> DevicePoll {
        let hash = secret_hash(device_code);
        let mut waiting = self.lock();
        let Some(request) = waiting.devices.get_mut(&hash) else {
            return DevicePoll::Expired;
        };
        if request.client.id != client_id || request.expires_at <= now {
            waiting.devices.remove(&hash);
            return DevicePoll::Expired;
        }
        match request.state.clone() {
            DeviceState::Waiting if now < request.next_poll_at => {
                // Asking too often: wait longer between asks from now on.
                request.interval += DEVICE_INTERVAL;
                request.next_poll_at = now + request.interval;
                DevicePoll::SlowDown
            }
            DeviceState::Waiting => {
                request.next_poll_at = now + request.interval;
                DevicePoll::Pending
            }
            DeviceState::Denied => {
                waiting.devices.remove(&hash);
                DevicePoll::Denied
            }
            DeviceState::Allowed(approval) => {
                waiting.devices.remove(&hash);
                DevicePoll::Allowed(approval)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::times::from_ms;

    /// `ms` milliseconds into the tests' made-up time.
    fn at(ms: i64) -> Timestamp {
        from_ms(1_795_000_000_000 + ms)
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /// RFC 7636's own example.
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn approval() -> Approval {
        Approval {
            user_id: 1,
            client: known_client("maxnines-cli").unwrap(),
            device: Some("laptop".to_string()),
            role: Role::Viewer,
        }
    }

    #[test]
    fn maxnines_own_apps_are_named_and_others_say_what_they_call_themselves() {
        let named = |id: &str| client(id).map(|client| (client.name, client.known));
        let own = |name: &str| Some((name.to_string(), true));
        assert_eq!(
            named("maxnines-desktop-mac"),
            own("MaxNines Desktop for Mac")
        );
        assert_eq!(
            named("maxnines-desktop-windows"),
            own("MaxNines Desktop for Windows")
        );
        assert_eq!(
            named("maxnines-desktop-linux"),
            own("MaxNines Desktop for Linux")
        );
        assert_eq!(
            named("grafana.sync_2"),
            Some((
                "grafana.sync_2 (not one of MaxNines' own)".to_string(),
                false
            ))
        );
        assert_eq!(
            app_name("my-script"),
            "my-script (not one of MaxNines' own)"
        );
        // Only MaxNines' own apps can use a code typed on another device.
        assert!(known_client("maxnines-cli").is_some());
        assert!(known_client("my-script").is_none());
        // An ID is checked at the door.
        let too_long = "a".repeat(MAX_CLIENT_ID_CHARS + 1);
        for bad in [
            "",
            "-dash-first",
            "Capital",
            "has space",
            "emoji-🔔",
            "a/b",
            too_long.as_str(),
        ] {
            assert_eq!(client(bad), None, "{bad}");
        }
        assert!(client(&"a".repeat(MAX_CLIENT_ID_CHARS)).is_some());
    }

    #[test]
    fn pkce_matches_the_rfcs_example() {
        assert!(verifier_matches(VERIFIER, CHALLENGE));
        assert!(!verifier_matches("short", CHALLENGE));
        assert!(!verifier_matches(&VERIFIER.replace('d', "e"), CHALLENGE));
        check_challenge(CHALLENGE, "S256").unwrap();
        assert!(check_challenge(CHALLENGE, "plain").is_err());
        assert!(check_challenge("x", "S256").is_err());
    }

    #[test]
    fn apps_are_only_sent_back_to_this_computer() {
        assert_eq!(
            check_redirect("http://127.0.0.1:53682/callback").unwrap(),
            "http://127.0.0.1:53682"
        );
        for bad in [
            "https://127.0.0.1:53682/",
            "http://localhost:53682/",
            "http://[::1]:53682/",
            "http://127.0.0.1/",
            "http://127.0.0.1:0/",
            "http://evil.example.com:80/",
            "http://127.0.0.1.evil.example.com:80/",
            "http://user@127.0.0.1:80/",
            "http://127.0.0.1:80/#x",
            "javascript:alert(1)",
        ] {
            assert!(check_redirect(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_code_works_once_and_only_with_its_proof() {
        let pending = PendingSignIns::default();
        let redirect = "http://127.0.0.1:5000/";
        let code = pending
            .approve_code(approval(), redirect, CHALLENGE, at(0))
            .unwrap();
        // The wrong proof spends it anyway, so it can't be guessed at.
        assert!(
            pending
                .take_code(
                    &code,
                    "maxnines-cli",
                    redirect,
                    "x".repeat(43).as_str(),
                    at(1)
                )
                .is_none()
        );
        assert!(
            pending
                .take_code(&code, "maxnines-cli", redirect, VERIFIER, at(1))
                .is_none()
        );

        let code = pending
            .approve_code(approval(), redirect, CHALLENGE, at(0))
            .unwrap();
        assert!(
            pending
                .take_code(&code, "maxnines-desktop-windows", redirect, VERIFIER, at(1))
                .is_none()
        );
        let code = pending
            .approve_code(approval(), redirect, CHALLENGE, at(0))
            .unwrap();
        assert_eq!(
            pending.take_code(&code, "maxnines-cli", redirect, VERIFIER, at(1)),
            Some(approval())
        );

        let code = pending
            .approve_code(approval(), redirect, CHALLENGE, at(0))
            .unwrap();
        assert!(
            pending
                .take_code(
                    &code,
                    "maxnines-cli",
                    redirect,
                    VERIFIER,
                    at(0) + PENDING_LIFETIME
                )
                .is_none()
        );
    }

    #[test]
    fn a_device_waits_slows_down_and_is_answered_once() {
        let pending = PendingSignIns::default();
        let start = pending
            .start_device(
                known_client("maxnines-cli").unwrap(),
                Some("build box"),
                Some(Role::Responder),
                at(0),
            )
            .unwrap()
            .unwrap();
        let code = &start.device_code;
        assert_eq!(start.user_code.len(), 9);

        assert_eq!(
            pending.poll_device(code, "maxnines-cli", at(0)),
            DevicePoll::Pending
        );
        assert_eq!(
            pending.poll_device(code, "maxnines-cli", at(1000)),
            DevicePoll::SlowDown
        );
        assert_eq!(
            pending.poll_device(code, "maxnines-cli", at(20_000)),
            DevicePoll::Pending
        );

        let typed = start.user_code.to_lowercase().replace('-', " ");
        let asking = pending.device_asking(&typed, at(20_000)).unwrap();
        assert_eq!(asking.device.as_deref(), Some("build box"));
        assert_eq!(asking.role, Some(Role::Responder));
        assert!(pending.decide_device(&typed, Some((1, Role::Viewer)), at(20_000)));
        assert!(!pending.decide_device(&typed, Some((1, Role::Viewer)), at(20_000)));

        let DevicePoll::Allowed(allowed) = pending.poll_device(code, "maxnines-cli", at(60_000))
        else {
            panic!("not allowed");
        };
        assert_eq!(allowed.device.as_deref(), Some("build box"));
        assert_eq!(
            pending.poll_device(code, "maxnines-cli", at(60_000)),
            DevicePoll::Expired
        );
    }

    #[test]
    fn only_so_many_devices_can_wait_at_once() {
        let pending = PendingSignIns::default();
        for _ in 0..MAX_WAITING_DEVICES {
            assert!(
                pending
                    .start_device(known_client("maxnines-cli").unwrap(), None, None, at(0))
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            pending
                .start_device(known_client("maxnines-cli").unwrap(), None, None, at(0))
                .unwrap()
                .is_none()
        );
        // Room comes back as they run out.
        let later = pending.start_device(
            known_client("maxnines-cli").unwrap(),
            None,
            None,
            at(0) + PENDING_LIFETIME,
        );
        assert!(later.unwrap().is_some());
    }

    #[test]
    fn a_device_turned_down_or_left_too_long_hears_so() {
        let pending = PendingSignIns::default();
        let start = pending
            .start_device(
                known_client("maxnines-desktop-mac").unwrap(),
                None,
                None,
                at(0),
            )
            .unwrap()
            .unwrap();
        assert!(pending.decide_device(&start.user_code, None, at(1)));
        assert_eq!(
            pending.poll_device(&start.device_code, "maxnines-desktop-mac", at(2)),
            DevicePoll::Denied
        );

        let start = pending
            .start_device(
                known_client("maxnines-desktop-mac").unwrap(),
                None,
                None,
                at(0),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.poll_device(
                &start.device_code,
                "maxnines-desktop-mac",
                at(0) + PENDING_LIFETIME
            ),
            DevicePoll::Expired
        );
        assert!(
            pending
                .device_asking(&start.user_code, at(0) + PENDING_LIFETIME)
                .is_none()
        );
    }
}
