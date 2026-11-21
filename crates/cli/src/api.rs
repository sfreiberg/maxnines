//! A server's API, as whoever a context signed in as, or with an API key.

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;

use crate::failure::Failure;
use crate::http::{Answer, Body, Http};
use crate::server::Server;
use crate::signin::{self, REFRESH_RETRIES, Refreshed};
use crate::tokens::{self, Store, Tokens};

/// How long before the access token runs out that it's refreshed.
const REFRESH_EARLY: TimeDelta = TimeDelta::minutes(1);

/// When a token the server says lasts `secs` seconds runs out. One that would last
/// past what can be counted runs out then.
pub fn expires_after(secs: i64) -> DateTime<Utc> {
    TimeDelta::try_seconds(secs)
        .and_then(|lasts| Utc::now().checked_add_signed(lasts))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// How the API is told who's asking.
pub enum Auth {
    /// An API key, as in CI.
    Key(String),
    /// A context signed in through the browser, refreshed as it needs to be.
    SignedIn {
        context: String,
        folder: PathBuf,
        store: Box<dyn Store>,
        tokens: RefCell<Tokens>,
    },
}

pub struct Api {
    pub http: Http,
    pub server: Server,
    pub context: String,
    auth: Auth,
}

impl Api {
    pub fn new(server: Server, context: String, auth: Auth) -> Self {
        Self {
            http: Http::new(),
            server,
            context,
            auth,
        }
    }

    /// Asks the API, at `path` under `/api/v1`, giving back its JSON or saying what's wrong.
    pub fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let answer = self.call_raw(method, path, body)?;
        self.read(&answer)
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.call("GET", path, None)
    }

    /// Asks, refreshing once and trying again if a signed-in context's token is turned down.
    pub fn call_raw(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Answer> {
        let url = self.server.url(&format!("/api/v1{path}"));
        let send = |token: &str| {
            let body = body.map_or(Body::None, Body::Json);
            self.http.send(method, &url, Some(token), body)
        };
        let token = self.token(false)?;
        let answer = send(&token)?;
        if answer.status == 401 && matches!(self.auth, Auth::SignedIn { .. }) {
            let token = self.token(true)?;
            return Ok(send(&token)?);
        }
        Ok(answer)
    }

    /// The JSON of a successful answer, or what's wrong, as a failure with its exit code.
    pub fn read(&self, answer: &Answer) -> Result<Value> {
        if answer.is_success() {
            return Ok(if answer.text.trim().is_empty() {
                Value::Null
            } else {
                answer.json()
            });
        }
        let said = answer.error();
        let failure = match answer.status {
            401 => Failure::not_allowed(match self.auth {
                Auth::Key(_) => "The server didn't accept the API key".to_string(),
                Auth::SignedIn { .. } => format!(
                    "Signed out of {}: run maxnines login {}",
                    self.context, self.context
                ),
            }),
            403 => Failure::not_allowed(
                said.unwrap_or_else(|| "Your role doesn't allow that".to_string()),
            ),
            404 => Failure::not_found(
                said.unwrap_or_else(|| "There's nothing at that address".to_string()),
            ),
            400 | 409 | 422 => Failure::refused(
                said.unwrap_or_else(|| format!("The server refused it (status {})", answer.status)),
            ),
            status => Failure::new(
                Failure::OTHER,
                format!("The server answered with status {status}"),
            ),
        };
        Err(failure.into())
    }

    /// The token to send. A signed-in context's access token is refreshed when it's
    /// about to run out, or when `stale` says the server turned it down.
    fn token(&self, stale: bool) -> Result<String> {
        match &self.auth {
            Auth::Key(key) => Ok(key.clone()),
            Auth::SignedIn {
                context,
                folder,
                store,
                tokens,
            } => {
                let fresh = |held: &Tokens| held.access_expires_at - Utc::now() > REFRESH_EARLY;
                if !stale && fresh(&tokens.borrow()) {
                    return Ok(tokens.borrow().access_token.clone());
                }
                // One refresh at a time across every maxnines running, and another may
                // have just done it, so look again once it's ours.
                let _lock = tokens::lock(folder)?;
                // Gone means another command signed it out meanwhile, which stands.
                let Some(saved) = store.load(context)? else {
                    return Err(Failure::not_allowed(format!(
                        "Not signed in to {context}: run maxnines login {context}"
                    ))
                    .into());
                };
                if saved.access_token != tokens.borrow().access_token && fresh(&saved) {
                    let token = saved.access_token.clone();
                    *tokens.borrow_mut() = saved;
                    return Ok(token);
                }
                let wait = |delay: Duration| std::thread::sleep(delay);
                let quick = Http::with_timeout(signin::REFRESH_TIMEOUT);
                match signin::refresh(
                    &quick,
                    &self.server,
                    &saved.refresh_token,
                    &REFRESH_RETRIES,
                    &wait,
                )? {
                    Refreshed::Issued(issued) => {
                        let renewed = Tokens {
                            access_token: issued.access_token,
                            access_expires_at: expires_after(issued.expires_in),
                            refresh_token: issued.refresh_token,
                            user: issued.user,
                            role: issued.role,
                        };
                        // Kept before it's used, as the server only takes the newest.
                        store.save(context, &renewed)?;
                        let token = renewed.access_token.clone();
                        *tokens.borrow_mut() = renewed;
                        Ok(token)
                    }
                    Refreshed::SignedOut => {
                        store.forget(context)?;
                        Err(Failure::not_allowed(format!(
                            "The sign in to {context} has run out or been revoked: run maxnines login {context}"
                        ))
                        .into())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store another command has just signed out of.
    struct SignedOutStore;

    impl Store for SignedOutStore {
        fn load(&self, _context: &str) -> Result<Option<Tokens>> {
            Ok(None)
        }
        fn save(&self, _context: &str, _tokens: &Tokens) -> Result<()> {
            panic!("a context signed out elsewhere was signed in again");
        }
        fn forget(&self, _context: &str) -> Result<()> {
            Ok(())
        }
        fn place(&self) -> &'static str {
            "nowhere"
        }
    }

    #[test]
    fn signing_out_elsewhere_stands_while_a_refresh_waits() {
        let folder = tempfile::tempdir().unwrap();
        // Nothing listens on port 0, so a refresh tried would fail as unreachable.
        let api = Api::new(
            Server::parse("http://127.0.0.1:0").unwrap(),
            "lan".to_string(),
            Auth::SignedIn {
                context: "lan".to_string(),
                folder: folder.path().to_path_buf(),
                store: Box::new(SignedOutStore),
                tokens: RefCell::new(Tokens {
                    access_token: "mxa_1".to_string(),
                    access_expires_at: DateTime::UNIX_EPOCH,
                    refresh_token: "mxr_1".to_string(),
                    user: "you@example.com".to_string(),
                    role: "viewer".to_string(),
                }),
            },
        );
        let failed = api.get("/hosts").unwrap_err();
        assert_eq!(crate::failure::exit_code(&failed), Failure::NOT_ALLOWED);
        assert!(
            failed.to_string().contains("maxnines login lan"),
            "{failed}"
        );
    }
}
