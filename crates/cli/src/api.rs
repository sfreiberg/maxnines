//! A server's API, as whoever a context signed in as, or with an API key.

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde_json::Value;

use crate::failure::Failure;
use crate::http::{Answer, Body, Http};
use crate::server::Server;
use crate::signin::{self, REFRESH_RETRIES, Refreshed};
use crate::tokens::{self, Store, Tokens};

/// How long before the access token runs out that it's refreshed.
const REFRESH_EARLY_MS: i64 = 60_000;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
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
                let fresh = |held: &Tokens| held.access_expires_ms - now_ms() > REFRESH_EARLY_MS;
                if !stale && fresh(&tokens.borrow()) {
                    return Ok(tokens.borrow().access_token.clone());
                }
                // One refresh at a time across every maxnines running, and another may
                // have just done it, so look again once it's ours.
                let _lock = tokens::lock(folder)?;
                let held = tokens.borrow().clone();
                if let Some(saved) = store.load(context)?
                    && saved.access_token != held.access_token
                    && fresh(&saved)
                {
                    let token = saved.access_token.clone();
                    *tokens.borrow_mut() = saved;
                    return Ok(token);
                }
                let latest = store.load(context)?.unwrap_or(held);
                let wait = |delay: Duration| std::thread::sleep(delay);
                let quick = Http::with_timeout(signin::REFRESH_TIMEOUT);
                match signin::refresh(
                    &quick,
                    &self.server,
                    &latest.refresh_token,
                    &REFRESH_RETRIES,
                    &wait,
                )? {
                    Refreshed::Issued(issued) => {
                        let renewed = Tokens {
                            access_token: issued.access_token,
                            access_expires_ms: now_ms() + issued.expires_in * 1000,
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
