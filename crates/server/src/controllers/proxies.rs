//! Settings, Proxies: which proxies in front of the server are trusted, and the ones
//! that turned up untrusted, with what's known about each to help decide.

use std::net::IpAddr;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};

use super::{CsrfForm, Page, local_time, server_error};
use crate::app_state::AppState;
use crate::metrics::now_ms;
use crate::proxies::{AddressKind, Decision, PROVIDERS, Seen, check_address};

pub const PROXIES_PAGE: &str = "/settings/proxies";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PROXIES_PAGE, get(index).post(decide))
        .route("/settings/proxies/{id}/delete", post(delete))
}

/// What the server knows about proxies, as the page and the API show it.
#[derive(Serialize)]
pub struct Overview {
    /// What the config trusts: `trusted_proxies`, or this machine when it isn't set.
    pub configured: Vec<String>,
    /// Whether `configured` is from the config, rather than the default.
    pub from_config: bool,
    /// What admins decided.
    pub decisions: Vec<Decision>,
    /// Proxies that passed on someone's address without being trusted, waiting for a
    /// decision, most recent first.
    pub waiting: Vec<Seen>,
}

pub async fn overview(state: &AppState) -> Result<Overview> {
    let (configured, from_config) = state.proxies.configured();
    Ok(Overview {
        configured: configured.iter().map(ToString::to_string).collect(),
        from_config,
        decisions: state.database.list_proxies().await?,
        waiting: state.proxies.undecided(),
    })
}

/// Decides about an address, range or provider, and puts it to use at once.
pub async fn decide_about(
    state: &AppState,
    address: &str,
    trusted: bool,
) -> Result<Result<Decision, String>> {
    let address = match check_address(address) {
        Ok(address) => address,
        Err(error) => return Ok(Err(error.to_string())),
    };
    let decision = state
        .database
        .decide_proxy(&address, trusted, now_ms())
        .await?;
    reload(state).await?;
    Ok(Ok(decision))
}

/// Forgets a decision. Gives back whether there was one.
pub async fn forget(state: &AppState, id: i64) -> Result<bool> {
    let deleted = state.database.delete_proxy(id).await?;
    reload(state).await?;
    Ok(deleted)
}

async fn reload(state: &AppState) -> Result<()> {
    state
        .proxies
        .set_decisions(&state.database.list_proxies().await?);
    Ok(())
}

/// What's noted on every page for admins while a proxy is waiting for a decision.
#[derive(Serialize)]
pub struct Notice {
    address: String,
    others: usize,
}

pub fn notice(state: &AppState) -> Option<Notice> {
    let waiting = state.proxies.undecided();
    let first = waiting.first()?;
    Some(Notice {
        address: first.address.to_string(),
        others: waiting.len() - 1,
    })
}

/// What's a name rather than an address: a provider's ranges.
fn label_of(address: &str) -> String {
    PROVIDERS
        .iter()
        .find(|provider| provider.key == address)
        .map_or_else(
            || address.to_string(),
            |provider| format!("{}'s published ranges", provider.name),
        )
}

#[derive(Serialize)]
struct WaitingRow {
    address: String,
    kind: &'static str,
    forwarded_for: String,
    people: Vec<String>,
    requests: u64,
    first_seen: String,
    last_seen: String,
    /// Whether whoever's looking came through it just now.
    yours: bool,
    suggested: String,
    suggested_label: String,
    /// Whether trusting the suggestion covers more than this address.
    wider: bool,
}

fn describe(seen: &Seen) -> &'static str {
    match (seen.kind, seen.provider) {
        (AddressKind::Loopback, _) => "This machine.",
        (AddressKind::Private, _) => {
            "A private network address. Cloud load balancers inside your own network, such as AWS's and Azure's, connect from these, as do proxies on your own network."
        }
        (AddressKind::Provider, Some("Cloudflare")) => "One of Cloudflare's published addresses.",
        (AddressKind::Provider, _) => "One of Google Cloud's load balancer addresses.",
        (AddressKind::Public, _) => {
            "A public internet address that belongs to no provider MaxNines knows. Trust it only if you know it's a proxy of yours."
        }
    }
}

#[derive(Serialize)]
struct DecisionRow {
    id: i64,
    label: String,
    trusted: bool,
    created: String,
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    page(&state, &token, None).await
}

async fn page(state: &AppState, token: &CsrfToken, error: Option<&str>) -> Response {
    let overview = match overview(state).await {
        Ok(overview) => overview,
        Err(error) => return server_error(&error),
    };
    let (mine, my_claim) = (crate::audit::source(), crate::audit::forwarded_for());
    let waiting: Vec<WaitingRow> = overview
        .waiting
        .iter()
        .map(|seen| WaitingRow {
            address: seen.address.to_string(),
            kind: describe(seen),
            forwarded_for: if mine == Some(seen.address) {
                my_claim.map_or_else(
                    || seen.forwarded_for.to_string(),
                    |claim: IpAddr| claim.to_string(),
                )
            } else {
                seen.forwarded_for.to_string()
            },
            people: seen.people.iter().cloned().collect(),
            requests: seen.requests,
            first_seen: local_time(seen.first_ms),
            last_seen: local_time(seen.last_ms),
            yours: mine == Some(seen.address),
            suggested_label: label_of(&seen.suggested),
            wider: seen.suggested != seen.address.to_string(),
            suggested: seen.suggested.clone(),
        })
        .collect();
    let decisions: Vec<DecisionRow> = overview
        .decisions
        .iter()
        .map(|decision| DecisionRow {
            id: decision.id,
            label: label_of(&decision.address),
            trusted: decision.trusted,
            created: local_time(decision.created_ms),
        })
        .collect();
    let providers: Vec<serde_json::Value> = PROVIDERS
        .iter()
        .map(|provider| serde_json::json!({ "key": provider.key, "name": provider.name }))
        .collect();
    let mut page = Page::new(state, token, "settings/proxies.html")
        .with("waiting", &waiting)
        .with("decisions", &decisions)
        .with("configured", &overview.configured)
        .with("from_config", &overview.from_config)
        .with("providers", &providers);
    if let Some(error) = error {
        page = page
            .with("error", error)
            .with_status(StatusCode::UNPROCESSABLE_ENTITY);
    }
    page.render()
}

async fn decide(State(state): State<AppState>, form: CsrfForm) -> Response {
    let address = form.fields.get("address").map_or("", String::as_str);
    let trusted = form
        .fields
        .get("trusted")
        .is_some_and(|value| value == "true");
    match decide_about(&state, address, trusted).await {
        Ok(Ok(_)) => (form.token, Redirect::to(PROXIES_PAGE)).into_response(),
        Ok(Err(problem)) => page(&state, &form.token, Some(&problem)).await,
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match forget(&state, id).await {
        Ok(true) => (form.token, Redirect::to(PROXIES_PAGE)).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// A decision asked for through the API.
#[derive(Deserialize)]
pub struct NewDecision {
    pub address: String,
    pub trusted: bool,
}

pub async fn api_list(State(state): State<AppState>) -> Response {
    match overview(&state).await {
        Ok(overview) => Json(overview).into_response(),
        Err(error) => server_error(&error),
    }
}

pub async fn api_decide(State(state): State<AppState>, Json(input): Json<NewDecision>) -> Response {
    match decide_about(&state, &input.address, input.trusted).await {
        Ok(Ok(decision)) => (StatusCode::CREATED, Json(decision)).into_response(),
        Ok(Err(problem)) => {
            let body = Json(serde_json::json!({ "error": problem }));
            (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
        }
        Err(error) => server_error(&error),
    }
}

pub async fn api_delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match forget(&state, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
