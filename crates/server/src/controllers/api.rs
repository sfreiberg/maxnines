//! The versioned API, which shares the server's port. Everything the web pages can
//! see and do is here too. It needs an API key, because a proxy may expose it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{Path as UrlPath, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::error;

use super::fleet::Health;
use super::host_list::HostSearch;
use super::hosts::suggestions;
use super::users::{refusal, setup_url};
use crate::alert_charts;
use crate::alerting::{self, Alert, AlertRuleInput, ChannelInput, ChannelKind, NameTaken};
use crate::app_state::{AppState, EventRefusal, HostDeletion};
use crate::audit::Via;
use crate::calculations::{self, Calculation, Question};
use crate::dashboard_variables::{self, Picks, Variable};
use crate::dashboards::{Placed, WidgetInput, check_layout, check_name};
use crate::events::EventInput;
use crate::facts::unflatten;
use crate::heartbeats;
use crate::locations::{LocationRuleInput, check_rule};
use crate::maintenance::MaintenanceWindowInput;
use crate::metrics::{SeriesResult, TimeRange, Unit};
use crate::metrics_pages::{MetricsPage, MetricsPageInput, SignIn};
use crate::models::User;
use crate::models::{ConfigStatus, MAX_TIMELINE, RuleInput, UserChange, check_new_user, is_theme};
use crate::notifier::{self, Notice};
use crate::presence::{HostPresence, Reach};
use crate::readings::{Arrays, Drives, FailedServices, TimeSync, Updates, WatchedService};
use crate::registration::{HostRecord, HostState, Upgrade};
use crate::remote_checks::{LatestResults, RemoteCheck, RemoteCheckInput, SignInWith};
use crate::roles::Role;
use crate::rule_engine::{self, ResolvedConfig};
use crate::silences::{ActiveSilences, Cover, SilenceInput};
use crate::times::{self, Timestamp, zone_named};

/// An agent as admins see it.
#[derive(Debug, Serialize, Deserialize)]
pub struct HostView {
    #[serde(flatten)]
    pub host: HostRecord,
    pub online: bool,
    pub health: Health,
    pub last_seen_at: Option<Timestamp>,
    /// Which side has to be upgraded before the server takes the host's agent again.
    pub needs_upgrading: Option<Upgrade>,
}

/// When the server last heard from a host.
fn last_seen_at(presence: Option<HostPresence>) -> Option<Timestamp> {
    presence?.last_seen_at
}

/// Facts come in two kinds. `trusted` is what the server knows for itself, and
/// `reported` is only what the agent claims, so it must never decide anything
/// security related.
#[derive(Debug, Serialize, Deserialize)]
pub struct FactsView {
    trusted: TrustedFacts,
    /// Current facts in their natural shape, with lists and nested values.
    reported: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedFacts {
    host_id: String,
    state: HostState,
    decided_by: Option<String>,
    online: bool,
    /// Where the latest connection came from, since the server started.
    source_address: Option<IpAddr>,
}

/// Where the API lives. A change that would break a client goes in a new version.
pub const BASE_PATH: &str = "/api/v1";

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/hosts", get(list).post(create_host))
        .route(
            "/hosts/{id}",
            get(show_host).put(rename_host).delete(delete_host),
        )
        .route(
            "/hosts/{id}/metrics-pages",
            get(list_metrics_pages).post(create_metrics_page),
        )
        .route(
            "/metrics-pages/{id}",
            get(show_metrics_page)
                .put(update_metrics_page)
                .delete(delete_metrics_page),
        )
        .route("/hosts/{id}/facts", get(facts))
        .route("/hosts/{id}/facts/history", get(facts_history))
        .route("/hosts/{id}/config", get(agent_config))
        .route("/hosts/{id}/drives", get(host_drives))
        .route("/hosts/{id}/raid", get(host_raid))
        .route("/hosts/{id}/updates", get(host_updates))
        .route("/hosts/{id}/time-sync", get(host_time_sync))
        .route("/hosts/{id}/services", get(host_services))
        .route("/hosts/{id}/metrics/{metric}", get(host_metric))
        .route("/metrics", get(metric_catalog))
        .route("/metrics/current", get(current_metrics))
        .route("/query", get(query))
        .route("/dashboards", get(list_dashboards).post(create_dashboard))
        .route(
            "/dashboards/{id}",
            get(show_dashboard)
                .put(rename_dashboard)
                .delete(delete_dashboard),
        )
        .route("/dashboards/{id}/layout", put(place_widgets))
        .route("/dashboards/{id}/widgets", post(create_widget))
        .route(
            "/dashboards/{id}/widgets/{widget}",
            get(widget_data).put(update_widget).delete(delete_widget),
        )
        .route(
            "/dashboards/{id}/variables",
            get(list_variables).put(save_variables),
        )
        .route("/rules", get(list_rules).post(create_rule))
        .route(
            "/rules/{id}",
            get(show_rule).put(update_rule).delete(delete_rule),
        )
        .route("/server", get(server_stats))
        .route("/alerts", get(list_alerts))
        .route("/alerts/delivery-problems", get(list_delivery_problems))
        .route("/alerts/{id}/acknowledge", post(acknowledge_alert))
        .route("/alerts/{id}/actions", get(alert_actions))
        .route("/alerts/{id}/series", get(alert_series))
        .route("/hosts/{id}/actions", get(host_actions).post(run_action))
        .route("/action-runs/{id}", get(show_action_run))
        .route("/alerts/{id}/unacknowledge", post(unacknowledge_alert))
        .route("/annotations", get(list_events).post(create_event))
        .route("/annotations/{id}", get(show_event).delete(delete_event))
        .route("/hosts/{id}/events", get(host_events))
        .route("/silences", get(list_silences).post(create_silence))
        .route("/silences/{id}", get(show_silence))
        .route("/silences/{id}/end", post(end_silence))
        .route(
            "/maintenance-windows",
            get(list_maintenance_windows).post(create_maintenance_window),
        )
        .route(
            "/maintenance-windows/{id}",
            get(show_maintenance_window)
                .put(update_maintenance_window)
                .delete(delete_maintenance_window),
        )
        .route(
            "/alert-rules",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route("/alert-rules/replay", post(replay_alert_rule))
        .route("/alert-rules/{id}/replay", post(replay_saved_alert_rule))
        .route(
            "/alert-rules/{id}",
            get(show_alert_rule)
                .put(update_alert_rule)
                .delete(delete_alert_rule),
        )
        .route(
            "/notification-channels",
            get(list_channels).post(create_channel),
        )
        .route(
            "/notification-channels/{id}",
            get(show_channel).put(update_channel).delete(delete_channel),
        )
        .route(
            "/remote-checks",
            get(list_remote_checks).post(create_remote_check),
        )
        .route(
            "/remote-checks/{id}",
            get(show_remote_check)
                .put(update_remote_check)
                .delete(delete_remote_check),
        )
        .route("/remote-checks/{id}/ping-address", post(new_ping_address))
        .route(
            "/location-rules",
            get(list_location_rules).post(create_location_rule),
        )
        .route(
            "/location-rules/{id}",
            get(show_location_rule)
                .put(update_location_rule)
                .delete(delete_location_rule),
        )
        .route("/map", get(map))
        .route("/places", get(super::map::search_places))
        .route("/places/nearest", get(super::map::nearest_place))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/audit-log", get(audit_log))
        .route("/api-keys/{id}", delete(revoke_api_key))
        .route("/me", get(me))
        .route("/sign-ins", get(list_sign_ins))
        .route(
            "/proxies",
            get(super::proxies::api_list).post(super::proxies::api_decide),
        )
        .route("/proxies/{id}", delete(super::proxies::api_delete))
        .route("/sign-ins/{kind}/{id}", delete(end_sign_in))
        .route("/app-sign-ins", get(list_app_sign_ins))
        .route("/app-sign-ins/{id}", delete(revoke_app_sign_in))
        .route("/hosts/filter-options", get(filter_options))
        .route("/hosts/{id}/approve", post(approve))
        .route("/hosts/{id}/revoke", post(revoke))
        .route("/rules/preview", post(preview_rule))
        .route("/notification-channels/{id}/test", post(test_channel))
        .route("/users", get(list_users).post(create_user))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/users/{id}/disable", post(disable_user))
        .route("/users/{id}/enable", post(enable_user))
        .route("/users/{id}/setup-link", post(new_setup_link))
        .route("/users/{id}/two-factor/reset", post(reset_two_factor))
        .route(
            "/users/two-factor",
            get(two_factor_requirement).put(require_two_factor),
        )
        .merge(super::templates::api_routes())
        .merge(super::template_parts::api_routes())
        .merge(super::suggestions::api_routes())
        .route_layer(middleware::from_fn_with_state(state, require_token))
        .fallback(no_such_route)
}

/// Clients expect an answer they can read, rather than the web pages' not found page.
async fn no_such_route() -> Response {
    let body = Json(json!({ "error": "There's nothing at this address" }));
    (StatusCode::NOT_FOUND, body).into_response()
}

fn failed(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

/// Who a request acts as, and how, if it carries a working API key or a signed-in
/// app's access token.
pub async fn key_holder(
    state: &AppState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<(User, Via)>> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(key) = presented else {
        return Ok(None);
    };
    if key.starts_with(crate::app_sign_ins::ACCESS_PREFIX) {
        let accepted = state.database.accept_app_token(key, times::now()).await?;
        return Ok(accepted.map(|(sign_in, owner)| {
            let via = Via::App {
                id: sign_in.id,
                name: sign_in.title(),
            };
            (owner, via)
        }));
    }
    let accepted = state.database.accept_api_key(key, times::now()).await?;
    Ok(accepted.map(|(key, owner)| {
        let via = Via::ApiKey {
            id: key.id,
            name: key.name,
        };
        (owner, via)
    }))
}

/// Someone whose API key or app's token has already been checked, on a request the
/// server makes to the API for them, as the MCP server does for each tool. Only the
/// server can put this on a request.
#[derive(Debug, Clone)]
pub struct KeyHolder {
    pub user: User,
    pub via: Via,
}

async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Some(KeyHolder { user, via }) = request.extensions().get::<KeyHolder>().cloned() {
        return super::run_as(&state, user, Some(via), request, next).await;
    }
    match key_holder(&state, request.headers()).await {
        Ok(Some((owner, via))) => super::run_as(&state, owner, Some(via), request, next).await,
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn list_users(State(state): State<AppState>) -> Response {
    match state.database.list_users().await {
        Ok(users) => Json(users).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn get_user(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.user(id).await {
        Ok(Some(user)) => Json(user).into_response(),
        Ok(None) => no_such_user(),
        Err(error) => server_error(&error),
    }
}

fn no_such_user() -> Response {
    failed(StatusCode::NOT_FOUND, "There's no user with that ID")
}

#[derive(Deserialize)]
struct NewUser {
    email: String,
    name: String,
    /// What they may do. A viewer if left out.
    role: Option<Role>,
}

/// Gives back the link for them to set a password, the only time it can be seen.
async fn create_user(State(state): State<AppState>, Json(input): Json<NewUser>) -> Response {
    let (email, name) = match check_new_user(&input.email, &input.name) {
        Ok(checked) => checked,
        Err(error) => return refused(&error),
    };
    let role = input.role.unwrap_or(Role::Viewer);
    match state
        .database
        .create_user(&email, &name, role, times::now())
        .await
    {
        Ok(Some((user, link))) => {
            let body = json!({ "user": user, "setup_url": setup_url(&state, &link) });
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Ok(None) => failed(
            StatusCode::CONFLICT,
            "There's already a user with that address",
        ),
        Err(error) => server_error(&error),
    }
}

/// Any of them. None is refused, so a misspelled field isn't taken as done.
#[derive(Deserialize)]
struct UserChanges {
    theme: Option<String>,
    time_zone: Option<String>,
    role: Option<Role>,
}

async fn update_user(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<UserChanges>,
) -> Response {
    if input.theme.is_none() && input.time_zone.is_none() && input.role.is_none() {
        return failed(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Give a theme, a time zone or a role",
        );
    }
    if input.theme.as_deref().is_some_and(|theme| !is_theme(theme)) {
        return failed(StatusCode::UNPROCESSABLE_ENTITY, "There's no such theme");
    }
    let zone = match input.time_zone.as_deref() {
        Some(name) => match zone_named(name) {
            Some(zone) => Some(zone),
            None => {
                return failed(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "There's no such time zone",
                );
            }
        },
        None => None,
    };
    // First, as it's the one change that can be refused.
    if let Some(role) = input.role {
        match state.database.set_role(id, role).await {
            Ok(UserChange::Done) => {}
            other => return after_user_change(other),
        }
    }
    let saved = async {
        let mut found = true;
        if let Some(theme) = &input.theme {
            found &= state.database.set_theme(id, theme).await?;
        }
        if let Some(zone) = zone {
            found &= state.database.set_time_zone(id, zone).await?;
        }
        anyhow::Ok(found)
    };
    match saved.await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => no_such_user(),
        Err(error) => server_error(&error),
    }
}

fn after_user_change(change: anyhow::Result<UserChange>) -> Response {
    match change {
        Ok(UserChange::Done) => StatusCode::NO_CONTENT.into_response(),
        Ok(UserChange::NoSuchUser) => no_such_user(),
        Ok(other) => failed(StatusCode::CONFLICT, refusal(other).unwrap_or_default()),
        Err(error) => server_error(&error),
    }
}

async fn disable_user(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    after_user_change(state.database.disable_user(id, times::now()).await)
}

async fn enable_user(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    after_user_change(state.database.enable_user(id).await)
}

async fn delete_user(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    after_user_change(state.database.delete_user(id).await)
}

/// Turns off someone's two-factor, for when they've lost their phone and codes.
async fn reset_two_factor(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.turn_off_two_factor(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => no_such_user(),
        Err(error) => server_error(&error),
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFactorRequirement {
    /// Whether everyone has to set up two-factor to use the pages.
    required: bool,
}

async fn two_factor_requirement(State(state): State<AppState>) -> Response {
    let required = state
        .require_two_factor
        .load(std::sync::atomic::Ordering::Relaxed);
    Json(TwoFactorRequirement { required }).into_response()
}

async fn require_two_factor(
    State(state): State<AppState>,
    Json(input): Json<TwoFactorRequirement>,
) -> Response {
    match super::users::require_for_everyone(&state, input.required).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(problem)) => failed(StatusCode::CONFLICT, problem),
        Err(error) => server_error(&error),
    }
}

/// Replaces a user's setup link, which is also how a forgotten password is reset.
async fn new_setup_link(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.new_setup_link(id, times::now()).await {
        Ok(Some(link)) => Json(json!({ "setup_url": setup_url(&state, &link) })).into_response(),
        Ok(None) => no_such_user(),
        Err(error) => server_error(&error),
    }
}

/// Their own, or everyone's for an admin.
async fn list_api_keys(State(state): State<AppState>) -> Response {
    match super::api_keys::visible_keys(&state).await {
        Ok(keys) => Json(keys).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Keys are only ever made by a person, and the API only ever has a key or an app.
async fn create_api_key() -> Response {
    failed(StatusCode::FORBIDDEN, crate::roles::KEYS_ARE_MADE_BY_PEOPLE)
}

async fn revoke_api_key(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match super::api_keys::revoke_if_allowed(&state, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn list_sign_ins(State(state): State<AppState>) -> Response {
    let Some(whose) = super::sign_ins::whose() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match super::sign_ins::sign_ins(&state, whose, times::now()).await {
        Ok(sign_ins) => Json(sign_ins).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn end_sign_in(
    State(state): State<AppState>,
    UrlPath((kind, id)): UrlPath<(String, i64)>,
) -> Response {
    let Some(kind) = super::sign_ins::Kind::parse(&kind) else {
        return failed(
            StatusCode::NOT_FOUND,
            "That's not a kind of sign-in: use browser, app or api_key",
        );
    };
    match super::sign_ins::end_if_allowed(&state, kind, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Who a request acts as, with the role it has now, and what it came with: an API key
/// or a signed-in app.
async fn me() -> Response {
    let Some(user) = super::signed_in_user() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let via = crate::audit::current().via.map(|via| {
        json!({
            "kind": via.kind(),
            "id": via.id().and_then(|id| id.parse::<i64>().ok()),
            "name": via.name(),
        })
    });
    Json(json!({
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "via": via,
    }))
    .into_response()
}

async fn list_app_sign_ins(State(state): State<AppState>) -> Response {
    match super::app_sign_ins::visible_sign_ins(&state).await {
        Ok(sign_ins) => Json(sign_ins).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn revoke_app_sign_in(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match super::app_sign_ins::revoke_if_allowed(&state, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// The most entries one request can ask for.
const MAX_AUDIT_ENTRIES: u64 = 1000;

#[derive(Deserialize)]
struct AuditParams {
    /// Only entries older than this one, to read on from the last entry of a page.
    before: Option<i64>,
    limit: Option<u64>,
}

/// Newest first.
async fn audit_log(State(state): State<AppState>, Query(params): Query<AuditParams>) -> Response {
    let limit = params.limit.unwrap_or(super::audit_log::PAGE_SIZE);
    if !(1..=MAX_AUDIT_ENTRIES).contains(&limit) {
        let error = format!("limit has to be from 1 to {MAX_AUDIT_ENTRIES}");
        return failed(StatusCode::BAD_REQUEST, &error);
    }
    match state.database.audit_log(params.before, limit).await {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Deserialize)]
struct ListParams {
    /// A filter, written as in the box on the Hosts page.
    filter: Option<String>,
}

async fn list(State(state): State<AppState>, Query(params): Query<ListParams>) -> Response {
    let data = async {
        let search = HostSearch::load(&state, params.filter.as_deref()).await?;
        let alerts = state.database.open_alerts().await?;
        anyhow::Ok((search, alerts))
    };
    let (search, open) = match data.await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };
    if let Some(error) = &search.error {
        return failed(StatusCode::BAD_REQUEST, error);
    }
    let mut alerts: BTreeMap<&str, Vec<&Alert>> = BTreeMap::new();
    for alert in &open {
        alerts.entry(&alert.host_id).or_default().push(alert);
    }

    let views: Vec<HostView> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|host| !host.is_local() && search.includes(&host.id, &host.hostname))
        .map(|host| {
            let presence: Option<HostPresence> = state.presence.get(&host.id);
            let reach = state.presence.reach(&host);
            let mine = alerts.get(host.id.as_str()).map_or(&[][..], Vec::as_slice);
            HostView {
                online: reach == Reach::Online,
                health: Health::of(reach, mine),
                last_seen_at: last_seen_at(presence),
                needs_upgrading: host.needs_upgrading(),
                host,
            }
        })
        .collect();
    Json(views).into_response()
}

async fn show_host(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    let Some(host) = state.registry.get(&id).await.filter(|a| !a.is_local()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let open = match state.database.open_alerts().await {
        Ok(open) => open,
        Err(error) => return server_error(&error),
    };
    let mine: Vec<&Alert> = open.iter().filter(|alert| alert.host_id == id).collect();
    let presence = state.presence.get(&id);
    let reach = state.presence.reach(&host);
    Json(HostView {
        online: reach == Reach::Online,
        health: Health::of(reach, &mine),
        last_seen_at: last_seen_at(presence),
        needs_upgrading: host.needs_upgrading(),
        host,
    })
    .into_response()
}

/// What adding a host with no agent, or renaming one, takes.
#[derive(Deserialize)]
struct AgentlessHostInput {
    hostname: String,
}

/// Adds a host with no agent, for the server to read from itself. Hosts with an
/// agent add themselves, by connecting.
async fn create_host(
    State(state): State<AppState>,
    Json(input): Json<AgentlessHostInput>,
) -> Response {
    if let Err(error) = crate::registration::checked_hostname(&input.hostname) {
        return refused(&error);
    }
    let Some(owner) = super::signed_in_user() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let added = state.registry.add_agentless(&input.hostname, &owner.email);
    match added.await {
        Ok(host) => (StatusCode::CREATED, Json(host)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Only a host with no agent can be renamed, as an agent says what its host is
/// called.
async fn rename_host(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Json(input): Json<AgentlessHostInput>,
) -> Response {
    if let Err(error) = crate::registration::checked_hostname(&input.hostname) {
        return refused(&error);
    }
    match state.registry.rename_agentless(&id, &input.hostname).await {
        Ok(Some(host)) => Json(host).into_response(),
        Ok(None) if state.registry.get(&id).await.is_some_and(|a| !a.is_local()) => failed(
            StatusCode::CONFLICT,
            "Only a host with no agent can be renamed",
        ),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// A metrics page as a request gives it. `sign_in` says how it's signed in to,
/// which is the only way to keep a saved token without sending it again.
#[derive(Deserialize)]
struct MetricsPageRequest {
    #[serde(flatten)]
    input: MetricsPageInput,
    #[serde(default)]
    sign_in: Option<SignIn>,
}

/// A metrics page as the API shows it. Its password or token can be set but not
/// read back.
#[derive(Debug, Serialize)]
struct MetricsPageView {
    id: i64,
    host_id: String,
    /// What the page is called, which each of its series' names starts with.
    name: String,
    url: String,
    names: Vec<String>,
    interval_secs: u64,
    enabled: bool,
    sign_in: SignIn,
    username: Option<String>,
    has_password: bool,
    password_env: Option<String>,
    has_token: bool,
    token_env: Option<String>,
}

impl MetricsPageView {
    fn new(page: MetricsPage) -> Self {
        Self {
            id: page.id,
            host_id: page.host_id,
            name: page.input.name().to_string(),
            sign_in: page.input.sign_in(),
            has_password: page.input.password.is_some(),
            has_token: page.input.token.is_some(),
            token_env: page.input.token_env,
            url: page.input.url,
            names: page.input.names,
            interval_secs: page.input.interval.as_secs(),
            enabled: page.input.enabled,
            username: page.input.username,
            password_env: page.input.password_env,
        }
    }
}

async fn list_metrics_pages(
    State(state): State<AppState>,
    UrlPath(host_id): UrlPath<String>,
) -> Response {
    if state
        .registry
        .get(&host_id)
        .await
        .is_none_or(|a| a.is_local())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.database.metrics_pages_of(&host_id).await {
        Ok(pages) => {
            let views: Vec<MetricsPageView> = pages.into_iter().map(MetricsPageView::new).collect();
            Json(views).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn show_metrics_page(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_metrics_page(id).await {
        Ok(Some(page)) => Json(MetricsPageView::new(page)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_metrics_page(
    State(state): State<AppState>,
    UrlPath(host_id): UrlPath<String>,
    Json(request): Json<MetricsPageRequest>,
) -> Response {
    let Some(host) = state.registry.get(&host_id).await.filter(|a| !a.is_local()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if state.agentless_host(&host_id).await.is_none() {
        let why = "Only a host with no agent has pages the server reads. An agent reads its \
                   own, from a config rule";
        return failed(StatusCode::CONFLICT, why);
    }
    let MetricsPageRequest { input, sign_in } = request;
    let checked = state.checked_metrics_page(&host.id, None, input, sign_in);
    let input = match checked.await {
        Ok(input) => input,
        Err(error) => return refused(&error),
    };
    match state.database.create_metrics_page(&host.id, &input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_metrics_page(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(request): Json<MetricsPageRequest>,
) -> Response {
    let saved = match state.database.get_metrics_page(id).await {
        Ok(Some(saved)) => saved,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    let MetricsPageRequest { input, sign_in } = request;
    let checked = state.checked_metrics_page(&saved.host_id, Some(id), input, sign_in);
    let input = match checked.await {
        Ok(input) => input,
        Err(error) => return refused(&error),
    };
    match state.database.update_metrics_page(id, input).await {
        Ok(true) => {
            state.page_reads.changed(id);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_metrics_page(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_metrics_page(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Deserialize)]
struct FilterOptionParams {
    term: Option<String>,
}

async fn filter_options(
    State(state): State<AppState>,
    Query(params): Query<FilterOptionParams>,
) -> Response {
    match suggestions(&state, &params.term.unwrap_or_default()).await {
        Ok(found) => Json(found).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn facts(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    let Some(host) = state.registry.get(&id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let current = match state.database.current_facts(&id).await {
        Ok(current) => current,
        Err(error) => return server_error(&error),
    };

    let presence = state.presence.get(&id);
    let online = state.presence.reach(&host) == Reach::Online;
    Json(FactsView {
        trusted: TrustedFacts {
            host_id: host.id,
            state: host.state,
            decided_by: host.decided_by,
            online,
            source_address: presence.map(|p| p.source),
        },
        reported: unflatten(&current.into_iter().map(|f| (f.name, f.value)).collect()),
    })
    .into_response()
}

async fn facts_history(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.database.facts_history(&id).await {
        Ok(history) => Json(history).into_response(),
        Err(error) => server_error(&error),
    }
}

/// What an agent should be running, and what it says it's running.
#[derive(Debug, Serialize)]
struct AgentConfigView {
    desired: ResolvedConfig,
    reported: Option<ConfigStatus>,
}

async fn agent_config(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let desired = match state.config_for(&id).await {
        Ok(desired) => desired,
        Err(error) => return server_error(&error),
    };
    match state.database.config_status(&id).await {
        Ok(reported) => Json(AgentConfigView { desired, reported }).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Each drive a host's SMART collector last read, and why it couldn't read any, as
/// the host's page shows them.
async fn host_drives(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Drives::load(&state.metrics, &id, times::now()).await {
        Ok(drives) => Json(drives).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Each RAID array and ZFS pool a host's raid collector last read, and what it
/// couldn't read, as the host's page shows them.
async fn host_raid(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Arrays::load(&state.metrics, &id, times::now()).await {
        Ok(arrays) => Json(arrays).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Whether a host is up to date, as its page shows it, or null if it hasn't said.
async fn host_updates(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Updates::load(&state.metrics, &id, times::now()).await {
        Ok(updates) => Json(updates).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Whether a host's clock is kept in sync, as its page shows it, or null if it
/// hasn't said.
async fn host_time_sync(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match TimeSync::load(&state.metrics, &id, times::now()).await {
        Ok(time_sync) => Json(time_sync).into_response(),
        Err(error) => server_error(&error),
    }
}

/// A host's services as its pages show them.
#[derive(Serialize)]
struct ServicesView {
    /// Those it's been set to watch, as its service manager last described them.
    watched: Vec<WatchedService>,
    /// Those that stopped with an error, on a system that counts them.
    failed: Option<FailedServices>,
}

async fn host_services(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let now = times::now();
    let services = async {
        let watched = WatchedService::load(&state.metrics, &id, now).await?;
        let failed = FailedServices::load(&state.metrics, &id, now).await?;
        anyhow::Ok(ServicesView { watched, failed })
    };
    match services.await {
        Ok(services) => Json(services).into_response(),
        Err(error) => server_error(&error),
    }
}

/// How much a query covers unless it says otherwise.
const DEFAULT_RANGE: TimeDelta = TimeDelta::hours(1);

/// Enough for any real host, while an agent inventing names can't make a
/// response huge.
const MAX_SERIES: usize = 100;

/// Every metric there is to read: the built-in ones, then each template's.
async fn metric_catalog(State(state): State<AppState>) -> Response {
    Json(state.catalog().all()).into_response()
}

async fn current_metrics(State(state): State<AppState>) -> Response {
    match state.metrics.current(times::now()).await {
        Ok(current) => Json(current).into_response(),
        Err(error) => server_error(&error),
    }
}

/// The span of time a request for readings asks for, in ISO 8601. Either end can
/// be left out: `to` is now, and `from` is `default` before `to`.
#[derive(Debug, Default, Deserialize)]
struct MetricParams {
    #[serde(
        default,
        deserialize_with = "crate::times::optional_moment::deserialize"
    )]
    from: Option<Timestamp>,
    #[serde(
        default,
        deserialize_with = "crate::times::optional_moment::deserialize"
    )]
    to: Option<Timestamp>,
}

impl MetricParams {
    /// The range asked for, or nothing for one that's backwards, empty or too long.
    fn range(&self, default: impl FnOnce(Timestamp) -> Option<Timestamp>) -> Option<TimeRange> {
        let to = self.to.unwrap_or_else(times::now);
        let from = match self.from {
            Some(from) => from,
            None => default(to)?,
        };
        TimeRange::new(from, to)
    }

    /// The last [`DEFAULT_RANGE`] up to `to`, unless it says.
    fn usual_range(&self) -> Option<TimeRange> {
        self.range(|to| to.checked_sub_signed(DEFAULT_RANGE))
    }
}

#[derive(Debug, Serialize)]
struct MetricView {
    metric: String,
    unit: Unit,
    from: Timestamp,
    to: Timestamp,
    /// How long each point covers, from its time.
    step_secs: i64,
    #[serde(flatten)]
    result: SeriesResult,
}

impl MetricView {
    fn new(metric: &str, unit: Unit, range: TimeRange, result: SeriesResult) -> Self {
        Self {
            metric: metric.to_string(),
            unit,
            from: range.from,
            to: range.to,
            step_secs: range.step.num_seconds(),
            result,
        }
    }
}

async fn host_metric(
    State(state): State<AppState>,
    UrlPath((id, name)): UrlPath<(String, String)>,
    Query(params): Query<MetricParams>,
) -> Response {
    let catalog = state.catalog();
    let (Some(host), Some(metric)) = (state.registry.get(&id).await, catalog.find(&name)) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let Some(range) = params.usual_range() else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    match state
        .metrics
        .series(&host.id, metric, range, MAX_SERIES)
        .await
    {
        Ok(result) => {
            Json(MetricView::new(&metric.name, metric.unit, range, result)).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn list_rules(State(state): State<AppState>) -> Response {
    match state.database.list_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Deserialize)]
struct PreviewParams {
    /// The saved rule this would replace, if any.
    id: Option<i64>,
}

/// What saving a rule would do, without saving it.
async fn preview_rule(
    State(state): State<AppState>,
    Query(params): Query<PreviewParams>,
    Json(input): Json<RuleInput>,
) -> Response {
    if let Some(response) = refuse_rule(&input) {
        return response;
    }
    match state.preview_rule(params.id, input).await {
        Ok(preview) => Json(preview).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_rule(id).await {
        Ok(Some(rule)) => Json(rule).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_rule(State(state): State<AppState>, Json(input): Json<RuleInput>) -> Response {
    if let Some(response) = refuse_rule(&input) {
        return response;
    }
    match state.database.create_rule(&input).await {
        Ok(id) => {
            state.config_changed();
            (StatusCode::CREATED, Json(json!({ "id": id }))).into_response()
        }
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn update_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<RuleInput>,
) -> Response {
    // A rule that comes with MaxNines can only be turned on or off.
    match state.database.get_rule(id).await {
        Ok(Some(saved)) if saved.built_in.is_some() => {
            if !crate::models::same_rule(&saved.rule, &input) {
                return refused_built_in(
                    "this rule comes with MaxNines, so only `enabled` can change. Add a rule of your own after it to change what it sets",
                );
            }
            return match state.database.set_rule_enabled(id, input.enabled).await {
                Ok(true) => {
                    state.config_changed();
                    StatusCode::NO_CONTENT.into_response()
                }
                Ok(false) => StatusCode::NOT_FOUND.into_response(),
                Err(error) => server_error(&error),
            };
        }
        Ok(_) => {}
        Err(error) => return server_error(&error),
    }
    if let Some(response) = refuse_rule(&input) {
        return response;
    }
    match state.database.update_rule(id, &input).await {
        Ok(true) => {
            state.config_changed();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn delete_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_rule(id).await {
        Ok(Some(saved)) if saved.built_in.is_some() => {
            return refused_built_in(
                "this rule comes with MaxNines, so it can't be deleted, but it can be turned off",
            );
        }
        Ok(_) => {}
        Err(error) => return server_error(&error),
    }
    match state.database.delete_rule(id).await {
        Ok(true) => {
            state.config_changed();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn server_stats(State(state): State<AppState>) -> Json<crate::server_stats::ServerStats> {
    Json(crate::server_stats::gather(&state).await)
}

/// How many ended alerts the API returns.
const RESOLVED_ALERTS: u64 = 200;

#[derive(Serialize)]
struct OpenAlert {
    #[serde(flatten)]
    alert: Alert,
    /// The silence keeping its notifications back, if there is one.
    silence_id: Option<i64>,
    /// The maintenance window keeping them back, if there is one.
    maintenance_window_id: Option<i64>,
}

impl OpenAlert {
    fn new(alert: Alert, cover: Option<Cover>) -> Self {
        let (silence_id, maintenance_window_id) = match cover {
            Some(Cover::Silence { id, .. }) => (Some(id), None),
            Some(Cover::Window { id, .. }) => (None, Some(id)),
            None => (None, None),
        };
        Self {
            alert,
            silence_id,
            maintenance_window_id,
        }
    }
}

async fn list_alerts(State(state): State<AppState>) -> Response {
    let alerts = async {
        let silences = ActiveSilences::load(&state.database, times::now()).await?;
        let open: Vec<OpenAlert> = state
            .database
            .open_alerts()
            .await?
            .into_iter()
            .map(|alert| {
                let cover = silences.covering(&alert);
                OpenAlert::new(alert, cover)
            })
            .collect();
        let resolved = state.database.resolved_alerts(RESOLVED_ALERTS).await?;
        anyhow::Ok(json!({ "open": open, "resolved": resolved }))
    };
    match alerts.await {
        Ok(alerts) => Json(alerts).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Notifications that haven't arrived, as the Alerts page lists them.
async fn list_delivery_problems(State(state): State<AppState>) -> Response {
    match state
        .database
        .delivery_problems(super::alerts::PROBLEMS)
        .await
    {
        Ok(problems) => Json(problems).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn acknowledge_alert(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state
        .database
        .acknowledge_alert(id, &super::recorded_by(), times::now())
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn unacknowledge_alert(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.unacknowledge_alert(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// How many ended silences the API returns.
const ENDED_SILENCES: u64 = 200;

async fn list_silences(State(state): State<AppState>) -> Response {
    let now = times::now();
    let silences = async {
        let active = state.database.active_silences(now).await?;
        let ended = state.database.ended_silences(now, ENDED_SILENCES).await?;
        anyhow::Ok(json!({ "active": active, "ended": ended }))
    };
    match silences.await {
        Ok(silences) => Json(silences).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_silence(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_silence(id).await {
        Ok(Some(silence)) => Json(silence).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_silence(
    State(state): State<AppState>,
    Json(input): Json<SilenceInput>,
) -> Response {
    if let Err(error) = state.check_silence(&input).await {
        return refused(&error);
    }
    match state
        .database
        .create_silence(&input, &super::recorded_by(), times::now())
        .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn end_silence(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.end_silence(id, times::now()).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    metric: String,
    #[serde(default = "default_calculation")]
    calculation: String,
    #[serde(default)]
    group_by: String,
    #[serde(default)]
    filter: String,
    #[serde(
        default,
        deserialize_with = "crate::times::optional_moment::deserialize"
    )]
    from: Option<Timestamp>,
    #[serde(
        default,
        deserialize_with = "crate::times::optional_moment::deserialize"
    )]
    to: Option<Timestamp>,
}

fn default_calculation() -> String {
    Calculation::Avg.as_str().to_string()
}

async fn query(State(state): State<AppState>, Query(params): Query<QueryParams>) -> Response {
    let question = Question::new(
        &state.catalog(),
        &params.metric,
        &params.calculation,
        &params.group_by,
        &params.filter,
    );
    let question = match question {
        Ok(question) => question,
        Err(error) => return refused(&anyhow::anyhow!(error)),
    };
    let span = MetricParams {
        from: params.from,
        to: params.to,
    };
    let Some(range) = span.usual_range() else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    match calculations::answer(&state.sources(), &question, range, MAX_SERIES).await {
        Ok(result) => {
            let view = MetricView::new(&question.metric.name, question.unit(), range, result);
            Json(view).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn list_dashboards(State(state): State<AppState>) -> Response {
    match state.database.list_dashboards().await {
        Ok(dashboards) => Json(dashboards).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_dashboard(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => Json(dashboard).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Debug, Deserialize)]
struct DashboardInput {
    name: String,
}

async fn create_dashboard(
    State(state): State<AppState>,
    Json(input): Json<DashboardInput>,
) -> Response {
    let name = match check_name(&input.name) {
        Ok(name) => name,
        Err(error) => return refused(&anyhow::anyhow!(error)),
    };
    match state.database.create_dashboard(&name, times::now()).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn rename_dashboard(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<DashboardInput>,
) -> Response {
    let name = match check_name(&input.name) {
        Ok(name) => name,
        Err(error) => return refused(&anyhow::anyhow!(error)),
    };
    match state.database.rename_dashboard(id, &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_dashboard(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_dashboard(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn place_widgets(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(widgets): Json<Vec<Placed>>,
) -> Response {
    if let Err(error) = check_layout(&widgets) {
        return refused(&anyhow::anyhow!(error));
    }
    match state.database.get_dashboard(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    }
    match state.database.place_widgets(id, &widgets).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_widget(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<WidgetInput>,
) -> Response {
    let dashboard = match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => dashboard,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    if let Err(error) = input.check(&state.catalog(), &dashboard.variables) {
        return refused(&anyhow::anyhow!(error));
    }
    if dashboard.is_full() {
        return refused(&anyhow::anyhow!(
            "This dashboard has as many widgets as it can."
        ));
    }
    match state.database.create_widget(id, &input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_widget(
    State(state): State<AppState>,
    UrlPath((id, widget)): UrlPath<(i64, i64)>,
    Json(input): Json<WidgetInput>,
) -> Response {
    let dashboard = match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => dashboard,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    if let Err(error) = input.check(&state.catalog(), &dashboard.variables) {
        return refused(&anyhow::anyhow!(error));
    }
    match state.database.update_widget(id, widget, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_widget(
    State(state): State<AppState>,
    UrlPath((id, widget)): UrlPath<(i64, i64)>,
) -> Response {
    match state.database.delete_widget(id, widget).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// A variable with what its picker offers.
#[derive(Serialize)]
struct VariableView {
    #[serde(flatten)]
    variable: Variable,
    choices: Vec<dashboard_variables::Choice>,
}

async fn list_variables(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    let dashboard = match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => dashboard,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    let mut views = Vec::with_capacity(dashboard.variables.len());
    for variable in dashboard.variables {
        match dashboard_variables::choices(&state.sources(), &variable).await {
            Ok(choices) => views.push(VariableView { variable, choices }),
            Err(error) => return server_error(&error),
        }
    }
    Json(views).into_response()
}

async fn save_variables(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(variables): Json<Vec<Variable>>,
) -> Response {
    let dashboard = match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => dashboard,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    let variables: Vec<Variable> = variables.into_iter().map(Variable::tidy).collect();
    if let Err(error) = dashboard.check_variables(&variables) {
        return refused(&anyhow::anyhow!(error));
    }
    match state.database.save_variables(id, &variables).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// What a widget shows, with `var-<name>` parameters picking what its variables
/// stand for, as the dashboard's pickers do.
#[derive(Serialize)]
struct WidgetData {
    title: String,
    kind: String,
    /// The widget's filter with its variables filled in.
    filter: String,
    #[serde(flatten)]
    view: MetricView,
}

async fn widget_data(
    State(state): State<AppState>,
    UrlPath((id, widget_id)): UrlPath<(i64, i64)>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let dashboard = match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => dashboard,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    let Some(widget) = dashboard.widgets.iter().find(|w| w.id == widget_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Read by hand, as the rest of the parameters are the variables' picks.
    let moment = |name: &str| params.get(name).map(|text| times::parse_moment(text));
    let span = match (moment("from"), moment("to")) {
        (Some(None), _) | (_, Some(None)) => return StatusCode::BAD_REQUEST.into_response(),
        (from, to) => MetricParams {
            from: from.flatten(),
            to: to.flatten(),
        },
    };
    let Some(range) = span.usual_range() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let picks = match Picks::from_params(&state.sources(), &dashboard.variables, &params).await {
        Ok(picks) => picks,
        Err(error) => return server_error(&error),
    };
    let input = &widget.input;
    let question = picks
        .fill_filter(input.filter.as_deref())
        .and_then(|filter| input.question_for(&state.catalog(), filter.as_deref()));
    let question = match question {
        Ok(question) => question,
        Err(error) => return refused(&anyhow::anyhow!(error)),
    };
    match calculations::answer(&state.sources(), &question, range, input.max_lines()).await {
        Ok(result) => Json(WidgetData {
            title: input.title(&question, &picks),
            kind: input.kind.clone(),
            filter: question.filter.clone(),
            view: MetricView::new(&question.metric.name, question.unit(), range, result),
        })
        .into_response(),
        Err(error) => server_error(&error),
    }
}

/// How long a list of events covers unless asked.
const DEFAULT_EVENTS: TimeDelta = TimeDelta::days(7);
/// How long a host's timeline covers unless asked.
const DEFAULT_TIMELINE: TimeDelta = TimeDelta::days(1);
/// The longest time a list of events can cover, as for a metric.
const MAX_EVENTS_SPAN: TimeDelta = TimeDelta::days(366);
/// How many annotations a list returns unless asked, and the most it can.
const ANNOTATIONS_LIMIT: (u64, u64) = (200, 1000);
/// How many of a host's events a timeline returns unless asked, and the most it can.
const TIMELINE_LIMIT: (u64, u64) = (MAX_TIMELINE, MAX_TIMELINE);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventParams {
    #[serde(
        default,
        deserialize_with = "crate::times::optional_moment::deserialize"
    )]
    from: Option<Timestamp>,
    #[serde(
        default,
        deserialize_with = "crate::times::optional_moment::deserialize"
    )]
    to: Option<Timestamp>,
    limit: Option<u64>,
}

/// Which events a list asks for.
struct EventSpan {
    from: Timestamp,
    to: Timestamp,
    limit: u64,
}

impl EventParams {
    /// What's asked for, covering `usual` up to now unless given, and as many as the
    /// first of `limits` unless given, up to the second. Or why it can't be answered.
    fn span(&self, usual: TimeDelta, limits: (u64, u64)) -> Result<EventSpan, String> {
        let to = self.to.unwrap_or_else(times::now);
        let from = self.from.unwrap_or_else(|| to - usual);
        if from >= to {
            return Err("from has to be before to".to_string());
        }
        if to - from > MAX_EVENTS_SPAN {
            let days = MAX_EVENTS_SPAN.num_days();
            return Err(format!("from and to can be up to {days} days apart"));
        }
        let (usual_limit, max_limit) = limits;
        let limit = self.limit.unwrap_or(usual_limit);
        if !(1..=max_limit).contains(&limit) {
            return Err(format!("limit has to be from 1 to {max_limit}"));
        }
        Ok(EventSpan { from, to, limit })
    }
}

async fn list_events(State(state): State<AppState>, Query(params): Query<EventParams>) -> Response {
    let span = match params.span(DEFAULT_EVENTS, ANNOTATIONS_LIMIT) {
        Ok(span) => span,
        Err(error) => return failed(StatusCode::BAD_REQUEST, &error),
    };
    let annotations = state
        .database
        .list_annotations(span.from, span.to, span.limit);
    match annotations.await {
        Ok(events) => Json(events).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_event(State(state): State<AppState>, Json(input): Json<EventInput>) -> Response {
    let by = super::recorded_by();
    match state.record_event(input, &by, times::now()).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(EventRefusal::Invalid(message)) => {
            let body = Json(json!({ "error": message }));
            (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
        }
        Err(EventRefusal::Failed(error)) => server_error(&error),
    }
}

async fn show_event(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_annotation(id).await {
        Ok(Some(event)) => Json(event).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_event(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_annotation(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Everything that happened to one host, newest first: a day's worth unless asked, and
/// the newest `limit` of it.
async fn host_events(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Query(params): Query<EventParams>,
) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let span = match params.span(DEFAULT_TIMELINE, TIMELINE_LIMIT) {
        Ok(span) => span,
        Err(error) => return failed(StatusCode::BAD_REQUEST, &error),
    };
    match state.timeline(&id, span.from, span.to).await {
        Ok(mut events) => {
            events.truncate(usize::try_from(span.limit).unwrap_or(usize::MAX));
            Json(events).into_response()
        }
        Err(error) => server_error(&error),
    }
}

/// How many of a host's runs the API returns.
const ACTION_RUNS: u64 = 100;

async fn alert_actions(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_alert(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    }
    match state.database.action_runs_for_alert(id).await {
        Ok(runs) => Json(runs).into_response(),
        Err(error) => server_error(&error),
    }
}

/// What an alert watches over a time, as its page charts it: just its own series,
/// with the rule's thresholds. Without a range it reaches back past the start.
#[derive(Debug, Serialize)]
struct AlertSeriesView {
    alert_id: i64,
    metric: String,
    unit: Unit,
    thresholds: Vec<ThresholdView>,
    from: Timestamp,
    to: Timestamp,
    /// How long each point covers, from its time.
    step_secs: i64,
    #[serde(flatten)]
    result: SeriesResult,
}

#[derive(Debug, Serialize)]
struct ThresholdView {
    severity: &'static str,
    value: f64,
}

async fn alert_series(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Query(params): Query<MetricParams>,
) -> Response {
    let alert = match state.database.get_alert(id).await {
        Ok(Some(alert)) => alert,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    // A quarter as long again before it started, to show what led up to it, and
    // never less than the usual range.
    let started = alert.started_at;
    let range = params.range(|to| {
        let lead = (to - started) / 4;
        let usual = to.checked_sub_signed(DEFAULT_RANGE)?;
        Some(started.checked_sub_signed(lead)?.min(usual))
    });
    let Some(range) = range else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match alert_charts::watched(&state.sources(), &alert, range).await {
        Ok(Some(watched)) => Json(AlertSeriesView {
            alert_id: alert.id,
            metric: watched.metric.name.clone(),
            unit: watched.unit,
            thresholds: watched
                .rule
                .thresholds()
                .into_iter()
                .map(|(severity, value)| ThresholdView {
                    severity: severity.as_str(),
                    value,
                })
                .collect(),
            from: range.from,
            to: range.to,
            step_secs: range.step.num_seconds(),
            result: watched.result,
        })
        .into_response(),
        // An offline alert, or one whose rule is gone, has nothing to chart.
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// What a host's agent can be asked to run, and what has been.
async fn host_actions(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let found = async {
        let available = state.database.host_actions(&id).await?;
        let runs = state
            .database
            .action_runs_for_host(&id, ACTION_RUNS)
            .await?;
        anyhow::Ok((available, runs))
    };
    match found.await {
        Ok((available, runs)) => {
            let available: Vec<Value> = available
                .into_iter()
                .map(|(name, variables)| json!({ "name": name, "variables": variables }))
                .collect();
            Json(json!({ "available": available, "runs": runs })).into_response()
        }
        Err(error) => server_error(&error),
    }
}

#[derive(Deserialize)]
struct RunActionInput {
    action: String,
    #[serde(default)]
    variables: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "timeout_secs",
        with = "maxnines_protocol::time::optional_seconds"
    )]
    timeout: Option<Duration>,
}

/// Asks a host to run an action now. The answer is the run as it stands, which is
/// usually still waiting: read it again at `/action-runs/{id}` for how it went.
async fn run_action(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Json(input): Json<RunActionInput>,
) -> Response {
    if state.registry.get(&id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let timeout = input
        .timeout
        .unwrap_or(maxnines_protocol::actions::DEFAULT_ACTION_TIMEOUT);
    if let Err(error) = crate::actions::check_timeout(timeout) {
        return refused(&error);
    }
    let new = crate::actions::NewRun {
        host_id: id,
        alert_id: None,
        action: input.action,
        run_on: crate::actions::RUN_BY_HAND.to_string(),
        variables: input.variables,
        requested_by: Some(super::recorded_by()),
        requested_at: times::now(),
        timeout,
    };
    let run = async {
        let id = state.actions.run(new).await?;
        state.database.get_action_run(id).await
    };
    match run.await {
        Ok(Some(run)) => (StatusCode::CREATED, Json(run)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_action_run(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_action_run(id).await {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

fn refused(error: &anyhow::Error) -> Response {
    let body = Json(json!({ "error": format!("{error:#}") }));
    (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
}

async fn list_maintenance_windows(State(state): State<AppState>) -> Response {
    match state.database.list_maintenance_windows().await {
        Ok(windows) => Json(windows).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_maintenance_window(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
) -> Response {
    match state.database.get_maintenance_window(id).await {
        Ok(Some(window)) => Json(window).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_maintenance_window(
    State(state): State<AppState>,
    Json(input): Json<MaintenanceWindowInput>,
) -> Response {
    if let Err(error) = state.check_maintenance_window(&input).await {
        return refused(&error);
    }
    match state.database.create_maintenance_window(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_maintenance_window(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<MaintenanceWindowInput>,
) -> Response {
    if let Err(error) = state.check_maintenance_window(&input).await {
        return refused(&error);
    }
    match state.database.update_maintenance_window(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_maintenance_window(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
) -> Response {
    match state.database.delete_maintenance_window(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn list_location_rules(State(state): State<AppState>) -> Response {
    match state.database.list_location_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_location_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_location_rule(id).await {
        Ok(Some(rule)) => Json(rule).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_location_rule(
    State(state): State<AppState>,
    Json(input): Json<LocationRuleInput>,
) -> Response {
    if let Err(error) = check_rule(&input) {
        return refused(&error);
    }
    match state.database.create_location_rule(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_location_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<LocationRuleInput>,
) -> Response {
    if let Err(error) = check_rule(&input) {
        return refused(&error);
    }
    match state.database.update_location_rule(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_location_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
) -> Response {
    match state.database.delete_location_rule(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Every site on the map with its hosts, and the hosts no rule places.
async fn map(State(state): State<AppState>) -> Response {
    match super::map::map_data(&state).await {
        Ok(data) => Json(data).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn list_alert_rules(State(state): State<AppState>) -> Response {
    match state.database.list_alert_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_alert_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_alert_rule(id).await {
        Ok(Some(rule)) => Json(rule).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// How often a rule would have alerted over the last day, without saving it.
async fn replay_alert_rule(
    State(state): State<AppState>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    let conditions = match state.check_alert_rule(&input).await {
        Ok(conditions) => conditions,
        Err(error) => return refused(&error),
    };
    let now = crate::times::now();
    match crate::alert_replay::replay(&state.sources(), &input, None, conditions, now).await {
        Ok(replay) => Json(replay).into_response(),
        Err(error) => server_error(&error),
    }
}

/// How often a saved rule, changed as the body says, would have alerted over the
/// last day: for one of a template's alerts, on what the template's alert is for.
async fn replay_saved_alert_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    let saved = match state.database.get_alert_rule(id).await {
        Ok(Some(saved)) => saved,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    let conditions = match state.check_saved_alert_rule(id, &input).await {
        Ok(conditions) => conditions,
        Err(error) => return refused(&error),
    };
    let now = crate::times::now();
    let template = saved.template.as_ref();
    match crate::alert_replay::replay(&state.sources(), &input, template, conditions, now).await {
        Ok(replay) => Json(replay).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_alert_rule(
    State(state): State<AppState>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    if let Err(error) = state.check_alert_rule(&input).await {
        return refused(&error);
    }
    match state.database.create_alert_rule(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn update_alert_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    if let Err(error) = state.check_saved_alert_rule(id, &input).await {
        return refused(&error);
    }
    match state.database.update_alert_rule(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn delete_alert_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_alert_rule(id, times::now()).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<crate::templates::Refused>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

/// A check as the API shows it. Its password or key can be set but not read back.
#[derive(Debug, Serialize)]
struct RemoteCheckView {
    id: i64,
    host_id: String,
    check: maxnines_protocol::Check,
    interval_secs: u64,
    /// For a heartbeat: how late a ping can be.
    #[serde(skip_serializing_if = "Option::is_none")]
    grace_secs: Option<u64>,
    enabled: bool,
    read_stats: bool,
    /// How it signs in: `none`, `password`, `key`, or for UniFi, `api_key`.
    sign_in: SignInWith,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    has_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_env: Option<String>,
    has_private_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_env: Option<String>,
    has_api_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_env: Option<String>,
    /// How it last went, or nothing if it hasn't run since the server started.
    latest: Option<LatestCheck>,
}

/// A check's last run, as the Checks page shows it.
#[derive(Debug, Serialize)]
struct LatestCheck {
    up: bool,
    ran_at: Timestamp,
    /// Why it was down.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl RemoteCheckView {
    fn new(check: RemoteCheck, results: &LatestResults) -> Self {
        let latest = results
            .latest(check.id)
            .map(|(result, ran_at)| LatestCheck {
                up: result["up"] == 1,
                ran_at,
                error: result["error"].as_str().map(String::from),
            });
        let input = check.input;
        let sign_in = input.sign_in;
        Self {
            latest,
            id: check.id,
            host_id: input.host_id,
            check: input.check,
            interval_secs: input.interval.as_secs(),
            grace_secs: input.grace.map(|grace| grace.as_secs()),
            enabled: input.enabled,
            read_stats: input.read_stats,
            sign_in: sign_in.with(),
            has_password: sign_in.password.is_some(),
            has_private_key: sign_in.private_key.is_some(),
            has_api_key: sign_in.api_key.is_some(),
            api_key_env: sign_in.api_key_env,
            username: sign_in.username,
            password_env: sign_in.password_env,
            private_key_env: sign_in.private_key_env,
        }
    }
}

/// A check as a request gives it. `sign_in` says how it signs in, which is the
/// only way to keep a saved password or key without sending it again.
#[derive(Deserialize)]
struct RemoteCheckRequest {
    /// The host with no agent it's about. Adding a check without one makes a new
    /// host for it, and changing one without one leaves it where it is.
    #[serde(default)]
    host_id: Option<String>,
    /// The new host's name, when one is made. Left out, it's named after the host
    /// the check reaches.
    #[serde(default)]
    hostname: Option<String>,
    #[serde(flatten)]
    input: RemoteCheckInput,
    #[serde(default)]
    sign_in: Option<SignInWith>,
}

async fn list_remote_checks(State(state): State<AppState>) -> Response {
    match state.database.list_remote_checks().await {
        Ok(checks) => {
            let views: Vec<RemoteCheckView> = checks
                .into_iter()
                .map(|check| RemoteCheckView::new(check, &state.check_results))
                .collect();
            Json(views).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn show_remote_check(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_remote_check(id).await {
        Ok(Some(check)) => Json(RemoteCheckView::new(check, &state.check_results)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_remote_check(
    State(state): State<AppState>,
    Json(request): Json<RemoteCheckRequest>,
) -> Response {
    let host = state.check_new_remote_check(
        request.host_id.as_deref(),
        request.hostname.as_deref(),
        &request.input,
    );
    let host = match host.await {
        Ok(host) => host,
        Err(error) => return refused(&error),
    };
    match state
        .add_remote_check(host, request.input, &super::recorded_by())
        .await
    {
        Ok((id, host_id)) => {
            let mut added = json!({ "id": id, "host_id": host_id });
            // Whoever adds a heartbeat needs its address, and only they may see it.
            match state.database.get_remote_check(id).await {
                Ok(Some(RemoteCheck {
                    ping_token: Some(token),
                    ..
                })) => {
                    added["ping_url"] = json!(heartbeats::ping_url(&state.web_url, &token));
                }
                Ok(_) => {}
                Err(error) => return server_error(&error),
            }
            (StatusCode::CREATED, Json(added)).into_response()
        }
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn update_remote_check(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(request): Json<RemoteCheckRequest>,
) -> Response {
    let saved = match state.database.get_remote_check(id).await {
        Ok(Some(saved)) => saved,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    if request.hostname.is_some() {
        let error = anyhow::anyhow!("a hostname is only for a new host, made as a check is added");
        return refused(&error);
    }
    let mut input = request.input;
    input.host_id = request.host_id.unwrap_or(saved.input.host_id);
    if crate::destinations::same_place(&saved.input.check.target, &input.check.target) {
        input.sign_in = input
            .sign_in
            .keeping_secrets_of(&saved.input.sign_in, request.sign_in);
    }
    if let Err(error) = state.check_remote_check(&input).await {
        return refused(&error);
    }
    match state.database.update_remote_check(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

/// Gives a heartbeat a new address, so the old one stops working, and says what it
/// is. It's never shown otherwise, as reading a check needs less than changing one.
async fn new_ping_address(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.new_ping_token(id).await {
        Ok(Some(token)) => {
            let url = heartbeats::ping_url(&state.web_url, &token);
            Json(json!({ "ping_url": url })).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_remote_check(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_remote_check(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// A channel as the API shows it. A webhook's URL can be set but not read back.
#[derive(Debug, Serialize)]
struct ChannelView {
    id: i64,
    name: String,
    kind: ChannelKind,
    target_preview: String,
    severities: std::collections::BTreeSet<crate::alerting::Severity>,
    /// Who email comes from and the mail server, for email channels. The password
    /// is write-only, like every other secret.
    mail: Option<crate::alerting::Mail>,
    /// What a custom webhook sends. Its headers are write-only, so only their
    /// names are shown.
    request: Option<crate::alerting::WebhookRequest>,
    header_names: Option<Vec<String>>,
    /// A PagerDuty account's service region.
    region: Option<crate::alerting::PagerDutyRegion>,
}

impl ChannelView {
    fn new(channel: crate::alerting::Channel) -> Self {
        Self {
            id: channel.id,
            target_preview: channel.channel.target_preview(),
            severities: channel.channel.severities.clone(),
            mail: channel.channel.mail.clone(),
            request: channel.channel.request.clone(),
            region: channel.channel.region,
            header_names: (channel.channel.kind == ChannelKind::CustomWebhook).then(|| {
                crate::channels::custom_webhook::header_names(
                    channel.channel.credential.as_deref().unwrap_or_default(),
                )
            }),
            name: channel.channel.name,
            kind: channel.channel.kind,
        }
    }
}

async fn list_channels(State(state): State<AppState>) -> Response {
    match state.database.list_channels().await {
        Ok(channels) => {
            let views: Vec<ChannelView> = channels.into_iter().map(ChannelView::new).collect();
            Json(views).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn show_channel(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_channel(id).await {
        Ok(Some(channel)) => Json(ChannelView::new(channel)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_channel(
    State(state): State<AppState>,
    Json(input): Json<ChannelInput>,
) -> Response {
    if let Err(error) = alerting::check_channel(&input) {
        return refused(&error);
    }
    match state.database.create_channel(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn update_channel(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<ChannelInput>,
) -> Response {
    let input = match state.database.get_channel(id).await {
        Ok(Some(saved)) => input.keeping_secrets_of(&saved.channel),
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    if let Err(error) = alerting::check_channel(&input) {
        return refused(&error);
    }
    match state.database.update_channel(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) if error.is::<NameTaken>() => refused(&error),
        Err(error) => server_error(&error),
    }
}

async fn delete_channel(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_channel(id, times::now()).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Explains what's wrong with a rule, if anything.
fn refused_built_in(why: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "error": why })),
    )
        .into_response()
}

/// A name another rule has is refused as the rule is saved, as only the database can
/// tell for certain.
fn refuse_rule(input: &RuleInput) -> Option<Response> {
    rule_engine::check_rule(input)
        .err()
        .map(|error| refused(&error))
}

pub(super) fn server_error(error: &anyhow::Error) -> Response {
    error!(error = format!("{error:#}"), "admin request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn approve(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    decide(&state, &id, HostState::Approved).await
}

async fn revoke(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    decide(&state, &id, HostState::Revoked).await
}

async fn delete_host(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    match state.delete_host(&id).await {
        Ok(HostDeletion::Deleted) => StatusCode::NO_CONTENT.into_response(),
        Ok(HostDeletion::NoSuchHost) => StatusCode::NOT_FOUND.into_response(),
        Ok(HostDeletion::NotRevoked) => {
            failed(StatusCode::CONFLICT, "Revoke the host before deleting it")
        }
        Err(error) => server_error(&error),
    }
}

/// Recorded as the key's owner, as a decision on the pages is.
async fn decide(state: &AppState, id: &str, decision: HostState) -> Response {
    let Some(owner) = super::signed_in_user() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.registry.decide_as(id, decision, &owner.email).await {
        Ok(Some(host)) => Json(host).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Sends a test notification. The error is the same one the channels page shows.
async fn test_channel(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    let channel = match state.database.get_channel(id).await {
        Ok(Some(channel)) => channel,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
    match notifier::send(channel, Notice::test(), None, state.senders.clone()).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => failed(StatusCode::BAD_GATEWAY, &format!("{error:#}")),
    }
}
