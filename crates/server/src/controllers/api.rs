//! The versioned API, which shares the server's port. Everything the web pages can
//! see and do is here too. It needs an API key, because a proxy may expose it.

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::extract::{Path as UrlPath, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::error;

use super::agents::suggestions;
use super::fleet::Health;
use super::host_list::HostSearch;
use super::users::{refusal, setup_url};
use crate::alerting::{Alert, AlertRuleInput, ChannelInput, ChannelKind};
use crate::app_state::{AgentDeletion, AppState};
use crate::audit::Via;
use crate::calculations::{self, Calculation, Question};
use crate::dashboards::{Placed, WidgetInput, check_layout, check_name};
use crate::facts::unflatten;
use crate::locations::{LocationRuleInput, check_rule};
use crate::maintenance::MaintenanceWindowInput;
use crate::metrics::{self, METRICS, Metric, SeriesResult, TimeRange, Unit, now_ms};
use crate::models::User;
use crate::models::{
    ConfigStatus, RuleInput, UserChange, check_api_key_name, check_new_user, expiry_after, is_theme,
};
use crate::notifier::{self, Notice};
use crate::presence::AgentPresence;
use crate::registration::{AgentRecord, AgentState};
use crate::remote_checks::{RemoteCheck, RemoteCheckInput};
use crate::roles::Role;
use crate::rule_engine::{self, ResolvedConfig};
use crate::silences::{ActiveSilences, Cover, SilenceInput};
use crate::times::zone_named;

/// An agent as admins see it.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentView {
    #[serde(flatten)]
    pub agent: AgentRecord,
    pub online: bool,
    pub health: Health,
    pub last_seen_ms: Option<u64>,
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
    agent_id: String,
    state: AgentState,
    decided_by: Option<String>,
    online: bool,
    /// Where the latest connection came from, since the server started.
    source_address: Option<IpAddr>,
}

/// Where the API lives. A change that would break a client goes in a new version.
pub const BASE_PATH: &str = "/api/v1";

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/agents", get(list))
        .route("/agents/{id}", get(show_agent).delete(delete_agent))
        .route("/agents/{id}/facts", get(facts))
        .route("/agents/{id}/facts/history", get(facts_history))
        .route("/agents/{id}/config", get(agent_config))
        .route("/agents/{id}/metrics/{metric}", get(agent_metric))
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
            put(update_widget).delete(delete_widget),
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
        .route("/alerts/{id}/unacknowledge", post(unacknowledge_alert))
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
        .route("/agents/filter-options", get(filter_options))
        .route("/agents/{id}/approve", post(approve))
        .route("/agents/{id}/revoke", post(revoke))
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

/// Who a request acts as, and the key it came with, if it carries a working API key.
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
    let accepted = state.database.accept_api_key(key, now_ms()).await?;
    Ok(accepted.map(|(key, owner)| {
        let via = Via::ApiKey {
            id: key.id,
            name: key.name,
        };
        (owner, via)
    }))
}

async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
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
        .create_user(&email, &name, role, now_ms())
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
    after_user_change(state.database.disable_user(id, now_ms()).await)
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
    match state.database.new_setup_link(id, now_ms()).await {
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

#[derive(Deserialize)]
struct NewApiKey {
    name: String,
    /// How long it lasts. Leaving this out makes a key that doesn't expire.
    expires_in_secs: Option<u64>,
    /// The most it can do, up to what the key making it can. That, if left out.
    role: Option<Role>,
}

/// The only time a key can be seen.
async fn create_api_key(State(state): State<AppState>, Json(input): Json<NewApiKey>) -> Response {
    let name = input.name.trim();
    if let Err(error) = check_api_key_name(name) {
        return refused(&error);
    }
    let now = now_ms();
    let expires_ms = match input.expires_in_secs.map(|secs| expiry_after(secs, now)) {
        Some(Ok(expires)) => Some(expires),
        Some(Err(error)) => return refused(&error),
        None => None,
    };
    // Always someone, as every request here comes with a key that acts as its owner.
    let Some(owner) = super::signed_in_user() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let role = input.role.unwrap_or(owner.role);
    if role > owner.role {
        return failed(
            StatusCode::FORBIDDEN,
            "A key can't do more than the key making it",
        );
    }
    match state
        .database
        .create_api_key(name, owner.id, role, expires_ms, now)
        .await
    {
        Ok((details, key)) => {
            let mut body = json!(details);
            body["key"] = json!(key);
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn revoke_api_key(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match super::api_keys::revoke_if_allowed(&state, id).await {
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
    /// A filter, written as in the box on the agents page.
    q: Option<String>,
}

async fn list(State(state): State<AppState>, Query(params): Query<ListParams>) -> Response {
    let data = async {
        let search = HostSearch::load(&state, params.q.as_deref()).await?;
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
        alerts.entry(&alert.agent_id).or_default().push(alert);
    }

    let views: Vec<AgentView> = state
        .registry
        .list()
        .await
        .into_iter()
        .filter(|agent| !agent.is_local() && search.includes(&agent.id, &agent.host))
        .map(|agent| {
            let presence: Option<AgentPresence> = state.presence.get(&agent.id);
            let online = presence.as_ref().is_some_and(|p| p.online);
            let mine = alerts.get(agent.id.as_str()).map_or(&[][..], Vec::as_slice);
            AgentView {
                online,
                health: Health::of(online, mine),
                last_seen_ms: presence.map(|p| p.last_seen_ms),
                agent,
            }
        })
        .collect();
    Json(views).into_response()
}

async fn show_agent(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    let Some(agent) = state.registry.get(&id).await.filter(|a| !a.is_local()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let open = match state.database.open_alerts().await {
        Ok(open) => open,
        Err(error) => return server_error(&error),
    };
    let mine: Vec<&Alert> = open.iter().filter(|alert| alert.agent_id == id).collect();
    let presence = state.presence.get(&id);
    let online = presence.as_ref().is_some_and(|p| p.online);
    Json(AgentView {
        online,
        health: Health::of(online, &mine),
        last_seen_ms: presence.map(|p| p.last_seen_ms),
        agent,
    })
    .into_response()
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
    let Some(agent) = state.registry.get(&id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let current = match state.database.current_facts(&id).await {
        Ok(current) => current,
        Err(error) => return server_error(&error),
    };

    let presence = state.presence.get(&id);
    Json(FactsView {
        trusted: TrustedFacts {
            agent_id: agent.id,
            state: agent.state,
            decided_by: agent.decided_by,
            online: presence.is_some_and(|p| p.online),
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

/// How much a query covers unless it says otherwise.
const DEFAULT_RANGE_MS: i64 = 3_600_000;

/// Enough for any real machine, while an agent inventing names can't make a
/// response huge.
const MAX_SERIES: usize = 100;

async fn metric_catalog() -> Json<&'static [Metric]> {
    Json(METRICS)
}

async fn current_metrics(State(state): State<AppState>) -> Response {
    match state.metrics.current(now_ms()).await {
        Ok(current) => Json(current).into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Debug, Deserialize)]
struct MetricParams {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
struct MetricView {
    metric: &'static str,
    unit: Unit,
    from_ms: i64,
    to_ms: i64,
    step_ms: i64,
    #[serde(flatten)]
    result: SeriesResult,
}

async fn agent_metric(
    State(state): State<AppState>,
    UrlPath((id, name)): UrlPath<(String, String)>,
    Query(params): Query<MetricParams>,
) -> Response {
    let (Some(agent), Some(metric)) = (state.registry.get(&id).await, metrics::find(&name)) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let to_ms = params.to_ms.unwrap_or_else(now_ms);
    let from_ms = params
        .from_ms
        .unwrap_or_else(|| to_ms.saturating_sub(DEFAULT_RANGE_MS));
    let Some(range) = TimeRange::new(from_ms, to_ms) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    match state
        .metrics
        .series(&agent.id, metric, range, MAX_SERIES)
        .await
    {
        Ok(result) => Json(MetricView {
            metric: metric.name,
            unit: metric.unit,
            from_ms,
            to_ms,
            step_ms: range.step_ms,
            result,
        })
        .into_response(),
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
    if let Some(response) = refuse_rule(&state, &input, params.id).await {
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
    if let Some(response) = refuse_rule(&state, &input, None).await {
        return response;
    }
    match state.database.create_rule(&input).await {
        Ok(id) => {
            state.config_changed();
            (StatusCode::CREATED, Json(json!({ "id": id }))).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn update_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<RuleInput>,
) -> Response {
    if let Some(response) = refuse_rule(&state, &input, Some(id)).await {
        return response;
    }
    match state.database.update_rule(id, &input).await {
        Ok(true) => {
            state.config_changed();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
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
    silenced_by: Option<i64>,
    /// The maintenance window keeping them back, if there is one.
    maintenance_window: Option<i64>,
}

impl OpenAlert {
    fn new(alert: Alert, cover: Option<Cover>) -> Self {
        let (silenced_by, maintenance_window) = match cover {
            Some(Cover::Silence { id, .. }) => (Some(id), None),
            Some(Cover::Window { id, .. }) => (None, Some(id)),
            None => (None, None),
        };
        Self {
            alert,
            silenced_by,
            maintenance_window,
        }
    }
}

async fn list_alerts(State(state): State<AppState>) -> Response {
    let alerts = async {
        let silences = ActiveSilences::load(&state.database, now_ms()).await?;
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
        Ok(problems) => {
            let problems: Vec<_> = problems
                .into_iter()
                .filter(|problem| problem.state != "sent")
                .collect();
            Json(problems).into_response()
        }
        Err(error) => server_error(&error),
    }
}

async fn acknowledge_alert(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.acknowledge_alert(id, "api", now_ms()).await {
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
    let now = now_ms();
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
    match state.database.create_silence(&input, "api", now_ms()).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn end_silence(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.end_silence(id, now_ms()).await {
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
    from_ms: Option<i64>,
    to_ms: Option<i64>,
}

fn default_calculation() -> String {
    Calculation::Avg.as_str().to_string()
}

async fn query(State(state): State<AppState>, Query(params): Query<QueryParams>) -> Response {
    let question = Question::new(
        &params.metric,
        &params.calculation,
        &params.group_by,
        &params.filter,
    );
    let question = match question {
        Ok(question) => question,
        Err(error) => return refused(&anyhow::anyhow!(error)),
    };
    let to_ms = params.to_ms.unwrap_or_else(now_ms);
    let from_ms = params
        .from_ms
        .unwrap_or_else(|| to_ms.saturating_sub(DEFAULT_RANGE_MS));
    let Some(range) = TimeRange::new(from_ms, to_ms) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    match calculations::answer(&state.sources(), &question, range, MAX_SERIES).await {
        Ok(result) => Json(MetricView {
            metric: question.metric.name,
            unit: question.unit(),
            from_ms,
            to_ms,
            step_ms: range.step_ms,
            result,
        })
        .into_response(),
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
    match state.database.create_dashboard(&name, now_ms()).await {
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
    if let Err(error) = input.check() {
        return refused(&anyhow::anyhow!(error));
    }
    let dashboard = match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => dashboard,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error(&error),
    };
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
    if let Err(error) = input.check() {
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

/// Every site on the map with its machines, and the machines no rule places.
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

async fn create_alert_rule(
    State(state): State<AppState>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    if let Err(error) = state.check_alert_rule(&input, None).await {
        return refused(&error);
    }
    match state.database.create_alert_rule(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_alert_rule(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<AlertRuleInput>,
) -> Response {
    if let Err(error) = state.check_alert_rule(&input, Some(id)).await {
        return refused(&error);
    }
    match state.database.update_alert_rule(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_alert_rule(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_alert_rule(id, now_ms()).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn list_remote_checks(State(state): State<AppState>) -> Response {
    match state.database.list_remote_checks().await {
        Ok(checks) => Json::<Vec<RemoteCheck>>(checks).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn show_remote_check(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.get_remote_check(id).await {
        Ok(Some(check)) => Json(check).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create_remote_check(
    State(state): State<AppState>,
    Json(input): Json<RemoteCheckInput>,
) -> Response {
    if let Err(error) = state.check_remote_check(&input, None).await {
        return refused(&error);
    }
    match state.database.create_remote_check(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_remote_check(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<RemoteCheckInput>,
) -> Response {
    if let Err(error) = state.check_remote_check(&input, Some(id)).await {
        return refused(&error);
    }
    match state.database.update_remote_check(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
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
}

impl ChannelView {
    fn new(channel: crate::alerting::Channel) -> Self {
        Self {
            id: channel.id,
            target_preview: channel.channel.target_preview(),
            severities: channel.channel.severities.clone(),
            mail: channel.channel.mail.clone(),
            request: channel.channel.request.clone(),
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
    if let Err(error) = state.check_channel(&input, None).await {
        return refused(&error);
    }
    match state.database.create_channel(&input).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update_channel(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<i64>,
    Json(input): Json<ChannelInput>,
) -> Response {
    if let Err(error) = state.check_channel(&input, Some(id)).await {
        return refused(&error);
    }
    match state.database.update_channel(id, &input).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_channel(State(state): State<AppState>, UrlPath(id): UrlPath<i64>) -> Response {
    match state.database.delete_channel(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

/// Explains what's wrong with a rule, if anything.
async fn refuse_rule(state: &AppState, input: &RuleInput, id: Option<i64>) -> Option<Response> {
    let problem = match rule_engine::check_rule(input) {
        Err(error) => format!("{error:#}"),
        Ok(()) => match state.database.list_rules().await {
            Err(error) => return Some(server_error(&error)),
            Ok(rules) => {
                let taken = rules
                    .iter()
                    .any(|rule| rule.rule.name == input.name && Some(rule.id) != id);
                if !taken {
                    return None;
                }
                format!("a rule named {:?} already exists", input.name)
            }
        },
    };
    Some(
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": problem })),
        )
            .into_response(),
    )
}

fn server_error(error: &anyhow::Error) -> Response {
    error!(error = format!("{error:#}"), "admin request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn approve(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    decide(&state, &id, AgentState::Approved).await
}

async fn revoke(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    decide(&state, &id, AgentState::Revoked).await
}

async fn delete_agent(State(state): State<AppState>, UrlPath(id): UrlPath<String>) -> Response {
    match state.delete_agent(&id).await {
        Ok(AgentDeletion::Deleted) => StatusCode::NO_CONTENT.into_response(),
        Ok(AgentDeletion::NoSuchAgent) => StatusCode::NOT_FOUND.into_response(),
        Ok(AgentDeletion::NotRevoked) => {
            failed(StatusCode::CONFLICT, "Revoke the agent before deleting it")
        }
        Err(error) => server_error(&error),
    }
}

/// Recorded as the key's owner, as a decision on the pages is.
async fn decide(state: &AppState, id: &str, decision: AgentState) -> Response {
    let Some(owner) = super::signed_in_user() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.registry.decide_as(id, decision, &owner.email).await {
        Ok(Some(agent)) => Json(agent).into_response(),
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
