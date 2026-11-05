//! The admin API, which shares the server's port. It needs the admin token,
//! because a proxy may expose it.

use std::net::IpAddr;

use axum::extract::{Path as UrlPath, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::error;

use crate::alerting::{AlertRuleInput, ChannelInput, ChannelKind};
use crate::app_state::AppState;
use crate::facts::unflatten;
use crate::metrics::{self, METRICS, Metric, SeriesResult, TimeRange, Unit, now_ms};
use crate::models::{ConfigStatus, RuleInput};
use crate::presence::AgentPresence;
use crate::registration::{AgentRecord, AgentState, hash_token};
use crate::remote_checks::{RemoteCheck, RemoteCheckInput};
use crate::rule_engine::{self, ResolvedConfig};

/// An agent as admins see it.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentView {
    #[serde(flatten)]
    pub agent: AgentRecord,
    pub online: bool,
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

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/admin/agents", get(list))
        .route("/admin/agents/{id}/facts", get(facts))
        .route("/admin/agents/{id}/facts/history", get(facts_history))
        .route("/admin/agents/{id}/config", get(agent_config))
        .route("/admin/agents/{id}/metrics/{metric}", get(agent_metric))
        .route("/admin/metrics", get(metric_catalog))
        .route("/admin/metrics/current", get(current_metrics))
        .route("/admin/rules", get(list_rules).post(create_rule))
        .route(
            "/admin/rules/{id}",
            get(show_rule).put(update_rule).delete(delete_rule),
        )
        .route("/admin/server", get(server_stats))
        .route("/admin/alerts", get(list_alerts))
        .route(
            "/admin/alert-rules",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route(
            "/admin/alert-rules/{id}",
            get(show_alert_rule)
                .put(update_alert_rule)
                .delete(delete_alert_rule),
        )
        .route(
            "/admin/notification-channels",
            get(list_channels).post(create_channel),
        )
        .route(
            "/admin/notification-channels/{id}",
            get(show_channel).put(update_channel).delete(delete_channel),
        )
        .route(
            "/admin/remote-checks",
            get(list_remote_checks).post(create_remote_check),
        )
        .route(
            "/admin/remote-checks/{id}",
            get(show_remote_check)
                .put(update_remote_check)
                .delete(delete_remote_check),
        )
        .route("/admin/agents/{id}/approve", post(approve))
        .route("/admin/agents/{id}/revoke", post(revoke))
        .route_layer(middleware::from_fn_with_state(state, require_token))
}

async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match presented {
        Some(token) if hash_token(token) == *state.admin_token_hash => next.run(request).await,
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn list(State(state): State<AppState>) -> Json<Vec<AgentView>> {
    let agents = state.registry.list().await;
    let views = agents
        .into_iter()
        .filter(|agent| !agent.is_local())
        .map(|agent| {
            let presence: Option<AgentPresence> = state.presence.get(&agent.id);
            AgentView {
                online: presence.is_some_and(|p| p.online),
                last_seen_ms: presence.map(|p| p.last_seen_ms),
                agent,
            }
        })
        .collect();
    Json(views)
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

async fn list_alerts(State(state): State<AppState>) -> Response {
    let alerts = async {
        let open = state.database.open_alerts().await?;
        let resolved = state.database.resolved_alerts(RESOLVED_ALERTS).await?;
        anyhow::Ok(json!({ "open": open, "resolved": resolved }))
    };
    match alerts.await {
        Ok(alerts) => Json(alerts).into_response(),
        Err(error) => server_error(&error),
    }
}

fn refused(error: &anyhow::Error) -> Response {
    let body = Json(json!({ "error": format!("{error:#}") }));
    (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
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
    match state.database.delete_alert_rule(id).await {
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
}

impl ChannelView {
    fn new(channel: crate::alerting::Channel) -> Self {
        Self {
            id: channel.id,
            target_preview: channel.channel.target_preview(),
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

async fn decide(state: &AppState, id: &str, decision: AgentState) -> Response {
    match state.registry.decide(id, decision).await {
        Ok(Some(agent)) => Json(agent).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}
