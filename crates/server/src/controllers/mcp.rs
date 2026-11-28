//! The MCP server, which AI assistants such as Claude Code, Claude and ChatGPT connect
//! to: tools that read hosts, alerts, metrics, checks, silences and events, and for a
//! responder, acknowledge alerts and silence them. It's at [`PATH`] on the server's
//! one port, speaking MCP's Streamable HTTP transport without sessions, each answer
//! plain JSON.
//!
//! It signs in as the API does, with an API key or a signed-in app's access token, and
//! acts with the role that gives. Someone without either is told where to find out how
//! to sign in, as RFC 9728 has it, which is how an assistant knows to sign in through
//! the browser. Each tool is calls to the API's own routes, run as the caller, so what
//! it may do, what it checks and what the audit log records are the API's, marked as
//! made over MCP. A tool shows only for a role that can use it.

use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rmcp::ErrorData;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use super::api::{self, KeyHolder};
use super::app_sign_ins::site_origin;
use super::server_error;
use crate::app_state::AppState;
use crate::audit::{self, Acting, Via};
use crate::roles::{self, Role};

/// Where the MCP server is.
pub const PATH: &str = "/mcp";

/// Where an assistant finds out how to sign in to it, as RFC 9728 has it.
const RESOURCE_METADATA: &str = "/.well-known/oauth-protected-resource";

/// The most rows a list gives back, so an answer stays small enough for an assistant
/// to read. Each says when it was cut short.
const MAX_ROWS: usize = 100;
/// The most ended alerts and silences a list gives back.
const MAX_ENDED: usize = 50;
/// The most series a metric's readings give back.
const MAX_SERIES: usize = 10;
/// The most points, across all the series, a metric's readings give back.
const MAX_POINTS: usize = 1000;
/// The most of an API answer that's read.
const MAX_ANSWER_BYTES: usize = 16 * 1024 * 1024;

/// What a tool's answer says to an assistant about how to use the server.
const INSTRUCTIONS: &str = "MaxNines monitors hosts: their metrics, checks and alerts. \
    Find hosts with list_hosts, using a filter as on the Hosts page, then look closer \
    with get_host, get_host_metric, list_host_events and list_checks. list_alerts gives \
    what's open now. Times are RFC 3339, such as 2026-11-24T09:30:00Z. Acknowledging \
    alerts and silencing them needs the responder role, and is recorded in the audit \
    log as the person who connected.";

pub fn routes(state: AppState) -> Router<AppState> {
    let api = Router::new()
        .nest(api::BASE_PATH, api::routes(state.clone()))
        .with_state(state.clone());
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        // Every request needs a token, so another site's page can't use it through
        // someone's browser, which is what checking the address guards against.
        .disable_allowed_hosts();
    let service = StreamableHttpService::new(
        move || Ok(Tools { api: api.clone() }),
        std::sync::Arc::new(NeverSessionManager::default()),
        config,
    );
    Router::new()
        .route_service(PATH, service)
        .route_layer(middleware::from_fn_with_state(state, require_token))
        .route(RESOURCE_METADATA, get(protected_resource))
        .route(
            &format!("{RESOURCE_METADATA}{PATH}"),
            get(protected_resource),
        )
}

/// The MCP server's address, which tokens for it are for.
pub fn resource(state: &AppState, headers: &HeaderMap) -> String {
    format!("{}{PATH}", site_origin(state, headers))
}

/// RFC 9728: what the MCP server is, and who signs people in to it, which is this
/// server.
async fn protected_resource(State(state): State<AppState>, headers: HeaderMap) -> Response {
    Json(json!({
        "resource": resource(&state, &headers),
        "authorization_servers": [site_origin(&state, &headers)],
        "bearer_methods_supported": ["header"],
        "resource_name": "MaxNines",
    }))
    .into_response()
}

/// Who's calling, as their token says, and where from, for the API calls each tool
/// makes. Those run in tasks of their own, which don't carry the request's.
#[derive(Clone)]
struct Caller {
    holder: KeyHolder,
    acting: Acting,
}

/// Lets in only a request with a working API key or app token. Without one, it says
/// where to find out how to sign in, which is how an assistant knows to.
async fn require_token(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let presented = request.headers().contains_key(header::AUTHORIZATION);
    let (user, via) = match api::key_holder(&state, request.headers()).await {
        Ok(Some(holder)) => holder,
        Ok(None) => return unauthorized(&state, request.headers(), presented),
        Err(error) => return server_error(&error),
    };
    if state.require_two_factor.load(Ordering::Relaxed) && !user.two_factor {
        let body = Json(json!({ "error": super::SET_UP_TWO_FACTOR }));
        return (StatusCode::FORBIDDEN, body).into_response();
    }
    let caller = Caller {
        holder: KeyHolder {
            user,
            via: Via::Mcp(Box::new(via)),
        },
        acting: audit::current(),
    };
    request.extensions_mut().insert(caller);
    next.run(request).await
}

/// RFC 6750 and 9728: no token, or one that doesn't work, and where to find out how to
/// get one.
fn unauthorized(state: &AppState, headers: &HeaderMap, presented: bool) -> Response {
    let metadata = format!("{}{RESOURCE_METADATA}{PATH}", site_origin(state, headers));
    let challenge = if presented {
        format!("Bearer error=\"invalid_token\", resource_metadata=\"{metadata}\"")
    } else {
        format!("Bearer resource_metadata=\"{metadata}\"")
    };
    let body = Json(json!({
        "error": "Sign in with an API key or through the browser: send Authorization: Bearer and the key or token"
    }));
    let mut response = (StatusCode::UNAUTHORIZED, body).into_response();
    if let Ok(challenge) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    response
}

// The tools.

/// What the arguments of a tool can be.
#[derive(Clone, Copy)]
enum Param {
    Text,
    Integer,
    Flag,
}

/// One of a tool's arguments.
struct Arg {
    name: &'static str,
    kind: Param,
    required: bool,
    description: &'static str,
}

const fn arg(name: &'static str, kind: Param, description: &'static str) -> Arg {
    Arg {
        name,
        kind,
        required: false,
        description,
    }
}

const fn needed(name: &'static str, kind: Param, description: &'static str) -> Arg {
    Arg {
        name,
        kind,
        required: true,
        description,
    }
}

/// A tool, and the API call that says which role it needs.
struct Spec {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    args: &'static [Arg],
    method: Method,
    route: &'static str,
    /// For one that changes something: whether doing it again changes nothing more.
    idempotent: Option<bool>,
}

const FROM: Arg = arg(
    "from",
    Param::Text,
    "Start of the time range, RFC 3339, such as 2026-11-24T09:30:00Z",
);
const TO: Arg = arg(
    "to",
    Param::Text,
    "End of the time range, RFC 3339. Now if left out",
);
const HOST_ID: Arg = needed(
    "host_id",
    Param::Text,
    "The host's ID, from list_hosts. Not its hostname, which needn't be unique",
);

static TOOLS: [Spec; 14] = [
    Spec {
        name: "list_hosts",
        title: "List hosts",
        description: "The hosts MaxNines monitors: each one's ID, hostname, whether it's \
            online, its health from its open alerts, and when it was last heard from. A \
            filter narrows them, written as in the box on the Hosts page, such as \
            `hostname=web*`, `os=linux` or `custom.role=db`.",
        args: &[arg(
            "filter",
            Param::Text,
            "A host filter, as on the Hosts page. Every host if left out",
        )],
        method: Method::GET,
        route: "/hosts",
        idempotent: None,
    },
    Spec {
        name: "get_host",
        title: "Get a host",
        description: "One host: whether it's online, its health, the facts its agent \
            reports, such as its operating system, hardware, addresses and disks, and what \
            its newest readings say: whether each drive passes its own SMART check, \
            whether each RAID array and ZFS pool is degraded, failed or rebuilding, the \
            updates waiting and whether it needs a reboot, whether a time service keeps \
            its clock in sync, the services it watches and whether they're running, and \
            the services that failed.",
        args: &[HOST_ID],
        method: Method::GET,
        route: "/hosts/{id}",
        idempotent: None,
    },
    Spec {
        name: "list_alerts",
        title: "List alerts",
        description: "The alerts open now, each with its rule, host, severity, summary and \
            whether someone's acknowledged it or a silence covers it, then the most recent \
            that have ended.",
        args: &[arg(
            "host_id",
            Param::Text,
            "Only this host's alerts. Every host's if left out",
        )],
        method: Method::GET,
        route: "/alerts",
        idempotent: None,
    },
    Spec {
        name: "get_alert",
        title: "Get an alert",
        description: "One alert, and the readings of the series it watches around when it \
            fired, with its rule's thresholds.",
        args: &[
            needed(
                "alert_id",
                Param::Integer,
                "The alert's ID, from list_alerts",
            ),
            FROM,
            TO,
        ],
        method: Method::GET,
        route: "/alerts/{id}/series",
        idempotent: None,
    },
    Spec {
        name: "list_metrics",
        title: "List metrics",
        description: "Every metric MaxNines can read, with its name, title, unit and the \
            collector or template it's from. Use a name with get_host_metric or \
            query_metrics.",
        args: &[arg(
            "search",
            Param::Text,
            "Only metrics whose name or title has this in it, ignoring case",
        )],
        method: Method::GET,
        route: "/metrics",
        idempotent: None,
    },
    Spec {
        name: "get_host_metric",
        title: "Get a host's metric",
        description: "A host's readings of one metric over a time range, the last hour \
            unless given, rolled up into at most 240 points per series, each with the \
            average, least and most. A metric with several series, such as one per disk, \
            gives each.",
        args: &[
            HOST_ID,
            needed(
                "metric",
                Param::Text,
                "The metric's name, such as cpu.usage, from list_metrics",
            ),
            FROM,
            TO,
        ],
        method: Method::GET,
        route: "/hosts/{id}/metrics/{metric}",
        idempotent: None,
    },
    Spec {
        name: "query_metrics",
        title: "Query metrics across hosts",
        description: "A metric across hosts over a time range, the last hour unless given, \
            calculated and grouped, such as the average CPU use of each host running \
            Linux.",
        args: &[
            needed(
                "metric",
                Param::Text,
                "The metric's name, from list_metrics",
            ),
            arg(
                "calculation",
                Param::Text,
                "avg, min, max, sum, or count for how many are reporting. avg if left out",
            ),
            arg(
                "group_by",
                Param::Text,
                "What gets a line of its own: nothing, host, series, or fact:<name> such as \
                 fact:os.family. nothing if left out",
            ),
            arg(
                "filter",
                Param::Text,
                "Only hosts this host filter matches, as on the Hosts page",
            ),
            FROM,
            TO,
        ],
        method: Method::GET,
        route: "/query",
        idempotent: None,
    },
    Spec {
        name: "list_checks",
        title: "List checks",
        description: "The checks MaxNines runs itself, such as HTTP, ping, TLS \
            certificates, databases and heartbeats: what each checks, how often, and how \
            it last went.",
        args: &[arg(
            "host_id",
            Param::Text,
            "Only checks about this host. Every check if left out",
        )],
        method: Method::GET,
        route: "/remote-checks",
        idempotent: None,
    },
    Spec {
        name: "list_silences",
        title: "List silences",
        description: "The silences holding back alerts' notifications now, with what each \
            covers, why and until when, then the most recent that have ended.",
        args: &[],
        method: Method::GET,
        route: "/silences",
        idempotent: None,
    },
    Spec {
        name: "list_host_events",
        title: "List a host's events",
        description: "Everything that happened to one host, newest first: annotations such \
            as deploys, restarts, config changes, alerts, and agent and system updates. \
            The last day unless given.",
        args: &[
            HOST_ID,
            FROM,
            TO,
            arg("limit", Param::Integer, "The most to give back, up to 100"),
        ],
        method: Method::GET,
        route: "/hosts/{id}/events",
        idempotent: None,
    },
    Spec {
        name: "list_annotations",
        title: "List annotations",
        description: "Annotations across all hosts, such as deploys and notes people and \
            automations added, newest first. The last week unless given.",
        args: &[
            FROM,
            TO,
            arg("limit", Param::Integer, "The most to give back, up to 100"),
        ],
        method: Method::GET,
        route: "/annotations",
        idempotent: None,
    },
    Spec {
        name: "acknowledge_alert",
        title: "Acknowledge an alert",
        description: "Says someone is dealing with an open alert, as its Acknowledge \
            button does, so reminders stop. Recorded as the person who connected.",
        args: &[needed(
            "alert_id",
            Param::Integer,
            "The open alert's ID, from list_alerts",
        )],
        method: Method::POST,
        route: "/alerts/{id}/acknowledge",
        idempotent: Some(true),
    },
    Spec {
        name: "create_silence",
        title: "Silence alerts",
        description: "Holds back notifications of the alerts it covers for a while: those \
            of one alert rule, on the hosts a filter matches, for one series, or any mix. \
            all_alerts has to be true to cover every alert. Recorded as the person who \
            connected.",
        args: &[
            needed("reason", Param::Text, "Why, which people are shown"),
            needed(
                "duration_secs",
                Param::Integer,
                "How long it lasts, in seconds, such as 3600 for an hour",
            ),
            arg(
                "rule_id",
                Param::Integer,
                "Only this alert rule's alerts, by the rule_id an alert has",
            ),
            arg(
                "filter",
                Param::Text,
                "Only alerts about hosts this host filter matches, such as id=<host_id> for one host",
            ),
            arg(
                "series",
                Param::Text,
                "Only alerts about this series, such as a disk's mount point",
            ),
            arg(
                "all_alerts",
                Param::Flag,
                "True to cover every alert, with no rule, filter or series",
            ),
        ],
        method: Method::POST,
        route: "/silences",
        idempotent: Some(false),
    },
    Spec {
        name: "end_silence",
        title: "End a silence",
        description: "Ends a silence now, so the alerts it covered notify again.",
        args: &[needed(
            "silence_id",
            Param::Integer,
            "The silence's ID, from list_silences",
        )],
        method: Method::POST,
        route: "/silences/{id}/end",
        idempotent: Some(true),
    },
];

impl Spec {
    /// The least role that can use it, as the API call it makes needs.
    fn needs(&self) -> Role {
        roles::required(&self.method, self.route)
    }

    fn definition(&self) -> Tool {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for arg in self.args {
            let kind = match arg.kind {
                Param::Text => "string",
                Param::Integer => "integer",
                Param::Flag => "boolean",
            };
            properties.insert(
                arg.name.to_string(),
                json!({ "type": kind, "description": arg.description }),
            );
            if arg.required {
                required.push(arg.name);
            }
        }
        let schema = json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        });
        let Value::Object(schema) = schema else {
            unreachable!("a schema is an object");
        };
        let annotations = match self.idempotent {
            None => ToolAnnotations::with_title(self.title)
                .read_only(true)
                .open_world(false),
            Some(idempotent) => ToolAnnotations::with_title(self.title)
                .read_only(false)
                .destructive(false)
                .idempotent(idempotent)
                .open_world(false),
        };
        Tool::new(self.name, self.description, schema)
            .with_title(self.title)
            .with_annotations(annotations)
    }
}

fn spec(name: &str) -> Option<&'static Spec> {
    TOOLS.iter().find(|spec| spec.name == name)
}

/// The MCP server for one request.
#[derive(Clone)]
struct Tools {
    /// The API's routes, which each tool calls.
    api: Router,
}

/// Who's calling, which [`require_token`] put on the request.
fn caller(context: &RequestContext<RoleServer>) -> Result<Caller, ErrorData> {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Caller>())
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("nobody is signed in", None))
}

impl ServerHandler for Tools {
    fn get_info(&self) -> ServerConfig {
        let mut implementation = Implementation::new("maxnines", env!("CARGO_PKG_VERSION"));
        implementation.title = Some("MaxNines".to_string());
        implementation.website_url = Some("https://maxnines.com".to_string());
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(implementation)
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let role = caller(&context)?.holder.user.role;
        let tools = TOOLS
            .iter()
            .filter(|spec| spec.needs() <= role)
            .map(Spec::definition)
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let caller = caller(&context)?;
        let Some(spec) = spec(&request.name) else {
            let message = format!("There's no tool called {}", request.name);
            return Err(ErrorData::invalid_params(message, None));
        };
        let role = caller.holder.user.role;
        if spec.needs() > role {
            let message = format!(
                "{} needs the {} role, and this connection acts as {} {}",
                spec.name,
                spec.needs().as_str(),
                super::article(role),
                role.as_str()
            );
            return Ok(refused(message).into());
        }
        let args = Args(request.arguments.unwrap_or_default());
        let call = Call {
            api: self.api.clone(),
            caller: caller.clone(),
        };
        let answer = audit::acting(caller.acting, call.run(spec, &args)).await;
        Ok(match answer {
            Ok(value) => CallToolResult::structured(value),
            Err(message) => refused(message),
        }
        .into())
    }
}

/// A tool's answer that it couldn't do what was asked, which the assistant reads.
fn refused(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

/// A tool's arguments.
struct Args(JsonObject);

impl Args {
    /// Checks them against the tool's, so a misspelled one isn't silently ignored.
    fn check(&self, spec: &Spec) -> Result<(), String> {
        for name in self.0.keys() {
            if !spec.args.iter().any(|arg| arg.name == name) {
                return Err(format!("{} doesn't take {name}", spec.name));
            }
        }
        for arg in spec.args {
            let value = self.0.get(arg.name).filter(|value| !value.is_null());
            let Some(value) = value else {
                if arg.required {
                    return Err(format!("{} needs {}", spec.name, arg.name));
                }
                continue;
            };
            let fits = match arg.kind {
                Param::Text => value.is_string(),
                Param::Integer => value.is_i64(),
                Param::Flag => value.is_boolean(),
            };
            if !fits {
                let kind = match arg.kind {
                    Param::Text => "text",
                    Param::Integer => "a whole number",
                    Param::Flag => "true or false",
                };
                return Err(format!("{} has to be {kind}", arg.name));
            }
        }
        Ok(())
    }

    fn text(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    }

    fn integer(&self, name: &str) -> Option<i64> {
        self.0.get(name).and_then(Value::as_i64)
    }

    /// The ones given of `names`, as a query string for the API.
    fn query(&self, names: &[&str]) -> String {
        let pairs: Vec<(&str, String)> = names
            .iter()
            .filter_map(|name| {
                let value = self.0.get(*name)?;
                let value = match value {
                    Value::String(text) if !text.is_empty() => text.clone(),
                    Value::Number(number) => number.to_string(),
                    _ => return None,
                };
                Some((*name, value))
            })
            .collect();
        if pairs.is_empty() {
            return String::new();
        }
        format!(
            "?{}",
            serde_urlencoded::to_string(pairs).unwrap_or_default()
        )
    }
}

/// Characters that go into an address as they are, as RFC 3986 has them.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Text as one part of an address's path.
fn segment(text: &str) -> String {
    utf8_percent_encode(text, SEGMENT).to_string()
}

/// A tool being run: calls to the API as the caller.
struct Call {
    api: Router,
    caller: Caller,
}

/// What an API call answered.
struct Answer {
    status: StatusCode,
    body: Value,
}

impl Answer {
    /// The body, if the call worked, or what to tell the assistant: what the API said
    /// was wrong, or for an answer with nothing to say, `missing` for not found.
    fn ok(self, missing: &str) -> Result<Value, String> {
        if self.status.is_success() {
            return Ok(self.body);
        }
        if let Some(error) = self.body["error"].as_str() {
            return Err(error.to_string());
        }
        Err(match self.status {
            StatusCode::NOT_FOUND => missing.to_string(),
            StatusCode::BAD_REQUEST => {
                "That time range doesn't work: from has to be before to, and neither in the \
                 future"
                    .to_string()
            }
            status if status.is_server_error() => {
                "MaxNines couldn't answer that just now. Try again".to_string()
            }
            status => format!("MaxNines refused that, with status {}", status.as_u16()),
        })
    }
}

impl Call {
    /// Asks the API, as the caller, for `path` under its base.
    async fn api(&self, method: Method, path: &str, body: Option<Value>) -> Result<Answer, String> {
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", api::BASE_PATH))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .map_err(|error| format!("That isn't a request MaxNines can make: {error}"))?;
        request.extensions_mut().insert(self.caller.holder.clone());
        let Ok(response) = self.api.clone().oneshot(request).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), MAX_ANSWER_BYTES)
            .await
            .map_err(|_| "MaxNines' answer was too long".to_string())?;
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok(Answer { status, body })
    }

    async fn get(&self, path: &str, missing: &str) -> Result<Value, String> {
        self.api(Method::GET, path, None).await?.ok(missing)
    }

    async fn run(&self, spec: &Spec, args: &Args) -> Result<Value, String> {
        args.check(spec)?;
        let host = || segment(args.text("host_id").unwrap_or_default());
        const NO_HOST: &str = "There's no host with that ID. list_hosts gives their IDs";
        const NO_ALERT: &str = "There's no alert with that ID";
        const NO_SILENCE: &str = "There's no silence with that ID";
        match spec.name {
            "list_hosts" => {
                let hosts = self
                    .get(&format!("/hosts{}", args.query(&["filter"])), "")
                    .await?;
                Ok(rows("hosts", hosts, MAX_ROWS))
            }
            "get_host" => {
                let shown = self.get(&format!("/hosts/{}", host()), NO_HOST).await?;
                let facts = self
                    .get(&format!("/hosts/{}/facts", host()), NO_HOST)
                    .await?;
                let mut drives = self
                    .get(&format!("/hosts/{}/drives", host()), NO_HOST)
                    .await?;
                let mut raid = self
                    .get(&format!("/hosts/{}/raid", host()), NO_HOST)
                    .await?;
                let updates = self
                    .get(&format!("/hosts/{}/updates", host()), NO_HOST)
                    .await?;
                let time_sync = self
                    .get(&format!("/hosts/{}/time-sync", host()), NO_HOST)
                    .await?;
                let mut services = self
                    .get(&format!("/hosts/{}/services", host()), NO_HOST)
                    .await?;
                let mut drives_listed = rows("drives", drives["drives"].take(), MAX_ROWS);
                drives_listed["problem"] = drives["problem"].take();
                let mut raid_listed = rows("arrays", raid["arrays"].take(), MAX_ROWS);
                raid_listed["problems"] = raid["problems"].take();
                let mut watched = rows("watched", services["watched"].take(), MAX_ROWS);
                watched["failed"] = services["failed"].take();
                Ok(json!({
                    "host": shown,
                    "facts": facts,
                    "drives": drives_listed,
                    "raid": raid_listed,
                    "updates": updates,
                    "time_sync": time_sync,
                    "services": watched,
                }))
            }
            "list_alerts" => {
                let mut alerts = self.get("/alerts", "").await?;
                if let Some(host_id) = args.text("host_id") {
                    for list in ["open", "resolved"] {
                        if let Some(rows) = alerts[list].as_array_mut() {
                            rows.retain(|alert| alert["host_id"] == host_id);
                        }
                    }
                }
                Ok(json!({
                    "open": rows("alerts", alerts["open"].take(), MAX_ROWS),
                    "resolved": rows("alerts", alerts["resolved"].take(), MAX_ENDED),
                }))
            }
            "get_alert" => {
                let id = args.integer("alert_id").unwrap_or_default();
                let mut alerts = self.get("/alerts", "").await?;
                let alert = ["open", "resolved"].into_iter().find_map(|list| {
                    let rows = alerts[list].as_array_mut()?;
                    let at = rows.iter().position(|alert| alert["id"] == id)?;
                    Some(rows.swap_remove(at))
                });
                let path = format!("/alerts/{id}/series{}", args.query(&["from", "to"]));
                let answer = self.api(Method::GET, &path, None).await?;
                let series = match answer.status {
                    // An alert about the host as a whole has no series to chart.
                    StatusCode::NOT_FOUND if alert.is_some() => Value::Null,
                    _ => cut_series(answer.ok(NO_ALERT)?),
                };
                Ok(json!({ "alert": alert, "series": series }))
            }
            "list_metrics" => {
                let mut metrics = self.get("/metrics", "").await?;
                if let (Some(search), Some(all)) = (args.text("search"), metrics.as_array_mut()) {
                    let search = search.to_lowercase();
                    all.retain(|metric| {
                        ["name", "title"].iter().any(|field| {
                            metric[field]
                                .as_str()
                                .is_some_and(|text| text.to_lowercase().contains(&search))
                        })
                    });
                }
                Ok(rows("metrics", metrics, 2 * MAX_ROWS))
            }
            "get_host_metric" => {
                let metric = segment(args.text("metric").unwrap_or_default());
                let path = format!(
                    "/hosts/{}/metrics/{metric}{}",
                    host(),
                    args.query(&["from", "to"])
                );
                let missing = "There's no host with that ID, or no metric with that name. \
                    list_hosts and list_metrics give them";
                Ok(cut_series(self.get(&path, missing).await?))
            }
            "query_metrics" => {
                let path = format!(
                    "/query{}",
                    args.query(&["metric", "calculation", "group_by", "filter", "from", "to"])
                );
                Ok(cut_series(self.get(&path, "").await?))
            }
            "list_checks" => {
                let mut checks = self.get("/remote-checks", "").await?;
                if let (Some(host_id), Some(all)) = (args.text("host_id"), checks.as_array_mut()) {
                    all.retain(|check| check["host_id"] == host_id);
                }
                Ok(rows("checks", checks, MAX_ROWS))
            }
            "list_silences" => {
                let mut silences = self.get("/silences", "").await?;
                Ok(json!({
                    "active": rows("silences", silences["active"].take(), MAX_ROWS),
                    "ended": rows("silences", silences["ended"].take(), MAX_ENDED),
                }))
            }
            "list_host_events" => {
                let path = format!(
                    "/hosts/{}/events{}",
                    host(),
                    args.query(&["from", "to", "limit"])
                );
                Ok(rows("events", self.get(&path, NO_HOST).await?, MAX_ROWS))
            }
            "list_annotations" => {
                let path = format!("/annotations{}", args.query(&["from", "to", "limit"]));
                Ok(rows("annotations", self.get(&path, "").await?, MAX_ROWS))
            }
            "acknowledge_alert" => {
                let id = args.integer("alert_id").unwrap_or_default();
                let path = format!("/alerts/{id}/acknowledge");
                let missing = "There's no open alert with that ID";
                self.api(Method::POST, &path, None).await?.ok(missing)?;
                Ok(json!({ "alert_id": id, "acknowledged": true }))
            }
            "create_silence" => {
                let mut input = args.0.clone();
                input.entry("all_alerts").or_insert(Value::Bool(false));
                let made = self
                    .api(Method::POST, "/silences", Some(Value::Object(input)))
                    .await?
                    .ok("")?;
                let id = made["id"].as_i64().unwrap_or_default();
                let silence = self.get(&format!("/silences/{id}"), NO_SILENCE).await?;
                Ok(json!({ "silence": silence }))
            }
            "end_silence" => {
                let id = args.integer("silence_id").unwrap_or_default();
                let path = format!("/silences/{id}/end");
                self.api(Method::POST, &path, None).await?.ok(NO_SILENCE)?;
                Ok(json!({ "silence_id": id, "ended": true }))
            }
            name => Err(format!("There's no tool called {name}")),
        }
    }
}

/// A list as a tool gives it back: at most `most` rows, saying how many there were and
/// whether it was cut short.
fn rows(name: &str, list: Value, most: usize) -> Value {
    let Value::Array(mut list) = list else {
        return json!({ name: [], "total": 0, "cut_short": false });
    };
    let total = list.len();
    list.truncate(most);
    let mut answer = json!({ name: list, "total": total, "cut_short": total > most });
    if total > most {
        answer["note"] = json!(format!(
            "Only the first {most} of {total} are here. Narrow it down to see the rest."
        ));
    }
    answer
}

/// A metric's readings as a tool gives them back: at most [`MAX_SERIES`] series and
/// [`MAX_POINTS`] points, keeping whole series, and saying how many were left out.
fn cut_series(mut readings: Value) -> Value {
    let Some(series) = readings["series"].as_array_mut() else {
        return readings;
    };
    let mut points = 0;
    let mut kept = 0;
    for one in series.iter() {
        let these = one["points"].as_array().map_or(0, Vec::len);
        if kept == MAX_SERIES || (kept > 0 && points + these > MAX_POINTS) {
            break;
        }
        points += these;
        kept += 1;
    }
    let left_out = series.len() - kept;
    series.truncate(kept);
    if left_out > 0 {
        let hidden = readings["hidden"].as_u64().unwrap_or_default();
        readings["hidden"] = json!(hidden + left_out as u64);
        readings["cut_short"] = json!(true);
        readings["note"] = json!(format!(
            "{left_out} more series were left out to keep this short. Ask for fewer, such \
             as with a filter or a shorter time range."
        ));
    } else {
        readings["cut_short"] = json!(readings["hidden"].as_u64().unwrap_or_default() > 0);
    }
    readings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_tool_needs_the_role_its_api_call_needs() {
        let needs = |name: &str| spec(name).unwrap().needs();
        for name in ["list_hosts", "get_host", "list_alerts", "get_host_metric"] {
            assert_eq!(needs(name), Role::Viewer, "{name}");
        }
        for name in ["acknowledge_alert", "create_silence", "end_silence"] {
            assert_eq!(needs(name), Role::Responder, "{name}");
        }
        // Only those that change something are marked as doing so.
        for spec in &TOOLS {
            let reads = spec.method == Method::GET;
            assert_eq!(spec.idempotent.is_none(), reads, "{}", spec.name);
            let tool = spec.definition();
            let hints = tool.annotations.unwrap();
            assert_eq!(hints.read_only_hint, Some(reads), "{}", spec.name);
        }
    }

    #[test]
    fn long_lists_and_readings_are_cut_short_and_say_so() {
        let list = rows("hosts", json!([1, 2, 3]), 2);
        assert_eq!(list["hosts"], json!([1, 2]));
        assert_eq!(list["total"], 3);
        assert_eq!(list["cut_short"], true);
        assert!(list["note"].as_str().unwrap().contains("first 2 of 3"));
        assert_eq!(rows("hosts", json!([1]), 2)["cut_short"], false);

        let point = json!({ "time": "2026-11-24T00:00:00Z", "avg": 1.0, "min": 1.0, "max": 1.0 });
        let series = |n: usize| json!({ "name": "x", "points": vec![point.clone(); n] });
        let readings = json!({ "series": vec![series(600); 3], "hidden": 2 });
        let cut = cut_series(readings);
        assert_eq!(cut["series"].as_array().unwrap().len(), 1);
        assert_eq!(cut["hidden"], 4);
        assert_eq!(cut["cut_short"], true);
        let whole = cut_series(json!({ "series": [series(10)], "hidden": 0 }));
        assert_eq!(whole["cut_short"], false);
    }

    #[test]
    fn arguments_are_checked_against_the_tools() {
        let spec = spec("get_host_metric").unwrap();
        let args = |value: Value| Args(value.as_object().unwrap().clone());
        assert!(
            args(json!({ "host_id": "a", "metric": "cpu.usage" }))
                .check(spec)
                .is_ok()
        );
        let missing = args(json!({ "host_id": "a" })).check(spec).unwrap_err();
        assert_eq!(missing, "get_host_metric needs metric");
        let unknown = args(json!({ "host_id": "a", "metric": "m", "hostname": "x" }));
        assert_eq!(
            unknown.check(spec).unwrap_err(),
            "get_host_metric doesn't take hostname"
        );
        let wrong = args(json!({ "host_id": 1, "metric": "m" })).check(spec);
        assert_eq!(wrong.unwrap_err(), "host_id has to be text");
        assert_eq!(segment("a/b c"), "a%2Fb%20c");
        assert_eq!(
            args(json!({ "from": "2026-11-24T00:00:00+01:00", "limit": 5 }))
                .query(&["from", "to", "limit"]),
            "?from=2026-11-24T00%3A00%3A00%2B01%3A00&limit=5"
        );
    }
}
