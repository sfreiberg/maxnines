//! The MCP server: how an assistant finds out how to sign in, which tools each role
//! sees, and that what they do goes through the API and into the audit log.

use super::*;
use crate::roles::Role;

/// The protocol version these tests speak.
const PROTOCOL: &str = "2025-11-25";

/// What the MCP server answered: the status, the headers and the JSON.
struct Answer {
    status: u16,
    headers: String,
    body: Value,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        let prefix = format!("{}: ", name.to_lowercase());
        self.headers.lines().find_map(|line| {
            line.to_lowercase()
                .starts_with(&prefix)
                .then(|| &line[prefix.len()..])
        })
    }
}

/// Sends a JSON-RPC message to the MCP server, as an assistant does.
async fn mcp(server: &TestServer, token: Option<&str>, message: &Value) -> Answer {
    let body = message.to_string();
    let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: x\r\n{auth}Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: {PROTOCOL}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (headers, text) = response.split_once("\r\n\r\n").unwrap();
    Answer {
        status: headers.split_whitespace().nth(1).unwrap().parse().unwrap(),
        headers: headers.to_string(),
        body: serde_json::from_str(text).unwrap_or(Value::Null),
    }
}

/// Calls a tool, giving back its result.
async fn call_tool(server: &TestServer, token: &str, name: &str, arguments: Value) -> Value {
    let message = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    });
    let answer = mcp(server, Some(token), &message).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    answer.body["result"].clone()
}

/// The names of the tools a token is shown.
pub(super) async fn tool_names(server: &TestServer, token: &str) -> Vec<String> {
    let message = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let answer = mcp(server, Some(token), &message).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    answer.body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect()
}

/// An API key of the test user's that acts with at most `role`.
async fn key_with(server: &TestServer, role: Role) -> String {
    let database = &server.state.database;
    let user = server.user_id().await;
    let name = format!("{} assistant", role.as_str());
    let (_, secret) = database
        .create_api_key(&name, user, role, None, crate::times::now())
        .await
        .unwrap();
    secret
}

#[tokio::test]
async fn an_assistant_finds_out_where_to_sign_in_without_signing_in() {
    let server = start().await;
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let response = server.http("GET", path, None).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{path}: {response}");
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        let metadata: Value = serde_json::from_str(body).unwrap();
        assert_eq!(metadata["resource"], "http://x/mcp", "{path}");
        assert_eq!(metadata["authorization_servers"], json!(["http://x"]));
    }
}

#[tokio::test]
async fn without_a_working_token_the_mcp_server_says_where_to_sign_in() {
    let server = start().await;
    let initialize = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });

    let answer = mcp(&server, None, &initialize).await;
    assert_eq!(answer.status, 401);
    assert_eq!(
        answer.header("www-authenticate"),
        Some(r#"Bearer resource_metadata="http://x/.well-known/oauth-protected-resource/mcp""#)
    );

    let answer = mcp(&server, Some("mxa_wrong"), &initialize).await;
    assert_eq!(answer.status, 401);
    assert_eq!(
        answer.header("www-authenticate"),
        Some(
            r#"Bearer error="invalid_token", resource_metadata="http://x/.well-known/oauth-protected-resource/mcp""#
        )
    );
}

#[tokio::test]
async fn an_api_key_connects_and_reads_through_the_tools() {
    let server = start().await;
    host_without_agent(&server, "db-1.example.com").await;
    let key = key_with(&server, Role::Viewer).await;

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "tests", "version": "1" },
        },
    });
    let answer = mcp(&server, Some(&key), &initialize).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.header("content-type"), Some("application/json"));
    let result = &answer.body["result"];
    assert_eq!(result["protocolVersion"], PROTOCOL);
    assert_eq!(result["serverInfo"]["name"], "maxnines");
    assert!(result["capabilities"]["tools"].is_object(), "{result}");

    let result = call_tool(&server, &key, "list_hosts", json!({})).await;
    assert_ne!(result["isError"], true, "{result}");
    let listed = &result["structuredContent"];
    assert_eq!(listed["total"], 1, "{listed}");
    assert_eq!(listed["hosts"][0]["hostname"], "db-1.example.com");
    assert_eq!(listed["cut_short"], false);
    // The same as text, for assistants that only read that.
    let text = result["content"][0]["text"].as_str().unwrap();
    assert_eq!(serde_json::from_str::<Value>(text).unwrap(), *listed);

    // A filter as on the Hosts page.
    let result = call_tool(&server, &key, "list_hosts", json!({ "filter": "web*" })).await;
    assert_eq!(result["structuredContent"]["total"], 0, "{result}");

    // A host that isn't there, and an argument the tool doesn't take, are the
    // assistant's to fix.
    let result = call_tool(&server, &key, "get_host", json!({ "host_id": "nope" })).await;
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no host with that ID"),
        "{result}"
    );
    let result = call_tool(&server, &key, "list_hosts", json!({ "hostname": "x" })).await;
    assert_eq!(result["isError"], true, "{result}");

    // A notification needs no answer, and there's no stream of messages to open, as
    // the server keeps no sessions.
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let answer = mcp(&server, Some(&key), &initialized).await;
    assert_eq!(answer.status, 202, "{}", answer.body);
    let response = server.http("GET", "/mcp", Some(&key)).await;
    assert!(response.starts_with("HTTP/1.1 405"), "{response}");
}

#[tokio::test]
async fn each_role_sees_only_the_tools_it_can_use() {
    let server = start().await;
    let viewer = key_with(&server, Role::Viewer).await;
    let responder = key_with(&server, Role::Responder).await;

    let seen = tool_names(&server, &viewer).await;
    for read in ["list_hosts", "get_host", "list_alerts", "get_host_metric"] {
        assert!(seen.iter().any(|name| name == read), "{read}: {seen:?}");
    }
    for write in ["acknowledge_alert", "create_silence", "end_silence"] {
        assert!(!seen.iter().any(|name| name == write), "{write}: {seen:?}");
    }
    let seen_by_responder = tool_names(&server, &responder).await;
    assert_eq!(
        seen_by_responder.len(),
        seen.len() + 3,
        "{seen_by_responder:?}"
    );

    // Asking anyway is refused, and nothing is made.
    let silence = json!({ "reason": "Deploying", "duration_secs": 600, "all_alerts": true });
    let result = call_tool(&server, &viewer, "create_silence", silence).await;
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        result["content"][0]["text"],
        "create_silence needs the responder role, and this connection acts as a viewer"
    );
    let now = crate::times::now();
    let active = server.state.database.active_silences(now).await.unwrap();
    assert!(active.is_empty());
}

#[tokio::test]
async fn what_a_responder_does_over_mcp_is_recorded_as_theirs() {
    let server = start().await;
    let responder = key_with(&server, Role::Responder).await;

    let silence = json!({ "reason": "Deploying", "duration_secs": 600, "all_alerts": true });
    let result = call_tool(&server, &responder, "create_silence", silence).await;
    assert_ne!(result["isError"], true, "{result}");
    let made = &result["structuredContent"]["silence"];
    assert_eq!(made["reason"], "Deploying", "{made}");
    assert_eq!(made["created_by"], "test@example.com");
    let id = made["id"].as_i64().unwrap();

    // The same checks as the page and the API.
    let unbounded = json!({ "reason": "Deploying", "duration_secs": 600 });
    let result = call_tool(&server, &responder, "create_silence", unbounded).await;
    assert_eq!(result["isError"], true, "{result}");

    let result = call_tool(
        &server,
        &responder,
        "end_silence",
        json!({ "silence_id": id }),
    )
    .await;
    assert_eq!(result["structuredContent"]["ended"], true, "{result}");

    let entries = server.state.database.audit_log(None, 10).await.unwrap();
    let made = entries
        .iter()
        .find(|entry| entry.subject.kind == "silence" && entry.action == "created")
        .unwrap();
    assert_eq!(made.actor.name, "test@example.com");
    let via = made.via.as_ref().unwrap();
    assert_eq!(via.kind, "mcp_api_key");
    assert_eq!(via.name, "responder assistant");
    assert_eq!(
        made.via_label().as_deref(),
        Some("via API key responder assistant over MCP")
    );
    assert!(made.source.is_some(), "{made:?}");
    assert!(
        entries
            .iter()
            .any(|entry| entry.subject.kind == "silence" && entry.action == "changed")
    );
}

#[tokio::test]
async fn get_host_says_which_drives_pass_and_which_services_failed() {
    let server = start_with_metrics().await;
    let host = identity();
    let mut client = server.connect_approved(&host, "nas-1").await;
    let id = host.id();
    let readings = BTreeMap::from([
        (
            "smart".to_string(),
            json!([
                { "name": "WDC WD40EFRX WD-1", "device": "/dev/sda", "model": "WDC WD40EFRX",
                  "healthy": 0, "temperature_celsius": 38.0, "asleep": 0, "note": "" },
            ]),
        ),
        (
            "raid".to_string(),
            json!([
                { "name": "/dev/md0", "kind": "md", "level": "raid1", "state": "degraded",
                  "not_working": "1 missing", "note": "", "devices": 2, "working_devices": 1,
                  "degraded": 1, "failed": 0, "rebuilding": 0 },
            ]),
        ),
        (
            "updates".to_string(),
            json!({ "manager": "apt", "pending": 4, "security": 1, "reboot_required": 0,
                    "lists_age_secs": 600, "problem": "", "note": "" }),
        ),
        (
            "services".to_string(),
            json!([{ "name": "nginx.service", "running": 0, "state": "failed" }]),
        ),
        (
            "system".to_string(),
            json!({ "processes": 90, "failed_services": 1,
                    "failed_service_names": "nginx.service" }),
        ),
    ]);
    let sample = Sample {
        time: crate::times::now(),
        metrics: readings,
    };
    send(&mut client, &AgentMessage::Sample(sample)).await;
    let key = key_with(&server, Role::Viewer).await;

    let deadline = Instant::now() + Duration::from_secs(5);
    let host = loop {
        let result = call_tool(&server, &key, "get_host", json!({ "host_id": id })).await;
        assert_ne!(result["isError"], true, "{result}");
        let host = result["structuredContent"].clone();
        if host["services"]["failed"].is_object()
            && host["drives"]["total"] == 1
            && host["raid"]["total"] == 1
        {
            break host;
        }
        assert!(
            Instant::now() < deadline,
            "the sample never arrived: {host}"
        );
        tokio::time::timeout(Duration::from_millis(10), client.next())
            .await
            .ok();
    };
    assert_eq!(host["drives"]["drives"][0]["healthy"], false, "{host}");
    assert_eq!(host["drives"]["drives"][0]["device"], "/dev/sda", "{host}");
    assert_eq!(host["drives"]["problem"], Value::Null, "{host}");
    assert_eq!(host["drives"]["cut_short"], false, "{host}");
    assert_eq!(host["raid"]["arrays"][0]["name"], "/dev/md0", "{host}");
    assert_eq!(host["raid"]["arrays"][0]["degraded"], true, "{host}");
    assert_eq!(host["raid"]["problems"], json!([]), "{host}");
    assert_eq!(host["raid"]["cut_short"], false, "{host}");
    assert_eq!(host["updates"]["pending"], 4, "{host}");
    assert_eq!(host["updates"]["reboot_required"], false, "{host}");
    assert_eq!(
        host["services"]["watched"][0],
        json!({ "name": "nginx.service", "running": false, "state": "failed" }),
        "{host}"
    );
    assert_eq!(
        host["services"]["failed"]["names"],
        json!(["nginx.service"]),
        "{host}"
    );
    assert_eq!(host["host"]["hostname"], "nas-1", "{host}");
    assert!(host["facts"].is_object(), "{host}");
}

#[tokio::test]
async fn every_read_tool_answers() {
    let server = start().await;
    let host = host_without_agent(&server, "db-1.example.com").await;
    let key = key_with(&server, Role::Viewer).await;

    for (name, arguments) in [
        ("get_host", json!({ "host_id": host })),
        ("list_alerts", json!({ "host_id": host })),
        ("list_metrics", json!({ "search": "cpu" })),
        (
            "get_host_metric",
            json!({ "host_id": host, "metric": "cpu.usage" }),
        ),
        (
            "query_metrics",
            json!({ "metric": "cpu.usage", "group_by": "host" }),
        ),
        ("list_checks", json!({})),
        ("list_silences", json!({})),
        ("list_host_events", json!({ "host_id": host, "limit": 5 })),
        ("list_annotations", json!({})),
    ] {
        let result = call_tool(&server, &key, name, arguments).await;
        assert_ne!(result["isError"], true, "{name}: {result}");
        assert!(result["structuredContent"].is_object(), "{name}: {result}");
    }

    // A host that hasn't read anything has nothing to say about them.
    let result = call_tool(&server, &key, "get_host", json!({ "host_id": host })).await;
    let shown = &result["structuredContent"];
    assert_eq!(shown["drives"]["total"], 0, "{shown}");
    assert_eq!(shown["raid"]["total"], 0, "{shown}");
    assert_eq!(shown["updates"], Value::Null, "{shown}");
    assert_eq!(shown["services"]["failed"], Value::Null, "{shown}");

    let result = call_tool(&server, &key, "list_metrics", json!({ "search": "cpu" })).await;
    let metrics = &result["structuredContent"]["metrics"];
    assert!(
        metrics
            .as_array()
            .unwrap()
            .iter()
            .any(|metric| metric["name"] == "cpu.usage")
    );
    let result = call_tool(
        &server,
        &key,
        "get_host_metric",
        json!({ "host_id": host, "metric": "cpu.usage", "from": "2026-11-24T10:00:00Z", "to": "2026-11-24T09:00:00Z" }),
    )
    .await;
    assert_eq!(result["isError"], true, "{result}");
    let result = call_tool(&server, &key, "get_alert", json!({ "alert_id": 999 })).await;
    assert_eq!(
        result["content"][0]["text"],
        "There's no alert with that ID"
    );
}
