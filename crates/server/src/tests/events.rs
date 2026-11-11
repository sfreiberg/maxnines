//! Events marked on machines' charts: annotations people and scripts add, and what the
//! server notices.

use super::*;
use crate::alerting::{NewAlert, Severity};

/// Calls the API with the admin token, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

async fn machine(server: &TestServer, host: &str, facts: Value) -> (Identity, Client) {
    let agent = identity();
    let mut client = server.connect_approved(&agent, host).await;
    send(&mut client, &AgentMessage::Facts { facts }).await;
    server.wait_for_facts(&agent.id(), 1).await;
    (agent, client)
}

async fn timeline(server: &TestServer, agent: &Identity) -> Vec<Value> {
    let path = format!("/api/v1/agents/{}/events", agent.id());
    let (status, events) = api(server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200, "{events}");
    events.as_array().unwrap().clone()
}

fn titles(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event["title"].as_str().unwrap())
        .collect()
}

/// Waits until the machine's timeline has an event of this kind.
async fn wait_for_kind(server: &TestServer, agent: &Identity, kind: &str) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = timeline(server, agent).await;
        if events.iter().any(|event| event["kind"] == kind) {
            return events;
        }
        assert!(Instant::now() < deadline, "no {kind}: {events:?}");
        sleep(Duration::from_millis(20)).await;
    }
}

fn with_boot(boot_secs: i64) -> AgentMessage {
    AgentMessage::Sample(Sample {
        timestamp_ms: now_ms() as u64,
        metrics: BTreeMap::from([(
            "host".to_string(),
            json!({ "uptime_secs": 60, "boot_time_secs": boot_secs }),
        )]),
    })
}

#[tokio::test]
async fn a_deploy_is_marked_on_the_machines_its_filter_picks() {
    let server = start().await;
    let (web, _web_client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let (db, _db_client) = machine(&server, "db-1", json!({ "role": "db" })).await;

    let deploy = json!({ "kind": "deploy", "title": "Shop v2.3", "detail": "Build 812", "filter": "role=web" });
    let (status, event) = api(&server, "POST", "/api/v1/annotations", &deploy).await;

    assert_eq!(status, 201, "{event}");
    let path = format!("/api/v1/annotations/{}", event["id"]);
    let (_, event) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(event["kind"], "deploy");
    assert_eq!(event["filter"], "role=web");
    let events = timeline(&server, &web).await;
    assert_eq!(titles(&events), ["Shop v2.3"]);
    assert_eq!(events[0]["detail"], "Build 812");
    assert_eq!(events[0]["by"], "test@example.com");
    assert!(timeline(&server, &db).await.is_empty());
}

#[tokio::test]
async fn an_event_without_a_filter_is_for_every_machine() {
    let server = start().await;
    let (web, _web_client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let (db, _db_client) = machine(&server, "db-1", json!({ "role": "db" })).await;

    let (status, event) = api(
        &server,
        "POST",
        "/api/v1/annotations",
        &json!({ "title": "Network change" }),
    )
    .await;

    assert_eq!(status, 201, "{event}");
    let path = format!("/api/v1/annotations/{}", event["id"]);
    assert_eq!(
        api(&server, "GET", &path, &Value::Null).await.1["kind"],
        "note"
    );
    assert_eq!(titles(&timeline(&server, &web).await), ["Network change"]);
    assert_eq!(titles(&timeline(&server, &db).await), ["Network change"]);
}

#[tokio::test]
async fn an_annotation_of_the_servers_own_kind_or_with_a_broken_filter_is_refused() {
    let server = start().await;
    let _machine = machine(&server, "web-1", json!({ "role": "web" })).await;

    for body in [
        json!({ "title": "Broken", "filter": "role=\"unclosed" }),
        json!({ "title": "Fake", "kind": "restart" }),
        json!({ "title": "" }),
        json!({ "title": "Old", "time_ms": 1000 }),
        json!({ "title": "Typo", "unknown": true }),
    ] {
        let (status, refusal) = api(&server, "POST", "/api/v1/annotations", &body).await;
        assert!(
            matches!(status, 400 | 422),
            "{body} gave {status} {refusal}"
        );
    }
    let (_, events) = api(&server, "GET", "/api/v1/annotations", &Value::Null).await;
    assert_eq!(events, json!([]));
}

#[tokio::test]
async fn an_event_can_be_dated_when_it_happened() {
    let server = start().await;
    let (web, _client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let earlier = now_ms() - 2 * 3_600_000;

    let body = json!({ "title": "Deployed before lunch", "kind": "deploy", "time_ms": earlier });
    let (status, _) = api(&server, "POST", "/api/v1/annotations", &body).await;

    assert_eq!(status, 201);
    assert_eq!(timeline(&server, &web).await[0]["time_ms"], earlier);
    let (_, listed) = api(&server, "GET", "/api/v1/annotations", &Value::Null).await;
    assert_eq!(listed[0]["time_ms"], earlier);
}

#[tokio::test]
async fn deleting_an_event_takes_it_off_every_machine_and_is_audited() {
    let server = start().await;
    let (web, _client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let (_, event) = api(
        &server,
        "POST",
        "/api/v1/annotations",
        &json!({ "title": "Oops" }),
    )
    .await;
    let path = format!("/api/v1/annotations/{}", event["id"]);

    let (status, _) = api(&server, "DELETE", &path, &Value::Null).await;

    assert_eq!(status, 204);
    assert!(timeline(&server, &web).await.is_empty());
    assert_eq!(api(&server, "GET", &path, &Value::Null).await.0, 404);
    assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 404);
    let (_, entries) = api(&server, "GET", "/api/v1/audit-log", &Value::Null).await;
    let actions: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["subject"]["kind"] == "event")
        .map(|entry| entry["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["deleted", "created"]);
}

#[tokio::test]
async fn a_restart_is_noticed_from_the_boot_time_and_a_backlog_is_not_one() {
    let server = start().await;
    let (agent, mut client) = machine(&server, "web-1", json!({ "n": 1 })).await;
    let first_boot = now_ms() / 1000 - 86_400;

    // The first boot time the server hears of is no restart.
    send(&mut client, &with_boot(first_boot)).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.state.database.boot_time(&agent.id()).await.unwrap() != Some(first_boot * 1000) {
        assert!(Instant::now() < deadline, "the boot time wasn't saved");
        sleep(Duration::from_millis(20)).await;
    }
    assert!(timeline(&server, &agent).await.is_empty());

    let second_boot = now_ms() / 1000 - 120;
    send(&mut client, &with_boot(second_boot)).await;
    let events = wait_for_kind(&server, &agent, "restart").await;
    assert_eq!(events[0]["time_ms"], second_boot * 1000);
    assert_eq!(events[0]["by"], Value::Null);

    // Samples kept from before the restart arrive after the live ones.
    send(&mut client, &with_boot(first_boot)).await;
    send(
        &mut client,
        &AgentMessage::Facts {
            facts: json!({ "n": 2 }),
        },
    )
    .await;
    server.wait_for_facts(&agent.id(), 2).await;
    let restarts = timeline(&server, &agent)
        .await
        .into_iter()
        .filter(|event| event["kind"] == "restart")
        .count();
    assert_eq!(restarts, 1);
}

#[tokio::test]
async fn a_restart_while_disconnected_is_noticed_on_reconnecting() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let first_boot = now_ms() / 1000 - 86_400;
    send(&mut client, &with_boot(first_boot)).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while server
        .state
        .database
        .boot_time(&agent.id())
        .await
        .unwrap()
        .is_none()
    {
        assert!(Instant::now() < deadline, "the boot time wasn't saved");
        sleep(Duration::from_millis(20)).await;
    }
    drop(client);

    let mut client = server.connect().await;
    let status = handshake(&mut client, &agent, "web-1", None).await;
    assert_eq!(status, RegistrationStatus::Approved);
    send(&mut client, &with_boot(now_ms() / 1000 - 30)).await;

    wait_for_kind(&server, &agent, "restart").await;
}

#[tokio::test]
async fn a_new_config_is_marked_but_not_the_first() {
    let server = start().await;
    let agent = identity();
    let mut client = server.connect_approved(&agent, "web-1").await;
    let (first, _) = TestServer::next_config(&mut client).await;
    let applied = |version: String| AgentMessage::ConfigResult {
        version,
        error: None,
    };
    send(&mut client, &applied(first.clone())).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while server
        .state
        .database
        .config_status(&agent.id())
        .await
        .unwrap()
        .is_none()
    {
        assert!(Instant::now() < deadline, "the config status wasn't saved");
        sleep(Duration::from_millis(20)).await;
    }

    server
        .create_rule("Slower", 50, "true", json!({ "interval_secs": 60 }))
        .await;
    let (second, _) = TestServer::next_config(&mut client).await;
    assert_ne!(first, second);
    send(&mut client, &applied(second)).await;

    let events = wait_for_kind(&server, &agent, "config").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["title"], "Config changed");
    assert_eq!(events[0]["detail"], "From rules: Default, Slower.");
}

#[tokio::test]
async fn alerts_and_updates_are_on_the_timeline_too() {
    let server = start().await;
    let (agent, mut client) =
        machine(&server, "web-1", json!({ "agent": { "version": "0.1.0" } })).await;
    send(
        &mut client,
        &AgentMessage::Facts {
            facts: json!({ "agent": { "version": "0.2.0" } }),
        },
    )
    .await;
    server.wait_for_facts(&agent.id(), 2).await;

    let rule = server
        .state
        .database
        .create_alert_rule(&super::alerting::cpu_rule())
        .await
        .unwrap();
    let started = now_ms() - 60_000;
    let new = NewAlert {
        rule_id: rule,
        rule_name: "Disk filling up".into(),
        severity: Severity::Warning,
        agent_id: agent.id(),
        host: "web-1".into(),
        series: "/".into(),
        value: Some(85.0),
        summary: "Disk usage of / is 85%".into(),
        started_ms: started,
    };
    let alert = server.state.database.fire_alert(&new, &[]).await.unwrap();
    server
        .state
        .database
        .resolve_alert(alert, started + 30_000, "cleared")
        .await
        .unwrap();

    let events = timeline(&server, &agent).await;
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| event["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["update", "resolved", "alert"], "{events:?}");
    assert_eq!(events[0]["title"], "Agent updated to 0.2.0");
    assert_eq!(events[0]["detail"], "It was 0.1.0.");
    assert_eq!(events[2]["title"], "Disk filling up (warning)");
    assert_eq!(events[2]["detail"], "Disk usage of / is 85%");
    // Only recorded events can be deleted.
    assert!(events.iter().all(|event| event["id"].is_null()));
}

#[tokio::test]
async fn a_note_from_the_machine_page_shows_in_its_events() {
    let server = start().await;
    let (agent, _client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let page = format!("/agents/{}/metrics?range=6h", agent.id());
    let mut browser = Browser::default();

    let fields = [
        ("kind", "deploy"),
        ("title", "Rolled back <b>nginx</b>"),
        ("range", "6h"),
    ];
    let posted = browser
        .submit(
            &server,
            &page,
            &format!("/agents/{}/annotations", agent.id()),
            &fields,
        )
        .await;

    assert_eq!(posted.status, 303, "{}", posted.body);
    assert!(posted.header("location").unwrap().contains("range=6h"));
    let shown = browser.get(&server, &page).await;
    assert!(
        shown.body.contains("Rolled back &lt;b&gt;nginx&lt;/b&gt;"),
        "{}",
        shown.body
    );
    assert!(shown.body.contains("event-kind k-deploy"));
    // Marked on the charts, with the title to read when hovering.
    assert!(shown.body.contains(r#"<circle class="event-dot k-deploy""#));
    assert!(!shown.body.contains("<b>nginx"));
    assert!(shown.has_only_our_scripts());
}

#[tokio::test]
async fn a_refused_note_says_why_on_the_page() {
    let server = start().await;
    let (agent, _client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let page = format!("/agents/{}/metrics", agent.id());
    let mut browser = Browser::default();

    let posted = browser
        .submit(
            &server,
            &page,
            &format!("/agents/{}/annotations", agent.id()),
            &[("title", "  ")],
        )
        .await;

    let location = posted.header("location").unwrap().to_string();
    let shown = browser.get(&server, &location).await;
    assert!(
        shown.body.contains("An event needs a title."),
        "{}",
        shown.body
    );
}

#[tokio::test]
async fn a_note_can_be_deleted_from_the_page() {
    let server = start().await;
    let (agent, _client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let (_, event) = api(
        &server,
        "POST",
        "/api/v1/annotations",
        &json!({ "title": "Mistake" }),
    )
    .await;
    let page = format!("/agents/{}/metrics", agent.id());
    let mut browser = Browser::default();

    let fields = [("agent_id", agent.id()), ("range", "1h".to_string())];
    let fields: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let posted = browser
        .submit(
            &server,
            &page,
            &format!("/metrics/annotations/{}/delete", event["id"]),
            &fields,
        )
        .await;

    assert_eq!(posted.status, 303);
    assert!(timeline(&server, &agent).await.is_empty());
}

#[tokio::test]
async fn deleting_a_machine_keeps_annotations_for_others_and_forgets_its_own() {
    let server = start().await;
    let (agent, client) = machine(&server, "web-1", json!({ "role": "web" })).await;
    let (_, event) = api(
        &server,
        "POST",
        "/api/v1/annotations",
        &json!({ "title": "Kept" }),
    )
    .await;
    let own = json!({ "title": "Gone", "filter": format!("id={}", agent.id()) });
    let (_, own) = api(&server, "POST", "/api/v1/annotations", &own).await;
    drop(client);
    server
        .state
        .registry
        .decide(&agent.id(), AgentState::Revoked)
        .await
        .unwrap();

    server.state.delete_agent(&agent.id()).await.unwrap();

    let path = format!("/api/v1/annotations/{}", event["id"]);
    let (status, _) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200);
    let own = format!("/api/v1/annotations/{}", own["id"]);
    assert_eq!(api(&server, "GET", &own, &Value::Null).await.0, 404);
    assert_eq!(
        server.state.database.boot_time(&agent.id()).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn an_annotation_follows_its_filter_to_machines_added_and_changed_later() {
    let server = start().await;
    let body = json!({ "kind": "deploy", "title": "Shop v2.4", "filter": "role=web" });

    // Nothing matches yet, which is fine.
    let (status, _) = api(&server, "POST", "/api/v1/annotations", &body).await;
    assert_eq!(status, 201);

    let (late, mut client) = machine(&server, "web-9", json!({ "role": "web" })).await;
    assert_eq!(titles(&timeline(&server, &late).await), ["Shop v2.4"]);

    send(
        &mut client,
        &AgentMessage::Facts {
            facts: json!({ "role": "db" }),
        },
    )
    .await;
    server.wait_for_facts(&late.id(), 2).await;
    assert!(timeline(&server, &late).await.is_empty());
}

#[tokio::test]
async fn the_annotations_tab_adds_one_for_a_filter_at_a_time_given() {
    let server = start().await;
    let zone = chrono_tz::America::Chicago;
    let user = server.user_id().await;
    server
        .state
        .database
        .set_time_zone(user, zone)
        .await
        .unwrap();
    let mut browser = Browser::default();
    let listing = browser.get(&server, "/metrics").await;
    assert!(listing.body.contains(r#"href="/metrics/annotations""#));

    let fields = [
        ("kind", "deploy"),
        ("title", "Upgraded Postgres to 17"),
        ("detail", ""),
        ("filter", "role=web"),
        ("when", "2026-11-10T09:30"),
    ];
    let posted = browser
        .submit(
            &server,
            "/metrics/annotations",
            "/metrics/annotations",
            &fields,
        )
        .await;

    assert_eq!(posted.status, 303, "{}", posted.body);
    let page = browser.get(&server, "/metrics/annotations").await;
    assert!(
        page.body.contains("Upgraded Postgres to 17"),
        "{}",
        page.body
    );
    assert!(page.body.contains("<code>role=web</code>"));
    let (_, listed) = api(
        &server,
        "GET",
        "/api/v1/annotations?from_ms=0",
        &Value::Null,
    )
    .await;
    // 09:30 in Chicago, where the person adding it is.
    let expected = chrono::TimeZone::from_local_datetime(
        &zone,
        &chrono::NaiveDate::from_ymd_opt(2026, 11, 10)
            .unwrap()
            .and_hms_opt(9, 30, 0)
            .unwrap(),
    )
    .earliest()
    .unwrap()
    .timestamp_millis();
    assert_eq!(listed[0]["time_ms"], expected);
}

#[tokio::test]
async fn the_annotations_tab_keeps_what_was_typed_when_it_refuses() {
    let server = start().await;
    let mut browser = Browser::default();

    let fields = [
        ("kind", "note"),
        ("title", "Kept title"),
        ("filter", "role=\"oops"),
        ("when", ""),
    ];
    let refused = browser
        .submit(
            &server,
            "/metrics/annotations",
            "/metrics/annotations",
            &fields,
        )
        .await;

    assert_eq!(refused.status, 422);
    assert!(
        refused.body.contains(r#"value="Kept title""#),
        "{}",
        refused.body
    );
    assert!(refused.body.contains(r#"class="error""#));
}
