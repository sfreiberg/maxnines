//! The audit log: what's recorded, who it says did it, and what it never keeps.

use super::*;
use crate::alerting::{ChannelInput, ChannelKind, every_severity};
use crate::audit::{self, Acting, Actor, Entry, HIDDEN};
use crate::locations::LocationRuleInput;
use crate::registration::HostRecord;

const PASSWORD: &str = "a long enough password";

/// The newest entry's ID, so a test can look only at what it caused.
async fn mark(server: &TestServer) -> i64 {
    let newest = server.state.database.audit_log(None, 1).await.unwrap();
    newest.first().map_or(0, |entry| entry.id)
}

/// Entries since `mark`, oldest first.
async fn since(server: &TestServer, mark: i64) -> Vec<Entry> {
    let mut entries = server.state.database.audit_log(None, 1000).await.unwrap();
    entries.retain(|entry| entry.id > mark);
    entries.reverse();
    entries
}

async fn person(server: &TestServer, email: &str) -> i64 {
    let database = &server.state.database;
    let (user, link) = database
        .create_user(email, "Someone", crate::roles::Role::Admin, now_ms())
        .await
        .unwrap()
        .unwrap();
    let hash = crate::passwords::hash_password(PASSWORD.to_string())
        .await
        .unwrap();
    assert!(
        database
            .use_setup_link(user.id, &link, &hash, now_ms())
            .await
            .unwrap()
    );
    user.id
}

async fn sign_in(server: &TestServer, browser: &mut Browser, email: &str, password: &str) -> Page {
    let fields = [("email", email), ("password", password)];
    browser.submit(server, "/login", "/login", &fields).await
}

fn actions(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|entry| entry.action.as_str()).collect()
}

#[tokio::test]
async fn signing_in_and_out_is_recorded_with_the_address() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let before = mark(&server).await;
    let mut browser = Browser::anonymous();

    assert_eq!(
        sign_in(&server, &mut browser, "a@example.com", PASSWORD)
            .await
            .status,
        303
    );
    let out = browser.submit(&server, "/profile", "/logout", &[]).await;
    assert_eq!(out.status, 303, "{}", out.body);

    let entries = since(&server, before).await;
    assert_eq!(actions(&entries), ["signed_in", "signed_out"]);
    for entry in &entries {
        assert_eq!(entry.actor.kind, "person");
        assert_eq!(entry.actor.id, Some(id.to_string()));
        assert_eq!(entry.actor.name, "a@example.com");
        assert_eq!(entry.subject.name, "a@example.com");
        assert_eq!(entry.source.as_deref(), Some("127.0.0.1"));
    }
}

#[tokio::test]
async fn a_failed_sign_in_is_recorded_with_the_address_that_was_tried() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let before = mark(&server).await;

    let wrong = sign_in(
        &server,
        &mut Browser::anonymous(),
        "A@example.com",
        "wrong guess",
    )
    .await;
    let unknown = sign_in(
        &server,
        &mut Browser::anonymous(),
        "b@example.com",
        PASSWORD,
    )
    .await;
    assert_eq!((wrong.status, unknown.status), (401, 401));

    let entries = since(&server, before).await;
    assert_eq!(actions(&entries), ["sign_in_failed", "sign_in_failed"]);
    assert_eq!(entries[0].subject.name, "a@example.com");
    assert_eq!(entries[0].subject.id, Some(id.to_string()));
    assert_eq!(entries[1].subject.name, "b@example.com");
    assert_eq!(entries[1].subject.id, None);
    for entry in &entries {
        assert_eq!(entry.actor.kind, "nobody");
        assert_eq!(entry.source.as_deref(), Some("127.0.0.1"));
        assert!(entry.changes.is_empty());
    }
    let text = serde_json::to_string(&entries).unwrap();
    assert!(!text.contains("wrong guess"), "{text}");
}

#[tokio::test]
async fn a_change_on_the_pages_records_who_made_it() {
    let server = start().await;
    let before = mark(&server).await;

    let fields = [
        ("name", "Backup script"),
        ("role", "admin"),
        ("lifetime", ""),
    ];
    let page = Browser::default()
        .submit(&server, "/settings/api-keys", "/settings/api-keys", &fields)
        .await;
    assert_eq!(page.status, 200, "{}", page.body);

    let entries = since(&server, before).await;
    assert_eq!(actions(&entries), ["created"]);
    let entry = &entries[0];
    assert_eq!(entry.actor.kind, "person");
    assert_eq!(entry.actor.name, "test@example.com");
    assert_eq!(entry.source.as_deref(), Some("127.0.0.1"));
    assert_eq!(entry.subject.kind, "api_key");
    assert_eq!(entry.subject.name, "Backup script");
    let owner = entry.changes.iter().find(|c| c.field == "owner").unwrap();
    assert_eq!(owner.after, Some(json!("test@example.com")));
    let listed = Browser::default().get(&server, "/settings/api-keys").await;
    assert!(
        listed.body.contains("<td>test@example.com<span"),
        "{}",
        listed.body
    );
}

/// Calls the API from behind a proxy that says the request came from `client`.
async fn api_from(server: &TestServer, client: &str, method: &str, path: &str, body: &str) -> u16 {
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\n\
         X-Forwarded-For: {client}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        server.api_key,
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
async fn an_api_change_records_the_key_and_the_values_before_and_after() {
    let server = start_with(r#"trusted_proxies = ["127.0.0.1"]"#).await;
    let before = mark(&server).await;

    let status = api_from(
        &server,
        "203.0.113.9",
        "POST",
        "/api/v1/dashboards",
        r#"{"name": "Ops"}"#,
    )
    .await;
    assert_eq!(status, 201);
    let id = server.state.database.list_dashboards().await.unwrap()[0].id;
    let path = format!("/api/v1/dashboards/{id}");
    let status = api_from(
        &server,
        "203.0.113.9",
        "PUT",
        &path,
        r#"{"name": "Night ops"}"#,
    )
    .await;
    assert_eq!(status, 204);

    let entries = since(&server, before).await;
    assert_eq!(actions(&entries), ["created", "changed"]);
    let changed = &entries[1];
    assert_eq!(changed.actor.kind, "person");
    assert_eq!(changed.actor.name, "test@example.com");
    let via = changed.via.as_ref().unwrap();
    assert_eq!((via.kind.as_str(), via.name.as_str()), ("api_key", "tests"));
    assert_eq!(changed.via_label().as_deref(), Some("via API key tests"));
    assert_eq!(changed.source.as_deref(), Some("203.0.113.9"));
    assert_eq!(changed.subject.name, "Night ops");
    assert_eq!(changed.changes.len(), 1, "{:?}", changed.changes);
    assert_eq!(changed.changes[0].field, "name");
    assert_eq!(changed.changes[0].before, Some(json!("Ops")));
    assert_eq!(changed.changes[0].after, Some(json!("Night ops")));
}

#[tokio::test]
async fn a_forwarded_address_from_anyone_else_is_ignored() {
    let server = start().await;
    let before = mark(&server).await;

    api_from(
        &server,
        "203.0.113.9",
        "POST",
        "/api/v1/dashboards",
        r#"{"name": "Ops"}"#,
    )
    .await;

    let entries = since(&server, before).await;
    assert_eq!(entries[0].source.as_deref(), Some("127.0.0.1"));
}

fn channel(kind: ChannelKind, target: &str, credential: Option<&str>) -> ChannelInput {
    ChannelInput {
        name: format!("Ops {}", kind.as_str()),
        kind,
        target: target.into(),
        credential: credential.map(String::from),
        app_token: None,
        severities: every_severity(),
        mail: None,
        request: None,
    }
}

#[tokio::test]
async fn secrets_never_reach_the_log() {
    let server = start().await;
    let database = &server.state.database;
    let before = mark(&server).await;

    let hook = database
        .create_channel(&channel(
            ChannelKind::Webhook,
            "https://hooks.test/first-secret",
            None,
        ))
        .await
        .unwrap();
    let changed = channel(
        ChannelKind::Webhook,
        "https://hooks.test/second-secret",
        None,
    );
    database.update_channel(hook, &changed).await.unwrap();
    let slack = database
        .create_channel(&channel(
            ChannelKind::Slack,
            "#ops",
            Some("xoxb-bot-secret"),
        ))
        .await
        .unwrap();
    let changed = channel(ChannelKind::Slack, "#alerts", Some("xoxb-new-secret"));
    database.update_channel(slack, &changed).await.unwrap();
    person(&server, "a@example.com").await;

    let entries = since(&server, before).await;
    let text = serde_json::to_string(&entries).unwrap();
    for secret in ["first-secret", "second-secret", "xoxb", "$argon2"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    let hook_change = &entries[1].changes;
    assert_eq!(hook_change[0].field, "target");
    assert!(hook_change[0].secret);
    assert_eq!(hook_change[0].after, Some(json!(HIDDEN)));
    // A Slack channel's name isn't a secret, but its bot token is.
    let slack_changes = &entries[3].changes;
    let fields: Vec<(&str, bool)> = slack_changes
        .iter()
        .map(|change| (change.field.as_str(), change.secret))
        .collect();
    assert_eq!(fields, [("credential", true), ("target", false)]);
    let password = entries
        .iter()
        .flat_map(|entry| &entry.changes)
        .find(|change| change.field == "password")
        .expect("setting a password is recorded");
    assert!(password.secret);
}

#[tokio::test]
async fn nothing_is_recorded_for_a_change_that_changes_nothing() {
    let server = start().await;
    let database = &server.state.database;
    let input = LocationRuleInput {
        name: "Office".into(),
        filter: String::new(),
        place: "London".into(),
        latitude: 51.5,
        longitude: -0.1,
        priority: 0,
    };
    let id = database.create_location_rule(&input).await.unwrap();
    let before = mark(&server).await;

    database.update_location_rule(id, &input).await.unwrap();
    assert!(!database.update_location_rule(id + 1, &input).await.unwrap());
    assert!(!database.delete_location_rule(id + 1).await.unwrap());

    assert_eq!(since(&server, before).await, []);
}

#[tokio::test]
async fn a_deletion_keeps_what_was_deleted() {
    let server = start().await;
    let database = &server.state.database;
    let id = database.create_dashboard("Ops", now_ms()).await.unwrap();
    let before = mark(&server).await;

    database.delete_dashboard(id).await.unwrap();

    let entries = since(&server, before).await;
    assert_eq!(actions(&entries), ["deleted"]);
    assert_eq!(entries[0].subject.name, "Ops");
    assert_eq!(entries[0].changes[0].before, Some(json!("Ops")));
    assert_eq!(entries[0].changes[0].after, None);
}

#[tokio::test]
async fn changes_with_nobody_acting_are_maxnines_own() {
    let server = start().await;
    let database = &server.state.database;
    let before = mark(&server).await;

    database
        .create_dashboard("By the server", now_ms())
        .await
        .unwrap();
    let command_line = Acting {
        actor: Actor::CommandLine {
            account: Some("sam".into()),
        },
        via: None,
        source: None,
    };
    audit::acting(command_line, database.create_dashboard("By hand", now_ms()))
        .await
        .unwrap();

    let entries = since(&server, before).await;
    assert_eq!(entries[0].actor.kind, "maxnines");
    assert_eq!(entries[0].source, None);
    assert_eq!(entries[1].actor.kind, "command_line");
    assert_eq!(entries[1].actor.name, "Command line (sam)");
}

#[tokio::test]
async fn approving_an_agent_records_its_state_changing() {
    let server = start().await;
    let host = identity();
    let mut client = server.connect().await;
    assert_eq!(
        handshake(&mut client, &host, "web-1", None).await,
        RegistrationStatus::Pending
    );
    let before = mark(&server).await;

    let path = format!("/api/v1/hosts/{}/approve", host.id());
    assert_eq!(api_from(&server, "127.0.0.1", "POST", &path, "").await, 200);

    let entries = since(&server, before).await;
    assert_eq!(actions(&entries), ["changed"]);
    let entry = &entries[0];
    assert_eq!(entry.actor.name, "test@example.com");
    assert_eq!(entry.via.as_ref().unwrap().kind, "api_key");
    assert_eq!(entry.subject.kind, "host");
    assert_eq!(entry.subject.id, Some(host.id()));
    assert_eq!(entry.subject.name, "web-1");
    let state = entry.changes.iter().find(|c| c.field == "state").unwrap();
    assert_eq!(state.before, Some(json!("pending")));
    assert_eq!(state.after, Some(json!("approved")));
    let by = entry
        .changes
        .iter()
        .find(|c| c.field == "decided_by")
        .unwrap();
    assert_eq!(by.after, Some(json!("test@example.com")));
}

#[tokio::test]
async fn an_agent_asking_to_join_is_recorded_as_maxnines() {
    let server = start().await;
    let before = mark(&server).await;
    let record = HostRecord {
        id: "ab".repeat(16),
        public_key: "cd".repeat(32),
        hostname: "web-1".into(),
        state: HostState::Pending,
        decided_by: None,
        first_seen_ms: 0,
        decided_ms: None,
    };

    server.state.database.save_host(&record).await.unwrap();
    server.state.database.save_host(&record).await.unwrap();

    let entries = since(&server, before).await;
    assert_eq!(
        actions(&entries),
        ["created"],
        "saving it again changes nothing"
    );
    assert_eq!(entries[0].actor.kind, "maxnines");
}

#[tokio::test]
async fn the_log_reads_newest_first_a_page_at_a_time() {
    let server = start().await;
    let database = &server.state.database;
    for name in ["One", "Two", "Three"] {
        database.create_dashboard(name, now_ms()).await.unwrap();
    }

    let first = database.audit_log(None, 2).await.unwrap();
    let names: Vec<&str> = first.iter().map(|e| e.subject.name.as_str()).collect();
    assert_eq!(names, ["Three", "Two"]);
    let next = database.audit_log(Some(first[1].id), 1).await.unwrap();
    assert_eq!(next[0].subject.name, "One");
}

#[tokio::test]
async fn the_page_shows_entries_without_secrets() {
    let server = start().await;
    let database = &server.state.database;
    let hook = channel(ChannelKind::Webhook, "https://hooks.test/page-secret", None);
    database.create_channel(&hook).await.unwrap();
    database
        .create_dashboard("<b>Ops</b>", now_ms())
        .await
        .unwrap();

    api_from(
        &server,
        "127.0.0.1",
        "POST",
        "/api/v1/dashboards",
        r#"{"name": "Keyed"}"#,
    )
    .await;

    let page = Browser::default().get(&server, "/settings/audit-log").await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("via API key tests"), "{}", page.body);
    assert!(page.body.contains("Notification channel"), "{}", page.body);
    assert!(page.body.contains("&lt;b&gt;Ops"), "{}", page.body);
    assert!(!page.body.contains("<b>Ops</b>"));
    assert!(!page.body.contains("page-secret"));
    assert!(page.has_only_our_scripts());
}

#[tokio::test]
async fn the_api_reads_the_log_within_limits() {
    let server = start().await;

    let (status, body) = {
        let response = server.request("GET", "/api/v1/audit-log?limit=1", "").await;
        let (head, text) = response.split_once("\r\n\r\n").unwrap();
        let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str::<Value>(text).unwrap())
    };
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert!(body[0]["actor"]["kind"].is_string(), "{body}");

    for limit in ["0", "1001"] {
        let response = server
            .request("GET", &format!("/api/v1/audit-log?limit={limit}"), "")
            .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{limit}: {response}");
    }
}
