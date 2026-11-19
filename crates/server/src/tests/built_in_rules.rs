//! The config rules that come with MaxNines, and limiting a rule to some operating
//! systems.

use super::*;
use crate::built_in_rules::{BuiltInRule, all};
use crate::models::ConfigRule;

/// The server's own built-in rules, as a real start writes them.
async fn with_every_built_in_rule() -> TestServer {
    let server = start().await;
    server
        .state
        .database
        .sync_built_in_rules(&all(), now_ms())
        .await
        .unwrap();
    server.state.config_changed();
    server
}

async fn rule_named(server: &TestServer, name: &str) -> ConfigRule {
    let rules = server.state.database.list_rules().await.unwrap();
    rules
        .into_iter()
        .find(|rule| rule.rule.name == name)
        .unwrap_or_else(|| panic!("no rule named {name}"))
}

/// The status and body of an API request with the test key.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, String) {
    let response = server.request(method, path, &body.to_string()).await;
    let status = response[9..12].parse().unwrap();
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

#[tokio::test]
async fn a_mac_gets_its_gpu_watched_and_linux_does_not() {
    let server = with_every_built_in_rule().await;
    let every_collector: Vec<&str> = maxnines_protocol::COLLECTORS.to_vec();

    let mut mac = server.connect_approved(&identity(), "mac-1").await;
    TestServer::next_config(&mut mac).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "os": { "family": "macos" }, "agent": { "collectors": every_collector } }),
    };
    send(&mut mac, &facts).await;
    let (_, config) = TestServer::next_config(&mut mac).await;
    assert!(config.collectors["gpu"].enabled, "{config:?}");
    // The Default rule still applies under it.
    assert!(config.collectors["cpu"].enabled);

    let mut linux = server.connect_approved(&identity(), "web-1").await;
    TestServer::next_config(&mut linux).await;
    send(&mut linux, &facts_of("linux")).await;
    server.wait_for_facts(&linux_id(&server).await, 1).await;
    let resolved = server
        .state
        .config_for(&linux_id(&server).await)
        .await
        .unwrap();
    assert!(
        !resolved.config.collectors.contains_key("gpu"),
        "{resolved:?}"
    );
    assert!(resolved.skipped_collectors.is_empty());
    assert!(!resolved.matched_rules.contains(&"macOS".to_string()));
}

fn facts_of(family: &str) -> AgentMessage {
    AgentMessage::Facts {
        facts: json!({ "os": { "family": family } }),
    }
}

async fn linux_id(server: &TestServer) -> String {
    let hosts = server.state.registry.list().await;
    hosts
        .into_iter()
        .find(|host| host.hostname == "web-1")
        .unwrap()
        .id
}

#[tokio::test]
async fn an_upgrade_brings_its_changes_to_built_in_rules_but_never_to_peoples_own() {
    let server = with_every_built_in_rule().await;
    let database = &server.state.database;
    let mac = rule_named(&server, "macOS").await;
    assert_eq!(mac.built_in.as_deref(), Some("macos"));
    // Someone turned it off.
    database.set_rule_enabled(mac.id, false).await.unwrap();
    // And someone has a rule of their own named like one a later version brings.
    server
        .create_rule("Linux", 50, "true", json!({ "interval_secs": 9 }))
        .await;

    let mut later = all();
    later[1].rule.settings =
        json!({ "collectors": { "gpu": { "enabled": true }, "sensors": { "enabled": true } } });
    later.push(BuiltInRule {
        key: "linux",
        rule: RuleInput {
            name: "Linux".to_string(),
            priority: 0,
            condition: None,
            operating_systems: vec!["linux".to_string()],
            enabled: true,
            settings: json!({ "collectors": { "sensors": { "enabled": true } } }),
        },
    });
    let changed = database
        .sync_built_in_rules(&later, now_ms())
        .await
        .unwrap();
    assert_eq!(changed, ["macOS", "Linux"]);

    let mac = rule_named(&server, "macOS").await;
    assert!(!mac.rule.enabled, "turning it off outlasts the upgrade");
    assert_eq!(mac.rule.settings["collectors"]["sensors"]["enabled"], true);
    assert!(mac.built_in_changed_at.is_some());
    let theirs = rule_named(&server, "Linux (yours)").await;
    assert_eq!(theirs.built_in, None);
    assert_eq!(theirs.rule.settings, json!({ "interval_secs": 9 }));
    assert_eq!(
        rule_named(&server, "Linux").await.built_in.as_deref(),
        Some("linux")
    );

    // Nothing more to do the next time it starts.
    assert!(
        database
            .sync_built_in_rules(&later, now_ms())
            .await
            .unwrap()
            .is_empty()
    );

    // A built-in rule no longer shipped goes.
    let changed = database
        .sync_built_in_rules(&all(), now_ms())
        .await
        .unwrap();
    assert!(changed.contains(&"Linux".to_string()), "{changed:?}");
    let names: Vec<String> = database
        .list_rules()
        .await
        .unwrap()
        .into_iter()
        .map(|rule| rule.rule.name)
        .collect();
    assert!(!names.contains(&"Linux".to_string()), "{names:?}");
    assert!(names.contains(&"Linux (yours)".to_string()));

    // The audit log says the server did it.
    let entries = database.audit_log(None, 100).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.subject.name == "macOS" && entry.actor_label() == "MaxNines"),
        "{entries:?}"
    );
}

#[tokio::test]
async fn an_unchanged_default_rule_becomes_the_built_in_one_and_a_changed_one_stays_theirs() {
    let database = Database::for_test().await;
    let default = database.list_rules().await.unwrap().remove(0);
    assert_eq!(
        default.built_in, None,
        "a new database's Default isn't marked yet"
    );
    database
        .sync_built_in_rules(&all(), now_ms())
        .await
        .unwrap();
    let rules = database.list_rules().await.unwrap();
    assert_eq!(rules[0].id, default.id);
    assert_eq!(rules[0].built_in.as_deref(), Some("default"));
    assert_eq!(
        rules[0].built_in_changed_at, None,
        "adopting it isn't a change"
    );

    let changed = Database::for_test().await;
    let mut edited = changed.list_rules().await.unwrap().remove(0);
    edited.rule.settings["interval_secs"] = json!(60);
    changed.update_rule(edited.id, &edited.rule).await.unwrap();
    changed.sync_built_in_rules(&all(), now_ms()).await.unwrap();
    let rules = changed.list_rules().await.unwrap();
    let theirs = rules.iter().find(|rule| rule.id == edited.id).unwrap();
    assert_eq!(theirs.rule.name, "Default (yours)");
    assert_eq!(theirs.rule.settings["interval_secs"], 60);
    let built_in = rules
        .iter()
        .find(|rule| rule.rule.name == "Default")
        .unwrap();
    assert_eq!(built_in.built_in.as_deref(), Some("default"));
    // Theirs still wins, being the same priority but not built in.
    assert!(
        rules.iter().position(|rule| rule.id == built_in.id)
            < rules.iter().position(|rule| rule.id == edited.id)
    );
}

#[tokio::test]
async fn a_built_in_rule_can_only_be_turned_on_or_off_through_the_api() {
    let server = with_every_built_in_rule().await;
    let mac = rule_named(&server, "macOS").await;
    let path = format!("/api/v1/rules/{}", mac.id);

    let (status, body) = api(&server, "GET", "/api/v1/rules", &Value::Null).await;
    assert_eq!(status, 200);
    let listed: Value = serde_json::from_str(&body).unwrap();
    let shown = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["name"] == "macOS")
        .unwrap();
    assert_eq!(shown["built_in"], "macos");
    assert_eq!(shown["operating_systems"], json!(["macos"]));

    let mut changed = serde_json::to_value(&mac.rule).unwrap();
    changed["settings"] = json!({ "interval_secs": 5 });
    let (status, body) = api(&server, "PUT", &path, &changed).await;
    assert_eq!(status, 422, "{body}");
    assert!(body.contains("only `enabled` can change"), "{body}");

    let (status, body) = api(&server, "DELETE", &path, &Value::Null).await;
    assert_eq!(status, 422, "{body}");

    let mut off = serde_json::to_value(&mac.rule).unwrap();
    off["enabled"] = json!(false);
    let (status, body) = api(&server, "PUT", &path, &off).await;
    assert_eq!(status, 204, "{body}");
    assert!(!rule_named(&server, "macOS").await.rule.enabled);
}

#[tokio::test]
async fn a_built_in_rule_is_locked_on_its_page_and_can_be_customized() {
    let server = with_every_built_in_rule().await;
    let mac = rule_named(&server, "macOS").await;
    let mut browser = Browser::default();

    let list = browser.get(&server, "/rules").await;
    assert!(list.body.contains("Comes with MaxNines"), "{}", list.body);

    let edit = format!("/rules/{}/edit", mac.id);
    let page = browser.get(&server, &edit).await;
    assert!(
        page.body.contains("comes with MaxNines and is updated"),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"<fieldset class="bare" disabled>"#));
    assert!(!page.body.contains(&format!("/rules/{}/delete", mac.id)));

    // Saving sends only whether it's on, as everything else is locked.
    let page = browser
        .submit(&server, &edit, &format!("/rules/{}", mac.id), &[])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let saved = rule_named(&server, "macOS").await;
    assert!(!saved.rule.enabled);
    assert_eq!(saved.rule.settings, mac.rule.settings);

    let page = browser
        .submit(&server, &edit, &format!("/rules/{}/delete", mac.id), &[])
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(page.body.contains("can&#39;t be deleted") || page.body.contains("can't be deleted"));

    let page = browser
        .get(&server, &format!("/rules/new?from={}", mac.id))
        .await;
    assert!(
        page.body.contains(r#"value="macOS changes""#),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(r#"name="priority" value="1""#),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(r#"name="os_macos" checked"#),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_rule_can_be_limited_to_some_operating_systems() {
    let server = start().await;
    let mut browser = Browser::default();
    let fields = [
        ("name", "Unix-like"),
        ("priority", "100"),
        ("os_linux", "on"),
        ("os_freebsd", "on"),
        ("enabled", "on"),
        ("interval_secs", "20"),
    ];
    let page = browser
        .submit(&server, "/rules/new", "/rules", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let rule = rule_named(&server, "Unix-like").await;
    assert_eq!(rule.rule.operating_systems, ["freebsd", "linux"]);
    assert_eq!(rule.rule.condition, None);

    let list = browser.get(&server, "/rules").await;
    assert!(list.body.contains("FreeBSD and Linux"), "{}", list.body);

    // Only hosts on those systems get it.
    let mut client = server.connect_approved(&identity(), "web-1").await;
    TestServer::next_config(&mut client).await;
    send(&mut client, &facts_of("linux")).await;
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.interval_secs, 20);

    let unknown = json!({
        "name": "Plan 9",
        "priority": 1,
        "condition": null,
        "operating_systems": ["plan9"],
        "settings": {},
    });
    let (status, body) = api(&server, "POST", "/api/v1/rules", &unknown).await;
    assert_eq!(status, 422, "{body}");
    assert!(body.contains("unknown operating system"), "{body}");
}
