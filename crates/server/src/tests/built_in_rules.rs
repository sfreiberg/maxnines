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
        .sync_built_in_rules(&all().unwrap(), crate::times::now())
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
    // The Host template's rule still applies under it.
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
    // And someone has a rule of their own named like one a later version brings, as
    // names are compared.
    server
        .create_rule("linux", 50, "true", json!({ "interval_secs": 9 }))
        .await;

    let mut later = all().unwrap();
    later[1].rule.settings =
        json!({ "collectors": { "gpu": { "enabled": true }, "sensors": { "enabled": true } } });
    later.push(BuiltInRule {
        key: "linux".to_string(),
        rule: RuleInput {
            name: "Linux".to_string(),
            priority: 0,
            applies_to: None,
            operating_systems: vec!["linux".to_string()],
            enabled: true,
            settings: json!({ "collectors": { "sensors": { "enabled": true } } }),
        },
    });
    let changed = database
        .sync_built_in_rules(&later, crate::times::now())
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
            .sync_built_in_rules(&later, crate::times::now())
            .await
            .unwrap()
            .is_empty()
    );

    // A built-in rule no longer shipped goes.
    let changed = database
        .sync_built_in_rules(&all().unwrap(), crate::times::now())
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
async fn an_upgrade_can_give_a_new_built_in_rule_the_name_of_one_it_drops() {
    let server = with_every_built_in_rule().await;
    let database = &server.state.database;
    let mut later = all().unwrap();
    let mac = later.iter_mut().find(|rule| rule.key == "macos").unwrap();
    mac.key = "apple".to_string();

    let changed = database
        .sync_built_in_rules(&later, crate::times::now())
        .await
        .unwrap();

    assert_eq!(changed, ["macOS", "macOS"]);
    assert_eq!(
        rule_named(&server, "macOS").await.built_in.as_deref(),
        Some("apple")
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
    let server = with_every_built_in_template().await;
    let mac = rule_named(&server, "macOS").await;
    let mut browser = Browser::default();

    let list = browser.get(&server, "/rules").await;
    assert!(
        list.body
            .contains("Comes with MaxNines, from the macOS template"),
        "{}",
        list.body
    );

    let edit = format!("/rules/{}/edit", mac.id);
    let page = browser.get(&server, &edit).await;
    assert!(
        page.body
            .contains("comes with MaxNines, as the agent settings of the built-in"),
        "{}",
        page.body
    );
    assert!(page.body.contains("macOS template</a>"), "{}", page.body);
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
    assert_eq!(rule.rule.applies_to, None);

    let list = browser.get(&server, "/rules").await;
    assert!(list.body.contains("FreeBSD and Linux"), "{}", list.body);

    // Only hosts on those systems get it.
    let mut client = server.connect_approved(&identity(), "web-1").await;
    TestServer::next_config(&mut client).await;
    send(&mut client, &facts_of("linux")).await;
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.interval, Duration::from_secs(20));

    let unknown = json!({
        "name": "Plan 9",
        "priority": 1,
        "applies_to": null,
        "operating_systems": ["plan9"],
        "settings": {},
    });
    let (status, body) = api(&server, "POST", "/api/v1/rules", &unknown).await;
    assert_eq!(status, 422, "{body}");
    assert!(body.contains("unknown operating system"), "{body}");
}

#[tokio::test]
async fn a_rule_named_like_another_whatever_the_case_is_refused() {
    let server = with_every_built_in_rule().await;
    let rule = json!({
        "name": " MACOS ",
        "priority": 5,
        "applies_to": "true",
        "operating_systems": [],
        "enabled": true,
        "settings": { "interval_secs": 9 },
    });
    let (status, body) = api(&server, "POST", "/api/v1/rules", &rule).await;
    assert_eq!(status, 422, "{body}");
    assert!(
        body.contains("a rule named \\\" MACOS \\\" already exists"),
        "{body}"
    );

    let mut renamed = rule.clone();
    renamed["name"] = json!("Mine");
    let (status, body) = api(&server, "POST", "/api/v1/rules", &renamed).await;
    assert_eq!(status, 201, "{body}");
    let id = rule_named(&server, "Mine").await.id;
    let (status, body) = api(&server, "PUT", &format!("/api/v1/rules/{id}"), &rule).await;
    assert_eq!(status, 422, "{body}");
}

/// Every built-in rule and template, as a real start writes them.
async fn with_every_built_in_template() -> TestServer {
    let server = with_every_built_in_rule().await;
    server
        .state
        .database
        .sync_templates(
            &crate::templates::built_in::all().unwrap(),
            crate::times::now(),
        )
        .await
        .unwrap();
    server
}

#[tokio::test]
async fn a_built_in_rule_is_only_in_force_while_its_template_is_enabled() {
    let server = with_every_built_in_template().await;
    let mac_rule = rule_named(&server, "macOS").await;
    let template = mac_rule.template.clone().expect("the rule's template");
    assert!(template.enabled);

    let mut mac = server.connect_approved(&identity(), "mac-1").await;
    TestServer::next_config(&mut mac).await;
    let facts = AgentMessage::Facts {
        facts: json!({
            "os": { "family": "macos" },
            "agent": { "collectors": maxnines_protocol::COLLECTORS.to_vec() },
        }),
    };
    send(&mut mac, &facts).await;
    let (_, config) = TestServer::next_config(&mut mac).await;
    assert!(config.collectors["gpu"].enabled, "{config:?}");

    // Turning the template off takes its settings with it, though the rule itself
    // is still turned on, and the Mac is sent its config without them.
    server
        .state
        .database
        .set_template_enabled(template.id, false, crate::times::now())
        .await
        .unwrap();
    let (_, config) = TestServer::next_config(&mut mac).await;
    assert!(!config.collectors.contains_key("gpu"), "{config:?}");
    assert!(config.collectors["cpu"].enabled);

    let (status, body) = api(
        &server,
        "GET",
        &format!("/api/v1/rules/{}", mac_rule.id),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    let shown: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(shown["enabled"], true);
    assert_eq!(
        shown["template"],
        json!({ "id": template.id, "enabled": false, "host_ids": [] })
    );

    // The pages say so, and link to the template.
    let list = Browser::default().get(&server, "/rules").await;
    assert!(list.body.contains("Template disabled"), "{}", list.body);
    let form = Browser::default()
        .get(&server, &format!("/rules/{}/edit", mac_rule.id))
        .await;
    assert!(
        form.body.contains(&format!(
            r#"<a href="/templates/{}">macOS template</a>"#,
            template.id
        )),
        "{}",
        form.body
    );
    assert!(form.body.contains("which it isn"), "{}", form.body);
}

#[tokio::test]
async fn a_built_in_templates_hcl_leaves_its_settings_to_its_rule_so_it_can_be_copied() {
    let server = with_every_built_in_template().await;
    let host_rule = rule_named(&server, "Host").await;
    let template = host_rule.template.clone().unwrap();
    let path = format!("/api/v1/templates/{}", template.id);
    let (status, body) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200);
    let shown: Value = serde_json::from_str(&body).unwrap();
    let hcl = shown["hcl"].as_str().unwrap();
    assert!(!hcl.contains("config {"), "{hcl}");
    assert!(hcl.contains("template \"host\""), "{hcl}");

    // So it can be saved as someone's own, under a key and names of their own, as
    // no two templates or alert rules share a name.
    let copied: String = hcl
        .replace("template \"host\"", "template \"my_host\"")
        .lines()
        .map(|line| match line.trim_start().starts_with("name ") {
            true => format!("{}\n", line.replacen("= \"", "= \"My ", 1)),
            false => format!("{line}\n"),
        })
        .collect();
    let (status, body) = api(
        &server,
        "POST",
        "/api/v1/templates",
        &json!({ "hcl": copied }),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    // Its page says where its settings are instead.
    let page = Browser::default()
        .get(&server, &format!("/templates/{}", template.id))
        .await;
    assert!(
        page.body.contains(&format!(
            r#"<a href="/rules/{}/edit">Host config rule</a>"#,
            host_rule.id
        )),
        "{}",
        page.body
    );
}

async fn host_id(server: &TestServer, hostname: &str) -> String {
    let hosts = server.state.registry.list().await;
    hosts
        .into_iter()
        .find(|host| host.hostname == hostname)
        .unwrap_or_else(|| panic!("no host {hostname}"))
        .id
}

/// Whether a host's config, as it is now, has the macOS template's GPU collector.
async fn watches_gpu(server: &TestServer, id: &str) -> bool {
    let resolved = server.state.config_for(id).await.unwrap();
    resolved
        .config
        .collectors
        .get("gpu")
        .is_some_and(|gpu| gpu.enabled)
}

#[tokio::test]
async fn a_built_in_rule_is_for_the_hosts_its_template_is_for_as_chosen_on_its_page() {
    let server = with_every_built_in_template().await;
    let mac_rule = rule_named(&server, "macOS").await;
    let template = mac_rule.template.clone().unwrap();
    let hosts_path = format!("/api/v1/templates/{}/hosts", template.id);
    let collectors = maxnines_protocol::COLLECTORS.to_vec();

    let mut first = server.connect_approved(&identity(), "mac-1").await;
    TestServer::next_config(&mut first).await;
    send(
        &mut first,
        &AgentMessage::Facts {
            facts: json!({ "os": { "family": "macos" }, "agent": { "collectors": collectors } }),
        },
    )
    .await;
    TestServer::next_config(&mut first).await;
    let mut second = server.connect_approved(&identity(), "mac-2").await;
    TestServer::next_config(&mut second).await;
    send(
        &mut second,
        &AgentMessage::Facts {
            facts: json!({
                "os": { "family": "macos" },
                "agent": { "collectors": collectors },
                "custom": { "role": "render" },
            }),
        },
    )
    .await;
    let (_, config) = TestServer::next_config(&mut second).await;
    assert!(config.collectors["gpu"].enabled, "{config:?}");
    let (first_id, second_id) = (
        host_id(&server, "mac-1").await,
        host_id(&server, "mac-2").await,
    );
    assert!(watches_gpu(&server, &first_id).await);

    // Picked by hand: only the Mac picked keeps the settings, and the one taken off
    // is sent its config without them.
    let (status, body) = api(
        &server,
        "PUT",
        &hosts_path,
        &json!({ "applies_to": null, "host_ids": [first_id] }),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (_, config) = TestServer::next_config(&mut second).await;
    assert!(!config.collectors.contains_key("gpu"), "{config:?}");
    assert!(
        config.collectors["cpu"].enabled,
        "the Host rule still applies"
    );
    assert!(watches_gpu(&server, &first_id).await);

    // The API and the pages say so.
    let (status, body) = api(
        &server,
        "GET",
        &format!("/api/v1/rules/{}", mac_rule.id),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    let shown: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(shown["template"]["host_ids"], json!([first_id]));
    assert_eq!(shown["applies_to"], Value::Null);
    let mut browser = Browser::default();
    let list = browser.get(&server, "/rules").await;
    assert!(
        list.body.contains("macOS, 1 host picked on its template"),
        "{}",
        list.body
    );
    let form = browser
        .get(&server, &format!("/rules/{}/edit", mac_rule.id))
        .await;
    assert!(form.body.contains("the host picked there"), "{}", form.body);
    // A rule of one's own after it names the picked host.
    let after = browser
        .get(&server, &format!("/rules/new?from={}", mac_rule.id))
        .await;
    assert!(after.body.contains("trusted.host_id in"), "{}", after.body);
    assert!(after.body.contains(&first_id), "{}", after.body);

    // A condition chosen in place of the template's: the Mac it picks gets them, and
    // the one it doesn't loses them.
    let (status, body) = api(
        &server,
        "PUT",
        &hosts_path,
        &json!({ "applies_to": "facts.custom.role == 'render'", "host_ids": [] }),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (_, config) = TestServer::next_config(&mut second).await;
    assert!(config.collectors["gpu"].enabled, "{config:?}");
    let (_, config) = TestServer::next_config(&mut first).await;
    assert!(!config.collectors.contains_key("gpu"), "{config:?}");
    let shown = rule_named(&server, "macOS").await;
    assert_eq!(
        shown.rule.applies_to.as_deref(),
        Some("facts.custom.role == 'render'")
    );

    // Going back to what the template says gives every Mac its settings again.
    let (status, body) = api(
        &server,
        "PUT",
        &hosts_path,
        &json!({ "applies_to": null, "host_ids": [] }),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (_, config) = TestServer::next_config(&mut first).await;
    assert!(config.collectors["gpu"].enabled, "{config:?}");
    assert!(watches_gpu(&server, &second_id).await);
    let shown = rule_named(&server, "macOS").await;
    assert_eq!(shown.rule.applies_to, None);
    assert_eq!(shown.template.unwrap().host_ids, Vec::<String>::new());
}
