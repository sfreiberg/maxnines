//! Templates: the built-in ones written as the server starts, people's own, and the
//! alert rules their alerts become, with what people change of them kept apart.

use super::*;
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::models::Database;
use crate::templates::Refused;
use crate::templates::built_in::{self, BuiltIn, from_source};
use maxnines_protocol::templates::parse;

fn shipped(sources: &[&str]) -> Vec<BuiltIn> {
    sources
        .iter()
        .map(|source| from_source(source.to_string()).unwrap())
        .collect()
}

const APP: &str = r#"
template "app" {
  name = "App"
  alert "slow" {
    name     = "App slow"
    warning  = "cpu.usage > 80"
    critical = "cpu.usage > 95"
    for      = "5m"
  }
  alert "gone" {
    name     = "App host gone"
    critical = "!online"
  }
}
"#;

/// The same, changed by an upgrade: the warning is lower, `gone` is gone and `busy`
/// is new.
const APP_UPGRADED: &str = r#"
template "app" {
  name = "App"
  alert "slow" {
    name     = "App slow"
    warning  = "cpu.usage > 70"
    critical = "cpu.usage > 95"
    for      = "5m"
  }
  alert "busy" {
    name    = "App busy"
    warning = "cpu.load['1 minute'] > 10"
  }
}
"#;

async fn rules_named(database: &Database) -> Vec<(String, bool)> {
    database
        .list_alert_rules()
        .await
        .unwrap()
        .into_iter()
        .map(|rule| (rule.rule.name, rule.rule.enabled))
        .collect()
}

async fn rule(database: &Database, name: &str) -> AlertRule {
    let rules = database.list_alert_rules().await.unwrap();
    rules
        .into_iter()
        .find(|rule| rule.rule.name == name)
        .unwrap_or_else(|| panic!("no rule named {name}"))
}

async fn template_id(database: &Database, key: &str) -> i64 {
    let all = database.list_templates().await.unwrap();
    all.iter()
        .find(|stored| stored.template.key == key)
        .unwrap_or_else(|| panic!("no template {key}"))
        .id
}

#[tokio::test]
async fn a_new_server_gets_the_host_template_and_its_rules_without_a_notice() {
    let database = Database::for_test().await;
    let all = built_in::all().unwrap();
    let changed = database
        .sync_templates(&all, crate::times::now())
        .await
        .unwrap();
    assert!(changed.is_empty(), "{changed:?}");
    assert!(database.template_upgrades().await.unwrap().is_empty());

    let templates = database.list_templates().await.unwrap();
    assert_eq!(templates.len(), 1);
    assert!(templates[0].built_in && templates[0].enabled);
    assert_eq!(templates[0].template.key, "host");
    let rules = database.list_alert_rules().await.unwrap();
    assert_eq!(rules.len(), 8);
    for rule in &rules {
        let link = rule.template.as_ref().unwrap();
        assert_eq!(link.id, templates[0].id);
        assert!(link.overridden.is_empty());
        assert!(!link.waits_for_agents, "{}", rule.rule.name);
        assert!(rule.conditions.is_some(), "{}", rule.rule.name);
    }

    // Starting again changes nothing.
    let changed = database
        .sync_templates(&all, crate::times::now())
        .await
        .unwrap();
    assert!(changed.is_empty());
    assert_eq!(database.list_alert_rules().await.unwrap(), rules);
}

#[tokio::test]
async fn an_upgrade_keeps_what_people_changed_and_says_so_to_admins() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();

    // Someone tells it a channel of their own and waits longer.
    let channel = database
        .create_channel(&crate::alerting::ChannelInput {
            name: "Ops".to_string(),
            kind: crate::alerting::ChannelKind::Webhook,
            target: "http://127.0.0.1:9/ops".to_string(),
            credential: None,
            app_token: None,
            severities: crate::alerting::every_severity(),
            mail: None,
            request: None,
        })
        .await
        .unwrap();
    let slow = rule(&database, "App slow").await;
    let wanted = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(10),
        all_channels: false,
        channels: vec![channel],
        ..slow.rule.clone()
    };
    assert!(database.update_alert_rule(slow.id, &wanted).await.unwrap());
    let changed = rule(&database, "App slow").await;
    assert_eq!(changed.rule, wanted);
    let mut overridden = changed.template.as_ref().unwrap().overridden.clone();
    overridden.sort();
    assert_eq!(overridden, ["all_channels", "channels", "for_secs"]);

    let changed = database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    assert_eq!(changed, ["App"]);
    let upgraded = rule(&database, "App slow").await;
    assert_eq!(upgraded.id, slow.id, "the same rule");
    assert_eq!(upgraded.rule.warning.as_deref(), Some("cpu.usage > 70"));
    assert_eq!(upgraded.rule.hold, chrono::TimeDelta::minutes(10));
    assert_eq!(upgraded.rule.channels, [channel]);
    let names: Vec<String> = rules_named(&database)
        .await
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(names, ["App busy", "App slow"], "gone is gone");

    assert_eq!(database.template_upgrades().await.unwrap(), ["App"]);
    let stored = database.list_templates().await.unwrap().remove(0);
    assert!(stored.upgraded_at.is_some());
    database.dismiss_template_upgrades().await.unwrap();
    assert!(database.template_upgrades().await.unwrap().is_empty());

    // Back to the template's values.
    assert!(
        database
            .reset_template_rule(slow.id, crate::times::now())
            .await
            .unwrap()
    );
    let reset = rule(&database, "App slow").await;
    assert_eq!(reset.rule.hold, chrono::TimeDelta::minutes(5));
    assert!(reset.rule.all_channels && reset.rule.channels.is_empty());
    assert!(reset.template.unwrap().overridden.is_empty());
}

#[tokio::test]
async fn a_disabled_template_stays_disabled_through_an_upgrade() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(&database, "app").await;
    assert!(
        database
            .set_template_enabled(id, false, crate::times::now())
            .await
            .unwrap()
    );
    assert!(rules_named(&database).await.iter().all(|(_, on)| !on));

    database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    assert!(!database.get_template(id).await.unwrap().unwrap().enabled);
    assert!(rules_named(&database).await.iter().all(|(_, on)| !on));

    // An alert turned off stays off when the template is turned back on.
    let busy = rule(&database, "App busy").await;
    let off = AlertRuleInput {
        enabled: false,
        ..busy.rule.clone()
    };
    database.update_alert_rule(busy.id, &off).await.unwrap();
    database
        .set_template_enabled(id, true, crate::times::now())
        .await
        .unwrap();
    assert_eq!(
        rules_named(&database).await,
        [
            ("App busy".to_string(), false),
            ("App slow".to_string(), true)
        ]
    );
}

#[tokio::test]
async fn a_renamed_template_keeps_its_rules_and_one_no_longer_shipped_goes() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(&database, "app").await;
    let slow = rule(&database, "App slow").await;
    let quiet = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(15),
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &quiet).await.unwrap();

    let renamed = APP.replace(
        "template \"app\" {",
        "template \"application\" {\n  renamed_from = [\"app\"]",
    );
    database
        .sync_templates(&shipped(&[&renamed]), crate::times::now())
        .await
        .unwrap();
    assert_eq!(template_id(&database, "application").await, id);
    let kept = rule(&database, "App slow").await;
    assert_eq!(kept.id, slow.id);
    assert_eq!(kept.rule.hold, chrono::TimeDelta::minutes(15));

    let changed = database
        .sync_templates(&[], crate::times::now())
        .await
        .unwrap();
    assert_eq!(changed, ["App"]);
    assert!(database.list_templates().await.unwrap().is_empty());
    assert!(database.list_alert_rules().await.unwrap().is_empty());
    assert_eq!(
        database.template_upgrades().await.unwrap(),
        ["App (removed)"]
    );
}

#[tokio::test]
async fn what_is_in_a_built_in_templates_way_is_moved_aside() {
    let database = Database::for_test().await;
    // Someone's own template and rule, with what a later version ships.
    let theirs = parse(
        &APP.replace("App slow", "Mine slow")
            .replace("App host gone", "Mine gone"),
    )
    .unwrap();
    database
        .create_template(&theirs, APP, crate::times::now())
        .await
        .unwrap();
    database
        .create_alert_rule(&AlertRuleInput::with_conditions(
            "App busy",
            None,
            Some("!online"),
        ))
        .await
        .unwrap();

    database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    let keys: Vec<(String, String, bool)> = database
        .list_templates()
        .await
        .unwrap()
        .into_iter()
        .map(|stored| (stored.template.key, stored.template.name, stored.built_in))
        .collect();
    assert_eq!(
        keys,
        [
            ("app".to_string(), "App".to_string(), true),
            ("app_yours".to_string(), "App (yours)".to_string(), false),
        ]
    );
    let names: Vec<String> = rules_named(&database)
        .await
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(
        names,
        [
            "App busy",
            "App busy (yours)",
            "App slow",
            "Mine gone",
            "Mine slow"
        ]
    );
}

#[tokio::test]
async fn peoples_own_templates_are_added_changed_and_deleted() {
    let database = Database::for_test().await;
    database
        .sync_templates(&built_in::all().unwrap(), crate::times::now())
        .await
        .unwrap();

    let app = parse(APP).unwrap();
    let id = database
        .create_template(&app, APP, crate::times::now())
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(!stored.built_in);
    assert_eq!(stored.source, APP);
    assert_eq!(database.template_rules(&stored).await.unwrap().len(), 2);

    // Its own key and name only.
    let again = database
        .create_template(&app, APP, crate::times::now())
        .await;
    let error = again.unwrap_err();
    assert!(
        matches!(error.downcast_ref(), Some(NameTaken::TemplateKey(_))),
        "{error:#}"
    );
    let host = parse(
        &APP.replace("\"app\"", "\"host\"")
            .replace("\"App\"", "\"Other\""),
    )
    .unwrap();
    let error = database
        .create_template(&host, APP, crate::times::now())
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref(),
        Some(NameTaken::TemplateKey(_))
    ));

    // A changed alert keeps what was changed of it; one that's gone takes its rule.
    let slow = rule(&database, "App slow").await;
    let renamed = AlertRuleInput {
        name: "Slow app".to_string(),
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &renamed).await.unwrap();
    let upgraded = parse(APP_UPGRADED).unwrap();
    assert!(
        database
            .update_template(id, &upgraded, APP_UPGRADED, crate::times::now())
            .await
            .unwrap()
    );
    let kept = rule(&database, "Slow app").await;
    assert_eq!(kept.id, slow.id);
    assert_eq!(kept.rule.warning.as_deref(), Some("cpu.usage > 70"));
    let stored = database.get_template(id).await.unwrap().unwrap();
    let mine: Vec<String> = database
        .template_rules(&stored)
        .await
        .unwrap()
        .into_iter()
        .map(|rule| rule.rule.name)
        .collect();
    assert_eq!(mine, ["Slow app", "App busy"]);

    // A template's rule is disabled, not deleted, and goes with its template.
    let error = database
        .delete_alert_rule(kept.id, crate::times::now())
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
    assert!(
        database
            .delete_template(id, crate::times::now())
            .await
            .unwrap()
    );
    assert_eq!(database.list_alert_rules().await.unwrap().len(), 8);

    // The built-in one stays as it ships.
    let host_id = template_id(&database, "host").await;
    let error = database
        .update_template(host_id, &upgraded, APP_UPGRADED, crate::times::now())
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some());
    let error = database
        .delete_template(host_id, crate::times::now())
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some());
}

#[tokio::test]
async fn a_template_alert_on_its_own_metrics_waits_for_agents() {
    let database = Database::for_test().await;
    let postgres = include_str!("../../../protocol/src/templates/examples/postgres.hcl");
    let template = crate::templates::load(postgres, &json!({})).unwrap();
    let id = database
        .create_template(&template, postgres, crate::times::now())
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    let rules = database.template_rules(&stored).await.unwrap();
    assert_eq!(rules.len(), template.alerts.len());
    assert!(rules.iter().all(AlertRule::waits_for_agents));
    let off = rules
        .iter()
        .find(|rule| rule.rule.name == "Too few standbys")
        .unwrap();
    assert!(!off.rule.enabled, "it ships off");
}

#[tokio::test]
async fn template_changes_are_in_the_audit_log() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(&database, "app").await;
    database
        .set_template_enabled(id, false, crate::times::now())
        .await
        .unwrap();
    let entries = database.audit_log(None, 100).await.unwrap();
    let about: Vec<(String, String)> = entries
        .iter()
        .filter(|entry| entry.subject.kind == "template")
        .map(|entry| (entry.action.clone(), entry.subject.name.clone()))
        .collect();
    assert_eq!(
        about,
        [
            ("changed".to_string(), "App".to_string()),
            ("created".to_string(), "App".to_string())
        ]
    );
}

/// Calls the API with the admin's key, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_templates_alert_is_changed_through_the_alert_rules_api_by_its_short_names() {
    let server = start().await;
    let postgres = include_str!("../../../protocol/src/templates/examples/postgres.hcl");
    let template = crate::templates::load(postgres, &json!({})).unwrap();
    server
        .state
        .database
        .create_template(&template, postgres, crate::times::now())
        .await
        .unwrap();
    let lagging = rule(&server.state.database, "Replica lagging").await;
    let path = format!("/api/v1/alert-rules/{}", lagging.id);

    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200, "{shown}");
    assert_eq!(shown["template"]["alert"], "replica_lagging");
    assert_eq!(shown["template"]["waits_for_agents"], true);

    let mut changed = shown.clone();
    changed["warning"] = json!("lag > duration('1m')");
    let (status, body) = api(&server, "PUT", &path, &changed).await;
    assert_eq!(status, 204, "{body}");
    let (_, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(shown["warning"], "lag > duration('1m')");
    assert_eq!(shown["template"]["overridden"], json!(["warning"]));

    changed["warning"] = json!("lagg > duration('1m')");
    let (status, body) = api(&server, "PUT", &path, &changed).await;
    assert_eq!(status, 422);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("no metric called lagg: did you mean lag?"),
        "{body}"
    );

    let (status, body) = api(&server, "DELETE", &path, &Value::Null).await;
    assert_eq!(status, 422);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("can be disabled but not deleted")
    );
}

/// A server with the built-in templates written, as a real start does.
async fn with_built_in_templates() -> TestServer {
    let server = start().await;
    server
        .state
        .database
        .sync_templates(&built_in::all().unwrap(), crate::times::now())
        .await
        .unwrap();
    server
}

#[tokio::test]
async fn the_templates_pages_show_each_templates_alerts_metrics_and_hcl() {
    let server = with_built_in_templates().await;
    let postgres = include_str!("../../../protocol/src/templates/examples/postgres.hcl");
    let template = crate::templates::load(postgres, &json!({})).unwrap();
    let id = server
        .state
        .database
        .create_template(&template, postgres, crate::times::now())
        .await
        .unwrap();
    let mut browser = Browser::default();

    let settings = browser.get(&server, "/settings").await;
    assert!(
        settings.body.contains(r#"href="/templates""#),
        "{}",
        settings.body
    );
    let list = browser.get(&server, "/templates").await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert!(list.body.contains("Comes with MaxNines"));
    assert!(list.body.contains("PostgreSQL") && list.body.contains("Each postgres database"));

    let page = browser.get(&server, &format!("/templates/{id}")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for expected in [
        "Replica lagging",
        "<code>lag &gt; duration(&#39;30s&#39;)</code>",
        "postgres.slot_retained",
        "Not checked yet",
        "template &quot;postgres&quot;",
    ] {
        assert!(page.body.contains(expected), "{expected}\n{}", page.body);
    }
    assert!(page.has_only_our_scripts());

    for path in [
        "/templates/new".to_string(),
        "/templates/new/hcl".to_string(),
        format!("/templates/{id}/edit"),
        format!("/templates/{id}/edit/hcl"),
    ] {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
    }
    // A built-in one isn't edited.
    let host = template_id(&server.state.database, "host").await;
    let page = browser
        .get(&server, &format!("/templates/{host}/edit"))
        .await;
    assert_eq!(page.status, 404);
}

#[tokio::test]
async fn a_template_is_added_with_the_form_a_row_at_a_time() {
    let server = with_built_in_templates().await;
    let mut browser = Browser::default();
    let token = browser.get(&server, "/templates/new").await.token();

    // Adding an alert shows the form again, with the alert's fields.
    let mut fields = vec![
        ("authenticity_token", token.as_str()),
        ("name", "App"),
        ("key", "app"),
        ("enabled", "on"),
        ("form_action", "add:alert"),
    ];
    let page = browser.post(&server, "/templates", &fields).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains(r#"name="alert.0.warning""#),
        "{}",
        page.body
    );

    // A mistake is said beside its field.
    fields.pop();
    fields.extend([
        ("alert.0.key", "slow"),
        ("alert.0.name", "App slow"),
        ("alert.0.warning", "cpu.usag > 80"),
        ("alert.0.for", "soon"),
        ("alert.0.enabled", "on"),
    ]);
    let page = browser.post(&server, "/templates", &fields).await;
    assert_eq!(page.status, 422, "{}", page.body);
    let warning = page.body.find(r#"name="alert.0.warning""#).unwrap();
    let error = page
        .body
        .find("there&#39;s no metric called cpu.usag")
        .unwrap();
    let hold = page.body.find(r#"name="alert.0.for""#).unwrap();
    let hold_error = page
        .body
        .find("&quot;soon&quot; isn&#39;t a length of time")
        .unwrap();
    assert!(
        warning < error && error < hold && hold < hold_error,
        "{}",
        page.body
    );
    assert!(page.body.contains("2 things need changing"));

    let fixed: Vec<(&str, &str)> = fields
        .iter()
        .map(|&(name, value)| match name {
            "alert.0.warning" => (name, "cpu.usage > 80"),
            "alert.0.for" => (name, "5m"),
            _ => (name, value),
        })
        .collect();
    let page = browser.post(&server, "/templates", &fixed).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let slow = rule(&server.state.database, "App slow").await;
    assert_eq!(slow.rule.hold, chrono::TimeDelta::minutes(5));
    let stored = server
        .state
        .database
        .get_template(template_id(&server.state.database, "app").await)
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.source.contains("alert \"slow\""),
        "{}",
        stored.source
    );
}

#[tokio::test]
async fn a_template_is_added_as_hcl_and_its_mistakes_named() {
    let server = with_built_in_templates().await;
    let mut browser = Browser::default();
    let broken = APP.replace("cpu.usage > 80", "cpu.usage >");
    let page = browser
        .submit(
            &server,
            "/templates/new/hcl",
            "/templates/hcl",
            &[("hcl", &broken)],
        )
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(
        page.body
            .contains("template &quot;app&quot;, alert &quot;slow&quot;, warning:"),
        "{}",
        page.body
    );
    let page = browser
        .submit(
            &server,
            "/templates/new/hcl",
            "/templates/hcl",
            &[("hcl", APP)],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let id = template_id(&server.state.database, "app").await;
    let stored = server
        .state
        .database
        .get_template(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.source, APP, "kept as written");

    // A built-in template's key is taken.
    let host = APP
        .replace("\"app\"", "\"host\"")
        .replace("\"App\"", "\"Mine\"");
    let page = browser
        .submit(
            &server,
            "/templates/new/hcl",
            "/templates/hcl",
            &[("hcl", &host)],
        )
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("already exists"), "{}", page.body);
}

#[tokio::test]
async fn admins_hear_of_upgraded_templates_until_one_dismisses_it() {
    let server = start().await;
    let database = &server.state.database;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    *server.state.template_upgrades.lock().unwrap() = database.template_upgrades().await.unwrap();

    let mut browser = Browser::default();
    let page = browser.get(&server, "/").await;
    assert!(
        page.body
            .contains("An upgrade changed the built-in template App"),
        "{}",
        page.body
    );
    let page = browser
        .submit(
            &server,
            "/",
            "/templates/upgrades/dismiss",
            &[("back", "/hosts")],
        )
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(page.header("location"), Some("/hosts"));
    let page = browser.get(&server, "/").await;
    assert!(!page.body.contains("An upgrade changed"));
    assert!(database.template_upgrades().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_templates_alert_is_changed_with_the_alert_rule_form_and_reset() {
    let server = with_built_in_templates().await;
    let mut browser = Browser::default();
    let offline = rule(&server.state.database, "Host offline").await;
    let edit = format!("/alerts/rules/{}/edit", offline.id);
    let page = browser.get(&server, &edit).await;
    assert!(page.body.contains("One of the"), "{}", page.body);
    assert!(!page.body.contains("Calculation across hosts"));
    assert!(
        !page
            .body
            .contains(&format!("/alerts/rules/{}/delete", offline.id))
    );

    let page = browser
        .submit(
            &server,
            &edit,
            &format!("/alerts/rules/{}", offline.id),
            &[
                ("name", "Host offline"),
                ("critical", "!online"),
                ("summary", "{{ hostname }} is offline"),
                ("resolved_summary", "{{ hostname }} is back online"),
                ("for_secs", "120"),
                ("all_channels", "on"),
                ("enabled", "on"),
                ("applies_to_mode", "builder"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let changed = rule(&server.state.database, "Host offline").await;
    assert_eq!(changed.rule.hold, chrono::TimeDelta::minutes(2));
    assert_eq!(changed.template.as_ref().unwrap().overridden, ["for_secs"]);
    let page = browser.get(&server, &edit).await;
    assert!(
        page.body
            .contains("Changed from the template: For at least"),
        "{}",
        page.body
    );

    let host = template_id(&server.state.database, "host").await;
    let page = browser
        .submit(
            &server,
            &edit,
            &format!("/templates/{host}/alerts/{}/reset", offline.id),
            &[("back", "rule")],
        )
        .await;
    assert_eq!(page.status, 303);
    let reset = rule(&server.state.database, "Host offline").await;
    assert_eq!(reset.rule.hold, chrono::TimeDelta::minutes(1));
}

#[tokio::test]
async fn the_api_covers_what_the_templates_pages_do() {
    let server = with_built_in_templates().await;
    let (status, list) = api(&server, "GET", "/api/v1/templates", &Value::Null).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list[0]["key"], "host");
    assert_eq!(list[0]["built_in"], true);

    let (status, body) = api(&server, "POST", "/api/v1/templates", &json!({ "hcl": APP })).await;
    assert_eq!(status, 201, "{body}");
    let id = body["id"].as_i64().unwrap();
    let path = format!("/api/v1/templates/{id}");
    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200, "{shown}");
    assert_eq!(shown["hcl"], APP);
    assert_eq!(shown["template"]["alerts"][0]["key"], "slow");
    assert_eq!(shown["alerts"][0]["key"], "slow");
    assert_eq!(
        shown["alerts"][0]["template_values"]["warning"],
        "cpu.usage > 80"
    );

    let broken = json!({ "hcl": APP.replace("\"5m\"", "\"soon\"") });
    let (status, body) = api(&server, "PUT", &path, &broken).await;
    assert_eq!(status, 422);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("alert \"slow\", for:"),
        "{body}"
    );
    let (status, body) = api(&server, "PUT", &path, &json!({ "hcl": APP_UPGRADED })).await;
    assert_eq!(status, 204, "{body}");

    // Changing one of its alerts, and putting it back.
    let slow = rule(&server.state.database, "App slow").await;
    let changed = AlertRuleInput {
        warning: Some("cpu.usage > 60".to_string()),
        ..slow.rule.clone()
    };
    let alert = format!("{path}/alerts/slow");
    let (status, body) = api(
        &server,
        "PUT",
        &alert,
        &serde_json::to_value(&changed).unwrap(),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (_, list) = api(&server, "GET", "/api/v1/templates", &Value::Null).await;
    let app = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["key"] == "app")
        .unwrap();
    assert_eq!(app["changed"], true);
    let (status, _) = api(&server, "POST", &format!("{alert}/reset"), &Value::Null).await;
    assert_eq!(status, 204);
    let reset = rule(&server.state.database, "App slow").await;
    assert_eq!(reset.rule.warning.as_deref(), Some("cpu.usage > 70"));

    let (status, _) = api(&server, "POST", &format!("{path}/disable"), &Value::Null).await;
    assert_eq!(status, 204);
    assert!(!rule(&server.state.database, "App slow").await.rule.enabled);
    let (status, _) = api(&server, "POST", &format!("{path}/enable"), &Value::Null).await;
    assert_eq!(status, 204);

    let host = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["key"] == "host")
        .unwrap();
    let host = format!("/api/v1/templates/{}", host["id"]);
    let (status, body) = api(&server, "DELETE", &host, &Value::Null).await;
    assert_eq!(status, 422, "{body}");
    let (status, _) = api(&server, "DELETE", &path, &Value::Null).await;
    assert_eq!(status, 204);
    let (status, _) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 404);

    let (status, body) = api(&server, "GET", "/api/v1/templates/upgrades", &Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({ "templates": [] }));
    let (status, _) = api(
        &server,
        "POST",
        "/api/v1/templates/upgrades/dismiss",
        &Value::Null,
    )
    .await;
    assert_eq!(status, 204);
}
