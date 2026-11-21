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
