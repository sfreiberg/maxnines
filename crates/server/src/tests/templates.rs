//! Templates: the built-in ones written as the server starts, people's own, and the
//! alert rules their alerts become, with what people change of them kept apart.

use super::*;
use crate::alerting::{AlertRule, AlertRuleInput, NameTaken};
use crate::catalog::Catalog;
use crate::models::{Database, Imported, Origin};
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

/// The PostgreSQL example as the docs have it, which is refused for its metrics'
/// names: see [`crate::templates::postgres_example`].
const POSTGRES_AS_WRITTEN: &str = include_str!("../../../../docs/examples/postgres.hcl");
static POSTGRES: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(crate::templates::postgres_example);
const IIS: &str = include_str!("../../../../docs/examples/iis.hcl");

/// The rule in use for a template's alert, and the template's own beside it if
/// that's a copy.
async fn alert_of(database: &Database, template: i64, key: &str) -> crate::models::TemplateAlert {
    let alerts = database.template_alerts(template).await.unwrap();
    alerts
        .into_iter()
        .find(|alert| alert.key == key)
        .unwrap_or_else(|| panic!("no alert {key}"))
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
    assert!(templates[0].origin == Origin::BuiltIn && templates[0].enabled);
    assert_eq!(templates[0].template.key, "host");
    let rules = database.list_alert_rules().await.unwrap();
    assert_eq!(rules.len(), 8);
    for rule in &rules {
        let link = rule.template.as_ref().unwrap();
        assert_eq!(link.id, templates[0].id);
        assert!(link.replaces_id.is_none() && link.template_enabled);
        assert!(rule.runs(), "{}", rule.rule.name);
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

/// A template is kept as rows, and HCL written from them reads back as the same
/// rows, whatever comments and layout it came with.
#[tokio::test]
async fn a_template_goes_from_hcl_to_rows_to_hcl_and_back_to_the_same_rows() {
    let host = built_in::all().unwrap().remove(0).source;
    for source in [POSTGRES.as_str(), IIS, host.as_str()] {
        let database = Database::for_test().await;
        let template = crate::templates::load(source, &json!({}), &Catalog::built_in()).unwrap();
        let id = database
            .create_template(&template, crate::times::now())
            .await
            .unwrap();
        let stored = database.get_template(id).await.unwrap().unwrap();
        assert_eq!(stored.template, template, "{}", template.key);

        // Written out, read and saved over itself, and nothing has changed.
        let written = stored.hcl();
        assert!(
            !written
                .lines()
                .any(|line| line.trim_start().starts_with('#')),
            "comments aren't kept"
        );
        let again = crate::templates::load(&written, &json!({}), &Catalog::built_in()).unwrap();
        assert!(
            database
                .update_template(id, &again, crate::times::now())
                .await
                .unwrap()
        );
        let after = database.get_template(id).await.unwrap().unwrap();
        assert_eq!(after.template, stored.template);
        assert_eq!(after.hcl(), written);
    }
}

#[tokio::test]
async fn changing_a_built_in_alert_makes_a_copy_that_upgrades_leave_alone() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(&database, "app").await;
    let slow = rule(&database, "App slow").await;
    let wanted = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(10),
        ..slow.rule.clone()
    };
    assert!(database.update_alert_rule(slow.id, &wanted).await.unwrap());

    // The copy is the one in use, and the built-in rule is as it was.
    let alert = alert_of(&database, id, "slow").await;
    assert_eq!(alert.rule.id, slow.id);
    assert_eq!(alert.rule.rule, slow.rule);
    let copy = alert.copy.clone().unwrap();
    assert_eq!(copy.rule, wanted);
    assert_eq!(copy.template.as_ref().unwrap().replaces_id, Some(slow.id));
    let in_use = rule(&database, "App slow").await;
    assert_eq!(in_use.id, copy.id, "only the copy is listed and checked");
    assert_eq!(database.list_alert_rules().await.unwrap().len(), 2);
    assert!(database.get_template(id).await.unwrap().unwrap().template == parse(APP).unwrap());

    // Saving it again, by either rule, changes the copy.
    let again = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(20),
        ..wanted.clone()
    };
    assert!(database.update_alert_rule(slow.id, &again).await.unwrap());
    assert_eq!(
        alert_of(&database, id, "slow").await.copy.unwrap().id,
        copy.id
    );

    let changed = database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    assert_eq!(changed, ["App"]);
    let alert = alert_of(&database, id, "slow").await;
    assert_eq!(alert.rule.rule.warning.as_deref(), Some("cpu.usage > 70"));
    let kept = alert.copy.unwrap();
    assert_eq!(kept.rule, again, "the copy is as it was left");
    assert!(kept.template.unwrap().original_changed_at.is_some());
    let names: Vec<String> = rules_named(&database)
        .await
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(names, ["App busy", "App slow"], "gone is gone");

    assert_eq!(
        database.template_upgrades().await.unwrap(),
        ["App (its version of App slow changed, which you have your own of)"]
    );
    database.dismiss_template_upgrades().await.unwrap();
    assert!(database.template_upgrades().await.unwrap().is_empty());

    // Resetting deletes the copy, and the built-in rule is in use again.
    assert!(
        database
            .reset_template_rule(copy.id, crate::times::now())
            .await
            .unwrap()
    );
    let reset = rule(&database, "App slow").await;
    assert_eq!(reset.id, slow.id);
    assert_eq!(reset.rule.warning.as_deref(), Some("cpu.usage > 70"));
    assert!(alert_of(&database, id, "slow").await.copy.is_none());
    assert!(
        !database
            .reset_template_rule(slow.id, crate::times::now())
            .await
            .unwrap(),
        "there's no copy to delete"
    );
}

#[tokio::test]
async fn what_is_turned_off_stays_off_through_an_upgrade() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(&database, "app").await;

    // Turning a built-in alert off is its own flag, with no copy.
    let slow = rule(&database, "App slow").await;
    let off = AlertRuleInput {
        enabled: false,
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &off).await.unwrap();
    let alert = alert_of(&database, id, "slow").await;
    assert!(alert.copy.is_none() && !alert.rule.rule.enabled);

    database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    let slow = rule(&database, "App slow").await;
    assert!(!slow.rule.enabled, "still off");
    assert_eq!(slow.rule.warning.as_deref(), Some("cpu.usage > 70"));

    // A template turned off stops its alerts without changing them, and stays off.
    assert!(
        database
            .set_template_enabled(id, false, crate::times::now())
            .await
            .unwrap()
    );
    let busy = rule(&database, "App busy").await;
    assert!(busy.rule.enabled && !busy.runs());
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    assert!(!database.get_template(id).await.unwrap().unwrap().enabled);
    database
        .set_template_enabled(id, true, crate::times::now())
        .await
        .unwrap();
    assert!(rule(&database, "App host gone").await.runs());
    assert!(!rule(&database, "App slow").await.runs());
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
    let alert = alert_of(&database, id, "slow").await;
    assert_eq!(alert.rule.id, slow.id);
    assert_eq!(
        alert.copy.unwrap().rule.hold,
        chrono::TimeDelta::minutes(15)
    );

    let changed = database
        .sync_templates(&[], crate::times::now())
        .await
        .unwrap();
    assert_eq!(changed, ["App"]);
    assert!(database.list_templates().await.unwrap().is_empty());
    // Their copy of one of its alerts stays, as an ordinary rule of theirs.
    let left = database.list_alert_rules().await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].rule.hold, chrono::TimeDelta::minutes(15));
    assert!(left[0].template.is_none());
    assert_eq!(
        database.template_upgrades().await.unwrap(),
        ["App (removed; your own copy of App slow is kept as a rule of yours)"]
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
        .create_template(&theirs, crate::times::now())
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
        .map(|stored| {
            (
                stored.template.key,
                stored.template.name,
                stored.origin == Origin::BuiltIn,
            )
        })
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
async fn peoples_own_templates_are_changed_directly_with_no_copies() {
    let database = Database::for_test().await;
    database
        .sync_templates(&built_in::all().unwrap(), crate::times::now())
        .await
        .unwrap();

    let app = parse(APP).unwrap();
    let id = database
        .create_template(&app, crate::times::now())
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(stored.origin, Origin::Own);
    assert_eq!(stored.template, app);
    assert_eq!(database.template_alerts(id).await.unwrap().len(), 2);

    // Its own key and name only.
    let again = database.create_template(&app, crate::times::now()).await;
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
        .create_template(&host, crate::times::now())
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref(),
        Some(NameTaken::TemplateKey(_))
    ));

    // Changing its alert with the rule's form changes the template itself.
    let slow = rule(&database, "App slow").await;
    let renamed = AlertRuleInput {
        name: "Slow app".to_string(),
        all_channels: false,
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &renamed).await.unwrap();
    let alert = alert_of(&database, id, "slow").await;
    assert!(alert.copy.is_none());
    assert_eq!(alert.rule.rule, renamed);
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(stored.template.alerts[0].name, "Slow app");

    // Saving the template keeps who its alerts tell; one that's gone takes its rule.
    let mut upgraded = parse(APP_UPGRADED).unwrap();
    upgraded.alerts[0].name = "Slow app".to_string();
    assert!(
        database
            .update_template(id, &upgraded, crate::times::now())
            .await
            .unwrap()
    );
    let kept = rule(&database, "Slow app").await;
    assert_eq!(kept.id, slow.id);
    assert_eq!(kept.rule.warning.as_deref(), Some("cpu.usage > 70"));
    assert!(!kept.rule.all_channels);
    let mine: Vec<String> = database
        .template_alerts(id)
        .await
        .unwrap()
        .into_iter()
        .map(|alert| alert.rule.rule.name)
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
        .update_template(host_id, &upgraded, crate::times::now())
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
async fn a_template_alert_on_its_own_metrics_is_checked_and_knows_what_discovery_picks() {
    let database = Database::for_test().await;
    let template =
        crate::templates::load(POSTGRES.as_str(), &json!({}), &Catalog::built_in()).unwrap();
    let id = database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let alerts = database.template_alerts(id).await.unwrap();
    assert_eq!(alerts.len(), template.alerts.len());
    for (alert, written) in alerts.iter().zip(&template.alerts) {
        // Its conditions are read with the template's own metrics, by their short
        // names, as saving it read them.
        let conditions = alert.rule.conditions.as_ref();
        assert!(conditions.is_some(), "{}", alert.key);
        // One for some of what discovery finds says so, and runs as any other.
        let picks = written.when.is_some() || written.since.is_some();
        assert_eq!(alert.rule.picks_by_discovery(), picks, "{}", alert.key);
        assert_eq!(alert.rule.runs(), written.enabled, "{}", alert.key);
    }
    let waiting: Vec<&str> = alerts
        .iter()
        .filter(|alert| alert.rule.picks_by_discovery())
        .map(|alert| alert.key.as_str())
        .collect();
    assert_eq!(
        waiting,
        [
            "checksum_failures",
            "replica_lagging",
            "replica_not_receiving",
            "standby_lagging",
            "too_few_standbys",
            "slot_lost",
            "archiving_failing"
        ]
    );
    let off = alerts
        .iter()
        .find(|alert| alert.rule.rule.name == "Too few standbys")
        .unwrap();
    assert!(!off.rule.rule.enabled, "it ships off");
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
    let postgres = POSTGRES.as_str();
    let template = crate::templates::load(postgres, &json!({}), &Catalog::built_in()).unwrap();
    server
        .state
        .database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let lagging = rule(&server.state.database, "Replica lagging").await;
    let path = format!("/api/v1/alert-rules/{}", lagging.id);

    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200, "{shown}");
    assert_eq!(shown["template"]["alert"], "replica_lagging");
    assert_eq!(shown["template"]["key"], "pg");
    // It's only for replicas, which discovery says.
    assert_eq!(shown["template"]["when"], "role == 'replica'");

    let mut changed = shown.clone();
    changed["warning"] = json!("lag > duration('1m')");
    let (status, body) = api(&server, "PUT", &path, &changed).await;
    assert_eq!(status, 204, "{body}");
    let (_, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(shown["warning"], "lag > duration('1m')");
    assert_eq!(
        shown["template"]["replaces_id"],
        Value::Null,
        "theirs, so changed directly"
    );

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
    let postgres = POSTGRES.as_str();
    let template = crate::templates::load(postgres, &json!({}), &Catalog::built_in()).unwrap();
    let id = server
        .state
        .database
        .create_template(&template, crate::times::now())
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
        "pg.slot_retained",
        "Only for the databases where what discovery found fits",
        "template &quot;pg&quot;",
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
    assert!(stored.hcl().contains("alert \"slow\""), "{}", stored.hcl());
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
    assert_eq!(stored.template, parse(APP).unwrap());

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
        page.body.contains("A new version changed the template App"),
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
    assert!(!page.body.contains("A new version changed"));
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
    // A copy of their own is in use now, and the built-in rule's form leads to it.
    let copy = rule(&server.state.database, "Host offline").await;
    assert_ne!(copy.id, offline.id);
    assert_eq!(copy.rule.hold, chrono::TimeDelta::minutes(2));
    assert_eq!(
        copy.template.as_ref().unwrap().replaces_id,
        Some(offline.id)
    );
    let page = browser.get(&server, &edit).await;
    assert_eq!(page.status, 303);
    let copy_edit = format!("/alerts/rules/{}/edit", copy.id);
    assert_eq!(page.header("location"), Some(copy_edit.as_str()));
    let page = browser.get(&server, &copy_edit).await;
    assert!(page.body.contains("Your own copy"), "{}", page.body);
    assert!(
        page.body.contains("For at least: 1 minute"),
        "{}",
        page.body
    );

    let host = template_id(&server.state.database, "host").await;
    let template_page = browser.get(&server, &format!("/templates/{host}")).await;
    assert!(template_page.body.contains("Your own copy. It comes as"));
    let page = browser
        .submit(
            &server,
            &copy_edit,
            &format!("/templates/{host}/alerts/{}/reset", copy.id),
            &[],
        )
        .await;
    assert_eq!(page.status, 303);
    let reset = rule(&server.state.database, "Host offline").await;
    assert_eq!(reset.id, offline.id);
    assert_eq!(reset.rule.hold, chrono::TimeDelta::minutes(1));
}

#[tokio::test]
async fn the_api_covers_what_the_templates_pages_do() {
    let server = with_built_in_templates().await;
    let (status, list) = api(&server, "GET", "/api/v1/templates", &Value::Null).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list[0]["key"], "host");
    assert_eq!(list[0]["origin"], "built_in");

    let (status, body) = api(&server, "POST", "/api/v1/templates", &json!({ "hcl": APP })).await;
    assert_eq!(status, 201, "{body}");
    let id = body["id"].as_i64().unwrap();
    let path = format!("/api/v1/templates/{id}");
    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200, "{shown}");
    assert!(
        shown["hcl"].as_str().unwrap().contains("alert \"slow\""),
        "{shown}"
    );
    assert_eq!(shown["template"]["alerts"][0]["key"], "slow");
    assert_eq!(shown["alerts"][0]["key"], "slow");
    assert_eq!(shown["alerts"][0]["rule"]["warning"], "cpu.usage > 80");
    assert_eq!(shown["alerts"][0]["built_in_rule"], Value::Null);

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

    // Changing a built-in template's alert makes a copy, and deleting it puts the
    // template's own back.
    let host = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["key"] == "host")
        .unwrap();
    let host = format!("/api/v1/templates/{}", host["id"]);
    let offline = rule(&server.state.database, "Host offline").await;
    let changed = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(2),
        ..offline.rule.clone()
    };
    let alert = format!("{host}/alerts/offline");
    let (status, body) = api(
        &server,
        "PUT",
        &alert,
        &serde_json::to_value(&changed).unwrap(),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (_, shown) = api(&server, "GET", &host, &Value::Null).await;
    assert_eq!(shown["changed"], true);
    let offline_shown = shown["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|alert| alert["key"] == "offline")
        .unwrap();
    assert_eq!(offline_shown["rule"]["for_secs"], 120);
    assert_eq!(offline_shown["built_in_rule"]["for_secs"], 60);
    assert_eq!(offline_shown["built_in_rule"]["id"], offline.id);
    let (status, _) = api(&server, "DELETE", &alert, &Value::Null).await;
    assert_eq!(status, 204);
    let (status, _) = api(&server, "POST", &format!("{alert}/reset"), &Value::Null).await;
    assert_eq!(status, 404, "there's no copy left");
    assert_eq!(
        rule(&server.state.database, "Host offline").await.id,
        offline.id
    );

    let (status, _) = api(&server, "POST", &format!("{path}/disable"), &Value::Null).await;
    assert_eq!(status, 204);
    assert!(!rule(&server.state.database, "App slow").await.runs());
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

#[tokio::test]
async fn cel_fields_get_suggestions_from_the_real_catalog() {
    let server = with_built_in_templates().await;
    let mut browser = Browser::default();
    let page = browser.get(&server, "/conditions/suggestions").await;
    assert_eq!(page.status, 200, "{}", page.body);
    let suggestions: Value = serde_json::from_str(&page.body).unwrap();
    let load = suggestions["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|metric| metric["name"] == "cpu.load")
        .unwrap();
    assert_eq!(
        load["series"],
        json!(["1 minute", "5 minutes", "15 minutes"])
    );
    let names = |part: &str| -> Vec<String> {
        suggestions[part]
            .as_array()
            .unwrap()
            .iter()
            .map(|each| each["name"].as_str().unwrap().to_string())
            .collect()
    };
    for expected in [
        "online",
        "reporting",
        "hostname",
        "series",
        "value",
        "facts",
    ] {
        assert!(
            names("variables").contains(&expected.to_string()),
            "{expected}"
        );
    }
    for expected in ["forecast", "duration", "kib", "mib", "gib", "tib"] {
        assert!(
            names("functions").contains(&expected.to_string()),
            "{expected}"
        );
    }

    // The API has the same, and the forms say where to use it.
    let (status, from_api) = api(
        &server,
        "GET",
        "/api/v1/conditions/suggestions",
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(from_api, suggestions);
    let rule = rule(&server.state.database, "Disk filling up").await;
    let form = browser
        .get(&server, &format!("/alerts/rules/{}/edit", rule.id))
        .await;
    assert!(
        form.body.contains(r#"name="warning""#) && form.body.contains(r#"data-cel="condition""#)
    );
    assert!(
        form.body.contains("data-cel-local="),
        "a template's rule knows its metrics"
    );
    assert!(
        form.body
            .contains(r#"<script src="/assets/js/cel_complete.js""#)
    );

    let postgres = POSTGRES.as_str();
    let template = crate::templates::load(postgres, &json!({}), &Catalog::built_in()).unwrap();
    let id = server
        .state
        .database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let form = browser.get(&server, &format!("/templates/{id}/edit")).await;
    let start = form.body.find("data-cel-local=\"").unwrap() + "data-cel-local=\"".len();
    let end = start + form.body[start..].find('"').unwrap();
    let local: Value =
        serde_json::from_str(&form.body[start..end].replace("&quot;", "\"")).unwrap();
    assert_eq!(local["prefix"], "pg");
    assert!(
        local["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "lag")
    );
    assert_eq!(
        local["discovered"],
        json!(["version", "archiving", "sees_all_sessions", "role"])
    );
}

#[tokio::test]
async fn an_imported_template_is_replaced_by_a_newer_one_keeping_copies_and_what_is_off() {
    let database = Database::for_test().await;
    database
        .sync_templates(&built_in::all().unwrap(), crate::times::now())
        .await
        .unwrap();
    let app = parse(APP).unwrap();
    assert_eq!(
        database.import_outcome(&app).await.unwrap(),
        Imported::Added
    );
    let (id, outcome) = database
        .import_template(&app, crate::times::now())
        .await
        .unwrap();
    assert_eq!(outcome, Imported::Added);
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(stored.origin, Origin::Imported);
    assert!(database.template_upgrades().await.unwrap().is_empty());

    // Like a built-in one: it isn't edited, its alert is copied to change it, and
    // turning an alert off is a flag.
    let error = database
        .update_template(id, &app, crate::times::now())
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some());
    let slow = rule(&database, "App slow").await;
    let wanted = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(10),
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &wanted).await.unwrap();
    let gone = rule(&database, "App host gone").await;
    let off = AlertRuleInput {
        enabled: false,
        ..gone.rule.clone()
    };
    database.update_alert_rule(gone.id, &off).await.unwrap();
    database
        .set_template_enabled(id, false, crate::times::now())
        .await
        .unwrap();

    // The same again changes nothing; a newer version replaces it.
    let (_, outcome) = database
        .import_template(&app, crate::times::now())
        .await
        .unwrap();
    assert_eq!(outcome, Imported::Unchanged);
    let newer = parse(&APP.replace("cpu.usage > 80", "cpu.usage > 70")).unwrap();
    let (again, outcome) = database
        .import_template(&newer, crate::times::now())
        .await
        .unwrap();
    assert_eq!((again, outcome), (id, Imported::Updated));
    let alert = alert_of(&database, id, "slow").await;
    assert_eq!(alert.rule.rule.warning.as_deref(), Some("cpu.usage > 70"));
    assert_eq!(alert.copy.unwrap().rule, wanted, "the copy is left");
    assert!(!rule(&database, "App host gone").await.rule.enabled);
    assert!(!database.get_template(id).await.unwrap().unwrap().enabled);
    assert_eq!(
        database.template_upgrades().await.unwrap(),
        ["App (its version of App slow changed, which you have your own of)"]
    );

    // Unlike a built-in one, it can be deleted, with its rules. Their copy stays.
    assert!(
        database
            .delete_template(id, crate::times::now())
            .await
            .unwrap()
    );
    let left = database.list_alert_rules().await.unwrap();
    assert_eq!(left.len(), 9);
    let kept = left
        .iter()
        .find(|rule| rule.rule.name == "App slow")
        .unwrap();
    assert!(kept.template.is_none());
    assert_eq!(kept.rule, wanted);
}

#[tokio::test]
async fn an_import_in_the_way_of_a_built_in_or_own_template_is_refused() {
    let database = Database::for_test().await;
    database
        .sync_templates(&built_in::all().unwrap(), crate::times::now())
        .await
        .unwrap();
    let own = parse(APP).unwrap();
    database
        .create_template(&own, crate::times::now())
        .await
        .unwrap();

    let host_key = parse(
        &APP.replace("\"app\"", "\"host\"")
            .replace("\"App\"", "\"Other\""),
    )
    .unwrap();
    let host_name = parse(
        &APP.replace("\"app\"", "\"other\"")
            .replace("\"App\"", "\"host\""),
    )
    .unwrap();
    for (template, expected) in [
        (&host_key, "is the key of the built-in template Host"),
        (&host_name, "is the name of a built-in template"),
        (&own, "is the key of your own template App"),
    ] {
        let error = database
            .import_template(template, crate::times::now())
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert!(database.import_outcome(template).await.is_err());
    }
    assert_eq!(database.list_templates().await.unwrap().len(), 2);
}

#[tokio::test]
async fn importing_shows_what_it_would_do_before_it_does_and_exports_read_back() {
    let server = with_built_in_templates().await;
    let mut browser = Browser::default();

    // A look first, with everything it would run, and nothing saved.
    let page = browser
        .submit(
            &server,
            "/templates/import",
            "/templates/import",
            &[("hcl", POSTGRES.as_str())],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    for expected in [
        "This would add a template.",
        "Replica lagging",
        "pg.slot_retained",
        "FROM pg_stat_replication",
        "invalidation_reason IS NOT NULL",
        r#"name="confirm""#,
    ] {
        assert!(page.body.contains(expected), "{expected}\n{}", page.body);
    }
    assert!(page.has_only_our_scripts());
    assert_eq!(
        server.state.database.list_templates().await.unwrap().len(),
        1
    );

    let broken = POSTGRES.replace("critical         = \"!up\"", "critical         = \"!upp\"");
    let page = browser
        .submit(
            &server,
            "/templates/import",
            "/templates/import",
            &[("hcl", &broken), ("confirm", "yes")],
        )
        .await;
    assert_eq!(page.status, 422);
    assert!(
        page.body.contains("It can't be imported as it is"),
        "{}",
        page.body
    );
    assert!(!page.body.contains(r#"name="confirm""#));

    let page = browser
        .submit(
            &server,
            "/templates/import",
            "/templates/import",
            &[("hcl", POSTGRES.as_str()), ("confirm", "yes")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let id = template_id(&server.state.database, "pg").await;

    // A newer version says what it would change.
    let newer = POSTGRES.replace("connections_used > 80", "connections_used > 70");
    let page = browser
        .submit(
            &server,
            "/templates/import",
            "/templates/import",
            &[("hcl", &newer)],
        )
        .await;
    assert!(
        page.body
            .contains("Changes the alert connections_running_out"),
        "{}",
        page.body
    );

    // The export is HCL that reads back as the same template, from the page and the API.
    let page = browser
        .get(&server, &format!("/templates/{id}/export"))
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.header("content-disposition")
            .unwrap()
            .contains("pg.hcl")
    );
    let stored = server
        .state
        .database
        .get_template(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parse(&page.body).unwrap(), stored.template);
    let response = server
        .request("GET", &format!("/api/v1/templates/{id}/export"), "")
        .await;
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    assert_eq!(parse(body).unwrap(), stored.template);
    let host = template_id(&server.state.database, "host").await;
    let page = browser
        .get(&server, &format!("/templates/{host}/export"))
        .await;
    assert!(page.body.contains("template \"host\""));

    // The API does the same, with a dry run for the look first.
    let (status, preview) = api(
        &server,
        "POST",
        "/api/v1/templates/import",
        &json!({ "hcl": newer, "dry_run": true }),
    )
    .await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["outcome"], "updated");
    assert_eq!(
        preview["changes"],
        json!(["Changes the alert connections_running_out"])
    );
    assert!(preview["sql"].as_array().unwrap().len() > 10);
    let (status, body) = api(
        &server,
        "POST",
        "/api/v1/templates/import",
        &json!({ "hcl": newer }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({ "id": id, "outcome": "updated" }));
    let (status, body) = api(
        &server,
        "POST",
        "/api/v1/templates/import",
        &json!({ "hcl": APP }),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = api(
        &server,
        "POST",
        "/api/v1/templates/import",
        &json!({ "hcl": APP.replace("\"app\"", "\"host\"").replace("\"App\"", "\"Other\"") }),
    )
    .await;
    assert_eq!(status, 422);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("built-in template"),
        "{body}"
    );

    // Imports and re-imports are in the audit log, as whoever did them.
    let entries = server.state.database.audit_log(None, 200).await.unwrap();
    let postgres: Vec<&str> = entries
        .iter()
        .filter(|entry| entry.subject.kind == "template" && entry.subject.name == "PostgreSQL")
        .map(|entry| entry.action.as_str())
        .collect();
    assert_eq!(postgres, ["changed", "created"]);
}

/// Whether a template or one of its alerts is on follows what a newer version
/// ships until someone chooses, and then it's theirs.
#[tokio::test]
async fn a_newer_version_turns_things_on_and_off_until_someone_chooses() {
    let database = Database::for_test().await;
    let shipped_off = APP
        .replace("name = \"App\"", "name = \"App\"\n  enabled = false")
        .replace(
            "name     = \"App slow\"",
            "name     = \"App slow\"\n    enabled = false",
        );
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(&database, "app").await;
    let gone = rule(&database, "App host gone").await;

    // Never touched: a newer version turns the template and an alert off, and on again.
    database
        .sync_templates(&shipped(&[&shipped_off]), crate::times::now())
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(!stored.enabled && stored.enabled_choice.is_none());
    let slow = rule(&database, "App slow").await;
    assert!(!slow.rule.enabled);
    assert_eq!(slow.template.as_ref().unwrap().enabled_choice, None);
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    assert!(database.get_template(id).await.unwrap().unwrap().enabled);
    assert!(rule(&database, "App slow").await.rule.enabled);

    // Chosen off: a newer version that ships it on leaves it off.
    let off = AlertRuleInput {
        enabled: false,
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &off).await.unwrap();
    database
        .set_template_enabled(id, false, crate::times::now())
        .await
        .unwrap();
    let newer = APP.replace("cpu.usage > 95", "cpu.usage > 96");
    database
        .sync_templates(&shipped(&[&newer]), crate::times::now())
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(!stored.enabled);
    assert_eq!(stored.enabled_choice, Some(false));
    let slow = rule(&database, "App slow").await;
    assert!(!slow.rule.enabled);
    assert_eq!(slow.template.as_ref().unwrap().enabled_choice, Some(false));

    // Chosen on: a newer version that ships it off leaves it on.
    let on = AlertRuleInput {
        enabled: true,
        ..slow.rule.clone()
    };
    database.update_alert_rule(slow.id, &on).await.unwrap();
    database
        .set_template_enabled(id, true, crate::times::now())
        .await
        .unwrap();
    database
        .sync_templates(&shipped(&[&shipped_off]), crate::times::now())
        .await
        .unwrap();
    assert!(database.get_template(id).await.unwrap().unwrap().enabled);
    let slow = rule(&database, "App slow").await;
    assert!(slow.rule.enabled);
    assert_eq!(slow.template.as_ref().unwrap().enabled_choice, Some(true));
    assert!(
        rule(&database, "App host gone").await.rule.enabled,
        "never shipped off"
    );
    assert_eq!(rule(&database, "App host gone").await.id, gone.id);

    // Putting them back follows the template again, which ships them off.
    assert!(
        database
            .reset_template_rule(slow.id, crate::times::now())
            .await
            .unwrap()
    );
    let slow = rule(&database, "App slow").await;
    assert!(!slow.rule.enabled);
    assert_eq!(slow.template.as_ref().unwrap().enabled_choice, None);
    assert!(
        database
            .follow_template_enabled(id, crate::times::now())
            .await
            .unwrap()
    );
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(!stored.enabled && stored.enabled_choice.is_none());
}

/// A template's parts are written over the rows they have, each matched by its key,
/// so a row keeps its ID while its part is there.
#[tokio::test]
async fn saving_a_template_keeps_the_rows_of_the_parts_it_still_has() {
    let database = Database::for_test().await;
    let mut template =
        crate::templates::load(POSTGRES.as_str(), &json!({}), &Catalog::built_in()).unwrap();
    let id = database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let ids = database.template_part_ids(id).await;
    assert!(ids.contains_key("discover server") && ids.contains_key("discover role"));
    assert!(ids.contains_key("notice cannot_see_sessions"));
    assert!(ids.contains_key("query slots fill lost version 17"));
    assert!(ids.contains_key("query throughput metric cache_hit"));

    // Saved as it is, nothing moves.
    database
        .update_template(id, &template, crate::times::now())
        .await
        .unwrap();
    assert_eq!(database.template_part_ids(id).await, ids);

    // A choice someone made of a query stays as its SQL changes, as does every row.
    let sessions = ids["query sessions"];
    database.set_query_choice(sessions, Some(false)).await;
    template.queries[0].sql = template.queries[0].sql.replace("AS uptime", "AS up_for");
    template.queries[0].interval = Some("2m".to_string());
    template.discover[0].interval = Some("5m".to_string());
    let slots = template
        .queries
        .iter_mut()
        .find(|q| q.key == "slots")
        .unwrap();
    slots.fills[2].versions.insert(
        "17".to_string(),
        "invalidation_reason IS NOT NULL".to_string(),
    );
    database
        .update_template(id, &template, crate::times::now())
        .await
        .unwrap();
    assert_eq!(database.template_part_ids(id).await, ids);
    assert_eq!(database.query_choice(sessions).await, Some(false));
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(stored.template, template);

    // Parts in another order keep their rows, and are read back in the new order.
    template.queries.swap(0, 1);
    template.alerts.swap(0, 2);
    database
        .update_template(id, &template, crate::times::now())
        .await
        .unwrap();
    assert_eq!(database.template_part_ids(id).await, ids);
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(stored.template, template);
    assert_eq!(stored.template.queries[0].key, "throughput");

    // One that's gone takes only its own rows, and a new one gets rows of its own.
    template.queries.retain(|query| query.key != "slots");
    template
        .alerts
        .retain(|alert| !alert.key.starts_with("slot_"));
    let mut added = template.queries[2].clone();
    added.key = "more".to_string();
    added.sql = "SELECT count(*) AS more FROM pg_stat_activity".to_string();
    added.fills.clear();
    added.metrics.clear();
    template.queries.push(added);
    let problems = crate::templates::check(&template, &json!({}), &Catalog::built_in());
    assert!(problems.is_empty(), "{problems:?}");
    database
        .update_template(id, &template, crate::times::now())
        .await
        .unwrap();
    let after = database.template_part_ids(id).await;
    assert!(after.contains_key("query more"));
    assert!(!after.keys().any(|part| part.starts_with("query slots")));
    for (part, row) in &after {
        if part != "query more" {
            assert_eq!(ids.get(part), Some(row), "{part}");
        }
    }
    assert_eq!(
        after.len(),
        ids.len() - ids.keys().filter(|p| p.starts_with("query slots")).count() + 1
    );
    assert_eq!(database.query_choice(sessions).await, Some(false));
}

#[tokio::test]
async fn importing_syncing_and_the_form_all_keep_the_rows_of_parts_still_there() {
    let server = with_built_in_templates().await;
    let database = &server.state.database;

    // An import replaced by a newer one.
    let iis = crate::templates::load(IIS, &json!({}), &Catalog::built_in()).unwrap();
    let (id, _) = database
        .import_template(&iis, crate::times::now())
        .await
        .unwrap();
    let ids = database.template_part_ids(id).await;
    assert!(ids.contains_key("discover iis registry HKLM\\SOFTWARE\\Microsoft\\InetStp"));
    assert!(ids.contains_key("counters app_pools metric pool_running"));
    let mut newer = iis.clone();
    newer.counters[0].metrics[0].counter = Some("Total Method Requests".to_string());
    newer.counters[0].metrics[0].total = true;
    newer
        .counters
        .retain(|counters| counters.key != "asp_net_apps");
    newer.alerts[0].hold = Some("2m".to_string());
    let (_, outcome) = database
        .import_template(&newer, crate::times::now())
        .await
        .unwrap();
    assert_eq!(outcome, Imported::Updated);
    let after = database.template_part_ids(id).await;
    assert!(
        !after
            .keys()
            .any(|part| part.starts_with("counters asp_net_apps"))
    );
    for (part, row) in &after {
        assert_eq!(ids.get(part), Some(row), "{part}");
    }
    assert_eq!(
        database.get_template(id).await.unwrap().unwrap().template,
        newer
    );

    // A built-in one, as the server starts with a newer version of it.
    database
        .sync_templates(&shipped(&[POSTGRES.as_str()]), crate::times::now())
        .await
        .unwrap();
    let postgres = template_id(database, "pg").await;
    let ids = database.template_part_ids(postgres).await;
    let sessions = ids["query sessions"];
    database.set_query_choice(sessions, Some(false)).await;
    database
        .sync_templates(
            &shipped(&[&POSTGRES.replace("AS uptime", "AS up_for")]),
            crate::times::now(),
        )
        .await
        .unwrap();
    assert_eq!(database.template_part_ids(postgres).await, ids);
    assert_eq!(database.query_choice(sessions).await, Some(false));

    // One of their own, saved from its form.
    let own = parse(
        &POSTGRES
            .replace("\"pg\" {", "\"mine\" {")
            .replace("\"PostgreSQL\"", "\"Mine\"")
            .replace("PostgreSQL down", "Mine down"),
    )
    .unwrap();
    let mut own = own;
    for alert in &mut own.alerts {
        alert.name = format!("Mine: {}", alert.name);
    }
    let mine = database
        .create_template(&own, crate::times::now())
        .await
        .unwrap();
    let ids = database.template_part_ids(mine).await;
    let mut form = crate::controllers::template_form::TemplateForm::from_template(&own);
    form.queries[0].interval = "3m".to_string();
    let fields = form.to_fields();
    let mut browser = Browser::default();
    let token = browser
        .get(&server, &format!("/templates/{mine}/edit"))
        .await
        .token();
    let mut sent: Vec<(&str, &str)> = vec![("authenticity_token", token.as_str())];
    sent.extend(
        fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let page = browser
        .post(&server, &format!("/templates/{mine}"), &sent)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(database.template_part_ids(mine).await, ids);
    let stored = database.get_template(mine).await.unwrap().unwrap();
    assert_eq!(stored.template.queries[0].interval.as_deref(), Some("3m"));
}

#[tokio::test]
async fn a_copy_of_an_alert_a_newer_version_drops_becomes_a_rule_of_ones_own() {
    let database = Database::for_test().await;
    database
        .sync_templates(&shipped(&[APP]), crate::times::now())
        .await
        .unwrap();
    let gone = rule(&database, "App host gone").await;
    let wanted = AlertRuleInput {
        hold: chrono::TimeDelta::minutes(3),
        ..gone.rule.clone()
    };
    database.update_alert_rule(gone.id, &wanted).await.unwrap();
    let copy = rule(&database, "App host gone").await;

    database
        .sync_templates(&shipped(&[APP_UPGRADED]), crate::times::now())
        .await
        .unwrap();
    let kept = rule(&database, "App host gone").await;
    assert_eq!(kept.id, copy.id);
    assert_eq!(kept.rule, wanted);
    assert!(kept.template.is_none(), "an ordinary rule now");
    assert_eq!(
        database.template_upgrades().await.unwrap(),
        ["App (it no longer has App host gone, so your own copy is now a rule of yours)"]
    );
    assert!(
        database
            .delete_alert_rule(kept.id, crate::times::now())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn the_documented_examples_are_served_to_read_and_import() {
    let server = with_built_in_templates().await;
    let mut browser = Browser::default();
    let page = browser.get(&server, "/docs/templates").await;
    assert_eq!(page.status, 200);
    for (file, text) in [("postgres.hcl", POSTGRES_AS_WRITTEN), ("iis.hcl", IIS)] {
        assert!(
            page.body
                .contains(&format!(r#"href="/docs/examples/{file}""#)),
            "{file}"
        );
        let example = browser
            .get(&server, &format!("/docs/examples/{file}"))
            .await;
        assert_eq!(example.status, 200, "{file}");
        assert_eq!(example.body, text);
    }
    assert_eq!(
        browser.get(&server, "/docs/examples/nope.hcl").await.status,
        404
    );
}

/// A template whose own alert watches its own metrics, with a series for each
/// region of each database it runs for.
const SHOP: &str = r#"template "shop" {
  name     = "Shop"
  database = "postgres"
  query "orders" {
    sql    = "SELECT region, count(*) AS waiting FROM orders GROUP BY region"
    labels = ["region"]
  }
  query "tills" {
    sql = "SELECT count(*) AS tills FROM tills"
  }
  alert "backlog" {
    name             = "Orders backing up"
    warning          = "waiting > 10"
    summary          = "{{ hostname }}: {{ waiting }} orders waiting in {{ labels.region }} on {{ instance }}, with {{ tills }} tills"
    resolved_summary = "{{ hostname }}: {{ labels.region }} on {{ instance }} is down to {{ shop.waiting }}"
  }
}"#;

/// Stores what an agent running the shop's template would send, straight through
/// the metrics writer, and waits until it's stored.
async fn store_shop(server: &TestServer, host_id: &str, time: Timestamp, waiting: u64) {
    let rows = json!([
        { "labels": { "instance": "main", "region": "north" }, "waiting": waiting },
        { "labels": { "instance": "main", "region": "south" }, "waiting": 2 },
        { "labels": { "instance": "main" }, "tills": 3 },
    ]);
    let (acks, mut stored) = tokio::sync::mpsc::channel(1);
    let command = crate::store::WriterCommand::SaveAndAck {
        sample: crate::store::NewSample {
            host_id: host_id.to_string(),
            hostname: "web-1".to_string(),
            sample: Sample {
                time,
                metrics: BTreeMap::from([("template.shop".to_string(), rows)]),
            },
        },
        acks,
    };
    server.state.writer.send(command).await.unwrap();
    assert_eq!(stored.recv().await, Some(time));
}

#[tokio::test]
async fn a_templates_metrics_are_listed_charted_and_alerted_on_like_any_other() {
    let server = start_with_metrics().await;
    let host = identity();
    let _client = server.connect_approved(&host, "web-1").await;
    let database = &server.state.database;
    let template = crate::templates::load(SHOP, &json!({}), &database.catalog()).unwrap();
    let id = database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let first = crate::times::now() - TimeDelta::seconds(2);
    store_shop(&server, &host.id(), first, 40).await;

    // Listed with what the template says of it.
    let listed = json_body(
        &server
            .http("GET", "/api/v1/metrics", Some(&server.api_key))
            .await,
    );
    let waiting = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|metric| metric["name"] == "shop.waiting")
        .unwrap();
    assert_eq!(waiting["template"], "shop");
    assert_eq!(waiting["collector"], "template.shop");

    // Charted on the host's page and read through the API, a series for each region.
    let path = format!("/api/v1/hosts/{}/metrics/shop.waiting", host.id());
    let read = json_body(&server.http("GET", &path, Some(&server.api_key)).await);
    let names: Vec<&str> = read["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|series| series["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["main, north", "main, south"]);
    let mut browser = Browser::default();
    let page = browser
        .get(&server, &format!("/hosts/{}/metrics", host.id()))
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Shop waiting"), "{}", page.body);

    // Its alert is checked, and only the region over the line fires, saying what
    // the template's other metrics and labels are.
    let mut evaluator = crate::alert_evaluator::Evaluator::new(
        &server.state,
        crate::times::now() - TimeDelta::hours(1),
    );
    evaluator.evaluate(crate::times::now()).await.unwrap();
    let open = database.open_alerts().await.unwrap();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].series.as_deref(), Some("main, north"));
    assert_eq!(
        open[0].summary,
        "web-1: 40 orders waiting in north on main, with 3 tills"
    );

    let second = crate::times::now() - TimeDelta::seconds(1);
    store_shop(&server, &host.id(), second, 4).await;
    evaluator.evaluate(crate::times::now()).await.unwrap();
    assert!(database.open_alerts().await.unwrap().is_empty());
    let resolved = database.resolved_alerts(10).await.unwrap();
    assert_eq!(
        resolved[0].resolved_summary.as_deref(),
        Some("web-1: north on main is down to 4")
    );

    // Turned off, its metrics go from what's read straight away, and come back.
    database
        .set_template_enabled(id, false, crate::times::now())
        .await
        .unwrap();
    assert!(database.catalog().find("shop.waiting").is_none());
    let read = server.http("GET", &path, Some(&server.api_key)).await;
    assert!(read.starts_with("HTTP/1.1 404"), "{read}");
    database
        .set_template_enabled(id, true, crate::times::now())
        .await
        .unwrap();
    assert!(database.catalog().find("shop.waiting").is_some());
}

#[tokio::test]
async fn a_template_alert_with_no_samples_yet_does_not_fire() {
    let server = start_with_metrics().await;
    let host = identity();
    let _client = server.connect_approved(&host, "web-1").await;
    let database = &server.state.database;
    let template = crate::templates::load(SHOP, &json!({}), &database.catalog()).unwrap();
    database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let mut evaluator = crate::alert_evaluator::Evaluator::new(
        &server.state,
        crate::times::now() - TimeDelta::hours(1),
    );
    evaluator.evaluate(crate::times::now()).await.unwrap();
    assert!(database.open_alerts().await.unwrap().is_empty());
}

/// A template whose alert fires on every host it's for that's online.
const HERE: &str = r#"
template "here" {
  name       = "Here"
  applies_to = "facts.custom.role == 'web'"
  alert "here" {
    name     = "Here"
    critical = "online"
  }
}
"#;

#[tokio::test]
async fn a_template_is_for_the_hosts_given_it_and_those_it_picks_and_its_alerts_too() {
    let server = start_with_metrics().await;
    let (a, b) = (identity(), identity());
    let _a = server.connect_approved(&a, "web-1").await;
    let _b = server.connect_approved(&b, "db-1").await;
    let database = &server.state.database;
    database
        .sync_templates(&shipped(&[HERE]), crate::times::now())
        .await
        .unwrap();
    let id = template_id(database, "here").await;
    let mut evaluator = crate::alert_evaluator::Evaluator::new(
        &server.state,
        crate::times::now() - TimeDelta::hours(1),
    );
    let firing_on = |open: Vec<crate::alerting::Alert>| {
        let mut hosts: Vec<String> = open.into_iter().map(|alert| alert.host_id).collect();
        hosts.sort();
        hosts
    };

    // As it comes, it picks hosts whose role is web, which neither has.
    evaluator.evaluate(crate::times::now()).await.unwrap();
    assert!(database.open_alerts().await.unwrap().is_empty());

    // Given b by hand, it's for b as well as those it picks.
    let path = format!("/api/v1/templates/{id}/hosts");
    let given_b = json!({ "applies_to": "facts.custom.role == 'web'", "host_ids": [b.id()] });
    assert_eq!(api(&server, "PUT", &path, &given_b).await.0, 204);
    let (_, shown) = api(
        &server,
        "GET",
        &format!("/api/v1/templates/{id}"),
        &json!(null),
    )
    .await;
    assert_eq!(shown["host_ids"], json!([b.id()]));
    // The same condition as it comes isn't a choice.
    assert_eq!(shown["applies_to_chosen"], false);
    evaluator.evaluate(crate::times::now()).await.unwrap();
    assert_eq!(firing_on(database.open_alerts().await.unwrap()), [b.id()]);

    // Every host, chosen in place of the hosts it picks, lasts through an upgrade.
    let everywhere = json!({ "applies_to": null, "host_ids": [] });
    assert_eq!(api(&server, "PUT", &path, &everywhere).await.0, 204);
    database
        .sync_templates(
            &shipped(&[&HERE.replace("\"online\"", "\"online || false\"")]),
            crate::times::now(),
        )
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(stored.applies_to_chosen);
    assert_eq!(stored.applies_to, None);
    evaluator.evaluate(crate::times::now()).await.unwrap();
    let mut both = vec![a.id(), b.id()];
    both.sort();
    assert_eq!(firing_on(database.open_alerts().await.unwrap()), both);

    // With no condition, hosts given it by hand are the only ones, as with a
    // template of one's own.
    let only_a = json!({ "applies_to": null, "host_ids": [a.id()] });
    assert_eq!(api(&server, "PUT", &path, &only_a).await.0, 204);
    evaluator.evaluate(crate::times::now()).await.unwrap();
    assert_eq!(firing_on(database.open_alerts().await.unwrap()), [a.id()]);

    // A condition has to be CEL, and a host has to be there.
    let broken = json!({ "applies_to": "facts.custom.role ==" });
    let (status, body) = api(&server, "PUT", &path, &broken).await;
    assert_eq!(status, 422);
    assert!(
        body["error"].as_str().unwrap().contains("isn't CEL"),
        "{body}"
    );
    let nowhere = json!({ "host_ids": ["nowhere"] });
    assert_eq!(api(&server, "PUT", &path, &nowhere).await.0, 422);

    // The page shows and saves the same.
    let mut browser = Browser::default();
    let page = browser.get(&server, &format!("/templates/{id}")).await;
    assert!(page.body.contains("Save hosts"), "{}", page.body);
    assert!(page.body.contains("db-1"), "{}", page.body);
    let token = page.token();
    // A mistake is shown on the page, with what was typed.
    let wrong = [
        ("authenticity_token", token.as_str()),
        ("applies_to", "facts.custom.role =="),
    ];
    let refused = browser
        .post(&server, &format!("/templates/{id}/hosts"), &wrong)
        .await;
    assert_eq!(refused.status, 422);
    assert!(refused.body.contains("isn&#39;t CEL"), "{}", refused.body);
    assert!(
        refused.body.contains("facts.custom.role =="),
        "{}",
        refused.body
    );
    let host_field = format!("host.{}", a.id());
    let form = [
        ("authenticity_token", token.as_str()),
        ("applies_to", "trusted.host_id == 'nowhere'"),
        (host_field.as_str(), "on"),
    ];
    let saved = browser
        .post(&server, &format!("/templates/{id}/hosts"), &form)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(stored.host_ids, [a.id()]);
    assert_eq!(
        stored.applies_to.as_deref(),
        Some("trusted.host_id == 'nowhere'")
    );
}

#[tokio::test]
async fn an_agent_is_sent_what_its_database_templates_read_and_again_when_they_change() {
    let server = start().await;
    let host = identity();
    let mut client = server.connect_approved(&host, "db-1").await;
    TestServer::next_config(&mut client).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "agent": { "databases": { "orders": "postgres", "cache": "mysql" } } }),
    };
    send(&mut client, &facts).await;
    server.wait_for_facts(&host.id(), 1).await;

    // A template for PostgreSQL, whose discovery runs for orders straight away.
    let database = &server.state.database;
    let template = crate::templates::load(&POSTGRES, &json!({}), &database.catalog()).unwrap();
    let id = database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.templates.len(), 1, "{config:?}");
    let work = &config.templates[0];
    assert_eq!(
        (work.template.as_str(), work.database.as_deref()),
        ("pg", Some("orders"))
    );
    let discover: Vec<&str> = work.discover.iter().map(|d| d.key.as_str()).collect();
    assert_eq!(discover, ["server", "role"]);
    // Its queries wait for what discovery finds, as it's for version 10 on.
    assert!(work.queries.is_empty(), "{work:?}");

    // Given to another host only, this one is sent nothing.
    let other = identity();
    let _other = server.connect_approved(&other, "db-2").await;
    database
        .set_template_hosts(
            id,
            None,
            &std::collections::BTreeSet::from([other.id()]),
            crate::times::now(),
        )
        .await
        .unwrap();
    let (_, config) = TestServer::next_config(&mut client).await;
    assert!(config.templates.is_empty(), "{config:?}");

    // Config rules can't set it.
    let rule: crate::models::RuleInput = serde_json::from_value(json!({
        "name": "Sneaky",
        "priority": 1,
        "settings": { "templates": [{ "template": "pg", "database": "orders" }] },
    }))
    .unwrap();
    let error = crate::rule_engine::check_rule(&rule).unwrap_err();
    assert!(format!("{error:#}").contains("templates"), "{error:#}");
}

/// A template whose alert is only for replicas, by what discovery finds.
const STOCK: &str = r#"template "stock" {
  name     = "Stock"
  database = "postgres"
  discover "role" {
    interval = "10s"
    sql      = "SELECT CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'primary' END AS role"
  }
  query "replicas" {
    when = "role == 'replica'"
    sql  = "SELECT 1 AS behind"
  }
  query "orders" {
    sql     = "SELECT count(*) AS waiting FROM orders"
    metrics = {
      waiting = { description = "Orders waiting" }
      doubled = { value = "waiting * 2" }
    }
  }
  alert "backlog" {
    name    = "Replica backlog"
    when    = "role == 'replica'"
    warning = "waiting > 10"
  }
}"#;

#[tokio::test]
async fn what_discovery_finds_is_kept_and_picks_queries_and_alerts() {
    let server = start_with_metrics().await;
    let host = identity();
    let mut client = server.connect_approved(&host, "db-1").await;
    TestServer::next_config(&mut client).await;
    let facts = AgentMessage::Facts {
        facts: json!({ "agent": { "databases": { "a": "postgres", "b": "postgres" } } }),
    };
    send(&mut client, &facts).await;
    server.wait_for_facts(&host.id(), 1).await;
    let database = &server.state.database;
    let template = crate::templates::load(STOCK, &json!({}), &database.catalog()).unwrap();
    database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    // Before discovery, each database reads only what needs nothing found.
    let (_, config) = TestServer::next_config(&mut client).await;
    let queries = |config: &AgentConfig, database: &str| -> Vec<String> {
        config
            .templates
            .iter()
            .find(|work| work.database.as_deref() == Some(database))
            .unwrap()
            .queries
            .iter()
            .map(|query| query.key.clone())
            .collect()
    };
    assert_eq!(queries(&config, "a"), ["orders"]);

    // The agent sends what it found with a sample, with the rows it read.
    let found = |role: &str, database: &str| json!({ "template": "stock", "database": database, "values": { "role": role } });
    let rows = json!([
        { "labels": { "instance": "a" }, "_query": "orders", "waiting": 40 },
        { "labels": { "instance": "b" }, "_query": "orders", "waiting": 40 },
    ]);
    let time = crate::times::now() - TimeDelta::seconds(1);
    let sample = AgentMessage::Sample(Sample {
        time,
        metrics: BTreeMap::from([
            ("template.stock".to_string(), rows),
            (
                "discovered".to_string(),
                json!([found("replica", "a"), found("primary", "b")]),
            ),
        ]),
    });
    send(&mut client, &sample).await;

    // What's sent changes with it: a replica reads what only replicas do.
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(queries(&config, "a"), ["replicas", "orders"]);
    assert_eq!(queries(&config, "b"), ["orders"]);
    let kept = database.discoveries(&host.id()).await.unwrap();
    assert_eq!(kept.len(), 2);
    assert!(kept.values().any(|values| values["role"] == "replica"));

    // The alert is only for the replica, though both are over the line.
    let mut evaluator = crate::alert_evaluator::Evaluator::new(
        &server.state,
        crate::times::now() - TimeDelta::hours(1),
    );
    // The sample is stored apart from what discovery found, so it may come after.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let open = loop {
        evaluator.evaluate(crate::times::now()).await.unwrap();
        let open = database.open_alerts().await.unwrap();
        if !open.is_empty() || std::time::Instant::now() > deadline {
            break open;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].series.as_deref(), Some("a"));
    // Trying it on the last day picks the same: the replica's series, not both.
    let backlog = rule(database, "Replica backlog").await;
    let (_, shown) = api(
        &server,
        "GET",
        &format!("/api/v1/alert-rules/{}", backlog.id),
        &Value::Null,
    )
    .await;
    let path = format!("/api/v1/alert-rules/{}/replay", backlog.id);
    let (status, replayed) = api(&server, "POST", &path, &shown).await;
    assert_eq!(status, 200, "{replayed}");
    assert_eq!(replayed["warned"], 1, "{replayed}");
    assert_eq!(replayed["alerted"][0]["name"], "db-1");
    // Given to another host only, it isn't tried on this one.
    let stock = template_id(database, "stock").await;
    let other = identity();
    let _other = server.connect_approved(&other, "db-2").await;
    database
        .set_template_hosts(
            stock,
            None,
            &std::collections::BTreeSet::from([other.id()]),
            crate::times::now(),
        )
        .await
        .unwrap();
    let (_, replayed) = api(&server, "POST", &path, &shown).await;
    assert_eq!(replayed["warned"], 0, "{replayed}");
    database
        .set_template_hosts(
            stock,
            None,
            &std::collections::BTreeSet::new(),
            crate::times::now(),
        )
        .await
        .unwrap();
    TestServer::next_config(&mut client).await;
    // Not for the host for a while, what discovery found there was forgotten, and
    // the agent finds it again as it's sent the template again.
    assert!(database.discoveries(&host.id()).await.unwrap().is_empty());
    let found_again = AgentMessage::Sample(Sample {
        time: time + TimeDelta::milliseconds(1),
        metrics: BTreeMap::from([(
            "discovered".to_string(),
            json!([found("replica", "a"), found("primary", "b")]),
        )]),
    });
    send(&mut client, &found_again).await;
    TestServer::next_config(&mut client).await;
    TestServer::next_config(&mut client).await;

    // What was found isn't stored as metrics.
    assert!(database.catalog().find("discovered").is_none());
    // What the template works out with CEL is worked out as the sample arrives.
    let path = format!("/api/v1/hosts/{}/metrics/stock.doubled", host.id());
    let read = json_body(&server.http("GET", &path, Some(&server.api_key)).await);
    let names: Vec<&str> = read["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|series| series["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["a", "b"], "{read}");

    // An older sample, sent late, doesn't undo what's newer.
    let old: Vec<maxnines_protocol::templates::work::Discovered> =
        serde_json::from_value(json!([found("primary", "a")])).unwrap();
    let late = time - TimeDelta::minutes(5);
    assert!(
        !database
            .save_discovered(&host.id(), &old, late)
            .await
            .unwrap()
    );
    let kept = database.discoveries(&host.id()).await.unwrap();
    assert!(kept.values().any(|values| values["role"] == "replica"));
    // A newer one does, and the alert goes.
    let newer = AgentMessage::Sample(Sample {
        time: crate::times::now(),
        metrics: BTreeMap::from([("discovered".to_string(), json!([found("primary", "a")]))]),
    });
    send(&mut client, &newer).await;
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(queries(&config, "a"), ["orders"]);
    evaluator.evaluate(crate::times::now()).await.unwrap();
    assert!(database.open_alerts().await.unwrap().is_empty());

    // A database the agent no longer has is forgotten, with what it found.
    let fewer = AgentMessage::Facts {
        facts: json!({ "agent": { "databases": { "a": "postgres" } } }),
    };
    send(&mut client, &fewer).await;
    let (_, config) = TestServer::next_config(&mut client).await;
    assert_eq!(config.templates.len(), 1);
    let kept = database.discoveries(&host.id()).await.unwrap();
    let databases: Vec<&str> = kept.keys().map(|(_, database)| database.as_str()).collect();
    assert_eq!(databases, ["a"]);
}
