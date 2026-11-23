//! A template's discover blocks, queries and counters blocks changed or turned off on
//! their own: copies of a built-in or imported template's, which upgrades leave
//! alone, and people's own templates changed in place.

use super::*;
use crate::models::{Database, Part, PartKind};
use crate::templates::Refused;
use maxnines_protocol::templates::{Query, parse};

const SHOP: &str = r#"template "shop" {
  name     = "Shop"
  database = "postgres"
  discover "server" {
    sql = "SELECT version() AS version"
  }
  query "orders" {
    sql    = "SELECT region, count(*) AS waiting FROM orders GROUP BY region"
    labels = ["region"]
  }
  query "tills" {
    sql = "SELECT count(*) AS tills FROM tills"
  }
  alert "backlog" {
    name    = "Orders backing up"
    warning = "waiting > 10"
  }
}"#;

fn query(template: &maxnines_protocol::templates::Template, key: &str) -> Query {
    template
        .queries
        .iter()
        .find(|query| query.key == key)
        .unwrap_or_else(|| panic!("no query {key}"))
        .clone()
}

async fn imported(database: &Database, source: &str) -> i64 {
    let (id, _) = database
        .import_template(&parse(source).unwrap(), crate::times::now())
        .await
        .unwrap();
    id
}

/// The query as the server has agents run it.
fn running(database: &Database, id: i64, key: &str) -> Query {
    let templates = database.running_templates();
    query(templates.get(id).unwrap().template(), key)
}

#[tokio::test]
async fn a_copy_of_an_imported_templates_query_runs_in_its_place_until_it_is_reset() {
    let database = Database::for_test().await;
    let id = imported(&database, SHOP).await;
    let mut tills = query(
        &database.template_as_run(id).await.unwrap().unwrap(),
        "tills",
    );
    tills.sql = "SELECT count(*) AS tills FROM tills WHERE open".to_string();
    tills.interval = Some("1m".to_string());
    let now = crate::times::now();
    assert!(
        database
            .save_template_part(id, Part::Query(tills.clone()), now)
            .await
            .unwrap()
    );

    // The copy runs; the template as it was written stays as it is.
    assert_eq!(running(&database, id, "tills"), tills);
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(
        query(&stored.template, "tills").sql,
        "SELECT count(*) AS tills FROM tills"
    );
    assert_eq!(stored.choices.len(), 1);
    assert!(stored.choices[0].copied);
    assert_eq!(stored.copies, [Part::Query(tills.clone())]);

    // Changing the copy again changes it; saving what the template says deletes it.
    tills.interval = Some("2m".to_string());
    database
        .save_template_part(id, Part::Query(tills.clone()), now)
        .await
        .unwrap();
    assert_eq!(
        running(&database, id, "tills").interval.as_deref(),
        Some("2m")
    );
    let own = query(&stored.template, "tills");
    database
        .save_template_part(id, Part::Query(own.clone()), now)
        .await
        .unwrap();
    assert_eq!(running(&database, id, "tills"), own);
    assert!(
        database
            .get_template(id)
            .await
            .unwrap()
            .unwrap()
            .choices
            .is_empty()
    );

    // Turning it off is a choice beside it, kept for a copy made after.
    database
        .set_template_part_enabled(id, PartKind::Query, "tills", false, now)
        .await
        .unwrap();
    assert!(!running(&database, id, "tills").enabled);
    database
        .save_template_part(id, Part::Query(tills.clone()), now)
        .await
        .unwrap();
    let run = running(&database, id, "tills");
    assert!(!run.enabled, "still off");
    assert_eq!(run.interval.as_deref(), Some("2m"));

    // Resetting forgets both.
    assert!(
        database
            .reset_template_part(id, PartKind::Query, "tills", now)
            .await
            .unwrap()
    );
    assert_eq!(running(&database, id, "tills"), own);
    assert!(
        !database
            .reset_template_part(id, PartKind::Query, "tills", now)
            .await
            .unwrap(),
        "nothing left to reset"
    );
    // A discover block is changed, but never turned off.
    let error = database
        .set_template_part_enabled(id, PartKind::Discover, "server", false, now)
        .await
        .unwrap_err();
    assert!(error.is::<Refused>());
    assert!(
        !database
            .save_template_part(
                id,
                Part::Query(Query {
                    key: "nope".to_string(),
                    ..own
                }),
                now
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_newer_version_leaves_a_copy_and_says_it_changed_what_it_copies() {
    let database = Database::for_test().await;
    let id = imported(&database, SHOP).await;
    let as_run = database.template_as_run(id).await.unwrap().unwrap();
    let mut tills = query(&as_run, "tills");
    tills.sql = "SELECT count(*) AS tills FROM tills WHERE open".to_string();
    let mut discover = as_run.discover[0].clone();
    discover.interval = Some("10m".to_string());
    let now = crate::times::now();
    for part in [Part::Query(tills.clone()), Part::Discover(discover.clone())] {
        database.save_template_part(id, part, now).await.unwrap();
    }
    assert_eq!(
        database
            .template_as_run(id)
            .await
            .unwrap()
            .unwrap()
            .discover[0],
        discover
    );

    // The newer version changes both originals.
    let newer = SHOP
        .replace("FROM tills\"", "FROM tills WHERE NOT closed\"")
        .replace(
            "SELECT version() AS version",
            "SELECT current_setting('server_version') AS version",
        );
    imported(&database, &newer).await;
    assert_eq!(running(&database, id, "tills"), tills, "the copy is left");
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(
        stored
            .choices
            .iter()
            .all(|choice| choice.original_changed_at.is_some())
    );
    assert_eq!(
        database.template_upgrades().await.unwrap(),
        [
            r#"Shop (its version of discover "server", query "tills" changed, which you have your own of)"#
        ]
    );

    // One that drops the query takes the copy with it, and says so.
    let dropped = newer.replace(
        "  query \"tills\" {\n    sql = \"SELECT count(*) AS tills FROM tills WHERE NOT closed\"\n  }\n",
        "",
    );
    assert_ne!(dropped, newer);
    imported(&database, &dropped).await;
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(
        stored
            .choices
            .iter()
            .all(|choice| choice.kind == PartKind::Discover)
    );
    let notices = database.template_upgrades().await.unwrap();
    assert!(
        notices[0].contains(r#"it no longer has query "tills", so your own copy went with it"#),
        "{notices:?}"
    );
}

#[tokio::test]
async fn a_part_of_ones_own_template_is_changed_in_it() {
    let database = Database::for_test().await;
    let template =
        crate::templates::load(SHOP, &json!({}), &crate::catalog::Catalog::built_in()).unwrap();
    let now = crate::times::now();
    let id = database.create_template(&template, now).await.unwrap();
    let mut tills = query(&template, "tills");
    tills.sql = "SELECT count(*) AS tills FROM tills WHERE open".to_string();
    database
        .save_template_part(id, Part::Query(tills.clone()), now)
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert_eq!(query(&stored.template, "tills"), tills);
    assert!(stored.choices.is_empty(), "no copies of one's own");

    database
        .set_template_part_enabled(id, PartKind::Query, "tills", false, now)
        .await
        .unwrap();
    let stored = database.get_template(id).await.unwrap().unwrap();
    assert!(!query(&stored.template, "tills").enabled);
    assert!(
        !database
            .reset_template_part(id, PartKind::Query, "tills", now)
            .await
            .unwrap()
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
async fn a_part_is_changed_on_its_own_page_and_turned_off_and_reset_from_the_templates() {
    let server = start().await;
    let database = &server.state.database;
    let id = imported(database, SHOP).await;
    let mut browser = Browser::default();

    let page = browser.get(&server, &format!("/templates/{id}")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for expected in [
        "<h2>Discovery</h2>",
        "<h2>Queries</h2>",
        "SELECT count(*) AS tills FROM tills",
        &format!("/templates/{id}/queries/tills/edit"),
        &format!("/templates/{id}/queries/tills/disable"),
        &format!("/templates/{id}/discover/server/edit"),
    ] {
        assert!(page.body.contains(expected), "{expected}\n{}", page.body);
    }
    assert!(
        !page
            .body
            .contains(&format!("/templates/{id}/discover/server/disable"))
    );

    let edit = format!("/templates/{id}/queries/tills/edit");
    let form = browser.get(&server, &edit).await;
    assert_eq!(form.status, 200, "{}", form.body);
    assert!(form.has_only_our_scripts());
    assert!(
        form.body.contains("Saving makes a copy of your own"),
        "{}",
        form.body
    );
    assert!(!form.body.contains("Remove query"));
    let save = format!("/templates/{id}/queries/tills");

    // What's wrong is said beside the field.
    let page = browser
        .submit(
            &server,
            &edit,
            &save,
            &[
                ("query.0.key", "tills"),
                ("query.0.sql", "DELETE FROM tills"),
            ],
        )
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(page.body.contains("field-error"), "{}", page.body);

    // A column an alert of the template uses can't go, and says which alert.
    let page = browser
        .submit(
            &server,
            &format!("/templates/{id}/queries/orders/edit"),
            &format!("/templates/{id}/queries/orders"),
            &[
                ("query.0.key", "orders"),
                ("query.0.sql", "SELECT count(*) AS queued FROM orders"),
            ],
        )
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(
        page.body.contains("alert &quot;backlog&quot;"),
        "{}",
        page.body
    );

    let page = browser
        .submit(
            &server,
            &edit,
            &save,
            &[
                ("query.0.key", "anything"),
                (
                    "query.0.sql",
                    "SELECT count(*) AS tills FROM tills WHERE open",
                ),
                ("query.0.interval", "1m"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let run = running(database, id, "tills");
    assert_eq!(run.key, "tills", "the key is the address's");
    assert_eq!(run.interval.as_deref(), Some("1m"));
    let page = browser.get(&server, &format!("/templates/{id}")).await;
    assert!(page.body.contains("Your own copy."), "{}", page.body);
    assert!(
        page.body
            .contains(&format!("/templates/{id}/queries/tills/reset"))
    );

    let page = browser
        .submit(
            &server,
            &format!("/templates/{id}"),
            &format!("/templates/{id}/queries/tills/disable"),
            &[],
        )
        .await;
    assert_eq!(page.status, 303);
    assert!(!running(database, id, "tills").enabled);
    let page = browser
        .submit(
            &server,
            &format!("/templates/{id}"),
            &format!("/templates/{id}/queries/tills/reset"),
            &[],
        )
        .await;
    assert_eq!(page.status, 303);
    let run = running(database, id, "tills");
    assert!(run.enabled && run.interval.is_none());

    // The same through the API.
    let path = format!("/api/v1/templates/{id}/queries/tills");
    let (status, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 200, "{shown}");
    assert_eq!(shown["sql"], "SELECT count(*) AS tills FROM tills");
    assert_eq!(shown["copied"], false);
    let mut changed = shown.clone();
    changed["sql"] = json!("SELECT count(*) AS tills FROM tills WHERE open");
    let (status, body) = api(&server, "PUT", &path, &changed).await;
    assert_eq!(status, 204, "{body}");
    let (_, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(shown["copied"], true);
    assert_eq!(
        shown["template_part"]["sql"],
        "SELECT count(*) AS tills FROM tills"
    );
    changed["sql"] = json!("DROP TABLE tills");
    let (status, body) = api(&server, "PUT", &path, &changed).await;
    assert_eq!(status, 422, "{body}");
    let (status, _) = api(&server, "POST", &format!("{path}/disable"), &Value::Null).await;
    assert_eq!(status, 204);
    let (_, template) = api(
        &server,
        "GET",
        &format!("/api/v1/templates/{id}"),
        &Value::Null,
    )
    .await;
    assert_eq!(
        template["choices"][0]["enabled_choice"], false,
        "{template}"
    );
    assert_eq!(template["copies"][0]["kind"], "query", "{template}");
    let (status, _) = api(&server, "DELETE", &path, &Value::Null).await;
    assert_eq!(status, 204);
    let (status, _) = api(&server, "DELETE", &path, &Value::Null).await;
    assert_eq!(status, 404, "nothing left to reset");
    let discover = format!("/api/v1/templates/{id}/discover/server/disable");
    let (status, _) = api(&server, "POST", &discover, &Value::Null).await;
    assert_eq!(status, 404, "a discover block has no switch");
}
