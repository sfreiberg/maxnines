//! Where templates run, what they read there, and what's going wrong reading them,
//! as agents say it, on the templates' pages, hosts' pages and the API.

use super::*;

const STOCK: &str = r#"template "stock" {
  name     = "Stock"
  database = "postgres"
  discover "server" {
    sql = "SELECT current_setting('server_version') AS version"
  }
  query "orders" {
    sql = "SELECT count(*) AS waiting FROM orders"
  }
}"#;

/// Waits until what's kept of what's going wrong on `host` is as `wanted` says.
async fn wait_for_errors(
    database: &crate::models::Database,
    host: &str,
    wanted: impl Fn(&[(String, String)]) -> bool,
) -> Vec<(String, String)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let kept: Vec<(String, String)> = database
            .template_errors(Some(host), None)
            .await
            .unwrap()
            .into_iter()
            .map(|error| (error.part, error.message))
            .collect();
        if wanted(&kept) {
            return kept;
        }
        assert!(std::time::Instant::now() < deadline, "{kept:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn errors_sample(time: Timestamp, said: Value) -> AgentMessage {
    AgentMessage::Sample(Sample {
        time,
        metrics: BTreeMap::from([("template_errors".to_string(), said)]),
    })
}

#[tokio::test]
async fn what_goes_wrong_is_kept_shown_where_each_template_runs_and_forgotten() {
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
    let id = database
        .create_template(&template, crate::times::now())
        .await
        .unwrap();
    TestServer::next_config(&mut client).await;

    let time = crate::times::now() - TimeDelta::seconds(10);
    let broken = json!([{
        "template": "stock",
        "database": "a",
        "errors": { "query orders": "relation \"orders\" does not exist" },
    }]);
    send(&mut client, &errors_sample(time, broken)).await;
    wait_for_errors(database, &host.id(), |kept| kept.len() == 1).await;
    let since = database.template_errors(None, Some(id)).await.unwrap()[0].since;

    // Where it runs, on the template's page and the host's, and through the API.
    let mut browser = Browser::default();
    let page = browser.get(&server, &format!("/templates/{id}")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for expected in [
        "Where it runs",
        "db-1",
        "<code>a</code>",
        "<code>b</code>",
        "query orders",
        "relation &quot;orders&quot; does not exist",
        "discover server",
    ] {
        assert!(page.body.contains(expected), "{expected}\n{}", page.body);
    }
    // The database going wrong comes first.
    let a = page.body.find("<code>a</code>").unwrap();
    let b = page.body.find("<code>b</code>").unwrap();
    assert!(a < b);
    let page = browser.get(&server, &format!("/hosts/{}", host.id())).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("<h2>Templates</h2>"), "{}", page.body);
    assert!(page.body.contains(&format!(r#"href="/templates/{id}""#)));
    assert!(page.body.contains("does not exist"));
    assert!(page.has_only_our_scripts());

    let path = format!("/api/v1/templates/{id}/runs");
    let runs = json_body(&server.http("GET", &path, Some(&server.api_key)).await);
    assert_eq!(runs.as_array().unwrap().len(), 2, "{runs}");
    assert_eq!(runs[0]["database"], "a");
    assert_eq!(runs[0]["queries"], json!(["orders"]));
    assert_eq!(runs[0]["errors"][0]["part"], "query orders");
    let path = format!("/api/v1/hosts/{}/templates", host.id());
    let on_host = json_body(&server.http("GET", &path, Some(&server.api_key)).await);
    assert_eq!(on_host, runs);

    // The same said again keeps when it began; something else is new.
    let same = json!([{
        "template": "stock",
        "database": "a",
        "errors": {
            "query orders": "relation \"orders\" does not exist",
            "discover server": "permission denied",
        },
    }]);
    send(
        &mut client,
        &errors_sample(time + TimeDelta::seconds(2), same),
    )
    .await;
    let kept = wait_for_errors(database, &host.id(), |kept| kept.len() == 2).await;
    assert!(kept.contains(&(
        "discover server".to_string(),
        "permission denied".to_string()
    )));
    let errors = database.template_errors(None, Some(id)).await.unwrap();
    let orders = errors.iter().find(|e| e.part == "query orders").unwrap();
    assert_eq!(orders.since, since);

    // A sample kept while the agent was away, older than what's kept, changes
    // nothing. Jobs are done in order, so once the next is in, it was skipped.
    let old = json!([{ "template": "stock", "database": "a", "errors": {} }]);
    send(
        &mut client,
        &errors_sample(time + TimeDelta::seconds(1), old),
    )
    .await;
    let refused =
        json!([{ "template": "stock", "database": "b", "errors": { "connecting": "refused" } }]);
    send(
        &mut client,
        &errors_sample(time + TimeDelta::seconds(3), refused),
    )
    .await;
    wait_for_errors(database, &host.id(), |kept| kept.len() == 3).await;

    // A newer one saying all's well clears it.
    let clear = json!([{ "template": "stock", "database": "a", "errors": {} }]);
    send(
        &mut client,
        &errors_sample(time + TimeDelta::seconds(4), clear),
    )
    .await;
    let kept = wait_for_errors(database, &host.id(), |kept| kept.len() == 1).await;
    assert_eq!(kept, [("connecting".to_string(), "refused".to_string())]);

    // What's said of a database the agent isn't sent is let go, and what's said of
    // one it no longer reads is forgotten.
    let other = json!([{ "template": "stock", "database": "c", "errors": { "connecting": "no" } }]);
    send(
        &mut client,
        &errors_sample(time + TimeDelta::seconds(5), other),
    )
    .await;
    let again = json!([{ "template": "stock", "database": "b", "errors": { "connecting": "refused again" } }]);
    send(
        &mut client,
        &errors_sample(time + TimeDelta::seconds(6), again),
    )
    .await;
    let kept = wait_for_errors(database, &host.id(), |kept| {
        kept.iter().any(|(_, message)| message == "refused again")
    })
    .await;
    assert_eq!(kept.len(), 1, "{kept:?}");
    let fewer = AgentMessage::Facts {
        facts: json!({ "agent": { "databases": { "a": "postgres" } } }),
    };
    send(&mut client, &fewer).await;
    TestServer::next_config(&mut client).await;
    wait_for_errors(database, &host.id(), <[_]>::is_empty).await;
}
