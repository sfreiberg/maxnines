//! Hosts with no agent, which the server reads from itself.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::alert_evaluator::Evaluator;
use crate::metrics_pages::Scheduler;

/// Calls the API with the admin's key, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

async fn add_host(server: &TestServer, hostname: &str) -> String {
    let body = json!({ "hostname": hostname });
    let (status, host) = api(server, "POST", "/api/v1/hosts", &body).await;
    assert_eq!(status, 201, "{host}");
    host["id"].as_str().unwrap().to_string()
}

async fn add_page(server: &TestServer, host_id: &str, page: &Value) -> i64 {
    let path = format!("/api/v1/hosts/{host_id}/metrics-pages");
    let (status, added) = api(server, "POST", &path, page).await;
    assert_eq!(status, 201, "{added}");
    added["id"].as_i64().unwrap()
}

const PAGE: &str =
    "# TYPE queue_depth gauge\nqueue_depth 7.5\n# TYPE jobs_total counter\njobs_total 100\n";

/// A metrics page that answers until it's told to stop, and only to requests that
/// carry `header`, when there is one.
struct Served {
    address: String,
    answering: Arc<AtomicBool>,
}

async fn serve(header: Option<&'static str>) -> Served {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let answering = Arc::new(AtomicBool::new(true));
    let up = answering.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            // The whole request goes first, so closing never loses the answer.
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(size) => request.extend_from_slice(&buffer[..size]),
                }
            }
            let request = String::from_utf8_lossy(&request).to_lowercase();
            let allowed = header.is_none_or(|header| request.contains(&header.to_lowercase()));
            let (status, body) = match (up.load(Ordering::Relaxed), allowed) {
                (false, _) => ("503 Service Unavailable", ""),
                (true, false) => ("401 Unauthorized", ""),
                (true, true) => ("200 OK", PAGE),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    Served { address, answering }
}

fn scheduler(server: &TestServer) -> Scheduler {
    let state = &server.state;
    Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.page_reads.clone(),
    )
}

/// Reads everything that's due at `now_ms`, and waits for it to be done.
async fn read_due(scheduler: &mut Scheduler, now_ms: i64) -> usize {
    let started = scheduler.start_due(now_ms).await.unwrap();
    let count = started.len();
    for read in started {
        read.await.unwrap();
    }
    count
}

#[tokio::test]
async fn a_host_without_an_agent_is_added_renamed_and_deleted() {
    let server = start().await;

    for bad in ["", "   ", &"x".repeat(256)] {
        let body = json!({ "hostname": bad });
        let (status, _) = api(&server, "POST", "/api/v1/hosts", &body).await;
        assert_eq!(status, 422, "{bad:?}");
    }
    let id = add_host(&server, "  orders-db ").await;
    assert_eq!(id.len(), 32);

    let (_, hosts) = api(&server, "GET", "/api/v1/hosts", &Value::Null).await;
    let listed = &hosts.as_array().unwrap()[0];
    assert_eq!(listed["hostname"], "orders-db");
    assert_eq!(listed["kind"], "agentless");
    assert_eq!(listed["state"], "approved");
    assert_eq!(listed["decided_by"], "test@example.com");
    // Nothing is read for it yet, so it's neither on nor off.
    assert_eq!(listed["online"], false);

    let path = format!("/api/v1/hosts/{id}");
    let renamed = json!({ "hostname": "orders-db-eu" });
    let (status, host) = api(&server, "PUT", &path, &renamed).await;
    assert_eq!((status, &host["hostname"]), (200, &json!("orders-db-eu")));
    // It's the same after a restart, as it's what the database has.
    let saved = server.state.database.load_hosts().await.unwrap();
    assert!(saved.iter().any(|host| host.hostname == "orders-db-eu"));

    // A host with an agent is called what its agent says.
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let agent_path = format!("/api/v1/hosts/{}", agent.id());
    let (status, _) = api(&server, "PUT", &agent_path, &renamed).await;
    assert_eq!(status, 409);
    let (status, _) = api(&server, "PUT", "/api/v1/hosts/nobody", &renamed).await;
    assert_eq!(status, 404);

    // There's no agent to revoke first.
    let page = json!({ "url": "http://db.example.com:9187/metrics", "interval_secs": 60 });
    let page_id = add_page(&server, &id, &page).await;
    let (status, _) = api(&server, "DELETE", &path, &Value::Null).await;
    assert_eq!(status, 204);
    let (status, _) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(status, 404);
    let page_path = format!("/api/v1/metrics-pages/{page_id}");
    let (status, _) = api(&server, "GET", &page_path, &Value::Null).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn a_pages_password_can_be_set_but_never_read_back() {
    let server = start().await;
    let id = add_host(&server, "orders-db").await;
    let url = "https://db.example.com:9187/metrics";
    let typed = json!({
        "url": url, "interval_secs": 60, "names": ["pg_*"],
        "username": "metrics", "password": "s3cret"
    });
    let page_id = add_page(&server, &id, &typed).await;

    let page_path = format!("/api/v1/metrics-pages/{page_id}");
    let (_, page) = api(&server, "GET", &page_path, &Value::Null).await;
    assert_eq!(
        page,
        json!({
            "id": page_id, "host_id": id, "name": "db.example.com:9187", "url": url,
            "names": ["pg_*"], "interval_secs": 60, "enabled": true,
            "username": "metrics", "has_password": true, "password_env": null
        })
    );
    let list_path = format!("/api/v1/hosts/{id}/metrics-pages");
    let (_, pages) = api(&server, "GET", &list_path, &Value::Null).await;
    assert!(!pages.to_string().contains("s3cret"), "{pages}");
    // Nor is it in what the audit log kept of the change.
    let (_, log) = api(&server, "GET", "/api/v1/audit-log", &Value::Null).await;
    assert!(log.to_string().contains("metrics_page"), "{log}");
    assert!(!log.to_string().contains("s3cret"), "{log}");

    // A change that gives no password keeps the one saved.
    let slower = json!({ "url": url, "interval_secs": 300, "username": "metrics" });
    let (status, _) = api(&server, "PUT", &page_path, &slower).await;
    assert_eq!(status, 204);
    let saved = server
        .state
        .database
        .get_metrics_page(page_id)
        .await
        .unwrap();
    let saved = saved.unwrap().input;
    assert_eq!(saved.interval_secs, 300);
    assert_eq!(saved.password.as_deref(), Some("s3cret"));

    // A variable takes its place, and only one set aside for secrets will do.
    let from_env = |variable: &str| json!({ "url": url, "interval_secs": 300, "username": "metrics", "password_env": variable });
    let (status, refused) = api(&server, "PUT", &page_path, &from_env("DATABASE_URL")).await;
    assert_eq!(status, 422);
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("MAXNINES_SECRET_"),
        "{refused}"
    );
    let variable = "MAXNINES_SECRET_ORDERS_DB";
    let (status, _) = api(&server, "PUT", &page_path, &from_env(variable)).await;
    assert_eq!(status, 204);
    let (_, page) = api(&server, "GET", &page_path, &Value::Null).await;
    assert_eq!(page["has_password"], false);
    assert_eq!(page["password_env"], variable);
}

#[tokio::test]
async fn pages_are_checked_before_they_are_saved() {
    let server = start().await;
    let id = add_host(&server, "orders-db").await;
    let path = format!("/api/v1/hosts/{id}/metrics-pages");
    let page = json!({ "url": "http://db.example.com:9187/metrics", "interval_secs": 60 });
    add_page(&server, &id, &page).await;

    for bad in [
        // Its series couldn't be told from the first one's.
        json!({ "url": "https://db.example.com:9187/metrics?x=1", "interval_secs": 60 }),
        json!({ "url": "db.example.com/metrics", "interval_secs": 60 }),
        json!({ "url": "http://a:b@db.example.com/metrics", "interval_secs": 60 }),
        json!({ "url": "http://db.example.com/metrics", "interval_secs": 5 }),
        json!({ "url": "http://db.example.com/metrics", "interval_secs": 60, "names": ["a b"] }),
        json!({ "url": "http://db.example.com/metrics", "interval_secs": 60, "username": "x" }),
        json!({ "url": "http://db.example.com/metrics", "interval_secs": 60, "password": "x" }),
    ] {
        let (status, refused) = api(&server, "POST", &path, &bad).await;
        assert_eq!(status, 422, "{bad}: {refused}");
        assert!(refused["error"].is_string(), "{refused}");
    }

    // A host with an agent has its pages read by its agent.
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;
    let agent_path = format!("/api/v1/hosts/{}/metrics-pages", agent.id());
    let (status, _) = api(&server, "POST", &agent_path, &page).await;
    assert_eq!(status, 409);
    let (status, _) = api(&server, "POST", "/api/v1/hosts/nobody/metrics-pages", &page).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn the_server_reads_a_hosts_pages_and_says_whether_it_is_there() {
    let server = start_with_metrics().await;
    let id = add_host(&server, "orders-db").await;
    // "metrics:s3cret", as basic authentication sends it.
    let served = serve(Some("authorization: Basic bWV0cmljczpzM2NyZXQ=")).await;
    let page = json!({
        "url": format!("http://{}/metrics", served.address), "interval_secs": 60,
        "username": "metrics", "password": "s3cret"
    });
    let page_id = add_page(&server, &id, &page).await;
    let mut scheduler = scheduler(&server);
    let now = now_ms();

    assert!(server.state.presence.get(&id).is_none());
    assert_eq!(read_due(&mut scheduler, now).await, 1);
    // Not due again until its interval has passed.
    assert_eq!(read_due(&mut scheduler, now + 59_000).await, 0);

    let presence = server.state.presence.get(&id).unwrap();
    assert!(presence.online);
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(
        result,
        json!({ "name": served.address, "up": 1, "dropped": 0 })
    );

    // What it read is the host's, under the page's name.
    let path = format!("/api/v1/hosts/{id}/metrics/openmetrics.value?range=1h");
    let deadline = Instant::now() + Duration::from_secs(5);
    let values = loop {
        let (_, body) = api(&server, "GET", &path, &Value::Null).await;
        if body["series"]
            .as_array()
            .is_some_and(|lines| !lines.is_empty())
        {
            break body;
        }
        assert!(Instant::now() < deadline, "nothing was saved: {body}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let name = format!("{} queue_depth", served.address);
    assert_eq!(values["series"][0]["name"], name.as_str());
    assert_eq!(values["series"][0]["points"][0]["avg"], 7.5);

    // Its only page stops answering, so the host is gone.
    served.answering.store(false, Ordering::Relaxed);
    assert_eq!(read_due(&mut scheduler, now + 60_000).await, 1);
    assert!(!server.state.presence.get(&id).unwrap().online);
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(result["up"], 0);
    assert_eq!(result["error"], "the page returned status 503");

    // A page that's turned off isn't read, and with nothing read the host is
    // neither on nor off.
    let off = json!({
        "url": format!("http://{}/metrics", served.address), "interval_secs": 60,
        "enabled": false, "username": "metrics"
    });
    let page_path = format!("/api/v1/metrics-pages/{page_id}");
    assert_eq!(api(&server, "PUT", &page_path, &off).await.0, 204);
    assert_eq!(read_due(&mut scheduler, now + 120_000).await, 0);
    assert!(server.state.presence.get(&id).is_none());
    assert_eq!(server.state.page_reads.result(page_id), None);
}

#[tokio::test]
async fn a_password_that_is_wrong_or_missing_shows_as_the_page_not_answering() {
    let server = start().await;
    let id = add_host(&server, "orders-db").await;
    let served = serve(Some("authorization: Basic bWV0cmljczpzM2NyZXQ=")).await;
    let url = format!("http://{}/metrics", served.address);
    let wrong = json!({
        "url": url, "interval_secs": 60, "username": "metrics", "password": "guess"
    });
    let page_id = add_page(&server, &id, &wrong).await;
    let mut scheduler = scheduler(&server);
    let now = now_ms();

    read_due(&mut scheduler, now).await;
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(result["error"], "the page returned status 401");

    // Nothing in the server's environment is called this.
    let unset = json!({
        "url": url, "interval_secs": 60, "username": "metrics",
        "password_env": "MAXNINES_SECRET_NEVER_SET"
    });
    let page_path = format!("/api/v1/metrics-pages/{page_id}");
    assert_eq!(api(&server, "PUT", &page_path, &unset).await.0, 204);
    read_due(&mut scheduler, now + 60_000).await;
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(
        result["error"],
        "the environment variable MAXNINES_SECRET_NEVER_SET isn't set"
    );
    assert!(!server.state.presence.get(&id).unwrap().online);
}

#[tokio::test]
async fn a_host_that_stops_answering_is_offline_and_one_with_nothing_to_read_is_not() {
    let server = start().await;
    let reading = add_host(&server, "orders-db").await;
    let idle = add_host(&server, "not-set-up-yet").await;
    let served = serve(None).await;
    let page = json!({ "url": format!("http://{}/metrics", served.address), "interval_secs": 60 });
    add_page(&server, &reading, &page).await;
    let mut scheduler = scheduler(&server);
    let state = &server.state;
    // The rule every server starts with.
    let built_in = Database::for_test().await.list_alert_rules().await.unwrap();
    let offline = built_in
        .into_iter()
        .find(|rule| rule.rule.kind == crate::alerting::RuleKind::Offline)
        .unwrap();
    state
        .database
        .create_alert_rule(&offline.rule)
        .await
        .unwrap();
    let started = now_ms();
    let mut evaluator = Evaluator::new(
        state.database.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.metrics.clone(),
        state.status.clone(),
        state.actions.clone(),
        started - 600_000,
    );

    read_due(&mut scheduler, started).await;
    evaluator.evaluate(started).await.unwrap();
    assert_eq!(state.database.open_alerts().await.unwrap(), []);

    served.answering.store(false, Ordering::Relaxed);
    read_due(&mut scheduler, started + 60_000).await;
    evaluator.evaluate(now_ms() + 61_000).await.unwrap();

    let open = state.database.open_alerts().await.unwrap();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].host_id, reading);
    assert_ne!(open[0].host_id, idle);
    assert_eq!(open[0].summary, "orders-db has been offline for 1 minute");
}

#[tokio::test]
async fn a_host_and_its_pages_are_added_from_the_hosts_page() {
    let server = start().await;
    let mut browser = Browser::default();

    let hosts = browser.get(&server, "/hosts").await;
    assert!(
        hosts.body.contains(r#"href="/hosts/new""#),
        "{}",
        hosts.body
    );

    let fields = [("hostname", "orders-db")];
    let added = browser
        .submit(&server, "/hosts/new", "/hosts", &fields)
        .await;
    assert_eq!(added.status, 303, "{}", added.body);
    let host_path = added.header("location").unwrap().to_string();
    let id = host_path.rsplit('/').next().unwrap().to_string();

    let page = browser.get(&server, &host_path).await;
    assert!(page.body.contains("No agent"), "{}", page.body);
    assert!(page.body.contains("Nothing is read for this host yet"));
    // What only an agent has isn't offered.
    assert!(!page.body.contains("Revoke"));
    assert!(!page.body.contains("Show the full config"));

    let form = format!("{host_path}/pages/new");
    let fields = [
        ("url", "https://db.example.com:9187/metrics"),
        ("interval_secs", "120"),
        ("names", "pg_*\nprocess_cpu_seconds_total\n"),
        ("enabled", "on"),
        ("username", "metrics"),
        ("password", "s3cret"),
        ("password_env", ""),
    ];
    let saved = browser
        .submit(&server, &form, &format!("{host_path}/pages"), &fields)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);

    let page = browser.get(&server, &host_path).await;
    assert!(page.body.contains("db.example.com:9187"), "{}", page.body);
    assert!(page.body.contains("Every 120 s"));
    assert!(page.body.contains("2 metric names"));
    assert!(page.body.contains("As metrics"));
    assert!(page.body.contains("Not read yet"));
    assert!(!page.body.contains("s3cret"));

    // The form to change it never has the password in it.
    let pages = server.state.database.metrics_pages_of(&id).await.unwrap();
    let edit = format!("{host_path}/pages/{}/edit", pages[0].id);
    let form = browser.get(&server, &edit).await;
    assert!(
        form.body.contains("Leave empty to keep it"),
        "{}",
        form.body
    );
    assert!(!form.body.contains("s3cret"));

    // A mistake comes back with what was typed, and why.
    let bad = [("url", "db.example.com"), ("interval_secs", "120")];
    let refused = browser
        .submit(
            &server,
            &edit,
            &format!("{host_path}/pages/{}", pages[0].id),
            &bad,
        )
        .await;
    assert_eq!(refused.status, 422);
    assert!(
        refused.body.contains("has to start with http://"),
        "{}",
        refused.body
    );

    let renamed = browser
        .submit(
            &server,
            &host_path,
            &format!("{host_path}/rename"),
            &[("hostname", "orders")],
        )
        .await;
    assert_eq!(renamed.status, 303);
    let hosts = browser.get(&server, "/hosts?view=table").await;
    assert!(hosts.body.contains(">orders</a>"), "{}", hosts.body);
    assert!(hosts.body.contains("No agent"));
}
