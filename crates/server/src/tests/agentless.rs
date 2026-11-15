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
            "sign_in": "password", "username": "metrics", "has_password": true,
            "password_env": null, "has_token": false, "token_env": null
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
    // How the page was before says nothing about it now, so that's forgotten and
    // it's read again without waiting out its interval.
    assert_eq!(server.state.page_reads.result(page_id), None);
    assert_eq!(read_due(&mut scheduler, now + 1_000).await, 1);
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(
        result["error"],
        "the environment variable MAXNINES_SECRET_NEVER_SET isn't set"
    );
    let presence = server.state.presence.get(&id).unwrap();
    assert!(!presence.online);
    // It has never answered, so it has never been seen.
    let (_, host) = api(&server, "GET", &format!("/api/v1/hosts/{id}"), &Value::Null).await;
    assert_eq!(host["last_seen_ms"], Value::Null, "{host}");
}

#[tokio::test]
async fn a_page_is_signed_in_to_with_a_token_that_is_never_read_back() {
    let server = start().await;
    let id = add_host(&server, "orders-app").await;
    let served = serve(Some("authorization: Bearer abc.DEF-123")).await;
    let url = format!("http://{}/metrics", served.address);
    let typed = json!({ "url": url, "interval_secs": 60, "token": "abc.DEF-123" });
    let page_id = add_page(&server, &id, &typed).await;
    let mut scheduler = scheduler(&server);
    let now = now_ms();

    read_due(&mut scheduler, now).await;
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(result["up"], 1, "{result}");

    let page_path = format!("/api/v1/metrics-pages/{page_id}");
    let (_, page) = api(&server, "GET", &page_path, &Value::Null).await;
    assert_eq!(page["sign_in"], "token");
    assert_eq!(page["has_token"], true);
    assert!(!page.to_string().contains("abc.DEF-123"), "{page}");
    let (_, log) = api(&server, "GET", "/api/v1/audit-log", &Value::Null).await;
    assert!(!log.to_string().contains("abc.DEF-123"), "{log}");
    let saved_token = || async {
        let saved = server.state.database.get_metrics_page(page_id).await;
        saved.unwrap().unwrap().input.token
    };

    // Saying how it signs in keeps the token without sending it again.
    let slower = json!({ "url": url, "interval_secs": 300, "sign_in": "token" });
    assert_eq!(api(&server, "PUT", &page_path, &slower).await.0, 204);
    assert_eq!(saved_token().await.as_deref(), Some("abc.DEF-123"));

    // A token and a username together are refused, as is a token with spaces.
    let both = json!({ "url": url, "interval_secs": 300, "username": "metrics", "token": "x" });
    assert_eq!(api(&server, "PUT", &page_path, &both).await.0, 422);
    let spaced = json!({ "url": url, "interval_secs": 300, "token": "two words" });
    assert_eq!(api(&server, "PUT", &page_path, &spaced).await.0, 422);
    let nothing = json!({ "url": url, "interval_secs": 300, "sign_in": "password" });
    assert_eq!(api(&server, "PUT", &page_path, &nothing).await.0, 422);
    assert_eq!(saved_token().await.as_deref(), Some("abc.DEF-123"));

    // One from the server's environment, which nothing here sets.
    let unset = json!({
        "url": url, "interval_secs": 60, "token_env": "MAXNINES_SECRET_NEVER_SET"
    });
    assert_eq!(api(&server, "PUT", &page_path, &unset).await.0, 204);
    assert_eq!(saved_token().await, None);
    read_due(&mut scheduler, now + 60_000).await;
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(
        result["error"],
        "the environment variable MAXNINES_SECRET_NEVER_SET isn't set"
    );

    // A change that says nothing about signing in takes it away.
    let plain = json!({ "url": url, "interval_secs": 60 });
    assert_eq!(api(&server, "PUT", &page_path, &plain).await.0, 204);
    let (_, page) = api(&server, "GET", &page_path, &Value::Null).await;
    assert_eq!(page["sign_in"], "none");
    read_due(&mut scheduler, now + 120_000).await;
    let result = server.state.page_reads.result(page_id).unwrap();
    assert_eq!(result["error"], "the page returned status 401");
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

    // Nor is it listed or counted as offline, as it couldn't be online.
    let (_, host) = api(
        &server,
        "GET",
        &format!("/api/v1/hosts/{idle}"),
        &Value::Null,
    )
    .await;
    assert_eq!(
        (&host["health"], &host["online"]),
        (&json!("not_read"), &json!(false))
    );
    let mut browser = Browser::default();
    let all = browser.get(&server, "/hosts").await;
    assert!(all.body.contains("0 of 1 online"), "{}", all.body);
    assert!(all.body.contains("Not read"), "{}", all.body);
    let offline = browser.get(&server, "/hosts?status=offline").await;
    assert!(offline.body.contains("orders-db"), "{}", offline.body);
    assert!(!offline.body.contains("not-set-up-yet"), "{}", offline.body);
    let overview = browser.get(&server, "/").await;
    assert!(overview.body.contains("1 offline"), "{}", overview.body);
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
        ("sign_in", "password"),
        ("username", "metrics"),
        ("password", "s3cret"),
        ("password_env", ""),
        // Left in the boxes for a way of signing in that wasn't chosen.
        ("token_env", "MAXNINES_SECRET_UNUSED"),
    ];
    let saved = browser
        .submit(&server, &form, &format!("{host_path}/pages"), &fields)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);

    // With no agent there's no CPU to chart, so its charts aren't left empty.
    let metrics = browser.get(&server, &format!("{host_path}/metrics")).await;
    assert_eq!(metrics.status, 200);
    assert!(!metrics.body.contains("CPU usage"), "{}", metrics.body);

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

fn check_scheduler(server: &TestServer) -> crate::remote_checks::Scheduler {
    let state = &server.state;
    crate::remote_checks::Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.check_results.clone(),
    )
}

async fn run_due(scheduler: &mut crate::remote_checks::Scheduler, now_ms: i64) -> usize {
    let started = scheduler.start_due(now_ms).await.unwrap();
    let count = started.len();
    for check in started {
        check.await.unwrap();
    }
    count
}

fn tcp_check(host_id: &str, name: &str, target: &str) -> Value {
    json!({
        "host_id": host_id,
        "check": { "name": name, "kind": "tcp", "target": target, "timeout_secs": 5 },
        "interval_secs": 60
    })
}

#[tokio::test]
async fn a_check_about_a_host_is_saved_under_it_and_says_whether_it_is_there() {
    let server = start_with_metrics().await;
    let id = add_host(&server, "orders-db").await;
    let served = serve(None).await;
    let open = tcp_check(&id, "orders port", &served.address);
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &open).await;
    assert_eq!(status, 201, "{added}");
    let check_path = format!("/api/v1/remote-checks/{}", added["id"]);
    let (_, saved) = api(&server, "GET", &check_path, &Value::Null).await;
    assert_eq!(saved["host_id"], id.as_str());
    let mut scheduler = check_scheduler(&server);
    let now = now_ms();

    assert!(server.state.presence.get(&id).is_none());
    assert_eq!(run_due(&mut scheduler, now).await, 1);
    assert!(server.state.presence.get(&id).unwrap().online);

    // The result is the host's.
    let path = format!("/api/v1/hosts/{id}/metrics/check.up?range=1h");
    let deadline = Instant::now() + Duration::from_secs(5);
    let up = loop {
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
    assert_eq!(up["series"][0]["name"], "orders port");
    // Nothing listens on port 1, so the only thing reaching the host fails.
    let closed = tcp_check(&id, "orders port", "127.0.0.1:1");
    assert_eq!(api(&server, "PUT", &check_path, &closed).await.0, 204);
    assert_eq!(run_due(&mut scheduler, now + 60_000).await, 1);
    assert!(!server.state.presence.get(&id).unwrap().online);

    // A check that's no longer about the host says nothing about it.
    let about_server = tcp_check("server", "orders port", "127.0.0.1:1");
    assert_eq!(api(&server, "PUT", &check_path, &about_server).await.0, 204);
    assert_eq!(run_due(&mut scheduler, now + 120_000).await, 1);
    assert!(server.state.presence.get(&id).is_none());
}

#[tokio::test]
async fn a_check_is_about_a_host_with_no_agent_or_the_server() {
    let server = start().await;
    let id = add_host(&server, "orders-db").await;
    let agent = identity();
    let _client = server.connect_approved(&agent, "web-1").await;

    for about in [agent.id(), "nobody".to_string()] {
        let check = tcp_check(&about, "port", "db.example.com:5432");
        let (status, refused) = api(&server, "POST", "/api/v1/remote-checks", &check).await;
        assert_eq!(status, 422, "{about}: {refused}");
    }
    // Left out, it's about the server, as every check used to be.
    let own = json!({
        "check": { "name": "site", "kind": "tcp", "target": "example.com:443" },
        "interval_secs": 60
    });
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &own).await;
    assert_eq!(status, 201, "{added}");
    let path = format!("/api/v1/remote-checks/{}", added["id"]);
    assert_eq!(
        api(&server, "GET", &path, &Value::Null).await.1["host_id"],
        "server"
    );

    // A host's checks go with it.
    let about_host = tcp_check(&id, "orders port", "db.example.com:5432");
    let (_, added) = api(&server, "POST", "/api/v1/remote-checks", &about_host).await;
    let host_path = format!("/api/v1/hosts/{id}");
    assert_eq!(
        api(&server, "DELETE", &host_path, &Value::Null).await.0,
        204
    );
    let path = format!("/api/v1/remote-checks/{}", added["id"]);
    assert_eq!(api(&server, "GET", &path, &Value::Null).await.0, 404);
    let (_, left) = api(&server, "GET", "/api/v1/remote-checks", &Value::Null).await;
    assert_eq!(left.as_array().unwrap().len(), 1, "{left}");
}

#[tokio::test]
async fn two_hosts_can_each_have_a_check_of_the_same_name() {
    let server = start().await;
    let orders = add_host(&server, "orders-db").await;
    let billing = add_host(&server, "billing-db").await;
    let served = serve(None).await;
    let add = |about: &str| {
        let check = tcp_check(about, "port", &served.address);
        let server = &server;
        async move { api(server, "POST", "/api/v1/remote-checks", &check).await }
    };
    for about in [orders.as_str(), billing.as_str(), "server"] {
        let (status, added) = add(about).await;
        assert_eq!(status, 201, "{about}: {added}");
    }
    let (status, refused) = add(&orders).await;
    assert_eq!(status, 422);
    let why = refused["error"].as_str().unwrap();
    assert!(why.contains("already exists for this host"), "{why}");

    // Each has its own result, and its own row on its host's page.
    let mut scheduler = check_scheduler(&server);
    assert_eq!(run_due(&mut scheduler, now_ms()).await, 3);
    assert_eq!(server.state.check_results.all().len(), 3);
    let mut browser = Browser::default();
    for host in [&orders, &billing] {
        let page = browser.get(&server, &format!("/hosts/{host}")).await;
        let row = format!("tcp {}", served.address);
        assert_eq!(page.body.matches(&row).count(), 1, "{}", page.body);
    }
    // Moving one onto a host that has its name is refused too.
    let (_, checks) = api(&server, "GET", "/api/v1/remote-checks", &Value::Null).await;
    let mut all = checks.as_array().unwrap().iter();
    let own = all.find(|check| check["host_id"] == "server").unwrap();
    let path = format!("/api/v1/remote-checks/{}", own["id"]);
    let moved = tcp_check(&billing, "port", &served.address);
    assert_eq!(api(&server, "PUT", &path, &moved).await.0, 422);
}

#[tokio::test]
async fn a_check_has_a_page_of_its_own_with_only_its_charts() {
    let server = start_with_metrics().await;
    let served = serve(None).await;
    let mut ids = Vec::new();
    for name in ["alpha-site", "beta-site"] {
        let check = tcp_check("server", name, &served.address);
        let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &check).await;
        assert_eq!(status, 201, "{added}");
        ids.push(added["id"].as_i64().unwrap());
    }
    let mut scheduler = check_scheduler(&server);
    assert_eq!(run_due(&mut scheduler, now_ms()).await, 2);
    let mut browser = Browser::default();

    // Its results are charted on its own page once they're saved.
    let path = format!("/checks/{}", ids[0]);
    let deadline = Instant::now() + Duration::from_secs(5);
    let page = loop {
        let page = browser.get(&server, &path).await;
        assert_eq!(page.status, 200, "{}", page.body);
        if !page.body.contains("No data in this range") {
            break page;
        }
        assert!(
            Instant::now() < deadline,
            "nothing was charted: {}",
            page.body
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    for shown in [
        "alpha-site",
        "Availability",
        "Last 24 hours",
        "100%",
        "Last run",
        "s ago",
        "Passing",
        "Response time",
        "Total",
        "No rule watches this check",
    ] {
        assert!(page.body.contains(shown), "{shown}: {}", page.body);
    }
    assert!(!page.body.contains("beta-site"), "{}", page.body);

    // A chart's numbers are the one check's too.
    let data = "/hosts/server/metrics/check.up?range=1h&series=alpha-site";
    let link = data.replace('&', "&amp;");
    assert!(page.body.contains(&link), "{}", page.body);

    // The list leads to each check's page.
    let list = browser.get(&server, "/checks").await;
    for id in &ids {
        let link = format!(r#"href="/checks/{id}""#);
        assert!(list.body.contains(&link), "{}", list.body);
    }
    assert_eq!(browser.get(&server, "/checks/999999").await.status, 404);
}

#[tokio::test]
async fn a_check_is_run_paused_and_quieted_from_its_page() {
    let server = start_with_metrics().await;
    let id = add_host(&server, "orders-db").await;
    let served = serve(None).await;
    let mut ids = Vec::new();
    for name in ["site", "admin"] {
        let check = tcp_check(&id, name, &served.address);
        let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &check).await;
        assert_eq!(status, 201, "{added}");
        ids.push(added["id"].as_i64().unwrap());
    }
    let path = format!("/checks/{}", ids[0]);
    let mut browser = Browser::default();

    // It hasn't run yet, until it's asked to.
    let page = browser.get(&server, &path).await;
    assert!(page.body.contains("Waiting"), "{}", page.body);
    let ran = browser
        .submit(&server, &path, &format!("{path}/run"), &[])
        .await;
    assert_eq!(ran.status, 303, "{}", ran.body);
    let page = browser.get(&server, &path).await;
    assert!(page.body.contains("s ago"), "{}", page.body);
    assert!(
        page.body.contains(">Up<") || page.body.contains("</span>Up"),
        "{}",
        page.body
    );
    assert!(server.state.check_results.ran_ms(ids[0]).is_some());
    assert_eq!(server.state.check_results.ran_ms(ids[1]), None);

    // Quieting it holds back alerts about it alone, not the host's other check.
    let fields = [("duration_secs", "3600"), ("reason", "Redeploying")];
    let quieted = browser
        .submit(&server, &path, &format!("{path}/maintenance"), &fields)
        .await;
    assert_eq!(quieted.status, 303, "{}", quieted.body);
    let about = |series: &str| crate::alerting::Alert {
        host_id: id.clone(),
        hostname: "orders-db".to_string(),
        series: series.to_string(),
        ..crate::channels::testing::alert()
    };
    let quiet = crate::silences::ActiveSilences::load(&server.state.database, now_ms())
        .await
        .unwrap();
    assert!(quiet.covering(&about("site")).is_some());
    assert!(quiet.covering(&about("admin")).is_none());
    assert!(
        quiet.covering_host(&id, "orders-db").is_none(),
        "the host isn't quiet"
    );
    let page = browser.get(&server, &path).await;
    assert!(page.body.contains("Redeploying"), "{}", page.body);
    assert!(page.body.contains("End now"), "{}", page.body);
    // The other check's page knows nothing of it.
    let other = browser.get(&server, &format!("/checks/{}", ids[1])).await;
    assert!(!other.body.contains("Redeploying"), "{}", other.body);
    // The Silences page says which check it's for.
    let silences = browser.get(&server, "/alerts/silences").await;
    assert!(silences.body.contains("Only site"), "{}", silences.body);

    let ended = browser
        .submit(&server, &path, &format!("{path}/maintenance/end"), &[])
        .await;
    assert_eq!(ended.status, 303);
    let quiet = crate::silences::ActiveSilences::load(&server.state.database, now_ms())
        .await
        .unwrap();
    assert!(quiet.covering(&about("site")).is_none());

    // Paused, it isn't run and can't be asked to; resumed, it can.
    let paused = browser
        .submit(&server, &path, &format!("{path}/pause"), &[])
        .await;
    assert_eq!(paused.status, 303);
    let saved = server.state.database.get_remote_check(ids[0]).await;
    assert!(!saved.unwrap().unwrap().input.enabled);
    let page = browser.get(&server, &path).await;
    assert!(page.body.contains("Paused"), "{}", page.body);
    assert!(page.body.contains("Resume"), "{}", page.body);
    assert!(!page.body.contains("Check now"), "{}", page.body);
    browser
        .submit(&server, &path, &format!("{path}/pause"), &[])
        .await;
    let saved = server.state.database.get_remote_check(ids[0]).await;
    assert!(saved.unwrap().unwrap().input.enabled);
}

#[tokio::test]
async fn a_checks_password_is_kept_but_never_given_back() {
    let server = start().await;
    let check = |extra: Value| {
        let mut body = json!({
            "check": { "name": "orders db", "kind": "postgres", "target": "127.0.0.1:1" },
            "interval_secs": 60
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let typed = check(json!({ "username": "maxnines", "password": "s3cret" }));
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &typed).await;
    assert_eq!(status, 201, "{added}");
    let id = added["id"].as_i64().unwrap();
    let path = format!("/api/v1/remote-checks/{id}");
    let (_, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(shown["sign_in"], "password");
    assert_eq!(shown["username"], "maxnines");
    assert_eq!(shown["has_password"], true);
    let (_, all) = api(&server, "GET", "/api/v1/remote-checks", &Value::Null).await;
    let (_, log) = api(&server, "GET", "/api/v1/audit-log", &Value::Null).await;
    for body in [&shown, &all, &log] {
        assert!(!body.to_string().contains("s3cret"), "{body}");
    }
    let saved = || async {
        let check = server.state.database.get_remote_check(id).await.unwrap();
        check.unwrap().input.sign_in
    };

    // An edit that doesn't give it again keeps it, and saying not to sign in
    // lets it go.
    let slower = check(json!({ "username": "maxnines", "interval_secs": 300 }));
    assert_eq!(api(&server, "PUT", &path, &slower).await.0, 204);
    assert_eq!(saved().await.password.as_deref(), Some("s3cret"));
    let plain = check(json!({ "sign_in": "none" }));
    assert_eq!(api(&server, "PUT", &path, &plain).await.0, 204);
    assert_eq!(saved().await, crate::remote_checks::SignIn::default());

    // Only what fits the kind is taken.
    let mut web = check(json!({ "username": "a", "password": "b" }));
    web["check"] = json!({ "name": "site", "kind": "http", "target": "https://example.com" });
    let key =
        check(json!({ "username": "a", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----" }));
    let leaked = check(json!({ "username": "a", "password_env": "DATABASE_URL" }));
    for refused in [web, key, leaked] {
        let (status, body) = api(&server, "POST", "/api/v1/remote-checks", &refused).await;
        assert_eq!(status, 422, "{refused}: {body}");
    }

    // One read from the server's environment says when it isn't there.
    let unset = check(json!({ "username": "a", "password_env": "MAXNINES_SECRET_NEVER_SET" }));
    assert_eq!(api(&server, "PUT", &path, &unset).await.0, 204);
    run_due(&mut check_scheduler(&server), now_ms()).await;
    let result = &server.state.check_results.all()[&id];
    assert_eq!(
        result["error"],
        "the environment variable MAXNINES_SECRET_NEVER_SET isn't set"
    );

    // The form never has it either.
    let typed = check(json!({ "username": "maxnines", "password": "s3cret" }));
    assert_eq!(api(&server, "PUT", &path, &typed).await.0, 204);
    let form = Browser::default()
        .get(&server, &format!("/checks/{id}/edit"))
        .await;
    assert!(
        form.body.contains("Saved. Leave empty to keep it"),
        "{}",
        form.body
    );
    assert!(!form.body.contains("s3cret"), "{}", form.body);

    // From the form, only the boxes for the way chosen count: a password for a
    // Redis without usernames, with a key left in the other box.
    let fields = [
        ("name", "cache"),
        ("kind", "redis"),
        ("target", "127.0.0.1:6379"),
        ("interval_secs", "60"),
        ("enabled", "on"),
        ("tls", "on"),
        ("sign_in", "password"),
        ("password", "r3dis"),
        ("private_key", "left behind"),
    ];
    let mut browser = Browser::default();
    let added = browser
        .submit(&server, "/checks/new", "/checks", &fields)
        .await;
    assert_eq!(added.status, 303, "{}", added.body);
    let checks = server.state.database.list_remote_checks().await.unwrap();
    let cache = checks
        .iter()
        .find(|c| c.input.check.name == "cache")
        .unwrap();
    assert_eq!(cache.input.check.tls, Some(true));
    assert_eq!(cache.input.sign_in.password.as_deref(), Some("r3dis"));
    assert_eq!(cache.input.sign_in.private_key, None);

    // MongoDB, with the database its account was made in.
    let fields = [
        ("name", "documents"),
        ("kind", "mongodb"),
        ("target", "127.0.0.1:27017"),
        ("interval_secs", "60"),
        ("enabled", "on"),
        ("database", "monitoring"),
        ("tls", "on"),
        ("sign_in", "password"),
        ("username", "maxnines"),
        ("password", "m0ngo"),
    ];
    let form = browser.get(&server, "/checks/new").await;
    assert!(
        form.body
            .contains(r#"<option value="mongodb">MongoDB</option>"#),
        "{}",
        form.body
    );
    let added = browser
        .submit(&server, "/checks/new", "/checks", &fields)
        .await;
    assert_eq!(added.status, 303, "{}", added.body);
    let checks = server.state.database.list_remote_checks().await.unwrap();
    let documents = checks
        .iter()
        .find(|c| c.input.check.name == "documents")
        .unwrap();
    assert_eq!(
        documents.input.check.kind,
        maxnines_protocol::CheckKind::Mongodb
    );
    assert_eq!(
        documents.input.check.database.as_deref(),
        Some("monitoring")
    );
    assert_eq!(documents.input.sign_in.password.as_deref(), Some("m0ngo"));
}

#[tokio::test]
async fn a_hosts_checks_are_added_from_its_page() {
    let server = start().await;
    let id = add_host(&server, "orders-db").await;
    let mut browser = Browser::default();
    let host_path = format!("/hosts/{id}");

    let page = browser.get(&server, &host_path).await;
    let link = format!(r#"href="/checks/new?host={id}""#);
    assert!(page.body.contains(&link), "{}", page.body);
    assert!(page.body.contains("No checks are about this host yet"));

    // The form starts on the host it was reached from.
    let form_path = format!("/checks/new?host={id}");
    let form = browser.get(&server, &form_path).await;
    let chosen = format!(r#"<option value="{id}" selected>orders-db</option>"#);
    assert!(form.body.contains(&chosen), "{}", form.body);
    assert!(
        form.body
            .contains(r#"<option value="server">MaxNines server</option>"#)
    );

    let fields = [
        ("host_id", id.as_str()),
        ("name", "orders port"),
        ("kind", "tcp"),
        ("target", "db.example.com:5432"),
        ("interval_secs", "60"),
        ("enabled", "on"),
    ];
    let saved = browser
        .submit(&server, &form_path, "/checks", &fields)
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    assert_eq!(saved.header("location"), Some(host_path.as_str()));

    let page = browser.get(&server, &host_path).await;
    assert!(page.body.contains("orders port"), "{}", page.body);
    assert!(page.body.contains("tcp db.example.com:5432"));
    assert!(page.body.contains("Waiting"));
    // The list of every check says whose it is.
    let checks = browser.get(&server, "/checks").await;
    let whose = format!(r#"<a href="/hosts/{id}">orders-db</a>"#);
    assert!(checks.body.contains(&whose), "{}", checks.body);
}

#[tokio::test]
async fn only_a_database_check_reads_stats_and_only_extras_there_are() {
    let server = start().await;
    let id = add_host(&server, "orders-db").await;
    let request = |kind: &str, target: &str, more: Value| {
        let mut request = json!({
            "host_id": id,
            "check": { "name": "orders", "kind": kind, "target": target },
            "interval_secs": 60,
            "username": "maxnines",
        });
        for (key, value) in more.as_object().unwrap() {
            request[key] = value.clone();
        }
        request
    };
    for refused in [
        request("tcp", "db:5432", json!({ "read_stats": true })),
        request("postgres", "db:5432", json!({ "extras": ["sizes"] })),
        request(
            "postgres",
            "db:5432",
            json!({ "read_stats": true, "extras": ["tables"] }),
        ),
    ] {
        let (status, body) = api(&server, "POST", "/api/v1/remote-checks", &refused).await;
        assert_eq!(status, 422, "{refused}: {body}");
    }
    let wanted = request(
        "postgres",
        "db:5432",
        json!({ "read_stats": true, "extras": ["sizes"] }),
    );
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &wanted).await;
    assert_eq!(status, 201, "{added}");
    let path = format!("/api/v1/remote-checks/{}", added["id"]);
    let (_, shown) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(shown["read_stats"], true);
    assert_eq!(shown["extras"], json!(["sizes"]));

    // The form keeps them too.
    let form = Browser::default()
        .get(&server, &format!("/checks/{}/edit", added["id"]))
        .await;
    assert!(
        form.body
            .contains(r#"<input type="checkbox" name="read_stats" checked>"#),
        "{}",
        form.body
    );
    assert!(
        form.body
            .contains(r#"<input type="checkbox" name="extra_sizes" checked>"#)
    );
}

/// Reads the throwaway PostgreSQL the checks crate's tests use, named as
/// `host:port username`, as a host with no agent.
#[tokio::test]
async fn a_database_check_reads_its_stats_as_the_hosts() {
    let Ok(real) = std::env::var("MAXNINES_TEST_CHECK_POSTGRES") else {
        return;
    };
    let (target, username) = real.split_once(' ').unwrap();
    let server = start_with_metrics().await;
    let id = add_host(&server, "orders-db").await;
    let check = json!({
        "host_id": id,
        "check": { "name": "orders", "kind": "postgres", "target": target },
        "interval_secs": 60,
        "username": username,
        "read_stats": true,
        "extras": ["sizes"],
    });
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &check).await;
    assert_eq!(status, 201, "{added}");
    let mut scheduler = check_scheduler(&server);
    assert_eq!(run_due(&mut scheduler, now_ms()).await, 1);

    // Saved as the host's, as an agent's would be.
    for metric in ["database.up", "database.connections", "database.size"] {
        let path = format!("/api/v1/hosts/{id}/metrics/{metric}?range=1h");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (_, body) = api(&server, "GET", &path, &Value::Null).await;
            if body["series"]
                .as_array()
                .is_some_and(|lines| !lines.is_empty())
            {
                break;
            }
            assert!(Instant::now() < deadline, "no {metric}: {body}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let page = Browser::default()
        .get(&server, &format!("/hosts/{id}/metrics"))
        .await;
    assert!(page.body.contains("Latest databases"), "{}", page.body);
}
