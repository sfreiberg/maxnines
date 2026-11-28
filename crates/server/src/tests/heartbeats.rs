//! Heartbeat checks: scheduled work pings the server, and the check is down when it
//! hasn't in time.

use chrono::TimeDelta;
use maxnines_protocol::CheckKind;

use super::*;
use crate::roles::Role;

/// Calls the API with the admin's key, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

/// Pings as scheduled work would, without signing in, giving the status and text.
async fn ping(server: &TestServer, method: &str, url: &str) -> (u16, String) {
    let path = url.strip_prefix("http://site.test").unwrap();
    let response = server.http(method, path, None).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, text.to_string())
}

fn scheduler(server: &TestServer) -> crate::remote_checks::Scheduler {
    let state = &server.state;
    crate::remote_checks::Scheduler::new(
        state.database.clone(),
        state.writer.clone(),
        state.registry.clone(),
        state.presence.clone(),
        state.check_results.clone(),
    )
}

/// Adds a heartbeat expected hourly with five minutes' grace, on a host of its own,
/// giving its ID, its host's and the address it's pinged at.
async fn add_heartbeat(server: &TestServer) -> (i64, String, String) {
    let body = json!({
        "check": { "name": "Nightly backup", "kind": "heartbeat", "target": "" },
        "interval_secs": 3600,
        "grace_secs": 300,
    });
    let (status, added) = api(server, "POST", "/api/v1/remote-checks", &body).await;
    assert_eq!(status, 201, "{added}");
    let url = added["ping_url"].as_str().unwrap().to_string();
    assert!(url.starts_with("http://site.test/ping/"), "{url}");
    let host_id = added["host_id"].as_str().unwrap().to_string();
    (added["id"].as_i64().unwrap(), host_id, url)
}

fn latest(server: &TestServer, id: i64) -> Value {
    server.state.check_results.latest(id).unwrap().0
}

/// However long checks wait for a slot to run in, a missed ping is seen.
#[tokio::test]
async fn a_late_heartbeat_is_seen_while_every_check_is_busy() {
    let server = start_with_metrics().await;
    // Named so it comes before the heartbeat, as checks are listed by name.
    let body = json!({
        "check": { "name": "Accounts db", "kind": "tcp", "target": "127.0.0.1:1" },
        "interval_secs": 60,
    });
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &body).await;
    assert_eq!(status, 201, "{added}");
    let (id, _, _) = add_heartbeat(&server).await;

    let mut scheduler = scheduler(&server);
    let _busy = scheduler.take_every_slot();
    let late = crate::times::now() + TimeDelta::minutes(66);
    let waiting = tokio::time::timeout(Duration::from_secs(1), scheduler.start_due(late));
    assert!(waiting.await.is_err(), "the check waits for a slot");

    let result = latest(&server, id);
    assert_eq!(result["up"], 0, "{result}");
}

#[tokio::test]
async fn a_heartbeat_is_up_while_pinged_in_time_and_down_once_it_is_late_or_fails() {
    let server = start_with_metrics().await;
    let (id, host_id, url) = add_heartbeat(&server).await;

    // Its new host is named after it, as it reaches nothing.
    let (_, host) = api(
        &server,
        "GET",
        &format!("/api/v1/hosts/{host_id}"),
        &Value::Null,
    )
    .await;
    assert_eq!(host["hostname"], "nightly backup", "{host}");
    // Reading the check never gives its address away.
    let path = format!("/api/v1/remote-checks/{id}");
    let (_, saved) = api(&server, "GET", &path, &Value::Null).await;
    assert_eq!(saved["grace_secs"], 300, "{saved}");
    assert!(!saved.to_string().contains("/ping/"), "{saved}");

    // A ping, with no sign in, says the work ran, at once.
    assert_eq!(ping(&server, "POST", &url).await, (200, "OK\n".to_string()));
    assert_eq!(latest(&server, id)["up"], 1);
    assert!(server.state.presence.get(&host_id).unwrap().online);

    // Within its hour and five minutes it's up, and after that it's late.
    let mut scheduler = scheduler(&server);
    let now = crate::times::now();
    scheduler
        .start_due(now + TimeDelta::minutes(64))
        .await
        .unwrap();
    assert_eq!(latest(&server, id)["up"], 1);
    scheduler
        .start_due(now + TimeDelta::minutes(66))
        .await
        .unwrap();
    let late = latest(&server, id);
    assert_eq!(late["up"], 0, "{late}");
    assert_eq!(late["error"], "it wasn't pinged within 1 h 5 min");
    assert!(!server.state.presence.get(&host_id).unwrap().online);

    // A run that times itself, then one that fails, each over a second after the
    // last ping, as pings closer together aren't counted.
    sleep(Duration::from_millis(1100)).await;
    assert_eq!(ping(&server, "GET", &format!("{url}/start")).await.0, 200);
    assert_eq!(
        latest(&server, id)["up"],
        0,
        "starting doesn't say it worked"
    );
    sleep(Duration::from_millis(1100)).await;
    assert_eq!(ping(&server, "HEAD", &url).await.0, 200);
    let timed = latest(&server, id);
    assert_eq!(timed["up"], 1, "{timed}");
    assert!(timed["response_secs"].as_f64().unwrap() >= 1.0, "{timed}");
    sleep(Duration::from_millis(1100)).await;
    assert_eq!(ping(&server, "POST", &format!("{url}/fail")).await.0, 200);
    let failed = latest(&server, id);
    assert_eq!(failed["up"], 0, "{failed}");
    assert_eq!(failed["error"], "its last run said it failed");

    // What it found is saved as its host's, as any check's is.
    let path = format!("/api/v1/hosts/{host_id}/metrics/check.up?range=1h");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (_, body) = api(&server, "GET", &path, &Value::Null).await;
        if body["series"][0]["name"] == "Nightly backup" {
            break;
        }
        assert!(Instant::now() < deadline, "nothing was saved: {body}");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn one_never_pinged_is_given_its_time_from_when_it_is_first_watched() {
    let server = start().await;
    let (id, _, _) = add_heartbeat(&server).await;
    let mut scheduler = scheduler(&server);
    let now = crate::times::now();
    scheduler.start_due(now).await.unwrap();
    assert_eq!(latest(&server, id)["up"], 1);
    scheduler
        .start_due(now + TimeDelta::minutes(66))
        .await
        .unwrap();
    let late = latest(&server, id);
    assert_eq!(late["up"], 0, "{late}");
    assert_eq!(
        late["error"],
        "it hasn't been pinged, in the 1 h 5 min it was given"
    );
}

#[tokio::test]
async fn pings_too_fast_or_to_addresses_that_are_no_heartbeat_s_are_turned_away() {
    let server = start().await;
    let (_, _, url) = add_heartbeat(&server).await;
    assert_eq!(ping(&server, "GET", &url).await.0, 200);
    assert_eq!(ping(&server, "GET", &url).await.0, 429);

    let unknown = "http://site.test/ping/00000000000000000000000000000000";
    assert_eq!(ping(&server, "GET", unknown).await.0, 404);
    assert_eq!(
        ping(&server, "GET", "http://site.test/ping/nope").await.0,
        404
    );
    // The rest of the site still needs signing in.
    let (status, _) = ping(&server, "GET", "http://site.test/checks").await;
    assert_ne!(status, 200);
}

#[tokio::test]
async fn a_new_address_stops_the_old_one_and_is_recorded_without_itself() {
    let server = start().await;
    let (id, _, old) = add_heartbeat(&server).await;
    let path = format!("/api/v1/remote-checks/{id}/ping-address");
    let (status, renewed) = api(&server, "POST", &path, &Value::Null).await;
    assert_eq!(status, 200, "{renewed}");
    let new = renewed["ping_url"].as_str().unwrap();
    assert_ne!(new, old);
    assert_eq!(ping(&server, "GET", &old).await.0, 404);
    assert_eq!(ping(&server, "GET", new).await.0, 200);

    let (_, log) = api(&server, "GET", "/api/v1/audit-log?limit=5", &Value::Null).await;
    let text = log.to_string();
    assert!(text.contains("new_ping_address"), "{text}");
    let token = new.rsplit('/').next().unwrap();
    assert!(!text.contains(token), "{text}");

    // Any other check has no address to renew.
    let site = json!({
        "check": { "name": "Home page", "kind": "tcp", "target": "127.0.0.1:1" },
        "interval_secs": 60,
    });
    let (_, added) = api(&server, "POST", "/api/v1/remote-checks", &site).await;
    assert!(added.get("ping_url").is_none(), "{added}");
    let path = format!("/api/v1/remote-checks/{}/ping-address", added["id"]);
    assert_eq!(api(&server, "POST", &path, &Value::Null).await.0, 404);
}

#[tokio::test]
async fn only_those_who_can_change_a_heartbeat_see_its_address() {
    let server = start().await;
    let (id, _, url) = add_heartbeat(&server).await;
    let page = Browser::default()
        .get(&server, &format!("/checks/{id}"))
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&url), "{}", page.body);
    assert!(
        !page.body.contains("Check now"),
        "a heartbeat has nothing to run"
    );

    let database = &server.state.database;
    let email = "viewer@example.com";
    let (user, link) = database
        .create_user(email, "Someone", Role::Viewer, crate::times::now())
        .await
        .unwrap()
        .unwrap();
    let password = "a long enough password";
    let hash = crate::passwords::hash_password(password.to_string())
        .await
        .unwrap();
    assert!(
        database
            .use_setup_link(user.id, &link, &hash, crate::times::now())
            .await
            .unwrap()
    );
    let mut viewer = Browser::anonymous();
    let fields = [("email", email), ("password", password)];
    let signed_in = viewer.submit(&server, "/login", "/login", &fields).await;
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    let page = viewer.get(&server, &format!("/checks/{id}")).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("/ping/"), "{}", page.body);
}

#[tokio::test]
async fn a_heartbeat_is_added_from_its_form_with_no_target() {
    let server = start().await;
    let mut browser = Browser::default();
    let fields = [
        ("host_id", ""),
        ("hostname", ""),
        ("name", "Weekly report"),
        ("kind", "heartbeat"),
        ("target", "left from another kind"),
        ("interval_secs", "604800"),
        ("grace_secs", "3600"),
        ("timeout_secs", "5"),
        ("enabled", "on"),
    ];
    let added = browser
        .submit(&server, "/checks/new", "/checks", &fields)
        .await;
    assert_eq!(added.status, 303, "{}", added.body);
    let checks = server.state.database.list_remote_checks().await.unwrap();
    let saved = &checks[0].input;
    assert_eq!(saved.check.kind, CheckKind::Heartbeat);
    assert_eq!(saved.check.target, "");
    assert_eq!(saved.check.timeout, None);
    assert_eq!(saved.grace, Some(Duration::from_secs(3600)));
    assert!(checks[0].ping_token.is_some());

    // Changed to another kind, it loses its address.
    let id = checks[0].id;
    let mut input = saved.clone();
    input.check = maxnines_protocol::Check::new("Weekly report", CheckKind::Tcp, "127.0.0.1:1");
    input.interval = Duration::from_secs(60);
    input.grace = None;
    assert!(
        server
            .state
            .database
            .update_remote_check(id, &input)
            .await
            .unwrap()
    );
    let changed = server
        .state
        .database
        .get_remote_check(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.ping_token, None);
}
