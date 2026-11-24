//! UniFi checks: the server reads a console's devices, each a host of its own.

use std::collections::BTreeMap;

use maxnines_checks::unifi::fake::{self, ACCESS_POINT, FakeConsole, GATEWAY, KEY, SWITCH};

use super::*;

/// Calls the API with the admin's key, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
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

/// Runs whatever's due and waits for it, `minutes` from now so it's due again.
async fn run(server: &TestServer, scheduler: &mut crate::remote_checks::Scheduler, minutes: i64) {
    let now = crate::times::now() + chrono::TimeDelta::minutes(minutes);
    for running in scheduler.start_due(now).await.unwrap() {
        running.await.unwrap();
    }
    let _ = server;
}

/// The hosts the check has made for devices, by the console's ID for each.
async fn device_hosts(server: &TestServer, id: i64) -> BTreeMap<String, String> {
    server.state.database.unifi_device_hosts(id).await.unwrap()
}

fn hostname(server: &TestServer, id: &str) -> String {
    server
        .state
        .registry
        .read(|hosts| hosts[id].hostname.clone())
}

fn online(server: &TestServer, id: &str) -> Option<bool> {
    server
        .state
        .presence
        .get(id)
        .map(|presence| presence.online)
}

#[tokio::test]
async fn each_device_becomes_a_host_kept_through_runs_and_offline_once_gone() {
    let server = start().await;
    let console = FakeConsole::start().await;
    let body = json!({
        "check": {
            "name": "Home network", "kind": "unifi", "target": console.target(),
            "insecure": true,
        },
        "interval_secs": 60,
        "api_key": KEY,
    });
    let (status, added) = api(&server, "POST", "/api/v1/remote-checks", &body).await;
    assert_eq!(status, 201, "{added}");
    let id = added["id"].as_i64().unwrap();
    let check_host = added["host_id"].as_str().unwrap().to_string();

    // The key can be set, but never read back.
    let (_, saved) = api(
        &server,
        "GET",
        &format!("/api/v1/remote-checks/{id}"),
        &Value::Null,
    )
    .await;
    assert_eq!(saved["sign_in"], "api_key", "{saved}");
    assert_eq!(saved["has_api_key"], true);
    assert!(!saved.to_string().contains(KEY), "{saved}");

    let mut scheduler = scheduler(&server);
    run(&server, &mut scheduler, 0).await;
    let result = server.state.check_results.latest(id).unwrap().0;
    assert_eq!(result["up"], 1, "{result}");
    assert_eq!(result["server_version"], "9.1.120");

    let hosts = device_hosts(&server, id).await;
    assert_eq!(hosts.len(), 3, "{hosts:?}");
    let (gateway, switch, access_point) = (&hosts[GATEWAY], &hosts[SWITCH], &hosts[ACCESS_POINT]);
    assert_eq!(hostname(&server, gateway), "Dream Machine");
    assert_eq!(hostname(&server, switch), "Garage switch");
    assert!(
        !hosts.values().any(|host| *host == check_host),
        "the console's own host is apart"
    );
    let approved = server.state.registry.read(|all| {
        hosts
            .values()
            .all(|id| all[id].is_agentless() && all[id].state == HostState::Approved)
    });
    assert!(approved, "adding the check decided to watch them");
    assert_eq!(online(&server, gateway), Some(true));
    assert_eq!(online(&server, access_point), Some(false));

    let facts = server.state.database.facts_of(&[gateway]).await.unwrap();
    assert_eq!(facts[gateway]["unifi.model"], "UDM Pro", "{facts:?}");
    assert_eq!(facts[gateway]["unifi.firmware"], "4.1.13");
    let sampled = server
        .saved
        .samples
        .lock()
        .unwrap()
        .iter()
        .any(|(host, _, _)| host == gateway);
    assert!(sampled, "each device's numbers are kept as its host's");

    // Renamed on the console, a device keeps its host, and none are added.
    let mut devices = vec![
        fake::device(GATEWAY, "Rack gateway", "ONLINE"),
        fake::device(SWITCH, "Garage switch", "OFFLINE"),
    ];
    console.set_devices(devices.clone());
    run(&server, &mut scheduler, 2).await;
    assert_eq!(device_hosts(&server, id).await, hosts);
    assert_eq!(online(&server, switch), Some(false));
    // One the console stopped listing is offline, and its host stays.
    assert_eq!(online(&server, access_point), Some(false));
    assert!(
        server
            .state
            .registry
            .read(|all| all.contains_key(access_point))
    );

    // A console that can't be read is the check failing, and leaves its devices
    // as they were.
    devices[1] = fake::device(SWITCH, "Garage switch", "ONLINE");
    console.set_devices(devices);
    let wrong = json!({
        "check": {
            "name": "Home network", "kind": "unifi", "target": console.target(),
            "insecure": true,
        },
        "interval_secs": 60,
        "api_key": "not-the-key",
    });
    let path = format!("/api/v1/remote-checks/{id}");
    let (status, answer) = api(&server, "PUT", &path, &wrong).await;
    assert_eq!(status, 204, "{answer}");
    run(&server, &mut scheduler, 4).await;
    let result = server.state.check_results.latest(id).unwrap().0;
    assert_eq!(result["up"], 0, "{result}");
    assert_eq!(result["error"], "the console refused the API key");
    assert_eq!(online(&server, gateway), Some(true));
    assert_eq!(online(&server, switch), Some(false));

    // Paused, the check no longer says anything of its devices.
    let paused = json!({
        "check": {
            "name": "Home network", "kind": "unifi", "target": console.target(),
            "insecure": true,
        },
        "interval_secs": 60,
        "enabled": false,
        "sign_in": "api_key",
    });
    let (status, answer) = api(&server, "PUT", &path, &paused).await;
    assert_eq!(status, 204, "{answer}");
    run(&server, &mut scheduler, 6).await;
    assert_eq!(online(&server, gateway), None);
}

#[tokio::test]
async fn a_unifi_check_needs_an_api_key_and_the_console_address_alone() {
    let server = start().await;
    let check = |target: &str| json!({ "name": "UniFi", "kind": "unifi", "target": target });
    let refused = [
        json!({ "check": check("https://192.168.1.1"), "interval_secs": 60 }),
        json!({
            "check": check("https://192.168.1.1/proxy"), "interval_secs": 60, "api_key": "k",
        }),
        json!({ "check": check("http://192.168.1.1"), "interval_secs": 60, "api_key": "k" }),
        json!({
            "check": check("https://192.168.1.1"), "interval_secs": 60,
            "username": "admin", "password": "secret",
        }),
    ];
    for body in refused {
        let (status, answer) = api(&server, "POST", "/api/v1/remote-checks", &body).await;
        assert_eq!(status, 422, "{body} gave {answer}");
    }
    // Nothing but a UniFi check takes an API key.
    let site = json!({
        "check": { "name": "Site", "kind": "http", "target": "https://example.com" },
        "interval_secs": 60, "api_key": "k",
    });
    let (status, _) = api(&server, "POST", "/api/v1/remote-checks", &site).await;
    assert_eq!(status, 422);
    // An agent never runs one.
    let mut unifi = maxnines_protocol::Check::new(
        "UniFi",
        maxnines_protocol::CheckKind::Unifi,
        "https://192.168.1.1",
    );
    unifi.site = Some("default".to_string());
    unifi.validate().unwrap();
}
