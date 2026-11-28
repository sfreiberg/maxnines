//! Proxies in front of the server: noticing one that isn't trusted, saying whether
//! it's yours, and what changes once it's trusted.

use super::app_sign_ins::call_json;
use super::audit::api_from;
use super::*;

/// A server that trusts no proxy, so the test client is an untrusted one.
async fn behind_an_untrusted_proxy() -> TestServer {
    start_with("trusted_proxies = []").await
}

/// Opens a page as the signed-in admin, through a proxy saying it's for `client`.
async fn page_from(server: &TestServer, client: &str, path: &str) -> Page {
    let mut browser = Browser::default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: x\r\nCookie: {}\r\nX-Forwarded-For: {client}\r\n\
         Connection: close\r\n\r\n",
        browser.cookie_header(server)
    );
    browser.send(server, request).await
}

#[tokio::test]
async fn an_untrusted_proxy_is_noticed_and_trusting_it_believes_it() {
    let server = behind_an_untrusted_proxy().await;
    // Nothing to say before anyone's come through one.
    let page = Browser::default().get(&server, "/settings").await;
    assert!(
        !page.body.contains("Requests seem to come through a proxy"),
        "{}",
        page.body
    );

    assert_eq!(
        api_from(&server, "203.0.113.9", "GET", "/api/v1/hosts", "").await,
        200
    );

    let page = Browser::default().get(&server, "/settings").await;
    assert!(
        page.body
            .contains("Requests seem to come through a proxy at <code>127.0.0.1</code>"),
        "{}",
        page.body
    );
    let (status, proxies) = call_json(&server, &server.api_key, "GET", "/api/v1/proxies").await;
    assert_eq!(status, 200, "{proxies}");
    let waiting = &proxies["waiting"][0];
    assert_eq!(waiting["address"], "127.0.0.1");
    assert_eq!(waiting["forwarded_for"], "203.0.113.9");
    assert_eq!(waiting["kind"], "loopback");
    assert_eq!(waiting["people"][0], "test@example.com");
    assert_eq!(proxies["from_config"], true);

    // The admin's own request through it says so, with the address it gave for them.
    let page = page_from(&server, "198.51.100.4", "/settings/proxies").await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body
            .contains("Your own request just now came through it"),
        "{}",
        page.body
    );
    assert!(page.body.contains("198.51.100.4"), "{}", page.body);

    // Trusted, it's believed at once and the notice goes.
    let mut browser = Browser::default();
    let fields = [("address", "127.0.0.1"), ("trusted", "true")];
    let page = browser
        .submit(&server, "/settings/proxies", "/settings/proxies", &fields)
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let before = server.state.database.audit_log(None, 1).await.unwrap()[0].id;
    api_from(
        &server,
        "203.0.113.9",
        "POST",
        "/api/v1/dashboards",
        r#"{"name": "Ops"}"#,
    )
    .await;
    let newest = &server.state.database.audit_log(None, 1).await.unwrap()[0];
    assert!(newest.id > before);
    assert_eq!(newest.source.as_deref(), Some("203.0.113.9"));
    assert_eq!(newest.forwarded_for, None);
    let page = Browser::default().get(&server, "/settings").await;
    assert!(
        !page.body.contains("Requests seem to come through a proxy"),
        "{}",
        page.body
    );

    // Deciding is recorded.
    let log = server.state.database.audit_log(None, 50).await.unwrap();
    assert!(
        log.iter().any(|entry| entry.subject.kind == "proxy"
            && entry.subject.name == "127.0.0.1"
            && entry.action == "created"),
        "{log:?}"
    );
}

#[tokio::test]
async fn not_a_proxy_stops_the_notice_but_never_believes_it() {
    let server = behind_an_untrusted_proxy().await;
    api_from(&server, "203.0.113.9", "GET", "/api/v1/hosts", "").await;

    let body = r#"{"address": "127.0.0.1", "trusted": false}"#;
    let (status, decided) = api_json(&server, "POST", "/api/v1/proxies", body).await;
    assert_eq!(status, 201, "{decided}");
    api_from(&server, "203.0.113.9", "GET", "/api/v1/hosts", "").await;
    let (_, proxies) = call_json(&server, &server.api_key, "GET", "/api/v1/proxies").await;
    assert_eq!(proxies["waiting"], json!([]));
    let page = Browser::default().get(&server, "/settings").await;
    assert!(
        !page.body.contains("Requests seem to come through a proxy"),
        "{}",
        page.body
    );

    // Forgetting the decision lets it be noticed again.
    let path = format!("/api/v1/proxies/{}", decided["id"]);
    assert_eq!(
        call_json(&server, &server.api_key, "DELETE", &path).await.0,
        204
    );
    assert_eq!(
        call_json(&server, &server.api_key, "DELETE", &path).await.0,
        404
    );
    api_from(&server, "203.0.113.9", "GET", "/api/v1/hosts", "").await;
    let (_, proxies) = call_json(&server, &server.api_key, "GET", "/api/v1/proxies").await;
    assert_eq!(proxies["waiting"][0]["address"], "127.0.0.1");
}

#[tokio::test]
async fn only_admins_decide_and_only_sensible_ranges() {
    let server = start().await;
    for (address, status) in [
        ("0.0.0.0/0", 422),
        ("10.0.0.0/7", 422),
        ("proxy.example.com", 422),
        ("10.0.1.9/24", 201),
        ("cloudflare", 201),
    ] {
        let body = format!(r#"{{"address": "{address}", "trusted": true}}"#);
        let (got, answer) = api_json(&server, "POST", "/api/v1/proxies", &body).await;
        assert_eq!(got, status, "{address}: {answer}");
    }
    let (_, proxies) = call_json(&server, &server.api_key, "GET", "/api/v1/proxies").await;
    let decided: Vec<&str> = proxies["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|decision| decision["address"].as_str().unwrap())
        .collect();
    assert_eq!(decided, ["10.0.1.0/24", "cloudflare"]);
    let page = Browser::default().get(&server, "/settings/proxies").await;
    assert!(
        page.body.contains("Cloudflare&#39;s published ranges"),
        "{}",
        page.body
    );
    assert!(page.has_only_our_scripts());

    let (_, editor) =
        super::app_sign_ins::person(&server, "editor@example.com", crate::roles::Role::Editor)
            .await;
    let mut editor = editor;
    assert_eq!(editor.get(&server, "/settings/proxies").await.status, 403);
    let page = editor.get(&server, "/settings").await;
    assert!(!page.body.contains("/settings/proxies"), "{}", page.body);
}

/// Calls the API as the admin's key with a JSON body.
async fn api_json(server: &TestServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        server.api_key,
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}
