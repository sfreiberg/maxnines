//! Signing in apps through the browser: approving one, the tokens it's given, and
//! how they're refreshed, limited and revoked.

use super::*;
use crate::app_sign_ins::{ACCESS_LIFETIME_MS, REFRESH_GRACE_MS, REFRESH_LIFETIME_MS};
use crate::models::Refreshed;
use crate::roles::Role;

/// RFC 7636's example: the verifier an app keeps, and the challenge it sends.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// Where the app listens for the answer.
const BACK: &str = "http://127.0.0.1:5555/callback";
const PASSWORD: &str = "a long enough password";

fn authorize_path(back: &str, role: &str) -> String {
    format!(
        "/oauth/authorize?response_type=code&client_id=maxnines-cli&redirect_uri={}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz&device=laptop&role={role}",
        encode(back)
    )
}

/// What the approval form sends, as the page fills it in.
fn approval_fields<'a>(role: &'a str, decision: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "maxnines-cli"),
        ("redirect_uri", BACK),
        ("state", "xyz"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("device", "laptop"),
        ("chosen_role", role),
        ("decision", decision),
    ]
}

/// Approves the app in `browser`, giving back where the browser is sent.
async fn approve(browser: &mut Browser, server: &TestServer, role: &str, decision: &str) -> String {
    let page = browser
        .submit(
            server,
            &authorize_path(BACK, role),
            "/oauth/authorize",
            &approval_fields(role, decision),
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    page.header("location").unwrap().to_string()
}

fn query_value(address: &str, name: &str) -> Option<String> {
    let query = address.split_once('?')?.1;
    serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .unwrap()
        .into_iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// Posts a form as an app does, with nobody signed in.
async fn app_post(server: &TestServer, path: &str, fields: &[(&str, &str)]) -> (u16, Value) {
    let page = Browser::anonymous().post(server, path, fields).await;
    (
        page.status,
        serde_json::from_str(&page.body).unwrap_or(Value::Null),
    )
}

async fn swap_code(server: &TestServer, code: &str, verifier: &str) -> (u16, Value) {
    let fields = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", BACK),
        ("client_id", "maxnines-cli"),
        ("code_verifier", verifier),
    ];
    app_post(server, "/oauth/token", &fields).await
}

async fn refresh(server: &TestServer, refresh_token: &str) -> (u16, Value) {
    let fields = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", "maxnines-cli"),
    ];
    app_post(server, "/oauth/token", &fields).await
}

/// Calls the API with a token, giving back the status and any JSON.
async fn call_json(server: &TestServer, token: &str, method: &str, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

/// Calls the API with a token, giving back the status.
async fn call(server: &TestServer, token: &str, method: &str, path: &str) -> u16 {
    call_json(server, token, method, path).await.0
}

/// Someone with this role, and a browser signed in as them.
async fn person(server: &TestServer, email: &str, role: Role) -> (i64, Browser) {
    let database = &server.state.database;
    let (user, link) = database
        .create_user(email, "Someone", role, now_ms())
        .await
        .unwrap()
        .unwrap();
    let hash = crate::passwords::hash_password(PASSWORD.to_string())
        .await
        .unwrap();
    assert!(
        database
            .use_setup_link(user.id, &link, &hash, now_ms())
            .await
            .unwrap()
    );
    let mut browser = Browser::anonymous();
    let fields = [("email", email), ("password", PASSWORD)];
    let page = browser.submit(server, "/login", "/login", &fields).await;
    assert_eq!(page.status, 303, "{}", page.body);
    (user.id, browser)
}

#[tokio::test]
async fn an_app_signs_in_through_the_browser_and_uses_its_token() {
    let server = start().await;
    let mut browser = Browser::default();

    let page = browser.get(&server, &authorize_path(BACK, "viewer")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("Sign in MaxNines command line?"),
        "{}",
        page.body
    );
    assert!(page.body.contains("laptop"), "{}", page.body);
    // The page's form may lead back to the app, and nowhere else new.
    let policy = page.header("content-security-policy").unwrap();
    assert!(
        policy.contains("form-action 'self' http://127.0.0.1:5555;"),
        "{policy}"
    );

    let back = approve(&mut browser, &server, "viewer", "allow").await;
    assert!(
        back.starts_with("http://127.0.0.1:5555/callback?code=mxc_"),
        "{back}"
    );
    assert_eq!(query_value(&back, "state").as_deref(), Some("xyz"));
    let code = query_value(&back, "code").unwrap();

    let (status, tokens) = swap_code(&server, &code, VERIFIER).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], ACCESS_LIFETIME_MS / 1000);
    assert_eq!(
        tokens["refresh_token_expires_in"],
        REFRESH_LIFETIME_MS / 1000
    );
    assert_eq!(tokens["role"], "viewer");
    let access = tokens["access_token"].as_str().unwrap();
    assert!(access.starts_with("mxa_"));

    // It reads like a viewer, and is refused anything more.
    assert_eq!(call(&server, access, "GET", "/api/v1/hosts").await, 200);
    let (status, refused) = call_json(&server, access, "POST", "/api/v1/silences").await;
    assert_eq!(status, 403);
    assert_eq!(
        refused["error"],
        "This needs the responder role, and this app acts as a viewer"
    );
    assert_eq!(
        call(&server, "mxa_wrong", "GET", "/api/v1/hosts").await,
        401
    );

    // A code only works once.
    let (status, refused) = swap_code(&server, &code, VERIFIER).await;
    assert_eq!(status, 400);
    assert_eq!(refused["error"], "invalid_grant");

    // What it does is recorded as its owner's, through the app.
    let page = browser.get(&server, "/settings/apps").await;
    assert!(
        page.body.contains("MaxNines command line on laptop"),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn nothing_is_given_without_the_right_proof_or_address() {
    let server = start().await;
    let mut browser = Browser::default();

    let back = approve(&mut browser, &server, "viewer", "allow").await;
    let code = query_value(&back, "code").unwrap();
    let (status, refused) = swap_code(&server, &code, &"x".repeat(43)).await;
    assert_eq!(status, 400);
    assert_eq!(refused["error"], "invalid_grant");

    // An answer is never sent anywhere but this computer.
    for elsewhere in [
        "https://evil.example.com/callback",
        "http://localhost:5555/",
        // A page's policy can't name an IPv6 address, so the browser couldn't go back.
        "http://[::1]:5555/",
    ] {
        let page = browser
            .get(&server, &authorize_path(elsewhere, "viewer"))
            .await;
        assert_eq!(page.status, 400, "{elsewhere}");
        assert!(page.header("location").is_none());
        assert!(page.body.contains("can't be signed in"), "{}", page.body);
    }

    let (status, refused) = app_post(
        &server,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "someone-else"),
        ],
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(refused["error"], "invalid_client");
}

#[tokio::test]
async fn saying_no_tells_the_app() {
    let server = start().await;
    let back = approve(&mut Browser::default(), &server, "viewer", "deny").await;
    assert_eq!(
        query_value(&back, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(query_value(&back, "state").as_deref(), Some("xyz"));
    assert!(query_value(&back, "code").is_none());
}

#[tokio::test]
async fn an_app_never_does_more_than_its_person() {
    let server = start().await;
    let (_, mut browser) = person(&server, "viewer@example.com", Role::Viewer).await;

    // Asked for more, it offers only what they have.
    let page = browser.get(&server, &authorize_path(BACK, "admin")).await;
    assert!(
        page.body.contains(r#"<option value="viewer" selected>"#),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains(r#"<option value="admin""#),
        "{}",
        page.body
    );

    // And more can't be sent: the page says so, rather than telling the app no.
    let page = browser
        .submit(
            &server,
            &authorize_path(BACK, "admin"),
            "/oauth/authorize",
            &approval_fields("editor", "allow"),
        )
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(
        page.body.contains("one you can give it now. Choose again."),
        "{}",
        page.body
    );
    assert!(page.header("location").is_none());
}

#[tokio::test]
async fn a_device_signs_in_with_a_code_typed_elsewhere() {
    let server = start().await;
    let fields = [
        ("client_id", "maxnines-cli"),
        ("device", "build box"),
        ("role", "responder"),
    ];
    let (status, started) = app_post(&server, "/oauth/device", &fields).await;
    assert_eq!(status, 200, "{started}");
    let device_code = started["device_code"].as_str().unwrap().to_string();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    assert!(
        started["verification_uri"]
            .as_str()
            .unwrap()
            .ends_with("/device")
    );
    assert_eq!(started["interval"], 5);

    let poll = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code.as_str()),
        ("client_id", "maxnines-cli"),
    ];
    let (status, waiting) = app_post(&server, "/oauth/token", &poll).await;
    assert_eq!(status, 400);
    assert_eq!(waiting["error"], "authorization_pending");
    let (_, waiting) = app_post(&server, "/oauth/token", &poll).await;
    assert_eq!(waiting["error"], "slow_down");

    let mut browser = Browser::default();
    let page = browser
        .get(&server, &format!("/device?code={user_code}"))
        .await;
    assert!(page.body.contains("build box"), "{}", page.body);
    assert!(page.body.contains(&user_code), "{}", page.body);
    let typed = user_code.to_lowercase();
    let page = browser
        .submit(
            &server,
            "/device",
            "/device/decide",
            &[
                ("user_code", typed.as_str()),
                ("chosen_role", "responder"),
                ("decision", "allow"),
            ],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("is signed in"), "{}", page.body);

    let (status, tokens) = app_post(&server, "/oauth/token", &poll).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["role"], "responder");
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(call(&server, access, "GET", "/api/v1/alerts").await, 200);

    // A code no app is waiting with says so.
    let page = browser
        .submit(&server, "/device", "/device", &[("user_code", "BBBB-BBBB")])
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("No app is waiting"), "{}", page.body);
}

#[tokio::test]
async fn refreshing_swaps_both_tokens_and_a_copied_one_revokes_the_sign_in() {
    let server = start().await;
    let back = approve(&mut Browser::default(), &server, "viewer", "allow").await;
    let (_, first) = swap_code(&server, &query_value(&back, "code").unwrap(), VERIFIER).await;
    let old_access = first["access_token"].as_str().unwrap();
    let old_refresh = first["refresh_token"].as_str().unwrap();

    let (status, second) = refresh(&server, old_refresh).await;
    assert_eq!(status, 200, "{second}");
    let new_access = second["access_token"].as_str().unwrap();
    let new_refresh = second["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh, old_refresh);
    assert_eq!(call(&server, old_access, "GET", "/api/v1/hosts").await, 401);
    assert_eq!(call(&server, new_access, "GET", "/api/v1/hosts").await, 200);

    // Long after it was swapped, the old one being used again means it was copied.
    let database = &server.state.database;
    let later = now_ms() + REFRESH_GRACE_MS + 1;
    let reused = database
        .refresh_app_sign_in(old_refresh, "maxnines-cli", later)
        .await
        .unwrap();
    assert_eq!(reused, Refreshed::Reused);
    assert_eq!(call(&server, new_access, "GET", "/api/v1/hosts").await, 401);
    let (status, refused) = refresh(&server, new_refresh).await;
    assert_eq!(status, 400, "{refused}");
}

#[tokio::test]
async fn a_lost_answer_can_be_asked_for_again_for_a_moment() {
    let server = start().await;
    let back = approve(&mut Browser::default(), &server, "viewer", "allow").await;
    let (_, first) = swap_code(&server, &query_value(&back, "code").unwrap(), VERIFIER).await;
    let old_refresh = first["refresh_token"].as_str().unwrap();

    let (status, _) = refresh(&server, old_refresh).await;
    assert_eq!(status, 200);
    // The answer never arrived, so the app tries the same token again.
    let (status, again) = refresh(&server, old_refresh).await;
    assert_eq!(status, 200, "{again}");
    let access = again["access_token"].as_str().unwrap();
    assert_eq!(call(&server, access, "GET", "/api/v1/hosts").await, 200);
}

#[tokio::test]
async fn tokens_expire_and_stop_with_their_owner() {
    let server = start().await;
    let database = &server.state.database;
    let (id, _) = person(&server, "someone@example.com", Role::Responder).await;
    let now = now_ms();
    let (_, tokens) = database
        .create_app_sign_in(id, "maxnines-menubar", "Mac", Role::Responder, now)
        .await
        .unwrap();

    let accepted = |at: i64| database.accept_app_token(&tokens.access_token, at);
    assert!(
        accepted(now + ACCESS_LIFETIME_MS - 1)
            .await
            .unwrap()
            .is_some()
    );
    assert!(accepted(now + ACCESS_LIFETIME_MS).await.unwrap().is_none());
    let late = database
        .refresh_app_sign_in(
            &tokens.refresh_token,
            "maxnines-menubar",
            now + REFRESH_LIFETIME_MS,
        )
        .await
        .unwrap();
    assert_eq!(late, Refreshed::Refused);
    // Another app can't use it either.
    let other = database
        .refresh_app_sign_in(&tokens.refresh_token, "maxnines-cli", now)
        .await
        .unwrap();
    assert_eq!(other, Refreshed::Refused);

    // And none of it works while they're disabled.
    database.disable_user(id, now).await.unwrap();
    assert!(accepted(now).await.unwrap().is_none());
    let disabled = database
        .refresh_app_sign_in(&tokens.refresh_token, "maxnines-menubar", now)
        .await
        .unwrap();
    assert_eq!(disabled, Refreshed::Refused);

    // An app can't be signed in to do more than its person.
    assert!(
        database
            .create_app_sign_in(id, "maxnines-cli", "", Role::Admin, now)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn signed_in_apps_are_listed_and_revoked() {
    let server = start().await;
    let database = &server.state.database;
    let owner = database.list_users().await.unwrap()[0].id;
    let now = now_ms();
    let (first, first_tokens) = database
        .create_app_sign_in(owner, "maxnines-cli", "laptop", Role::Viewer, now)
        .await
        .unwrap();
    let (_, second_tokens) = database
        .create_app_sign_in(owner, "maxnines-tray", "office PC", Role::Viewer, now)
        .await
        .unwrap();

    let (status, listed) = call_json(&server, &server.api_key, "GET", "/api/v1/app-sign-ins").await;
    assert_eq!(status, 200);
    assert_eq!(listed[0]["app"], "MaxNines for Windows");
    assert_eq!(listed[0]["device"], "office PC");
    assert!(listed[0].get("access_hash").is_none());

    let path = format!("/api/v1/app-sign-ins/{}", first.id);
    assert_eq!(
        call_json(&server, &server.api_key, "DELETE", &path).await.0,
        204
    );
    let token = &first_tokens.access_token;
    assert_eq!(call(&server, token, "GET", "/api/v1/hosts").await, 401);

    // An app signs itself out with what it holds.
    let fields = [
        ("token", second_tokens.refresh_token.as_str()),
        ("client_id", "maxnines-tray"),
    ];
    let (status, _) = app_post(&server, "/oauth/revoke", &fields).await;
    assert_eq!(status, 200);
    let token = &second_tokens.access_token;
    assert_eq!(call(&server, token, "GET", "/api/v1/hosts").await, 401);

    let page = Browser::default().get(&server, "/settings/apps").await;
    assert!(page.body.contains("Revoked"), "{}", page.body);
    assert!(!page.body.contains("/revoke\""), "{}", page.body);
}

#[tokio::test]
async fn an_app_is_offered_no_more_than_it_asked_for_and_viewer_if_it_didnt_ask() {
    let server = start().await;
    let mut browser = Browser::default();

    let page = browser
        .get(&server, &authorize_path(BACK, "responder"))
        .await;
    assert!(
        page.body.contains(r#"<option value="responder" selected>"#),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains(r#"<option value="editor""#),
        "{}",
        page.body
    );

    // Not asking isn't asking for everything: one click gives a viewer.
    let page = browser.get(&server, &authorize_path(BACK, "")).await;
    assert!(
        page.body.contains(r#"<option value="viewer" selected>"#),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(r#"<option value="admin""#),
        "{}",
        page.body
    );

    // What it asked for is carried through, so more can't be chosen than was offered.
    let mut fields = approval_fields("admin", "allow");
    fields.push(("role", "responder"));
    let page = browser
        .submit(
            &server,
            &authorize_path(BACK, "responder"),
            "/oauth/authorize",
            &fields,
        )
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
}

#[tokio::test]
async fn only_someone_at_the_pages_can_approve_an_app_and_apps_cant_make_keys() {
    let server = start().await;
    let back = approve(&mut Browser::default(), &server, "admin", "allow").await;
    let (_, tokens) = swap_code(&server, &query_value(&back, "code").unwrap(), VERIFIER).await;
    let access = tokens["access_token"].as_str().unwrap();

    let (status, refused) = call_json(&server, access, "POST", "/api/v1/api-keys").await;
    assert_eq!(status, 403);
    assert_eq!(
        refused["error"],
        "An app signed in through the browser can't make API keys"
    );
    assert!(server.state.database.list_api_keys().await.unwrap().len() == 1);

    // Neither an app nor a key can approve another app.
    for token in [access, server.api_key.as_str()] {
        assert_eq!(
            call(&server, token, "GET", &authorize_path(BACK, "")).await,
            403
        );
        assert_eq!(call(&server, token, "POST", "/device/decide").await, 403);
    }
    // A key can still make a key.
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let body = r#"{"name": "another"}"#;
    let request = format!(
        "POST /api/v1/api-keys HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        server.api_key,
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");
}

#[tokio::test]
async fn using_a_swapped_token_again_never_stretches_its_minute() {
    let server = start().await;
    let database = &server.state.database;
    let owner = database.list_users().await.unwrap()[0].id;
    let now = now_ms();
    let (_, first) = database
        .create_app_sign_in(owner, "maxnines-cli", "", Role::Viewer, now)
        .await
        .unwrap();
    let refresh = |token: String, at: i64| async move {
        database
            .refresh_app_sign_in(&token, "maxnines-cli", at)
            .await
            .unwrap()
    };
    let Refreshed::Issued(_, second) = refresh(first.refresh_token.clone(), now).await else {
        panic!("not refreshed");
    };
    // Its answer was lost, so it's used again inside the minute: that works.
    let half = now + REFRESH_GRACE_MS / 2;
    assert!(matches!(
        refresh(first.refresh_token.clone(), half).await,
        Refreshed::Issued(..)
    ));
    // But the minute still counts from the first swap, so a copy can't be kept alive
    // by using it again and again.
    let after = now + REFRESH_GRACE_MS + 1;
    assert_eq!(
        refresh(first.refresh_token.clone(), after).await,
        Refreshed::Reused
    );
    assert_eq!(
        refresh(second.refresh_token.clone(), after).await,
        Refreshed::Refused
    );
}

#[tokio::test]
async fn two_refreshes_at_once_both_get_tokens_and_the_newest_works() {
    let server = start().await;
    let database = &server.state.database;
    let owner = database.list_users().await.unwrap()[0].id;
    let now = now_ms();
    let (_, first) = database
        .create_app_sign_in(owner, "maxnines-cli", "", Role::Viewer, now)
        .await
        .unwrap();
    let (one, two) = tokio::join!(
        database.refresh_app_sign_in(&first.refresh_token, "maxnines-cli", now),
        database.refresh_app_sign_in(&first.refresh_token, "maxnines-cli", now),
    );
    let (Refreshed::Issued(_, one), Refreshed::Issued(_, two)) = (one.unwrap(), two.unwrap())
    else {
        panic!("not both refreshed");
    };
    // Whichever was saved last is the one that works now.
    let one_works = database
        .accept_app_token(&one.access_token, now)
        .await
        .unwrap();
    let two_works = database
        .accept_app_token(&two.access_token, now)
        .await
        .unwrap();
    assert!(one_works.is_some() != two_works.is_some());
}

#[tokio::test]
async fn someone_who_cant_sign_in_any_more_gets_a_final_no() {
    let server = start().await;
    let (id, mut browser) = person(&server, "leaving@example.com", Role::Viewer).await;
    let back = approve(&mut browser, &server, "viewer", "allow").await;
    server
        .state
        .database
        .disable_user(id, now_ms())
        .await
        .unwrap();
    let (status, refused) =
        swap_code(&server, &query_value(&back, "code").unwrap(), VERIFIER).await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"], "invalid_grant");
    assert_eq!(
        refused["error_description"],
        "The person who approved it can't sign in now"
    );
}

#[tokio::test]
async fn only_your_own_apps_can_be_revoked_and_old_ones_are_cleared_away() {
    let server = start().await;
    let database = &server.state.database;
    let admin = database.list_users().await.unwrap()[0].id;
    let now = now_ms();
    let (theirs, _) = database
        .create_app_sign_in(admin, "maxnines-cli", "admin's laptop", Role::Viewer, now)
        .await
        .unwrap();
    let (viewer, _) = person(&server, "viewer@example.com", Role::Viewer).await;
    let (_, key) = database
        .create_api_key("viewer's", viewer, Role::Viewer, None, now)
        .await
        .unwrap();
    let path = format!("/api/v1/app-sign-ins/{}", theirs.id);
    assert_eq!(call(&server, &key, "DELETE", &path).await, 404);
    let (_, listed) = call_json(&server, &key, "GET", "/api/v1/app-sign-ins").await;
    assert_eq!(listed, json!([]));
    assert!(
        database
            .get_app_sign_in(theirs.id)
            .await
            .unwrap()
            .unwrap()
            .revoked_ms
            .is_none()
    );

    // Revoked long ago, it goes the next time an app signs in.
    database.revoke_app_sign_in(theirs.id, now).await.unwrap();
    let much_later = now + 91 * 24 * 60 * 60 * 1000;
    database
        .create_app_sign_in(
            admin,
            "maxnines-cli",
            "new laptop",
            Role::Viewer,
            much_later,
        )
        .await
        .unwrap();
    assert!(database.get_app_sign_in(theirs.id).await.unwrap().is_none());
    assert_eq!(database.list_app_sign_ins(None).await.unwrap().len(), 1);
}
