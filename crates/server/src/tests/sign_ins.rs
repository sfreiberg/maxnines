//! Who's signed in: the list admins see under Settings, Users, Sign-ins, the one each
//! person sees on their profile, and ending what's there.

use super::app_sign_ins::{PASSWORD, call_json, person};
use super::*;
use crate::roles::Role;

const CHROME_ON_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// The one sign-in of this kind belonging to `email` in a list from the API.
fn find<'a>(listed: &'a Value, kind: &str, email: &str) -> &'a Value {
    let all = listed.as_array().unwrap();
    let mut found = all
        .iter()
        .filter(|row| row["kind"] == kind && row["user"] == email);
    let row = found
        .next()
        .unwrap_or_else(|| panic!("no {kind} for {email} in {listed}"));
    assert!(
        found.next().is_none(),
        "more than one {kind} for {email} in {listed}"
    );
    row
}

#[tokio::test]
async fn admins_see_everyone_signed_in_and_from_where() {
    let server = start().await;
    let database = &server.state.database;
    let (editor, _browser) = person(&server, "editor@example.com", Role::Editor).await;
    let (_, app) = database
        .create_app_sign_in(
            editor,
            "maxnines-cli",
            Some("laptop"),
            Role::Viewer,
            crate::times::now(),
        )
        .await
        .unwrap();
    // Used once, so the address it came from is noted.
    let (status, _) = call_json(&server, &app.access_token, "GET", "/api/v1/me").await;
    assert_eq!(status, 200);
    let (unused, _) = database
        .create_api_key(
            "never used",
            editor,
            Role::Viewer,
            None,
            crate::times::now(),
        )
        .await
        .unwrap();

    let (status, listed) = call_json(&server, &server.api_key, "GET", "/api/v1/sign-ins").await;
    assert_eq!(status, 200, "{listed}");
    let browser = find(&listed, "browser", "editor@example.com");
    assert_eq!(browser["role"], "editor");
    assert_eq!(browser["address"], "127.0.0.1");
    assert_eq!(browser["current"], false);
    assert!(browser["last_used_at"].is_string(), "{browser}");
    let app_row = find(&listed, "app", "editor@example.com");
    assert_eq!(app_row["name"], "MaxNines command line on laptop");
    // An app does no more than it was allowed, even for someone who could.
    assert_eq!(app_row["role"], "viewer");
    assert_eq!(app_row["address"], "127.0.0.1");
    // The key making this request is in use; one never used isn't signed in.
    let key = find(&listed, "api_key", "test@example.com");
    assert_eq!(key["name"], "tests");
    let all = listed.as_array().unwrap();
    assert!(
        !all.iter()
            .any(|row| row["kind"] == "api_key" && row["id"] == unused.id)
    );

    let page = Browser::default()
        .get(&server, "/settings/users/sign-ins")
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("editor@example.com"), "{}", page.body);
    assert!(
        page.body.contains("MaxNines command line on laptop"),
        "{}",
        page.body
    );
    assert!(page.body.contains("127.0.0.1"), "{}", page.body);
    assert!(page.body.contains("this browser"), "{}", page.body);
    assert!(page.has_only_our_scripts());
}

#[tokio::test]
async fn a_browser_is_named_and_noted_where_it_was_last_used() {
    let server = start().await;
    let database = &server.state.database;
    let owner = database.list_users().await.unwrap()[0].id;
    database
        .start_session(owner, crate::times::now(), Some(CHROME_ON_MAC))
        .await
        .unwrap();
    let (_, listed) = call_json(&server, &server.api_key, "GET", "/api/v1/sign-ins").await;
    let all = listed.as_array().unwrap();
    let row = all
        .iter()
        .find(|row| row["kind"] == "browser" && row["name"] == "Chrome 131 on macOS")
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(row["user_agent"], CHROME_ON_MAC);
}

#[tokio::test]
async fn a_browser_that_updates_is_named_by_its_new_version() {
    let server = start().await;
    let database = &server.state.database;
    let owner = database.list_users().await.unwrap()[0].id;
    let token = database
        .start_session(owner, crate::times::now(), Some(CHROME_ON_MAC))
        .await
        .unwrap();
    let updated = CHROME_ON_MAC.replace("Chrome/131", "Chrome/132");
    // Straight after signing in, so only the new version makes it worth saving.
    database
        .session(&token, Some(&updated), crate::times::now())
        .await
        .unwrap()
        .unwrap();
    let (_, listed) = call_json(&server, &server.api_key, "GET", "/api/v1/sign-ins").await;
    // The test server's own browser said nothing about itself.
    let row = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == "browser" && !row["user_agent"].is_null())
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(row["name"], "Chrome 132 on macOS", "{listed}");
    assert_eq!(row["user_agent"], updated.as_str());
    let page = Browser::default()
        .get(&server, "/settings/users/sign-ins")
        .await;
    assert!(page.body.contains("What it says it is"), "{}", page.body);
    assert!(page.body.contains("Chrome/132.0.0.0"), "{}", page.body);
}

#[tokio::test]
async fn people_see_and_end_only_their_own() {
    let server = start().await;
    let database = &server.state.database;
    let (viewer, mut first) = person(&server, "viewer@example.com", Role::Viewer).await;
    let mut second = Browser::anonymous();
    let fields = [("email", "viewer@example.com"), ("password", PASSWORD)];
    let page = second.submit(&server, "/login", "/login", &fields).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let (_, app) = database
        .create_app_sign_in(
            viewer,
            "maxnines-cli",
            Some("laptop"),
            Role::Viewer,
            crate::times::now(),
        )
        .await
        .unwrap();

    // Their own list has their two browsers and their app, and nobody else's.
    let (status, theirs) = call_json(&server, &app.access_token, "GET", "/api/v1/sign-ins").await;
    assert_eq!(status, 200, "{theirs}");
    let rows = theirs.as_array().unwrap();
    assert!(
        rows.iter().all(|row| row["user"] == "viewer@example.com"),
        "{theirs}"
    );
    let browsers: Vec<i64> = rows
        .iter()
        .filter(|row| row["kind"] == "browser")
        .map(|row| row["id"].as_i64().unwrap())
        .collect();
    assert_eq!(browsers.len(), 2, "{theirs}");
    let page = first.get(&server, "/profile").await;
    assert!(
        page.body.contains("Where you're signed in"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("MaxNines command line on laptop"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("test@example.com"), "{}", page.body);

    // The admin's own browser isn't theirs to end, nor is the admins' page theirs to see.
    let (_, everyone) = call_json(&server, &server.api_key, "GET", "/api/v1/sign-ins").await;
    let admins = find(&everyone, "browser", "test@example.com")["id"]
        .as_i64()
        .unwrap();
    let path = format!("/profile/sign-ins/browser/{admins}/end");
    assert_eq!(
        first.submit(&server, "/profile", &path, &[]).await.status,
        404
    );
    let path = format!("/api/v1/sign-ins/browser/{admins}");
    assert_eq!(
        call_json(&server, &app.access_token, "DELETE", &path)
            .await
            .0,
        404
    );
    assert_eq!(
        first.get(&server, "/settings/users/sign-ins").await.status,
        403
    );

    // Ending their other browser signs it out at once.
    let first_id = session_id(&first, &server).await;
    let other = browsers.into_iter().find(|id| *id != first_id).unwrap();
    let path = format!("/profile/sign-ins/browser/{other}/end");
    let page = first
        .submit(&server, "/profile", &path, &[("back", "/profile")])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(page.header("location"), Some("/profile"));
    assert_eq!(second.get(&server, "/profile").await.status, 303);

    // Ending their app revokes it.
    let (_, mine) = call_json(&server, &app.access_token, "GET", "/api/v1/sign-ins").await;
    let app_id = find(&mine, "app", "viewer@example.com")["id"]
        .as_i64()
        .unwrap();
    let path = format!("/profile/sign-ins/app/{app_id}/end");
    assert_eq!(
        first.submit(&server, "/profile", &path, &[]).await.status,
        303
    );
    assert_eq!(
        call_json(&server, &app.access_token, "GET", "/api/v1/me")
            .await
            .0,
        401
    );

    // And ending this browser's own sign-in signs it out.
    let path = format!("/profile/sign-ins/browser/{first_id}/end");
    let page = first.submit(&server, "/profile", &path, &[]).await;
    assert_eq!(page.header("location"), Some("/login"));
    assert_eq!(first.get(&server, "/profile").await.status, 303);
}

/// The browser session a browser is signed in with.
async fn session_id(browser: &Browser, server: &TestServer) -> i64 {
    let token = &browser.cookies["maxnines_session"];
    let found = server
        .state
        .database
        .session(token, None, crate::times::now())
        .await
        .unwrap();
    found.unwrap().1
}

#[tokio::test]
async fn an_admin_ends_anyones_and_it_is_recorded() {
    let server = start().await;
    let (_, mut theirs) = person(&server, "someone@example.com", Role::Responder).await;
    let (_, listed) = call_json(&server, &server.api_key, "GET", "/api/v1/sign-ins").await;
    let id = find(&listed, "browser", "someone@example.com")["id"]
        .as_i64()
        .unwrap();

    let path = format!("/api/v1/sign-ins/browser/{id}");
    assert_eq!(
        call_json(&server, &server.api_key, "DELETE", &path).await.0,
        204
    );
    assert_eq!(theirs.get(&server, "/profile").await.status, 303);
    assert_eq!(
        call_json(&server, &server.api_key, "DELETE", &path).await.0,
        404
    );
    let path = "/api/v1/sign-ins/nonsense/1";
    assert_eq!(
        call_json(&server, &server.api_key, "DELETE", path).await.0,
        404
    );

    let (_, log) = call_json(&server, &server.api_key, "GET", "/api/v1/audit-log").await;
    let entries = log["entries"].as_array().or(log.as_array()).unwrap();
    assert!(
        entries.iter().any(|entry| entry["action"] == "signed_out"
            && entry["subject"]["name"] == "someone@example.com"
            && entry["actor"]["name"] == "test@example.com"),
        "{log}"
    );
}
