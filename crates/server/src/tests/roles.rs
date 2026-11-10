//! Roles: what each may do, on the pages and through the API, and that the server
//! refuses the rest whatever a page shows.

use super::*;
use crate::roles::Role;

const PASSWORD: &str = "a long enough password";

/// Adds someone with this role and a password.
async fn person(server: &TestServer, email: &str, role: Role) -> i64 {
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
    user.id
}

/// A browser signed in as someone new with this role.
async fn browser_as(server: &TestServer, role: Role) -> Browser {
    let email = format!("{}@example.com", role.as_str());
    person(server, &email, role).await;
    let mut browser = Browser::anonymous();
    let fields = [("email", email.as_str()), ("password", PASSWORD)];
    let page = browser.submit(server, "/login", "/login", &fields).await;
    assert_eq!(page.status, 303, "{}", page.body);
    browser
}

/// A key for someone new with this role, which can do as much as they can.
async fn key_as(server: &TestServer, role: Role) -> (i64, String) {
    let email = format!("{}-key@example.com", role.as_str());
    let id = person(server, &email, role).await;
    let database = &server.state.database;
    let (_, key) = database
        .create_api_key("theirs", id, role, None, now_ms())
        .await
        .unwrap();
    (id, key)
}

/// Calls the API with a key, giving back the status and any JSON.
async fn api(server: &TestServer, key: &str, method: &str, path: &str, body: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_viewer_sees_the_pages_but_changes_nothing() {
    let server = start().await;
    let mut viewer = browser_as(&server, Role::Viewer).await;

    for path in [
        "/",
        "/agents",
        "/alerts",
        "/alerts/rules",
        "/rules",
        "/settings",
        "/profile",
    ] {
        assert_eq!(viewer.get(&server, path).await.status, 200, "{path}");
    }
    for path in [
        "/settings/users",
        "/settings/audit-log",
        "/alerts/rules/new",
        "/alerts/silences/new",
    ] {
        let page = viewer.get(&server, path).await;
        assert_eq!(page.status, 403, "{path}");
        assert!(
            page.body.contains("Your role doesn"),
            "{path}: {}",
            page.body
        );
    }
    let token = viewer.get(&server, "/profile").await.token();
    let token = [("authenticity_token", token.as_str())];
    for path in [
        "/alerts/1/acknowledge",
        "/alerts/silences",
        "/alerts/rules",
        "/dashboards",
        "/settings/users",
        "/agents/abc/approve",
        "/agents/abc/delete",
    ] {
        assert_eq!(
            viewer.post(&server, path, &token).await.status,
            403,
            "{path}"
        );
    }
    assert!(
        server
            .state
            .database
            .list_dashboards()
            .await
            .unwrap()
            .is_empty()
    );
    // What isn't there still only says so.
    assert_eq!(viewer.get(&server, "/no-such-page").await.status, 404);
}

#[tokio::test]
async fn everyone_keeps_their_own_profile() {
    let server = start().await;
    let mut viewer = browser_as(&server, Role::Viewer).await;

    let fields = [("theme", "paper")];
    let page = viewer
        .submit(&server, "/profile", "/profile/theme", &fields)
        .await;

    assert_eq!(page.status, 303, "{}", page.body);
}

#[tokio::test]
async fn a_responder_silences_but_does_not_change_rules() {
    let server = start().await;
    let mut responder = browser_as(&server, Role::Responder).await;

    assert_eq!(
        responder.get(&server, "/alerts/silences/new").await.status,
        200
    );
    let fields = [
        ("filter", ""),
        ("reason", "Deploying"),
        ("duration_secs", "3600"),
    ];
    let page = responder
        .submit(&server, "/alerts/silences/new", "/alerts/silences", &fields)
        .await;
    assert_ne!(page.status, 403, "{}", page.body);
    let silences = server
        .state
        .database
        .active_silences(now_ms())
        .await
        .unwrap();
    assert_eq!(silences.len(), 1, "{}", page.body);

    let token = responder.get(&server, "/profile").await.token();
    let token = [("authenticity_token", token.as_str())];
    assert_eq!(
        responder
            .post(&server, "/alerts/rules", &token)
            .await
            .status,
        403
    );
    assert_eq!(
        responder.get(&server, "/alerts/rules/new").await.status,
        403
    );
}

#[tokio::test]
async fn an_editor_changes_the_setup_but_not_people() {
    let server = start().await;
    let mut editor = browser_as(&server, Role::Editor).await;

    let fields = [("name", "Ops")];
    let page = editor
        .submit(&server, "/dashboards", "/dashboards", &fields)
        .await;
    assert_ne!(page.status, 403, "{}", page.body);
    assert_eq!(
        server.state.database.list_dashboards().await.unwrap().len(),
        1
    );

    assert_eq!(editor.get(&server, "/settings/users").await.status, 403);
    assert_eq!(editor.get(&server, "/settings/audit-log").await.status, 403);
    let token = editor.get(&server, "/profile").await.token();
    let token = [("authenticity_token", token.as_str())];
    let page = editor.post(&server, "/agents/abc/delete", &token).await;
    assert_eq!(page.status, 403);
}

#[tokio::test]
async fn the_api_asks_the_same_of_a_key() {
    let server = start().await;
    let (_, viewer) = key_as(&server, Role::Viewer).await;
    let (_, responder) = key_as(&server, Role::Responder).await;
    let (_, editor) = key_as(&server, Role::Editor).await;

    assert_eq!(
        api(&server, &viewer, "GET", "/api/v1/agents", "").await.0,
        200
    );
    let (status, body) = api(
        &server,
        &viewer,
        "POST",
        "/api/v1/dashboards",
        r#"{"name":"x"}"#,
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(
        body["error"],
        "This needs the editor role, and this key acts as a viewer"
    );
    for path in ["/api/v1/users", "/api/v1/users/1", "/api/v1/audit-log"] {
        assert_eq!(
            api(&server, &editor, "GET", path, "").await.0,
            403,
            "{path}"
        );
    }
    assert_eq!(
        api(&server, &editor, "DELETE", "/api/v1/agents/abc", "")
            .await
            .0,
        403
    );

    let silence = r#"{"reason":"Deploying","duration_secs":3600}"#;
    assert_eq!(
        api(&server, &viewer, "POST", "/api/v1/silences", silence)
            .await
            .0,
        403
    );
    assert_eq!(
        api(&server, &responder, "POST", "/api/v1/silences", silence)
            .await
            .0,
        201
    );
    let (status, _) = api(
        &server,
        &responder,
        "POST",
        "/api/v1/dashboards",
        r#"{"name":"x"}"#,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = api(
        &server,
        &editor,
        "POST",
        "/api/v1/dashboards",
        r#"{"name":"x"}"#,
    )
    .await;
    assert_eq!(status, 201);
}

#[tokio::test]
async fn a_key_does_no_more_than_it_was_given_or_its_owner_can() {
    let server = start().await;
    let database = &server.state.database;
    let owner = person(&server, "owner@example.com", Role::Editor).await;
    let (_, reader) = database
        .create_api_key("reader", owner, Role::Viewer, None, now_ms())
        .await
        .unwrap();
    let (_, full) = database
        .create_api_key("full", owner, Role::Editor, None, now_ms())
        .await
        .unwrap();
    let dashboard = r#"{"name":"x"}"#;

    // A reading key from someone who could do more still only reads.
    assert_eq!(
        api(&server, &reader, "POST", "/api/v1/dashboards", dashboard)
            .await
            .0,
        403
    );
    assert_eq!(
        api(&server, &full, "POST", "/api/v1/dashboards", dashboard)
            .await
            .0,
        201
    );
    // Nobody is given a key that does more than they can.
    let admin_key = database.create_api_key("too much", owner, Role::Admin, None, now_ms());
    assert!(admin_key.await.is_err());

    // Their keys follow them down.
    database.set_role(owner, Role::Viewer).await.unwrap();
    assert_eq!(
        api(&server, &full, "POST", "/api/v1/dashboards", dashboard)
            .await
            .0,
        403
    );
    assert_eq!(
        api(&server, &full, "GET", "/api/v1/dashboards", "").await.0,
        200
    );
}

#[tokio::test]
async fn a_key_cannot_make_a_key_that_does_more() {
    let server = start().await;
    let (_, editor) = key_as(&server, Role::Editor).await;

    let (status, _) = api(
        &server,
        &editor,
        "POST",
        "/api/v1/api-keys",
        r#"{"name":"up","role":"admin"}"#,
    )
    .await;
    assert_eq!(status, 403);
    let (status, made) = api(
        &server,
        &editor,
        "POST",
        "/api/v1/api-keys",
        r#"{"name":"same"}"#,
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(made["role"], "editor");
    let (status, made) = api(
        &server,
        &editor,
        "POST",
        "/api/v1/api-keys",
        r#"{"name":"less","role":"viewer"}"#,
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(made["role"], "viewer");
    // The page refuses the same.
    let mut browser = browser_as(&server, Role::Responder).await;
    let fields = [("name", "up"), ("role", "admin"), ("lifetime", "")];
    let page = browser
        .submit(&server, "/settings/api-keys", "/settings/api-keys", &fields)
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(page.body.contains("more than you can"));
}

#[tokio::test]
async fn people_see_and_revoke_only_their_own_keys_unless_they_are_admins() {
    let server = start().await;
    let (_, editor) = key_as(&server, Role::Editor).await;
    let (_, viewer) = key_as(&server, Role::Viewer).await;

    let (_, mine) = api(&server, &viewer, "GET", "/api/v1/api-keys", "").await;
    let mine = mine.as_array().unwrap();
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0]["owner"], "viewer-key@example.com");
    let (_, all) = api(&server, &server.api_key, "GET", "/api/v1/api-keys", "").await;
    assert_eq!(all.as_array().unwrap().len(), 3);

    let theirs = all
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["owner"] == "editor-key@example.com");
    let path = format!("/api/v1/api-keys/{}", theirs.unwrap()["id"]);
    assert_eq!(api(&server, &viewer, "DELETE", &path, "").await.0, 404);
    assert_eq!(
        api(&server, &editor, "GET", "/api/v1/agents", "").await.0,
        200
    );
    assert_eq!(
        api(&server, &server.api_key, "DELETE", &path, "").await.0,
        204
    );
    assert_eq!(
        api(&server, &editor, "GET", "/api/v1/agents", "").await.0,
        401
    );
}

#[tokio::test]
async fn an_admin_changes_roles_but_one_admin_always_remains() {
    let server = start().await;
    let database = &server.state.database;
    let admin = server.user_id().await;
    let other = person(&server, "other@example.com", Role::Viewer).await;
    let mut browser = Browser::default();

    let path = format!("/settings/users/{other}/role");
    let page = browser
        .submit(&server, "/settings/users", &path, &[("role", "editor")])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(
        database.user(other).await.unwrap().unwrap().role,
        Role::Editor
    );

    let path = format!("/settings/users/{admin}/role");
    let page = browser
        .submit(&server, "/settings/users", &path, &[("role", "viewer")])
        .await;
    assert_eq!(page.status, 422, "{}", page.body);
    assert!(
        page.body.contains("no admin able to sign in"),
        "{}",
        page.body
    );
    assert_eq!(
        database.user(admin).await.unwrap().unwrap().role,
        Role::Admin
    );

    // With another admin, the first can step down.
    let body = r#"{"role":"admin"}"#;
    let path = format!("/api/v1/users/{other}");
    assert_eq!(
        api(&server, &server.api_key, "PUT", &path, body).await.0,
        204
    );
    let path = format!("/api/v1/users/{admin}");
    assert_eq!(
        api(
            &server,
            &server.api_key,
            "PUT",
            &path,
            r#"{"role":"viewer"}"#
        )
        .await
        .0,
        204
    );
    // Which their own key feels at once.
    assert_eq!(
        api(&server, &server.api_key, "GET", "/api/v1/users", "")
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn the_api_adds_people_as_viewers_unless_told() {
    let server = start().await;
    let key = &server.api_key;

    let (status, made) = api(
        &server,
        key,
        "POST",
        "/api/v1/users",
        r#"{"email":"a@example.com","name":"A"}"#,
    )
    .await;
    assert_eq!(status, 201, "{made}");
    assert_eq!(made["user"]["role"], "viewer");
    let (_, made) = api(
        &server,
        key,
        "POST",
        "/api/v1/users",
        r#"{"email":"b@example.com","name":"B","role":"responder"}"#,
    )
    .await;
    assert_eq!(made["user"]["role"], "responder");
    let (status, _) = api(
        &server,
        key,
        "POST",
        "/api/v1/users",
        r#"{"email":"c@example.com","name":"C","role":"owner"}"#,
    )
    .await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn a_role_change_is_in_the_audit_log() {
    let server = start().await;
    let database = &server.state.database;
    let other = person(&server, "other@example.com", Role::Viewer).await;

    database.set_role(other, Role::Responder).await.unwrap();

    let entry = &database.audit_log(None, 1).await.unwrap()[0];
    assert_eq!(entry.subject.name, "other@example.com");
    assert_eq!(entry.changes[0].field, "role");
    assert_eq!(entry.changes[0].before, Some(json!("viewer")));
    assert_eq!(entry.changes[0].after, Some(json!("responder")));
}

#[tokio::test]
async fn the_pages_only_offer_what_a_role_allows() {
    let server = start().await;
    let database = &server.state.database;
    let rule = crate::locations::LocationRuleInput {
        name: "Office".into(),
        filter: String::new(),
        place: "London".into(),
        latitude: 51.5,
        longitude: -0.1,
        priority: 0,
    };
    let rule = database.create_location_rule(&rule).await.unwrap();
    let mut viewer = browser_as(&server, Role::Viewer).await;
    let mut admin = Browser::default();

    // A viewer can open what's there to read it, without a way to save it.
    let path = format!("/map/rules/{rule}/edit");
    let page = viewer.get(&server, &path).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Office"));
    assert!(!page.body.contains("Save location"), "{}", page.body);
    assert!(!page.body.contains("Delete location"));
    assert!(page.body.contains("but not change it"));
    let page = admin.get(&server, &path).await;
    assert!(page.body.contains("Save location") && page.body.contains("Delete location"));

    for (path, offer) in [
        ("/map/rules", "Add a location"),
        ("/alerts/rules", "New rule"),
        ("/alerts/channels", "New channel"),
        ("/alerts/silences", "New silence"),
        ("/dashboards", "Create dashboard"),
        ("/settings", "Audit log"),
        ("/settings", "/settings/users"),
    ] {
        let seen = viewer.get(&server, path).await;
        assert!(
            !seen.body.contains(offer),
            "a viewer is offered {offer} on {path}"
        );
        let seen = admin.get(&server, path).await;
        assert!(
            seen.body.contains(offer),
            "an admin isn't offered {offer} on {path}"
        );
    }
}
