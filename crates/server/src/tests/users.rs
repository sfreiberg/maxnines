//! Signing in, and who can get at what.

use super::*;
use crate::models::UserChange;

const PASSWORD: &str = "a long enough password";

/// Adds someone with a password, ready to sign in.
async fn person(server: &TestServer, email: &str) -> i64 {
    let database = &server.state.database;
    let (user, link) = database
        .create_user(email, "Someone", now_ms())
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

/// Calls the API with the admin token, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

/// The session cookie a response sets, among any others.
fn session_cookie(page: &Page) -> Option<&str> {
    page.headers.lines().find_map(|line| {
        let cookie = line.get("set-cookie: ".len()..)?;
        cookie.starts_with("maxnines_session=").then_some(cookie)
    })
}

async fn sign_in(server: &TestServer, browser: &mut Browser, email: &str, password: &str) -> Page {
    let fields = [("email", email), ("password", password)];
    browser.submit(server, "/login", "/login", &fields).await
}

async fn signed_in(server: &TestServer, email: &str) -> Browser {
    let mut browser = Browser::anonymous();
    let page = sign_in(server, &mut browser, email, PASSWORD).await;
    assert_eq!(page.status, 303, "{}", page.body);
    browser
}

#[tokio::test]
async fn every_page_needs_someone_signed_in() {
    let server = start().await;
    for path in [
        "/",
        "/agents",
        "/agents/nope",
        "/metrics",
        "/checks",
        "/alerts",
        "/rules",
        "/settings",
        "/server",
        "/settings/users",
        "/settings/api-keys",
        "/settings/audit-log",
        "/profile",
        "/no-such-page",
    ] {
        let page = Browser::anonymous().get(&server, path).await;
        assert_eq!(page.status, 303, "{path}");
        let to = page.header("location").unwrap();
        assert!(to.starts_with("/login?next="), "{path}: {to}");
        assert!(!page.body.contains("MaxNines "), "{path}");
    }
}

#[tokio::test]
async fn forms_need_someone_signed_in_too() {
    let server = start().await;
    let mut browser = Browser::anonymous();
    // A real CSRF token, so only the missing sign in can stop this.
    let token = browser.get(&server, "/login").await.token();
    let page = browser
        .post(
            &server,
            "/settings/users",
            &[
                ("authenticity_token", &token),
                ("email", "new@example.com"),
                ("name", "New"),
            ],
        )
        .await;

    assert_eq!(page.status, 303);
    let users = server.state.database.list_users().await.unwrap();
    assert!(!users.iter().any(|user| user.email == "new@example.com"));
}

#[tokio::test]
async fn what_signing_in_needs_stays_open() {
    let server = start().await;
    for path in [
        "/login",
        "/assets/css/application.css",
        "/assets/manifest.webmanifest",
        "/assets/js/theme.js",
    ] {
        let page = Browser::anonymous().get(&server, path).await;
        assert_eq!(page.status, 200, "{path}");
    }
}

#[tokio::test]
async fn the_api_still_answers_to_its_own_tokens() {
    let server = start().await;
    let page = Browser::anonymous().get(&server, "/api/v1/agents").await;
    assert_eq!(page.status, 401);
    assert_eq!(
        api(&server, "GET", "/api/v1/agents", &Value::Null).await.0,
        200
    );
    // A session isn't a key.
    let page = Browser::default().get(&server, "/api/v1/agents").await;
    assert_eq!(page.status, 401);
}

#[tokio::test]
async fn a_page_updating_itself_leaves_for_the_sign_in_page() {
    let server = start().await;
    let request = "GET /agents HTTP/1.1\r\nHost: x\r\nHX-Request: true\r\n\
                   Connection: close\r\n\r\n";
    let page = Browser::anonymous()
        .send(&server, request.to_string())
        .await;

    assert_eq!(page.status, 401);
    assert_eq!(page.header("hx-redirect"), Some("/login?next=%2Fagents"));
    assert!(!page.body.contains("<form"));
}

#[tokio::test]
async fn a_form_being_filled_in_survives_a_session_running_out() {
    let server = start().await;
    let page = Browser::anonymous()
        .get(&server, "/update-notice?build=same")
        .await;
    assert_ne!(page.status, 303);
    assert!(page.header("hx-redirect").is_none());
}

#[tokio::test]
async fn signing_in_opens_the_page_that_was_wanted() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut browser = Browser::anonymous();

    let to = browser.get(&server, "/agents?view=table").await;
    let to = to.header("location").unwrap().to_string();
    let form = browser.get(&server, &to).await;
    assert!(
        form.body
            .contains(r#"name="next" value="/agents?view=table""#)
    );
    let page = browser
        .post(
            &server,
            "/login",
            &[
                ("authenticity_token", &form.token()),
                ("email", "A@Example.com "),
                ("password", PASSWORD),
                ("next", "/agents?view=table"),
            ],
        )
        .await;

    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(page.header("location"), Some("/agents?view=table"));
    assert_eq!(browser.get(&server, "/agents").await.status, 200);
}

#[tokio::test]
async fn sessions_are_kept_in_a_cookie_scripts_cannot_read() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let page = sign_in(
        &server,
        &mut Browser::anonymous(),
        "a@example.com",
        PASSWORD,
    )
    .await;

    let cookie = session_cookie(&page).unwrap();
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(cookie.contains("Path=/"), "{cookie}");
    assert!(
        cookie.contains("Secure"),
        "the test server's address is wss"
    );
}

#[tokio::test]
async fn a_site_on_plain_http_can_still_keep_a_session() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut state = server.state.clone();
    state.audience = "ws://192.168.0.2:9000/ws".into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = app(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    let plain = TestServer {
        address,
        session: String::new(),
        api_key: server.api_key.clone(),
        state: server.state.clone(),
        saved: Saved::default(),
        _folder: None,
    };

    let mut browser = Browser::anonymous();
    let page = sign_in(&plain, &mut browser, "a@example.com", PASSWORD).await;

    // A browser would refuse to keep a Secure cookie from a plain address.
    assert!(!session_cookie(&page).unwrap().contains("Secure"));
}

#[tokio::test]
async fn a_wrong_password_and_an_unknown_address_look_the_same() {
    let server = start().await;
    person(&server, "a@example.com").await;

    let wrong = sign_in(
        &server,
        &mut Browser::anonymous(),
        "a@example.com",
        "not the password",
    )
    .await;
    let unknown = sign_in(
        &server,
        &mut Browser::anonymous(),
        "b@example.com",
        PASSWORD,
    )
    .await;

    for page in [&wrong, &unknown] {
        assert_eq!(page.status, 401);
        assert!(page.body.contains("That email or password isn"));
        assert_eq!(session_cookie(page), None);
    }
}

#[tokio::test]
async fn someone_who_never_set_a_password_cannot_sign_in() {
    let server = start().await;
    let database = &server.state.database;
    database
        .create_user("new@example.com", "New", now_ms())
        .await
        .unwrap();

    for guess in ["", "there is no password here"] {
        let page = sign_in(&server, &mut Browser::anonymous(), "new@example.com", guess).await;
        assert_eq!(page.status, 401, "{guess:?}");
    }
}

#[tokio::test]
async fn guessing_passwords_soon_stops_working() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut browser = Browser::anonymous();

    for _ in 0..5 {
        let page = sign_in(&server, &mut browser, "a@example.com", "wrong guess").await;
        assert_eq!(page.status, 401);
    }
    // Even the right password, or a guess could be confirmed by getting in.
    let page = sign_in(&server, &mut browser, "a@example.com", PASSWORD).await;
    assert_eq!(page.status, 429);
    assert!(page.body.contains("Too many attempts"));
}

#[tokio::test]
async fn signing_in_needs_a_csrf_token() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let fields = [("email", "a@example.com"), ("password", PASSWORD)];

    let page = Browser::anonymous().post(&server, "/login", &fields).await;

    assert_eq!(page.status, 403);
}

#[tokio::test]
async fn signing_out_ends_the_session_on_the_server() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut browser = signed_in(&server, "a@example.com").await;
    let stolen = browser.cookies["maxnines_session"].clone();

    let page = browser.submit(&server, "/profile", "/logout", &[]).await;
    assert_eq!(page.status, 303);
    assert_eq!(page.header("location"), Some("/login"));

    // Even someone who kept a copy of the cookie is out.
    let mut thief = Browser::anonymous();
    thief.cookies.insert("maxnines_session".to_string(), stolen);
    assert_eq!(thief.get(&server, "/agents").await.status, 303);
}

#[tokio::test]
async fn a_session_runs_out() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let database = &server.state.database;
    let long_ago = now_ms() - crate::models::SESSION_LIFETIME_MS - 1000;
    let token = database.start_session(id, long_ago).await.unwrap();

    assert!(
        database
            .session_user(&token, now_ms())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sessions_and_links_are_only_stored_as_hashes() {
    let server = start().await;
    let database = &server.state.database;
    let (user, link) = database
        .create_user("a@example.com", "A", now_ms())
        .await
        .unwrap()
        .unwrap();
    let session = database.start_session(user.id, now_ms()).await.unwrap();

    let saved = database.saved_secrets().await.join("\n");
    assert!(!saved.is_empty());
    assert!(!saved.contains(&link), "{saved}");
    assert!(!saved.contains(&session), "{saved}");
}

#[tokio::test]
async fn someone_new_sets_their_own_password_from_a_link() {
    let server = start().await;
    let mut admin = Browser::default();
    let page = admin
        .submit(
            &server,
            "/settings/users",
            "/settings/users",
            &[("email", "New@Example.com"), ("name", "New Person")],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert_eq!(page.header("cache-control"), Some("no-store"));
    let start = page.body.find("http://site.test/setup/").unwrap();
    let link = page.body[start..].split('<').next().unwrap();
    let path = link.strip_prefix("http://site.test").unwrap().to_string();

    // A refresh of the list doesn't show it again.
    let again = admin.get(&server, "/settings/users").await;
    assert!(!again.body.contains(&path));
    assert!(again.body.contains("new@example.com"));
    assert!(again.body.contains("Invited"));

    let mut newcomer = Browser::anonymous();
    let form = newcomer.get(&server, &path).await;
    assert_eq!(form.status, 200);
    assert_eq!(form.header("cache-control"), Some("no-store"));
    assert_eq!(form.header("referrer-policy"), Some("no-referrer"));

    let short = [("password", "too short"), ("confirm", "too short")];
    let page = newcomer.submit(&server, &path, &path, &short).await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("at least 12"));
    let different = [
        ("password", PASSWORD),
        ("confirm", "something else entirely"),
    ];
    let page = newcomer.submit(&server, &path, &path, &different).await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("match"));

    let good = [("password", PASSWORD), ("confirm", PASSWORD)];
    let page = newcomer.submit(&server, &path, &path, &good).await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(newcomer.get(&server, "/agents").await.status, 200);

    // It only works once.
    let page = Browser::anonymous().get(&server, &path).await;
    assert_eq!(page.status, 404);
    assert!(page.body.contains("stopped working"));

    signed_in(&server, "new@example.com").await;
}

#[tokio::test]
async fn an_old_setup_link_stops_working() {
    let server = start().await;
    let database = &server.state.database;
    let week_ago = now_ms() - 8 * 24 * 60 * 60 * 1000;
    let (_, link) = database
        .create_user("a@example.com", "A", week_ago)
        .await
        .unwrap()
        .unwrap();

    let page = Browser::anonymous()
        .get(&server, &format!("/setup/{link}"))
        .await;

    assert_eq!(page.status, 404);
}

#[tokio::test]
async fn a_new_link_replaces_the_old_one_and_resets_a_password() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let mut browser = signed_in(&server, "a@example.com").await;
    let database = &server.state.database;

    let first = database
        .new_setup_link(id, now_ms())
        .await
        .unwrap()
        .unwrap();
    let second = database
        .new_setup_link(id, now_ms())
        .await
        .unwrap()
        .unwrap();
    let page = Browser::anonymous()
        .get(&server, &format!("/setup/{first}"))
        .await;
    assert_eq!(page.status, 404);

    // The old password still works until the link is used.
    assert_eq!(browser.get(&server, "/agents").await.status, 200);

    let path = format!("/setup/{second}");
    let new = "a completely new password";
    let fields = [("password", new), ("confirm", new)];
    let page = Browser::anonymous()
        .submit(&server, &path, &path, &fields)
        .await;
    assert_eq!(page.status, 303);

    assert_eq!(browser.get(&server, "/agents").await.status, 303);
    let page = sign_in(
        &server,
        &mut Browser::anonymous(),
        "a@example.com",
        PASSWORD,
    )
    .await;
    assert_eq!(page.status, 401);
    let page = sign_in(&server, &mut Browser::anonymous(), "a@example.com", new).await;
    assert_eq!(page.status, 303);
}

#[tokio::test]
async fn disabling_someone_signs_them_out_at_once() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let mut browser = signed_in(&server, "a@example.com").await;
    assert_eq!(browser.get(&server, "/agents").await.status, 200);

    let page = Browser::default()
        .submit(
            &server,
            "/settings/users",
            &format!("/settings/users/{id}/disable"),
            &[],
        )
        .await;
    assert_eq!(page.status, 303);

    assert_eq!(browser.get(&server, "/agents").await.status, 303);
    let page = sign_in(
        &server,
        &mut Browser::anonymous(),
        "a@example.com",
        PASSWORD,
    )
    .await;
    assert_eq!(page.status, 401);
    let link = server.state.database.new_setup_link(id, now_ms()).await;
    let page = Browser::anonymous()
        .get(&server, &format!("/setup/{}", link.unwrap().unwrap()))
        .await;
    assert_eq!(page.status, 404, "a link can't let them back in");

    server.state.database.enable_user(id).await.unwrap();
    signed_in(&server, "a@example.com").await;
}

#[tokio::test]
async fn a_sign_in_finishing_just_as_someone_is_disabled_does_not_count() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let database = &server.state.database;
    database.disable_user(id, now_ms()).await.unwrap();

    let token = database.start_session(id, now_ms()).await.unwrap();

    let user = database.session_user(&token, now_ms()).await.unwrap();
    assert_eq!(user, None);
}

#[tokio::test]
async fn nobody_can_lock_everyone_out() {
    let server = start().await;
    let users = server.state.database.list_users().await.unwrap();
    let me = users[0].id;

    // There's nobody else, through the page or the API.
    let path = format!("/settings/users/{me}/disable");
    let page = Browser::default()
        .submit(&server, "/settings/users", &path, &[])
        .await;
    assert_eq!(page.status, 422);
    let path = format!("/api/v1/users/{me}/disable");
    assert_eq!(api(&server, "POST", &path, &Value::Null).await.0, 409);

    let id = person(&server, "a@example.com").await;
    let change = server.state.database.disable_user(id, now_ms()).await;
    assert_eq!(change.unwrap(), UserChange::Done);
    let change = server.state.database.disable_user(me, now_ms()).await;
    assert_eq!(change.unwrap(), UserChange::LastUser);
}

#[tokio::test]
async fn nobody_can_disable_themselves() {
    let server = start().await;
    person(&server, "other@example.com").await;
    let users = server.state.database.list_users().await.unwrap();
    let me = users.iter().find(|user| user.email == "test@example.com");

    let path = format!("/settings/users/{}/disable", me.unwrap().id);
    let mut browser = Browser::default();
    let page = browser.submit(&server, "/settings/users", &path, &[]).await;

    assert_eq!(page.status, 422);
    assert_eq!(browser.get(&server, "/agents").await.status, 200);
}

#[tokio::test]
async fn deleting_someone_takes_two_steps() {
    let server = start().await;
    let id = person(&server, "a@example.com").await;
    let path = format!("/settings/users/{id}/delete");

    let page = Browser::default()
        .submit(&server, "/settings/users", &path, &[])
        .await;
    assert_eq!(page.status, 422);

    server
        .state
        .database
        .disable_user(id, now_ms())
        .await
        .unwrap();
    let page = Browser::default()
        .submit(&server, "/settings/users", &path, &[])
        .await;
    assert_eq!(page.status, 303);
    assert!(server.state.database.user(id).await.unwrap().is_none());
}

#[tokio::test]
async fn changing_a_password_signs_out_everywhere_else() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut here = signed_in(&server, "a@example.com").await;
    let mut elsewhere = signed_in(&server, "a@example.com").await;
    let new = "a completely new password";

    let fields = [
        ("current", "not it at all"),
        ("password", new),
        ("confirm", new),
    ];
    let page = here
        .submit(&server, "/profile", "/profile/password", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("current password"));
    assert_eq!(elsewhere.get(&server, "/agents").await.status, 200);

    let fields = [("current", PASSWORD), ("password", new), ("confirm", new)];
    let page = here
        .submit(&server, "/profile", "/profile/password", &fields)
        .await;
    assert_eq!(page.status, 200, "{}", page.body);

    assert_eq!(here.get(&server, "/agents").await.status, 200);
    assert_eq!(elsewhere.get(&server, "/agents").await.status, 303);
    let page = sign_in(&server, &mut Browser::anonymous(), "a@example.com", new).await;
    assert_eq!(page.status, 303);
}

#[tokio::test]
async fn a_theme_belongs_to_a_person_and_needs_no_scripts() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut browser = signed_in(&server, "a@example.com").await;

    let page = browser.get(&server, "/agents").await;
    assert!(page.body.contains(r#"data-theme="carbon""#));

    let fields = [("theme", "paper")];
    let page = browser
        .submit(&server, "/profile", "/profile/theme", &fields)
        .await;
    assert_eq!(page.status, 303);

    // Right from the server, so the page never draws in the wrong colours.
    let page = browser.get(&server, "/agents").await;
    assert!(
        page.body
            .contains(r#"<html lang="en" data-choice="paper" data-theme="paper">"#)
    );
    let page = Browser::default().get(&server, "/agents").await;
    assert!(page.body.contains(r#"data-theme="carbon""#), "someone else");

    let mut other_device = signed_in(&server, "a@example.com").await;
    let page = other_device.get(&server, "/agents").await;
    assert!(page.body.contains(r#"data-theme="paper""#));

    let page = browser
        .submit(
            &server,
            "/profile",
            "/profile/theme",
            &[("theme", "system")],
        )
        .await;
    assert_eq!(page.status, 303);
    let page = browser.get(&server, "/agents").await;
    assert!(
        page.body.contains(r#"data-choice="system">"#),
        "the browser decides"
    );

    let fields = [("theme", r#""><script>alert(1)</script>"#)];
    let page = browser
        .submit(&server, "/profile", "/profile/theme", &fields)
        .await;
    assert_eq!(page.status, 422);
}

#[tokio::test]
async fn each_person_sees_times_in_their_own_time_zone() {
    let server = start().await;
    person(&server, "a@example.com").await;
    let mut browser = signed_in(&server, "a@example.com").await;

    // Their own last sign in is on the users page.
    let page = browser.get(&server, "/settings/users").await;
    assert!(page.body.contains(" UTC</td>"), "{}", page.body);
    let page = browser.get(&server, "/profile").await;
    assert!(page.body.contains(r#"name="time_zone" value="UTC""#));

    let fields = [("time_zone", " Asia/Kolkata ")];
    let page = browser
        .submit(&server, "/profile", "/profile/time-zone", &fields)
        .await;
    assert_eq!(page.status, 303);

    let page = browser.get(&server, "/settings/users").await;
    assert!(page.body.contains(" IST</td>"), "{}", page.body);
    let page = browser.get(&server, "/server").await;
    assert!(page.body.contains("Times are in Asia/Kolkata."));
    let page = browser.get(&server, "/profile").await;
    assert!(
        page.body
            .contains(r#"name="time_zone" value="Asia/Kolkata""#)
    );

    let page = Browser::default().get(&server, "/server").await;
    assert!(page.body.contains("Times are in UTC."), "someone else");

    let fields = [("time_zone", "<b>Mars/Olympus</b>")];
    let page = browser
        .submit(&server, "/profile", "/profile/time-zone", &fields)
        .await;
    assert_eq!(page.status, 422);
    assert!(
        page.body
            .contains("&quot;&lt;b&gt;Mars/Olympus&lt;/b&gt;&quot; isn&#39;t a time zone"),
        "{}",
        page.body
    );
    let page = browser.get(&server, "/server").await;
    assert!(page.body.contains("Times are in Asia/Kolkata."), "kept");
}

#[tokio::test]
async fn the_frame_shows_who_is_signed_in() {
    let server = start().await;
    let page = Browser::default().get(&server, "/").await;

    assert!(page.body.contains(r#"id="profile-link""#));
    assert!(page.body.contains(r#"<span class="avatar">T</span>"#));
}

#[tokio::test]
async fn names_are_only_ever_text() {
    let server = start().await;
    let name = "<img src=x onerror=alert(1)>";
    server
        .state
        .database
        .create_user("a@example.com", name, now_ms())
        .await
        .unwrap();

    let page = Browser::default().get(&server, "/settings/users").await;

    assert!(!page.body.contains(name));
    assert!(page.has_only_our_scripts());
}

#[tokio::test]
async fn an_approval_records_who_made_it() {
    let test = start().await;
    let agent = identity();
    let mut socket = test.connect().await;
    handshake(&mut socket, &agent, "new-1", None).await;

    let path = format!("/agents/{}/approve", agent.id());
    let page = Browser::default()
        .submit(&test, "/agents", &path, &[])
        .await;

    assert_eq!(page.status, 303, "{}", page.body);
    let list = test.state.registry.list().await;
    let approved = list.iter().find(|record| record.id == agent.id()).unwrap();
    assert_eq!(approved.decided_by.as_deref(), Some("test@example.com"));
}

#[tokio::test]
async fn an_api_key_reads_pages_as_its_owner_but_cannot_submit_forms() {
    let server = start().await;
    let database = &server.state.database;
    let (_, key) = database
        .create_api_key("k", server.user_id().await, None, now_ms())
        .await
        .unwrap();
    let mut browser = Browser::anonymous();

    let request = format!(
        "GET /agents HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\n\
         Connection: close\r\n\r\n"
    );
    let page = browser.send(&server, request).await;
    assert_eq!(page.status, 200);
    // A key acts as its owner, so the page is theirs.
    assert!(page.body.contains(r#"id="profile-link""#));

    let body = "email=a%40example.com&name=A";
    let request = format!(
        "POST /settings/users HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    assert_eq!(browser.send(&server, request).await.status, 403);
}

#[tokio::test]
async fn the_api_manages_users_without_giving_away_anything_secret() {
    let server = start().await;
    let none = Value::Null;
    let body = json!({ "email": "New@Example.com", "name": "New" });
    let (status, created) = api(&server, "POST", "/api/v1/users", &body).await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["user"]["email"], "new@example.com");
    let url = created["setup_url"].as_str().unwrap();
    assert!(url.starts_with("http://site.test/setup/"), "{url}");
    let id = created["user"]["id"].as_i64().unwrap();

    assert_eq!(api(&server, "POST", "/api/v1/users", &body).await.0, 409);
    let bad = json!({ "email": "not an address", "name": "New" });
    assert_eq!(api(&server, "POST", "/api/v1/users", &bad).await.0, 422);

    let (status, list) = api(&server, "GET", "/api/v1/users", &none).await;
    assert_eq!(status, 200);
    let text = list.to_string();
    assert!(!text.contains("hash"), "{text}");
    assert!(!text.contains("setup"), "{text}");

    let path = format!("/api/v1/users/{id}");
    let (status, user) = api(&server, "GET", &path, &none).await;
    assert_eq!(status, 200);
    assert_eq!(user["has_password"], false);

    let theme = json!({ "theme": "dusk" });
    assert_eq!(api(&server, "PUT", &path, &theme).await.0, 204);
    assert_eq!(api(&server, "GET", &path, &none).await.1["theme"], "dusk");
    let theme = json!({ "theme": "nope" });
    assert_eq!(api(&server, "PUT", &path, &theme).await.0, 422);

    assert_eq!(
        api(&server, "GET", &path, &none).await.1["time_zone"],
        "UTC"
    );
    let both = json!({ "theme": "paper", "time_zone": "America/New_York" });
    assert_eq!(api(&server, "PUT", &path, &both).await.0, 204);
    let (_, user) = api(&server, "GET", &path, &none).await;
    assert_eq!(
        (&user["theme"], &user["time_zone"]),
        (&json!("paper"), &json!("America/New_York"))
    );
    let zone = json!({ "time_zone": "Mars/Olympus" });
    assert_eq!(api(&server, "PUT", &path, &zone).await.0, 422);
    assert_eq!(api(&server, "PUT", &path, &json!({})).await.0, 422);
    let missing = json!({ "time_zone": "UTC" });
    assert_eq!(
        api(&server, "PUT", "/api/v1/users/999", &missing).await.0,
        404
    );

    assert_eq!(api(&server, "DELETE", &path, &none).await.0, 409, "enabled");
    let disable = format!("{path}/disable");
    let enable = format!("{path}/enable");
    assert_eq!(api(&server, "POST", &disable, &none).await.0, 204);
    assert_eq!(api(&server, "POST", &enable, &none).await.0, 204);
    assert_eq!(api(&server, "POST", &disable, &none).await.0, 204);
    assert_eq!(api(&server, "DELETE", &path, &none).await.0, 204);
    assert_eq!(api(&server, "GET", &path, &none).await.0, 404);

    let link = format!("{path}/setup-link");
    assert_eq!(api(&server, "POST", &link, &none).await.0, 404);
    let response = server.http("GET", "/api/v1/users", None).await;
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
}
