//! Two-factor sign-in, from setting it up to being kept out without it.

use super::*;
use crate::roles::Role;
use crate::two_factor::code_at;

const PASSWORD: &str = "a long enough password";
const EMAIL: &str = "a@example.com";

async fn person(server: &TestServer, email: &str) -> i64 {
    let database = &server.state.database;
    let (user, link) = database
        .create_user(email, "Someone", Role::Admin, now_ms())
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

fn secs() -> u64 {
    u64::try_from(now_ms() / 1000).unwrap()
}

/// Turns two-factor on for someone, and gives their secret and recovery codes.
async fn with_two_factor(server: &TestServer, id: i64, email: &str) -> (String, Vec<String>) {
    let database = &server.state.database;
    let secret = database.start_two_factor(id).await.unwrap().unwrap();
    // A step back, so the code for now is still unused when signing in.
    let code = code_at(&secret, email, secs() - 30);
    let codes = database.confirm_two_factor(id, &code, now_ms()).await;
    (secret, codes.unwrap().unwrap())
}

async fn give_password(server: &TestServer, browser: &mut Browser, email: &str) -> Page {
    let fields = [
        ("email", email),
        ("password", PASSWORD),
        ("next", "/agents"),
    ];
    browser.submit(server, "/login", "/login", &fields).await
}

async fn give_code(server: &TestServer, browser: &mut Browser, code: &str) -> Page {
    let fields = [("code", code), ("next", "/agents")];
    browser
        .submit(server, "/login/code", "/login/code", &fields)
        .await
}

fn has_session(browser: &Browser) -> bool {
    browser
        .cookies
        .get("maxnines_session")
        .is_some_and(|value| !value.is_empty())
}

#[tokio::test]
async fn signing_in_with_two_factor_takes_a_code_after_the_password() {
    let server = start().await;
    let id = person(&server, EMAIL).await;
    let (secret, _) = with_two_factor(&server, id, EMAIL).await;
    let mut browser = Browser::anonymous();

    let page = give_password(&server, &mut browser, EMAIL).await;
    assert_eq!(page.status, 303);
    assert!(page.header("location").unwrap().starts_with("/login/code"));
    assert!(!has_session(&browser), "a password alone signs nobody in");
    assert_eq!(browser.get(&server, "/agents").await.status, 303);

    let wrong = give_code(&server, &mut browser, "000000").await;
    assert_eq!(wrong.status, 401, "{}", wrong.body);
    assert!(wrong.body.contains("That code isn"));
    assert!(!has_session(&browser));

    let page = give_code(&server, &mut browser, &code_at(&secret, EMAIL, secs())).await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(page.header("location"), Some("/agents"));
    assert!(has_session(&browser));
    assert_eq!(browser.get(&server, "/agents").await.status, 200);
}

#[tokio::test]
async fn a_code_only_works_once() {
    let server = start().await;
    let id = person(&server, EMAIL).await;
    let (secret, _) = with_two_factor(&server, id, EMAIL).await;
    let database = &server.state.database;
    let code = code_at(&secret, EMAIL, secs());

    assert!(
        database
            .accept_two_factor_code(id, &code, now_ms())
            .await
            .unwrap()
    );
    assert!(
        !database
            .accept_two_factor_code(id, &code, now_ms())
            .await
            .unwrap()
    );
    // Nor does an older one, once a newer one has been used.
    let older = code_at(&secret, EMAIL, secs() - 30);
    assert!(
        !database
            .accept_two_factor_code(id, &older, now_ms())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_recovery_code_signs_in_once() {
    let server = start().await;
    let id = person(&server, EMAIL).await;
    let (_, codes) = with_two_factor(&server, id, EMAIL).await;
    let typed = codes[0].to_uppercase().replace('-', " ");

    let mut browser = Browser::anonymous();
    give_password(&server, &mut browser, EMAIL).await;
    assert_eq!(give_code(&server, &mut browser, &typed).await.status, 303);
    assert!(has_session(&browser));

    let mut again = Browser::anonymous();
    give_password(&server, &mut again, EMAIL).await;
    assert_eq!(give_code(&server, &mut again, &codes[0]).await.status, 401);
    let database = &server.state.database;
    assert_eq!(database.recovery_codes_left(id).await.unwrap(), 9);
    // Nothing kept would let someone reading the database sign in.
    let saved = format!("{:?}", database.saved_secrets().await);
    assert!(!saved.contains(&codes[1]));
}

#[tokio::test]
async fn the_code_page_needs_a_password_first() {
    let server = start().await;
    let id = person(&server, EMAIL).await;
    let (secret, _) = with_two_factor(&server, id, EMAIL).await;
    let mut browser = Browser::anonymous();

    let page = browser.get(&server, "/login/code").await;
    assert_eq!(page.status, 303);
    assert_eq!(page.header("location"), Some("/login"));
    // A right code without the password's token gets nowhere.
    let token = browser.get(&server, "/login").await.token();
    let code = code_at(&secret, EMAIL, secs());
    let fields = [
        ("authenticity_token", token.as_str()),
        ("code", code.as_str()),
    ];
    let page = browser.post(&server, "/login/code", &fields).await;
    assert_eq!(page.status, 303);
    assert!(!has_session(&browser));
}

#[tokio::test]
async fn guessing_codes_soon_stops_working() {
    let server = start().await;
    let id = person(&server, EMAIL).await;
    let (secret, _) = with_two_factor(&server, id, EMAIL).await;
    let mut browser = Browser::anonymous();
    give_password(&server, &mut browser, EMAIL).await;

    let mut last = 0;
    for _ in 0..6 {
        last = give_code(&server, &mut browser, "000000").await.status;
    }
    assert_eq!(last, 429);
    // Even the right code, or a guess could be confirmed by getting in.
    let code = code_at(&secret, EMAIL, secs());
    assert_eq!(give_code(&server, &mut browser, &code).await.status, 429);
}

#[tokio::test]
async fn someone_sets_it_up_from_their_profile() {
    let server = start().await;
    person(&server, EMAIL).await;
    let mut browser = Browser::anonymous();
    assert_eq!(
        give_password(&server, &mut browser, EMAIL).await.status,
        303
    );
    assert!(has_session(&browser));

    let page = browser
        .submit(&server, "/profile", "/profile/two-factor/start", &[])
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("/profile/two-factor/qr.png"));
    assert_eq!(page.header("cache-control"), Some("no-store"));
    let qr = browser.get(&server, "/profile/two-factor/qr.png").await;
    assert_eq!(qr.status, 200);
    assert_eq!(qr.header("content-type"), Some("image/png"));

    let id = server
        .state
        .database
        .active_user_by_email(EMAIL)
        .await
        .unwrap()
        .unwrap()
        .id;
    let secret = server
        .state
        .database
        .pending_two_factor_secret(id)
        .await
        .unwrap()
        .unwrap();
    assert!(page.body.contains(&crate::two_factor::grouped(&secret)));
    let wrong = [("code", "000000")];
    let page = browser
        .submit(&server, "/profile", "/profile/two-factor/confirm", &wrong)
        .await;
    assert_eq!(page.status, 422);
    assert!(
        !server
            .state
            .database
            .user(id)
            .await
            .unwrap()
            .unwrap()
            .two_factor
    );

    let code = code_at(&secret, EMAIL, secs());
    let page = browser
        .submit(
            &server,
            "/profile",
            "/profile/two-factor/confirm",
            &[("code", &code)],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Your recovery codes"));
    assert_eq!(page.body.matches("<li><code>").count(), 10);
    assert!(
        server
            .state
            .database
            .user(id)
            .await
            .unwrap()
            .unwrap()
            .two_factor
    );
    // Once it's on there's no secret or QR code to fetch.
    assert_eq!(
        browser
            .get(&server, "/profile/two-factor/qr.png")
            .await
            .status,
        404
    );

    // Turning it off takes the password.
    let page = browser
        .submit(
            &server,
            "/profile",
            "/profile/two-factor/off",
            &[("current", "wrong")],
        )
        .await;
    assert_eq!(page.status, 422);
    let page = browser
        .submit(
            &server,
            "/profile",
            "/profile/two-factor/off",
            &[("current", PASSWORD)],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(
        !server
            .state
            .database
            .user(id)
            .await
            .unwrap()
            .unwrap()
            .two_factor
    );
}

#[tokio::test]
async fn a_key_acting_as_someone_never_sees_their_qr_code() {
    let server = start().await;
    let id = server.user_id().await;
    server.state.database.start_two_factor(id).await.unwrap();

    let response = server
        .http("GET", "/profile/two-factor/qr.png", Some(&server.api_key))
        .await;

    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}

#[tokio::test]
async fn an_admin_can_require_it_for_everyone() {
    let server = start().await;
    let admin = server.user_id().await;
    let mut browser = Browser::default();
    let require = [("required", "true")];

    // Not before having it themselves, or they'd be the first kept out.
    let page = browser
        .submit(
            &server,
            "/settings/users",
            "/settings/users/two-factor",
            &require,
        )
        .await;
    assert_eq!(page.status, 422);
    assert!(page.body.contains("on your own profile first"));

    with_two_factor(&server, admin, "test@example.com").await;
    let page = browser
        .submit(
            &server,
            "/settings/users",
            "/settings/users/two-factor",
            &require,
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(server.state.database.two_factor_required().await.unwrap());

    // Someone without it is sent to their profile, and can set it up there.
    person(&server, EMAIL).await;
    let mut other = Browser::anonymous();
    give_password(&server, &mut other, EMAIL).await;
    let page = other.get(&server, "/agents").await;
    assert_eq!(page.status, 303);
    assert_eq!(page.header("location"), Some("/profile"));
    let page = other.get(&server, "/profile").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("required for everyone"));
    // The admin, who has it, carries on.
    assert_eq!(browser.get(&server, "/agents").await.status, 200);
    // And it can't be turned off while it's required.
    let page = browser
        .submit(
            &server,
            "/profile",
            "/profile/two-factor/off",
            &[("current", PASSWORD)],
        )
        .await;
    assert_eq!(page.status, 422);

    let entry = &server.state.database.audit_log(None, 5).await.unwrap();
    assert!(
        entry.iter().any(|e| e.subject.kind == "setting"),
        "{entry:?}"
    );
}

#[tokio::test]
async fn an_admin_resets_it_for_someone_who_lost_their_phone() {
    let server = start().await;
    let id = person(&server, EMAIL).await;
    with_two_factor(&server, id, EMAIL).await;

    let path = format!("/settings/users/{id}/two-factor/reset");
    let page = Browser::default()
        .submit(&server, "/settings/users", &path, &[])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let database = &server.state.database;
    assert!(!database.user(id).await.unwrap().unwrap().two_factor);
    assert_eq!(database.recovery_codes_left(id).await.unwrap(), 0);
    let mut browser = Browser::anonymous();
    give_password(&server, &mut browser, EMAIL).await;
    assert!(has_session(&browser));
    let entry = &database.audit_log(None, 2).await.unwrap()[1];
    assert_eq!(entry.changes[0].field, "two_factor");
    assert_eq!(entry.actor.name, "test@example.com");
}

#[tokio::test]
async fn the_two_factor_card_updates_in_place() {
    let server = start().await;
    person(&server, EMAIL).await;
    let mut browser = Browser::anonymous();
    give_password(&server, &mut browser, EMAIL).await;

    let profile = browser.get(&server, "/profile").await;
    // The card swaps itself for the same card from the answer, so the page around
    // it stays where it was.
    for attribute in [
        r##"id="two-factor" hx-target="this" hx-select="#two-factor""##,
        r#"hx-post="/profile/two-factor/start""#,
    ] {
        assert!(profile.body.contains(attribute), "{attribute}");
    }
    // A form with a problem comes back as 422, which htmx has to show.
    assert!(profile.body.contains(r#"{"code":"422","swap":true}"#));

    let token = profile.token();
    let started = browser
        .post(
            &server,
            "/profile/two-factor/start",
            &[("authenticity_token", &token)],
        )
        .await;
    assert!(
        started
            .body
            .contains(r#"hx-post="/profile/two-factor/confirm""#)
    );
    // Its problems are inside it, where the swap shows them.
    let token = started.token();
    let wrong = browser
        .post(
            &server,
            "/profile/two-factor/confirm",
            &[("authenticity_token", &token), ("code", "000000")],
        )
        .await;
    assert_eq!(wrong.status, 422);
    let card = &wrong.body[wrong.body.find(r#"id="two-factor""#).unwrap()..];
    let card = &card[..card.find("</section>").unwrap()];
    assert!(card.contains("That code isn"), "{card}");
    // And the other forms on the page still work with the token they had.
    let page = browser
        .post(
            &server,
            "/profile/theme",
            &[("authenticity_token", &profile.token()), ("theme", "paper")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
}
