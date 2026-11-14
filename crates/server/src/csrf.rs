//! The CSRF protection's secrets. They live in the main database with the other
//! server secrets, so that a form left open across a restart still submits.

use anyhow::Result;
use axum_csrf::{CsrfConfig, Key};

use crate::models::Database;

const KEY: &str = "csrf_key";
const SALT: &str = "csrf_salt";

/// `secure` is whether browsers reach the server over HTTPS, which also lets the
/// cookie carry the `__Host-` prefix, tying it to this host and path.
pub async fn config(database: &Database, secure: bool) -> Result<CsrfConfig> {
    let key = database.server_secret(KEY).await?;
    let salt = database.server_secret(SALT).await?;
    Ok(CsrfConfig::default()
        .with_key(Some(Key::from(key.as_bytes())))
        .with_salt(salt)
        .with_secure(secure)
        .with_prefix_with_host(secure))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum_csrf::CsrfToken;
    use tokio::net::TcpListener;

    use super::*;

    async fn issue(token: CsrfToken) -> impl IntoResponse {
        let text = token.authenticity_token().unwrap();
        (token, text)
    }

    async fn check(token: CsrfToken, body: String) -> StatusCode {
        match token.verify(&body) {
            Ok(()) => StatusCode::OK,
            Err(_) => StatusCode::FORBIDDEN,
        }
    }

    /// A page that hands out tokens and checks them, like every form does.
    async fn serve(config: CsrfConfig) -> String {
        let app = Router::new()
            .route("/", get(issue).post(check))
            .with_state(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{address}/")
    }

    /// Gets a form from one server and submits it to another.
    async fn submit_across(from: String, to: String) -> u16 {
        tokio::task::spawn_blocking(move || {
            let agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .new_agent();
            let mut page = agent.get(&from).call().unwrap();
            let cookie = page
                .headers()
                .get("set-cookie")
                .unwrap()
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string();
            let token = page.body_mut().read_to_string().unwrap();
            agent
                .post(&to)
                .header("cookie", &cookie)
                .send(token.as_bytes())
                .unwrap()
                .status()
                .as_u16()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_form_opened_before_a_restart_still_submits_after_it() {
        let database = Database::for_test().await;
        let before = serve(config(&database, false).await.unwrap()).await;
        let after = serve(config(&database, false).await.unwrap()).await;

        assert_eq!(submit_across(before.clone(), after).await, 200);

        // Without the saved secrets, each start would refuse the other's forms.
        let other = serve(CsrfConfig::default()).await;
        assert_eq!(submit_across(before, other).await, 403);
    }
}
