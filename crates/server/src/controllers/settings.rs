use axum::Router;
use axum::extract::State;
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum_csrf::CsrfToken;

use super::{Page, server_error};
use crate::app_state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings", get(index))
        // Where the Server page used to be.
        .route(
            "/settings/server",
            get(|| async { Redirect::permanent("/server") }),
        )
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let counts = async {
        let rules = state.database.list_rules().await?.len();
        let alert_rules = state.database.list_alert_rules().await?.len();
        let api_keys = state.database.list_api_keys().await?.len();
        let app_sign_ins = super::app_sign_ins::active_sign_ins(&state).await?;
        let channels = state.database.list_channels().await?.len();
        let users = state.database.user_count().await?;
        anyhow::Ok((rules, alert_rules, channels, api_keys, app_sign_ins, users))
    };
    match counts.await {
        Ok((rules, alert_rules, channels, api_keys, app_sign_ins, users)) => {
            Page::new(&state, &token, "settings/index.html")
                .with("rules", &rules)
                .with("alert_rules", &alert_rules)
                .with("api_keys", &api_keys)
                .with("app_sign_ins", &app_sign_ins)
                .with("users", &users)
                .with("channels", &channels)
                .render()
        }
        Err(error) => server_error(&error),
    }
}
