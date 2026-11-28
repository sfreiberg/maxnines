use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum_csrf::CsrfToken;

use super::{Page, server_error};
use crate::app_state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/settings", get(index))
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let counts = async {
        let rules = state.database.list_rules().await?.len();
        let alert_rules = state.database.list_alert_rules().await?.len();
        let api_keys = state.database.list_api_keys().await?.len();
        let app_sign_ins = super::app_sign_ins::active_sign_ins(&state).await?;
        let channels = state.database.list_channels().await?.len();
        let users = state.database.user_count().await?;
        let templates = state.database.list_templates().await?.len();
        anyhow::Ok((
            rules,
            alert_rules,
            channels,
            api_keys,
            app_sign_ins,
            users,
            templates,
        ))
    };
    match counts.await {
        Ok((rules, alert_rules, channels, api_keys, app_sign_ins, users, templates)) => {
            Page::new(&state, &token, "settings/index.html")
                .with("rules", &rules)
                .with("alert_rules", &alert_rules)
                .with("api_keys", &api_keys)
                .with("app_sign_ins", &app_sign_ins)
                .with("users", &users)
                .with("channels", &channels)
                .with("templates", &templates)
                .render()
        }
        Err(error) => server_error(&error),
    }
}
