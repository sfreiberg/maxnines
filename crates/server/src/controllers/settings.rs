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
        let channels = state.database.list_channels().await?.len();
        anyhow::Ok((rules, alert_rules, channels))
    };
    match counts.await {
        Ok((rules, alert_rules, channels)) => Page::new(&state, &token, "settings/index.html")
            .with("rules", &rules)
            .with("alert_rules", &alert_rules)
            .with("channels", &channels)
            .render(),
        Err(error) => server_error(&error),
    }
}
