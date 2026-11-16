//! What each person may do. Roles build on each other: a viewer sees everything,
//! a responder can also acknowledge and silence alerts and add and delete annotations, an
//! editor can also change the setup, and an admin can also manage people, read the
//! audit log and delete agents.
//!
//! [`required`] is the one place that says what a request needs, and every request
//! from a person or an API key passes through it before its handler runs. Anything
//! new that changes something needs an editor unless it's listed here.

use anyhow::{Context, Result};
use axum::http::Method;
use serde::{Deserialize, Serialize};

use crate::audit::Via;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Responder,
    Editor,
    Admin,
}

impl Role {
    /// From the least able to the most.
    pub const ALL: [Self; 4] = [Self::Viewer, Self::Responder, Self::Editor, Self::Admin];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Responder => "responder",
            Self::Editor => "editor",
            Self::Admin => "admin",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Viewer => "Viewer",
            Self::Responder => "Responder",
            Self::Editor => "Editor",
            Self::Admin => "Admin",
        }
    }

    /// What it adds, for the page where roles are chosen.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Viewer => "Sees everything except users and the audit log",
            Self::Responder => {
                "Also acknowledges and silences alerts, and adds and deletes annotations"
            }
            Self::Editor => {
                "Also changes rules, channels, checks and dashboards, and approves hosts"
            }
            Self::Admin => "Also manages users, reads the audit log and deletes hosts",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == text)
            .with_context(|| {
                format!("{text:?} isn't a role: choose viewer, responder, editor or admin")
            })
    }
}

/// Paths only admins use, by how they start: people and the audit log. They're
/// given as the pages have them and as the API does.
const ADMIN_ONLY: [&str; 4] = [
    "/settings/users",
    "/users",
    "/settings/audit-log",
    "/audit-log",
];

/// Paths open to everyone signed in, by how they start. Each acts only on what's
/// the person's own: their profile, their session, their API keys and signed-in
/// apps, where the handlers check whose each is, and approving an app to act as them,
/// which can't do more than they can.
const OWN: [&str; 9] = [
    "/profile",
    "/logout",
    "/settings/api-keys",
    "/api-keys",
    "/settings/apps",
    "/app-sign-ins",
    "/sign-ins",
    "/oauth/authorize",
    "/device",
];

/// Dealing with alerts as they happen: acknowledging them and silencing them.
const RESPONDING: [&str; 18] = [
    "/checks/{id}/run",
    "/checks/{id}/maintenance",
    "/checks/{id}/maintenance/end",
    "/hosts/{id}/actions",
    "/hosts/{id}/annotations",
    "/hosts/{id}/maintenance",
    "/hosts/{id}/maintenance/end",
    "/alerts/{id}/acknowledge",
    "/alerts/{id}/unacknowledge",
    "/alerts/silences",
    "/alerts/silences/new",
    "/alerts/silences/{id}/end",
    "/annotations",
    "/annotations/{id}",
    "/metrics/annotations",
    "/metrics/annotations/{id}/delete",
    "/silences",
    "/silences/{id}/end",
];

/// Approving an app to act as someone, which only a person at the pages may do. An app
/// or a key doing it would make a sign in that outlives revoking the app or the key.
const APPROVING_APPS: [&str; 2] = ["/oauth/authorize", "/device"];

/// Making API keys, which a signed-in app may not: a key it made would go on working
/// after the app was signed out or revoked.
const MAKING_KEYS: [&str; 2] = ["/api-keys", "/settings/api-keys"];

/// Why a request isn't allowed however it came, whatever the role: not as an API key
/// or a signed-in app, as `via` says, if that's how it came. `route` is as for
/// [`required`].
pub fn refused_via(via: Option<&Via>, method: &Method, route: &str) -> Option<&'static str> {
    let via = via?;
    if APPROVING_APPS.iter().any(|prefix| starts(route, prefix)) {
        return Some("Only someone signed in to the pages in a browser can approve an app");
    }
    let changes = method != Method::GET && method != Method::HEAD;
    if matches!(via, Via::App { .. }) && changes && MAKING_KEYS.contains(&route) {
        return Some("An app signed in through the browser can't make API keys");
    }
    None
}

fn starts(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The least role a request needs. `route` is the route it matched, as it's written
/// with its `{id}` placeholders, without the API's prefix.
pub fn required(method: &Method, route: &str) -> Role {
    let reads = method == Method::GET || method == Method::HEAD;
    if ADMIN_ONLY.iter().any(|prefix| starts(route, prefix)) {
        return Role::Admin;
    }
    // Deleting a host takes its history with it.
    let deletes_host =
        (method == Method::DELETE && route == "/hosts/{id}") || route == "/hosts/{id}/delete";
    if deletes_host {
        return Role::Admin;
    }
    if OWN.iter().any(|prefix| starts(route, prefix)) {
        return Role::Viewer;
    }
    if RESPONDING.contains(&route) {
        return if reads && route != "/alerts/silences/new" {
            Role::Viewer
        } else {
            Role::Responder
        };
    }
    // Anyone can open a rule or a channel to read it, where saving is what's
    // refused. A form for something new is only for those who can make one, and so
    // is a dashboard's editing mode, which saves as widgets are dragged.
    let for_editing =
        route.ends_with("/new") || (route.starts_with("/dashboards/") && route.ends_with("/edit"));
    if reads && !for_editing {
        return Role::Viewer;
    }
    Role::Editor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_build_on_each_other_and_read_back() {
        assert!(Role::Viewer < Role::Responder);
        assert!(Role::Responder < Role::Editor);
        assert!(Role::Editor < Role::Admin);
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()).unwrap(), role);
        }
        assert!(Role::parse("owner").is_err());
    }

    #[test]
    fn reading_needs_a_viewer_and_changing_needs_an_editor() {
        for route in [
            "/",
            "/hosts",
            "/alerts",
            "/alerts/rules",
            "/alerts/rules/{id}/edit",
            "/alerts/channels/{id}/edit",
            "/dashboards/{id}",
            "/server",
        ] {
            assert_eq!(required(&Method::GET, route), Role::Viewer, "{route}");
        }
        for (method, route) in [
            (Method::POST, "/alerts/rules"),
            (Method::PUT, "/alert-rules/{id}"),
            (Method::DELETE, "/dashboards/{id}"),
            (Method::POST, "/hosts/{id}/approve"),
            (Method::POST, "/notification-channels/{id}/test"),
            (Method::GET, "/alerts/rules/new"),
            (Method::GET, "/dashboards/{id}/edit"),
            (Method::GET, "/dashboards/{id}/widgets/{widget}/edit"),
            (Method::POST, "/something/added/later"),
        ] {
            assert_eq!(required(&method, route), Role::Editor, "{method} {route}");
        }
    }

    #[test]
    fn responders_acknowledge_and_silence() {
        for route in [
            "/alerts/{id}/acknowledge",
            "/alerts/{id}/unacknowledge",
            "/alerts/silences",
            "/silences",
            "/silences/{id}/end",
            "/hosts/{id}/actions",
            "/checks/{id}/run",
            "/checks/{id}/maintenance",
            "/checks/{id}/maintenance/end",
        ] {
            assert_eq!(required(&Method::POST, route), Role::Responder, "{route}");
        }
        // Turning a check off changes what's watched, which is an editor's to do.
        assert_eq!(required(&Method::POST, "/checks/{id}/pause"), Role::Editor);
        assert_eq!(required(&Method::GET, "/hosts/{id}/actions"), Role::Viewer);
        assert_eq!(
            required(&Method::GET, "/alerts/silences/new"),
            Role::Responder
        );
        assert_eq!(required(&Method::GET, "/alerts/silences"), Role::Viewer);
        for (method, route) in [
            (Method::POST, "/hosts/{id}/annotations"),
            (Method::POST, "/annotations"),
            (Method::DELETE, "/annotations/{id}"),
            (Method::POST, "/metrics/annotations"),
            (Method::POST, "/metrics/annotations/{id}/delete"),
        ] {
            assert_eq!(
                required(&method, route),
                Role::Responder,
                "{method} {route}"
            );
        }
        assert_eq!(required(&Method::GET, "/annotations"), Role::Viewer);
        assert_eq!(required(&Method::GET, "/metrics/annotations"), Role::Viewer);
        assert_eq!(required(&Method::GET, "/hosts/{id}/events"), Role::Viewer);
        assert_eq!(required(&Method::GET, "/silences"), Role::Viewer);
    }

    #[test]
    fn people_the_audit_log_and_deleting_agents_need_an_admin() {
        for (method, route) in [
            (Method::GET, "/settings/users"),
            (Method::POST, "/settings/users/{id}/role"),
            (Method::GET, "/users"),
            (Method::PUT, "/users/{id}"),
            (Method::GET, "/settings/audit-log"),
            (Method::GET, "/audit-log"),
            (Method::DELETE, "/hosts/{id}"),
            (Method::POST, "/hosts/{id}/delete"),
        ] {
            assert_eq!(required(&method, route), Role::Admin, "{method} {route}");
        }
        // Only whole path segments count.
        assert_eq!(required(&Method::GET, "/users-guide"), Role::Viewer);
    }

    #[test]
    fn apps_and_keys_cant_approve_apps_and_apps_cant_make_keys() {
        let key = Via::ApiKey {
            id: 1,
            name: "script".to_string(),
        };
        let app = Via::App {
            id: 1,
            name: "MaxNines command line".to_string(),
        };
        for route in ["/oauth/authorize", "/device", "/device/decide"] {
            for method in [Method::GET, Method::POST] {
                assert!(refused_via(Some(&key), &method, route).is_some(), "{route}");
                assert!(refused_via(Some(&app), &method, route).is_some(), "{route}");
                assert!(refused_via(None, &method, route).is_none(), "{route}");
            }
        }
        for route in ["/api-keys", "/settings/api-keys"] {
            assert!(refused_via(Some(&app), &Method::POST, route).is_some());
            assert!(refused_via(Some(&app), &Method::GET, route).is_none());
            // A key can still make a key, which can't do more than it can.
            assert!(refused_via(Some(&key), &Method::POST, route).is_none());
            assert!(refused_via(None, &Method::POST, route).is_none());
        }
        // An app can still revoke a key, or itself.
        assert!(refused_via(Some(&app), &Method::DELETE, "/api-keys/{id}").is_none());
        assert!(refused_via(Some(&app), &Method::DELETE, "/app-sign-ins/{id}").is_none());
    }

    #[test]
    fn everyone_manages_what_is_their_own() {
        for (method, route) in [
            (Method::POST, "/profile/theme"),
            (Method::POST, "/profile/password"),
            (Method::POST, "/logout"),
            (Method::POST, "/settings/api-keys"),
            (Method::POST, "/settings/api-keys/{id}/revoke"),
            (Method::DELETE, "/api-keys/{id}"),
            (Method::POST, "/settings/apps/{id}/revoke"),
            (Method::DELETE, "/app-sign-ins/{id}"),
            (Method::DELETE, "/sign-ins/{kind}/{id}"),
            (Method::POST, "/profile/sign-ins/{kind}/{id}/end"),
            (Method::POST, "/oauth/authorize"),
            (Method::POST, "/device"),
            (Method::POST, "/device/decide"),
        ] {
            assert_eq!(required(&method, route), Role::Viewer, "{method} {route}");
        }
    }
}
