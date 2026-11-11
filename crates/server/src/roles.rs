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
            Self::Editor => "Also changes rules, channels, checks, dashboards and agents",
            Self::Admin => "Also manages users, reads the audit log and deletes agents",
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
/// the person's own: their profile, their session, and their API keys, where the
/// handlers check whose a key is.
const OWN: [&str; 4] = ["/profile", "/logout", "/settings/api-keys", "/api-keys"];

/// Dealing with alerts as they happen: acknowledging them and silencing them.
const RESPONDING: [&str; 14] = [
    "/agents/{id}/annotations",
    "/agents/{id}/maintenance",
    "/agents/{id}/maintenance/end",
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
    // Deleting a machine takes its history with it.
    let deletes_agent =
        (method == Method::DELETE && route == "/agents/{id}") || route == "/agents/{id}/delete";
    if deletes_agent {
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
            "/agents",
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
            (Method::POST, "/agents/{id}/approve"),
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
        ] {
            assert_eq!(required(&Method::POST, route), Role::Responder, "{route}");
        }
        assert_eq!(
            required(&Method::GET, "/alerts/silences/new"),
            Role::Responder
        );
        assert_eq!(required(&Method::GET, "/alerts/silences"), Role::Viewer);
        for (method, route) in [
            (Method::POST, "/agents/{id}/annotations"),
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
        assert_eq!(required(&Method::GET, "/agents/{id}/events"), Role::Viewer);
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
            (Method::DELETE, "/agents/{id}"),
            (Method::POST, "/agents/{id}/delete"),
        ] {
            assert_eq!(required(&method, route), Role::Admin, "{method} {route}");
        }
        // Only whole path segments count.
        assert_eq!(required(&Method::GET, "/users-guide"), Role::Viewer);
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
        ] {
            assert_eq!(required(&method, route), Role::Viewer, "{method} {route}");
        }
    }
}
