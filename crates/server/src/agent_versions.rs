//! Whether an agent runs the newest agent there is.
//!
//! The newest is the agent released alongside this server. For now they share a
//! version number, so it's the server's own. Once the agent is versioned on its own,
//! this should become the agent's version from the same commit, so that releasing a
//! server alone never makes agents look old.

use std::cmp::Ordering;

use semver::Version;
use serde::Serialize;

/// The version of the agent released alongside this server.
pub const NEWEST_AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How an agent's version compares with the newest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionState {
    Current,
    /// There's a newer agent to update to.
    Outdated,
    /// The agent was upgraded before the server, which should be upgraded first.
    NewerThanServer,
}

/// Nothing for a version that isn't a version, as nothing useful can be said about it.
/// Build details after a `+` don't count, as they don't make one version newer.
pub fn compare(reported: &str) -> Option<VersionState> {
    let reported = Version::parse(reported).ok()?;
    let newest = Version::parse(NEWEST_AGENT_VERSION).ok()?;
    Some(match reported.cmp_precedence(&newest) {
        Ordering::Less => VersionState::Outdated,
        Ordering::Equal => VersionState::Current,
        Ordering::Greater => VersionState::NewerThanServer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare_with(reported: &str, newest: &str) -> Ordering {
        Version::parse(reported)
            .unwrap()
            .cmp_precedence(&Version::parse(newest).unwrap())
    }

    #[test]
    fn the_newest_version_is_a_version() {
        assert!(Version::parse(NEWEST_AGENT_VERSION).is_ok());
        assert_eq!(compare(NEWEST_AGENT_VERSION), Some(VersionState::Current));
    }

    #[test]
    fn older_and_newer_agents_are_told_apart() {
        assert_eq!(compare("0.0.1"), Some(VersionState::Outdated));
        assert_eq!(compare("999.0.0"), Some(VersionState::NewerThanServer));
        assert_eq!(compare("not a version"), None);
        assert_eq!(compare(""), None);
    }

    #[test]
    fn pre_releases_compare_by_their_numbers_and_come_before_the_release() {
        assert_eq!(
            compare_with("0.1.0-alpha.2", "0.1.0-alpha.10"),
            Ordering::Less
        );
        assert_eq!(
            compare_with("0.1.0-beta.1", "0.1.0-alpha.9"),
            Ordering::Greater
        );
        assert_eq!(compare_with("0.1.0-rc.1", "0.1.0"), Ordering::Less);
        assert_eq!(compare_with("0.1.0+linux", "0.1.0"), Ordering::Equal);
    }
}
