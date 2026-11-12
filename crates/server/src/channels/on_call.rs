//! What PagerDuty, AlertOps and SIGNL4 share: each alert is an incident that opens
//! when it fires and closes when it ends, and they repeat for themselves.

use anyhow::{Result, anyhow, ensure};
use axum::http::Uri;

use crate::alerting::Event;
use crate::notifier::Notice;

/// Ties a test's two steps together.
const TEST_INCIDENT_ID: &str = "maxnines-test";

/// What a notification does to an incident in an on-call service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incident {
    Open,
    Close,
}

/// What this means for an on-call service. A test has to open an incident to prove
/// anything, so it closes it again rather than leave someone paged.
pub fn steps(notice: &Notice) -> &'static [Incident] {
    match notice.event {
        // Sent again with the same ID, which updates the incident's severity.
        Event::Firing | Event::Escalated | Event::Eased => &[Incident::Open],
        Event::Resolved => &[Incident::Close],
        Event::Test => &[Incident::Open, Incident::Close],
        // They repeat for themselves, and what an action printed would only page
        // someone again, so they're never sent these.
        Event::Reminder | Event::Action => &[],
    }
}

/// Ties closing an incident to the one that was opened, and makes a repeat delivery
/// land on that incident too.
pub fn id(notice: &Notice) -> String {
    notice.alert.as_ref().map_or_else(
        || TEST_INCIDENT_ID.to_string(),
        |alert| format!("maxnines-alert-{}", alert.id),
    )
}

pub fn title(notice: &Notice) -> &str {
    notice.alert.as_ref().map_or("Test", |a| &a.rule_name)
}

pub fn severity(notice: &Notice) -> &'static str {
    notice
        .alert
        .as_ref()
        .map_or("info", |a| a.severity.as_str())
}

pub fn hostname(notice: &Notice) -> &str {
    notice.alert.as_ref().map_or("MaxNines", |a| &a.hostname)
}

/// A URL from an on-call service, which has a secret after `path`. `complaint` is
/// fixed text, as the URL itself mustn't end up on the page.
pub fn check_service_url(url: &str, domain: &str, path: &str, complaint: &str) -> Result<()> {
    let uri: Uri = url.trim().parse().map_err(|_| anyhow!("{complaint}"))?;
    let secret = uri.path().strip_prefix(path).unwrap_or_default();
    ensure!(
        uri.scheme_str() == Some("https")
            && uri.host().unwrap_or_default().ends_with(domain)
            && !secret.is_empty(),
        "{complaint}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{Alert, Severity};
    use crate::channels::testing::{alert, notice};

    #[test]
    fn a_change_of_severity_updates_the_same_incident() {
        let warning = Alert {
            severity: Severity::Warning,
            ..alert()
        };
        for notice in [
            notice(Event::Escalated, alert()),
            notice(Event::Eased, warning),
        ] {
            assert_eq!(steps(&notice), [Incident::Open]);
            assert_eq!(id(&notice), "maxnines-alert-7");
        }
        assert_eq!(steps(&notice(Event::Reminder, alert())), []);
        assert_eq!(steps(&Notice::test()), [Incident::Open, Incident::Close]);
    }
}
