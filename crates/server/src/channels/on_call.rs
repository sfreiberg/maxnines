//! What PagerDuty, AlertOps and SIGNL4 share: an alert opens an incident when it
//! fires, and closes it when it ends, and they repeat for themselves until someone
//! acknowledges it. Each level an alert reaches is an incident of its own, so a
//! warning that becomes critical pages someone even if its warning was acknowledged.
//! Those that can be told are acknowledged along with the alert, or when a silence
//! starts covering it.

use anyhow::{Result, anyhow, ensure};
use axum::http::Uri;

use crate::alerting::{Alert, ChannelInput, Event, Severity};
use crate::notifier::Notice;

/// Ties a test's two steps together.
pub const TEST_INCIDENT_ID: &str = "maxnines-test";

/// What a notification does to an incident in an on-call service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incident {
    /// Opens it, or updates it if it's open, which doesn't page anyone again.
    Open,
    /// Someone's on it, so the service stops paging people. It stays open.
    Acknowledge,
    Close,
}

/// One thing to tell the service, about the incident with this ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub incident: Incident,
    pub id: String,
}

/// What a notification tells an on-call service, and the incident that's open for
/// the alert once it has, which the next notification about it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub open: Option<String>,
}

/// The incident for an alert at one level, which ties closing it to its opening,
/// and makes a repeat delivery land on it too.
pub fn incident_id(alert_id: i64, level: Severity) -> String {
    format!("maxnines-alert-{alert_id}-{}", level.as_str())
}

/// Which of an alert's incidents `id` is, by its level.
fn level_of(alert: &Alert, id: &str) -> Option<Severity> {
    [Severity::Warning, Severity::Critical]
        .into_iter()
        .find(|level| incident_id(alert.id, *level) == id)
}

/// What a notification means for an on-call service on `channel`, where `open` is
/// the alert's incident that's open there, as the last notification about it said.
/// An alert opens a new incident only when it reaches a level above any it has
/// opened there, and one the channel takes. The new one pages, even if the one
/// before was acknowledged, and closes the one before. Otherwise it updates the one
/// that's open, with its severity now. A test has to open an incident to prove
/// anything, so it closes it again rather than leave someone paged.
pub fn plan(notice: &Notice, channel: &ChannelInput, open: Option<&str>) -> Plan {
    let Some(alert) = notice
        .alert
        .as_ref()
        .filter(|_| notice.event != Event::Test)
    else {
        let step = |incident| Step {
            incident,
            id: TEST_INCIDENT_ID.to_string(),
        };
        return Plan {
            steps: vec![step(Incident::Open), step(Incident::Close)],
            open: None,
        };
    };
    let opened = open.and_then(|id| level_of(alert, id));
    // What there is to tell, when the alert has no incident open: one at its level.
    let current = opened.unwrap_or(alert.severity);
    let id = incident_id(alert.id, current);
    let one = |incident| Plan {
        steps: vec![Step {
            incident,
            id: id.clone(),
        }],
        open: Some(id.clone()),
    };
    match notice.event {
        Event::Firing | Event::Escalated | Event::Eased => match opened {
            Some(opened)
                if alert.severity > opened && channel.severities.contains(&alert.severity) =>
            {
                let higher = incident_id(alert.id, alert.severity);
                let open = |id: &str| Step {
                    incident: Incident::Open,
                    id: id.to_string(),
                };
                let close = Step {
                    incident: Incident::Close,
                    id: id.clone(),
                };
                Plan {
                    steps: vec![open(&higher), close],
                    open: Some(higher),
                }
            }
            _ => one(Incident::Open),
        },
        Event::Acknowledged => one(Incident::Acknowledge),
        Event::Resolved => one(Incident::Close),
        // They repeat for themselves, and what an action printed would only page
        // someone again, so they're never sent these.
        Event::Reminder | Event::Action | Event::Test => Plan {
            steps: Vec::new(),
            open: open.map(str::to_string),
        },
    }
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
    use std::collections::BTreeSet;

    use super::*;
    use crate::alerting::ChannelKind;
    use crate::channels::testing::{alert, notice};

    fn taking(severities: &[Severity]) -> ChannelInput {
        ChannelInput {
            name: "Pager".to_string(),
            kind: ChannelKind::PagerDuty,
            target: String::new(),
            credential: None,
            app_token: None,
            severities: severities.iter().copied().collect::<BTreeSet<_>>(),
            mail: None,
            request: None,
            region: None,
        }
    }

    fn at(severity: Severity) -> Alert {
        Alert {
            severity,
            ..alert()
        }
    }

    fn step(incident: Incident, id: &str) -> Step {
        Step {
            incident,
            id: id.to_string(),
        }
    }

    const WARNING: &str = "maxnines-alert-7-warning";
    const CRITICAL: &str = "maxnines-alert-7-critical";

    #[test]
    fn each_level_an_alert_reaches_is_an_incident_of_its_own() {
        let both = taking(&[Severity::Warning, Severity::Critical]);
        let fired = plan(&notice(Event::Firing, at(Severity::Warning)), &both, None);
        assert_eq!(fired.steps, [step(Incident::Open, WARNING)]);
        assert_eq!(fired.open.as_deref(), Some(WARNING));

        let worse = plan(&notice(Event::Escalated, alert()), &both, Some(WARNING));
        assert_eq!(
            worse.steps,
            [
                step(Incident::Open, CRITICAL),
                step(Incident::Close, WARNING)
            ]
        );
        assert_eq!(worse.open.as_deref(), Some(CRITICAL));

        // Easing, and getting worse again, only ever update the critical one.
        let eased = notice(Event::Eased, at(Severity::Warning));
        let worse_again = notice(Event::Escalated, alert());
        for notice in [eased, worse_again] {
            let plan = plan(&notice, &both, Some(CRITICAL));
            assert_eq!(plan.steps, [step(Incident::Open, CRITICAL)]);
            assert_eq!(plan.open.as_deref(), Some(CRITICAL));
        }

        let resolved = plan(&notice(Event::Resolved, alert()), &both, Some(CRITICAL));
        assert_eq!(resolved.steps, [step(Incident::Close, CRITICAL)]);
        let acknowledged = notice(Event::Acknowledged, at(Severity::Warning));
        let acknowledged = plan(&acknowledged, &both, Some(CRITICAL));
        assert_eq!(acknowledged.steps, [step(Incident::Acknowledge, CRITICAL)]);
    }

    #[test]
    fn a_channel_taking_one_level_has_one_incident_named_by_it() {
        let pager = taking(&[Severity::Critical]);
        let fired = plan(&notice(Event::Firing, alert()), &pager, None);
        assert_eq!(fired.steps, [step(Incident::Open, CRITICAL)]);
        let eased = notice(Event::Eased, at(Severity::Warning));
        assert_eq!(
            plan(&eased, &pager, Some(CRITICAL)).steps,
            [step(Incident::Open, CRITICAL)]
        );

        // Warnings only doesn't open a critical incident, as it doesn't take them.
        let chat = taking(&[Severity::Warning]);
        let worse = plan(&notice(Event::Escalated, alert()), &chat, Some(WARNING));
        assert_eq!(worse.steps, [step(Incident::Open, WARNING)]);
        assert_eq!(worse.open.as_deref(), Some(WARNING));
    }

    #[test]
    fn reminders_and_tests_leave_the_incident_as_it_is() {
        let both = taking(&[Severity::Warning, Severity::Critical]);
        let reminder = plan(&notice(Event::Reminder, alert()), &both, Some(CRITICAL));
        assert_eq!(reminder.steps, []);
        assert_eq!(reminder.open.as_deref(), Some(CRITICAL));
        let test = plan(&Notice::test(), &both, None);
        assert_eq!(
            test.steps,
            [
                step(Incident::Open, TEST_INCIDENT_ID),
                step(Incident::Close, TEST_INCIDENT_ID)
            ]
        );
        assert_eq!(test.open, None);
    }

    #[test]
    fn an_alert_with_nothing_open_is_told_of_at_its_level() {
        let both = taking(&[Severity::Warning, Severity::Critical]);
        let resolved = plan(&notice(Event::Resolved, alert()), &both, None);
        assert_eq!(resolved.steps, [step(Incident::Close, CRITICAL)]);
        // An incident named some other way isn't one of this alert's.
        let fired = plan(
            &notice(Event::Firing, alert()),
            &both,
            Some("maxnines-alert-7"),
        );
        assert_eq!(fired.steps, [step(Incident::Open, CRITICAL)]);
    }
}
