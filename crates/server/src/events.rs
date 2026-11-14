//! Things that happened to hosts, marked on their charts so a change in a graph can
//! be matched to what caused it. Annotations, deploys and notes, come from people and
//! their scripts, for the hosts a filter picks whenever a chart is drawn. The
//! server records restarts and config changes itself, and alerts and updates come from
//! what's already kept about them.

use serde::{Deserialize, Serialize};

use crate::host_filter::HostFilter;

pub const MAX_TITLE_LEN: usize = 200;
pub const MAX_DETAIL_LEN: usize = 2000;
pub const MAX_FILTER_LEN: usize = 500;
const DAY_MS: i64 = 86_400_000;
/// How long ago an event can be said to have happened, such as a deploy recorded late.
const LONGEST_AGO_MS: i64 = 366 * DAY_MS;
/// A script's clock can be a little ahead of the server's.
const FURTHEST_AHEAD_MS: i64 = 3_600_000;
/// Who the server's own events are by.
pub const SERVER: &str = "server";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Deploy,
    Note,
    Restart,
    Config,
    Alert,
    Resolved,
    Update,
}

impl EventKind {
    const ALL: [Self; 7] = [
        Self::Deploy,
        Self::Note,
        Self::Restart,
        Self::Config,
        Self::Alert,
        Self::Resolved,
        Self::Update,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Note => "note",
            Self::Restart => "restart",
            Self::Config => "config",
            Self::Alert => "alert",
            Self::Resolved => "resolved",
            Self::Update => "update",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Deploy => "Deploy",
            Self::Note => "Note",
            Self::Restart => "Restart",
            Self::Config => "Config change",
            Self::Alert => "Alert",
            Self::Resolved => "Resolved",
            Self::Update => "Update",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// What people can record. The rest the server works out.
    pub fn is_recorded_by_people(self) -> bool {
        matches!(self, Self::Deploy | Self::Note)
    }
}

/// What someone records: a deploy or a note, for the hosts a filter picks.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInput {
    /// `deploy` or `note`, which is the default.
    #[serde(default)]
    pub kind: Option<String>,
    pub title: String,
    #[serde(default)]
    pub detail: Option<String>,
    /// When it happened. Defaults to now.
    #[serde(default)]
    pub time_ms: Option<i64>,
    /// Which hosts, as a host filter, matched whenever a chart is drawn. Empty means
    /// every host.
    #[serde(default)]
    pub filter: Option<String>,
}

impl EventInput {
    pub fn tidy(&mut self) {
        self.title = self.title.trim().to_string();
        self.detail = self
            .detail
            .as_deref()
            .map(str::trim)
            .filter(|detail| !detail.is_empty())
            .map(str::to_string);
        self.filter = self
            .filter
            .as_deref()
            .map(|filter| filter.trim().to_string());
        self.kind = self.kind.as_deref().map(|kind| kind.trim().to_lowercase());
    }

    /// Checks everything that doesn't need the database, and says what's wrong in a
    /// way that can be shown to whoever sent it.
    pub fn check(&self, now_ms: i64) -> Result<EventKind, String> {
        let kind = match self.kind.as_deref() {
            None | Some("") => EventKind::Note,
            Some(text) => EventKind::parse(text)
                .filter(|kind| kind.is_recorded_by_people())
                .ok_or("An event's kind has to be deploy or note.")?,
        };
        if self.title.is_empty() {
            return Err("An event needs a title.".into());
        }
        if self.title.chars().count() > MAX_TITLE_LEN {
            return Err(format!(
                "A title can be at most {MAX_TITLE_LEN} characters."
            ));
        }
        if self
            .detail
            .as_deref()
            .is_some_and(|detail| detail.chars().count() > MAX_DETAIL_LEN)
        {
            return Err(format!(
                "Detail can be at most {MAX_DETAIL_LEN} characters."
            ));
        }
        if let Some(time) = self.time_ms
            && !(now_ms - LONGEST_AGO_MS..=now_ms + FURTHEST_AHEAD_MS).contains(&time)
        {
            return Err("An event's time has to be within the last year.".into());
        }
        let filter = self.filter.as_deref().unwrap_or_default();
        if filter.chars().count() > MAX_FILTER_LEN {
            return Err(format!(
                "A filter can be at most {MAX_FILTER_LEN} characters."
            ));
        }
        HostFilter::parse(filter)?;
        Ok(kind)
    }
}

/// An annotation as it was recorded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Event {
    pub id: i64,
    pub time_ms: i64,
    pub kind: EventKind,
    pub title: String,
    pub detail: Option<String>,
    pub filter: String,
    pub created_by: String,
    pub created_ms: i64,
}

/// One thing on a host's timeline, from wherever it came from. Only those that were
/// recorded have an `id`, and only they can be deleted.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimelineEvent {
    pub time_ms: i64,
    pub kind: EventKind,
    pub title: String,
    pub detail: Option<String>,
    pub created_by: Option<String>,
    pub id: Option<i64>,
}

/// Facts whose changes are worth marking, and what to call them.
pub const UPDATE_FACTS: [(&str, &str); 3] = [
    ("agent.version", "Agent"),
    ("os.version", "OS"),
    ("os.kernel", "Kernel"),
];

/// A host is only taken to have restarted when its boot time moves by more than
/// this, as some systems work it out from the uptime and it wobbles.
pub const BOOT_TIME_SLACK_MS: i64 = 60_000;

/// Whether a boot time reported now means the host restarted since `known`.
pub fn restarted(known: Option<i64>, reported: i64) -> bool {
    known.is_some_and(|known| (reported - known).abs() > BOOT_TIME_SLACK_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000 * DAY_MS;

    fn input(title: &str) -> EventInput {
        EventInput {
            title: title.to_string(),
            ..EventInput::default()
        }
    }

    #[test]
    fn an_event_is_a_note_unless_it_says_it_is_a_deploy() {
        assert_eq!(input("x").check(NOW), Ok(EventKind::Note));
        let deploy = EventInput {
            kind: Some("deploy".into()),
            ..input("x")
        };
        assert_eq!(deploy.check(NOW), Ok(EventKind::Deploy));
    }

    #[test]
    fn people_can_not_record_what_the_server_works_out() {
        for kind in [
            "restart", "config", "alert", "resolved", "update", "nonsense",
        ] {
            let event = EventInput {
                kind: Some(kind.into()),
                ..input("x")
            };
            assert!(event.check(NOW).is_err(), "{kind}");
        }
    }

    #[test]
    fn a_title_is_needed_and_limited() {
        let mut blank = input("   ");
        blank.tidy();
        assert!(blank.check(NOW).is_err());
        assert!(input(&"x".repeat(MAX_TITLE_LEN)).check(NOW).is_ok());
        assert!(input(&"x".repeat(MAX_TITLE_LEN + 1)).check(NOW).is_err());
    }

    #[test]
    fn an_event_can_be_recorded_late_but_not_far_off() {
        let at = |time_ms| EventInput {
            time_ms: Some(time_ms),
            ..input("x")
        };
        assert!(at(NOW - 30 * DAY_MS).check(NOW).is_ok());
        assert!(at(NOW + 60_000).check(NOW).is_ok());
        assert!(at(NOW - 400 * DAY_MS).check(NOW).is_err());
        assert!(at(NOW + DAY_MS).check(NOW).is_err());
    }

    #[test]
    fn the_filter_has_to_make_sense() {
        let filtered = |filter: &str| EventInput {
            filter: Some(filter.into()),
            ..input("x")
        };
        assert!(filtered("role=web").check(NOW).is_ok());
        assert!(filtered("").check(NOW).is_ok());
        assert!(filtered("role=\"unclosed").check(NOW).is_err());
    }

    #[test]
    fn empty_detail_is_none() {
        let mut event = EventInput {
            detail: Some("  ".into()),
            ..input(" x ")
        };
        event.tidy();
        assert_eq!(event.detail, None);
        assert_eq!(event.title, "x");
    }

    #[test]
    fn a_restart_moves_the_boot_time_by_more_than_a_wobble() {
        assert!(!restarted(None, NOW));
        assert!(!restarted(Some(NOW), NOW + 1_000));
        assert!(restarted(Some(NOW), NOW + 3_600_000));
    }
}
