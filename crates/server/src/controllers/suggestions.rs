//! What the CEL fields on the pages suggest as people type: metrics by their names,
//! with the series of those that have fixed ones, facts, the names conditions know,
//! and functions. The pages' script asks for it once, so it's the real catalog, with
//! every template's metrics by their full names; the short names of a template's own
//! come with the form that has them.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use crate::alert_conditions::Variable;
use crate::app_state::AppState;
use crate::catalog::Catalog;
use crate::metrics::Source;

pub fn routes() -> Router<AppState> {
    Router::new().route("/conditions/suggestions", get(show))
}

/// The same for the API.
pub fn api_routes() -> Router<AppState> {
    Router::new().route("/conditions/suggestions", get(show))
}

#[derive(Debug, Serialize)]
pub struct MetricSuggestion {
    name: String,
    title: String,
    /// The series picked out with brackets, for a metric with fixed ones, like
    /// `cpu.load['5 minutes']`.
    series: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct NameSuggestion {
    name: &'static str,
    /// What's put in when it's picked.
    insert: &'static str,
    about: &'static str,
    /// Where it can be used: `condition`, `calculation`, `value`, `when` or
    /// `applies_to`.
    used_in: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub struct Suggestions {
    metrics: Vec<MetricSuggestion>,
    /// Facts hosts report, without `facts.`.
    facts: Vec<String>,
    variables: Vec<NameSuggestion>,
    functions: Vec<NameSuggestion>,
    /// Called on a value with a dot, like `series.startsWith('/var')`.
    methods: Vec<NameSuggestion>,
}

const CONDITIONS: &[&str] = &["condition"];

/// The functions conditions can call, beside the names of things.
pub const FUNCTIONS: [NameSuggestion; 13] = [
    NameSuggestion {
        name: "duration",
        insert: "duration('",
        about: "a length of time, like duration('5m')",
        used_in: &["condition", "value", "when", "applies_to"],
    },
    NameSuggestion {
        name: "forecast",
        insert: "forecast(",
        about: "where a metric is heading, like forecast(disk.usage, duration('4h'))",
        used_in: CONDITIONS,
    },
    NameSuggestion {
        name: "kib",
        insert: "kib(",
        about: "kibibytes, like kib(512)",
        used_in: &["condition", "value"],
    },
    NameSuggestion {
        name: "mib",
        insert: "mib(",
        about: "mebibytes, like mib(512)",
        used_in: &["condition", "value"],
    },
    NameSuggestion {
        name: "gib",
        insert: "gib(",
        about: "gibibytes, like gib(10)",
        used_in: &["condition", "value"],
    },
    NameSuggestion {
        name: "tib",
        insert: "tib(",
        about: "tebibytes, like tib(1)",
        used_in: &["condition", "value"],
    },
    NameSuggestion {
        name: "has",
        insert: "has(",
        about: "whether something is there, like has(facts.gpu.model)",
        used_in: &["condition", "when", "applies_to"],
    },
    NameSuggestion {
        name: "size",
        insert: "size(",
        about: "how long a list, map or text is",
        used_in: &["condition", "value", "when", "applies_to"],
    },
    NameSuggestion {
        name: "int",
        insert: "int(",
        about: "a whole number",
        used_in: &["condition", "value", "when", "applies_to"],
    },
    NameSuggestion {
        name: "double",
        insert: "double(",
        about: "a number with a fraction",
        used_in: &["condition", "value", "when", "applies_to"],
    },
    NameSuggestion {
        name: "string",
        insert: "string(",
        about: "text",
        used_in: &["condition", "value", "when", "applies_to"],
    },
    NameSuggestion {
        name: "timestamp",
        insert: "timestamp('",
        about: "a moment, like timestamp('2026-01-01T00:00:00Z')",
        used_in: &["condition", "when", "applies_to"],
    },
    NameSuggestion {
        name: "matches",
        insert: "matches(",
        about: "whether text matches a regular expression",
        used_in: &["condition", "when", "applies_to"],
    },
];

const EVERYWHERE: &[&str] = &["condition", "value", "when", "applies_to"];

pub const METHODS: [NameSuggestion; 6] = [
    NameSuggestion {
        name: "startsWith",
        insert: "startsWith('",
        about: "whether text starts with some other",
        used_in: EVERYWHERE,
    },
    NameSuggestion {
        name: "endsWith",
        insert: "endsWith('",
        about: "whether text ends with some other",
        used_in: EVERYWHERE,
    },
    NameSuggestion {
        name: "contains",
        insert: "contains('",
        about: "whether text has some other in it",
        used_in: EVERYWHERE,
    },
    NameSuggestion {
        name: "matches",
        insert: "matches('",
        about: "whether text matches a regular expression",
        used_in: EVERYWHERE,
    },
    NameSuggestion {
        name: "exists",
        insert: "exists(",
        about: "whether any item in a list or map holds, like m.exists(k, m[k] > 1)",
        used_in: EVERYWHERE,
    },
    NameSuggestion {
        name: "all",
        insert: "all(",
        about: "whether every item in a list or map holds",
        used_in: EVERYWHERE,
    },
];

fn variable(variable: Variable) -> NameSuggestion {
    let used_in: &'static [&'static str] = match variable {
        Variable::Facts => EVERYWHERE,
        Variable::Value => &["calculation", "value"],
        _ => CONDITIONS,
    };
    NameSuggestion {
        name: variable.name(),
        insert: match variable {
            Variable::Facts => "facts.",
            _ => variable.name(),
        },
        about: variable.describe(),
        used_in,
    }
}

/// Everything there is to suggest: the metrics of `catalog`, and facts from the
/// hosts there are.
pub fn suggestions(catalog: &Catalog, facts: Vec<String>) -> Suggestions {
    Suggestions {
        metrics: catalog
            .all()
            .iter()
            .map(|metric| MetricSuggestion {
                name: metric.name.clone(),
                title: metric.title.clone(),
                series: match &metric.source {
                    Source::Fields(fields) => fields.iter().map(|(name, _)| *name).collect(),
                    _ => Vec::new(),
                },
            })
            .collect(),
        facts,
        variables: Variable::ALL.into_iter().map(variable).collect(),
        functions: FUNCTIONS.into_iter().collect(),
        methods: METHODS.into_iter().collect(),
    }
}

async fn show(State(state): State<AppState>) -> Response {
    // Names to suggest. Typing still works without them, so a failure isn't worth
    // stopping for.
    let facts = state
        .database
        .known_facts()
        .await
        .unwrap_or_default()
        .into_keys()
        .collect();
    Json(suggestions(&state.catalog(), facts)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_function_suggested_is_one_conditions_have() {
        use crate::alert_conditions::{Condition, Names, Scope};
        // CEL's macros, which aren't functions, as conditions use them.
        let macros = [
            ("has", "has(facts.gpu.model)"),
            ("exists", "facts.tags.exists(t, t == 'web')"),
            ("all", "facts.tags.all(t, t != 'web')"),
        ];
        for suggestion in FUNCTIONS.iter().chain(&METHODS) {
            assert!(suggestion.insert.starts_with(suggestion.name));
            match macros.iter().find(|(name, _)| *name == suggestion.name) {
                Some((_, example)) => {
                    let catalog = Catalog::built_in();
                    Condition::compile(example, Scope::Hosts, &Names::of(&catalog)).unwrap();
                }
                None => assert!(
                    crate::alert_conditions::is_function(suggestion.name),
                    "{}",
                    suggestion.name
                ),
            }
        }
    }

    #[test]
    fn metrics_with_fixed_series_say_which() {
        let all = suggestions(&Catalog::built_in(), vec!["os.family".to_string()]);
        let load = all.metrics.iter().find(|m| m.name == "cpu.load").unwrap();
        assert_eq!(load.series, ["1 minute", "5 minutes", "15 minutes"]);
        let usage = all.metrics.iter().find(|m| m.name == "disk.usage").unwrap();
        assert!(usage.series.is_empty());
        assert!(all.variables.iter().any(|v| v.name == "online"));
        assert_eq!(all.facts, ["os.family"]);
    }
}
