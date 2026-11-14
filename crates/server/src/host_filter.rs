//! Filters for finding hosts, in the style of a GitHub search box: `os=linux
//! hostname=web*`. Every term has to match. A word on its own looks for that text in
//! the host name, and `*` and `?` work as wildcards in values.

use std::collections::BTreeSet;
use std::ops::Range;

use serde::Serialize;
use serde_json::Value;
use wildmatch::WildMatch;

use crate::facts::{FlatFacts, fact_text};

/// Far more than anyone types, and it bounds the work one request can ask for.
const MAX_TERMS: usize = 20;
/// How many suggestions to offer at once.
pub const MAX_SUGGESTIONS: usize = 12;

/// The name people look for most. The hostname isn't a fact, as hosts are listed
/// before their agents have reported any.
const HOSTNAME: &str = "hostname";
/// Picks out one host whatever it's called, as names needn't be unique.
const ID_NAME: &str = "id";
const OS_NAME: &str = "os";
const OS_FACT: &str = "os.family";

#[derive(Debug)]
enum Term {
    /// Text anywhere in the host name, in lower case.
    Text(String),
    Host {
        pattern: String,
        negated: bool,
    },
    /// The agent's ID, or the start of it with a wildcard.
    Id {
        pattern: String,
        negated: bool,
    },
    Fact {
        name: String,
        pattern: String,
        negated: bool,
    },
}

#[derive(Debug, Default)]
pub struct HostFilter {
    terms: Vec<Term>,
}

fn matches(pattern: &str, text: &str) -> bool {
    WildMatch::new_case_insensitive(pattern).matches(text)
}

/// Splits on spaces, except inside double quotes.
fn split_terms(text: &str) -> Result<Vec<String>, String> {
    let mut terms = Vec::new();
    let mut term = String::new();
    let mut quoted = false;
    for character in text.chars() {
        match character {
            '"' => quoted = !quoted,
            space if space.is_whitespace() && !quoted => {
                if !term.is_empty() {
                    terms.push(std::mem::take(&mut term));
                }
            }
            other => term.push(other),
        }
    }
    if quoted {
        return Err("A quote isn't closed.".to_string());
    }
    if !term.is_empty() {
        terms.push(term);
    }
    Ok(terms)
}

fn parse_term(text: &str) -> Result<Term, String> {
    let Some((name, value)) = text.split_once('=') else {
        return Ok(Term::Text(text.to_lowercase()));
    };
    let (name, negated) = match name.strip_suffix('!') {
        Some(name) => (name, true),
        None => (name, false),
    };
    if name.is_empty() {
        return Err(format!("\"{text}\" needs a name before the =."));
    }
    if value.is_empty() {
        return Err(format!("{name} needs a value, like {name}=web*."));
    }
    let pattern = value.to_string();
    Ok(if name == HOSTNAME {
        Term::Host { pattern, negated }
    } else if name == ID_NAME {
        Term::Id { pattern, negated }
    } else {
        Term::Fact {
            name: fact_name(name).to_string(),
            pattern,
            negated,
        }
    })
}

/// The fact a name in a filter means.
pub fn fact_name(name: &str) -> &str {
    if name == OS_NAME { OS_FACT } else { name }
}

impl HostFilter {
    /// The error says what's wrong in a way that can be shown to whoever typed it.
    pub fn parse(text: &str) -> Result<Self, String> {
        let terms = split_terms(text)?;
        if terms.len() > MAX_TERMS {
            return Err(format!("A filter can have up to {MAX_TERMS} terms."));
        }
        let terms = terms
            .iter()
            .map(|term| parse_term(term))
            .collect::<Result<_, _>>()?;
        Ok(Self { terms })
    }

    /// The facts this filter looks at, so only those need loading.
    pub fn fact_names(&self) -> BTreeSet<&str> {
        self.terms
            .iter()
            .filter_map(|term| match term {
                Term::Fact { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    pub fn matches(&self, id: &str, hostname: &str, facts: Option<&FlatFacts>) -> bool {
        self.terms.iter().all(|term| match term {
            Term::Text(text) => hostname.to_lowercase().contains(text),
            Term::Host { pattern, negated } => matches(pattern, hostname) != *negated,
            Term::Id { pattern, negated } => matches(pattern, id) != *negated,
            Term::Fact {
                name,
                pattern,
                negated,
            } => facts.is_some_and(|facts| fact_matches(facts, name, pattern)) != *negated,
        })
    }
}

/// A list matches if any item does, as it's stored as `name[0]`, `name[1]` and so on.
fn fact_matches(facts: &FlatFacts, name: &str, pattern: &str) -> bool {
    let list = format!("{name}[");
    let items = facts
        .range(list.clone()..)
        .take_while(|(item, _)| item.starts_with(&list))
        .map(|(_, value)| value);
    let value_matches = |value: &Value| matches(pattern, &fact_text(value));
    facts.get(name).is_some_and(value_matches) || items.into_iter().any(value_matches)
}

/// Something the filter box can offer. `text` replaces what's being typed.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub text: String,
    pub label: String,
}

/// What's being typed, once it's got as far as a value.
pub struct PartialValue<'a> {
    written_name: &'a str,
    operator: &'static str,
    pub partial: &'a str,
}

impl<'a> PartialValue<'a> {
    /// `None` while the name is still being typed.
    pub fn of(term: &'a str) -> Option<Self> {
        let (name, partial) = term.split_once('=')?;
        let (written_name, operator) = match name.strip_suffix('!') {
            Some(name) => (name, "!="),
            None => (name, "="),
        };
        let partial = partial.trim_start_matches('"');
        Some(Self {
            written_name,
            operator,
            partial,
        })
    }

    pub fn is_host(&self) -> bool {
        self.written_name == HOSTNAME
    }

    pub fn is_id(&self) -> bool {
        self.written_name == ID_NAME
    }

    pub fn fact(&self) -> &str {
        fact_name(self.written_name)
    }

    pub fn suggestion(&self, value: &str) -> Suggestion {
        Suggestion {
            text: format!(
                "{}{}{}",
                self.written_name,
                self.operator,
                written_value(value)
            ),
            label: value.to_string(),
        }
    }

    /// A suggestion shown as something other than the value it fills in, such as
    /// an agent's name for its ID.
    pub fn labelled(&self, value: &str, label: String) -> Suggestion {
        Suggestion {
            label,
            ..self.suggestion(value)
        }
    }
}

/// A value as a filter has to write it, so it stays one term. There's no way to
/// write a quote inside quotes, so it's left to a wildcard.
pub fn written_value(value: &str) -> String {
    let safe = value.replace('"', "?");
    if safe.chars().any(char::is_whitespace) {
        format!("\"{safe}\"")
    } else {
        safe
    }
}

/// Where each term is in `text`, quotes and all, split the way [`HostFilter::parse`]
/// splits them.
pub fn term_spans(text: &str) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut start = None;
    let mut quoted = false;
    for (index, character) in text.char_indices() {
        if character == '"' {
            quoted = !quoted;
        }
        if character.is_whitespace() && !quoted {
            if let Some(start) = start.take() {
                spans.push(start..index);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start) = start {
        spans.push(start..text.len());
    }
    spans
}

/// The filter for one host alone, by its ID, as names needn't be unique.
pub fn only(host_id: &str) -> String {
    format!("{ID_NAME}={host_id}")
}

/// Names matching what's been typed, those starting with it first.
pub fn suggest_names(term: &str, facts: impl IntoIterator<Item = String>) -> Vec<Suggestion> {
    let term = term.to_lowercase();
    let mut names: BTreeSet<String> = facts.into_iter().collect();
    names.extend([
        HOSTNAME.to_string(),
        ID_NAME.to_string(),
        OS_NAME.to_string(),
    ]);

    let mut found: Vec<String> = names
        .into_iter()
        .filter(|name| name.to_lowercase().contains(&term))
        .collect();
    found.sort_by_key(|name| !name.to_lowercase().starts_with(&term));
    found.truncate(MAX_SUGGESTIONS);
    found
        .into_iter()
        .map(|name| Suggestion {
            text: format!("{name}="),
            label: name,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn terms_are_found_where_they_are_written() {
        let text = r#" os=linux  hostname="web 1" $host"#;
        let terms: Vec<&str> = term_spans(text)
            .into_iter()
            .map(|span| &text[span])
            .collect();
        assert_eq!(terms, ["os=linux", r#"hostname="web 1""#, "$host"]);
        assert!(term_spans("   ").is_empty());
    }

    #[test]
    fn a_written_value_is_one_term() {
        assert_eq!(written_value("linux"), "linux");
        assert_eq!(written_value("Ubuntu Linux"), r#""Ubuntu Linux""#);
        assert_eq!(written_value(r#"say "hi" there"#), r#""say ?hi? there""#);
        let term = format!("os.name={}", written_value("Windows Server 2022"));
        assert_eq!(term_spans(&term).len(), 1);
    }

    use serde_json::json;

    use super::*;

    fn facts() -> FlatFacts {
        FlatFacts::from([
            ("os.family".to_string(), json!("linux")),
            ("os.long_version".to_string(), json!("Ubuntu 22.04 LTS")),
            ("cpu.logical_cores".to_string(), json!(8)),
            ("custom.tags[0]".to_string(), json!("db")),
            ("custom.tags[1]".to_string(), json!("eu-west")),
            ("custom.tagsy".to_string(), json!("not a list item")),
        ])
    }

    const ID: &str = "3f2a1c9d0b7e4a6f8c1d2e3f4a5b6c7d";

    fn found(filter: &str) -> bool {
        HostFilter::parse(filter)
            .unwrap()
            .matches(ID, "Web-01.example.com", Some(&facts()))
    }

    /// Names needn't be unique, so the ID is how to mean one host.
    #[test]
    fn an_id_picks_out_one_host() {
        assert!(found(&format!("id={ID}")));
        assert!(found("id=3f2a1c9d*"));
        assert!(found("id!=abcdef*"));
        assert!(!found("id=abcdef*"));
        assert!(!found(&format!("id!={ID}")));
        assert!(found(&format!("web id={ID}")));
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        assert!(found(""));
        assert!(found("   "));
        let filter = HostFilter::parse("").unwrap();
        assert!(filter.matches(ID, "web", None));
    }

    #[test]
    fn a_word_looks_in_the_host_name() {
        assert!(found("web"));
        assert!(found("WEB-01"));
        assert!(!found("db"));
    }

    #[test]
    fn host_names_can_use_wildcards() {
        assert!(found("hostname=web*"));
        assert!(found("hostname=web-??.example.com"));
        // `host` is only ever a fact, never the hostname.
        assert!(!found("host=web*"));
        assert!(!found("hostname=web"));
        assert!(!found("hostname=db*"));
    }

    #[test]
    fn os_is_short_for_the_family() {
        assert!(found("os=linux"));
        assert!(found("os=LINUX"));
        assert!(!found("os=windows"));
    }

    #[test]
    fn facts_match_by_their_full_name() {
        assert!(found("os.family=linux"));
        assert!(found("os.family=li*"));
        assert!(!found("os.family=li"));
    }

    #[test]
    fn numbers_match_as_written() {
        assert!(found("cpu.logical_cores=8"));
        assert!(!found("cpu.logical_cores=16"));
    }

    #[test]
    fn quotes_keep_spaces_in_a_value() {
        assert!(found(r#"os.long_version="Ubuntu 22.04 LTS""#));
        assert!(found(r#"os.long_version="Ubuntu 22*""#));
    }

    #[test]
    fn any_item_of_a_list_can_match() {
        assert!(found("custom.tags=db"));
        assert!(found("custom.tags=eu-*"));
        assert!(!found("custom.tags=web"));
        assert!(!found("custom.tags=not*"), "custom.tagsy is another fact");
    }

    #[test]
    fn every_term_has_to_match() {
        assert!(found("web os=linux custom.tags=db"));
        assert!(!found("web os=windows"));
    }

    #[test]
    fn not_equals_excludes_what_matches() {
        assert!(found("os!=windows"));
        assert!(!found("os!=linux"));
        assert!(!found("hostname!=web*"));
        assert!(!found("custom.tags!=db"));
    }

    #[test]
    fn a_fact_nobody_reported_never_equals_anything() {
        assert!(!found("custom.rack=a1"));
        assert!(found("custom.rack!=a1"));
        let filter = HostFilter::parse("os=linux").unwrap();
        assert!(!filter.matches(ID, "web", None));
    }

    #[test]
    fn mistakes_are_explained() {
        for (text, error) in [
            ("=linux", "needs a name"),
            ("os=", "needs a value"),
            (r#"os="linux"#, "isn't closed"),
        ] {
            let found = HostFilter::parse(text).unwrap_err();
            assert!(found.contains(error), "{text}: {found}");
        }
        assert!(HostFilter::parse(&"a ".repeat(MAX_TERMS + 1)).is_err());
        assert!(HostFilter::parse(&"a ".repeat(MAX_TERMS)).is_ok());
    }

    #[test]
    fn only_the_facts_in_use_are_named() {
        let filter = HostFilter::parse("web hostname=a os=linux custom.tags!=db").unwrap();
        let names: Vec<&str> = filter.fact_names().into_iter().collect();
        assert_eq!(names, ["custom.tags", "os.family"]);
    }

    fn labels(suggestions: &[Suggestion]) -> Vec<&str> {
        suggestions.iter().map(|s| s.label.as_str()).collect()
    }

    #[test]
    fn names_are_suggested_with_the_best_matches_first() {
        let known = ["custom.os_image", "os.family", "memory.total_bytes"];
        let found = suggest_names("os", known.map(String::from));

        assert_eq!(
            labels(&found),
            ["os", "os.family", "custom.os_image", "hostname"]
        );
        assert_eq!(found[0].text, "os=");
    }

    #[test]
    fn names_are_limited() {
        let many = (0..100).map(|number| format!("custom.fact{number}"));
        assert_eq!(suggest_names("", many).len(), MAX_SUGGESTIONS);
    }

    #[test]
    fn a_term_with_an_equals_sign_is_asking_for_values() {
        assert!(PartialValue::of("os").is_none());

        let value = PartialValue::of("os=li").unwrap();
        assert_eq!(value.fact(), "os.family");
        assert_eq!(value.partial, "li");
        assert!(!value.is_host());
        assert!(PartialValue::of("hostname=").unwrap().is_host());
    }

    #[test]
    fn suggested_values_keep_what_was_typed() {
        let value = PartialValue::of("os!=").unwrap();
        assert_eq!(value.suggestion("linux").text, "os!=linux");

        let value = PartialValue::of(r#"os.name="Ubu"#).unwrap();
        assert_eq!(value.partial, "Ubu");
        assert_eq!(
            value.suggestion("Ubuntu Linux").text,
            r#"os.name="Ubuntu Linux""#
        );
    }

    #[test]
    fn a_suggested_value_can_always_be_read_back() {
        let value = PartialValue::of("custom.note=").unwrap();
        let reported = r#"a "quoted" word"#;

        let suggestion = value.suggestion(reported);

        let facts = FlatFacts::from([("custom.note".to_string(), json!(reported))]);
        let filter = HostFilter::parse(&suggestion.text).unwrap();
        assert!(filter.matches(ID, "web", Some(&facts)));
    }
}
