//! Turns simple conditions into CEL expressions and back, so people can write
//! rules with form fields. Rules only ever store the expression. Anything the
//! builder can't represent stays as text, because reading it back only succeeds
//! if the result would be written out exactly the same.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use serde::Serialize;

/// The most conditions one rule can have in the builder.
pub const MAX_CLAUSES: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Includes,
    GreaterThan,
    LessThan,
    Exists,
    Missing,
}

/// In the order they're offered: the name a form uses, then what people read.
pub const OPERATORS: [(Operator, &str, &str); 10] = [
    (Operator::Equals, "equals", "is"),
    (Operator::NotEquals, "not_equals", "is not"),
    (Operator::Contains, "contains", "contains text"),
    (Operator::StartsWith, "starts_with", "starts with"),
    (Operator::EndsWith, "ends_with", "ends with"),
    (Operator::Includes, "includes", "list includes"),
    (Operator::GreaterThan, "greater_than", "is more than"),
    (Operator::LessThan, "less_than", "is less than"),
    (Operator::Exists, "exists", "exists"),
    (Operator::Missing, "missing", "doesn't exist"),
];

impl Operator {
    pub fn parse(name: &str) -> Option<Self> {
        OPERATORS
            .iter()
            .find(|(_, form_name, _)| *form_name == name)
            .map(|(operator, _, _)| *operator)
    }

    pub fn form_name(self) -> &'static str {
        OPERATORS
            .iter()
            .find(|(operator, _, _)| *operator == self)
            .map_or("equals", |(_, form_name, _)| form_name)
    }

    fn label(self) -> &'static str {
        OPERATORS
            .iter()
            .find(|(operator, _, _)| *operator == self)
            .map_or("is", |(_, _, label)| label)
    }

    fn needs_value(self) -> bool {
        !matches!(self, Self::Exists | Self::Missing)
    }
}

/// How a value is written in an expression. `"1"` and `1` never match each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Text,
    Number,
    Boolean,
}

impl ValueKind {
    pub fn parse(name: &str) -> Self {
        match name {
            "number" => Self::Number,
            "boolean" => Self::Boolean,
            _ => Self::Text,
        }
    }

    pub fn form_name(self) -> &'static str {
        match self {
            Self::Text => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Clause {
    /// A fact's name, such as `os.family`.
    pub fact: String,
    pub operator: Operator,
    pub value: String,
    pub kind: ValueKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    All,
    Any,
}

impl MatchMode {
    fn joiner(self) -> &'static str {
        match self {
            Self::All => " && ",
            Self::Any => " || ",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::All => " and ",
            Self::Any => " or ",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    pub mode: MatchMode,
    pub clauses: Vec<Clause>,
}

impl Builder {
    /// `None` means no conditions, so the rule applies to every agent.
    pub fn to_expression(&self, known: &BTreeMap<String, String>) -> Result<Option<String>> {
        ensure!(
            self.clauses.len() <= MAX_CLAUSES,
            "a rule can have at most {MAX_CLAUSES} conditions"
        );
        let parts = self
            .clauses
            .iter()
            .map(|clause| clause_expression(clause, known))
            .collect::<Result<Vec<_>>>()?;

        Ok((!parts.is_empty()).then(|| parts.join(self.mode.joiner())))
    }

    /// Reads an expression back, or returns `None` if it's too complex.
    pub fn from_expression(expression: &str) -> Option<Self> {
        let expression = expression.trim();
        let (mode, parts) = split(expression)?;
        let clauses = parts
            .iter()
            .map(|part| parse_clause(part))
            .collect::<Option<Vec<_>>>()?;

        let builder = Self { mode, clauses };
        let rewritten = builder.to_expression(&BTreeMap::new()).ok()??;
        (rewritten == expression).then_some(builder)
    }

    /// Says what a condition means in plain words.
    pub fn describe(&self) -> String {
        let parts: Vec<String> = self
            .clauses
            .iter()
            .map(|clause| {
                let label = clause.operator.label();
                if clause.operator.needs_value() {
                    format!("{} {label} {}", clause.fact, clause.value)
                } else {
                    format!("{} {label}", clause.fact)
                }
            })
            .collect();
        parts.join(self.mode.word())
    }
}

fn clause_expression(clause: &Clause, known: &BTreeMap<String, String>) -> Result<String> {
    let path = fact_path(&clause.fact)?;
    let value = clause.value.trim();
    if clause.operator.needs_value() {
        ensure!(!value.is_empty(), "{} needs a value", clause.fact);
    }

    let kind = known
        .get(&clause.fact)
        .map_or(clause.kind, |name| ValueKind::parse(name));

    Ok(match clause.operator {
        Operator::Equals => format!("{path} == {}", literal(value, kind, &clause.fact)?),
        Operator::NotEquals => format!("{path} != {}", literal(value, kind, &clause.fact)?),
        Operator::Contains => format!("{path}.contains({})", quote(value)),
        Operator::StartsWith => format!("{path}.startsWith({})", quote(value)),
        Operator::EndsWith => format!("{path}.endsWith({})", quote(value)),
        Operator::Includes => format!("{} in {path}", literal(value, kind, &clause.fact)?),
        Operator::GreaterThan => format!("{path} > {}", number(value, &clause.fact)?),
        Operator::LessThan => format!("{path} < {}", number(value, &clause.fact)?),
        Operator::Exists => format!("has({path})"),
        Operator::Missing => format!("!has({path})"),
    })
}

/// Names are checked strictly, because they're written into the expression.
fn fact_path(name: &str) -> Result<String> {
    let name = name.trim();
    ensure!(!name.is_empty(), "every condition needs a fact");

    let mut path = String::from("facts");
    for part in name.split('.') {
        let is_identifier = part.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if is_identifier {
            path.push('.');
            path.push_str(part);
        } else {
            let is_plain = !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
            if !is_plain {
                bail!("{name:?} isn't a fact name");
            }
            path.push_str(&format!("[\"{part}\"]"));
        }
    }
    Ok(path)
}

fn literal(value: &str, kind: ValueKind, fact: &str) -> Result<String> {
    Ok(match kind {
        ValueKind::Text => quote(value),
        ValueKind::Number => number(value, fact)?,
        ValueKind::Boolean => match value {
            "true" | "false" => value.to_string(),
            _ => bail!("{fact} must be true or false"),
        },
    })
}

/// Only what CEL reads as a number: digits, with an optional sign and fraction.
/// Rust would also take "1." or "1e3", which CEL refuses with a cryptic error.
fn number(value: &str, fact: &str) -> Result<String> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    let (whole, fraction) = match digits.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (digits, None),
    };
    let all_digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let is_number = all_digits(whole) && fraction.is_none_or(all_digits);
    ensure!(is_number, "{fact} needs a number");
    Ok(value.to_string())
}

/// Everything that could end the string is escaped, so a value is only a value.
fn quote(value: &str) -> String {
    let mut text = String::with_capacity(value.len() + 2);
    text.push('"');
    for character in value.chars() {
        match character {
            '\\' => text.push_str("\\\\"),
            '"' => text.push_str("\\\""),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            '\t' => text.push_str("\\t"),
            other => text.push(other),
        }
    }
    text.push('"');
    text
}

/// Splits on the top-level `&&` or `||`. Using both needs brackets to mean
/// anything clear, so that's left to the expression box.
fn split(expression: &str) -> Option<(MatchMode, Vec<String>)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut mode = None;
    let mut in_string = false;
    let mut characters = expression.chars().peekable();

    while let Some(character) = characters.next() {
        if in_string {
            current.push(character);
            match character {
                '\\' => current.extend(characters.next()),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        let found = match character {
            '"' => {
                in_string = true;
                None
            }
            '&' if characters.peek() == Some(&'&') => Some(MatchMode::All),
            '|' if characters.peek() == Some(&'|') => Some(MatchMode::Any),
            _ => None,
        };

        match found {
            Some(next) => {
                if mode.is_some_and(|mode| mode != next) {
                    return None;
                }
                mode = Some(next);
                characters.next();
                parts.push(current.trim().to_string());
                current.clear();
            }
            None => current.push(character),
        }
    }

    parts.push(current.trim().to_string());
    Some((mode.unwrap_or(MatchMode::All), parts))
}

fn parse_clause(text: &str) -> Option<Clause> {
    let clause = |fact: String, operator, value: String, kind| Clause {
        fact,
        operator,
        value,
        kind,
    };

    if let Some(inner) = text.strip_prefix("!has(").and_then(|t| t.strip_suffix(')')) {
        let (fact, rest) = parse_path(inner)?;
        return rest
            .is_empty()
            .then(|| clause(fact, Operator::Missing, String::new(), ValueKind::Text));
    }
    if let Some(inner) = text.strip_prefix("has(").and_then(|t| t.strip_suffix(')')) {
        let (fact, rest) = parse_path(inner)?;
        return rest
            .is_empty()
            .then(|| clause(fact, Operator::Exists, String::new(), ValueKind::Text));
    }

    if !text.starts_with("facts") {
        let (value, kind, rest) = parse_literal(text)?;
        let (fact, rest) = parse_path(rest.strip_prefix(" in ")?)?;
        return rest
            .is_empty()
            .then(|| clause(fact, Operator::Includes, value, kind));
    }

    let (fact, rest) = parse_path(text)?;
    for (call, operator) in [
        (".contains(", Operator::Contains),
        (".startsWith(", Operator::StartsWith),
        (".endsWith(", Operator::EndsWith),
    ] {
        if let Some(argument) = rest.strip_prefix(call).and_then(|t| t.strip_suffix(')')) {
            let (value, kind, after) = parse_literal(argument)?;
            return (after.is_empty() && kind == ValueKind::Text)
                .then(|| clause(fact, operator, value, kind));
        }
    }
    for (symbol, operator) in [
        (" == ", Operator::Equals),
        (" != ", Operator::NotEquals),
        (" > ", Operator::GreaterThan),
        (" < ", Operator::LessThan),
    ] {
        if let Some(argument) = rest.strip_prefix(symbol) {
            let (value, kind, after) = parse_literal(argument)?;
            return after
                .is_empty()
                .then(|| clause(fact, operator, value, kind));
        }
    }
    None
}

/// Reads `facts.a.b` or `facts.a["b-c"]`, returning the name and what's left.
fn parse_path(text: &str) -> Option<(String, &str)> {
    let mut rest = text.strip_prefix("facts")?;
    let mut parts = Vec::new();

    loop {
        if let Some(after) = rest.strip_prefix("[\"") {
            let (part, after) = after.split_once("\"]")?;
            parts.push(part.to_string());
            rest = after;
        } else if let Some(after) = rest.strip_prefix('.') {
            let end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            // A method call such as `.contains(` isn't part of the name.
            if end == 0 || after[end..].starts_with('(') {
                break;
            }
            parts.push(after[..end].to_string());
            rest = &after[end..];
        } else {
            break;
        }
    }

    (!parts.is_empty()).then(|| (parts.join("."), rest))
}

/// Reads a string, number or boolean, returning what's left after it.
fn parse_literal(text: &str) -> Option<(String, ValueKind, &str)> {
    if let Some(body) = text.strip_prefix('"') {
        let mut value = String::new();
        let mut characters = body.char_indices();
        while let Some((index, character)) = characters.next() {
            match character {
                '"' => return Some((value, ValueKind::Text, &body[index + 1..])),
                '\\' => match characters.next()?.1 {
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    '\\' => value.push('\\'),
                    '"' => value.push('"'),
                    _ => return None,
                },
                other => value.push(other),
            }
        }
        return None;
    }

    let end = text.find(' ').unwrap_or(text.len());
    let (word, rest) = text.split_at(end);
    match word {
        "true" | "false" => Some((word.to_string(), ValueKind::Boolean, rest)),
        _ => {
            word.parse::<f64>().ok()?;
            Some((word.to_string(), ValueKind::Number, rest))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn only_numbers_cel_accepts_pass_as_numbers() {
        for good in ["1", "-1", "1.5", "0.25", "-0.5", "1000000"] {
            assert_eq!(number(good, "f").unwrap(), good);
        }
        for bad in [
            "1.", ".5", "1e3", "1_000", "", "-", "1.2.3", "NaN", "inf", " 1",
        ] {
            assert!(number(bad, "f").is_err(), "{bad:?}");
        }
    }

    use super::*;
    use crate::rule_engine::evaluate;

    fn clause(fact: &str, operator: Operator, value: &str, kind: ValueKind) -> Clause {
        Clause {
            fact: fact.to_string(),
            operator,
            value: value.to_string(),
            kind,
        }
    }

    fn text(fact: &str, operator: Operator, value: &str) -> Clause {
        clause(fact, operator, value, ValueKind::Text)
    }

    fn all(clauses: Vec<Clause>) -> Builder {
        Builder {
            mode: MatchMode::All,
            clauses,
        }
    }

    fn expression(clauses: Vec<Clause>) -> String {
        all(clauses)
            .to_expression(&BTreeMap::new())
            .unwrap()
            .unwrap()
    }

    fn facts() -> serde_json::Value {
        json!({
            "os": { "family": "linux", "version": "24.04" },
            "host": { "name": "web-01" },
            "memory": { "total_bytes": 1000 },
            "custom": {
                "role": "web",
                "tags": ["prod", "eu"],
                "rack": 12,
                "production": true,
                "has-dash": "yes",
                "quoted": "say \"hi\"",
            },
        })
    }

    fn matches(clause: Clause) -> bool {
        evaluate(&expression(vec![clause]), &facts(), "host-1").unwrap()
    }

    #[test]
    fn every_operator_writes_a_working_expression() {
        use Operator::*;
        let number = ValueKind::Number;

        assert!(matches(text("os.family", Equals, "linux")));
        assert!(!matches(text("os.family", Equals, "windows")));
        assert!(matches(text("os.family", NotEquals, "windows")));
        assert!(matches(text("host.name", Contains, "eb-")));
        assert!(matches(text("host.name", StartsWith, "web-")));
        assert!(matches(text("host.name", EndsWith, "-01")));
        assert!(matches(text("custom.tags", Includes, "prod")));
        assert!(!matches(text("custom.tags", Includes, "us")));
        assert!(matches(clause(
            "memory.total_bytes",
            GreaterThan,
            "500",
            number
        )));
        assert!(matches(clause(
            "memory.total_bytes",
            LessThan,
            "5000",
            number
        )));
        assert!(matches(clause("custom.rack", Equals, "12", number)));
        assert!(matches(clause(
            "custom.production",
            Equals,
            "true",
            ValueKind::Boolean
        )));
        assert!(matches(text("custom.role", Exists, "")));
        assert!(matches(text("custom.nothing", Missing, "")));
        assert!(matches(text("custom.has-dash", Equals, "yes")));
    }

    #[test]
    fn all_and_any_combine_conditions() {
        let linux = text("os.family", Operator::Equals, "linux");
        let windows = text("os.family", Operator::Equals, "windows");
        let builder = |mode| Builder {
            mode,
            clauses: vec![linux.clone(), windows.clone()],
        };
        let check = |mode| {
            let written = builder(mode)
                .to_expression(&BTreeMap::new())
                .unwrap()
                .unwrap();
            evaluate(&written, &facts(), "host-1").unwrap()
        };

        assert!(!check(MatchMode::All));
        assert!(check(MatchMode::Any));
    }

    #[test]
    fn no_conditions_means_every_agent() {
        assert_eq!(
            all(Vec::new()).to_expression(&BTreeMap::new()).unwrap(),
            None
        );
    }

    #[test]
    fn a_value_can_not_change_the_meaning_of_an_expression() {
        // Each tries to close the string and add a condition that's always true.
        for attack in [
            r#"x" || true || "y"#,
            r#"x\" || true || \"y"#,
            "x\" || true || \"y\n",
            r#"\"#,
            r#"\\" || true || "#,
        ] {
            let written = expression(vec![text("os.family", Operator::Equals, attack)]);
            assert!(!evaluate(&written, &facts(), "host-1").unwrap(), "{attack}");

            let written = expression(vec![text("host.name", Operator::Contains, attack)]);
            assert!(!evaluate(&written, &facts(), "host-1").unwrap(), "{attack}");
        }
    }

    #[test]
    fn a_value_with_quotes_still_matches_itself() {
        assert!(matches(text(
            "custom.quoted",
            Operator::Equals,
            r#"say "hi""#
        )));
    }

    #[test]
    fn a_fact_name_can_not_inject_an_expression() {
        for name in [
            "a || true",
            "a) || (true",
            "a\"]",
            "a[0]",
            "a..b",
            ".a",
            "os family",
            "",
        ] {
            let clause = text(name, Operator::Equals, "x");
            assert!(
                all(vec![clause]).to_expression(&BTreeMap::new()).is_err(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_number_can_not_inject_an_expression() {
        for value in ["1 || true", "1)", "abc", "NaN", "inf", "1e5"] {
            let clause = clause(
                "custom.rack",
                Operator::GreaterThan,
                value,
                ValueKind::Number,
            );
            assert!(
                all(vec![clause]).to_expression(&BTreeMap::new()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn missing_values_are_explained() {
        let clause = text("os.family", Operator::Equals, "   ");
        let error = all(vec![clause])
            .to_expression(&BTreeMap::new())
            .unwrap_err();
        assert!(error.to_string().contains("needs a value"), "{error}");
    }

    #[test]
    fn too_many_conditions_are_refused() {
        let clause = text("os.family", Operator::Equals, "linux");
        let builder = all(vec![clause; MAX_CLAUSES + 1]);
        assert!(builder.to_expression(&BTreeMap::new()).is_err());
    }

    #[test]
    fn the_known_type_of_a_fact_decides_how_its_value_is_written() {
        let known = BTreeMap::from([
            ("custom.rack".to_string(), "number".to_string()),
            ("os.version".to_string(), "string".to_string()),
            ("custom.production".to_string(), "boolean".to_string()),
        ]);
        let write = |clause| all(vec![clause]).to_expression(&known).unwrap().unwrap();

        assert_eq!(
            write(text("custom.rack", Operator::Equals, "12")),
            "facts.custom.rack == 12"
        );
        assert_eq!(
            write(text("os.version", Operator::Equals, "24")),
            r#"facts.os.version == "24""#
        );
        assert_eq!(
            write(text("custom.production", Operator::Equals, "true")),
            "facts.custom.production == true"
        );
    }

    #[test]
    fn expressions_read_back_into_the_same_conditions() {
        use Operator::*;
        let number = ValueKind::Number;

        for builder in [
            all(vec![text("os.family", Equals, "linux")]),
            all(vec![text("os.family", NotEquals, "linux")]),
            all(vec![text("host.name", Contains, "web")]),
            all(vec![text("host.name", StartsWith, "web-")]),
            all(vec![text("host.name", EndsWith, "-01")]),
            all(vec![text("custom.tags", Includes, "prod")]),
            all(vec![clause("custom.ports", Includes, "443", number)]),
            all(vec![clause(
                "memory.total_bytes",
                GreaterThan,
                "500",
                number,
            )]),
            all(vec![clause("memory.total_bytes", LessThan, "1.5", number)]),
            all(vec![clause("custom.rack", Equals, "12", number)]),
            all(vec![clause(
                "custom.on",
                Equals,
                "true",
                ValueKind::Boolean,
            )]),
            all(vec![text("custom.role", Exists, "")]),
            all(vec![text("custom.role", Missing, "")]),
            all(vec![text("custom.has-dash", Equals, "yes")]),
            all(vec![text("custom.note", Equals, r#"say "hi" && \bye\"#)]),
            all(vec![text("custom.note", Equals, "line\nbreak")]),
            all(vec![
                text("os.family", Equals, "linux"),
                text("host.name", StartsWith, "web"),
            ]),
            Builder {
                mode: MatchMode::Any,
                clauses: vec![
                    text("os.family", Equals, "linux"),
                    text("os.family", Equals, "freebsd"),
                ],
            },
        ] {
            let written = builder.to_expression(&BTreeMap::new()).unwrap().unwrap();
            assert_eq!(
                Builder::from_expression(&written),
                Some(builder),
                "{written}"
            );
        }
    }

    #[test]
    fn expressions_the_builder_can_not_show_are_left_alone() {
        for expression in [
            "true",
            "1 + 1",
            r#"facts.a == "x" && facts.b == "y" || facts.c == "z""#,
            r#"(facts.a == "x")"#,
            r#"!(facts.a == "x")"#,
            r#"facts.a=="x""#,
            r#"facts.a.size() > 1"#,
            r#"facts.a == facts.b"#,
            r#"trusted.host_id == "x""#,
            r#"facts.a.matches("x.*")"#,
            r#"facts.a in ["x", "y"]"#,
            r#"facts.a == "x" && "#,
            "",
        ] {
            assert_eq!(Builder::from_expression(expression), None, "{expression}");
        }
    }

    #[test]
    fn an_expression_that_would_be_rewritten_is_left_alone() {
        // Each means the same as something the builder writes, but different
        // text, and a rule's text is never changed behind someone's back.
        for expression in [
            r#"facts["a"] == "x""#,
            r#"facts.a == "x"   &&   facts.b == "y""#,
            r#""prod" in facts["tags"]"#,
            r#"has(facts["a"])"#,
        ] {
            assert_eq!(Builder::from_expression(expression), None, "{expression}");
        }
    }

    #[test]
    fn conditions_are_described_in_plain_words() {
        let builder = all(vec![
            text("os.family", Operator::Equals, "linux"),
            text("custom.role", Operator::Exists, ""),
        ]);

        assert_eq!(
            builder.describe(),
            "os.family is linux and custom.role exists"
        );
    }

    #[test]
    fn every_operator_can_be_found_by_its_form_name() {
        for (operator, name, _) in OPERATORS {
            assert_eq!(Operator::parse(name), Some(operator));
            assert_eq!(operator.form_name(), name);
        }
        assert_eq!(Operator::parse("nope"), None);
    }
}
