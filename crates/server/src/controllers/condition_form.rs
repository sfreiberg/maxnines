//! The "Applies to" part of a form, shared by everything that targets agents by
//! their facts. It shows a condition in the builder when it fits, or as an
//! expression when it doesn't, and works without any JavaScript.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use serde::Serialize;

use crate::condition_builder::{
    Builder, Clause, MAX_CLAUSES, MatchMode, OPERATORS, Operator, ValueKind,
};

const TOO_COMPLEX: &str = "This condition is too complex for the builder, so it's shown as an \
                          expression.";

/// A condition as its form shows it, including whatever was just typed.
#[derive(Serialize, Default)]
pub struct ConditionForm {
    /// The expression, when it's being written by hand.
    pub condition: String,
    /// Whether the expression box is showing instead of the builder.
    pub use_expression: bool,
    /// Why the builder can't show this condition.
    pub note: Option<String>,
    pub match_any: bool,
    pub clauses: Vec<ClauseRow>,
}

/// One row of the builder.
#[derive(Serialize, Clone)]
pub struct ClauseRow {
    pub fact: String,
    pub operator: String,
    pub value: String,
    pub kind: String,
}

impl ClauseRow {
    pub fn blank() -> Self {
        Self {
            fact: String::new(),
            operator: Operator::Equals.form_name().to_string(),
            value: String::new(),
            kind: ValueKind::Text.form_name().to_string(),
        }
    }

    fn from_clause(clause: Clause) -> Self {
        Self {
            fact: clause.fact,
            operator: clause.operator.form_name().to_string(),
            value: clause.value,
            kind: clause.kind.form_name().to_string(),
        }
    }

    pub fn is_blank(&self) -> bool {
        self.fact.trim().is_empty() && self.value.trim().is_empty()
    }

    fn to_clause(&self) -> Result<Clause> {
        Ok(Clause {
            fact: self.fact.trim().to_string(),
            operator: Operator::parse(&self.operator).context("unknown comparison")?,
            value: self.value.clone(),
            kind: ValueKind::parse(&self.kind),
        })
    }
}

#[derive(Serialize)]
pub struct OperatorOption {
    name: &'static str,
    label: &'static str,
}

/// The comparisons the builder offers.
pub fn operators() -> Vec<OperatorOption> {
    OPERATORS
        .iter()
        .map(|(_, name, label)| OperatorOption { name, label })
        .collect()
}

impl ConditionForm {
    pub fn blank() -> Self {
        Self {
            clauses: vec![ClauseRow::blank()],
            ..Self::default()
        }
    }

    /// Shows a condition in the builder if it fits there, or as text if not.
    pub fn set_condition(&mut self, condition: Option<&str>) {
        self.condition = condition.unwrap_or_default().to_string();
        match condition.map(Builder::from_expression) {
            None => self.clauses = vec![ClauseRow::blank()],
            Some(Some(builder)) => {
                self.match_any = builder.mode == MatchMode::Any;
                self.clauses = builder
                    .clauses
                    .into_iter()
                    .map(ClauseRow::from_clause)
                    .collect();
                self.use_expression = false;
                self.note = None;
            }
            Some(None) => {
                self.use_expression = true;
                self.note = Some(TOO_COMPLEX.to_string());
            }
        }
    }

    pub fn from_condition(condition: Option<&str>) -> Self {
        let mut form = Self::default();
        form.set_condition(condition);
        form
    }

    fn builder(&self) -> Result<Builder> {
        let clauses = self
            .clauses
            .iter()
            .filter(|row| !row.is_blank())
            .map(ClauseRow::to_clause)
            .collect::<Result<Vec<_>>>()?;
        let mode = if self.match_any {
            MatchMode::Any
        } else {
            MatchMode::All
        };
        Ok(Builder { mode, clauses })
    }

    pub fn expression(&self, known: &BTreeMap<String, String>) -> Result<Option<String>> {
        if self.use_expression {
            let condition = self.condition.trim();
            return Ok((!condition.is_empty()).then(|| condition.to_string()));
        }
        self.builder()?.to_expression(known)
    }

    pub fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            condition: text("condition"),
            use_expression: text("condition_mode") == "expression",
            note: None,
            match_any: text("match") == "any",
            clauses: (0..MAX_CLAUSES)
                .map_while(|index| {
                    fields.get(&format!("clause_fact_{index}"))?;
                    Some(ClauseRow {
                        fact: text(&format!("clause_fact_{index}")),
                        operator: text(&format!("clause_operator_{index}")),
                        value: text(&format!("clause_value_{index}")),
                        kind: text(&format!("clause_kind_{index}")),
                    })
                })
                .collect(),
        }
    }

    /// The builder's buttons change the form without saving it. Returns true if
    /// one of them was pressed.
    pub fn apply_action(&mut self, action: &str, known: &BTreeMap<String, String>) -> bool {
        if action == "add_clause" {
            if self.clauses.len() < MAX_CLAUSES {
                self.clauses.push(ClauseRow::blank());
            }
            return true;
        }

        if let Some(index) = action.strip_prefix("remove_clause_") {
            if let Some(index) = index
                .parse::<usize>()
                .ok()
                .filter(|i| *i < self.clauses.len())
            {
                self.clauses.remove(index);
            }
            if self.clauses.is_empty() {
                self.clauses.push(ClauseRow::blank());
            }
            return true;
        }

        match action {
            "use_expression" => {
                // Keep what's been built, if it's complete enough to write out.
                if let Ok(expression) = self.builder().and_then(|b| b.to_expression(known)) {
                    self.condition = expression.unwrap_or_default();
                }
                self.use_expression = true;
                self.note = None;
                true
            }
            "use_builder" => {
                let condition = self.condition.trim().to_string();
                self.use_expression = false;
                self.set_condition((!condition.is_empty()).then_some(condition.as_str()));
                true
            }
            _ => false,
        }
    }
}
