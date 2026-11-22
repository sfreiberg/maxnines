//! Writing a template as HCL, as [`super::parse`] reads it. Comments and layout
//! aren't kept: what's written is the template's own fields in the usual order.

use hcl::expr::{Heredoc, HeredocStripMode, TemplateExpr};
use hcl::{Block, Body, Expression, Identifier, Object, ObjectKey};
use indexmap::IndexMap;

use super::{Alert, Counters, Discover, Metric, Notice, Query, Target, Template};

/// The template as HCL.
pub fn to_hcl(template: &Template) -> String {
    let body = Body::builder().add_block(template_block(template)).build();
    let text = hcl::format::to_string(&body).unwrap_or_else(|error| {
        // A body built from strings, lists and maps always formats.
        unreachable!("formatting a template: {error}")
    });
    indent_heredocs(&text)
}

fn text(value: &str) -> Expression {
    let heredoc = value.contains('\n')
        && !value.contains("${")
        && !value.contains("%{")
        && !value.lines().any(|line| line.trim() == "EOT");
    if heredoc {
        let mut body = value.to_string();
        if !body.ends_with('\n') {
            body.push('\n');
        }
        let heredoc = Heredoc::new(Identifier::unchecked("EOT"), body)
            .with_strip_mode(HeredocStripMode::Indent);
        return Expression::TemplateExpr(Box::new(TemplateExpr::Heredoc(heredoc)));
    }
    Expression::String(value.to_string())
}

fn list(values: &[String]) -> Expression {
    Expression::Array(values.iter().map(|value| text(value)).collect())
}

fn map(values: &IndexMap<String, String>) -> Expression {
    let object: Object<ObjectKey, Expression> = values
        .iter()
        .map(|(key, value)| (ObjectKey::from(key_expression(key)), text(value)))
        .collect();
    Expression::Object(object)
}

/// A map's key: bare when it's a name, quoted otherwise, like `"12"`.
fn key_expression(key: &str) -> Expression {
    if super::is_key(key) {
        Expression::Variable(hcl::expr::Variable::unchecked(key))
    } else {
        Expression::String(key.to_string())
    }
}

struct Attributes(Vec<(String, Expression)>);

impl Attributes {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn add(&mut self, name: &str, value: Expression) {
        self.0.push((name.to_string(), value));
    }

    fn text(&mut self, name: &str, value: Option<&String>) {
        if let Some(value) = value {
            self.add(name, text(value));
        }
    }

    fn list(&mut self, name: &str, values: &[String]) {
        if !values.is_empty() {
            self.add(name, list(values));
        }
    }

    fn map(&mut self, name: &str, values: &IndexMap<String, String>) {
        if !values.is_empty() {
            self.add(name, map(values));
        }
    }

    /// `enabled = false`, the only way it's ever written.
    fn off(&mut self, enabled: bool) {
        if !enabled {
            self.add("enabled", Expression::Bool(false));
        }
    }

    fn block(self, identifier: &str, label: Option<&str>) -> hcl::structure::BlockBuilder {
        let mut block = Block::builder(identifier);
        if let Some(label) = label {
            block = block.add_label(label);
        }
        for (name, value) in self.0 {
            block = block.add_attribute((name, value));
        }
        block
    }
}

fn template_block(template: &Template) -> Block {
    let mut attributes = Attributes::new();
    attributes.add("name", text(&template.name));
    attributes.text("description", template.description.as_ref());
    match &template.target {
        Some(Target::Database(kind)) => attributes.add("database", text(kind)),
        Some(Target::Service(service)) => attributes.add("service", text(service)),
        Some(Target::Os(systems)) => attributes.add("os", list(systems)),
        None => {}
    }
    attributes.text("applies_to", template.applies_to.as_ref());
    attributes.text("min_version", template.min_version.as_ref());
    attributes.list("renamed_from", &template.renamed_from);
    attributes.off(template.enabled);
    attributes.list("services", &template.services);

    let mut block = attributes.block("template", Some(&template.key));
    if let Some(discover) = &template.discover {
        block = block.add_block(discover_block(discover));
    }
    for notice in &template.notices {
        block = block.add_block(notice_block(notice));
    }
    for query in &template.queries {
        block = block.add_block(query_block(query));
    }
    for counters in &template.counters {
        block = block.add_block(counters_block(counters));
    }
    for alert in &template.alerts {
        block = block.add_block(alert_block(alert));
    }
    block.build()
}

fn discover_block(discover: &Discover) -> Block {
    let mut attributes = Attributes::new();
    attributes.text("interval", discover.interval.as_ref());
    attributes.text("sql", discover.sql.as_ref());
    attributes.map("counter_sets", &discover.counter_sets);
    let mut block = attributes.block("discover", None);
    for read in &discover.registry {
        let mut values = Attributes::new();
        for (name, value) in &read.values {
            values.add(name, text(value));
        }
        block = block.add_block(values.block("registry", Some(&read.key)).build());
    }
    block.build()
}

fn notice_block(notice: &Notice) -> Block {
    let mut attributes = Attributes::new();
    attributes.text("when", notice.when.as_ref());
    attributes.add("text", text(&notice.text));
    attributes.block("notice", Some(&notice.key)).build()
}

/// `metrics = { … }`, with a counter that's only its name written as a string.
fn metrics(metrics: &[Metric]) -> Expression {
    let object: Object<ObjectKey, Expression> = metrics
        .iter()
        .map(|metric| {
            let value = match (&metric.counter, metric.is_only_counter()) {
                (Some(counter), true) => text(counter),
                _ => {
                    let mut fields: Object<ObjectKey, Expression> = Object::new();
                    let mut put = |name: &str, value: Expression| {
                        fields.insert(ObjectKey::from(key_expression(name)), value);
                    };
                    if let Some(counter) = &metric.counter {
                        put("counter", text(counter));
                    }
                    if metric.total {
                        put("total", Expression::Bool(true));
                    }
                    if let Some(unit) = &metric.unit {
                        put("unit", text(unit));
                    }
                    if let Some(value) = &metric.value {
                        put("value", text(value));
                    }
                    if let Some(since) = &metric.since {
                        put("since", text(since));
                    }
                    if let Some(description) = &metric.description {
                        put("description", text(description));
                    }
                    if !metric.states.is_empty() {
                        put("states", map(&metric.states));
                    }
                    Expression::Object(fields)
                }
            };
            (ObjectKey::from(key_expression(&metric.key)), value)
        })
        .collect();
    Expression::Object(object)
}

fn query_block(query: &Query) -> Block {
    let mut attributes = Attributes::new();
    attributes.off(query.enabled);
    attributes.text("when", query.when.as_ref());
    attributes.text("since", query.since.as_ref());
    attributes.text("interval", query.interval.as_ref());
    attributes.add("sql", text(&query.sql));
    attributes.list("labels", &query.labels);
    if !query.metrics.is_empty() {
        attributes.add("metrics", metrics(&query.metrics));
    }
    let mut block = attributes.block("query", Some(&query.key));
    for fill in &query.fills {
        let mut fields = Attributes::new();
        fields.map("versions", &fill.versions);
        fields.text("older", fill.older.as_ref());
        block = block.add_block(fields.block("fill", Some(&fill.key)).build());
    }
    block.build()
}

fn counters_block(counters: &Counters) -> Block {
    let mut attributes = Attributes::new();
    attributes.off(counters.enabled);
    attributes.text("when", counters.when.as_ref());
    attributes.text("since", counters.since.as_ref());
    attributes.text("interval", counters.interval.as_ref());
    attributes.add("object", text(&counters.object));
    attributes.text("label", counters.label.as_ref());
    attributes.text("pattern", counters.pattern.as_ref());
    attributes.text("instance", counters.instance.as_ref());
    attributes.list("exclude", &counters.exclude);
    attributes.map("groups", &counters.groups);
    if !counters.metrics.is_empty() {
        attributes.add("metrics", metrics(&counters.metrics));
    }
    let mut block = attributes.block("counters", Some(&counters.key));
    if let Some(join) = &counters.join {
        let mut fields = Attributes::new();
        fields.add("object", text(&join.object));
        fields.add("pattern", text(&join.pattern));
        block = block.add_block(fields.block("join", None).build());
    }
    block.build()
}

fn alert_block(alert: &Alert) -> Block {
    let mut attributes = Attributes::new();
    attributes.off(alert.enabled);
    attributes.add("name", text(&alert.name));
    attributes.text("when", alert.when.as_ref());
    attributes.text("since", alert.since.as_ref());
    attributes.text("warning", alert.warning.as_ref());
    attributes.text("critical", alert.critical.as_ref());
    attributes.text("for", alert.hold.as_ref());
    attributes.text("window", alert.window.as_ref());
    attributes.text("summary", alert.summary.as_ref());
    attributes.text("resolved_summary", alert.resolved_summary.as_ref());
    attributes.block("alert", Some(&alert.key)).build()
}

/// Indents each heredoc's lines to line up with the attribute it belongs to, which
/// `<<-` takes away again as it's read.
fn indent_heredocs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut inside: Option<(String, String)> = None;
    for line in text.split_inclusive('\n') {
        match &inside {
            Some((delimiter, indent)) => {
                let bare = line.trim_end_matches('\n');
                if bare.trim() == delimiter {
                    out.push_str(indent);
                    out.push_str(bare.trim());
                    out.push('\n');
                    inside = None;
                } else {
                    if !bare.is_empty() {
                        out.push_str(indent);
                        out.push_str("  ");
                    }
                    out.push_str(line);
                }
            }
            None => {
                out.push_str(line);
                if line.trim_end().ends_with("<<-EOT") {
                    let indent: String = line.chars().take_while(|c| *c == ' ').collect();
                    inside = Some(("EOT".to_string(), indent));
                }
            }
        }
    }
    out
}
