//! Reading a template from HCL. Each block is read on its own, so a mistake says
//! which template, block and field it's in, and every field has to be one the
//! format has.

use anyhow::{Context, Result, anyhow, bail, ensure};
use hcl::{Block, BlockLabel, Body, Structure, Value};
use indexmap::IndexMap;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{
    Alert, Counters, Discover, Fill, Join, Metric, Notice, Query, RegistryRead, Target, Template,
    yes,
};

/// Reads a template file, which holds one `template "<key>" { … }` block. Only the
/// format is checked here: [`Template::check`] says what else is wrong with it.
pub fn parse(text: &str) -> Result<Template> {
    let body = hcl::parse(text).map_err(|error| anyhow!("{error}"))?;
    let (attributes, blocks) = split(body);
    if let Some(attribute) = attributes.attributes().next() {
        bail!(
            "{} has to be inside the template block",
            attribute.key.as_str()
        );
    }
    let mut templates = blocks.into_iter();
    let Some(block) = templates.next() else {
        bail!("there's no template block, like template \"myapp\" {{ … }}");
    };
    ensure!(
        templates.next().is_none(),
        "a file holds one template block"
    );
    ensure!(
        block.identifier.as_str() == "template",
        "{} blocks go inside the template block",
        block.identifier.as_str()
    );
    let key = label_of(&block, "template")?;
    read_template(key.clone(), block.body).with_context(|| format!("template {key:?}"))
}

/// A body's attributes as a body of their own, and its blocks.
fn split(body: Body) -> (Body, Vec<Block>) {
    let mut attributes = Vec::new();
    let mut blocks = Vec::new();
    for structure in body {
        match structure {
            Structure::Attribute(attribute) => attributes.push(Structure::Attribute(attribute)),
            Structure::Block(block) => blocks.push(block),
        }
    }
    (Body::from(attributes), blocks)
}

fn label_text(label: &BlockLabel) -> String {
    match label {
        BlockLabel::String(text) => text.clone(),
        BlockLabel::Identifier(name) => name.to_string(),
    }
}

/// The one label a block has, like `query "sessions"`.
fn label_of(block: &Block, what: &str) -> Result<String> {
    match block.labels.as_slice() {
        [label] => Ok(label_text(label)),
        [] => bail!("a {what} block needs a name, like {what} \"name\" {{ … }}"),
        _ => bail!("a {what} block has one name"),
    }
}

fn no_label(block: &Block) -> Result<()> {
    let what = block.identifier.as_str();
    ensure!(
        block.labels.is_empty(),
        "a {what} block has no name, like {what} {{ … }}"
    );
    Ok(())
}

fn read_fields<T: DeserializeOwned>(attributes: Body) -> Result<T> {
    hcl::from_body(attributes).map_err(|error| anyhow!("{error}"))
}

fn no_blocks(blocks: Vec<Block>, inside: &str) -> Result<()> {
    if let Some(block) = blocks.first() {
        bail!(
            "a {inside} block can't hold a {} block",
            block.identifier.as_str()
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateFields {
    name: String,
    description: Option<String>,
    database: Option<String>,
    service: Option<String>,
    os: Option<Vec<String>>,
    applies_to: Option<String>,
    min_version: Option<String>,
    #[serde(default)]
    renamed_from: Vec<String>,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    services: Vec<String>,
}

fn read_template(key: String, body: Body) -> Result<Template> {
    let (attributes, blocks) = split(body);
    let fields: TemplateFields = read_fields(attributes)?;
    let target = match (fields.database, fields.service, fields.os) {
        (None, None, None) => None,
        (Some(database), None, None) => Some(Target::Database(database)),
        (None, Some(service), None) => Some(Target::Service(service)),
        (None, None, Some(systems)) => Some(Target::Os(systems)),
        _ => {
            bail!("a template is for a database, a service or operating systems, not more than one")
        }
    };
    let mut template = Template {
        key,
        name: fields.name,
        description: fields.description,
        target,
        applies_to: fields.applies_to,
        min_version: fields.min_version,
        renamed_from: fields.renamed_from,
        enabled: fields.enabled,
        services: fields.services,
        config: None,
        discover: Vec::new(),
        notices: Vec::new(),
        queries: Vec::new(),
        counters: Vec::new(),
        alerts: Vec::new(),
    };
    for block in blocks {
        match block.identifier.as_str() {
            "config" => {
                no_label(&block)?;
                ensure!(template.config.is_none(), "a template has one config block");
                let settings: serde_json::Value =
                    hcl::from_body(block.body).map_err(|error| anyhow!("config: {error}"))?;
                let serde_json::Value::Object(settings) = settings else {
                    bail!("config holds settings, like interval_secs = 15");
                };
                template.config = Some(settings);
            }
            "discover" => {
                let key = label_of(&block, "discover")?;
                let discover = read_discover(key.clone(), block.body)
                    .with_context(|| format!("discover {key:?}"))?;
                template.discover.push(discover);
            }
            "notice" => {
                let key = label_of(&block, "notice")?;
                let notice = read_notice(key.clone(), block.body)
                    .with_context(|| format!("notice {key:?}"))?;
                template.notices.push(notice);
            }
            "query" => {
                let key = label_of(&block, "query")?;
                let query = read_query(key.clone(), block.body)
                    .with_context(|| format!("query {key:?}"))?;
                template.queries.push(query);
            }
            "counters" => {
                let key = label_of(&block, "counters")?;
                let counters = read_counters(key.clone(), block.body)
                    .with_context(|| format!("counters {key:?}"))?;
                template.counters.push(counters);
            }
            "alert" => {
                let key = label_of(&block, "alert")?;
                let alert = read_alert(key.clone(), block.body)
                    .with_context(|| format!("alert {key:?}"))?;
                template.alerts.push(alert);
            }
            other => bail!(
                "a template has no {other} blocks: it has config, discover, notice, query, counters and alert"
            ),
        }
    }
    Ok(template)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoverFields {
    interval: Option<String>,
    sql: Option<String>,
    #[serde(default)]
    counter_sets: IndexMap<String, String>,
}

fn read_discover(key: String, body: Body) -> Result<Discover> {
    let (attributes, blocks) = split(body);
    let fields: DiscoverFields = read_fields(attributes)?;
    let mut registry = Vec::new();
    for block in blocks {
        ensure!(
            block.identifier.as_str() == "registry",
            "a discover block has no {} blocks: it has registry blocks",
            block.identifier.as_str()
        );
        let key = label_of(&block, "registry")?;
        let (attributes, inner) = split(block.body);
        no_blocks(inner, "registry")?;
        let values: IndexMap<String, String> =
            read_fields(attributes).with_context(|| format!("registry {key:?}"))?;
        registry.push(RegistryRead { key, values });
    }
    Ok(Discover {
        key,
        interval: fields.interval,
        sql: fields.sql,
        registry,
        counter_sets: fields.counter_sets,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeFields {
    when: Option<String>,
    text: String,
}

fn read_notice(key: String, body: Body) -> Result<Notice> {
    let (attributes, blocks) = split(body);
    no_blocks(blocks, "notice")?;
    let fields: NoticeFields = read_fields(attributes)?;
    Ok(Notice {
        key,
        when: fields.when,
        text: fields.text,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricFields {
    title: Option<String>,
    counter: Option<String>,
    unit: Option<String>,
    #[serde(default)]
    total: bool,
    description: Option<String>,
    value: Option<String>,
    since: Option<String>,
    #[serde(default)]
    states: IndexMap<String, String>,
}

/// `metrics = { … }`, where each is a counter's name or a map of what's known about it.
fn read_metrics(metrics: IndexMap<String, Value>) -> Result<Vec<Metric>> {
    metrics
        .into_iter()
        .map(|(key, value)| {
            let metric = match value {
                Value::String(counter) => Metric {
                    key: key.clone(),
                    counter: Some(counter),
                    ..Metric::default()
                },
                Value::Object(_) => {
                    let fields: MetricFields = hcl::from_value(value)
                        .map_err(|error| anyhow!("{error}"))
                        .with_context(|| format!("metrics, {key}"))?;
                    Metric {
                        key: key.clone(),
                        title: fields.title,
                        counter: fields.counter,
                        unit: fields.unit,
                        total: fields.total,
                        description: fields.description,
                        value: fields.value,
                        since: fields.since,
                        states: fields.states,
                    }
                }
                _ => bail!(
                    "metrics, {key}: is a counter's name or a map, like {{ unit = \"bytes\" }}"
                ),
            };
            Ok(metric)
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryFields {
    sql: String,
    interval: Option<String>,
    since: Option<String>,
    when: Option<String>,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    columns: IndexMap<String, String>,
    #[serde(default)]
    metrics: IndexMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FillFields {
    #[serde(default)]
    versions: IndexMap<String, String>,
    older: Option<String>,
}

fn read_query(key: String, body: Body) -> Result<Query> {
    let (attributes, blocks) = split(body);
    let fields: QueryFields = read_fields(attributes)?;
    let mut fills = Vec::new();
    for block in blocks {
        ensure!(
            block.identifier.as_str() == "fill",
            "a query block has no {} blocks: it has fill blocks",
            block.identifier.as_str()
        );
        let key = label_of(&block, "fill")?;
        let (attributes, inner) = split(block.body);
        no_blocks(inner, "fill")?;
        let fill: FillFields = read_fields(attributes).with_context(|| format!("fill {key:?}"))?;
        fills.push(Fill {
            key,
            versions: fill.versions,
            older: fill.older,
        });
    }
    Ok(Query {
        key,
        sql: fields.sql,
        interval: fields.interval,
        since: fields.since,
        when: fields.when,
        enabled: fields.enabled,
        labels: fields.labels,
        columns: fields.columns,
        fills,
        metrics: read_metrics(fields.metrics)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CountersFields {
    object: String,
    label: Option<String>,
    pattern: Option<String>,
    instance: Option<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    groups: IndexMap<String, String>,
    when: Option<String>,
    since: Option<String>,
    interval: Option<String>,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    metrics: IndexMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinFields {
    object: String,
    pattern: String,
}

fn read_counters(key: String, body: Body) -> Result<Counters> {
    let (attributes, blocks) = split(body);
    let fields: CountersFields = read_fields(attributes)?;
    let mut join = None;
    for block in blocks {
        ensure!(
            block.identifier.as_str() == "join",
            "a counters block has no {} blocks: it has a join block",
            block.identifier.as_str()
        );
        no_label(&block)?;
        ensure!(join.is_none(), "a counters block has one join block");
        let (attributes, inner) = split(block.body);
        no_blocks(inner, "join")?;
        let fields: JoinFields = read_fields(attributes).context("join")?;
        join = Some(Join {
            object: fields.object,
            pattern: fields.pattern,
        });
    }
    Ok(Counters {
        key,
        object: fields.object,
        label: fields.label,
        pattern: fields.pattern,
        instance: fields.instance,
        exclude: fields.exclude,
        groups: fields.groups,
        join,
        when: fields.when,
        since: fields.since,
        interval: fields.interval,
        enabled: fields.enabled,
        metrics: read_metrics(fields.metrics)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertFields {
    name: String,
    warning: Option<String>,
    critical: Option<String>,
    #[serde(rename = "for")]
    hold: Option<String>,
    window: Option<String>,
    summary: Option<String>,
    resolved_summary: Option<String>,
    when: Option<String>,
    since: Option<String>,
    #[serde(default = "yes")]
    enabled: bool,
}

fn read_alert(key: String, body: Body) -> Result<Alert> {
    let (attributes, blocks) = split(body);
    no_blocks(blocks, "alert")?;
    let fields: AlertFields = read_fields(attributes)?;
    Ok(Alert {
        key,
        name: fields.name,
        warning: fields.warning,
        critical: fields.critical,
        hold: fields.hold,
        window: fields.window,
        summary: fields.summary,
        resolved_summary: fields.resolved_summary,
        when: fields.when,
        since: fields.since,
        enabled: fields.enabled,
    })
}
