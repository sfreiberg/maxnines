//! The templates that ship inside the server, from its `templates/` folder. They're
//! written to the database as it starts: see [`crate::models::Database::sync_templates`].

use anyhow::{Context, Result, ensure};
use ring::digest::{SHA256, digest};
use rust_embed::RustEmbed;
use serde_json::{Map, Value};

use maxnines_protocol::templates::{Template, to_hcl};

use crate::catalog::Catalog;

#[derive(RustEmbed)]
#[folder = "templates/"]
#[include = "*.hcl"]
struct Files;

/// A template this version of the server ships.
#[derive(Debug, Clone, PartialEq)]
pub struct BuiltIn {
    pub template: Template,
    /// As the file has it, comments and all.
    pub source: String,
    /// What says whether it changed: a hash of what it says, so a change to a
    /// comment or the layout isn't an upgrade.
    pub fingerprint: String,
}

/// A hash of what a template says, as its HCL is written out.
pub fn fingerprint(template: &Template) -> String {
    hex::encode(digest(&SHA256, to_hcl(template).as_bytes()))
}

/// Every built-in template, by file name, each read and checked as a template
/// someone added would be.
pub fn all() -> Result<Vec<BuiltIn>> {
    let mut names: Vec<_> = Files::iter().collect();
    names.sort();
    let mut all: Vec<BuiltIn> = Vec::new();
    for name in names {
        let file = Files::get(&name).context("a built-in template went missing")?;
        let source = String::from_utf8(file.data.into_owned())
            .with_context(|| format!("{name} isn't UTF-8"))?;
        let built_in =
            from_source(source).with_context(|| format!("the built-in template in {name}"))?;
        ensure!(
            !all.iter()
                .any(|other| other.template.key == built_in.template.key),
            "two built-in templates are called {:?}",
            built_in.template.key
        );
        all.push(built_in);
    }
    Ok(all)
}

/// A built-in template from its file, read and checked.
pub fn from_source(source: String) -> Result<BuiltIn> {
    // A built-in template is checked against the metrics the code has, as it's
    // read before there's a database to have any others.
    let template = super::load(&source, &Value::Object(Map::new()), &Catalog::built_in())?;
    Ok(BuiltIn {
        fingerprint: fingerprint(&template),
        template,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASED: &str = include_str!("../../templates/released-keys.txt");

    fn released() -> Vec<&'static str> {
        RELEASED
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    }

    #[test]
    fn every_built_in_template_loads() {
        let all = all().unwrap();
        assert!(all.iter().any(|built_in| built_in.template.key == "host"));
    }

    /// A key a release shipped can't go without a template saying it was renamed,
    /// or a server upgraded past it would lose what people changed in it.
    #[test]
    fn no_released_key_disappears() {
        let all = all().unwrap();
        for key in released() {
            let kept = all.iter().any(|built_in| {
                built_in.template.key == key
                    || built_in.template.renamed_from.iter().any(|old| old == key)
            });
            assert!(
                kept,
                "the released template {key:?} is gone: give its new key renamed_from = [\"{key}\"]"
            );
        }
    }

    /// What charts and lists call a built-in metric is written for it, not made up
    /// from its key.
    #[test]
    fn every_built_in_metric_has_a_title_of_its_own() {
        for built_in in all().unwrap() {
            let template = &built_in.template;
            let metrics = template.queries.iter().flat_map(|query| {
                crate::templates::query_columns_of(template, query)
                    .into_iter()
                    .filter(|column| !query.labels.contains(column))
                    .chain(query.metrics.iter().map(|metric| metric.key.clone()))
                    .map(move |key| (key, query))
            });
            for (key, query) in metrics {
                let titled = query
                    .metrics
                    .iter()
                    .any(|metric| metric.key == key && metric.title.is_some());
                assert!(titled, "{}.{key} has no title", template.key);
            }
        }
        let catalog = crate::catalog::Catalog::with_templates(
            all().unwrap().iter().map(|built_in| &built_in.template),
        );
        assert_eq!(catalog.find("postgres.up").unwrap().title, "PostgreSQL up");
        assert_eq!(
            catalog.find("postgres.xid_age").unwrap().title,
            "PostgreSQL transaction ID age (wraparound)"
        );
        assert_eq!(
            catalog.find("clickhouse.up").unwrap().title,
            "ClickHouse up"
        );
    }

    #[test]
    fn every_built_in_key_is_in_the_released_list() {
        let released = released();
        for built_in in all().unwrap() {
            let key = &built_in.template.key;
            assert!(
                released.contains(&key.as_str()),
                "add {key:?} to templates/released-keys.txt"
            );
        }
    }

    #[test]
    fn comments_and_layout_leave_the_fingerprint_alone() {
        let all = all().unwrap();
        let host = all.iter().find(|one| one.template.key == "host").unwrap();
        let reworded = format!(
            "# Another comment.\n{}",
            host.source.replace("  name", "  name  ")
        );
        let template = maxnines_protocol::templates::parse(&reworded).unwrap();
        assert_eq!(fingerprint(&template), host.fingerprint);
        let mut changed = template.clone();
        changed.alerts[0].hold = Some("2m".to_string());
        assert_ne!(fingerprint(&changed), host.fingerprint);
    }
}
