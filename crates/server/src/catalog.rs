//! Every metric there is to read: the ones named in code, in [`crate::metrics`], and
//! those of each template, which change as templates do.
//!
//! [`crate::models::Database`] keeps the catalog, and makes it again whenever a
//! template is saved, imported, turned on or off or deleted, so nothing needs a
//! restart. Everything that reads metrics asks it rather than the fixed list.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use maxnines_protocol::templates::Template;
use tracing::warn;

use crate::metrics::{self, Metric};

/// The metrics there are, by name.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// The ones named in code first, then each template's, in the order they're
    /// written.
    metrics: Vec<Arc<Metric>>,
    by_name: HashMap<String, Arc<Metric>>,
    /// Metrics of templates and of their queries and counters that are turned off.
    /// Nothing lists, charts or keeps them, but a condition that names one can
    /// still be read, and finds no readings.
    off: HashMap<String, Arc<Metric>>,
}

impl Default for Catalog {
    fn default() -> Self {
        Self::built_in()
    }
}

impl Catalog {
    /// Only the metrics named in code.
    pub fn built_in() -> Self {
        let metrics = metrics::built_in().to_vec();
        Self {
            by_name: metrics
                .iter()
                .map(|metric| (metric.name.clone(), metric.clone()))
                .collect(),
            metrics,
            off: HashMap::new(),
        }
    }

    /// The metrics named in code and those of these templates, each as it runs:
    /// with `enabled` saying whether it and each of its parts is on.
    pub fn with_templates<'a>(templates: impl IntoIterator<Item = &'a Template>) -> Self {
        let mut catalog = Self::built_in();
        for template in templates {
            catalog.add(template);
        }
        catalog
    }

    /// This catalog with a template's metrics as the template says them, in place
    /// of any it had under that key, for checking a template before it's saved.
    /// Every part counts, on or off, as an alert can be about one that's turned on
    /// later.
    pub fn with_template(&self, template: &Template) -> Self {
        let mut catalog = self.clone();
        let theirs = |metric: &Arc<Metric>| metric.template.as_deref() == Some(&template.key);
        catalog.metrics.retain(|metric| !theirs(metric));
        catalog.by_name.retain(|_, metric| !theirs(metric));
        catalog.off.retain(|_, metric| !theirs(metric));
        for (metric, _) in crate::templates::metrics_of(template) {
            catalog.insert(metric, true);
        }
        catalog
    }

    fn add(&mut self, template: &Template) {
        for (metric, on) in crate::templates::metrics_of(template) {
            self.insert(metric, on);
        }
    }

    fn insert(&mut self, metric: Metric, on: bool) {
        // Saving a template refuses a key the code's metrics start with, so this is
        // one an upgrade brought a metric under since.
        if metric
            .template
            .as_deref()
            .is_some_and(|key| metrics::prefixes().contains(key))
        {
            warn!(
                metric = metric.name,
                "a template's key is what built-in metrics start with, so its metrics aren't read"
            );
            return;
        }
        let metric = Arc::new(metric);
        if on {
            self.by_name.insert(metric.name.clone(), metric.clone());
            self.metrics.push(metric);
        } else {
            self.off.insert(metric.name.clone(), metric);
        }
    }

    /// Every metric that's read, in the catalog's order. Those of templates and
    /// parts that are turned off are left out.
    pub fn all(&self) -> &[Arc<Metric>] {
        &self.metrics
    }

    /// A metric that's read, by its full name.
    pub fn find(&self, name: &str) -> Option<&Arc<Metric>> {
        self.by_name.get(name)
    }

    /// A metric a condition can name: one that's read, or one that would be if its
    /// template, query or counters were turned on.
    pub fn find_known(&self, name: &str) -> Option<&Arc<Metric>> {
        self.find(name).or_else(|| self.off.get(name))
    }

    /// The metrics of one template, on or off, in no particular order.
    pub fn of_template<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Arc<Metric>> {
        let theirs = move |metric: &&Arc<Metric>| metric.template.as_deref() == Some(key);
        self.metrics
            .iter()
            .filter(theirs)
            .chain(self.off.values().filter(theirs))
    }
}

/// The catalog as it is now, shared by everything that reads metrics, and replaced
/// whole when templates change.
#[derive(Debug, Clone, Default)]
pub struct SharedCatalog(Arc<RwLock<Arc<Catalog>>>);

impl SharedCatalog {
    pub fn get(&self) -> Arc<Catalog> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set(&self, catalog: Catalog) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(catalog);
    }
}
