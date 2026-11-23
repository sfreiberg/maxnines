//! Metrics a template works out with CEL, `value = "<CEL>"`, which the server does
//! as an agent's samples arrive, as agents have no CEL: for a query, from the other
//! columns of its rows, and for a counters block, from the counter's own reading,
//! `value`, which the worked-out number then takes the place of.
//!
//! Each row an agent sends says which query or counters block it's from, which is
//! taken out before it's stored. Each metric is worked out for the rows of its
//! query or block, from each row's numbers by their names, with the host's facts
//! under `facts`. `rate(x)` is a running total's change over the seconds since that
//! query last sent that series, so its first sample has none, and nor does one sent
//! late, after a newer one, as an agent sends samples it kept while away. A metric
//! naming a column the row doesn't have isn't worked out, and nor is one left out
//! where it runs, as its `since` is past the version found there.

use std::collections::{HashMap, HashSet};

use cel::common::ast::IdedExpr;
use cel::extractors::Arguments;
use cel::{Context as CelContext, ExecutionError, Program, Value as CelValue};
use chrono::TimeDelta;
use serde_json::{Map, Value, json};

use maxnines_protocol::Sample;
use maxnines_protocol::templates::work::{QUERY_FIELD, TemplateWork, collector_of};
use maxnines_protocol::templates::{Metric, Template};

use crate::cel_env::{FUNCTIONS, NUMBER, fractions, number};
use crate::metrics::INSTANCE_LABEL;
use crate::times::Timestamp;

/// A running total's change each second, for a template's `value` metrics.
pub const RATE: &str = "rate";
/// What the host's facts are under.
const FACTS: &str = "facts";

/// How long a series no sample has had is remembered, which is longer than any
/// query's interval can be.
const FORGET_AFTER: TimeDelta = TimeDelta::days(2);

/// What a counters block's `value` calls the counter's own reading.
pub const VALUE: &str = "value";

/// The metrics one of a template's queries or counters blocks works out, compiled.
pub struct QueryValues {
    /// The template's key.
    template: String,
    /// The query's or the counters block's key.
    query: String,
    /// Whether it's a counters block, whose metrics work out from their own reading.
    counters: bool,
    metrics: Vec<(String, IdedExpr)>,
}

/// The metrics a template that's on works out with CEL, by query and counters
/// block. One that doesn't compile is left out, as saving a template refuses it.
pub fn worked_out(template: &Template) -> Vec<QueryValues> {
    if !template.enabled {
        return Vec::new();
    }
    let compiled = |metrics: &[Metric]| -> Vec<(String, IdedExpr)> {
        metrics
            .iter()
            .filter_map(|metric| {
                let program = Program::compile(metric.value.as_deref()?).ok()?;
                let mut expr = program.expression().clone();
                fractions(&mut expr);
                Some((metric.key.clone(), expr))
            })
            .collect()
    };
    let queries = template
        .queries
        .iter()
        .filter(|query| query.enabled)
        .map(|query| (&query.key, false, compiled(&query.metrics)));
    let counters = template
        .counters
        .iter()
        .filter(|counters| counters.enabled)
        .map(|counters| (&counters.key, true, compiled(&counters.metrics)));
    queries
        .chain(counters)
        .filter(|(_, _, metrics)| !metrics.is_empty())
        .map(|(key, counters, metrics)| QueryValues {
            template: template.key.clone(),
            query: key.clone(),
            counters,
            metrics,
        })
        .collect()
}

/// When each query last sent each series on a connection, to work out rates.
#[derive(Debug, Default)]
pub struct LastSent(HashMap<(String, String), Timestamp>);

/// Works out each `value` metric for the rows of a sample, adding it to each row
/// of its query, or putting it in place of a counter's reading. `sent` is what the
/// agent was last sent to read, and `facts` the host's, in their natural shape.
pub fn work_out(
    sample: &mut Sample,
    queries: &[QueryValues],
    sent: &[TemplateWork],
    facts: &Value,
    last_sent: &mut LastSent,
) {
    // Once a sample, however many rows and metrics use it.
    let Ok(facts) = cel::to_value(facts) else {
        return;
    };
    for query in queries {
        let collector = collector_of(&query.template);
        let Some(Value::Array(rows)) = sample.metrics.get_mut(&collector) else {
            continue;
        };
        let mut seen: HashSet<String> = HashSet::new();
        for row in rows.iter_mut() {
            let Some(row) = row.as_object_mut() else {
                continue;
            };
            let labels = row
                .get("labels")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let numbers: Map<String, Value> = row
                .iter()
                .filter(|(_, value)| value.is_number())
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            if row.get(QUERY_FIELD).and_then(Value::as_str) != Some(query.query.as_str()) {
                continue;
            }
            let database = labels.get(INSTANCE_LABEL).and_then(Value::as_str);
            let mut sent_for = sent
                .iter()
                .filter(|work| work.template == query.template)
                .filter(|work| work.database.as_deref() == database);
            // Whether each metric is read where the row is from: a query's, unless
            // it's left out, or a counters block's, if it was sent.
            let read: Box<dyn Fn(&str) -> bool> = match query.counters {
                false => {
                    let Some(omit) = sent_for
                        .find_map(|work| work.queries.iter().find(|sent| sent.key == query.query))
                        .map(|sent| &sent.omit)
                    else {
                        continue;
                    };
                    Box::new(move |key: &str| !omit.iter().any(|left_out| left_out == key))
                }
                true => {
                    let Some(block) = sent_for
                        .find_map(|work| work.counters.iter().find(|sent| sent.key == query.query))
                    else {
                        continue;
                    };
                    Box::new(move |key: &str| block.metrics.iter().any(|metric| metric.key == key))
                }
            };
            let series = Value::Object(labels).to_string();
            seen.insert(series.clone());
            let elapsed = last_sent.note(&collector, &query.query, series, sample.time);
            for (key, expr) in &query.metrics {
                if !read(key) {
                    continue;
                }
                if query.counters {
                    // The counter's reading, which what's worked out takes the place of.
                    let Some(reading) = row.remove(key) else {
                        continue;
                    };
                    let mut numbers = numbers.clone();
                    numbers.insert(VALUE.to_string(), reading);
                    if let Some(value) = evaluate(expr, &numbers, &facts, elapsed) {
                        row.insert(key.clone(), json!(value));
                    }
                } else if !row.contains_key(key)
                    && let Some(value) = evaluate(expr, &numbers, &facts, elapsed)
                {
                    row.insert(key.clone(), json!(value));
                }
            }
        }
        last_sent.forget(&collector, &query.query, &seen, sample.time);
    }
}

impl LastSent {
    /// Notes that a query sent a series at `time`, giving the seconds since it last
    /// did, or nothing for its first, or one older than what's been noted.
    fn note(
        &mut self,
        collector: &str,
        query: &str,
        series: String,
        time: Timestamp,
    ) -> Option<f64> {
        let key = (format!("{collector}\n{query}"), series);
        match self.0.get(&key) {
            Some(last) if *last >= time => None,
            last => {
                let elapsed = last.map(|last| (time - *last).as_seconds_f64());
                self.0.insert(key, time);
                elapsed
            }
        }
    }

    /// Forgets the series a query no longer sends: those not among what it just
    /// sent, if it sent any, and any not sent for a long while.
    fn forget(&mut self, collector: &str, query: &str, sent: &HashSet<String>, time: Timestamp) {
        let of_query = format!("{collector}\n{query}");
        self.0.retain(|(owner, series), last| {
            let gone = *owner == of_query && !sent.is_empty() && !sent.contains(series);
            !gone && time - *last < FORGET_AFTER
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Takes out what each of a template's rows says of its query, once it's been used,
/// so it isn't stored.
pub fn strip_queries(sample: &mut Sample) {
    for (collector, rows) in sample.metrics.iter_mut() {
        if !collector.starts_with("template.") {
            continue;
        }
        for row in rows.as_array_mut().into_iter().flatten() {
            if let Some(row) = row.as_object_mut() {
                row.remove(QUERY_FIELD);
            }
        }
    }
}

/// A metric's value from a row's numbers and the host's facts, as CEL, or nothing if
/// it can't be worked out.
fn evaluate(
    expr: &IdedExpr,
    numbers: &Map<String, Value>,
    facts: &CelValue,
    elapsed: Option<f64>,
) -> Option<f64> {
    let mut context = CelContext::with_env(FUNCTIONS.clone());
    for (name, value) in numbers {
        context.add_variable_from_value(name.as_str(), CelValue::Float(value.as_f64()?));
    }
    // A map is shared, not copied, so this costs the same however many facts.
    context.add_variable_from_value(FACTS, facts.clone());
    let rate = move |Arguments(args): Arguments| -> Result<CelValue, ExecutionError> {
        let change = match args.as_slice() {
            [CelValue::Float(change)] => *change,
            [CelValue::Int(change)] => *change as f64,
            [CelValue::UInt(change)] => *change as f64,
            _ => return Err(ExecutionError::function_error(RATE, "takes one number")),
        };
        match elapsed.filter(|secs| *secs > 0.0) {
            Some(secs) => Ok(CelValue::Float(change / secs)),
            None => Err(ExecutionError::function_error(
                RATE,
                "has nothing earlier to compare with",
            )),
        }
    };
    context.add_function(RATE, rate).ok()?;
    context.add_function(NUMBER, number).ok()?;
    let value = match context.resolve(expr).ok()? {
        CelValue::Float(number) => number,
        CelValue::Int(number) => number as f64,
        CelValue::UInt(number) => number as f64,
        CelValue::Bool(yes) => f64::from(u8::from(yes)),
        _ => return None,
    };
    value.is_finite().then_some(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeDelta;
    use maxnines_protocol::templates::work::QueryWork;

    use super::*;

    const PG: &str = r#"
        template "pg" {
          name     = "PG"
          database = "postgres"
          query "throughput" {
            sql = "SELECT sum(numbackends) AS backends, sum(blks_hit) AS hits, sum(blks_read) AS reads, sum(xact_commit) AS commits FROM pg_stat_database"
            metrics = {
              hits      = { total = true }
              reads     = { total = true }
              commits   = { total = true }
              cache_hit = { value = "rate(hits) / (rate(hits) + rate(reads)) * 100", unit = "%" }
              per_sec   = { value = "rate(commits)" }
              newer     = { value = "backends * 2", since = "15" }
              always    = { value = "1" }
            }
          }
          query "sessions" {
            sql = "SELECT count(*) AS backends FROM pg_stat_activity"
          }
          query "slots" {
            sql     = "SELECT slot_name AS slot, 1 AS held FROM pg_replication_slots"
            labels  = ["slot"]
            metrics = { doubled = { value = "held * 2" } }
          }
        }
    "#;

    fn sent(omit: &[&str]) -> Vec<TemplateWork> {
        let query = |key: &str, omit: &[&str]| QueryWork {
            key: key.to_string(),
            sql: "SELECT".to_string(),
            interval: None,
            labels: Vec::new(),
            totals: Vec::new(),
            omit: omit.iter().map(|key| (*key).to_string()).collect(),
        };
        vec![TemplateWork {
            template: "pg".to_string(),
            database: Some("main".to_string()),
            discover: Vec::new(),
            queries: vec![
                query("throughput", omit),
                query("sessions", &[]),
                query("slots", &[]),
            ],
            counters: Vec::new(),
        }]
    }

    fn sample(at: Timestamp, rows: Value) -> Sample {
        Sample {
            time: at,
            metrics: BTreeMap::from([("template.pg".to_string(), rows)]),
        }
    }

    fn worked(at: Timestamp, rows: Value, omit: &[&str], last_sent: &mut LastSent) -> Vec<Value> {
        let template = maxnines_protocol::templates::parse(PG).unwrap();
        let mut sample = sample(at, rows);
        work_out(
            &mut sample,
            &worked_out(&template),
            &sent(omit),
            &Value::Null,
            last_sent,
        );
        sample.metrics["template.pg"].as_array().unwrap().clone()
    }

    fn throughput(backends: u64, totals: Option<(u64, u64, u64)>) -> Value {
        let mut row = json!({ "labels": { "instance": "main" }, "_query": "throughput", "backends": backends });
        if let Some((hits, reads, commits)) = totals {
            row["hits"] = json!(hits);
            row["reads"] = json!(reads);
            row["commits"] = json!(commits);
        }
        row
    }

    #[test]
    fn a_value_is_worked_out_from_its_rows_numbers_and_their_rates() {
        let mut last_sent = LastSent::default();
        let start = crate::times::now();
        // The agent's first read has no totals' changes, and no rate is known.
        let first = worked(start, json!([throughput(3, None)]), &[], &mut last_sent);
        assert_eq!(first[0]["newer"], 6.0);
        assert!(first[0].get("per_sec").is_none(), "{}", first[0]);

        // The next has the changes, and the time since the first.
        let at = start + TimeDelta::seconds(10);
        let second = worked(
            at,
            json!([throughput(3, Some((90, 10, 20)))]),
            &["newer"],
            &mut last_sent,
        );
        assert_eq!(second[0]["cache_hit"], 90.0);
        assert_eq!(second[0]["per_sec"], 2.0);
        // Left out where its since is past the version found.
        assert!(second[0].get("newer").is_none(), "{}", second[0]);
    }

    #[test]
    fn a_value_is_only_worked_out_for_its_own_querys_rows() {
        let mut last_sent = LastSent::default();
        let rows = json!([
            throughput(3, None),
            { "labels": { "instance": "main" }, "_query": "sessions", "backends": 5 },
            { "labels": { "instance": "main" }, "up": 1 },
            { "labels": { "instance": "main", "slot": "a" }, "_query": "slots", "held": 1 },
        ]);
        let read = worked(crate::times::now(), rows, &[], &mut last_sent);
        // Not on another query's row, though it has a column of the same name, nor
        // on whether the database is up.
        assert_eq!(read[0]["always"], 1.0);
        assert!(read[1].get("always").is_none(), "{}", read[1]);
        assert!(read[2].get("always").is_none(), "{}", read[2]);
        assert!(read[3].get("always").is_none(), "{}", read[3]);
        assert_eq!(read[3]["doubled"], 2.0);
    }

    #[test]
    fn a_sample_sent_late_has_no_rate_and_moves_nothing_back() {
        let mut last_sent = LastSent::default();
        let start = crate::times::now();
        let row = || json!([throughput(3, Some((10, 10, 10)))]);
        worked(start, row(), &[], &mut last_sent);
        worked(start + TimeDelta::seconds(10), row(), &[], &mut last_sent);
        let late = worked(start + TimeDelta::seconds(5), row(), &[], &mut last_sent);
        assert!(late[0].get("per_sec").is_none(), "{}", late[0]);
        let next = worked(start + TimeDelta::seconds(20), row(), &[], &mut last_sent);
        assert_eq!(next[0]["per_sec"], 1.0);
    }

    #[test]
    fn what_a_row_says_of_its_query_is_not_stored() {
        let mut sample = sample(crate::times::now(), json!([throughput(1, None)]));
        strip_queries(&mut sample);
        assert!(sample.metrics["template.pg"][0].get("_query").is_none());
    }

    #[test]
    fn series_a_query_no_longer_sends_are_forgotten() {
        let mut last_sent = LastSent::default();
        let start = crate::times::now();
        let slot = |name: &str| json!({ "labels": { "instance": "main", "slot": name }, "_query": "slots", "held": 1 });
        worked(start, json!([slot("a"), slot("b")]), &[], &mut last_sent);
        assert_eq!(last_sent.len(), 2);
        worked(
            start + TimeDelta::seconds(10),
            json!([slot("c")]),
            &[],
            &mut last_sent,
        );
        assert_eq!(last_sent.len(), 1);
        // And anything not sent for days.
        worked(
            start + TimeDelta::days(3),
            json!([throughput(1, None)]),
            &[],
            &mut last_sent,
        );
        assert_eq!(last_sent.len(), 1);
    }

    #[test]
    fn a_counters_value_takes_the_place_of_its_reading_with_the_hosts_facts() {
        let template = maxnines_protocol::templates::parse(
            r#"template "iis" {
                 name    = "IIS"
                 service = "W3SVC"
                 counters "pools" {
                   object  = "APP_POOL_WAS"
                   label   = "pool"
                   metrics = {
                     pool_state   = "Current Application Pool State"
                     pool_running = { counter = "Current Application Pool State", value = "value == 3" }
                     pool_cpu     = { counter = "% Processor Time", value = "value / facts.cpu.logical_cores" }
                     newer        = { counter = "Newer", value = "value * 2", since = "10" }
                   }
                 }
               }"#,
        )
        .unwrap();
        let found = json!({ "version": "9" });
        let sent = crate::templates::work::host_work(&template, found.as_object());
        // Only from a later version than the one found, so not read.
        assert!(
            sent.counters[0]
                .metrics
                .iter()
                .all(|metric| metric.key != "newer"),
            "{sent:?}"
        );
        let facts = json!({ "cpu": { "logical_cores": 4 } });
        let mut sample = Sample {
            time: crate::times::now(),
            metrics: BTreeMap::from([(
                "template.iis".to_string(),
                json!([
                    { "labels": { "pool": "a" }, "_query": "pools", "pool_state": 3, "pool_running": 3, "pool_cpu": 50 },
                    { "labels": { "pool": "b" }, "_query": "pools", "pool_state": 5, "pool_running": 5 },
                ]),
            )]),
        };
        work_out(
            &mut sample,
            &worked_out(&template),
            &[sent],
            &facts,
            &mut LastSent::default(),
        );
        let rows = &sample.metrics["template.iis"];
        assert_eq!(rows[0]["pool_state"], 3);
        assert_eq!(rows[0]["pool_running"], 1.0);
        assert_eq!(rows[0]["pool_cpu"], 12.5);
        assert_eq!(rows[1]["pool_running"], 0.0);
        assert!(rows[1].get("pool_cpu").is_none(), "{}", rows[1]);
    }
}
