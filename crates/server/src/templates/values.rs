//! Metrics a template works out with CEL, `value = "<CEL>"`, from the other columns
//! of its query's rows, which the server does as an agent's samples arrive, as
//! agents have no CEL. Each is worked out for each row with the query's labels,
//! from that row's numbers by their names. `rate(x)` is a running total's change
//! over the seconds since that row's series was last sent, so the first sample of a
//! series has none, and nor does a metric naming a column the row doesn't have.
//! A metric left out where it runs, as its `since` is past the version found there,
//! isn't worked out.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, LazyLock};

use cel::common::ast::{CallExpr, Expr, IdedExpr, operators};
use cel::extractors::Arguments;
use cel::{Context as CelContext, Env, ExecutionError, Program, Value as CelValue};
use serde_json::{Map, Value, json};

use maxnines_protocol::Sample;
use maxnines_protocol::templates::work::{TemplateWork, collector_of};
use maxnines_protocol::templates::{Target, Template};

use crate::metrics::INSTANCE_LABEL;
use crate::times::Timestamp;

/// CEL's own functions, made once.
static FUNCTIONS: LazyLock<Arc<Env>> = LazyLock::new(|| Arc::new(Env::stdlib()));

/// What a template's `value` metrics need besides their own: a running total's
/// change each second.
pub const RATE: &str = "rate";

/// Makes a whole number one with a fraction, which no one can call by name.
const NUMBER: &str = "number:";

/// One metric a template works out, compiled.
pub struct WorkedOut {
    /// The template's key.
    template: String,
    /// The query it's a metric of.
    query: String,
    key: String,
    /// The labels the query's rows have.
    labels: BTreeSet<String>,
    expr: IdedExpr,
}

/// Every `value` metric of a template that's on, compiled. One that doesn't compile
/// is left out, as saving a template refuses it.
pub fn worked_out(template: &Template) -> Vec<WorkedOut> {
    if !template.enabled {
        return Vec::new();
    }
    let instance = matches!(template.target, Some(Target::Database(_)));
    let mut all = Vec::new();
    for query in template.queries.iter().filter(|query| query.enabled) {
        let mut labels: BTreeSet<String> = query.labels.iter().cloned().collect();
        if instance {
            labels.insert(INSTANCE_LABEL.to_string());
        }
        for metric in &query.metrics {
            let Some(text) = &metric.value else {
                continue;
            };
            let Ok(program) = Program::compile(text) else {
                continue;
            };
            let mut expr = program.expression().clone();
            fractions(&mut expr);
            all.push(WorkedOut {
                template: template.key.clone(),
                query: query.key.clone(),
                key: metric.key.clone(),
                labels: labels.clone(),
                expr,
            });
        }
    }
    all
}

/// When each row's series was last sent on a connection, to work out rates.
pub type LastSent = HashMap<String, Timestamp>;

/// Works out each `value` metric for the rows of a sample, adding it to each row it
/// can be worked out for. `sent` is what the agent was last sent to read.
pub fn work_out(
    sample: &mut Sample,
    metrics: &[WorkedOut],
    sent: &[TemplateWork],
    last_sent: &mut LastSent,
) {
    let mut by_template: HashMap<&str, Vec<&WorkedOut>> = HashMap::new();
    for metric in metrics {
        by_template
            .entry(&metric.template)
            .or_default()
            .push(metric);
    }
    for (template, metrics) in by_template {
        let collector = collector_of(template);
        let Some(Value::Array(rows)) = sample.metrics.get_mut(&collector) else {
            continue;
        };
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
            // A series is the row's labels and what it has, so rows of two queries
            // with the same labels, or a database's `up`, are told apart.
            let names: Vec<&String> = numbers.keys().collect();
            let series = format!("{collector}\n{}\n{names:?}", Value::Object(labels.clone()));
            let elapsed = last_sent
                .insert(series, sample.time)
                .map(|last| (sample.time - last).as_seconds_f64())
                .filter(|secs| *secs > 0.0);
            let database = labels.get(INSTANCE_LABEL).and_then(Value::as_str);
            let label_names: BTreeSet<String> = labels.keys().cloned().collect();
            for metric in &metrics {
                if metric.labels != label_names || row.contains_key(&metric.key) {
                    continue;
                }
                let runs = sent
                    .iter()
                    .filter(|work| work.template == metric.template)
                    .filter(|work| work.database.as_deref() == database)
                    .flat_map(|work| &work.queries)
                    .any(|query| query.key == metric.query && !query.omit.contains(&metric.key));
                if !runs {
                    continue;
                }
                if let Some(value) = evaluate(&metric.expr, &numbers, elapsed) {
                    row.insert(metric.key.clone(), json!(value));
                }
            }
        }
    }
}

/// Makes the whole numbers in sums ones with fractions as they're worked out, so
/// `hits * 2` works as it reads, as conditions do.
fn fractions(expr: &mut IdedExpr) {
    let Expr::Call(call) = &mut expr.expr else {
        return;
    };
    if let Some(target) = &mut call.target {
        fractions(target);
    }
    call.args.iter_mut().for_each(fractions);
    let sums = matches!(
        call.func_name.as_str(),
        operators::ADD | operators::SUBSTRACT | operators::MULTIPLY | operators::DIVIDE
    );
    if sums && call.target.is_none() {
        for arg in &mut call.args {
            let inner = std::mem::take(arg);
            *arg = IdedExpr {
                id: inner.id,
                expr: Expr::Call(CallExpr {
                    func_name: NUMBER.to_string(),
                    target: None,
                    args: vec![inner],
                }),
            };
        }
    }
}

fn number(Arguments(args): Arguments) -> Result<CelValue, ExecutionError> {
    match args.as_slice() {
        [CelValue::Int(whole)] => Ok(CelValue::Float(*whole as f64)),
        [CelValue::UInt(whole)] => Ok(CelValue::Float(*whole as f64)),
        [other] => Ok(other.clone()),
        _ => Err(ExecutionError::invalid_argument_count(1, args.len())),
    }
}

/// A metric's value from a row's numbers, or nothing if it can't be worked out.
fn evaluate(expr: &IdedExpr, numbers: &Map<String, Value>, elapsed: Option<f64>) -> Option<f64> {
    let mut context = CelContext::with_env(FUNCTIONS.clone());
    for (name, value) in numbers {
        context.add_variable_from_value(name.as_str(), CelValue::Float(value.as_f64()?));
    }
    let rate = move |Arguments(args): Arguments| -> Result<CelValue, ExecutionError> {
        let change = match args.as_slice() {
            [CelValue::Float(change)] => *change,
            [CelValue::Int(change)] => *change as f64,
            [CelValue::UInt(change)] => *change as f64,
            _ => return Err(ExecutionError::function_error(RATE, "takes one number")),
        };
        match elapsed {
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
            sql = "SELECT sum(blks_hit) AS hits, sum(blks_read) AS reads, sum(xact_commit) AS commits FROM pg_stat_database"
            metrics = {
              hits      = { total = true }
              reads     = { total = true }
              commits   = { total = true }
              cache_hit = { value = "rate(hits) / (rate(hits) + rate(reads)) * 100", unit = "%" }
              per_sec   = { value = "rate(commits)" }
              newer     = { value = "hits * 2", since = "15" }
            }
          }
        }
    "#;

    fn sent(omit: &[&str]) -> Vec<TemplateWork> {
        vec![TemplateWork {
            template: "pg".to_string(),
            database: Some("main".to_string()),
            discover: Vec::new(),
            queries: vec![QueryWork {
                key: "throughput".to_string(),
                sql: "SELECT".to_string(),
                interval: None,
                labels: Vec::new(),
                totals: vec!["hits".into(), "reads".into(), "commits".into()],
                omit: omit.iter().map(|key| (*key).to_string()).collect(),
            }],
        }]
    }

    fn sample(at: Timestamp, row: Value) -> Sample {
        Sample {
            time: at,
            metrics: BTreeMap::from([(
                "template.pg".to_string(),
                json!([row, { "labels": { "instance": "main" }, "up": 1 }]),
            )]),
        }
    }

    #[test]
    fn a_value_is_worked_out_from_its_rows_numbers_and_their_rates() {
        let template = maxnines_protocol::templates::parse(PG).unwrap();
        let metrics = worked_out(&template);
        assert_eq!(metrics.len(), 3);
        let mut last_sent = LastSent::new();
        let start = crate::times::now();
        let row = |hits: u64, reads: u64, commits: u64| json!({ "labels": { "instance": "main" }, "hits": hits, "reads": reads, "commits": commits });

        // The first has nothing to work a rate out from, but the rest work.
        let mut first = sample(start, row(90, 10, 20));
        work_out(&mut first, &metrics, &sent(&[]), &mut last_sent);
        let read = &first.metrics["template.pg"][0];
        assert!(read.get("cache_hit").is_none(), "{read}");
        assert_eq!(read["newer"], 180.0);

        let mut second = sample(start + TimeDelta::seconds(10), row(90, 10, 20));
        work_out(&mut second, &metrics, &sent(&["newer"]), &mut last_sent);
        let read = &second.metrics["template.pg"][0];
        assert_eq!(read["cache_hit"], 90.0);
        assert_eq!(read["per_sec"], 2.0);
        // Left out where its since is past the version found.
        assert!(read.get("newer").is_none(), "{read}");
        // A database's `up` isn't a row of the query.
        assert!(second.metrics["template.pg"][1].get("cache_hit").is_none());

        // Not worked out where the query doesn't run.
        let mut elsewhere = sample(start + TimeDelta::seconds(20), row(1, 1, 1));
        work_out(&mut elsewhere, &metrics, &[], &mut last_sent);
        assert!(
            elsewhere.metrics["template.pg"][0]
                .get("cache_hit")
                .is_none()
        );
    }
}
