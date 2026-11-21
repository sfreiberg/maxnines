//! What alert rules watch for: a warning and a critical condition, each CEL over
//! metrics by their catalog names, such as `disk.usage > 90`. A rule about hosts has
//! its conditions worked out for each host, and for each disk, interface or service
//! where its metrics have one series for each. A rule with a calculation has its
//! conditions worked out on each line of the calculation, as `value`.
//!
//! The `cel` crate doesn't check types, so conditions are read here when they're saved:
//! every name against the catalog, and a run on made-up values of the right types,
//! so a typing mistake, or a length of time compared with a number, is said then
//! rather than never alerting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail, ensure};
use cel::common::ast::{CallExpr, EntryExpr, Expr, IdedExpr, LiteralValue, operators};
use cel::extractors::Arguments;
use cel::{Context as CelContext, Env, ExecutionError, Program, Value as CelValue};
use chrono::TimeDelta;

use crate::metrics::{self, METRICS, Metric, Source, Unit};

/// What the database column holds, with room to spare for anyone's condition.
pub const MAX_CONDITION_LEN: usize = 2000;

/// The functions conditions have beside CEL's own: sizes in binary units, and where
/// a metric is heading.
const SIZES: [(&str, f64); 4] = [
    ("kib", 1024.0),
    ("mib", 1024.0 * 1024.0),
    ("gib", 1024.0 * 1024.0 * 1024.0),
    ("tib", 1024.0 * 1024.0 * 1024.0 * 1024.0),
];
const FORECAST: &str = "forecast";
/// What every number a sum works on goes through, so whole numbers and metrics'
/// fractions mix: CEL only adds two numbers of the same kind. Nobody can type it,
/// as it isn't a name.
const NUMBER: &str = "number:";

/// What a metric's forecast is bound as, which nobody can type, as it isn't a name.
fn heading_name(metric: &Metric) -> String {
    format!("forecast:{}", metric.name)
}

/// The names conditions can use beside metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variable {
    /// What the host's agent reports about it, such as `facts.os.family`.
    Facts,
    /// Whether the host is connected.
    Online,
    /// Whether a connected host's samples are arriving.
    Reporting,
    /// The hostname. It isn't `host`, which some metrics' names start with, so
    /// `host.uptime` can be shown in a summary as well.
    Hostname,
    /// The series being looked at, such as a disk's mount point, or empty.
    Series,
    /// The calculated value, for a rule with a calculation.
    Value,
}

impl Variable {
    pub const ALL: [Self; 6] = [
        Self::Facts,
        Self::Online,
        Self::Reporting,
        Self::Hostname,
        Self::Series,
        Self::Value,
    ];

    /// What it is, in a few words.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Facts => "what the host's agent reports about it",
            Self::Online => "whether the host is connected",
            Self::Reporting => "whether a connected host's samples are arriving",
            Self::Hostname => "the hostname",
            Self::Series => "the series being looked at",
            Self::Value => "a calculation's value",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Facts => "facts",
            Self::Online => "online",
            Self::Reporting => "reporting",
            Self::Hostname => "hostname",
            Self::Series => "series",
            Self::Value => "value",
        }
    }
}

/// What a condition is worked out over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Each host, with its metrics by name.
    Hosts,
    /// Each line of a calculation across hosts, as `value`.
    Calculation,
}

/// A metric as a condition uses it.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricUse {
    pub metric: &'static Metric,
    /// Picked out with brackets, `cpu.load['5 minutes']`, so it's a map of each
    /// series to its value rather than one value.
    pub bracketed: bool,
    /// The series the brackets pick, when it's written out.
    pub picked: Option<String>,
    /// Inside `forecast()`, so what's wanted is where it's heading.
    pub forecast: bool,
}

/// What kind of value a template's own metric is, as far as can be told before an
/// agent sends one: a query's column could be a number, a length of time or a yes or
/// no until the database says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalKind {
    Number,
    Seconds,
    Flag,
    Unknown,
}

impl LocalKind {
    fn sample(self) -> CelValue {
        match self {
            Self::Number | Self::Unknown => CelValue::Float(50.0),
            Self::Seconds => duration(50.0),
            Self::Flag => CelValue::Bool(true),
        }
    }
}

/// One of a template's own metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalMetric {
    pub kind: LocalKind,
    /// What tells its series apart, such as `slot`. Metrics pair up when these match.
    pub labels: Vec<String>,
}

/// A template's own metrics, which its conditions use by their short names, `lag`,
/// or by their full ones, `postgres.lag`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalMetrics {
    /// The template's key, which starts their full names.
    pub prefix: String,
    pub metrics: BTreeMap<String, LocalMetric>,
}

impl LocalMetrics {
    /// The short name of the metric a dotted name means, if it's one of these.
    fn find(&self, name: &[String]) -> Option<String> {
        let short = match name {
            [short] => short,
            [prefix, short] if *prefix == self.prefix => short,
            _ => return None,
        };
        self.metrics.contains_key(short).then(|| short.clone())
    }

    fn full_name(&self, short: &str) -> String {
        format!("{}.{short}", self.prefix)
    }
}

/// One of a template's own metrics as a condition uses it.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalUse {
    pub short: String,
    pub bracketed: bool,
    pub picked: Option<String>,
    pub forecast: bool,
}

/// A condition, read and ready to work out.
#[derive(Debug, Clone)]
pub struct Condition {
    text: String,
    /// The condition with every metric named as it's bound.
    expr: IdedExpr,
    uses: Vec<MetricUse>,
    /// A template's own metrics it uses, which only a template's checks bind.
    local: Vec<LocalUse>,
    variables: BTreeSet<Variable>,
}

impl PartialEq for Condition {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

/// Whether a function is one of CEL's operators, which are written as symbols.
fn is_operator(name: &str) -> bool {
    name.starts_with('_')
        || name.starts_with('@')
        || name == operators::LOGICAL_NOT
        || name == operators::NEGATE
}

/// The dotted name an expression spells, such as `disk.usage`, if it is one.
fn name_of(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Ident(name) => Some(vec![name.clone()]),
        Expr::Select(select) if !select.test => {
            let mut name = name_of(&select.operand.expr)?;
            name.push(select.field.clone());
            Some(name)
        }
        _ => None,
    }
}

/// The metric a name starts with, the longest that fits, and how many of its parts
/// that takes.
fn metric_in(name: &[String]) -> Option<(&'static Metric, usize)> {
    (1..=name.len())
        .rev()
        .find_map(|parts| Some((metrics::find(&name[..parts].join("."))?, parts)))
}

/// The catalog's name closest to a mistyped one.
fn closest_metric(name: &str) -> Option<&'static str> {
    METRICS
        .iter()
        .map(|metric| (strsim::levenshtein(name, metric.name), metric.name))
        .filter(|(distance, _)| *distance <= 3)
        .min()
        .map(|(_, closest)| closest)
}

fn string_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Literal(LiteralValue::String(text)) => Some(text.inner().to_string()),
        _ => None,
    }
}

/// Reads a condition's names, binding each metric under its own name.
struct Reader<'a> {
    scope: Scope,
    local_metrics: Option<&'a LocalMetrics>,
    uses: Vec<MetricUse>,
    local: Vec<LocalUse>,
    variables: BTreeSet<Variable>,
    functions: BTreeSet<String>,
    /// Names a macro such as `exists` brings in.
    locals: Vec<String>,
}

impl Reader<'_> {
    fn use_metric(&mut self, used: MetricUse) -> Result<()> {
        ensure!(
            self.scope == Scope::Hosts,
            "a rule with a calculation watches the calculated value, like value > 80, not {}",
            used.metric.name
        );
        self.uses.push(used);
        Ok(())
    }

    /// The template's own metric most like a name that isn't one, if any is close.
    fn closest_local(&self, name: &str) -> Option<String> {
        let local = self.local_metrics?;
        local
            .metrics
            .keys()
            .map(|short| (strsim::levenshtein(name, short), short))
            .filter(|(distance, _)| *distance <= 3)
            .min()
            .map(|(_, short)| short.clone())
    }

    /// Notes a template's own metric being used, giving the name it's bound as.
    fn use_local(&mut self, used: LocalUse) -> Result<String> {
        let local = self.local_metrics.expect("only found with local metrics");
        let full = local.full_name(&used.short);
        ensure!(
            self.scope == Scope::Hosts,
            "a rule with a calculation watches the calculated value, like value > 80, not {full}"
        );
        let bound = match used.forecast {
            true => format!("forecast:{full}"),
            false => full,
        };
        self.local.push(used);
        Ok(bound)
    }

    /// The template's own metric an expression names, by itself or picked out with
    /// brackets, and whether it's bracketed.
    fn local_named(&self, expr: &Expr) -> Option<(String, bool)> {
        let local = self.local_metrics?;
        let (target, bracketed) = match expr {
            Expr::Call(call) if is_index(call) => (&call.args[0].expr, true),
            other => (other, false),
        };
        let name = name_of(target)?;
        if self.locals.contains(&name[0]) {
            return None;
        }
        Some((local.find(&name)?, bracketed))
    }

    fn read(&mut self, expr: &mut IdedExpr) -> Result<()> {
        if let Some(name) = name_of(&expr.expr) {
            return self.name(expr, &name);
        }
        match &mut expr.expr {
            // has(), or a field of something that isn't a name.
            Expr::Select(select) => self.read(&mut select.operand),
            Expr::Call(_) => self.call(expr),
            Expr::Comprehension(comprehension) => {
                self.read(&mut comprehension.iter_range)?;
                self.read(&mut comprehension.accu_init)?;
                let before = self.locals.len();
                self.locals.push(comprehension.iter_var.clone());
                self.locals.extend(comprehension.iter_var2.clone());
                self.locals.push(comprehension.accu_var.clone());
                let read = [
                    &mut comprehension.loop_cond,
                    &mut comprehension.loop_step,
                    &mut comprehension.result,
                ]
                .into_iter()
                .try_for_each(|part| self.read(part));
                self.locals.truncate(before);
                read
            }
            Expr::List(list) => list
                .elements
                .iter_mut()
                .try_for_each(|item| self.read(item)),
            Expr::Map(map) => map
                .entries
                .iter_mut()
                .try_for_each(|entry| self.entry(&mut entry.expr)),
            Expr::Struct(made) => made
                .entries
                .iter_mut()
                .try_for_each(|entry| self.entry(&mut entry.expr)),
            Expr::Literal(_) | Expr::Unspecified | Expr::Ident(_) => Ok(()),
        }
    }

    fn entry(&mut self, entry: &mut EntryExpr) -> Result<()> {
        match entry {
            EntryExpr::MapEntry(entry) => {
                self.read(&mut entry.key)?;
                self.read(&mut entry.value)
            }
            EntryExpr::StructField(field) => self.read(&mut field.value),
        }
    }

    fn name(&mut self, expr: &mut IdedExpr, name: &[String]) -> Result<()> {
        if self.locals.contains(&name[0]) {
            return Ok(());
        }
        let whole = name.join(".");
        if let Some(short) = self.local_metrics.and_then(|local| local.find(name)) {
            let full = self.use_local(LocalUse {
                short,
                bracketed: false,
                picked: None,
                forecast: false,
            })?;
            expr.expr = Expr::Ident(full);
            return Ok(());
        }
        if let Some((metric, parts)) = metric_in(name) {
            ensure!(
                parts == name.len(),
                "{} has no part called {:?}",
                metric.name,
                name[parts..].join(".")
            );
            self.use_metric(MetricUse {
                metric,
                bracketed: false,
                picked: None,
                forecast: false,
            })?;
            expr.expr = Expr::Ident(metric.name.to_string());
            return Ok(());
        }
        let variable = Variable::ALL
            .into_iter()
            .find(|variable| variable.name() == name[0])
            .filter(|variable| *variable == Variable::Facts || name.len() == 1);
        match (variable, self.scope) {
            (Some(Variable::Value), Scope::Hosts) => bail!(
                "value is for a rule with a calculation; here, use the metric's name, like disk.usage > 90"
            ),
            (Some(Variable::Value), Scope::Calculation) | (Some(_), Scope::Hosts) => {
                self.variables.extend(variable);
                Ok(())
            }
            (Some(_), Scope::Calculation) => bail!(
                "a rule with a calculation watches the calculated value, like value > 80, not {whole}"
            ),
            (None, _) => match self
                .closest_local(&whole)
                .or_else(|| closest_metric(&whole).map(str::to_string))
            {
                Some(closest) => bail!("there's no metric called {whole}: did you mean {closest}?"),
                None => bail!(
                    "{whole} isn't a metric or anything else a condition knows: it can use metrics by their names, facts, online, reporting, hostname and series"
                ),
            },
        }
    }

    /// The metric an expression names, by itself or picked out with brackets, and
    /// whether it's bracketed.
    fn metric_named(&self, expr: &Expr) -> Option<(&'static Metric, bool)> {
        let (target, bracketed) = match expr {
            Expr::Call(call) if is_index(call) => (&call.args[0].expr, true),
            other => (other, false),
        };
        let name = name_of(target)?;
        if self.locals.contains(&name[0]) {
            return None;
        }
        Some((metrics::find(&name.join("."))?, bracketed))
    }

    /// Binds a metric written by itself or picked out with brackets, as a forecast's
    /// starting point if it's in `forecast()`. False if it isn't a metric.
    fn metric_argument(&mut self, expr: &mut IdedExpr, forecast: bool) -> Result<bool> {
        if let Some((short, bracketed)) = self.local_named(&expr.expr) {
            let picked = match &expr.expr {
                Expr::Call(call) if bracketed => string_literal(&call.args[1].expr),
                _ => None,
            };
            let bound = Expr::Ident(self.use_local(LocalUse {
                short,
                bracketed,
                picked,
                forecast,
            })?);
            match &mut expr.expr {
                Expr::Call(call) if bracketed => {
                    call.args[0].expr = bound;
                    self.read(&mut call.args[1])?;
                }
                _ => expr.expr = bound,
            }
            return Ok(true);
        }
        let Some((metric, bracketed)) = self.metric_named(&expr.expr) else {
            return Ok(false);
        };
        let picked = match &expr.expr {
            Expr::Call(call) if bracketed => string_literal(&call.args[1].expr),
            _ => None,
        };
        if let (Source::Fields(fields), Some(picked)) = (metric.source, &picked) {
            ensure!(
                fields.iter().any(|(field, _)| field == picked),
                "{} has no series called {picked:?}: it has {}",
                metric.name,
                parts_of(fields)
            );
        }
        self.use_metric(MetricUse {
            metric,
            bracketed,
            picked,
            forecast,
        })?;
        let bound = Expr::Ident(if forecast {
            heading_name(metric)
        } else {
            metric.name.to_string()
        });
        match &mut expr.expr {
            Expr::Call(call) if bracketed => {
                call.args[0].expr = bound;
                self.read(&mut call.args[1])?;
            }
            _ => expr.expr = bound,
        }
        Ok(true)
    }

    fn call(&mut self, expr: &mut IdedExpr) -> Result<()> {
        if self.metric_argument(expr, false)? {
            return Ok(());
        }
        let Expr::Call(call) = &mut expr.expr else {
            return Ok(());
        };
        if call.func_name == FORECAST && call.target.is_none() {
            ensure!(
                self.scope == Scope::Hosts,
                "forecast() is for a host's metrics, not a calculation"
            );
            let usage = "forecast() takes a metric and how far ahead, like forecast(disk.usage, duration('4h'))";
            ensure!(call.args.len() == 2, "{usage}");
            ensure!(self.metric_argument(&mut call.args[0], true)?, "{usage}");
            self.functions.insert(FORECAST.to_string());
            return self.read(&mut call.args[1]);
        }
        if !is_operator(&call.func_name) {
            self.functions.insert(call.func_name.clone());
        }
        if let Some(target) = &mut call.target {
            self.read(target)?;
        }
        call.args.iter_mut().try_for_each(|arg| self.read(arg))?;
        // A sum's whole numbers are made numbers with fractions as it's worked out,
        // so `cpu.usage / 2` works as it reads. Comparisons mix them already.
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
        Ok(())
    }
}

/// Whether a call picks something out with brackets.
fn is_index(call: &CallExpr) -> bool {
    call.target.is_none()
        && call.args.len() == 2
        && matches!(
            call.func_name.as_str(),
            operators::INDEX | operators::OPT_INDEX
        )
}

/// A metric's fixed series, for saying which there are.
fn parts_of(fields: &[(&str, metrics::Reading)]) -> String {
    let names: Vec<String> = fields.iter().map(|(name, _)| format!("'{name}'")).collect();
    names.join(", ")
}

/// The functions and macros conditions can use, made once, as making them takes far
/// longer than working a condition out.
static FUNCTIONS: LazyLock<Arc<Env>> = LazyLock::new(|| Arc::new(Env::stdlib()));

fn number_of(value: &CelValue) -> Option<f64> {
    match value {
        CelValue::Int(number) => Some(*number as f64),
        CelValue::UInt(number) => Some(*number as f64),
        CelValue::Float(number) => Some(*number),
        _ => None,
    }
}

/// A number of seconds as CEL's length of time, to the nanosecond.
fn duration(secs: f64) -> CelValue {
    let nanos = (secs * 1e9).round();
    let nanos = nanos.clamp(i64::MIN as f64, i64::MAX as f64) as i64;
    CelValue::Duration(TimeDelta::nanoseconds(nanos))
}

fn seconds_of(value: &CelValue) -> Option<f64> {
    match value {
        CelValue::Duration(length) => Some(length.as_seconds_f64()),
        _ => None,
    }
}

/// A host's facts as conditions see them. A host with none has none, rather than
/// nothing at all, so a fact it lacks is missing like any other.
pub fn facts_value(facts: &serde_json::Value) -> CelValue {
    match facts {
        serde_json::Value::Object(_) => cel::to_value(facts).unwrap_or(CelValue::Null),
        _ => CelValue::Map(HashMap::<String, CelValue>::new().into()),
    }
}

/// A reading as a condition sees it: a length of time for a metric in seconds, so
/// it's compared with `duration('5m')`, and a number otherwise.
pub fn bind_value(unit: Unit, value: f64) -> CelValue {
    match unit {
        Unit::Seconds => duration(value),
        _ => CelValue::Float(value),
    }
}

/// A forecast's starting point: the value now, and how much it changes each second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Heading {
    pub value: f64,
    pub slope_per_sec: f64,
}

fn heading_value(unit: Unit, heading: Heading) -> CelValue {
    let fields: HashMap<String, CelValue> = HashMap::from([
        ("value".to_string(), CelValue::Float(heading.value)),
        ("slope".to_string(), CelValue::Float(heading.slope_per_sec)),
        ("seconds".to_string(), CelValue::Bool(unit == Unit::Seconds)),
    ]);
    fields.into()
}

/// `forecast(metric, ahead)`: where the metric will be after `ahead` if it carries on
/// the way it's been going.
fn forecast(Arguments(args): Arguments) -> Result<CelValue, ExecutionError> {
    let wrong = || {
        ExecutionError::function_error(
            FORECAST,
            "it takes a metric and how far ahead, like forecast(disk.usage, duration('4h'))",
        )
    };
    let [CelValue::Map(heading), ahead] = args.as_slice() else {
        return Err(wrong());
    };
    let ahead = seconds_of(ahead).ok_or_else(|| {
        ExecutionError::function_error(
            FORECAST,
            "how far ahead has to be a duration, like duration('4h')",
        )
    })?;
    let field = |name: &str| heading.map.get(&cel::objects::Key::from(name)).cloned();
    let (Some(CelValue::Float(value)), Some(CelValue::Float(slope)), Some(CelValue::Bool(secs))) =
        (field("value"), field("slope"), field("seconds"))
    else {
        return Err(wrong());
    };
    let then = value + slope * ahead;
    Ok(if secs {
        duration(then)
    } else {
        CelValue::Float(then)
    })
}

fn size(name: &'static str, factor: f64, args: &[CelValue]) -> Result<CelValue, ExecutionError> {
    match args {
        [count] => number_of(count)
            .map(|count| CelValue::Float(count * factor))
            .ok_or_else(|| ExecutionError::function_error(name, "it takes a number")),
        _ => Err(ExecutionError::function_error(name, "it takes one number")),
    }
}

/// A whole number as one with a fraction, and anything else as it is.
fn number(Arguments(args): Arguments) -> Result<CelValue, ExecutionError> {
    match args.as_slice() {
        [CelValue::Int(whole)] => Ok(CelValue::Float(*whole as f64)),
        [CelValue::UInt(whole)] => Ok(CelValue::Float(*whole as f64)),
        [other] => Ok(other.clone()),
        _ => Err(ExecutionError::invalid_argument_count(1, args.len())),
    }
}

/// The functions conditions have, made once, as making them takes far longer than
/// working a condition out. Each working out binds its values in a scope of its own
/// under this one.
static BASE: LazyLock<CelContext<'static, 'static>> = LazyLock::new(|| {
    let mut context = CelContext::with_env(FUNCTIONS.clone());
    for (name, factor) in SIZES {
        // The names aren't CEL's own, so adding them can't fail.
        let _ = context.add_function(name, move |Arguments(args): Arguments| {
            size(name, factor, &args)
        });
    }
    let _ = context.add_function(FORECAST, forecast);
    let _ = context.add_function(NUMBER, number);
    context
});

/// Whether CEL, or what's added here, has a function by this name, called either way.
fn is_function(name: &str) -> bool {
    let null = IdedExpr {
        id: 0,
        expr: Expr::Literal(LiteralValue::Null),
    };
    [None, Some(Box::new(null))].into_iter().any(|target| {
        let call = IdedExpr {
            id: 0,
            expr: Expr::Call(CallExpr {
                func_name: name.to_string(),
                target,
                args: Vec::new(),
            }),
        };
        !matches!(
            BASE.resolve(&call),
            Err(ExecutionError::UndeclaredReference(_))
        )
    })
}

impl Condition {
    /// Reads a condition, refusing one that isn't CEL, uses a name nothing has, or
    /// uses a metric in a way that can't work.
    pub fn compile(text: &str, scope: Scope) -> Result<Self> {
        Self::compile_in(text, scope, None)
    }

    /// Reads a condition that can use a template's own metrics as well.
    pub fn compile_in(text: &str, scope: Scope, local: Option<&LocalMetrics>) -> Result<Self> {
        ensure!(!text.trim().is_empty(), "a condition can't be empty");
        ensure!(
            text.len() <= MAX_CONDITION_LEN,
            "a condition can be up to {MAX_CONDITION_LEN} characters"
        );
        let program = Program::compile(text).map_err(|error| anyhow!("{error}"))?;
        let mut expr = program.expression().clone();
        let mut reader = Reader {
            scope,
            local_metrics: local,
            uses: Vec::new(),
            local: Vec::new(),
            variables: BTreeSet::new(),
            functions: BTreeSet::new(),
            locals: Vec::new(),
        };
        reader.read(&mut expr)?;
        if let Some(unknown) = reader.functions.iter().find(|name| !is_function(name)) {
            bail!("there's no function called {unknown}");
        }
        Ok(Self {
            text: text.to_string(),
            expr,
            uses: reader.uses,
            local: reader.local,
            variables: reader.variables,
        })
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Each time it uses a metric, in the order they're written.
    pub fn uses(&self) -> &[MetricUse] {
        &self.uses
    }

    pub fn uses_variable(&self, variable: Variable) -> bool {
        self.variables.contains(&variable)
    }

    /// Whether it's true. Anything else, such as an error from a fact a host doesn't
    /// have, isn't.
    pub fn holds(&self, bindings: &Bindings) -> bool {
        matches!(bindings.0.resolve(&self.expr), Ok(CelValue::Bool(true)))
    }

    /// The level to draw across a chart of what it watches, for a condition that
    /// only compares one metric, or a calculation's value, with a number or length
    /// of time, such as `disk.usage > 90`.
    pub fn threshold(&self) -> Option<Threshold> {
        let Expr::Call(call) = &self.expr.expr else {
            return None;
        };
        let compares = matches!(
            call.func_name.as_str(),
            operators::GREATER
                | operators::GREATER_EQUALS
                | operators::LESS
                | operators::LESS_EQUALS
        );
        if !compares || call.target.is_some() || call.args.len() != 2 || self.uses.len() > 1 {
            return None;
        }
        let used = self.uses.first().filter(|used| !used.forecast);
        let watched = |expr: &IdedExpr| match (&expr.expr, used) {
            (Expr::Ident(name), Some(used)) if !used.bracketed && used.metric.name == name => {
                Some((Some(used.metric.name), None))
            }
            (Expr::Ident(name), None) if name == Variable::Value.name() => Some((None, None)),
            (Expr::Call(call), Some(used)) if call.func_name == operators::INDEX => {
                matches!(&call.args[0].expr, Expr::Ident(name) if *name == used.metric.name)
                    .then(|| (Some(used.metric.name), used.picked.clone()))
            }
            _ => None,
        };
        let level = |expr: &IdedExpr| {
            let literal = match &expr.expr {
                Expr::Literal(_) => true,
                Expr::Call(call) => {
                    (call.func_name == "duration" && call.args.len() == 1)
                        && matches!(call.args[0].expr, Expr::Literal(LiteralValue::String(_)))
                        || (call.func_name == operators::NEGATE
                            && matches!(call.args[0].expr, Expr::Literal(_)))
                }
                _ => false,
            };
            if !literal {
                return None;
            }
            let value = BASE.resolve(expr).ok()?;
            number_of(&value).or_else(|| seconds_of(&value))
        };
        let ((metric, picked), level) = match (&call.args[0], &call.args[1]) {
            (watched_side, number) if watched(watched_side).is_some() => {
                (watched(watched_side)?, level(number)?)
            }
            (number, watched_side) => (watched(watched_side)?, level(number)?),
        };
        Some(Threshold {
            metric,
            picked,
            level,
        })
    }
}

/// A level to draw across a chart, and what it's a level of.
#[derive(Debug, Clone, PartialEq)]
pub struct Threshold {
    /// The metric, or none for a calculation's value.
    pub metric: Option<&'static str>,
    /// The series picked out with brackets, if one is.
    pub picked: Option<String>,
    pub level: f64,
}

/// One metric's newest values on a host, as a condition sees them.
#[derive(Debug, Clone, PartialEq)]
pub enum Values<T> {
    /// The value for the series being looked at.
    One(T),
    /// Every series' value, for a metric picked out with brackets.
    Each(BTreeMap<String, T>),
}

/// Everything one working out of a rule's conditions sees.
pub struct Inputs<'a> {
    /// The host's facts, made ready for CEL once for all its series. Null when no
    /// condition uses them.
    pub facts: CelValue,
    pub hostname: &'a str,
    pub series: &'a str,
    pub online: bool,
    pub reporting: bool,
    /// The calculated value, for a rule with a calculation.
    pub value: Option<CelValue>,
    pub metrics: BTreeMap<&'static str, Values<f64>>,
    pub headings: BTreeMap<&'static str, Values<Heading>>,
}

/// What conditions are worked out against.
pub struct Bindings(CelContext<'static, 'static>);

impl Inputs<'_> {
    pub fn bind(&self) -> Bindings {
        let mut context = BASE.new_inner_scope();
        context.add_variable_from_value(Variable::Facts.name(), self.facts.clone());
        context.add_variable_from_value(Variable::Hostname.name(), self.hostname.to_string());
        context.add_variable_from_value(Variable::Series.name(), self.series.to_string());
        context.add_variable_from_value(Variable::Online.name(), self.online);
        context.add_variable_from_value(Variable::Reporting.name(), self.reporting);
        if let Some(value) = &self.value {
            context.add_variable_from_value(Variable::Value.name(), value.clone());
        }
        for (name, values) in &self.metrics {
            let Some(metric) = metrics::find(name) else {
                continue;
            };
            let bound = match values {
                Values::One(value) => bind_value(metric.unit, *value),
                Values::Each(each) => each
                    .iter()
                    .map(|(series, value)| (series.clone(), bind_value(metric.unit, *value)))
                    .collect::<HashMap<String, CelValue>>()
                    .into(),
            };
            context.add_variable_from_value(*name, bound);
        }
        for (name, headings) in &self.headings {
            let Some(metric) = metrics::find(name) else {
                continue;
            };
            let bound = match headings {
                Values::One(heading) => heading_value(metric.unit, *heading),
                Values::Each(each) => each
                    .iter()
                    .map(|(series, heading)| (series.clone(), heading_value(metric.unit, *heading)))
                    .collect::<HashMap<String, CelValue>>()
                    .into(),
            };
            context.add_variable_from_value(heading_name(metric), bound);
        }
        Bindings(context)
    }
}

/// A rule's conditions, mildest first.
#[derive(Debug, Clone, PartialEq)]
pub struct Conditions {
    pub warning: Option<Condition>,
    pub critical: Option<Condition>,
}

impl Conditions {
    /// Reads a rule's conditions, and checks they can work together: metrics with a
    /// series for each of something are worked out for each, so the ones used by
    /// themselves have to be about the same things to pair up.
    pub fn compile(warning: Option<&str>, critical: Option<&str>, scope: Scope) -> Result<Self> {
        Self::compile_in(warning, critical, scope, None)
    }

    /// Reads conditions that can use a template's own metrics as well.
    pub fn compile_in(
        warning: Option<&str>,
        critical: Option<&str>,
        scope: Scope,
        local: Option<&LocalMetrics>,
    ) -> Result<Self> {
        ensure!(
            warning.is_some() || critical.is_some(),
            "a rule needs a warning or critical condition, or both"
        );
        let read = |text: Option<&str>, which: &str| {
            text.map(|text| {
                Condition::compile_in(text, scope, local)
                    .map_err(|error| anyhow!("the {which} condition: {error:#}"))
            })
            .transpose()
        };
        let conditions = Self {
            warning: read(warning, "warning")?,
            critical: read(critical, "critical")?,
        };
        conditions.check_series()?;
        if let Some(local) = local {
            conditions.check_local_series(local)?;
        }
        Ok(conditions)
    }

    /// The template's own metrics they use, each time they use one.
    pub fn local_uses(&self) -> impl Iterator<Item = &LocalUse> {
        let warning = self.warning.iter().flat_map(|condition| &condition.local);
        let critical = self.critical.iter().flat_map(|condition| &condition.local);
        warning.chain(critical)
    }

    /// Whether they use any of a template's own metrics, which only an agent running
    /// the template sends.
    pub fn uses_local(&self) -> bool {
        self.local_uses().next().is_some()
    }

    /// A template's own metrics used by themselves are worked out for each series, so
    /// those with labels have to have the same ones to pair up, and can't pair with a
    /// metric that has a series for each disk or such.
    fn check_local_series(&self, local: &LocalMetrics) -> Result<()> {
        let uses: Vec<&LocalUse> = self.local_uses().collect();
        for used in &uses {
            let both = uses.iter().any(|other| {
                other.short == used.short
                    && other.bracketed != used.bracketed
                    && other.forecast == used.forecast
            });
            ensure!(
                !both,
                "{} is used both with and without brackets, which can't be worked out together: pick a series with brackets each time, or none",
                used.short
            );
        }
        let labelled: Vec<(&str, &Vec<String>)> = uses
            .iter()
            .filter(|used| !used.bracketed)
            .map(|used| (used.short.as_str(), &local.metrics[&used.short].labels))
            .filter(|(_, labels)| !labels.is_empty())
            .collect();
        fn sorted(labels: &[String]) -> BTreeSet<&String> {
            labels.iter().collect()
        }
        if let Some((first, labels)) = labelled.first()
            && let Some((other, theirs)) = labelled
                .iter()
                .find(|(_, theirs)| sorted(theirs) != sorted(labels))
        {
            bail!(
                "{first} and {other} have series labelled differently ({} and {}), so they can't be paired up: pick a series of one of them with brackets, like {other}['name']",
                labels.join(", "),
                theirs.join(", ")
            );
        }
        if let (Some((first, _)), Some(fanned)) = (labelled.first(), self.fanned_out().first()) {
            bail!(
                "{first} and {} have series of different things, so they can't be paired up: pick a series of one of them with brackets, like {}['name']",
                fanned.metric.name,
                fanned.metric.name
            );
        }
        Ok(())
    }

    /// Each condition with the severity it's for, mildest first.
    pub fn levels(&self) -> Vec<(crate::alerting::Severity, &Condition)> {
        use crate::alerting::Severity;
        let warning = self.warning.as_ref().map(|c| (Severity::Warning, c));
        let critical = self.critical.as_ref().map(|c| (Severity::Critical, c));
        warning.into_iter().chain(critical).collect()
    }

    pub fn uses(&self) -> impl Iterator<Item = &MetricUse> {
        let warning = self.warning.iter().flat_map(|condition| &condition.uses);
        let critical = self.critical.iter().flat_map(|condition| &condition.uses);
        warning.chain(critical)
    }

    pub fn uses_variable(&self, variable: Variable) -> bool {
        self.levels()
            .iter()
            .any(|(_, condition)| condition.uses_variable(variable))
    }

    /// The metric the rule is mostly about: the first one it uses, which its alerts
    /// chart and give the value of.
    pub fn primary(&self) -> Option<&MetricUse> {
        self.uses().next()
    }

    /// The metrics whose newest readings are needed.
    pub fn read_metrics(&self) -> BTreeSet<&'static str> {
        self.uses()
            .filter(|used| !used.forecast)
            .map(|used| used.metric.name)
            .collect()
    }

    /// The metrics whose forecasts are needed.
    pub fn forecast_metrics(&self) -> BTreeSet<&'static str> {
        self.uses()
            .filter(|used| used.forecast)
            .map(|used| used.metric.name)
            .collect()
    }

    /// The metrics used by themselves that have a series for each disk, interface or
    /// such, which the rule is worked out for each of.
    pub fn fanned_out(&self) -> Vec<&MetricUse> {
        let mut fanned: Vec<&MetricUse> = Vec::new();
        for used in self.uses() {
            let each = !used.bracketed && !matches!(used.metric.source, Source::Fields(_));
            if each
                && !fanned.iter().any(|seen| {
                    seen.metric.name == used.metric.name && seen.forecast == used.forecast
                })
            {
                fanned.push(used);
            }
        }
        fanned
    }

    fn check_series(&self) -> Result<()> {
        let uses: Vec<&MetricUse> = self.uses().collect();
        for used in &uses {
            let name = used.metric.name;
            if let (Source::Fields(fields), false) = (used.metric.source, used.bracketed)
                && fields.len() > 1
            {
                bail!(
                    "{name} has several series, so pick one with brackets, like {name}['{}']: it has {}",
                    fields[0].0,
                    parts_of(fields)
                );
            }
            let both = uses.iter().any(|other| {
                other.metric.name == name
                    && other.bracketed != used.bracketed
                    && other.forecast == used.forecast
            });
            ensure!(
                !both,
                "{name} is used both with and without brackets, which can't be worked out together: pick a series with brackets each time, or none"
            );
        }
        let fanned = self.fanned_out();
        if let Some((first, rest)) = fanned.split_first()
            && let Some(other) = rest
                .iter()
                .find(|other| series_kind(other.metric) != series_kind(first.metric))
        {
            bail!(
                "{} and {} have series of different things, so they can't be paired up: pick a series of one of them with brackets, like {}['name']",
                first.metric.name,
                other.metric.name,
                other.metric.name
            );
        }
        Ok(())
    }

    /// Works both conditions out on made-up values of the right types, with `facts`
    /// from a real host if there is one, and says what's wrong in plain words. A fact
    /// that isn't there is fine, as hosts differ.
    pub fn dry_run(&self, facts: &serde_json::Value, value_unit: Unit) -> Result<()> {
        self.dry_run_in(facts, value_unit, None)
    }

    /// The same, with a template's own metrics bound as well. One whose kind can't be
    /// told yet, a query's column, is tried as each kind it could be, and the
    /// conditions only have to work for one way of choosing them.
    pub fn dry_run_in(
        &self,
        facts: &serde_json::Value,
        value_unit: Unit,
        local: Option<&LocalMetrics>,
    ) -> Result<()> {
        let inputs = self.sample_inputs(facts, value_unit);
        let mut unknown: Vec<&str> = Vec::new();
        if let Some(local) = local {
            for used in self.local_uses() {
                if local.metrics[&used.short].kind == LocalKind::Unknown
                    && !unknown.contains(&used.short.as_str())
                {
                    unknown.push(&used.short);
                }
            }
        }
        const CHOICES: [LocalKind; 3] = [LocalKind::Number, LocalKind::Seconds, LocalKind::Flag];
        // Every way of choosing, while there are few enough; otherwise the same kind
        // for all of them.
        let ways: Vec<Vec<LocalKind>> = match u32::try_from(unknown.len()) {
            Ok(count) if count <= 5 => (0..3usize.pow(count))
                .map(|mut way| {
                    (0..unknown.len())
                        .map(|_| {
                            let kind = CHOICES[way % 3];
                            way /= 3;
                            kind
                        })
                        .collect()
                })
                .collect(),
            _ => CHOICES
                .iter()
                .map(|kind| vec![*kind; unknown.len()])
                .collect(),
        };
        let mut first_error = None;
        for way in ways {
            let mut bindings = inputs.bind();
            if let Some(local) = local {
                let kind_of = |short: &str| match unknown.iter().position(|name| *name == short) {
                    Some(at) => way[at],
                    None => local.metrics[short].kind,
                };
                self.bind_local(&mut bindings, local, &kind_of);
            }
            let tried = self
                .levels()
                .into_iter()
                .try_for_each(|(severity, condition)| {
                    condition
                        .dry_run(&bindings)
                        .map_err(|error| anyhow!("the {} condition: {error:#}", severity.as_str()))
                });
            match tried {
                Ok(()) => return Ok(()),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.expect("there's always a way to try"))
    }

    /// Binds a sample of each of a template's own metrics that's used, as `kind_of` says.
    fn bind_local(
        &self,
        bindings: &mut Bindings,
        local: &LocalMetrics,
        kind_of: &dyn Fn(&str) -> LocalKind,
    ) {
        let mut picked: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for used in self.local_uses() {
            picked
                .entry(&used.short)
                .or_default()
                .extend(used.picked.clone());
        }
        for used in self.local_uses() {
            let sample = kind_of(&used.short).sample();
            let full = local.full_name(&used.short);
            let value = match used.bracketed {
                true => picked[used.short.as_str()]
                    .iter()
                    .map(|series| (series.clone(), sample.clone()))
                    .collect::<HashMap<String, CelValue>>()
                    .into(),
                false => sample,
            };
            let name = match used.forecast {
                true => format!("forecast:{full}"),
                false => full,
            };
            let value = match used.forecast {
                // A forecast's starting point, as a catalog metric's is bound.
                true => {
                    let heading = |value: &CelValue| {
                        let unit = match value {
                            CelValue::Duration(_) => Unit::Seconds,
                            _ => Unit::Number,
                        };
                        heading_value(
                            unit,
                            Heading {
                                value: 50.0,
                                slope_per_sec: 0.0,
                            },
                        )
                    };
                    match &value {
                        CelValue::Map(map) => map
                            .map
                            .iter()
                            .map(|(key, value)| (key.clone(), heading(value)))
                            .collect::<HashMap<cel::objects::Key, CelValue>>()
                            .into(),
                        other => heading(other),
                    }
                }
                false => value,
            };
            bindings.0.add_variable_from_value(name, value);
        }
    }

    fn sample_inputs(&self, facts: &serde_json::Value, value_unit: Unit) -> Inputs<'static> {
        // Every series a condition picks out by name, so a picked one is there.
        let mut picked: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        for used in self.uses() {
            let names = picked.entry(used.metric.name).or_default();
            names.extend(used.picked.clone());
            if let Source::Fields(fields) = used.metric.source {
                names.extend(fields.iter().map(|(name, _)| name.to_string()));
            }
        }
        let sample = 50.0;
        let values = |used: &MetricUse| -> BTreeMap<String, f64> {
            picked[used.metric.name]
                .iter()
                .map(|name| (name.clone(), sample))
                .collect()
        };
        let mut inputs = Inputs {
            facts: facts_value(facts),
            hostname: "web-1",
            series: "/",
            online: true,
            reporting: true,
            value: Some(bind_value(value_unit, sample)),
            metrics: BTreeMap::new(),
            headings: BTreeMap::new(),
        };
        for used in self.uses() {
            let name = used.metric.name;
            if used.forecast {
                let heading = Heading {
                    value: sample,
                    slope_per_sec: 0.0,
                };
                let bound = match used.bracketed {
                    true => {
                        Values::Each(values(used).into_keys().map(|key| (key, heading)).collect())
                    }
                    false => Values::One(heading),
                };
                inputs.headings.insert(name, bound);
            } else {
                let bound = match used.bracketed {
                    true => Values::Each(values(used)),
                    false => Values::One(sample),
                };
                inputs.metrics.insert(name, bound);
            }
        }
        inputs
    }
}

/// What a metric's series are, so two metrics used by themselves only pair up when
/// their series name the same things, such as mount points.
fn series_kind(metric: &Metric) -> Option<(&'static str, &'static str)> {
    match metric.source {
        Source::Fields(_) => None,
        Source::Items { name, .. } => Some((metric.collector, name)),
        Source::Entries(_) => Some((metric.collector, "")),
    }
}

/// A kind of value in words.
fn kind_in_words(kind: &str) -> String {
    match kind {
        "int" | "uint" | "double" => "a number".to_string(),
        "duration" | "google.protobuf.Duration" => "a length of time".to_string(),
        "timestamp" | "google.protobuf.Timestamp" => "a moment".to_string(),
        "string" => "text".to_string(),
        "bool" => "true or false".to_string(),
        "map" => "a map".to_string(),
        "list" => "a list".to_string(),
        "null_type" | "null" => "nothing".to_string(),
        other => format!("a {other}"),
    }
}

fn kind_of(value: &CelValue) -> &'static str {
    match value {
        CelValue::Int(_) => "int",
        CelValue::UInt(_) => "uint",
        CelValue::Float(_) => "double",
        CelValue::String(_) => "string",
        CelValue::Bool(_) => "bool",
        CelValue::Duration(_) => "duration",
        CelValue::Timestamp(_) => "timestamp",
        CelValue::Map(_) => "map",
        CelValue::List(_) => "list",
        CelValue::Null => "null",
        _ => "value",
    }
}

/// What an operator does, in words, for saying it can't.
fn doing(operator: &str) -> &str {
    match operator {
        operators::GREATER
        | operators::GREATER_EQUALS
        | operators::LESS
        | operators::LESS_EQUALS
        | operators::EQUALS
        | operators::NOT_EQUALS => "compare",
        operators::ADD | "add" => "add",
        operators::SUBSTRACT | "sub" => "subtract",
        operators::MULTIPLY | "mul" => "multiply",
        operators::DIVIDE | "div" => "divide",
        operators::MODULO | "rem" => "take the remainder of",
        operators::LOGICAL_AND | operators::LOGICAL_OR => "combine",
        _ => "use",
    }
}

/// A mistake found by working a condition out, in plain words.
fn explain(error: &ExecutionError) -> Option<String> {
    let pair = |operator: &str, kinds: &[String]| match kinds {
        [one, two] => format!(
            "can't {} {} with {}",
            doing(operator),
            kind_in_words(one),
            kind_in_words(two)
        ),
        kinds => format!(
            "can't {} {}",
            doing(operator),
            kinds
                .iter()
                .map(|kind| kind_in_words(kind))
                .collect::<Vec<_>>()
                .join(" and ")
        ),
    };
    Some(match error {
        ExecutionError::NoSuchOverload(overload) if is_operator(overload.function()) => {
            pair(overload.function(), overload.argument_types())
        }
        ExecutionError::NoSuchOverload(overload) => format!(
            "{}() doesn't take {}",
            overload.function(),
            overload
                .argument_types()
                .iter()
                .map(|kind| kind_in_words(kind))
                .collect::<Vec<_>>()
                .join(" and ")
        ),
        ExecutionError::ValuesNotComparable(one, two) => pair(
            operators::GREATER,
            &[kind_of(one).to_string(), kind_of(two).to_string()],
        ),
        ExecutionError::UnsupportedBinaryOperator(operator, one, two) => pair(
            operator,
            &[kind_of(one).to_string(), kind_of(two).to_string()],
        ),
        ExecutionError::UnexpectedType { got, want } => {
            format!(
                "expected {} but got {}",
                kind_in_words(want),
                kind_in_words(got)
            )
        }
        ExecutionError::FunctionError { function, message } => format!("{function}(): {message}"),
        ExecutionError::InvalidArgumentCount { expected, actual } => {
            format!("a function was given {actual} arguments rather than {expected}")
        }
        // A fact or series that isn't there is fine: hosts differ.
        ExecutionError::NoSuchKey(_) => return None,
        other => other.to_string(),
    })
}

impl Condition {
    /// Works the condition out on sample values, and each comparison and sum in it on
    /// its own, as `||` and `&&` skip what can't change their answer.
    fn dry_run(&self, bindings: &Bindings) -> Result<()> {
        let mut problem = None;
        each_operation(&self.expr, &mut |expr| {
            if problem.is_none()
                && let Err(error) = bindings.0.resolve(expr)
            {
                problem = explain(&error);
            }
        });
        if problem.is_none() {
            problem = match bindings.0.resolve(&self.expr) {
                Ok(CelValue::Bool(_)) => None,
                Ok(other) => Some(format!(
                    "a condition has to be true or false, and this is {}",
                    kind_in_words(kind_of(&other))
                )),
                Err(error) => explain(&error),
            };
        }
        match problem {
            None => Ok(()),
            Some(problem) => bail!("{}", self.with_hint(problem)),
        }
    }

    /// Adds how to write a length of time where that's what went wrong.
    fn with_hint(&self, problem: String) -> String {
        let timed = self
            .uses
            .iter()
            .find(|used| used.metric.unit == Unit::Seconds);
        match timed {
            Some(used) if problem.contains("length of time") => format!(
                "{problem}: {} is a length of time, so compare it with one, like duration('30s')",
                used.metric.name
            ),
            _ => problem,
        }
    }
}

/// Calls `found` on each operator in an expression that works on values, outside
/// macros, which bring in names of their own.
fn each_operation(expr: &IdedExpr, found: &mut dyn FnMut(&IdedExpr)) {
    match &expr.expr {
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                each_operation(target, found);
            }
            for arg in &call.args {
                each_operation(arg, found);
            }
            let combines = matches!(
                call.func_name.as_str(),
                operators::LOGICAL_AND
                    | operators::LOGICAL_OR
                    | operators::CONDITIONAL
                    | operators::LOGICAL_NOT
            );
            if is_operator(&call.func_name) && !combines {
                found(expr);
            }
        }
        Expr::Select(select) => each_operation(&select.operand, found),
        Expr::List(list) => list
            .elements
            .iter()
            .for_each(|item| each_operation(item, found)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::Severity;
    use serde_json::json;

    fn hosts(text: &str) -> Result<Condition> {
        Condition::compile(text, Scope::Hosts)
    }

    fn error(text: &str) -> String {
        let read = Conditions::compile(None, Some(text), Scope::Hosts).and_then(|conditions| {
            conditions.dry_run(&json!({ "cpu": { "logical_cores": 8 } }), Unit::Number)
        });
        format!("{:#}", read.unwrap_err())
    }

    fn inputs<'a>(metrics: &[(&'static str, Values<f64>)]) -> Inputs<'a> {
        Inputs {
            facts: cel::to_value(
                json!({ "os": { "family": "linux" }, "cpu": { "logical_cores": 4 } }),
            )
            .unwrap(),
            hostname: "web-1",
            series: "/",
            online: true,
            reporting: true,
            value: None,
            metrics: metrics.iter().cloned().collect(),
            headings: BTreeMap::new(),
        }
    }

    #[test]
    fn every_metric_can_be_written_by_its_name() {
        for metric in METRICS {
            let condition = hosts(&format!("{} == 1", metric.name))
                .unwrap_or_else(|error| panic!("{}: {error:#}", metric.name));
            assert_eq!(condition.uses()[0].metric.name, metric.name);
            assert!(
                Variable::ALL
                    .iter()
                    .all(|variable| variable.name() != metric.name),
                "{} is also a variable",
                metric.name
            );
        }
    }

    #[test]
    fn metrics_are_compared_by_their_names() {
        let condition = hosts("disk.usage > 90").unwrap();
        let full = inputs(&[("disk.usage", Values::One(95.0))]).bind();
        let fine = inputs(&[("disk.usage", Values::One(50.0))]).bind();
        assert!(condition.holds(&full));
        assert!(!condition.holds(&fine));
        // Missing isn't true.
        assert!(!condition.holds(&inputs(&[]).bind()));
    }

    #[test]
    fn seconds_are_lengths_of_time_and_bytes_have_units() {
        let lag = hosts("clock.difference > duration('30s')").unwrap();
        assert!(lag.holds(&inputs(&[("clock.difference", Values::One(31.0))]).bind()));
        assert!(!lag.holds(&inputs(&[("clock.difference", Values::One(29.0))]).bind()));

        let memory = hosts("process.memory > gib(2) && process.memory < tib(1)").unwrap();
        let three = 3.0 * 1024.0 * 1024.0 * 1024.0;
        assert!(memory.holds(&inputs(&[("process.memory", Values::One(three))]).bind()));
        assert!(!memory.holds(&inputs(&[("process.memory", Values::One(1024.0))]).bind()));
        let small = hosts("process.memory > kib(1) + mib(1)").unwrap();
        assert!(small.holds(&inputs(&[("process.memory", Values::One(three))]).bind()));
    }

    #[test]
    fn brackets_pick_a_series() {
        let load = hosts("cpu.load['5 minutes'] > facts.cpu.logical_cores").unwrap();
        let each = |five: f64| {
            Values::Each(BTreeMap::from([
                ("1 minute".to_string(), 1.0),
                ("5 minutes".to_string(), five),
            ]))
        };
        assert!(load.holds(&inputs(&[("cpu.load", each(6.0))]).bind()));
        assert!(!load.holds(&inputs(&[("cpu.load", each(2.0))]).bind()));
        assert_eq!(load.uses()[0].picked.as_deref(), Some("5 minutes"));
        assert!(load.uses()[0].bracketed);
    }

    #[test]
    fn host_series_online_and_reporting_can_be_used() {
        let condition = hosts("series != '/boot' && hostname == 'web-1' && online && reporting && facts.os.family == 'linux'").unwrap();
        assert!(condition.holds(&inputs(&[]).bind()));
        let offline = hosts("!online").unwrap();
        let mut gone = inputs(&[]);
        gone.online = false;
        assert!(offline.holds(&gone.bind()));
        assert!(!offline.holds(&inputs(&[]).bind()));
    }

    #[test]
    fn a_forecast_carries_the_line_on() {
        let filling = hosts("forecast(disk.usage, duration('4h')) >= 100").unwrap();
        let heading = |slope_per_hour: f64| Inputs {
            headings: BTreeMap::from([(
                "disk.usage",
                Values::One(Heading {
                    value: 90.0,
                    slope_per_sec: slope_per_hour / 3600.0,
                }),
            )]),
            ..inputs(&[])
        };
        assert!(filling.holds(&heading(3.0).bind()));
        assert!(!filling.holds(&heading(2.0).bind()));
        assert!(filling.uses()[0].forecast);

        let lag = hosts("forecast(clock.difference, duration('1h')) > duration('1m')").unwrap();
        let drifting = Inputs {
            headings: BTreeMap::from([(
                "clock.difference",
                Values::One(Heading {
                    value: 30.0,
                    slope_per_sec: 1.0 / 60.0,
                }),
            )]),
            ..inputs(&[])
        };
        assert!(lag.holds(&drifting.bind()));
    }

    #[test]
    fn a_calculation_is_about_its_value() {
        let busy = Condition::compile("value > 80", Scope::Calculation).unwrap();
        let mut line = inputs(&[]);
        line.value = Some(CelValue::Float(85.0));
        assert!(busy.holds(&line.bind()));
        assert_eq!(
            busy.threshold().map(|threshold| threshold.level),
            Some(80.0)
        );

        for (text, expected) in [
            ("cpu.usage > 80", "watches the calculated value"),
            ("facts.os.family == 'linux'", "watches the calculated value"),
            ("forecast(value, duration('1h')) > 1", "not a calculation"),
        ] {
            let error = format!(
                "{:#}",
                Condition::compile(text, Scope::Calculation).unwrap_err()
            );
            assert!(error.contains(expected), "{text}: {error}");
        }
        let error = format!("{:#}", hosts("value > 1").unwrap_err());
        assert!(error.contains("disk.usage > 90"), "{error}");
    }

    #[test]
    fn mistakes_are_said_in_plain_words() {
        for (text, expected) in [
            ("disk.usage >", "Syntax error"),
            (
                "cpu.lod > 1",
                "there's no metric called cpu.lod: did you mean cpu.load?",
            ),
            ("nothing_like_it > 1", "isn't a metric or anything else"),
            (
                "cpu.usage.total > 1",
                "cpu.usage has no part called \"total\"",
            ),
            (
                "cpu.load > 4",
                "pick one with brackets, like cpu.load['1 minute']: it has '1 minute', '5 minutes', '15 minutes'",
            ),
            (
                "cpu.load['1 min'] > 4",
                "cpu.load has no series called \"1 min\"",
            ),
            (
                "disk.usage > 90 && check.up == 0",
                "disk.usage and check.up have series of different things",
            ),
            (
                "disk.usage > 90 && disk.usage['/'] > 1",
                "both with and without brackets",
            ),
            (
                "clock.difference > 30",
                "can't compare a length of time with a number: clock.difference is a length of time, so compare it with one, like duration('30s')",
            ),
            (
                "cpu.usage > 90 || clock.difference > 30",
                "can't compare a length of time with a number",
            ),
            (
                "cpu.usage + 1.0",
                "has to be true or false, and this is a number",
            ),
            (
                "clock.difference + 1 > duration('1s')",
                "can't add a length of time with a number",
            ),
            ("cpu.usage > 'high'", "can't compare a number with text"),
            (
                "frobnicate(cpu.usage)",
                "there's no function called frobnicate",
            ),
            (
                "forecast(cpu.usage * 2, duration('1h')) > 1",
                "forecast() takes a metric",
            ),
            (
                "forecast(disk.usage, 4) > 1",
                "how far ahead has to be a duration",
            ),
            (
                "facts.cpu.logical_cores > duration('1s')",
                "can't compare a number with a length of time",
            ),
        ] {
            let error = error(text);
            assert!(error.contains(expected), "{text}: {error}");
        }
        // What some host has as a fact is fine for others not to.
        Conditions::compile(
            None,
            Some("facts.virtualization.role == 'guest'"),
            Scope::Hosts,
        )
        .unwrap()
        .dry_run(&json!({}), Unit::Number)
        .unwrap();
        // Nor is a host with no facts at all, as on a server with no hosts yet.
        Conditions::compile(
            None,
            Some("cpu.load['5 minutes'] > facts.cpu.logical_cores"),
            Scope::Hosts,
        )
        .unwrap()
        .dry_run(&serde_json::Value::Null, Unit::Number)
        .unwrap();
        // A calculation's value is in its metric's unit.
        let lag =
            Conditions::compile(None, Some("value > duration('2s')"), Scope::Calculation).unwrap();
        lag.dry_run(&json!({}), Unit::Seconds).unwrap();
        assert!(lag.dry_run(&json!({}), Unit::Number).is_err());
    }

    #[test]
    fn metrics_with_series_of_the_same_things_pair_up() {
        let conditions = Conditions::compile(
            Some("disk.usage > 80"),
            Some("disk.usage > 90 && disk.inodes > 80"),
            Scope::Hosts,
        )
        .unwrap();
        let fanned: Vec<&str> = conditions
            .fanned_out()
            .iter()
            .map(|used| used.metric.name)
            .collect();
        assert_eq!(fanned, ["disk.usage", "disk.inodes"]);
        assert_eq!(conditions.primary().unwrap().metric.name, "disk.usage");
        assert_eq!(
            conditions
                .levels()
                .iter()
                .map(|(severity, _)| *severity)
                .collect::<Vec<_>>(),
            [Severity::Warning, Severity::Critical]
        );
        // One picked out with brackets doesn't need to pair.
        Conditions::compile(
            None,
            Some("disk.usage > 90 && check.up['www'] == 0"),
            Scope::Hosts,
        )
        .unwrap();
    }

    #[test]
    fn whole_numbers_mix_with_metrics_and_facts() {
        let at = |usage: f64| inputs(&[("cpu.usage", Values::One(usage))]).bind();
        for text in [
            "cpu.usage / 2 > 40",
            "cpu.usage * 100 > 8000",
            "cpu.usage + 1 >= 82",
            "cpu.usage - 1 >= 80",
            "cpu.usage > 80",
            "cpu.usage == 81",
            "cpu.usage / facts.cpu.logical_cores > 20",
            "cpu.usage > facts.cpu.logical_cores * 20",
            "1 + 1 == 2",
            "[1, 2][1] == 2",
            "process.memory > gib(1) || cpu.usage > 80",
        ] {
            let condition = hosts(text).unwrap_or_else(|error| panic!("{text}: {error:#}"));
            assert!(condition.holds(&at(81.0)), "{text}");
            Conditions::compile(None, Some(text), Scope::Hosts)
                .unwrap()
                .dry_run(&json!({ "cpu": { "logical_cores": 4 } }), Unit::Number)
                .unwrap_or_else(|error| panic!("{text}: {error:#}"));
        }
        assert!(!hosts("cpu.usage / 2 > 40").unwrap().holds(&at(79.0)));
        // Lengths of time and text still add up as they do.
        assert!(
            hosts("duration('1h') + duration('1m') == duration('61m')")
                .unwrap()
                .holds(&at(1.0))
        );
        assert!(hosts("hostname + '!' == 'web-1!'").unwrap().holds(&at(1.0)));
    }

    #[test]
    fn only_a_plain_comparison_has_a_level_to_draw() {
        for (text, level) in [
            ("disk.usage > 90", Some(90.0)),
            ("90 <= disk.usage", Some(90.0)),
            ("clock.difference > duration('30s')", Some(30.0)),
            ("cpu.load['5 minutes'] > 4", Some(4.0)),
            ("network.received < -1", Some(-1.0)),
            ("disk.usage > 90 && series != '/boot'", None),
            ("disk.usage > facts.limit", None),
            ("forecast(disk.usage, duration('4h')) >= 100", None),
            ("!online", None),
        ] {
            let threshold = hosts(text).unwrap().threshold();
            assert_eq!(threshold.map(|threshold| threshold.level), level, "{text}");
        }
    }
}
