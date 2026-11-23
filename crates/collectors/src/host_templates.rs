//! Reads what templates that run once on a Windows host have it read, as the server
//! worked it out for this host: the registry values and counter sets their discover
//! blocks look for, and their counters blocks' performance counters.
//!
//! Each discover block runs at once, then every `interval`. What every block of a
//! template found goes back together, as the server works out what to read next
//! from it. A registry value that isn't there, or can't be read, isn't found, and a
//! counter set is found to be there or not.
//!
//! Each counters block reads its counters every sample, or every `interval`. Its
//! instances are labelled by name, by a pattern's named groups, by a counter of the
//! same instance (`groups`), or by matching another counter set's instances (`join`).
//! `_Total` is left out of those, and so are instances `exclude` names. Instances that
//! end up with the same labels add up, or take the highest for a percentage, and a
//! running total is sent as its change since the last read. Each row says which
//! counters block it's from.
//!
//! Other systems have none of this, so an agent on one reads nothing for them.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use maxnines_protocol::templates::work::{
    CounterWork, CountersWork, Discovered, Instances, MAX_INSTANCES, QUERY_FIELD, TemplateWork,
};
use regex_lite::Regex;
use serde_json::{Map, Value, json};

/// The instance a counter set with none, or the one instance read, is read as.
pub const ONLY: &str = "";
/// Windows' name for the instance that adds up all the others.
pub const TOTAL: &str = "_Total";

/// What one counters block's counters read at one collection.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Readings {
    /// Each counter's value for each instance, by the counter's name, instances
    /// named as Windows numbers programs that share a name. A counter set with no
    /// instances, or one instance read, has one named [`ONLY`].
    pub counters: BTreeMap<String, Vec<(String, f64)>>,
    /// The instances of the counter set it's joined to, by name.
    pub joined: Vec<String>,
}

/// Each running total's last reading, by series and metric, which turns the next
/// into the change since.
#[derive(Debug, Default)]
pub struct Totals(HashMap<String, f64>);

/// One counters block's rows: each series' metrics, labelled, with which block
/// they're from. Instances it doesn't read or can't label give nothing.
pub fn rows(work: &CountersWork, readings: &Readings, totals: &mut Totals) -> Vec<Value> {
    let pattern = match &work.instances {
        Instances::Pattern(pattern) => match Regex::new(pattern) {
            Ok(regex) => Some(regex),
            // The server checks patterns, so there's nothing to read with one that's bad.
            Err(_) => return Vec::new(),
        },
        _ => None,
    };
    let join = match &work.join {
        Some(join) => match Regex::new(&join.pattern) {
            Ok(regex) => Some(joined_labels(&regex, &readings.joined)),
            Err(_) => return Vec::new(),
        },
        None => None,
    };
    let every_instance = matches!(
        work.instances,
        Instances::Labelled(_) | Instances::Pattern(_)
    );

    // Every instance any metric's counter has, in order.
    let mut names: Vec<&String> = Vec::new();
    for metric in &work.metrics {
        for (name, _) in readings.counters.get(&metric.counter).into_iter().flatten() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    let mut series: BTreeMap<BTreeMap<String, String>, BTreeMap<String, f64>> = BTreeMap::new();
    for name in names {
        if every_instance && name == TOTAL || work.exclude.contains(name) {
            continue;
        }
        let mut labels: BTreeMap<String, String> = BTreeMap::new();
        match &work.instances {
            Instances::Labelled(label) => {
                labels.insert(label.clone(), name.clone());
            }
            Instances::Pattern(_) => {
                let Some(found) = pattern.as_ref().and_then(|regex| groups(regex, name)) else {
                    continue;
                };
                labels.extend(found);
            }
            Instances::None | Instances::One(_) => {}
        }
        let mut grouped = true;
        for (group, counter) in &work.groups {
            match value_of(readings, counter, name) {
                Some(value) => {
                    labels.insert(group.clone(), group_value(value));
                }
                None => grouped = false,
            }
        }
        if !grouped {
            continue;
        }
        if let Some(theirs) = &join {
            let Some(labels_now) = joined(labels, theirs) else {
                continue;
            };
            labels = labels_now;
        }
        if series.len() >= MAX_INSTANCES && !series.contains_key(&labels) {
            continue;
        }
        let metrics = series.entry(labels).or_default();
        for metric in &work.metrics {
            let Some(value) = value_of(readings, &metric.counter, name) else {
                continue;
            };
            metrics
                .entry(metric.key.clone())
                .and_modify(|seen| *seen = combined(metric, *seen, value))
                .or_insert(value);
        }
    }

    let mut seen = HashMap::new();
    let mut read = Vec::with_capacity(series.len());
    for (labels, metrics) in series {
        let key = serde_json::to_string(&labels).unwrap_or_default();
        let mut row = Map::new();
        for metric in &work.metrics {
            let Some(value) = metrics.get(&metric.key).copied() else {
                continue;
            };
            if metric.total {
                let total = format!("{key}\n{}", metric.key);
                let last = totals.0.get(&total).copied();
                seen.insert(total, value);
                match last {
                    // A total that went down started again from nothing.
                    Some(last) => row.insert(
                        metric.key.clone(),
                        json!(if value >= last { value - last } else { value }),
                    ),
                    None => continue,
                };
            } else {
                row.insert(metric.key.clone(), json!(value));
            }
        }
        if !row.is_empty() {
            row.insert("labels".to_string(), json!(labels));
            row.insert(QUERY_FIELD.to_string(), json!(work.key));
            read.push(Value::Object(row));
        }
    }
    // A series that's gone starts again from nothing if it comes back.
    totals.0 = seen;
    read
}

fn value_of(readings: &Readings, counter: &str, instance: &str) -> Option<f64> {
    readings
        .counters
        .get(counter)?
        .iter()
        .find(|(name, _)| name == instance)
        .map(|(_, value)| *value)
        .filter(|value| value.is_finite())
}

/// A counter read as a label, such as a process ID: whole numbers without a
/// fraction, so `4120` and not `4120.0`.
fn group_value(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        value.to_string()
    }
}

/// Two instances' values that end up in one series.
fn combined(metric: &CounterWork, seen: f64, value: f64) -> f64 {
    match metric.highest {
        true => seen.max(value),
        false => seen + value,
    }
}

/// A pattern's named groups in an instance's name, or nothing if it doesn't match.
fn groups(regex: &Regex, name: &str) -> Option<BTreeMap<String, String>> {
    let captures = regex.captures(name)?;
    Some(
        regex
            .capture_names()
            .flatten()
            .filter_map(|group| {
                let found = captures.name(group)?;
                Some((group.to_string(), found.as_str().to_string()))
            })
            .collect(),
    )
}

/// The labels of each of the joined counter set's instances its pattern matches.
fn joined_labels(regex: &Regex, instances: &[String]) -> Vec<BTreeMap<String, String>> {
    instances
        .iter()
        .filter(|name| *name != TOTAL)
        .filter_map(|name| groups(regex, name))
        .collect()
}

/// An instance's labels once matched to one of the joined counter set's: the
/// groups both have are only for matching, so they go, and the other's other
/// groups label it. Nothing if none matches.
fn joined(
    own: BTreeMap<String, String>,
    theirs: &[BTreeMap<String, String>],
) -> Option<BTreeMap<String, String>> {
    let matched = theirs.iter().find(|other| {
        let mut shared = other.keys().filter(|key| own.contains_key(*key)).peekable();
        shared.peek().is_some() && shared.all(|key| own.get(key) == other.get(key))
    })?;
    let mut labels: BTreeMap<String, String> = matched
        .iter()
        .filter(|(key, _)| !own.contains_key(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    labels.extend(
        own.into_iter()
            .filter(|(key, _)| !matched.contains_key(key)),
    );
    Some(labels)
}

/// What templates that run on the host have this agent read, and what it's read.
#[derive(Default)]
pub struct HostTemplates {
    templates: BTreeMap<String, HostTemplate>,
}

struct HostTemplate {
    work: TemplateWork,
    /// When each discover block runs next.
    discover_at: Vec<Instant>,
    found: Map<String, Value>,
    counters: Vec<CountersAt>,
}

struct CountersAt {
    work: CountersWork,
    reader: platform::CounterReader,
    at: Instant,
    totals: Totals,
}

/// What templates on the host read at one collection.
#[derive(Debug, Default)]
pub struct HostRead {
    /// Each template's rows, by its key.
    pub rows: BTreeMap<String, Vec<Value>>,
    pub discovered: Vec<Discovered>,
}

impl HostTemplates {
    /// Changes what's read to the templates in `work` that run on the host. One whose
    /// work is the same carries on; one whose counters block is the same keeps its
    /// counters and running totals, and what its discovery found.
    pub fn update(&mut self, work: &[TemplateWork]) {
        let wanted: Vec<&TemplateWork> = work.iter().filter(|one| one.database.is_none()).collect();
        if !wanted.is_empty() && !platform::READS {
            tracing::warn!(
                "templates for the registry and performance counters are only read on Windows"
            );
            self.templates.clear();
            return;
        }
        self.templates
            .retain(|key, _| wanted.iter().any(|one| &one.template == key));
        let now = Instant::now();
        for one in wanted {
            match self.templates.get_mut(&one.template) {
                Some(running) if running.work == *one => {}
                Some(running) => {
                    let mut before = std::mem::take(&mut running.counters);
                    running.counters = one
                        .counters
                        .iter()
                        .map(|counters| {
                            match before.iter().position(|kept| kept.work == *counters) {
                                Some(at) => before.swap_remove(at),
                                None => CountersAt::new(counters, now),
                            }
                        })
                        .collect();
                    // A discover block that's new, or changed, runs at once.
                    running.discover_at = one
                        .discover
                        .iter()
                        .map(|discover| {
                            let same = running.work.discover.iter().position(|was| was == discover);
                            same.and_then(|at| running.discover_at.get(at).copied())
                                .unwrap_or(now)
                        })
                        .collect();
                    running.work = one.clone();
                }
                None => {
                    self.templates.insert(
                        one.template.clone(),
                        HostTemplate {
                            work: one.clone(),
                            discover_at: vec![now; one.discover.len()],
                            found: Map::new(),
                            counters: one
                                .counters
                                .iter()
                                .map(|counters| CountersAt::new(counters, now))
                                .collect(),
                        },
                    );
                }
            }
        }
    }

    /// Reads what's due: each discover block on its interval, and each counters
    /// block every sample, `every`, unless it says.
    pub fn collect(&mut self, every: Duration) -> HostRead {
        let now = Instant::now();
        let mut read = HostRead::default();
        for (key, running) in &mut self.templates {
            let mut discovered = false;
            let mut refreshed = false;
            for (at, discover) in running.discover_at.iter_mut().zip(&running.work.discover) {
                if *at > now {
                    continue;
                }
                *at = now + discover.interval;
                if !discover.counter_sets.is_empty() && !refreshed {
                    platform::refresh_counter_sets();
                    refreshed = true;
                }
                for registry in &discover.registry {
                    for (name, value) in &registry.values {
                        match platform::registry_value(&registry.key, value) {
                            Some(found) => running.found.insert(name.clone(), found),
                            None => running.found.remove(name),
                        };
                    }
                }
                for (name, object) in &discover.counter_sets {
                    match platform::counter_set_exists(object) {
                        Some(there) => running.found.insert(name.clone(), json!(there)),
                        None => running.found.remove(name),
                    };
                }
                discovered = true;
            }
            if discovered {
                read.discovered.push(Discovered {
                    template: key.clone(),
                    database: None,
                    values: running.found.clone(),
                });
            }
            let mut read_now = Vec::new();
            for counters in &mut running.counters {
                if counters.at > now {
                    continue;
                }
                counters.at = now + counters.work.interval.unwrap_or(every);
                if let Some(readings) = counters.reader.read() {
                    read_now.extend(rows(&counters.work, &readings, &mut counters.totals));
                }
            }
            if !read_now.is_empty() {
                read.rows.insert(key.clone(), read_now);
            }
        }
        read
    }
}

impl CountersAt {
    fn new(work: &CountersWork, now: Instant) -> Self {
        Self {
            reader: platform::CounterReader::new(work),
            work: work.clone(),
            at: now,
            totals: Totals::default(),
        }
    }
}

/// The English path of a counters block's counter, for every instance it reads.
pub fn path(work: &CountersWork, counter: &str) -> String {
    let object = &work.object;
    match &work.instances {
        Instances::None => format!(r"\{object}\{counter}"),
        Instances::One(instance) => format!(r"\{object}({instance})\{counter}"),
        Instances::Labelled(_) | Instances::Pattern(_) => format!(r"\{object}(*)\{counter}"),
    }
}

/// The counters a block reads, each once: its metrics' and its groups'.
pub fn counters_read(work: &CountersWork) -> Vec<String> {
    let mut counters: Vec<String> = Vec::new();
    let all = work
        .metrics
        .iter()
        .map(|metric| &metric.counter)
        .chain(work.groups.values());
    for counter in all {
        if !counters.contains(counter) {
            counters.push(counter.clone());
        }
    }
    counters
}

#[cfg(windows)]
mod platform {
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};
    use windows_sys::Win32::System::Performance::{
        PDH_CSTATUS_NO_OBJECT, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA, PDH_RAW_COUNTER_ITEM_W,
        PERF_DETAIL_WIZARD, PdhAddCounterW, PdhCloseQuery, PdhCollectQueryData,
        PdhEnumObjectItemsW, PdhEnumObjectsW, PdhGetRawCounterArrayW, PdhOpenQueryW,
    };

    use super::{CountersWork, ONLY, Readings, counters_read, path};
    use crate::counters::numbered;
    use crate::counters::pdh::{Formatted, added, formatted};
    use crate::windows_text::{from_wide, wide};

    pub const READS: bool = true;

    /// How often counters a host doesn't have are looked for again, as some only
    /// appear once their software runs.
    const RETRY_EVERY: Duration = Duration::from_secs(60);

    /// One query holding a counters block's counters, and the counter whose
    /// instances name the counter set it's joined to.
    pub struct CounterReader {
        query: Option<PDH_HQUERY>,
        counters: Vec<(String, String, Option<PDH_HCOUNTER>)>,
        join: Option<(String, Option<PDH_HCOUNTER>)>,
        looked: Instant,
    }

    // SAFETY: a query's handles work from any thread. This only ever uses them from
    // one at a time, as `read` and `drop` take it mutably.
    unsafe impl Send for CounterReader {}

    impl CounterReader {
        pub fn new(work: &CountersWork) -> Self {
            let mut query: PDH_HQUERY = null_mut();
            // SAFETY: no data source means this host, live, and the handle has
            // somewhere to go.
            let opened = unsafe { PdhOpenQueryW(null(), 0, &mut query) } == 0;
            let query = opened.then_some(query);
            let counters = counters_read(work)
                .into_iter()
                .map(|counter| {
                    let path = path(work, &counter);
                    let handle = query.and_then(|query| added(query, &path).ok());
                    (counter, path, handle)
                })
                .collect();
            let join = work.join.as_ref().map(|join| {
                let handle = query.and_then(|query| instances_of(query, &join.object));
                (join.object.clone(), handle)
            });
            let mut reader = Self {
                query,
                counters,
                join,
                looked: Instant::now(),
            };
            // A rate is worked out between two collections, so the first is now.
            reader.collect();
            reader
        }

        fn collect(&mut self) {
            if let Some(query) = self.query {
                // SAFETY: the query is open. A failure shows in each counter's values.
                unsafe { PdhCollectQueryData(query) };
            }
        }

        /// What its counters read now, or nothing if its query couldn't be opened.
        pub fn read(&mut self) -> Option<Readings> {
            let query = self.query?;
            // Software installed since may have brought its counters with it.
            if self.looked.elapsed() >= RETRY_EVERY {
                self.looked = Instant::now();
                for (_, path, handle) in &mut self.counters {
                    if handle.is_none() {
                        *handle = added(query, path).ok();
                    }
                }
                if let Some((object, handle @ None)) = &mut self.join {
                    *handle = instances_of(query, object);
                }
            }
            self.collect();
            let mut readings = Readings::default();
            for (counter, path, handle) in &self.counters {
                let Some(handle) = handle else {
                    continue;
                };
                let Formatted::Values(values) = formatted(*handle) else {
                    continue;
                };
                let values = match path.contains("(*)") {
                    true => {
                        let (names, values): (Vec<String>, Vec<f64>) = values.into_iter().unzip();
                        numbered(names).into_iter().zip(values).collect()
                    }
                    false => values
                        .into_iter()
                        .take(1)
                        .map(|(_, value)| (ONLY.to_string(), value))
                        .collect(),
                };
                readings.counters.insert(counter.clone(), values);
            }
            if let Some((_, Some(handle))) = &self.join {
                readings.joined = numbered(raw_names(*handle));
            }
            Some(readings)
        }
    }

    impl Drop for CounterReader {
        fn drop(&mut self) {
            if let Some(query) = self.query.take() {
                // SAFETY: the query is open, and closing it closes its counters too.
                unsafe { PdhCloseQuery(query) };
            }
        }
    }

    /// The names Windows has for a counter set's counters and instances, or
    /// nothing if it has no such counter set.
    fn object_items(object: &str) -> Result<(Vec<String>, Vec<String>), u32> {
        let object = wide(object);
        let (mut counters_len, mut instances_len) = (0u32, 0u32);
        // SAFETY: asking how much room the names need, with nowhere to put them yet.
        let status = unsafe {
            PdhEnumObjectItemsW(
                null(),
                null(),
                object.as_ptr(),
                null_mut(),
                &mut counters_len,
                null_mut(),
                &mut instances_len,
                PERF_DETAIL_WIZARD,
                0,
            )
        };
        if status != PDH_MORE_DATA && status != 0 {
            return Err(status);
        }
        let mut counters = vec![0u16; counters_len as usize];
        let mut instances = vec![0u16; instances_len as usize];
        // SAFETY: each buffer is as long as Windows asked for.
        let status = unsafe {
            PdhEnumObjectItemsW(
                null(),
                null(),
                object.as_ptr(),
                if counters.is_empty() {
                    null_mut()
                } else {
                    counters.as_mut_ptr()
                },
                &mut counters_len,
                if instances.is_empty() {
                    null_mut()
                } else {
                    instances.as_mut_ptr()
                },
                &mut instances_len,
                PERF_DETAIL_WIZARD,
                0,
            )
        };
        if status != 0 {
            return Err(status);
        }
        Ok((names(&counters), names(&instances)))
    }

    /// The names in a list Windows gives as names each ending with a zero, ending
    /// with another.
    fn names(list: &[u16]) -> Vec<String> {
        list.split(|unit| *unit == 0)
            .filter(|name| !name.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    /// A counter of a counter set whose instances are that set's instances, to read
    /// their names from at each collection. Windows names counters in its own
    /// language here, so the counter set has to be found by the name it has there.
    fn instances_of(query: PDH_HQUERY, object: &str) -> Option<PDH_HCOUNTER> {
        let (counters, _) = object_items(object).ok()?;
        let first = counters.first()?;
        let path = wide(&format!(r"\{object}(*)\{first}"));
        let mut counter: PDH_HCOUNTER = null_mut();
        // SAFETY: the query is open, the path ends with a zero, and the handle has
        // somewhere to go.
        let status = unsafe { PdhAddCounterW(query, path.as_ptr(), 0, &mut counter) };
        (status == 0).then_some(counter)
    }

    /// The names of a counter's instances at the last collection, as Windows gives
    /// them.
    fn raw_names(counter: PDH_HCOUNTER) -> Vec<String> {
        let (mut size, mut count) = (0u32, 0u32);
        // SAFETY: asking how much room the values need, with nowhere to put them yet.
        let status = unsafe { PdhGetRawCounterArrayW(counter, &mut size, &mut count, null_mut()) };
        if status != PDH_MORE_DATA {
            return Vec::new();
        }
        // In eights, as the items hold numbers and pointers that need that alignment.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let items = buffer.as_mut_ptr().cast::<PDH_RAW_COUNTER_ITEM_W>();
        // SAFETY: the buffer is at least as big as Windows asked for, and aligned.
        let status = unsafe { PdhGetRawCounterArrayW(counter, &mut size, &mut count, items) };
        if status != 0 {
            return Vec::new();
        }
        // SAFETY: Windows filled in `count` items at the start of the buffer.
        let items = unsafe { std::slice::from_raw_parts(items, count as usize) };
        items
            .iter()
            // SAFETY: each name ends with a zero.
            .map(|item| unsafe { from_wide(item.szName) })
            .collect()
    }

    /// Has Windows look again at which counter sets there are, as one whose software
    /// was installed since isn't otherwise found.
    pub fn refresh_counter_sets() {
        let mut size = 0u32;
        // SAFETY: asking for the size of the list, refreshing it on the way, with
        // nowhere to put it.
        unsafe { PdhEnumObjectsW(null(), null(), null_mut(), &mut size, PERF_DETAIL_WIZARD, 1) };
    }

    /// Whether the host has a counter set, or nothing if that can't be told.
    pub fn counter_set_exists(object: &str) -> Option<bool> {
        match object_items(object) {
            Ok(_) => Some(true),
            Err(PDH_CSTATUS_NO_OBJECT) => Some(false),
            Err(_) => None,
        }
    }

    /// A value under `HKEY_LOCAL_MACHINE`, as text or a number: several pieces of
    /// text are joined with commas, and anything else isn't read.
    pub fn registry_value(key: &str, name: &str) -> Option<Value> {
        use windows_registry::{LOCAL_MACHINE, Type};

        let path = maxnines_protocol::templates::local_machine_key(key)?;
        let key = LOCAL_MACHINE.open(path).ok()?;
        match key.get_type(name).ok()? {
            Type::String | Type::ExpandString => Some(json!(key.get_string(name).ok()?)),
            Type::U32 => Some(json!(key.get_u32(name).ok()?)),
            Type::U64 => Some(json!(key.get_u64(name).ok()?)),
            Type::MultiString => Some(json!(key.get_multi_string(name).ok()?.join(", "))),
            _ => None,
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use serde_json::Value;

    use super::{CountersWork, Readings};

    pub const READS: bool = false;

    /// Elsewhere there are no counters to read.
    pub struct CounterReader;

    impl CounterReader {
        pub fn new(_: &CountersWork) -> Self {
            Self
        }

        pub fn read(&mut self) -> Option<Readings> {
            None
        }
    }

    pub fn refresh_counter_sets() {}

    pub fn counter_set_exists(_: &str) -> Option<bool> {
        None
    }

    pub fn registry_value(_: &str, _: &str) -> Option<Value> {
        None
    }
}

#[cfg(test)]
mod tests;
