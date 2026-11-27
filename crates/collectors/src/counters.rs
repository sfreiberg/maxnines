//! Windows performance counters, chosen by their English paths, like
//! `\Processor(_Total)\% Processor Time`. They're read through Windows' own counter
//! API, which works out rates such as disk reads a second between one sample and the
//! next. English names are looked up whatever language Windows is in, so one config
//! works everywhere. `(*)` in a path reads every instance, each as a series of its own.
//!
//! A path that isn't on a host is reported as failing, with a fixed message, and
//! looked for again each minute, as some only appear once their software runs.
//!
//! A wildcard path reports `_Total` first, then its other instances in order of
//! their names, up to [`MAX_INSTANCES`], so each sample keeps the same ones, and
//! says how many more there were.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use serde_json::{Map, Value, json};

use crate::Collector;

/// The most instances one wildcard path reports, as `\Process(*)` has one for every
/// program running and each is a series on the server.
pub const MAX_INSTANCES: usize = 64;

pub const NOT_FOUND: &str = "not found on this host";
pub const NOT_READ: &str = "couldn't be read";
pub const NOT_WINDOWS: &str = "performance counters are only on Windows";

/// What one configured path gave.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    /// Each instance's path and value, and how many instances there were beyond
    /// the most reported. One with no wildcard has one.
    Values {
        values: Vec<(String, f64)>,
        dropped: usize,
    },
    /// A rate that has nothing to compare with yet.
    Waiting,
    Failed(&'static str),
}

/// The path for one instance of a wildcard path, like `\PhysicalDisk(0 C:)\Disk
/// Reads/sec` for the `0 C:` instance of `\PhysicalDisk(*)\Disk Reads/sec`.
pub fn instance_path(path: &str, instance: &str) -> String {
    path.replacen("(*)", &format!("({instance})"), 1)
}

/// Windows gives every instance of a program the same name, so the second `svchost`
/// becomes `svchost#1`, as Windows' own tools number them.
pub fn numbered(instances: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    instances
        .into_iter()
        .map(|name| {
            let count = seen.entry(name.clone()).or_default();
            let numbered = if *count == 0 {
                name
            } else {
                format!("{name}#{count}")
            };
            *count += 1;
            numbered
        })
        .collect()
}

/// Each instance with a value, numbered as Windows numbers programs that share a
/// name, counting the ones without a value, as Windows does, so `svchost#2` is the
/// same program in every counter read at once, whichever have a value for it.
pub fn numbered_with_values(
    instances: impl IntoIterator<Item = (String, Option<f64>)>,
) -> Vec<(String, f64)> {
    let (names, values): (Vec<String>, Vec<Option<f64>>) = instances.into_iter().unzip();
    numbered(names)
        .into_iter()
        .zip(values)
        .filter_map(|(name, value)| Some((name, value?)))
        .collect()
}

/// The instances of a wildcard path to report, already numbered: `_Total` first,
/// then the rest by name, up to the most kept, each with its path, and how many
/// weren't kept.
pub fn kept_instances(
    path: &str,
    mut instances: Vec<(String, f64)>,
) -> (Vec<(String, f64)>, usize) {
    instances.sort_by(|(a, _), (b, _)| (a != "_Total", a).cmp(&(b != "_Total", b)));
    let dropped = instances.len().saturating_sub(MAX_INSTANCES);
    instances.truncate(MAX_INSTANCES);
    let kept = instances
        .into_iter()
        .map(|(instance, value)| (instance_path(path, &instance), value))
        .collect();
    (kept, dropped)
}

/// The collector's output: an item for each configured path saying whether it works,
/// and one for each value, by path. A path with no wildcard has both in one item. A
/// wildcard path's item says how many instances there were beyond the most reported.
pub fn output(readings: &[(String, Reading)]) -> Value {
    fn item<'a>(
        items: &'a mut BTreeMap<String, Map<String, Value>>,
        name: &str,
    ) -> &'a mut Map<String, Value> {
        items.entry(name.to_string()).or_insert_with(|| {
            let mut item = Map::new();
            item.insert("name".into(), json!(name));
            item
        })
    }

    let mut items = BTreeMap::new();
    for (path, reading) in readings {
        match reading {
            Reading::Values { values, dropped } => {
                let item_of_path = item(&mut items, path);
                item_of_path.insert("ok".into(), json!(1));
                if path.contains("(*)") {
                    item_of_path.insert("dropped".into(), json!(dropped));
                }
                for (name, value) in values.iter().filter(|(_, value)| value.is_finite()) {
                    item(&mut items, name).insert("value".into(), json!(value));
                }
            }
            Reading::Waiting => {
                item(&mut items, path).insert("ok".into(), json!(1));
            }
            Reading::Failed(error) => {
                let item = item(&mut items, path);
                item.insert("ok".into(), json!(0));
                item.insert("error".into(), json!(error));
            }
        }
    }
    Value::Array(items.into_values().map(Value::Object).collect())
}

/// Reads the counters it's given, and only those.
pub struct CounterCollector {
    counters: pdh::Counters,
}

impl CounterCollector {
    pub fn new(paths: Vec<String>) -> Self {
        Self {
            counters: pdh::Counters::new(paths),
        }
    }
}

impl Collector for CounterCollector {
    fn name(&self) -> &'static str {
        "counters"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(output(&self.counters.read()))
    }
}

#[cfg(windows)]
pub(crate) mod pdh {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::System::Performance::{
        PDH_CSTATUS_BAD_COUNTERNAME, PDH_CSTATUS_INVALID_DATA, PDH_CSTATUS_NEW_DATA,
        PDH_CSTATUS_NO_COUNTER, PDH_CSTATUS_NO_OBJECT, PDH_CSTATUS_VALID_DATA,
        PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PDH_INVALID_DATA,
        PDH_MORE_DATA, PDH_NO_DATA, PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData,
        PdhGetFormattedCounterArrayW, PdhOpenQueryW,
    };

    use std::time::{Duration, Instant};

    use super::{NOT_FOUND, NOT_READ, Reading, kept_instances, numbered_with_values};
    use crate::windows_text::{from_wide, wide};

    /// How often a path a host doesn't have is looked for again. Looking up a name
    /// that isn't there is slow.
    const RETRY_EVERY: Duration = Duration::from_secs(60);

    /// Percentages of processor time can pass 100 on a host with several cores.
    const NO_CAP_AT_100: u32 = 0x8000;
    const FORMAT: u32 = PDH_FMT_DOUBLE | NO_CAP_AT_100;

    /// One query holding every counter, as a collection reads them all at once.
    pub struct Counters {
        query: Option<PDH_HQUERY>,
        counters: Vec<(String, Result<PDH_HCOUNTER, &'static str>)>,
        /// When paths that weren't found were last looked for.
        looked: Instant,
    }

    // SAFETY: a query's handles work from any thread. This only ever uses them from one
    // at a time, as `read` and `drop` take it mutably.
    unsafe impl Send for Counters {}

    /// Adds a counter by its English path to an open query.
    pub(crate) fn added(query: PDH_HQUERY, path: &str) -> Result<PDH_HCOUNTER, &'static str> {
        let mut counter: PDH_HCOUNTER = null_mut();
        let path = wide(path);
        // SAFETY: the query is open, the path ends with a zero, and the handle has
        // somewhere to go.
        let status = unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) };
        match status {
            0 => Ok(counter),
            PDH_CSTATUS_NO_OBJECT | PDH_CSTATUS_NO_COUNTER | PDH_CSTATUS_BAD_COUNTERNAME => {
                Err(NOT_FOUND)
            }
            _ => Err(NOT_READ),
        }
    }

    /// What a counter's values were at the last collection, each by its instance's
    /// name, or why there are none.
    pub(crate) enum Formatted {
        Values(Vec<(String, f64)>),
        /// A rate that has nothing to compare with yet.
        Waiting,
        Failed,
    }

    fn values(path: &str, counter: PDH_HCOUNTER) -> Reading {
        let usable = match formatted(counter) {
            Formatted::Values(usable) => usable,
            Formatted::Waiting => return Reading::Waiting,
            Formatted::Failed => return Reading::Failed(NOT_READ),
        };
        if !path.contains("(*)") {
            return Reading::Values {
                values: usable
                    .first()
                    .map(|(_, value)| (path.to_string(), *value))
                    .into_iter()
                    .collect(),
                dropped: 0,
            };
        }
        let (values, dropped) = kept_instances(path, usable);
        Reading::Values { values, dropped }
    }

    /// A counter's values, by instance, in the order Windows gives them, programs
    /// that share a name numbered as Windows numbers them.
    pub(crate) fn formatted(counter: PDH_HCOUNTER) -> Formatted {
        let (mut size, mut count) = (0u32, 0u32);
        // SAFETY: asking how much room the values need, with nowhere to put them yet.
        let status = unsafe {
            PdhGetFormattedCounterArrayW(counter, FORMAT, &mut size, &mut count, null_mut())
        };
        match status {
            PDH_MORE_DATA => {}
            0 => return Formatted::Values(Vec::new()),
            PDH_INVALID_DATA | PDH_CSTATUS_INVALID_DATA | PDH_NO_DATA => return Formatted::Waiting,
            _ => return Formatted::Failed,
        }
        // In eights, as the items hold numbers and pointers that need that alignment.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let items = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        // SAFETY: the buffer is at least as big as Windows asked for, and aligned.
        let status =
            unsafe { PdhGetFormattedCounterArrayW(counter, FORMAT, &mut size, &mut count, items) };
        match status {
            0 => {}
            PDH_INVALID_DATA | PDH_CSTATUS_INVALID_DATA | PDH_NO_DATA => return Formatted::Waiting,
            _ => return Formatted::Failed,
        }
        // SAFETY: Windows filled in `count` items at the start of the buffer.
        let items = unsafe { std::slice::from_raw_parts(items, count as usize) };
        let all = items.iter().map(|item| {
            let valid = matches!(
                item.FmtValue.CStatus,
                PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA
            );
            // SAFETY: with PDH_FMT_DOUBLE asked for, the value is a double.
            let value = valid.then_some(unsafe { item.FmtValue.Anonymous.doubleValue });
            // SAFETY: each name ends with a zero.
            (unsafe { from_wide(item.szName) }, value)
        });
        Formatted::Values(numbered_with_values(all))
    }

    impl Counters {
        pub fn new(paths: Vec<String>) -> Self {
            let mut query: PDH_HQUERY = null_mut();
            // SAFETY: no data source means this host, live, and the handle has
            // somewhere to go.
            let opened = unsafe { PdhOpenQueryW(null(), 0, &mut query) } == 0;
            let query = opened.then_some(query);
            let counters = paths
                .into_iter()
                .map(|path| {
                    let counter = query.map_or(Err(NOT_READ), |query| added(query, &path));
                    (path, counter)
                })
                .collect();
            let mut counters = Self {
                query,
                counters,
                looked: Instant::now(),
            };
            // A rate is worked out between two collections, so the first is now.
            counters.collect();
            counters
        }

        fn collect(&mut self) {
            if let Some(query) = self.query {
                // SAFETY: the query is open. A failure shows in each counter's values.
                unsafe { PdhCollectQueryData(query) };
            }
        }

        pub fn read(&mut self) -> Vec<(String, Reading)> {
            // Software installed since may have brought its counters with it.
            if let Some(query) = self.query
                && self.looked.elapsed() >= RETRY_EVERY
            {
                self.looked = Instant::now();
                for (path, counter) in &mut self.counters {
                    if counter.is_err() {
                        *counter = added(query, path);
                    }
                }
            }
            self.collect();
            self.counters
                .iter()
                .map(|(path, counter)| {
                    let reading = match counter {
                        Ok(counter) => values(path, *counter),
                        Err(error) => Reading::Failed(error),
                    };
                    (path.clone(), reading)
                })
                .collect()
        }
    }

    impl Drop for Counters {
        fn drop(&mut self) {
            if let Some(query) = self.query.take() {
                // SAFETY: the query is open, and closing it closes its counters too.
                unsafe { PdhCloseQuery(query) };
            }
        }
    }
}

#[cfg(not(windows))]
pub(crate) mod pdh {
    use super::{NOT_WINDOWS, Reading};

    /// Elsewhere, every path fails the same way, so a rule that turns counters on
    /// everywhere says why nothing comes of it.
    pub struct Counters {
        paths: Vec<String>,
    }

    impl Counters {
        pub fn new(paths: Vec<String>) -> Self {
            Self { paths }
        }

        pub fn read(&mut self) -> Vec<(String, Reading)> {
            self.paths
                .iter()
                .map(|path| (path.clone(), Reading::Failed(NOT_WINDOWS)))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_instance_gets_its_own_path() {
        assert_eq!(
            instance_path(r"\PhysicalDisk(*)\Disk Reads/sec", "0 C:"),
            r"\PhysicalDisk(0 C:)\Disk Reads/sec"
        );
        assert_eq!(
            instance_path(r"\Memory\Available MBytes", "x"),
            r"\Memory\Available MBytes"
        );
    }

    #[test]
    fn instances_sharing_a_name_are_numbered() {
        let names = ["svchost", "lsass", "svchost", "svchost"].map(String::from);
        assert_eq!(
            numbered(names),
            ["svchost", "lsass", "svchost#1", "svchost#2"]
        );
    }

    /// One without a value still takes its number, so the programs after it keep
    /// theirs, and each counter's `svchost#2` is the same program.
    #[test]
    fn an_instance_without_a_value_keeps_the_others_numbers() {
        let read = [
            ("svchost", Some(1.0)),
            ("svchost", None),
            ("lsass", Some(3.0)),
            ("svchost", Some(4.0)),
        ]
        .map(|(name, value)| (name.to_string(), value));
        assert_eq!(
            numbered_with_values(read),
            [
                ("svchost".to_string(), 1.0),
                ("lsass".to_string(), 3.0),
                ("svchost#2".to_string(), 4.0),
            ]
        );
    }

    #[test]
    fn a_path_without_a_wildcard_is_one_item_with_its_value() {
        let path = r"\Processor(_Total)\% Processor Time".to_string();
        let readings = [(
            path.clone(),
            Reading::Values {
                values: vec![(path.clone(), 12.5)],
                dropped: 0,
            },
        )];
        assert_eq!(
            output(&readings),
            json!([{ "name": path, "ok": 1, "value": 12.5 }])
        );
    }

    #[test]
    fn a_wildcard_says_it_works_and_gives_each_instance() {
        let path = r"\PhysicalDisk(*)\Disk Reads/sec".to_string();
        let values = vec![
            (instance_path(&path, "0 C:"), 3.0),
            (instance_path(&path, "_Total"), 3.0),
        ];
        let readings = [(path.clone(), Reading::Values { values, dropped: 2 })];
        assert_eq!(
            output(&readings),
            json!([
                { "name": r"\PhysicalDisk(*)\Disk Reads/sec", "ok": 1, "dropped": 2 },
                { "name": r"\PhysicalDisk(0 C:)\Disk Reads/sec", "value": 3.0 },
                { "name": r"\PhysicalDisk(_Total)\Disk Reads/sec", "value": 3.0 },
            ])
        );
    }

    #[test]
    fn a_wildcard_keeps_the_total_and_the_same_instances_each_time() {
        let path = r"\Process(*)\% Processor Time";
        let mut instances: Vec<(String, f64)> = (0..MAX_INSTANCES + 5)
            .map(|i| (format!("app{i:03}"), 1.0))
            .collect();
        instances.reverse();
        instances.push(("_Total".to_string(), 50.0));
        instances.push(("app000".to_string(), 2.0));
        let instances = numbered_with_values(instances.into_iter().map(|(n, v)| (n, Some(v))));
        let (kept, dropped) = kept_instances(path, instances);
        assert_eq!(kept.len(), MAX_INSTANCES);
        assert_eq!(dropped, 7);
        assert_eq!(
            kept[0],
            (r"\Process(_Total)\% Processor Time".to_string(), 50.0)
        );
        assert_eq!(kept[1].0, r"\Process(app000)\% Processor Time");
        // The second program with that name, numbered as Windows numbers them.
        assert_eq!(kept[2].0, r"\Process(app000#1)\% Processor Time");
        assert_eq!(kept[3].0, r"\Process(app001)\% Processor Time");
    }

    #[test]
    fn a_failure_says_why_and_a_rate_waiting_for_its_second_look_has_no_value() {
        let readings = [
            (r"\Nothing\Here".to_string(), Reading::Failed(NOT_FOUND)),
            (
                r"\PhysicalDisk(_Total)\Disk Reads/sec".to_string(),
                Reading::Waiting,
            ),
        ];
        assert_eq!(
            output(&readings),
            json!([
                { "name": r"\Nothing\Here", "ok": 0, "error": NOT_FOUND },
                { "name": r"\PhysicalDisk(_Total)\Disk Reads/sec", "ok": 1 },
            ])
        );
    }

    #[test]
    fn values_that_are_not_numbers_are_left_out() {
        let path = r"\X\Y".to_string();
        let readings = [(
            path.clone(),
            Reading::Values {
                values: vec![(path.clone(), f64::NAN)],
                dropped: 0,
            },
        )];
        assert_eq!(output(&readings), json!([{ "name": path, "ok": 1 }]));
    }

    #[cfg(not(windows))]
    #[test]
    fn elsewhere_every_path_says_counters_are_only_on_windows() {
        let mut collector = CounterCollector::new(vec![r"\Memory\Available MBytes".into()]);
        let output = collector.collect().unwrap();
        assert_eq!(output[0]["error"], NOT_WINDOWS);
    }

    #[cfg(windows)]
    #[test]
    fn this_host_reports_its_counters() {
        let mut collector = CounterCollector::new(vec![
            r"\Memory\Available MBytes".into(),
            r"\Processor(*)\% Processor Time".into(),
            r"\No Such Object\Nothing".into(),
        ]);
        std::thread::sleep(std::time::Duration::from_millis(250));
        let output = collector.collect().unwrap();
        let item = |name: &str| {
            output
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == name)
                .cloned()
                .unwrap_or_else(|| panic!("no {name} in {output}"))
        };

        let memory = item(r"\Memory\Available MBytes");
        assert_eq!(memory["ok"], 1, "{output}");
        assert!(memory["value"].as_f64().unwrap() > 0.0, "{output}");
        assert_eq!(item(r"\Processor(*)\% Processor Time")["ok"], 1);
        let total = item(r"\Processor(_Total)\% Processor Time")["value"]
            .as_f64()
            .unwrap();
        assert!((0.0..=100.0 * 1024.0).contains(&total), "{output}");
        assert_eq!(item(r"\No Such Object\Nothing")["error"], NOT_FOUND);
    }
}
