//! Windows performance counters, chosen by their English paths, like
//! `\Processor(_Total)\% Processor Time`. They're read through Windows' own counter
//! API, which works out rates such as disk reads a second between one sample and the
//! next. English names are looked up whatever language Windows is in, so one config
//! works everywhere. `(*)` in a path reads every instance, each as a series of its own.
//!
//! A path that isn't on a host is reported as failing, with a fixed message, and
//! looked for again on the next sample, as some only appear once their software runs.

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
    /// Each instance's path and value. One with no wildcard has one.
    Values(Vec<(String, f64)>),
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

/// The collector's output: an item for each configured path saying whether it works,
/// and one for each value, by path. A path with no wildcard has both in one item.
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
            Reading::Values(values) => {
                item(&mut items, path).insert("ok".into(), json!(1));
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

    use super::{MAX_INSTANCES, NOT_FOUND, NOT_READ, Reading, instance_path, numbered};

    /// Percentages of processor time can pass 100 on a host with several cores.
    const NO_CAP_AT_100: u32 = 0x8000;
    const FORMAT: u32 = PDH_FMT_DOUBLE | NO_CAP_AT_100;

    /// One query holding every counter, as a collection reads them all at once.
    pub struct Counters {
        query: Option<PDH_HQUERY>,
        counters: Vec<(String, Result<PDH_HCOUNTER, &'static str>)>,
    }

    // SAFETY: a query's handles work from any thread. This only ever uses them from one
    // at a time, as `read` and `drop` take it mutably.
    unsafe impl Send for Counters {}

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn added(query: PDH_HQUERY, path: &str) -> Result<PDH_HCOUNTER, &'static str> {
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

    /// Reads up to a zero, as Windows' own strings end.
    ///
    /// # Safety
    /// `text` has to be null or point to a string that ends with a zero.
    unsafe fn from_wide(text: *const u16) -> String {
        if text.is_null() {
            return String::new();
        }
        let mut length = 0;
        // SAFETY: the string ends with a zero, so nothing past it is read.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: those `length` characters were just read.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
    }

    fn values(path: &str, counter: PDH_HCOUNTER) -> Reading {
        let (mut size, mut count) = (0u32, 0u32);
        // SAFETY: asking how much room the values need, with nowhere to put them yet.
        let status = unsafe {
            PdhGetFormattedCounterArrayW(counter, FORMAT, &mut size, &mut count, null_mut())
        };
        match status {
            PDH_MORE_DATA => {}
            0 => return Reading::Values(Vec::new()),
            PDH_INVALID_DATA | PDH_CSTATUS_INVALID_DATA | PDH_NO_DATA => return Reading::Waiting,
            _ => return Reading::Failed(NOT_READ),
        }
        // In eights, as the items hold numbers and pointers that need that alignment.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let items = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        // SAFETY: the buffer is at least as big as Windows asked for, and aligned.
        let status =
            unsafe { PdhGetFormattedCounterArrayW(counter, FORMAT, &mut size, &mut count, items) };
        match status {
            0 => {}
            PDH_INVALID_DATA | PDH_CSTATUS_INVALID_DATA | PDH_NO_DATA => return Reading::Waiting,
            _ => return Reading::Failed(NOT_READ),
        }
        // SAFETY: Windows filled in `count` items at the start of the buffer.
        let items = unsafe { std::slice::from_raw_parts(items, count as usize) };
        let usable: Vec<(String, f64)> = items
            .iter()
            .filter(|item| {
                matches!(
                    item.FmtValue.CStatus,
                    PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA
                )
            })
            .map(|item| {
                // SAFETY: each name ends with a zero, and with PDH_FMT_DOUBLE asked for,
                // the value is a double.
                unsafe { (from_wide(item.szName), item.FmtValue.Anonymous.doubleValue) }
            })
            .collect();
        if !path.contains("(*)") {
            return Reading::Values(
                usable
                    .first()
                    .map(|(_, value)| (path.to_string(), *value))
                    .into_iter()
                    .collect(),
            );
        }
        let (names, values): (Vec<String>, Vec<f64>) =
            usable.into_iter().take(MAX_INSTANCES).unzip();
        Reading::Values(
            numbered(names)
                .into_iter()
                .zip(values)
                .map(|(instance, value)| (instance_path(path, &instance), value))
                .collect(),
        )
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
            let mut counters = Self { query, counters };
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
            if let Some(query) = self.query {
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

    #[test]
    fn a_path_without_a_wildcard_is_one_item_with_its_value() {
        let path = r"\Processor(_Total)\% Processor Time".to_string();
        let readings = [(path.clone(), Reading::Values(vec![(path.clone(), 12.5)]))];
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
        let readings = [(path.clone(), Reading::Values(values))];
        assert_eq!(
            output(&readings),
            json!([
                { "name": r"\PhysicalDisk(*)\Disk Reads/sec", "ok": 1 },
                { "name": r"\PhysicalDisk(0 C:)\Disk Reads/sec", "value": 3.0 },
                { "name": r"\PhysicalDisk(_Total)\Disk Reads/sec", "value": 3.0 },
            ])
        );
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
            Reading::Values(vec![(path.clone(), f64::NAN)]),
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
