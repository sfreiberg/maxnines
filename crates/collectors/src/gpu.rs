//! How busy each GPU is, and how much memory it's using. Only built for macOS so far,
//! where IOKit publishes each GPU's own statistics to anyone, without extra rights.

use anyhow::Result;
use chrono::{DateTime, Utc};
use maxnines_protocol::entries::Entry;
use serde_json::{Value, json};

use crate::Collector;
use crate::entries::{Entries, at};

/// Where macOS keeps how busy a GPU is: Apple's own GPUs and AMD's say the first,
/// and some older drivers the second.
const USAGE_KEYS: [&str; 2] = ["Device Utilization %", "GPU Activity(%)"];

/// Where macOS keeps how much memory a GPU is using: the memory Apple's GPUs share
/// with the rest of the Mac, or a separate card's own.
const MEMORY_KEYS: [&str; 2] = ["In use system memory", "vramUsedBytes"];

/// One GPU, as far as it says.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub name: String,
    pub usage_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
}

/// A GPU's reading from its statistics, read by `number`. One with neither usage
/// nor memory has nothing to report.
fn reading(name: Option<String>, number: impl Fn(&str) -> Option<i64>) -> Option<Reading> {
    let first = |keys: &[&str]| keys.iter().find_map(|key| number(key));
    let usage_percent = first(&USAGE_KEYS).map(|percent| (percent as f64).clamp(0.0, 100.0));
    let memory_used_bytes = first(&MEMORY_KEYS).and_then(|bytes| u64::try_from(bytes).ok());
    if usage_percent.is_none() && memory_used_bytes.is_none() {
        return None;
    }
    Some(Reading {
        name: name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "GPU".to_string()),
        usage_percent,
        memory_used_bytes,
    })
}

/// Each GPU's own name, numbering any that share one, such as the two cards in a
/// Mac Pro, so each is its own series.
fn named_apart(mut readings: Vec<Reading>) -> Vec<Reading> {
    let names: Vec<String> = readings
        .iter()
        .map(|reading| reading.name.clone())
        .collect();
    for (index, reading) in readings.iter_mut().enumerate() {
        let shared = names.iter().filter(|name| **name == reading.name).count() > 1;
        if shared {
            let number = names[..=index]
                .iter()
                .filter(|name| **name == reading.name)
                .count();
            reading.name = format!("{} {number}", reading.name);
        }
    }
    readings
}

pub struct GpuCollector;

impl Collector for GpuCollector {
    fn name(&self) -> &'static str {
        "gpu"
    }

    fn collect(&mut self) -> Result<Value> {
        let gpus = named_apart(platform::readings())
            .into_iter()
            .map(|gpu| {
                json!({
                    "name": gpu.name,
                    "usage_percent": gpu.usage_percent,
                    "memory_used_bytes": gpu.memory_used_bytes,
                })
            })
            .collect();
        Ok(Value::Array(gpus))
    }

    fn metrics(&self) -> &'static [&'static str] {
        &["gpu.usage", "gpu.memory"]
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        let mut entries = Entries::at(time);
        let gpus = output.as_array().map(Vec::as_slice).unwrap_or_default();
        let named = gpus
            .iter()
            .filter_map(|gpu| Some((gpu.get("name")?.as_str()?, gpu)));
        let mut any = false;
        for (name, gpu) in named {
            any = true;
            for (metric, field) in GPU_FIELDS {
                entries.read(metric, &[name], at(gpu, field));
            }
        }
        // A host whose GPUs say nothing has nothing for either.
        if !any {
            for (metric, _) in GPU_FIELDS {
                entries.nothing(metric, &[]);
            }
        }
        entries.done()
    }
}

/// A GPU's metrics, and what each is read from.
const GPU_FIELDS: [(&str, &str); 2] = [
    ("gpu.usage", "usage_percent"),
    ("gpu.memory", "memory_used_bytes"),
];

mod platform {
    use objc2_core_foundation::{CFData, CFDictionary, CFNumber, CFRetained, CFString, CFType};
    use objc2_io_kit::{
        IOIteratorNext, IOObjectRelease, IORegistryEntryCreateCFProperty,
        IORegistryEntrySearchCFProperty, IOServiceGetMatchingServices, IOServiceMatching,
        io_registry_entry_t, kIOMainPortDefault, kIORegistryIterateParents,
        kIORegistryIterateRecursively, kIOServicePlane,
    };

    use super::Reading;
    use crate::disk_activity::platform::io_name;

    /// Every GPU IOKit knows of, with what it says about itself.
    pub fn readings() -> Vec<Reading> {
        // SAFETY: the name is a C string IOKit only reads.
        let Some(matching) = (unsafe { IOServiceMatching(c"IOAccelerator".as_ptr()) }) else {
            return Vec::new();
        };
        let mut iterator = 0;
        // SAFETY: the matching dictionary is handed over, as IOKit releases it, and
        // the iterator has somewhere to go.
        let status = unsafe {
            IOServiceGetMatchingServices(
                kIOMainPortDefault,
                Some(CFRetained::<CFDictionary>::from(&matching)),
                &mut iterator,
            )
        };
        if status != 0 || iterator == 0 {
            return Vec::new();
        }
        let mut found = Vec::new();
        loop {
            let entry = IOIteratorNext(iterator);
            if entry == 0 {
                break;
            }
            found.extend(read(entry));
            IOObjectRelease(entry);
        }
        IOObjectRelease(iterator);
        found
    }

    fn read(entry: io_registry_entry_t) -> Option<Reading> {
        let key = CFString::from_static_str("PerformanceStatistics");
        // SAFETY: the entry is valid until released, and is only read.
        let statistics = unsafe { IORegistryEntryCreateCFProperty(entry, Some(&key), None, 0) }?;
        let statistics = statistics.downcast::<CFDictionary>().ok()?;
        // SAFETY: IOKit's property dictionaries have strings for keys.
        let statistics = unsafe { statistics.cast_unchecked::<CFString, CFType>() };
        let number = |key: &str| -> Option<i64> {
            let value = statistics.get(&CFString::from_str(key))?;
            value.downcast::<CFNumber>().ok()?.as_i64()
        };
        super::reading(model(entry), number)
    }

    /// What the GPU is called, such as "Apple M4 Pro". Apple's GPUs say so
    /// themselves, while a separate card's name is on the PCI device above it.
    fn model(entry: io_registry_entry_t) -> Option<String> {
        let key = CFString::from_static_str("model");
        let mut plane = io_name(kIOServicePlane);
        // SAFETY: the entry is valid until released, and the plane is a C string
        // IOKit only reads.
        let value = unsafe {
            IORegistryEntrySearchCFProperty(
                entry,
                &raw mut plane,
                Some(&key),
                None,
                kIORegistryIterateRecursively | kIORegistryIterateParents,
            )
        }?;
        text(value)
    }

    /// A name kept as a string, or as bytes ending in a zero, as PCI devices keep it.
    fn text(value: CFRetained<CFType>) -> Option<String> {
        let value = match value.downcast::<CFString>() {
            Ok(string) => return Some(string.to_string()),
            Err(value) => value,
        };
        let bytes = value.downcast::<CFData>().ok()?.to_vec();
        let name = bytes.split(|byte| *byte == 0).next()?;
        String::from_utf8(name.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::entries::tests::{every_metric_has_an_entry, said, time};

    #[test]
    fn gpu_entries_have_a_series_for_each_gpu() {
        let output = json!([
            { "name": "Apple M4 Pro", "usage_percent": 31.0, "memory_used_bytes": 390_922_240 },
            // An older card that only says how busy it is.
            { "name": "Radeon 2", "usage_percent": 7.0, "memory_used_bytes": null },
        ]);
        let entries = GpuCollector.entries(&output, time());
        assert_eq!(
            said(&entries),
            [
                ("gpu.usage[Apple M4 Pro]".to_string(), json!(31.0)),
                ("gpu.memory[Apple M4 Pro]".to_string(), json!(390_922_240)),
                ("gpu.usage[Radeon 2]".to_string(), json!(7.0)),
                ("gpu.memory[Radeon 2]".to_string(), Value::Null),
            ]
        );
        every_metric_has_an_entry(&GpuCollector, &entries);

        // With no GPUs, each metric says it has nothing.
        let none = GpuCollector.entries(&json!([]), time());
        assert_eq!(
            said(&none),
            [
                ("gpu.usage".to_string(), Value::Null),
                ("gpu.memory".to_string(), Value::Null),
            ]
        );
        every_metric_has_an_entry(&GpuCollector, &none);
    }

    /// What a real collection says is entries for exactly the collector's metrics.
    #[test]
    fn what_this_hosts_gpus_really_say_becomes_entries_for_their_metrics() {
        let output = GpuCollector.collect().unwrap();
        every_metric_has_an_entry(&GpuCollector, &GpuCollector.entries(&output, time()));
    }

    fn statistics(pairs: &[(&str, i64)]) -> impl Fn(&str) -> Option<i64> {
        let pairs: HashMap<String, i64> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), *value))
            .collect();
        move |key| pairs.get(key).copied()
    }

    #[test]
    fn an_apple_gpu_says_how_busy_it_is_and_the_memory_it_shares() {
        let found = reading(
            Some("Apple M4 Pro".to_string()),
            statistics(&[
                ("Device Utilization %", 31),
                ("Renderer Utilization %", 31),
                ("In use system memory", 390_922_240),
            ]),
        );
        assert_eq!(
            found,
            Some(Reading {
                name: "Apple M4 Pro".to_string(),
                usage_percent: Some(31.0),
                memory_used_bytes: Some(390_922_240),
            })
        );
    }

    #[test]
    fn a_card_with_its_own_memory_and_older_words_is_read_too() {
        let found = reading(
            Some("AMD Radeon Pro 5500M".to_string()),
            statistics(&[("GPU Activity(%)", 7), ("vramUsedBytes", 1_073_741_824)]),
        )
        .unwrap();
        assert_eq!(found.usage_percent, Some(7.0));
        assert_eq!(found.memory_used_bytes, Some(1_073_741_824));
    }

    #[test]
    fn a_gpu_with_nothing_to_say_is_left_out_and_one_without_a_name_is_still_a_gpu() {
        assert_eq!(reading(Some("Quiet".to_string()), statistics(&[])), None);
        let found = reading(
            Some("  ".to_string()),
            statistics(&[("Device Utilization %", 5)]),
        );
        assert_eq!(found.unwrap().name, "GPU");
    }

    #[test]
    fn readings_out_of_range_are_kept_in_it() {
        let busy = reading(None, statistics(&[("Device Utilization %", 140)])).unwrap();
        assert_eq!(busy.usage_percent, Some(100.0));
        let odd = reading(
            None,
            statistics(&[("In use system memory", -1), ("Device Utilization %", 1)]),
        );
        assert_eq!(odd.unwrap().memory_used_bytes, None);
    }

    #[test]
    fn gpus_sharing_a_name_are_numbered() {
        let gpu = |name: &str| Reading {
            name: name.to_string(),
            usage_percent: Some(1.0),
            memory_used_bytes: None,
        };
        let names: Vec<String> = named_apart(vec![gpu("Radeon"), gpu("Intel"), gpu("Radeon")])
            .into_iter()
            .map(|gpu| gpu.name)
            .collect();
        assert_eq!(names, ["Radeon 1", "Intel", "Radeon 2"]);
    }

    #[test]
    fn this_host_reports_a_list_of_gpus() {
        let output = GpuCollector.collect().unwrap();
        let gpus = output.as_array().unwrap();
        for gpu in gpus {
            assert!(
                gpu["name"].as_str().is_some_and(|name| !name.is_empty()),
                "{output}"
            );
            if let Some(usage) = gpu["usage_percent"].as_f64() {
                assert!((0.0..=100.0).contains(&usage), "{output}");
            }
        }
        // Every Mac has a GPU, though a virtual one may say nothing about it.
        if std::env::var_os("CI").is_none() {
            assert!(!gpus.is_empty(), "{output}");
        }
    }
}
