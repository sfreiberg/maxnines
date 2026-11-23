use std::collections::BTreeMap;

use maxnines_protocol::templates::work::JoinWork;
use serde_json::json;

use super::*;

fn metric(key: &str, counter: &str) -> CounterWork {
    CounterWork {
        key: key.to_string(),
        counter: counter.to_string(),
        total: false,
        highest: counter.starts_with('%'),
    }
}

fn block(instances: Instances, metrics: Vec<CounterWork>) -> CountersWork {
    CountersWork {
        key: "pools".to_string(),
        object: "W3SVC_W3WP".to_string(),
        instances,
        exclude: Vec::new(),
        groups: BTreeMap::new(),
        join: None,
        interval: None,
        metrics,
    }
}

fn readings(counters: &[(&str, &[(&str, f64)])]) -> Readings {
    Readings {
        counters: counters
            .iter()
            .map(|(counter, values)| {
                let values = values
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), *value))
                    .collect();
                ((*counter).to_string(), values)
            })
            .collect(),
        joined: Vec::new(),
    }
}

#[test]
fn each_instance_is_labelled_by_its_name_leaving_out_the_total_and_those_excluded() {
    let mut work = block(
        Instances::Labelled("site".to_string()),
        vec![metric("connections", "Current Connections")],
    );
    work.exclude = vec!["Old".to_string()];
    let read = readings(&[(
        "Current Connections",
        &[("_Total", 9.0), ("Shop", 5.0), ("Old", 1.0), ("Blog", 3.0)],
    )]);
    assert_eq!(
        rows(&work, &read, &mut Totals::default()),
        [
            json!({ "labels": { "site": "Blog" }, "connections": 3.0, "_query": "pools" }),
            json!({ "labels": { "site": "Shop" }, "connections": 5.0, "_query": "pools" }),
        ]
    );
}

#[test]
fn a_pattern_labels_by_its_groups_and_same_labels_add_up_or_take_the_highest() {
    let work = block(
        Instances::Pattern(r"^\d+_(?<pool>.+)$".to_string()),
        vec![
            metric("active_requests", "Active Requests"),
            metric("server_errors", "% 500 HTTP Response Sent"),
        ],
    );
    let read = readings(&[
        (
            "Active Requests",
            &[
                ("_Total", 7.0),
                ("41_shop", 2.0),
                ("52_shop", 3.0),
                ("60_api", 2.0),
                ("odd", 1.0),
            ],
        ),
        (
            "% 500 HTTP Response Sent",
            &[("41_shop", 4.0), ("52_shop", 1.0), ("60_api", 0.5)],
        ),
    ]);
    assert_eq!(
        rows(&work, &read, &mut Totals::default()),
        [
            json!({ "labels": { "pool": "api" }, "active_requests": 2.0, "server_errors": 0.5, "_query": "pools" }),
            json!({ "labels": { "pool": "shop" }, "active_requests": 5.0, "server_errors": 4.0, "_query": "pools" }),
        ]
    );
}

#[test]
fn a_running_total_is_sent_as_its_change_from_the_second_read() {
    let mut failures = metric("worker_failures", "Total Worker Process Failures");
    failures.total = true;
    let work = block(Instances::Labelled("pool".to_string()), vec![failures]);
    let mut totals = Totals::default();
    let read = |value: f64| readings(&[("Total Worker Process Failures", &[("shop", value)])]);
    assert!(rows(&work, &read(4.0), &mut totals).is_empty());
    assert_eq!(
        rows(&work, &read(6.0), &mut totals)[0]["worker_failures"],
        2.0
    );
    // Counted again from nothing, as when IIS restarts.
    assert_eq!(
        rows(&work, &read(1.0), &mut totals)[0]["worker_failures"],
        1.0
    );
}

#[test]
fn one_instance_or_a_set_with_none_is_one_unlabelled_series() {
    let work = block(
        Instances::One("__Total__".to_string()),
        vec![metric("aspnet_requests", "Requests/Sec")],
    );
    let read = readings(&[("Requests/Sec", &[(ONLY, 12.0)])]);
    assert_eq!(
        rows(&work, &read, &mut Totals::default()),
        [json!({ "labels": {}, "aspnet_requests": 12.0, "_query": "pools" })]
    );
    assert_eq!(
        path(&work, "Requests/Sec"),
        r"\W3SVC_W3WP(__Total__)\Requests/Sec"
    );
    let none = block(Instances::None, Vec::new());
    assert_eq!(
        path(&none, "Requests Queued"),
        r"\W3SVC_W3WP\Requests Queued"
    );
    let every = block(Instances::Labelled("x".to_string()), Vec::new());
    assert_eq!(
        path(&every, "Active Requests"),
        r"\W3SVC_W3WP(*)\Active Requests"
    );
}

#[test]
fn a_join_by_a_group_in_both_patterns_labels_with_the_others_groups() {
    let mut work = block(
        Instances::Pattern(r"^w3wp:(?<pid>\d+)$".to_string()),
        vec![metric("pool_memory", "Working Set - Private")],
    );
    work.object = "Process V2".to_string();
    work.join = Some(JoinWork {
        object: "W3SVC_W3WP".to_string(),
        pattern: r"^(?<pid>\d+)_(?<pool>.+)$".to_string(),
    });
    let mut read = readings(&[(
        "Working Set - Private",
        &[
            ("w3wp:41", 100.0),
            ("w3wp:52", 50.0),
            ("w3wp:60", 10.0),
            ("w3wp:99", 7.0),
            ("svchost:3", 1.0),
        ],
    )]);
    read.joined = ["_Total", "41_shop", "52_shop", "60_api"]
        .map(String::from)
        .to_vec();
    assert_eq!(
        rows(&work, &read, &mut Totals::default()),
        [
            json!({ "labels": { "pool": "api" }, "pool_memory": 10.0, "_query": "pools" }),
            json!({ "labels": { "pool": "shop" }, "pool_memory": 150.0, "_query": "pools" }),
        ]
    );
}

#[test]
fn a_group_read_from_a_counter_joins_as_a_patterns_group_does() {
    let mut work = block(
        Instances::Pattern(String::new()),
        vec![metric("pool_memory", "Working Set - Private")],
    );
    work.object = "Process".to_string();
    work.groups = BTreeMap::from([("pid".to_string(), "ID Process".to_string())]);
    work.join = Some(JoinWork {
        object: "W3SVC_W3WP".to_string(),
        pattern: r"^(?<pid>\d+)_(?<pool>.+)$".to_string(),
    });
    let mut read = readings(&[
        (
            "Working Set - Private",
            &[
                ("_Total", 999.0),
                ("w3wp", 100.0),
                ("w3wp#1", 50.0),
                ("explorer", 5.0),
            ],
        ),
        (
            "ID Process",
            &[
                ("_Total", 0.0),
                ("w3wp", 41.0),
                ("w3wp#1", 52.0),
                ("explorer", 7.0),
            ],
        ),
    ]);
    read.joined = ["41_shop", "52_api"].map(String::from).to_vec();
    assert_eq!(
        rows(&work, &read, &mut Totals::default()),
        [
            json!({ "labels": { "pool": "api" }, "pool_memory": 50.0, "_query": "pools" }),
            json!({ "labels": { "pool": "shop" }, "pool_memory": 100.0, "_query": "pools" }),
        ]
    );
}

#[test]
fn the_counters_a_block_reads_are_each_read_once() {
    let mut work = block(
        Instances::Labelled("pool".to_string()),
        vec![
            metric("pool_state", "Current Application Pool State"),
            metric("pool_running", "Current Application Pool State"),
        ],
    );
    work.groups = BTreeMap::from([("pid".to_string(), "ID Process".to_string())]);
    assert_eq!(
        counters_read(&work),
        ["Current Application Pool State", "ID Process"]
    );
}

#[cfg(not(windows))]
#[test]
fn elsewhere_nothing_is_read_for_templates_on_the_host() {
    let work = TemplateWork {
        template: "iis".to_string(),
        database: None,
        discover: Vec::new(),
        queries: Vec::new(),
        counters: vec![block(
            Instances::Labelled("site".to_string()),
            vec![metric("connections", "Current Connections")],
        )],
    };
    let mut templates = HostTemplates::default();
    templates.update(&[work]);
    let read = templates.collect(Duration::from_secs(10));
    assert!(read.rows.is_empty() && read.discovered.is_empty());
}

/// What a Windows host has: its own processor's counters, and a registry value
/// every Windows has, read the way a template has them read.
#[cfg(windows)]
#[test]
fn this_host_reads_counters_counter_sets_and_the_registry() {
    use maxnines_protocol::templates::work::{DiscoverWork, RegistryWork};

    let work = TemplateWork {
        template: "win".to_string(),
        database: None,
        discover: vec![DiscoverWork {
            key: "os".to_string(),
            interval: Duration::from_secs(3600),
            sql: None,
            registry: vec![RegistryWork {
                key: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion".to_string(),
                values: BTreeMap::from([
                    ("build".to_string(), "CurrentBuildNumber".to_string()),
                    ("nothing".to_string(), "No Such Value".to_string()),
                ]),
            }],
            counter_sets: BTreeMap::from([
                ("processor".to_string(), "Processor".to_string()),
                ("missing".to_string(), "No Such Counter Set".to_string()),
            ]),
        }],
        queries: Vec::new(),
        counters: vec![
            CountersWork {
                key: "cpu".to_string(),
                object: "Processor".to_string(),
                instances: Instances::Labelled("core".to_string()),
                exclude: Vec::new(),
                groups: BTreeMap::new(),
                join: None,
                interval: None,
                metrics: vec![metric("busy", "% Processor Time")],
            },
            CountersWork {
                key: "memory".to_string(),
                object: "Memory".to_string(),
                instances: Instances::None,
                exclude: Vec::new(),
                groups: BTreeMap::new(),
                join: None,
                interval: None,
                metrics: vec![metric("available", "Available MBytes")],
            },
            // Each process joined to the processor core of the same number: the
            // Idle process, whose ID is 0, to the first core, which every host has.
            CountersWork {
                key: "processes".to_string(),
                object: "Process".to_string(),
                instances: Instances::Pattern(String::new()),
                exclude: Vec::new(),
                groups: BTreeMap::from([("pid".to_string(), "ID Process".to_string())]),
                join: Some(JoinWork {
                    object: "Processor".to_string(),
                    pattern: r"^(?<pid>(?<core>\d+))$".to_string(),
                }),
                interval: None,
                metrics: vec![metric("threads", "Thread Count")],
            },
        ],
    };
    let mut templates = HostTemplates::default();
    templates.update(&[work]);
    std::thread::sleep(Duration::from_millis(250));
    let read = templates.collect(Duration::from_secs(10));

    let found = &read.discovered[0];
    assert_eq!(found.template, "win");
    assert_eq!(found.database, None);
    let build = found.values["build"].as_str().unwrap_or_default();
    assert!(build.parse::<u64>().is_ok(), "{found:?}");
    assert!(!found.values.contains_key("nothing"), "{found:?}");
    assert_eq!(found.values["processor"], json!(true), "{found:?}");
    assert_eq!(found.values["missing"], json!(false), "{found:?}");

    let rows = &read.rows["win"];
    let of = |block: &str| -> Vec<&Value> {
        rows.iter()
            .filter(|row| row[QUERY_FIELD] == block)
            .collect()
    };
    let cpu = of("cpu");
    assert!(!cpu.is_empty(), "{rows:?}");
    assert!(
        cpu.iter().all(|row| row["labels"]["core"] != TOTAL),
        "{rows:?}"
    );
    let memory = of("memory");
    assert!(memory[0]["available"].as_f64().unwrap() > 0.0, "{rows:?}");
    let idle = of("processes")
        .into_iter()
        .find(|row| row["labels"] == json!({ "core": "0" }))
        .unwrap_or_else(|| panic!("no Idle process joined to core 0 in {rows:?}"));
    assert!(idle["threads"].as_f64().unwrap() > 0.0, "{rows:?}");

    // Discovery waits for its interval, and counters read again.
    let again = templates.collect(Duration::from_secs(10));
    assert!(again.discovered.is_empty());
    assert!(!again.rows["win"].is_empty());
}
