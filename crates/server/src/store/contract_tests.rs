// What every metrics store has to do, the same way. Each store's tests include this,
// with `TestStore` and `in_memory` of their own.

fn names(result: &SeriesResult) -> Vec<&str> {
    result.series.iter().map(|s| s.name.as_str()).collect()
}


fn new_sample(agent_id: &str, host: &str, sample: &Sample) -> NewSample {
    NewSample {
        agent_id: agent_id.to_string(),
        host: host.to_string(),
        sample: sample.clone(),
    }
}

fn write_one(
    store: &mut TestStore,
    agent_id: &str,
    host: &str,
    sample: &Sample,
) -> Result<()> {
    store.write(&[new_sample(agent_id, host, sample)])
}

fn write_metric(
    store: &mut TestStore,
    agent: &str,
    time_ms: u64,
    collector: &str,
    data: Value,
) {
    let sample = Sample {
        timestamp_ms: time_ms,
        metrics: BTreeMap::from([(collector.to_string(), data)]),
    };
    write_one(store, agent, "host", &sample).unwrap();
}

fn query(store: &TestStore, agent_id: &str, metric: &str, max_series: usize) -> SeriesResult {
    store
        .reader()
        .unwrap()
        .series(&SeriesQuery {
            agent_id,
            metric: find(metric).unwrap(),
            range: TimeRange::new(0, HOUR_MS).unwrap(),
            max_series,
        })
        .unwrap()
}

fn averages(series: &Series) -> Vec<f64> {
    series.points.iter().map(|point| point.avg).collect()
}

fn latest_output(store: &TestStore, agent: &str, collector: &str) -> Option<Value> {
    let reader = store.reader().unwrap();
    reader.latest_output(agent, collector, 0, 9000).unwrap()
}

fn newest(store: &TestStore, metric: &str, since: i64, until: i64) -> Vec<NewestReading> {
    store
        .reader()
        .unwrap()
        .newest(find(metric).unwrap(), since, until)
        .unwrap()
}

fn values(readings: &[NewestReading]) -> Vec<(&str, &str, i64, f64)> {
    readings
        .iter()
        .map(|r| (r.agent_id.as_str(), r.series.as_str(), r.time_ms, r.value))
        .collect()
}

fn calculate(
    store: &TestStore,
    metric: &str,
    calculation: Calculation,
    members: &[(&str, &str)],
    by_series: bool,
) -> SeriesResult {
    let query = CalculationQuery {
        metric: find(metric).unwrap(),
        range: TimeRange::new(0, 3_600_000).unwrap(),
        calculation,
        members: members
            .iter()
            .map(|(agent_id, group)| Member {
                agent_id: agent_id.to_string(),
                group: group.to_string(),
            })
            .collect(),
        by_series,
        max_lines: 8,
    };
    store.reader().unwrap().calculate(&query).unwrap()
}

fn line(series: &Series) -> Vec<f64> {
    series.points.iter().map(|point| point.avg).collect()
}

/// Two machines at 10% and 30%, and a third at 80% on its own.
fn three_machines() -> TestStore {
    let mut store = in_memory();
    for (agent, usage) in [("a", 10.0), ("b", 30.0), ("c", 80.0)] {
        write_metric(
            &mut store,
            agent,
            1000,
            "cpu",
            json!({ "usage_percent": usage }),
        );
    }
    store
}

#[test]
fn values_in_a_bucket_are_summarized_together() {
    let mut store = in_memory();
    for (time_ms, usage) in [(1000, 10.0), (2000, 30.0), (16_000, 50.0)] {
        write_metric(
            &mut store,
            "a",
            time_ms,
            "cpu",
            json!({ "usage_percent": usage }),
        );
    }

    let result = query(&store, "a", "cpu.usage", 8);

    assert_eq!(names(&result), ["CPU"]);
    assert_eq!(
        result.series[0].points,
        [
            Point {
                time_ms: 0,
                avg: 20.0,
                min: 10.0,
                max: 30.0
            },
            Point {
                time_ms: 15_000,
                avg: 50.0,
                min: 50.0,
                max: 50.0
            },
        ]
    );
}

#[test]
fn a_metric_can_have_several_fixed_series() {
    let mut store = in_memory();
    let load = json!({ "load_average": { "one": 1.0, "five": 2.0, "fifteen": 3.0 } });
    write_metric(&mut store, "a", 1000, "cpu", load);

    let result = query(&store, "a", "cpu.load", 8);

    assert_eq!(names(&result), ["1 minute", "15 minutes", "5 minutes"]);
    assert_eq!(averages(&result.series[1]), [3.0]);
}

#[test]
fn a_platform_without_a_value_has_no_series_for_it() {
    let mut store = in_memory();
    write_metric(
        &mut store,
        "a",
        1000,
        "cpu",
        json!({ "load_average": null }),
    );
    assert!(query(&store, "a", "cpu.load", 8).series.is_empty());
}

#[test]
fn usage_is_a_percentage_and_nothing_to_use_is_not_zero() {
    let mut store = in_memory();
    let memory = json!({
        "used_bytes": 1, "total_bytes": 4, "swap_used_bytes": 0, "swap_total_bytes": 0,
    });
    write_metric(&mut store, "a", 1000, "memory", memory);

    let result = query(&store, "a", "memory.usage", 8);

    assert_eq!(names(&result), ["Memory"]);
    assert_eq!(averages(&result.series[0]), [25.0]);
}

#[test]
fn each_disk_is_a_series() {
    let mut store = in_memory();
    let disks = json!([
        { "mount_point": "/", "used_bytes": 1, "total_bytes": 2 },
        { "mount_point": "/data", "used_bytes": 3, "total_bytes": 4 },
    ]);
    write_metric(&mut store, "a", 1000, "disk", disks);

    let result = query(&store, "a", "disk.usage", 8);

    assert_eq!(names(&result), ["/", "/data"]);
    assert_eq!(averages(&result.series[1]), [75.0]);
}

#[test]
fn each_disk_reports_how_hard_it_is_working() {
    let mut store = in_memory();
    let disks = json!([
        { "mount_point": "/", "busy_percent": 12.5, "read_ops_per_sec": 40.0,
          "write_latency_ms": 3.25, "queue_length": 0.5 },
        { "mount_point": "/data", "busy_percent": 90.0, "read_ops_per_sec": 800.0,
          "write_latency_ms": 18.0 },
    ]);
    write_metric(&mut store, "a", 1000, "disk", disks);

    let busy = query(&store, "a", "disk.busy", 8);
    assert_eq!(names(&busy), ["/", "/data"]);
    assert_eq!(averages(&busy.series[1]), [90.0]);
    assert_eq!(averages(&query(&store, "a", "disk.read_ops", 8).series[0]), [40.0]);
    assert_eq!(averages(&query(&store, "a", "disk.write_latency", 8).series[0]), [3.25]);
    // A platform without a queue length leaves that disk out of the chart.
    assert_eq!(names(&query(&store, "a", "disk.queue", 8)), ["/"]);
}

#[test]
fn drops_and_tcp_connections_read_what_the_agent_sends() {
    let mut store = in_memory();
    let interfaces = |dropped: u64| json!({ "en0": { "receive_drops": dropped } });
    write_metric(&mut store, "a", 0, "network", interfaces(0));
    write_metric(&mut store, "a", 10_000, "network", interfaces(30));
    let tcp = json!({ "tcp_established": 12, "tcp_listening": 4, "tcp_time_wait": 300,
                      "tcp_close_wait": 2, "tcp_connections": 318 });
    write_metric(&mut store, "a", 10_000, "system", tcp);

    // 30 dropped over 10 seconds.
    let drops = query(&store, "a", "network.drops.received", 8);
    assert_eq!(names(&drops), ["en0"]);
    assert_eq!(averages(&drops.series[0]), [3.0]);
    let tcp = query(&store, "a", "system.tcp", 8);
    assert_eq!(names(&tcp), ["Close wait", "Established", "Listening", "Time wait"]);
    assert_eq!(averages(&tcp.series[3]), [300.0]);
}

#[test]
fn the_top_processes_are_each_a_series_by_name() {
    let mut store = in_memory();
    let top = json!([
        { "name": "postgres", "count": 12, "cpu_percent": 40.0, "memory_bytes": 4_000_000_000u64 },
        { "name": "nginx", "count": 4, "cpu_percent": 5.0, "memory_bytes": 80_000_000 },
    ]);
    write_metric(&mut store, "a", 1000, "top_processes", top);

    let cpu = query(&store, "a", "top.cpu", 8);
    assert_eq!(names(&cpu), ["nginx", "postgres"]);
    assert_eq!(averages(&cpu.series[1]), [40.0]);
    assert_eq!(averages(&query(&store, "a", "top.memory", 8).series[1]), [4e9]);
}

#[test]
fn updates_and_a_waiting_restart_read_what_the_agent_sends() {
    let mut store = in_memory();
    let system = json!({ "pending_updates": 14, "security_updates": 3, "reboot_required": 1 });
    write_metric(&mut store, "a", 1000, "system", system);

    let updates = query(&store, "a", "system.updates", 8);
    assert_eq!(names(&updates), ["All", "Security"]);
    assert_eq!(averages(&updates.series[1]), [3.0]);
    assert_eq!(averages(&query(&store, "a", "system.reboot_required", 8).series[0]), [1.0]);
}

#[test]
fn the_connection_tracking_table_is_a_share_of_its_limit() {
    let mut store = in_memory();
    write_metric(&mut store, "a", 1000, "system", json!({ "conntrack": 196_608, "max_conntrack": 262_144 }));

    assert_eq!(averages(&query(&store, "a", "system.conntrack_used", 8).series[0]), [75.0]);
    assert_eq!(names(&query(&store, "a", "system.conntrack", 8)), ["Limit", "Tracked"]);
}

#[test]
fn failed_services_are_counted_and_named() {
    let mut store = in_memory();
    let system = json!({ "failed_services": 2, "failed_service_names": "backup.timer, nginx.service" });
    write_metric(&mut store, "a", 1000, "system", system);

    assert_eq!(averages(&query(&store, "a", "system.failed_services", 8).series[0]), [2.0]);
    let latest = latest_output(&store, "a", "system").unwrap();
    assert_eq!(latest["failed_service_names"], "backup.timer, nginx.service");
}

#[test]
fn each_core_is_a_series_named_by_its_number() {
    let mut store = in_memory();
    let cpu = json!({ "usage_percent": 40.0, "per_core_percent": [10.0, 90.0, 20.0] });
    write_metric(&mut store, "a", 1000, "cpu", cpu);

    let result = query(&store, "a", "cpu.cores", 8);
    assert_eq!(names(&result), ["0", "1", "2"]);
    assert_eq!(averages(&result.series[1]), [90.0]);

    // The busiest are kept, so one pegged core is never the one left out.
    let result = query(&store, "a", "cpu.cores", 1);
    assert_eq!(names(&result), ["1"]);
    assert_eq!(result.hidden, 2);

    let newest = newest(&store, "cpu.cores", 0, HOUR_MS);
    let mut cores: Vec<(&str, f64)> = newest
        .iter()
        .map(|reading| (reading.series.as_str(), reading.value))
        .collect();
    cores.sort_by(|a, b| a.0.cmp(b.0));
    assert_eq!(cores, [("0", 10.0), ("1", 90.0), ("2", 20.0)]);
}

#[test]
fn network_counts_become_rates_using_the_time_between_samples() {
    let mut store = in_memory();
    for (time_ms, bytes) in [(0, 999_999), (10_000, 5000), (30_000, 20_000)] {
        let data = json!({ "en0": { "received_bytes": bytes, "transmitted_bytes": 0 } });
        write_metric(&mut store, "a", time_ms, "network", data);
    }

    let result = query(&store, "a", "network.received", 8);

    // The first has nothing before it, so nothing says what time it covers.
    assert_eq!(names(&result), ["en0"]);
    assert_eq!(averages(&result.series[0]), [500.0, 1000.0]);
}

#[test]
fn an_idle_interface_is_left_out_without_counting_as_hidden() {
    let mut store = in_memory();
    for time_ms in [0, 15_000, 30_000] {
        let data = json!({
            "en0": { "received_bytes": 10 },
            "utun3": { "received_bytes": 0 },
        });
        write_metric(&mut store, "a", time_ms, "network", data);
    }

    let result = query(&store, "a", "network.received", 8);

    assert_eq!(names(&result), ["en0"]);
    assert_eq!(result.hidden, 0);
}

#[test]
fn output_of_the_wrong_shape_is_skipped() {
    let mut store = in_memory();
    for data in [
        json!("text"),
        json!(null),
        json!([1, 2]),
        json!(7),
        json!({ "a": 1 }),
    ] {
        for collector in ["cpu", "memory", "disk", "network"] {
            write_metric(&mut store, "a", 1000, collector, data.clone());
            write_metric(&mut store, "a", 2000, collector, data.clone());
        }
    }

    for metric in METRICS {
        assert_eq!(query(&store, "a", metric.name, 8), SeriesResult::default());
    }
}

#[test]
fn a_good_item_survives_bad_items_beside_it() {
    let mut store = in_memory();
    let disks = json!([
        7,
        { "used_bytes": 1, "total_bytes": 2 },
        { "mount_point": "/", "used_bytes": "x", "total_bytes": 2 },
        { "mount_point": "/ok", "used_bytes": 1, "total_bytes": 2 },
    ]);
    write_metric(&mut store, "a", 1000, "disk", disks);

    assert_eq!(names(&query(&store, "a", "disk.usage", 8)), ["/ok"]);
}

#[test]
fn text_where_a_number_is_expected_is_skipped() {
    // JSON can't carry NaN or infinity, so these arrive as text if at all.
    let mut store = in_memory();
    for (time_ms, usage) in [
        (1000, json!("NaN")),
        (2000, json!("inf")),
        (3000, json!(5.0)),
    ] {
        write_metric(
            &mut store,
            "a",
            time_ms,
            "cpu",
            json!({ "usage_percent": usage }),
        );
    }

    let result = query(&store, "a", "cpu.usage", 8);

    assert_eq!(averages(&result.series[0]), [5.0]);
}

#[test]
fn numbers_too_large_to_add_up_are_skipped() {
    let mut store = in_memory();
    for (time_ms, usage) in [(1000, 1.7e308), (2000, 1.7e308), (3000, 5.0)] {
        let data = json!({ "usage_percent": usage });
        write_metric(&mut store, "a", time_ms, "cpu", data);
    }

    let result = query(&store, "a", "cpu.usage", 8);

    assert_eq!(averages(&result.series[0]), [5.0]);
}

#[test]
fn a_query_only_sees_its_agent_and_its_time_range() {
    let mut store = in_memory();
    let cpu = || json!({ "usage_percent": 1.0 });
    write_metric(&mut store, "a", 1000, "cpu", cpu());
    write_metric(&mut store, "b", 1000, "cpu", cpu());
    write_metric(&mut store, "a", HOUR_MS as u64, "cpu", cpu());

    let result = query(&store, "a", "cpu.usage", 8);

    assert_eq!(result.series[0].points.len(), 1);
    assert_eq!(
        query(&store, "' OR 1=1 --", "cpu.usage", 8),
        SeriesResult::default()
    );
}

#[test]
fn only_the_highest_series_are_kept_and_the_rest_are_counted() {
    let mut store = in_memory();
    let disks: Vec<Value> = (0..12)
        .map(|index| {
            json!({ "mount_point": format!("/{index:02}"), "used_bytes": index, "total_bytes": 100 })
        })
        .collect();
    write_metric(&mut store, "a", 1000, "disk", Value::Array(disks));

    let result = query(&store, "a", "disk.usage", 3);

    assert_eq!(names(&result), ["/09", "/10", "/11"]);
    assert_eq!(result.hidden, 9);
}

#[test]
fn last_samples_give_each_agents_newest_time_from_any_collector() {
    let mut store = in_memory();
    let cpu = || json!({ "usage_percent": 1.0 });
    write_metric(&mut store, "a", 1000, "cpu", cpu());
    write_metric(&mut store, "a", 2000, "memory", json!({ "used_bytes": 1 }));
    write_metric(&mut store, "b", 1500, "cpu", cpu());

    let mut last = store.reader().unwrap().last_samples(0, 5000).unwrap();
    last.sort_by_key(|sample| sample.agent_id.clone());

    assert_eq!(
        last,
        [
            LastSample {
                agent_id: "a".to_string(),
                time_ms: 2000
            },
            LastSample {
                agent_id: "b".to_string(),
                time_ms: 1500
            },
        ]
    );
}

#[test]
fn last_samples_ignore_what_is_outside_their_window() {
    let mut store = in_memory();
    let cpu = || json!({ "usage_percent": 1.0 });
    write_metric(&mut store, "old", 1000, "cpu", cpu());
    write_metric(&mut store, "now", 5000, "cpu", cpu());
    write_metric(&mut store, "future", 9000, "cpu", cpu());

    let last = store.reader().unwrap().last_samples(2000, 8000).unwrap();

    assert_eq!(last.len(), 1);
    assert_eq!(last[0].agent_id, "now");
}

#[test]
fn the_latest_output_keeps_text_and_whole_numbers_as_they_were_sent() {
    let mut store = in_memory();
    let old = json!([{ "name": "site", "kind": "http", "up": 1 }]);
    write_metric(&mut store, "a", 1000, "checks", old);
    let checks = json!([
        {
            "name": "site", "kind": "http", "up": 0, "error": "<refused>",
            "status": 503, "cert_days_left": -2, "response_ms": 12.5,
            "protocol": "HTTP/2", "cert_valid": false,
        },
        { "name": "dns", "kind": "dns", "up": 1 },
    ]);
    write_metric(&mut store, "a", 2000, "checks", checks);

    let output = latest_output(&store, "a", "checks").unwrap();

    assert_eq!(
        output,
        json!([
            {
                "name": "site", "kind": "http", "up": 0, "error": "<refused>",
                "status": 503, "cert_days_left": -2, "response_ms": 12.5,
                "protocol": "HTTP/2", "cert_valid": false,
            },
            { "name": "dns", "kind": "dns", "up": 1 },
        ])
    );
    assert_eq!(output[0]["status"].as_u64(), Some(503));
}

#[test]
fn the_latest_output_of_one_thing_is_an_object() {
    let mut store = in_memory();
    write_metric(&mut store, "a", 1000, "host", json!({ "uptime_secs": 90 }));

    let output = latest_output(&store, "a", "host").unwrap();

    assert_eq!(output, json!({ "uptime_secs": 90 }));
}

#[test]
fn the_latest_output_is_only_ever_this_agents_and_recent() {
    let mut store = in_memory();
    let custom = |name| json!([{ "name": name, "ok": 1, "value": 1.5 }]);
    write_metric(&mut store, "a", 1000, "custom", custom("mine"));
    write_metric(&mut store, "b", 2000, "custom", custom("theirs"));
    write_metric(&mut store, "a", 20_000, "custom", custom("too new"));

    let output = latest_output(&store, "a", "custom").unwrap();

    assert_eq!(output[0]["name"], "mine");
    assert_eq!(output[0]["value"], 1.5);
    assert_eq!(latest_output(&store, "c", "custom"), None);
    assert_eq!(latest_output(&store, "a", "nonsense"), None);
}

#[test]
fn reads_see_writes_and_work_while_writes_continue() {
    let mut store = in_memory();
    let reader = store.reader().unwrap();

    let reads = std::thread::spawn(move || {
        for _ in 0..200 {
            reader.last_samples(0, HOUR_MS).unwrap();
        }
        reader
    });
    for time_ms in 0..200 {
        write_metric(
            &mut store,
            "a",
            time_ms,
            "cpu",
            json!({ "usage_percent": 1.0 }),
        );
    }
    let reader = reads.join().unwrap();

    assert_eq!(reader.last_samples(0, HOUR_MS).unwrap()[0].time_ms, 199);
}

#[test]
fn newest_gives_each_agents_latest_value() {
    let mut store = in_memory();
    write_metric(
        &mut store,
        "a",
        1000,
        "cpu",
        json!({ "usage_percent": 10.0 }),
    );
    write_metric(
        &mut store,
        "a",
        2000,
        "cpu",
        json!({ "usage_percent": 20.0 }),
    );
    write_metric(
        &mut store,
        "b",
        1500,
        "cpu",
        json!({ "usage_percent": 30.0 }),
    );

    assert_eq!(
        values(&newest(&store, "cpu.usage", 0, HOUR_MS)),
        [("a", "CPU", 2000, 20.0), ("b", "CPU", 1500, 30.0)]
    );
}

#[test]
fn newest_keeps_each_series_apart() {
    let mut store = in_memory();
    let disk = |used: u64| {
        json!([
            { "mount_point": "/", "total_bytes": 100, "used_bytes": used },
            { "mount_point": "/data", "total_bytes": 100, "used_bytes": 50 },
        ])
    };
    write_metric(&mut store, "a", 1000, "disk", disk(10));
    write_metric(&mut store, "a", 2000, "disk", disk(20));

    assert_eq!(
        values(&newest(&store, "disk.usage", 0, HOUR_MS)),
        [("a", "/", 2000, 20.0), ("a", "/data", 2000, 50.0)]
    );
}

#[test]
fn newest_ignores_samples_outside_its_window() {
    let mut store = in_memory();
    write_metric(
        &mut store,
        "a",
        1000,
        "cpu",
        json!({ "usage_percent": 10.0 }),
    );
    write_metric(
        &mut store,
        "a",
        2000,
        "cpu",
        json!({ "usage_percent": 20.0 }),
    );
    write_metric(
        &mut store,
        "a",
        3000,
        "cpu",
        json!({ "usage_percent": 30.0 }),
    );

    assert_eq!(
        values(&newest(&store, "cpu.usage", 1500, 2500)),
        [("a", "CPU", 2000, 20.0)]
    );
}

#[test]
fn newest_turns_counts_into_rates_per_agent() {
    let mut store = in_memory();
    let count = |bytes: u64| json!({ "en0": { "received_bytes": bytes } });
    write_metric(&mut store, "a", 10_000, "network", count(1000));
    write_metric(&mut store, "a", 20_000, "network", count(5000));
    // Sampled between the other agent's, which mustn't affect its rate.
    write_metric(&mut store, "b", 15_000, "network", count(100));
    write_metric(&mut store, "b", 16_000, "network", count(100));

    assert_eq!(
        values(&newest(&store, "network.received", 0, HOUR_MS)),
        [("a", "en0", 20_000, 500.0), ("b", "en0", 16_000, 100.0)]
    );
}

#[test]
fn newest_needs_two_samples_for_a_rate() {
    let mut store = in_memory();
    let data = json!({ "en0": { "received_bytes": 1000 } });
    write_metric(&mut store, "a", 10_000, "network", data);

    assert!(newest(&store, "network.received", 0, HOUR_MS).is_empty());
}

#[test]
fn newest_skips_values_that_are_not_usable_numbers() {
    let mut store = in_memory();
    write_metric(
        &mut store,
        "a",
        1000,
        "cpu",
        json!({ "usage_percent": 10.0 }),
    );
    write_metric(
        &mut store,
        "a",
        2000,
        "cpu",
        json!({ "usage_percent": "lots" }),
    );
    write_metric(
        &mut store,
        "a",
        3000,
        "cpu",
        json!({ "usage_percent": 1.7e308 }),
    );
    write_metric(&mut store, "b", 1000, "cpu", json!({ "other": 1 }));

    assert_eq!(
        values(&newest(&store, "cpu.usage", 0, HOUR_MS)),
        [("a", "CPU", 1000, 10.0)]
    );
}

#[test]
fn newest_handles_names_agents_choose() {
    let mut store = in_memory();
    let count = |bytes: u64| json!({ "eth0.100": { "received_bytes": bytes } });
    write_metric(&mut store, "a", 10_000, "network", count(100));
    write_metric(&mut store, "a", 20_000, "network", count(100));

    let readings = newest(&store, "network.received", 0, HOUR_MS);
    assert_eq!(readings[0].series, "eth0.100");
}

#[test]
fn process_metrics_keep_each_watched_name_apart() {
    let mut store = in_memory();
    let data = json!([
        { "name": "nginx", "count": 3, "cpu_percent": 1.5, "memory_percent": 2.5 },
        { "name": "postgres", "count": 0, "cpu_percent": 0.0, "memory_percent": 0.0 },
    ]);
    write_metric(&mut store, "a", 1000, "processes", data);

    assert_eq!(
        values(&newest(&store, "process.count", 0, HOUR_MS)),
        [("a", "nginx", 1000, 3.0), ("a", "postgres", 1000, 0.0)]
    );
    assert_eq!(newest(&store, "process.cpu", 0, HOUR_MS)[0].value, 1.5);
    assert_eq!(newest(&store, "process.memory", 0, HOUR_MS)[0].value, 2.5);
    assert_eq!(
        names(&query(&store, "a", "process.count", 10)),
        ["nginx", "postgres"]
    );
}

#[test]
fn cpu_and_memory_detail_read_what_the_agent_sends() {
    let mut store = in_memory();
    let cpu = |switches: u64| {
        json!({
            "time_percent": { "user": 20.0, "system": 5.0, "iowait": 7.5, "idle": 67.5 },
            "context_switches": switches,
        })
    };
    write_metric(&mut store, "a", 1000, "cpu", cpu(100));
    write_metric(&mut store, "a", 11_000, "cpu", cpu(500));
    let memory = json!({
        "detail": { "active_bytes": 2048, "free_bytes": 1024 },
        "swap_in_pages": 30,
    });
    write_metric(&mut store, "a", 1000, "memory", memory);

    let time = newest(&store, "cpu.time", 0, HOUR_MS);
    let reading = |name: &str| time.iter().find(|r| r.series == name).map(|r| r.value);
    assert_eq!(reading("User"), Some(20.0));
    assert_eq!(reading("I/O wait"), Some(7.5));
    assert_eq!(reading("Interrupt"), None);

    let rate = query(&store, "a", "cpu.context_switches", 10);
    assert_eq!(rate.series[0].points.last().unwrap().avg, 50.0);

    let detail = newest(&store, "memory.detail", 0, HOUR_MS);
    assert_eq!(
        values(&detail),
        [("a", "Active", 1000, 2048.0), ("a", "Free", 1000, 1024.0)]
    );
    assert_eq!(names(&query(&store, "a", "memory.detail", 10)).len(), 2);
}

#[test]
fn limits_and_sessions_read_what_the_agent_sends() {
    let mut store = in_memory();
    let data = json!({
        "open_files": 250, "max_open_files": 1000,
        "processes": 1024, "max_processes": 4096, "login_sessions": 2,
        "threads": 3000, "max_threads": 30000,
    });
    write_metric(&mut store, "a", 1000, "system", data);

    assert_eq!(
        newest(&store, "system.open_files_used", 0, HOUR_MS)[0].value,
        25.0
    );
    assert_eq!(
        newest(&store, "system.processes_used", 0, HOUR_MS)[0].value,
        25.0
    );
    assert_eq!(
        newest(&store, "system.threads_used", 0, HOUR_MS)[0].value,
        10.0
    );
    assert_eq!(newest(&store, "system.sessions", 0, HOUR_MS)[0].value, 2.0);
    assert_eq!(
        names(&query(&store, "a", "system.open_files", 10)),
        ["Limit", "Open"]
    );
}

#[test]
fn a_broken_custom_metric_has_no_value_but_can_be_alerted_on() {
    let mut store = in_memory();
    let data = json!([
        { "name": "queue", "ok": 1, "value": 12.5 },
        { "name": "broken", "ok": 0, "error": "timed out" },
    ]);
    write_metric(&mut store, "a", 1000, "custom", data);

    assert_eq!(
        values(&newest(&store, "custom.value", 0, HOUR_MS)),
        [("a", "queue", 1000, 12.5)]
    );
    assert_eq!(
        values(&newest(&store, "custom.ok", 0, HOUR_MS)),
        [("a", "broken", 1000, 0.0), ("a", "queue", 1000, 1.0)]
    );
}

#[test]
fn a_platform_without_a_limit_reports_no_percentage() {
    let mut store = in_memory();
    let data = json!({ "open_files": null, "max_open_files": null, "login_sessions": 1 });
    write_metric(&mut store, "a", 1000, "system", data);
    assert!(newest(&store, "system.open_files_used", 0, HOUR_MS).is_empty());
}

#[test]
fn new_metrics_read_what_the_agent_sends() {
    let mut store = in_memory();
    let disk = |read: u64| {
        json!([{
            "mount_point": "/", "read_bytes": read, "written_bytes": 500,
            "inodes_total": 1000, "inodes_used": 250,
        }])
    };
    write_metric(&mut store, "a", 10_000, "disk", disk(0));
    write_metric(&mut store, "a", 20_000, "disk", disk(1000));
    let network = |packets: u64| {
        json!({ "en0": {
            "packets_received": packets, "packets_transmitted": 20, "receive_errors": 5,
            "transmit_errors": 0, "link_up": 1,
        } })
    };
    write_metric(&mut store, "a", 10_000, "network", network(0));
    write_metric(&mut store, "a", 20_000, "network", network(50));
    let sensors = json!([{ "label": "CPU die", "celsius": 54.5 }]);
    write_metric(&mut store, "a", 20_000, "sensors", sensors);
    let checks = json!([
        {
            "name": "site", "up": 1, "response_ms": 12.5, "cert_days_left": 30,
            "first_byte_ms": 8.0, "dns_ms": 1.0, "connect_ms": 2.0, "tls_ms": 3.0,
            "download_ms": 4.0, "content_length": 512, "status": 200,
            "records": 2, "packet_loss_percent": 20.0,
        },
        { "name": "db", "up": 0, "error": "couldn't connect" },
    ]);
    write_metric(&mut store, "a", 20_000, "checks", checks);
    let services = json!([{ "name": "nginx", "running": 1, "state": "active" }]);
    write_metric(&mut store, "a", 20_000, "services", services);
    let files = json!([
        { "path": "/b", "exists": 1, "size_bytes": 2048, "age_secs": 60.0 },
        { "path": "/gone", "exists": 0 },
        { "path": "/nfs", "error": "timed out" },
    ]);
    write_metric(&mut store, "a", 20_000, "files", files);

    let value = |metric: &str, series: &str| {
        let readings = newest(&store, metric, 0, HOUR_MS);
        let found = readings.iter().find(|r| r.series == series);
        found.map(|r| r.value)
    };
    assert_eq!(value("disk.read", "/"), Some(100.0));
    assert_eq!(value("disk.written", "/"), Some(50.0));
    assert_eq!(value("disk.inodes", "/"), Some(25.0));
    assert_eq!(value("network.packets.received", "en0"), Some(5.0));
    assert_eq!(value("network.packets.transmitted", "en0"), Some(2.0));
    assert_eq!(value("network.errors.received", "en0"), Some(0.5));
    assert_eq!(value("network.errors.transmitted", "en0"), Some(0.0));
    assert_eq!(value("network.link", "en0"), Some(1.0));
    assert_eq!(value("sensor.temperature", "CPU die"), Some(54.5));
    assert_eq!(value("check.up", "site"), Some(1.0));
    assert_eq!(value("check.up", "db"), Some(0.0));
    assert_eq!(value("check.response", "site"), Some(12.5));
    assert_eq!(
        value("check.response", "db"),
        None,
        "a failed check has no time"
    );
    assert_eq!(value("check.cert_days", "site"), Some(30.0));
    assert_eq!(value("check.first_byte", "site"), Some(8.0));
    assert_eq!(value("check.dns", "site"), Some(1.0));
    assert_eq!(value("check.connect", "site"), Some(2.0));
    assert_eq!(value("check.tls", "site"), Some(3.0));
    assert_eq!(value("check.download", "site"), Some(4.0));
    assert_eq!(value("check.size", "site"), Some(512.0));
    assert_eq!(value("check.status", "site"), Some(200.0));
    assert_eq!(value("check.records", "site"), Some(2.0));
    assert_eq!(value("check.packet_loss", "site"), Some(20.0));
    assert_eq!(value("service.running", "nginx"), Some(1.0));
    assert_eq!(value("file.exists", "/b"), Some(1.0));
    assert_eq!(value("file.exists", "/gone"), Some(0.0));
    assert_eq!(
        value("file.exists", "/nfs"),
        None,
        "a timeout isn't an answer"
    );
    assert_eq!(value("file.size", "/b"), Some(2048.0));
    assert_eq!(value("file.age", "/b"), Some(60.0));
}

#[test]
fn every_metric_can_be_read_across_agents() {
    let store = in_memory();
    for metric in METRICS {
        assert!(
            newest(&store, metric.name, 0, HOUR_MS).is_empty(),
            "{}",
            metric.name
        );
    }
}


#[test]
fn machines_are_combined_into_one_line() {
    let store = three_machines();
    let everyone = [("a", "All"), ("b", "All"), ("c", "All")];

    for (calculation, expected) in [
        (Calculation::Avg, 40.0),
        (Calculation::Sum, 120.0),
        (Calculation::Min, 10.0),
        (Calculation::Max, 80.0),
        (Calculation::Count, 3.0),
    ] {
        let result = calculate(&store, "cpu.usage", calculation, &everyone, false);
        assert_eq!(result.series.len(), 1);
        assert_eq!(result.series[0].name, "All");
        assert_eq!(line(&result.series[0]), [expected], "{calculation:?}");
    }
}

#[test]
fn machines_can_be_grouped_into_a_line_each() {
    let store = three_machines();
    let members = [("a", "web"), ("b", "web"), ("c", "db")];

    let result = calculate(&store, "cpu.usage", Calculation::Avg, &members, false);

    assert_eq!(result.series[0].name, "db");
    assert_eq!(line(&result.series[0]), [80.0]);
    assert_eq!(result.series[1].name, "web");
    assert_eq!(line(&result.series[1]), [20.0]);
}

#[test]
fn only_the_machines_asked_for_count() {
    let store = three_machines();
    let result = calculate(&store, "cpu.usage", Calculation::Sum, &[("a", "x")], false);
    assert_eq!(line(&result.series[0]), [10.0]);
}

#[test]
fn a_machine_nothing_has_been_heard_from_is_left_out() {
    let store = three_machines();
    let result = calculate(
        &store,
        "cpu.usage",
        Calculation::Sum,
        &[("nobody", "x")],
        false,
    );
    assert!(result.series.is_empty());
}

#[test]
fn a_metrics_own_series_can_each_have_a_line() {
    let mut store = in_memory();
    let disks = |used: f64| {
        json!([
            { "mount_point": "/", "used_bytes": used, "total_bytes": 100.0 },
            { "mount_point": "/data", "used_bytes": 50.0, "total_bytes": 100.0 },
        ])
    };
    write_metric(&mut store, "a", 1000, "disk", disks(10.0));
    write_metric(&mut store, "b", 1000, "disk", disks(30.0));

    let members = [("a", "All"), ("b", "All")];
    let result = calculate(&store, "disk.usage", Calculation::Avg, &members, true);

    assert_eq!(result.series[0].name, "/");
    assert_eq!(line(&result.series[0]), [20.0]);
    assert_eq!(result.series[1].name, "/data");
    assert_eq!(line(&result.series[1]), [50.0]);
}

#[test]
fn a_metrics_different_measures_are_not_mixed_together() {
    let mut store = in_memory();
    let load =
        |one: f64| json!({ "load_average": { "one": one, "five": 100.0, "fifteen": 200.0 } });
    write_metric(&mut store, "a", 1000, "cpu", load(1.0));
    write_metric(&mut store, "b", 1000, "cpu", load(3.0));
    let everyone = [("a", "All"), ("b", "All")];

    let main_line = calculate(&store, "cpu.load", Calculation::Avg, &everyone, false);
    assert_eq!(line(&main_line.series[0]), [2.0]);

    let each_line = calculate(&store, "cpu.load", Calculation::Avg, &everyone, true);
    assert_eq!(each_line.series.len(), 3);
}

#[test]
fn machines_reporting_at_different_moments_still_add_up() {
    let mut store = in_memory();
    for (agent, time, usage) in [("a", 10_000, 10.0), ("b", 40_000, 30.0)] {
        write_metric(
            &mut store,
            agent,
            time,
            "cpu",
            json!({ "usage_percent": usage }),
        );
    }

    let everyone = [("a", "All"), ("b", "All")];
    let sum = calculate(&store, "cpu.usage", Calculation::Sum, &everyone, false);
    let count = calculate(&store, "cpu.usage", Calculation::Count, &everyone, false);

    assert_eq!(line(&sum.series[0]), [40.0]);
    assert_eq!(line(&count.series[0]), [2.0]);
}

#[test]
fn a_moment_still_filling_up_is_left_out() {
    let mut store = in_memory();
    for agent in ["a", "b"] {
        write_metric(
            &mut store,
            agent,
            10_000,
            "cpu",
            json!({ "usage_percent": 10.0 }),
        );
    }
    write_metric(
        &mut store,
        "a",
        70_000,
        "cpu",
        json!({ "usage_percent": 10.0 }),
    );

    let query = CalculationQuery {
        metric: find("cpu.usage").unwrap(),
        range: TimeRange::new(0, 90_000).unwrap(),
        calculation: Calculation::Sum,
        members: ["a", "b"]
            .iter()
            .map(|agent_id| Member {
                agent_id: agent_id.to_string(),
                group: "All".to_string(),
            })
            .collect(),
        by_series: false,
        max_lines: 8,
    };
    let result = store.reader().unwrap().calculate(&query).unwrap();

    // Only "a" has reported in the second minute so far, which isn't a fall by half.
    assert_eq!(line(&result.series[0]), [20.0]);
}

#[test]
fn a_sample_stored_twice_does_not_change_a_sum() {
    let mut store = three_machines();
    write_metric(
        &mut store,
        "a",
        1000,
        "cpu",
        json!({ "usage_percent": 10.0 }),
    );

    let everyone = [("a", "All"), ("b", "All"), ("c", "All")];
    let result = calculate(&store, "cpu.usage", Calculation::Sum, &everyone, false);

    assert_eq!(line(&result.series[0]), [120.0]);
}

#[test]
fn the_highest_lines_are_kept_when_there_are_too_many() {
    let mut store = in_memory();
    let mut members = Vec::new();
    for number in 0..10 {
        let (agent, usage) = (format!("agent-{number}"), f64::from(number));
        write_metric(
            &mut store,
            &agent,
            1000,
            "cpu",
            json!({ "usage_percent": usage }),
        );
        members.push(agent);
    }

    let members: Vec<(&str, &str)> = members.iter().map(|a| (a.as_str(), a.as_str())).collect();
    let result = calculate(&store, "cpu.usage", Calculation::Avg, &members, false);

    assert_eq!(result.series.len(), 8);
    assert_eq!(result.hidden, 2);
    assert!(!result.series.iter().any(|series| series.name == "agent-0"));
}

#[test]
fn rates_are_worked_out_per_machine_before_being_combined() {
    let mut store = in_memory();
    for (agent, per_sample) in [("a", 10.0), ("b", 30.0)] {
        for time in [10_000, 20_000] {
            let eth = json!({ "eth0": { "received_bytes": per_sample } });
            write_metric(&mut store, agent, time, "network", eth);
        }
    }

    let everyone = [("a", "All"), ("b", "All")];
    let result = calculate(
        &store,
        "network.received",
        Calculation::Sum,
        &everyone,
        false,
    );

    // 10 and 30 bytes over 10 seconds.
    assert_eq!(line(&result.series[0]), [4.0]);
}

#[test]
fn series_are_counted_once_however_often_they_report() {
    let mut store = in_memory();
    let reader = store.reader().unwrap();
    assert_eq!(reader.series_count().unwrap(), 0);

    for time in [1000, 2000] {
        let cpu = json!({ "usage_percent": 1.0, "load": 2.0 });
        write_metric(&mut store, "a", time, "cpu", cpu);
    }

    assert_eq!(reader.series_count().unwrap(), 2);
}

#[test]
fn stats_work_on_an_empty_database() {
    let stats = in_memory().reader().unwrap().stats(0).unwrap();
    assert!(stats.collectors.is_empty());
}

#[test]
fn something_no_longer_reported_is_left_out_of_the_latest_output() {
    let mut store = in_memory();
    let failing = json!([
        { "name": "a", "up": 0, "error": "refused" },
        { "name": "b", "up": 1 },
    ]);
    write_metric(&mut store, "a", 1000, "checks", failing);
    write_metric(
        &mut store,
        "a",
        2000,
        "checks",
        json!([{ "name": "b", "up": 1 }]),
    );

    let output = latest_output(&store, "a", "checks").unwrap();

    assert_eq!(output, json!([{ "name": "b", "up": 1 }]));
}

#[test]
fn names_with_quotes_in_them_come_back_unharmed() {
    let mut store = in_memory();
    let odd = "it's a \\ test' OR '1'='1";
    write_metric(&mut store, "a", 1000, "disk", json!([{ "mount_point": odd, "used_bytes": 5, "total_bytes": 10 }]));

    let result = query(&store, "a", "disk.usage", 8);

    assert_eq!(names(&result), [odd]);
}

#[test]
fn deleting_an_agent_removes_everything_it_sent_and_nothing_else() {
    let mut store = in_memory();
    for agent in ["gone", "kept"] {
        write_metric(&mut store, agent, 1000, "cpu", json!({ "usage_percent": 5.0 }));
        let checks = json!([{ "name": "site", "kind": "http", "up": 0, "error": "refused" }]);
        write_metric(&mut store, agent, 2000, "checks", checks);
    }
    // Into the sorted table too, for a store that has one, as the hour is over.
    while store.tidy(2 * HOUR_MS).unwrap() {}
    write_metric(&mut store, "gone", HOUR_MS as u64 + 1000, "cpu", json!({ "usage_percent": 6.0 }));

    store.delete_agent("gone").unwrap();

    assert!(query(&store, "gone", "cpu.usage", 8).series.is_empty());
    assert_eq!(latest_output(&store, "gone", "checks"), None);
    let reader = store.reader().unwrap();
    let agents: Vec<String> = reader
        .last_samples(0, 9000)
        .unwrap()
        .into_iter()
        .map(|last| last.agent_id)
        .collect();
    assert_eq!(agents, ["kept"]);
    assert_eq!(averages(&query(&store, "kept", "cpu.usage", 8).series[0]), [5.0]);
    assert!(latest_output(&store, "kept", "checks").is_some());

    // Deleting what isn't there does nothing.
    store.delete_agent("gone").unwrap();
    store.delete_agent("never-here").unwrap();
}

#[test]
fn a_deleted_agent_starts_afresh_and_new_agents_keep_to_themselves() {
    let mut store = in_memory();
    for agent in ["gone", "kept"] {
        write_metric(&mut store, agent, 1000, "cpu", json!({ "usage_percent": 5.0 }));
    }
    store.delete_agent("gone").unwrap();

    write_metric(&mut store, "new", 2000, "cpu", json!({ "usage_percent": 7.0 }));
    write_metric(&mut store, "gone", 3000, "cpu", json!({ "usage_percent": 9.0 }));

    assert_eq!(averages(&query(&store, "kept", "cpu.usage", 8).series[0]), [5.0]);
    assert_eq!(averages(&query(&store, "new", "cpu.usage", 8).series[0]), [7.0]);
    assert_eq!(averages(&query(&store, "gone", "cpu.usage", 8).series[0]), [9.0]);
}

fn trends(store: &TestStore, metric: &str, since: i64, until: i64) -> Vec<Trend> {
    store
        .reader()
        .unwrap()
        .trends(find(metric).unwrap(), since, until)
        .unwrap()
}

#[test]
fn trends_fit_a_line_through_each_series() {
    let mut store = in_memory();
    let minute = 60_000;
    // The root disk fills a percent a minute, give or take, and /data doesn't change.
    for (i, used) in [10, 12, 11, 13, 14].into_iter().enumerate() {
        let disks = json!([
            { "mount_point": "/", "total_bytes": 100, "used_bytes": used },
            { "mount_point": "/data", "total_bytes": 100, "used_bytes": 50 },
        ]);
        write_metric(&mut store, "a", minute * (i as u64 + 1), "disk", disks);
    }
    write_metric(
        &mut store,
        "b",
        minute,
        "disk",
        json!([{ "mount_point": "/", "total_bytes": 100, "used_bytes": 90 }]),
    );
    write_metric(
        &mut store,
        "b",
        3 * minute,
        "disk",
        json!([{ "mount_point": "/", "total_bytes": 100, "used_bytes": 80 }]),
    );

    let found = trends(&store, "disk.usage", 0, HOUR_MS);
    let summary: Vec<(&str, &str, i64, f64, i64, u64)> = found
        .iter()
        .map(|t| {
            let value = (t.value * 1e6).round() / 1e6;
            (t.agent_id.as_str(), t.series.as_str(), t.time_ms, value, t.first_ms, t.samples)
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("a", "/", 5 * 60_000, 14.0, 60_000, 5),
            ("a", "/data", 5 * 60_000, 50.0, 60_000, 5),
            ("b", "/", 3 * 60_000, 80.0, 60_000, 2),
        ]
    );
    // Least squares through 10, 12, 11, 13, 14 a minute apart is 0.9 a minute.
    let per_minute = |trend: &Trend| trend.slope_per_ms * 60_000.0;
    assert!((per_minute(&found[0]) - 0.9).abs() < 1e-9, "{found:?}");
    assert!(per_minute(&found[1]).abs() < 1e-9, "{found:?}");
    assert!((per_minute(&found[2]) + 5.0).abs() < 1e-9, "{found:?}");
}

#[test]
fn trends_need_two_readings_at_different_times_inside_the_window() {
    let mut store = in_memory();
    let cpu = |percent: f64| json!({ "usage_percent": percent });
    write_metric(&mut store, "a", 1000, "cpu", cpu(10.0));
    write_metric(&mut store, "b", 1000, "cpu", cpu(10.0));
    write_metric(&mut store, "b", 2000, "cpu", cpu(20.0));
    write_metric(&mut store, "b", 3000, "cpu", cpu(90.0));

    // One reading makes no line, and a window with one of b's makes none either.
    assert!(trends(&store, "cpu.usage", 0, 1500).is_empty());
    let found = trends(&store, "cpu.usage", 1500, HOUR_MS);
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].agent_id.as_str(), found[0].samples), ("b", 2));
    assert!((found[0].slope_per_ms - 0.07).abs() < 1e-9, "{found:?}");
}

// ---- Rollups and how long things are kept

const RECENT_DAY_MS: i64 = 86_400_000;

/// The start of an hour this many hours before the current one, so charts read it
/// as they would any recent data.
fn hours_ago(hours: i64) -> i64 {
    crate::store::rollups::hour_of(crate::metrics::now_ms()) - hours * HOUR_MS
}

fn settle(store: &mut TestStore, now_ms: i64) {
    while store.tidy(now_ms).unwrap() {}
}

fn retention(full_days: i64, five_minute_days: i64, hour_days: Option<i64>) -> Retention {
    Retention {
        full_ms: full_days * RECENT_DAY_MS,
        five_minute_ms: five_minute_days * RECENT_DAY_MS,
        hour_ms: hour_days.map(|days| days * RECENT_DAY_MS),
    }
}

/// A chart of one agent, at a step chosen rather than worked out from the range.
fn chart_of(
    store: &TestStore,
    agent_id: &str,
    metric: &str,
    (from_ms, to_ms): (i64, i64),
    step_ms: i64,
) -> SeriesResult {
    store
        .reader()
        .unwrap()
        .series(&SeriesQuery {
            agent_id,
            metric: find(metric).unwrap(),
            range: TimeRange {
                from_ms,
                to_ms,
                step_ms,
            },
            max_series: 8,
        })
        .unwrap()
}

/// CPU every 15 seconds for `minutes`, at `percent` except where `spikes` say.
fn cpu_from(
    store: &mut TestStore,
    agent: &str,
    start_ms: i64,
    minutes: i64,
    percent: f64,
    spikes: &[(i64, f64)],
) {
    for index in 0..minutes * 4 {
        let time = start_ms + index * 15_000;
        let value = spikes
            .iter()
            .find(|(at, _)| *at == time)
            .map_or(percent, |(_, spike)| *spike);
        write_metric(store, agent, time as u64, "cpu", json!({ "usage_percent": value }));
    }
}

fn high_avg_low(point: &Point) -> (f64, f64, f64) {
    (point.max, point.avg, point.min)
}

#[test]
fn a_spike_outlasts_its_samples_in_the_rollups() {
    let mut store = with_retention(retention(2, 4, None));
    let start = hours_ago(72);
    let spike = start + 30 * 60_000;
    cpu_from(&mut store, "a", start, 120, 10.0, &[(spike, 100.0)]);

    settle(&mut store, crate::metrics::now_ms());

    // The samples themselves are gone, as they're older than two days.
    assert!(newest(&store, "cpu.usage", start, start + 2 * HOUR_MS).is_empty());
    let hours = chart_of(&store, "a", "cpu.usage", (start, start + 2 * HOUR_MS), HOUR_MS);
    let points = &hours.series[0].points;
    assert_eq!(points.len(), 2);
    let (high, avg, low) = high_avg_low(&points[0]);
    assert_eq!((high, low), (100.0, 10.0));
    assert!((avg - (239.0 * 10.0 + 100.0) / 240.0).abs() < 1e-9, "{avg}");
    assert_eq!(high_avg_low(&points[1]), (10.0, 10.0, 10.0));

    // Every 5 minutes is still kept, so a close look finds when it happened.
    let spans = chart_of(&store, "a", "cpu.usage", (start, start + HOUR_MS), 15_000);
    let points = &spans.series[0].points;
    assert_eq!(points.len(), 12);
    let peak = points.iter().find(|point| point.max == 100.0).unwrap();
    assert_eq!(peak.time_ms, spike);
    assert_eq!(peak.avg, (19.0 * 10.0 + 100.0) / 20.0);
}

#[test]
fn a_burst_keeps_its_peak_rate_once_rolled_up() {
    let mut store = with_retention(retention(2, 4, None));
    let start = hours_ago(72);
    for index in 0..240 {
        let time = start + index * 15_000;
        // 100 bytes a second, and ten seconds' worth at 10 kB a second once.
        let bytes = if index == 100 { 150_000 } else { 1_500 };
        let interfaces = json!({ "en0": { "received_bytes": bytes } });
        write_metric(&mut store, "a", time as u64, "network", interfaces);
    }

    settle(&mut store, crate::metrics::now_ms());

    let hours = chart_of(&store, "a", "network.received", (start, start + HOUR_MS), HOUR_MS);
    let (high, _, low) = high_avg_low(&hours.series[0].points[0]);
    assert_eq!((high, low), (10_000.0, 100.0));
}

#[test]
fn the_newest_hour_is_charted_before_it_is_rolled_up() {
    let mut store = with_retention(Retention::KEEP_EVERYTHING);
    let start = hours_ago(2);
    for (hour, percent) in [(0, 10.0), (1, 20.0), (2, 30.0)] {
        cpu_from(&mut store, "a", start + hour * HOUR_MS, 10, percent, &[]);
    }

    // The two finished hours are rolled up, and the current one can't be yet.
    settle(&mut store, start + 2 * HOUR_MS + 30 * 60_000);

    let chart = chart_of(&store, "a", "cpu.usage", (start, start + 3 * HOUR_MS), HOUR_MS);
    assert_eq!(averages(&chart.series[0]), [10.0, 20.0, 30.0]);
}

#[test]
fn a_sample_that_arrives_late_is_rolled_up_too() {
    let mut store = with_retention(Retention::KEEP_EVERYTHING);
    let start = hours_ago(5);
    cpu_from(&mut store, "a", start, 60, 10.0, &[]);
    settle(&mut store, crate::metrics::now_ms());
    let range = (start, start + HOUR_MS);
    assert_eq!(chart_of(&store, "a", "cpu.usage", range, HOUR_MS).series[0].points[0].max, 10.0);

    // As from an agent that was cut off and sends what it kept once it's back.
    write_metric(&mut store, "a", (start + 20 * 60_000 + 5_000) as u64, "cpu", json!({ "usage_percent": 90.0 }));
    settle(&mut store, crate::metrics::now_ms());

    let point = chart_of(&store, "a", "cpu.usage", range, HOUR_MS).series[0].points[0];
    assert_eq!(point.max, 90.0);
    assert!((point.avg - (240.0 * 10.0 + 90.0) / 241.0).abs() < 1e-9, "{point:?}");
}

#[test]
fn deleting_an_agent_deletes_its_rollups() {
    let mut store = with_retention(Retention::KEEP_EVERYTHING);
    let start = hours_ago(5);
    cpu_from(&mut store, "gone", start, 60, 10.0, &[]);
    cpu_from(&mut store, "kept", start, 60, 20.0, &[]);
    settle(&mut store, crate::metrics::now_ms());

    store.delete_agent("gone").unwrap();

    let range = (start, start + HOUR_MS);
    assert!(chart_of(&store, "gone", "cpu.usage", range, HOUR_MS).series.is_empty());
    assert_eq!(averages(&chart_of(&store, "kept", "cpu.usage", range, HOUR_MS).series[0]), [20.0]);
}

#[test]
fn rollups_go_once_they_are_older_than_they_are_kept() {
    let mut store = with_retention(retention(2, 3, Some(4)));
    let five_days_ago = hours_ago(120);
    let three_and_a_half_days_ago = hours_ago(84);
    cpu_from(&mut store, "a", five_days_ago, 60, 10.0, &[]);
    cpu_from(&mut store, "a", three_and_a_half_days_ago, 60, 20.0, &[]);

    settle(&mut store, crate::metrics::now_ms());

    let gone = (five_days_ago, five_days_ago + HOUR_MS);
    assert!(chart_of(&store, "a", "cpu.usage", gone, HOUR_MS).series.is_empty());
    // Its 5 minute spans are past three days, but its hour is still kept.
    let kept = (three_and_a_half_days_ago, three_and_a_half_days_ago + HOUR_MS);
    let close_look = chart_of(&store, "a", "cpu.usage", kept, 15_000);
    assert_eq!(averages(&close_look.series[0]), [20.0]);
}

#[test]
fn machines_are_combined_from_their_rollups() {
    let mut store = with_retention(Retention::KEEP_EVERYTHING);
    let start = hours_ago(5);
    cpu_from(&mut store, "a", start, 60, 10.0, &[]);
    cpu_from(&mut store, "b", start, 60, 30.0, &[]);
    settle(&mut store, crate::metrics::now_ms());

    let query = CalculationQuery {
        metric: find("cpu.usage").unwrap(),
        range: TimeRange {
            from_ms: start,
            to_ms: start + 2 * HOUR_MS,
            step_ms: HOUR_MS,
        },
        calculation: Calculation::Avg,
        members: ["a", "b"]
            .iter()
            .map(|agent_id| Member {
                agent_id: agent_id.to_string(),
                group: "all".to_string(),
            })
            .collect(),
        by_series: false,
        max_lines: 8,
    };
    let result = store.reader().unwrap().calculate(&query).unwrap();
    assert_eq!(averages(&result.series[0]), [20.0]);
}
