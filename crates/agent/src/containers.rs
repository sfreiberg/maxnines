//! Containers on the host, through Docker's API, which Podman offers too. Reading
//! it needs the agent's user to be allowed Docker's socket, which is as good as root,
//! so the collector is off until a rule turns it on.
//!
//! Each container is named as Docker names it, so one recreated by Compose keeps its
//! history. Its `up` says whether it's doing its job: running and not unhealthy. One
//! that exited cleanly, such as a job that finished or a service stopped on purpose,
//! has no `up`, so stopping something deliberately doesn't alert.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bollard::models::{
    ContainerInspectResponse, ContainerStateStatusEnum, ContainerStatsResponse, ContainerSummary,
    HealthStatusEnum,
};
use bollard::query_parameters::{ListContainersOptionsBuilder, StatsOptionsBuilder};
use bollard::{API_DEFAULT_VERSION, Docker};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use futures_util::future::join_all;
use maxnines_collectors::entries::{Entries, at, percent};
use maxnines_protocol::entries::Entry;
use serde_json::{Map, Value, json};
use tracing::warn;

use crate::background::{Background, Missed};
use crate::collector::Collector;

/// No host needs more than this many charted, and each one is its own series.
const MAX_CONTAINERS: usize = 64;

/// How long one call to Docker can take, in seconds.
const TIMEOUT_SECS: u64 = 10;

/// How long a whole round can take: listing, then reading each container at once,
/// which is inspecting it and then reading its use, so three calls one after another.
/// A Docker that stalls past it gives no containers, rather than the last ones.
const ROUND_LIMIT: Duration = Duration::from_secs(3 * TIMEOUT_SECS);

/// Where Docker and Podman listen, in the order they're tried. `DOCKER_HOST` comes
/// first when it names a socket.
const SOCKETS: [&str; 2] = ["/var/run/docker.sock", "/run/podman/podman.sock"];

pub struct ContainerCollector {
    background: Background,
}

impl ContainerCollector {
    pub fn new(interval: Duration) -> Result<Self> {
        let socket = find_socket(std::env::var("DOCKER_HOST").ok().as_deref());
        let complained = Arc::new(Mutex::new(None::<String>));
        // Each container's CPU time and the host's when last read, to measure use
        // from one read to the next.
        let mut cpu = HashMap::new();
        let mut background = Background::new();
        let told = complained.clone();
        let round = move || {
            let socket = socket.clone();
            let complained = complained.clone();
            async move {
                let read = match &socket {
                    Some(socket) => read_all(socket).await,
                    None => Err(anyhow!(
                        "found no Docker or Podman socket at {}",
                        SOCKETS.join(" or ")
                    )),
                };
                match read {
                    Ok(containers) => {
                        *complained.lock().unwrap_or_else(PoisonError::into_inner) = None;
                        Value::Array(containers)
                    }
                    Err(error) => {
                        complain(&complained, format!("{error:#}"));
                        Value::Null
                    }
                }
            }
        };
        let settle = move |containers: Result<Value, Missed>| {
            // A panic is in the log already.
            if containers == Err(Missed::OutOfTime) {
                let limit = ROUND_LIMIT.as_secs();
                complain(
                    &told,
                    format!("reading them didn't finish within {limit} seconds"),
                );
            }
            let mut containers = containers.unwrap_or_default();
            let mut seen = HashMap::new();
            if let Value::Array(rows) = &mut containers {
                for row in rows {
                    settle_cpu(row, &cpu, &mut seen);
                }
            }
            cpu = seen;
            containers
        };
        background.repeat(interval, Some(ROUND_LIMIT), round, settle)?;
        Ok(Self { background })
    }
}

impl Collector for ContainerCollector {
    fn name(&self) -> &'static str {
        "containers"
    }

    fn collect(&mut self) -> Result<Value> {
        Ok(self.background.latest().pop().unwrap_or_default())
    }

    fn metrics(&self) -> &'static [&'static str] {
        &CONTAINER_METRICS
    }

    fn entries(&self, output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
        container_entries(output, time)
    }
}

/// What was read of each container, as entries. It's apart from the collector so
/// it can be tried without one, which would look for Docker.
fn container_entries(output: &Value, time: DateTime<Utc>) -> Vec<Entry> {
    let mut entries = Entries::at(time);
    let containers = output.as_array().map(Vec::as_slice).unwrap_or_default();
    let named = containers
        .iter()
        .filter_map(|container| Some((container.get("name")?.as_str()?, container)));
    let mut any = false;
    for (name, container) in named {
        any = true;
        let series = [name];
        let of_limit = percent(
            at(container, "memory_bytes"),
            at(container, "memory_limit_bytes"),
        );
        entries.number("container.memory_limit", &series, of_limit);
        for (metric, field) in CONTAINER_FIELDS {
            entries.read(metric, &series, at(container, field));
        }
    }
    // With no containers, or when they couldn't be read, each metric has nothing.
    if !any {
        for metric in CONTAINER_METRICS {
            entries.nothing(metric, &[]);
        }
    }
    entries.done()
}

/// A container's metrics that are read as they are, and what each is read from.
/// What it received, sent, read and wrote are Docker's own running totals since
/// the container started. One that isn't running has only what it is and how it
/// ended.
const CONTAINER_FIELDS: [(&str, &str); 14] = [
    ("container.up", "up"),
    ("container.cpu", "cpu_percent"),
    ("container.memory", "memory_bytes"),
    ("container.memory_limit_bytes", "memory_limit_bytes"),
    ("container.received", "received_bytes"),
    ("container.sent", "sent_bytes"),
    ("container.read", "read_bytes"),
    ("container.written", "written_bytes"),
    ("container.restarts", "restarts"),
    ("container.processes", "processes"),
    ("container.image", "image"),
    ("container.state", "state"),
    ("container.health", "health"),
    ("container.exit_code", "exit_code"),
];

/// Every metric a container has: the one worked out, then those read as they are.
const CONTAINER_METRICS: [&str; 15] = {
    let mut metrics = ["container.memory_limit"; 15];
    let mut at = 0;
    while at < CONTAINER_FIELDS.len() {
        metrics[at + 1] = CONTAINER_FIELDS[at].0;
        at += 1;
    }
    metrics
};

/// Logs why containers can't be read, once for each new reason, as they're read
/// every interval.
fn complain(complained: &Mutex<Option<String>>, error: String) {
    let mut said = complained.lock().unwrap_or_else(PoisonError::into_inner);
    if said.as_deref() != Some(&error) {
        warn!(error, "can't read containers");
        *said = Some(error);
    }
}

/// The socket to use: `DOCKER_HOST` when it names one, else the first that's there.
fn find_socket(docker_host: Option<&str>) -> Option<String> {
    if let Some(path) = docker_host.and_then(|host| host.strip_prefix("unix://")) {
        return Some(path.to_string());
    }
    SOCKETS
        .into_iter()
        .find(|path| Path::new(path).exists())
        .map(str::to_string)
}

async fn read_all(socket: &str) -> Result<Vec<Value>> {
    let docker = Docker::connect_with_unix(socket, TIMEOUT_SECS, API_DEFAULT_VERSION)
        .with_context(|| format!("connecting to {socket}"))?;
    let options = ListContainersOptionsBuilder::new().all(true).build();
    let mut listed = docker
        .list_containers(Some(options))
        .await
        .with_context(|| format!("listing containers through {socket}"))?;
    listed.sort_by_key(name_of);
    listed.truncate(MAX_CONTAINERS);
    let read = listed.iter().map(|summary| read_one(&docker, summary));
    Ok(join_all(read).await.into_iter().flatten().collect())
}

/// What's known about one container. One removed while it was being read is left out.
async fn read_one(docker: &Docker, summary: &ContainerSummary) -> Option<Value> {
    let id = summary.id.as_deref()?;
    let inspected = docker.inspect_container(id, None).await.ok()?;
    let running = inspected.state.as_ref().and_then(|state| state.running) == Some(true);
    let stats = if running {
        let options = StatsOptionsBuilder::new()
            .stream(false)
            .one_shot(true)
            .build();
        docker.stats(id, Some(options)).next().await?.ok()
    } else {
        None
    };
    Some(describe(summary, &inspected, stats.as_ref()))
}

/// Docker gives names with a leading slash.
fn name_of(summary: &ContainerSummary) -> String {
    summary
        .names
        .as_ref()
        .and_then(|names| names.first())
        .map(|name| name.trim_start_matches('/').to_string())
        .or_else(|| {
            summary
                .id
                .as_deref()
                .map(|id| id.chars().take(12).collect())
        })
        .unwrap_or_default()
}

/// Whether it's doing its job. Nothing for one that's never run or exited cleanly,
/// as that's a job finishing or a service stopped on purpose.
fn up(state: &str, exit_code: Option<i64>, health: Option<&str>) -> Option<u8> {
    match state {
        "running" => Some(u8::from(health != Some("unhealthy"))),
        "exited" if exit_code == Some(0) => None,
        "created" | "removing" => None,
        _ => Some(0),
    }
}

/// What it uses, without the files it has cached, as `docker stats` counts it.
fn memory_used(stats: &ContainerStatsResponse) -> Option<u64> {
    let memory = stats.memory_stats.as_ref()?;
    let usage = memory.usage?;
    let cached = memory.stats.as_ref().and_then(|detail| {
        detail
            .get("inactive_file")
            .or_else(|| detail.get("total_inactive_file"))
            .copied()
    });
    Some(usage.saturating_sub(cached.unwrap_or(0)))
}

/// Bytes read and written, across its devices.
fn disk_bytes(stats: &ContainerStatsResponse) -> (u64, u64) {
    let entries = stats
        .blkio_stats
        .as_ref()
        .and_then(|blkio| blkio.io_service_bytes_recursive.as_ref());
    let mut read = 0;
    let mut written = 0;
    for entry in entries.into_iter().flatten() {
        let value = entry.value.unwrap_or(0);
        match entry.op.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("read") => read += value,
            Some("write") => written += value,
            _ => {}
        }
    }
    (read, written)
}

fn describe(
    summary: &ContainerSummary,
    inspected: &ContainerInspectResponse,
    stats: Option<&ContainerStatsResponse>,
) -> Value {
    let state = inspected.state.as_ref();
    let status = state
        .and_then(|state| state.status)
        .unwrap_or(ContainerStateStatusEnum::EMPTY)
        .to_string();
    let health = state
        .and_then(|state| state.health.as_ref())
        .and_then(|health| health.status)
        .filter(|status| !matches!(status, HealthStatusEnum::EMPTY | HealthStatusEnum::NONE))
        .map(|status| status.to_string());
    let exit_code = state.and_then(|state| state.exit_code);

    let mut row = Map::new();
    row.insert("name".into(), json!(name_of(summary)));
    row.insert(
        "image".into(),
        json!(summary.image.clone().unwrap_or_default()),
    );
    row.insert("state".into(), json!(status));
    if let Some(health) = &health {
        row.insert("health".into(), json!(health));
    }
    if let Some(up) = up(&status, exit_code, health.as_deref()) {
        row.insert("up".into(), json!(up));
    }
    if status == "exited" {
        row.insert("exit_code".into(), json!(exit_code));
    }
    row.insert(
        "restarts".into(),
        json!(inspected.restart_count.unwrap_or(0)),
    );

    if let Some(stats) = stats {
        if let Some(cpu) = &stats.cpu_stats {
            let total = cpu.cpu_usage.as_ref().and_then(|usage| usage.total_usage);
            if let (Some(total), Some(system)) = (total, cpu.system_cpu_usage) {
                row.insert("cpu_total".into(), json!(total));
                row.insert("system_total".into(), json!(system));
            }
        }
        if let Some(used) = memory_used(stats) {
            row.insert("memory_bytes".into(), json!(used));
            let limit = stats.memory_stats.as_ref().and_then(|memory| memory.limit);
            if let Some(limit) = limit.filter(|limit| *limit > 0) {
                row.insert("memory_limit_bytes".into(), json!(limit));
                row.insert(
                    "memory_percent".into(),
                    json!(used as f64 * 100.0 / limit as f64),
                );
            }
        }
        if let Some(networks) = &stats.networks {
            let received: u64 = networks.values().filter_map(|n| n.rx_bytes).sum();
            let sent: u64 = networks.values().filter_map(|n| n.tx_bytes).sum();
            row.insert("received_bytes".into(), json!(received));
            row.insert("sent_bytes".into(), json!(sent));
        }
        let (read, written) = disk_bytes(stats);
        row.insert("read_bytes".into(), json!(read));
        row.insert("written_bytes".into(), json!(written));
        if let Some(processes) = stats.pids_stats.as_ref().and_then(|pids| pids.current) {
            row.insert("processes".into(), json!(processes));
        }
    }
    Value::Object(row)
}

/// Swaps a row's CPU totals for the share of the whole host it used since the last
/// read, as other CPU figures are, so one busy core of eight is 12.5%. Docker's
/// host total counts every CPU. The first sample has nothing to compare with.
fn settle_cpu(
    row: &mut Value,
    before: &HashMap<String, (u64, u64)>,
    seen: &mut HashMap<String, (u64, u64)>,
) {
    let Some(fields) = row.as_object_mut() else {
        return;
    };
    let name = fields
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let total = fields.remove("cpu_total").and_then(|v| v.as_u64());
    let system = fields.remove("system_total").and_then(|v| v.as_u64());
    let (Some(total), Some(system)) = (total, system) else {
        return;
    };
    if let Some((total_before, system_before)) = before.get(&name) {
        let used = total.checked_sub(*total_before);
        let passed = system
            .checked_sub(*system_before)
            .filter(|passed| *passed > 0);
        if let (Some(used), Some(passed)) = (used, passed) {
            let percent = used as f64 / passed as f64 * 100.0;
            fields.insert("cpu_percent".into(), json!(percent));
        }
    }
    seen.insert(name, (total, system));
}

#[cfg(test)]
mod tests {
    use bollard::models::{
        ContainerBlkioStatEntry, ContainerBlkioStats, ContainerCpuStats, ContainerCpuUsage,
        ContainerMemoryStats, ContainerNetworkStats, ContainerState, Health,
    };

    use super::*;
    use crate::collector::test_entries::{every_metric_has_an_entry, said, time};

    fn summary(name: &str) -> ContainerSummary {
        ContainerSummary {
            id: Some(format!("{name}-id")),
            names: Some(vec![format!("/{name}")]),
            image: Some("nginx:1.27".to_string()),
            ..ContainerSummary::default()
        }
    }

    fn inspected(
        status: ContainerStateStatusEnum,
        exit_code: i64,
        health: Option<HealthStatusEnum>,
    ) -> ContainerInspectResponse {
        ContainerInspectResponse {
            state: Some(ContainerState {
                status: Some(status),
                running: Some(status == ContainerStateStatusEnum::RUNNING),
                exit_code: Some(exit_code),
                health: health.map(|status| Health {
                    status: Some(status),
                    ..Health::default()
                }),
                ..ContainerState::default()
            }),
            restart_count: Some(3),
            ..ContainerInspectResponse::default()
        }
    }

    fn stats(total: u64, system: u64) -> ContainerStatsResponse {
        ContainerStatsResponse {
            cpu_stats: Some(ContainerCpuStats {
                cpu_usage: Some(ContainerCpuUsage {
                    total_usage: Some(total),
                    ..ContainerCpuUsage::default()
                }),
                system_cpu_usage: Some(system),
                online_cpus: Some(4),
                ..ContainerCpuStats::default()
            }),
            memory_stats: Some(ContainerMemoryStats {
                usage: Some(300),
                limit: Some(1000),
                stats: Some(HashMap::from([("inactive_file".to_string(), 100)])),
                ..ContainerMemoryStats::default()
            }),
            networks: Some(HashMap::from([
                (
                    "eth0".to_string(),
                    ContainerNetworkStats {
                        rx_bytes: Some(10),
                        tx_bytes: Some(20),
                        ..ContainerNetworkStats::default()
                    },
                ),
                (
                    "eth1".to_string(),
                    ContainerNetworkStats {
                        rx_bytes: Some(1),
                        tx_bytes: Some(2),
                        ..ContainerNetworkStats::default()
                    },
                ),
            ])),
            blkio_stats: Some(ContainerBlkioStats {
                io_service_bytes_recursive: Some(vec![
                    ContainerBlkioStatEntry {
                        op: Some("read".to_string()),
                        value: Some(5),
                        ..ContainerBlkioStatEntry::default()
                    },
                    ContainerBlkioStatEntry {
                        op: Some("Write".to_string()),
                        value: Some(7),
                        ..ContainerBlkioStatEntry::default()
                    },
                ]),
                ..ContainerBlkioStats::default()
            }),
            ..ContainerStatsResponse::default()
        }
    }

    #[test]
    fn a_container_is_up_while_it_runs_and_isnt_unhealthy() {
        assert_eq!(up("running", Some(0), None), Some(1));
        assert_eq!(up("running", Some(0), Some("healthy")), Some(1));
        assert_eq!(up("running", Some(0), Some("starting")), Some(1));
        assert_eq!(up("running", Some(0), Some("unhealthy")), Some(0));
        assert_eq!(up("restarting", Some(1), None), Some(0));
        assert_eq!(up("exited", Some(137), None), Some(0));
        assert_eq!(up("dead", None, None), Some(0));
        assert_eq!(up("paused", Some(0), None), Some(0));
        // Done, or stopped on purpose.
        assert_eq!(up("exited", Some(0), None), None);
        assert_eq!(up("created", None, None), None);
    }

    #[test]
    fn a_running_container_reports_what_it_uses() {
        let row = describe(
            &summary("web"),
            &inspected(
                ContainerStateStatusEnum::RUNNING,
                0,
                Some(HealthStatusEnum::HEALTHY),
            ),
            Some(&stats(500, 10_000)),
        );
        assert_eq!(row["name"], "web");
        assert_eq!(row["image"], "nginx:1.27");
        assert_eq!(row["state"], "running");
        assert_eq!(row["health"], "healthy");
        assert_eq!(row["up"], 1);
        assert_eq!(row["restarts"], 3);
        assert_eq!(row["memory_bytes"], 200);
        assert_eq!(row["memory_limit_bytes"], 1000);
        assert_eq!(row["memory_percent"], 20.0);
        assert_eq!(row["received_bytes"], 11);
        assert_eq!(row["sent_bytes"], 22);
        assert_eq!(row["read_bytes"], 5);
        assert_eq!(row["written_bytes"], 7);
        assert!(row.get("exit_code").is_none());
    }

    #[test]
    fn a_container_that_failed_says_how() {
        let row = describe(
            &summary("worker"),
            &inspected(ContainerStateStatusEnum::EXITED, 1, None),
            None,
        );
        assert_eq!(row["up"], 0);
        assert_eq!(row["exit_code"], 1);
        assert!(row.get("health").is_none());
        assert!(row.get("memory_bytes").is_none());

        let finished = describe(
            &summary("migrate"),
            &inspected(ContainerStateStatusEnum::EXITED, 0, None),
            None,
        );
        assert!(finished.get("up").is_none(), "{finished}");
    }

    #[test]
    fn cpu_use_is_measured_from_one_sample_to_the_next() {
        let mut before = HashMap::new();
        let mut row = describe(
            &summary("web"),
            &inspected(ContainerStateStatusEnum::RUNNING, 0, None),
            Some(&stats(1_000, 100_000)),
        );
        let mut seen = HashMap::new();
        settle_cpu(&mut row, &before, &mut seen);
        assert!(row.get("cpu_percent").is_none());
        assert!(row.get("cpu_total").is_none());
        before = seen;

        let mut row = describe(
            &summary("web"),
            &inspected(ContainerStateStatusEnum::RUNNING, 0, None),
            Some(&stats(3_000, 110_000)),
        );
        let mut seen = HashMap::new();
        settle_cpu(&mut row, &before, &mut seen);
        // 2,000 of the host's 10,000, whatever its number of CPUs.
        assert_eq!(row["cpu_percent"], 20.0);
        assert!(row.get("system_total").is_none());
    }

    /// Only says which metrics the collector has, as a real one looks for Docker.
    struct Metrics;

    impl Collector for Metrics {
        fn name(&self) -> &'static str {
            "containers"
        }

        fn collect(&mut self) -> Result<Value> {
            Ok(Value::Null)
        }

        fn metrics(&self) -> &'static [&'static str] {
            &CONTAINER_METRICS
        }
    }

    #[test]
    fn container_entries_have_a_series_for_each_container() {
        let output = json!([
            { "name": "web", "image": "nginx:1.27", "state": "running", "health": "healthy",
              "up": 1, "restarts": 3, "cpu_percent": 12.5, "memory_bytes": 200,
              "memory_limit_bytes": 1000, "memory_percent": 20.0,
              "received_bytes": 11000, "sent_bytes": 22000, "read_bytes": 5000,
              "written_bytes": 7000, "processes": 4 },
            { "name": "worker", "image": "app", "state": "exited", "exit_code": 1,
              "up": 0, "restarts": 4 },
            // One without a name can't be told from the others.
            { "image": "busybox", "up": 1 },
        ]);
        let entries = container_entries(&output, time());
        let of = |name: &str| name.to_string();
        assert_eq!(
            said(&entries),
            [
                (of("container.memory_limit[web]"), json!(20.0)),
                (of("container.up[web]"), json!(1)),
                (of("container.cpu[web]"), json!(12.5)),
                (of("container.memory[web]"), json!(200)),
                (of("container.memory_limit_bytes[web]"), json!(1000)),
                // The running totals, as Docker counts them.
                (of("container.received[web]"), json!(11000)),
                (of("container.sent[web]"), json!(22000)),
                (of("container.read[web]"), json!(5000)),
                (of("container.written[web]"), json!(7000)),
                (of("container.restarts[web]"), json!(3)),
                (of("container.processes[web]"), json!(4)),
                (of("container.image[web]"), json!("nginx:1.27")),
                (of("container.state[web]"), json!("running")),
                (of("container.health[web]"), json!("healthy")),
                (of("container.exit_code[web]"), Value::Null),
                // One that isn't running uses nothing.
                (of("container.memory_limit[worker]"), Value::Null),
                (of("container.up[worker]"), json!(0)),
                (of("container.cpu[worker]"), Value::Null),
                (of("container.memory[worker]"), Value::Null),
                (of("container.memory_limit_bytes[worker]"), Value::Null),
                (of("container.received[worker]"), Value::Null),
                (of("container.sent[worker]"), Value::Null),
                (of("container.read[worker]"), Value::Null),
                (of("container.written[worker]"), Value::Null),
                (of("container.restarts[worker]"), json!(4)),
                (of("container.processes[worker]"), Value::Null),
                (of("container.image[worker]"), json!("app")),
                (of("container.state[worker]"), json!("exited")),
                (of("container.health[worker]"), Value::Null),
                (of("container.exit_code[worker]"), json!(1)),
            ]
        );
        every_metric_has_an_entry(&Metrics, &entries);

        // With no containers, or when they couldn't be read, each has nothing.
        for output in [json!([]), Value::Null] {
            let none = container_entries(&output, time());
            assert_eq!(none.len(), CONTAINER_METRICS.len());
            assert!(
                said(&none)
                    .iter()
                    .all(|(name, value)| !name.contains('[') && value.is_null())
            );
            every_metric_has_an_entry(&Metrics, &none);
        }
    }

    #[test]
    fn what_docker_says_of_a_container_becomes_entries() {
        let mut running = describe(
            &summary("web"),
            &inspected(
                ContainerStateStatusEnum::RUNNING,
                0,
                Some(HealthStatusEnum::HEALTHY),
            ),
            Some(&stats(500, 10_000)),
        );
        // A first sample has no CPU use yet.
        settle_cpu(&mut running, &HashMap::new(), &mut HashMap::new());
        let finished = describe(
            &summary("migrate"),
            &inspected(ContainerStateStatusEnum::EXITED, 0, None),
            None,
        );
        let entries = container_entries(&json!([running, finished]), time());
        every_metric_has_an_entry(&Metrics, &entries);
        let said = said(&entries);
        assert_eq!(said.len(), 2 * CONTAINER_METRICS.len());
        for (name, value) in [
            ("container.up[web]", json!(1)),
            ("container.cpu[web]", Value::Null),
            ("container.memory[web]", json!(200)),
            ("container.memory_limit[web]", json!(20.0)),
            ("container.memory_limit_bytes[web]", json!(1000)),
            ("container.received[web]", json!(11)),
            ("container.sent[web]", json!(22)),
            ("container.read[web]", json!(5)),
            ("container.written[web]", json!(7)),
            ("container.health[web]", json!("healthy")),
            // One that finished cleanly isn't up or down.
            ("container.up[migrate]", Value::Null),
            ("container.state[migrate]", json!("exited")),
            ("container.exit_code[migrate]", json!(0)),
            ("container.restarts[migrate]", json!(3)),
        ] {
            assert!(
                said.contains(&(name.to_string(), value)),
                "{name}: {said:?}"
            );
        }
    }

    #[test]
    fn nothing_is_reported_until_containers_have_been_read() {
        let mut collector = ContainerCollector::new(Duration::from_secs(3600)).unwrap();
        assert_eq!(collector.name(), "containers");
        assert_eq!(collector.collect().unwrap(), Value::Null);
    }

    #[test]
    fn the_socket_comes_from_docker_host_first() {
        assert_eq!(
            find_socket(Some("unix:///run/user/1000/docker.sock")).as_deref(),
            Some("/run/user/1000/docker.sock")
        );
    }

    /// A stand-in for Docker's API on a socket, answering each request with the body
    /// for the first path it starts with.
    async fn fake_docker(answers: Vec<(&'static str, Value)>) -> (tempfile::TempDir, String) {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let answers = answers.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(size) => request.extend_from_slice(&buffer[..size]),
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let path = text.split_whitespace().nth(1).unwrap_or_default();
                    let path = path
                        .split_once("/containers")
                        .map_or(path, |(_, rest)| rest);
                    let body = answers
                        .iter()
                        .find(|(start, _)| path.starts_with(start))
                        .map_or(Value::Null, |(_, body)| body.clone())
                        .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let socket = path.display().to_string();
        (folder, socket)
    }

    #[tokio::test]
    async fn containers_are_read_through_the_socket() {
        let (_folder, socket) = fake_docker(vec![
            (
                "/json",
                json!([
                    { "Id": "b", "Names": ["/web"], "Image": "nginx", "State": "running" },
                    { "Id": "a", "Names": ["/job"], "Image": "busybox", "State": "exited" },
                ]),
            ),
            (
                "/b/json",
                json!({ "RestartCount": 2, "State": { "Status": "running", "Running": true,
                        "ExitCode": 0, "Health": { "Status": "unhealthy" } } }),
            ),
            (
                "/a/json",
                json!({ "RestartCount": 0, "State": { "Status": "exited", "Running": false,
                        "ExitCode": 2 } }),
            ),
            (
                "/b/stats",
                json!({ "memory_stats": { "usage": 50, "limit": 100 },
                        "cpu_stats": { "cpu_usage": { "total_usage": 1 },
                                       "system_cpu_usage": 10, "online_cpus": 1 } }),
            ),
        ])
        .await;

        let containers = read_all(&socket).await.unwrap();
        let names: Vec<&str> = containers
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["job", "web"]);
        assert_eq!(containers[0]["up"], 0);
        assert_eq!(containers[0]["exit_code"], 2);
        assert_eq!(containers[1]["up"], 0, "unhealthy: {}", containers[1]);
        assert_eq!(containers[1]["restarts"], 2);
        assert_eq!(containers[1]["memory_percent"], 50.0);
    }

    #[tokio::test]
    async fn a_missing_socket_says_where_it_looked() {
        let error = read_all("/no/such/docker.sock").await.unwrap_err();
        assert!(
            format!("{error:#}").contains("/no/such/docker.sock"),
            "{error:#}"
        );
    }
}
