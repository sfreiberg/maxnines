//! Simulates a fleet of agents against a server to see how it copes, so people can
//! size a server before depending on it.

mod fleet;
mod keys;
mod monitor;
mod options;
mod report;
mod report_html;
mod sample;
mod server;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures_util::{StreamExt, stream};
use maxnines_protocol::RegistrationStatus;
use maxnines_protocol::auth::Identity;
use serde_json::{Value, json};
use sysinfo::{CpuRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::watch;
use tokio::time::sleep;

use fleet::{Counters, Plan, SimulatedAgent, register};
use monitor::{Snapshot, Timeline};
use options::Options;
use report::{
    Connections, ErrorCount, Event, Outcome, PageResult, Projection, Report, Samples,
    ServerSummary, Spread, judge, overall,
};
use sample::Shape;
use server::Server;

/// How often to ask the server how it's doing.
const STATS_EVERY: Duration = Duration::from_secs(5);
const PROGRESS_EVERY: Duration = Duration::from_secs(10);
/// How many agents to register at once. It only happens once for each agent.
const REGISTERING_AT_ONCE: usize = 16;
/// How long the server gets to save what's been sent once the test has stopped.
const DRAIN_LIMIT: Duration = Duration::from_secs(30);
const WAIT_FOR_RECOVERY: Duration = Duration::from_secs(180);
const SECONDS_PER_DAY: f64 = 86_400.0;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Each connection needs a file, and the usual limit on Linux is 1024.
#[cfg(unix)]
fn raise_open_file_limit(agents: usize) {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let limit = getrlimit(Resource::Nofile);
    let wanted = limit.maximum.unwrap_or(u64::MAX);
    let raised = Rlimit {
        current: Some(wanted),
        maximum: limit.maximum,
    };
    if setrlimit(Resource::Nofile, raised).is_err() {
        let current = limit.current.unwrap_or(u64::MAX);
        if current < agents as u64 + 100 {
            eprintln!(
                "Warning: this process can only open {current} files, and {agents} agents \
                 need one each. Raise it with ulimit -n."
            );
        }
    }
}

#[cfg(not(unix))]
fn raise_open_file_limit(_agents: usize) {}

fn host_name(prefix: &str, index: usize) -> String {
    format!("{prefix}-{index:05}")
}

/// Makes sure the server knows every agent and has approved it.
async fn register_all(options: &Options, server: &Server, identities: &[Identity]) -> Result<()> {
    let results: Vec<Result<()>> = stream::iter(identities.iter().enumerate())
        .map(|(index, identity)| {
            let (url, server) = (options.url.clone(), server.clone());
            let host = host_name(&options.host_prefix, index);
            let id = identity.id();
            async move {
                match register(&url, identity, &host).await? {
                    RegistrationStatus::Approved => Ok(()),
                    RegistrationStatus::Pending => {
                        tokio::task::spawn_blocking(move || server.approve(&id))
                            .await
                            .context("approving an agent")?
                    }
                    RegistrationStatus::Rejected => bail!(
                        "the server rejected {host}, probably after an earlier --revoke. Use a \
                         new --keys-file"
                    ),
                }
            }
        })
        .buffer_unordered(REGISTERING_AT_ONCE)
        .collect()
        .await;
    results.into_iter().collect()
}

/// What's measured while a test runs, by the threads doing the measuring.
struct Measurements {
    timeline: Mutex<Timeline>,
    pages: Mutex<BTreeMap<String, PageTimes>>,
    events: Mutex<Vec<Event>>,
    peak_queued: AtomicU64,
    peak_online: AtomicU64,
    generator_cpu: Mutex<Vec<f64>>,
    began: Instant,
}

#[derive(Default)]
struct PageTimes {
    times_ms: Vec<f64>,
    errors: usize,
    bytes: usize,
}

impl Measurements {
    fn event(&self, text: String) {
        let time_secs = self.began.elapsed().as_secs_f64();
        println!("  {}  {text}", report::clock(time_secs));
        lock(&self.events).push(Event { time_secs, text });
    }

    fn record(&self, snapshot: Snapshot, counters: &Counters) {
        let online = counters.online.load(Relaxed);
        self.peak_online.fetch_max(online, Relaxed);
        self.peak_queued.fetch_max(snapshot.queued, Relaxed);
        lock(&self.timeline).add(self.began.elapsed(), online, counters.samples(), snapshot);
    }
}

/// How much of this machine the load generator is using, to tell whether the results
/// show the server's limits or this machine's.
struct OwnCpu {
    system: System,
    pid: Pid,
    cores: f32,
}

impl OwnCpu {
    fn new() -> Option<Self> {
        let mut system = System::new().ok()?;
        system.refresh_cpu_list(CpuRefreshKind::nothing());
        let cores = system.cpus().len().max(1) as f32;
        let pid = sysinfo::get_current_pid().ok()?;
        Some(Self { system, pid, cores })
    }

    fn percent(&mut self) -> f64 {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        self.system
            .process(self.pid)
            .map_or(0.0, |process| f64::from(process.cpu_usage() / self.cores))
    }
}

fn watch_server(
    server: Server,
    measurements: Arc<Measurements>,
    plan: Arc<Plan>,
    finished: Arc<AtomicBool>,
) {
    let mut own_cpu = OwnCpu::new();
    while !finished.load(Relaxed) {
        if let Ok(stats) = server.stats() {
            measurements.record(Snapshot::read(&stats, now_ms()), &plan.counters);
        }
        if let Some(own_cpu) = &mut own_cpu {
            lock(&measurements.generator_cpu).push(own_cpu.percent());
        }
        thread::sleep(STATS_EVERY);
    }
}

fn pages_to_view(agent_id: &str) -> Vec<(String, String)> {
    let mut pages: Vec<(String, String)> = [
        "/",
        "/agents",
        "/agents?view=table",
        "/agents?q=os%3Dlinux",
        "/metrics",
        "/alerts",
        "/settings/server",
    ]
    .iter()
    .map(|path| ((*path).to_string(), (*path).to_string()))
    .collect();
    pages.push(("/agents/:id".to_string(), format!("/agents/{agent_id}")));
    pages.push((
        "/agents/:id/metrics".to_string(),
        format!("/agents/{agent_id}/metrics"),
    ));
    pages
}

fn view_pages(
    server: Server,
    pages: Vec<(String, String)>,
    every: Duration,
    measurements: Arc<Measurements>,
    finished: Arc<AtomicBool>,
) {
    thread::sleep(every.mul_f64(rand::random()));
    while !finished.load(Relaxed) {
        let round = Instant::now();
        for (label, path) in &pages {
            let load = server.load_page(path);
            let mut pages = lock(&measurements.pages);
            let times = pages.entry(label.clone()).or_default();
            times.times_ms.push(load.took.as_secs_f64() * 1000.0);
            times.bytes = load.bytes.max(times.bytes);
            times.errors += usize::from(!load.ok);
        }
        let wait = every.saturating_sub(round.elapsed());
        let until = Instant::now() + wait;
        while Instant::now() < until && !finished.load(Relaxed) {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

async fn wait_until_online(plan: &Plan, wanted: u64, limit: Duration) -> Option<Duration> {
    let began = Instant::now();
    while began.elapsed() < limit {
        if plan.counters.online.load(Relaxed) >= wanted {
            return Some(began.elapsed());
        }
        sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Takes every agent offline for a while, then reports how long they took to return.
async fn run_outage(
    at: Duration,
    lasts: Duration,
    outage: watch::Sender<bool>,
    plan: Arc<Plan>,
    measurements: Arc<Measurements>,
    wanted: u64,
) {
    sleep(at).await;
    outage.send_replace(true);
    measurements.event("Every agent lost its connection".to_string());
    sleep(lasts).await;
    outage.send_replace(false);
    measurements.event("The outage ended".to_string());
    match wait_until_online(&plan, wanted, WAIT_FOR_RECOVERY).await {
        Some(took) => measurements.event(format!(
            "All agents were back after {:.1} seconds",
            took.as_secs_f64()
        )),
        None => measurements.event("Not all agents came back".to_string()),
    }
}

/// Changes a setting that does no harm, so every agent is sent a new config.
async fn run_rule_change(
    at: Duration,
    server: Server,
    plan: Arc<Plan>,
    measurements: Arc<Measurements>,
    original: Arc<Mutex<Option<(i64, Value)>>>,
) {
    sleep(at).await;
    let online = plan.counters.online.load(Relaxed);
    let before = plan.counters.configs.load(Relaxed);
    let began = Instant::now();

    let saved = {
        let original = original.clone();
        tokio::task::spawn_blocking(move || {
            let (id, rule) = server.first_rule()?;
            let mut changed = rule.clone();
            let every = rule["settings"]["facts_interval_secs"]
                .as_u64()
                .unwrap_or(3600);
            changed["settings"]["facts_interval_secs"] = json!(every + 1);
            *lock(&original) = Some((id, rule));
            server.save_rule(id, &changed)
        })
        .await
    };
    match saved {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            measurements.event(format!("Changing a rule failed: {error:#}"));
            return;
        }
        Err(error) => {
            measurements.event(format!("Changing a rule failed: {error}"));
            return;
        }
    }

    measurements.event("A config rule changed".to_string());
    while began.elapsed() < WAIT_FOR_RECOVERY {
        if plan.counters.configs.load(Relaxed) >= before + online {
            measurements.event(format!(
                "All agents had the new config after {:.1} seconds",
                began.elapsed().as_secs_f64()
            ));
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    measurements.event("Not every agent got the new config".to_string());
}

/// Waits for the server to finish saving what it's been sent.
async fn drain(server: &Server, measurements: &Measurements) {
    let began = Instant::now();
    let mut last_written = None;
    while began.elapsed() < DRAIN_LIMIT {
        sleep(Duration::from_secs(2)).await;
        let client = server.clone();
        let Ok(Ok(stats)) = tokio::task::spawn_blocking(move || client.stats()).await else {
            continue;
        };
        let snapshot = Snapshot::read(&stats, now_ms());
        let settled = snapshot.queued == 0 && last_written == Some(snapshot.written);
        last_written = Some(snapshot.written);
        lock(&measurements.timeline).settle(snapshot);
        if settled {
            return;
        }
    }
}

fn page_results(measurements: &Measurements) -> Vec<PageResult> {
    let mut pages = lock(&measurements.pages);
    pages
        .iter_mut()
        .map(|(path, times)| PageResult {
            path: path.clone(),
            loads: times.times_ms.len(),
            errors: times.errors,
            bytes: times.bytes,
            times: Spread::of(&mut times.times_ms),
        })
        .collect()
}

/// What this load would come to if it carried on.
fn project(options: &Options, timeline: &Timeline, ran_for: f64) -> Projection {
    let (Some(first), Some(last)) = (&timeline.first, &timeline.last) else {
        return Projection::default();
    };
    let cores: Vec<f64> = timeline.points.iter().filter_map(|p| p.cpu_cores).collect();
    let peak_memory_mb = timeline
        .points
        .iter()
        .filter_map(|p| p.memory_mb)
        .fold(None, |peak: Option<f64>, value| {
            Some(peak.map_or(value, |peak| peak.max(value)))
        });

    let grown = last
        .metrics_bytes
        .zip(first.metrics_bytes)
        .map(|(last, first)| last.saturating_sub(first) as f64);
    let bytes_per_sample = grown
        .filter(|_| timeline.written > 0)
        .map(|grown| grown / timeline.written as f64);
    let samples_per_day = options.agents as f64 * SECONDS_PER_DAY / options.interval.as_secs_f64();
    let bytes_per_day = bytes_per_sample.map(|bytes| bytes * samples_per_day);

    Projection {
        bytes_per_sample,
        metrics_gb_per_day: bytes_per_day.map(|bytes| bytes / 1e9),
        days_until_disk_full: bytes_per_day
            .filter(|bytes| *bytes > 0.0)
            .zip(last.disk_available_bytes)
            .map(|(bytes, available)| available as f64 / bytes),
        memory_mb_per_agent: peak_memory_mb
            .zip(first.memory_bytes)
            .map(|(peak, start)| (peak - start as f64 / 1e6).max(0.0) / options.agents as f64),
        average_cpu_cores: (!cores.is_empty() && ran_for > 0.0)
            .then(|| cores.iter().sum::<f64>() / cores.len() as f64),
        peak_cpu_cores: cores.iter().copied().reduce(f64::max),
        peak_memory_mb,
    }
}

fn server_summary(stats: &Value) -> ServerSummary {
    let text = |value: &Value| value.as_str().unwrap_or("unknown").to_string();
    ServerSummary {
        version: text(&stats["version"]),
        commit: text(&stats["commit"]),
        os: text(&stats["os"]),
        cores: stats["process"]["cores"].as_u64().unwrap_or_default(),
        memory_gb: stats["process"]["machine_memory_total_bytes"]
            .as_f64()
            .unwrap_or_default()
            / 1e9,
        database: format!(
            "{} and {}",
            text(&stats["metrics"]["engine"]),
            text(&stats["database"]["engine"])
        ),
    }
}

fn connections(
    plan: &Plan,
    wanted: u64,
    peak_online: u64,
    online_after: Option<f64>,
) -> Connections {
    let counters = &plan.counters;
    let mut times: Vec<f64> = lock(&counters.connect_times)
        .iter()
        .map(|time| time.as_secs_f64() * 1000.0)
        .collect();
    let mut errors: Vec<ErrorCount> = lock(&counters.errors)
        .iter()
        .map(|(error, count)| ErrorCount {
            error: error.clone(),
            count: *count,
        })
        .collect();
    errors.sort_by_key(|error| std::cmp::Reverse(error.count));
    Connections {
        wanted,
        churning: false,
        online_at_end: 0,
        peak_online,
        attempts: counters.attempts.load(Relaxed),
        succeeded: counters.connected.load(Relaxed),
        lost: counters.lost.load(Relaxed),
        all_online_after_secs: online_after,
        times: Spread::of(&mut times),
        errors,
    }
}

async fn run(options: Options) -> Result<Outcome> {
    options.check()?;
    raise_open_file_limit(options.agents);

    let server = Server::new(options.admin_address(), options.admin_token.clone());
    let client = server.clone();
    let stats = tokio::task::spawn_blocking(move || client.stats())
        .await
        .context("reaching the server")??;
    let summary = server_summary(&stats);
    println!(
        "Testing MaxNines {} ({}) on {} with {} agents for {}",
        summary.version,
        summary.commit,
        summary.os,
        options.agents,
        humantime::format_duration(options.duration)
    );

    let identities = keys::load(&options.keys_file, options.agents)?;
    print!("Registering agents... ");
    let registering = Instant::now();
    register_all(&options, &server, &identities).await?;
    println!("done in {:.1}s", registering.elapsed().as_secs_f64());

    let first_id = identities[0].id();
    let ids: Vec<String> = identities.iter().map(Identity::id).collect();
    let plan = Arc::new(Plan {
        url: options.url.clone(),
        interval: options.interval,
        shape: Shape {
            cores: options.cores,
            disks: options.disks,
            interfaces: options.interfaces,
        },
        backlog: options.backlog,
        backlog_gap: options.backlog_gap,
        churn_percent: options.churn,
        facts_every: options.facts_every,
        fact_change_percent: options.fact_changes,
        hot_percent: options.hot_agents,
        counters: Counters::default(),
    });
    let measurements = Arc::new(Measurements {
        timeline: Mutex::default(),
        pages: Mutex::default(),
        events: Mutex::default(),
        peak_queued: AtomicU64::new(0),
        peak_online: AtomicU64::new(0),
        generator_cpu: Mutex::default(),
        began: Instant::now(),
    });

    let (stop, stopped) = watch::channel(false);
    let (outage, outage_watch) = watch::channel(false);
    let finished = Arc::new(AtomicBool::new(false));
    let wanted = options.agents as u64;

    let mut agents = Vec::with_capacity(options.agents);
    for (index, identity) in identities.into_iter().enumerate() {
        let host = host_name(&options.host_prefix, index);
        let agent = SimulatedAgent::new(index, identity, host, &plan);
        let start_after = options.ramp.mul_f64(index as f64 / options.agents as f64);
        agents.push(tokio::spawn(agent.run(
            plan.clone(),
            start_after,
            stopped.clone(),
            outage_watch.clone(),
        )));
    }

    let mut threads = Vec::new();
    {
        let (server, measurements) = (server.clone(), measurements.clone());
        let (plan, finished) = (plan.clone(), finished.clone());
        threads.push(thread::spawn(move || {
            watch_server(server, measurements, plan, finished);
        }));
    }
    for _ in 0..options.viewers {
        let (server, measurements) = (server.clone(), measurements.clone());
        let finished = finished.clone();
        let pages = pages_to_view(&first_id);
        let every = options.page_every;
        threads.push(thread::spawn(move || {
            view_pages(server, pages, every, measurements, finished);
        }));
    }

    let all_online = {
        let (plan, measurements) = (plan.clone(), measurements.clone());
        let limit = options.duration;
        tokio::spawn(async move {
            let took = wait_until_online(&plan, wanted, limit).await;
            if let Some(took) = took {
                measurements.event(format!(
                    "All agents were online after {:.1} seconds",
                    took.as_secs_f64()
                ));
            }
            took
        })
    };
    if let Some(at) = options.outage_at {
        tokio::spawn(run_outage(
            at,
            options.outage_for,
            outage,
            plan.clone(),
            measurements.clone(),
            wanted,
        ));
    }
    let original_rule = Arc::new(Mutex::new(None));
    if let Some(at) = options.rule_change_at {
        tokio::spawn(run_rule_change(
            at,
            server.clone(),
            plan.clone(),
            measurements.clone(),
            original_rule.clone(),
        ));
    }

    let mut stopped_early = false;
    let ending = sleep(options.duration);
    tokio::pin!(ending);
    let mut progress = tokio::time::interval(PROGRESS_EVERY);
    loop {
        tokio::select! {
            () = &mut ending => break,
            _ = tokio::signal::ctrl_c() => {
                println!("\nStopping early...");
                stopped_early = true;
                break;
            }
            _ = progress.tick() => {
                let timeline = lock(&measurements.timeline);
                let latest = timeline.points.last();
                println!(
                    "  {}  {} online, {} samples sent, {:.0}/s written, queue {}, CPU {}, memory {}",
                    report::clock(measurements.began.elapsed().as_secs_f64()),
                    plan.counters.online.load(Relaxed),
                    plan.counters.samples(),
                    latest.map_or(0.0, |p| p.samples_written_per_sec),
                    latest.map_or(0, |p| p.queued),
                    latest.and_then(|p| p.cpu_cores).map_or("?".to_string(), |c| format!("{c:.2}")),
                    latest.and_then(|p| p.memory_mb).map_or("?".to_string(), |m| format!("{m:.0} MB")),
                );
            }
        }
    }

    let ran_for = measurements.began.elapsed().as_secs_f64();
    let online_at_end = plan.counters.online.load(Relaxed);
    println!("Stopping and waiting for the server to catch up...");
    stop.send_replace(true);
    finished.store(true, Relaxed);
    for agent in agents {
        agent.await.ok();
    }
    for thread in threads {
        thread.join().ok();
    }
    drain(&server, &measurements).await;

    let restore = lock(&original_rule).take();
    if let Some((id, rule)) = restore {
        let client = server.clone();
        match tokio::task::spawn_blocking(move || client.save_rule(id, &rule)).await {
            Ok(Ok(())) => {}
            _ => eprintln!("Warning: the config rule couldn't be put back"),
        }
    }
    if options.revoke {
        print!("Revoking agents... ");
        let client = server.clone();
        tokio::task::spawn_blocking(move || {
            for id in &ids {
                client.revoke(id).ok();
            }
        })
        .await
        .ok();
        println!("done");
    }

    let online_after = if all_online.is_finished() {
        all_online.await.ok().flatten().map(|t| t.as_secs_f64())
    } else {
        None
    };
    let mut connections = connections(
        &plan,
        wanted,
        measurements.peak_online.load(Relaxed),
        online_after,
    );
    connections.online_at_end = online_at_end;
    connections.churning = options.churn > 0.0;

    let timeline = lock(&measurements.timeline);
    let counters = &plan.counters;
    let last = timeline.last.clone().unwrap_or_default();
    let samples = Samples {
        live_sent: counters.live_samples.load(Relaxed),
        saved_sent: counters.saved_samples.load(Relaxed),
        written: timeline.written,
        failed: timeline.failed,
        average_bytes: match counters.samples() {
            0 => 0.0,
            count => counters.bytes.load(Relaxed) as f64 / count as f64,
        },
        peak_queued: measurements.peak_queued.load(Relaxed),
        queue_capacity: last.queue_capacity,
    };
    let pages = page_results(&measurements);
    let generator = {
        let readings = lock(&measurements.generator_cpu);
        readings.iter().sum::<f64>() / readings.len().max(1) as f64
    };
    let checks = judge(&connections, &samples, &pages, &timeline.points, generator);
    let outcome = overall(&checks);
    let report = Report {
        started: humantime::format_rfc3339_seconds(
            SystemTime::now() - Duration::from_secs_f64(ran_for),
        )
        .to_string(),
        ran_for_secs: ran_for,
        stopped_early,
        outcome,
        checks,
        settings: options.settings(),
        server: summary,
        projection: project(&options, &timeline, ran_for),
        connections,
        samples,
        pages,
        events: std::mem::take(&mut *lock(&measurements.events)),
        timeline: timeline.points.clone(),
        generator_average_cpu_percent: generator,
    };

    print!("{}", report.text());
    std::fs::write(&options.report, report_html::render(&report))
        .with_context(|| format!("writing {}", options.report.display()))?;
    println!("\nReport: {}", options.report.display());
    if let Some(path) = &options.json {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("Results: {}", path.display());
    }
    Ok(outcome)
}

#[tokio::main]
async fn main() -> ExitCode {
    let options = Options::parse();
    let strict = options.strict;
    match run(options).await {
        Ok(Outcome::Pass) => ExitCode::SUCCESS,
        Ok(Outcome::Warning) if !strict => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_sort_in_order() {
        assert_eq!(host_name("loadtest", 7), "loadtest-00007");
        assert!(host_name("a", 9) < host_name("a", 10));
    }

    #[test]
    fn pages_hide_the_agent_in_their_labels() {
        let pages = pages_to_view("abc");
        let (label, path) = pages.last().unwrap();
        assert_eq!(label, "/agents/:id/metrics");
        assert_eq!(path, "/agents/abc/metrics");
    }
}
