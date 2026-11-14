//! The report as one file with nothing to download, to read or pass around. Each
//! chart shows one measure, as they don't share a scale. Everything from the server
//! is escaped, as it's reported by the thing being tested.

use std::fmt::Write;

use crate::monitor::Point;
use crate::report::{Event, Outcome, Report, clock};

const STYLE: &str = include_str!("report.css");
const SCRIPT: &str = include_str!("report.js");

const WIDTH: f64 = 560.0;
const HEIGHT: f64 = 190.0;
const LEFT: f64 = 58.0;
const RIGHT: f64 = 14.0;
const TOP: f64 = 16.0;
const BOTTOM: f64 = 26.0;
const GRID_LINES: usize = 4;
const MIN_EVENT_GAP: f64 = 16.0;

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A top for the scale that gives round numbers at each grid line.
fn scale_top(largest: f64) -> f64 {
    if largest <= 0.0 {
        return 1.0;
    }
    let step = largest / GRID_LINES as f64;
    let magnitude = 10_f64.powf(step.log10().floor());
    let round_step = [1.0, 2.0, 2.5, 5.0, 10.0]
        .iter()
        .map(|factor| factor * magnitude)
        .find(|candidate| *candidate >= step)
        .unwrap_or(step);
    round_step * GRID_LINES as f64
}

fn number(value: f64) -> String {
    let rounded = if value.abs() >= 100.0 {
        format!("{value:.0}")
    } else if value.abs() >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    };
    if rounded.contains('.') {
        rounded
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    } else {
        rounded
    }
}

struct Chart<'a> {
    title: &'a str,
    unit: &'a str,
    points: Vec<(f64, f64)>,
    /// The top of the scale, for measures with a limit worth seeing.
    limit: Option<f64>,
}

fn series<'a>(
    title: &'a str,
    unit: &'a str,
    timeline: &[Point],
    value: impl Fn(&Point) -> Option<f64>,
) -> Chart<'a> {
    let points = timeline
        .iter()
        .filter_map(|point| value(point).map(|value| (point.time_secs, value)))
        .collect();
    Chart {
        title,
        unit,
        points,
        limit: None,
    }
}

/// Numbers for the events along the top of a chart. Events too close together to
/// read apart share a label, like "5, 6".
fn event_labels(events: &[Event], x: impl Fn(f64) -> f64) -> Vec<(f64, String)> {
    let mut labels: Vec<(f64, String)> = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let at = x(event.time_secs);
        let number = (index + 1).to_string();
        match labels.last_mut() {
            Some((last, text)) if at - *last < MIN_EVENT_GAP => {
                text.push_str(", ");
                text.push_str(&number);
            }
            _ => labels.push((at, number)),
        }
    }
    labels
}

fn draw(chart: &Chart, duration: f64, events: &[Event]) -> String {
    let mut out = format!(
        r#"<figure class="chart"><figcaption>{}</figcaption>"#,
        escape(chart.title)
    );
    if chart.points.len() < 2 {
        out.push_str(r#"<p class="muted">Not enough data to draw.</p></figure>"#);
        return out;
    }

    let duration = duration.max(1.0);
    let largest = chart.points.iter().map(|p| p.1).fold(0.0, f64::max);
    let top = chart.limit.unwrap_or_else(|| scale_top(largest));
    let inner_width = WIDTH - LEFT - RIGHT;
    let inner_height = HEIGHT - TOP - BOTTOM;
    let x = |time: f64| LEFT + (time / duration).min(1.0) * inner_width;
    let y = |value: f64| TOP + (1.0 - (value / top).min(1.0)) * inner_height;

    let data: Vec<String> = chart
        .points
        .iter()
        .map(|(time, value)| {
            format!(
                "[{:.1},{:.1},\"{}\",\"{} {}\"]",
                x(*time),
                y(*value),
                clock(*time),
                number(*value),
                escape(chart.unit)
            )
        })
        .collect();
    let _ = write!(
        out,
        r#"<div class="plot"><svg viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="{}, peaking at {} {}" data-points='[{}]'>"#,
        escape(chart.title),
        number(largest),
        escape(chart.unit),
        data.join(",")
    );

    for line in 0..=GRID_LINES {
        let value = top * line as f64 / GRID_LINES as f64;
        let height = y(value);
        let _ = write!(
            out,
            r#"<line class="grid" x1="{LEFT}" x2="{:.1}" y1="{height:.1}" y2="{height:.1}"/><text class="tick" x="{:.1}" y="{:.1}" text-anchor="end">{}</text>"#,
            WIDTH - RIGHT,
            LEFT - 8.0,
            height + 4.0,
            number(value)
        );
    }
    for step in 0..=3 {
        let time = duration * f64::from(step) / 3.0;
        let anchor = match step {
            0 => "start",
            3 => "end",
            _ => "middle",
        };
        let _ = write!(
            out,
            r#"<text class="tick" x="{:.1}" y="{:.1}" text-anchor="{anchor}">{}</text>"#,
            x(time),
            HEIGHT - 6.0,
            clock(time)
        );
    }
    for event in events {
        let at = x(event.time_secs);
        let _ = write!(
            out,
            r#"<line class="event" x1="{at:.1}" x2="{at:.1}" y1="{TOP}" y2="{:.1}"/>"#,
            HEIGHT - BOTTOM,
        );
    }
    for (at, label) in event_labels(events, x) {
        let _ = write!(
            out,
            r#"<text class="event-number" x="{at:.1}" y="{:.1}" text-anchor="middle">{label}</text>"#,
            TOP - 5.0,
        );
    }

    let path: Vec<String> = chart
        .points
        .iter()
        .map(|(time, value)| format!("{:.1},{:.1}", x(*time), y(*value)))
        .collect();
    let _ = write!(
        out,
        r#"<polyline class="line" points="{}"/><line class="cross" y1="{TOP}" y2="{:.1}" hidden/><circle class="dot" r="4" hidden/></svg><div class="tip" hidden></div></div></figure>"#,
        path.join(" "),
        HEIGHT - BOTTOM
    );
    out
}

fn icon(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "✓",
        Outcome::Warning => "!",
        Outcome::Fail => "✕",
    }
}

fn class(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "pass",
        Outcome::Warning => "warning",
        Outcome::Fail => "fail",
    }
}

fn tile(label: &str, value: &str, note: &str) -> String {
    format!(
        r#"<div class="tile"><span class="label">{}</span><span class="value">{}</span><span class="muted">{}</span></div>"#,
        escape(label),
        escape(value),
        escape(note)
    )
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn or_dash(value: Option<f64>, write: impl Fn(f64) -> String) -> String {
    value.map_or_else(|| "–".to_string(), write)
}

fn row(cells: &[String]) -> String {
    let cells: String = cells
        .iter()
        .map(|cell| format!("<td>{}</td>", escape(cell)))
        .collect();
    format!("<tr>{cells}</tr>")
}

fn table(headings: &[&str], rows: &str) -> String {
    let headings: String = headings
        .iter()
        .map(|heading| format!(r#"<th scope="col">{}</th>"#, escape(heading)))
        .collect();
    format!(
        r#"<div class="tablebox"><table><thead><tr>{headings}</tr></thead><tbody>{rows}</tbody></table></div>"#
    )
}

fn definitions(items: &[(&str, String)]) -> String {
    let items: String = items
        .iter()
        .map(|(name, value)| format!("<dt>{}</dt><dd>{}</dd>", escape(name), escape(value)))
        .collect();
    format!("<dl>{items}</dl>")
}

fn checks(report: &Report) -> String {
    let items: String = report
        .checks
        .iter()
        .map(|check| {
            format!(
                r#"<li class="{}"><span class="mark" aria-hidden="true">{}</span><span><strong>{}</strong> <span class="state">{}</span><br><span class="muted">{}</span></span></li>"#,
                class(check.outcome),
                icon(check.outcome),
                escape(check.name),
                check.outcome.label(),
                escape(&check.detail)
            )
        })
        .collect();
    format!(r#"<ul class="checks">{items}</ul>"#)
}

fn tiles(report: &Report) -> String {
    let projection = &report.projection;
    let worst_page = report
        .pages
        .iter()
        .map(|page| page.times.p95_ms)
        .fold(0.0, f64::max);
    [
        tile(
            "Agents online",
            &format!(
                "{} of {}",
                grouped(report.connections.online_at_end),
                grouped(report.connections.wanted)
            ),
            &format!("{} attempts", grouped(report.connections.attempts)),
        ),
        tile(
            "Samples saved",
            &grouped(report.samples.written),
            &format!("{} failed", grouped(report.samples.failed)),
        ),
        tile(
            "Server CPU",
            &or_dash(projection.average_cpu_cores, |c| format!("{c:.2} cores")),
            &format!(
                "peak {}, of {}",
                or_dash(projection.peak_cpu_cores, |c| format!("{c:.2}")),
                report.server.cores
            ),
        ),
        tile(
            "Server memory",
            &or_dash(projection.peak_memory_mb, |m| format!("{m:.0} MB")),
            &format!(
                "peak, {} per agent",
                or_dash(projection.memory_mb_per_agent, |m| format!("{m:.2} MB"))
            ),
        ),
        tile(
            "Metrics per day",
            &or_dash(projection.metrics_gb_per_day, |g| format!("{g:.1} GB")),
            &or_dash(projection.bytes_per_sample, |b| {
                format!("{:.2} KB per sample", b / 1000.0)
            }),
        ),
        tile(
            "Slowest page",
            &format!("{worst_page:.0} ms"),
            "95th percentile",
        ),
    ]
    .concat()
}

fn charts(report: &Report) -> String {
    let timeline = &report.timeline;
    let list = [
        series("Agents online", "agents", timeline, |p| {
            Some(p.agents_online as f64)
        }),
        series("Samples written", "per second", timeline, |p| {
            Some(p.samples_written_per_sec)
        }),
        Chart {
            limit: Some(report.samples.queue_capacity.max(1) as f64),
            ..series("Write queue", "waiting", timeline, |p| {
                Some(p.queued as f64)
            })
        },
        series("Server CPU", "cores", timeline, |p| p.cpu_cores),
        series("Server memory", "MB", timeline, |p| p.memory_mb),
        series("Metrics database", "MB", timeline, |p| p.metrics_mb),
    ];
    let drawn: String = list
        .iter()
        .map(|chart| draw(chart, report.ran_for_secs, &report.events))
        .collect();
    format!(r#"<div class="charts">{drawn}</div>"#)
}

fn events(report: &Report) -> String {
    if report.events.is_empty() {
        return String::new();
    }
    let items: String = report
        .events
        .iter()
        .map(|event| {
            format!(
                "<li><time>{}</time> {}</li>",
                clock(event.time_secs),
                escape(&event.text)
            )
        })
        .collect();
    format!(r#"<section><h2>Events</h2><ol class="events">{items}</ol></section>"#)
}

fn connection_section(report: &Report) -> String {
    let connections = &report.connections;
    let mut items = vec![
        ("Attempts", grouped(connections.attempts)),
        ("Worked", grouped(connections.succeeded)),
        ("Unexpected disconnects", grouped(connections.lost)),
        (
            "Connecting took",
            format!(
                "{:.0} ms typically, {:.0} ms at the 99th percentile",
                connections.times.median_ms, connections.times.p99_ms
            ),
        ),
    ];
    if let Some(after) = connections.all_online_after_secs {
        items.push(("All online after", format!("{after:.1} seconds")));
    }
    let errors: String = connections
        .errors
        .iter()
        .take(10)
        .map(|error| row(&[error.error.clone(), grouped(error.count)]))
        .collect();
    let errors = if errors.is_empty() {
        String::new()
    } else {
        table(&["Error", "Times"], &errors)
    };
    format!(
        "<section><h2>Connections</h2>{}{errors}</section>",
        definitions(&items)
    )
}

fn capacity_section(report: &Report) -> String {
    let samples = &report.samples;
    let projection = &report.projection;
    let mut items = vec![
        ("Live samples sent", grouped(samples.live_sent)),
        ("Saved samples sent", grouped(samples.saved_sent)),
        (
            "Average sample",
            format!("{:.1} KB as sent", samples.average_bytes / 1000.0),
        ),
        (
            "Write queue peak",
            format!("{} of {}", samples.peak_queued, samples.queue_capacity),
        ),
    ];
    if let Some(days) = projection.days_until_disk_full {
        items.push(("Disk would fill in", format!("about {days:.0} days")));
    }
    format!(
        "<section><h2>Samples and capacity</h2>{}</section>",
        definitions(&items)
    )
}

fn pages_section(report: &Report) -> String {
    if report.pages.is_empty() {
        return String::new();
    }
    let rows: String = report
        .pages
        .iter()
        .map(|page| {
            row(&[
                page.path.clone(),
                format!("{:.0} ms", page.times.median_ms),
                format!("{:.0} ms", page.times.p95_ms),
                format!("{:.0} ms", page.times.max_ms),
                format!("{:.0} KB", page.bytes as f64 / 1000.0),
                grouped(page.loads as u64),
                grouped(page.errors as u64),
            ])
        })
        .collect();
    format!(
        "<section><h2>Pages</h2>{}</section>",
        table(
            &[
                "Page", "Median", "95th", "Slowest", "Size", "Loads", "Errors"
            ],
            &rows
        )
    )
}

fn data_section(report: &Report) -> String {
    let rows: String = report
        .timeline
        .iter()
        .map(|point| {
            row(&[
                clock(point.time_secs),
                point.agents_online.to_string(),
                format!("{:.0}", point.samples_written_per_sec),
                point.queued.to_string(),
                or_dash(point.cpu_cores, |c| format!("{c:.2}")),
                or_dash(point.memory_mb, |m| format!("{m:.0}")),
                or_dash(point.metrics_mb, |m| format!("{m:.0}")),
            ])
        })
        .collect();
    format!(
        "<details><summary>Chart data as a table</summary>{}</details>",
        table(
            &[
                "Time",
                "Online",
                "Written/s",
                "Queued",
                "CPU cores",
                "Memory MB",
                "Metrics MB"
            ],
            &rows
        )
    )
}

pub fn render(report: &Report) -> String {
    let server = &report.server;
    let settings: Vec<(&str, String)> = report
        .settings
        .iter()
        .map(|setting| (setting.name, setting.value.clone()))
        .collect();
    let running = definitions(&[
        ("Version", format!("{} ({})", server.version, server.commit)),
        ("System", server.os.clone()),
        ("Cores", server.cores.to_string()),
        ("Memory", format!("{:.0} GB", server.memory_gb)),
        ("Database", server.database.clone()),
    ]);
    let early = if report.stopped_early {
        r#"<p class="note">This test was stopped early.</p>"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MaxNines load test</title>
<style>{STYLE}</style>
</head>
<body>
<main>
<header>
  <div>
    <h1>MaxNines load test</h1>
    <p class="muted">{agents} agents for {length}, started {started}</p>
  </div>
  <p class="verdict {class}"><span aria-hidden="true">{icon}</span> {label}</p>
</header>
{early}
<div class="tiles">{tiles}</div>
<section><h2>Checks</h2>{checks}</section>
<section><h2>Over time</h2>{charts}</section>
{events}
<div class="columns">{connections}{capacity}</div>
{pages}
<div class="columns">
<section><h2>Server</h2>{running}</section>
<section><h2>Settings</h2>{settings}</section>
</div>
{data}
<p class="muted">Projections assume this load continues unchanged. They're only as good as how closely these simulated agents match your real ones, so compare a real agent's sample size with the one above.</p>
</main>
<script>{SCRIPT}</script>
</body>
</html>
"#,
        agents = grouped(report.connections.wanted),
        length = clock(report.ran_for_secs),
        started = escape(&report.started),
        class = class(report.outcome),
        icon = icon(report.outcome),
        label = report.outcome.label(),
        tiles = tiles(report),
        checks = checks(report),
        charts = charts(report),
        events = events(report),
        connections = connection_section(report),
        capacity = capacity_section(report),
        pages = pages_section(report),
        settings = definitions(&settings),
        data = data_section(report),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_from_the_server_is_never_markup() {
        assert_eq!(
            escape(r#"<img src=x onerror="a('b')">&"#),
            "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;"
        );
    }

    #[test]
    fn scales_end_on_round_numbers() {
        assert_eq!(scale_top(0.0), 1.0);
        assert_eq!(scale_top(95.0), 100.0);
        assert_eq!(scale_top(5000.0), 8000.0);
        assert_eq!(scale_top(2661.0), 4000.0);
        assert_eq!(scale_top(0.7), 0.8);
    }

    #[test]
    fn a_scale_always_reaches_the_largest_value() {
        for value in [0.3, 1.0, 7.0, 99.0, 333.0, 12_345.0] {
            assert!(scale_top(value) >= value, "{value}");
        }
    }

    #[test]
    fn numbers_lose_digits_they_do_not_need() {
        assert_eq!(number(2000.0), "2000");
        assert_eq!(number(12.5), "12.5");
        assert_eq!(number(0.25), "0.25");
        assert_eq!(number(3.0), "3");
    }

    #[test]
    fn big_numbers_are_grouped() {
        assert_eq!(grouped(5), "5");
        assert_eq!(grouped(5000), "5,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    #[test]
    fn a_chart_with_too_little_data_says_so() {
        let chart = Chart {
            title: "CPU",
            unit: "cores",
            points: vec![(1.0, 1.0)],
            limit: None,
        };
        assert!(draw(&chart, 60.0, &[]).contains("Not enough data"));
    }

    #[test]
    fn events_close_together_share_a_label() {
        let event = |time_secs| Event {
            time_secs,
            text: String::new(),
        };
        let labels = event_labels(&[event(10.0), event(11.0), event(100.0)], |time| time);

        assert_eq!(
            labels,
            [(10.0, "1, 2".to_string()), (100.0, "3".to_string())]
        );
    }

    #[test]
    fn a_limit_sets_the_top_of_the_scale() {
        let chart = Chart {
            title: "Queue",
            unit: "waiting",
            points: vec![(0.0, 0.0), (60.0, 0.0)],
            limit: Some(1024.0),
        };
        assert!(draw(&chart, 60.0, &[]).contains(">1024</text>"));
    }

    #[test]
    fn a_chart_marks_events() {
        let chart = Chart {
            title: "CPU",
            unit: "cores",
            points: vec![(0.0, 1.0), (60.0, 2.0)],
            limit: None,
        };
        let events = [Event {
            time_secs: 30.0,
            text: "outage".to_string(),
        }];
        let drawn = draw(&chart, 60.0, &events);
        assert!(drawn.contains(r#"class="event""#));
        assert!(drawn.contains(">1</text>"));
    }
}
