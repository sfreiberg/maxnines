//! A picture of what an alert is about, for the channels that show images: the last
//! hour of the metric or calculation it watches, with the rule's thresholds and the
//! moment it started. It's drawn in the Carbon theme, from the colours in
//! `themes.css`, and turned into a PNG inside the server.
//!
//! Agents choose host and series names, so every bit of text is escaped before it
//! goes into the SVG.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result};
use chrono_tz::Tz;
use resvg::{tiny_skia, usvg};

use crate::alerting::{Alert, AlertRuleInput, RuleKind, Severity, clean};
use crate::calculations::{self, Grouping, Sources};
use crate::metric_charts::{self, Frame, MAX_SERIES, Marked};
use crate::metrics::{Metric, Metrics, SeriesResult, Source, TimeRange, Unit};
use crate::models::Database;
use crate::registration::Registry;

/// How far back the picture goes.
const HOUR_MS: i64 = 3_600_000;

/// The picture's size before it's doubled for sharp screens.
const WIDTH: f64 = 720.0;
const HEIGHT: f64 = 340.0;
const PADDING: f64 = 16.0;
/// Room above the chart for the title.
const HEADER: f64 = 58.0;
const SCALE: f32 = 2.0;

const FONT: &str = "Inter";
static FONTS: LazyLock<Arc<usvg::fontdb::Database>> = LazyLock::new(|| {
    let mut fonts = usvg::fontdb::Database::new();
    fonts.load_font_data(include_bytes!("../assets/fonts/inter-regular.ttf").to_vec());
    fonts.load_font_data(include_bytes!("../assets/fonts/inter-semibold.ttf").to_vec());
    Arc::new(fonts)
});

/// The Carbon theme's colours, by name without the leading `--`.
static CARBON: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| theme_colours(include_str!("../assets/static/css/themes.css"), "carbon"));

/// The custom properties in a theme's block of `themes.css`.
fn theme_colours(css: &str, theme: &str) -> BTreeMap<String, String> {
    let selector = format!("[data-theme=\"{theme}\"]");
    let Some(block) = css
        .find(&selector)
        .and_then(|start| css[start..].split_once('{'))
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(block, _)| block)
    else {
        return BTreeMap::new();
    };
    block
        .split(';')
        .filter_map(|declaration| declaration.trim().strip_prefix("--")?.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn colour(name: &str) -> &'static str {
    CARBON.get(name).map_or("#888888", String::as_str)
}

/// What a chart needs to be read.
pub struct ChartSources {
    pub database: Database,
    pub registry: Arc<Registry>,
    pub metrics: Metrics,
}

impl ChartSources {
    /// The alert's picture as a PNG, or nothing for an alert that has no metric to
    /// show, such as an agent going offline, or whose rule is gone.
    pub async fn draw(&self, alert: &Alert, now_ms: i64) -> Result<Option<Vec<u8>>> {
        let Some(rule_id) = alert.rule_id else {
            return Ok(None);
        };
        let Some(rule) = self.database.get_alert_rule(rule_id).await? else {
            return Ok(None);
        };
        let Some(range) = TimeRange::new(now_ms - HOUR_MS, now_ms) else {
            return Ok(None);
        };
        let rule = &rule.rule;
        let Some((metric, unit, mut result)) = self.read(alert, rule, range).await? else {
            return Ok(None);
        };
        result
            .series
            .retain(|series| alert.series.is_empty() || clean(&series.name) == alert.series);
        if result.series.is_empty() {
            return Ok(None);
        }

        let svg = svg(alert, rule, metric, unit, &result, range);
        let png = tokio::task::spawn_blocking(move || png(&svg))
            .await
            .context("drawing a chart")??;
        Ok(Some(png))
    }

    async fn read(
        &self,
        alert: &Alert,
        rule: &AlertRuleInput,
        range: TimeRange,
    ) -> Result<Option<(&'static Metric, Unit, SeriesResult)>> {
        match rule.kind {
            RuleKind::Offline => Ok(None),
            RuleKind::Metric => {
                let Some(metric) = rule.metric() else {
                    return Ok(None);
                };
                let result = self
                    .metrics
                    .series(&alert.agent_id, metric, range, MAX_SERIES)
                    .await?;
                Ok(Some((metric, metric.unit, result)))
            }
            RuleKind::Calculation => {
                let Ok(question) = rule.question() else {
                    return Ok(None);
                };
                let sources = Sources {
                    database: &self.database,
                    registry: &self.registry,
                    metrics: &self.metrics,
                };
                let mut result =
                    calculations::answer(&sources, &question, range, MAX_SERIES).await?;
                // One line for everything is named after the metric in the alert.
                if question.grouping == Grouping::Nothing {
                    for series in &mut result.series {
                        series.name = alert.series.clone();
                    }
                }
                Ok(Some((question.metric, question.unit(), result)))
            }
        }
    }
}

/// Escapes text for SVG.
fn xml(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// What the alert watches, in a few words.
fn heading(alert: &Alert, metric: &Metric) -> String {
    let watched = match metric.source {
        Source::Fields([_]) => metric.title.to_string(),
        _ if alert.series.is_empty() => metric.title.to_string(),
        _ => format!("{} ({})", metric.title, alert.series),
    };
    format!("{watched} on {}", alert.host)
}

fn severity_colour(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => colour("warn"),
        Severity::Critical => colour("bad"),
    }
}

fn svg(
    alert: &Alert,
    rule: &AlertRuleInput,
    metric: &Metric,
    unit: Unit,
    result: &SeriesResult,
    range: TimeRange,
) -> String {
    let frame = Frame {
        width: WIDTH - 2.0 * PADDING,
        height: HEIGHT - HEADER - PADDING,
    };
    let levels = rule.levels();
    let thresholds: Vec<f64> = levels.iter().map(|(_, threshold)| *threshold).collect();
    let Marked { chart, marks } = metric_charts::build_marked(
        metric,
        unit,
        metric.title,
        frame,
        result,
        range,
        Tz::UTC,
        &thresholds,
    );

    let mut svg = String::new();
    let _ = write!(
        svg,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" font-family="{FONT}">"#
    );
    let _ = write!(
        svg,
        r#"<rect width="{WIDTH}" height="{HEIGHT}" rx="10" fill="{}"/>"#,
        colour("surface")
    );
    let _ = write!(
        svg,
        r#"<text x="{PADDING}" y="30" font-size="16" font-weight="600" fill="{}">{}</text>"#,
        colour("text"),
        xml(&heading(alert, metric))
    );
    let _ = write!(
        svg,
        r#"<text x="{PADDING}" y="48" font-size="12" fill="{}">The last hour, in UTC · {}</text>"#,
        colour("muted"),
        xml(&rule.name)
    );

    let _ = write!(svg, r#"<g transform="translate({PADDING} {HEADER})">"#);
    for tick in &chart.y_ticks {
        let _ = write!(
            svg,
            r#"<line x1="{}" x2="{}" y1="{y}" y2="{y}" stroke="{}" stroke-width="1"/>"#,
            chart.left,
            chart.right,
            colour("border-strong"),
            y = tick.position
        );
        let _ = write!(
            svg,
            r#"<text x="{}" y="{}" font-size="11" text-anchor="end" fill="{}">{}</text>"#,
            chart.left - 6.0,
            tick.position + 4.0,
            colour("muted"),
            xml(&tick.label)
        );
    }
    for tick in &chart.x_ticks {
        let _ = write!(
            svg,
            r#"<text x="{}" y="{}" font-size="11" text-anchor="middle" fill="{}">{}</text>"#,
            tick.position,
            chart.bottom + 18.0,
            colour("muted"),
            xml(&tick.label)
        );
    }

    // When the alert started, if it was within the hour.
    if alert.started_ms >= range.from_ms {
        let x = metric_charts::x_of(alert.started_ms, range, frame);
        let _ = write!(
            svg,
            r#"<line x1="{x}" x2="{x}" y1="{}" y2="{}" stroke="{}" stroke-width="1" stroke-dasharray="2 3"/>"#,
            chart.top,
            chart.bottom,
            colour("muted")
        );
        let _ = write!(
            svg,
            r#"<text x="{}" y="{}" font-size="10" fill="{}">Started</text>"#,
            x + 4.0,
            chart.bottom - 6.0,
            colour("muted")
        );
    }

    for ((severity, threshold), y) in levels.iter().zip(&marks) {
        let paint = severity_colour(*severity);
        let _ = write!(
            svg,
            r#"<line x1="{}" x2="{}" y1="{y}" y2="{y}" stroke="{paint}" stroke-width="1.5" stroke-dasharray="6 4"/>"#,
            chart.left, chart.right
        );
        let _ = write!(
            svg,
            r#"<text x="{}" y="{}" font-size="11" text-anchor="end" fill="{paint}">{} {}</text>"#,
            chart.right,
            y - 5.0,
            xml(&metric_charts::format_value(unit, *threshold)),
            severity.as_str()
        );
    }

    for line in &chart.lines {
        let paint = colour(&format!("series-{}", line.slot));
        for segment in &line.segments {
            let _ = write!(
                svg,
                r#"<polyline points="{segment}" fill="none" stroke="{paint}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>"#
            );
        }
        for dot in &line.dots {
            let _ = write!(
                svg,
                r#"<circle cx="{}" cy="{}" r="3" fill="{paint}"/>"#,
                dot.x, dot.y
            );
        }
    }
    svg.push_str("</g></svg>");
    svg
}

fn png(svg: &str) -> Result<Vec<u8>> {
    let options = usvg::Options {
        fontdb: FONTS.clone(),
        font_family: FONT.to_string(),
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_str(svg, &options).context("reading the chart")?;
    let size = tree
        .size()
        .to_int_size()
        .scale_by(SCALE)
        .context("sizing the chart")?;
    let mut pixmap =
        tiny_skia::Pixmap::new(size.width(), size.height()).context("making the chart's image")?;
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(SCALE, SCALE),
        &mut pixmap.as_mut(),
    );
    pixmap.encode_png().context("encoding the chart")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::Comparison;
    use crate::metrics::{self, Point, Series};

    fn alert() -> Alert {
        Alert {
            id: 1,
            rule_id: Some(1),
            rule_name: "Disk filling up".to_string(),
            severity: Severity::Warning,
            agent_id: "abc".to_string(),
            host: "web-<1>".to_string(),
            series: "/".to_string(),
            value: Some(85.0),
            summary: String::new(),
            started_ms: 1_700_000_000_000 - 600_000,
            resolved_ms: None,
            resolve_reason: None,
            acknowledged_by: None,
            acknowledged_ms: None,
        }
    }

    fn rule() -> AlertRuleInput {
        AlertRuleInput {
            name: "Disk & more".to_string(),
            kind: RuleKind::Metric,
            metric: Some("disk.usage".to_string()),
            series: None,
            comparison: Some(Comparison::Above),
            threshold: Some(90.0),
            warning_threshold: Some(80.0),
            for_secs: 300,
            severity: Severity::Critical,
            condition: None,
            enabled: true,
            channels: Vec::new(),
            all_channels: true,
            calculation: None,
            group_by: None,
            filter: None,
            window_secs: None,
            remind_every_secs: None,
        }
    }

    fn hour() -> (TimeRange, SeriesResult) {
        let now = 1_700_000_000_000;
        let range = TimeRange::new(now - HOUR_MS, now).unwrap();
        let points = (0..60)
            .map(|minute| Point {
                time_ms: now - HOUR_MS + minute * 60_000,
                avg: 70.0 + minute as f64 / 3.0,
                min: 70.0,
                max: 90.0,
            })
            .collect();
        let result = SeriesResult {
            series: vec![Series {
                name: "/".to_string(),
                points,
            }],
            hidden: 0,
        };
        (range, result)
    }

    #[test]
    fn the_colours_come_from_the_carbon_theme() {
        let css = include_str!("../assets/static/css/themes.css");
        let carbon = theme_colours(css, "carbon");
        for name in [
            "surface",
            "text",
            "muted",
            "warn",
            "bad",
            "series-1",
            "border-strong",
        ] {
            assert!(
                carbon.get(name).is_some_and(|value| value.starts_with('#')),
                "{name}"
            );
        }
        assert_eq!(colour("bad"), carbon["bad"]);
    }

    #[test]
    fn a_chart_shows_both_thresholds_and_escapes_what_agents_chose() {
        let metric = metrics::find("disk.usage").unwrap();
        let (range, result) = hour();
        let svg = svg(&alert(), &rule(), metric, metric.unit, &result, range);

        assert!(svg.contains("Disk usage (/) on web-&lt;1&gt;"), "{svg}");
        assert!(svg.contains("Disk &amp; more"));
        assert!(svg.contains(">80% warning</text>"), "{svg}");
        assert!(svg.contains(">90% critical</text>"));
        assert!(svg.contains("<polyline"));
        assert!(!svg.contains("web-<1>"));
    }

    #[test]
    fn a_chart_becomes_a_png_twice_its_size() {
        let metric = metrics::find("disk.usage").unwrap();
        let (range, result) = hour();
        let png = png(&svg(&alert(), &rule(), metric, metric.unit, &result, range)).unwrap();

        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(png[20..24].try_into().unwrap());
        assert_eq!((width, height), (1440, 680));
    }

    #[test]
    fn the_fonts_load() {
        assert_eq!(FONTS.len(), 2);
        assert!(FONTS.faces().all(|face| face.families[0].0 == FONT));
    }
}
