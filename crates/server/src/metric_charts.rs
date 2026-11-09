//! Turns metric series into charts. The geometry is worked out here and the
//! template draws it, so names chosen by agents only ever reach the page through
//! the template's escaping.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone};
use chrono_tz::Tz;
use serde::Serialize;

use crate::metrics::{Metric, Series, SeriesResult, TimeRange, Unit};
use crate::times::format_time;

/// The chart palette has this many colors, and a chart shows no more series.
pub const MAX_SERIES: usize = 8;

const WIDTH: f64 = 480.0;
const HEIGHT: f64 = 200.0;
const LEFT: f64 = 74.0;
const TOP: f64 = 10.0;
/// What's left of the plot's right and bottom edges, for the last label and the times.
const RIGHT_MARGIN: f64 = 8.0;
const BOTTOM_MARGIN: f64 = 24.0;

/// The space a chart is drawn in. Text stays the same size whatever this is.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Frame {
    pub width: f64,
    pub height: f64,
}

impl Frame {
    /// What charts are on the pages that show them in a grid of their own.
    pub const STANDARD: Self = Self {
        width: WIDTH,
        height: HEIGHT,
    };

    fn right(self) -> f64 {
        self.width - RIGHT_MARGIN
    }

    fn bottom(self) -> f64 {
        self.height - BOTTOM_MARGIN
    }
}

const MINUTE_MS: i64 = 60_000;
const DAY_MS: i64 = 1440 * MINUTE_MS;

/// Spacing for time labels, of which a chart shows at most [`MAX_TIME_LABELS`].
const TIME_LABEL_STEPS_MS: [i64; 13] = [
    MINUTE_MS,
    5 * MINUTE_MS,
    15 * MINUTE_MS,
    30 * MINUTE_MS,
    60 * MINUTE_MS,
    120 * MINUTE_MS,
    360 * MINUTE_MS,
    720 * MINUTE_MS,
    DAY_MS,
    2 * DAY_MS,
    7 * DAY_MS,
    14 * DAY_MS,
    30 * DAY_MS,
];
const MAX_TIME_LABELS: i64 = 5;

/// Half the width of a time label, which must stay inside the chart.
const TIME_LABEL_MARGIN: f64 = 18.0;

/// Points further apart than this many steps have a gap between them, so no
/// line is drawn across a time when nothing was reported.
const GAP_STEPS: f64 = 2.5;

/// Keeps very large values from overflowing when the axis is worked out.
const LARGEST_VALUE: f64 = 1e300;

const MAX_NAME_CHARS: usize = 15;
const TOOLTIP_CHAR_WIDTH: f64 = 6.5;
const TOOLTIP_PADDING: f64 = 30.0;
/// Wide enough for the time, which every tooltip starts with, in any time zone.
const TOOLTIP_MIN_WIDTH: f64 = 166.0;
const TOOLTIP_MAX_WIDTH: f64 = 190.0;
const TOOLTIP_ROW_HEIGHT: f64 = 15.0;
const TOOLTIP_GAP: f64 = 8.0;

#[derive(Debug, Serialize)]
pub struct Tick {
    pub position: f64,
    pub label: String,
}

/// A series' line. Each segment is a run with no gaps, and a point with nothing
/// either side is a dot, since a line needs two ends.
#[derive(Debug, Serialize)]
pub struct Line {
    pub slot: usize,
    pub segments: Vec<String>,
    pub dots: Vec<Dot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Dot {
    pub x: f64,
    pub y: f64,
}

/// One series in a tooltip.
#[derive(Debug, Serialize)]
pub struct TooltipRow {
    pub slot: usize,
    pub name: String,
    pub value: String,
    pub dot: Dot,
    pub text_y: f64,
}

/// A moment with data: the strip of the chart that shows it when hovered, and
/// what it shows.
#[derive(Debug, Serialize)]
pub struct Column {
    pub x: f64,
    pub hit_x: f64,
    pub hit_width: f64,
    /// For finding the same moment on the page's other charts.
    pub time_ms: i64,
    pub time: String,
    pub tooltip_x: f64,
    pub tooltip_width: f64,
    pub tooltip_height: f64,
    pub rows: Vec<TooltipRow>,
    /// A value per series, for the data table.
    pub cells: Vec<Option<String>>,
}

/// A row under the chart: the legend, with numbers that don't need hovering.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub slot: usize,
    pub name: String,
    pub latest: String,
    pub average: String,
    pub peak: String,
}

#[derive(Debug, Serialize)]
pub struct Chart {
    pub name: &'static str,
    pub title: String,
    pub has_data: bool,
    /// Series left out because a chart only shows so many.
    pub hidden: usize,
    pub left: f64,
    pub right: f64,
    pub top: f64,
    pub bottom: f64,
    pub width: f64,
    pub height: f64,
    pub y_ticks: Vec<Tick>,
    pub x_ticks: Vec<Tick>,
    pub lines: Vec<Line>,
    pub columns: Vec<Column>,
    /// How far from a moment this chart's data still counts as being at that moment.
    /// Further than this is a gap in its lines, so it has nothing to show for it.
    pub reach_ms: i64,
    pub summary: Vec<Summary>,
}

/// A chart with its times in `zone`.
pub fn build(metric: &Metric, result: &SeriesResult, range: TimeRange, zone: Tz) -> Chart {
    build_as(
        metric,
        metric.unit,
        metric.title,
        Frame::STANDARD,
        result,
        range,
        zone,
    )
}

/// A chart of something worked out from a metric, which can have its own unit and
/// title. Its times are in `zone`.
pub fn build_as(
    metric: &Metric,
    unit: Unit,
    title: &str,
    frame: Frame,
    result: &SeriesResult,
    range: TimeRange,
    zone: Tz,
) -> Chart {
    let axis = Axis::new(unit, &result.series, frame, &[]);
    chart_on(axis, metric, unit, title, frame, result, range, zone)
}

/// A chart whose scale reaches these values too, such as an alert's thresholds,
/// with how far down the chart each one is.
pub struct Marked {
    pub chart: Chart,
    pub marks: Vec<f64>,
}

#[allow(clippy::too_many_arguments)]
pub fn build_marked(
    metric: &Metric,
    unit: Unit,
    title: &str,
    frame: Frame,
    result: &SeriesResult,
    range: TimeRange,
    zone: Tz,
    values: &[f64],
) -> Marked {
    let axis = Axis::new(unit, &result.series, frame, values);
    let marks = values.iter().map(|value| axis.y(*value)).collect();
    Marked {
        chart: chart_on(axis, metric, unit, title, frame, result, range, zone),
        marks,
    }
}

/// How far across a chart a moment is.
pub fn x_of(time_ms: i64, range: TimeRange, frame: Frame) -> f64 {
    x_for(time_ms, range, frame)
}

#[allow(clippy::too_many_arguments)]
fn chart_on(
    axis: Axis,
    metric: &Metric,
    unit: Unit,
    title: &str,
    frame: Frame,
    result: &SeriesResult,
    range: TimeRange,
    zone: Tz,
) -> Chart {
    let slots = colour_slots(metric, &result.series);

    Chart {
        name: metric.name,
        title: title.to_string(),
        has_data: !result.series.is_empty(),
        hidden: result.hidden,
        left: LEFT,
        right: frame.right(),
        top: TOP,
        bottom: frame.bottom(),
        width: frame.width,
        height: frame.height,
        y_ticks: axis
            .ticks
            .iter()
            .map(|tick| Tick {
                position: axis.y(*tick),
                label: format_tick(unit, *tick),
            })
            .collect(),
        x_ticks: time_ticks(range, frame, zone),
        lines: result
            .series
            .iter()
            .zip(&slots)
            .map(|(series, slot)| line(series, *slot, &axis, range))
            .collect(),
        columns: columns(unit, &result.series, &slots, &axis, range, zone),
        reach_ms: result
            .series
            .iter()
            .map(|series| (gap_limit_ms(series, range) / 2.0) as i64)
            .max()
            .unwrap_or(0),
        summary: result
            .series
            .iter()
            .zip(&slots)
            .map(|(series, slot)| summary(unit, series, *slot))
            .collect(),
    }
}

fn x_for(time_ms: i64, range: TimeRange, frame: Frame) -> f64 {
    let share = (time_ms - range.from_ms) as f64 / (range.to_ms - range.from_ms) as f64;
    LEFT + share.clamp(0.0, 1.0) * (frame.right() - LEFT)
}

/// The vertical scale. It always includes zero, so a small change doesn't look
/// like a large one.
struct Axis {
    low: f64,
    high: f64,
    ticks: Vec<f64>,
    frame: Frame,
}

impl Axis {
    /// `include` are values the scale has to reach whatever the series do.
    fn new(unit: Unit, series: &[Series], frame: Frame, include: &[f64]) -> Self {
        let values = || {
            series
                .iter()
                .flat_map(|series| &series.points)
                .map(|point| point.avg)
                .chain(include.iter().copied())
                .map(|value| value.clamp(-LARGEST_VALUE, LARGEST_VALUE))
        };
        let lowest = values().fold(0.0, f64::min);
        let highest = values().fold(0.0, f64::max);

        let (floor, ceiling) = match unit {
            Unit::Percent => (0.0, 100.0),
            Unit::Number => (0.0, 1.0),
            Unit::BytesPerSecond | Unit::Bytes => (0.0, 1000.0),
            Unit::PerSecond | Unit::Seconds | Unit::Milliseconds => (0.0, 10.0),
            Unit::Celsius => (0.0, 100.0),
        };
        // A percentage reads best on its whole scale, and anything else on its
        // own values. Agents can still report beyond 100%.
        let fixed = unit == Unit::Percent && lowest >= floor && highest <= ceiling;
        let (lowest, highest) = if fixed {
            (floor, ceiling)
        } else if highest > lowest {
            (lowest, highest)
        } else {
            (floor, ceiling)
        };

        let step = nice_step(highest - lowest);
        let low = (lowest / step).floor() * step;
        let count = ((highest - low) / step).ceil().clamp(1.0, 12.0) as usize;
        let ticks: Vec<f64> = (0..=count).map(|index| low + index as f64 * step).collect();
        let high = ticks.last().copied().unwrap_or(highest);
        Self {
            low,
            high,
            ticks,
            frame,
        }
    }

    fn y(&self, value: f64) -> f64 {
        let value = value.clamp(-LARGEST_VALUE, LARGEST_VALUE);
        let share = (value - self.low) / (self.high - self.low);
        let bottom = self.frame.bottom();
        bottom - share.clamp(0.0, 1.0) * (bottom - TOP)
    }
}

/// A round step that divides `span` into about four.
fn nice_step(span: f64) -> f64 {
    let rough = span / 4.0;
    let magnitude = 10_f64.powf(rough.log10().floor());
    let step = [1.0, 2.0, 2.5, 5.0, 10.0]
        .into_iter()
        .find(|nice| nice * magnitude >= rough)
        .unwrap_or(10.0);
    step * magnitude
}

/// Labels on round times in `zone`, so they read 09:00 in a zone half an hour from
/// UTC, and days start at its midnight. Rounding is done on the zone's wall clock,
/// counted as if it were UTC, then each label goes back to the moment it names.
fn time_ticks(range: TimeRange, frame: Frame, zone: Tz) -> Vec<Tick> {
    let span = range.to_ms - range.from_ms;
    let step = TIME_LABEL_STEPS_MS
        .into_iter()
        .find(|step| span / step <= MAX_TIME_LABELS)
        .unwrap_or(span / MAX_TIME_LABELS)
        .max(1);
    let format = if step < DAY_MS { "%H:%M" } else { "%b %-d" };

    let Some(start) = DateTime::from_timestamp_millis(range.from_ms) else {
        return Vec::new();
    };
    let wall_start = start.with_timezone(&zone).naive_local().and_utc();
    let first = (wall_start.timestamp_millis() / step + 1) * step;
    // One more than fits, as clocks going back can make room for it.
    (0..=MAX_TIME_LABELS + 1)
        .map(|index| first + index * step)
        .filter_map(|wall| {
            let wall = DateTime::from_timestamp_millis(wall)?.naive_utc();
            // Nothing, for a time skipped when the clocks go forward.
            zone.from_local_datetime(&wall).earliest()
        })
        .map(|moment| (moment, moment.timestamp_millis()))
        .take_while(|(_, time)| *time < range.to_ms)
        .map(|(moment, time)| (moment, x_for(time, range, frame)))
        .filter(|(_, x)| *x - TIME_LABEL_MARGIN >= 0.0 && *x + TIME_LABEL_MARGIN <= frame.width)
        .map(|(moment, x)| Tick {
            position: x,
            label: moment.format(format).to_string(),
        })
        .collect()
}

/// Spacing is judged against the series itself as well as the step, because
/// an agent sampling every minute leaves empty buckets on a short range.
fn gap_limit_ms(series: &Series, range: TimeRange) -> f64 {
    let mut spacing: Vec<i64> = series
        .points
        .windows(2)
        .map(|pair| pair[1].time_ms - pair[0].time_ms)
        .collect();
    spacing.sort_unstable();
    let typical = spacing.get(spacing.len() / 2).copied().unwrap_or(0);
    GAP_STEPS * typical.max(range.step_ms) as f64
}

/// Which colour each series gets. A metric with named fields gives each of its
/// first few fields a colour of its own, the same on every machine, whichever
/// other fields a machine reports. Fields beyond the colours there are, as in
/// the memory breakdown, take whichever colours the machine's other fields leave
/// free, so no line is drawn in a colour that doesn't exist. Other metrics colour
/// their series in order.
fn colour_slots(metric: &Metric, series: &[Series]) -> Vec<usize> {
    let positions: Vec<Option<usize>> = series
        .iter()
        .map(|series| metric.position(&series.name))
        .collect();
    let mut slots: Vec<usize> = positions
        .iter()
        .enumerate()
        .map(|(index, position)| match position {
            Some(position) if *position < MAX_SERIES => position + 1,
            Some(_) => 0,
            None => index + 1,
        })
        .collect();
    let taken = slots.clone();
    let mut spare = (1..=MAX_SERIES).filter(move |slot| !taken.contains(slot));
    let mut overflow: Vec<usize> = (0..slots.len()).filter(|i| slots[*i] == 0).collect();
    overflow.sort_by_key(|i| positions[*i]);
    for index in overflow {
        slots[index] = spare
            .next()
            .unwrap_or(positions[index].unwrap_or(index) % MAX_SERIES + 1);
    }
    slots
}

fn line(series: &Series, slot: usize, axis: &Axis, range: TimeRange) -> Line {
    let limit = gap_limit_ms(series, range);

    let mut runs: Vec<Vec<Dot>> = Vec::new();
    let mut previous = None;
    for point in &series.points {
        let dot = Dot {
            x: x_for(point.time_ms, range, axis.frame),
            y: axis.y(point.avg),
        };
        match (previous, runs.last_mut()) {
            (Some(time), Some(run)) if (point.time_ms - time) as f64 <= limit => run.push(dot),
            _ => runs.push(vec![dot]),
        }
        previous = Some(point.time_ms);
    }

    let (dots, segments): (Vec<_>, Vec<_>) = runs.into_iter().partition(|run| run.len() == 1);
    Line {
        slot,
        dots: dots.into_iter().flatten().collect(),
        segments: segments
            .iter()
            .map(|run| {
                let points: Vec<String> = run
                    .iter()
                    .map(|dot| format!("{:.1},{:.1}", dot.x, dot.y))
                    .collect();
                points.join(" ")
            })
            .collect(),
    }
}

fn short_name(name: &str) -> String {
    if name.chars().count() <= MAX_NAME_CHARS {
        return name.to_string();
    }
    let start: String = name.chars().take(MAX_NAME_CHARS - 1).collect();
    format!("{start}…")
}

fn columns(
    unit: Unit,
    series: &[Series],
    slots: &[usize],
    axis: &Axis,
    range: TimeRange,
    zone: Tz,
) -> Vec<Column> {
    // Every moment any series has a value for, with a place for each series.
    let mut moments: BTreeMap<i64, Vec<Option<f64>>> = BTreeMap::new();
    for (index, series) in series.iter().enumerate() {
        for point in &series.points {
            moments
                .entry(point.time_ms)
                .or_insert_with(|| vec![None; slots.len()])[index] = Some(point.avg);
        }
    }

    let xs: Vec<f64> = moments
        .keys()
        .map(|time| x_for(*time, range, axis.frame))
        .collect();
    moments
        .iter()
        .enumerate()
        .map(|(index, (time, values))| {
            // Strips meet halfway, so hovering always lands on the nearest data.
            let start = index
                .checked_sub(1)
                .map_or(LEFT, |before| f64::midpoint(xs[before], xs[index]));
            let end = xs
                .get(index + 1)
                .map_or(axis.frame.right(), |after| f64::midpoint(xs[index], *after));
            column(
                unit,
                series,
                slots,
                axis,
                (*time, xs[index]),
                values,
                start,
                end,
                zone,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn column(
    unit: Unit,
    series: &[Series],
    slots: &[usize],
    axis: &Axis,
    (time_ms, x): (i64, f64),
    values: &[Option<f64>],
    start: f64,
    end: f64,
    zone: Tz,
) -> Column {
    let rows: Vec<TooltipRow> = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| Some((index, (*value)?)))
        .enumerate()
        .map(|(row, (index, value))| TooltipRow {
            slot: slots[index],
            name: short_name(&series[index].name),
            value: format_value(unit, value),
            dot: Dot {
                x,
                y: axis.y(value),
            },
            text_y: TOP + 2.0 * TOOLTIP_ROW_HEIGHT + row as f64 * TOOLTIP_ROW_HEIGHT,
        })
        .collect();

    let longest = rows
        .iter()
        .map(|row| row.name.chars().count() + row.value.chars().count())
        .max()
        .unwrap_or(0);
    let tooltip_width = (longest as f64 * TOOLTIP_CHAR_WIDTH + TOOLTIP_PADDING)
        .clamp(TOOLTIP_MIN_WIDTH, TOOLTIP_MAX_WIDTH);
    // Opens toward the middle, so it never runs off the chart.
    let tooltip_x = if x > f64::midpoint(LEFT, axis.frame.right()) {
        x - TOOLTIP_GAP - tooltip_width
    } else {
        x + TOOLTIP_GAP
    };

    Column {
        x,
        hit_x: start,
        hit_width: end - start,
        time_ms,
        time: format_time(u64::try_from(time_ms).unwrap_or(0), zone),
        tooltip_x,
        tooltip_width,
        tooltip_height: (rows.len() + 1) as f64 * TOOLTIP_ROW_HEIGHT + 12.0,
        rows,
        cells: values
            .iter()
            .map(|value| value.map(|value| format_value(unit, value)))
            .collect(),
    }
}

fn summary(unit: Unit, series: &Series, slot: usize) -> Summary {
    let count = series.points.len().max(1) as f64;
    let average = series.points.iter().map(|point| point.avg / count).sum();
    let peak = series
        .points
        .iter()
        .map(|point| point.max)
        .fold(f64::NEG_INFINITY, f64::max);
    let latest = series.points.last().map_or(0.0, |point| point.avg);

    Summary {
        slot,
        name: series.name.clone(),
        latest: format_value(unit, latest),
        average: format_value(unit, average),
        peak: format_value(unit, peak),
    }
}

/// Rounds without trailing zeros, so a label reads 2.5 and not 2.50.
fn trimmed(value: f64, decimals: usize) -> String {
    if value.abs() >= 1e15 {
        return format!("{value:.2e}");
    }
    let text = format!("{value:.decimals$}");
    let text = if text.contains('.') {
        text.trim_end_matches('0').trim_end_matches('.')
    } else {
        &text
    };
    if text == "-0" {
        "0".to_string()
    } else {
        text.to_string()
    }
}

fn format_size(value: f64, decimals: usize) -> String {
    let (divisor, label) = match value.abs() {
        size if size >= 1e12 => (1e12, "TB"),
        size if size >= 1e9 => (1e9, "GB"),
        size if size >= 1e6 => (1e6, "MB"),
        size if size >= 1e3 => (1e3, "KB"),
        _ => (1.0, "B"),
    };
    format!("{} {label}", trimmed(value / divisor, decimals))
}

fn format_rate(value: f64, decimals: usize) -> String {
    let (divisor, label) = match value.abs() {
        size if size >= 1e9 => (1e9, "GB/s"),
        size if size >= 1e6 => (1e6, "MB/s"),
        size if size >= 1e3 => (1e3, "KB/s"),
        _ => (1.0, "B/s"),
    };
    format!("{} {label}", trimmed(value / divisor, decimals))
}

fn format_age(value: f64, decimals: usize) -> String {
    let (divisor, label) = match value.abs() {
        age if age >= 86_400.0 => (86_400.0, "d"),
        age if age >= 3600.0 => (3600.0, "h"),
        age if age >= 60.0 => (60.0, "m"),
        _ => (1.0, "s"),
    };
    format!("{} {label}", trimmed(value / divisor, decimals))
}

pub fn format_value(unit: Unit, value: f64) -> String {
    match unit {
        Unit::Percent => format!("{}%", trimmed(value, 1)),
        Unit::Number => trimmed(value, 2),
        Unit::BytesPerSecond => format_rate(value, 1),
        other => format_other(other, value, 1),
    }
}

fn format_other(unit: Unit, value: f64, decimals: usize) -> String {
    match unit {
        Unit::PerSecond => format!("{}/s", trimmed(value, decimals)),
        Unit::Bytes => format_size(value, decimals),
        Unit::Seconds => format_age(value, decimals),
        Unit::Milliseconds => format!("{} ms", trimmed(value, decimals)),
        Unit::Celsius => format!("{}°C", trimmed(value, decimals)),
        Unit::Percent | Unit::Number | Unit::BytesPerSecond => trimmed(value, decimals),
    }
}

/// Tick steps can be finer than values are shown, and 2.25 mustn't read as 2.3.
fn format_tick(unit: Unit, value: f64) -> String {
    match unit {
        Unit::Percent => format!("{}%", trimmed(value, 2)),
        Unit::Number => trimmed(value, 2),
        Unit::BytesPerSecond => format_rate(value, 2),
        other => format_other(other, value, 2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{Point, find};
    use chrono_tz::Tz;

    const HOUR_MS: i64 = 3_600_000;

    fn range() -> TimeRange {
        TimeRange::new(0, HOUR_MS).unwrap()
    }

    fn point(time_ms: i64, avg: f64) -> Point {
        Point {
            time_ms,
            avg,
            min: avg,
            max: avg,
        }
    }

    fn series(name: &str, points: &[(i64, f64)]) -> Series {
        Series {
            name: name.to_string(),
            points: points.iter().map(|(t, v)| point(*t, *v)).collect(),
        }
    }

    fn chart(metric: &str, series: Vec<Series>) -> Chart {
        let result = SeriesResult { series, hidden: 0 };
        build(find(metric).unwrap(), &result, range(), Tz::UTC)
    }

    fn labels(ticks: &[Tick]) -> Vec<&str> {
        ticks.iter().map(|tick| tick.label.as_str()).collect()
    }

    /// Fifteen seconds apart, as an agent normally reports.
    fn steady(count: i64) -> Vec<(i64, f64)> {
        (0..count).map(|index| (index * 15_000, 50.0)).collect()
    }

    #[test]
    fn percentages_use_their_whole_scale() {
        let chart = chart("cpu.usage", vec![series("CPU", &[(0, 3.0), (15_000, 4.0)])]);
        assert_eq!(labels(&chart.y_ticks), ["0%", "25%", "50%", "75%", "100%"]);
    }

    #[test]
    fn a_percentage_beyond_100_still_fits_on_the_chart() {
        let chart = chart("cpu.usage", vec![series("CPU", &[(0, 450.0)])]);

        assert_eq!(chart.y_ticks.last().unwrap().label, "600%");
        let y = chart.columns[0].rows[0].dot.y;
        assert!(y > TOP && y < Frame::STANDARD.bottom(), "{y}");
    }

    #[test]
    fn a_negative_value_stays_on_the_chart() {
        let chart = chart(
            "cpu.load",
            vec![series("1 minute", &[(0, -3.0), (15_000, 1.0)])],
        );

        let lowest = chart.columns[0].rows[0].dot.y;
        assert!(lowest <= Frame::STANDARD.bottom(), "{lowest}");
        assert!(chart.y_ticks[0].label.starts_with('-'));
    }

    #[test]
    fn rates_get_round_ticks_in_a_readable_unit() {
        let chart = chart(
            "network.received",
            vec![series("en0", &[(0, 1_200_000.0), (15_000, 3_700_000.0)])],
        );
        assert_eq!(
            labels(&chart.y_ticks),
            ["0 B/s", "1 MB/s", "2 MB/s", "3 MB/s", "4 MB/s"]
        );
    }

    #[test]
    fn a_flat_line_at_zero_still_has_a_scale() {
        let chart = chart(
            "cpu.load",
            vec![series("1 minute", &[(0, 0.0), (15_000, 0.0)])],
        );

        assert_eq!(chart.y_ticks.first().unwrap().label, "0");
        assert_eq!(chart.y_ticks.last().unwrap().label, "1");
        assert_eq!(chart.columns[0].rows[0].dot.y, Frame::STANDARD.bottom());
    }

    #[test]
    fn extreme_values_stay_finite_and_on_the_chart() {
        for value in [f64::MAX, -f64::MAX, 1e-320] {
            let chart = chart(
                "cpu.load",
                vec![series("1 minute", &[(0, value), (15_000, 1.0)])],
            );

            assert!(chart.y_ticks.len() <= 13);
            for tick in &chart.y_ticks {
                assert!(tick.position.is_finite(), "{value}");
            }
            for column in &chart.columns {
                let y = column.rows[0].dot.y;
                assert!(
                    (TOP..=Frame::STANDARD.bottom()).contains(&y),
                    "{value} gave {y}"
                );
            }
        }
    }

    #[test]
    fn higher_values_are_higher_on_the_chart() {
        let chart = chart(
            "cpu.usage",
            vec![series("CPU", &[(0, 25.0), (15_000, 75.0)])],
        );

        let (low, high) = (&chart.columns[0], &chart.columns[1]);
        assert!(high.rows[0].dot.y < low.rows[0].dot.y);
        assert!(high.x > low.x);
    }

    #[test]
    fn a_steady_series_is_one_line() {
        let chart = chart("cpu.usage", vec![series("CPU", &steady(20))]);

        assert_eq!(chart.lines[0].segments.len(), 1);
        assert!(chart.lines[0].dots.is_empty());
    }

    #[test]
    fn no_line_is_drawn_across_a_gap() {
        let mut points = steady(4);
        points.extend((0..4).map(|index| (600_000 + index * 15_000, 50.0)));

        let chart = chart("cpu.usage", vec![series("CPU", &points)]);

        assert_eq!(chart.lines[0].segments.len(), 2);
    }

    #[test]
    fn a_missed_sample_is_not_a_gap() {
        let chart = chart(
            "cpu.usage",
            vec![series(
                "CPU",
                &[(0, 1.0), (15_000, 1.0), (45_000, 1.0), (60_000, 1.0)],
            )],
        );
        assert_eq!(chart.lines[0].segments.len(), 1);
    }

    #[test]
    fn an_agent_sampling_slowly_still_gets_a_line() {
        let points: Vec<(i64, f64)> = (0..10).map(|index| (index * 120_000, 1.0)).collect();

        let chart = chart("cpu.usage", vec![series("CPU", &points)]);

        assert_eq!(chart.lines[0].segments.len(), 1);
    }

    #[test]
    fn a_point_on_its_own_is_a_dot() {
        let mut points = steady(4);
        points.push((1_800_000, 50.0));

        let chart = chart("cpu.usage", vec![series("CPU", &points)]);

        assert_eq!(chart.lines[0].segments.len(), 1);
        assert_eq!(chart.lines[0].dots.len(), 1);
    }

    #[test]
    fn a_single_point_is_a_dot() {
        let chart = chart("cpu.usage", vec![series("CPU", &[(0, 5.0)])]);

        assert!(chart.lines[0].segments.is_empty());
        assert_eq!(chart.lines[0].dots.len(), 1);
    }

    #[test]
    fn hover_strips_cover_the_plot_without_overlapping() {
        let chart = chart(
            "cpu.usage",
            vec![series(
                "CPU",
                &[(600_000, 1.0), (615_000, 2.0), (3_000_000, 3.0)],
            )],
        );

        let columns = &chart.columns;
        assert_eq!(columns[0].hit_x, LEFT);
        for pair in columns.windows(2) {
            let end = pair[0].hit_x + pair[0].hit_width;
            assert!((end - pair[1].hit_x).abs() < 1e-9);
        }
        let last = columns.last().unwrap();
        assert!((last.hit_x + last.hit_width - Frame::STANDARD.right()).abs() < 1e-9);
    }

    #[test]
    fn a_bigger_frame_gives_a_bigger_plot_with_everything_inside_it() {
        let frame = Frame {
            width: 1000.0,
            height: 400.0,
        };
        let result = SeriesResult {
            series: vec![series("CPU", &[(0, 0.0), (HOUR_MS - 1, 100.0)])],
            hidden: 0,
        };

        let chart = build_as(
            find("cpu.usage").unwrap(),
            Unit::Percent,
            "Busy machines",
            frame,
            &result,
            range(),
            Tz::UTC,
        );

        assert_eq!(chart.title, "Busy machines");
        assert_eq!((chart.width, chart.height), (1000.0, 400.0));
        assert_eq!(chart.bottom, 376.0);
        assert_eq!(chart.columns[0].rows[0].dot.y, 376.0);
        let last = chart.columns.last().unwrap();
        assert!(last.x > 900.0 && last.x <= chart.right, "{}", last.x);
        assert!(last.tooltip_x >= 0.0);
    }

    #[test]
    fn columns_say_when_they_are_and_how_far_the_chart_reaches() {
        let chart = chart("cpu.usage", vec![series("CPU", &[(0, 1.0), (60_000, 2.0)])]);

        let times: Vec<i64> = chart.columns.iter().map(|column| column.time_ms).collect();
        assert_eq!(times, [0, 60_000]);
        assert_eq!(chart.reach_ms, 75_000);
    }

    /// macOS reports fields from the end of the memory breakdown's list, which
    /// would otherwise land on colours that don't exist.
    #[test]
    fn every_line_gets_one_of_the_colours_there_are() {
        let names = [
            "Active",
            "Wired",
            "Compressed",
            "Speculative",
            "Purgeable",
            "Free",
        ];
        let all = names.map(|name| series(name, &[(0, 1.0)])).to_vec();

        let built = chart("memory.detail", all);

        // Active, Wired and Compressed keep their own colours; the three fields past
        // the eighth take the lowest colours left.
        let slots: Vec<usize> = built.lines.iter().map(|line| line.slot).collect();
        assert_eq!(slots, [1, 3, 8, 2, 4, 5]);
        assert!(slots.iter().all(|slot| (1..=MAX_SERIES).contains(slot)));

        let linux = ["Active", "Inactive", "Cached", "Free"].map(|name| series(name, &[(0, 1.0)]));
        let built = chart("memory.detail", linux.to_vec());
        let slots: Vec<usize> = built.lines.iter().map(|line| line.slot).collect();
        assert_eq!(slots, [1, 2, 4, 3]);
    }

    #[test]
    fn tooltips_stay_inside_the_chart() {
        let name = "a very long series name that keeps on going";
        let points: Vec<(i64, f64)> = (0..240).map(|index| (index * 15_000, 1e14)).collect();

        let chart = chart("network.received", vec![series(name, &points)]);

        for column in &chart.columns {
            assert!(column.tooltip_x >= 0.0, "{}", column.tooltip_x);
            assert!(column.tooltip_x + column.tooltip_width <= WIDTH);
        }
    }

    #[test]
    fn a_full_tooltip_fits_the_chart_height() {
        let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let all = names.map(|name| series(name, &[(0, 1.0)])).to_vec();

        let chart = chart("disk.usage", all);

        assert_eq!(chart.columns[0].rows.len(), MAX_SERIES);
        assert!(TOP + chart.columns[0].tooltip_height <= HEIGHT);
    }

    #[test]
    fn a_tooltip_lists_every_series_at_that_moment_and_no_others() {
        let chart = chart(
            "memory.usage",
            vec![
                series("Memory", &[(0, 50.0), (15_000, 60.0)]),
                series("Swap", &[(15_000, 5.0)]),
            ],
        );

        assert_eq!(chart.columns[0].rows.len(), 1);
        assert_eq!(chart.columns[1].rows.len(), 2);
        assert_eq!(chart.columns[1].rows[1].value, "5%");
        assert_eq!(chart.columns[0].cells, [Some("50%".to_string()), None]);
    }

    #[test]
    fn long_names_are_shortened_in_tooltips_but_not_the_summary() {
        let name = "é".repeat(40);
        let chart = chart("disk.usage", vec![series(&name, &[(0, 1.0)])]);

        assert_eq!(
            chart.columns[0].rows[0].name.chars().count(),
            MAX_NAME_CHARS
        );
        assert_eq!(chart.summary[0].name, name);
    }

    #[test]
    fn a_fixed_series_keeps_its_color_when_another_is_missing() {
        let chart = chart("memory.usage", vec![series("Swap", &[(0, 5.0)])]);
        assert_eq!(chart.lines[0].slot, 2);
    }

    #[test]
    fn the_summary_shows_latest_average_and_peak() {
        let mut memory = series("Memory", &[(0, 10.0), (15_000, 30.0)]);
        memory.points[0].max = 90.0;

        let chart = chart("memory.usage", vec![memory]);

        let row = &chart.summary[0];
        assert_eq!(row.latest, "30%");
        assert_eq!(row.average, "20%");
        assert_eq!(row.peak, "90%");
    }

    #[test]
    fn an_average_of_huge_values_does_not_overflow() {
        let chart = chart(
            "cpu.load",
            vec![series("1 minute", &[(0, f64::MAX), (15_000, f64::MAX)])],
        );
        assert!(!chart.summary[0].average.contains("inf"));
    }

    #[test]
    fn no_data_gives_an_empty_chart_with_axes() {
        let chart = chart("cpu.usage", Vec::new());

        assert!(!chart.has_data);
        assert!(chart.columns.is_empty());
        assert!(!chart.x_ticks.is_empty());
    }

    #[test]
    fn time_labels_suit_the_range() {
        let start = 1_700_000_000_000;
        let ticks = |hours: i64| {
            let range = TimeRange::new(start, start + hours * HOUR_MS).unwrap();
            time_ticks(range, Frame::STANDARD, Tz::UTC)
        };

        assert_eq!(labels(&ticks(1)), ["22:15", "22:30", "22:45", "23:00"]);
        assert_eq!(labels(&ticks(24)), ["00:00", "06:00", "12:00", "18:00"]);
        assert_eq!(labels(&ticks(24 * 7)).first(), Some(&"Nov 15"));
    }

    #[test]
    fn time_labels_fall_on_round_times_in_the_readers_zone() {
        let start = 1_700_000_000_000;
        let ticks = |hours: i64, zone: Tz| {
            let range = TimeRange::new(start, start + hours * HOUR_MS).unwrap();
            time_ticks(range, Frame::STANDARD, zone)
        };

        // Half an hour from UTC, so labels on round UTC times would read 03:45 and so on.
        assert_eq!(
            labels(&ticks(1, Tz::Asia__Kolkata)),
            ["03:45", "04:00", "04:15", "04:30"]
        );
        assert_eq!(
            labels(&ticks(24, Tz::Asia__Kolkata)),
            ["06:00", "12:00", "18:00", "00:00"]
        );
        assert_eq!(
            labels(&ticks(24, Tz::America__Los_Angeles)),
            ["18:00", "00:00", "06:00", "12:00"]
        );
        // A week is labelled every other day, at the zone's midnight. It starts at 11:13
        // on Nov 15 in Auckland, when it's still Nov 14 in UTC.
        let week = ticks(24 * 7, Tz::Pacific__Auckland);
        assert_eq!(labels(&week).first(), Some(&"Nov 17"));
        let auckland_midnight = 1_700_132_400_000; // Nov 17 00:00 NZDT
        let range = TimeRange::new(start, start + 24 * 7 * HOUR_MS).unwrap();
        assert_eq!(
            week[0].position,
            x_for(auckland_midnight, range, Frame::STANDARD)
        );
    }

    #[test]
    fn time_labels_skip_the_hour_the_clocks_jump_over() {
        // Clocks in New York went from 02:00 to 03:00 on March 10, 2024 (07:00 UTC).
        let from = 1_710_050_400_000; // 01:00 EST
        let range = TimeRange::new(from, from + 3 * HOUR_MS).unwrap();

        let ticks = time_ticks(range, Frame::STANDARD, Tz::America__New_York);

        let labels = labels(&ticks);
        assert!(!labels.contains(&"02:00"), "{labels:?}");
        assert!(labels.contains(&"03:00"), "{labels:?}");
        for pair in ticks.windows(2) {
            assert!(pair[0].position < pair[1].position);
        }
    }

    #[test]
    fn tooltips_give_the_time_in_the_readers_zone() {
        let result = SeriesResult {
            series: vec![series("CPU", &[(0, 1.0)])],
            hidden: 0,
        };
        let chart = build(
            find("cpu.usage").unwrap(),
            &result,
            range(),
            Tz::Asia__Kathmandu,
        );

        assert_eq!(chart.columns[0].time, "1970-01-01 05:30:00 +0530");
    }

    #[test]
    fn time_labels_stay_in_order_and_inside_the_chart() {
        for hours in [1, 6, 24, 24 * 7, 24 * 30, 24 * 366] {
            let from = 1_700_000_123_456;
            let range = TimeRange::new(from, from + hours * HOUR_MS).unwrap();

            let ticks = time_ticks(range, Frame::STANDARD, Tz::UTC);

            assert!(!ticks.is_empty(), "{hours}");
            assert!(ticks.len() <= 6, "{hours}");
            for pair in ticks.windows(2) {
                assert!(pair[0].position < pair[1].position);
            }
        }
    }

    #[test]
    fn values_read_naturally() {
        for (unit, value, text) in [
            (Unit::Percent, 12.34, "12.3%"),
            (Unit::Percent, 100.0, "100%"),
            (Unit::Number, 1.5, "1.5"),
            (Unit::Number, -0.001, "0"),
            (Unit::BytesPerSecond, 512.0, "512 B/s"),
            (Unit::BytesPerSecond, 1500.0, "1.5 KB/s"),
            (Unit::BytesPerSecond, 2_500_000.0, "2.5 MB/s"),
            (Unit::BytesPerSecond, 3e9, "3 GB/s"),
            (Unit::Number, 2e20, "2.00e20"),
            (Unit::PerSecond, 12.5, "12.5/s"),
            (Unit::Bytes, 512.0, "512 B"),
            (Unit::Bytes, 2_500_000.0, "2.5 MB"),
            (Unit::Bytes, 4e12, "4 TB"),
            (Unit::Seconds, 45.0, "45 s"),
            (Unit::Seconds, 90.0, "1.5 m"),
            (Unit::Seconds, 7200.0, "2 h"),
            (Unit::Seconds, 172_800.0, "2 d"),
            (Unit::Milliseconds, 12.34, "12.3 ms"),
            (Unit::Celsius, 54.5, "54.5°C"),
        ] {
            assert_eq!(format_value(unit, value), text);
        }
    }

    #[test]
    fn tick_labels_keep_the_precision_of_their_step() {
        assert_eq!(format_tick(Unit::Number, 2.25), "2.25");
        assert_eq!(format_tick(Unit::BytesPerSecond, 2_250_000.0), "2.25 MB/s");
    }
}
