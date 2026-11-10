//! Dashboards people put together from widgets, each asking one question about the
//! fleet. Everyone signed in shares them for now.

use anyhow::Result;
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::app_state::AppState;
use crate::calculations::{self, Grouping, Question};
use crate::dashboard_variables::{Picks, Variable, check_uses, check_variables, uses};
use crate::metric_charts::{self, Chart, Frame, MAX_SERIES};
use crate::metrics::TimeRange;

/// The grid's width. GridStack is told the same.
pub const COLUMNS: i32 = 12;
const MAX_ROWS: i32 = 24;
const MAX_POSITION: i32 = 10_000;
const MAX_NAME_LEN: usize = 100;
const MAX_WIDGETS: usize = 50;
/// A table has room for more than a chart has colours.
const MAX_TABLE_LINES: usize = 25;

/// How a grid cell turns into space on a chart, so text is about the same size on any
/// widget. It doesn't have to be exact, as the chart scales to fit.
const FRAME_PER_COLUMN: f64 = 96.0;
const FRAME_PER_ROW: f64 = 66.0;
/// A tooltip with every series has to fit.
const SMALLEST_FRAME_HEIGHT: f64 = 165.0;

pub const KINDS: [&str; 3] = ["chart", "number", "table"];

fn default_width() -> i32 {
    COLUMNS / 2
}

fn default_height() -> i32 {
    4
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    #[serde(default)]
    pub x: i32,
    #[serde(default)]
    pub y: i32,
    #[serde(default = "default_width")]
    pub w: i32,
    #[serde(default = "default_height")]
    pub h: i32,
}

impl Default for Placement {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            w: default_width(),
            h: default_height(),
        }
    }
}

impl Placement {
    fn is_valid(self) -> bool {
        (0..COLUMNS).contains(&self.x)
            && (1..=COLUMNS).contains(&self.w)
            && self.x + self.w <= COLUMNS
            && (0..=MAX_POSITION).contains(&self.y)
            && (1..=MAX_ROWS).contains(&self.h)
    }

    fn frame(self) -> Frame {
        Frame {
            width: f64::from(self.w) * FRAME_PER_COLUMN,
            height: (f64::from(self.h - 1) * FRAME_PER_ROW).max(SMALLEST_FRAME_HEIGHT),
        }
    }
}

/// A widget's place, as the layout is saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placed {
    pub id: i64,
    #[serde(flatten)]
    pub placement: Placement,
}

fn default_kind() -> String {
    KINDS[0].to_string()
}

fn default_calculation() -> String {
    "avg".to_string()
}

fn default_group_by() -> String {
    "nothing".to_string()
}

/// What makes up a widget. Everything's kept as it was chosen, and checked by
/// [`WidgetInput::question`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WidgetInput {
    #[serde(default)]
    pub title: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub metric: String,
    #[serde(default = "default_calculation")]
    pub calculation: String,
    #[serde(default = "default_group_by")]
    pub group_by: String,
    #[serde(default)]
    pub filter: String,
    #[serde(flatten)]
    pub placement: Placement,
}

impl WidgetInput {
    /// A number shows one value, so nothing gets a line of its own.
    pub fn question(&self) -> Result<Question, String> {
        self.question_for(&self.filter)
    }

    /// The question with its filter as variables fill it in.
    pub fn question_for(&self, filter: &str) -> Result<Question, String> {
        let group_by = if self.kind == "number" {
            "nothing"
        } else {
            self.group_by.as_str()
        };
        Question::new(&self.metric, &self.calculation, group_by, filter)
    }

    /// How many lines it has room for.
    pub fn max_lines(&self) -> usize {
        match self.kind.as_str() {
            "table" => MAX_TABLE_LINES,
            "number" => 1,
            _ => MAX_SERIES,
        }
    }

    /// The error says what's wrong, to show whoever chose it. Its filter can only use
    /// the dashboard's `variables`.
    pub fn check(&self, variables: &[Variable]) -> Result<(), String> {
        if self.title.chars().count() > MAX_NAME_LEN {
            return Err(format!("A title can be up to {MAX_NAME_LEN} characters."));
        }
        if !KINDS.contains(&self.kind.as_str()) {
            return Err("Choose a kind of widget.".to_string());
        }
        if !self.placement.is_valid() {
            return Err("That doesn't fit on the grid.".to_string());
        }
        check_uses(&self.filter, variables)?;
        self.question().map(|_| ())
    }

    pub fn title(&self, question: &Question, picks: &Picks) -> String {
        match self.title.trim() {
            "" => question.metric.title.to_string(),
            title => picks.fill_title(title),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Widget {
    pub id: i64,
    #[serde(flatten)]
    pub input: WidgetInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dashboard {
    pub id: i64,
    pub name: String,
    pub variables: Vec<Variable>,
    pub widgets: Vec<Widget>,
}

impl Dashboard {
    /// Where a new widget goes: on a row of its own at the bottom.
    pub fn next_row(&self) -> i32 {
        self.widgets
            .iter()
            .map(|widget| widget.input.placement.y + widget.input.placement.h)
            .max()
            .unwrap_or(0)
    }

    pub fn is_full(&self) -> bool {
        self.widgets.len() >= MAX_WIDGETS
    }

    /// Whether its widgets could all still be shown with these variables instead.
    /// The error names a widget that uses one that would be gone.
    pub fn check_variables(&self, variables: &[Variable]) -> Result<(), String> {
        check_variables(variables)?;
        for widget in &self.widgets {
            if let Some(name) = uses(&widget.input.filter)
                .into_iter()
                .find(|name| !variables.iter().any(|variable| variable.name == *name))
            {
                let title = match widget.input.title.trim() {
                    "" => widget.input.metric.as_str(),
                    title => title,
                };
                return Err(format!(
                    "The widget \u{201c}{title}\u{201d} uses ${name}. Change its filter first."
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DashboardSummary {
    pub id: i64,
    pub name: String,
    pub widgets: u64,
}

/// A name that can be saved, or what's wrong with it.
pub fn check_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("A dashboard needs a name.".to_string());
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(format!("A name can be up to {MAX_NAME_LEN} characters."));
    }
    Ok(name.to_string())
}

/// A layout that can be saved, or what's wrong with it.
pub fn check_layout(widgets: &[Placed]) -> Result<(), String> {
    if widgets.iter().all(|widget| widget.placement.is_valid()) {
        Ok(())
    } else {
        Err("That doesn't fit on the grid.".to_string())
    }
}

/// What a widget shows right now.
#[derive(Debug, Serialize)]
pub struct WidgetView {
    pub kind: String,
    pub title: String,
    pub chart: Option<Chart>,
    /// Lines left out because there are too many to show.
    pub hidden: usize,
    pub failed: bool,
    /// Why there's nothing to show, such as no machine to pick.
    pub missing: Option<String>,
}

/// One widget failing leaves the others working, so this always has something to show.
/// Its times are in `zone`, and its variables stand for what's in `picks`.
pub async fn view(
    state: &AppState,
    widget: &Widget,
    picks: &Picks,
    range: TimeRange,
    zone: Tz,
) -> WidgetView {
    let input = &widget.input;
    let filter = match picks.fill_filter(&input.filter) {
        Ok(filter) => filter,
        Err(missing) => {
            return WidgetView {
                title: picks.fill_title(&input.title),
                missing: Some(missing),
                failed: false,
                ..failed_view(input)
            };
        }
    };
    let question = match input.question_for(&filter) {
        Ok(question) => question,
        Err(error) => {
            warn!(
                widget = widget.id,
                error, "a saved widget doesn't make sense"
            );
            return failed_view(input);
        }
    };
    match calculations::answer(&state.sources(), &question, range, input.max_lines()).await {
        Ok(result) => {
            let title = input.title(&question, picks);
            let chart = metric_charts::build_as(
                question.metric,
                question.unit(),
                &title,
                input.placement.frame(),
                &result,
                range,
                zone,
            );
            WidgetView {
                kind: input.kind.clone(),
                title,
                hidden: chart.hidden,
                chart: Some(chart),
                failed: false,
                missing: None,
            }
        }
        Err(error) => {
            let error = format!("{error:#}");
            warn!(widget = widget.id, error, "reading a widget failed");
            failed_view(input)
        }
    }
}

fn failed_view(input: &WidgetInput) -> WidgetView {
    WidgetView {
        kind: input.kind.clone(),
        title: input.title.clone(),
        chart: None,
        hidden: 0,
        failed: true,
        missing: None,
    }
}

/// What a widget's form offers for grouping, as the form's two fields.
pub fn grouping_fields(group_by: &str) -> (String, String) {
    match Grouping::parse(group_by) {
        Some(Grouping::Fact(name)) => ("fact".to_string(), name),
        Some(grouping) => (grouping.as_text(), String::new()),
        None => (default_group_by(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> WidgetInput {
        WidgetInput {
            title: String::new(),
            kind: "chart".to_string(),
            metric: "cpu.usage".to_string(),
            calculation: "avg".to_string(),
            group_by: "host".to_string(),
            filter: String::new(),
            placement: Placement::default(),
        }
    }

    #[test]
    fn a_widget_has_to_fit_on_the_grid() {
        let at = |x, y, w, h| {
            let mut widget = input();
            widget.placement = Placement { x, y, w, h };
            widget.check(&[])
        };
        assert!(at(0, 0, 12, 4).is_ok());
        assert!(at(6, 100, 6, 24).is_ok());
        assert!(at(7, 0, 6, 4).is_err(), "runs off the side");
        assert!(at(-1, 0, 6, 4).is_err());
        assert!(at(0, 0, 0, 4).is_err());
        assert!(at(0, 0, 6, 0).is_err());
        assert!(at(0, 0, 6, 25).is_err());
        assert!(at(0, -1, 6, 4).is_err());
    }

    #[test]
    fn a_widget_has_to_be_something_it_can_show() {
        let mut widget = input();
        widget.kind = "pie".to_string();
        assert!(widget.check(&[]).is_err());

        let mut widget = input();
        widget.metric = "nope".to_string();
        assert!(widget.check(&[]).is_err());

        let mut widget = input();
        widget.title = "x".repeat(101);
        assert!(widget.check(&[]).is_err());
    }

    #[test]
    fn a_number_shows_one_value_however_it_was_grouped() {
        let mut widget = input();
        widget.kind = "number".to_string();
        assert_eq!(widget.question().unwrap().grouping, Grouping::Nothing);
    }

    #[test]
    fn a_widget_with_no_title_is_named_after_its_metric() {
        let widget = input();
        let question = widget.question().unwrap();
        assert_eq!(widget.title(&question, &Picks::default()), "CPU usage");
    }

    #[test]
    fn a_new_widget_goes_below_the_rest() {
        let mut dashboard = Dashboard {
            id: 1,
            name: "Fleet".to_string(),
            variables: Vec::new(),
            widgets: Vec::new(),
        };
        assert_eq!(dashboard.next_row(), 0);

        let mut widget = input();
        widget.placement = Placement {
            x: 0,
            y: 3,
            w: 6,
            h: 4,
        };
        dashboard.widgets.push(Widget {
            id: 1,
            input: widget,
        });
        assert_eq!(dashboard.next_row(), 7);
    }

    #[test]
    fn names_are_tidied_and_checked() {
        assert_eq!(check_name("  Fleet "), Ok("Fleet".to_string()));
        assert!(check_name("   ").is_err());
        assert!(check_name(&"x".repeat(101)).is_err());
    }

    fn machine() -> Variable {
        Variable {
            name: "machine".to_string(),
            label: String::new(),
            kind: crate::dashboard_variables::VariableKind::Machine,
            fact: String::new(),
            filter: String::new(),
        }
    }

    #[test]
    fn a_widget_can_only_use_the_dashboards_variables() {
        let mut widget = input();
        widget.filter = "$machine os=linux".to_string();
        assert!(widget.check(&[machine()]).is_ok());
        assert_eq!(
            widget.check(&[]),
            Err("This dashboard has no variable called $machine.".to_string())
        );
    }

    #[test]
    fn a_variable_a_widget_uses_stays() {
        let mut widget = input();
        widget.title = "Busy".to_string();
        widget.filter = "$machine".to_string();
        let dashboard = Dashboard {
            id: 1,
            name: "Machine".to_string(),
            variables: vec![machine()],
            widgets: vec![Widget {
                id: 1,
                input: widget,
            }],
        };
        assert!(dashboard.check_variables(&[machine()]).is_ok());
        assert_eq!(
            dashboard.check_variables(&[]),
            Err(
                "The widget \u{201c}Busy\u{201d} uses $machine. Change its filter first."
                    .to_string()
            )
        );
    }

    #[test]
    fn a_tall_tooltip_still_fits_a_small_widget() {
        let small = Placement {
            x: 0,
            y: 0,
            w: 3,
            h: 2,
        };
        assert!(small.frame().height >= SMALLEST_FRAME_HEIGHT);
    }

    #[test]
    fn a_form_splits_a_fact_out_of_its_grouping() {
        assert_eq!(
            grouping_fields("fact:os.name"),
            ("fact".to_string(), "os.name".to_string())
        );
        assert_eq!(grouping_fields("host"), ("host".to_string(), String::new()));
    }
}
