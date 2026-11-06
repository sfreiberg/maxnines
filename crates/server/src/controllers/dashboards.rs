//! Pages for building dashboards and showing them. Each widget loads and refreshes on
//! its own, because the grid around them belongs to GridStack, and replacing the page
//! under it would lose the layout.

use std::collections::BTreeMap;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};

use super::metrics::{RangeParams, not_found, range_links, selected_range, time_range};
use super::{CsrfForm, Page, server_error};
use crate::app_state::AppState;
use crate::calculations::Calculation;
use crate::dashboards::{
    self, COLUMNS, Dashboard, KINDS, Placed, Placement, WidgetInput, check_layout, check_name,
    grouping_fields,
};
use crate::metrics::{METRICS, now_ms};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/dashboards", get(index).post(create))
        .route("/dashboards/{id}", get(show).post(rename))
        .route("/dashboards/{id}/edit", get(edit))
        .route("/dashboards/{id}/delete", post(delete))
        .route("/dashboards/{id}/layout", post(place))
        .route("/dashboards/{id}/widgets", post(create_widget))
        .route("/dashboards/{id}/widgets/new", get(new_widget))
        .route(
            "/dashboards/{id}/widgets/{widget}",
            get(show_widget).post(update_widget),
        )
        .route("/dashboards/{id}/widgets/{widget}/edit", get(edit_widget))
        .route(
            "/dashboards/{id}/widgets/{widget}/delete",
            post(delete_widget),
        )
}

fn index_page(
    state: &AppState,
    token: &CsrfToken,
    dashboards: &[dashboards::DashboardSummary],
    error: Option<&str>,
) -> Response {
    Page::new(state, token, "dashboards/index.html")
        .with("dashboards", dashboards)
        .with("error", &error)
        .render()
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    match state.database.list_dashboards().await {
        Ok(dashboards) => index_page(&state, &token, &dashboards, None),
        Err(error) => server_error(&error),
    }
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let name = form.fields.get("name").map_or("", String::as_str);
    let name = match check_name(name) {
        Ok(name) => name,
        Err(error) => {
            return match state.database.list_dashboards().await {
                Ok(dashboards) => index_page(&state, &form.token, &dashboards, Some(&error)),
                Err(error) => server_error(&error),
            };
        }
    };
    match state.database.create_dashboard(&name, now_ms()).await {
        Ok(id) => (form.token, Redirect::to(&format!("/dashboards/{id}/edit"))).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Finds a dashboard, or answers for the handler that wanted it.
async fn load(state: &AppState, token: &CsrfToken, id: i64) -> Result<Dashboard, Box<Response>> {
    match state.database.get_dashboard(id).await {
        Ok(Some(dashboard)) => Ok(dashboard),
        Ok(None) => Err(Box::new(not_found(state, token))),
        Err(error) => Err(Box::new(server_error(&error))),
    }
}

async fn show(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<RangeParams>,
    token: CsrfToken,
) -> Response {
    let dashboard = match load(&state, &token, id).await {
        Ok(dashboard) => dashboard,
        Err(response) => return *response,
    };
    let (selected, _, _) = selected_range(&params);
    Page::new(&state, &token, "dashboards/show.html")
        .with("dashboard", &dashboard)
        .with("editing", &false)
        .with("ranges", &range_links(selected))
        .with("range", selected)
        .render()
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    edit_page(&state, &token, id, None).await
}

async fn edit_page(state: &AppState, token: &CsrfToken, id: i64, error: Option<&str>) -> Response {
    let dashboard = match load(state, token, id).await {
        Ok(dashboard) => dashboard,
        Err(response) => return *response,
    };
    let (selected, _, _) = selected_range(&RangeParams::default());
    Page::new(state, token, "dashboards/show.html")
        .with("dashboard", &dashboard)
        .with("editing", &true)
        .with("error", &error)
        .with("range", selected)
        .render()
}

async fn rename(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let name = form.fields.get("name").map_or("", String::as_str);
    let name = match check_name(name) {
        Ok(name) => name,
        Err(error) => return edit_page(&state, &form.token, id, Some(&error)).await,
    };
    match state.database.rename_dashboard(id, &name).await {
        Ok(true) => (form.token, Redirect::to(&format!("/dashboards/{id}/edit"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.delete_dashboard(id).await {
        Ok(true) => (form.token, Redirect::to("/dashboards")).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}

/// Called as widgets are dragged, with the whole grid as JSON in a `layout` field.
async fn place(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let layout = form.fields.get("layout").map_or("", String::as_str);
    let Ok(widgets) = serde_json::from_str::<Vec<Placed>>(layout) else {
        return (form.token, StatusCode::BAD_REQUEST).into_response();
    };
    if check_layout(&widgets).is_err() {
        return (form.token, StatusCode::BAD_REQUEST).into_response();
    }
    match state.database.place_widgets(id, &widgets).await {
        Ok(()) => (form.token, StatusCode::NO_CONTENT).into_response(),
        Err(error) => server_error(&error),
    }
}

/// A widget as its form shows it, including whatever was just typed.
#[derive(Serialize)]
struct WidgetForm {
    title: String,
    kind: String,
    metric: String,
    calculation: String,
    group_by: String,
    fact: String,
    filter: String,
}

impl WidgetForm {
    fn blank() -> Self {
        Self {
            title: String::new(),
            kind: KINDS[0].to_string(),
            metric: "cpu.usage".to_string(),
            calculation: Calculation::Avg.as_str().to_string(),
            group_by: "host".to_string(),
            fact: String::new(),
            filter: String::new(),
        }
    }

    fn from_input(input: &WidgetInput) -> Self {
        let (group_by, fact) = grouping_fields(&input.group_by);
        Self {
            title: input.title.clone(),
            kind: input.kind.clone(),
            metric: input.metric.clone(),
            calculation: input.calculation.clone(),
            group_by,
            fact,
            filter: input.filter.clone(),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| fields.get(name).cloned().unwrap_or_default();
        Self {
            title: text("title").trim().to_string(),
            kind: text("kind"),
            metric: text("metric"),
            calculation: text("calculation"),
            group_by: text("group_by"),
            fact: text("fact").trim().to_string(),
            filter: text("filter").trim().to_string(),
        }
    }

    fn to_input(&self, placement: Placement) -> WidgetInput {
        WidgetInput {
            title: self.title.clone(),
            kind: self.kind.clone(),
            metric: self.metric.clone(),
            calculation: self.calculation.clone(),
            group_by: if self.group_by == "fact" {
                format!("fact:{}", self.fact)
            } else {
                self.group_by.clone()
            },
            filter: self.filter.clone(),
            placement,
        }
    }
}

/// A choice on the form.
#[derive(Serialize)]
struct Choice {
    value: &'static str,
    label: &'static str,
}

fn widget_form(
    state: &AppState,
    token: &CsrfToken,
    dashboard: &Dashboard,
    widget_id: Option<i64>,
    form: &WidgetForm,
    error: Option<&str>,
) -> Response {
    let metrics: Vec<Choice> = METRICS
        .iter()
        .map(|metric| Choice {
            value: metric.name,
            label: metric.title,
        })
        .collect();
    let calculations: Vec<Choice> = Calculation::ALL
        .into_iter()
        .map(|calculation| Choice {
            value: calculation.as_str(),
            label: calculation.label(),
        })
        .collect();
    Page::new(state, token, "dashboards/widget_form.html")
        .with("dashboard_id", &dashboard.id)
        .with("dashboard_name", &dashboard.name)
        .with("id", &widget_id)
        .with("widget", form)
        .with("metrics", &metrics)
        .with("calculations", &calculations)
        .with("error", &error)
        .render()
}

async fn new_widget(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    token: CsrfToken,
) -> Response {
    match load(&state, &token, id).await {
        Ok(dashboard) => widget_form(&state, &token, &dashboard, None, &WidgetForm::blank(), None),
        Err(response) => *response,
    }
}

/// New widgets start at a size that suits them, on a row of their own.
fn starting_place(kind: &str, dashboard: &Dashboard) -> Placement {
    let (w, h) = match kind {
        "number" => (3, 2),
        "table" => (COLUMNS / 2, 5),
        _ => (COLUMNS / 2, 4),
    };
    Placement {
        x: 0,
        y: dashboard.next_row(),
        w,
        h,
    }
}

async fn create_widget(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    form: CsrfForm,
) -> Response {
    let dashboard = match load(&state, &form.token, id).await {
        Ok(dashboard) => dashboard,
        Err(response) => return *response,
    };
    let fields = WidgetForm::from_fields(&form.fields);
    let input = fields.to_input(starting_place(&fields.kind, &dashboard));
    let problem = if dashboard.is_full() {
        Err("This dashboard has as many widgets as it can.".to_string())
    } else {
        input.check()
    };
    if let Err(error) = problem {
        return widget_form(&state, &form.token, &dashboard, None, &fields, Some(&error));
    }
    match state.database.create_widget(id, &input).await {
        Ok(_) => (form.token, Redirect::to(&format!("/dashboards/{id}/edit"))).into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Deserialize, Default)]
struct WidgetParams {
    range: Option<String>,
    edit: Option<String>,
}

/// Just the widget, for dropping into the page. A failure shows in the widget.
async fn show_widget(
    State(state): State<AppState>,
    Path((id, widget_id)): Path<(i64, i64)>,
    Query(params): Query<WidgetParams>,
    token: CsrfToken,
) -> Response {
    let widget = match state.database.get_widget(id, widget_id).await {
        Ok(Some(widget)) => widget,
        Ok(None) => return not_found(&state, &token),
        Err(error) => return server_error(&error),
    };
    let (_, _, length_ms) = selected_range(&RangeParams {
        range: params.range,
    });
    let Some(range) = time_range(length_ms) else {
        return not_found(&state, &token);
    };
    let view = dashboards::view(&state, &widget, range).await;
    Page::new(&state, &token, "dashboards/_widget.html")
        .with("widget", &view)
        .with("chart", &view.chart)
        .with(
            "edit_url",
            &params
                .edit
                .map(|_| format!("/dashboards/{id}/widgets/{widget_id}/edit")),
        )
        .render()
}

async fn edit_widget(
    State(state): State<AppState>,
    Path((id, widget_id)): Path<(i64, i64)>,
    token: CsrfToken,
) -> Response {
    let dashboard = match load(&state, &token, id).await {
        Ok(dashboard) => dashboard,
        Err(response) => return *response,
    };
    let Some(widget) = dashboard.widgets.iter().find(|w| w.id == widget_id) else {
        return not_found(&state, &token);
    };
    let form = WidgetForm::from_input(&widget.input);
    widget_form(&state, &token, &dashboard, Some(widget_id), &form, None)
}

async fn update_widget(
    State(state): State<AppState>,
    Path((id, widget_id)): Path<(i64, i64)>,
    form: CsrfForm,
) -> Response {
    let dashboard = match load(&state, &form.token, id).await {
        Ok(dashboard) => dashboard,
        Err(response) => return *response,
    };
    let Some(widget) = dashboard.widgets.iter().find(|w| w.id == widget_id) else {
        return not_found(&state, &form.token);
    };
    let fields = WidgetForm::from_fields(&form.fields);
    let input = fields.to_input(widget.input.placement);
    if let Err(error) = input.check() {
        let id = Some(widget_id);
        return widget_form(&state, &form.token, &dashboard, id, &fields, Some(&error));
    }
    match state.database.update_widget(id, widget_id, &input).await {
        Ok(_) => (form.token, Redirect::to(&format!("/dashboards/{id}/edit"))).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete_widget(
    State(state): State<AppState>,
    Path((id, widget_id)): Path<(i64, i64)>,
    form: CsrfForm,
) -> Response {
    match state.database.delete_widget(id, widget_id).await {
        Ok(true) => (form.token, Redirect::to(&format!("/dashboards/{id}/edit"))).into_response(),
        Ok(false) => not_found(&state, &form.token),
        Err(error) => server_error(&error),
    }
}
