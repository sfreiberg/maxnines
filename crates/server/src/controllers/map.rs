//! The map: where hosts are, coloured by how they're doing, and the location
//! rules that put them there.

use std::collections::BTreeMap;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};

use super::fleet::Health;
use super::{CsrfForm, Page, server_error};
use crate::alerting::Alert;
use crate::app_state::AppState;
use crate::host_filter;
use crate::locations::{LocationRule, LocationRuleInput, Locator, check_rule};
use crate::places::{self, CREDIT, Found, MAX_RESULTS};
use crate::registration::{HostState, short_id};

/// What a rule for one host gets, so it outranks the broader rules it sits among.
pub const ONE_HOST_PRIORITY: i32 = 100;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/map", get(index))
        .route("/map/places", get(search_places))
        .route("/map/nearest", get(nearest_place))
        .route("/map/rules", get(rules).post(create))
        .route("/map/rules/new", get(new))
        .route("/map/rules/{id}", post(update))
        .route("/map/rules/{id}/edit", get(edit))
        .route("/map/rules/{id}/delete", post(delete))
}

/// A host on the map, or waiting for a place on it.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MapHost {
    pub id: String,
    pub short_id: String,
    pub hostname: String,
    pub health: Health,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    pub critical: usize,
    pub warning: usize,
    pub offline: usize,
    pub online: usize,
}

impl Counts {
    fn add(&mut self, health: Health) {
        match health {
            Health::Critical => self.critical += 1,
            Health::Warning => self.warning += 1,
            Health::Offline => self.offline += 1,
            Health::Online => self.online += 1,
        }
    }

    pub fn total(&self) -> usize {
        self.critical + self.warning + self.offline + self.online
    }

    /// The worst of them, which is what the site's marker shows.
    fn health(&self) -> Health {
        if self.critical > 0 {
            Health::Critical
        } else if self.warning > 0 {
            Health::Warning
        } else if self.offline > 0 {
            Health::Offline
        } else {
            Health::Online
        }
    }
}

/// The hosts one rule puts in one place.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Site {
    pub rule_id: i64,
    pub name: String,
    pub place: String,
    pub latitude: f64,
    pub longitude: f64,
    pub health: Health,
    pub counts: Counts,
    pub hosts: Vec<MapHost>,
}

/// Everything the map shows.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MapData {
    /// Those most in need of attention first.
    pub sites: Vec<Site>,
    /// Approved hosts no rule places.
    pub unplaced: Vec<MapHost>,
}

/// Where every approved host is, and how it's doing.
pub async fn map_data(state: &AppState) -> Result<MapData> {
    let locator = Locator::load(&state.database).await?;
    let open = state.database.open_alerts().await?;
    let mut alerts: BTreeMap<&str, Vec<&Alert>> = BTreeMap::new();
    for alert in &open {
        alerts.entry(&alert.host_id).or_default().push(alert);
    }

    let mut sites: BTreeMap<i64, Site> = BTreeMap::new();
    let mut unplaced = Vec::new();
    for host in state.registry.list().await {
        if host.state != HostState::Approved || host.is_local() {
            continue;
        }
        let online = state.presence.get(&host.id).is_some_and(|p| p.online);
        let mine = alerts.get(host.id.as_str()).map_or(&[][..], Vec::as_slice);
        let pin = MapHost {
            short_id: short_id(&host.id).to_string(),
            health: Health::of(online, mine),
            hostname: host.hostname.clone(),
            id: host.id.clone(),
        };
        let Some(rule) = locator.locate(&host.id, &host.hostname) else {
            unplaced.push(pin);
            continue;
        };
        let site = sites.entry(rule.id).or_insert_with(|| site_for(rule));
        site.counts.add(pin.health);
        site.hosts.push(pin);
    }

    let mut sites: Vec<Site> = sites
        .into_values()
        .map(|mut site| {
            site.health = site.counts.health();
            site.hosts.sort_by(|a, b| {
                a.health
                    .cmp(&b.health)
                    .then_with(|| a.hostname.cmp(&b.hostname))
            });
            site
        })
        .collect();
    sites.sort_by(|a, b| {
        a.health
            .cmp(&b.health)
            .then_with(|| b.counts.total().cmp(&a.counts.total()))
            .then_with(|| a.name.cmp(&b.name))
    });
    unplaced.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    Ok(MapData { sites, unplaced })
}

fn site_for(rule: &LocationRule) -> Site {
    Site {
        rule_id: rule.id,
        name: rule.rule.name.clone(),
        place: rule.rule.place.clone(),
        latitude: rule.rule.latitude,
        longitude: rule.rule.longitude,
        health: Health::Online,
        counts: Counts::default(),
        hosts: Vec::new(),
    }
}

/// A site as the list beside the map shows it.
#[derive(Serialize)]
struct SiteRow {
    rule_id: i64,
    name: String,
    place: String,
    health: Health,
    total: usize,
    breakdown: String,
}

fn breakdown(counts: &Counts) -> String {
    [
        (counts.critical, "critical"),
        (counts.warning, "warning"),
        (counts.offline, "offline"),
        (counts.online, "online"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, word)| format!("{count} {word}"))
    .collect::<Vec<_>>()
    .join(" · ")
}

async fn index(State(state): State<AppState>, token: CsrfToken) -> Response {
    let data = match map_data(&state).await {
        Ok(data) => data,
        Err(error) => return server_error(&error),
    };
    let rows: Vec<SiteRow> = data
        .sites
        .iter()
        .map(|site| SiteRow {
            rule_id: site.rule_id,
            name: site.name.clone(),
            place: site.place.clone(),
            health: site.health,
            total: site.counts.total(),
            breakdown: breakdown(&site.counts),
        })
        .collect();
    let hosts: usize = data
        .sites
        .iter()
        .map(|site| site.counts.total())
        .sum::<usize>()
        + data.unplaced.len();
    let attention = data
        .sites
        .iter()
        .filter(|site| site.health != Health::Online)
        .count();
    // Drawn by map.js. The template escapes it, so agents' names stay text.
    let json = match serde_json::to_string(&data) {
        Ok(json) => json,
        Err(error) => return server_error(&anyhow::Error::from(error)),
    };
    Page::new(&state, &token, "map/index.html")
        .with("site_count", &rows.len())
        .with("sites", &rows)
        .with("unplaced", &data.unplaced)
        .with("host_count", &hosts)
        .with("attention", &attention)
        .with("map_json", &json)
        .with("credit", CREDIT)
        .render()
}

#[derive(Deserialize)]
pub(super) struct PlaceQuery {
    #[serde(default)]
    q: String,
}

/// Reading the list the first time takes a moment, so it's done off the async threads.
async fn with_places<T: Send + 'static>(
    work: impl FnOnce(&'static places::Places) -> T + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || places::places().map(work))
        .await
        .map_err(|_| anyhow::anyhow!("searching places failed unexpectedly"))?
}

/// Places for the search box on the location form.
pub(super) async fn search_places(Query(query): Query<PlaceQuery>) -> Response {
    let q = query.q;
    match with_places(move |places| places.search(&q, MAX_RESULTS)).await {
        Ok(found) => Json(found).into_response(),
        Err(error) => server_error(&error),
    }
}

#[derive(Deserialize)]
pub(super) struct PointQuery {
    lat: f64,
    lon: f64,
}

/// The place closest to where someone clicked.
pub(super) async fn nearest_place(Query(point): Query<PointQuery>) -> Response {
    if !(point.lat.is_finite() && point.lon.is_finite()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match with_places(move |places| places.nearest(point.lat, point.lon)).await {
        Ok(found) => Json::<Option<Found>>(found).into_response(),
        Err(error) => server_error(&error),
    }
}

// ---- The rules

#[derive(Serialize)]
struct RuleRow {
    id: i64,
    name: String,
    place: String,
    filter: String,
    priority: i32,
    hosts: usize,
}

async fn rules(State(state): State<AppState>, token: CsrfToken) -> Response {
    let data = async {
        let locator = Locator::load(&state.database).await?;
        let mut counts: BTreeMap<i64, usize> = BTreeMap::new();
        for host in state.registry.list().await {
            if host.state != HostState::Approved || host.is_local() {
                continue;
            }
            if let Some(rule) = locator.locate(&host.id, &host.hostname) {
                *counts.entry(rule.id).or_default() += 1;
            }
        }
        let rows: Vec<RuleRow> = locator
            .rules()
            .map(|rule| RuleRow {
                id: rule.id,
                name: rule.rule.name.clone(),
                place: rule.rule.place.clone(),
                filter: rule.rule.filter.clone(),
                priority: rule.rule.priority,
                hosts: counts.get(&rule.id).copied().unwrap_or_default(),
            })
            .collect();
        anyhow::Ok(rows)
    };
    match data.await {
        Ok(rows) => Page::new(&state, &token, "map/rules.html")
            .with("rules", &rows)
            .render(),
        Err(error) => server_error(&error),
    }
}

/// A rule as its form shows it, including whatever was just typed.
#[derive(Serialize, Default)]
struct RuleForm {
    name: String,
    filter: String,
    place: String,
    latitude: String,
    longitude: String,
    priority: String,
}

impl RuleForm {
    fn from_rule(rule: &LocationRuleInput) -> Self {
        Self {
            name: rule.name.clone(),
            filter: rule.filter.clone(),
            place: rule.place.clone(),
            latitude: rule.latitude.to_string(),
            longitude: rule.longitude.to_string(),
            priority: rule.priority.to_string(),
        }
    }

    fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let text = |name: &str| {
            fields
                .get(name)
                .map(|value| value.trim().to_string())
                .unwrap_or_default()
        };
        Self {
            name: text("name"),
            filter: text("filter"),
            place: text("place"),
            latitude: text("latitude"),
            longitude: text("longitude"),
            priority: text("priority"),
        }
    }

    fn to_input(&self) -> Result<LocationRuleInput, String> {
        let number = |text: &str, what: &str| -> Result<f64, String> {
            text.parse()
                .map_err(|_| format!("Choose a place, or type its {what} as a number."))
        };
        let priority = match self.priority.as_str() {
            "" => 0,
            text => text
                .parse()
                .map_err(|_| "The priority has to be a whole number.".to_string())?,
        };
        let input = LocationRuleInput {
            name: self.name.clone(),
            filter: self.filter.clone(),
            place: self.place.clone(),
            latitude: number(&self.latitude, "latitude")?,
            longitude: number(&self.longitude, "longitude")?,
            priority,
        };
        check_rule(&input).map_err(|error| error.to_string())?;
        Ok(input)
    }
}

/// What the new rule form can be opened with, as from an agent's page.
#[derive(Deserialize, Default)]
struct NewRule {
    #[serde(default)]
    host: Option<String>,
}

fn form_page(
    state: &AppState,
    token: &CsrfToken,
    id: Option<i64>,
    rule: &RuleForm,
    error: Option<&str>,
) -> Response {
    let mut page = Page::new(state, token, "map/rule_form.html")
        .with("rule", rule)
        .with("credit", CREDIT)
        .with("one_host_priority", &ONE_HOST_PRIORITY);
    if let Some(id) = id {
        page = page.with("id", &id);
    }
    match error {
        Some(error) => page
            .with("error", error)
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .render(),
        None => page.render(),
    }
}

/// Opened from an agent's page, the form is for that one host.
async fn new(
    State(state): State<AppState>,
    Query(query): Query<NewRule>,
    token: CsrfToken,
) -> Response {
    let mut rule = RuleForm {
        priority: "0".to_string(),
        ..RuleForm::default()
    };
    if let Some(id) = query.host {
        let found = state
            .registry
            .get(&id)
            .await
            .filter(|host| !host.is_local());
        let Some(host) = found else {
            return StatusCode::NOT_FOUND.into_response();
        };
        rule.name = host.hostname;
        rule.filter = host_filter::only(&host.id);
        rule.priority = ONE_HOST_PRIORITY.to_string();
    }
    form_page(&state, &token, None, &rule, None)
}

async fn edit(State(state): State<AppState>, Path(id): Path<i64>, token: CsrfToken) -> Response {
    match state.database.get_location_rule(id).await {
        Ok(Some(rule)) => form_page(
            &state,
            &token,
            Some(id),
            &RuleForm::from_rule(&rule.rule),
            None,
        ),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn create(State(state): State<AppState>, form: CsrfForm) -> Response {
    let rule = RuleForm::from_fields(&form.fields);
    let input = match rule.to_input() {
        Ok(input) => input,
        Err(error) => return form_page(&state, &form.token, None, &rule, Some(&error)),
    };
    match state.database.create_location_rule(&input).await {
        Ok(_) => (form.token, Redirect::to("/map/rules")).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn update(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    let rule = RuleForm::from_fields(&form.fields);
    let input = match rule.to_input() {
        Ok(input) => input,
        Err(error) => return form_page(&state, &form.token, Some(id), &rule, Some(&error)),
    };
    match state.database.update_location_rule(id, &input).await {
        Ok(true) => (form.token, Redirect::to("/map/rules")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

async fn delete(State(state): State<AppState>, Path(id): Path<i64>, form: CsrfForm) -> Response {
    match state.database.delete_location_rule(id).await {
        Ok(true) => (form.token, Redirect::to("/map/rules")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_shows_its_worst_host() {
        let mut counts = Counts::default();
        counts.add(Health::Online);
        assert_eq!(counts.health(), Health::Online);
        counts.add(Health::Offline);
        assert_eq!(counts.health(), Health::Offline);
        counts.add(Health::Critical);
        assert_eq!(counts.health(), Health::Critical);
        assert_eq!(breakdown(&counts), "1 critical · 1 offline · 1 online");
    }

    #[test]
    fn the_form_needs_a_place_or_its_coordinates() {
        let form = RuleForm {
            name: "Leeds office".to_string(),
            latitude: String::new(),
            longitude: "-1.55".to_string(),
            ..RuleForm::default()
        };
        assert!(form.to_input().unwrap_err().contains("latitude"));

        let form = RuleForm {
            latitude: "53.8".to_string(),
            ..form
        };
        let input = form.to_input().unwrap();
        assert_eq!(input.priority, 0);
        assert_eq!(input.latitude, 53.8);
    }
}
