//! Where towns and cities are, for putting a host on the map by name. The list is
//! every place GeoNames knows of with 1,000 people or more, built into the server so
//! that looking one up never leaves the host. It's read the first time someone
//! looks, as it takes some memory, and kept from then on.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use serde::Serialize;

/// Made by data/generate.py.
const DATA: &[u8] = include_bytes!("../data/places.tsv.gz");

/// GeoNames asks for this wherever its data is used.
pub const CREDIT: &str = "Places from GeoNames, CC BY 4.0";

pub const MAX_RESULTS: usize = 10;

struct Region {
    name: String,
    country_code: String,
    /// The region and country names in lower case, for narrowing a search.
    words: String,
}

struct Place {
    name: Box<str>,
    /// How it's written in plain letters, when that's different.
    ascii: Option<Box<str>>,
    region: u32,
    latitude: f32,
    longitude: f32,
    population: u32,
}

pub struct Places {
    countries: BTreeMap<String, String>,
    regions: Vec<Region>,
    /// Biggest first, which is the order results come in.
    places: Vec<Place>,
}

/// A place, as the pages and the API show it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Found {
    pub name: String,
    pub region: String,
    pub country: String,
    pub country_code: String,
    pub latitude: f64,
    pub longitude: f64,
    pub population: u32,
    /// The name with its region and country, as in "Portland, Maine, United States".
    pub label: String,
}

static PLACES: OnceLock<Result<Places, String>> = OnceLock::new();

/// The list, read the first time it's needed. Reading it takes a moment, so call
/// this off the async threads.
pub fn places() -> Result<&'static Places> {
    PLACES
        .get_or_init(|| Places::read(DATA).map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow!("reading the place list: {error}"))
}

/// Whether `text` starts with `start`, ignoring case, without making new strings.
fn starts_with_folded(text: &str, start: &str) -> bool {
    let mut text = text.chars().flat_map(char::to_lowercase);
    start
        .chars()
        .flat_map(char::to_lowercase)
        .all(|wanted| text.next() == Some(wanted))
}

fn same_folded(text: &str, other: &str) -> bool {
    text.chars()
        .flat_map(char::to_lowercase)
        .eq(other.chars().flat_map(char::to_lowercase))
}

impl Places {
    fn read(compressed: &[u8]) -> Result<Self> {
        let mut text = String::new();
        GzDecoder::new(compressed)
            .read_to_string(&mut text)
            .context("unpacking")?;
        let mut lines = text.lines().filter(|line| !line.starts_with('#'));
        fn section<'a>(lines: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<usize> {
            let line = lines.next().with_context(|| format!("no {name}"))?;
            let (found, count) = line.split_once('\t').context("a section with no count")?;
            if found != name {
                bail!("expected {name}, found {found}");
            }
            count.parse().context("a section's count")
        }

        let count = section(&mut lines, "countries")?;
        let mut countries = BTreeMap::new();
        for line in lines.by_ref().take(count) {
            let (code, name) = line.split_once('\t').context("a country")?;
            countries.insert(code.to_string(), name.to_string());
        }

        let count = section(&mut lines, "regions")?;
        let mut regions = Vec::with_capacity(count);
        for line in lines.by_ref().take(count) {
            let (name, code) = line.split_once('\t').context("a region")?;
            let country = countries.get(code).map_or("", String::as_str);
            regions.push(Region {
                words: format!("{name} {country}").to_lowercase(),
                name: name.to_string(),
                country_code: code.to_string(),
            });
        }

        let count = section(&mut lines, "places")?;
        let mut places = Vec::with_capacity(count);
        for line in lines.by_ref().take(count) {
            let mut fields = line.split('\t');
            let mut field = || fields.next().context("a place with too few fields");
            let name = field()?;
            let ascii = field()?;
            let region = field()?.parse().context("a place's region")?;
            let latitude = field()?.parse().context("a place's latitude")?;
            let longitude = field()?.parse().context("a place's longitude")?;
            let population = field()?.parse().context("a place's population")?;
            if usize::try_from(region).map_or(true, |region: usize| region >= regions.len()) {
                bail!("{name} names a region that isn't listed");
            }
            places.push(Place {
                name: name.into(),
                ascii: (!ascii.is_empty()).then(|| ascii.into()),
                region,
                latitude,
                longitude,
                population,
            });
        }
        Ok(Self {
            countries,
            regions,
            places,
        })
    }

    fn found(&self, place: &Place) -> Found {
        let region = &self.regions[place.region as usize];
        let country = self
            .countries
            .get(&region.country_code)
            .cloned()
            .unwrap_or_else(|| region.country_code.clone());
        let label = [place.name.as_ref(), region.name.as_str(), country.as_str()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        Found {
            name: place.name.to_string(),
            region: region.name.clone(),
            country,
            country_code: region.country_code.clone(),
            latitude: f64::from(place.latitude),
            longitude: f64::from(place.longitude),
            population: place.population,
            label,
        }
    }

    /// Places whose name starts with what's typed before any comma. Words after a
    /// comma narrow the region or country, as in "portland, maine" or "paris, us".
    /// An exact name comes before one it only starts, and bigger places first.
    pub fn search(&self, query: &str, limit: usize) -> Vec<Found> {
        let (name, narrowing) = query.split_once(',').unwrap_or((query, ""));
        let name = name.trim();
        if name.chars().count() < 2 {
            return Vec::new();
        }
        let narrowing: Vec<String> = narrowing
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();

        let mut exact = Vec::new();
        let mut starting = Vec::new();
        for place in &self.places {
            let named = starts_with_folded(&place.name, name)
                || place
                    .ascii
                    .as_deref()
                    .is_some_and(|ascii| starts_with_folded(ascii, name));
            if !named {
                continue;
            }
            let region = &self.regions[place.region as usize];
            let narrowed = narrowing.iter().all(|word| {
                region.words.contains(word.as_str())
                    || region.country_code.eq_ignore_ascii_case(word)
            });
            if !narrowed {
                continue;
            }
            let is_exact = same_folded(&place.name, name)
                || place
                    .ascii
                    .as_deref()
                    .is_some_and(|ascii| same_folded(ascii, name));
            if is_exact {
                exact.push(place);
                if exact.len() == limit {
                    break;
                }
            } else if starting.len() < limit {
                starting.push(place);
            }
        }
        exact
            .into_iter()
            .chain(starting)
            .take(limit)
            .map(|place| self.found(place))
            .collect()
    }

    /// The listed place closest to a point, to name where someone clicked.
    pub fn nearest(&self, latitude: f64, longitude: f64) -> Option<Found> {
        let squash = latitude.to_radians().cos();
        self.places
            .iter()
            .min_by(|a, b| {
                let distance = |place: &Place| {
                    let up = f64::from(place.latitude) - latitude;
                    let mut across = (f64::from(place.longitude) - longitude).abs();
                    if across > 180.0 {
                        across = 360.0 - across;
                    }
                    up * up + (across * squash).powi(2)
                };
                distance(a).total_cmp(&distance(b))
            })
            .map(|place| self.found(place))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(query: &str) -> Vec<String> {
        places()
            .unwrap()
            .search(query, 3)
            .into_iter()
            .map(|found| found.label)
            .collect()
    }

    #[test]
    fn the_built_in_list_reads() {
        assert!(places().unwrap().places.len() > 150_000);
    }

    #[test]
    fn the_biggest_place_with_a_name_comes_first() {
        assert_eq!(labels("Leeds")[0], "Leeds, England, United Kingdom");
        assert_eq!(labels("leeds")[0], "Leeds, England, United Kingdom");
    }

    #[test]
    fn words_after_a_comma_narrow_it_down() {
        assert_eq!(
            labels("Portland, maine"),
            ["Portland, Maine, United States"]
        );
        assert_eq!(
            labels("boardman, oregon"),
            ["Boardman, Oregon, United States"]
        );
        assert_eq!(labels("boardman, us").len(), 2);
    }

    #[test]
    fn accents_can_be_typed_or_left_out() {
        assert_eq!(labels("sao paulo")[0], "São Paulo, São Paulo, Brazil");
        assert_eq!(labels("São Paulo")[0], "São Paulo, São Paulo, Brazil");
    }

    #[test]
    fn a_name_has_to_be_two_letters_or_more() {
        assert!(labels("l").is_empty());
        assert!(labels(" , england").is_empty());
    }

    #[test]
    fn a_point_is_named_after_the_closest_place() {
        let places = places().unwrap();
        let near = places.nearest(53.93, -1.39).unwrap();
        assert_eq!(near.label, "Wetherby, England, United Kingdom");
        // Across the date line, Fiji's nearest place is still in Fiji.
        let near = places.nearest(-16.8, 179.99).unwrap();
        assert_eq!(near.country_code, "FJ");
    }

    #[test]
    fn a_damaged_list_says_so() {
        assert!(Places::read(b"not gzip").is_err());
    }
}
