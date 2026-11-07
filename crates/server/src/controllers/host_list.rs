//! What lists of hosts share: filtering them and showing them a page at a time. A
//! fleet can be far too big for one page.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;

use crate::app_state::AppState;
use crate::facts::FlatFacts;
use crate::host_filter::HostFilter;
use crate::models::Database;

pub const PAGE_SIZE: usize = 100;

/// A filter from the address, with the facts needed to apply it.
#[derive(Serialize)]
pub struct HostSearch {
    pub text: String,
    pub error: Option<String>,
    #[serde(skip)]
    filter: Option<HostFilter>,
    #[serde(skip)]
    facts: BTreeMap<String, FlatFacts>,
}

impl HostSearch {
    pub async fn load(state: &AppState, text: Option<&str>) -> Result<Self> {
        Self::from_database(&state.database, text).await
    }

    pub async fn from_database(database: &Database, text: Option<&str>) -> Result<Self> {
        let text = text.unwrap_or_default().trim().to_string();
        let (filter, error) = match HostFilter::parse(&text) {
            Ok(filter) => (Some(filter), None),
            Err(error) => (None, Some(error)),
        };
        let names: Vec<&str> = filter
            .iter()
            .flat_map(|filter| filter.fact_names())
            .collect();
        let facts = if names.is_empty() {
            BTreeMap::new()
        } else {
            database.facts_named(&names).await?
        };
        Ok(Self {
            text,
            error,
            filter,
            facts,
        })
    }

    /// A filter that can't be read matches nothing, so a list is never mistaken for
    /// the filtered one someone asked for.
    pub fn includes(&self, id: &str, host: &str) -> bool {
        self.filter
            .as_ref()
            .is_some_and(|filter| filter.matches(host, self.facts.get(id)))
    }
}

/// Where a list has got to, for the links under it.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Pagination {
    pub first: usize,
    pub last: usize,
    pub total: usize,
    pub previous: Option<String>,
    pub next: Option<String>,
}

/// Which page was asked for. Anything odd gives the first, as these come from links
/// that can be edited or go out of date.
pub fn page_number(text: Option<&str>) -> usize {
    text.and_then(|text| text.parse().ok())
        .filter(|page| *page > 0)
        .unwrap_or(1)
}

/// Keeps one page of a list. A page past the end gives the last one, which happens
/// when a list shrinks while someone is looking at it.
pub fn paginate<T>(items: &mut Vec<T>, page: usize, link: impl Fn(usize) -> String) -> Pagination {
    let total = items.len();
    let pages = total.div_ceil(PAGE_SIZE).max(1);
    let page = page.min(pages);
    let start = (page - 1) * PAGE_SIZE;

    items.drain(..start);
    items.truncate(PAGE_SIZE);

    Pagination {
        first: if total == 0 { 0 } else { start + 1 },
        last: start + items.len(),
        total,
        previous: (page > 1).then(|| link(page - 1)),
        next: (page < pages).then(|| link(page + 1)),
    }
}

/// An address with the given values, leaving out any that are empty.
pub fn address(path: &str, values: &[(&str, &str)]) -> String {
    let values: Vec<&(&str, &str)> = values.iter().filter(|(_, v)| !v.is_empty()).collect();
    match serde_urlencoded::to_string(&values) {
        Ok(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(page: usize) -> String {
        format!("page {page}")
    }

    fn numbers(count: usize) -> Vec<usize> {
        (0..count).collect()
    }

    #[test]
    fn a_short_list_is_one_page() {
        let mut items = numbers(3);

        let pages = paginate(&mut items, 1, link);

        assert_eq!(items.len(), 3);
        assert_eq!((pages.first, pages.last, pages.total), (1, 3, 3));
        assert_eq!((pages.previous, pages.next), (None, None));
    }

    #[test]
    fn an_empty_list_has_nothing_to_count() {
        let pages = paginate(&mut Vec::<usize>::new(), 1, link);

        assert_eq!((pages.first, pages.last, pages.total), (0, 0, 0));
        assert_eq!((pages.previous, pages.next), (None, None));
    }

    #[test]
    fn a_page_in_the_middle_links_both_ways() {
        let mut items = numbers(PAGE_SIZE * 2 + 5);

        let pages = paginate(&mut items, 2, link);

        assert_eq!(items.len(), PAGE_SIZE);
        assert_eq!(items[0], PAGE_SIZE);
        assert_eq!(pages.first, PAGE_SIZE + 1);
        assert_eq!(pages.last, PAGE_SIZE * 2);
        assert_eq!(pages.previous.as_deref(), Some("page 1"));
        assert_eq!(pages.next.as_deref(), Some("page 3"));
    }

    #[test]
    fn the_last_page_holds_what_is_left() {
        let mut items = numbers(PAGE_SIZE + 5);

        let pages = paginate(&mut items, 2, link);

        assert_eq!(items.len(), 5);
        assert_eq!(pages.last, PAGE_SIZE + 5);
        assert_eq!(pages.next, None);
    }

    #[test]
    fn exactly_one_full_page_has_no_next() {
        let mut items = numbers(PAGE_SIZE);
        assert_eq!(paginate(&mut items, 1, link).next, None);
    }

    #[test]
    fn a_page_past_the_end_gives_the_last_one() {
        let mut items = numbers(PAGE_SIZE + 5);

        let pages = paginate(&mut items, 99, link);

        assert_eq!(items.len(), 5);
        assert_eq!(pages.previous.as_deref(), Some("page 1"));
    }

    #[test]
    fn odd_page_numbers_give_the_first_page() {
        for text in [None, Some(""), Some("0"), Some("abc"), Some("-1")] {
            assert_eq!(page_number(text), 1, "{text:?}");
        }
        assert_eq!(page_number(Some("7")), 7);
    }

    #[test]
    fn addresses_leave_out_empty_values_and_encode_the_rest() {
        assert_eq!(address("/agents", &[("q", "")]), "/agents");
        assert_eq!(
            address(
                "/agents",
                &[("q", "os=linux web"), ("page", "2"), ("view", "")]
            ),
            "/agents?q=os%3Dlinux+web&page=2"
        );
    }
}
