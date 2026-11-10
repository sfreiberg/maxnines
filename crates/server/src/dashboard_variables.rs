//! Variables let one dashboard show any machine, or any value of a fact, picked at
//! the top of the page. A widget's filter uses one as a term on its own, like
//! `$machine`, and its title can mention one the same way.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::calculations::Sources;
use crate::controllers::host_list::HostSearch;
use crate::facts::fact_text;
use crate::host_filter::{self, HostFilter, term_spans, written_value};
use crate::registration::{AgentRecord, AgentState, short_id};

pub const MAX_VARIABLES: usize = 10;
const MAX_NAME_LEN: usize = 32;
const MAX_LABEL_LEN: usize = 100;
const MAX_FACT_LEN: usize = 200;
const MAX_FILTER_LEN: usize = 500;
/// More than a picker is any use with. A fleet bigger than this needs a filter.
pub const MAX_CHOICES: usize = 1000;
/// What starts a variable's name in an address, so it can't be mistaken for
/// anything else there.
pub const PARAM_PREFIX: &str = "var-";
/// What a picker offering everything shows, and what a title says for it.
const ALL_LABEL: &str = "All";
/// What a title says when there's nothing to pick.
const NONE_LABEL: &str = "none";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableKind {
    /// One machine, written into a filter as `id=`.
    Machine,
    /// A value of a fact, or every value.
    Fact,
}

impl VariableKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::Fact => "fact",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "machine" => Some(Self::Machine),
            "fact" => Some(Self::Fact),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variable {
    /// Written as `$name` in filters and titles.
    pub name: String,
    /// What the picker is called. Empty uses the name.
    #[serde(default)]
    pub label: String,
    pub kind: VariableKind,
    /// The fact whose values are offered, for a fact variable.
    #[serde(default)]
    pub fact: String,
    /// Which machines are offered, or whose values are, in the host list's filter.
    #[serde(default)]
    pub filter: String,
}

impl Variable {
    /// Trims what was typed, and drops a fact a machine variable has no use for.
    pub fn tidy(mut self) -> Self {
        self.name = self.name.trim().trim_start_matches('$').to_string();
        self.label = self.label.trim().to_string();
        self.fact = match self.kind {
            VariableKind::Machine => String::new(),
            VariableKind::Fact => self.fact.trim().to_string(),
        };
        self.filter = self.filter.trim().to_string();
        self
    }

    /// The error says what's wrong, to show whoever chose it.
    pub fn check(&self) -> Result<(), String> {
        let name = &self.name;
        let starts_with_letter = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        let well_formed = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !starts_with_letter || !well_formed {
            return Err(
                "A variable's name starts with a letter, and has only letters, digits and _."
                    .to_string(),
            );
        }
        if name.len() > MAX_NAME_LEN {
            return Err(format!(
                "A variable's name can be up to {MAX_NAME_LEN} characters."
            ));
        }
        if self.label.chars().count() > MAX_LABEL_LEN {
            return Err(format!("A label can be up to {MAX_LABEL_LEN} characters."));
        }
        if self.kind == VariableKind::Fact {
            if self.fact.is_empty() {
                return Err("Choose which fact's values to offer.".to_string());
            }
            if self.fact.len() > MAX_FACT_LEN {
                return Err(format!(
                    "A fact's name can be up to {MAX_FACT_LEN} characters."
                ));
            }
            if self.fact.contains(['=', '"', '$']) || self.fact.contains(char::is_whitespace) {
                return Err("That isn't a fact's name.".to_string());
            }
        }
        if self.filter.len() > MAX_FILTER_LEN {
            return Err(format!(
                "A filter can be up to {MAX_FILTER_LEN} characters."
            ));
        }
        if !uses(&self.filter).is_empty() {
            return Err("Which machines a variable offers can't depend on a variable.".to_string());
        }
        HostFilter::parse(&self.filter).map(|_| ())
    }

    /// What its picker is called.
    pub fn title(&self) -> &str {
        if self.label.is_empty() {
            &self.name
        } else {
            &self.label
        }
    }

    /// The parameter that carries its value in an address.
    pub fn param(&self) -> String {
        format!("{PARAM_PREFIX}{}", self.name)
    }
}

/// A dashboard's whole list, which is checked and saved together.
pub fn check_variables(variables: &[Variable]) -> Result<(), String> {
    if variables.len() > MAX_VARIABLES {
        return Err(format!(
            "A dashboard can have up to {MAX_VARIABLES} variables."
        ));
    }
    let mut names = BTreeSet::new();
    for variable in variables {
        variable.check()?;
        if !names.insert(variable.name.as_str()) {
            return Err(format!(
                "There's already a variable called ${}.",
                variable.name
            ));
        }
    }
    Ok(())
}

/// The variables a filter uses, as terms on their own like `$machine`.
pub fn uses(filter: &str) -> Vec<&str> {
    term_spans(filter)
        .into_iter()
        .filter_map(|span| filter[span].strip_prefix('$'))
        .collect()
}

/// A filter can only use variables the dashboard has.
pub fn check_uses(filter: &str, variables: &[Variable]) -> Result<(), String> {
    for name in uses(filter) {
        if !variables.iter().any(|variable| variable.name == name) {
            return Err(format!("This dashboard has no variable called ${name}."));
        }
    }
    Ok(())
}

/// Something a picker offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

/// What a variable stands for at the moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// Every machine, so its term is left out.
    All,
    One(Choice),
    /// A machine variable with no machines to offer, so there's nothing to show.
    Nothing,
}

impl Pick {
    /// What goes in an address for it. Nothing to pick needs nothing there.
    fn param_value(&self) -> Option<&str> {
        match self {
            Self::All => Some(""),
            Self::One(choice) => Some(&choice.value),
            Self::Nothing => None,
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::All => ALL_LABEL,
            Self::One(choice) => &choice.label,
            Self::Nothing => NONE_LABEL,
        }
    }
}

/// The approved machines in the fleet, as dashboards see it: the server isn't one.
fn fleet(agents: Vec<AgentRecord>) -> impl Iterator<Item = AgentRecord> {
    agents
        .into_iter()
        .filter(|agent| agent.state == AgentState::Approved && !agent.is_local())
}

/// What a variable's picker offers, in order. A fact variable also offers All,
/// which isn't in the list.
pub async fn choices(sources: &Sources<'_>, variable: &Variable) -> Result<Vec<Choice>> {
    let search = HostSearch::from_database(sources.database, Some(&variable.filter)).await?;
    let agents: Vec<AgentRecord> = fleet(sources.registry.list().await)
        .filter(|agent| search.includes(&agent.id, &agent.host))
        .collect();
    let mut choices = match variable.kind {
        VariableKind::Machine => machines(&agents),
        VariableKind::Fact => fact_values(sources, variable, &agents).await?,
    };
    choices.truncate(MAX_CHOICES);
    Ok(choices)
}

/// By name. Names needn't be unique, so machines sharing one are told apart by ID.
fn machines(agents: &[AgentRecord]) -> Vec<Choice> {
    let mut named: HashMap<&str, usize> = HashMap::new();
    for agent in agents {
        *named.entry(agent.host.as_str()).or_default() += 1;
    }
    let mut choices: Vec<Choice> = agents
        .iter()
        .map(|agent| Choice {
            value: agent.id.clone(),
            label: if named[agent.host.as_str()] > 1 {
                format!("{} ({})", agent.host, short_id(&agent.id))
            } else {
                agent.host.clone()
            },
        })
        .collect();
    choices.sort_by(|a, b| {
        a.label
            .to_lowercase()
            .cmp(&b.label.to_lowercase())
            .then_with(|| a.value.cmp(&b.value))
    });
    choices
}

/// The different values the machines have, a list counting each of its items.
async fn fact_values(
    sources: &Sources<'_>,
    variable: &Variable,
    agents: &[AgentRecord],
) -> Result<Vec<Choice>> {
    let fact = host_filter::fact_name(&variable.fact);
    let facts = sources.database.facts_named(&[fact]).await?;
    let items = format!("{fact}[");
    let is_value = |name: &str| {
        name == fact
            || name
                .strip_prefix(&items)
                .and_then(|rest| rest.strip_suffix(']'))
                .is_some_and(|index| index.parse::<usize>().is_ok())
    };
    let mut values = BTreeSet::new();
    for agent in agents {
        let Some(facts) = facts.get(&agent.id) else {
            continue;
        };
        for (name, value) in facts {
            let text = fact_text(value);
            if is_value(name) && !text.trim().is_empty() {
                values.insert(text);
            }
        }
    }
    Ok(values
        .into_iter()
        .map(|value| Choice {
            label: value.clone(),
            value,
        })
        .collect())
}

/// What's picked, given what was asked for in the address and what's on offer. A
/// value that isn't offered, such as a machine that's since been removed, falls back
/// to the first machine, or to All.
pub fn pick(variable: &Variable, choices: &[Choice], asked: Option<&str>) -> Pick {
    if let Some(choice) = asked.and_then(|asked| choices.iter().find(|c| c.value == asked)) {
        return Pick::One(choice.clone());
    }
    match variable.kind {
        VariableKind::Fact => Pick::All,
        VariableKind::Machine => choices.first().cloned().map_or(Pick::Nothing, Pick::One),
    }
}

/// A picker at the top of a dashboard.
#[derive(Debug, Serialize)]
pub struct Picker {
    pub param: String,
    pub title: String,
    /// A fact variable can show every machine at once.
    pub offers_all: bool,
    pub choices: Vec<Choice>,
    /// What's picked: empty for All, and nothing when there's nothing to pick.
    pub selected: Option<String>,
}

/// Every variable's picker, and what each stands for, from an address's
/// parameters.
pub async fn read(
    sources: &Sources<'_>,
    variables: &[Variable],
    params: &BTreeMap<String, String>,
) -> Result<(Vec<Picker>, Picks)> {
    let mut pickers = Vec::with_capacity(variables.len());
    let mut picks = Vec::with_capacity(variables.len());
    for variable in variables {
        let choices = choices(sources, variable).await?;
        let asked = params.get(&variable.param()).map(String::as_str);
        let picked = pick(variable, &choices, asked);
        pickers.push(Picker {
            param: variable.param(),
            title: variable.title().to_string(),
            offers_all: variable.kind == VariableKind::Fact,
            choices,
            selected: picked.param_value().map(str::to_string),
        });
        picks.push((variable.clone(), picked));
    }
    Ok((pickers, Picks::new(picks)))
}

/// What every variable stands for, by name.
#[derive(Debug, Clone, Default)]
pub struct Picks(BTreeMap<String, (Variable, Pick)>);

impl Picks {
    pub fn new(picks: impl IntoIterator<Item = (Variable, Pick)>) -> Self {
        Self(
            picks
                .into_iter()
                .map(|(variable, pick)| (variable.name.clone(), (variable, pick)))
                .collect(),
        )
    }

    /// Works out every variable from an address, offering what they'd offer on the
    /// page.
    pub async fn from_params(
        sources: &Sources<'_>,
        variables: &[Variable],
        params: &BTreeMap<String, String>,
    ) -> Result<Self> {
        Ok(read(sources, variables, params).await?.1)
    }

    /// What's picked, ready to add to an address after a `&`.
    pub fn query(&self) -> String {
        serde_urlencoded::to_string(self.params()).unwrap_or_default()
    }

    /// The address's parameters for what's picked, to keep it as the page changes.
    pub fn params(&self) -> Vec<(String, String)> {
        self.0
            .values()
            .filter_map(|(variable, pick)| {
                pick.param_value()
                    .map(|value| (variable.param(), value.to_string()))
            })
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<&Pick> {
        self.0.get(name).map(|(_, pick)| pick)
    }

    /// The filter with each variable written in, or why there's nothing to show.
    pub fn fill_filter(&self, filter: &str) -> Result<String, String> {
        let mut filled = Vec::new();
        for span in term_spans(filter) {
            let term = &filter[span];
            let Some(name) = term.strip_prefix('$') else {
                filled.push(term.to_string());
                continue;
            };
            let Some((variable, pick)) = self.0.get(name) else {
                return Err(format!("This dashboard has no variable called ${name}."));
            };
            match pick {
                Pick::All => {}
                Pick::One(choice) => filled.push(match variable.kind {
                    VariableKind::Machine => host_filter::only(&choice.value),
                    VariableKind::Fact => {
                        format!("{}={}", variable.fact, written_value(&choice.value))
                    }
                }),
                Pick::Nothing => {
                    return Err(format!(
                        "There's no machine to pick for {}.",
                        variable.title()
                    ));
                }
            }
        }
        Ok(filled.join(" "))
    }

    /// A title with each variable's name replaced by what's picked. Longer names go
    /// first, so `$machine` is never mistaken for `$machine_two`.
    pub fn fill_title(&self, title: &str) -> String {
        let mut names: Vec<&String> = self.0.keys().collect();
        names.sort_by_key(|name| std::cmp::Reverse(name.len()));
        let mut title = title.to_string();
        for name in names {
            let pick = &self.0[name].1;
            title = title.replace(&format!("${name}"), pick.label());
        }
        title
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Variable {
        Variable {
            name: "machine".to_string(),
            label: String::new(),
            kind: VariableKind::Machine,
            fact: String::new(),
            filter: String::new(),
        }
    }

    fn environment() -> Variable {
        Variable {
            name: "env".to_string(),
            label: "Environment".to_string(),
            kind: VariableKind::Fact,
            fact: "environment".to_string(),
            filter: String::new(),
        }
    }

    fn choice(value: &str, label: &str) -> Choice {
        Choice {
            value: value.to_string(),
            label: label.to_string(),
        }
    }

    #[test]
    fn names_are_letters_digits_and_underscores() {
        let named = |name: &str| {
            Variable {
                name: name.to_string(),
                ..machine()
            }
            .tidy()
            .check()
        };
        assert!(named("machine").is_ok());
        assert!(named("$web_2").is_ok(), "a $ typed in front is dropped");
        assert!(named("2web").is_err());
        assert!(named("web-2").is_err());
        assert!(named("").is_err());
        assert!(named(&"m".repeat(33)).is_err());
    }

    #[test]
    fn a_fact_variable_needs_a_fact_and_a_machine_variable_drops_one() {
        let mut variable = environment();
        variable.fact = " ".to_string();
        assert!(variable.tidy().check().is_err());
        let mut variable = environment();
        variable.fact = "os name".to_string();
        assert!(variable.check().is_err());

        let mut variable = machine();
        variable.fact = "anything".to_string();
        assert_eq!(variable.tidy().fact, "");
    }

    #[test]
    fn what_a_variable_offers_cant_depend_on_another() {
        let mut variable = machine();
        variable.filter = "os=windows".to_string();
        assert!(variable.check().is_ok());
        variable.filter = "$env".to_string();
        assert!(variable.check().is_err());
        variable.filter = "os=\"windows".to_string();
        assert!(variable.check().is_err());
    }

    #[test]
    fn a_dashboard_has_each_name_once_and_not_too_many() {
        assert!(check_variables(&[machine(), environment()]).is_ok());
        assert!(check_variables(&[machine(), machine()]).is_err());
        let many: Vec<Variable> = (0..11)
            .map(|n| Variable {
                name: format!("v{n}"),
                ..machine()
            })
            .collect();
        assert!(check_variables(&many).is_err());
    }

    #[test]
    fn a_filter_can_only_use_variables_the_dashboard_has() {
        assert_eq!(uses("os=linux $machine \"$quoted text\""), ["machine"]);
        assert!(check_uses("$machine os=linux", &[machine()]).is_ok());
        assert_eq!(
            check_uses("$host", &[machine()]),
            Err("This dashboard has no variable called $host.".to_string())
        );
    }

    #[test]
    fn a_pick_falls_back_when_what_was_asked_for_is_not_offered() {
        let machines = [choice("aa", "db-1"), choice("bb", "web-1")];
        assert_eq!(
            pick(&machine(), &machines, Some("bb")),
            Pick::One(choice("bb", "web-1"))
        );
        assert_eq!(
            pick(&machine(), &machines, Some("gone")),
            Pick::One(choice("aa", "db-1"))
        );
        assert_eq!(pick(&machine(), &[], None), Pick::Nothing);
        assert_eq!(pick(&environment(), &machines, Some("")), Pick::All);
        assert_eq!(pick(&environment(), &machines, None), Pick::All);
    }

    #[test]
    fn picks_are_written_into_filters_and_titles() {
        let picks = Picks::new([
            (machine(), Pick::One(choice("ab12", "web-1"))),
            (environment(), Pick::One(choice("live east", "live east"))),
        ]);
        assert_eq!(
            picks.fill_filter("$machine os=linux $env").unwrap(),
            "id=ab12 os=linux environment=\"live east\""
        );
        assert_eq!(
            picks.fill_title("CPU on $machine in $env"),
            "CPU on web-1 in live east"
        );

        let picks = Picks::new([(environment(), Pick::All), (machine(), Pick::Nothing)]);
        assert_eq!(picks.fill_filter("$env os=linux").unwrap(), "os=linux");
        assert_eq!(picks.fill_title("CPU in $env"), "CPU in All");
        assert!(picks.fill_filter("$machine").is_err());
        assert!(picks.fill_filter("$other").is_err());
    }

    #[test]
    fn a_longer_name_is_filled_before_one_it_starts_with() {
        let two = Variable {
            name: "machine_two".to_string(),
            ..machine()
        };
        let picks = Picks::new([
            (machine(), Pick::One(choice("a", "web-1"))),
            (two, Pick::One(choice("b", "web-2"))),
        ]);
        assert_eq!(
            picks.fill_title("$machine vs $machine_two"),
            "web-1 vs web-2"
        );
    }

    #[test]
    fn the_address_keeps_what_is_picked() {
        let picks = Picks::new([
            (machine(), Pick::One(choice("ab12", "web-1"))),
            (environment(), Pick::All),
        ]);
        assert_eq!(
            picks.params(),
            [
                ("var-env".to_string(), String::new()),
                ("var-machine".to_string(), "ab12".to_string()),
            ]
        );
        let none = Picks::new([(machine(), Pick::Nothing)]);
        assert!(none.params().is_empty());
    }

    #[test]
    fn machines_sharing_a_name_are_told_apart() {
        let agent = |id: &str, host: &str| AgentRecord {
            id: id.to_string(),
            public_key: String::new(),
            host: host.to_string(),
            state: AgentState::Approved,
            decided_by: None,
            first_seen_ms: 0,
            decided_at_ms: None,
        };
        let choices = machines(&[
            agent("ffff00001111", "web"),
            agent("aaaa00001111", "web"),
            agent("bbbb00001111", "db"),
        ]);
        let labels: Vec<&str> = choices.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, ["db", "web (aaaa0000)", "web (ffff0000)"]);
    }
}
