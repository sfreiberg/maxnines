use serde_json::json;

use super::*;
use maxnines_protocol::templates::parse;

const IIS: &str = include_str!("../../../../docs/examples/iis.hcl");

fn no_facts() -> Value {
    json!({})
}

fn problems(text: &str) -> Vec<String> {
    let template = parse(text).unwrap();
    check(&template, &no_facts(), &Catalog::built_in())
        .iter()
        .map(|problem| problem.describe(&template))
        .collect()
}

/// A template with one query and these alerts.
fn with_alerts(alerts: &str) -> String {
    format!(
        r#"template "app" {{
             name     = "App"
             database = "postgres"
             query "replication" {{
               sql = <<-SQL
                 SELECT application_name AS standby, replay_lag AS lag,
                        state = 'streaming' AS streaming
                 FROM pg_stat_replication
               SQL
               labels  = ["standby"]
               metrics = {{ lag_secs = {{ value = "lag", unit = "s" }} }}
             }}
             query "slots" {{
               sql    = "SELECT slot_name AS slot, active AS in_use FROM pg_replication_slots"
               labels = ["slot"]
             }}
             {alerts}
           }}"#
    )
}

#[test]
fn the_postgres_template_and_the_iis_example_load() {
    for text in [postgres_as_pg().as_str(), IIS] {
        let template = load(text, &no_facts(), &Catalog::built_in())
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert!(!template.alerts.is_empty());
    }
}

/// A template's metrics as they're read, by their names within it.
fn own(template: &Template) -> std::collections::BTreeMap<String, Metric> {
    metrics_of(template)
        .into_iter()
        .map(|(metric, _)| {
            let short = metric.name[template.key.len() + 1..].to_string();
            (short, metric)
        })
        .collect()
}

#[test]
fn a_template_knows_its_own_metrics_and_what_they_are() {
    let postgres = own(&parse(&postgres_as_pg()).unwrap());
    let kind = |name: &str| postgres[name].kind;
    assert_eq!(postgres["lag"].name, "pg.lag");
    assert_eq!(postgres["lag"].collector, "template.pg");
    assert_eq!(postgres["lag"].template.as_deref(), Some("pg"));
    assert_eq!(kind("up"), Kind::Flag);
    assert_eq!(kind("lag"), Kind::Seconds);
    assert_eq!(kind("connections"), Kind::Unknown);
    assert_eq!(kind("cache_hit"), Kind::Number);
    assert_eq!(kind("checkpoints_requested"), Kind::Number);
    // A database template runs once for each database, so every series says which.
    assert_eq!(postgres["up"].labels(), ["instance"]);
    assert_eq!(postgres["slot_retained"].labels(), ["instance", "slot"]);
    assert_eq!(
        postgres["lag_bytes"].labels(),
        ["instance", "application", "address"]
    );
    // Two queries give a lag, one for each standby and one for the replica itself,
    // so it has the labels of both.
    assert_eq!(
        postgres["lag"].labels(),
        ["instance", "application", "address"]
    );
    assert!(!postgres.contains_key("slot"), "a label isn't a metric");
    // From each version's SQL.
    assert!(postgres.contains_key("checksum_failures"));
    assert!(postgres.contains_key("slot_lost"));

    // What a metric is measured in is what the template says, with a running total
    // read as a rate.
    let unit = |name: &str| postgres[name].unit;
    assert_eq!(unit("connections_used"), Unit::Percent);
    assert_eq!(unit("slot_retained"), Unit::Bytes);
    assert_eq!(unit("temp_written"), Unit::BytesPerSecond);
    assert_eq!(unit("transactions"), Unit::PerSecond);
    assert_eq!(unit("connections"), Unit::Number);
    let total = |name: &str| match &postgres[name].source {
        Source::Labelled(labelled) => labelled.total,
        _ => panic!("{name} isn't a template's"),
    };
    assert!(total("transactions") && !total("connections"));
    assert_eq!(
        postgres["connections_used"].description.as_deref(),
        Some("Connections in use, out of those not reserved for superusers")
    );
    assert_eq!(postgres["slot_retained"].title, "PG slot retained");

    let iis = own(&parse(IIS).unwrap());
    assert_eq!(iis["pool_running"].kind, Kind::Flag);
    assert_eq!(iis["queue_oldest"].kind, Kind::Seconds);
    assert_eq!(iis["queue_oldest"].unit, Unit::Seconds);
    // It runs once on a host, so its series only have their own labels.
    assert_eq!(iis["requests"].labels(), ["site"]);
    assert_eq!(iis["pool_memory"].labels(), ["pool"]);
    // Windows' own names say what its counters are measured in.
    assert_eq!(iis["requests"].unit, Unit::PerSecond);
    assert!(!iis.contains_key("up"), "only databases are up or not");
}

#[test]
fn a_metric_is_on_while_its_template_and_a_part_that_gives_it_are() {
    let mut template = parse(&postgres_as_pg()).unwrap();
    let on = |template: &Template, name: &str| {
        let metrics = metrics_of(template);
        let (_, on) = metrics
            .iter()
            .find(|(metric, _)| metric.name == name)
            .unwrap_or_else(|| panic!("no {name}"));
        *on
    };
    assert!(on(&template, "pg.connections"));
    // The sizes ship turned off.
    assert!(!on(&template, "pg.size"));
    // Both queries that give a lag have to be off for it to be.
    let standbys = template.queries.iter().position(|q| q.key == "standbys");
    template.queries[standbys.unwrap()].enabled = false;
    assert!(on(&template, "pg.lag") && !on(&template, "pg.lag_bytes"));
    template.enabled = false;
    assert!(!on(&template, "pg.connections") && !on(&template, "pg.up"));
}

#[test]
fn the_catalog_has_the_metrics_of_templates_that_are_on() {
    let postgres = parse(&postgres_as_pg()).unwrap();
    let iis = parse(IIS).unwrap();
    let built_in = Catalog::built_in();
    let catalog = Catalog::with_templates([&postgres, &iis]);
    assert!(built_in.find("pg.lag").is_none());
    assert_eq!(catalog.find("pg.lag").unwrap().title, "PG lag");
    assert!(catalog.find("iis.requests").is_some());
    // The built-in ones come first, as they did.
    let names = |catalog: &Catalog| -> Vec<String> {
        let all = catalog.all().iter();
        all.map(|metric| metric.name.clone()).collect()
    };
    assert_eq!(
        names(&catalog)[..built_in.all().len()],
        names(&built_in)[..]
    );
    assert_eq!(catalog.find("cpu.usage"), built_in.find("cpu.usage"));

    // One of a part that's off isn't listed or read, but a condition can still
    // name it.
    assert!(catalog.find("pg.size").is_none());
    assert!(!names(&catalog).contains(&"pg.size".to_string()));
    assert!(catalog.find_known("pg.size").is_some());

    // A template that's off has none that are read.
    let mut off = postgres.clone();
    off.enabled = false;
    let catalog = Catalog::with_templates([&off]);
    assert!(catalog.find("pg.lag").is_none() && catalog.find_known("pg.lag").is_some());
    assert_eq!(catalog.all().len(), built_in.all().len());

    // Checking a template knows its metrics as it says them now, whatever the
    // catalog had under its key.
    let mut changed = postgres.clone();
    changed.queries.retain(|query| query.key != "slots");
    let checked = Catalog::with_templates([&postgres]).with_template(&changed);
    assert!(checked.find_known("pg.slot_retained").is_none());
    assert!(checked.find("pg.size").is_some(), "every part counts");
}

/// MaxNines reads MongoDB itself, under names a template keyed `mongodb` would give
/// its metrics too, so one is refused.
#[test]
fn a_metric_with_a_built_in_metrics_name_is_refused() {
    let found = problems(
        r#"template "mongodb" {
             name     = "MongoDB"
             database = "mongodb"
             query "server" { sql = "SELECT 1 AS connections, 2 AS spare, 3 AS uptime" }
           }"#,
    );
    assert_eq!(
        found,
        [
            r#"template "mongodb": its metric mongodb.up would have the name of one MaxNines has built in: give the template another key"#,
            r#"template "mongodb", query "server": its metrics mongodb.connections, mongodb.uptime would have the names of ones MaxNines has built in: give the columns other names, or the template another key"#,
        ]
    );
    // The built-in PostgreSQL template's are its own, and under another key it
    // has nothing wrong with it either.
    assert_eq!(problems(&postgres_as_pg()), Vec::<String>::new());

    // One name is enough, and it's the column that says where.
    let found = problems(
        r#"template "cpu" {
             name     = "Processor"
             database = "postgres"
             query "q" { sql = "SELECT 1 AS usage, 2 AS heat" }
           }"#,
    );
    assert_eq!(
        found,
        [
            r#"template "cpu", query "q": its metric cpu.usage would have the name of one MaxNines has built in: give the columns other names, or the template another key"#
        ]
    );
}

#[test]
fn alerts_use_their_own_metrics_by_either_name() {
    let found = problems(&with_alerts(
        r#"alert "a" {
             name     = "Lagging"
             warning  = "lag > duration('30s') && streaming"
             critical = "app.lag_secs > duration('5m')"
             summary  = "{{ hostname }}: {{ labels.standby }} on {{ instance }} is {{ lag }} behind, {{ app.lag_secs }}"
           }
           alert "b" {
             name     = "Slot"
             critical = "!in_use && slot_retained > 1"
           }"#,
    ));
    // Only the slot's mistake.
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0]
            .starts_with(r#"template "app", alert "b", critical: slot_retained isn't a metric"#),
        "{found:#?}"
    );
}

#[test]
fn alert_mistakes_name_the_field_they_are_in() {
    for (alert, expected) in [
        (
            r#"warning = "lagg > duration('30s')""#,
            r#"alert "a", warning: there's no metric called lagg: did you mean lag?"#,
        ),
        (r#"critical = "lag_secs > 30""#, r#"alert "a", critical: "#),
        (
            r#"critical = "lag > duration('1m') && in_use""#,
            r#"alert "a": lag and in_use have series labelled differently (standby and slot)"#,
        ),
        (
            r#"critical = "!streaming"
               summary  = "{{ labels.nothing }}""#,
            r#"alert "a", summary: "#,
        ),
        (
            r#"critical = "!streaming"
               summary  = "{{ broken""#,
            r#"alert "a", summary: "#,
        ),
        (
            r#"critical = "!streaming"
               when     = "role ==""#,
            r#"alert "a", when: isn't CEL"#,
        ),
        (
            r#"critical = "!streaming"
               window   = "2h""#,
            r#"alert "a", window: only a calculation or forecast() looks back over a window"#,
        ),
    ] {
        let found = problems(&with_alerts(&format!(
            "alert \"a\" {{\n name = \"A\"\n {alert}\n}}"
        )));
        assert!(
            found.iter().any(|problem| problem.contains(expected)),
            "{expected}\n{found:#?}"
        );
    }
}

#[test]
fn a_query_says_what_columns_it_gives() {
    let postgres = PostgreSqlDialect {};
    assert_eq!(
        columns(&postgres, "SELECT a, t.b, count(*) AS c, \"d\" FROM t").unwrap(),
        ["a", "b", "c", "d"].map(String::from)
    );
    // Not quoted, so lowercase to the database.
    assert_eq!(columns(&postgres, "SELECT Version").unwrap(), ["version"]);
    for (sql, expected) in [
        ("SELECT count(*) FROM t", "column 1 needs a name"),
        ("SELECT * FROM t", "rather than use *"),
        ("SELECT a, b AS a FROM t", "two columns called \"a\""),
        ("SELECT \"Mixed Case\" FROM t", "can't be a metric's name"),
        ("DELETE FROM t", "has to be one SELECT"),
        ("SELECT 1 AS a; SELECT 2 AS b", "has to be one SELECT"),
        ("SELEC a", "can't be read"),
    ] {
        let error = columns(&postgres, sql).unwrap_err();
        assert!(error.contains(expected), "{sql}: {error}");
    }
}

#[test]
fn queries_name_their_labels_and_metrics_among_their_columns() {
    let found = problems(
        r#"template "app" {
             name = "App"
             query "q" {
               sql     = "SELECT a, b FROM t"
               labels  = ["c"]
               metrics = {
                 d = { unit = "bytes" }
                 e = { value = "a / b" }
               }
             }
             query "online" { sql = "SELECT 1 AS online" }
           }"#,
    );
    for expected in [
        r#"query "q", labels: "c" isn't one of the query's columns"#,
        r#"query "q", metric "d": "d" isn't one of the query's columns"#,
        r#"template "app": a metric can't be called online"#,
    ] {
        assert!(
            found.iter().any(|problem| problem.contains(expected)),
            "{expected}\n{found:#?}"
        );
    }
    assert!(!found.iter().any(|problem| problem.contains("metric \"e\"")));
}

#[test]
fn every_cel_expression_has_to_compile() {
    let found = problems(
        r#"template "app" {
             name = "App"
             os   = ["windows"]
             notice "n" {
               when = "a &&"
               text = "Hi"
             }
             counters "c" {
               object  = "Process"
               when    = "(("
               metrics = { m = { counter = "X", value = "value ==" } }
             }
           }"#,
    );
    for expected in [
        r#"notice "n", when: isn't CEL"#,
        r#"counters "c", when: isn't CEL"#,
        r#"counters "c", metric "m", value: isn't CEL"#,
    ] {
        assert!(
            found.iter().any(|problem| problem.contains(expected)),
            "{expected}\n{found:#?}"
        );
    }
}

/// What the eight built-in alert rules were before they moved into the host
/// template, which they have to stay.
#[test]
fn the_host_template_keeps_the_built_in_alert_rules() {
    let host = built_in::all().unwrap().remove(0).template;
    let rules: Vec<AlertRuleInput> = host
        .alerts
        .iter()
        .map(|alert| alert_rule(&host, alert).unwrap())
        .collect();
    fn summarised(rule: &AlertRuleInput) -> (&str, Option<&str>, Option<&str>, i64, Option<i64>) {
        (
            rule.name.as_str(),
            rule.warning.as_deref(),
            rule.critical.as_deref(),
            rule.hold.num_seconds(),
            rule.window.map(|window| window.num_seconds()),
        )
    }
    let all: Vec<_> = rules.iter().map(summarised).collect();
    assert_eq!(
        all,
        [
            ("Host offline", None, Some("!online"), 60, None),
            (
                "Disk filling up",
                Some("disk.usage > 80"),
                Some("disk.usage > 90"),
                300,
                None
            ),
            ("Container down", None, Some("container.up < 1"), 60, None),
            (
                "Disk will be full soon",
                Some("forecast(disk.usage, duration('24h')) >= 100"),
                Some("forecast(disk.usage, duration('4h')) >= 100"),
                1800,
                Some(21_600)
            ),
            (
                "Disk running out of inodes",
                Some("disk.inodes > 80"),
                Some("disk.inodes > 90"),
                300,
                None
            ),
            (
                "Clock is wrong",
                Some("clock.difference > duration('5s')"),
                Some("clock.difference > duration('30s')"),
                60,
                None
            ),
            (
                "Service stopped",
                None,
                Some("service.running < 1"),
                60,
                None
            ),
            (
                "Host sending no metrics",
                None,
                Some("!reporting"),
                300,
                None
            ),
            (
                "Database account can do more than read",
                Some("database_account.overprivileged > 0"),
                None,
                60,
                None
            ),
        ]
    );
    for rule in &rules {
        assert!(rule.all_channels && rule.enabled && rule.applies_to.is_none());
        crate::alerting::check_rule(rule).unwrap();
    }
    assert_eq!(
        rules[0].summary.as_deref(),
        Some("{{ hostname }} is offline")
    );
    assert_eq!(
        rules[7].resolved_summary.as_deref(),
        Some("{{ hostname }} is sending metrics again")
    );
}

#[test]
fn an_os_template_alerts_only_on_those_systems() {
    let template = parse(
        r#"template "app" {
             name = "App"
             os   = ["linux", "freebsd"]
           }"#,
    )
    .unwrap();
    assert_eq!(
        applies_to(&template).as_deref(),
        Some("facts.os.family in ['linux', 'freebsd']")
    );
    cel::Program::compile(&applies_to(&template).unwrap()).unwrap();
}

/// `instance` is the database a series is from, in every template, so none can give
/// a label that name.
#[test]
fn no_template_labels_a_series_instance() {
    let found = problems(
        r#"template "app" {
             name = "App"
             os   = ["windows"]
             counters "named" {
               object  = "Web Service"
               label   = "instance"
               metrics = { requests = "Total Method Requests/sec" }
             }
             counters "patterned" {
               object  = "W3SVC_W3WP"
               pattern = "^\\d+_(?<instance>.+)$"
               metrics = { active = "Active Requests" }
             }
             counters "fine" {
               object  = "Web Service"
               label   = "site"
               metrics = { connections = "Current Connections" }
             }
           }"#,
    );
    for block in ["named", "patterned"] {
        let expected = format!(r#"counters "{block}": a label can't be called instance"#);
        assert!(
            found.iter().any(|problem| problem.contains(&expected)),
            "{expected}\n{found:#?}"
        );
    }
    assert!(
        !found.iter().any(|problem| problem.contains("\"fine\"")),
        "{found:#?}"
    );
}

#[test]
fn sql_needs_a_template_for_a_database() {
    let found = problems(
        r#"template "app" {
             name = "App"
             os   = ["linux"]
             discover "d" { sql = "SELECT 1 AS one" }
             query "q" { sql = "SELECT 1 AS two" }
           }"#,
    );
    for place in [r#"discover "d", sql"#, r#"query "q", sql"#] {
        let expected = format!(r#"template "app", {place}: needs a database to run on"#);
        assert!(
            found.iter().any(|problem| problem.starts_with(&expected)),
            "{expected}\n{found:#?}"
        );
    }
}

#[test]
fn what_discover_blocks_find_is_found_once() {
    let found = problems(
        r#"template "app" {
             name     = "App"
             database = "postgres"
             discover "one" { sql = "SELECT 1 AS version, 2 AS role" }
             discover "two" {
               sql = "SELECT 3 AS role"
               registry "HKLM\\SOFTWARE\\App" { version = "Version" }
             }
           }"#,
    );
    for expected in [
        r#"template "app", discover "two", sql: "role" is found by another discover block too"#,
        r#"template "app", discover "two", registry: "version" is found by another discover block too"#,
    ] {
        assert!(
            found.iter().any(|p| p == expected),
            "{expected}\n{found:#?}"
        );
    }
}
