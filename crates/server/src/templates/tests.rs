use serde_json::json;

use super::*;
use maxnines_protocol::templates::parse;

const POSTGRES: &str = include_str!("../../../protocol/src/templates/examples/postgres.hcl");
const IIS: &str = include_str!("../../../protocol/src/templates/examples/iis.hcl");

fn no_facts() -> Value {
    json!({})
}

fn problems(text: &str) -> Vec<String> {
    let template = parse(text).unwrap();
    check(&template, &no_facts())
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
fn both_examples_load() {
    for text in [POSTGRES, IIS] {
        let template = load(text, &no_facts()).unwrap_or_else(|error| panic!("{error:#}"));
        assert!(!template.alerts.is_empty());
    }
}

#[test]
fn a_template_knows_its_own_metrics_and_what_they_are() {
    let postgres = local_metrics(&parse(POSTGRES).unwrap());
    assert_eq!(postgres.prefix, "postgres");
    let kind = |name: &str| postgres.metrics[name].kind;
    assert_eq!(kind("up"), LocalKind::Flag);
    assert_eq!(kind("lag"), LocalKind::Unknown);
    assert_eq!(kind("cache_hit"), LocalKind::Number);
    assert_eq!(kind("checkpoints_requested"), LocalKind::Number);
    assert_eq!(postgres.metrics["slot_retained"].labels, ["slot"]);
    assert_eq!(
        postgres.metrics["lag_bytes"].labels,
        ["application", "address"]
    );
    assert!(
        !postgres.metrics.contains_key("slot"),
        "a label isn't a metric"
    );
    // From each version's SQL.
    assert!(postgres.metrics.contains_key("checksum_failures"));
    assert!(postgres.metrics.contains_key("slot_lost"));

    let iis = local_metrics(&parse(IIS).unwrap());
    assert_eq!(iis.metrics["pool_running"].kind, LocalKind::Flag);
    assert_eq!(iis.metrics["queue_oldest"].kind, LocalKind::Seconds);
    assert_eq!(iis.metrics["requests"].labels, ["site"]);
    assert_eq!(iis.metrics["pool_memory"].labels, ["pool"]);
    assert!(
        !iis.metrics.contains_key("up"),
        "only databases are up or not"
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
