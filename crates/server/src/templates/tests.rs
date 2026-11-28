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
    assert_eq!(
        postgres["slot_retained"].title,
        "PG WAL kept by a replication slot"
    );

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
    assert_eq!(catalog.find("pg.lag").unwrap().title, "PG replication lag");
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

/// A template kept from before its key was one built-in metrics start with has none
/// of its metrics read, on or off, and the built-in ones are as they were.
#[test]
fn the_catalog_leaves_out_a_template_whose_key_built_in_metrics_start_with() {
    let stored = parse(
        r#"template "cpu" {
             name     = "Processor"
             database = "postgres"
             query "q" { sql = "SELECT 1 AS heat, 2 AS usage" }
             query "off" {
               enabled = false
               sql     = "SELECT 1 AS spare"
             }
           }"#,
    )
    .unwrap();
    let built_in = Catalog::built_in();
    let catalog = Catalog::with_templates([&stored]);
    assert_eq!(catalog.all().len(), built_in.all().len());
    assert!(catalog.find("cpu.heat").is_none());
    assert!(catalog.find("cpu.up").is_none());
    assert!(catalog.find_known("cpu.spare").is_none());
    assert_eq!(catalog.find("cpu.usage"), built_in.find("cpu.usage"));
    assert_eq!(catalog.of_template("cpu").count(), 0);
}

/// A template's metrics can't be named among the ones MaxNines has built in.
#[test]
fn a_template_with_metrics_cannot_have_a_key_built_in_metrics_start_with() {
    // The built-in PostgreSQL template's are its own, and under another key it
    // has nothing wrong with it either.
    assert_eq!(problems(&postgres_as_pg()), Vec::<String>::new());

    // Whatever its metrics are called, and it's said once: its alerts, which would
    // be read as being about the built-in metrics, aren't checked until then.
    let found = problems(
        r#"template "cpu" {
             name     = "Processor"
             database = "postgres"
             query "q" { sql = "SELECT 1 AS heat" }
             alert "hot" {
               name    = "Hot"
               warning = "usage > 90 && no_such_metric > 1"
             }
           }"#,
    );
    assert_eq!(
        found,
        [
            r#"template "cpu", key: "cpu" is what metrics MaxNines has built in start with, and this template's own, such as cpu.up, would be named among them: give it another key"#
        ]
    );

    // A database template has one of its own without a query: whether it answers.
    let found = problems(
        r#"template "server" {
             name     = "Server"
             database = "postgres"
           }"#,
    );
    assert_eq!(
        found,
        [
            r#"template "server", key: "server" is what metrics MaxNines has built in start with, and this template's own, such as server.up, would be named among them: give it another key"#
        ]
    );

    // Counters blocks' are metrics too.
    let found = problems(
        r#"template "disk" {
             name = "Disks"
             os   = ["windows"]
             counters "c" {
               object  = "PhysicalDisk"
               metrics = { speed = { counter = "Disk Bytes/sec" } }
             }
           }"#,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("such as disk.speed"), "{found:?}");

    // One with only alerts about other metrics has none to name, as the built-in
    // `raid` and `updates` are, and a key that only starts like a taken one is free.
    let alerts_only = r#"template "disk" {
             name = "Disks"
             alert "full" {
               name    = "Disk full"
               warning = "disk.usage > 90"
             }
           }"#;
    assert_eq!(problems(alerts_only), Vec::<String>::new());
    let free = r#"template "disks" {
             name     = "Disks"
             database = "postgres"
             query "q" { sql = "SELECT 1 AS heat" }
           }"#;
    assert_eq!(problems(free), Vec::<String>::new());
}

/// Every built-in metric's name is one, and the keys the docs say are taken are
/// what they start with, worked out from them.
#[test]
fn the_keys_built_in_metrics_take_are_the_ones_the_docs_list() {
    for metric in crate::metrics::built_in() {
        assert!(
            maxnines_protocol::entries::is_metric_name(&metric.name),
            "{}",
            metric.name
        );
    }
    let docs = include_str!("../../../../docs/templates.md");
    let listed = docs
        .lines()
        .skip_while(|line| !line.ends_with("The keys taken are:"))
        .find(|line| line.starts_with('`'))
        .expect("the docs list the keys taken");
    let listed: Vec<&str> = listed
        .trim_end_matches('.')
        .split(", ")
        .map(|key| key.trim_matches('`'))
        .collect();
    let taken: Vec<&str> = crate::metrics::prefixes().iter().copied().collect();
    assert_eq!(listed, taken);
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
    let host = built_in::all()
        .unwrap()
        .into_iter()
        .find(|one| one.template.key == "host")
        .unwrap()
        .template;
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

#[test]
fn a_query_can_be_one_show_statement_naming_its_columns() {
    let template = |database: &str, sql: &str, columns: &str| {
        format!(
            r#"template "my" {{
                 name     = "My"
                 database = "{database}"
                 query "replication" {{
                   sql     = "{sql}"
                   {columns}
                   labels  = ["channel"]
                 }}
               }}"#
        )
    };
    let columns = r#"columns = { channel = "Channel_Name", behind = "Seconds_Behind_Source" }"#;
    let fine = template("mysql", "SHOW REPLICA STATUS", columns);
    assert_eq!(problems(&fine), Vec::<String>::new());
    let parsed = parse(&fine).unwrap();
    assert_eq!(
        query_columns_of(&parsed, &parsed.queries[0]),
        ["channel", "behind"]
    );
    // Any SHOW the database takes, on any kind of database: what it may read is up to
    // its account.
    let any = template("postgres", "SHOW GRANTS", columns);
    assert_eq!(problems(&any), Vec::<String>::new());
    let refused = |text: String, expected: &str| {
        let found = problems(&text);
        assert!(
            found.iter().any(|problem| problem.contains(expected)),
            "{expected}: {found:#?}"
        );
    };
    refused(
        template("mysql", "SHOW STATUS; DROP TABLE x", columns),
        "one SELECT or SHOW statement",
    );
    refused(
        template("mysql", "SHOW REPLICA STATUS", ""),
        "has to name the columns",
    );
    refused(
        template("mysql", "SELECT 1 AS channel", columns),
        "only for a SHOW statement",
    );
}

/// Binary logs are only read where they're on: off, the query isn't sent, so there's
/// nothing for it to say.
#[test]
fn the_mysql_template_reads_binary_logs_only_where_they_are_on() {
    let mut mysql = built_in::all()
        .unwrap()
        .into_iter()
        .find(|one| one.template.key == "mysql")
        .unwrap()
        .template;
    for query in &mut mysql.queries {
        query.enabled = true;
    }
    let sent = |binary_logging: f64, mariadb: f64| -> Vec<String> {
        let found = json!({
            "version": "8.4.3",
            "mariadb": mariadb,
            "binary_logging": binary_logging,
        });
        work::database_work(&mysql, "shop", found.as_object())
            .queries
            .into_iter()
            .map(|query| query.key)
            .collect()
    };
    assert!(sent(1.0, 0.0).contains(&"binary_logs".to_string()));
    assert!(!sent(0.0, 0.0).contains(&"binary_logs".to_string()));
    // MySQL's queries and MariaDB's are each sent only to their own.
    assert!(sent(1.0, 0.0).contains(&"replication".to_string()));
    assert!(!sent(1.0, 0.0).contains(&"replication_mariadb".to_string()));
    assert!(sent(1.0, 1.0).contains(&"replication_mariadb".to_string()));
    assert!(!sent(1.0, 1.0).contains(&"status".to_string()));
}

/// A built-in template's settings are a config rule's, checked as one is, and go
/// out and back in HCL as they are.
#[test]
fn a_templates_config_is_checked_as_a_rules_settings_and_kept_in_hcl() {
    let with = |settings: &str| {
        format!(
            r#"template "box" {{
                 name = "Box"
                 os   = ["linux"]
                 config {{
                   {settings}
                 }}
               }}"#
        )
    };
    let fine = with("collectors = { gpu = { enabled = true } }\n interval_secs = 30");
    assert_eq!(problems(&fine), Vec::<String>::new());
    let template = parse(&fine).unwrap();
    assert_eq!(
        template.config.as_ref().unwrap()["collectors"]["gpu"]["enabled"],
        true
    );
    let again = parse(&maxnines_protocol::templates::to_hcl(&template)).unwrap();
    assert_eq!(again, template);
    let rule = crate::built_in_rules::of_template(&template).unwrap();
    assert_eq!(rule.key, "box");
    assert_eq!(rule.rule.name, "Box");
    assert_eq!(rule.rule.operating_systems, ["linux"]);
    assert_eq!(rule.rule.priority, 0);

    let wrong = problems(&with("collectors = { teleporter = { enabled = true } }"));
    assert!(
        wrong.iter().any(|problem| problem.contains("config")),
        "{wrong:#?}"
    );
}

/// A template for MongoDB, which isn't SQL: one command each, with the fields read
/// from its reply named.
const DOCS: &str = r#"
template "docs" {
  name     = "Documents"
  database = "mongodb"

  discover "role" {
    command = "{ \"hello\": 1 }"
    columns = { primary = "isWritablePrimary", replica_set = "setName" }
  }

  query "members" {
    when    = "replica_set != null"
    command = "{ \"replSetGetStatus\": 1 }"
    rows    = "members"
    labels  = ["member"]
    columns = {
      member  = "name"
      _health = "health"
      _state  = "state"
      _optime = "optimeDate"
      _leader = "$.members[state=1].optimeDate"
    }
    metrics = {
      healthy = { value = "_health == 1" }
      lag     = { value = "_state == 2 ? _leader - _optime : null", unit = "s" }
    }
  }

  alert "unhealthy" {
    name    = "Member unhealthy"
    warning = "!healthy"
    summary = "{{ labels.member }} isn't healthy"
  }
}
"#;

#[test]
fn mongodb_is_asked_with_commands_whose_fields_become_metrics() {
    assert_eq!(problems(DOCS), Vec::<String>::new());
    let template = parse(DOCS).unwrap();
    assert_eq!(discovered_names(&template), ["primary", "replica_set"]);
    // What's only for working others out isn't a metric.
    let metrics: Vec<(String, Kind)> = metrics_of(&template)
        .into_iter()
        .map(|(metric, _)| (metric.name, metric.kind))
        .collect();
    assert_eq!(
        metrics,
        [
            ("docs.up".to_string(), Kind::Flag),
            ("docs.healthy".to_string(), Kind::Flag),
            ("docs.lag".to_string(), Kind::Seconds),
        ]
    );

    // A command has to be one, and its fields named.
    let found = problems(&DOCS.replace("{ \\\"hello\\\": 1 }", "hello"));
    assert!(
        found
            .iter()
            .any(|p| p
                .starts_with(r#"template "docs", discover "role", command: isn't one command"#)),
        "{found:?}"
    );
    let found = problems(&DOCS.replace(
        "columns = { primary = \"isWritablePrimary\", replica_set = \"setName\" }",
        "",
    ));
    assert!(
        found
            .iter()
            .any(|p| p.contains(r#"discover "role", columns: has to name what it finds"#)),
        "{found:?}"
    );
    let found = problems(&DOCS.replace(
        "\"{ \\\"replSetGetStatus\\\": 1 }\"",
        "\"{ \\\"replSetGetStatus\\\": 1, \\\"$out\\\": 1 }\"",
    ));
    assert!(
        found
            .iter()
            .any(|p| p.contains(r#"query "members", command: can't give $out"#)),
        "{found:?}"
    );
}

/// What real Redis 8.12 said to INFO, captured by the checks' `fixtures/redis/capture.sh`.
macro_rules! redis_info {
    ($name:literal) => {
        include_str!(concat!("../../../checks/fixtures/redis/", $name, ".info"))
    };
}

/// Each row the built-in Redis template's work gives for INFO saying each of
/// `infos` in turn, a minute apart, where discovery found `found`, with what the
/// server works out from them: the last round's rows.
fn redis_rows(found: Value, infos: &[&str]) -> Vec<Value> {
    use maxnines_checks::templates::{Cell, Totals, metric_rows, picked, redis::info};
    use maxnines_protocol::Sample;
    use maxnines_protocol::templates::work::collector_of;
    use std::collections::{BTreeMap, HashMap};

    let template = built_in::all()
        .unwrap()
        .into_iter()
        .find(|built_in| built_in.template.key == "redis")
        .unwrap()
        .template;
    let found = found.as_object().unwrap().clone();
    let work = work::database_work(&template, "cache", Some(&found));
    let values = values::worked_out(&template);
    let mut totals: HashMap<String, Totals> = HashMap::new();
    let mut last_sent = values::LastSent::default();
    let start = crate::times::now();
    let mut rows = Vec::new();
    for (round, text) in infos.iter().enumerate() {
        let mut read = Vec::new();
        for query in &work.queries {
            // What the agent's Redis session gives: the reply, as a document.
            let reply = vec![vec![(
                "reply".to_string(),
                Cell::Reply(Box::new(info(text))),
            )]];
            let totals = totals.entry(query.key.clone()).or_default();
            read.extend(metric_rows(&picked(reply, query), query, "cache", totals));
        }
        let mut sample = Sample {
            time: start + chrono::TimeDelta::minutes(round as i64),
            metrics: BTreeMap::from([(collector_of("redis"), Value::Array(read))]),
        };
        values::work_out(
            &mut sample,
            &values,
            std::slice::from_ref(&work),
            &Value::Null,
            &mut last_sent,
        );
        rows = sample.metrics[&collector_of("redis")]
            .as_array()
            .unwrap()
            .clone();
    }
    rows
}

/// The one row of a query's whose labels hold these, besides the database's.
fn redis_row<'a>(rows: &'a [Value], query: &str, labels: Value) -> &'a Value {
    let matching: Vec<&Value> = rows
        .iter()
        .filter(|row| row["_query"] == query)
        .filter(|row| {
            labels
                .as_object()
                .unwrap()
                .iter()
                .all(|(name, value)| &row["labels"][name] == value)
        })
        .collect();
    assert_eq!(matching.len(), 1, "{query} {labels}: {rows:#?}");
    matching[0]
}

#[test]
fn the_built_in_redis_template_reads_what_real_redis_says() {
    let template = built_in::all()
        .unwrap()
        .into_iter()
        .find(|built_in| built_in.template.key == "redis")
        .unwrap()
        .template;
    // Commands go to where they run as their words, so they can't be taken for SQL.
    let found = json!({ "version": "8.12.0", "role": "master", "policy": "noeviction" });
    let work = work::database_work(&template, "cache", found.as_object());
    assert_eq!(
        work.discover[0].sql.as_deref(),
        Some(r#"["INFO","server"]"#)
    );
    assert_eq!(work.queries[0].sql, r#"["INFO"]"#);
    maxnines_protocol::templates::work::check_work(&[work]).unwrap();

    // A primary with no limit and one replica, then the same with a limit it's
    // evicting keys to stay under.
    let rows = redis_rows(
        found.clone(),
        &[redis_info!("primary"), redis_info!("maxmemory")],
    );
    let server = redis_row(&rows, "server", json!({ "instance": "cache" }));
    assert_eq!(server["memory_limit"], 4_194_304.0);
    let used = server["memory_used"].as_f64().unwrap();
    assert!((100.0..101.0).contains(&used), "{server}");
    // Running totals are what changed in the minute between.
    assert_eq!(server["evicted"], 832.0);
    assert_eq!(server["last_save_ok"], 1.0);
    assert_eq!(server["refused"], 0.0);
    assert!(
        server["connections_used"].as_f64().unwrap() > 0.0,
        "{server}"
    );
    let primary = redis_row(&rows, "primary", json!({}));
    assert_eq!(
        (&primary["replica"], &primary["replicas"]),
        (&json!(0.0), &json!(1.0))
    );
    assert_eq!(primary["replicas_online"], 1.0);
    let replica = redis_row(
        &rows,
        "replicas",
        json!({ "replica": "127.0.0.1", "port": "56380" }),
    );
    assert_eq!(replica["lag_bytes"], 10_057_467.0 - 60.0);
    assert_eq!(replica["last_acknowledged"], 0.0);

    // No limit gives nothing used of it, rather than dividing by 0. Keys in two
    // databases.
    let rows = redis_rows(found.clone(), &[redis_info!("standalone")]);
    let server = redis_row(&rows, "server", json!({}));
    assert_eq!(server["memory_limit"], 0.0);
    assert!(server.get("memory_used").is_none(), "{server}");
    let db0 = redis_row(&rows, "keyspace", json!({ "db": "db0" }));
    assert_eq!((&db0["keys"], &db0["expires"]), (&json!(12.0), &json!(2.0)));
    let db3 = redis_row(&rows, "keyspace", json!({ "db": "db3" }));
    assert_eq!((&db3["keys"], &db3["expires"]), (&json!(2.0), &json!(1.0)));
    assert!(
        !rows.iter().any(|row| row["_query"] == "replicas"),
        "{rows:#?}"
    );

    // A background save that failed.
    let rows = redis_rows(found, &[redis_info!("bgsave-failed")]);
    assert_eq!(redis_row(&rows, "server", json!({}))["last_save_ok"], 0.0);

    // A replica, its link up, then down once its primary had gone.
    let replica = json!({ "version": "8.12.0", "role": "slave", "policy": "noeviction" });
    let rows = redis_rows(replica.clone(), &[redis_info!("replica")]);
    let up = redis_row(&rows, "replica", json!({}));
    assert_eq!(
        (&up["replica"], &up["receiving"]),
        (&json!(1.0), &json!(1.0))
    );
    assert_eq!(
        (&up["last_received"], &up["syncing"]),
        (&json!(0.0), &json!(0.0))
    );
    assert!(
        !rows.iter().any(|row| row["_query"] == "primary"),
        "{rows:#?}"
    );
    let rows = redis_rows(replica, &[redis_info!("replica-link-down")]);
    let down = redis_row(&rows, "replica", json!({}));
    assert_eq!(down["receiving"], 0.0);
    // Redis says -1 when it hasn't heard at all, which is nothing to chart.
    assert!(down.get("last_received").is_none(), "{down}");
}
