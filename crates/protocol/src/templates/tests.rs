use super::*;

const POSTGRES: &str = include_str!("../../../../docs/examples/postgres.hcl");
const IIS: &str = include_str!("../../../../docs/examples/iis.hcl");

fn problems(text: &str) -> Vec<String> {
    let template = parse(text).unwrap();
    template
        .check()
        .iter()
        .map(|problem| problem.describe(&template))
        .collect()
}

#[test]
fn the_examples_are_read_and_have_nothing_wrong_with_them() {
    for text in [POSTGRES, IIS] {
        let template = parse(text).unwrap();
        let found: Vec<String> = template
            .check()
            .iter()
            .map(|problem| problem.describe(&template))
            .collect();
        assert!(found.is_empty(), "{}: {found:#?}", template.key);
    }
}

#[test]
fn the_postgres_example_is_read_as_written() {
    let template = parse(POSTGRES).unwrap();
    assert_eq!(template.key, "postgres");
    assert_eq!(template.name, "PostgreSQL");
    assert_eq!(
        template.target,
        Some(Target::Database("postgres".to_string()))
    );
    assert_eq!(template.min_version.as_deref(), Some("10"));
    let [server, role] = template.discover.as_slice() else {
        panic!("{:?}", template.discover);
    };
    assert_eq!(role.key, "role");
    assert_eq!(role.interval.as_deref(), Some("10s"));
    let discover = server;
    assert_eq!(discover.interval.as_deref(), Some("1h"));
    assert!(
        discover
            .sql
            .as_ref()
            .unwrap()
            .starts_with("SELECT current_setting")
    );
    assert_eq!(template.notices[0].key, "cannot_see_sessions");

    let throughput = template
        .queries
        .iter()
        .find(|q| q.key == "throughput")
        .unwrap();
    assert_eq!(throughput.fills[0].key, "checksums");
    assert_eq!(
        throughput.fills[0].versions.get("12").map(String::as_str),
        Some("coalesce(sum(checksum_failures), 0)")
    );
    assert_eq!(throughput.fills[0].older.as_deref(), Some("NULL"));
    let cache_hit = throughput
        .metrics
        .iter()
        .find(|m| m.key == "cache_hit")
        .unwrap();
    assert_eq!(cache_hit.unit.as_deref(), Some("%"));
    assert!(
        cache_hit
            .value
            .as_ref()
            .unwrap()
            .starts_with("rate(blocks_hit)")
    );

    let sizes = template.queries.iter().find(|q| q.key == "sizes").unwrap();
    assert!(!sizes.enabled);
    assert_eq!(sizes.labels, ["database"]);

    let down = &template.alerts[0];
    assert_eq!(down.key, "down");
    assert_eq!(down.critical.as_deref(), Some("!up"));
    assert_eq!(down.hold.as_deref(), Some("1m"));
    let too_few = template
        .alerts
        .iter()
        .find(|a| a.key == "too_few_standbys")
        .unwrap();
    assert!(!too_few.enabled);
    assert_eq!(too_few.when.as_deref(), Some("role == 'primary'"));
}

#[test]
fn the_iis_example_is_read_as_written() {
    let template = parse(IIS).unwrap();
    assert_eq!(template.target, Some(Target::Service("W3SVC".to_string())));
    assert_eq!(template.services, ["W3SVC", "WAS"]);
    let discover = &template.discover[0];
    assert_eq!(discover.registry[0].key, r"HKLM\SOFTWARE\Microsoft\InetStp");
    assert_eq!(
        discover.registry[0]
            .values
            .get("version")
            .map(String::as_str),
        Some("VersionString")
    );
    assert_eq!(discover.counter_sets.len(), 3);

    let pools = template
        .counters
        .iter()
        .find(|c| c.key == "app_pools")
        .unwrap();
    assert_eq!(pools.label.as_deref(), Some("pool"));
    let state = &pools.metrics[0];
    assert_eq!(
        state.counter.as_deref(),
        Some("Current Application Pool State")
    );
    assert_eq!(state.states.get("3").map(String::as_str), Some("Running"));
    let running = &pools.metrics[1];
    assert_eq!(running.value.as_deref(), Some("value == 3"));

    let older = template
        .counters
        .iter()
        .find(|c| c.key == "pool_processes_older")
        .unwrap();
    assert_eq!(
        older.groups.get("pid").map(String::as_str),
        Some("ID Process")
    );
    assert_eq!(older.join.as_ref().unwrap().object, "W3SVC_W3WP");
    assert_eq!(older.labels(), ["pool"]);
    let workers = template
        .counters
        .iter()
        .find(|c| c.key == "workers")
        .unwrap();
    assert_eq!(workers.pattern.as_deref(), Some(r"^\d+_(?<pool>.+)$"));
    assert_eq!(workers.labels(), ["pool"]);
    assert!(workers.metrics[0].is_only_counter());
}

#[test]
fn a_template_goes_to_hcl_and_back_unchanged() {
    for text in [POSTGRES, IIS] {
        let template = parse(text).unwrap();
        let written = to_hcl(&template);
        let again = parse(&written).unwrap_or_else(|error| panic!("{error:#}\n{written}"));
        assert_eq!(again, template, "{written}");
        assert_eq!(to_hcl(&again), written);
    }
}

#[test]
fn sql_written_out_is_indented_with_its_block() {
    let template = parse(POSTGRES).unwrap();
    let written = to_hcl(&template);
    assert!(
        written.contains("    sql = <<-EOT\n      SELECT current_setting"),
        "{written}"
    );
}

#[test]
fn mistakes_in_the_format_say_where_they_are() {
    for (text, expected) in [
        ("", "there's no template block"),
        (r#"name = "x""#, "name has to be inside the template block"),
        (
            "template \"a\" { name = \"A\" }\ntemplate \"b\" { name = \"B\" }",
            "one template block",
        ),
        (r#"template { name = "A" }"#, "needs a name"),
        (
            r#"template "a" { nme = "A" }"#,
            "template \"a\": unknown field `nme`",
        ),
        (
            r#"template "a" {
                 name = "A"
                 query "q" {
                   sql  = "SELECT 1"
                   sqll = "x"
                 }
               }"#,
            "template \"a\": query \"q\": unknown field `sqll`",
        ),
        (
            r#"template "a" {
                 name = "A"
                 counters "c" {
                   object = "X"
                   metrics = { m = { counter = "Y", unti = "s" } }
                 }
               }"#,
            "counters \"c\": metrics, m: unknown field `unti`",
        ),
        (
            r#"template "a" {
                 name = "A"
                 alert "x" {
                   name = "X"
                   fro  = "1m"
                 }
               }"#,
            "alert \"x\": unknown field `fro`",
        ),
        (
            "template \"a\" {\n name = \"A\"\n database = \"postgres\"\n service = \"x\"\n}",
            "not more than one",
        ),
        (
            "template \"a\" {\n name = \"A\"\n widget \"w\" {}\n}",
            "has no widget blocks",
        ),
    ] {
        let error = format!("{:#}", parse(text).unwrap_err());
        assert!(error.contains(expected), "{text}: {error}");
    }
}

#[test]
fn checks_name_the_template_block_and_field() {
    let found = problems(
        r#"template "app" {
             name = "App"
             os   = ["linux", "plan9", "linux"]
             min_version = "ten"
             discover "d" { interval = "soon" }
             discover "d" { sql = "SELECT 1" }
             query "q" {
               interval = "0s"
               sql      = "SELECT {{ missing }}, {{ v }}"
               fill "v" { versions = { "1x" = "a" } }
               fill "unused" {
                 versions = { "2" = "b" }
                 older = "c"
               }
               metrics = { n = { unit = "furlongs", counter = "X", states = { one = "One" } } }
             }
             query "q" { sql = "SELECT 1" }
             counters "c" {
               object  = "Process"
               pattern = "^w3wp:(?<pid>\\d+$"
               metrics = {}
             }
             counters "j" {
               object  = "Process"
               pattern = "^w3wp:(?<pid>\\d+)$"
               join {
                 object  = "W3SVC_W3WP"
                 pattern = "^(?<id>\\d+)_(?<pool>.+)$"
               }
               metrics = { m = "M" }
             }
             alert "Bad Key" {
               name = ""
               for  = "1.5s"
             }
           }"#,
    );
    for expected in [
        r#"template "app", os: "plan9" isn't an operating system"#,
        r#"template "app", os: "linux" is listed twice"#,
        r#"template "app", min_version: "ten" isn't a version"#,
        r#"template "app", discover "d", interval: "soon" isn't a length of time"#,
        r#"template "app", discover "d": needs sql, a registry block or counter_sets"#,
        r#"template "app", discover "d", key: "d" is used twice"#,
        r#"template "app", query "q", key: "q" is used twice"#,
        r#"template "app", query "q", interval: has to be longer than nothing"#,
        r#"template "app", query "q", sql: {{ missing }} has no fill block"#,
        r#"template "app", query "q", fill "v", older: needs the SQL for older versions"#,
        r#"template "app", query "q", fill "v", versions: "1x" isn't a version"#,
        r#"template "app", query "q", fill "unused": the query's SQL has no {{ unused }} for it"#,
        r#"template "app", query "q", metric "n", counter: is only for counters"#,
        r#"template "app", query "q", metric "n", unit: "furlongs" isn't a unit"#,
        r#"template "app", query "q", metric "n", states: "one" isn't a whole number"#,
        r#"template "app", counters "c", pattern: isn't a regular expression"#,
        r#"template "app", counters "c", metrics: needs at least one metric"#,
        r#"template "app", counters "j", join, pattern: has no group named in both patterns to join by: this one has id, pool, the counters have pid"#,
        r#"template "app", alert "Bad Key", key: "Bad Key" has to be lowercase"#,
        r#"template "app", alert "Bad Key", name: can't be empty"#,
        r#"template "app", alert "Bad Key": needs a warning or critical condition"#,
        r#"template "app", alert "Bad Key", for: "1.5s" has to be whole seconds"#,
    ] {
        assert!(
            found.iter().any(|problem| problem.starts_with(expected)),
            "{expected}\n{found:#?}"
        );
    }
}

#[test]
fn a_problem_names_the_form_field_it_belongs_to() {
    let problem = Problem::new(Place::QueryMetric(1, 2), "unit", "x");
    assert_eq!(problem.form_field(), "query.1.metric.2.unit");
    assert_eq!(
        Problem::new(Place::Template, "name", "x").form_field(),
        "name"
    );
    assert_eq!(
        Problem::new(Place::Join(0), "pattern", "x").form_field(),
        "counters.0.join.pattern"
    );
}

#[test]
fn versions_compare_as_numbers() {
    let version = |text: &str| Version::parse(text).unwrap();
    assert!(version("9.6") < version("13"));
    assert!(version("13") < version("16.2"));
    assert_eq!(version("13.0"), version("13"));
    assert_eq!(version("8.0").to_string(), "8");
    for wrong in ["", "x", "1.", "1..2", "-1", "1.2a"] {
        assert_eq!(Version::parse(wrong), None, "{wrong}");
    }
}

#[test]
fn every_version_of_a_query_is_filled_in() {
    let template = parse(POSTGRES).unwrap();
    let slots = template.queries.iter().find(|q| q.key == "slots").unwrap();
    let filled = filled_sql(slots);
    // Older than 13, from 13 and from 17.
    assert_eq!(filled.len(), 3, "{filled:#?}");
    assert!(filled.iter().all(|sql| !sql.contains("{{")));
    assert!(
        filled[0].contains("NULL         AS wal_status"),
        "{}",
        filled[0]
    );
    assert!(filled[2].contains("invalidation_reason IS NOT NULL"));
}

#[test]
fn lengths_of_time_are_whole_seconds() {
    assert_eq!(parse_duration("1m"), Ok(60));
    assert_eq!(parse_duration("1h 30m"), Ok(5400));
    assert!(parse_duration("1.5s").is_err());
    assert!(parse_duration("soon").is_err());
    assert_eq!(format_duration(5400), "1h 30m");
}

#[test]
fn a_template_can_only_ask_what_an_agent_takes() {
    let long = "x".repeat(work::MAX_SQL_LEN);
    let mut queries = String::new();
    for number in 0..=work::MAX_STATEMENTS {
        queries.push_str(&format!(
            "query \"q{number}\" {{ sql = \"SELECT 1 AS one\" }}\n"
        ));
    }
    let found = problems(&format!(
        r#"template "app" {{
             name     = "App"
             database = "postgres"
             discover "d" {{
               interval = "7d"
               sql      = "SELECT '{long}' AS version"
             }}
             {queries}
           }}"#
    ));
    for expected in [
        r#"template "app", discover "d", interval: can be up to a day"#,
        r#"template "app", discover "d", sql: can be up to 64 KB"#,
        r#"template "app": has more than 64 discover blocks and queries together"#,
    ] {
        assert!(
            found.iter().any(|problem| problem.starts_with(expected)),
            "{expected}\n{found:#?}"
        );
    }
    // A day is fine.
    let found = problems(
        r#"template "app" {
             name     = "App"
             database = "postgres"
             query "q" {
               interval = "24h"
               sql      = "SELECT 1 AS one"
             }
           }"#,
    );
    assert!(found.is_empty(), "{found:#?}");
}
