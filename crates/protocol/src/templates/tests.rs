use super::*;

const POSTGRES: &str = include_str!("../../../server/templates/postgres.hcl");
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
fn the_postgres_template_is_read_as_written() {
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
    assert_eq!(throughput.fills[0].older.as_deref(), Some("0"));
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
        filled[0].contains("NULL            AS slot_headroom"),
        "{}",
        filled[0]
    );
    assert!(
        filled[0].contains("false                AS slot_lost"),
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
        r#"template "app": has more than 64 discover blocks, queries and counters together"#,
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

#[test]
fn the_registry_and_counters_are_only_read_on_windows_hosts() {
    let reading = |target: &str, key: &str| {
        problems(&format!(
            r#"template "app" {{
                 name = "App"
                 {target}
                 discover "d" {{
                   registry "{key}" {{ version = "Version" }}
                   counter_sets = {{ asp = "ASP.NET" }}
                 }}
                 counters "c" {{
                   object  = "Web Service"
                   metrics = {{ m = "Current Connections" }}
                 }}
               }}"#
        ))
    };
    for target in [r#"service = "W3SVC""#, r#"os = ["windows", "linux"]"#, ""] {
        let found = reading(target, r"HKLM\\SOFTWARE\\App");
        assert!(found.is_empty(), "{target}: {found:#?}");
    }
    let found = reading(r#"database = "postgres""#, r"HKLM\\SOFTWARE\\App");
    for expected in [
        r#"template "app", discover "d", registry: The registry is the host's, not a database's"#,
        r#"template "app", discover "d", counter_sets: A counter set is the host's"#,
        r#"template "app", counters "c", object: A performance counter is the host's"#,
    ] {
        assert!(
            found.iter().any(|problem| problem.starts_with(expected)),
            "{expected}\n{found:#?}"
        );
    }
    let found = reading(r#"os = ["linux"]"#, r"HKCU\\SOFTWARE\\App");
    for expected in [
        r#"template "app", discover "d", registry: The registry is only on Windows"#,
        r#"template "app", counters "c", object: A performance counter is only on Windows"#,
        r#"template "app", discover "d", registry: "HKCU\\SOFTWARE\\App" isn't under HKLM"#,
    ] {
        assert!(
            found.iter().any(|problem| problem.starts_with(expected)),
            "{expected}\n{found:#?}"
        );
    }
}

#[test]
fn only_the_hosts_own_registry_keys_are_read() {
    assert_eq!(
        local_machine_key(r"HKLM\SOFTWARE\Microsoft\InetStp"),
        Some(r"SOFTWARE\Microsoft\InetStp")
    );
    assert_eq!(
        local_machine_key(r"hkey_local_machine\SOFTWARE\"),
        Some("SOFTWARE")
    );
    assert_eq!(local_machine_key(r"HKCU\SOFTWARE"), None);
    assert_eq!(local_machine_key("HKLM"), None);
    assert_eq!(local_machine_key(r"HKLM\"), None);
}

#[test]
fn an_error_is_sent_no_longer_than_an_agent_sends_one() {
    use super::work::{MAX_ERROR_LEN, error_text};
    assert_eq!(error_text("refused"), "refused");
    let long = "é".repeat(MAX_ERROR_LEN * 2);
    let sent = error_text(&long);
    assert_eq!(sent.chars().count(), MAX_ERROR_LEN);
    assert!(sent.ends_with('…'));
}

#[test]
fn a_statement_is_a_select_or_a_show() {
    assert!(!is_show("SELECT 1"));
    assert!(is_show("  show   replica status ;"));
    assert!(is_show("-- what's behind\n/* note */ SHOW BINARY LOGS"));
    assert!(is_show("# MySQL's own comments\n# twice\nSHOW BINARY LOGS"));
    assert_eq!(first_keyword("(SELECT 1) UNION (SELECT 2)"), "SELECT");
    for fine in [
        "SELECT 1",
        "WITH a AS (SELECT 1) SELECT * FROM a",
        "SHOW GRANTS",
        "# lag\nSELECT 1 AS lag",
        r#"{ "serverStatus": 1 }"#,
    ] {
        assert!(work::check_statement("q", fine).is_ok(), "{fine}");
    }
    for refused in [
        "DELETE FROM orders",
        "SET ROLE admin",
        "CALL rebuild()",
        r#"{ "ping": 1, "$readPreference": {} }"#,
        "{ not json }",
    ] {
        assert!(work::check_statement("q", refused).is_err(), "{refused}");
    }
}

const MONGO: &str = r#"
template "docs" {
  name     = "Documents"
  database = "mongodb"

  discover "server" {
    command = <<-JSON
      { "buildInfo": 1 }
    JSON
    columns = { version = "version" }
  }

  query "members" {
    command = <<-JSON
      { "replSetGetStatus": 1 }
    JSON
    rows   = "members"
    labels = ["member"]
    columns = {
      member  = "name"
      _health = "health"
      _leader = "$.members[state=1].optimeDate"
    }
    metrics = {
      _health        = { total = true }
      member_healthy = { value = "_health == 1" }
    }
  }
}
"#;

#[test]
fn mongodb_is_asked_with_commands_whose_replies_columns_name() {
    let template = parse(MONGO).unwrap();
    assert!(template.check().is_empty(), "{:?}", template.check());
    assert_eq!(template.asked(), Asked::Mongodb);
    assert_eq!(
        template.discover[0].sql.as_deref(),
        Some("{ \"buildInfo\": 1 }\n")
    );
    assert_eq!(template.discover[0].columns["version"], "version");
    let query = &template.queries[0];
    assert_eq!(query.rows.as_deref(), Some("members"));
    assert_eq!(query.columns["_leader"], "$.members[state=1].optimeDate");
    // Written out as it was read, with command in place of sql.
    let written = to_hcl(&template);
    assert!(written.contains("command = <<-EOT"), "{written}");
    assert!(!written.contains("sql"), "{written}");
    assert_eq!(parse(&written).unwrap(), template);

    // Each kind of database is asked its own way.
    let sql_for_mongo = MONGO.replace(
        "command = <<-JSON\n      { \"buildInfo\": 1 }",
        "sql = <<-JSON\n      SELECT 1",
    );
    let error = format!("{:#}", parse(&sql_for_mongo).unwrap_err());
    assert!(error.contains("MongoDB isn't asked with SQL"), "{error}");
    let command_for_postgres = MONGO.replace("\"mongodb\"", "\"postgres\"");
    let error = format!("{:#}", parse(&command_for_postgres).unwrap_err());
    assert!(error.contains("a command is only for MongoDB"), "{error}");
}

#[test]
fn a_mongodb_command_is_one_command_and_where_it_runs() {
    assert_eq!(
        check_command(r#"{ "serverStatus": 1 }"#),
        Ok(("serverStatus".to_string(), "admin".to_string()))
    );
    assert_eq!(
        check_command(r#"{ "$db": "local", "find": "oplog.rs", "limit": 1 }"#),
        Ok(("find".to_string(), "local".to_string()))
    );
    for (command, why) in [
        ("serverStatus", "isn't one command written as JSON"),
        (
            r#"{ "ping": 1 } { "ping": 1 }"#,
            "isn't one command written as JSON",
        ),
        ("{}", "needs a command"),
        (r#"{ "ping": 1, "$readPreference": {} }"#, "only $db"),
        (r#"{ "ping": 1, "$db": 3 }"#, "$db is the name"),
    ] {
        let error = check_command(command).unwrap_err();
        assert!(error.contains(why), "{command}: {error}");
    }
    assert!(is_command("  {\"ping\": 1}"));
    assert!(!is_command("SELECT 1"));
}

#[test]
fn a_path_says_where_a_field_is_in_a_reply() {
    assert_eq!(
        parse_path("connections.current"),
        Ok(Path {
            from_reply: false,
            steps: vec![
                Step {
                    field: "connections".to_string(),
                    only: None
                },
                Step {
                    field: "current".to_string(),
                    only: None
                },
            ],
        })
    );
    // A value can hold dots, as host names do.
    let path = parse_path("$.members[name=db1.example.com:27017].optimeDate").unwrap();
    assert!(path.from_reply);
    assert_eq!(
        path.steps[0].only,
        Some(("name".to_string(), "db1.example.com:27017".to_string()))
    );
    assert_eq!(path.steps[1].field, "optimeDate");
    // Fields can have spaces, as WiredTiger's do.
    assert_eq!(
        parse_path("wiredTiger.cache.bytes currently in the cache")
            .unwrap()
            .steps[2]
            .field,
        "bytes currently in the cache"
    );
    for (path, why) in [
        ("", "needs the field"),
        ("$.", "needs the field"),
        ("a..b", "a field with no name"),
        ("members[state=1", "[ with no ]"),
        ("members[state]", "[field=value]"),
        ("members[=1]", "a field to keep documents by"),
        ("members[state=1]x", "something after a ]"),
        ("a]", "] with no ["),
    ] {
        let error = parse_path(path).unwrap_err();
        assert!(error.contains(why), "{path:?}: {error}");
    }
}

#[test]
fn a_column_only_for_working_others_out_starts_with_an_underscore() {
    assert!(is_helper("_leader"));
    assert!(!is_helper("leader"));
    assert!(!is_helper("_Leader"));
    assert!(!is_helper("_"));
    // That's what says which query a row is from.
    assert!(!is_helper(work::QUERY_FIELD));
    let wrong = MONGO.replace("_leader = \"$.members", "_Leader = \"$.members");
    assert!(
        problems(&wrong)
            .iter()
            .any(|problem| problem.contains("\"_Leader\"")),
        "{:?}",
        problems(&wrong)
    );
    // Columns and rows are only MongoDB's, and its paths have to be paths.
    let not_mongo = r#"
        template "pg" {
          name     = "PG"
          database = "postgres"
          discover "server" {
            sql     = "SELECT 1 AS one"
            columns = { one = "one" }
          }
          query "q" {
            sql  = "SELECT 1 AS one"
            rows = "members"
          }
        }
    "#;
    let found = problems(not_mongo);
    assert!(
        found
            .iter()
            .any(|p| p.contains("columns: are only for MongoDB")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|p| p.contains("rows: are only for MongoDB")),
        "{found:?}"
    );
    let bad_path = MONGO.replace("rows   = \"members\"", "rows   = \"members[\"");
    assert!(
        problems(&bad_path)
            .iter()
            .any(|problem| problem.contains("[ with no ]")),
        "{:?}",
        problems(&bad_path)
    );
}

const REDIS_TEMPLATE: &str = r#"
template "cache" {
  name     = "Cache"
  database = "redis"

  discover "server" {
    command = "INFO server"
    columns = { version = "server.redis_version" }
  }

  query "keyspace" {
    command = "INFO keyspace"
    rows    = "keyspace"
    labels  = ["db"]
    columns = {
      db   = "k"
      keys = "v.keys"
    }
  }
}
"#;

#[test]
fn redis_is_asked_with_its_commands_written_as_words() {
    let template = parse(REDIS_TEMPLATE).unwrap();
    assert!(template.check().is_empty(), "{:?}", template.check());
    assert_eq!(template.asked(), Asked::Redis);
    assert!(template.asked().with_commands());
    assert_eq!(template.queries[0].sql, "INFO keyspace");
    // Written out as it was read, with command in place of sql.
    let written = to_hcl(&template);
    assert!(written.contains("command = \"INFO keyspace\""), "{written}");
    assert_eq!(parse(&written).unwrap(), template);
    let sql_for_redis = REDIS_TEMPLATE.replace("command = \"INFO keyspace\"", "sql = \"SELECT 1\"");
    let error = format!("{:#}", parse(&sql_for_redis).unwrap_err());
    assert!(error.contains("Redis isn't asked with SQL"), "{error}");
}

#[test]
fn a_redis_command_is_its_words_sent_as_a_list() {
    assert_eq!(
        redis_command("  CONFIG GET  maxmemory\n"),
        Ok(vec![
            "CONFIG".to_string(),
            "GET".to_string(),
            "maxmemory".to_string()
        ])
    );
    for (command, why) in [
        ("", "needs a command"),
        ("{ \"ping\": 1 }", "isn't a command's name"),
    ] {
        let error = redis_command(command).unwrap_err();
        assert!(error.contains(why), "{command}: {error}");
    }
    let sent = redis_command_sent(&redis_command("INFO server").unwrap());
    assert_eq!(sent, r#"["INFO","server"]"#);
    assert!(is_command(&sent));
    assert_eq!(
        read_redis_command(&sent),
        Ok(vec!["INFO".to_string(), "server".to_string()])
    );
    // Where it runs takes it as one, and nothing else as one.
    assert!(work::check_statement("q", &sent).is_ok());
    for refused in [
        r#"[]"#,
        r#"["INFO server"]"#,
        r#"["INFO", 1]"#,
        "INFO server",
    ] {
        assert!(work::check_statement("q", refused).is_err(), "{refused}");
    }
}

/// SQL of any shape comes back as it went: without a last newline, indented all
/// through, with blank or space-only lines, tabs, or carriage returns.
#[test]
fn any_multi_line_text_goes_to_hcl_and_back_unchanged() {
    let base = parse(POSTGRES).unwrap();
    for sql in [
        "SELECT 1\nFROM t",
        "SELECT 1\nFROM t\n",
        "  SELECT 1\n  FROM t\n",
        "\tSELECT 1\n\tFROM t\n",
        "SELECT 1\n\nFROM t\n",
        "SELECT 1\n   \nFROM t\n",
        "SELECT 1\r\nFROM t\r\n",
        "SELECT 1\nFROM t\n\n",
        "\nSELECT 1\n",
        "SELECT 1 -- EOT\nEOT\n",
        // Other whitespace than spaces before every line, which isn't indenting.
        "\u{a0}SELECT 1\n\u{a0}FROM t\n",
        "\u{3000}SELECT 1\n\u{3000}FROM t\n",
        "\u{a0}SELECT 1\n  FROM t\n",
        "SELECT 1\n \u{a0}FROM t\n",
    ] {
        let mut template = base.clone();
        template.queries[0].sql = sql.to_string();
        let written = to_hcl(&template);
        let again = parse(&written).unwrap_or_else(|error| panic!("{error:#}\n{written}"));
        assert_eq!(again.queries[0].sql, sql, "{written}");
    }
}
