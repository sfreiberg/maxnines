//! Dashboards, and asking about many machines at once.

use super::*;

const MINUTE_MS: i64 = 60_000;

/// Calls the API with the admin token, giving back the status and any JSON.
async fn api(server: &TestServer, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = server.request(method, path, &body.to_string()).await;
    let (head, text) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(text).unwrap_or(Value::Null))
}

/// When every machine's reading was taken: the middle of a minute that's over, as the
/// one still filling up isn't counted. It's the same for every machine, as one taking
/// its own time could land in the next minute and be counted apart.
static READING_TIME: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    let minute = MINUTE_MS as u64;
    (now_ms() as u64 / minute - 2) * minute + minute / 2
});

/// An approved machine reporting a CPU reading, with these facts.
async fn machine(server: &TestServer, host: &str, usage: f64, facts: Value) -> (Identity, Client) {
    let agent = identity();
    let mut client = server.connect_approved(&agent, host).await;
    send(&mut client, &AgentMessage::Facts { facts }).await;
    let sample = AgentMessage::Sample(Sample {
        timestamp_ms: *READING_TIME,
        metrics: BTreeMap::from([("cpu".to_string(), json!({ "usage_percent": usage }))]),
    });
    send(&mut client, &sample).await;
    server.wait_for_facts(&agent.id(), 1).await;
    (agent, client)
}

/// Asks until the samples have been written, which happens in the background.
async fn query(server: &TestServer, path: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (status, result) = api(server, "GET", path, &Value::Null).await;
        assert_eq!(status, 200, "{result}");
        if result["series"].as_array().is_some_and(|s| !s.is_empty()) {
            return result;
        }
        assert!(Instant::now() < deadline, "nothing came back: {result}");
        sleep(Duration::from_millis(20)).await;
    }
}

fn newest(series: &Value) -> f64 {
    let points = series["points"].as_array().unwrap();
    points.last().unwrap()["avg"].as_f64().unwrap()
}

async fn three_machines(server: &TestServer) -> Vec<(Identity, Client)> {
    vec![
        machine(server, "web-1", 10.0, json!({ "role": "web" })).await,
        machine(server, "web-2", 30.0, json!({ "role": "web" })).await,
        machine(server, "db-1", 80.0, json!({ "role": "db" })).await,
    ]
}

async fn wait_for_all_three(server: &TestServer) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let path = "/api/v1/query?metric=cpu.usage&calculation=count";
        let result = query(server, path).await;
        if newest(&result["series"][0]) == 3.0 {
            return;
        }
        assert!(Instant::now() < deadline, "{result}");
        sleep(Duration::from_millis(20)).await;
    }
}

mod query_api {
    use super::*;

    #[tokio::test]
    async fn machines_can_be_combined() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;

        let result = query(&server, "/api/v1/query?metric=cpu.usage&calculation=avg").await;

        assert_eq!(result["unit"], "percent");
        assert_eq!(newest(&result["series"][0]), 40.0);
    }

    #[tokio::test]
    async fn machines_can_be_grouped_by_a_fact() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;

        let path = "/api/v1/query?metric=cpu.usage&calculation=sum&group_by=fact:role";
        let result = query(&server, path).await;

        assert_eq!(result["series"][0]["name"], "db");
        assert_eq!(newest(&result["series"][0]), 80.0);
        assert_eq!(result["series"][1]["name"], "web");
        assert_eq!(newest(&result["series"][1]), 40.0);
    }

    #[tokio::test]
    async fn a_filter_picks_the_machines() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;

        let path = "/api/v1/query?metric=cpu.usage&calculation=sum&filter=role%3Dweb";
        let result = query(&server, path).await;

        assert_eq!(newest(&result["series"][0]), 40.0);
    }

    #[tokio::test]
    async fn a_line_can_be_given_to_each_machine() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;

        let path = "/api/v1/query?metric=cpu.usage&group_by=host";
        let result = query(&server, path).await;

        let names: Vec<&str> = result["series"]
            .as_array()
            .unwrap()
            .iter()
            .map(|series| series["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["db-1", "web-1", "web-2"]);
    }

    /// Two machines can share a name, and still each get a line of their own.
    #[tokio::test]
    async fn machines_sharing_a_name_each_keep_their_own_line() {
        let server = start_with_metrics().await;
        let (first, _one) = machine(&server, "cache", 10.0, json!({ "role": "cache" })).await;
        let (second, _two) = machine(&server, "cache", 30.0, json!({ "role": "cache" })).await;
        let (_lone, _three) = machine(&server, "web-1", 50.0, json!({ "role": "web" })).await;

        let path = "/api/v1/query?metric=cpu.usage&group_by=host";
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            let result = query(&server, path).await;
            if result["series"].as_array().unwrap().len() == 3 {
                break result;
            }
            assert!(
                Instant::now() < deadline,
                "not every machine arrived: {result}"
            );
            sleep(Duration::from_millis(20)).await;
        };

        let mut names: Vec<&str> = result["series"]
            .as_array()
            .unwrap()
            .iter()
            .map(|series| series["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        let mut expected = vec![
            format!("cache ({})", &first.id()[..8]),
            format!("cache ({})", &second.id()[..8]),
            "web-1".to_string(),
        ];
        expected.sort_unstable();
        assert_eq!(names, expected);
    }

    #[tokio::test]
    async fn the_server_is_not_part_of_the_fleet() {
        let server = start_with_metrics().await;
        let facts = json!({ "role": "web" });
        let (_agent, _client) = machine(&server, "web-1", 10.0, facts).await;
        let mut recorded = crate::server_stats::Recorded::with_machine();
        crate::server_stats::record_once(&server.state, &mut recorded).await;
        sleep(Duration::from_millis(300)).await;
        crate::server_stats::record_once(&server.state, &mut recorded).await;

        let result = query(&server, "/api/v1/query?metric=cpu.usage&calculation=count").await;

        assert_eq!(newest(&result["series"][0]), 1.0);
    }

    #[tokio::test]
    async fn a_question_that_makes_no_sense_is_refused() {
        let server = start_with_metrics().await;
        for path in [
            "/api/v1/query?metric=nope",
            "/api/v1/query?metric=cpu.usage&calculation=median",
            "/api/v1/query?metric=cpu.usage&group_by=colour",
            "/api/v1/query?metric=cpu.usage&filter=%22unfinished",
        ] {
            let (status, body) = api(&server, "GET", path, &Value::Null).await;
            assert_eq!(status, 422, "{path}: {body}");
            assert!(body["error"].is_string(), "{path}: {body}");
        }
    }

    #[tokio::test]
    async fn nobody_gets_in_without_a_key() {
        let server = start_with_metrics().await;
        let response = server
            .http("GET", "/api/v1/query?metric=cpu.usage", None)
            .await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }
}

mod dashboards_api {
    use super::*;

    const WIDGET: &str = r#"{ "metric": "cpu.usage", "calculation": "avg", "group_by": "host" }"#;

    async fn dashboard(server: &TestServer, name: &str) -> i64 {
        let body = json!({ "name": name });
        let (status, created) = api(server, "POST", "/api/v1/dashboards", &body).await;
        assert_eq!(status, 201, "{created}");
        created["id"].as_i64().unwrap()
    }

    async fn widget(server: &TestServer, dashboard: i64) -> i64 {
        let path = format!("/api/v1/dashboards/{dashboard}/widgets");
        let body: Value = serde_json::from_str(WIDGET).unwrap();
        let (status, created) = api(server, "POST", &path, &body).await;
        assert_eq!(status, 201, "{created}");
        created["id"].as_i64().unwrap()
    }

    #[tokio::test]
    async fn a_dashboard_keeps_its_widgets() {
        let server = start().await;
        let id = dashboard(&server, "Fleet").await;
        let widget_id = widget(&server, id).await;

        let path = format!("/api/v1/dashboards/{id}");
        let (status, shown) = api(&server, "GET", &path, &Value::Null).await;

        assert_eq!(status, 200);
        assert_eq!(shown["name"], "Fleet");
        assert_eq!(shown["widgets"][0]["id"], widget_id);
        assert_eq!(shown["widgets"][0]["metric"], "cpu.usage");
        assert_eq!(shown["widgets"][0]["kind"], "chart");
        assert_eq!(shown["widgets"][0]["w"], 6);

        let (_, list) = api(&server, "GET", "/api/v1/dashboards", &Value::Null).await;
        assert_eq!(list[0]["name"], "Fleet");
        assert_eq!(list[0]["widgets"], 1);
    }

    #[tokio::test]
    async fn widgets_can_be_changed_moved_and_removed() {
        let server = start().await;
        let id = dashboard(&server, "Fleet").await;
        let widget_id = widget(&server, id).await;
        let path = format!("/api/v1/dashboards/{id}/widgets/{widget_id}");

        let change = json!({ "metric": "memory.usage", "title": "Memory", "kind": "table" });
        assert_eq!(api(&server, "PUT", &path, &change).await.0, 204);

        let layout = format!("/api/v1/dashboards/{id}/layout");
        let moved = json!([{ "id": widget_id, "x": 6, "y": 2, "w": 3, "h": 5 }]);
        assert_eq!(api(&server, "PUT", &layout, &moved).await.0, 204);

        let shown = format!("/api/v1/dashboards/{id}");
        let (_, shown_now) = api(&server, "GET", &shown, &Value::Null).await;
        let saved = &shown_now["widgets"][0];
        assert_eq!(saved["title"], "Memory");
        assert_eq!((&saved["x"], &saved["w"]), (&json!(6), &json!(3)));

        assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 204);
        assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 404);
    }

    #[tokio::test]
    async fn a_widget_can_not_be_reached_through_another_dashboard() {
        let server = start().await;
        let first = dashboard(&server, "First").await;
        let second = dashboard(&server, "Second").await;
        let widget_id = widget(&server, first).await;

        let wrong = format!("/api/v1/dashboards/{second}/widgets/{widget_id}");
        let change = json!({ "metric": "memory.usage" });
        assert_eq!(api(&server, "PUT", &wrong, &change).await.0, 404);
        assert_eq!(api(&server, "DELETE", &wrong, &Value::Null).await.0, 404);

        let layout = format!("/api/v1/dashboards/{second}/layout");
        let moved = json!([{ "id": widget_id, "x": 6, "y": 2, "w": 3, "h": 5 }]);
        api(&server, "PUT", &layout, &moved).await;
        let shown = format!("/api/v1/dashboards/{first}");
        let (_, kept) = api(&server, "GET", &shown, &Value::Null).await;
        assert_eq!(
            kept["widgets"][0]["x"], 0,
            "moved through the wrong dashboard"
        );
    }

    #[tokio::test]
    async fn a_widget_that_makes_no_sense_is_refused() {
        let server = start().await;
        let id = dashboard(&server, "Fleet").await;
        let path = format!("/api/v1/dashboards/{id}/widgets");

        for body in [
            json!({ "metric": "nope" }),
            json!({ "metric": "cpu.usage", "kind": "pie" }),
            json!({ "metric": "cpu.usage", "calculation": "median" }),
            json!({ "metric": "cpu.usage", "x": 10, "w": 6 }),
        ] {
            let (status, answer) = api(&server, "POST", &path, &body).await;
            assert_eq!(status, 422, "{body}: {answer}");
        }

        let layout = format!("/api/v1/dashboards/{id}/layout");
        let moved = json!([{ "id": 1, "x": 11, "y": 0, "w": 6, "h": 4 }]);
        assert_eq!(api(&server, "PUT", &layout, &moved).await.0, 422);
    }

    #[tokio::test]
    async fn deleting_a_dashboard_takes_its_widgets_with_it() {
        let server = start().await;
        let id = dashboard(&server, "Fleet").await;
        let widget_id = widget(&server, id).await;

        let path = format!("/api/v1/dashboards/{id}");
        assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 204);

        assert_eq!(api(&server, "GET", &path, &Value::Null).await.0, 404);
        let gone = server.state.database.get_widget(id, widget_id).await;
        assert!(gone.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_dashboard_needs_a_name() {
        let server = start().await;
        let body = json!({ "name": "   " });
        let (status, _) = api(&server, "POST", "/api/v1/dashboards", &body).await;
        assert_eq!(status, 422);
    }
}

mod dashboard_pages {
    use super::*;

    async fn built(server: &TestServer, browser: &mut Browser) -> i64 {
        let page = browser
            .submit(server, "/dashboards", "/dashboards", &[("name", "Fleet")])
            .await;
        assert_eq!(page.status, 303, "{}", page.body);
        server.state.database.list_dashboards().await.unwrap()[0].id
    }

    async fn add_widget(
        server: &TestServer,
        browser: &mut Browser,
        id: i64,
        fields: &[(&str, &str)],
    ) -> Page {
        let form = format!("/dashboards/{id}/widgets/new");
        let action = format!("/dashboards/{id}/widgets");
        browser.submit(server, &form, &action, fields).await
    }

    const CHART: [(&str, &str); 6] = [
        ("kind", "chart"),
        ("metric", "cpu.usage"),
        ("calculation", "avg"),
        ("group_by", "host"),
        ("filter", ""),
        ("title", "Busy machines"),
    ];

    #[tokio::test]
    async fn a_dashboard_can_be_built_on_the_pages() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let mut browser = Browser::default();
        let id = built(&server, &mut browser).await;

        let page = add_widget(&server, &mut browser, id, &CHART).await;
        assert_eq!(page.status, 303, "{}", page.body);

        let shown = browser.get(&server, &format!("/dashboards/{id}")).await;
        assert_eq!(shown.status, 200);
        assert!(
            shown.body.contains(r#"class="grid-stack""#),
            "{}",
            shown.body
        );
        assert!(shown.body.contains("every 30s"), "views refresh themselves");

        let widget = server
            .state
            .database
            .get_dashboard(id)
            .await
            .unwrap()
            .unwrap();
        let path = format!("/dashboards/{id}/widgets/{}", widget.widgets[0].id);
        let drawn = browser.get(&server, &path).await;
        assert_eq!(drawn.status, 200);
        assert!(drawn.body.contains("Busy machines"), "{}", drawn.body);
        assert!(
            drawn.body.contains(r#"<svg class="chart""#),
            "{}",
            drawn.body
        );
        assert!(drawn.body.contains("web-2"), "{}", drawn.body);
        assert!(!drawn.body.contains("<html"), "just the widget");
    }

    #[tokio::test]
    async fn a_page_with_forms_does_not_refresh_itself() {
        let server = start().await;
        let mut browser = Browser::default();
        let id = built(&server, &mut browser).await;
        add_widget(&server, &mut browser, id, &CHART).await;

        let page = browser
            .get(&server, &format!("/dashboards/{id}/edit"))
            .await;

        assert!(page.body.contains("Add widget"));
        assert!(!page.body.contains("every 30s"), "{}", page.body);
    }

    #[tokio::test]
    async fn dragging_a_widget_saves_where_it_went() {
        let server = start().await;
        let mut browser = Browser::default();
        let id = built(&server, &mut browser).await;
        add_widget(&server, &mut browser, id, &CHART).await;
        let database = &server.state.database;
        let widget = database.get_dashboard(id).await.unwrap().unwrap().widgets[0].id;

        let layout = format!(r#"[{{"id":{widget},"x":6,"y":1,"w":6,"h":5}}]"#);
        let page = browser
            .submit(
                &server,
                &format!("/dashboards/{id}/edit"),
                &format!("/dashboards/{id}/layout"),
                &[("layout", &layout)],
            )
            .await;

        assert_eq!(page.status, 204, "{}", page.body);
        let saved = database.get_widget(id, widget).await.unwrap().unwrap();
        assert_eq!(saved.input.placement.x, 6);
        assert_eq!(saved.input.placement.h, 5);
    }

    #[tokio::test]
    async fn a_mistake_on_the_form_keeps_what_was_typed() {
        let server = start().await;
        let mut browser = Browser::default();
        let id = built(&server, &mut browser).await;

        let mut fields = CHART;
        fields[4] = ("filter", "\"unfinished");
        let page = add_widget(&server, &mut browser, id, &fields).await;

        assert_eq!(page.status, 200);
        assert!(page.body.contains(r#"class="error""#), "{}", page.body);
        assert!(page.body.contains("Busy machines"), "{}", page.body);
    }

    #[tokio::test]
    async fn what_agents_report_is_never_treated_as_html() {
        let server = start_with_metrics().await;
        let hostile = "<script>alert(1)</script>";
        let (_agent, _client) = machine(&server, "web-1", 10.0, json!({ "role": hostile })).await;
        query(&server, "/api/v1/query?metric=cpu.usage&calculation=count").await;
        let mut browser = Browser::default();
        let id = built(&server, &mut browser).await;
        let mut fields = CHART.to_vec();
        fields[3] = ("group_by", "fact");
        fields.push(("fact", "role"));
        add_widget(&server, &mut browser, id, &fields).await;

        let dashboard = server
            .state
            .database
            .get_dashboard(id)
            .await
            .unwrap()
            .unwrap();
        let path = format!("/dashboards/{id}/widgets/{}", dashboard.widgets[0].id);
        let page = browser.get(&server, &path).await;

        assert!(!page.body.contains(hostile), "{}", page.body);
        assert!(page.body.contains("&lt;script"), "{}", page.body);
    }

    #[tokio::test]
    async fn one_broken_widget_says_so_without_stopping_the_page() {
        let saved = Saved::default();
        let store = Box::new(MemoryStore(saved.clone()));
        let server = start_on("", store, Arc::new(FailingReader), saved, None).await;
        let (agent, _client) = (identity(), ());
        server.connect_approved(&agent, "web-1").await;
        let mut browser = Browser::default();
        let id = built(&server, &mut browser).await;
        add_widget(&server, &mut browser, id, &CHART).await;

        let dashboard = server
            .state
            .database
            .get_dashboard(id)
            .await
            .unwrap()
            .unwrap();
        let path = format!("/dashboards/{id}/widgets/{}", dashboard.widgets[0].id);
        let page = browser.get(&server, &path).await;

        assert_eq!(page.status, 200);
        assert!(page.body.contains("couldn't be read"), "{}", page.body);
        assert!(!page.body.contains("secret"), "{}", page.body);
    }

    #[tokio::test]
    async fn dashboards_need_someone_signed_in() {
        let server = start().await;
        let mut stranger = Browser::anonymous();
        for path in ["/dashboards", "/dashboards/1", "/dashboards/1/widgets/1"] {
            let page = stranger.get(&server, path).await;
            assert_eq!(page.status, 303, "{path}");
            assert!(page.header("location").unwrap().starts_with("/login"));
        }
    }

    #[tokio::test]
    async fn something_that_does_not_exist_is_not_found() {
        let server = start().await;
        let mut browser = Browser::default();
        for path in [
            "/dashboards/99",
            "/dashboards/99/edit",
            "/dashboards/99/widgets/new",
            "/dashboards/99/widgets/1",
            "/dashboards/99/widgets/1/edit",
        ] {
            assert_eq!(browser.get(&server, path).await.status, 404, "{path}");
        }
    }
}

mod variables {
    use super::*;

    async fn dashboard_with(server: &TestServer, variables: Value, widget: Value) -> (i64, i64) {
        let (status, created) = api(
            server,
            "POST",
            "/api/v1/dashboards",
            &json!({ "name": "Machine" }),
        )
        .await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_i64().unwrap();
        let path = format!("/api/v1/dashboards/{id}/variables");
        let (status, answer) = api(server, "PUT", &path, &variables).await;
        assert_eq!(status, 204, "{answer}");
        let path = format!("/api/v1/dashboards/{id}/widgets");
        let (status, created) = api(server, "POST", &path, &widget).await;
        assert_eq!(status, 201, "{created}");
        (id, created["id"].as_i64().unwrap())
    }

    fn machine_variable() -> Value {
        json!([{ "name": "machine", "label": "Machine", "kind": "machine" }])
    }

    fn per_machine_widget() -> Value {
        json!({
            "metric": "cpu.usage", "group_by": "host",
            "filter": "$machine", "title": "CPU on $machine",
        })
    }

    #[tokio::test]
    async fn a_machine_picker_shows_one_machine_at_a_time() {
        let server = start_with_metrics().await;
        let machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let web_2 = machines[1].0.id();
        let (id, widget) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;
        let mut browser = Browser::default();

        let page = browser.get(&server, &format!("/dashboards/{id}")).await;
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(page.body.contains(r#"name="var-machine""#), "{}", page.body);
        let db_first = page.body.find(">db-1<").unwrap() < page.body.find(">web-1<").unwrap();
        assert!(db_first, "machines are in order: {}", page.body);

        let path = format!("/dashboards/{id}/widgets/{widget}?var-machine={web_2}");
        let drawn = browser.get(&server, &path).await;
        assert!(drawn.body.contains("CPU on web-2"), "{}", drawn.body);
        assert!(!drawn.body.contains("db-1"), "{}", drawn.body);

        let path = format!("/dashboards/{id}/widgets/{widget}");
        let drawn = browser.get(&server, &path).await;
        assert!(
            drawn.body.contains("CPU on db-1"),
            "the first machine when none is picked: {}",
            drawn.body
        );
    }

    #[tokio::test]
    async fn the_range_and_what_is_picked_are_kept_together() {
        let server = start_with_metrics().await;
        let machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let web_2 = machines[1].0.id();
        let (id, _) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;

        let path = format!("/dashboards/{id}?range=6h&var-machine={web_2}");
        let page = Browser::default().get(&server, &path).await;

        let kept = format!("?range=24h&amp;var-machine={web_2}");
        assert!(
            page.body.contains(&kept),
            "range links keep the pick: {}",
            page.body
        );
        assert!(
            page.body.contains(r#"name="range" value="6h""#),
            "pickers keep the range: {}",
            page.body
        );
        let selected = format!(r#"value="{web_2}" selected"#);
        assert!(page.body.contains(&selected), "{}", page.body);
    }

    #[tokio::test]
    async fn a_fact_picker_offers_each_value_and_all_of_them() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let variables = json!([{ "name": "role", "kind": "fact", "fact": "role" }]);
        let widget = json!({ "metric": "cpu.usage", "kind": "number", "filter": "$role" });
        let (id, widget) = dashboard_with(&server, variables, widget).await;

        let path = format!("/api/v1/dashboards/{id}/variables");
        let (status, listed) = api(&server, "GET", &path, &Value::Null).await;
        assert_eq!(status, 200, "{listed}");
        assert_eq!(listed[0]["name"], "role");
        let choices: Vec<&str> = listed[0]["choices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|choice| choice["value"].as_str().unwrap())
            .collect();
        assert_eq!(choices, ["db", "web"]);

        let data = format!("/api/v1/dashboards/{id}/widgets/{widget}");
        let web = query(&server, &format!("{data}?var-role=web")).await;
        assert_eq!(web["filter"], "role=web");
        assert_eq!(newest(&web["series"][0]), 20.0);
        let all = query(&server, &format!("{data}?var-role=")).await;
        assert_eq!(all["filter"], "");
        assert_eq!(newest(&all["series"][0]), 40.0);
    }

    #[tokio::test]
    async fn only_what_a_picker_offers_reaches_a_filter() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let variables = json!([{ "name": "role", "kind": "fact", "fact": "role" }]);
        let widget = json!({ "metric": "cpu.usage", "kind": "number", "filter": "$role" });
        let (id, widget) = dashboard_with(&server, variables, widget).await;

        let path = format!("/api/v1/dashboards/{id}/widgets/{widget}?var-role=web%20role%3Ddb");
        let result = query(&server, &path).await;

        assert_eq!(result["filter"], "", "{result}");
    }

    #[tokio::test]
    async fn a_picker_offers_only_the_machines_its_filter_picks() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let variables = json!([{ "name": "machine", "kind": "machine", "filter": "role=web" }]);
        let (id, _) = dashboard_with(&server, variables, per_machine_widget()).await;

        let path = format!("/api/v1/dashboards/{id}/variables");
        let (_, listed) = api(&server, "GET", &path, &Value::Null).await;
        let labels: Vec<&str> = listed[0]["choices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|choice| choice["label"].as_str().unwrap())
            .collect();
        assert_eq!(labels, ["web-1", "web-2"]);
    }

    #[tokio::test]
    async fn with_no_machine_to_pick_a_widget_says_so() {
        let server = start().await;
        let (id, widget) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;
        let mut browser = Browser::default();

        let page = browser.get(&server, &format!("/dashboards/{id}")).await;
        assert!(page.body.contains("No machines"), "{}", page.body);
        let path = format!("/dashboards/{id}/widgets/{widget}");
        let drawn = browser.get(&server, &path).await;
        assert!(
            drawn.body.contains("no machine to pick for Machine"),
            "{}",
            drawn.body
        );
        let data = format!("/api/v1/dashboards/{id}/widgets/{widget}");
        assert_eq!(api(&server, "GET", &data, &Value::Null).await.0, 422);
    }

    #[tokio::test]
    async fn a_widget_can_only_use_the_dashboards_variables() {
        let server = start().await;
        let (status, created) = api(
            &server,
            "POST",
            "/api/v1/dashboards",
            &json!({ "name": "Fleet" }),
        )
        .await;
        assert_eq!(status, 201);
        let id = created["id"].as_i64().unwrap();

        let path = format!("/api/v1/dashboards/{id}/widgets");
        let (status, answer) = api(&server, "POST", &path, &per_machine_widget()).await;
        assert_eq!(status, 422);
        assert_eq!(
            answer["error"],
            "This dashboard has no variable called $machine."
        );

        let mut browser = Browser::default();
        let page = browser
            .submit(
                &server,
                &format!("/dashboards/{id}/widgets/new"),
                &format!("/dashboards/{id}/widgets"),
                &[
                    ("kind", "chart"),
                    ("metric", "cpu.usage"),
                    ("calculation", "avg"),
                    ("group_by", "host"),
                    ("filter", "$machine"),
                ],
            )
            .await;
        assert_eq!(page.status, 200);
        assert!(
            page.body.contains("no variable called $machine"),
            "{}",
            page.body
        );
    }

    #[tokio::test]
    async fn a_variable_a_widget_uses_can_not_be_removed() {
        let server = start().await;
        let (id, _) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;

        let path = format!("/api/v1/dashboards/{id}/variables");
        let (status, answer) = api(&server, "PUT", &path, &json!([])).await;
        assert_eq!(status, 422);
        assert!(
            answer["error"].as_str().unwrap().contains("uses $machine"),
            "{answer}"
        );

        let mut browser = Browser::default();
        let page = browser
            .submit(
                &server,
                &format!("/dashboards/{id}/edit"),
                &format!("/dashboards/{id}/variables/machine/delete"),
                &[],
            )
            .await;
        assert_eq!(page.status, 200);
        assert!(page.body.contains("uses $machine"), "{}", page.body);
        let kept = server
            .state
            .database
            .get_dashboard(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.variables.len(), 1);
    }

    #[tokio::test]
    async fn variables_can_be_added_changed_and_removed_on_the_pages() {
        let server = start().await;
        let (status, created) = api(
            &server,
            "POST",
            "/api/v1/dashboards",
            &json!({ "name": "Fleet" }),
        )
        .await;
        assert_eq!(status, 201);
        let id = created["id"].as_i64().unwrap();
        let mut browser = Browser::default();
        let database = &server.state.database;

        let page = browser
            .submit(
                &server,
                &format!("/dashboards/{id}/variables/new"),
                &format!("/dashboards/{id}/variables"),
                &[
                    ("name", "$env"),
                    ("label", "Environment"),
                    ("kind", "fact"),
                    ("fact", "environment"),
                    ("filter", "os=linux"),
                ],
            )
            .await;
        assert_eq!(page.status, 303, "{}", page.body);
        let saved = &database.get_dashboard(id).await.unwrap().unwrap().variables;
        assert_eq!(saved[0].name, "env");
        assert_eq!(saved[0].fact, "environment");

        let edit = browser
            .get(&server, &format!("/dashboards/{id}/edit"))
            .await;
        assert!(edit.body.contains("<code>$env</code>"), "{}", edit.body);

        let page = browser
            .submit(
                &server,
                &format!("/dashboards/{id}/variables/env/edit"),
                &format!("/dashboards/{id}/variables/env"),
                &[
                    ("name", "env"),
                    ("label", ""),
                    ("kind", "fact"),
                    ("fact", ""),
                    ("filter", ""),
                ],
            )
            .await;
        assert_eq!(page.status, 200, "a fact variable needs a fact");
        assert!(page.body.contains("Choose which fact"), "{}", page.body);

        let page = browser
            .submit(
                &server,
                &format!("/dashboards/{id}/edit"),
                &format!("/dashboards/{id}/variables/env/delete"),
                &[],
            )
            .await;
        assert_eq!(page.status, 303, "{}", page.body);
        let saved = database.get_dashboard(id).await.unwrap().unwrap();
        assert!(saved.variables.is_empty());
    }

    #[tokio::test]
    async fn machine_names_in_a_picker_are_never_markup() {
        let server = start_with_metrics().await;
        let hostile = "<b>web</b>";
        let (_agent, _client) = machine(&server, hostile, 10.0, json!({ "role": "web" })).await;
        let (id, _) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;

        let page = Browser::default()
            .get(&server, &format!("/dashboards/{id}"))
            .await;

        assert!(!page.body.contains(hostile), "{}", page.body);
        assert!(page.body.contains("&lt;b&gt;web"), "{}", page.body);
    }

    #[tokio::test]
    async fn deleting_a_dashboard_takes_its_variables_with_it() {
        let server = start().await;
        let (id, _) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;

        let path = format!("/api/v1/dashboards/{id}");
        assert_eq!(api(&server, "DELETE", &path, &Value::Null).await.0, 204);

        let database = &server.state.database;
        let id = database.create_dashboard("Again", now_ms()).await.unwrap();
        let fresh = database.get_dashboard(id).await.unwrap().unwrap();
        assert!(fresh.variables.is_empty());
    }

    #[tokio::test]
    async fn a_variable_that_does_not_exist_is_not_found() {
        let server = start().await;
        let (id, _) = dashboard_with(&server, machine_variable(), per_machine_widget()).await;
        let mut browser = Browser::default();
        for path in [
            "/dashboards/99/variables/new".to_string(),
            format!("/dashboards/{id}/variables/nope/edit"),
        ] {
            assert_eq!(browser.get(&server, &path).await.status, 404, "{path}");
        }
    }
}

mod calculation_alerts {
    use super::*;
    use crate::alert_evaluator::Evaluator;
    use crate::alerting::{AlertRuleInput, Comparison, RuleKind, Severity};
    use crate::calculations::Calculation;

    fn rule(calculation: Calculation, comparison: Comparison, threshold: f64) -> AlertRuleInput {
        AlertRuleInput {
            name: "Fleet".to_string(),
            kind: RuleKind::Calculation,
            metric: Some("cpu.usage".to_string()),
            series: None,
            comparison: Some(comparison),
            threshold: Some(threshold),
            warning_threshold: None,
            for_secs: 0,
            severity: Severity::Warning,
            condition: None,
            enabled: true,
            channels: Vec::new(),
            all_channels: false,
            calculation: Some(calculation),
            group_by: None,
            filter: None,
            window_secs: Some(300),
            remind_every_secs: None,
            forecast_secs: None,
            warning_forecast_secs: None,
        }
    }

    fn evaluator(server: &TestServer, started_ms: i64) -> Evaluator {
        let state = &server.state;
        Evaluator::new(
            state.database.clone(),
            state.registry.clone(),
            state.presence.clone(),
            state.metrics.clone(),
            state.status.clone(),
            started_ms,
        )
    }

    /// Well after the start, so the wait for agents to come back is over.
    fn past_grace() -> i64 {
        now_ms() - 600_000
    }

    async fn open_alerts(server: &TestServer) -> Vec<crate::alerting::Alert> {
        server.state.database.open_alerts().await.unwrap()
    }

    #[tokio::test]
    async fn an_average_across_machines_fires_one_alert() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let database = &server.state.database;
        let firing = rule(Calculation::Avg, Comparison::Above, 35.0);
        database.create_alert_rule(&firing).await.unwrap();

        evaluator(&server, past_grace())
            .evaluate(now_ms())
            .await
            .unwrap();

        let alerts = open_alerts(&server).await;
        assert_eq!(
            alerts.len(),
            1,
            "one alert for the group, not one per machine"
        );
        assert_eq!(alerts[0].agent_id, "fleet");
        assert_eq!(alerts[0].host, "Fleet");
        assert_eq!(alerts[0].value, Some(40.0));
        assert!(
            alerts[0].summary.contains("Average of CPU usage is 40%"),
            "{}",
            alerts[0].summary
        );
    }

    #[tokio::test]
    async fn the_rules_list_says_which_machines_a_calculation_covers() {
        let server = start().await;
        let mut narrowed = rule(Calculation::Avg, Comparison::Above, 90.0);
        narrowed.name = "Web fleet".to_string();
        narrowed.filter = Some("role=web".to_string());
        let database = &server.state.database;
        database.create_alert_rule(&narrowed).await.unwrap();

        let list = Browser::default().get(&server, "/alerts/rules").await;
        let row = list.body.split("Web fleet").nth(1).unwrap();
        let row = row.split("</tr>").next().unwrap();
        assert!(row.contains("role=web"), "{row}");
        assert!(!row.contains("Every"), "{row}");
    }

    #[tokio::test]
    async fn staying_under_the_threshold_fires_nothing() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let quiet = rule(Calculation::Avg, Comparison::Above, 90.0);
        server
            .state
            .database
            .create_alert_rule(&quiet)
            .await
            .unwrap();

        evaluator(&server, past_grace())
            .evaluate(now_ms())
            .await
            .unwrap();

        assert!(open_alerts(&server).await.is_empty());
    }

    #[tokio::test]
    async fn each_group_can_have_its_own_alert() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let mut grouped = rule(Calculation::Avg, Comparison::Above, 50.0);
        grouped.group_by = Some("fact:role".to_string());
        server
            .state
            .database
            .create_alert_rule(&grouped)
            .await
            .unwrap();

        evaluator(&server, past_grace())
            .evaluate(now_ms())
            .await
            .unwrap();

        let alerts = open_alerts(&server).await;
        assert_eq!(alerts.len(), 1, "web averages 20%, and db 80%");
        assert_eq!(alerts[0].series, "db");
    }

    #[tokio::test]
    async fn a_filter_limits_the_machines_a_rule_watches() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let mut filtered = rule(Calculation::Max, Comparison::Above, 50.0);
        filtered.filter = Some("role=web".to_string());
        server
            .state
            .database
            .create_alert_rule(&filtered)
            .await
            .unwrap();

        evaluator(&server, past_grace())
            .evaluate(now_ms())
            .await
            .unwrap();

        assert!(
            open_alerts(&server).await.is_empty(),
            "db-1 isn't being watched"
        );
    }

    #[tokio::test]
    async fn no_machines_reporting_at_all_is_caught_by_a_count() {
        let server = start_with_metrics().await;
        let (agent, _client) = (identity(), ());
        server.connect_approved(&agent, "web-1").await;
        let counting = rule(Calculation::Count, Comparison::Below, 1.0);
        server
            .state
            .database
            .create_alert_rule(&counting)
            .await
            .unwrap();

        evaluator(&server, past_grace())
            .evaluate(now_ms())
            .await
            .unwrap();

        let alerts = open_alerts(&server).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].value, Some(0.0));
    }

    #[tokio::test]
    async fn a_restart_does_not_look_like_the_fleet_disappearing() {
        let server = start_with_metrics().await;
        let counting = rule(Calculation::Count, Comparison::Below, 1.0);
        server
            .state
            .database
            .create_alert_rule(&counting)
            .await
            .unwrap();

        evaluator(&server, now_ms())
            .evaluate(now_ms())
            .await
            .unwrap();

        assert!(open_alerts(&server).await.is_empty());
    }

    #[tokio::test]
    async fn an_alert_resolves_when_the_calculation_recovers() {
        let server = start_with_metrics().await;
        let _machines = three_machines(&server).await;
        wait_for_all_three(&server).await;
        let database = &server.state.database;
        let id = database
            .create_alert_rule(&rule(Calculation::Avg, Comparison::Above, 35.0))
            .await
            .unwrap();
        let mut evaluator = evaluator(&server, past_grace());
        evaluator.evaluate(now_ms()).await.unwrap();
        assert_eq!(open_alerts(&server).await.len(), 1);

        // Raising the threshold has the same effect as the number coming down.
        let raised = rule(Calculation::Avg, Comparison::Above, 90.0);
        database.update_alert_rule(id, &raised).await.unwrap();
        evaluator.evaluate(now_ms() + MINUTE_MS).await.unwrap();

        assert!(open_alerts(&server).await.is_empty());
    }

    #[tokio::test]
    async fn a_calculation_that_can_not_be_read_changes_nothing() {
        let saved = Saved::default();
        let store = Box::new(MemoryStore(saved.clone()));
        let server = start_on("", store, Arc::new(FailingReader), saved, None).await;
        let agent = identity();
        server.connect_approved(&agent, "web-1").await;
        let counting = rule(Calculation::Count, Comparison::Below, 1.0);
        server
            .state
            .database
            .create_alert_rule(&counting)
            .await
            .unwrap();

        evaluator(&server, past_grace())
            .evaluate(now_ms())
            .await
            .unwrap();

        assert!(
            open_alerts(&server).await.is_empty(),
            "not knowing isn't zero"
        );
    }

    #[tokio::test]
    async fn the_fleet_is_not_a_machine_anyone_can_see_or_change() {
        let server = start().await;
        let database = &server.state.database;
        let agents = database.load_agents().await.unwrap();
        let fleet = agents
            .into_iter()
            .find(|agent| agent.id == "fleet")
            .unwrap();
        server.state.registry.insert_for_test(fleet).await;

        let list = Browser::default().get(&server, "/agents").await;
        assert!(!list.body.contains("/agents/fleet"), "{}", list.body);

        let revoked = server
            .state
            .registry
            .decide("fleet", AgentState::Revoked)
            .await
            .unwrap();
        assert!(revoked.is_none());
    }

    #[tokio::test]
    async fn a_rule_can_be_made_through_the_api_and_the_pages() {
        let server = start().await;
        let body = json!({
            "name": "Busy fleet", "kind": "calculation", "metric": "cpu.usage",
            "calculation": "avg", "comparison": "above", "threshold": 80.0,
            "filter": "os=linux", "group_by": "fact:role", "window_secs": 600,
            "for_secs": 60, "severity": "warning",
        });
        let (status, made) = api(&server, "POST", "/api/v1/alert-rules", &body).await;
        assert_eq!(status, 201, "{made}");

        let mut browser = Browser::default();
        let page = browser.get(&server, "/alerts/rules").await;
        assert!(
            page.body.contains("Average of CPU usage above 80%"),
            "{}",
            page.body
        );

        let id = made["id"].as_i64().unwrap();
        let form = browser
            .get(&server, &format!("/alerts/rules/{id}/edit"))
            .await;
        assert!(form.body.contains(r#"value="os=linux""#), "{}", form.body);
        assert!(form.body.contains(r#"value="role""#), "{}", form.body);
        assert!(form.body.contains(r#"value="600""#), "{}", form.body);
    }

    #[tokio::test]
    async fn a_rule_that_makes_no_sense_is_refused() {
        let server = start().await;
        let good = json!({
            "name": "x", "kind": "calculation", "metric": "cpu.usage", "calculation": "avg",
            "comparison": "above", "threshold": 80.0, "for_secs": 0, "severity": "warning",
        });
        for (field, value) in [
            ("metric", json!("nope")),
            ("calculation", Value::Null),
            ("filter", json!("\"unfinished")),
            ("group_by", json!("colour")),
            ("window_secs", json!(5)),
            ("comparison", Value::Null),
            ("threshold", Value::Null),
            ("condition", json!("true")),
        ] {
            let mut body = good.clone();
            body[field] = value;
            let (status, answer) = api(&server, "POST", "/api/v1/alert-rules", &body).await;
            assert_eq!(status, 422, "{field}: {answer}");
        }

        let mut offline = json!({
            "name": "x", "kind": "offline", "for_secs": 0, "severity": "warning",
        });
        offline["filter"] = json!("os=linux");
        let (status, _) = api(&server, "POST", "/api/v1/alert-rules", &offline).await;
        assert_eq!(status, 422, "only calculations have filters");
    }
}

/// Fails with a secret in the error, which must never reach a page.
struct FailingReader;

impl MetricsReader for FailingReader {
    fn series(
        &self,
        _query: &crate::metrics::SeriesQuery,
    ) -> anyhow::Result<crate::metrics::SeriesResult> {
        anyhow::bail!("a secret");
    }

    fn last_samples(
        &self,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::LastSample>> {
        Ok(Vec::new())
    }

    fn latest_output(
        &self,
        _agent_id: &str,
        _collector: &str,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Option<Value>> {
        Ok(None)
    }

    fn newest(
        &self,
        _metric: &crate::metrics::Metric,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::NewestReading>> {
        Ok(Vec::new())
    }

    fn trends(
        &self,
        _metric: &crate::metrics::Metric,
        _since_ms: i64,
        _until_ms: i64,
    ) -> anyhow::Result<Vec<crate::metrics::Trend>> {
        Ok(Vec::new())
    }

    fn stats(&self, _hour_ago_ms: i64) -> anyhow::Result<crate::store::StoreStats> {
        Ok(Default::default())
    }

    fn series_count(&self) -> anyhow::Result<u64> {
        Ok(0)
    }

    fn calculate(
        &self,
        _query: &crate::calculations::CalculationQuery,
    ) -> anyhow::Result<crate::metrics::SeriesResult> {
        anyhow::bail!("a secret");
    }
}
