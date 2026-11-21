//! The documentation pages, as someone signed in sees them.

use super::*;

#[tokio::test]
async fn the_docs_need_someone_signed_in() {
    let server = start().await;
    for path in [
        "/docs",
        "/docs/https",
        "/docs/search?q=tls",
        "/docs/no-such-chapter",
    ] {
        let page = Browser::anonymous().get(&server, path).await;
        assert_ne!(page.status, 200, "{path}");
        assert!(!page.body.contains("docs-page"), "{path}");
    }
}

#[tokio::test]
async fn the_docs_open_on_the_first_chapter_with_every_chapter_beside_it() {
    let server = start().await;
    let page = Browser::default().get(&server, "/docs").await;

    assert_eq!(page.status, 200);
    assert!(page.body.contains("<h1"), "{}", page.body);
    assert!(
        page.body
            .contains(r#"href="/docs/introduction" aria-current="page""#)
    );
    for chapter in ["installing", "https", "api", "load-testing"] {
        assert!(
            page.body.contains(&format!(r#"href="/docs/{chapter}""#)),
            "{chapter}"
        );
    }
    assert!(page.body.contains(r#"class="rail-link on" href="/docs""#));
}

#[tokio::test]
async fn a_chapter_shows_its_coloured_examples_and_links_to_others() {
    let server = start().await;
    let page = Browser::default().get(&server, "/docs/https").await;

    assert_eq!(page.status, 200);
    assert!(page.body.contains("<title>HTTPS · Docs · MaxNines</title>"));
    assert!(
        page.body.contains(r#"<h2 id="automatic-certificates">"#),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains(r#"<pre class="code"><code><span class="hl-"#)
    );
    assert!(page.body.contains(r#"class="table-scroll""#));
    // Nothing on the page is styled inline, which the security policy would block.
    assert!(!page.body.contains("style="));
}

#[tokio::test]
async fn a_chapter_that_isnt_there_is_not_found() {
    let server = start().await;
    let page = Browser::default()
        .get(&server, "/docs/no-such-chapter")
        .await;
    assert_eq!(page.status, 404);
}

#[tokio::test]
async fn searching_the_docs_links_to_each_section_found() {
    let server = start().await;
    let mut browser = Browser::default();

    let page = browser
        .get(&server, "/docs/search?q=maintenance+window")
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains(r#"href="/docs/alerts#silences""#),
        "{}",
        page.body
    );

    let page = browser.get(&server, "/docs/search?q=").await;
    assert!(page.body.contains("Type what you"), "{}", page.body);

    let page = browser.get(&server, "/docs/search?q=%3Cscript%3Ezzz").await;
    assert!(page.body.contains("&lt;script&gt;zzz"), "{}", page.body);
    assert!(!page.body.contains("<script>zzz"));
}

/// The docs' HTML is made from Markdown built into the server. Everything else,
/// including whatever agents report, has to go through the templates' escaping.
#[test]
fn only_the_docs_page_takes_html_as_it_is() {
    let views = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/views");
    let mut found = Vec::new();
    let mut folders = vec![views.clone()];
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                folders.push(path);
            } else {
                let text = std::fs::read_to_string(&path).unwrap();
                let compact = text.replace(' ', "");
                if compact.contains("|safe") || compact.contains("safe(") {
                    found.push(path.strip_prefix(&views).unwrap().display().to_string());
                }
            }
        }
    }
    let docs_page = std::path::Path::new("docs").join("show.html");
    assert_eq!(found, [docs_page.display().to_string()]);
}
