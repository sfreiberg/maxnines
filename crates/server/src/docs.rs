//! The documentation in the repository's `docs/` folder, built into the server so
//! it always matches the running version, and shown at `/docs` to anyone signed in.
//!
//! `SUMMARY.md` lists the chapters in order, as mdBook reads it, so the same files
//! can also be built into a website. Links between chapters are written as links
//! to their files, which works on GitHub and here alike.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use pulldown_cmark::{
    CodeBlockKind, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html,
};
use rust_embed::RustEmbed;
use serde::Serialize;
use syntect::html::{ClassStyle, ClassedHTMLGenerator};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

#[derive(RustEmbed)]
#[folder = "../../docs/"]
#[include = "*.md"]
struct DocFiles;

/// Where the pages are served, which chapter links are rewritten to.
pub const BASE_PATH: &str = "/docs";

/// The prefix on the classes that colour code, which `themes.css` styles.
const CODE_CLASS_PREFIX: &str = "hl-";

/// Results a search shows at most.
const MAX_HITS: usize = 25;

/// Every chapter, rendered.
pub struct Docs {
    chapters: Vec<Chapter>,
    by_name: HashMap<String, usize>,
}

/// One chapter in the order `SUMMARY.md` gives.
pub struct Chapter {
    /// Its file name without `.md`, which is also its address under `/docs`.
    pub name: String,
    /// As `SUMMARY.md` lists it.
    pub title: String,
    pub html: String,
    sections: Vec<Section>,
    /// Links to other chapters, or within this one, as `chapter#anchor`.
    links: Vec<String>,
    /// Links that are neither to a chapter nor to a web address.
    unusable_links: Vec<String>,
    anchors: HashSet<String>,
}

/// The text under one heading, for searching.
struct Section {
    anchor: String,
    heading: String,
    text: String,
    /// The words in the heading, then in the text, in lowercase.
    heading_words: Vec<String>,
    words: Vec<String>,
}

/// An entry in the contents beside every page.
#[derive(Debug, Serialize)]
pub struct ContentsEntry {
    pub name: String,
    pub title: String,
}

/// A section that has every word searched for.
#[derive(Debug, Serialize)]
pub struct Hit {
    pub chapter: String,
    pub heading: String,
    pub link: String,
    pub excerpt: String,
}

impl Docs {
    /// Rendered once, the first time they're asked for: rendering colours every
    /// code example, which takes a moment.
    pub fn get() -> Result<Arc<Docs>> {
        static DOCS: OnceLock<Arc<Docs>> = OnceLock::new();
        if let Some(docs) = DOCS.get() {
            return Ok(Arc::clone(docs));
        }
        let docs = Arc::new(Self::load()?);
        Ok(Arc::clone(DOCS.get_or_init(|| docs)))
    }

    fn load() -> Result<Self> {
        let summary = file("SUMMARY.md")?;
        let syntaxes = two_face::syntax::extra_newlines();
        let mut chapters = Vec::new();
        let mut by_name = HashMap::new();
        for (title, name) in parse_summary(&summary)? {
            let markdown = file(&format!("{name}.md"))?;
            let chapter = render(&name, &title, &markdown, &syntaxes)
                .with_context(|| format!("rendering docs/{name}.md"))?;
            ensure!(
                by_name.insert(name.clone(), chapters.len()).is_none(),
                "SUMMARY.md lists {name}.md twice"
            );
            chapters.push(chapter);
        }
        ensure!(!chapters.is_empty(), "SUMMARY.md lists no chapters");
        let docs = Self { chapters, by_name };
        let broken = docs.broken_links();
        ensure!(
            broken.is_empty(),
            "links that lead nowhere: {}",
            broken.join(", ")
        );
        Ok(docs)
    }

    /// The first chapter, which `/docs` shows.
    pub fn first(&self) -> &Chapter {
        &self.chapters[0]
    }

    pub fn chapter(&self, name: &str) -> Option<&Chapter> {
        self.by_name.get(name).map(|&index| &self.chapters[index])
    }

    pub fn contents(&self) -> Vec<ContentsEntry> {
        self.chapters
            .iter()
            .map(|chapter| ContentsEntry {
                name: chapter.name.clone(),
                title: chapter.title.clone(),
            })
            .collect()
    }

    /// Sections where each word in `query` starts a word, so "key" finds "keys".
    /// Those with every word in their heading come first, then the rest in the
    /// order they come in the docs.
    pub fn search(&self, query: &str) -> Vec<Hit> {
        let words = words_of(query);
        if words.is_empty() {
            return Vec::new();
        }
        let starts = |within: &[String], word: &String| {
            within
                .iter()
                .any(|candidate| candidate.starts_with(word.as_str()))
        };
        let mut hits: Vec<(bool, Hit)> = Vec::new();
        for chapter in &self.chapters {
            for section in &chapter.sections {
                let found = |word: &String| {
                    starts(&section.heading_words, word) || starts(&section.words, word)
                };
                if !words.iter().all(found) {
                    continue;
                }
                let in_heading = words
                    .iter()
                    .all(|word| starts(&section.heading_words, word));
                let link = match section.anchor.as_str() {
                    "" => format!("{BASE_PATH}/{}", chapter.name),
                    anchor => format!("{BASE_PATH}/{}#{anchor}", chapter.name),
                };
                hits.push((
                    in_heading,
                    Hit {
                        chapter: chapter.title.clone(),
                        heading: section.heading.clone(),
                        link,
                        excerpt: excerpt(&section.text, &words),
                    },
                ));
            }
        }
        // Stable, so each group keeps the docs' own order.
        hits.sort_by_key(|(in_heading, _)| !in_heading);
        hits.into_iter()
            .take(MAX_HITS)
            .map(|(_, hit)| hit)
            .collect()
    }

    /// Links that lead nowhere: to a chapter `SUMMARY.md` doesn't list, to a
    /// heading that isn't there, or to a file that isn't a chapter, which the
    /// server has no way to show.
    pub fn broken_links(&self) -> Vec<String> {
        let mut broken = Vec::new();
        for chapter in &self.chapters {
            for link in &chapter.unusable_links {
                broken.push(format!("{}.md: {link}", chapter.name));
            }
            for link in &chapter.links {
                let (target, anchor) = link.split_once('#').unwrap_or((link, ""));
                let reaches = self
                    .chapter(target)
                    .is_some_and(|found| anchor.is_empty() || found.anchors.contains(anchor));
                if !reaches {
                    broken.push(format!("{}.md: {link}", chapter.name));
                }
            }
        }
        broken
    }
}

fn file(name: &str) -> Result<String> {
    let file = DocFiles::get(name).ok_or_else(|| anyhow!("docs/{name} is missing"))?;
    String::from_utf8(file.data.into_owned()).with_context(|| format!("docs/{name} isn't text"))
}

/// The chapters `SUMMARY.md` lists, as `(title, name)`. Anything else in it is
/// refused, so a mistake there shows up in the tests rather than as a missing page.
fn parse_summary(summary: &str) -> Result<Vec<(String, String)>> {
    let mut chapters = Vec::new();
    for line in summary.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("# ") {
            continue;
        }
        let entry = line
            .strip_prefix("- [")
            .and_then(|rest| rest.split_once("]("))
            .and_then(|(title, rest)| Some((title, rest.strip_suffix(".md)")?)));
        let Some((title, name)) = entry else {
            bail!("SUMMARY.md has a line that isn't a chapter: {line}");
        };
        let simple = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        ensure!(
            !name.is_empty() && name.chars().all(simple) && name != "search",
            "chapter names are lowercase letters, digits and hyphens, and not search: {name}"
        );
        chapters.push((title.to_string(), name.to_string()));
    }
    Ok(chapters)
}

/// Turns a chapter's Markdown into HTML for the page. Raw HTML in the Markdown is
/// shown as text, headings get the same anchors GitHub gives them, links to other
/// chapters point at their pages here, and code is coloured with classes.
fn render(name: &str, title: &str, markdown: &str, syntaxes: &SyntaxSet) -> Result<Chapter> {
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let mut events: Vec<Event> = Parser::new_ext(markdown, options).collect();

    let mut anchors = Anchors::default();
    let mut sections = vec![Section {
        anchor: String::new(),
        heading: title.to_string(),
        text: String::new(),
        heading_words: Vec::new(),
        words: Vec::new(),
    }];
    let mut links = Vec::new();
    let mut unusable_links = Vec::new();
    let mut output = Vec::with_capacity(events.len());
    let mut index = 0;
    while index < events.len() {
        match std::mem::replace(&mut events[index], Event::Text(CowStr::Borrowed(""))) {
            Event::Start(Tag::Heading {
                level,
                classes,
                attrs,
                ..
            }) => {
                let end = position(&events, index, |event| {
                    matches!(event, Event::End(TagEnd::Heading(_)))
                })?;
                let heading = plain_text(&events[index + 1..end]);
                let anchor = anchors.add(&heading);
                if level != HeadingLevel::H1 {
                    sections.push(Section {
                        anchor: anchor.clone(),
                        heading: heading.clone(),
                        text: String::new(),
                        heading_words: Vec::new(),
                        words: Vec::new(),
                    });
                }
                output.push(Event::Start(Tag::Heading {
                    level,
                    id: Some(anchor.into()),
                    classes,
                    attrs,
                }));
                // The heading's own words are the section's heading, not its text.
                output.extend(events[index + 1..end].iter().cloned());
                index = end - 1;
            }
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => {
                let rewritten = match chapter_link(name, &dest_url) {
                    Some(Ok((target, anchor))) => {
                        links.push(match anchor {
                            "" => target.to_string(),
                            anchor => format!("{target}#{anchor}"),
                        });
                        Some(match anchor {
                            "" => format!("{BASE_PATH}/{target}"),
                            anchor if target == name => format!("#{anchor}"),
                            anchor => format!("{BASE_PATH}/{target}#{anchor}"),
                        })
                    }
                    Some(Err(())) => {
                        unusable_links.push(dest_url.to_string());
                        None
                    }
                    None => None,
                };
                let dest_url = rewritten.map_or(dest_url, CowStr::from);
                output.push(Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                }));
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                let end = position(&events, index, |event| {
                    matches!(event, Event::End(TagEnd::CodeBlock))
                })?;
                let code = plain_text(&events[index + 1..end]);
                let language = match &kind {
                    CodeBlockKind::Fenced(language) => language.as_ref(),
                    CodeBlockKind::Indented => "",
                };
                push_text(&mut sections, &code);
                output.push(Event::Html(highlight(&code, language, syntaxes)?.into()));
                index = end;
            }
            Event::Start(Tag::Table(alignments)) => {
                // Wide tables scroll on their own rather than widening the page.
                output.push(Event::Html(r#"<div class="table-scroll">"#.into()));
                output.push(Event::Start(Tag::Table(alignments)));
            }
            Event::End(TagEnd::Table) => {
                output.push(Event::End(TagEnd::Table));
                output.push(Event::Html("</div>".into()));
            }
            // The docs are ours, but HTML in them is still only text.
            Event::Html(text) | Event::InlineHtml(text) => {
                push_text(&mut sections, &text);
                output.push(Event::Text(text));
            }
            Event::Text(text) => {
                push_text(&mut sections, &text);
                output.push(Event::Text(text));
            }
            Event::Code(text) => {
                push_text(&mut sections, &text);
                output.push(Event::Code(text));
            }
            Event::SoftBreak | Event::HardBreak => {
                push_text(&mut sections, " ");
                output.push(Event::SoftBreak);
            }
            event => output.push(event),
        }
        index += 1;
    }

    let mut page = String::new();
    html::push_html(&mut page, output.into_iter());
    for section in &mut sections {
        section.text = section
            .text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        section.heading_words = words_of(&section.heading);
        section.words = words_of(&section.text);
    }
    Ok(Chapter {
        name: name.to_string(),
        title: title.to_string(),
        html: page,
        sections,
        links,
        unusable_links,
        anchors: anchors.seen,
    })
}

/// Where the matching end of the element starting at `start` is.
fn position(events: &[Event], start: usize, is_end: impl Fn(&Event) -> bool) -> Result<usize> {
    events[start..]
        .iter()
        .position(is_end)
        .map(|offset| start + offset)
        .ok_or_else(|| anyhow!("an element is never closed"))
}

fn plain_text(events: &[Event]) -> String {
    let mut text = String::new();
    for event in events {
        match event {
            Event::Text(part) | Event::Code(part) | Event::Html(part) | Event::InlineHtml(part) => {
                text.push_str(part);
            }
            Event::SoftBreak | Event::HardBreak => text.push(' '),
            _ => {}
        }
    }
    text
}

fn push_text(sections: &mut [Section], text: &str) {
    if let Some(section) = sections.last_mut() {
        section.text.push_str(text);
        section.text.push(' ');
    }
}

/// For a link to a chapter, which one and the heading in it. `None` is a web
/// address, left as it is, and `Err` a link to some other file.
fn chapter_link<'a>(current: &'a str, url: &'a str) -> Option<Result<(&'a str, &'a str), ()>> {
    if let Some(anchor) = url.strip_prefix('#') {
        return Some(Ok((current, anchor)));
    }
    if url.contains("://") || url.starts_with("mailto:") {
        return None;
    }
    let (path, anchor) = url.split_once('#').unwrap_or((url, ""));
    match path.strip_suffix(".md") {
        Some(target) if !target.contains('/') => Some(Ok((target, anchor))),
        _ => Some(Err(())),
    }
}

/// Heading anchors as GitHub makes them, so a link to one works there and here.
#[derive(Default)]
struct Anchors {
    seen: HashSet<String>,
}

impl Anchors {
    fn add(&mut self, heading: &str) -> String {
        let base: String = heading
            .trim()
            .to_lowercase()
            .chars()
            .filter_map(|c| match c {
                ' ' => Some('-'),
                c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
                _ => None,
            })
            .collect();
        let mut anchor = base.clone();
        let mut repeat = 0;
        while !self.seen.insert(anchor.clone()) {
            repeat += 1;
            anchor = format!("{base}-{repeat}");
        }
        anchor
    }
}

/// Code as HTML, coloured by classes when its language is known.
fn highlight(code: &str, language: &str, syntaxes: &SyntaxSet) -> Result<String> {
    let body = match syntaxes.find_syntax_by_token(language) {
        Some(syntax) if !language.is_empty() => {
            let style = ClassStyle::SpacedPrefixed {
                prefix: CODE_CLASS_PREFIX,
            };
            let mut generator = ClassedHTMLGenerator::new_with_class_style(syntax, syntaxes, style);
            for line in LinesWithEndings::from(code) {
                generator
                    .parse_html_for_line_which_includes_newline(line)
                    .with_context(|| format!("colouring {language}"))?;
            }
            generator.finalize()
        }
        _ => {
            let mut escaped = String::new();
            html::push_html(&mut escaped, std::iter::once(Event::Text(code.into())));
            escaped
        }
    };
    Ok(format!(r#"<pre class="code"><code>{body}</code></pre>"#))
}

/// Lowercase words, split wherever there's something other than a letter or digit.
fn words_of(text: &str) -> Vec<String> {
    let mut words: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect();
    words.sort_unstable();
    words.dedup();
    words
}

/// Up to about 200 characters around the first word found.
fn excerpt(text: &str, words: &[String]) -> String {
    const BEFORE: usize = 60;
    const LENGTH: usize = 200;
    let lower = text.to_lowercase();
    let found = words
        .iter()
        .filter_map(|word| lower.find(word.as_str()))
        .min()
        .unwrap_or(0);
    // Lowercasing can change byte offsets, so count in characters from here.
    let found = lower[..found].chars().count();
    let start = found.saturating_sub(BEFORE);
    let chars: Vec<char> = text.chars().collect();
    let end = (start + LENGTH).min(chars.len());
    let mut excerpt: String = chars[start.min(end)..end].iter().collect();
    if start > 0 {
        excerpt = format!("…{}", excerpt.trim_start());
    }
    if end < chars.len() {
        excerpt = format!("{}…", excerpt.trim_end());
    }
    excerpt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docs() -> Arc<Docs> {
        Docs::get().unwrap()
    }

    fn chapter(markdown: &str) -> Chapter {
        render(
            "example",
            "Example",
            markdown,
            &two_face::syntax::extra_newlines(),
        )
        .unwrap()
    }

    #[test]
    fn every_chapter_is_listed_and_every_listed_chapter_exists() {
        let docs = docs();
        let listed: HashSet<String> = docs.chapters.iter().map(|c| c.name.clone()).collect();
        for file in DocFiles::iter() {
            let name = file.strip_suffix(".md").unwrap();
            if name != "SUMMARY" {
                assert!(listed.contains(name), "SUMMARY.md doesn't list docs/{file}");
            }
        }
        assert_eq!(docs.first().name, "introduction");
    }

    #[test]
    fn every_link_leads_somewhere() {
        assert_eq!(docs().broken_links(), Vec::<String>::new());
    }

    #[test]
    fn links_to_chapters_point_at_their_pages() {
        let page = chapter(
            "See [HTTPS](https.md#agents), [users](users.md) and [below](#more).\n\n## More\n",
        );
        assert!(
            page.html.contains(r#"href="/docs/https#agents""#),
            "{}",
            page.html
        );
        assert!(page.html.contains(r#"href="/docs/users""#), "{}", page.html);
        assert!(page.html.contains(r##"href="#more""##), "{}", page.html);
        assert_eq!(page.links, ["https#agents", "users", "example#more"]);
    }

    #[test]
    fn links_to_other_files_are_caught() {
        let page =
            chapter("[config](../crates/agent/config/agent.hcl) and [site](https://example.com)");
        assert_eq!(page.unusable_links, ["../crates/agent/config/agent.hcl"]);
        assert!(page.html.contains(r#"href="https://example.com""#));
    }

    #[test]
    fn headings_get_the_anchors_github_gives_them() {
        let page = chapter(
            "# Title\n\n## Main database\n\n## GET /api/v1/agents/{id}\n\n## Main database\n",
        );
        for anchor in ["main-database", "get-apiv1agentsid", "main-database-1"] {
            assert!(
                page.html.contains(&format!(r#"id="{anchor}""#)),
                "{anchor}\n{}",
                page.html
            );
        }
    }

    #[test]
    fn html_in_the_markdown_is_only_text() {
        let page = chapter("<script>alert(1)</script>\n\nSome <b>bold</b> words.");
        assert!(!page.html.contains("<script>"), "{}", page.html);
        assert!(!page.html.contains("<b>"), "{}", page.html);
        assert!(page.html.contains("&lt;script&gt;"), "{}", page.html);
    }

    // PowerShell isn't here: its syntax needs the C regex engine, so the few
    // PowerShell examples are shown plain.
    #[test]
    fn code_is_coloured_by_class_in_the_languages_the_docs_use() {
        for (language, code) in [
            ("sh", "echo \"hello\" # greet\n"),
            ("hcl", "server {\n  url = \"ws://localhost:9000/ws\"\n}\n"),
            ("json", "{\"id\": 1}\n"),
        ] {
            let page = chapter(&format!("```{language}\n{code}```\n"));
            assert!(
                page.html.contains(r#"<pre class="code"><code>"#),
                "{language}\n{}",
                page.html
            );
            assert!(
                page.html.contains(r#"class="hl-"#),
                "{language} isn't coloured\n{}",
                page.html
            );
            assert!(!page.html.contains("style="), "{language}\n{}", page.html);
        }
    }

    #[test]
    fn code_in_an_unknown_language_is_escaped() {
        let page = chapter("```\n<b>&</b>\n```\n");
        assert!(
            page.html.contains("&lt;b&gt;&amp;&lt;/b&gt;"),
            "{}",
            page.html
        );
    }

    #[test]
    fn tables_scroll_by_themselves() {
        let page = chapter("| A | B |\n| --- | --- |\n| 1 | 2 |\n");
        assert!(
            page.html.contains(r#"<div class="table-scroll"><table>"#),
            "{}",
            page.html
        );
        assert!(
            page.html.contains("</table>\n</div>") || page.html.contains("</table></div>"),
            "{}",
            page.html
        );
    }

    #[test]
    fn search_finds_sections_with_every_word() {
        let docs = docs();
        let hits = docs.search("Let's Encrypt staging");
        assert!(!hits.is_empty());
        assert!(
            hits.iter().all(|hit| hit.link.starts_with("/docs/https")),
            "{hits:?}"
        );

        let hits = docs.search("main database");
        assert_eq!(hits[0].heading, "Main database", "{hits:?}");
        assert_eq!(hits[0].link, "/docs/databases#main-database");
        assert!(!hits[0].excerpt.starts_with("Main database"), "{hits:?}");

        // A word has to start a word in the docs, not just appear inside one.
        let hits = docs.search("ecrypt");
        assert!(hits.is_empty(), "{hits:?}");
        let hits = docs.search("encrypt");
        assert!(
            hits.iter().any(|hit| hit.link.starts_with("/docs/https")),
            "{hits:?}"
        );

        assert!(docs.search("").is_empty());
        assert!(docs.search("nothing-mentions-this-word").is_empty());
    }

    #[test]
    fn an_excerpt_is_around_what_was_found() {
        let text = format!("{} needle {}", "a ".repeat(100), "b ".repeat(100));
        let found = excerpt(&text, &["needle".to_string()]);
        assert!(found.starts_with('…') && found.ends_with('…'), "{found}");
        assert!(found.contains("needle"), "{found}");
        assert!(found.chars().count() <= 202, "{found}");
    }

    #[test]
    fn summary_lines_must_be_chapters() {
        assert!(parse_summary("# Summary\n\n- [One](one.md)\n  - [Two](two.md)\n").is_ok());
        for bad in [
            "Some text",
            "- [Up](../up.md)",
            "- [Search](search.md)",
            "- [Caps](Caps.md)",
        ] {
            assert!(parse_summary(bad).is_err(), "{bad}");
        }
    }
}
