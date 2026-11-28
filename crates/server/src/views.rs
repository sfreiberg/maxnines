//! Templates and static files, embedded in the binary so a deploy is one file.
//! Debug builds read them from disk instead, so edits show on refresh.

use anyhow::{Context as _, Result, anyhow};
use rust_embed::RustEmbed;
use tera::{Context, Tera};

#[derive(RustEmbed)]
#[folder = "assets/views/"]
struct ViewFiles;

#[derive(RustEmbed)]
#[folder = "assets/static/"]
pub struct StaticFiles;

pub struct Views {
    tera: Tera,
}

impl Views {
    pub fn load() -> Result<Self> {
        Ok(Self { tera: load_tera()? })
    }

    pub fn render(&self, template: &str, context: &Context) -> Result<String> {
        if cfg!(debug_assertions) {
            return load_tera()?
                .render(template, context)
                .with_context(|| format!("rendering {template}"));
        }
        self.tera
            .render(template, context)
            .with_context(|| format!("rendering {template}"))
    }
}

fn load_tera() -> Result<Tera> {
    let mut templates = Vec::new();
    for name in ViewFiles::iter() {
        let file = ViewFiles::get(&name).ok_or_else(|| anyhow!("missing template {name}"))?;
        let text = std::str::from_utf8(&file.data)
            .with_context(|| format!("template {name} isn't text"))?
            .to_string();
        templates.push((name.to_string(), text));
    }

    let mut tera = Tera::new();
    tera.add_raw_templates(templates)
        .context("loading templates")?;
    Ok(tera)
}
