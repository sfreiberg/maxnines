use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use maxnines_protocol::Sample;

use crate::config::{Config, ExporterConfig, OutputFormat};
use crate::identity;
use crate::websocket::{FactSettings, WebSocketExporter};

/// A destination for samples.
pub trait Exporter {
    fn export(&mut self, sample: &Sample) -> Result<()>;
}

pub fn build(
    name: &str,
    exporter: &ExporterConfig,
    config: &Config,
    host: &str,
) -> Result<Box<dyn Exporter>> {
    Ok(match name {
        "stdout" => Box::new(StdoutExporter {
            format: exporter.format,
        }),
        "websocket" => {
            let url = exporter
                .url
                .clone()
                .context("websocket exporter needs a url")?;
            let identity = identity::load_or_create(&config.key_file)?;
            let facts = FactSettings {
                custom: config.facts.clone(),
                every: Duration::from_secs(config.facts_interval_secs),
            };
            Box::new(WebSocketExporter::start(
                url, host, identity, exporter, facts,
            )?)
        }
        other => bail!("unknown exporter {other:?}"),
    })
}

struct StdoutExporter {
    format: OutputFormat,
}

impl Exporter for StdoutExporter {
    fn export(&mut self, sample: &Sample) -> Result<()> {
        let line = match self.format {
            OutputFormat::Json => serde_json::to_string(sample)?,
            OutputFormat::Pretty => serde_json::to_string_pretty(sample)?,
        };
        let mut out = std::io::stdout().lock();
        writeln!(out, "{line}")?;
        out.flush()?;
        Ok(())
    }
}
