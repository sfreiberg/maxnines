//! The man pages, made from the same definitions as `--help` so the two can't
//! disagree: `maxnines.1`, and a page for each command, such as `maxnines-get.1`
//! and `maxnines-config-use.1`, as git has. The release workflow writes them with
//! `maxnines man-pages <folder>` and puts them in every Unix archive and package.
//! That isn't a command clap knows, as the completions would offer even a hidden
//! one to everyone.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::CommandFactory as _;
use clap_mangen::Man;

/// Where the rest is, with examples, which a man page made from `--help` hasn't room for.
const GUIDE: &str = "The full guide, with examples, is the Command line page of the \
    documentation, at /docs/cli on any MaxNines server.";

/// Writes the pages if this is `maxnines man-pages <folder>`, saying how it went,
/// or nothing for every other command.
pub fn asked_for() -> Option<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != "man-pages" {
        return None;
    }
    let (Some(folder), None) = (args.next(), args.next()) else {
        eprintln!(
            "Error: say which folder to write the man pages into: maxnines man-pages <folder>"
        );
        return Some(ExitCode::from(2));
    };
    Some(match write(crate::Cli::command(), Path::new(&folder)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::from(7)
        }
    })
}

/// Writes every page into `folder`, making it if need be.
pub fn write(command: clap::Command, folder: &Path) -> Result<()> {
    fs::create_dir_all(folder).with_context(|| format!("couldn't make {}", folder.display()))?;
    // Each page names itself after the commands it's under, which building works out.
    let mut command = command.disable_help_subcommand(true);
    command.build();
    let mut pages = Vec::new();
    commands(&command, &mut pages);
    let names: Vec<String> = pages
        .iter()
        .map(|page| {
            page.get_display_name()
                .unwrap_or(page.get_name())
                .to_string()
        })
        .collect();
    write_page(folder, &command, &names)?;
    for page in &pages {
        write_page(folder, page, &["maxnines".to_string()])?;
    }
    Ok(())
}

/// Every command below `command` that `--help` lists, depth first.
fn commands(command: &clap::Command, pages: &mut Vec<clap::Command>) {
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        pages.push(sub.clone());
        commands(sub, pages);
    }
}

/// One page, as clap_mangen renders it, then a SEE ALSO section naming `see`, and
/// on the top page where the guide is.
fn write_page(folder: &Path, command: &clap::Command, see: &[String]) -> Result<()> {
    let man = Man::new(command.clone()).source(format!("maxnines {}", env!("CARGO_PKG_VERSION")));
    let path = folder.join(man.get_filename());
    let mut page = Vec::new();
    man.render(&mut page)?;
    writeln!(page, ".SH \"SEE ALSO\"")?;
    for (i, name) in see.iter().enumerate() {
        let comma = if i + 1 < see.len() { "," } else { "" };
        writeln!(page, ".BR {} (1){comma}", name.replace('-', "\\-"))?;
    }
    if command
        .get_display_name()
        .is_none_or(|name| name == "maxnines")
    {
        writeln!(page, ".PP\n{GUIDE}")?;
    }
    fs::write(&path, page).with_context(|| format!("couldn't write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use crate::Cli;

    #[test]
    fn the_completions_dont_offer_it() {
        let mut completions = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut Cli::command(),
            "maxnines",
            &mut completions,
        );
        assert!(
            !String::from_utf8(completions)
                .unwrap()
                .contains("man-pages")
        );
    }

    #[test]
    fn there_is_a_page_for_every_command_and_none_for_hidden_ones() {
        let folder = tempfile::tempdir().unwrap();
        super::write(Cli::command(), folder.path()).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(folder.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        for name in [
            "maxnines.1",
            "maxnines-get.1",
            "maxnines-silence.1",
            "maxnines-config.1",
            "maxnines-config-use.1",
            "maxnines-completion.1",
        ] {
            assert!(names.contains(&name.to_string()), "{names:?}");
        }
        assert!(
            !names
                .iter()
                .any(|name| name.contains("man-pages") || name.contains("help")),
            "{names:?}"
        );
        let top = std::fs::read_to_string(folder.path().join("maxnines.1")).unwrap();
        assert!(top.contains(".BR maxnines\\-silence (1),"), "{top}");
        assert!(top.contains("/docs/cli"), "{top}");
        let silence = std::fs::read_to_string(folder.path().join("maxnines-silence.1")).unwrap();
        assert!(silence.contains("\\-\\-reason"), "{silence}");
        assert!(silence.contains(".BR maxnines (1)"), "{silence}");
    }
}
