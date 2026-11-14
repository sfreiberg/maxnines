//! Records which build this is, for the web interface to show.

use std::error::Error;

use vergen_gitcl::{Build, Emitter, Gitcl};

fn main() -> Result<(), Box<dyn Error>> {
    // Everything that ends up in the binary, or the build time would go stale.
    for path in [
        "src",
        "assets",
        "Cargo.toml",
        "../protocol/src",
        "../../Cargo.lock",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    // A source download has no git history, and that shouldn't stop a build.
    Emitter::default()
        .default_on_error()
        .add_instructions(&Build::builder().build_timestamp(true).build())?
        .add_instructions(&Gitcl::builder().sha(true).dirty(true).build())?
        .emit()?;
    Ok(())
}
