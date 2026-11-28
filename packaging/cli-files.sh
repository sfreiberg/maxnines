#!/bin/sh
# Writes what the command line's Linux packages install beside it, from the built
# program itself: its man pages, compressed as packages keep them, and its
# completions for bash, zsh and fish. They go in cli-files beside the program,
# where crates/cli/Cargo.toml's package metadata looks for them.
#
#   packaging/cli-files.sh target.nosync/x86_64-unknown-linux-musl/release
set -eu
release=$1
out=$release/cli-files

rm -rf "$out"
mkdir -p "$out/man"
"$release/maxnines" man-pages "$out/man"
gzip -9n "$out"/man/*.1
"$release/maxnines" completion bash >"$out/maxnines.bash"
"$release/maxnines" completion zsh >"$out/_maxnines"
"$release/maxnines" completion fish >"$out/maxnines.fish"
ls -l "$out" "$out/man"
