#!/bin/sh
# Packs one built program with its licence, the README and its example config,
# as <program>-<version>-<target>.tar.gz. Windows has installers instead. The
# command line, maxnines-cli, is the program maxnines, and has its man pages in
# man/ rather than a config, which it writes itself, so it has to run here.
#
#   packaging/archive.sh maxnines-agent 0.1.0 x86_64-unknown-linux-musl dist
set -eu
program=$1
version=$2
target=$3
out=$4

name=$program-$version-$target
short=${program#maxnines-}

mkdir -p "$out/$name"
if [ "$program" = maxnines-cli ]; then
  cp "target.nosync/$target/release/maxnines" LICENSE README.md "$out/$name/"
  "target.nosync/$target/release/maxnines" man-pages "$out/$name/man"
else
  cp "target.nosync/$target/release/$program" "$out/$name/"
  cp LICENSE README.md "crates/$short/config/$short.hcl" "$out/$name/"
fi
cd "$out"
tar -czf "$name.tar.gz" "$name"
rm -r "$name"
