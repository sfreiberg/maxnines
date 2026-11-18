#!/bin/sh
# Packs one built program with its licence, the README and its example config,
# as <program>-<version>-<target>.tar.gz. Windows has installers instead.
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
cp "target.nosync/$target/release/$program" "$out/$name/"
cp LICENSE README.md "crates/$short/config/$short.hcl" "$out/$name/"
cd "$out"
tar -czf "$name.tar.gz" "$name"
rm -r "$name"
