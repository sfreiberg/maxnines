#!/bin/sh
# Packs one built program with its licence, the README and its example config,
# as <program>-<version>-<target>.tar.gz, or .zip for Windows.
#
#   packaging/archive.sh maxnines-agent 0.1.0 x86_64-unknown-linux-musl dist
set -eu
program=$1
version=$2
target=$3
out=$4

case $target in
  *windows*) exe=.exe ;;
  *) exe= ;;
esac
name=$program-$version-$target
short=${program#maxnines-}

mkdir -p "$out/$name"
cp "target.nosync/$target/release/$program$exe" "$out/$name/"
cp LICENSE README.md "crates/$short/config/$short.hcl" "$out/$name/"
cd "$out"
case $target in
  *windows*)
    if command -v 7z >/dev/null; then
      7z a -tzip "$name.zip" "$name" >/dev/null
    else
      powershell -NoProfile -Command "Compress-Archive -Path '$name' -DestinationPath '$name.zip'"
    fi
    ;;
  *) tar -czf "$name.tar.gz" "$name" ;;
esac
rm -r "$name"
