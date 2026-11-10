#!/usr/bin/env bash
# Fails if a Windows program needs the Visual C++ runtime, which isn't on every
# Windows machine. Without it, Windows stops the program before it starts, and over
# SSH that happens with no message at all.
#
# The DLLs a program needs are named in it as plain text, so this looks for the
# runtime's names in each one.
#
#   packaging/check-windows-dlls.sh <program.exe>...
set -euo pipefail

runtime='vcruntime[0-9]*\.dll|msvcp[0-9]*\.dll|api-ms-win-crt-[a-z0-9-]*\.dll|ucrtbase\.dll'
failed=0
for program in "$@"; do
  needs=$(grep -aoiE "$runtime" "$program" | sort -fu || true)
  if [ -n "$needs" ]; then
    echo "$program needs the Visual C++ runtime:" >&2
    echo "$needs" | sed 's/^/  /' >&2
    failed=1
  else
    echo "$program needs nothing installed"
  fi
done
exit "$failed"
