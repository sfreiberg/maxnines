#!/bin/sh
# Builds an AppleRAID mirror on disk images and keeps what `diskutil appleRAID
# list` says at each step: no sets, a healthy mirror, one member gone, and a
# rebuild onto a new member. The capture-raid-outputs workflow runs it with sudo
# on a macOS runner, by hand only. Each step is kept under out/<system>/appleraid/.
set -u

out="${OUT:-out}/macos-$(sw_vers -productVersion)/appleraid"
mkdir -p "$out"
work=$(mktemp -d)
sw_vers >"$out/version"

snap() {
  LC_ALL=C diskutil appleRAID list >"$out/$1.txt" 2>&1
  LC_ALL=C diskutil appleRAID list -plist >"$out/$1.plist" 2>&1
  echo "== $1"
  cat "$out/$1.txt"
}

# image <name>: a blank disk image attached with nothing mounted, printed as its disk.
image() {
  hdiutil create -size 256m -layout NONE -type UDIF -o "$work/$1" >/dev/null
  hdiutil attach -nomount "$work/$1.dmg" | awk 'NR == 1 { sub("/dev/", "", $1); print $1 }'
}

snap empty
one=$(image one)
two=$(image two)
three=$(image three)
diskutil appleRAID create mirror Capture JHFS+ "$one" "$two"
set_id=$(diskutil appleRAID list | awk '/^Unique ID:/ { print $3; exit }')
snap healthy

# One member goes away.
hdiutil detach -force "$two"
sleep 5
snap degraded

# A new member is added and the mirror rebuilds onto it.
diskutil appleRAID add member "$three" "$set_id"
sleep 2
snap rebuilding
tries=0
while diskutil appleRAID list | grep -q Rebuilding && [ "$tries" -lt 300 ]; do
  tries=$((tries + 1))
  sleep 1
done
snap rebuilt
exit 0
