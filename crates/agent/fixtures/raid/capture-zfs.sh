#!/bin/sh
# Builds ZFS pools on files and keeps what `zpool list` and `zpool status`, which
# the agent's raid collector reads, say at each step: no pools, healthy mirror and
# raidz pools with a log, cache and spare, a scrub running, paused and finished,
# a device offline, faulted and gone, a resilver running and finished, a scrub
# that repaired damage and one that found damage it couldn't, and a pool nearly
# full. The capture-raid-outputs workflow runs it as root on Ubuntu and in
# FreeBSD virtual machines, by hand only. Each step is kept under
# out/<system>/zfs/ as <step>.list, <step>.status and, where this OpenZFS has
# it, <step>.json from `zpool status -j`.
set -u

if [ "$(uname)" = FreeBSD ]; then
  system="freebsd-$(freebsd-version -u | cut -d- -f1-2)"
  kldload zfs 2>/dev/null || true
  # Who runs a command as an ordinary user.
  as_user() { su -m nobody -c "$*"; }
  random=/dev/random
else
  # shellcheck disable=SC1091
  system=$(. /etc/os-release && echo "$ID-$VERSION_ID")
  modprobe zfs 2>/dev/null || true
  as_user() { sudo -u nobody sh -c "$*"; }
  random=/dev/urandom
fi
out="${OUT:-out}/$system/zfs"
mkdir -p "$out"
work=/var/tmp/zfs-capture
rm -rf "$work"
mkdir -p "$work"

# The very commands the agent runs.
LIST="zpool list -Hp -o name,health,size,allocated,free,fragmentation,capacity"
STATUS="zpool status -p"
if zpool status -j >/dev/null 2>&1; then
  json=yes
else
  json=no
fi

# snap <step>: keeps what zpool says now, as the agent asks it.
snap() {
  LC_ALL=C $LIST >"$out/$1.list" 2>"$out/$1.list.stderr"
  LC_ALL=C $STATUS >"$out/$1.status" 2>"$out/$1.status.stderr"
  if [ "$json" = yes ]; then
    LC_ALL=C zpool status -j -p >"$out/$1.json" 2>/dev/null
  fi
  echo "== $1"
  cat "$out/$1.list" "$out/$1.status"
}

# until_seen <pattern> <pool>: waits up to 60 seconds for zpool status to say it.
until_seen() {
  tries=0
  while ! zpool status "$2" | grep -q "$1"; do
    tries=$((tries + 1))
    if [ "$tries" -gt 600 ]; then
      echo "never saw: $1" >&2
      return 1
    fi
    sleep 0.1
  done
}

# fill <file> <MiB>: data that won't compress.
fill() {
  dd if="$random" of="$1" bs=1048576 count="$2" 2>/dev/null
  sync
}

zpool version >"$out/version" 2>&1 || zfs version >"$out/version" 2>&1
uname -r >"$out/kernel"

snap empty

for file in m1 m2 r1 r2 r3 log cache spare s1 f1; do
  truncate -s 1G "$work/$file"
done
zpool create -f -o failmode=continue mirror0 mirror "$work/m1" "$work/m2"
zpool create -f raidz0 raidz "$work/r1" "$work/r2" "$work/r3"
zpool add -f mirror0 log "$work/log" cache "$work/cache" spare "$work/spare"
fill /mirror0/data 600
fill /raidz0/data 600
snap healthy
as_user "LC_ALL=C $LIST" >"$out/healthy-user.list" 2>&1
as_user "LC_ALL=C $STATUS" >"$out/healthy-user.status" 2>&1

# Scrubs: running, paused, and finished with nothing found.
zpool scrub mirror0
until_seen "scrub in progress" mirror0 && snap scrubbing
zpool scrub -p mirror0 2>/dev/null && snap scrub-paused
zpool scrub mirror0
zpool wait -t scrub mirror0
snap scrubbed

# Devices out of service: one taken offline, one faulted, one whose file is gone.
zpool offline raidz0 "$work/r2"
snap offline
zpool online raidz0 "$work/r2"
zpool wait -t resilver raidz0 2>/dev/null
zpool offline -f mirror0 "$work/m2"
snap faulted

# Written to while one side was out, it has something to resilver when it's back.
fill /mirror0/more 300
zpool online mirror0 "$work/m2"
zpool clear mirror0
until_seen "resilver in progress" mirror0 && snap resilvering
zpool wait -t resilver mirror0
snap resilvered

# Damage one side of the mirror, which a scrub repairs from the other.
dd if="$random" of="$work/m1" bs=1048576 seek=64 count=512 conv=notrunc 2>/dev/null
zpool scrub mirror0
zpool wait -t scrub mirror0
snap scrub-repaired

# A pool with nowhere else to read from loses what's damaged.
zpool create -f single "$work/s1"
fill /single/data 600
zpool export single
dd if="$random" of="$work/s1" bs=1048576 seek=64 count=512 conv=notrunc 2>/dev/null
zpool import -d "$work" single
zpool scrub single
zpool wait -t scrub single
snap data-errors
as_user "LC_ALL=C $STATUS" >"$out/data-errors-user.status" 2>&1
zpool destroy -f single

rm -f "$work/r3"
zpool reopen raidz0 2>/dev/null
zpool scrub raidz0 2>/dev/null
zpool wait -t scrub raidz0 2>/dev/null
snap missing

# Nearly full, then as full as it gets.
zpool create -f full "$work/f1"
size=$(zpool list -Hp -o size full)
fill /full/data $((size * 85 / 100 / 1048576))
snap nearly-full
dd if="$random" of=/full/rest bs=1048576 2>/dev/null
sync
snap full

for pool in full raidz0 mirror0; do
  zpool destroy -f "$pool"
done
rm -rf "$work"
exit 0
