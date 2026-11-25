#!/bin/sh
# Builds ZFS pools on files and keeps what `zpool list` and `zpool status`, which
# the agent's raid collector reads, say at each step: no pools, healthy mirror and
# raidz pools with a log, cache and spare, a scrub running, paused and finished,
# a device offline, faulted and missing, a resilver running and finished, a scrub
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

# slow <pool> <file>...: holds up each read and write of these devices for 20
# milliseconds, where zinject is installed, so a scan runs long enough to see.
slow() {
  pool=$1
  shift
  if command -v zinject >/dev/null; then
    for file in "$@"; do
      zinject -D 20:1 -d "$work/$file" "$pool" >/dev/null
    done
  else
    echo "zinject isn't installed, so scans run at full speed"
  fi
}
fast() {
  if command -v zinject >/dev/null; then
    zinject -c all >/dev/null
  fi
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
zpool create -f -o failmode=continue tank mirror "$work/m1" "$work/m2"
zpool create -f vault raidz "$work/r1" "$work/r2" "$work/r3"
zpool add -f tank log "$work/log" cache "$work/cache" spare "$work/spare"
fill /tank/data 600
fill /vault/data 600
snap healthy
as_user "LC_ALL=C $LIST" >"$out/healthy-user.list" 2>&1
as_user "LC_ALL=C $STATUS" >"$out/healthy-user.status" 2>&1

# Scrubs: running, paused, and finished with nothing found. Pools this small
# scrub in a second, so each read and write is held up while one is caught.
slow tank m1 m2
zpool scrub tank
until_seen "scrub in progress" tank && snap scrubbing
zpool scrub -p tank 2>/dev/null && snap scrub-paused
zpool scrub tank
until_seen "scrub in progress" tank
fast
zpool wait -t scrub tank
snap scrubbed

# Devices out of service: one taken offline, and one faulted.
zpool offline vault "$work/r2"
snap offline
zpool online vault "$work/r2"
zpool wait -t resilver vault 2>/dev/null
zpool offline -f tank "$work/m2"
snap faulted

# Written to while one side was out, it has something to resilver when it's back.
fill /tank/more 300
slow tank m1 m2
zpool online tank "$work/m2"
zpool clear tank
until_seen "resilver in progress" tank && snap resilvering
fast
zpool wait -t resilver tank
snap resilvered

# Damage one side of the mirror, which a scrub repairs from the other.
dd if="$random" of="$work/m1" bs=1048576 seek=64 count=512 conv=notrunc 2>/dev/null
zpool scrub tank
zpool wait -t scrub tank
snap scrub-repaired

# A pool with nowhere else to read from loses what's damaged. A scrub reads the
# disk, not what's cached.
zpool create -f single "$work/s1"
fill /single/data 600
dd if="$random" of="$work/s1" bs=1048576 seek=300 count=64 conv=notrunc 2>/dev/null
zpool scrub single
zpool wait -t scrub single
snap data-errors
as_user "LC_ALL=C $STATUS" >"$out/data-errors-user.status" 2>&1
zpool destroy -f single

# A device gone while the pool was exported, as a disk missing at boot.
zpool export vault
rm -f "$work/r3"
zpool import -d "$work" vault
snap missing

# Nearly full, then as full as it gets.
zpool create -f full "$work/f1"
size=$(zpool list -Hp -o size full)
fill /full/data $((size * 85 / 100 / 1048576))
snap nearly-full
dd if="$random" of=/full/rest bs=1048576 2>/dev/null
sync
snap full

for pool in full vault tank; do
  zpool destroy -f "$pool"
done
rm -rf "$work"
exit 0
