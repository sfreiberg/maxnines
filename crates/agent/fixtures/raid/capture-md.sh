#!/bin/sh
# Builds Linux software RAID arrays with mdadm on loop devices and keeps what
# /proc/mdstat, which the agent's raid collector reads, says at each step: no
# arrays, healthy RAID 0, 1, 5 and 10, a first resync, a device failed and then
# removed, recovery after it's added back, a check, a spare taking over and an
# array that can't start. The capture-raid-outputs workflow runs it as root on an
# Ubuntu runner, by hand only. Each step is kept as out/<system>/md/<step>.mdstat.
set -u

# shellcheck disable=SC1091
. /etc/os-release
out="${OUT:-out}/$ID-$VERSION_ID/md"
mkdir -p "$out"
work=$(mktemp -d)

modprobe md_mod 2>/dev/null || true
for personality in raid0 raid1 raid456 raid10; do
  modprobe "$personality" 2>/dev/null || true
done

# snap <step>: keeps what /proc/mdstat says now.
snap() {
  cp /proc/mdstat "$out/$1.mdstat"
  echo "== $1"
  cat /proc/mdstat
}

# disk <name> <size>: a loop device backed by a file, printed as its path.
disk() {
  truncate -s "$2" "$work/$1"
  losetup --find --show "$work/$1"
}

# slow / fast: how fast md may resync, in KiB a second. Slow keeps a rebuild going
# long enough to be seen.
slow() {
  echo 1000 >/proc/sys/dev/raid/speed_limit_min
  echo 1000 >/proc/sys/dev/raid/speed_limit_max
}
fast() {
  echo 2000000 >/proc/sys/dev/raid/speed_limit_max
  echo 2000000 >/proc/sys/dev/raid/speed_limit_min
}

create() {
  mdadm --create "$@" --run --metadata=1.2 >/dev/null 2>&1 || mdadm --create "$@" --run --metadata=1.2
}

snap empty

a1=$(disk a1 128M)
a2=$(disk a2 128M)
b1=$(disk b1 128M)
b2=$(disk b2 128M)
b3=$(disk b3 128M)
b4=$(disk b4 128M)
c1=$(disk c1 64M)
c2=$(disk c2 64M)
d1=$(disk d1 64M)
d2=$(disk d2 64M)
d3=$(disk d3 64M)
d4=$(disk d4 64M)

slow
create /dev/md0 --level=1 --raid-devices=2 "$a1" "$a2"
create /dev/md1 --level=5 --raid-devices=3 "$b1" "$b2" "$b3"
sleep 3
# RAID 1 resyncs its first time, and RAID 5 builds its parity by recovering
# onto its last device.
snap first-sync

fast
create /dev/md2 --level=0 --raid-devices=2 "$c1" "$c2"
create /dev/md3 --level=10 --raid-devices=4 "$d1" "$d2" "$d3" "$d4"
mdadm --wait /dev/md0 /dev/md1 /dev/md3 >/dev/null 2>&1
snap healthy

# A device fails, then is taken out.
mdadm /dev/md0 --fail "$a2" >/dev/null 2>&1
snap raid1-failed
mdadm /dev/md0 --remove "$a2" >/dev/null 2>&1
snap raid1-degraded
mdadm /dev/md3 --fail "$d2" >/dev/null 2>&1
mdadm /dev/md3 --remove "$d2" >/dev/null 2>&1
snap raid10-degraded

# Added back, it's rebuilt.
slow
mdadm --zero-superblock "$a2" >/dev/null 2>&1
mdadm /dev/md0 --add "$a2" >/dev/null 2>&1
sleep 3
snap raid1-recovering
fast
mdadm --wait /dev/md0 >/dev/null 2>&1
mdadm --zero-superblock "$d2" >/dev/null 2>&1
mdadm /dev/md3 --add "$d2" >/dev/null 2>&1
mdadm --wait /dev/md3 >/dev/null 2>&1

# A check reads everything and compares, as a monthly cron job does.
slow
echo check >/sys/block/md1/md/sync_action
sleep 3
snap raid5-check
echo idle >/sys/block/md1/md/sync_action
fast
mdadm --wait /dev/md1 >/dev/null 2>&1

# A spare waits, then takes a failed device's place.
mdadm /dev/md1 --add "$b4" >/dev/null 2>&1
snap raid5-spare
slow
mdadm /dev/md1 --fail "$b2" >/dev/null 2>&1
sleep 3
snap raid5-spare-rebuilding
fast
mdadm --wait /dev/md1 >/dev/null 2>&1
mdadm /dev/md1 --remove "$b2" >/dev/null 2>&1
snap raid5-rebuilt

# An array with too few of its devices doesn't start.
mdadm --stop /dev/md2 >/dev/null 2>&1
mdadm --assemble /dev/md2 "$c1" >/dev/null 2>&1
snap inactive

# A RAID 5 with two devices gone has failed.
mdadm /dev/md1 --fail "$b3" >/dev/null 2>&1
mdadm /dev/md1 --fail "$b4" >/dev/null 2>&1
snap raid5-failed

uname -r >"$out/kernel"
mdadm --version >"$out/mdadm-version" 2>&1
for md in /dev/md0 /dev/md1 /dev/md2 /dev/md3; do
  mdadm --stop "$md" >/dev/null 2>&1
done
exit 0
