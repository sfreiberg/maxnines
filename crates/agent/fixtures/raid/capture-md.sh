#!/bin/sh
# Builds Linux software RAID arrays with mdadm on loop devices and keeps what
# /proc/mdstat, which the agent's raid collector reads, says at each step: no
# arrays, healthy RAID 0, 1, 5 and 10, a first resync, a device failed and then
# removed, recovery after it's added back, a check and a repair, a spare taking
# over, an array waiting for its devices, a resync left pending by an array
# started read-only, and an Intel RST container with an array in it. The
# capture-raid-outputs workflow runs it as root on an Ubuntu runner. Each step is
# kept as out/<system>/md/<step>.mdstat, and what sysfs says an array is doing,
# where the agent reads that too, as <step>.<array>.sync_action.
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

# action <step> <array>: keeps what sysfs says the array is doing now.
action() {
  cp "/sys/block/$2/md/sync_action" "$out/$1.$2.sync_action"
  echo "== $1 $2: $(cat "/sys/block/$2/md/sync_action")"
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
action first-sync md0

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

# A repair rewrites what a check only counts. /proc/mdstat calls it a resync, and
# only sysfs says it's a repair.
slow
echo repair >/sys/block/md1/md/sync_action
sleep 3
snap raid5-repair
action raid5-repair md1
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

# An array found with too few of its devices waits for the rest, inactive, as
# it does when a disk is missing at boot.
mdadm --stop /dev/md2 >/dev/null 2>&1
mdadm --incremental "$c1" >/dev/null 2>&1
snap inactive

# md won't fail the device a RAID 5 can't do without, so this is as far as
# failing devices goes.
mdadm /dev/md1 --fail "$b3" >/dev/null 2>&1
mdadm /dev/md1 --fail "$b4" >/dev/null 2>&1
snap raid5-failed

# An array started read-only, as Debian and Ubuntu start those found at boot until
# something writes to them, leaves a resync it was in the middle of pending.
e1=$(disk e1 128M)
e2=$(disk e2 128M)
slow
create /dev/md4 --level=1 --raid-devices=2 "$e1" "$e2"
sleep 3
mdadm --stop /dev/md4 >/dev/null 2>&1
echo 1 >/sys/module/md_mod/parameters/start_ro
mdadm --assemble /dev/md4 "$e1" "$e2" >/dev/null 2>&1
snap resync-pending
mdadm --stop /dev/md4 >/dev/null 2>&1
echo 0 >/sys/module/md_mod/parameters/start_ro
fast

# Intel's RST keeps its metadata in a container, an md array that's always
# inactive and holds nothing itself, with the arrays it holds next to it. mdadm's
# own tests make one on loop devices with these.
export IMSM_NO_PLATFORM=1 IMSM_DEVNAME_AS_SERIAL=1
f1=$(disk f1 256M)
f2=$(disk f2 256M)
mdadm --create /dev/md/imsm0 --run --metadata=imsm --raid-devices=2 "$f1" "$f2"
mdadm --create /dev/md/vol0 --run --level=1 --raid-devices=2 --size=65536 /dev/md/imsm0
sleep 3
snap container

uname -r >"$out/kernel"
mdadm --version >"$out/mdadm-version" 2>&1
mdadm --stop --scan >/dev/null 2>&1
exit 0
