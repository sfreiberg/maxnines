#!/bin/sh
# Captures what the kernel says about the clock's sync on Linux, FreeBSD and macOS,
# with the time service running, stopped and started again, so the time_sync
# collector is tested against what kernels really say. Run as root, on a machine
# whose time service it may stop: it's meant for capture-time-sync-outputs.yml.
set -u
here=$(dirname "$0")
cc -o /tmp/time-sync-read "$here/read.c" || exit 1

case $(uname -s) in
Linux)
    . /etc/os-release
    os="$ID-$VERSION_ID"
    ;;
FreeBSD) os="freebsd-$(freebsd-version -u)" ;;
Darwin) os="macos-$(sw_vers -productVersion)" ;;
esac
out="out/$os"
mkdir -p "$out"
uname -a >"$out/kernel"

capture() { /tmp/time-sync-read >"$out/$1.txt" 2>&1; }

# The maximum error every 30 seconds for a while, to see how often the time
# service corrects the clock and how fast the error grows in between.
watch() {
    : >"$out/$1.txt"
    i=0
    while [ $i -lt "$2" ]; do
        printf '%s ' "$(date -u +%H:%M:%S)" >>"$out/$1.txt"
        /tmp/time-sync-read | tr '\n' ' ' >>"$out/$1.txt"
        echo >>"$out/$1.txt"
        i=$((i + 1))
        sleep 30
    done
}

# Waits up to $1 seconds for the kernel to say it's synced.
wait_synced() {
    i=0
    while [ $i -lt "$1" ]; do
        status=$(/tmp/time-sync-read | sed -n 's/^status=//p')
        [ $((status & 0x40)) -eq 0 ] && return 0
        sleep 10
        i=$((i + 10))
    done
    return 1
}

daemons() { ps -A -o comm= | grep -E 'chronyd|systemd-timesyn|ntpd|timed$' | sort -u; }

case $(uname -s) in
Linux)
    daemons >"$out/daemon"
    chronyc tracking >"$out/chronyc-tracking.txt" 2>&1
    timedatectl show >"$out/timedatectl.txt" 2>&1
    capture chrony-synced
    watch chrony-watch 10
    systemctl stop chrony 2>/dev/null || systemctl stop chronyd
    capture chrony-stopped
    sleep 120
    capture chrony-stopped-2m
    systemctl start chrony 2>/dev/null || systemctl start chronyd
    wait_synced 300
    capture chrony-started
    # systemd-timesyncd, which Ubuntu uses where nothing else is installed. It
    # takes chrony's place.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd-timesyncd >/dev/null 2>&1
    systemctl restart systemd-timesyncd
    daemons >"$out/daemon-timesyncd"
    wait_synced 300
    timedatectl show-timesync >"$out/timesyncd-show.txt" 2>&1
    capture timesyncd-synced
    watch timesyncd-watch 10
    systemctl stop systemd-timesyncd
    capture timesyncd-stopped
    sleep 120
    capture timesyncd-stopped-2m
    ;;
FreeBSD)
    # ntpd isn't on unless the installer was told to turn it on.
    daemons >"$out/daemon"
    capture as-found
    service ntpd onestart
    wait_synced 900
    capture ntpd-synced
    ntpq -p >"$out/ntpq.txt" 2>&1
    watch ntpd-watch 10
    service ntpd onestop
    capture ntpd-stopped
    sleep 120
    capture ntpd-stopped-2m
    ;;
Darwin)
    daemons >"$out/daemon"
    systemsetup -getusingnetworktime >"$out/network-time.txt" 2>&1
    capture as-found
    watch timed-watch 20
    systemsetup -setusingnetworktime off >/dev/null 2>&1
    capture network-time-off
    sleep 120
    capture network-time-off-2m
    systemsetup -setusingnetworktime on >/dev/null 2>&1
    sleep 120
    capture network-time-on-2m
    ;;
esac
exit 0
