#!/bin/sh
# Runs the commands the agent's updates collector runs, exactly as it runs them,
# on whatever system this is, and keeps what each printed and its exit code under
# out/<system>/, as the collector's tests read them. The capture-update-outputs
# workflow runs it in a container for each system, by hand only. The collector
# never refreshes package lists itself; this does, as a container starts with
# none, and makes sure something is waiting where it can.
set -u

# shellcheck disable=SC1091
. /etc/os-release
system="$ID-${VERSION_ID:-rolling}"
out="/work/out/$system"
mkdir -p "$out"
cp /etc/os-release "$out/os-release"

# cap <name> <command...>: runs it in the C locale, as the agent does.
cap() {
  name=$1
  shift
  LC_ALL=C "$@" >"$out/$name.stdout" 2>"$out/$name.stderr"
  echo $? >"$out/$name.code"
}

# as_user <name> <command line>: the same, as an ordinary user.
as_user() {
  name=$1
  shift
  cap "$name" su -s /bin/sh tester -c "LC_ALL=C $*"
}

add_user() {
  if command -v useradd >/dev/null; then
    useradd -m tester
  else
    adduser -D tester
  fi
}

case "$ID" in
ubuntu | debian)
  apt-get update -qq
  # The release's own openssl, so its security fixes are waiting. Its library is
  # libssl3t64 from Ubuntu 24.04 on, and libssl3 before.
  for library in libssl3t64 libssl3; do
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades \
      "openssl/$VERSION_CODENAME" "$library/$VERSION_CODENAME" >/dev/null 2>&1 && break
  done
  add_user
  cap apt /usr/bin/apt-get -s -o Debug::NoLocking=true dist-upgrade
  as_user apt-user /usr/bin/apt-get -s -o Debug::NoLocking=true dist-upgrade
  ;;
rocky | almalinux | rhel | centos | fedora)
  dnf -y -q makecache >/dev/null
  # su comes with util-linux, which Fedora's image leaves out.
  dnf -y -q install sudo util-linux >/dev/null 2>&1 || true
  if [ "$ID" = fedora ]; then
    dnf -y -q install dnf5-plugins >/dev/null 2>&1 || true
  else
    dnf -y -q install dnf-utils >/dev/null 2>&1 || true
  fi
  # Something older than the newest, if nothing is waiting already.
  if dnf -C -q check-update >/dev/null 2>&1; then
    dnf -y -q downgrade curl openssl-libs >/dev/null 2>&1 || true
  fi
  add_user
  cap dnf-check-update /usr/bin/dnf -C -q check-update
  cap dnf-security /usr/bin/dnf -C -q updateinfo list --security
  # Without root, as the agent's user runs them.
  as_user dnf-check-update-user /usr/bin/dnf -C -q check-update
  as_user dnf-security-user /usr/bin/dnf -C -q updateinfo list --security
  if [ -x /usr/bin/needs-restarting ]; then
    cap needs-restarting /usr/bin/needs-restarting -r
  fi
  ;;
opensuse-leap | opensuse-tumbleweed | sles)
  zypper --non-interactive --quiet refresh >/dev/null
  zypper --non-interactive --quiet install shadow findutils >/dev/null 2>&1 || true
  # Leap's image is often current, so curl from the release's own repository,
  # older than its updates, when nothing is waiting.
  if ! zypper --non-interactive --no-refresh --xmlout list-updates | grep -q '<update '; then
    release=$(zypper --xmlout repos | sed -n 's/.*alias="\([^"]*\)".*/\1/p' | grep -iv update | grep -i oss | head -1)
    zypper --non-interactive --quiet install --oldpackage --force --repo "$release" curl libcurl4 >/dev/null 2>&1 || true
  fi
  add_user
  cap zypper-updates /usr/bin/zypper --non-interactive --no-refresh --xmlout list-updates
  cap zypper-security /usr/bin/zypper --non-interactive --no-refresh --xmlout list-patches --category security
  as_user zypper-updates-user /usr/bin/zypper --non-interactive --no-refresh --xmlout list-updates
  as_user zypper-security-user /usr/bin/zypper --non-interactive --no-refresh --xmlout list-patches --category security
  ;;
arch)
  # Fetches the package lists and pacman-contrib, upgrading nothing else, so
  # what the image is behind by stays waiting.
  pacman -Sy --noconfirm --needed pacman-contrib >/dev/null
  add_user
  # checkupdates needs fakeroot, which pacman-contrib doesn't bring.
  cap checkupdates-no-fakeroot /usr/bin/checkupdates --nosync
  pacman -S --noconfirm --needed fakeroot >/dev/null
  cap checkupdates /usr/bin/checkupdates --nosync
  as_user checkupdates-user /usr/bin/checkupdates --nosync
  ;;
alpine)
  apk update -q >/dev/null
  add_user
  cap apk /sbin/apk --no-network list --upgradable
  as_user apk-user /sbin/apk --no-network list --upgradable
  ;;
esac

# What reboot required and the package lists' age are judged from.
cat /proc/sys/kernel/osrelease >"$out/osrelease"
ls -la /lib/modules /usr/lib/modules >"$out/modules" 2>&1
ls -la /run/reboot-required /var/run/reboot-required >"$out/reboot-required" 2>&1
find /var/lib/apt/periodic /var/lib/apt/lists /var/cache/dnf /var/cache/libdnf5 \
  /var/cache/yum /var/cache/zypp/raw /var/lib/pacman/sync /var/cache/apk -maxdepth 4 \
  \( -name '*Release' -o -name repomd.xml -o -name '*.db' -o -name 'APKINDEX*' \
  -o -name last_makecache -o -name update-success-stamp \) >"$out/lists" 2>/dev/null
# Where zypper keeps what it fetched, as its folders differ between releases.
ls -laR /var/cache/zypp >"$out/zypp-cache" 2>&1 || true
exit 0
