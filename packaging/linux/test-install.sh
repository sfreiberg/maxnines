#!/bin/sh
# Installs the built packages on whatever system this runs on, then runs both
# programs as their services would, to show they work there. The release
# workflow runs it in a container for each system the packages are meant for.
set -eu

if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq ./packages/*.deb
else
  dnf install -y -q ./packages/*.rpm
fi

id maxnines
for config in server agent; do
  test "$(stat -c '%U:%G %a' "/etc/maxnines/$config.hcl")" = "root:maxnines 640"
done
test -f /usr/lib/systemd/system/maxnines-server.service
test -f /usr/lib/systemd/system/maxnines-agent.service

# systemd makes these when a service starts, and containers have no systemd.
install -d -o maxnines -g maxnines /var/lib/maxnines-server /var/lib/maxnines-agent
as_service() {
  setpriv --reuid maxnines --regid maxnines --init-groups "$@"
}
as_service maxnines-agent --config /etc/maxnines/agent.hcl facts >/dev/null
# Creates the main database and runs every migration.
as_service maxnines-server --config /etc/maxnines/server.hcl users list
echo "Installed and ran on $(. /etc/os-release && echo "$PRETTY_NAME")"
