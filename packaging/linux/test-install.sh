#!/bin/sh
# Installs the built packages on whatever system this runs on, then runs both
# programs as their services would, to show they work there. The release
# workflow runs it in a container for each system the packages are meant for.
set -eu

if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq sudo ./packages/*.deb
else
  dnf install -y -q sudo ./packages/*.rpm
fi

id maxnines
for config in server agent; do
  test "$(stat -c '%U:%G %a' "/etc/maxnines/$config.hcl")" = "root:maxnines 640"
done
test -f /usr/lib/systemd/system/maxnines-server.service
test -f /usr/lib/systemd/system/maxnines-agent.service

# systemd makes the server's when it starts, and containers have no systemd. The
# agent's is made by its package.
install -d -o maxnines -g maxnines /var/lib/maxnines-server
test "$(stat -c '%U:%G %a' /var/lib/maxnines-agent)" = "maxnines:maxnines 750"
as_service() {
  setpriv --reuid maxnines --regid maxnines --init-groups "$@"
}
as_service maxnines-agent --config /etc/maxnines/agent.hcl facts >/dev/null
# Creates the main database and runs every migration.
as_service maxnines-server --config /etc/maxnines/server.hcl users list

# Started as root, as its service is, the agent gives that up and keeps a helper
# that doesn't. An action's command always runs as the agent's user.
cat >>/etc/maxnines/agent.hcl <<'ACTIONS'
action "who" {
  command = ["/usr/bin/id", "-un"]
}
action "who_with_sudo" {
  command = ["/usr/bin/sudo", "-n", "/usr/bin/id", "-un"]
}
ACTIONS
agent_action() {
  maxnines-agent --config /etc/maxnines/agent.hcl action "$@"
}
test "$(agent_action who)" = "maxnines"
test "$(as_service maxnines-agent --config /etc/maxnines/agent.hcl action who)" = "maxnines"
# One that needs more uses sudo, however the agent was started.
echo 'maxnines ALL=(root) NOPASSWD: /usr/bin/id' >/etc/sudoers.d/maxnines
chmod 0440 /etc/sudoers.d/maxnines
test "$(agent_action who_with_sudo)" = "root"
test "$(as_service maxnines-agent --config /etc/maxnines/agent.hcl action who_with_sudo)" = "root"
# The helper reads what only root can, for the built-in actions that need it,
# and keeps what it saw where only root can write.
install -d -m 0700 /srv/only-root
head -c 4194304 /dev/zero >/srv/only-root/file
agent_action disk_space disk=/srv/only-root | grep -q "/srv/only-root"
test "$(stat -c '%U %a' /var/lib/maxnines-agent-helper)" = "root 700"
test -f /var/lib/maxnines-agent-helper/disk_space.json
if as_service maxnines-agent --config /etc/maxnines/agent.hcl action disk_space disk=/srv/only-root; then
  exit 1
fi
# The helper also sees whose every socket is, which the agent's user can't.
agent_action connections | grep -q "TCP connection"
if agent_action connections | grep -q "isn't running as root"; then
  exit 1
fi
as_service maxnines-agent --config /etc/maxnines/agent.hcl action connections | grep -q "isn't running as root"
# It won't start with a folder its user can't write to, rather than fail later.
chown root /var/lib/maxnines-agent
if agent_action who; then
  exit 1
fi
chown maxnines /var/lib/maxnines-agent
# And the agent itself really has stopped being root: of its two processes, the
# one that runs actions is maxnines and the helper is root.
test "$(agent_action top_cpu | awk '$NF == "maxnines-agent" { print $2 }' | sort -u | tr '\n' ' ')" = "maxnines root "

# Upgrading keeps an edited config without asking: Debian doesn't track it at all,
# and RPM keeps it as noreplace.
for config in server agent; do
  echo "# Edited" >>"/etc/maxnines/$config.hcl"
done
if command -v apt-get >/dev/null; then
  test -z "$(dpkg-query -W -f='${Conffiles}' maxnines-server maxnines-agent)"
  apt-get install -y -qq --reinstall ./packages/*.deb </dev/null
else
  dnf reinstall -y -q ./packages/*.rpm </dev/null
fi
for config in server agent; do
  test "$(tail -n 1 "/etc/maxnines/$config.hcl")" = "# Edited"
  test "$(stat -c '%U:%G %a' "/etc/maxnines/$config.hcl")" = "root:maxnines 640"
done

# Purging deletes the configs and their folder.
if command -v apt-get >/dev/null; then
  apt-get purge -y -qq maxnines-server maxnines-agent </dev/null
  test ! -e /etc/maxnines
fi
echo "Installed and ran on $(. /etc/os-release && echo "$PRETTY_NAME")"
