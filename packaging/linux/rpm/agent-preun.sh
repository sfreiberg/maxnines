# Removing, not upgrading: stop it first.
if [ "$1" -eq 0 ]; then
  systemctl disable --now maxnines-agent.service >/dev/null 2>&1 || :
fi
