systemctl daemon-reload >/dev/null 2>&1 || :
# Upgrading: pick up the new version if it was running.
if [ "$1" -ge 1 ]; then
  systemctl try-restart maxnines-agent.service >/dev/null 2>&1 || :
fi
