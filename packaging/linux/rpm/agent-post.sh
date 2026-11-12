# The config can hold secrets, so only root and the service can read it.
chgrp maxnines /etc/maxnines/agent.hcl
chmod 0640 /etc/maxnines/agent.hcl
# Where it keeps its key and what it hasn't sent yet. The agent's own user owns it.
if [ ! -e /var/lib/maxnines-agent ]; then
  install -d -m 0750 -o maxnines -g maxnines /var/lib/maxnines-agent
fi
systemctl daemon-reload >/dev/null 2>&1 || :
