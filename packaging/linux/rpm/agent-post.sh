# The config can hold secrets, so only root and the service can read it.
chgrp maxnines /etc/maxnines/agent.hcl
chmod 0640 /etc/maxnines/agent.hcl
systemctl daemon-reload >/dev/null 2>&1 || :
