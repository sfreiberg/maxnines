# The config can hold secrets, so only root and the service can read it.
chgrp maxnines /etc/maxnines/server.hcl
chmod 0640 /etc/maxnines/server.hcl
systemctl daemon-reload >/dev/null 2>&1 || :
