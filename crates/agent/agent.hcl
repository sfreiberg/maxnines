# Seconds between samples.
interval_secs = 15

# This agent's private key. Created on first start if missing, or ahead of time
# with `maxnines-agent identity generate`. Keep it out of synced folders.
key_file = "data.nosync/agent.key"

# How often to report facts, on top of every connection. Defaults to an hour.
facts_interval_secs = 3600

# Your own facts, reported alongside the built-in ones under "custom". Names
# can use letters, digits, - and _, and dots when quoted. Values can be text,
# numbers, booleans, lists or maps. A list item is reported as name[0], name[1]
# and so on.
# facts = {
#   role        = "web"
#   "one.thing" = "x"
#   rack        = 12
#   tags        = ["prod", "eu"]
# }
#
# A label groups facts under a name, so this one is reported as disk.size:
# facts "disk" {
#   size = 500
# }

# Uptime. Details that rarely change, like the OS, are reported as facts.
collector "host" {}

collector "cpu" {}

collector "memory" {}

collector "disk" {
  # Leave out mount_points to report every disk.
  mount_points = ["/"]
}

collector "network" {
  enabled = true
}

exporter "stdout" {
  # "json" prints one object per line; "pretty" is indented for reading.
  format = "json"
}

exporter "websocket" {
  # Use wss:// for anything beyond this machine.
  url = "ws://127.0.0.1:9000/ws"

  # Enrollment token, for servers with automatic approval rules.
  # token_file = "/etc/maxnines/enrollment.token"

  # Trust only this CA instead of the public roots, for testing.
  # ca_file = "/etc/maxnines/test-ca.pem"
}
