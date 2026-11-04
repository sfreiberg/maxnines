# Only what's needed to reach the server. What to monitor is set on the server.

server {
  # Use wss:// for anything beyond this machine.
  url = "ws://127.0.0.1:9000/ws"

  # Enrollment token, for servers with automatic approval rules.
  # token_file = "/etc/maxnines/enrollment.token"

  # Trust only this CA instead of the public roots, for testing.
  # ca_file = "/etc/maxnines/test-ca.pem"
}

# Where the agent keeps its key and the last config it received. Keep it out of
# synced folders.
state_dir = "data.nosync"

# Your own facts, which server rules can match on. Reported under "custom".
# Names can use letters, digits, - and _, and dots when quoted. Values can be
# text, numbers, booleans, lists or maps. A list item is reported as name[0],
# name[1] and so on.
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
