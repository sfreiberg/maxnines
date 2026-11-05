# Only what's needed to reach the server. What to monitor is set on the server.
#
# Any value can come from the environment, on its own or inside a longer value:
#
#   url = env("MAXNINES_SERVER_URL")
#   url = env("MAXNINES_SERVER_URL", "ws://127.0.0.1:9000/ws")
#   url = "wss://${env("MONITOR_HOST")}/ws"
#
# The agent won't start if a variable with no default isn't set.

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

# Your own metrics, from commands. A command prints one number to standard output,
# or a JSON object of up to 32 numbers such as {"depth": 12, "oldest_secs": 40},
# which report as queue_depth.depth and queue_depth.oldest_secs. It runs as the
# agent's user, directly rather than through a shell. For pipes, use
# ["/bin/sh", "-c", "..."].
#
# The server chooses which of these to collect and how often, by name, but it can
# only pick from this list. Only the numbers are reported, never other output. Keep
# this file writable only by its owner, because what's here gets run.
#
# custom_metric "queue_depth" {
#   command      = ["/usr/local/bin/queue-depth", "--name", "mail"]
#   timeout_secs = 5   # from 1 to 60, 10 if left out
# }
