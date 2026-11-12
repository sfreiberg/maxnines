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
  # Use wss:// for anything beyond this host.
  url = "ws://127.0.0.1:9000/ws"

  # Enrollment token, for servers with automatic approval rules.
  # token_file = "/etc/maxnines/enrollment.token"

  # Trust only this CA instead of the public roots, for testing.
  # ca_file = "/etc/maxnines/test-ca.pem"
}

# Where the agent keeps its key, the last config it received, and samples while
# the server can't be reached, up to 64 MiB. Keep it out of synced folders.
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

# Actions the server can ask this host to run, by name, such as when an alert
# fires or someone presses Run now. What a command prints, to standard output and
# standard error, goes back to the server, up to 64 KiB, so don't print secrets.
#
# The server can only pick from this list, and say how long an action gets. It
# can pass in a few values from the alert, which a command uses by naming them in
# braces in its arguments: {disk}, {interface}, {process}, {container}, {check}
# or {series} for what the alert is about, and {hostname}, {rule}, {severity},
# {metric}, {value} and {threshold}. A command runs as the agent's user, directly
# rather than through a shell, and each value stays inside its own argument. Keep
# this file writable only by its owner, because what's here gets run.
#
# Every agent also has these built in, which only look and never change anything:
#   top_cpu      the processes using the most CPU
#   top_memory   the processes using the most memory
#   disk_io      the processes reading and writing the most
#   disk_space   where the space on {disk} is going
# They name programs and folders, so turn them off if the server shouldn't be
# able to ask for that:
# built_in_actions = false
#
# Try any action as the agent's user, the way the server would run it:
#   maxnines-agent --config agent.hcl action disk_space disk=/var
#
# action "largest_folders" {
#   command = ["/usr/bin/du", "-x", "-h", "--max-depth=2", "{disk}"]
# }
#
# An action that changes something needs whatever permissions that takes, such
# as a sudoers rule letting the agent's user run exactly this command:
# action "restart_nginx" {
#   command = ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", "nginx"]
# }
