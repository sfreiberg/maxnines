# The server only ever reads this file. Anything it generates or changes is kept
# in its databases.
#
# Any value can come from the environment, on its own or inside a longer value:
#
#   listen = env("LISTEN_ADDRESS")
#   listen = env("LISTEN_ADDRESS", "127.0.0.1:9000")
#   url    = "postgres://maxnines:${env("DB_PASSWORD")}@db:5432/maxnines"
#
# The server won't start if a variable with no default isn't set.

# Address to listen on. Agents and the admin commands share this one port.
listen = "127.0.0.1:9000"

# The address agents connect to, which they sign as part of proving who they
# are. Must match the url in agent.hcl exactly, so behind a proxy use its public
# address, such as "wss://monitor.example.com/ws".
public_url = "ws://127.0.0.1:9000/ws"

# Proxies whose X-Forwarded-For header can be believed, as addresses or CIDRs.
trusted_proxies = []

# The server pings each agent this often, and counts an agent as offline after
# this long without hearing from it.
heartbeat_interval_secs = 5
heartbeat_timeout_secs  = 15

# Where samples are saved.
metrics "duckdb" {
  # Parent folders are created if needed. The .nosync folder keeps the live
  # database and its write-ahead log out of iCloud Drive.
  path = "data.nosync/maxnines.duckdb"

  # How much memory DuckDB may use, such as "1GB" or "512MB". Defaults to 1GB.
  memory_limit = "1GB"
}

# Where everything else is saved, such as registered agents. The URL picks the
# database. Use url_file instead of url to keep a password out of this file.
#
#   sqlite://data.nosync/maxnines.sqlite?mode=rwc
#   postgres://user:password@host:5432/maxnines
#   mysql://user:password@host:3306/maxnines
database {
  url = "sqlite://data.nosync/maxnines.sqlite?mode=rwc"
}

registration {
  # New agents waiting for approval, after which new requests are ignored.
  max_pending = 1000

  # Rules run in order and the first match decides. With no match, an agent
  # waits for manual approval. All conditions in a rule must match. Hostnames
  # are reported by the agent, so an "approve" rule also needs a source_cidrs
  # or token_file condition.
  #
  # rule "production-subnet" {
  #   action       = "approve"
  #   source_cidrs = ["10.20.0.0/16"]
  #   hostname     = "web-*"
  #   token_file   = "/etc/maxnines/enrollment.token"
  # }
  #
  # rule "block-guest-network" {
  #   action       = "reject"
  #   source_cidrs = ["10.99.0.0/16"]
  # }
}

# The mail server for email notifications. Leave this out if you don't use them.
#
# email {
#   host = "smtp.example.com"
#
#   # "starttls" (the default), "tls", or "none" for a relay on this machine.
#   security = "starttls"
#
#   # Defaults to the usual port for the security setting.
#   # port = 587
#
#   # The password is read from a file to keep it out of this one.
#   username      = "alerts@example.com"
#   password_file = "/etc/maxnines/smtp.password"
#
#   from = "MaxNines <alerts@example.com>"
# }
