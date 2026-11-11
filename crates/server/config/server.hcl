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

# HTTPS. Leave this out behind a proxy that handles it, or on a trusted network. With
# it, public_url has to start with wss://. Certificates are picked up as they change,
# with no restart.
#
# Your own certificate:
#
# tls {
#   certificate_file = "/etc/maxnines/server.crt"
#   key_file         = "/etc/maxnines/server.key"
# }
#
# Or automatic certificates from Let's Encrypt. The service checks who you are by
# connecting to this server on port 443, so that has to reach it from the internet.
#
# tls {
#   acme {
#     domains   = ["maxnines.example.com"]
#     email     = "you@example.com"
#     cache_dir = "/var/lib/maxnines/acme"
#
#     # Another ACME service, and who to trust for a private one.
#     # directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
#     # ca_file   = "/etc/maxnines/acme-ca.pem"
#   }
# }

# Where samples are saved.
metrics "duckdb" {
  # Parent folders are created if needed. The .nosync folder keeps the live
  # database and its write-ahead log out of iCloud Drive.
  path = "data.nosync/maxnines.duckdb"

  # How much memory DuckDB may use, such as "1GiB" or "512MiB". Defaults to 1GiB.
  memory_limit = "1GiB"
}

# For bigger fleets, use ClickHouse instead. It runs as a server of its own, and the
# database and its tables are created for you.
#
# metrics "clickhouse" {
#   url      = "http://127.0.0.1:8123"
#   database = "maxnines"
#
#   # Only if ClickHouse needs a login. The password stays out of this file.
#   user          = "maxnines"
#   password_file = "/etc/maxnines/clickhouse.password"
# }

# How long metrics are kept, in days. Every sample is kept for full_resolution_days.
# Each 5 minutes and each hour are kept longer, as their lowest, highest and average
# value, which is what charts of long ranges read, so a spike still shows. These are
# the defaults. Leave hour_days out to keep hours for good.
retention {
  full_resolution_days = 30
  five_minute_days     = 365
  # hour_days          = 1825
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
