# The MaxNines server's settings in its container. Set MAXNINES_PUBLIC_URL to the
# address agents use, or mount your own file over this one.
#
# Every setting is described in the README:
# https://github.com/sfreiberg/maxnines#readme

listen = env("MAXNINES_LISTEN", "0.0.0.0:9000")

# The address agents connect to. It has to match the url in each agent.hcl
# exactly.
public_url = env("MAXNINES_PUBLIC_URL", "ws://localhost:9000/ws")

metrics "duckdb" {
  path = "/var/lib/maxnines-server/metrics.duckdb"
}

database {
  url = "sqlite:///var/lib/maxnines-server/maxnines.sqlite?mode=rwc"
}
