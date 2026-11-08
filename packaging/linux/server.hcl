# The MaxNines server's settings. It only ever reads this file. Everything it
# changes is kept in its databases, in /var/lib/maxnines-server.
#
# Every setting is described in the README:
# https://github.com/sfreiberg/maxnines#readme

# Address to listen on. Agents, the web pages and the API share this one port.
listen = "127.0.0.1:9000"

# The address agents connect to. It has to match the url in each agent.hcl
# exactly, so behind a proxy use its public address, such as
# "wss://monitor.example.com/ws".
public_url = "ws://127.0.0.1:9000/ws"

metrics "duckdb" {
  path = "/var/lib/maxnines-server/metrics.duckdb"
}

database {
  url = "sqlite:///var/lib/maxnines-server/maxnines.sqlite?mode=rwc"
}
