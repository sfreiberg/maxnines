# The MaxNines server's settings. It only ever reads this file. Everything it
# changes is kept in its databases, in this folder.
#
# The installer sets the address, the port and HTTPS. To change them, open
# Settings > Apps > Installed apps > MaxNines Server > Modify. Anything else
# here can be edited by hand, then restart the MaxNinesServer service.
#
# Every setting is described in the documentation, on the server's Docs page
# and at https://github.com/sfreiberg/maxnines/tree/main/docs

# Address to listen on. Agents, the web pages and the API share this one port.
listen = "0.0.0.0:9000"

# The address agents connect to. It has to match the url in each agent.hcl
# exactly, so behind a proxy use its public address, such as
# "wss://monitor.example.com/ws".
public_url = "ws://localhost:9000/ws"

metrics "duckdb" {
  path = "metrics.duckdb"
}

# How long metrics are kept, in days: every sample, then each 5 minutes and each hour as
# their lowest, highest and average value. Leave hour_days out to keep hours for good.
retention {
  full_resolution_days = 30
  five_minute_days     = 365
}

database {
  url = "sqlite://maxnines.sqlite?mode=rwc"
}
