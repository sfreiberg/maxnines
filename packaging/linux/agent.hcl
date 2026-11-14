# The MaxNines agent's settings: only how to reach the server. What to monitor is
# set on the server.
#
# Every setting is described in the documentation, on the server's Docs page
# and at https://github.com/sfreiberg/maxnines/tree/main/docs

server {
  # The server's public_url. Use wss:// for anything beyond a trusted network.
  url = "ws://127.0.0.1:9000/ws"
}

# Its key, its last config and samples waiting to be sent, up to 64 MB.
state_dir = "/var/lib/maxnines-agent"
