# The MaxNines agent's settings: only how to reach the server. What to monitor is
# set on the server.
#
# The installer sets the server. To change it, open Settings > Apps > Installed
# apps > MaxNines Agent > Modify. Anything else here can be edited by hand, then
# restart the MaxNinesAgent service.
#
# Every setting is described in the documentation, on the server's Docs page
# and at https://github.com/sfreiberg/maxnines/tree/main/docs

server {
  # The server's public_url.
  url = "wss://monitor.example.com/ws"
}

# Its key, its last config and samples waiting to be sent, up to 64 MiB. A
# relative path, here or in any setting, is from this file's folder.
state_dir = "state"
