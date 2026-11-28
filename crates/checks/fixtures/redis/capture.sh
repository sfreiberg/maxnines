#!/bin/sh
# Captures what a real Redis's INFO says, byte for byte, in each state the Redis
# template's tests read: on its own with no memory limit, with a limit that's
# evicting keys, as a primary with a replica, as that replica with its link up and
# then down, and after a background save that failed. It starts throwaway servers
# on 127.0.0.1 with their data under a directory of their own, and stops them all
# before it ends. Run it from anywhere with redis-server, redis-cli and python3:
#
#   crates/checks/fixtures/redis/capture.sh /tmp/redis-capture
set -eu

work=${1:?give a directory for the servers data}
out=$(cd "$(dirname "$0")" && pwd)
primary=56379
replica=56380

cli() {
  port=$1
  shift
  redis-cli -p "$port" "$@"
}

start() {
  port=$1
  shift
  redis-server --port "$port" --bind 127.0.0.1 --dir "$work/$port" --daemonize yes \
    --pidfile "$work/$port.pid" --logfile "$work/$port.log" --save "" "$@"
  until cli "$port" ping >/dev/null 2>&1; do sleep 0.1; done
}

stop() {
  cli "$1" shutdown nosave >/dev/null 2>&1 || true
}
trap 'stop $primary; stop $replica' EXIT

# Keeps the reply to INFO exactly as Redis sent it, \r\n and all.
capture() {
  python3 -I - "$1" "$out/$2.info" <<'PY'
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
with socket.create_connection(("127.0.0.1", port)) as s:
    s.sendall(b"*1\r\n$4\r\nINFO\r\n")
    data = b""
    while b"\r\n" not in data:
        data += s.recv(65536)
    head, body = data.split(b"\r\n", 1)
    size = int(head[1:])
    while len(body) < size:
        body += s.recv(65536)
open(path, "wb").write(body[:size])
PY
}

mkdir -p "$work/$primary" "$work/$replica"
start $primary

# Twelve keys in db0, two of them expiring, and two in db3, one expiring, with
# some hits and misses.
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do cli $primary set "k$i" v >/dev/null; done
cli $primary expire k1 1000 >/dev/null
cli $primary expire k2 2000 >/dev/null
cli $primary -n 3 set other v >/dev/null
cli $primary -n 3 set other2 v EX 500 >/dev/null
for i in 1 2 3; do
  cli $primary get "k$i" >/dev/null
  cli $primary get "missing$i" >/dev/null
done
capture $primary standalone

# An account that can only read INFO and PING, as the docs suggest.
cli $primary acl setuser maxnines on '>s3cret' -@all +info +ping >/dev/null

# The replica, once its link is up.
start $replica --replicaof 127.0.0.1 $primary
until cli $replica info replication | grep -q 'master_link_status:up'; do sleep 0.1; done
until cli $primary info replication | grep -q 'state=online'; do sleep 0.1; done
cli $primary set after-sync v >/dev/null
capture $primary primary
capture $replica replica

# A limit that keys are evicted to stay under.
cli $primary config set maxmemory-policy allkeys-lru >/dev/null
cli $primary config set maxmemory 4mb >/dev/null
python3 -I - $primary <<'PY'
import socket, sys
port = int(sys.argv[1])
value = b"x" * 10000
with socket.create_connection(("127.0.0.1", port)) as s:
    for i in range(1000):
        key = b"fill%d" % i
        s.sendall(b"*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n" % (len(key), key, len(value), value))
        reply = b""
        while not reply.endswith(b"\r\n"):
            reply += s.recv(1024)
PY
capture $primary maxmemory

# A background save into a directory it can't write.
chmod 500 "$work/$primary"
cli $primary bgsave >/dev/null || true
until cli $primary info persistence | grep -q 'rdb_last_bgsave_status:err'; do sleep 0.1; done
chmod 700 "$work/$primary"
capture $primary bgsave-failed

# The replica once its primary has gone.
stop $primary
until cli $replica info replication | grep -q 'master_link_status:down'; do sleep 0.1; done
until cli $replica info replication | grep -q 'master_link_down_since_seconds:[1-9]'; do sleep 0.1; done
capture $replica replica-link-down

redis-server --version >"$out/version"
