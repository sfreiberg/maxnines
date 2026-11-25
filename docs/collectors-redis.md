# Redis

MaxNines reads a Redis server's health, memory, keys, persistence and replication:
its clients against their limit, memory against `maxmemory`, keys evicted and expired,
how often lookups find their key, each database's keys, whether its last save worked,
and, from a primary, each replica and how far behind it is. It's read by the built-in
**Redis** [template](templates.md), with Redis' own [commands](templates.md#redis-commands),
the same way on an agent and on the server.

Everything it reads comes from `INFO`, whose fields have been there since Redis 4,
apart from the connection limit, which `INFO` gives from Redis 7. It's tested
against Redis 8.12. **Valkey** keeps Redis' `INFO` fields, so it's read the same way,
though that hasn't been tested against a real Valkey.

## Turning it on

**On a host with an agent**, add a `database` block to the agent's own `agent.hcl`,
with where Redis is and how to sign in, so the password never leaves the host:

```hcl
database "sessions" {
  kind     = "redis"
  target   = "127.0.0.1:6379"
  username = "maxnines"
  password = env("SESSIONS_REDIS_PASSWORD")
}
```

Leave out `username` to sign in with a password alone, as Redis before 6 and its
`default` user take, and both where Redis asks for no password. Redis takes a password
as it is, with nothing to hide it, so one is only sent without TLS to the host itself:
for a Redis elsewhere, set `tls = true`, which Redis has to be set up for. A database is
read from the one server given, so give each primary and replica a block of its own.
The [settings](database-stats.md#the-database-block) are the same for every kind of
database. Restart the agent after changing them.

That's all: the Redis template reads every Redis `database` block on every host it's
for, which as it ships is every host, with no config rule needed. Choose which hosts on
the template's page, under **Settings > Templates**, or turn it off there.

**On a host without an agent**, such as a managed service, add a Redis check about the
host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**. See [hosts without an agent](database-stats.md#hosts-without-an-agent).

## The account to sign in as

On Redis 6 and later, give MaxNines a user of its own that can only run `INFO` and
`PING`:

```text
ACL SETUSER maxnines on >a-long-random-password -@all +info +ping
ACL SAVE
```

That runs every command the template does. `ACL SAVE` keeps the user over a restart
when users are kept in an ACL file; with users in `redis.conf`, use `CONFIG REWRITE`
instead. A template of your own that asks for more, such as `CONFIG GET maxclients`,
needs that too, such as `+config|get`. Nothing stops a template's command doing more
than reading, so what it may do is up to the account.

**What the account may do.** MaxNines [reads](database-stats.md#what-the-account-may-do)
what the account may do with `ACL GETUSER`. A user like the one above can't run it,
which is all that can be told of it, so it counts as only reading, and it's asked once
for each connection rather than every 5 minutes, as Redis notes each refusal in its
`ACL LOG`. A password alone, before Redis 6, or Redis' `default` user, which may run
everything unless it's been changed, counts as able to do anything, which the
**Database account can do more than read** alert warns about.

## What's read, and how often

The template finds out about the server first, with **`server`**, its version, every
hour, **`role`**, every 10 seconds, so a failover changes what's read quickly, whether
it's a primary, which Redis calls `master`, or a replica, `slave`, and **`memory`**,
every minute, what it does when its memory is full, its `maxmemory_policy`. Then every
sample it reads:

- **`server`**, `INFO`: its clients, commands, memory and its limit, keys evicted and
  expired, lookups, and how its last save and append-only file write went;
- **`keyspace`**, `INFO keyspace`: each database's keys;
- **`replicas`**, `INFO replication`: each replica streaming from it, which a replica
  of a replica has too;
- on a primary, **`primary`**, `INFO replication`: how many replicas it has;
- on a replica, **`replica`**, `INFO replication`: its link to its primary.

A replica only knows how far it has got, not how far its primary has, so how far
behind a replica is in bytes is read on its primary, which says where each replica had
got when it last acknowledged, as each does every second.

What discovery found, and anything that went wrong, are on the template's page and the
host's **Templates** card.

## What's reported

Each metric has a series for each database block or check, labelled `instance`, such
as `sessions`, and those about several things are labelled by them too, such as the
database `sessions, db0` or the replica `sessions, 10.0.0.12, 6379`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `redis.up` | 1 or 0 | Each database | Whether the server answered |
| `redis.uptime` | Seconds | Each database | How long the server has been running |
| `redis.connections` | Number | Each database | Clients connected, not counting replicas |
| `redis.connections_used` | % | Each database | Clients connected, of `maxclients`, from Redis 7 |
| `redis.blocked` | Number | Each database | Clients waiting on a blocking command, such as `BLPOP` |
| `redis.refused` | A second | Each database | Connections refused because `maxclients` were already connected |
| `redis.commands` | A second | Each database | Commands run |
| `redis.memory` | Bytes | Each database | Memory Redis has allocated, for its data and itself |
| `redis.memory_limit` | Bytes | Each database | `maxmemory`, where 0 means no limit |
| `redis.memory_used` | % | Each database | Memory used, of `maxmemory`, with a limit set |
| `redis.fragmentation` | Number | Each database | Memory the system gave Redis over what it uses. Well over 1.5 is memory wasted, and under 1 means some of it is swapped out |
| `redis.evicted` | A second | Each database | Keys taken out to stay under `maxmemory` |
| `redis.expired` | A second | Each database | Keys that expired |
| `redis.hits` | A second | Each database | Lookups that found their key |
| `redis.misses` | A second | Each database | Lookups that didn't |
| `redis.cache_hit` | % | Each database | Lookups that found their key, of all lookups |
| `redis.changes_since_save` | Number | Each database | Writes the last RDB snapshot doesn't have |
| `redis.last_save_ok` | 1 or 0 | Each database | Whether the last background save worked |
| `redis.aof_write_ok` | 1 or 0 | Each database | Whether the last write to the append-only file worked, always 1 with it turned off |
| `redis.keys` | Number | Each database and database in it | Keys in each database, such as `sessions, db0` |
| `redis.expires` | Number | Each database and database in it | Keys with an expiry in each database |
| `redis.replica` | 1 or 0 | Each database | Whether it's a replica |
| `redis.replicas` | Number | Each database | On a primary, replicas connected |
| `redis.replicas_online` | Number | Each database | On a primary, replicas past their first full copy and streaming |
| `redis.last_acknowledged` | Seconds | Each database and replica | How long since each replica streaming from it said how far it had got, such as `sessions, 10.0.0.12, 6379` |
| `redis.lag_bytes` | Bytes | Each database and replica | How far each replica streaming from it is behind, as of its last acknowledgement |
| `redis.receiving` | 1 or 0 | Each database | On a replica, whether its link to its primary is up |
| `redis.last_received` | Seconds | Each database | On a replica, how long since it heard from its primary, which pings every 10 seconds when there's nothing to send. Left out while it hasn't heard at all |
| `redis.syncing` | 1 or 0 | Each database | On a replica, whether it's copying everything from its primary |

## Built-in alerts

The template brings these, for each Redis it reads. Change or turn off any of them on
the template's page.

| Alert | When | Level |
| --- | --- | --- |
| **Redis down** | It hasn't answered for a minute. A Redis check alerts on nothing itself, so this is the alert that it's down | Critical |
| **Redis memory near its limit** | With `maxmemory` set, over 90% of it for 5 minutes, or over 95%. Only where being full matters: with `noeviction`, Redis refuses writes at its limit, and with a `volatile-` policy once no key with an expiry is left. A cache that may evict any key, `allkeys-lru` and the like, is meant to run full | Warning, then critical |
| **Redis evicting keys** | Keys evicted in every sample for 5 minutes, with a `volatile-` policy, where it means keys going before they expire. With `allkeys-` policies evicting is the cache doing its job, and with `noeviction` nothing is evicted | Warning |
| **Redis replica not receiving** | A replica's link to its primary down for 2 minutes, which a full copy from the primary takes it down for while it runs | Critical |
| **Redis background save failed** | The last background save failed. By default Redis refuses writes until one works | Critical |
| **Redis refusing connections** | A connection refused at its `maxclients` limit | Warning |
