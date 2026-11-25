# Redis's health, memory, keys, persistence and replication, with the alerts on
# them. It runs once for each Redis: each `database` block of kind redis in an
# agent's config, and each Redis check that reads stats on a host without an agent.
# Valkey answers INFO as Redis does, so it's read the same way.
#
# Redis isn't SQL, so each query is one Redis command, written as its words, and
# `columns` names where in its reply each thing it reads is. INFO's reply is a
# document for each section, by its name in lower case, so `clients` holds
# `connected_clients`, and a value of name=value pairs, such as a database's
# `db0:keys=12,expires=3`, is a document of its own. INFO's `ok` and `up` are read
# as true, and `err` and `down` as false. An account that can run INFO and PING can
# run every one of them.

template "redis" {
  name        = "Redis"
  description = "Health, memory, keys, persistence and replication of Redis or Valkey, for an account that can run INFO."
  database    = "redis"

  discover "server" {
    interval = "1h"
    command  = "INFO server"
    columns = {
      version = "server.redis_version"
    }
  }

  # Every ten seconds, so a failover switches what's read quickly. Redis says
  # master or slave.
  discover "role" {
    interval = "10s"
    command  = "INFO replication"
    columns = {
      role = "replication.role"
    }
  }

  # What it does when its memory is full, such as noeviction or allkeys-lru, which
  # can be changed at any time.
  discover "memory" {
    interval = "1m"
    command  = "INFO memory"
    columns = {
      policy = "memory.maxmemory_policy"
    }
  }

  # ---------------------------------------------------------------------------
  # Health and load

  query "server" {
    command = "INFO"
    columns = {
      uptime             = "server.uptime_in_seconds"
      connections        = "clients.connected_clients"
      _max_connections   = "clients.maxclients"
      blocked            = "clients.blocked_clients"
      refused            = "stats.rejected_connections"
      commands           = "stats.total_commands_processed"
      memory             = "memory.used_memory"
      memory_limit       = "memory.maxmemory"
      fragmentation      = "memory.mem_fragmentation_ratio"
      evicted            = "stats.evicted_keys"
      expired            = "stats.expired_keys"
      hits               = "stats.keyspace_hits"
      misses             = "stats.keyspace_misses"
      changes_since_save = "persistence.rdb_changes_since_last_save"
      last_save_ok       = "persistence.rdb_last_bgsave_status"
      aof_write_ok       = "persistence.aof_last_write_status"
    }
    metrics = {
      uptime           = { title = "Redis uptime", unit = "s" }
      connections      = { title = "Redis connections", description = "Clients connected, not counting replicas" }
      connections_used = { title = "Redis connections used of the limit", value = "connections / _max_connections * 100", unit = "%", description = "Out of maxclients, which INFO gives from Redis 7" }
      blocked          = { title = "Redis clients blocked", description = "Clients waiting on a blocking command, such as BLPOP" }
      refused          = { title = "Redis connections refused at the limit", total = true, description = "Turned away because maxclients were already connected" }
      commands         = { title = "Redis commands", total = true }
      memory           = { title = "Redis memory used", unit = "bytes", description = "What Redis has allocated for its data and itself" }
      memory_limit     = { title = "Redis memory limit", unit = "bytes", description = "maxmemory, where 0 means no limit" }
      # No limit, maxmemory 0, gives nothing rather than dividing by it.
      memory_used   = { title = "Redis memory used of the limit", value = "memory_limit > 0 ? memory / memory_limit * 100 : null", unit = "%" }
      fragmentation = { title = "Redis memory fragmentation ratio", description = "Memory the system gave Redis over what it uses: well over 1.5 is memory wasted, and under 1 means some of it is swapped out" }
      evicted       = { title = "Redis keys evicted", total = true, description = "Keys taken out to stay under maxmemory" }
      expired       = { title = "Redis keys expired", total = true }
      hits          = { title = "Redis lookups that found their key", total = true }
      misses        = { title = "Redis lookups that missed", total = true }
      cache_hit = {
        title       = "Redis cache hit rate"
        value       = "rate(hits) / (rate(hits) + rate(misses)) * 100"
        unit        = "%"
        description = "Lookups that found their key"
      }
      changes_since_save = { title = "Redis changes since the last save", description = "Writes an RDB snapshot doesn't have yet" }
      last_save_ok       = { title = "Redis last background save worked" }
      aof_write_ok       = { title = "Redis last AOF write worked", description = "Always true with the append-only file turned off" }
    }
  }

  # Keys and keys with an expiry in each logical database, db0 and so on.
  query "keyspace" {
    command = "INFO keyspace"
    rows    = "keyspace"
    labels  = ["db"]
    columns = {
      db      = "k"
      keys    = "v.keys"
      expires = "v.expires"
    }
    metrics = {
      keys    = { title = "Redis keys" }
      expires = { title = "Redis keys with an expiry" }
    }
  }

  # ---------------------------------------------------------------------------
  # Replication

  query "primary" {
    when    = "role == 'master'"
    command = "INFO replication"
    columns = {
      replicas        = "replication.connected_slaves"
      replicas_online = "replication[state=online]"
    }
    metrics = {
      replica         = { title = "Redis is a replica", value = "false" }
      replicas        = { title = "Redis replicas connected" }
      replicas_online = { title = "Redis replicas online", description = "Replicas past their first full copy and streaming" }
    }
  }

  # Each replica streaming from this server, as it says: how long since each said
  # how far it had got, which it does every second, and how far that is behind.
  query "replicas" {
    command = "INFO replication"
    rows    = "replication[state=online]"
    labels  = ["replica", "port"]
    columns = {
      replica           = "v.ip"
      port              = "v.port"
      last_acknowledged = "v.lag"
      _offset           = "v.offset"
      _primary_offset   = "$.replication.master_repl_offset"
    }
    metrics = {
      last_acknowledged = { title = "Redis time since each replica acknowledged", unit = "s" }
      lag_bytes         = { title = "Redis replica lag in bytes", value = "_primary_offset > _offset ? _primary_offset - _offset : 0", unit = "bytes", description = "How far each replica's acknowledged position is behind this server's" }
    }
  }

  # A replica only knows how far it has got, not how far its primary has, so how far
  # behind it is in bytes is read on its primary, above.
  query "replica" {
    when    = "role == 'slave'"
    command = "INFO replication"
    columns = {
      receiving = "replication.master_link_status"
      _last_io  = "replication.master_last_io_seconds_ago"
      syncing   = "replication.master_sync_in_progress"
    }
    metrics = {
      replica       = { title = "Redis is a replica", value = "true" }
      receiving     = { title = "Redis replica receiving", description = "Whether its link to its primary is up" }
      last_received = { title = "Redis time since the replica heard from its primary", value = "_last_io >= 0 ? _last_io : null", unit = "s", description = "Its primary pings every 10 seconds when there's nothing to send" }
      syncing       = { title = "Redis replica copying everything from its primary" }
    }
  }

  # ---------------------------------------------------------------------------
  # Alerts

  # `up` is every database template's: false when it can't be signed in to. A
  # Redis check alerts on nothing itself, so this is the only alert that it's down.
  alert "down" {
    name             = "Redis down"
    critical         = "!up"
    for              = "1m"
    summary          = "{{ hostname }}: Redis {{ instance }} isn't answering"
    resolved_summary = "{{ hostname }}: Redis {{ instance }} is answering again"
  }

  # Only with a limit, as memory_used is nothing without one, and only where being
  # full matters: with noeviction Redis refuses writes at its limit, and with a
  # volatile policy once no key with an expiry is left to evict. A cache that may
  # evict any key, allkeys-lru and the like, is meant to run full.
  alert "memory_near_limit" {
    name     = "Redis memory near its limit"
    when     = "!policy.startsWith('allkeys')"
    warning  = "memory_used > 90"
    critical = "memory_used > 95"
    for      = "5m"
    summary  = "{{ hostname }}: {{ instance }} is using {{ memory_used }} of its maxmemory"
  }

  # Evicting under a volatile policy drops keys before they expire, for 5 minutes
  # running rather than once. With allkeys, evicting is the cache doing its job,
  # and with noeviction nothing is evicted.
  alert "evicting" {
    name    = "Redis evicting keys"
    when    = "!policy.startsWith('allkeys')"
    warning = "evicted > 0"
    for     = "5m"
    summary = "{{ hostname }}: {{ instance }} is evicting keys to stay under its maxmemory"
  }

  # A full copy from the primary takes the link down while it runs, so a few
  # minutes, as other databases' replicas get.
  alert "replica_not_receiving" {
    name     = "Redis replica not receiving"
    when     = "role == 'slave'"
    critical = "!receiving"
    for      = "2m"
    summary  = "{{ hostname }}: replica {{ instance }}'s link to its primary is down"
  }

  # By default Redis refuses writes after a background save fails, so at once.
  alert "save_failed" {
    name     = "Redis background save failed"
    critical = "!last_save_ok"
    summary  = "{{ hostname }}: {{ instance }}'s last background save failed, and by default Redis refuses writes until one works"
  }

  # Each one is a client turned away at maxclients.
  alert "refusing_connections" {
    name    = "Redis refusing connections"
    warning = "refused > 0"
    summary = "{{ hostname }}: {{ instance }} refused {{ refused }} connections at its maxclients limit"
  }
}
