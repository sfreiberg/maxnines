# MongoDB's health, load and replication, with the alerts on them. It runs once for
# each MongoDB database: each `database` block of kind mongodb in an agent's config,
# and each MongoDB check that reads stats on a host without an agent. It reads the
# one server it's given, so each member of a replica set is read on its own, and
# says what the set looks like from there.
#
# MongoDB isn't SQL, so each query is one command, written as JSON, and `columns`
# names the fields of its reply that it reads. An account with the clusterMonitor
# role can run every one of them. MongoDB 7.0 moved WiredTiger's tickets to
# `queues.execution`, and older versions are past their end of life.

template "mongodb" {
  name        = "MongoDB"
  description = "Health, load and replication of MongoDB, each member of a replica set as it sees the set."
  database    = "mongodb"
  min_version = "7.0"

  discover "server" {
    interval = "1h"
    command  = <<-JSON
      { "buildInfo": 1 }
    JSON
    columns = {
      version = "version"
    }
  }

  # What it is in its replica set, looked at often, so a failover switches what's
  # read quickly. A server on its own has no set name, and a mongos router says
  # isdbgrid.
  discover "role" {
    interval = "10s"
    command  = <<-JSON
      { "hello": 1 }
    JSON
    columns = {
      replica_set = "setName"
      primary     = "isWritablePrimary"
      secondary   = "secondary"
      router      = "msg"
    }
  }

  # ---------------------------------------------------------------------------
  # The server's own status.

  query "server" {
    command = <<-JSON
      { "serverStatus": 1, "tcmalloc": 0 }
    JSON
    columns = {
      uptime                = "uptime"
      connections           = "connections.current"
      connections_available = "connections.available"
      refused               = "connections.rejected"
      reads                 = "opLatencies.reads.ops"
      read_time             = "opLatencies.reads.latency"
      writes                = "opLatencies.writes.ops"
      write_time            = "opLatencies.writes.latency"
      queued_reads          = "globalLock.currentQueue.readers"
      queued_writes         = "globalLock.currentQueue.writers"
      read_tickets          = "queues.execution.read.available"
      write_tickets         = "queues.execution.write.available"
      cache_size            = "wiredTiger.cache.bytes currently in the cache"
      cache_dirty_size      = "wiredTiger.cache.tracked dirty bytes in the cache"
      cache_limit           = "wiredTiger.cache.maximum bytes configured"
      cursors_open          = "metrics.cursor.open.total"
      cursors_timed_out     = "metrics.cursor.timedOut"
      _regular_asserts      = "asserts.regular"
      _warning_asserts      = "asserts.warning"
      _resident_mb          = "mem.resident"
      flow_control_lagged   = "flowControl.isLagged"
      replica               = "repl.secondary"
    }
    metrics = {
      uptime                = { title = "MongoDB uptime", unit = "s" }
      connections           = { title = "MongoDB connections" }
      connections_available = { title = "MongoDB connections free", description = "How many more connections it takes before refusing them" }
      connections_used      = { title = "MongoDB connections used", value = "connections / (connections + connections_available) * 100", unit = "%" }
      refused               = { title = "MongoDB connections refused at the limit", total = true }
      reads                 = { title = "MongoDB reads", total = true }
      read_time             = { title = "MongoDB time spent reading", total = true, description = "Microseconds spent on reads" }
      read_latency          = { title = "MongoDB read latency", value = "rate(read_time) / rate(reads) / 1000000", unit = "s" }
      writes                = { title = "MongoDB writes", total = true }
      write_time            = { title = "MongoDB time spent writing", total = true, description = "Microseconds spent on writes" }
      write_latency         = { title = "MongoDB write latency", value = "rate(write_time) / rate(writes) / 1000000", unit = "s" }
      queued_reads          = { title = "MongoDB reads queued" }
      queued_writes         = { title = "MongoDB writes queued" }
      read_tickets          = { title = "MongoDB read tickets free", description = "Few free means the storage engine is the bottleneck" }
      write_tickets         = { title = "MongoDB write tickets free" }
      cache_size            = { title = "MongoDB WiredTiger cache in use", unit = "bytes" }
      cache_dirty_size      = { title = "MongoDB WiredTiger cache changed", unit = "bytes" }
      cache_limit           = { title = "MongoDB WiredTiger cache size", unit = "bytes" }
      cache_used            = { title = "MongoDB cache used", value = "cache_size / cache_limit * 100", unit = "%" }
      cache_dirty           = { title = "MongoDB cache dirty", value = "cache_dirty_size / cache_limit * 100", unit = "%", description = "Over 20% starts slowing writes" }
      cursors_open          = { title = "MongoDB cursors open" }
      cursors_timed_out     = { title = "MongoDB cursors timed out", total = true }
      _regular_asserts      = { total = true }
      _warning_asserts      = { total = true }
      asserts               = { title = "MongoDB assertions", value = "rate(_regular_asserts) + rate(_warning_asserts)", unit = "/s" }
      memory                = { title = "MongoDB memory in use", value = "_resident_mb * 1048576", unit = "bytes" }
      flow_control_lagged   = { title = "MongoDB held back by flow control", description = "On a primary, whether flow control is holding writes back" }
      replica               = { title = "MongoDB is a replica" }
    }
  }

  # Each kind of operation, from a document of counts, a row to each.
  query "operations" {
    command = <<-JSON
      { "serverStatus": 1, "wiredTiger": 0, "metrics": 0, "tcmalloc": 0, "repl": 0 }
    JSON
    rows   = "opcounters"
    labels = ["operation"]
    columns = {
      operation  = "k"
      operations = "v"
    }
    metrics = {
      operations = { title = "MongoDB operations", total = true }
    }
  }

  # The longest-running operation a client asked for.
  query "oldest_query" {
    command = <<-JSON
      {
        "aggregate": 1,
        "pipeline": [
          { "$currentOp": { "allUsers": true, "idleConnections": false } },
          { "$match": { "active": true, "client": { "$exists": true } } },
          { "$group": { "_id": null, "oldest": { "$max": "$secs_running" } } }
        ],
        "cursor": {}
      }
    JSON
    columns = {
      oldest_query = "oldest"
    }
    metrics = {
      oldest_query = { title = "MongoDB oldest query", unit = "s" }
    }
  }

  # Opt-in: each database's size on disk, which costs more with many databases.
  query "sizes" {
    enabled  = false
    interval = "5m"
    command  = <<-JSON
      { "listDatabases": 1 }
    JSON
    rows   = "databases"
    labels = ["database"]
    columns = {
      database = "name"
      size     = "sizeOnDisk"
    }
    metrics = {
      size = { title = "MongoDB database size", unit = "bytes" }
    }
  }

  # ---------------------------------------------------------------------------
  # Its replica set, as this member sees it.

  query "replica_set" {
    when    = "replica_set != null"
    command = <<-JSON
      { "replSetGetStatus": 1 }
    JSON
    columns = {
      members         = "members"
      members_healthy = "members[health=1]"
      _primaries      = "members[state=1]"
      term            = "term"
    }
    metrics = {
      members         = { title = "MongoDB replica set members" }
      members_healthy = { title = "MongoDB replica set members healthy" }
      has_primary     = { title = "MongoDB replica set has a primary", value = "_primaries > 0" }
      term            = { title = "MongoDB election term", description = "Rises with each election" }
    }
  }

  # Each member, and how far behind the primary each secondary is.
  query "members" {
    when    = "replica_set != null"
    command = <<-JSON
      { "replSetGetStatus": 1 }
    JSON
    rows   = "members"
    labels = ["member"]
    columns = {
      member  = "name"
      _health = "health"
      _state  = "state"
      _optime = "optimeDate"
      _leader = "$.members[state=1].optimeDate"
    }
    metrics = {
      member_healthy = { title = "MongoDB member healthy", value = "_health == 1" }
      member_lag     = { title = "MongoDB member lag", value = "_state == 2 && _health == 1 ? (_leader > _optime ? _leader - _optime : 0) : null", unit = "s" }
    }
  }

  # On a secondary: how far behind the primary it is, and whether it's copying
  # from another member.
  query "replication" {
    when    = "secondary == true"
    command = <<-JSON
      { "replSetGetStatus": 1 }
    JSON
    columns = {
      _leader = "members[state=1].optimeDate"
      _own    = "members[self=true].optimeDate"
      _source = "syncSourceId"
    }
    metrics = {
      lag       = { title = "MongoDB replication lag", value = "_leader > _own ? _leader - _own : 0", unit = "s" }
      receiving = { title = "MongoDB replica receiving", value = "_source >= 0" }
    }
  }

  # On the primary: how far majority-committed writes are behind its own.
  query "majority" {
    when    = "primary == true && replica_set != null"
    command = <<-JSON
      { "replSetGetStatus": 1 }
    JSON
    columns = {
      _applied   = "optimes.lastAppliedWallTime"
      _committed = "optimes.lastCommittedWallTime"
    }
    metrics = {
      majority_lag = { title = "MongoDB majority commit lag", value = "_applied > _committed ? _applied - _committed : 0", unit = "s" }
    }
  }

  # How long the oplog covers, which is how long a secondary can be away and still
  # catch up without copying everything again.
  query "oplog" {
    when     = "replica_set != null"
    interval = "1m"
    command  = <<-JSON
      { "serverStatus": 1, "oplog": 1, "wiredTiger": 0, "metrics": 0, "tcmalloc": 0 }
    JSON
    columns = {
      _latest   = "oplog.latestOptime"
      _earliest = "oplog.earliestOptime"
    }
    metrics = {
      oplog_window = { title = "MongoDB oplog window", value = "_latest - _earliest", unit = "s" }
    }
  }

  # ---------------------------------------------------------------------------

  alert "down" {
    name             = "MongoDB down"
    critical         = "!up"
    for              = "1m"
    summary          = "{{ hostname }}: MongoDB {{ instance }} isn't answering"
    resolved_summary = "{{ hostname }}: MongoDB {{ instance }} is answering again"
  }

  alert "connections_running_out" {
    name     = "MongoDB connections running out"
    warning  = "connections_used > 80"
    critical = "connections_used > 90"
    for      = "5m"
    summary  = "{{ hostname }}: {{ instance }} is using {{ connections_used }} of its connections"
  }

  alert "no_primary" {
    name     = "MongoDB replica set has no primary"
    critical = "!has_primary"
    for      = "1m"
    summary  = "{{ hostname }}: {{ instance }}'s replica set has no primary, so it can't take writes"
  }

  alert "member_unhealthy" {
    name    = "MongoDB replica set member unhealthy"
    warning = "!member_healthy"
    for     = "2m"
    summary = "{{ hostname }}: {{ labels.member }} isn't healthy, as {{ instance }} sees it"
  }

  alert "replica_lagging" {
    name     = "MongoDB replica lagging"
    warning  = "lag > duration('1m')"
    critical = "lag > duration('5m')"
    for      = "2m"
    summary  = "{{ hostname }}: secondary {{ instance }} is {{ lag }} behind its primary"
  }

  alert "replication_stopped" {
    name     = "MongoDB replication stopped"
    critical = "!receiving"
    for      = "2m"
    summary  = "{{ hostname }}: secondary {{ instance }} isn't copying from any member"
  }

  # A new replica set's oplog covers only the time since it started, so this ships
  # turned off: turn it on once yours has filled.
  alert "oplog_window_short" {
    name    = "MongoDB oplog window short"
    enabled = false
    warning = "oplog_window < duration('24h')"
    for     = "10m"
    summary = "{{ hostname }}: {{ instance }}'s oplog only covers {{ oplog_window }}, so a secondary away longer has to copy everything again"
  }
}
